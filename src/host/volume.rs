//! Native persistence from `runner.py`'s install/format/claim protocol.
//!
//! These records bind an installation, not permission to format a device or
//! proof of its mount identity. No device, mount, subprocess or service work is
//! performed here. Callers must establish those facts separately, retain the
//! installation guard throughout, and reopen directories after mount transitions.

use eyre::{ensure, Result};
use nix::errno::Errno;
use serde_json::{json, Value};

use super::{
    files::{Directory, Lock},
    HostInstallSpec,
};

pub mod device;
pub mod evidence;
pub mod prepare;
pub mod probe;

/// Exact original volume identity without taking a lock or publishing a file.
/// Long-lived producer startup uses this read-only boundary while its parent
/// activation action retains the installation lock.
pub(super) fn identity(spec: &HostInstallSpec) -> Result<Vec<u8>> {
    encoded(json!({
        "apiVersion": "zdn-host-volume/v1alpha1",
        "deploymentId": spec.deployment_id,
        "nodeId": spec.node_id,
        "volumeId": spec.volume_id,
        "consensusFingerprint": spec.consensus_fingerprint,
        "installSha256": spec.install_sha256()?,
    }))
}

/// Holds the same `install.lock` used by historical install/update/recovery
/// operations. The expected-owner directory must be reached through trusted
/// traversal (production: `/`, owner 0), not an unchecked pathname.
pub struct Installation<'a> {
    directory: &'a Directory,
    _lock: Lock,
    identity: Vec<u8>,
    format_intent: Vec<u8>,
    requires_format_intent: bool,
}

impl<'a> Installation<'a> {
    /// Validate the saved spec before taking authority or writing anything.
    /// Existing identity bytes/mode must match; a different install is never
    /// adopted or repaired. Exact retries retain the existing inode.
    pub fn acquire(directory: &'a Directory, spec: &HostInstallSpec) -> Result<Self> {
        Self::acquire_with_initialization(directory, spec, None)
    }

    /// Native first installation must record its immutable selection before
    /// original identity publication. Existing legacy identities cannot acquire
    /// this authority, even when all their original bytes match. A crash after
    /// intent but before identity can recover forward under the same lock.
    pub(in crate::host) fn acquire_native(
        directory: &'a Directory,
        spec: &HostInstallSpec,
        manifest: &[u8],
    ) -> Result<Self> {
        Self::acquire_with_initialization(directory, spec, Some(manifest))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.acquire")
    )]
    fn acquire_with_initialization(
        directory: &'a Directory,
        spec: &HostInstallSpec,
        initialization: Option<&[u8]>,
    ) -> Result<Self> {
        let identity = identity(spec)?;
        let format_intent = encoded(json!({
            "apiVersion": "zdn-host-format/v1alpha1",
            "identity": serde_json::from_slice::<Value>(&identity)?,
            "newVolume": spec.new_volume,
        }))?;
        let lock = directory.lock("install.lock")?;
        if let Some(manifest) = initialization {
            match directory.read("identity.json", 8192) {
                Ok(existing) => {
                    ensure!(existing == identity, "host volume record differs");
                    require_record(directory, "native-install-intent.json", manifest)?;
                    directory.publish("native-install-intent.json", manifest, 0o600)?;
                }
                Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {
                    directory.publish("native-install-intent.json", manifest, 0o600)?;
                }
                Err(error) => return Err(error),
            }
        }
        directory.publish("identity.json", &identity, 0o600)?;
        Ok(Self {
            directory,
            _lock: lock,
            identity,
            format_intent,
            requires_format_intent: spec.new_volume.is_some(),
        })
    }

    /// Expected bytes for `.zdn-volume.json`. `claim_mounted` permits adoption
    /// only after checking first-install intent and empty-filesystem evidence;
    /// the caller must separately establish fresh mount/device identity.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Bind another phase of the same action to this guard's complete spec.
    pub(crate) fn verify_spec(&self, spec: &HostInstallSpec) -> Result<String> {
        let digest = spec.install_sha256()?;
        let identity: Value = serde_json::from_slice(&self.identity)?;
        ensure!(
            identity["installSha256"] == digest,
            "installation guard belongs to another host spec"
        );
        Ok(digest)
    }

    /// Persist intent AFTER the caller's blankness/provenance and attachment
    /// checks and BEFORE any mkfs. Even an identical earlier format intent is
    /// uncertain: it may have reached mkfs, so never authorize a second format.
    /// A previously claimed disk that now appears blank must also fail closed.
    /// The exclusive borrow prevents two threads sharing one guard from both
    /// observing absent intent before either publishes it.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.begin_format")
    )]
    pub fn begin_format(&mut self) -> Result<()> {
        self.directory.require_absent("volume-claimed.json")?;
        self.directory.require_absent("format-intent.json")?;
        require_record(self.directory, "identity.json", &self.identity)?;
        self.directory
            .publish("format-intent.json", &self.format_intent, 0o600)
    }

    /// An interrupted first install may finish claiming an already formatted
    /// empty filesystem with exactly this intent. This is not format authority.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.verify_format_intent")
    )]
    pub fn verify_format_intent(&self) -> Result<()> {
        require_record(self.directory, "format-intent.json", &self.format_intent)
    }

    /// Verify an existing on-volume claim, or complete a first-install claim on
    /// an empty filesystem (optionally containing an empty real lost+found).
    /// The caller must freshly verify attachment/mount identity and reopen this
    /// trusted directory after mounting. A Directory alone is NOT mount proof.
    /// Restarts never adopt unclaimed filesystems. No formatting is performed.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.claim_mounted")
    )]
    pub fn claim_mounted(&self, mounted: &Directory, allow_create: bool) -> Result<()> {
        match mounted.read(".zdn-volume.json", self.identity.len() as u64) {
            Ok(identity) => ensure!(identity == self.identity, "host volume record differs"),
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {
                ensure!(
                    allow_create,
                    "existing chain volume has no ownership record"
                );
                // Fail on the first foreign entry; do not collect an unbounded
                // directory listing or follow a lost+found symlink.
                for entry in mounted.entries()? {
                    ensure!(
                        entry?.file_name() == "lost+found",
                        "unclaimed EBS filesystem contains data"
                    );
                    let lost_found = mounted.open_directory("lost+found")?;
                    ensure!(
                        lost_found.entries()?.next().transpose()?.is_none(),
                        "unclaimed EBS filesystem contains data"
                    );
                }
                require_record(self.directory, "identity.json", &self.identity)?;
                if self.requires_format_intent {
                    self.verify_format_intent()?;
                }
                mounted.publish(".zdn-volume.json", &self.identity, 0o600)?;
            }
            Err(error) => return Err(error),
        }
        self.record_volume_claim(mounted)
    }

    /// Record root-disk evidence only AFTER verifying an existing on-volume
    /// claim. `mounted` must be freshly opened after a verified mount transition;
    /// a directory descriptor alone does not prove the expected volume is mounted.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.record_volume_claim")
    )]
    pub fn record_volume_claim(&self, mounted: &Directory) -> Result<()> {
        require_record(mounted, ".zdn-volume.json", &self.identity)?;
        self.directory
            .publish("volume-claimed.json", &self.identity, 0o600)
    }
}

fn require_record(directory: &Directory, name: &str, expected: &[u8]) -> Result<()> {
    ensure!(
        directory.read(name, expected.len() as u64)? == expected,
        "host volume record differs"
    );
    Ok(())
}

fn encoded(value: Value) -> Result<Vec<u8>> {
    // serde_json's locked default Map is sorted. All fields are validated ASCII;
    // this matches Python's sort_keys=True, compact separators and final LF,
    // including the nested authorization (or explicit null for legacy installs).
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
