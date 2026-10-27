//! Native persistence from `install.py::{format_intent,prepare_cache}`.
//!
//! Cache ownership is distinct from chain-volume ownership. These records do
//! not prove EBS attachment, device blankness or a mounted filesystem, and never
//! perform a format/mount. A future privileged installer must authenticate the
//! spec and native selection, establish those facts, retain this lock, and
//! reopen the cache directory after mount transitions. No deployment uses this
//! API yet. In particular, matching legacy records alone do not authorize a
//! deployment to switch to a native runtime.

use eyre::{ensure, Result};
use nix::errno::Errno;
use serde_json::{json, Value};

use super::{hash, render_service, LightwalletInstallSpec, INSTALL_API_VERSION};
use crate::host::files::{Directory, Lock};

pub mod prepare;

const CLAIM: &str = ".zdn-lightwalletd-volume.json";

/// The historical lightwallet `install.lock`, not the node's lock. Reach the
/// expected-owner metadata directory through trusted descriptor traversal
/// (production: `/etc/zdn-lightwalletd`, owner 0). The expected owner must not
/// concurrently replace trusted ancestors or mount points.
pub struct Installation<'a> {
    directory: &'a Directory,
    _lock: Lock,
    identity: Vec<u8>,
    cache_identity: Vec<u8>,
    format_intent: Vec<u8>,
}

impl<'a> Installation<'a> {
    /// Validate before creating records. Exact retries retain existing bytes,
    /// permissions and inodes; mismatching installations are never adopted.
    pub fn acquire(directory: &'a Directory, spec: &LightwalletInstallSpec) -> Result<Self> {
        Self::acquire_with_initialization(directory, spec, None)
    }

    /// Native first-install journaling, not migration authorization. The caller
    /// must authenticate native node intent, executable and legacy program/unit
    /// absence before calling. Intent is durable before the original identity;
    /// an interrupted intent-only install can recover only with identical bytes.
    /// Existing original identities without native intent are never adopted.
    pub fn acquire_native(
        directory: &'a Directory,
        manifest: &super::native::Manifest,
    ) -> Result<Self> {
        let bytes = manifest.bytes()?;
        Self::acquire_with_initialization(directory, &manifest.spec, Some(&bytes))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.cache.acquire")
    )]
    fn acquire_with_initialization(
        directory: &'a Directory,
        spec: &LightwalletInstallSpec,
        initialization: Option<&[u8]>,
    ) -> Result<Self> {
        spec.validate()?;
        let service = render_service(&spec.host, &spec.service)?;
        let cache: Value = serde_json::from_str(&service.cache_identity_json)?;
        let identity = encoded(json!({
            "apiVersion": INSTALL_API_VERSION,
            "installSha256": hash(&serde_json::to_vec(spec)?),
            "serviceSha256": service.service_sha256,
            "cacheIdentity": cache,
        }))?;
        let cache_identity = encoded(cache)?;
        let format_intent = encoded(json!({
            "apiVersion": "zdn-lightwallet-format/v1alpha1",
            "identity": serde_json::from_slice::<Value>(&identity)?,
            "newVolume": spec.new_volume,
        }))?;
        let lock = directory.lock("install.lock")?;
        if let Some(manifest) = initialization {
            match directory.read("identity.json", identity.len() as u64) {
                Ok(existing) => {
                    ensure!(existing == identity, "lightwallet cache record differs");
                    require_record(directory, "native-install-intent.json", manifest)?;
                }
                Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {}
                Err(error) => return Err(error),
            }
            directory.publish("native-install-intent.json", manifest, 0o600)?;
        }
        directory.publish("identity.json", &identity, 0o600)?;
        Ok(Self {
            directory,
            _lock: lock,
            identity,
            cache_identity,
            format_intent,
        })
    }

    /// Bind every authenticated install field before preparation has effects.
    fn verify_spec(&self, spec: &LightwalletInstallSpec) -> Result<()> {
        spec.validate()?;
        let identity: Value = serde_json::from_slice(&self.identity)?;
        ensure!(
            identity["installSha256"] == hash(&serde_json::to_vec(spec)?),
            "cache installation spec differs"
        );
        require_record(self.directory, "identity.json", &self.identity)
    }

    /// Original cache claim bytes, including its dedicated volume and service
    /// identities. This is data, not mounted-volume evidence.
    pub fn cache_identity(&self) -> &[u8] {
        &self.cache_identity
    }

    /// Persist intent only AFTER fresh device/signature/size/provenance/unused
    /// checks and BEFORE mkfs. Even an identical existing intent is uncertain:
    /// it may have reached formatting, so it cannot authorize another format.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.cache.begin_format")
    )]
    pub fn begin_format(&mut self) -> Result<()> {
        self.directory.require_absent("volume-claimed.json")?;
        self.directory.require_absent("format-intent.json")?;
        require_record(self.directory, "identity.json", &self.identity)?;
        self.directory
            .publish("format-intent.json", &self.format_intent, 0o600)
    }

    /// Allows recovery toward claiming an already formatted filesystem, never
    /// another format. Binds the complete installation and creation provenance.
    pub fn verify_format_intent(&self) -> Result<()> {
        require_record(self.directory, "format-intent.json", &self.format_intent)
    }

    /// Verify a claim or complete first-install claiming after fresh mount
    /// verification. Unclaimed filesystems need exact prior formatting intent
    /// and no entries except an empty, real `lost+found`. Restarts cannot adopt
    /// them. A directory descriptor by itself is NOT proof of a cache mount.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.cache.claim_mounted")
    )]
    pub fn claim_mounted(&self, mounted: &Directory, allow_create: bool) -> Result<()> {
        match mounted.read(CLAIM, self.cache_identity.len() as u64) {
            Ok(identity) => ensure!(
                identity == self.cache_identity,
                "cache volume record differs"
            ),
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {
                ensure!(allow_create, "cache has no saved ownership identity");
                self.verify_format_intent()?;
                for entry in mounted.entries()? {
                    ensure!(
                        entry?.file_name() == "lost+found",
                        "unclaimed cache contains data"
                    );
                    let lost_found = mounted.open_directory("lost+found")?;
                    ensure!(
                        lost_found.entries()?.next().transpose()?.is_none(),
                        "unclaimed cache contains data"
                    );
                }
                require_record(self.directory, "identity.json", &self.identity)?;
                mounted.publish(CLAIM, &self.cache_identity, 0o600)?;
            }
            Err(error) => return Err(error),
        }
        self.record_volume_claim(mounted)
    }

    /// Root-disk acknowledgement is published only after verifying the
    /// on-volume claim. Reopen `mounted` after any intentional mount change.
    pub fn record_volume_claim(&self, mounted: &Directory) -> Result<()> {
        require_record(mounted, CLAIM, &self.cache_identity)?;
        self.directory
            .publish("volume-claimed.json", &self.cache_identity, 0o600)
    }
}

fn require_record(directory: &Directory, name: &str, expected: &[u8]) -> Result<()> {
    ensure!(
        directory.read(name, expected.len() as u64)? == expected,
        "lightwallet cache record differs"
    );
    Ok(())
}

fn encoded(value: Value) -> Result<Vec<u8>> {
    // Locked serde_json sorted maps match Python's compact sort_keys encoding
    // for these validated ASCII identities, including the final newline.
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
