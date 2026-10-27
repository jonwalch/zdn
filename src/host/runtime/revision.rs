//! Records only, never execution authority. Callers establish trusted ancestors,
//! original native-install intent, live mount identity, staging verification and
//! readiness/producer authorization separately. No Python dispatcher state is used.
//! One state file couples phase, selection and maintenance; immutable request
//! receipts follow transaction publication. Hold is durable before stopping.
//! No interrupted phase rolls back.

use eyre::{ensure, Result};
#[cfg(target_os = "linux")]
use nix::errno::Errno;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use super::Manifest;
use crate::host::S3Object;
#[cfg(target_os = "linux")]
use crate::host::{files::Directory, volume::Installation};
use crate::image::ImageRecord;

pub const API_VERSION: &str = "zdn-native-image-update/v1alpha1";
pub const EXECUTION_PROTOCOL: &str = "zdn-native-image-update-execution/v1alpha1";
pub const NAMESPACE: &str = "native-updates";
pub const MAX_REQUEST_BYTES: u64 = super::MAX_MANIFEST_BYTES + 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_STATE_BYTES: u64 = 2 * MAX_REQUEST_BYTES + 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub api_version: String,
    pub original: Manifest,
    pub update_id: Uuid,
    pub expected_image: String,
    pub expected_update_id: Option<Uuid>,
    pub image: ImageRecord,
    pub image_record: S3Object,
    pub image_manifest: S3Object,
    pub image_config: S3Object,
}

fn uuid4(id: Uuid) -> Result<()> {
    ensure!(
        id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
        "native update requires UUIDv4"
    );
    Ok(())
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported native update version"
        );
        self.original.bytes()?;
        uuid4(self.update_id)?;
        if let Some(id) = self.expected_update_id {
            uuid4(id)?;
            ensure!(id != self.update_id, "self-referencing native update");
        }
        self.image.validate()?;
        let mut spec = self.original.spec.clone();
        spec.image = self.expected_image.clone();
        spec.validate()?;
        spec.image = self.image.image.clone();
        spec.validate()?;
        let scope = &self.original.spec.helper;
        for (object, max) in [
            (&self.image_record, crate::image::MAX_RECORD_BYTES),
            (&self.image_manifest, crate::image::MAX_MANIFEST_BYTES),
            (&self.image_config, crate::image::MAX_CONFIG_BYTES),
        ] {
            object.validate()?;
            ensure!(
                object.bytes <= max as u64,
                "native image artifact exceeds parser bound"
            );
            ensure!(
                object.bucket == scope.bucket
                    && object.region == scope.region
                    && object.owner_account == scope.owner_account,
                "foreign native image artifact scope"
            );
        }
        ensure!(
            self.image_manifest.sha256
                == self
                    .image
                    .image
                    .rsplit_once('@')
                    .unwrap()
                    .1
                    .trim_start_matches("sha256:")
                && self.image_config.sha256
                    == self.image.config_digest.trim_start_matches("sha256:"),
            "native image digest pins differ"
        );
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = encoded(self)?;
        ensure!(
            bytes.len() as u64 <= MAX_REQUEST_BYTES,
            "native request exceeds bound"
        );
        Ok(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let request: Self = canonical(bytes, MAX_REQUEST_BYTES)?;
        ensure!(request.bytes()? == bytes, "noncanonical native request");
        Ok(request)
    }

    /// Deterministic native-only transport for exact saved SSM request binding.
    /// No installer, mutable script, Python program or unpinned helper is run.
    pub fn render(&self) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = self.bytes()?;
        let executable = format!(
            "/etc/zdn/runtime/{}/zdn",
            self.original.runtime.helper.sha256
        );
        let manifest = format!("/etc/zdn/runtime/manifests/{}", self.original.file_name()?);
        Ok(format!(
            "#!/bin/bash\nset -euo pipefail\numask 077\n{executable} __runtime-capabilities --require {EXECUTION_PROTOCOL} >/dev/null\nbase64 --decode <<'ZDN_NATIVE_UPDATE' | {executable} __host-update --protocol {EXECUTION_PROTOCOL} --manifest {manifest}\n{}\nZDN_NATIVE_UPDATE\n",
            STANDARD.encode(bytes)
        ))
    }

    #[cfg(target_os = "linux")]
    fn receipt(&self) -> String {
        format!("{}.json", self.update_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Staging,
    Stopping,
    Activating,
    Ready,
    Done,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transaction {
    pub request: Request,
    pub phase: Phase,
}

/// Read-only observation, including uncertain transaction-before-receipt prefixes.
/// A missing receipt is valid ONLY in staging, never permission to execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub api_version: String,
    pub active: Option<Request>,
    pub transaction: Option<Transaction>,
    pub producer_hold: bool,
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8], max: u64) -> Result<T> {
    ensure!(bytes.len() as u64 <= max, "native journal exceeds bound");
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(encoded(&value)? == bytes, "noncanonical native journal");
    Ok(value)
}

#[cfg(target_os = "linux")]
fn optional(directory: &Directory, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
    match directory.regular(name, max) {
        Ok(file) => {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            ensure!(
                metadata.mode() & 0o7777 == 0o600,
                "unsafe native journal record"
            );
            // Immutable publish uses link+unlink: an interrupted publication
            // may retain its private staging link. Do not reject that exact
            // receipt retry. Mutable replacement independently requires nlink=1.
            Ok(Some(directory.read(name, max)?))
        }
        Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn bound(request: &Request, original: &Manifest) -> Result<()> {
    ensure!(
        request.original.bytes()? == original.bytes()?,
        "native original manifest differs"
    );
    request.validate()
}

#[cfg(target_os = "linux")]
impl Snapshot {
    /// Read-only lookup from trusted installation metadata. Ordinary first
    /// installation/restart does not create an update namespace as a side effect.
    pub fn from_installation(metadata: &Directory, original: &Manifest) -> Result<Option<Self>> {
        original.validate()?;
        match metadata.open_directory(NAMESPACE) {
            Ok(directory) => Self::load(&directory, original).map(Some),
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `directory` is the trusted /etc/zdn/native-updates leaf. No lock is
    /// acquired: producer startup may run while its parent retains install.lock.
    pub fn load(directory: &Directory, original: &Manifest) -> Result<Self> {
        original.validate()?;
        let Some(bytes) = optional(directory, "state.json", MAX_STATE_BYTES)? else {
            return Ok(Self {
                api_version: API_VERSION.into(),
                active: None,
                transaction: None,
                producer_hold: false,
            });
        };
        let state: Self = canonical(&bytes, MAX_STATE_BYTES)?;
        ensure!(
            state.api_version == API_VERSION,
            "unsupported native journal version"
        );
        if let Some(active) = &state.active {
            bound(active, original)?;
            ensure!(
                optional(directory, &active.receipt(), MAX_REQUEST_BYTES)?.as_deref()
                    == Some(active.bytes()?.as_slice()),
                "active native receipt differs"
            );
        }
        let tx = state
            .transaction
            .as_ref()
            .ok_or_else(|| eyre::eyre!("native journal lacks transaction"))?;
        bound(&tx.request, original)?;
        let receipt = optional(directory, &tx.request.receipt(), MAX_REQUEST_BYTES)?;
        ensure!(
            receipt.as_deref() == Some(tx.request.bytes()?.as_slice())
                || (receipt.is_none() && tx.phase == Phase::Staging && !state.producer_hold),
            "native transaction receipt differs"
        );
        let target_active =
            state.active.as_ref().map(Request::bytes).transpose()? == Some(tx.request.bytes()?);
        let old_active = state
            .active
            .as_ref()
            .map(|r| (r.image.image.as_str(), Some(r.update_id)))
            .unwrap_or((&original.spec.image, None));
        let expected = (
            tx.request.expected_image.as_str(),
            tx.request.expected_update_id,
        );
        ensure!(
            match tx.phase {
                Phase::Staging | Phase::Stopping => old_active == expected,
                Phase::Activating => target_active || old_active == expected,
                Phase::Ready | Phase::Done => target_active,
            },
            "native active/transaction disagreement"
        );
        ensure!(
            match tx.phase {
                // Hold-before-stopping is an intentional durable prefix.
                Phase::Staging => true,
                Phase::Stopping | Phase::Activating => state.producer_hold,
                Phase::Ready => true,
                Phase::Done => !state.producer_hold,
            },
            "native maintenance/phase disagreement"
        );
        Ok(state)
    }
}

/// Exclusive mutable borrow retains the original complete-spec installation
/// lock. The caller separately authenticates native intent and mounted storage.
#[cfg(target_os = "linux")]
pub struct Journal<'a, 'i> {
    directory: &'a Directory,
    original: &'a Manifest,
    installation: &'a mut Installation<'i>,
}

#[cfg(target_os = "linux")]
impl<'a, 'i> Journal<'a, 'i> {
    pub fn open(
        directory: &'a Directory,
        original: &'a Manifest,
        installation: &'a mut Installation<'i>,
    ) -> Result<Self> {
        original.validate()?;
        installation.verify_spec(&original.spec)?;
        Snapshot::load(directory, original)?;
        Ok(Self {
            directory,
            original,
            installation,
        })
    }

    fn save(&self, state: &Snapshot) -> Result<()> {
        self.installation.verify_spec(&self.original.spec)?;
        self.directory
            .replace("state.json", &encoded(state)?, MAX_STATE_BYTES)
    }

    /// Transaction first, immutable receipt second. Exact retries finish the
    /// interrupted prefix; completed old UUIDs cannot be replayed after a switch.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.runtime.revision.begin")
    )]
    pub fn begin(&mut self, request: &Request) -> Result<Snapshot> {
        request.bytes()?;
        bound(request, self.original)?;
        let mut state = Snapshot::load(self.directory, self.original)?;
        let prior = optional(self.directory, &request.receipt(), MAX_REQUEST_BYTES)?;
        if let Some(bytes) = &prior {
            ensure!(*bytes == request.bytes()?, "native UUID reused");
        }
        let same = state
            .transaction
            .as_ref()
            .is_some_and(|tx| tx.request.update_id == request.update_id);
        if same {
            ensure!(
                state.transaction.as_ref().unwrap().request.bytes()? == request.bytes()?,
                "native UUID conflict"
            );
        } else {
            ensure!(
                state
                    .transaction
                    .as_ref()
                    .is_none_or(|tx| tx.phase == Phase::Done),
                "another native update is incomplete"
            );
            ensure!(prior.is_none(), "old native update replay");
            let active = state
                .active
                .as_ref()
                .map(|r| (r.image.image.as_str(), Some(r.update_id)))
                .unwrap_or((&self.original.spec.image, None));
            ensure!(
                active == (request.expected_image.as_str(), request.expected_update_id),
                "stale native expected revision"
            );
            state.transaction = Some(Transaction {
                request: request.clone(),
                phase: Phase::Staging,
            });
            self.save(&state)?;
        }
        self.directory
            .publish(&request.receipt(), &request.bytes()?, 0o600)?;
        Snapshot::load(self.directory, self.original)
    }

    /// Finite forward-only phase edges; retries of the current edge are exact.
    /// Staging/stopping completion and readiness are caller attestations, not
    /// observations made here. Hold is durably published before the stopping
    /// phase, before any caller may stop a producer. A staging+hold prefix is
    /// uncertain maintenance and must never implicitly release the hold.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.runtime.revision.advance")
    )]
    pub fn advance(&mut self, id: Uuid, phase: Phase) -> Result<Snapshot> {
        let mut state = Snapshot::load(self.directory, self.original)?;
        let tx = state
            .transaction
            .as_mut()
            .ok_or_else(|| eyre::eyre!("no native transaction"))?;
        ensure!(tx.request.update_id == id, "foreign native transaction");
        ensure!(
            optional(self.directory, &tx.request.receipt(), MAX_REQUEST_BYTES)?.is_some(),
            "native receipt missing; retry begin"
        );
        if tx.phase != phase {
            ensure!(
                matches!(
                    (tx.phase, phase),
                    (Phase::Staging, Phase::Stopping)
                        | (Phase::Stopping, Phase::Activating)
                        | (Phase::Activating, Phase::Ready)
                        | (Phase::Ready, Phase::Done)
                ),
                "invalid native phase edge"
            );
            if matches!(phase, Phase::Ready | Phase::Done) {
                ensure!(
                    state.active.as_ref().map(Request::bytes).transpose()?
                        == Some(tx.request.bytes()?),
                    "target is not active"
                );
            }
            if phase == Phase::Stopping {
                state.producer_hold = true;
                self.save(&state)?;
            }
            if phase == Phase::Done {
                ensure!(!state.producer_hold, "native maintenance remains held");
            }
            state.transaction.as_mut().unwrap().phase = phase;
        }
        // Re-acknowledge durability on exact retries too.
        self.save(&state)?;
        Snapshot::load(self.directory, self.original)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.runtime.revision.publish_active")
    )]
    pub fn publish_active(&mut self, id: Uuid) -> Result<Snapshot> {
        let mut state = Snapshot::load(self.directory, self.original)?;
        let tx = state
            .transaction
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no native transaction"))?;
        ensure!(
            tx.request.update_id == id && tx.phase == Phase::Activating,
            "active publication requires activating"
        );
        state.active = Some(tx.request.clone());
        self.save(&state)?;
        Snapshot::load(self.directory, self.original)
    }

    /// Re-hold after an interrupted/failed producer release. This never regresses
    /// a phase or reopens a completed transaction; exact ready retries are safe.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.runtime.revision.hold_maintenance")
    )]
    pub fn hold_maintenance(&mut self, id: Uuid) -> Result<Snapshot> {
        let mut state = Snapshot::load(self.directory, self.original)?;
        let tx = state
            .transaction
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no native transaction"))?;
        ensure!(
            tx.request.update_id == id && tx.phase == Phase::Ready,
            "maintenance recovery requires ready"
        );
        state.producer_hold = true;
        self.save(&state)?;
        Snapshot::load(self.directory, self.original)
    }

    /// Caller must first perform fresh trusted readiness AND original producer
    /// authorization checks. This releases maintenance, not producer authority.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.runtime.revision.release_maintenance")
    )]
    pub fn release_maintenance(&mut self, id: Uuid) -> Result<Snapshot> {
        let mut state = Snapshot::load(self.directory, self.original)?;
        let tx = state
            .transaction
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no native transaction"))?;
        ensure!(
            tx.request.update_id == id && tx.phase == Phase::Ready,
            "maintenance release requires ready"
        );
        state.producer_hold = false;
        self.save(&state)?;
        Snapshot::load(self.directory, self.original)
    }
}
