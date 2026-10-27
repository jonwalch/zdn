//! Offline controller handoffs. A hash pin is integrity, not cloud authority.
use crate::{
    devnet::{self, Artifact},
    foundation::Deployment,
    state::{BindingExport, OperationReceipt, PhaseStatus},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

pub mod export;
pub mod import;

pub const API_VERSION: &str = "zdn-deployment-handoff/v1alpha1";
pub const MANIFEST_NAME: &str = "handoff.json";
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARCHIVE_BYTES: u64 = 768 * 1024 * 1024;

/// The tar contains this manifest and exactly its inventoried regular files.
/// Deployment and operation receipts are data, never permission to execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: String,
    pub binding: BindingExport,
    pub deployment: Deployment,
    pub operations: Vec<OperationReceipt>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub updates: BTreeMap<Uuid, crate::update::UpdateIntent>,
    pub files: BTreeMap<String, Artifact>,
}

impl Manifest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "handoff.manifest.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported deployment handoff version"
        );
        self.binding.validate()?;
        let deployment = &self.deployment;
        deployment.validate()?;
        ensure!(
            self.binding.network_id == deployment.spec.network_id
                && self.binding.scope == deployment.spec.scope,
            "handoff deployment identity differs from its binding"
        );
        ensure!(
            !deployment.destroyed && deployment.cleanup.is_none(),
            "destroyed or cleanup deployments cannot be handed off"
        );
        ensure!(
            deployment.unresolved_operation.is_none(),
            "reconcile unresolved operations before handoff"
        );
        if deployment.cluster.is_none() {
            crate::build::preparation::initial_shape(deployment)?;
            ensure!(
                self.operations.is_empty() && self.updates.is_empty(),
                "initial preparation cannot contain operation or update history"
            );
            self.require(crate::build::preparation::RECORD)?;
            self.require("build/attempt.json")?;
            ensure!(
                self.files.len() <= 16,
                "source preparation inventory exceeds its bound"
            );
            for (path, artifact) in &self.files {
                devnet::validate_hash(&artifact.sha256)?;
                ensure!(
                    artifact.bytes <= self.file_limit(path)?,
                    "source preparation file exceeds bound"
                );
            }
            return Ok(());
        }
        self.validate_updates()?;
        let request = deployment
            .cluster
            .as_ref()
            .context("handoff requires a staged node request; incomplete builds are unsupported")?;
        let mut ids = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            ensure!(
                operation.network_id == self.binding.network_id
                    && operation.scope == self.binding.scope,
                "handoff operation belongs to another deployment"
            );
            ensure!(
                ids.insert(operation.operation_id),
                "duplicate handoff operation ID"
            );
        }
        if let Some(id) = deployment.last_operation {
            let operation = self
                .operations
                .iter()
                .find(|op| op.operation_id == id)
                .context("missing last operation evidence")?;
            let completed = matches!(operation.kind.as_str(), "devnet-up" | "devnet-update")
                && !deployment.runtime.as_ref().is_some_and(|r| r.pending())
                && operation
                    .phases
                    .iter()
                    .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. }));
            let interrupted = deployment
                .runtime
                .as_ref()
                .and_then(|r| r.update.as_ref())
                .filter(|u| !u.finished)
                .is_some_and(|intent| {
                    operation.kind == "devnet-update"
                        && operation.phases.len() == 1
                        && operation.phases[0].name == "update"
                        && matches!(&operation.phases[0].status,
                            PhaseStatus::Running { external_ref: Some(id) }
                            | PhaseStatus::Unknown { external_ref: Some(id), .. }
                            if id == &intent.id.to_string())
                });
            ensure!(!operation.cancel_requested && (completed || interrupted),
                "handoff requires a completed operation or an identified interrupted update with validated command histories");
            ensure!(
                deployment.stack_initialized && deployment.outputs.is_some(),
                "completed deployment is missing stack outputs"
            );
        } else {
            ensure!(
                !deployment.stack_initialized
                    && deployment.outputs.is_none()
                    && self.operations.is_empty(),
                "staged deployment has unaccounted operation effects"
            );
            ensure!(
                self.files.keys().all(|path| path.starts_with("artifacts/")),
                "unlaunched handoff cannot contain runtime recovery evidence"
            );
        }
        ensure!(
            self.files.len() <= 1024,
            "handoff inventory exceeds its file bound"
        );
        for (path, artifact) in &self.files {
            devnet::validate_hash(&artifact.sha256)?;
            ensure!(
                artifact.bytes <= self.file_limit(path)?,
                "handoff file exceeds its size bound"
            );
        }
        for (name, artifact) in &request.artifacts {
            let saved = self
                .files
                .get(&format!("artifacts/{name}"))
                .context("handoff is missing a staged artifact")?;
            ensure!(
                saved.sha256 == artifact.sha256 && saved.bytes == artifact.bytes,
                "handoff artifact inventory differs from saved request"
            );
        }
        if let Some(outputs) = &deployment.outputs {
            for node in outputs.nodes.keys() {
                self.require(&format!("{node}-install.sh"))?;
                self.require(&format!("{node}-install-command.json"))?;
            }
            if request.block_interval_seconds.is_some() {
                self.require("node-1-start-producer-command.json")?;
            }
            if request.lightwallet.is_some() {
                for name in [
                    "lightwallet-install.sh",
                    "lightwallet-install-command.json",
                    "lightwallet-capacity.json",
                    "lightwallet-capacity-command.json",
                ] {
                    self.require(name)?;
                }
            }
            if request.client_access {
                self.require("client-rpc-install.sh")?;
                self.require("client-rpc-install-command.json")?;
            }
        }
        for stem in self.stems()? {
            if stem == "client-rpc" {
                continue;
            }
            let receipt = self.files.contains_key(&format!("{stem}-new-volume.json"));
            let checkpoint = self
                .files
                .contains_key(&format!("{stem}-new-volume-checkpoint.json"));
            ensure!(
                receipt == checkpoint
                    && (!receipt || self.files.contains_key("new-volume-creation.json")),
                "incomplete new-volume proof chain in handoff"
            );
            ensure!(
                deployment.outputs.is_none()
                    || !self.files.contains_key("new-volume-creation.json")
                    || receipt,
                "handoff is missing a completed new-volume authorization"
            );
        }
        Ok(())
    }

    fn require(&self, path: &str) -> Result<()> {
        ensure!(
            self.files.contains_key(path),
            "handoff is missing required recovery evidence: {path}"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "handoff.manifest.validate_updates")
    )]
    fn validate_updates(&self) -> Result<()> {
        crate::update::validate_handoff_history(&self.deployment, &self.updates)?;
        for (id, intent) in &self.updates {
            let revision = intent
                .revision
                .as_ref()
                .context("update lacks candidate revision")?;
            if intent.finished {
                self.require(&format!("updates/{id}/completed.json"))?;
            }
            if intent.build_exporter_protocol.is_some() {
                for name in [
                    "attempt.json",
                    "result.json",
                    "image.json",
                    "image-manifest.json",
                    "image-config.json",
                ] {
                    self.require(&format!("updates/{id}/build/{name}"))?;
                }
            }
            for (name, artifact) in &revision.artifacts {
                let saved = self
                    .files
                    .get(&format!("updates/{id}/artifacts/{name}"))
                    .context("missing update image artifact")?;
                ensure!(
                    saved.sha256 == artifact.sha256 && saved.bytes == artifact.bytes,
                    "update artifact inventory mismatch"
                );
            }
            for node in intent.targets.keys() {
                self.require(&format!("updates/{id}/{node}-update.sh"))?;
                self.require(&format!("updates/{id}/{node}-command.json"))?;
            }
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "handoff.manifest.stems")
    )]
    fn stems(&self) -> Result<Vec<String>> {
        let request = self
            .deployment
            .cluster
            .as_ref()
            .context("missing node request")?;
        let mut stems: Vec<_> = request
            .topology()?
            .nodes()
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        if request.lightwallet.is_some() {
            stems.push("lightwallet".into());
        }
        if request.client_access {
            stems.push("client-rpc".into());
        }
        Ok(stems)
    }

    /// A closed inventory vocabulary, not an archive path sanitizer. Unknown
    /// recovery files must be supported deliberately rather than silently lost.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "handoff.manifest.file_limit")
    )]
    pub fn file_limit(&self, path: &str) -> Result<u64> {
        if self.deployment.cluster.is_none() {
            return crate::build::preparation::file_limit(path);
        }
        if let Some(rest) = path.strip_prefix("updates/") {
            let (id, name) = rest
                .split_once('/')
                .context("invalid update payload path")?;
            let uuid = Uuid::parse_str(id)?;
            ensure!(uuid.to_string() == id, "noncanonical update UUID");
            let intent = self.updates.get(&uuid).context("unknown update payload")?;
            if intent.build_exporter_protocol.is_some() {
                match name {
                    "build/attempt.json" => return Ok(65536),
                    "build/result.json" | "build/image.json" => {
                        return Ok(crate::image::MAX_RECORD_BYTES as u64)
                    }
                    "build/image-manifest.json" => {
                        return Ok(crate::image::MAX_MANIFEST_BYTES as u64)
                    }
                    "build/image-config.json" => return Ok(crate::image::MAX_CONFIG_BYTES as u64),
                    _ => {}
                }
            }
            if name == "completed.json" {
                ensure!(
                    intent.completed.len() == intent.targets.len(),
                    "completion metadata requires every target to be confirmed"
                );
                return Ok(MAX_MANIFEST_BYTES);
            }
            if let Some(artifact) = name.strip_prefix("artifacts/") {
                return intent
                    .revision
                    .as_ref()
                    .context("missing update revision")?
                    .artifacts
                    .get(artifact)
                    .map(|a| a.bytes)
                    .context("unknown update artifact");
            }
            for node in intent.targets.keys() {
                if name == format!("{node}-update.sh") {
                    return Ok(32 * 1024 * 1024);
                }
                if name == format!("{node}-command.json") {
                    return Ok(128 * 1024);
                }
            }
            eyre::bail!("unsupported update recovery file: {path}");
        }
        let request = self
            .deployment
            .cluster
            .as_ref()
            .context("missing node request")?;
        if let Some(name) = path.strip_prefix("artifacts/") {
            return request
                .artifacts
                .get(name)
                .map(|a| a.bytes)
                .context("unknown handoff artifact");
        }
        if matches!(
            path,
            "new-volume-creation.json"
                | "cleanup-volume-identities.json"
                | "stale-address-recovery.json"
                | "client-endpoints.json"
        ) {
            return Ok(16 * 1024 * 1024);
        }
        if path == "lightwallet-capacity.json" && request.lightwallet.is_some() {
            return Ok(128 * 1024);
        }
        for stem in self.stems()? {
            if path == format!("{stem}-install.sh") {
                return Ok(32 * 1024 * 1024);
            }
            if stem != "client-rpc"
                && (path == format!("{stem}-new-volume.json")
                    || path == format!("{stem}-new-volume-checkpoint.json"))
            {
                return Ok(16 * 1024 * 1024);
            }
            if path == format!("{stem}-install-command.json")
                || (stem == "node-1"
                    && request.block_interval_seconds.is_some()
                    && path == "node-1-start-producer-command.json")
                || (stem == "lightwallet"
                    && matches!(
                        path,
                        "lightwallet-capacity-command.json" | "lightwallet-start-command.json"
                    ))
            {
                return Ok(128 * 1024);
            }
            if let Some(id) = path
                .strip_prefix(&format!("{stem}-observe-"))
                .and_then(|s| s.strip_suffix(".json"))
            {
                if Uuid::parse_str(id)
                    .is_ok_and(|uuid| uuid.get_version_num() == 4 && uuid.to_string() == id)
                {
                    return Ok(128 * 1024);
                }
            }
        }
        eyre::bail!("unsupported handoff recovery file: {path}")
    }

    /// Revalidate materialized data before either exporting or publishing it.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "handoff.manifest.verify_directory")
    )]
    pub fn verify_directory(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        for (path, artifact) in &self.files {
            ensure!(
                devnet::hash_file(&directory.join(path), self.file_limit(path)?)? == *artifact,
                "handoff payload integrity mismatch"
            );
        }
        if self.deployment.cluster.is_none() {
            let preparation = crate::build::preparation::Preparation::read(directory)?;
            preparation.verify(directory, &self.deployment)?;
            let observation = crate::build_job::validate_preparation(
                &directory.join("build"),
                &self.deployment.team,
                &preparation.contract,
            )?;
            if let Some(helper) = &observation.exporter_helper {
                ensure!(
                    self.files.get("build/exporter") == Some(helper)
                        && preparation.files.get("source-preparation/zdn") == Some(helper),
                    "handoff exporter differs from the prepared helper"
                );
            }
            ensure!(
                self.files.len()
                    == preparation.files.len()
                        + 2
                        + usize::from(observation.exporter_helper.is_some())
                    && preparation
                        .files
                        .iter()
                        .all(|(path, artifact)| self.files.get(path) == Some(artifact)),
                "handoff inventory differs from source preparation"
            );
            return Ok(());
        }
        self.deployment
            .cluster
            .as_ref()
            .context("missing node request")?
            .verify_local(directory)?;
        for (id, intent) in self
            .updates
            .iter()
            .filter(|(_, intent)| intent.build_exporter_protocol.is_some())
        {
            let revision = intent
                .revision
                .as_ref()
                .context("native update candidate missing")?;
            let mut request = self
                .deployment
                .cluster
                .as_ref()
                .context("missing node request")?
                .clone();
            request.image = revision.image.clone();
            request.build = revision.build.clone();
            request.artifacts = revision.artifacts.clone();
            let build = directory.join(format!("updates/{id}/build"));
            let _lock =
                crate::build_job::validate_handoff(&build, &self.deployment.team, &request)?
                    .context("native update build receipt missing")?;
            ensure!(
                crate::build_job::validate_preparation(
                    &build,
                    &self.deployment.team,
                    request
                        .build
                        .as_ref()
                        .context("native update contract missing")?
                )?
                .exporter_helper
                .is_some(),
                "native update exporter selection missing"
            );
            crate::build_job::removal_evidence(&build, &self.deployment.team)?;
        }
        for (id, intent) in self.updates.iter().filter(|(id, intent)| {
            intent.finished
                || self
                    .files
                    .contains_key(&format!("updates/{id}/completed.json"))
        }) {
            let saved: crate::update::UpdateIntent =
                serde_json::from_slice(&devnet::read_bounded(
                    &directory.join(format!("updates/{id}/completed.json")),
                    MAX_MANIFEST_BYTES,
                )?)?;
            let mut expected = intent.clone();
            expected.finished = true;
            ensure!(
                serde_json::to_value(saved)? == serde_json::to_value(expected)?,
                "completed update payload differs from manifest"
            );
        }
        crate::foundation_live::validate_handoff(&self.deployment, directory, &self.updates)?;
        self.deployment.render()?;
        Ok(())
    }
}

/// Sync children before their parents so nested update evidence is durable.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.sync_directories")
)]
fn sync_directories(directory: &Path) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = std::fs::symlink_metadata(entry.path())?.file_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "handoff refuses links and special files"
        );
        if kind.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}
