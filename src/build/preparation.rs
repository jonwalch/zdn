//! Portable initial-source inputs. This is not a launchable node request.
use crate::{build::BuildContract, config::Config, devnet, foundation::Deployment};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

pub const RECORD: &str = "source-preparation.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preparation {
    pub schema_version: u32,
    pub deployment_sha256: String,
    pub config: Config,
    pub contract: BuildContract,
    pub reward_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer_fetch_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_runtime_protocol: Option<String>,
    pub files: BTreeMap<String, devnet::Artifact>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build.preparation.initial_shape")
)]
pub fn initial_shape(deployment: &Deployment) -> Result<()> {
    deployment.validate()?;
    ensure!(
        deployment.foundation_runtime.is_none()
            && deployment.cluster.is_none()
            && deployment.runtime.is_none()
            && !deployment.stack_initialized
            && deployment.outputs.is_none()
            && deployment.last_operation.is_none()
            && deployment.unresolved_operation.is_none()
            && !deployment.destroyed
            && deployment.cleanup.is_none(),
        "source preparation requires an untouched initial deployment"
    );
    Ok(())
}

fn binding(deployment: &Deployment) -> Result<String> {
    Ok(devnet::sha256(&serde_json::to_vec(&(
        &deployment.spec,
        &deployment.team,
        deployment.owner_id,
    ))?))
}

/// The vocabulary is closed even before the record has been decoded.
pub fn file_limit(path: &str) -> Result<u64> {
    Ok(match path {
        RECORD | "source-snapshot/receipt.json" => 16 * 1024 * 1024,
        "source-build-inputs.json" | "build/attempt.json" => 65536,
        "source-snapshot/source.tar" => crate::build::MAX_SOURCE_BYTES,
        "source-preparation/manifest.json" => 2 * 1024 * 1024,
        "source-preparation/chain.tar" => 256 * 1024 * 1024,
        "source-preparation/zdn" | "build/exporter" => devnet::MAX_HELPER_BYTES,
        "source-preparation/lightwallet-image.json" => crate::image::MAX_RECORD_BYTES as u64,
        "source-preparation/lightwallet-image-manifest.json" => {
            crate::image::MAX_MANIFEST_BYTES as u64
        }
        "source-preparation/lightwallet-image-config.json" => crate::image::MAX_CONFIG_BYTES as u64,
        _ => eyre::bail!("unsupported source preparation payload: {path}"),
    })
}

impl Preparation {
    /// Save all caller-owned bytes before any build submission. Existing records
    /// are immutable; a missing receipt never authorizes a replacement capture.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.preparation.save")
    )]
    pub fn save(
        config: &Config,
        deployment: &Deployment,
        contract: &BuildContract,
        reward_address: &str,
        native_runtime: bool,
        sources: &BTreeMap<String, std::path::PathBuf>,
        directory: &Path,
    ) -> Result<Self> {
        initial_shape(deployment)?;
        let saved = directory
            .join(RECORD)
            .try_exists()?
            .then(|| Self::read(directory))
            .transpose()?;
        let mut value = Self {
            schema_version: 1,
            deployment_sha256: binding(deployment)?,
            config: config.clone(),
            contract: contract.clone(),
            reward_address: reward_address.into(),
            native_runtime_protocol: devnet::select_native_runtime(
                saved.as_ref().map(|s| s.native_runtime_protocol.as_deref()),
                native_runtime,
            )?,
            capacity_protocol: match &saved {
                Some(saved) => saved.capacity_protocol.clone(),
                None if config.services.lightwallet => Some(crate::host::CAPACITY_PROTOCOL.into()),
                _ => None,
            },
            installer_fetch_protocol: match &saved {
                Some(saved) => saved.installer_fetch_protocol.clone(),
                None => Some(crate::host::installer_bootstrap::PROTOCOL.into()),
            },
            files: BTreeMap::new(),
        };
        let staging = tempfile::tempdir()?;
        for path in value.required_files() {
            let source = sources
                .get(path)
                .map_or_else(|| directory.join(path), Clone::clone);
            let target = staging.path().join(path);
            crate::foundation::private_directory(
                target.parent().context("missing payload parent")?,
            )?;
            value.files.insert(
                path.into(),
                devnet::snapshot_file(&source, &target, file_limit(path)?)?,
            );
        }
        // Semantic checks use exactly the private bytes whose digests we recorded,
        // never a second read of mutable caller-owned paths.
        value.verify(staging.path(), deployment)?;
        if let Some(saved) = saved {
            ensure!(
                serde_json::to_value(&saved)? == serde_json::to_value(&value)?,
                "source preparation inputs changed; use the saved preparation"
            );
            saved.verify(directory, deployment)?;
            ensure!(
                std::fs::symlink_metadata(directory.join("build"))?.is_dir()
                    && std::fs::symlink_metadata(directory.join("build/attempt.json"))?.is_file(),
                "saved preparation lost its build receipt; refusing a new attempt"
            );
            return Ok(saved);
        }
        ensure!(
            !directory.join("build").try_exists()?
                && !directory.join("source-preparation").try_exists()?,
            "build or preparation payloads exist without source preparation; refusing reconstruction"
        );
        crate::foundation::private_directory(&directory.join("source-preparation"))?;
        for (path, artifact) in &value.files {
            devnet::publish_snapshot(&staging.path().join(path), &directory.join(path), artifact)?;
        }
        value.verify(directory, deployment)?;
        // Publish the complete record only after its original attempt exists.
        crate::build_job::prepare_native(
            &directory.join("build"),
            &deployment.team,
            contract,
            &directory.join("source-preparation/zdn"),
        )?;
        crate::foundation::write_json(&directory.join(RECORD), &value)?;
        Ok(value)
    }

    pub fn read(directory: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&devnet::read_bounded(
            &directory.join(RECORD),
            file_limit(RECORD)?,
        )?)?)
    }

    fn required_files(&self) -> Vec<&'static str> {
        let mut paths = vec![
            "source-snapshot/receipt.json",
            "source-snapshot/source.tar",
            "source-build-inputs.json",
            "source-preparation/manifest.json",
            "source-preparation/chain.tar",
            "source-preparation/zdn",
        ];
        if self.config.services.lightwallet {
            paths.extend([
                "source-preparation/lightwallet-image.json",
                "source-preparation/lightwallet-image-manifest.json",
                "source-preparation/lightwallet-image-config.json",
            ]);
        }
        paths
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.preparation.verify")
    )]
    pub fn verify(&self, directory: &Path, deployment: &Deployment) -> Result<()> {
        initial_shape(deployment)?;
        for name in ["source-snapshot", "source-preparation"] {
            ensure!(
                std::fs::symlink_metadata(directory.join(name))?.is_dir(),
                "source preparation directory must be real"
            );
        }
        self.config.validate()?;
        devnet::require_supported_services(&self.config)?;
        devnet::validate_native_runtime(
            self.native_runtime_protocol.as_deref(),
            self.config
                .services
                .lightwallet
                .then_some(self.capacity_protocol.as_deref()),
            self.installer_fetch_protocol.as_deref(),
        )?;
        ensure!(
            self.capacity_protocol.as_deref().is_none_or(
                |p| self.config.services.lightwallet && p == crate::host::CAPACITY_PROTOCOL
            ),
            "unsupported source-preparation capacity protocol"
        );
        ensure!(
            self.installer_fetch_protocol
                .as_deref()
                .is_none_or(crate::host::installer_bootstrap::supports),
            "unsupported source-preparation installer-fetch protocol"
        );
        ensure!(
            self.schema_version == 1 && self.deployment_sha256 == binding(deployment)?,
            "source preparation deployment binding mismatch"
        );
        ensure!(
            self.config.node.source.image.is_none()
                && self.config.node.resources.preset == deployment.spec.size
                && self.config.access.visibility == crate::config::Visibility::Private,
            "source preparation configuration mismatch"
        );
        let required = self.required_files();
        ensure!(
            self.files.len() == required.len()
                && required.iter().all(|p| self.files.contains_key(*p)),
            "incomplete source preparation inventory"
        );
        for (path, expected) in &self.files {
            ensure!(
                devnet::hash_file(&directory.join(path), file_limit(path)?)? == *expected,
                "source preparation payload mismatch: {path}"
            );
        }
        let receipt_bytes = devnet::read_bounded(
            &directory.join("source-snapshot/receipt.json"),
            file_limit("source-snapshot/receipt.json")?,
        )?;
        let receipt: crate::source::SnapshotReceipt = serde_json::from_slice(&receipt_bytes)?;
        ensure!(
            matches!(
                (self.config.node.source.snapshot, receipt.mode),
                (
                    None | Some(crate::config::SnapshotMode::Worktree),
                    crate::source::SnapshotMode::Worktree
                ) | (
                    Some(crate::config::SnapshotMode::Revision),
                    crate::source::SnapshotMode::Revision
                )
            ),
            "source preparation snapshot mode mismatch"
        );
        let expected = BuildContract::new(
            &receipt,
            self.config
                .node
                .build
                .as_ref()
                .context("missing source build settings")?,
        )?;
        ensure!(
            expected == self.contract,
            "source preparation build contract mismatch"
        );
        self.contract
            .verify_archive(&directory.join("source-snapshot/source.tar"))?;
        let inputs: crate::state::OperationInput = serde_json::from_slice(&devnet::read_bounded(
            &directory.join("source-build-inputs.json"),
            65536,
        )?)?;
        inputs.validate()?;
        ensure!(
            inputs.config_sha256 == self.config.fingerprint()?
                && inputs.source_manifest_sha256.as_deref()
                    == Some(devnet::sha256(&receipt_bytes).as_str())
                && inputs.archive_sha256.as_deref() == Some(self.contract.source_sha256.as_str()),
            "source preparation input binding mismatch"
        );
        let manifest = devnet::validate_chain_inputs(
            &self.config,
            &devnet::read_bounded(
                &directory.join("source-preparation/manifest.json"),
                2 * 1024 * 1024,
            )?,
            &directory.join("source-preparation/chain.tar"),
        )?;
        devnet::validate_helper_file(&directory.join("source-preparation/zdn"))?;
        let mut options =
            crate::chain::runtime_config::RuntimeOptions::new(deployment.spec.network_id, "node-1");
        options.role = crate::chain::runtime_config::NodeRole::Producer;
        options.reward_address = Some(self.reward_address.clone());
        crate::chain::runtime_config::render_runtime_config(&manifest, &options)?;
        if self.config.services.lightwallet {
            let record = crate::lightwallet_image::ImageRecord::from_json(&devnet::read_bounded(
                &directory.join("source-preparation/lightwallet-image.json"),
                crate::image::MAX_RECORD_BYTES as u64,
            )?)?;
            crate::lightwallet_image::validate_artifacts(
                &record,
                &devnet::read_bounded(
                    &directory.join("source-preparation/lightwallet-image-manifest.json"),
                    crate::image::MAX_MANIFEST_BYTES as u64,
                )?,
                &devnet::read_bounded(
                    &directory.join("source-preparation/lightwallet-image-config.json"),
                    crate::image::MAX_CONFIG_BYTES as u64,
                )?,
                None,
            )?;
        }
        Ok(())
    }

    /// Stage only after the ordinary runner has verified the image and ECR bytes.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.preparation.stage")
    )]
    pub fn stage(
        &self,
        directory: &Path,
        deployment: &Deployment,
    ) -> Result<devnet::ClusterRequest> {
        devnet::select_native_runtime(Some(self.native_runtime_protocol.as_deref()), false)?;
        self.verify(directory, deployment)?;
        let inputs = directory.join("source-preparation");
        let build = directory.join("build");
        let mut request = devnet::stage_with_lightwallet(
            &self.config,
            &deployment.spec,
            &deployment.team,
            &devnet::InputPaths {
                build_contract: Some(&self.contract),
                manifest: &inputs.join("manifest.json"),
                bundle: &inputs.join("chain.tar"),
                helper: &inputs.join("zdn"),
                image_record: &build.join("image.json"),
                image_manifest: &build.join("image-manifest.json"),
                image_config: &build.join("image-config.json"),
            },
            self.config
                .services
                .lightwallet
                .then_some(&devnet::LightwalletInputPaths {
                    image_record: &inputs.join("lightwallet-image.json"),
                    image_manifest: &inputs.join("lightwallet-image-manifest.json"),
                    image_config: &inputs.join("lightwallet-image-config.json"),
                }),
            &self.reward_address,
            directory,
        )?;
        if let Some(service) = &mut request.lightwallet {
            service.capacity_protocol = self.capacity_protocol.clone();
        }
        request.installer_fetch_protocol = self.installer_fetch_protocol.clone();
        request.native_runtime_protocol = self.native_runtime_protocol.clone();
        request.validate(&deployment.spec, &deployment.team)?;
        Ok(request)
    }
}
