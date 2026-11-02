//! Immutable first-image preparation. Public chain inputs precede image creation;
//! native build submission/reuse/recovery stay in the existing build journal.
use crate::{
    build::BuildContract,
    config::Config,
    devnet::Artifact,
    foundation::{self, Deployment},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

pub const SCHEMA: &str = "zdn-external-source-preparation/v1";
pub const FILE: &str = "external-source-preparation.json";
pub const ROOT: &str = "external-source";

/// Portable structural contract for handoff/cleanup. No executable discovery or
/// source checkout access is required by validate/verify_local.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePreparation {
    pub schema: String,
    pub deployment_sha256: String,
    pub config: Config,
    pub trust: Value,
    pub compiled_json: String,
    pub contract: BuildContract,
    /// Seven fixed public package slots plus the exact Linux ZDN helper.
    pub artifacts: BTreeMap<String, Artifact>,
    pub native_port: u16,
    pub reward_address: String,
}

fn scope_pin(deployment: &Deployment) -> Result<String> {
    Ok(crate::devnet::sha256(&serde_json::to_vec(&(
        &deployment.spec,
        &deployment.team,
        deployment.owner_id,
    ))?))
}

pub fn limits() -> BTreeMap<String, u64> {
    [
        ("package.json", 2 * 1024 * 1024),
        ("descriptor.json", 2 * 1024 * 1024),
        ("native-rules.json", 2 * 1024 * 1024),
        ("wallet-profile.json", 2 * 1024 * 1024),
        ("seed-blocks.bin", 128 * 1024 * 1024),
        ("host-adapter", 128 * 1024 * 1024),
        ("compiled.json", 4 * 1024 * 1024),
        ("zdn", crate::devnet::MAX_HELPER_BYTES),
    ]
    .into_iter()
    .map(|(name, limit)| (name.into(), limit))
    .collect()
}

impl SourcePreparation {
    /// Read either the normal record or its atomically published copy. The
    /// latter bridges a crash between directory publication and receipt save.
    /// Reading never opens a source checkout or executable and never writes.
    pub fn read(directory: &Path) -> Result<Option<Self>> {
        let path = directory.join(FILE);
        let staged = directory.join(ROOT).join(FILE);
        if path.try_exists()? {
            return Ok(Some(foundation::read_json(&path)?));
        }
        if staged.try_exists()? {
            return Ok(Some(foundation::read_json(&staged)?));
        }
        Ok(None)
    }

    pub fn validate(&self, deployment: &Deployment) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.deployment_sha256 == scope_pin(deployment)?,
            "external source scope differs"
        );
        self.config.validate()?;
        self.contract.validate()?;
        crate::cluster_infra::ClusterTopology::new(u8::try_from(self.config.network.nodes)?)?;
        ensure!(
            self.config.network.mining.interval_seconds()? <= 3600,
            "external host runtime cadence exceeds one hour"
        );
        ensure!(
            self.config.node.source.path.is_some() && self.config.node.build.is_some(),
            "external source settings missing"
        );
        let settings = self
            .config
            .node
            .build
            .as_ref()
            .context("external source recipe missing")?;
        ensure!(
            Path::new(&self.contract.recipe.dockerfile) == settings.dockerfile
                && Path::new(&self.contract.recipe.context) == settings.context
                && self.contract.recipe.target == settings.target
                && self.contract.platform == settings.platform
                && (settings.cargo_features.is_empty()
                    || settings.cargo_features == self.contract.recipe.cargo_features),
            "external source recipe differs from config"
        );
        ensure!(
            matches!(
                self.config.chain,
                Some(crate::config::ChainSelection::External { .. })
            ),
            "external source requires explicit chain selection"
        );
        ensure!(
            self.native_port != 0
                && !self.reward_address.is_empty()
                && self.reward_address.len() <= 512
                && self
                    .reward_address
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric()),
            "invalid external source runtime selection"
        );
        ensure!(
            self.artifacts.len() == limits().len(),
            "external source slot set differs"
        );
        for (name, limit) in limits() {
            let artifact = self
                .artifacts
                .get(&name)
                .context("external source slot missing")?;
            crate::devnet::validate_hash(&artifact.sha256)?;
            ensure!(
                artifact.bytes > 0 && artifact.bytes <= limit,
                "external source slot exceeds bound"
            );
        }
        #[cfg(target_os = "linux")]
        {
            let trust: crate::public_chain_adapter::package::CoreTrust =
                serde_json::from_value(self.trust.clone())?;
            crate::devnet::external::require_selection(&self.config, &trust)?;
            let compiled: crate::public_chain_adapter::contract::Compiled =
                crate::public_chain_adapter::contract::parse(self.compiled_json.as_bytes())?;
            let mut expected = self.contract.clone();
            expected.require_external(&compiled.image_requirements()?)?;
            ensure!(
                expected == self.contract
                    && self.compiled_json.as_bytes() == serde_json::to_vec(&compiled)?,
                "external source requirements differ"
            );
            for (name, pin) in [
                ("package.json", trust.package),
                ("host-adapter", trust.executable),
                (
                    "compiled.json",
                    crate::public_chain_adapter::contract::Pin::of(self.compiled_json.as_bytes()),
                ),
            ] {
                ensure!(
                    self.artifacts[name].bytes == pin.bytes
                        && self.artifacts[name].sha256 == pin.sha256,
                    "external source trust pin differs"
                );
            }
            if let Some(external) = &deployment.external {
                let request = external.typed_request()?;
                ensure!(
                    request.build.as_ref() == Some(&self.contract)
                        && request.config_sha256 == self.config.fingerprint()?
                        && request.production_limits.as_ref()
                            == self.config.external_production_limits()
                        && external.native_port == self.native_port
                        && external.reward_address == self.reward_address,
                    "completed external source request differs"
                );
                for (name, artifact) in &self.artifacts {
                    ensure!(
                        request.artifacts[name] == *artifact,
                        "completed external source artifact differs"
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.external.source.verify_local")
    )]
    pub fn verify_local(&self, deployment: &Deployment, directory: &Path) -> Result<()> {
        self.validate(deployment)?;
        let saved = Self::read(directory)?.context("external source preparation record missing")?;
        ensure!(
            serde_json::to_value(&saved)? == serde_json::to_value(self)?,
            "external source preparation record differs"
        );
        let published: Self = foundation::read_json(&directory.join(ROOT).join(FILE))?;
        ensure!(
            serde_json::to_value(&published)? == serde_json::to_value(self)?,
            "published external source preparation differs"
        );
        for (name, limit) in limits() {
            let bytes = crate::devnet::read_bounded(
                &directory.join(ROOT).join("public").join(&name),
                limit,
            )?;
            let artifact = &self.artifacts[&name];
            ensure!(
                bytes.len() as u64 == artifact.bytes
                    && crate::devnet::sha256(&bytes) == artifact.sha256,
                "external source artifact changed"
            );
        }
        self.contract
            .verify_archive(&directory.join(ROOT).join("source-snapshot/source.tar"))?;
        let receipt: crate::source::SnapshotReceipt =
            foundation::read_json(&directory.join(ROOT).join("source-snapshot/receipt.json"))?;
        let mut expected = BuildContract::new(
            &receipt,
            self.config
                .node
                .build
                .as_ref()
                .context("external source recipe missing")?,
        )?;
        if let Some(requirements) = &self.contract.required_capabilities.build_requirements {
            expected.require_external(requirements)?;
        }
        ensure!(
            expected == self.contract,
            "external captured source recipe differs"
        );
        crate::build_job::validate_preparation(
            &directory.join(ROOT).join("build"),
            &deployment.team,
            &self.contract,
        )?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl SourcePreparation {
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.external.source.prepare")
    )]
    pub fn prepare(
        deployment: &Deployment,
        config: &Config,
        config_path: &Path,
        directory: &Path,
        public: &Path,
        trust: crate::public_chain_adapter::package::CoreTrust,
        helper: &Path,
        exporter: &Path,
        native_port: u16,
        reward_address: String,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        use crate::public_chain_adapter::package::PreparedExternalChain;
        use std::time::{Duration, Instant};
        crate::build::preparation::initial_shape(deployment)?;
        crate::devnet::external::require_selection(config, &trust)?;
        ensure!(
            deployment.external.is_none()
                && deployment.external_source.is_none()
                && deployment.cluster.is_none()
                && !directory.join(FILE).try_exists()?
                && !directory.join(ROOT).try_exists()?,
            "external source preparation already exists"
        );
        let temporary = tempfile::tempdir_in(directory)?;
        let public_snapshot = temporary.path().join("public");
        foundation::private_directory(&public_snapshot)?;
        let mut artifacts = BTreeMap::new();
        for (name, limit) in limits() {
            let source = if name == "zdn" {
                helper.to_path_buf()
            } else {
                public.join(&name)
            };
            artifacts.insert(
                name.clone(),
                crate::devnet::snapshot_file(&source, &public_snapshot.join(&name), limit)?,
            );
        }
        crate::devnet::validate_helper(&crate::devnet::read_bounded(
            &public_snapshot.join("zdn"),
            crate::devnet::MAX_HELPER_BYTES,
        )?)?;
        let prepared = PreparedExternalChain::prepare(
            &crate::devnet::read_bounded(&public_snapshot.join("package.json"), 2 * 1024 * 1024)?,
            &public_snapshot,
            &trust,
            Instant::now() + Duration::from_secs(120),
            cancelled,
        )?;
        let receipt = crate::source::capture(&crate::source::CaptureOptions {
            source: config
                .source_root(config_path)?
                .context("external first build requires local source")?,
            output: temporary.path().join("source-snapshot"),
            revision: config.node.source.revision.clone(),
            include: vec![],
        })?;
        let mut contract = BuildContract::new(
            &receipt,
            config
                .node
                .build
                .as_ref()
                .context("external build recipe missing")?,
        )?;
        contract.require_external(&prepared.requirements()?)?;
        crate::build_job::prepare_native(
            &temporary.path().join("build"),
            &deployment.team,
            &contract,
            exporter,
        )?;
        let value = Self {
            schema: SCHEMA.into(),
            deployment_sha256: scope_pin(deployment)?,
            config: config.clone(),
            trust: serde_json::to_value(trust)?,
            compiled_json: String::from_utf8(serde_json::to_vec(prepared.compiled())?)?,
            contract,
            artifacts,
            native_port,
            reward_address,
        };
        value.validate(deployment)?;
        foundation::write_json(&temporary.path().join(FILE), &value)?;
        std::fs::rename(temporary.path(), directory.join(ROOT))?;
        std::fs::File::open(directory)?.sync_all()?;
        foundation::write_json(&directory.join(FILE), &value)?;
        value.verify_local(deployment, directory)?;
        Ok(value)
    }

    /// Recompile only saved public bytes, build through existing authenticated
    /// submission/reuse/recovery machinery, then materialize the immutable request.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.external.source.complete")
    )]
    pub fn complete(
        &self,
        api: &dyn crate::aws::AwsApi,
        deployment: &Deployment,
        directory: &Path,
        runtime: &impl crate::foundation_live::Runtime,
        cancelled: &std::sync::atomic::AtomicBool,
        progress: &mut crate::build_job::BuildProgress<'_>,
    ) -> Result<super::ExternalDeployment> {
        use std::{
            sync::atomic::Ordering,
            time::{Duration, Instant},
        };
        self.verify_local(deployment, directory)?;
        let root = directory.join(ROOT);
        let public = root.join("public");
        let build = root.join("build");
        let trust: crate::public_chain_adapter::package::CoreTrust =
            serde_json::from_value(self.trust.clone())?;
        crate::public_chain_adapter::package::PreparedExternalChain::prepare(
            &crate::devnet::read_bounded(&public.join("package.json"), 2 * 1024 * 1024)?,
            &public,
            &trust,
            Instant::now() + Duration::from_secs(120),
            cancelled,
        )?;
        crate::aws::verify_identity(
            api,
            &crate::aws::AwsSelection {
                profile: deployment.spec.aws_profile.clone(),
                account_id: deployment.spec.scope.account_id.clone(),
                region: deployment.spec.scope.region.clone(),
            },
        )?;
        crate::build_job::run_with_progress(
            api,
            &deployment.team,
            &self.contract,
            &root.join("source-snapshot/source.tar"),
            &build,
            runtime,
            || {
                ensure!(
                    !cancelled.load(Ordering::SeqCst),
                    "external source build cancelled"
                );
                Ok(())
            },
            progress,
        )?;
        let temporary = tempfile::tempdir_in(directory)?;
        let staged = temporary.path().join("artifacts");
        let request = crate::devnet::external::stage(
            &self.config,
            &trust,
            &crate::devnet::external::Paths {
                public_directory: &public,
                image_record: &build.join("image.json"),
                image_manifest: &build.join("image-manifest.json"),
                image_config: &build.join("image-config.json"),
                helper: &public.join("zdn"),
                build: Some(&self.contract),
            },
            &staged,
            Instant::now() + Duration::from_secs(180),
            cancelled,
        )?;
        request.snapshot(
            &staged,
            &directory.join("artifacts"),
            Instant::now() + Duration::from_secs(180),
            cancelled,
        )?;
        super::ExternalDeployment::new(request, self.native_port, self.reward_address.clone())
    }
}
