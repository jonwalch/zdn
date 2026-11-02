//! Immutable external staging and controller expectations. No ordinary
//! ConsensusManifest, payment-pool default or wallet interpretation enters here.
use super::Artifact;
use crate::{
    config::{ChainSelection, Config},
    image::{ImageBuildRequirements, ImageRecord},
    public_chain_adapter::{
        contract::{self, Compiled, Pin, RenderOptions},
        package::{CoreTrust, PreparedExternalChain},
    },
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::atomic::AtomicBool, time::Instant};

pub const SCHEMA: &str = "zdn-external-artifact-set/v1";
pub const FILE_NAME: &str = "external-request.json";

pub fn artifact_limits() -> BTreeMap<String, u64> {
    [
        ("package.json", 2 * 1024 * 1024),
        ("descriptor.json", 2 * 1024 * 1024),
        ("native-rules.json", 2 * 1024 * 1024),
        ("wallet-profile.json", 2 * 1024 * 1024),
        ("seed-blocks.bin", contract::MAX_BUNDLE as u64),
        ("host-adapter", 128 * 1024 * 1024),
        ("compiled.json", 4 * 1024 * 1024),
        ("image.json", crate::image::MAX_RECORD_BYTES as u64),
        (
            "image-manifest.json",
            crate::image::MAX_MANIFEST_BYTES as u64,
        ),
        ("image-config.json", crate::image::MAX_CONFIG_BYTES as u64),
        ("zdn", super::MAX_HELPER_BYTES),
    ]
    .into_iter()
    .map(|(n, b)| (n.into(), b))
    .collect()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalRequest {
    pub schema: String,
    pub config_sha256: String,
    pub trust: CoreTrust,
    pub compiled: Compiled,
    pub image: ImageRecord,
    pub build: Option<crate::build::BuildContract>,
    pub node_count: u8,
    pub block_interval_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production_limits: Option<crate::config::ExternalProductionLimits>,
    pub artifacts: BTreeMap<String, Artifact>,
}

pub struct Paths<'a> {
    pub public_directory: &'a Path,
    pub image_record: &'a Path,
    pub image_manifest: &'a Path,
    pub image_config: &'a Path,
    pub helper: &'a Path,
    pub build: Option<&'a crate::build::BuildContract>,
}

impl ExternalRequest {
    pub fn objects(
        &self,
        team: &crate::aws::TeamDefinition,
        spec: &crate::infra::FoundationSpec,
    ) -> Result<crate::host::external::Objects> {
        self.validate()?;
        let object = |name: &str| -> Result<crate::host::S3Object> {
            let artifact = self
                .artifacts
                .get(name)
                .context("missing external artifact")?;
            let object = crate::host::S3Object {
                bucket: team.backend_bucket()?.into(),
                key: format!(
                    "{}{}/{}",
                    super::artifact_prefix(team, spec),
                    artifact.sha256,
                    name
                ),
                sha256: artifact.sha256.clone(),
                bytes: artifact.bytes,
                owner_account: team.aws.account_id.clone(),
                region: team.aws.region.clone(),
            };
            object.validate()?;
            Ok(object)
        };
        Ok(crate::host::external::Objects {
            package: object("package.json")?,
            descriptor: object("descriptor.json")?,
            native_rules: object("native-rules.json")?,
            wallet_profile: object("wallet-profile.json")?,
            seed_bundle: object("seed-blocks.bin")?,
            host_adapter: object("host-adapter")?,
            compiled_result: object("compiled.json")?,
            image_record: object("image.json")?,
            image_manifest: object("image-manifest.json")?,
            image_config: object("image-config.json")?,
            host_helper: object("zdn")?,
        })
    }

    /// Create-only publication into the deployment-owned artifact directory.
    /// The executable comes exclusively from the explicit request's fixed slot.
    pub fn snapshot(
        &self,
        source: &Path,
        destination: &Path,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        self.prepare(source, deadline, cancelled)?;
        crate::foundation::private_directory(destination)?;
        for (name, limit) in artifact_limits() {
            let staging = tempfile::tempdir()?;
            let path = staging.path().join(&name);
            ensure!(
                super::snapshot_file(&source.join(&name), &path, limit)? == self.artifacts[&name],
                "external artifact changed during snapshot"
            );
            super::publish_snapshot(&path, &destination.join(&name), &self.artifacts[&name])?;
        }
        let path = destination.join(FILE_NAME);
        if path.try_exists()? {
            ensure!(
                super::read_bounded(&path, 4 * 1024 * 1024)? == self.bytes()?,
                "saved external request differs"
            );
        } else {
            crate::foundation::write_private(&path, &self.bytes()?)?;
        }
        self.prepare(destination, deadline, cancelled)?;
        Ok(())
    }

    /// Structural saved ownership, independent of companion installation.
    pub fn validate(&self) -> Result<ImageBuildRequirements> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported external artifact schema"
        );
        let hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        ensure!(hash(&self.config_sha256), "invalid external config pin");
        let requirements = self.compiled.image_requirements()?;
        requirements.validate_image(&self.image)?;
        crate::cluster_infra::ClusterTopology::new(self.node_count)?;
        ensure!(
            (1..=86400).contains(&self.block_interval_seconds),
            "external cadence exceeds bounds"
        );
        if let Some(limits) = &self.production_limits {
            limits.validate()?;
        }
        let limits = artifact_limits();
        ensure!(
            self.artifacts.len() == limits.len(),
            "incorrect external artifact inventory"
        );
        for (name, limit) in limits {
            let pin = self
                .artifacts
                .get(&name)
                .context("missing external artifact")?;
            ensure!(
                pin.bytes > 0 && pin.bytes <= limit && hash(&pin.sha256),
                "invalid external artifact pin"
            );
        }
        ensure!(
            pin(&self.artifacts["package.json"]) == self.trust.package
                && pin(&self.artifacts["host-adapter"]) == self.trust.executable
                && pin(&self.artifacts["compiled.json"])
                    == Pin::of(&serde_json::to_vec(&self.compiled)?),
            "external selection and artifact pins differ"
        );
        if let Some(build) = &self.build {
            let mut expected = build.clone();
            expected.require_external(&requirements)?;
            ensure!(
                &expected == build,
                "build contract is not bound to compiled requirements"
            );
            build.validate_image(&self.image)?;
        }
        Ok(requirements)
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let b = serde_json::to_vec(self)?;
        ensure!(
            b.len() <= 4 * 1024 * 1024,
            "external artifact metadata exceeds bound"
        );
        Ok(b)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "external artifact metadata exceeds bound"
        );
        let value: Self = contract::parse(bytes)?;
        ensure!(value.bytes()? == bytes, "noncanonical external request");
        Ok(value)
    }

    pub fn require_config(&self, config: &Config) -> Result<()> {
        require_selection(config, &self.trust)?;
        ensure!(
            self.config_sha256 == config.fingerprint()?,
            "external request belongs to another config"
        );
        ensure!(
            u16::from(self.node_count) == config.network.nodes
                && self.block_interval_seconds == config.network.mining.interval_seconds()?
                && self.production_limits.as_ref() == config.external_production_limits(),
            "external topology, cadence or production limits differ from config"
        );
        if let Some(build) = &self.build {
            let settings = config
                .node
                .build
                .as_ref()
                .context("external source build settings are missing")?;
            ensure!(
                config.node.source.path.is_some()
                    && Path::new(&build.recipe.dockerfile) == settings.dockerfile
                    && Path::new(&build.recipe.context) == settings.context
                    && build.recipe.target == settings.target
                    && build.platform == settings.platform
                    && (settings.cargo_features.is_empty()
                        || settings.cargo_features == build.recipe.cargo_features),
                "external source build recipe differs from config"
            );
        } else {
            ensure!(
                config.node.source.image.as_deref() == Some(&self.image.image),
                "external image differs from configured image"
            );
        }
        Ok(())
    }

    /// Verify all bytes before executing a companion. Recompilation is fresh
    /// for each controller operation, never a cached node observation.
    pub fn prepare(
        &self,
        directory: &Path,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PreparedExternalChain> {
        self.prepare_execution(directory, deadline, cancelled, false)
    }

    /// Host admission retains the fixed unprivileged sandbox for all renders.
    pub fn prepare_isolated(
        &self,
        directory: &Path,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PreparedExternalChain> {
        crate::host::external::require_isolated_execution()?;
        self.prepare_execution(directory, deadline, cancelled, true)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.external.prepare_execution")
    )]
    fn prepare_execution(
        &self,
        directory: &Path,
        deadline: Instant,
        cancelled: &AtomicBool,
        isolated: bool,
    ) -> Result<PreparedExternalChain> {
        let requirements = self.validate()?;
        for (name, limit) in artifact_limits() {
            ensure!(
                super::hash_file(&directory.join(&name), limit)? == self.artifacts[&name],
                "external staged artifact differs"
            );
        }
        let image = ImageRecord::from_json_for_requirements(
            &super::read_bounded(
                &directory.join("image.json"),
                crate::image::MAX_RECORD_BYTES as u64,
            )?,
            &requirements,
        )?;
        ensure!(image == self.image, "external staged image differs");
        let proof = crate::image::validate_manifest_bytes_for_requirements(
            &image,
            &requirements,
            &super::read_bounded(
                &directory.join("image-manifest.json"),
                crate::image::MAX_MANIFEST_BYTES as u64,
            )?,
        )?;
        crate::image::validate_config_bytes_for_requirements(
            &image,
            &requirements,
            &proof,
            &super::read_bounded(
                &directory.join("image-config.json"),
                crate::image::MAX_CONFIG_BYTES as u64,
            )?,
        )?;
        super::validate_helper_file(&directory.join("zdn"))?;
        let prepare = if isolated {
            PreparedExternalChain::prepare_isolated
        } else {
            PreparedExternalChain::prepare
        };
        let prepared = prepare(
            &super::read_bounded(
                &directory.join("package.json"),
                contract::MAX_METADATA as u64,
            )?,
            directory,
            &self.trust,
            deadline,
            cancelled,
        )?;
        ensure!(
            serde_json::to_vec(prepared.compiled())? == serde_json::to_vec(&self.compiled)?,
            "external controller compile result differs"
        );
        Ok(prepared)
    }

    pub(crate) fn require_sources(&self, objects: &crate::host::external::Objects) -> Result<()> {
        self.validate()?;
        for (name, object, limit) in objects.slots() {
            object.validate()?;
            ensure!(
                object.bytes <= limit
                    && object.bucket == objects.package.bucket
                    && object.owner_account == objects.package.owner_account
                    && object.region == objects.package.region,
                "external source crosses artifact authority"
            );
            ensure!(
                pin(&self.artifacts[name])
                    == Pin {
                        bytes: object.bytes,
                        sha256: object.sha256.clone()
                    },
                "external host source differs from staged artifact"
            );
        }
        Ok(())
    }

    /// Render only after the complete, independently pinned native cohort.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.external.render")
    )]
    pub fn render(
        &self,
        directory: &Path,
        options: RenderOptions,
        inventory: &crate::native_peers::NativeInventory,
        inventory_pin: &Pin,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<crate::public_chain_adapter::PinnedResult<contract::Rendered>> {
        self.prepare(directory, deadline, cancelled)?
            .render_with_inventory(options, inventory, inventory_pin, deadline, cancelled)
    }

    /// Freeze authenticated delivery sources and the exact runtime selection.
    /// No source authority or extra artifact is accepted from the companion.
    /// Callers retain these bytes and the inventory pin in lifecycle evidence.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.external.host_manifest")
    )]
    pub fn host_manifest(
        &self,
        directory: &Path,
        objects: crate::host::external::Objects,
        mut options: RenderOptions,
        inventory: &crate::native_peers::NativeInventory,
        inventory_pin: &Pin,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<crate::host::external::Manifest> {
        self.validate()?;
        for (name, object, _) in objects.slots() {
            ensure!(
                pin(&self.artifacts[name])
                    == Pin {
                        bytes: object.bytes,
                        sha256: object.sha256.clone()
                    },
                "external host source differs from staged artifact"
            );
        }
        ensure!(
            self.image
                .image
                .ends_with(&format!("@{}", options.image_digest)),
            "external host image differs from compiled artifact set"
        );
        inventory.bind_render_options(&mut options)?;
        let prepared = self.prepare(directory, deadline, cancelled)?;
        let rendered = prepared.render_with_inventory(
            options.clone(),
            inventory,
            inventory_pin,
            deadline,
            cancelled,
        )?;
        let config_toml = rendered.value().config_toml.clone();
        let manifest = crate::host::external::Manifest {
            schema: crate::host::external::SCHEMA.into(),
            request: Pin::of(&self.bytes()?),
            trust: self.trust.clone(),
            objects,
            compiled_json: String::from_utf8(serde_json::to_vec(prepared.compiled())?)?,
            native_inventory: inventory_pin.clone(),
            options,
            config: Pin::of(config_toml.as_bytes()),
            config_toml,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Snapshots only eleven fixed public/node/helper files. No recursive export,
/// funder input or arbitrary attachment map can be supplied by the companion.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.external.stage")
)]
pub fn stage(
    config: &Config,
    trust: &CoreTrust,
    paths: &Paths<'_>,
    output: &Path,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<ExternalRequest> {
    require_selection(config, trust)?;
    ensure!(!output.exists(), "external staging output must be new");
    let staging = tempfile::tempdir()?;
    let mut artifacts = BTreeMap::new();
    for (name, limit) in artifact_limits() {
        let source = match name.as_str() {
            "image.json" => paths.image_record,
            "image-manifest.json" => paths.image_manifest,
            "image-config.json" => paths.image_config,
            "zdn" => paths.helper,
            _ => {
                artifacts.insert(
                    name.clone(),
                    super::snapshot_file(
                        &paths.public_directory.join(&name),
                        &staging.path().join(&name),
                        limit,
                    )?,
                );
                continue;
            }
        };
        artifacts.insert(
            name.clone(),
            super::snapshot_file(source, &staging.path().join(&name), limit)?,
        );
    }
    let prepared = PreparedExternalChain::prepare(
        &super::read_bounded(
            &staging.path().join("package.json"),
            contract::MAX_METADATA as u64,
        )?,
        staging.path(),
        trust,
        deadline,
        cancelled,
    )?;
    let requirements = prepared.requirements()?;
    let image = ImageRecord::from_json_for_requirements(
        &super::read_bounded(
            &staging.path().join("image.json"),
            crate::image::MAX_RECORD_BYTES as u64,
        )?,
        &requirements,
    )?;
    let request = ExternalRequest {
        schema: SCHEMA.into(),
        config_sha256: config.fingerprint()?,
        trust: trust.clone(),
        compiled: prepared.compiled().clone(),
        image,
        build: paths.build.cloned(),
        node_count: config.network.nodes.try_into()?,
        block_interval_seconds: config.network.mining.interval_seconds()?,
        production_limits: config.external_production_limits().cloned(),
        artifacts,
    };
    request.require_config(config)?;
    request.prepare(staging.path(), deadline, cancelled)?;
    // All validation above precedes any destination publication.
    crate::foundation::private_directory(output)?;
    for (name, artifact) in &request.artifacts {
        super::publish_snapshot(&staging.path().join(name), &output.join(name), artifact)?;
    }
    crate::foundation::write_private(&output.join(FILE_NAME), &request.bytes()?)?;
    Ok(request)
}

fn pin(artifact: &Artifact) -> Pin {
    Pin {
        bytes: artifact.bytes,
        sha256: artifact.sha256.clone(),
    }
}

pub(crate) fn require_selection(config: &Config, trust: &CoreTrust) -> Result<()> {
    config.validate()?;
    match &config.chain {
        Some(ChainSelection::External {
            package_sha256,
            adapter_selection_sha256,
            ..
        }) => ensure!(
            *package_sha256 == trust.package.sha256
                && *adapter_selection_sha256 == trust.adapter_selection_sha256,
            "external config selection differs from independently trusted package"
        ),
        _ => eyre::bail!("external staging requires explicit external selection"),
    }
    ensure!(
        !config.services.lightwallet && !config.services.wallet && !config.services.faucet,
        "external chain does not select ordinary wallet/faucet/lightwallet services"
    );
    ensure!(
        config.network.mining.producer == "node-1",
        "external scheduled producer must be node-1"
    );
    Ok(())
}
