//! Immutable inputs and artifact staging for private Zakura hosts.
//! Scheduled blocks do not qualify wallet clients or payments.

use crate::{
    aws::{AwsApi, AwsCall, TeamDefinition},
    chain::{
        artifacts,
        manifest::ConsensusManifest,
        node_config::RenderOptions,
        runtime_config::{render_runtime_config, NodeRole, RuntimeOptions},
    },
    cluster_infra::{ClusterNodeOutputs, ClusterTopology},
    config::Config,
    foundation,
    host::{HostInstallSpec, S3Object},
    image::ImageRecord,
    infra::{FoundationSpec, PulumiProgram},
};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const API_VERSION: &str = "zdn-private-nodes/v1alpha1";
pub const MAX_HELPER_BYTES: u64 = 256 * 1024 * 1024;

/// Fresh requests are native; legacy inputs remain data, not execution authority.
pub fn select_native_runtime(
    saved: Option<Option<&str>>,
    _requested: bool,
) -> Result<Option<String>> {
    if let Some(saved) = saved {
        ensure!(
            saved == Some(crate::host::runtime::PROTOCOL),
            "cannot convert saved legacy inputs to native runtime; destroy the test deployment and use a fresh binding"
        );
    }
    Ok(Some(crate::host::runtime::PROTOCOL.into()))
}

pub(crate) fn validate_native_runtime(
    protocol: Option<&str>,
    lightwallet_capacity: Option<Option<&str>>,
    installer_fetch_protocol: Option<&str>,
) -> Result<()> {
    ensure!(
        protocol.is_none_or(|p| p == crate::host::runtime::PROTOCOL),
        "unsupported native runtime protocol"
    );
    ensure!(
        protocol.is_none()
            || lightwallet_capacity.is_none_or(|p| p == Some(crate::host::CAPACITY_PROTOCOL)),
        "native lightwallet runtime requires native capacity protocol"
    );
    ensure!(
        protocol.is_none()
            || installer_fetch_protocol.is_some_and(crate::host::installer_bootstrap::supports),
        "native runtime requires native installer transport"
    );
    Ok(())
}

/// Pure local capability report, not artifact validation or deployment readiness.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.capabilities")
)]
pub fn capabilities(config: &Config) -> Result<Value> {
    config.validate()?;
    let unsupported = unsupported_services(config);
    // Common explicit artifact inputs only: image/source build inputs vary by
    // source selection, and a verified --package can supply artifact files.
    let mut input_hints = vec![
        "--manifest",
        "--bundle",
        "--host-helper",
        "--reward-address",
    ];
    if config.services.lightwallet {
        input_hints.extend([
            "--lightwallet-image-record",
            "--lightwallet-image-manifest",
            "--lightwallet-image-config",
        ]);
    }
    Ok(json!({
        "apiVersion": "zdn-capabilities/v1alpha1",
        "configurationValid": true,
        "requestedServicesSupported": unsupported.is_empty(),
        "unsupportedServices": unsupported,
        "requestedServices": config.services,
        "deploymentPrerequisites": {
            "status": "unchecked",
            "explicitInputHints": input_hints,
            "unchecked": ["artifacts", "tools", "aws-identity", "aws-permissions"]
        },
        "liveReadinessChecked": false,
        "paymentQualification": "pending",
        "launchReady": false
    }))
}

fn unsupported_services(config: &Config) -> Vec<&'static str> {
    [
        ("wallet", config.services.wallet),
        ("faucet", config.services.faucet),
    ]
    .into_iter()
    .filter_map(|(name, requested)| requested.then_some(name))
    .collect()
}

/// Keep unimplemented service requests from producing a partial deployment.
pub fn require_supported_services(config: &Config) -> Result<()> {
    ensure!(
        unsupported_services(config).is_empty(),
        "wallet and faucet services are not implemented for devnet deployment; explicitly set services.wallet and services.faucet to false"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterRequest {
    pub api_version: String,
    pub config_sha256: String,
    /// Absent in historical requests; selects exact SSM transport command bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer_fetch_protocol: Option<String>,
    /// Selects the existing `zdn` artifact as the native runtime helper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_runtime_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<crate::build::BuildContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_set: Option<crate::artifact_set::ArtifactSet>,
    pub manifest: ConsensusManifest,
    pub image: ImageRecord,
    pub node_count: u8,
    /// Private client gateway and fixed-port SSM documents. Legacy requests omit this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_access: bool,
    pub reward_address: String,
    /// Absent in older node-only deployments. Never silently activate them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_interval_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightwallet: Option<LightwalletDeployment>,
    pub artifacts: BTreeMap<String, Artifact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletDeployment {
    pub image: crate::lightwallet_image::ImageRecord,
    pub allocation: crate::cluster_infra::LightwalletAllocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_protocol: Option<String>,
}

pub struct LightwalletInputPaths<'a> {
    pub image_record: &'a Path,
    pub image_manifest: &'a Path,
    pub image_config: &'a Path,
}

pub struct InputPaths<'a> {
    pub build_contract: Option<&'a crate::build::BuildContract>,
    pub manifest: &'a Path,
    pub bundle: &'a Path,
    pub image_record: &'a Path,
    pub image_manifest: &'a Path,
    pub image_config: &'a Path,
    pub helper: &'a Path,
}

pub(crate) const INPUTS: &[(&str, u64)] = &[
    ("manifest.json", 2 * 1024 * 1024),
    ("chain.tar", 256 * 1024 * 1024),
    ("image.json", 64 * 1024),
    ("image-manifest.json", 1024 * 1024),
    ("image-config.json", 4 * 1024 * 1024),
    ("zdn", MAX_HELPER_BYTES),
];

pub(crate) const LIGHTWALLET_INPUTS: &[(&str, u64)] = &[
    ("lightwallet-image.json", 64 * 1024),
    ("lightwallet-image-manifest.json", 1024 * 1024),
    ("lightwallet-image-config.json", 4 * 1024 * 1024),
];

pub fn artifact_prefix(team: &TeamDefinition, spec: &FoundationSpec) -> String {
    format!("{}/artifacts/{}/", team.metadata_prefix(), spec.network_id)
}

impl ClusterRequest {
    fn inputs(&self) -> impl Iterator<Item = &(&'static str, u64)> {
        INPUTS.iter().chain(
            LIGHTWALLET_INPUTS
                .iter()
                .filter(|_| self.lightwallet.is_some()),
        )
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.validate")
    )]
    pub fn validate(&self, spec: &FoundationSpec, team: &TeamDefinition) -> Result<()> {
        spec.validate()?;
        team.validate()?;
        ensure!(spec.scope == team.scope(), "deployment team scope mismatch");
        ensure!(team.deployment.is_some(),"private nodes require administrator-managed runtime access; run setup bootstrap with deployment-role configuration");
        ensure!(
            self.api_version == API_VERSION,
            "unsupported private-node request version"
        );
        validate_hash(&self.config_sha256)?;
        validate_native_runtime(
            self.native_runtime_protocol.as_deref(),
            self.lightwallet
                .as_ref()
                .map(|s| s.capacity_protocol.as_deref()),
            self.installer_fetch_protocol.as_deref(),
        )?;
        ensure!(
            self.installer_fetch_protocol
                .as_deref()
                .is_none_or(crate::host::installer_bootstrap::supports),
            "unsupported installer-fetch protocol"
        );
        ensure!(
            self.block_interval_seconds
                .is_none_or(|n| (1..=86_400).contains(&n)),
            "block interval must be 1 to 86400 seconds"
        );
        self.image.validate()?;
        if let Some(build) = &self.build {
            build.validate_image(&self.image)?;
        }
        if let Some(set) = &self.artifact_set {
            set.validate()?;
            ensure!(
                set.consensus_fingerprint == self.manifest.fingerprint()?
                    && set.node_image == self.image
                    && set.lightwallet_image.as_ref()
                        == self.lightwallet.as_ref().map(|s| &s.image)
                    && set.build == self.build
                    && set.artifacts == self.artifacts,
                "artifact set differs from the immutable deployment request"
            );
        }
        self.topology()?;
        let normalized = self.manifest.normalized()?;
        ensure!(
            normalized.experimental_slh.is_none(),
            "experimental profiles are not supported by private-node deployment"
        );
        let saved = std::iter::once(&normalized.genesis)
            .chain(normalized.seed_blocks.iter())
            .collect::<Vec<_>>();
        ensure!(
            normalized.checkpoints.len() == saved.len()
                && normalized
                    .checkpoints
                    .iter()
                    .zip(saved)
                    .all(|(cp, b)| cp.height == b.height && cp.hash == b.hash),
            "deployment requires a checkpoint at every saved height and no later checkpoint"
        );
        if let Some(service) = &self.lightwallet {
            service.image.ecr_repository(team)?;
            service.allocation.validate_for(spec.size)?;
            ensure!(
                service
                    .capacity_protocol
                    .as_deref()
                    .is_none_or(|p| p == crate::host::CAPACITY_PROTOCOL),
                "unsupported lightwallet capacity protocol"
            );
            ensure!(
                self.block_interval_seconds.is_some(),
                "lightwallet deployment requires scheduled block production"
            );
            ensure!(
                normalized.seed_blocks.len() < 62,
                "lightwallet readiness supports at most 62 saved blocks including genesis"
            );
        }
        ensure!(
            self.artifacts.len() == self.inputs().count(),
            "incomplete deployment artifacts"
        );
        for (name, limit) in self.inputs() {
            let artifact = self
                .artifacts
                .get(*name)
                .context("missing deployment artifact")?;
            validate_hash(&artifact.sha256)?;
            ensure!(
                artifact.bytes > 0 && artifact.bytes <= *limit,
                "deployment artifact size is invalid"
            );
        }
        self.ecr_repository(team)?;
        for node in self.topology()?.nodes() {
            self.runtime(spec, &node.node_id)?;
        }
        Ok(())
    }
    pub fn topology(&self) -> Result<ClusterTopology> {
        ClusterTopology::new(self.node_count)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.ecr_repository")
    )]
    pub fn ecr_repository(&self, team: &TeamDefinition) -> Result<String> {
        let prefix = format!(
            "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
            team.aws.account_id, team.aws.region, team.team_id
        );
        let tail=self.image.image.strip_prefix(&prefix).context("private-node images must use this team's same-account regional ECR namespace zdn/TEAM/")?;
        let name = tail.split_once('@').context("image digest missing")?.0;
        ensure!(!name.is_empty(), "ECR repository is missing");
        Ok(format!("zdn/{}/{name}", team.team_id))
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.runtime")
    )]
    pub fn runtime(
        &self,
        spec: &FoundationSpec,
        node_id: &str,
    ) -> Result<crate::chain::runtime_config::RenderedRuntimeConfig> {
        let topology = self.topology()?;
        let node = topology
            .nodes()
            .into_iter()
            .find(|n| n.node_id == node_id)
            .context("unknown node")?;
        let mut options = RuntimeOptions::new(spec.network_id, node_id);
        options.network = RenderOptions {
            listen_addr: format!("{}:{}", node.private_ip, crate::cluster_infra::P2P_PORT),
            peers: topology.peers(node_id)?,
            ..Default::default()
        };
        options.role = if node.producer {
            NodeRole::Producer
        } else {
            NodeRole::Follower
        };
        options.reward_address = node.producer.then(|| self.reward_address.clone());
        render_runtime_config(&self.manifest, &options)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.s3_object")
    )]
    pub fn s3_object(
        &self,
        team: &TeamDefinition,
        spec: &FoundationSpec,
        name: &str,
    ) -> Result<S3Object> {
        let artifact = self.artifacts.get(name).context("missing artifact")?;
        Ok(S3Object {
            bucket: team.backend_bucket()?.into(),
            key: format!(
                "{}{}/{}",
                artifact_prefix(team, spec),
                artifact.sha256,
                name
            ),
            sha256: artifact.sha256.clone(),
            bytes: artifact.bytes,
            owner_account: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
        })
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.host_spec")
    )]
    pub fn host_spec(
        &self,
        spec: &FoundationSpec,
        team: &TeamDefinition,
        node: &ClusterNodeOutputs,
    ) -> Result<HostInstallSpec> {
        self.validate(spec, team)?;
        let runtime = self.runtime(spec, &node.node_id)?;
        let allocation = spec.size.allocation();
        Ok(HostInstallSpec {
            api_version: crate::host::API_VERSION.into(),
            deployment_id: spec.network_id,
            node_id: node.node_id.clone(),
            consensus_fingerprint: runtime.consensus_fingerprint,
            volume_id: node.volume_id.clone(),
            image: self.image.image.clone(),
            config_toml: runtime.config_toml,
            config_sha256: runtime.config_sha256,
            role: if runtime.role == NodeRole::Producer {
                "producer"
            } else {
                "follower"
            }
            .into(),
            memory_bytes: u64::from(allocation.max_node_gib) * crate::infra::GIB,
            host_reserve_bytes: u64::from(allocation.host_reserve_gib) * crate::infra::GIB,
            cpu_millis: allocation.vcpus * 1000 - crate::infra::HOST_CPU_RESERVE_MILLIS,
            manifest: self.s3_object(team, spec, "manifest.json")?,
            bundle: self.s3_object(team, spec, "chain.tar")?,
            helper: self.s3_object(team, spec, "zdn")?,
            image_record: self.s3_object(team, spec, "image.json")?,
            image_manifest: self.s3_object(team, spec, "image-manifest.json")?,
            new_volume: None,
            block_interval_seconds: self.block_interval_seconds,
        })
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.render")
    )]
    pub fn render(
        &self,
        base: PulumiProgram,
        spec: &FoundationSpec,
        team: &TeamDefinition,
    ) -> Result<PulumiProgram> {
        self.validate(spec, team)?;
        let scripts = self
            .topology()?
            .nodes()
            .into_iter()
            .map(|n| (n.node_id, crate::host::base_user_data().to_string()))
            .collect();
        let program = if let Some(service) = &self.lightwallet {
            self.topology()?.render_with_lightwallet(
                base,
                spec,
                &scripts,
                service.allocation.cache_gib,
            )?
        } else {
            self.topology()?.render(base, spec, &scripts)?
        };
        let mut value = serde_json::to_value(program)?;
        if self.client_access {
            for (key, resource) in crate::endpoints::session_document_resources(
                &spec.scope,
                team.bootstrap_id,
                spec.network_id,
                self.lightwallet.is_some(),
            )? {
                value["resources"][key] = resource;
            }
        }
        value["resources"]["hostArtifactsPolicy"] = json!({"name":spec.resource_name("host-artifacts-policy"),"type":"aws:iam:RolePolicyAttachment","properties":{"role":"${hostRole.name}","policyArn":crate::access::runtime_data_policy_arn(team)},"options":{"provider":"${provider}"}});
        for node in self.topology()?.nodes() {
            value["resources"][&node.host_key]["options"]["dependsOn"]
                .as_array_mut()
                .context("host dependency list missing")?
                .push(json!("${hostArtifactsPolicy}"));
        }
        let program: PulumiProgram = serde_json::from_value(value)?;
        program.validate_references()?;
        Ok(program)
    }
    /// Re-read the immutable local copies before any cloud allocation.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "devnet.cluster_request.verify_local")
    )]
    pub fn verify_local(&self, directory: &Path) -> Result<()> {
        if let Some(set) = &self.artifact_set {
            set.verify(&directory.join("artifacts"))?;
        }
        for (name, limit) in self.inputs() {
            ensure!(
                self.artifacts.get(*name)
                    == Some(&hash_file(&artifact_path(directory, name), *limit)?),
                "staged artifact changed: {name}"
            );
        }
        let record = ImageRecord::from_json(&read_bounded(
            &artifact_path(directory, "image.json"),
            64 * 1024,
        )?)?;
        ensure!(
            record == self.image,
            "staged image differs from saved request"
        );
        let manifest_bytes = read_bounded(
            &artifact_path(directory, "image-manifest.json"),
            1024 * 1024,
        )?;
        let proof = crate::image::validate_manifest_bytes(&record, &manifest_bytes)?;
        crate::image::validate_config_bytes(
            &record,
            &proof,
            &read_bounded(
                &artifact_path(directory, "image-config.json"),
                4 * 1024 * 1024,
            )?,
        )?;
        if let Some(service) = &self.lightwallet {
            let record = crate::lightwallet_image::ImageRecord::from_json(&read_bounded(
                &artifact_path(directory, "lightwallet-image.json"),
                64 * 1024,
            )?)?;
            ensure!(
                record == service.image,
                "staged lightwallet image differs from saved request"
            );
            crate::lightwallet_image::validate_artifacts(
                &record,
                &read_bounded(
                    &artifact_path(directory, "lightwallet-image-manifest.json"),
                    1024 * 1024,
                )?,
                &read_bounded(
                    &artifact_path(directory, "lightwallet-image-config.json"),
                    4 * 1024 * 1024,
                )?,
                None,
            )?;
        }
        let manifest: ConsensusManifest =
            foundation::read_json(&artifact_path(directory, "manifest.json"))?;
        ensure!(
            manifest.fingerprint()? == self.manifest.fingerprint()?,
            "staged chain differs from request"
        );
        artifacts::verify_bundle(&manifest, &artifact_path(directory, "chain.tar"))?;
        validate_helper_file(&artifact_path(directory, "zdn"))?;
        Ok(())
    }
}

pub fn stage(
    config: &Config,
    spec: &FoundationSpec,
    team: &TeamDefinition,
    paths: &InputPaths<'_>,
    reward_address: &str,
    directory: &Path,
) -> Result<ClusterRequest> {
    stage_with_lightwallet(config, spec, team, paths, None, reward_address, directory)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.stage")
)]
pub fn stage_with_lightwallet(
    config: &Config,
    spec: &FoundationSpec,
    team: &TeamDefinition,
    paths: &InputPaths<'_>,
    lightwallet_paths: Option<&LightwalletInputPaths<'_>>,
    reward_address: &str,
    directory: &Path,
) -> Result<ClusterRequest> {
    config.validate()?;
    require_supported_services(config)?;
    ensure!(config.services.lightwallet == lightwallet_paths.is_some(), "services.lightwallet requires all three lightwallet image inputs; disable it for a node-only deployment");
    let staging = tempfile::tempdir()?;
    let mut inventory = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    for ((name, limit), path) in INPUTS.iter().zip([
        paths.manifest,
        paths.bundle,
        paths.image_record,
        paths.image_manifest,
        paths.image_config,
        paths.helper,
    ]) {
        inventory.insert(
            (*name).to_string(),
            snapshot_file(path, &staging.path().join(name), *limit)?,
        );
        if *name != "chain.tar" && *name != "zdn" {
            inputs.insert(
                (*name).to_string(),
                read_bounded(&staging.path().join(name), *limit)?,
            );
        }
    }
    let lightwallet = if let Some(paths) = lightwallet_paths {
        for ((name, limit), path) in LIGHTWALLET_INPUTS.iter().zip([
            paths.image_record,
            paths.image_manifest,
            paths.image_config,
        ]) {
            inventory.insert(
                (*name).to_string(),
                snapshot_file(path, &staging.path().join(name), *limit)?,
            );
            inputs.insert(
                (*name).to_string(),
                read_bounded(&staging.path().join(name), *limit)?,
            );
        }
        let image =
            crate::lightwallet_image::ImageRecord::from_json(&inputs["lightwallet-image.json"])?;
        crate::lightwallet_image::validate_artifacts(
            &image,
            &inputs["lightwallet-image-manifest.json"],
            &inputs["lightwallet-image-config.json"],
            None,
        )?;
        Some(LightwalletDeployment {
            image,
            allocation: crate::cluster_infra::LightwalletAllocation::for_size(spec.size),
            capacity_protocol: None,
        })
    } else {
        None
    };
    let manifest = validate_chain_inputs(
        config,
        &inputs["manifest.json"],
        &staging.path().join("chain.tar"),
    )?;
    let image = ImageRecord::from_json(&inputs["image.json"])?;
    if let Some(build) = paths.build_contract {
        ensure!(
            config.node.source.path.is_some(),
            "build contract requires a source-path configuration"
        );
        build.validate_image(&image)?;
        let settings = config
            .node
            .build
            .as_ref()
            .context("missing build settings")?;
        ensure!(
            Path::new(&build.recipe.dockerfile) == settings.dockerfile
                && Path::new(&build.recipe.context) == settings.context
                && build.recipe.target == settings.target
                && build.platform == settings.platform,
            "build recipe differs from configured source recipe"
        );
    } else {
        ensure!(config.node.source.image.as_deref() == Some(&image.image), "source deployments require a verified build contract; image deployments require the exact pinned image");
    }
    ensure!(
        config.network.mining.producer == "node-1",
        "the first cluster uses node-1 as its producer"
    );
    let proof = crate::image::validate_manifest_bytes(&image, &inputs["image-manifest.json"])?;
    crate::image::validate_config_bytes(&image, &proof, &inputs["image-config.json"])?;
    validate_helper_file(&staging.path().join("zdn"))?;
    let request = ClusterRequest {
        api_version: API_VERSION.into(),
        config_sha256: config.fingerprint()?,
        installer_fetch_protocol: None,
        native_runtime_protocol: None,
        build: paths.build_contract.cloned(),
        artifact_set: None,
        manifest: manifest.normalized()?,
        image,
        node_count: config.network.nodes.try_into()?,
        client_access: true,
        reward_address: reward_address.into(),
        block_interval_seconds: Some(config.network.mining.interval_seconds()?),
        lightwallet,
        artifacts: inventory,
    };
    request.validate(spec, team)?;
    let target = directory.join("artifacts");
    foundation::private_directory(&target)?;
    for (name, artifact) in &request.artifacts {
        publish_snapshot(&staging.path().join(name), &target.join(name), artifact)?;
    }
    request.verify_local(directory)?;
    Ok(request)
}

/// Shared source-build preflight and deployment validation. Never runs a node.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.validate_chain_inputs")
)]
pub fn validate_chain_inputs(
    config: &Config,
    manifest: &[u8],
    bundle: &Path,
) -> Result<ConsensusManifest> {
    ensure!(
        manifest.len() <= 2 * 1024 * 1024,
        "manifest exceeds size limit"
    );
    let manifest: ConsensusManifest = serde_json::from_slice(manifest)?;
    let manifest = manifest.normalized()?;
    let upgrades = serde_json::to_value(&manifest.upgrades)?;
    for (name, height) in config.resolved_upgrades()? {
        ensure!(
            upgrades[&name].as_u64() == Some(u64::from(height)),
            "saved chain manifest disagrees with configured upgrade {name}"
        );
    }
    ensure!(
        serde_json::to_value(manifest.difficulty.proof_of_work)?
            == config.network.mining.proof_of_work,
        "saved chain proof of work differs from devnet configuration"
    );
    artifacts::verify_bundle(&manifest, bundle)?;
    Ok(manifest)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.validate_helper")
)]
pub fn validate_helper(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 64
            && &bytes[..4] == b"\x7fELF"
            && bytes[4] == 2
            && bytes[5] == 1
            && u16::from_le_bytes([bytes[18], bytes[19]]) == 62
            && matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3),
        "host helper must be a Linux x86-64 ELF executable (not the local macOS/ARM binary)"
    );
    Ok(())
}
pub fn artifact_path(directory: &Path, name: &str) -> PathBuf {
    directory.join("artifacts").join(name)
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn validate_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA-256"
    );
    Ok(())
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.read_bounded")
)]
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "artifact exceeds its size limit"
    );
    Ok(bytes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.open_regular")
)]
fn open_regular(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open deployment artifact")?;
    ensure!(
        file.metadata()?.is_file(),
        "artifact must be a regular file"
    );
    Ok(file)
}

/// Hash the actual bounded bytes, optionally copying the same stream to a private snapshot.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "artifact.copy_hash")
)]
pub(crate) fn copy_file(path: &Path, limit: u64, output: &mut impl Write) -> Result<Artifact> {
    let mut input = open_regular(path)?.take(limit.saturating_add(1));
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        ensure!(bytes <= limit, "artifact exceeds its size limit");
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    Ok(Artifact {
        sha256: hex::encode(hash.finalize()),
        bytes,
    })
}

pub(crate) fn hash_file(path: &Path, limit: u64) -> Result<Artifact> {
    copy_file(path, limit, &mut std::io::sink())
}

pub(crate) fn validate_helper_file(path: &Path) -> Result<()> {
    let mut header = [0; 64];
    open_regular(path)?.read_exact(&mut header)?;
    validate_helper(&header)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "artifact.snapshot")
)]
pub(crate) fn snapshot_file(source: &Path, path: &Path, limit: u64) -> Result<Artifact> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("artifact parent missing")?)?;
    let artifact = copy_file(source, limit, file.as_file_mut())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(artifact)
}

/// Never replace an immutable destination, including retries after partial publication.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "artifact.publish")
)]
pub(crate) fn publish_snapshot(source: &Path, path: &Path, expected: &Artifact) -> Result<()> {
    let parent = path.parent().context("artifact parent missing")?;
    ensure!(
        fs::symlink_metadata(parent)?.is_dir(),
        "artifact parent must be a real directory"
    );
    if fs::symlink_metadata(path).is_ok() {
        ensure!(
            hash_file(path, expected.bytes)? == *expected,
            "staged artifact changed: {}",
            path.display()
        );
    } else {
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        ensure!(
            copy_file(source, expected.bytes, file.as_file_mut())? == *expected,
            "snapshot changed"
        );
        file.as_file().sync_all()?;
        file.persist_noclobber(path)?;
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Verify a registry still has the exact immutable child manifest before provisioning.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.verify_ecr")
)]
pub fn verify_ecr(
    api: &dyn AwsApi,
    request: &ClusterRequest,
    team: &TeamDefinition,
    directory: &Path,
) -> Result<()> {
    let response=api.call("ecr","batch-get-image",json!({"registryId":team.aws.account_id,"repositoryName":request.ecr_repository(team)?,"imageIds":[{"imageDigest":request.image.manifest_digest()?}],"acceptedMediaTypes":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"]}),&[])?;
    ensure!(
        response["failures"].as_array().is_some_and(Vec::is_empty),
        "ECR image is unavailable"
    );
    let images = response["images"]
        .as_array()
        .context("ECR images missing")?;
    ensure!(
        images.len() == 1
            && images[0]["imageId"]["imageDigest"] == request.image.manifest_digest()?,
        "ECR returned a different image"
    );
    let bytes = images[0]["imageManifest"]
        .as_str()
        .context("ECR manifest missing")?
        .as_bytes();
    ensure!(
        bytes
            == read_bounded(
                &artifact_path(directory, "image-manifest.json"),
                1024 * 1024
            )?,
        "ECR manifest differs from saved bytes"
    );
    crate::image::validate_manifest_bytes(&request.image, bytes)?;
    if let Some(service) = &request.lightwallet {
        let response = api.call("ecr", "batch-get-image", json!({"registryId":team.aws.account_id,"repositoryName":service.image.ecr_repository(team)?,"imageIds":[{"imageDigest":service.image.manifest_digest()?}],"acceptedMediaTypes":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"]}), &[])?;
        ensure!(
            response["failures"].as_array().is_some_and(Vec::is_empty),
            "ECR lightwallet image is unavailable"
        );
        let images = response["images"]
            .as_array()
            .context("ECR lightwallet images missing")?;
        ensure!(
            images.len() == 1
                && images[0]["imageId"]["imageDigest"] == service.image.manifest_digest()?,
            "ECR returned a different lightwallet image"
        );
        let bytes = images[0]["imageManifest"]
            .as_str()
            .context("ECR lightwallet manifest missing")?
            .as_bytes();
        ensure!(
            bytes
                == read_bounded(
                    &artifact_path(directory, "lightwallet-image-manifest.json"),
                    1024 * 1024
                )?,
            "ECR lightwallet manifest differs from saved bytes"
        );
        crate::lightwallet_image::validate_manifest_bytes(&service.image, bytes)?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.upload")
)]
pub fn upload(
    api: &dyn AwsApi,
    request: &ClusterRequest,
    spec: &FoundationSpec,
    team: &TeamDefinition,
    directory: &Path,
) -> Result<()> {
    request.verify_local(directory)?;
    let files = request
        .artifacts
        .keys()
        .map(|name| {
            Ok((
                request.s3_object(team, spec, name)?,
                artifact_path(directory, name),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    upload_files(api, team, &files)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.upload_file")
)]
pub fn upload_file(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    object: &S3Object,
    path: &Path,
) -> Result<()> {
    upload_files(api, team, &[(object.clone(), path.to_path_buf())])
}

/// Validate all local inputs before remote work, then HEAD, conditionally PUT,
/// and reconcile independent immutable objects in bounded API phases.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.upload_files")
)]
pub fn upload_files(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    files: &[(S3Object, PathBuf)],
) -> Result<()> {
    use base64::Engine;
    let checksums = files
        .iter()
        .map(|(object, path)| {
            path.to_str().context("artifact path is not UTF-8")?;
            let artifact = hash_file(path, MAX_HELPER_BYTES)?;
            ensure!(
                artifact.bytes == object.bytes && artifact.sha256 == object.sha256,
                "upload input changed"
            );
            Ok(base64::engine::general_purpose::STANDARD.encode(hex::decode(&artifact.sha256)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let check = |index: usize, value: &Value| -> Result<()> {
        let object = &files[index].0;
        ensure!(
            value["ContentLength"].as_u64() == Some(object.bytes)
                && value["ChecksumSHA256"] == checksums[index]
                && value["ServerSideEncryption"] == "aws:kms"
                && value["SSEKMSKeyId"] == team.state.kms_key_arn,
            "existing artifact does not match immutable content/encryption"
        );
        Ok(())
    };
    let heads: Vec<_> = files.iter().map(|(object, _)| AwsCall {
        operation: "head-object",
        input: json!({"Bucket":object.bucket,"Key":object.key,"ExpectedBucketOwner":object.owner_account,"ChecksumMode":"ENABLED"}),
        extra_args: vec![],
    }).collect();
    let mut missing = Vec::new();
    let head_results = api.batch_call_all("s3api", &heads)?;
    ensure!(
        head_results.len() == heads.len(),
        "AWS batch HEAD response count differs"
    );
    for (index, result) in head_results.into_iter().enumerate() {
        match result {
            Ok(value) => check(index, &value)?,
            Err(error)
                if error
                    .downcast_ref::<crate::aws::AwsApiError>()
                    .is_some_and(|e| {
                        matches!(e.code.as_str(), "404" | "NoSuchKey" | "NotFound")
                    }) =>
            {
                missing.push(index)
            }
            Err(error) => return Err(error),
        }
    }
    let puts: Vec<_> = missing.iter().map(|&index| {
        let (object, path) = &files[index];
        AwsCall {
            operation: "put-object",
            input: json!({"Bucket":object.bucket,"Key":object.key,"ExpectedBucketOwner":object.owner_account,"IfNoneMatch":"*","ChecksumSHA256":checksums[index],"ServerSideEncryption":"aws:kms","SSEKMSKeyId":team.state.kms_key_arn,"Metadata":{"sha256":object.sha256}}),
            extra_args: vec!["--body".into(), path.to_str().expect("validated path").into()],
        }
    }).collect();
    let put_results = api.batch_call("s3api", &puts);
    // Even failures may be lost successful writes. Reconcile every candidate,
    // including successful peers, before propagating any PUT/verification error.
    let reconcile: Vec<_> = missing
        .iter()
        .map(|&index| AwsCall {
            operation: "head-object",
            input: heads[index].input.clone(),
            extra_args: vec![],
        })
        .collect();
    let verified = api.batch_call_all("s3api", &reconcile)?;
    ensure!(
        verified.len() == reconcile.len(),
        "AWS batch reconciliation response count differs"
    );
    // Authenticate successful peers even if PUT returned an infrastructure
    // error or malformed outcome vector. Never truncate verification via zip.
    let verified: Vec<_> = missing
        .iter()
        .zip(verified)
        .map(|(&index, head)| head.map(|value| check(index, &value)))
        .collect();
    let put_results = put_results?;
    ensure!(
        put_results.len() == puts.len(),
        "AWS batch PUT response count differs"
    );
    let mut failure = None;
    for (put, head) in put_results.into_iter().zip(verified) {
        let result = match head {
            Ok(result) => result,
            Err(error) => put.and(Err(error)),
        };
        if failure.is_none() {
            failure = result.err();
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.validate_observation")
)]
pub fn validate_observation(
    report: &Value,
    spec: &HostInstallSpec,
    install_sha256: &str,
) -> Result<()> {
    ensure!(
        report["apiVersion"] == "zdn-host-observation/v1alpha1"
            && report["nodeId"] == spec.node_id
            && report["deploymentId"] == spec.deployment_id.to_string()
            && report["consensusFingerprint"] == spec.consensus_fingerprint
            && report["configSha256"] == spec.config_sha256
            && report["image"] == spec.image
            && report["installSha256"] == install_sha256
            && report["status"] == "ready"
            && report["launchReady"] == false
            && report["paymentQualification"] == "pending",
        "host observation identity or status differs from request"
    );
    let readiness = &report["readiness"];
    ensure!(
        readiness["apiVersion"] == crate::chain::readiness::API_VERSION
            && readiness["consensusFingerprint"] == spec.consensus_fingerprint
            && readiness["role"] == spec.role
            && readiness["effectiveRulesVerified"] == true
            && readiness["historyPresent"] == true
            && readiness["miningReady"] == (spec.role == "producer")
            && readiness["launchReady"] == false
            && readiness["paymentQualification"] == "pending",
        "host did not establish node readiness"
    );
    ensure!(
        readiness
            .pointer("/tip/height")
            .and_then(Value::as_u64)
            .is_some_and(|height| height <= u64::from(u32::MAX)),
        "host readiness tip height missing or out of range"
    );
    validate_hash(
        readiness
            .pointer("/tip/hash")
            .and_then(Value::as_str)
            .context("host readiness tip hash missing")?,
    )?;
    let limits = &report["effectiveLimits"];
    let memory = limits["effectiveMemoryBytes"]
        .as_u64()
        .context("effective host memory missing")?;
    let cpu = limits["visibleCpuMillis"]
        .as_u64()
        .context("effective host CPU missing")?;
    let node_memory = limits["nodeMemoryBytes"]
        .as_u64()
        .context("node memory limit missing")?;
    let node_cpu = limits["nodeCpuMillis"]
        .as_u64()
        .context("node CPU limit missing")?;
    ensure!(
        limits["hostReserveBytes"].as_u64() == Some(spec.host_reserve_bytes)
            && limits["hostReserveCpuMillis"] == 250
            && node_memory >= crate::infra::GIB
            && node_memory <= spec.memory_bytes
            && node_cpu >= 250
            && node_cpu <= u64::from(spec.cpu_millis)
            && memory
                .checked_sub(node_memory)
                .is_some_and(|n| n >= spec.host_reserve_bytes)
            && cpu.checked_sub(node_cpu).is_some_and(|n| n >= 250),
        "host limits do not preserve the requested resource reserve"
    );
    validate_producer_observation(report, spec, false)?;
    Ok(())
}

/// Activation requires a fresh host observation. Configuration or an old
/// successful start command alone cannot establish a running controller.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "devnet.validate_producer_observation")
)]
pub fn validate_producer_observation(
    report: &Value,
    spec: &HostInstallSpec,
    require_running: bool,
) -> Result<bool> {
    let enabled = spec.block_interval_seconds.is_some() && spec.role == "producer";
    let scheduled = match report["scheduledProducer"].as_bool() {
        Some(value) => value,
        None if spec.block_interval_seconds.is_none() => false,
        None => eyre::bail!("host did not report producer state"),
    };
    ensure!(
        !scheduled || enabled,
        "unexpected controller on a host without production enabled"
    );
    ensure!(
        !require_running || !enabled || scheduled,
        "scheduled producer is not running"
    );
    let producer = &report["producer"];
    if !scheduled {
        ensure!(producer.is_null(), "inactive host reports a producer");
        return Ok(false);
    }
    ensure!(
        producer["apiVersion"] == crate::chain::producer::API_VERSION
            && producer["identity"]["deploymentId"] == spec.deployment_id.to_string()
            && producer["identity"]["nodeId"] == spec.node_id
            && producer["identity"]["consensusFingerprint"] == spec.consensus_fingerprint
            && producer["intervalSecs"].as_u64() == spec.block_interval_seconds
            && producer["controllerLocked"] == true
            && producer["ownerPid"]
                .as_u64()
                .is_some_and(|pid| pid > 0 && pid <= u64::from(u32::MAX))
            && matches!(producer["phase"].as_str(), Some("waiting" | "generating"))
            && producer["paymentQualification"] == "pending"
            && producer["launchReady"] == false,
        "host producer identity, ownership or health differs from request"
    );
    let session = producer["ownerSession"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    ensure!(
        session.is_some_and(
            |id| id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
        ),
        "host producer session is invalid"
    );
    Ok(true)
}
