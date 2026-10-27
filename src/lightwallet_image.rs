//! Immutable candidate image inputs for the private lightwalletd service.
//!
//! This contract follows `image`'s saved-byte and host-inspection checks. The
//! source/protocol fields are declarations, not source-to-image attestations.
//! Neither registry metadata nor labels qualify an Ironwood wallet or payment.

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub use crate::image::{MAX_CONFIG_BYTES, MAX_INSPECT_BYTES, MAX_MANIFEST_BYTES, MAX_RECORD_BYTES};
use crate::{aws::TeamDefinition, image::RequiredLaunch};

pub const API_VERSION: &str = "zdn-lightwallet-image/v1alpha1";
pub const VALIDATION_API_VERSION: &str = "zdn-lightwallet-image-validation/v1alpha1";
pub const SOURCE_REVISION: &str = crate::lightwallet_service::SOURCE_REVISION;
pub const SOURCE_VERSION: &str = crate::lightwallet_service::SOURCE_VERSION;
pub const PROTOCOL_REVISION: &str = "ac7cee052a1bf5d430985a478d39e8b513fc4bd4";
pub const PROTOCOL_VERSION: &str = crate::lightwallet::PROTOCOL_VERSION;
pub const BINARY_PATH: &str = "/usr/local/bin/lightwalletd";
pub const ENVIRONMENT_LAUNCHER: &str = "/usr/bin/env";
const VENDOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRecord {
    pub api_version: String,
    /// Untagged repository and single-platform child manifest digest.
    pub image: String,
    pub config_digest: String,
    pub platform: String,
    pub source_revision: String,
    pub source_version: String,
    pub protocol_revision: String,
    pub protocol_version: String,
    /// A declared path. Metadata inspection does not prove file contents.
    pub binary_path: String,
    pub environment_launcher: String,
}

impl ImageRecord {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_image.record.from_json")
    )]
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "lightwallet image record is too large"
        );
        let record: Self =
            serde_json::from_slice(bytes).context("decode lightwallet image record")?;
        record.validate()?;
        Ok(record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_image.record.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported lightwallet image record version"
        );
        validate_reference(&self.image)?;
        validate_digest(&self.config_digest)?;
        ensure!(
            self.platform == "linux/amd64",
            "lightwallet image platform must be linux/amd64"
        );
        ensure!(
            self.source_revision == SOURCE_REVISION && self.source_version == SOURCE_VERSION,
            "lightwallet image must declare the pinned candidate source and version"
        );
        ensure!(
            self.protocol_revision == PROTOCOL_REVISION
                && self.protocol_version == PROTOCOL_VERSION,
            "lightwallet image must declare the pinned canonical protocol"
        );
        ensure!(
            self.binary_path == BINARY_PATH && self.environment_launcher == ENVIRONMENT_LAUNCHER,
            "unsupported lightwallet binary or clean-environment launcher"
        );
        Ok(())
    }

    pub fn manifest_digest(&self) -> Result<&str> {
        self.validate()?;
        Ok(self
            .image
            .rsplit_once('@')
            .expect("validated image reference")
            .1)
    }

    /// Deployment authorization is narrower than offline artifact inspection.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_image.record.ecr_repository")
    )]
    pub fn ecr_repository(&self, team: &TeamDefinition) -> Result<String> {
        self.validate()?;
        team.validate()?;
        let prefix = format!(
            "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
            team.aws.account_id, team.aws.region, team.team_id
        );
        let tail = self.image.strip_prefix(&prefix).context(
            "lightwallet image must use this team's same-account regional ECR namespace zdn/TEAM/",
        )?;
        let (name, _) = tail.rsplit_once('@').expect("validated image reference");
        ensure!(!name.is_empty(), "lightwallet ECR repository is missing");
        Ok(format!("zdn/{}/{name}", team.team_id))
    }
}

/// In-memory evidence only. It cannot be created by deserializing a receipt.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    record_sha256: String,
    manifest_digest: String,
    config_size: u64,
    layer_count: usize,
}

/// Requires both the child manifest and exact configuration bytes.
#[derive(Clone, Debug)]
pub struct VerifiedImage {
    manifest: VerifiedManifest,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageValidationReport {
    pub api_version: String,
    pub image: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub platform: String,
    pub declared_source_revision: String,
    pub declared_source_version: String,
    pub declared_protocol_revision: String,
    pub declared_protocol_version: String,
    pub manifest_bytes_verified: bool,
    pub config_bytes_verified: bool,
    pub single_platform_manifest: bool,
    pub docker_metadata_verified: bool,
    pub source_provenance_verified: bool,
    pub binary_contents_verified: bool,
    pub qualification: String,
    pub launch_ready: bool,
    pub required_launch: RequiredLaunch,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryManifest {
    schema_version: u32,
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default, rename = "annotations")]
    _annotations: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, rename = "annotations")]
    _annotations: BTreeMap<String, String>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_manifest_bytes")
)]
pub fn validate_manifest_bytes(record: &ImageRecord, bytes: &[u8]) -> Result<VerifiedManifest> {
    record.validate()?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_MANIFEST_BYTES,
        "invalid lightwallet manifest size"
    );
    let digest = sha256(bytes);
    ensure!(
        digest == record.manifest_digest()?,
        "lightwallet manifest SHA-256 does not match the pinned child digest"
    );
    let manifest: RegistryManifest =
        serde_json::from_slice(bytes).context("decode single-platform lightwallet manifest")?;
    ensure!(
        manifest.schema_version == 2,
        "unsupported lightwallet manifest schema"
    );
    let config_type = match manifest.media_type.as_str() {
        OCI_MANIFEST => OCI_CONFIG,
        DOCKER_MANIFEST => DOCKER_CONFIG,
        _ => eyre::bail!("lightwallet image must pin an OCI or Docker single-platform manifest"),
    };
    ensure!(
        manifest.config.media_type == config_type,
        "unsupported lightwallet configuration media type"
    );
    validate_digest(&manifest.config.digest)?;
    ensure!(
        manifest.config.digest == record.config_digest,
        "lightwallet manifest configuration digest differs from the record"
    );
    ensure!(
        (1..=MAX_CONFIG_BYTES as u64).contains(&manifest.config.size),
        "invalid lightwallet configuration size"
    );
    ensure!(
        (1..=128).contains(&manifest.layers.len()),
        "lightwallet image requires 1 to 128 filesystem layers"
    );
    for layer in &manifest.layers {
        validate_digest(&layer.digest)?;
        ensure!(
            (1..=16 * 1024u64.pow(3)).contains(&layer.size),
            "invalid lightwallet image layer size"
        );
        let supported = if manifest.media_type == OCI_MANIFEST {
            [
                "application/vnd.oci.image.layer.v1.tar",
                "application/vnd.oci.image.layer.v1.tar+gzip",
                "application/vnd.oci.image.layer.v1.tar+zstd",
            ]
            .contains(&layer.media_type.as_str())
        } else {
            layer.media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip"
        };
        ensure!(supported, "unsupported lightwallet image layer media type");
    }
    Ok(VerifiedManifest {
        record_sha256: record_sha256(record)?,
        manifest_digest: digest,
        config_size: manifest.config.size,
        layer_count: manifest.layers.len(),
    })
}

#[derive(Deserialize)]
struct RegistryConfig {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: String,
    config: RuntimeConfig,
    rootfs: RootFilesystem,
}

#[derive(Deserialize)]
struct RootFilesystem {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_config_bytes")
)]
pub fn validate_config_bytes(
    record: &ImageRecord,
    manifest: &VerifiedManifest,
    bytes: &[u8],
) -> Result<VerifiedImage> {
    record.validate()?;
    ensure!(
        manifest.record_sha256 == record_sha256(record)?,
        "manifest verification belongs to a different lightwallet record"
    );
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= MAX_CONFIG_BYTES
            && bytes.len() as u64 == manifest.config_size,
        "lightwallet configuration size does not match the manifest"
    );
    ensure!(
        sha256(bytes) == record.config_digest,
        "lightwallet configuration SHA-256 does not match the manifest"
    );
    let config: RegistryConfig =
        serde_json::from_slice(bytes).context("decode lightwallet image configuration")?;
    validate_platform(&config.os, &config.architecture, &config.variant)?;
    ensure!(
        config.rootfs.kind == "layers" && config.rootfs.diff_ids.len() == manifest.layer_count,
        "lightwallet rootfs must match the manifest layers"
    );
    for digest in config.rootfs.diff_ids {
        validate_digest(&digest)?;
    }
    validate_runtime_defaults(&config.config)?;
    Ok(VerifiedImage {
        manifest: manifest.clone(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerImage {
    id: String,
    repo_digests: Vec<String>,
    os: String,
    architecture: String,
    #[serde(default)]
    variant: String,
    config: RuntimeConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RuntimeConfig {
    env: Vec<String>,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    #[serde(default)]
    user: String,
    working_dir: String,
    #[serde(default)]
    stop_signal: String,
    volumes: Option<BTreeMap<String, serde_json::Value>>,
    on_build: Option<Vec<String>>,
}

/// Inspection must come from the trusted host's Docker daemon after pulling
/// the exact immutable image. Publisher-provided JSON is not host evidence.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_docker_inspect")
)]
pub fn validate_docker_inspect(
    record: &ImageRecord,
    image: &VerifiedImage,
    bytes: &[u8],
) -> Result<ImageValidationReport> {
    record.validate()?;
    ensure!(
        image.manifest.record_sha256 == record_sha256(record)?,
        "image verification belongs to a different lightwallet record"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_INSPECT_BYTES,
        "invalid lightwallet Docker inspection size"
    );
    let mut images: Vec<DockerImage> =
        serde_json::from_slice(bytes).context("decode lightwallet Docker image inspection")?;
    ensure!(
        images.len() == 1,
        "Docker must inspect exactly one lightwallet image"
    );
    let inspected = images.pop().expect("checked image count");
    ensure!(
        inspected.id == record.config_digest,
        "pulled lightwallet configuration digest does not match the manifest"
    );
    ensure!(
        inspected.repo_digests.len() <= 128
            && inspected
                .repo_digests
                .iter()
                .any(|digest| digest == &record.image),
        "pulled lightwallet image lacks the exact pinned repository digest"
    );
    validate_platform(&inspected.os, &inspected.architecture, &inspected.variant)?;
    validate_runtime_defaults(&inspected.config)?;
    Ok(report(record, image, true))
}

/// CLI convenience: perform saved-byte validation, then optional host inspection.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_artifacts")
)]
pub fn validate_artifacts(
    record: &ImageRecord,
    manifest: &[u8],
    config: &[u8],
    inspect: Option<&[u8]>,
) -> Result<ImageValidationReport> {
    let manifest = validate_manifest_bytes(record, manifest)?;
    let image = validate_config_bytes(record, &manifest, config)?;
    match inspect {
        Some(bytes) => validate_docker_inspect(record, &image, bytes),
        None => Ok(report(record, &image, false)),
    }
}

fn report(record: &ImageRecord, image: &VerifiedImage, inspected: bool) -> ImageValidationReport {
    ImageValidationReport {
        api_version: VALIDATION_API_VERSION.into(),
        image: record.image.clone(),
        manifest_digest: image.manifest.manifest_digest.clone(),
        config_digest: record.config_digest.clone(),
        platform: record.platform.clone(),
        declared_source_revision: record.source_revision.clone(),
        declared_source_version: record.source_version.clone(),
        declared_protocol_revision: record.protocol_revision.clone(),
        declared_protocol_version: record.protocol_version.clone(),
        manifest_bytes_verified: true,
        config_bytes_verified: true,
        single_platform_manifest: true,
        docker_metadata_verified: inspected,
        source_provenance_verified: false,
        binary_contents_verified: false,
        qualification: "pending".into(),
        launch_ready: false,
        required_launch: RequiredLaunch {
            binary_path: BINARY_PATH.into(),
            stop_signal: "SIGTERM".into(),
            ..RequiredLaunch::default()
        },
    }
}

fn validate_platform(os: &str, architecture: &str, variant: &str) -> Result<()> {
    ensure!(
        os == "linux" && architecture == "amd64" && variant.is_empty(),
        "lightwallet image must be native Linux amd64 without a variant"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_runtime_defaults")
)]
fn validate_runtime_defaults(config: &RuntimeConfig) -> Result<()> {
    // Clearing the environment inside /usr/bin/env happens after its loader
    // starts. Reject inherited loader, proxy and application environment values.
    ensure!(
        config.env == [format!("PATH={VENDOR_PATH}")]
            || config.env == [format!("PATH={}", crate::image::LAUNCH_PATH)],
        "lightwallet image must contain only the supported PATH environment"
    );
    ensure!(
        config.entrypoint == ["lightwalletd"] || config.entrypoint == [BINARY_PATH],
        "lightwallet image must declare the candidate executable entrypoint"
    );
    ensure!(
        config.cmd == ["--help"] && config.working_dir == "/srv/lightwalletd",
        "lightwallet image does not match the candidate default command and working directory"
    );
    ensure!(
        config.volumes.as_ref().is_none_or(BTreeMap::is_empty),
        "lightwallet image-declared volumes are not supported"
    );
    ensure!(
        config.on_build.as_ref().is_none_or(Vec::is_empty),
        "lightwallet image build triggers are not supported"
    );
    for value in [&config.user, &config.stop_signal] {
        ensure!(
            value.len() <= 4096 && !value.contains('\0'),
            "invalid overridden lightwallet image metadata"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_image.validate_reference")
)]
fn validate_reference(image: &str) -> Result<()> {
    ensure!(
        image.len() <= 512,
        "lightwallet image reference is too long"
    );
    let (repository, digest) = image
        .rsplit_once('@')
        .context("lightwallet image requires a pinned SHA-256 child digest")?;
    validate_digest(digest)?;
    ensure!(
        repository.len() <= 255,
        "lightwallet repository name is too long"
    );
    let (registry, path) = repository
        .split_once('/')
        .context("lightwallet image requires an explicit registry and repository")?;
    let (host, port) = registry
        .split_once(':')
        .map_or((registry, None), |(host, port)| (host, Some(port)));
    ensure!(
        (host == "localhost" || host.contains('.'))
            && host.len() <= 253
            && host.split('.').all(|part| valid_component(part, 63, b"-")),
        "invalid lightwallet image registry host"
    );
    if let Some(port) = port {
        ensure!(
            !port.is_empty()
                && port.bytes().all(|c| c.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port > 0),
            "invalid lightwallet image registry port"
        );
    }
    ensure!(
        !path.is_empty()
            && path
                .split('/')
                .all(|part| valid_component(part, 128, b"._-")),
        "invalid lightwallet image repository; tags and shell syntax are not accepted"
    );
    Ok(())
}

fn valid_component(value: &str, max: usize, separators: &[u8]) -> bool {
    let alphanumeric = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes().first().is_some_and(|c| alphanumeric(*c))
        && value.as_bytes().last().is_some_and(|c| alphanumeric(*c))
        && value
            .bytes()
            .all(|c| alphanumeric(c) || separators.contains(&c))
}

fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest
            .strip_prefix("sha256:")
            .is_some_and(|value| value.len() == 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))),
        "lightwallet image digests must use SHA-256 and 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn record_sha256(record: &ImageRecord) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(record)?))
}
