//! Immutable image inputs for the direct Zakura runtime.
//!
//! A record declares capabilities; it cannot attest them. The saved registry
//! manifest binds a single-platform child digest to its image configuration.
//! A trusted host's Docker inspection then checks the pulled configuration and
//! platform before start. Parsed rules and stored history still need the live
//! bootstrap/readiness checks. Neither labels nor source metadata qualify a
//! chain recipe, wallet, or payment path.

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const API_VERSION: &str = "zdn-zakura-image/v1alpha1";
pub const VALIDATION_API_VERSION: &str = "zdn-zakura-image-validation/v1alpha1";
pub const NODE_BINARY: &str = "/usr/local/bin/zakurad";
pub const ENV_ENTRYPOINT: &str = "/usr/bin/env";
pub const LAUNCH_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
pub const LAUNCH_HOME: &str = "/nonexistent";
pub const RUNTIME_UID: u32 = 10001;
pub const RUNTIME_GID: u32 = 10001;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_INSPECT_BYTES: usize = 2 * 1024 * 1024;
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const VENDOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Build/release provenance supplied by the publisher. Digests bind inputs but
/// do not authenticate the publisher or establish reproducible builds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ImageProvenance {
    Source {
        revision: String,
        #[serde(rename = "snapshotSha256")]
        snapshot_sha256: String,
    },
    Release {
        revision: String,
        version: String,
    },
}

/// Exact interfaces required by this adapter, declared by the image publisher.
/// The declarations are not evidence that the binaries implement the methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCapabilities {
    pub ruleset: String,
    pub chain_rules_api: String,
    pub block_inspection_api: String,
    pub runtime_adapter: String,
    pub cookie_auth: bool,
    pub block_submission: bool,
    pub generate_rpc: bool,
}

impl Default for ImageCapabilities {
    fn default() -> Self {
        Self {
            ruleset: crate::chain::manifest::RULESET.into(),
            chain_rules_api: "zakura-chain-rules/v1".into(),
            block_inspection_api: "zakura-block-inspection/v1".into(),
            runtime_adapter: crate::chain::runtime_config::ADAPTER.into(),
            cookie_auth: true,
            block_submission: true,
            generate_rpc: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRecord {
    pub api_version: String,
    /// Fully qualified, untagged repository and the single-platform child
    /// manifest SHA-256, never a mutable tag or a multi-platform index digest.
    pub image: String,
    /// Docker's image ID is the digest of this configuration object.
    pub config_digest: String,
    pub platform: String,
    pub provenance: ImageProvenance,
    pub capabilities: ImageCapabilities,
    pub binary_path: String,
    pub environment_launcher: String,
}

impl ImageRecord {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_RECORD_BYTES, "image record is too large");
        let record: Self = serde_json::from_slice(bytes).context("decode image record")?;
        record.validate()?;
        Ok(record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "image.record.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported image record version"
        );
        validate_reference(&self.image)?;
        validate_digest(&self.config_digest)?;
        ensure!(
            self.platform == "linux/amd64",
            "image platform must be linux/amd64"
        );
        ensure!(
            self.binary_path == NODE_BINARY,
            "unsupported node binary path"
        );
        ensure!(
            self.environment_launcher == ENV_ENTRYPOINT,
            "image requires the /usr/bin/env clean-environment launcher"
        );
        ensure!(
            self.capabilities == ImageCapabilities::default(),
            "image must declare the exact supported runtime and RPC capabilities"
        );
        match &self.provenance {
            ImageProvenance::Source {
                revision,
                snapshot_sha256,
            } => {
                validate_revision(revision)?;
                ensure!(
                    lower_hex(snapshot_sha256, 64),
                    "invalid source snapshot SHA-256"
                );
            }
            ImageProvenance::Release { revision, version } => {
                validate_revision(revision)?;
                ensure!(
                    !version.is_empty()
                        && version.len() <= 128
                        && version
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
                        && !["latest", "main", "master", "stable", "nightly"]
                            .contains(&version.as_str()),
                    "release provenance requires an exact version identifier"
                );
            }
        }
        Ok(())
    }

    pub fn manifest_digest(&self) -> Result<&str> {
        self.validate()?;
        Ok(self
            .image
            .rsplit_once('@')
            .expect("validated image digest")
            .1)
    }
}

/// Produced only after checking the exact saved manifest bytes. Keeping the
/// constructor private prevents accidental substitution of declared metadata
/// for this step. This receipt is not persisted or deserialized as authority.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    record_sha256: String,
    manifest_digest: String,
    config_digest: String,
    config_size: u64,
    layer_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredLaunch {
    pub entrypoint: String,
    pub clear_environment: bool,
    pub path: String,
    pub home: String,
    pub binary_path: String,
    pub uid: u32,
    pub gid: u32,
    pub working_directory: String,
    pub stop_signal: String,
    pub override_command: bool,
    pub disable_image_healthcheck: bool,
}

impl Default for RequiredLaunch {
    fn default() -> Self {
        Self {
            entrypoint: ENV_ENTRYPOINT.into(),
            clear_environment: true,
            path: LAUNCH_PATH.into(),
            home: LAUNCH_HOME.into(),
            binary_path: NODE_BINARY.into(),
            uid: RUNTIME_UID,
            gid: RUNTIME_GID,
            working_directory: "/".into(),
            stop_signal: "SIGINT".into(),
            override_command: true,
            disable_image_healthcheck: true,
        }
    }
}

/// A host observation of image metadata, not observation of a running node.
/// RequiredLaunch lists actions the caller must take; it does not attest them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageInspectionReport {
    pub api_version: String,
    pub image: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub platform: String,
    pub manifest_bytes_verified: bool,
    pub single_platform_manifest: bool,
    pub docker_metadata_verified: bool,
    pub capabilities_observed: bool,
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

/// Verify the raw registry response before any JSON reformatting. OCI indexes,
/// Docker manifest lists, foreign layers, and artifact manifests are outside
/// this runtime's supported image contract.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_manifest_bytes")
)]
pub fn validate_manifest_bytes(record: &ImageRecord, bytes: &[u8]) -> Result<VerifiedManifest> {
    record.validate()?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_MANIFEST_BYTES,
        "invalid image manifest size"
    );
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    ensure!(
        digest == record.manifest_digest()?,
        "image manifest SHA-256 does not match the pinned child digest"
    );
    let manifest: RegistryManifest =
        serde_json::from_slice(bytes).context("decode single-platform image manifest")?;
    ensure!(
        manifest.schema_version == 2,
        "unsupported image manifest schema"
    );
    let expected_config_type = match manifest.media_type.as_str() {
        OCI_MANIFEST => OCI_CONFIG,
        DOCKER_MANIFEST => DOCKER_CONFIG,
        _ => eyre::bail!("image must pin an OCI or Docker single-platform image manifest"),
    };
    ensure!(
        manifest.config.media_type == expected_config_type,
        "unsupported image configuration media type"
    );
    validate_digest(&manifest.config.digest)?;
    ensure!(
        manifest.config.digest == record.config_digest,
        "image manifest configuration digest differs from the record"
    );
    ensure!(
        (1..=4 * 1024 * 1024).contains(&manifest.config.size),
        "invalid image configuration size"
    );
    ensure!(
        !manifest.layers.is_empty() && manifest.layers.len() <= 128,
        "image requires 1 to 128 filesystem layers"
    );
    for layer in &manifest.layers {
        validate_digest(&layer.digest)?;
        ensure!(
            layer.size > 0 && layer.size <= 16 * 1024 * 1024 * 1024,
            "invalid image layer size"
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
        ensure!(supported, "unsupported image layer media type");
    }
    Ok(VerifiedManifest {
        record_sha256: record_sha256(record)?,
        manifest_digest: digest,
        config_digest: manifest.config.digest,
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
    config: DockerConfig,
    rootfs: RootFilesystem,
}

#[derive(Deserialize)]
struct RootFilesystem {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

/// Check the saved registry config before creating hosts. The digest and byte
/// length bind it to the child manifest; platform and startup defaults are read
/// from these bytes, not copied from the record. Docker must still inspect its
/// actual pulled image on each host. No node code or layer is executed here.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_config_bytes")
)]
pub fn validate_config_bytes(
    record: &ImageRecord,
    verified: &VerifiedManifest,
    bytes: &[u8],
) -> Result<()> {
    record.validate()?;
    ensure!(
        verified.record_sha256 == record_sha256(record)?,
        "manifest verification belongs to a different image record"
    );
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= MAX_CONFIG_BYTES
            && bytes.len() as u64 == verified.config_size,
        "image configuration size does not match the manifest"
    );
    ensure!(
        format!("sha256:{}", hex::encode(Sha256::digest(bytes))) == verified.config_digest,
        "image configuration SHA-256 does not match the manifest"
    );
    let config: RegistryConfig =
        serde_json::from_slice(bytes).context("decode registry image configuration")?;
    ensure!(
        config.os == "linux" && config.architecture == "amd64" && config.variant.is_empty(),
        "image configuration must be Linux amd64 without a variant"
    );
    ensure!(
        config.rootfs.kind == "layers" && config.rootfs.diff_ids.len() == verified.layer_count,
        "image configuration rootfs must match the manifest layers"
    );
    for digest in config.rootfs.diff_ids {
        validate_digest(&digest)?;
    }
    validate_runtime_defaults(&config.config)
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
    config: DockerConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerConfig {
    env: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    #[serde(default)]
    user: String,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    stop_signal: String,
    volumes: Option<BTreeMap<String, serde_json::Value>>,
    on_build: Option<Vec<String>>,
}

/// Inspect exactly one pulled image by immutable reference. The JSON must come
/// from the trusted host's `docker image inspect`, not publisher-supplied labels
/// or an arbitrary precomputed attestation. The daemon still owns layer checks.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_docker_inspect")
)]
pub fn validate_docker_inspect(
    record: &ImageRecord,
    verified: &VerifiedManifest,
    bytes: &[u8],
) -> Result<ImageInspectionReport> {
    record.validate()?;
    ensure!(
        verified.record_sha256 == record_sha256(record)?,
        "manifest verification belongs to a different image record"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_INSPECT_BYTES,
        "invalid Docker inspection size"
    );
    let mut images: Vec<DockerImage> =
        serde_json::from_slice(bytes).context("decode Docker image inspection")?;
    ensure!(images.len() == 1, "Docker must inspect exactly one image");
    let image = images.pop().expect("checked image count");
    ensure!(
        image.id == verified.config_digest,
        "pulled image configuration digest does not match the manifest"
    );
    ensure!(
        image.repo_digests.len() <= 128
            && image
                .repo_digests
                .iter()
                .any(|digest| digest == &record.image),
        "pulled image lacks the exact pinned repository digest"
    );
    ensure!(
        image.os == "linux" && image.architecture == "amd64" && image.variant.is_empty(),
        "pulled image must be Linux amd64 without a variant"
    );
    validate_runtime_defaults(&image.config)?;
    Ok(ImageInspectionReport {
        api_version: VALIDATION_API_VERSION.into(),
        image: record.image.clone(),
        manifest_digest: verified.manifest_digest.clone(),
        config_digest: verified.config_digest.clone(),
        platform: record.platform.clone(),
        manifest_bytes_verified: true,
        single_platform_manifest: true,
        docker_metadata_verified: true,
        capabilities_observed: false,
        qualification: "pending".into(),
        launch_ready: false,
        required_launch: RequiredLaunch::default(),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_runtime_defaults")
)]
fn validate_runtime_defaults(config: &DockerConfig) -> Result<()> {
    validate_environment(config.env.as_deref().unwrap_or_default())?;
    ensure!(
        config.volumes.as_ref().is_none_or(BTreeMap::is_empty),
        "image-declared volumes are not supported"
    );
    ensure!(
        config.on_build.as_ref().is_none_or(Vec::is_empty),
        "image build triggers are not supported"
    );
    // The launcher replaces these defaults, including healthcheck, user,
    // working directory and stop signal. Bound the metadata but never execute
    // or interpolate it into a host command.
    for value in [&config.entrypoint, &config.cmd] {
        ensure!(
            value.as_ref().is_none_or(|value| value.len() <= 128
                && value
                    .iter()
                    .all(|arg| arg.len() <= 4096 && !arg.contains('\0'))),
            "invalid image command metadata"
        );
    }
    for value in [&config.user, &config.working_dir, &config.stop_signal] {
        ensure!(
            value.len() <= 4096 && !value.contains('\0'),
            "invalid overridden image metadata"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_environment")
)]
fn validate_environment(env: &[String]) -> Result<()> {
    ensure!(env.len() <= 16, "too many image environment variables");
    let mut names = BTreeSet::new();
    for item in env {
        ensure!(
            item.len() <= 1024,
            "image environment variable is too large"
        );
        let (name, value) = item
            .split_once('=')
            .context("invalid image environment assignment")?;
        ensure!(names.insert(name), "duplicate image environment variable");
        let supported = match name {
            "PATH" => [VENDOR_PATH, LAUNCH_PATH].contains(&value),
            "HOME" => ["/home/zebra", LAUNCH_HOME].contains(&value),
            "USER" => value == "zebra",
            "UID" | "GID" => value == "10001",
            "FEATURES" => {
                !value.is_empty()
                    && value.len() <= 256
                    && value.split(',').all(|feature| {
                        !feature.is_empty()
                            && feature
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                    })
            }
            _ => false,
        };
        ensure!(
            supported,
            "image contains an unsupported environment variable or value"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "image.validate_reference")
)]
fn validate_reference(image: &str) -> Result<()> {
    ensure!(image.len() <= 512, "image reference is too long");
    let (repository, digest) = image
        .rsplit_once('@')
        .context("image requires a pinned sha256 child digest")?;
    validate_digest(digest)?;
    ensure!(repository.len() <= 255, "image repository name is too long");
    let (registry, path) = repository
        .split_once('/')
        .context("image requires an explicit registry and repository")?;
    let (host, port) = registry
        .split_once(':')
        .map_or((registry, None), |(host, port)| (host, Some(port)));
    ensure!(
        host == "localhost" || host.contains('.'),
        "image requires a fully qualified registry host"
    );
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host
                .split('.')
                .all(|label| valid_component(label, 63, b"-")),
        "invalid image registry hostname"
    );
    if let Some(port) = port {
        ensure!(
            !port.is_empty()
                && port.bytes().all(|c| c.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port > 0),
            "invalid image registry port"
        );
    }
    ensure!(
        !path.is_empty()
            && path
                .split('/')
                .all(|part| valid_component(part, 128, b"._-")),
        "invalid image repository path; tags and shell syntax are not accepted"
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
            .is_some_and(|hash| lower_hex(hash, 64)),
        "image digests must use sha256 and 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_revision(revision: &str) -> Result<()> {
    ensure!(
        lower_hex(revision, 40) || lower_hex(revision, 64),
        "image provenance requires a full lowercase Git revision"
    );
    Ok(())
}

fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn record_sha256(record: &ImageRecord) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(record)?)))
}
