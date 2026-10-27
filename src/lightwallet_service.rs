//! Offline recipe for a private, cookie-authenticated lightwalletd service.
//!
//! The recipe does not allocate a cache volume, install a service, or establish
//! Ironwood compatibility. The native runtime refuses unprepared hosts and never
//! formats storage. Candidate CLI flags come from the pinned upstream source.

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::{host::HostInstallSpec, infra::HostObservation};

#[cfg(target_os = "linux")]
pub mod cache;
#[cfg(target_os = "linux")]
pub mod image_delivery;
mod install;
pub mod native;
#[cfg(target_os = "linux")]
pub mod runtime;
pub use install::{
    validate_observation, LightwalletHostObservation, LightwalletInstallSpec,
    RenderedLightwalletInstall, INSTALL_API_VERSION, OBSERVATION_API_VERSION,
};

pub const API_VERSION: &str = "zdn-lightwallet-service/v1alpha1";
pub const SOURCE_REVISION: &str = "d16d48124e9ad4157ebc2324b5090c6ba201470c";
pub const SOURCE_VERSION: &str = "v0.5.5";
pub const GRPC_ENDPOINT: &str = "127.0.0.1:9067";
pub const HTTP_ENDPOINT: &str = "127.0.0.1:9068";
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletServiceSpec {
    pub api_version: String,
    /// A team ECR image pinned by digest; a tag is never accepted.
    pub image: String,
    pub source_revision: String,
    /// A dedicated cache disk, distinct from the node's retained chain disk.
    pub cache_volume_id: String,
    pub cache_bytes: u64,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub host_observation: HostObservation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedLightwalletService {
    pub api_version: String,
    pub service_sha256: String,
    pub docker_arguments: Vec<String>,
    pub cache_root: String,
    pub cache_identity_json: String,
    pub credential_path: String,
    pub grpc_endpoint: String,
    pub http_endpoint: String,
    pub qualification: String,
    pub deployment_ready: bool,
    pub launch_ready: bool,
    pub remaining_requirements: Vec<String>,
}

impl LightwalletServiceSpec {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_service.spec.validate")
    )]
    pub fn validate(&self, host: &HostInstallSpec) -> Result<()> {
        host.validate()?;
        ensure!(
            self.api_version == API_VERSION,
            "unsupported lightwallet service version"
        );
        ensure!(
            self.source_revision == SOURCE_REVISION,
            "unsupported lightwalletd source revision"
        );
        let registry = format!(
            "{}.dkr.ecr.{}.amazonaws.com/",
            host.helper.owner_account, host.helper.region
        );
        let image = self
            .image
            .strip_prefix(&registry)
            .context("lightwalletd image must use the host's regional private ECR registry")?;
        let (repository, digest) = image
            .split_once("@sha256:")
            .context("lightwalletd image must be pinned by SHA-256")?;
        ensure!(
            repository.starts_with("zdn/")
                && repository.len() <= 256
                && repository
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != "..")
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/._-".contains(&b)),
            "invalid lightwalletd image repository"
        );
        ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "expected lowercase lightwalletd image SHA-256"
        );
        let volume = self
            .cache_volume_id
            .strip_prefix("vol-")
            .context("lightwalletd requires a dedicated EBS cache volume")?;
        ensure!(
            [8, 17].contains(&volume.len())
                && volume
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && self.cache_volume_id != host.volume_id,
            "cache volume must be a distinct canonical EBS volume"
        );
        ensure!(
            (GIB..=2048 * GIB).contains(&self.cache_bytes) && self.cache_bytes.is_multiple_of(GIB),
            "cache disk size must be 1 to 2048 whole GiB"
        );
        // Bounds are contract limits, not qualified capacity recommendations.
        ensure!(
            (GIB / 4..=32 * GIB).contains(&self.memory_bytes),
            "lightwalletd memory limit must be 256 MiB to 32 GiB"
        );
        ensure!(
            (250..=8000).contains(&self.cpu_millis),
            "lightwalletd CPU limit must be 250 to 8000 milli-CPUs"
        );
        let observed = &self.host_observation;
        let memory = observed
            .ancestor_memory_limits_bytes
            .iter()
            .copied()
            .fold(observed.mem_total_bytes, u64::min);
        let required_memory = host
            .memory_bytes
            .checked_add(host.host_reserve_bytes)
            .and_then(|n| n.checked_add(self.memory_bytes))
            .context("lightwalletd memory budget overflow")?;
        ensure!(required_memory <= memory, "node, host reserve and lightwalletd exceed effective memory; reduce the node budget explicitly");
        let cpu = observed
            .online_cpu_count
            .min(observed.affinity_cpu_count)
            .checked_mul(1000)
            .context("host CPU observation overflow")?;
        let cpu = observed
            .ancestor_cpu_quota_millis
            .iter()
            .copied()
            .fold(cpu, u32::min);
        let required_cpu = host
            .cpu_millis
            .checked_add(250)
            .and_then(|n| n.checked_add(self.cpu_millis))
            .context("lightwalletd CPU budget overflow")?;
        ensure!(required_cpu <= cpu, "node, host reserve and lightwalletd exceed effective CPU; reduce the node budget explicitly");
        let endpoint = rpc_endpoint(host)?;
        ensure!(
            ![9067, 9068].contains(&endpoint.port()),
            "node RPC port conflicts with private lightwalletd services"
        );
        Ok(())
    }
}

pub fn render_service(
    host: &HostInstallSpec,
    service: &LightwalletServiceSpec,
) -> Result<RenderedLightwalletService> {
    service.validate(host)?;
    let service_sha256 = hash(&serde_json::to_vec(
        &serde_json::json!({"host": host, "service": service}),
    )?);
    let cache_root = format!(
        "/var/lib/zdn-lightwalletd/deployments/{}/nodes/{}/chains/{}",
        host.deployment_id, host.node_id, host.consensus_fingerprint
    );
    let runtime_root = format!(
        "/run/zdn-lightwalletd/{}-{}",
        host.deployment_id, host.node_id
    );
    let credential_path = format!("{runtime_root}/credentials/zcash.conf");
    let identity = serde_json::json!({"apiVersion": API_VERSION, "deploymentId": host.deployment_id,
        "nodeId": host.node_id, "consensusFingerprint": host.consensus_fingerprint,
        "volumeId": service.cache_volume_id, "cacheBytes": service.cache_bytes, "serviceSha256": service_sha256});
    let container = format!("zdn-lightwalletd-{}-{}", host.deployment_id, host.node_id);
    let arguments = vec![
        "run".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--name".into(),
        container.clone(),
        "--platform".into(),
        "linux/amd64".into(),
        "--network".into(),
        "host".into(),
        "--user".into(),
        "10001:10001".into(),
        "--workdir".into(),
        "/".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--no-healthcheck".into(),
        "--stop-signal".into(),
        "SIGTERM".into(),
        "--stop-timeout".into(),
        "30".into(),
        "--pids-limit".into(),
        "256".into(),
        "--memory".into(),
        service.memory_bytes.to_string(),
        "--memory-swap".into(),
        service.memory_bytes.to_string(),
        "--cpus".into(),
        format!(
            "{}.{:03}",
            service.cpu_millis / 1000,
            service.cpu_millis % 1000
        ),
        "--log-driver".into(),
        "journald".into(),
        "--label".into(),
        format!("zdn.lightwalletd={service_sha256}"),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777".into(),
        "--mount".into(),
        format!("type=bind,src={cache_root}/data,dst=/var/lib/lightwalletd"),
        "--mount".into(),
        format!("type=bind,src={runtime_root}/credentials,dst=/run/zdn-lightwalletd,readonly"),
        "--entrypoint".into(),
        "/usr/bin/env".into(),
        service.image.clone(),
        "-i".into(),
        "PATH=/usr/local/bin:/usr/bin:/bin".into(),
        "HOME=/nonexistent".into(),
        "/usr/local/bin/lightwalletd".into(),
        "--grpc-bind-addr".into(),
        GRPC_ENDPOINT.into(),
        "--http-bind-addr".into(),
        HTTP_ENDPOINT.into(),
        "--no-tls-very-insecure".into(),
        "--zcash-conf-path".into(),
        "/run/zdn-lightwalletd/zcash.conf".into(),
        "--data-dir".into(),
        "/var/lib/lightwalletd".into(),
        "--log-level".into(),
        "4".into(),
        "--log-file".into(),
        "/dev/stdout".into(),
    ];
    Ok(RenderedLightwalletService {
        api_version: API_VERSION.into(), service_sha256,
        docker_arguments: arguments, cache_root, cache_identity_json: serde_json::to_string_pretty(&identity)?,
        credential_path, grpc_endpoint: GRPC_ENDPOINT.into(), http_endpoint: HTTP_ENDPOINT.into(),
        qualification: "pending".into(), deployment_ready: false, launch_ready: false,
        remaining_requirements: vec!["qualify the pinned lightwalletd image with the selected Ironwood chain and wallet".into(),
            "allocate, identify, mount and retain or delete the dedicated cache EBS volume".into(),
            "install the verified image, service files and exact cache identity through the owned host lifecycle".into(),
            "qualify cookie rotation, resource budgets and private gRPC readiness on a real host".into()],
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_service.rpc_endpoint")
)]
fn rpc_endpoint(host: &HostInstallSpec) -> Result<SocketAddr> {
    let config: toml::Value = toml::from_str(&host.config_toml)?;
    config
        .get("rpc")
        .and_then(|rpc| rpc.get("listen_addr"))
        .and_then(toml::Value::as_str)
        .context("host config has no RPC endpoint")?
        .parse()
        .context("invalid node RPC endpoint")
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
