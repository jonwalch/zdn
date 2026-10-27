//! Immutable first-install contract for a private AL2023 Zakura host.
//!
//! Rendering is offline. The resulting script is run through SSM only after
//! the expected EBS volume is attached. A separate activation step starts the
//! persistent controller only after the complete cluster has been seeded.

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use uuid::{Uuid, Variant};

use crate::chain::{
    node_config::RenderOptions,
    runtime_config::{NodeRole, RuntimeOptions},
};

#[cfg(target_os = "linux")]
pub mod artifact_delivery;
pub mod capacity;
pub mod capacity_bootstrap;
#[cfg(target_os = "linux")]
pub mod command;
#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod files;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod image_delivery;
#[cfg(target_os = "linux")]
pub mod inputs;
pub mod installer_bootstrap;
#[cfg(target_os = "linux")]
pub mod node_paths;
#[cfg(target_os = "linux")]
pub mod producer;
#[cfg(target_os = "linux")]
pub mod readiness;
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod volume;

pub const API_VERSION: &str = "zdn-host-install/v1alpha1";
pub const CAPACITY_PROTOCOL: &str = "zdn-host-capacity/v1alpha1";
pub const DATA_ROOT: &str = "/var/lib/zdn";
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct S3Object {
    pub bucket: String,
    pub key: String,
    pub sha256: String,
    pub bytes: u64,
    pub owner_account: String,
    pub region: String,
}

impl S3Object {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.s3_object.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (3..=63).contains(&self.bucket.len())
                && self
                    .bucket
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && self.bucket.as_bytes()[0].is_ascii_alphanumeric()
                && self.bucket.as_bytes()[self.bucket.len() - 1].is_ascii_alphanumeric(),
            "host artifacts require a canonical, non-dotted S3 bucket name"
        );
        ensure!(
            !self.key.is_empty()
                && self.key.len() <= 1024
                && self
                    .key
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != "..")
                && self
                    .key
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c)),
            "invalid host artifact key"
        );
        digest(&self.sha256)?;
        ensure!(
            (1..=MAX_ARTIFACT_BYTES).contains(&self.bytes),
            "host artifact size is out of bounds"
        );
        ensure!(
            self.owner_account.len() == 12
                && self.owner_account.bytes().all(|b| b.is_ascii_digit()),
            "invalid artifact owner account"
        );
        ensure!(
            !self.region.is_empty()
                && self.region.len() <= 32
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !self.region.starts_with("cn-")
                && !self.region.starts_with("us-gov-"),
            "invalid artifact region"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewVolumeAuthorization {
    pub api_version: String,
    pub volume_id: String,
    pub instance_id: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub creation_intent_sha256: String,
    pub checkpoint_sha256: String,
}

pub const NEW_VOLUME_API_VERSION: &str = "zdn-new-ebs-volume/v1alpha1";

impl NewVolumeAuthorization {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.new_volume_authorization.validate")
    )]
    pub fn validate(&self, volume_id: &str) -> Result<()> {
        ensure!(
            self.api_version == NEW_VOLUME_API_VERSION && self.volume_id == volume_id,
            "new-volume authorization belongs to another volume or version"
        );
        let id = self
            .instance_id
            .strip_prefix("i-")
            .context("new-volume authorization requires an EC2 instance")?;
        ensure!(
            [8, 17].contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid new-volume instance ID"
        );
        ensure!(
            (1024 * 1024 * 1024..=2 * 1024u64.pow(4)).contains(&self.size_bytes)
                && self.size_bytes.is_multiple_of(1024 * 1024 * 1024),
            "invalid new-volume size"
        );
        ensure!(
            (20..=64).contains(&self.created_at.len())
                && self
                    .created_at
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"-:TZ+.".contains(&b)),
            "invalid new-volume creation time"
        );
        digest(&self.creation_intent_sha256)?;
        digest(&self.checkpoint_sha256)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostInstallSpec {
    pub api_version: String,
    pub deployment_id: Uuid,
    pub node_id: String,
    pub consensus_fingerprint: String,
    pub volume_id: String,
    pub image: String,
    pub config_toml: String,
    pub config_sha256: String,
    pub role: String,
    /// A durable producer cannot change cadence during an unchanged install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_interval_seconds: Option<u64>,
    pub memory_bytes: u64,
    pub host_reserve_bytes: u64,
    pub cpu_millis: u32,
    pub manifest: S3Object,
    pub bundle: S3Object,
    pub helper: S3Object,
    pub image_record: S3Object,
    pub image_manifest: S3Object,
    /// Issued only by the controller after checking the saved create intent,
    /// managed Pulumi checkpoint and exact AWS volume. Legacy installs omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_volume: Option<NewVolumeAuthorization>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedHostInstall {
    pub api_version: String,
    pub install_sha256: String,
    pub script_sha256: String,
    pub script: String,
    pub node_root: String,
    pub rpc_endpoint: String,
    pub qualification: String,
    pub launch_ready: bool,
}

impl HostInstallSpec {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.install_spec.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported host install version"
        );
        ensure!(
            self.deployment_id.get_version_num() == 4
                && self.deployment_id.get_variant() == Variant::RFC4122,
            "host deployment ID must be UUIDv4"
        );
        let node = self.node_id.as_bytes();
        ensure!(
            !node.is_empty()
                && node.len() <= 63
                && node
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                && node[0].is_ascii_alphanumeric()
                && node[node.len() - 1].is_ascii_alphanumeric(),
            "invalid host node ID"
        );
        digest(&self.consensus_fingerprint)?;
        digest(&self.config_sha256)?;
        ensure!(
            self.config_toml.len() <= 8 * 1024 * 1024
                && hash(self.config_toml.as_bytes()) == self.config_sha256,
            "host configuration SHA-256 mismatch"
        );
        let volume = self
            .volume_id
            .strip_prefix("vol-")
            .context("expected EBS volume ID")?;
        ensure!(
            [8, 17].contains(&volume.len())
                && volume
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid EBS volume ID"
        );
        if let Some(authorization) = &self.new_volume {
            authorization.validate(&self.volume_id)?;
        }
        ensure!(
            matches!(self.role.as_str(), "producer" | "follower"),
            "invalid host node role"
        );
        ensure!(
            self.block_interval_seconds.is_none()
                || self.role != "producer"
                || self.node_id == "node-1",
            "only node-1 can own the block controller"
        );
        ensure!(
            self.block_interval_seconds
                .is_none_or(|seconds| (1..=86_400).contains(&seconds)),
            "host block interval must be between 1 and 86400 seconds"
        );
        ensure!(
            (1024 * 1024 * 1024..=512 * 1024 * 1024 * 1024).contains(&self.memory_bytes),
            "host node memory limit is out of bounds"
        );
        ensure!(
            (1024 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.host_reserve_bytes),
            "host memory reserve is out of bounds"
        );
        ensure!(
            (250..=128_000).contains(&self.cpu_millis),
            "host node CPU limit is out of bounds"
        );
        for object in [
            &self.manifest,
            &self.bundle,
            &self.helper,
            &self.image_record,
            &self.image_manifest,
        ] {
            object.validate()?;
            ensure!(
                object.owner_account == self.helper.owner_account
                    && object.region == self.helper.region
                    && object.bucket == self.helper.bucket,
                "host artifacts must share their team bucket, region and owner"
            );
        }
        self.validate_image(&self.image)?;
        self.runtime_arguments()?;
        Ok(())
    }

    /// Image revisions retain the original installation's regional authority.
    pub(crate) fn validate_image(&self, image: &str) -> Result<()> {
        let registry = format!(
            "{}.dkr.ecr.{}.amazonaws.com/",
            self.helper.owner_account, self.helper.region
        );
        let reference = image
            .strip_prefix(&registry)
            .context("host image must use the artifact account's regional private ECR registry")?;
        let (repository, image_digest) = reference
            .split_once("@sha256:")
            .context("host image must be pinned by SHA-256")?;
        digest(image_digest)?;
        ensure!(
            repository.starts_with("zdn/")
                && repository.len() <= 256
                && repository
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != "..")
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/._-".contains(&b)),
            "invalid host image repository"
        );
        Ok(())
    }

    /// Exact first-install identity without constructing the installer script.
    /// Validation includes runtime paths, private listeners and mining policy.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.install_spec.install_sha256")
    )]
    pub fn install_sha256(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        serde_json::to_writer(&mut digest, self)?;
        Ok(hex::encode(digest.finalize()))
    }

    pub fn node_root(&self) -> String {
        format!(
            "{DATA_ROOT}/deployments/{}/nodes/{}/chains/{}",
            self.deployment_id, self.node_id, self.consensus_fingerprint
        )
    }

    /// Re-render with the fetched manifest before any EBS mutation. That catches
    /// arbitrary extra TOML settings as well as mismatched declared paths.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.install_spec.runtime_options")
    )]
    fn runtime_options(&self) -> Result<RuntimeOptions> {
        let config: toml::Value =
            toml::from_str(&self.config_toml).context("decode host runtime configuration")?;
        let network = config
            .get("network")
            .context("host config has no network")?;
        let listener = field_str(network, "listen_addr")?;
        private_peer(listener)?;
        let rpc = config.get("rpc").context("host config has no RPC")?;
        let endpoint = field_str(rpc, "listen_addr")?;
        let parsed: SocketAddr = endpoint.parse().context("invalid host RPC endpoint")?;
        ensure!(
            parsed.ip().is_loopback() && parsed.port() != 0,
            "host RPC must listen on numeric loopback"
        );
        let root = self.node_root();
        ensure!(
            field_str(
                config.get("state").context("host config has no state")?,
                "cache_dir"
            )? == format!("{root}/state"),
            "host state path does not match its identity"
        );
        ensure!(
            field_str(network, "identity_dir")? == format!("{root}/identity"),
            "host peer identity path does not match its identity"
        );
        ensure!(
            field_str(rpc, "cookie_dir")? == format!("{root}/rpc")
                && field_str(rpc, "cookie_file_name")? == ".cookie",
            "host RPC cookie path does not match its identity"
        );
        ensure!(
            rpc.get("enable_cookie_auth").and_then(toml::Value::as_bool) == Some(true),
            "host RPC requires cookie authentication"
        );
        let mining = config
            .get("mining")
            .context("host config has no mining policy")?;
        ensure!(
            mining.get("internal_miner").and_then(toml::Value::as_bool) == Some(false),
            "host internal miner must remain stopped"
        );
        let mut peers = Vec::new();
        for peer in network
            .get("initial_testnet_peers")
            .and_then(toml::Value::as_array)
            .context("host configuration has no private peer list")?
        {
            let peer = peer.as_str().context("invalid private peer")?;
            private_peer(peer)?;
            peers.push(peer.into());
        }
        let reward_address = if self.role == "producer" {
            Some(field_str(mining, "miner_address")?.into())
        } else {
            ensure!(
                mining.get("miner_address").is_none(),
                "follower has a reward address"
            );
            None
        };
        Ok(RuntimeOptions {
            network: RenderOptions {
                network_name: None,
                listen_addr: listener.into(),
                peers,
            },
            deployment_id: self.deployment_id,
            node_id: self.node_id.clone(),
            data_root: DATA_ROOT.into(),
            rpc_listen_addr: endpoint.into(),
            role: if self.role == "producer" {
                NodeRole::Producer
            } else {
                NodeRole::Follower
            },
            reward_address,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.install_spec.runtime_arguments")
    )]
    pub(crate) fn runtime_arguments(&self) -> Result<(Vec<String>, String)> {
        let options = self.runtime_options()?;
        let mut args = vec![
            "chain".into(),
            "render-runtime".into(),
            "--manifest".into(),
            "/etc/zdn/artifacts/manifest.json".into(),
            "--deployment-id".into(),
            self.deployment_id.to_string(),
            "--node-id".into(),
            self.node_id.clone(),
            "--listen-addr".into(),
            options.network.listen_addr,
            "--rpc-listen-addr".into(),
            options.rpc_listen_addr.clone(),
            "--role".into(),
            self.role.clone(),
        ];
        for peer in options.network.peers {
            args.extend(["--peer".into(), peer]);
        }
        if let Some(address) = options.reward_address {
            args.extend(["--reward-address".into(), address]);
        }
        Ok((args, options.rpc_listen_addr))
    }
}

/// Cloud-init only installs host prerequisites. It never guesses a data device
/// or starts a node before Pulumi has attached the expected EBS volume.
pub fn base_user_data() -> &'static str {
    r#"#!/bin/bash
set -euo pipefail
umask 077
test "$(uname -m)" = x86_64
. /etc/os-release
test "$ID" = amzn
test "$VERSION_ID" = 2023
dnf install -y docker awscli-2 amazon-ssm-agent e2fsprogs util-linux iptables-nft
systemctl enable --now docker amazon-ssm-agent
ready=/etc/zdn-prerequisites-ready
pending=$(mktemp /etc/.zdn-prerequisites-ready.XXXXXXXX)
trap 'rm -f -- "$pending"' EXIT
printf '%s\n' 'zdn-host-prerequisites/v1alpha1' >"$pending"
chown root:root "$pending"
chmod 0600 "$pending"
mv -T -- "$pending" "$ready"
"#
}

fn field_str<'a>(value: &'a toml::Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(toml::Value::as_str)
        .with_context(|| format!("host config has no {name}"))
}

fn private_peer(text: &str) -> Result<()> {
    let peer: SocketAddr = text.parse().context("invalid private peer endpoint")?;
    ensure!(
        matches!(peer.ip(), IpAddr::V4(ip) if ip.is_private()) && peer.port() != 0,
        "AWS host P2P must use an RFC1918 IPv4 endpoint"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.digest")
)]
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected lowercase SHA-256"
    );
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
