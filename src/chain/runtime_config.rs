//! Candidate Zakura runtime configuration and a declarative startup recipe.
//!
//! Fields follow `ZakuradConfig`, the state/network/RPC/mining/consensus configs,
//! mempool, tracing, metrics, health and zcashd-compat configs in
//! `node/zakura/crates/` at research
//! commit `860203d4d39a480c145f9c04bdf0d1dd08ab0625`. The argv order follows
//! `zakurad/src/commands/entry_point.rs`; the binary path follows
//! `node/zakura/docker/Dockerfile`. Testnet transparent address versions follow
//! `zakura-chain/src/parameters/network.rs` and its pinned `zcash_protocol`.
//!
//! This module does not execute that recipe, create directories or secrets,
//! resolve filesystem paths, load seed history, or validate config with a node.
//! A future launcher must remove the reported environment prefixes, arrange
//! private writable directories and mount the exact config at `config_file`.
//! Rendered paths cannot establish filesystem ownership or exclude symlinks.

use super::{
    manifest::{ConsensusManifest, ProofOfWork},
    node_config::{render_network_config, RenderOptions},
};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use uuid::{Uuid, Variant};

pub const API_VERSION: &str = "zdn-zakura-runtime/v1alpha1";
pub const ADAPTER: &str = "zakura-runtime-toml/v1alpha1";
const MAX_DATA_ROOT_BYTES: usize = 512;
const MAX_NODE_ID_BYTES: usize = 63;
const MAX_ENDPOINT_BYTES: usize = 64;
const MAX_REWARD_ADDRESS_BYTES: usize = 64;
const MAX_TOML_BYTES: usize = 8 * 1024 * 1024;

/// A declared generation role, not an RPC authorization boundary. An
/// authenticated primary listener exposes the node's full RPC method set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Producer,
    Follower,
}

/// Per-node settings that do not change the consensus fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeOptions {
    pub network: RenderOptions,
    /// The deployment UUID from the devnet binding, not the chain fingerprint.
    pub deployment_id: Uuid,
    /// 1–63 lowercase ASCII letters, digits or hyphens, with alphanumeric ends.
    pub node_id: String,
    /// Canonical absolute Linux container directory. Rendering does not inspect
    /// the local or future container filesystem.
    pub data_root: String,
    /// Numeric loopback IP with an explicit nonzero port.
    pub rpc_listen_addr: String,
    pub role: NodeRole,
    /// Required for a producer; forbidden for a follower. This initial adapter
    /// accepts Testnet Base58Check P2PKH/P2SH addresses only. It does not prove
    /// ownership, a spend path, or reward-to-Ironwood compatibility.
    pub reward_address: Option<String>,
}

impl RuntimeOptions {
    pub fn new(deployment_id: Uuid, node_id: impl Into<String>) -> Self {
        Self {
            network: RenderOptions::default(),
            deployment_id,
            node_id: node_id.into(),
            data_root: "/var/lib/zdn".into(),
            rpc_listen_addr: "127.0.0.1:18232".into(),
            role: NodeRole::Follower,
            reward_address: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimePaths {
    pub node_root: String,
    pub state_dir: String,
    /// Kept outside the state snapshot subtree, even though the current legacy
    /// P2P stack does not use the native Zakura identity key.
    pub identity_dir: String,
    pub cookie_dir: String,
    pub cookie_file: String,
    pub config_file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedRuntimeConfig {
    pub api_version: String,
    pub adapter: String,
    pub scope: String,
    pub consensus_fingerprint: String,
    /// SHA-256 of the exact UTF-8 `config_toml`, including its final newline.
    pub config_sha256: String,
    pub config_toml: String,
    pub deployment_id: Uuid,
    pub node_id: String,
    pub role: NodeRole,
    pub paths: RuntimePaths,
    /// Declarative argv only. No process is run by the renderer.
    pub startup_argv: Vec<String>,
    /// The future launcher must remove these inherited environment variables.
    /// Zakura applies ZEBRA_/ZAKURA_ above TOML; OTEL_ can enable trace export.
    pub required_environment_removal_prefixes: Vec<String>,
    pub node_config_validated: bool,
    pub qualification: String,
    pub launch_ready: bool,
}

/// Render a full candidate node configuration without filesystem or process
/// effects. Node parsing, bootstrap, readiness and payment qualification remain
/// pending even when this offline conversion succeeds.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.runtime_config.render")
)]
pub fn render_runtime_config(
    manifest: &ConsensusManifest,
    options: &RuntimeOptions,
) -> Result<RenderedRuntimeConfig> {
    validate_deployment_id(options.deployment_id)?;
    validate_node_id(&options.node_id)?;
    validate_data_root(&options.data_root)?;
    let rpc_listen_addr = rpc_endpoint(&options.rpc_listen_addr)?;
    match options.role {
        NodeRole::Producer => {
            ensure!(
                manifest.difficulty.proof_of_work == ProofOfWork::Disabled,
                "the candidate producer requires disabled proof of work for generate RPC"
            );
            validate_reward_address(
                options
                    .reward_address
                    .as_deref()
                    .context("a producer requires a Testnet reward address")?,
            )?;
        }
        NodeRole::Follower => ensure!(
            options.reward_address.is_none(),
            "a follower must not specify a reward address"
        ),
    }

    let network_config = render_network_config(manifest, &options.network)?;
    // Zakura appends its network name to the state and non-finalized backup
    // directories. Pin that name so a display-name override cannot silently
    // select a different database under the same deployment/node/chain path.
    let expected_name = format!("zdn_{}", &network_config.consensus_fingerprint[..16]);
    ensure!(
        options
            .network
            .network_name
            .as_ref()
            .is_none_or(|name| name == &expected_name),
        "runtime network name must be the consensus-derived name {expected_name}"
    );
    let mut config: toml::Table = toml::from_str(&network_config.config_toml)
        .context("decode rendered network configuration")?;
    let network = config
        .get_mut("network")
        .and_then(toml::Value::as_table_mut)
        .context("rendered network configuration has no network table")?;
    let p2p_listen_addr: SocketAddr = network
        .get("listen_addr")
        .and_then(toml::Value::as_str)
        .context("rendered network configuration has no listen address")?
        .parse()
        .context("decode rendered P2P listener")?;
    ensure!(
        rpc_listen_addr != p2p_listen_addr,
        "RPC and P2P must use different listen endpoints"
    );

    // Include deployment, node, and consensus identity in the storage namespace.
    // This separates nodes on the same chain, separate deployments of that
    // chain, and changed rules within an existing deployment.
    let node_root = format!(
        "{}/deployments/{}/nodes/{}/chains/{}",
        options.data_root,
        options.deployment_id,
        options.node_id,
        network_config.consensus_fingerprint
    );
    let paths = RuntimePaths {
        state_dir: format!("{node_root}/state"),
        identity_dir: format!("{node_root}/identity"),
        cookie_dir: format!("{node_root}/rpc"),
        cookie_file: format!("{node_root}/rpc/.cookie"),
        config_file: format!("{node_root}/zakura.toml"),
        node_root,
    };
    network.insert(
        "identity_dir".into(),
        toml::Value::String(paths.identity_dir.clone()),
    );

    insert_section(
        &mut config,
        "state",
        &StateConfig {
            cache_dir: &paths.state_dir,
            ephemeral: false,
            should_backup_non_finalized_state: true,
            delete_old_database: false,
            storage_mode: "archive",
        },
    )?;
    insert_section(
        &mut config,
        "consensus",
        &ConsensusConfig {
            checkpoint_sync: true,
            vct_fast_sync: false,
        },
    )?;
    // The isolated development chain must not depend on a public-network tip
    // estimate or recent seed timestamps to enable its mempool. This affects
    // only the activation policy, not transaction or block validation. Waiting
    // for the highest declared history height does not itself prove that the
    // history matches: a future readiness check must still verify the hashes.
    let mempool_height = manifest
        .seed_blocks
        .iter()
        .map(|block| block.height)
        .chain(
            manifest
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.height),
        )
        .max()
        .unwrap_or(0);
    insert_section(
        &mut config,
        "mempool",
        &MempoolConfig {
            debug_enable_at_height: mempool_height,
        },
    )?;
    insert_section(
        &mut config,
        "rpc",
        &RpcConfig {
            listen_addr: rpc_listen_addr,
            cookie_dir: &paths.cookie_dir,
            cookie_file_name: ".cookie",
            enable_cookie_auth: true,
            debug_force_finished_sync: false,
        },
    )?;
    insert_section(
        &mut config,
        "mining",
        &MiningConfig {
            miner_address: options.reward_address.as_deref(),
            internal_miner: false,
            optimistic_block_inventory: false,
        },
    )?;
    insert_section(
        &mut config,
        "tracing",
        &TracingConfig {
            use_color: false,
            force_use_color: false,
            use_journald: false,
        },
    )?;
    insert_section(
        &mut config,
        "zcashd_compat",
        &ZcashdCompatConfig { enabled: false },
    )?;
    // TOML has no null value. Empty tables deliberately inherit the inspected
    // None listener defaults. RPC admin/indexer/TLS and tracing filter-control,
    // flamegraph, progress, file-log and OTLP options are likewise omitted.
    config.insert("metrics".into(), toml::Value::Table(toml::Table::new()));
    config.insert("health".into(), toml::Value::Table(toml::Table::new()));

    let config_toml = toml::to_string(&config).context("serialize Zakura runtime configuration")?;
    ensure!(
        config_toml.len() <= MAX_TOML_BYTES,
        "rendered Zakura runtime configuration exceeds 8 MiB"
    );
    Ok(RenderedRuntimeConfig {
        api_version: API_VERSION.into(),
        adapter: ADAPTER.into(),
        scope: "runtime".into(),
        consensus_fingerprint: network_config.consensus_fingerprint,
        config_sha256: hex::encode(Sha256::digest(config_toml.as_bytes())),
        config_toml,
        deployment_id: options.deployment_id,
        node_id: options.node_id.clone(),
        role: options.role,
        startup_argv: vec![
            "/usr/local/bin/zakurad".into(),
            "--config".into(),
            paths.config_file.clone(),
            "start".into(),
        ],
        paths,
        required_environment_removal_prefixes: vec![
            "ZAKURA_".into(),
            "ZEBRA_".into(),
            "OTEL_".into(),
        ],
        node_config_validated: false,
        qualification: "pending".into(),
        launch_ready: false,
    })
}

fn insert_section(config: &mut toml::Table, name: &str, section: &impl Serialize) -> Result<()> {
    config.insert(
        name.into(),
        toml::Value::try_from(section)
            .with_context(|| format!("encode Zakura {name} configuration"))?,
    );
    Ok(())
}

fn validate_deployment_id(id: Uuid) -> Result<()> {
    ensure!(
        id.get_version_num() == 4 && id.get_variant() == Variant::RFC4122,
        "deployment ID must be an RFC 4122 version 4 UUID"
    );
    Ok(())
}

fn validate_node_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty() && id.len() <= MAX_NODE_ID_BYTES,
        "node ID must contain 1 to {MAX_NODE_ID_BYTES} ASCII characters"
    );
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    ensure!(
        id.bytes().all(|b| alphanumeric(b) || b == b'-')
            && id.bytes().next().is_some_and(alphanumeric)
            && id.bytes().last().is_some_and(alphanumeric),
        "node ID must use lowercase letters, digits or hyphens with alphanumeric ends"
    );
    Ok(())
}

fn validate_data_root(path: &str) -> Result<()> {
    ensure!(
        path.len() > 1 && path.len() <= MAX_DATA_ROOT_BYTES && path.starts_with('/'),
        "data root must be a non-root absolute Linux path of at most {MAX_DATA_ROOT_BYTES} bytes"
    );
    for component in path[1..].split('/') {
        ensure!(
            !component.is_empty()
                && component.len() <= 255
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "data root must use canonical ASCII path components without empty, dot or parent segments"
        );
    }
    Ok(())
}

fn rpc_endpoint(text: &str) -> Result<SocketAddr> {
    ensure!(
        !text.is_empty() && text.len() <= MAX_ENDPOINT_BYTES,
        "RPC listen address must contain at most {MAX_ENDPOINT_BYTES} bytes"
    );
    let endpoint: SocketAddr = text
        .parse()
        .context("RPC listen address must be a numeric IP and explicit port")?;
    let normalized = match endpoint {
        SocketAddr::V4(_) => endpoint,
        SocketAddr::V6(v6) => {
            ensure!(
                v6.scope_id() == 0 && v6.flowinfo() == 0,
                "RPC listen address must not use an IPv6 scope ID or flow info"
            );
            match v6.ip().to_ipv4_mapped() {
                Some(ip) => SocketAddr::new(IpAddr::V4(ip), endpoint.port()),
                None => endpoint,
            }
        }
    };
    ensure!(
        normalized.ip().is_loopback() && normalized.port() != 0,
        "RPC listen address must use loopback and a nonzero port"
    );
    Ok(normalized)
}

fn validate_reward_address(address: &str) -> Result<()> {
    ensure!(
        !address.is_empty() && address.len() <= MAX_REWARD_ADDRESS_BYTES,
        "reward address must be a Testnet transparent Base58Check address"
    );
    let decoded = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .context("reward address must have valid Base58Check encoding and checksum")?;
    ensure!(
        decoded.len() == 22 && (decoded[..2] == [0x1d, 0x25] || decoded[..2] == [0x1c, 0xba]),
        "reward address must be a Testnet P2PKH or P2SH address with a 20-byte payload"
    );
    ensure!(
        bs58::encode(&decoded).with_check().into_string() == address,
        "reward address must use canonical Base58Check encoding"
    );
    Ok(())
}

#[derive(Serialize)]
struct StateConfig<'a> {
    cache_dir: &'a str,
    ephemeral: bool,
    should_backup_non_finalized_state: bool,
    delete_old_database: bool,
    storage_mode: &'a str,
}

#[derive(Serialize)]
struct ConsensusConfig {
    checkpoint_sync: bool,
    vct_fast_sync: bool,
}

#[derive(Serialize)]
struct MempoolConfig {
    debug_enable_at_height: u32,
}

#[derive(Serialize)]
struct RpcConfig<'a> {
    listen_addr: SocketAddr,
    cookie_dir: &'a str,
    cookie_file_name: &'a str,
    enable_cookie_auth: bool,
    debug_force_finished_sync: bool,
}

#[derive(Serialize)]
struct MiningConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    miner_address: Option<&'a str>,
    internal_miner: bool,
    optimistic_block_inventory: bool,
}

#[derive(Serialize)]
struct TracingConfig {
    use_color: bool,
    force_use_color: bool,
    use_journald: bool,
}

#[derive(Serialize)]
struct ZcashdCompatConfig {
    enabled: bool,
}
