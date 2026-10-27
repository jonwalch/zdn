//! Pure rendering of a candidate Zakura network configuration fragment.
//!
//! The adapter follows `DTestnetParameters` and the network bootstrap settings
//! in `node/zakura/crates/zakura-network/src/config.rs`, the configured types in
//! `zakura-chain/src/parameters/network/testnet.rs`, and the address and hash
//! encodings in `zakura-chain/src/{transparent/address,block/hash}.rs` at research
//! commit `860203d4d39a480c145f9c04bdf0d1dd08ab0625`. Compact targets follow
//! `zakura-chain/src/work/difficulty.rs`; their expansion here is an encoding
//! conversion, not a difficulty or consensus check. No node code is imported.
//!
//! This is not a complete launch configuration or evidence of node acceptance.
//! It does not load saved blocks, configure state/RPC/mining, check monetary or
//! funding-period rules, or qualify a client. Explicit peers may still advertise
//! other peers: disabling public seed lists and peer caches is not a firewall.

use super::manifest::{ConsensusManifest, FundingReceiver, ProofOfWork};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
};

pub const API_VERSION: &str = "zdn-zakura-config/v1alpha1";
pub const ADAPTER: &str = "zakura-network-toml/v1alpha1";
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOML_BYTES: usize = 8 * 1024 * 1024;
const MAX_PEERS: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 64;
const MAX_NAME_BYTES: usize = 30;
const RESERVED_NAMES: [&str; 6] = [
    "Mainnet",
    "Testnet",
    "Regtest",
    "MainnetKind",
    "TestnetKind",
    "RegtestKind",
];

/// Runtime settings are outside the consensus fingerprint. Numeric peer
/// endpoints avoid DNS resolution or implicit ports while rendering offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderOptions {
    /// Optional 1–30 byte ASCII name containing letters, digits, or underscores.
    /// Unlike Zakura's wider name syntax, zdn rejects reserved names in any case.
    pub network_name: Option<String>,
    /// Numeric unicast IP and explicit nonzero port; unspecified listeners are
    /// deliberately outside this narrow candidate-fragment interface.
    pub listen_addr: String,
    /// At most 128 numeric unicast endpoints. IPv4-mapped IPv6 addresses are
    /// normalized to IPv4, then the endpoints are sorted and deduplicated.
    pub peers: Vec<String>,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            network_name: None,
            listen_addr: "127.0.0.1:18233".into(),
            peers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedNetworkConfig {
    pub api_version: String,
    pub adapter: String,
    pub scope: String,
    pub consensus_fingerprint: String,
    /// SHA-256 of the exact UTF-8 `config_toml` bytes, including its newline.
    pub config_sha256: String,
    pub config_toml: String,
    pub node_config_validated: bool,
    pub qualification: String,
    pub launch_ready: bool,
}

/// Render without reading files, resolving addresses, invoking a node, or
/// changing state. Unsupported manifest rules fail before returning any config.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.node_config.render")
)]
pub fn render_network_config(
    manifest: &ConsensusManifest,
    options: &RenderOptions,
) -> Result<RenderedNetworkConfig> {
    // Bound direct library callers as well as the CLI before normalization
    // clones the manifest. Defaults can increase the normalized size slightly.
    check_manifest_size(manifest)?;
    let manifest = manifest.normalized()?;
    check_manifest_size(&manifest)?;
    let orchard_height = manifest
        .temporary_orchard_disabling_height
        .context("Zakura custom Testnet configuration cannot disable the temporary Orchard rule")?;
    ensure!(
        !manifest.subsidy.allow_unshielded_coinbase_spends,
        "Zakura custom Testnet configuration cannot allow unshielded coinbase spends"
    );
    ensure!(
        manifest.experimental_slh.is_none(),
        "Zakura custom Testnet configuration does not support experimental SLH"
    );

    ensure!(
        options.peers.len() <= MAX_PEERS,
        "at most {MAX_PEERS} explicit peers are supported"
    );
    if let Some(name) = &options.network_name {
        validate_name(name)?;
    }
    let listen_addr = endpoint(&options.listen_addr, "listen address")?;
    let peers = options
        .peers
        .iter()
        .map(|peer| endpoint(peer, "peer address"))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect();
    let fingerprint = manifest.fingerprint()?;
    let network_name = options
        .network_name
        .clone()
        .unwrap_or_else(|| format!("zdn_{}", &fingerprint[..16]));

    let mut network_magic = [0; 4];
    hex::decode_to_slice(&manifest.network_magic, &mut network_magic)?;
    let upgrades = &manifest.upgrades;
    let mut activation_heights = BTreeMap::from([
        ("BeforeOverwinter", upgrades.before_overwinter),
        ("Overwinter", upgrades.overwinter),
        ("Sapling", upgrades.sapling),
        ("Blossom", upgrades.blossom),
        ("Heartwood", upgrades.heartwood),
        ("Canopy", upgrades.canopy),
        ("NU5", upgrades.nu5),
        ("NU6", upgrades.nu6),
        ("NU6.1", upgrades.nu6_1),
        ("NU6.2", upgrades.nu6_2),
        ("NU6.3", upgrades.nu6_3),
    ]);
    if let Some(height) = upgrades.nu7 {
        activation_heights.insert("NU7", height);
    }

    let funding_streams = manifest
        .subsidy
        .funding_streams
        .iter()
        .map(|stream| {
            Ok(FundingStreamConfig {
                height_range: HeightRange {
                    start: stream.start_height,
                    end: stream.end_height,
                },
                recipients: stream
                    .recipients
                    .iter()
                    .map(|recipient| {
                        Ok(FundingRecipientConfig {
                            receiver: match recipient.receiver {
                                FundingReceiver::Ecc => "ECC",
                                FundingReceiver::ZcashFoundation => "ZcashFoundation",
                                FundingReceiver::MajorGrants => "MajorGrants",
                                FundingReceiver::Deferred => "Deferred",
                            },
                            numerator: recipient.numerator,
                            addresses: recipient
                                .script_hashes
                                .iter()
                                .map(|hash| testnet_p2sh_address(hash))
                                .collect::<Result<_>>()?,
                        })
                    })
                    .collect::<Result<_>>()?,
            })
        })
        .collect::<Result<_>>()?;
    let lockbox_disbursements = manifest
        .subsidy
        .lockbox_disbursements
        .iter()
        .map(|output| {
            Ok(LockboxConfig {
                address: testnet_p2sh_address(&output.script_hash)?,
                amount: output.amount,
            })
        })
        .collect::<Result<_>>()?;
    let checkpoints = manifest
        .checkpoints
        .iter()
        .map(|checkpoint| {
            let mut hash = [0; 32];
            hex::decode_to_slice(&checkpoint.hash, &mut hash)?;
            // Zakura's derived serde for block::Hash uses internal byte order,
            // unlike its display/FromStr form used by genesis_hash.
            hash.reverse();
            Ok((checkpoint.height, hash))
        })
        .collect::<Result<_>>()?;

    let config = ConfigFragment {
        network: NetworkConfig {
            listen_addr,
            initial_mainnet_peers: [],
            initial_testnet_peers: peers,
            cache_dir: false,
            p2p_stack: "legacy",
            network: TestnetConfig {
                network_name,
                network_magic,
                slow_start_interval: manifest.subsidy.slow_start_interval,
                target_difficulty_limit: expanded_target_hex(
                    &manifest.difficulty.target_difficulty_limit_compact,
                )?,
                disable_pow: manifest.difficulty.proof_of_work == ProofOfWork::Disabled,
                max_block_time_start_height: manifest.difficulty.max_block_time_start_height,
                genesis_hash: manifest.genesis.hash,
                pre_blossom_halving_interval: manifest.subsidy.pre_blossom_halving_interval,
                extend_funding_stream_addresses_as_required: false,
                temporary_orchard_disabling_soft_fork_height: orchard_height,
                initial_nsm_value_balance: manifest.subsidy.initial_nsm_value_balance,
                checkpoints,
                activation_heights,
                funding_streams,
                lockbox_disbursements,
            },
            zakura: NativeConfig {
                bootstrap_peers: [],
            },
        },
    };
    let config_toml = toml::to_string(&config).context("serialize Zakura network configuration")?;
    ensure!(
        config_toml.len() <= MAX_TOML_BYTES,
        "rendered Zakura network configuration exceeds 8 MiB"
    );
    Ok(RenderedNetworkConfig {
        api_version: API_VERSION.into(),
        adapter: ADAPTER.into(),
        scope: "network".into(),
        consensus_fingerprint: fingerprint,
        config_sha256: hex::encode(Sha256::digest(config_toml.as_bytes())),
        config_toml,
        node_config_validated: false,
        qualification: "pending".into(),
        launch_ready: false,
    })
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_NAME_BYTES
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "network name must contain 1 to {MAX_NAME_BYTES} ASCII letters, digits, or underscores"
    );
    ensure!(
        !RESERVED_NAMES
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved)),
        "network name matches a Zakura reserved name (case-insensitive)"
    );
    Ok(())
}

fn endpoint(value: &str, kind: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_ENDPOINT_BYTES,
        "{kind} must be a bounded numeric IP address with an explicit port"
    );
    let address: SocketAddr = value
        .parse()
        .with_context(|| format!("{kind} must be a numeric IP address with an explicit port"))?;
    ensure!(address.port() != 0, "{kind} cannot use port zero");
    if let SocketAddr::V6(ipv6) = address {
        ensure!(ipv6.scope_id() == 0, "{kind} cannot use an IPv6 scope ID");
    }
    let ip = match address.ip() {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
        ip => ip,
    };
    ensure!(
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V4(ipv4) if ipv4.is_broadcast()),
        "{kind} must be a unicast address, not unspecified, multicast, or broadcast"
    );
    Ok(SocketAddr::new(ip, address.port()).to_string())
}

fn testnet_p2sh_address(script_hash: &str) -> Result<String> {
    let mut payload = [0; 22];
    // Zcash Testnet P2SH address prefix. Manifest bytes are already script order.
    payload[..2].copy_from_slice(&[0x1c, 0xba]);
    hex::decode_to_slice(script_hash, &mut payload[2..])?;
    Ok(bs58::encode(payload).with_check().into_string())
}

fn expanded_target_hex(compact: &str) -> Result<String> {
    let compact = u32::from_str_radix(compact, 16)?;
    let exponent = (compact >> 24) as usize;
    let coefficient = compact & 0x00ff_ffff;
    let mut expanded = [0; 32];
    if exponent <= 3 {
        let value = coefficient >> (8 * (3 - exponent));
        expanded[28..].copy_from_slice(&value.to_be_bytes());
    } else {
        // A valid exponent of 33 has a leading zero sign-padding byte, which
        // lies just outside the 256-bit field and is intentionally omitted.
        for (index, byte) in coefficient.to_be_bytes()[1..].iter().enumerate() {
            let offset = 32 + index;
            if offset >= exponent {
                expanded[offset - exponent] = *byte;
            } else {
                ensure!(*byte == 0, "expanded compact target exceeds 256 bits");
            }
        }
    }
    // The node's uint-generated U256::FromStr parses hexadecimal; Display is decimal.
    Ok(format!("0x{}", hex::encode(expanded)))
}

fn check_manifest_size(manifest: &ConsensusManifest) -> Result<()> {
    struct BoundedCounter(usize);
    impl Write for BoundedCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_MANIFEST_BYTES.saturating_sub(self.0) {
                return Err(io::Error::other("manifest exceeds 2 MiB"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(BoundedCounter(0), manifest)
        .context("network configuration manifest must fit within 2 MiB")
}

#[derive(Serialize)]
struct ConfigFragment {
    network: NetworkConfig,
}

#[derive(Serialize)]
struct NetworkConfig {
    listen_addr: String,
    initial_mainnet_peers: [String; 0],
    initial_testnet_peers: Vec<String>,
    cache_dir: bool,
    p2p_stack: &'static str,
    network: TestnetConfig,
    zakura: NativeConfig,
}

#[derive(Serialize)]
struct NativeConfig {
    bootstrap_peers: [String; 0],
}

#[derive(Serialize)]
struct TestnetConfig {
    network_name: String,
    network_magic: [u8; 4],
    slow_start_interval: u32,
    target_difficulty_limit: String,
    disable_pow: bool,
    max_block_time_start_height: u32,
    genesis_hash: String,
    pre_blossom_halving_interval: u32,
    extend_funding_stream_addresses_as_required: bool,
    temporary_orchard_disabling_soft_fork_height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_nsm_value_balance: Option<u64>,
    checkpoints: Vec<(u32, [u8; 32])>,
    activation_heights: BTreeMap<&'static str, u32>,
    funding_streams: Vec<FundingStreamConfig>,
    lockbox_disbursements: Vec<LockboxConfig>,
}

#[derive(Serialize)]
struct FundingStreamConfig {
    height_range: HeightRange,
    recipients: Vec<FundingRecipientConfig>,
}

#[derive(Serialize)]
struct HeightRange {
    start: u32,
    end: u32,
}

#[derive(Serialize)]
struct FundingRecipientConfig {
    receiver: &'static str,
    numerator: u64,
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct LockboxConfig {
    address: String,
    amount: u64,
}
