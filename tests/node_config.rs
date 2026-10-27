//! Offline format checks, independent of the renderer's private structs/codecs.
//! These fixtures are synthetic and never establish node or chain acceptance.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zdn::chain::{
    manifest::{ConsensusManifest, LockboxDisbursement, ProofOfWork},
    node_config::{render_network_config, RenderOptions, RenderedNetworkConfig},
};

const INPUT: &str = include_str!("fixtures/chain-manifest/valid.json");
const VECTORS: &str = include_str!("fixtures/node-config/encoding-vectors.json");
const UPGRADE_NAMES: &[&str] = &[
    "BeforeOverwinter",
    "Overwinter",
    "Sapling",
    "Blossom",
    "Heartwood",
    "Canopy",
    "NU5",
    "NU6",
    "NU6.1",
    "NU6.2",
    "NU6.3",
];

// Required fields have no defaults: their absence must not silently inherit
// public-network settings. Deny unknown fields to catch extra runtime sections,
// misspelled names, and the incompatible Regtest-only testnet_parameters shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    network: Network,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    listen_addr: String,
    initial_mainnet_peers: Vec<String>,
    initial_testnet_peers: Vec<String>,
    cache_dir: bool,
    p2p_stack: String,
    network: Testnet,
    zakura: NativePeers,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePeers {
    bootstrap_peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Testnet {
    network_name: String,
    network_magic: [u8; 4],
    genesis_hash: String,
    checkpoints: Vec<(u32, [u8; 32])>,
    activation_heights: BTreeMap<String, u32>,
    slow_start_interval: u32,
    pre_blossom_halving_interval: u32,
    funding_streams: Vec<FundingStream>,
    lockbox_disbursements: Vec<Lockbox>,
    extend_funding_stream_addresses_as_required: bool,
    initial_nsm_value_balance: Option<u64>,
    target_difficulty_limit: String,
    disable_pow: bool,
    max_block_time_start_height: u32,
    temporary_orchard_disabling_soft_fork_height: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingStream {
    height_range: std::ops::Range<u32>,
    recipients: Vec<Recipient>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipient {
    receiver: String,
    numerator: u64,
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lockbox {
    address: String,
    amount: u64,
}

#[derive(Deserialize)]
struct EncodingVectors {
    p2sh: Vec<AddressVector>,
    difficulty: Vec<DifficultyVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressVector {
    script_hash: String,
    address: String,
}

#[derive(Deserialize)]
struct DifficultyVector {
    compact: String,
    expanded: String,
}

fn fixture() -> ConsensusManifest {
    serde_json::from_str(INPUT).unwrap()
}

fn input() -> Value {
    serde_json::from_str(INPUT).unwrap()
}

fn manifest(value: &Value) -> ConsensusManifest {
    serde_json::from_value(value.clone()).unwrap()
}

fn vectors() -> EncodingVectors {
    serde_json::from_str(VECTORS).unwrap()
}

fn parsed(report: &RenderedNetworkConfig) -> Fragment {
    toml::from_str(&report.config_toml).unwrap()
}

fn render(value: &Value) -> RenderedNetworkConfig {
    render_network_config(&manifest(value), &RenderOptions::default()).unwrap()
}

#[test]
fn default_fragment_is_explicit_and_only_claims_unqualified_network_rendering() {
    let manifest = fixture();
    let options = RenderOptions::default();
    assert_eq!(options.network_name, None);
    assert_eq!(options.listen_addr, "127.0.0.1:18233");
    assert!(options.peers.is_empty());
    let report = render_network_config(&manifest, &options).unwrap();
    let report_json = serde_json::to_value(&report).unwrap();
    assert_eq!(report_json["apiVersion"], "zdn-zakura-config/v1alpha1");
    assert_eq!(report_json["adapter"], "zakura-network-toml/v1alpha1");
    assert_eq!(report_json["scope"], "network");
    assert_eq!(report_json["nodeConfigValidated"], false);
    assert_eq!(report_json["qualification"], "pending");
    assert_eq!(report_json["launchReady"], false);
    assert_eq!(report_json.as_object().unwrap().len(), 9);
    assert_eq!(
        report.consensus_fingerprint,
        manifest.fingerprint().unwrap()
    );
    assert_eq!(
        report.config_sha256,
        hex::encode(Sha256::digest(report.config_toml.as_bytes()))
    );
    assert!(report.config_toml.ends_with('\n'));

    let network = parsed(&report).network;
    assert_eq!(network.listen_addr, "127.0.0.1:18233");
    assert!(network.initial_mainnet_peers.is_empty());
    assert!(network.initial_testnet_peers.is_empty());
    assert!(network.zakura.bootstrap_peers.is_empty());
    assert!(!network.cache_dir);
    assert_eq!(network.p2p_stack, "legacy");
    let testnet = network.network;
    assert_eq!(
        testnet.network_name,
        format!("zdn_{}", &report.consensus_fingerprint[..16])
    );
    assert_eq!(testnet.network_magic, [0xa1, 0xb2, 0xc3, 0xd4]);
    assert_eq!(testnet.genesis_hash, "ab".repeat(32));
    assert_eq!(testnet.checkpoints, vec![(0, [0xab; 32])]);
    assert_eq!(testnet.slow_start_interval, 0);
    assert_eq!(testnet.pre_blossom_halving_interval, 840_000);
    assert!(testnet.funding_streams.is_empty());
    assert_eq!(testnet.lockbox_disbursements.len(), 1);
    assert_eq!(testnet.lockbox_disbursements[0].amount, 0);
    assert!(!testnet.extend_funding_stream_addresses_as_required);
    assert_eq!(testnet.initial_nsm_value_balance, None);
    assert!(testnet.disable_pow);
    assert_eq!(testnet.max_block_time_start_height, 653_606);
    assert_eq!(
        testnet.temporary_orchard_disabling_soft_fork_height,
        4_048_500
    );
    let expected_upgrades: BTreeMap<_, _> = UPGRADE_NAMES
        .iter()
        .map(|name| ((*name).to_owned(), 1))
        .collect();
    assert_eq!(testnet.activation_heights, expected_upgrades);
}

#[test]
fn checkpoint_bytes_reverse_display_hashes_but_genesis_and_magic_do_not() {
    let mut value = input();
    let genesis: Vec<u8> = (0..32).collect();
    let later: Vec<u8> = (32..64).collect();
    value["genesis"]["hash"] = json!(hex::encode(&genesis));
    value["networkMagic"] = json!("017f80fe");
    value["checkpoints"] = json!([
        {"height": 50, "hash": hex::encode(&later)},
        {"height": 0, "hash": hex::encode(&genesis)}
    ]);
    let config = parsed(&render(&value)).network.network;
    assert_eq!(config.genesis_hash, hex::encode(&genesis));
    assert_eq!(config.network_magic, [1, 127, 128, 254]);
    assert_eq!(config.checkpoints.len(), 2);
    assert_eq!(config.checkpoints[0].0, 0);
    assert_eq!(config.checkpoints[1].0, 50);
    assert_eq!(
        config.checkpoints[0].1.to_vec(),
        (0..32).rev().collect::<Vec<u8>>()
    );
    assert_eq!(
        config.checkpoints[1].1.to_vec(),
        (32..64).rev().collect::<Vec<u8>>()
    );
}

#[test]
fn compact_targets_match_independent_python_integer_vectors() {
    for vector in vectors().difficulty {
        let mut manifest = fixture();
        manifest.difficulty.target_difficulty_limit_compact = vector.compact.clone();
        manifest.validate().unwrap();
        for pow in [ProofOfWork::Disabled, ProofOfWork::Equihash] {
            manifest.difficulty.proof_of_work = pow;
            let report = render_network_config(&manifest, &RenderOptions::default()).unwrap();
            let config = parsed(&report).network.network;
            assert_eq!(
                config.target_difficulty_limit, vector.expanded,
                "{}",
                vector.compact
            );
            assert_eq!(config.target_difficulty_limit.len(), 66);
            assert!(config.target_difficulty_limit.starts_with("0x"));
            assert_eq!(config.disable_pow, pow == ProofOfWork::Disabled);
            assert!(!report.launch_ready);
        }
    }
}

#[test]
fn testnet_p2sh_addresses_match_independent_python_hashlib_base58_vectors() {
    let mut manifest = fixture();
    let vectors = vectors().p2sh;
    manifest.subsidy.lockbox_disbursements = vectors
        .iter()
        .enumerate()
        .map(|(index, vector)| LockboxDisbursement {
            script_hash: vector.script_hash.clone(),
            amount: index as u64,
        })
        .collect();
    let report = render_network_config(&manifest, &RenderOptions::default()).unwrap();
    let config = parsed(&report).network.network;
    assert_eq!(config.lockbox_disbursements.len(), vectors.len());
    for (index, (output, vector)) in config.lockbox_disbursements.iter().zip(vectors).enumerate() {
        assert_eq!(
            output.address, vector.address,
            "script {}",
            vector.script_hash
        );
        assert_eq!(output.amount, index as u64);
    }
}

#[test]
fn funding_ranges_receivers_and_destination_period_order_survive_rendering() {
    let mut value = input();
    value["subsidy"]["fundingStreams"] = json!([
        {"startHeight": 30, "endHeight": 40, "recipients": []},
        {"startHeight": 10, "endHeight": 20, "recipients": [
            {"receiver": "zcash-foundation", "numerator": 5, "scriptHashes": ["12".repeat(20)]},
            {"receiver": "ecc", "numerator": 7, "scriptHashes": ["ff".repeat(20), "00".repeat(20), "ff".repeat(20)]},
            {"receiver": "major-grants", "numerator": 8, "scriptHashes": ["00".repeat(20)]},
            {"receiver": "deferred", "numerator": 9, "scriptHashes": []}
        ]}
    ]);
    let config = parsed(&render(&value)).network.network;
    assert_eq!(config.funding_streams.len(), 2);
    assert_eq!(config.funding_streams[0].height_range, 10..20);
    assert_eq!(config.funding_streams[1].height_range, 30..40);
    assert!(config.funding_streams[1].recipients.is_empty());
    let vectors = vectors().p2sh;
    let recipients: BTreeMap<_, _> = config.funding_streams[0]
        .recipients
        .iter()
        .map(|recipient| (recipient.receiver.as_str(), recipient))
        .collect();
    assert_eq!(recipients.len(), 4);
    assert_eq!(recipients["ECC"].numerator, 7);
    assert_eq!(
        recipients["ECC"].addresses,
        [
            vectors[3].address.clone(),
            vectors[0].address.clone(),
            vectors[3].address.clone()
        ]
    );
    assert_eq!(recipients["ZcashFoundation"].numerator, 5);
    assert_eq!(
        recipients["ZcashFoundation"].addresses,
        [vectors[2].address.clone()]
    );
    assert_eq!(recipients["MajorGrants"].numerator, 8);
    assert_eq!(
        recipients["MajorGrants"].addresses,
        [vectors[0].address.clone()]
    );
    assert_eq!(recipients["Deferred"].numerator, 9);
    assert!(recipients["Deferred"].addresses.is_empty());
    assert!(!config.extend_funding_stream_addresses_as_required);
}

#[test]
fn duplicate_lockbox_outputs_remain_separate_and_nsm_zero_differs_from_omission() {
    let mut value = input();
    value["subsidy"]["lockboxDisbursements"] = json!([
        {"scriptHash": "12".repeat(20), "amount": 75},
        {"scriptHash": "12".repeat(20), "amount": 75},
        {"scriptHash": "00".repeat(20), "amount": 0}
    ]);
    let unset = render(&value);
    let tree: toml::Value = toml::from_str(&unset.config_toml).unwrap();
    assert!(tree["network"]["network"]
        .get("initial_nsm_value_balance")
        .is_none());
    value["subsidy"]["initialNsmValueBalance"] = json!(0);
    let explicit = render(&value);
    let config = parsed(&explicit).network.network;
    assert_eq!(config.initial_nsm_value_balance, Some(0));
    assert_eq!(config.lockbox_disbursements.len(), 3);
    assert_eq!(config.lockbox_disbursements[0].amount, 0);
    assert_eq!(config.lockbox_disbursements[1].amount, 75);
    assert_eq!(config.lockbox_disbursements[2].amount, 75);
    assert_eq!(
        config.lockbox_disbursements[1].address,
        config.lockbox_disbursements[2].address
    );
    assert_ne!(unset.consensus_fingerprint, explicit.consensus_fingerprint);
    assert_ne!(unset.config_sha256, explicit.config_sha256);
}

#[test]
fn explicit_upgrade_schedule_includes_distinct_heights_and_optional_nu7() {
    let mut value = input();
    for (index, name) in UPGRADE_NAMES.iter().enumerate() {
        value["upgrades"][name] = json!(index + 1);
    }
    value["upgrades"]["NU7"] = json!(20);
    value["checkpoints"] = json!([
        {"height": 0, "hash": value["genesis"]["hash"]},
        {"height": 5, "hash": "bc".repeat(32)}
    ]);
    value["subsidy"]["slowStartInterval"] = json!(200);
    value["subsidy"]["preBlossomHalvingInterval"] = json!(1000);
    value["subsidy"]["initialNsmValueBalance"] = json!(123456);
    value["difficulty"]["maxBlockTimeStartHeight"] = json!(0);
    value["temporaryOrchardDisablingHeight"] = json!(0);
    let config = parsed(&render(&value)).network.network;
    assert_eq!(config.activation_heights.len(), UPGRADE_NAMES.len() + 1);
    for (index, name) in UPGRADE_NAMES.iter().enumerate() {
        assert_eq!(config.activation_heights[*name], index as u32 + 1);
    }
    assert_eq!(config.activation_heights["NU7"], 20);
    assert_eq!(config.slow_start_interval, 200);
    assert_eq!(config.pre_blossom_halving_interval, 1000);
    assert_eq!(config.initial_nsm_value_balance, Some(123456));
    assert_eq!(config.max_block_time_start_height, 0);
    assert_eq!(config.temporary_orchard_disabling_soft_fork_height, 0);
}

#[test]
fn peer_normalization_is_deterministic_and_changes_no_consensus_identity() {
    let manifest = fixture();
    let options = RenderOptions {
        network_name: Some("branch_ABC_1".into()),
        listen_addr: "[::ffff:127.0.0.1]:18233".into(),
        peers: vec![
            "[2001:0db8:0000::2]:18233".into(),
            "192.0.2.10:18233".into(),
            "[::ffff:192.0.2.10]:18233".into(),
            "[2001:db8::2]:18233".into(),
        ],
    };
    let first = render_network_config(&manifest, &options).unwrap();
    let mut canonical = options;
    canonical.listen_addr = "127.0.0.1:18233".into();
    canonical.peers = vec!["[2001:db8::2]:18233".into(), "192.0.2.10:18233".into()];
    let second = render_network_config(&manifest, &canonical).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.consensus_fingerprint, manifest.fingerprint().unwrap());
    let config = parsed(&first).network;
    assert_eq!(config.listen_addr, "127.0.0.1:18233");
    assert_eq!(
        config.initial_testnet_peers,
        ["192.0.2.10:18233", "[2001:db8::2]:18233"]
    );
    assert_eq!(config.network.network_name, "branch_ABC_1");
    assert!(config.initial_mainnet_peers.is_empty());
    assert!(config.zakura.bootstrap_peers.is_empty());
    assert!(!config.cache_dir);
    assert_eq!(config.p2p_stack, "legacy");
    for changed in [
        RenderOptions {
            network_name: Some("another_name".into()),
            ..canonical.clone()
        },
        RenderOptions {
            listen_addr: "127.0.0.1:18234".into(),
            ..canonical.clone()
        },
        RenderOptions {
            peers: vec!["192.0.2.10:18234".into()],
            ..canonical.clone()
        },
    ] {
        let report = render_network_config(&manifest, &changed).unwrap();
        assert_eq!(report.consensus_fingerprint, first.consensus_fingerprint);
        assert_ne!(report.config_sha256, first.config_sha256);
    }
}

#[test]
fn equivalent_manifest_spellings_render_the_same_bytes_and_report() {
    let value = input();
    let expected = render(&value);
    let mut equivalent = value;
    equivalent["networkMagic"] = json!("A1B2C3D4");
    equivalent["genesis"]["hash"] = json!("AB".repeat(32));
    equivalent["genesis"]["bytesSha256"] = json!("CD".repeat(32));
    equivalent["difficulty"]["targetDifficultyLimitCompact"] = json!("1F07FFFF");
    equivalent["checkpoints"] = json!([{"height": 0, "hash": "AB".repeat(32)}]);
    assert_eq!(render(&equivalent), expected);
}

#[test]
fn saved_block_claims_bind_identity_without_becoming_node_configuration() {
    let first = fixture();
    let mut changed = first.clone();
    changed.genesis.bytes_sha256 = "01".repeat(32);
    changed.genesis.bytes_length = 200;
    let options = RenderOptions {
        network_name: Some("fixed_name".into()),
        ..RenderOptions::default()
    };
    let original = render_network_config(&first, &options).unwrap();
    let changed = render_network_config(&changed, &options).unwrap();
    assert_ne!(
        original.consensus_fingerprint,
        changed.consensus_fingerprint
    );
    assert_eq!(original.config_toml, changed.config_toml);
    assert_eq!(original.config_sha256, changed.config_sha256);
    assert!(!changed.node_config_validated);
    assert!(!changed.launch_ready);
}

#[test]
fn valid_but_unrepresentable_manifest_choices_are_rejected() {
    let mut missing_orchard = input();
    missing_orchard["temporaryOrchardDisablingHeight"] = Value::Null;
    let mut unshielded = input();
    unshielded["subsidy"]["allowUnshieldedCoinbaseSpends"] = json!(true);
    let mut slh = input();
    slh["upgrades"]["NU7"] = json!(1);
    slh["experimentalSlh"] = json!({
        "profile": "custom-testnet-slh-v1", "contract": "slh-dsa-b-128s-v1",
        "activationHeight": 2, "transactionChecks": 16, "blockChecks": 64
    });
    for (case, value, expected) in [
        ("no Orchard rule", missing_orchard, "Orchard"),
        ("unshielded coinbase", unshielded, "coinbase"),
        ("SLH", slh, "SLH"),
    ] {
        let manifest = manifest(&value);
        manifest.validate().unwrap();
        let error = render_network_config(&manifest, &RenderOptions::default()).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");
    }
}

#[test]
fn invalid_manifests_are_not_formatted_as_candidate_configuration() {
    for (field, replacement) in [
        ("/apiVersion", json!("future-version")),
        ("/ruleset", json!("unknown-node")),
        ("/networkMagic", json!("fa1af9bf")),
        (
            "/difficulty/targetDifficultyLimitCompact",
            json!("2200ffff"),
        ),
        ("/genesis/hash", json!("00".repeat(32))),
        ("/upgrades/NU6.3", json!(0)),
    ] {
        let mut value = input();
        *value.pointer_mut(field).unwrap() = replacement;
        assert!(
            render_network_config(&manifest(&value), &RenderOptions::default()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn names_reject_reserved_values_paths_unicode_and_toml_injection() {
    for name in [
        "",
        "Mainnet",
        "Testnet",
        "Regtest",
        "MainnetKind",
        "TestnetKind",
        "RegtestKind",
        "mAiNnEt",
        "testnetkind",
        "branch-name",
        "../chain",
        "foo/bar",
        "café",
        "x y",
        "x\n[rpc]\nenabled=true",
        "x\"",
        "$(touch secret)",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let options = RenderOptions {
            network_name: Some(name.into()),
            ..RenderOptions::default()
        };
        assert!(
            render_network_config(&fixture(), &options).is_err(),
            "accepted name {name:?}"
        );
    }
    for name in ["a", "_", "123", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
        let options = RenderOptions {
            network_name: Some(name.into()),
            ..RenderOptions::default()
        };
        let report = render_network_config(&fixture(), &options).unwrap();
        assert_eq!(parsed(&report).network.network.network_name, name);
    }
}

#[test]
fn listeners_and_peers_reject_non_numeric_or_non_unicast_endpoints() {
    for endpoint in [
        "",
        "localhost:18233",
        "example.com:18233",
        "127.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "0.0.0.0:18233",
        "[::]:18233",
        "224.0.0.1:18233",
        "255.255.255.255:18233",
        "[ff02::1]:18233",
        "[fe80::1%2]:18233",
        "[::ffff:0.0.0.0]:18233",
        "[::ffff:224.0.0.1]:18233",
        "[::ffff:255.255.255.255]:18233",
        "127.0.0.1:18233\n[rpc]\nenabled=true",
        "127.0.0.1:18233; touch secret",
        " 127.0.0.1:18233",
    ] {
        for options in [
            RenderOptions {
                listen_addr: endpoint.into(),
                ..RenderOptions::default()
            },
            RenderOptions {
                peers: vec![endpoint.into()],
                ..RenderOptions::default()
            },
        ] {
            assert!(
                render_network_config(&fixture(), &options).is_err(),
                "accepted endpoint {endpoint:?}"
            );
        }
    }
    let oversized = RenderOptions {
        peers: vec!["1".repeat(65)],
        ..RenderOptions::default()
    };
    assert!(render_network_config(&fixture(), &oversized).is_err());
}

#[test]
fn explicit_peer_count_is_bounded_before_deduplication() {
    let mut options = RenderOptions {
        peers: vec!["192.0.2.1:18233".into(); 128],
        ..RenderOptions::default()
    };
    let report = render_network_config(&fixture(), &options).unwrap();
    assert_eq!(parsed(&report).network.initial_testnet_peers.len(), 1);
    options.peers.push("192.0.2.1:18233".into());
    let error = render_network_config(&fixture(), &options).unwrap_err();
    assert!(error.to_string().contains("128"));
}

#[test]
fn direct_library_callers_cannot_render_an_oversized_valid_manifest() {
    let mut manifest = fixture();
    manifest.subsidy.lockbox_disbursements = vec![
        LockboxDisbursement {
            script_hash: "00".repeat(20),
            amount: 0
        };
        40_000
    ];
    manifest.validate().unwrap();
    assert!(serde_json::to_vec(&manifest).unwrap().len() > 2 * 1024 * 1024);
    let error = render_network_config(&manifest, &RenderOptions::default()).unwrap_err();
    assert!(format!("{error:#}").contains("2 MiB"));
}
