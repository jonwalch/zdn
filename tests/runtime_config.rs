//! Independent offline schema and safety checks for candidate runtime TOML.
//!
//! Field names follow the inspected Zakura config types in zakura-state,
//! zakura-network, zakura-rpc, and zakurad. Required fields deliberately have no
//! serde defaults; these checks cannot establish that a real node accepts or
//! starts from the configuration. Address vectors originally used Python's
//! independent integer/Base58 and hashlib implementation; reference_vectors.rs
//! now reproduces them without the production codec.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;
use zdn::chain::{
    manifest::{BlockIdentity, Checkpoint, ConsensusManifest, ProofOfWork},
    node_config::render_network_config,
    runtime_config::{render_runtime_config, NodeRole, RenderedRuntimeConfig, RuntimeOptions},
};

const MANIFEST: &str = include_str!("fixtures/chain-manifest/valid.json");
const ADDRESSES: &str = include_str!("fixtures/runtime-config/addresses.json");
const DEPLOYMENT: &str = "12345678-1234-4123-8123-123456789abc";
const OTHER_DEPLOYMENT: &str = "12345678-1234-4123-8123-123456789abd";

// These structs encode the node-facing contract independently of the renderer.
// Extra sections/fields need deliberate review, especially additional listeners.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeToml {
    consensus: Consensus,
    network: toml::Value,
    state: State,
    rpc: Rpc,
    mining: Mining,
    tracing: Tracing,
    zcashd_compat: Compatibility,
    metrics: DisabledListener,
    health: DisabledListener,
    mempool: Mempool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consensus {
    checkpoint_sync: bool,
    vct_fast_sync: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mempool {
    debug_enable_at_height: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    cache_dir: String,
    ephemeral: bool,
    should_backup_non_finalized_state: bool,
    delete_old_database: bool,
    storage_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rpc {
    listen_addr: String,
    enable_cookie_auth: bool,
    cookie_dir: String,
    cookie_file_name: String,
    debug_force_finished_sync: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mining {
    miner_address: Option<String>,
    internal_miner: bool,
    optimistic_block_inventory: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tracing {
    use_color: bool,
    force_use_color: bool,
    use_journald: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compatibility {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisabledListener {}

#[derive(Deserialize)]
struct AddressVectors {
    accepted: Vec<AcceptedAddress>,
    rejected: Vec<RejectedAddress>,
}

#[derive(Deserialize)]
struct AcceptedAddress {
    kind: String,
    hash: String,
    address: String,
}

#[derive(Deserialize)]
struct RejectedAddress {
    reason: String,
    address: String,
}

fn manifest() -> ConsensusManifest {
    serde_json::from_str(MANIFEST).unwrap()
}

fn options() -> RuntimeOptions {
    RuntimeOptions::new(Uuid::parse_str(DEPLOYMENT).unwrap(), "node-1")
}

fn addresses() -> AddressVectors {
    serde_json::from_str(ADDRESSES).unwrap()
}

fn producer() -> RuntimeOptions {
    let mut options = options();
    options.role = NodeRole::Producer;
    options.reward_address = Some(addresses().accepted[0].address.clone());
    options
}

fn parse(report: &RenderedRuntimeConfig) -> RuntimeToml {
    toml::from_str(&report.config_toml).unwrap()
}

fn report_json(report: &RenderedRuntimeConfig) -> Value {
    serde_json::to_value(report).unwrap()
}

fn assert_rejected(options: &RuntimeOptions, case: &str) {
    assert!(
        render_runtime_config(&manifest(), options).is_err(),
        "accepted invalid runtime option: {case}"
    );
}

#[test]
fn runtime_has_explicit_persistent_state_authenticated_loopback_and_no_extra_listeners() {
    let manifest = manifest();
    let options = options();
    assert_eq!(options.role, NodeRole::Follower);
    assert_eq!(options.data_root, "/var/lib/zdn");
    assert_eq!(options.rpc_listen_addr, "127.0.0.1:18232");
    assert!(options.reward_address.is_none());
    let report = render_runtime_config(&manifest, &options).unwrap();
    let config = parse(&report);
    let fingerprint = manifest.fingerprint().unwrap();
    let node_root =
        format!("/var/lib/zdn/deployments/{DEPLOYMENT}/nodes/node-1/chains/{fingerprint}");
    assert!(config.consensus.checkpoint_sync);
    assert!(!config.consensus.vct_fast_sync);
    assert_eq!(config.mempool.debug_enable_at_height, 0);
    assert_eq!(config.state.cache_dir, format!("{node_root}/state"));
    assert!(!config.state.ephemeral);
    assert!(config.state.should_backup_non_finalized_state);
    assert!(!config.state.delete_old_database);
    assert_eq!(config.state.storage_mode, "archive");
    assert_eq!(
        config.network["identity_dir"].as_str(),
        Some(format!("{node_root}/identity").as_str())
    );
    assert_eq!(config.rpc.listen_addr, "127.0.0.1:18232");
    assert!(config.rpc.enable_cookie_auth);
    assert_eq!(config.rpc.cookie_dir, format!("{node_root}/rpc"));
    assert_eq!(config.rpc.cookie_file_name, ".cookie");
    assert!(!config.rpc.debug_force_finished_sync);
    assert!(config.mining.miner_address.is_none());
    assert!(!config.mining.internal_miner);
    assert!(!config.mining.optimistic_block_inventory);
    assert!(!config.tracing.use_color);
    assert!(!config.tracing.force_use_color);
    assert!(!config.tracing.use_journald);
    assert!(!config.zcashd_compat.enabled);
    let _ = (config.metrics, config.health);

    let value = report_json(&report);
    assert_eq!(value["apiVersion"], "zdn-zakura-runtime/v1alpha1");
    assert_eq!(value["adapter"], "zakura-runtime-toml/v1alpha1");
    assert_eq!(value["scope"], "runtime");
    assert_eq!(value["consensusFingerprint"], fingerprint);
    assert_eq!(value["deploymentId"], DEPLOYMENT);
    assert_eq!(value["nodeId"], "node-1");
    assert_eq!(value["role"], "follower");
    assert_eq!(value["nodeConfigValidated"], false);
    assert_eq!(value["qualification"], "pending");
    assert_eq!(value["launchReady"], false);
    assert_eq!(
        value["paths"],
        json!({
            "nodeRoot": node_root,
            "stateDir": format!("{node_root}/state"),
            "identityDir": format!("{node_root}/identity"),
            "cookieDir": format!("{node_root}/rpc"),
            "cookieFile": format!("{node_root}/rpc/.cookie"),
            "configFile": format!("{node_root}/zakura.toml")
        })
    );
    assert_eq!(
        value["startupArgv"],
        json!([
            "/usr/local/bin/zakurad",
            "--config",
            format!("{node_root}/zakura.toml"),
            "start"
        ])
    );
    assert_eq!(
        value["requiredEnvironmentRemovalPrefixes"],
        json!(["ZAKURA_", "ZEBRA_", "OTEL_"])
    );
    assert_eq!(
        value["configSha256"],
        hex::encode(Sha256::digest(report.config_toml.as_bytes()))
    );
    assert!(report.config_toml.ends_with('\n'));
}

#[test]
fn runtime_preserves_the_candidate_network_contract_and_only_adds_identity_storage() {
    let manifest = manifest();
    let mut options = options();
    options.network.network_name = Some(format!("zdn_{}", &manifest.fingerprint().unwrap()[..16]));
    options.network.listen_addr = "10.20.0.1:18233".into();
    options.network.peers = vec!["10.20.0.3:18233".into(), "10.20.0.2:18233".into()];
    let fragment = render_network_config(&manifest, &options.network).unwrap();
    let expected: toml::Value = toml::from_str(&fragment.config_toml).unwrap();
    let report = render_runtime_config(&manifest, &options).unwrap();
    let mut network = parse(&report).network;
    let identity = network
        .as_table_mut()
        .unwrap()
        .remove("identity_dir")
        .unwrap();
    assert!(identity.as_str().unwrap().ends_with("/identity"));
    assert_eq!(network, expected["network"]);
    assert_eq!(network["p2p_stack"].as_str(), Some("legacy"));
    assert_eq!(network["cache_dir"].as_bool(), Some(false));
    assert!(network["initial_mainnet_peers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(network["zakura"]["bootstrap_peers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(report_json(&report)["launchReady"], false);
}

#[test]
fn deployment_node_and_consensus_changes_separate_all_persistent_paths() {
    let original_manifest = manifest();
    let original_options = options();
    let baseline =
        report_json(&render_runtime_config(&original_manifest, &original_options).unwrap());
    let mut other_deployment = original_options.clone();
    other_deployment.deployment_id = Uuid::parse_str(OTHER_DEPLOYMENT).unwrap();
    let mut other_node = original_options.clone();
    other_node.node_id = "node-2".into();
    let mut other_chain = original_manifest.clone();
    other_chain.network_magic = "a1b2c3d5".into();
    let reports = [
        render_runtime_config(&original_manifest, &other_deployment).unwrap(),
        render_runtime_config(&original_manifest, &other_node).unwrap(),
        render_runtime_config(&other_chain, &original_options).unwrap(),
    ];
    for report in reports {
        let value = report_json(&report);
        for field in [
            "nodeRoot",
            "stateDir",
            "identityDir",
            "cookieDir",
            "cookieFile",
            "configFile",
        ] {
            assert_ne!(value["paths"][field], baseline["paths"][field], "{field}");
        }
        assert_ne!(value["configSha256"], baseline["configSha256"]);
        let state = value["paths"]["stateDir"].as_str().unwrap();
        assert!(!value["paths"]["identityDir"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{state}/")));
        assert!(!value["paths"]["cookieDir"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{state}/")));
    }
    let mut renamed = original_options.clone();
    renamed.network.network_name = Some("renamed_display_name".into());
    assert!(render_runtime_config(&original_manifest, &renamed).is_err());
    let mut explicit = original_options;
    explicit.network.network_name = Some(format!(
        "zdn_{}",
        &original_manifest.fingerprint().unwrap()[..16]
    ));
    let explicit = report_json(&render_runtime_config(&original_manifest, &explicit).unwrap());
    assert_eq!(explicit["paths"], baseline["paths"]);
    assert_eq!(
        explicit["consensusFingerprint"],
        baseline["consensusFingerprint"]
    );
    assert_eq!(explicit["configSha256"], baseline["configSha256"]);
}

#[test]
fn producer_accepts_independent_testnet_address_vectors_and_remains_unqualified() {
    let manifest = manifest();
    let follower = render_runtime_config(&manifest, &options()).unwrap();
    let vectors = addresses().accepted;
    assert_eq!(vectors.len(), 6);
    assert_eq!(
        vectors
            .iter()
            .map(|v| v.kind.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["p2pkh", "p2sh"])
    );
    for vector in vectors {
        assert_eq!(vector.hash.len(), 40);
        let mut options = producer();
        options.reward_address = Some(vector.address.clone());
        let report = render_runtime_config(&manifest, &options).unwrap();
        let config = parse(&report);
        assert_eq!(
            config.mining.miner_address.as_deref(),
            Some(vector.address.as_str())
        );
        assert!(!config.mining.internal_miner);
        assert!(!config.mining.optimistic_block_inventory);
        let value = report_json(&report);
        assert_eq!(value["role"], "producer");
        assert_eq!(value["launchReady"], false);
        assert_eq!(value["nodeConfigValidated"], false);
        assert_eq!(value["qualification"], "pending");
        assert_eq!(
            value["consensusFingerprint"],
            report_json(&follower)["consensusFingerprint"]
        );
        assert_ne!(
            value["configSha256"],
            report_json(&follower)["configSha256"]
        );
    }
}

#[test]
fn reward_address_rejects_wrong_network_version_lengths_checksum_and_syntax() {
    let mut vectors = addresses().rejected;
    let valid = addresses().accepted[0].address.clone();
    let mut bad_checksum = valid.clone().into_bytes();
    let last = bad_checksum.last_mut().unwrap();
    *last = if *last == b'1' { b'2' } else { b'1' };
    for address in [
        String::new(),
        format!(" {valid}"),
        format!("{valid} "),
        format!("{valid}\n"),
        format!("{valid}\0"),
        String::from_utf8(bad_checksum).unwrap(),
        "tm00000000000000000000000000000000000".into(),
        "ztestsapling1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhecet38rq"
            .into(),
        "\"\n[rpc]\nenable_cookie_auth = false\n".into(),
        "1".repeat(65_536),
    ] {
        vectors.push(RejectedAddress {
            reason: "invalid or unsupported address form".into(),
            address,
        });
    }
    for vector in vectors {
        let mut options = producer();
        options.reward_address = Some(vector.address);
        assert_rejected(&options, &vector.reason);
    }
}

#[test]
fn roles_require_an_explicit_reward_only_on_the_producer() {
    let mut missing = producer();
    missing.reward_address = None;
    assert_rejected(&missing, "producer without reward address");
    for address in [addresses().accepted[0].address.clone(), String::new()] {
        let mut follower = options();
        follower.reward_address = Some(address);
        assert_rejected(&follower, "follower reward address");
    }
}

#[test]
fn generate_producer_rejects_equihash_but_follower_does_not_claim_a_mining_requirement() {
    let mut manifest = manifest();
    manifest.difficulty.proof_of_work = ProofOfWork::Equihash;
    assert!(render_runtime_config(&manifest, &producer()).is_err());
    let follower = render_runtime_config(&manifest, &options()).unwrap();
    assert_eq!(
        parse(&follower).network["network"]["disable_pow"].as_bool(),
        Some(false)
    );
    assert_eq!(report_json(&follower)["launchReady"], false);
}

#[test]
fn development_mempool_activation_waits_for_the_highest_declared_seed_or_checkpoint() {
    let mut manifest = manifest();
    manifest.seed_blocks = vec![
        BlockIdentity {
            height: 2,
            hash: "02".repeat(32),
            bytes_sha256: "12".repeat(32),
            bytes_length: 100,
        },
        BlockIdentity {
            height: 1,
            hash: "01".repeat(32),
            bytes_sha256: "11".repeat(32),
            bytes_length: 100,
        },
    ];
    manifest.checkpoints = vec![
        Checkpoint {
            height: 5,
            hash: "05".repeat(32),
        },
        Checkpoint {
            height: 0,
            hash: manifest.genesis.hash.clone(),
        },
        Checkpoint {
            height: 3,
            hash: "03".repeat(32),
        },
    ];
    let report = render_runtime_config(&manifest, &options()).unwrap();
    let config = parse(&report);
    assert_eq!(config.mempool.debug_enable_at_height, 5);
    assert!(config.consensus.checkpoint_sync);
    assert!(!config.consensus.vct_fast_sync);
    let equivalent = render_runtime_config(&manifest.normalized().unwrap(), &options()).unwrap();
    assert_eq!(report.config_toml, equivalent.config_toml);
    manifest.checkpoints.clear();
    let report = render_runtime_config(&manifest, &options()).unwrap();
    assert_eq!(parse(&report).mempool.debug_enable_at_height, 2);
    manifest.seed_blocks.clear();
    let report = render_runtime_config(&manifest, &options()).unwrap();
    assert_eq!(parse(&report).mempool.debug_enable_at_height, 0);
    assert_eq!(report_json(&report)["launchReady"], false);
}

#[test]
fn rpc_accepts_only_explicit_nonzero_loopback_endpoints() {
    for invalid in [
        "",
        "127.0.0.1",
        "localhost:18232",
        "127.0.0.1:0",
        "0.0.0.0:18232",
        "10.0.0.1:18232",
        "169.254.169.254:80",
        "224.0.0.1:18232",
        "255.255.255.255:18232",
        "[::]:18232",
        "[2001:db8::1]:18232",
        "[::ffff:10.0.0.1]:18232",
        "[::1%1]:18232",
        "127.0.0.1:65536",
        "127.0.0.1:18232\n",
        "http://127.0.0.1:18232",
    ] {
        let mut options = options();
        options.rpc_listen_addr = invalid.into();
        assert_rejected(&options, invalid);
    }
    for (input, expected) in [
        ("127.0.0.1:1", "127.0.0.1:1"),
        ("127.4.3.2:65535", "127.4.3.2:65535"),
        ("[::1]:18232", "[::1]:18232"),
        ("[::ffff:127.0.0.1]:18232", "127.0.0.1:18232"),
    ] {
        let mut options = options();
        options.rpc_listen_addr = input.into();
        let report = render_runtime_config(&manifest(), &options).unwrap();
        assert_eq!(parse(&report).rpc.listen_addr, expected);
    }
}

#[test]
fn rpc_and_p2p_cannot_bind_the_same_canonical_endpoint() {
    for (rpc, p2p) in [
        ("127.0.0.1:18233", "127.0.0.1:18233"),
        ("[::ffff:127.0.0.1]:18233", "127.0.0.1:18233"),
        ("127.0.0.1:18233", "[::ffff:127.0.0.1]:18233"),
        ("[::1]:18233", "[::1]:18233"),
    ] {
        let mut options = options();
        options.rpc_listen_addr = rpc.into();
        options.network.listen_addr = p2p.into();
        assert_rejected(&options, "overlapping listeners");
    }
    let mut options = options();
    options.rpc_listen_addr = "127.0.0.1:18233".into();
    options.network.listen_addr = "10.0.0.1:18233".into();
    render_runtime_config(&manifest(), &options).unwrap();
}

#[test]
fn data_roots_reject_relative_ambiguous_and_injected_linux_paths() {
    for invalid in [
        "",
        "/",
        "data",
        "./data",
        "../data",
        "~/data",
        "$HOME/data",
        "/data/..",
        "/data/.",
        "/data/../other",
        "/data/./other",
        "//data",
        "/data//other",
        "/data/",
        "/two words",
        "/data\nother",
        "/data\0other",
        "/data\\other",
        "/data\"other",
        "/dátá",
        "C:\\data",
        "/$(touch_marker)",
        "/`touch_marker`",
        "/data;touch_marker",
    ] {
        let mut options = options();
        options.data_root = invalid.into();
        assert_rejected(&options, invalid);
    }
}

#[test]
fn data_root_byte_and_component_limits_allow_usable_boundaries() {
    let mut options = options();
    options.data_root = format!("/{}/{}", "a".repeat(255), "b".repeat(255));
    assert_eq!(options.data_root.len(), 512);
    render_runtime_config(&manifest(), &options).unwrap();
    options.data_root.push('b');
    assert_rejected(&options, "513-byte root");
    options.data_root = format!("/{}", "x".repeat(256));
    assert_rejected(&options, "256-byte path component");
    options.data_root = "/srv/.private/zdn_data-v1.2".into();
    let report = render_runtime_config(&manifest(), &options).unwrap();
    assert!(parse(&report)
        .state
        .cache_dir
        .starts_with("/srv/.private/zdn_data-v1.2/deployments/"));
}

#[test]
fn node_names_reject_path_escapes_option_injection_and_ambiguous_names() {
    for invalid in [
        "",
        ".",
        "..",
        "../node-1",
        "node/1",
        "node\\1",
        "NODE-1",
        "node_1",
        "node.1",
        "node 1",
        "-node",
        "node-",
        "--config",
        "node\n1",
        "node\0",
        "nödé",
        "$(touch_marker)",
    ] {
        let mut options = options();
        options.node_id = invalid.into();
        assert_rejected(&options, invalid);
    }
    for valid in ["a".into(), "0".into(), "node--2".into(), "a".repeat(63)] {
        let mut options = options();
        options.node_id = valid;
        render_runtime_config(&manifest(), &options).unwrap();
    }
    let mut options = options();
    options.node_id = "a".repeat(64);
    assert_rejected(&options, "64-byte node name");
}

#[test]
fn deployment_identity_requires_an_rfc_variant_version_four_uuid() {
    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "12345678-1234-1123-8123-123456789abc",
        "12345678-1234-4123-0123-123456789abc",
        "12345678-1234-4123-c123-123456789abc",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ] {
        let mut options = options();
        options.deployment_id = Uuid::parse_str(invalid).unwrap();
        assert_rejected(&options, invalid);
    }
}

#[test]
fn equivalent_inputs_render_the_same_bytes_and_deployment_options_do_not_change_consensus() {
    let baseline_manifest = manifest();
    let mut original = options();
    original.network.peers = vec!["10.0.0.2:18233".into(), "10.0.0.3:18233".into()];
    let baseline = render_runtime_config(&baseline_manifest, &original).unwrap();
    let mut equivalent_manifest = baseline_manifest.clone();
    equivalent_manifest.network_magic.make_ascii_uppercase();
    equivalent_manifest.genesis.hash.make_ascii_uppercase();
    let mut equivalent_options = original.clone();
    equivalent_options.network.peers = vec![
        "10.0.0.3:18233".into(),
        "[::ffff:10.0.0.2]:18233".into(),
        "10.0.0.3:18233".into(),
    ];
    equivalent_options.rpc_listen_addr = "[::ffff:127.0.0.1]:18232".into();
    let equivalent = render_runtime_config(&equivalent_manifest, &equivalent_options).unwrap();
    assert_eq!(baseline.config_toml, equivalent.config_toml);
    assert_eq!(report_json(&baseline), report_json(&equivalent));

    let mut changed = original;
    changed.rpc_listen_addr = "127.0.0.1:28232".into();
    let changed = render_runtime_config(&baseline_manifest, &changed).unwrap();
    assert_eq!(
        report_json(&baseline)["consensusFingerprint"],
        report_json(&changed)["consensusFingerprint"]
    );
    assert_ne!(
        report_json(&baseline)["configSha256"],
        report_json(&changed)["configSha256"]
    );
}

#[test]
fn runtime_rejects_unrepresentable_consensus_and_bad_network_options() {
    let mut manifest = manifest();
    manifest.temporary_orchard_disabling_height = None;
    assert!(render_runtime_config(&manifest, &options()).is_err());
    manifest.temporary_orchard_disabling_height = Some(4_048_500);
    manifest.subsidy.allow_unshielded_coinbase_spends = true;
    assert!(render_runtime_config(&manifest, &options()).is_err());
    manifest.subsidy.allow_unshielded_coinbase_spends = false;
    let mut options = options();
    options.network.network_name = Some("Testnet".into());
    assert!(render_runtime_config(&manifest, &options).is_err());
    options.network.network_name = None;
    options.network.peers = vec!["10.0.0.1:18233".into(); 129];
    assert!(render_runtime_config(&manifest, &options).is_err());
    options.network.peers = vec!["seed.example.invalid:18233".into()];
    assert!(render_runtime_config(&manifest, &options).is_err());
}

#[test]
fn rendering_only_describes_files_and_never_creates_runtime_state_or_cookie_material() {
    let directory = tempfile::tempdir().unwrap();
    let data_root = directory.path().join("not-created");
    let mut options = options();
    options.data_root = data_root.to_str().unwrap().into();
    let first = render_runtime_config(&manifest(), &options).unwrap();
    let second = render_runtime_config(&manifest(), &options).unwrap();
    assert_eq!(first.config_toml, second.config_toml);
    assert!(!data_root.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let config: toml::Value = toml::from_str(&first.config_toml).unwrap();
    assert!(config["rpc"].get("cookie").is_none());
    assert!(config["rpc"].get("password").is_none());
    assert!(config["network"].get("zakura_node_secret_key").is_none());
    assert_eq!(report_json(&first)["launchReady"], false);
}
