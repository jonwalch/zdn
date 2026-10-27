//! Gateway policy through the native public recipe and observation interfaces.
#[path = "support/lightwallet_service.rs"]
mod fixture;

use sha2::{Digest, Sha256};
use zdn::{
    client_gateway::{native, ALLOWED_METHODS, ENDPOINT},
    host::{
        runtime::{Manifest, Selection, PROTOCOL},
        HostInstallSpec,
    },
};

fn manifest(host: HostInstallSpec) -> Manifest {
    let helper = host.helper.clone();
    Manifest::new(
        host,
        Selection {
            protocol: PROTOCOL.into(),
            helper,
        },
    )
    .unwrap()
}

#[test]
fn native_service_preserves_private_participant_policy() {
    let (host, _) = fixture::specs();
    let manifest = manifest(host.clone());
    let unit = native::unit(&manifest).unwrap();
    for line in [
        "BindsTo=zdn-node.service",
        "PartOf=zdn-node.service",
        "WantedBy=zdn-node.service",
        "KillMode=control-group",
        "ProtectSystem=strict",
        "MemoryMax=256M",
        "TasksMax=16",
    ] {
        assert!(unit.contains(line));
    }
    assert!(ALLOWED_METHODS.contains(&"sendrawtransaction"));
    for method in [
        "generate",
        "getblocktemplate",
        "submitblock",
        "getchainrules",
        "inspectchainblock",
        "invalidateblock",
        "reconsiderblock",
        "addnode",
        "stop",
        "z_sendmany",
        "dumpwallet",
    ] {
        assert!(!ALLOWED_METHODS.contains(&method));
    }
    let mut other = host;
    other.role = "producer".into();
    assert!(other.validate().is_err());
}

#[test]
fn native_gateway_rejects_reserved_upstream_ports() {
    for port in [18234, 9067, 9068] {
        let (mut host, _) = fixture::specs();
        host.config_toml = host
            .config_toml
            .replace("127.0.0.1:18232", &format!("127.0.0.1:{port}"));
        host.config_sha256 = hex::encode(Sha256::digest(host.config_toml.as_bytes()));
        let manifest = manifest(host);
        assert!(native::upstream(&manifest).is_err());
        assert!(native::unit(&manifest).is_err());
    }
}

#[test]
fn native_gateway_supports_the_same_boundary_for_a_single_producer() {
    use zdn::chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, NodeRole, RuntimeOptions},
    };
    let (mut host, _) = fixture::specs();
    let consensus: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let addresses: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/runtime-config/addresses.json")).unwrap();
    let mut options = RuntimeOptions::new(host.deployment_id, "node-1");
    options.network.listen_addr = "10.90.1.10:18233".into();
    options.role = NodeRole::Producer;
    options.reward_address = Some(addresses["accepted"][0]["address"].as_str().unwrap().into());
    let runtime = render_runtime_config(&consensus, &options).unwrap();
    host.node_id = "node-1".into();
    host.role = "producer".into();
    host.block_interval_seconds = Some(25);
    host.config_toml = runtime.config_toml;
    host.config_sha256 = runtime.config_sha256;
    let manifest = manifest(host);
    assert!(!native::unit(&manifest).unwrap().contains("zdn-producer"));
    assert_eq!(
        native::observation(&manifest, "ready").unwrap()["endpoint"],
        ENDPOINT
    );
}

#[test]
fn native_observation_binds_exact_service_and_node_identity() {
    let (host, _) = fixture::specs();
    let manifest = manifest(host);
    let report = native::observation(&manifest, "ready").unwrap();
    native::validate_observation(&report, &manifest).unwrap();
    let stopped = native::observation(&manifest, "stopped").unwrap();
    native::validate_observation(&stopped, &manifest).unwrap();
    for (key, value) in [
        ("apiVersion", "future"),
        ("deploymentId", "22345678-1234-4123-8123-123456789abc"),
        ("nodeId", "node-99"),
        ("serviceSha256", &"a".repeat(64)),
        ("consensusFingerprint", &"b".repeat(64)),
        ("endpoint", "0.0.0.0:18234"),
        ("status", "failed"),
    ] {
        let mut changed = report.clone();
        changed[key] = value.into();
        assert!(
            native::validate_observation(&changed, &manifest).is_err(),
            "{key}"
        );
    }
    assert!(native::observation(&manifest, "failed").is_err());
}
