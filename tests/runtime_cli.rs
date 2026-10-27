//! Offline runtime rendering never installs files or starts a node.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const MANIFEST: &str = include_str!("fixtures/chain-manifest/valid.json");
const DEPLOYMENT: &str = "5d8a12f4-cb89-4b79-8970-c9267b4ce398";
// Synthetic Testnet P2SH destination from independent encoding vectors.
const REWARD: &str = "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB";

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
    command.env_clear().current_dir(directory).args([
        "chain",
        "render-runtime",
        "--manifest",
        "candidate.json",
        "--deployment-id",
        DEPLOYMENT,
        "--node-id",
        "node-0",
    ]);
    command
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn runtime_report_and_startup_arguments_need_no_tools_or_local_runtime_directories() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    let output = command(directory.path()).output().unwrap();
    let report = report(&output);
    assert_eq!(report["apiVersion"], "zdn-zakura-runtime/v1alpha1");
    assert_eq!(report["adapter"], "zakura-runtime-toml/v1alpha1");
    assert_eq!(report["scope"], "runtime");
    assert_eq!(report["deploymentId"], DEPLOYMENT);
    assert_eq!(report["nodeId"], "node-0");
    assert_eq!(report["role"], "follower");
    assert_eq!(report["nodeConfigValidated"], false);
    assert_eq!(report["qualification"], "pending");
    assert_eq!(report["launchReady"], false);
    let fingerprint = include_str!("fixtures/chain-manifest/sha256.txt").trim();
    assert_eq!(report["consensusFingerprint"], fingerprint);
    let node_root =
        format!("/var/lib/zdn/deployments/{DEPLOYMENT}/nodes/node-0/chains/{fingerprint}");
    assert_eq!(report["paths"]["nodeRoot"], node_root);
    assert_eq!(
        report["startupArgv"],
        serde_json::json!([
            "/usr/local/bin/zakurad",
            "--config",
            format!("{node_root}/zakura.toml"),
            "start"
        ])
    );
    assert_eq!(
        report["requiredEnvironmentRemovalPrefixes"],
        serde_json::json!(["ZAKURA_", "ZEBRA_", "OTEL_"])
    );
    let config = report["configToml"].as_str().unwrap();
    assert_eq!(
        report["configSha256"],
        hex::encode(Sha256::digest(config.as_bytes()))
    );
    let config: toml::Value = toml::from_str(config).unwrap();
    assert_eq!(config["rpc"]["enable_cookie_auth"].as_bool(), Some(true));
    assert_eq!(
        config["rpc"]["listen_addr"].as_str(),
        Some("127.0.0.1:18232")
    );
    assert_eq!(
        config["state"]["cache_dir"].as_str(),
        Some(format!("{node_root}/state").as_str())
    );
    assert_eq!(config["mining"]["internal_miner"].as_bool(), Some(false));
    assert!(config["mining"].get("miner_address").is_none());
    assert!(report.get("cookie").is_none());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(directory.path().join("candidate.json")).unwrap(),
        MANIFEST
    );
}

#[test]
fn producer_options_are_wired_to_saved_toml_without_replacing_existing_output() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    let output = command(directory.path())
        .args([
            "--role",
            "producer",
            "--reward-address",
            REWARD,
            "--data-root",
            "/srv/zdn",
            "--listen-addr",
            "10.0.1.5:18233",
            "--rpc-listen-addr",
            "127.0.0.1:18234",
            "--peer",
            "10.0.1.6:18233",
            "--output",
            "candidate runtime.toml",
        ])
        .output()
        .unwrap();
    let report = report(&output);
    assert_eq!(report["role"], "producer");
    let config: toml::Value = toml::from_str(report["configToml"].as_str().unwrap()).unwrap();
    assert_eq!(config["mining"]["miner_address"].as_str(), Some(REWARD));
    assert_eq!(
        config["network"]["listen_addr"].as_str(),
        Some("10.0.1.5:18233")
    );
    assert_eq!(
        config["network"]["initial_testnet_peers"][0].as_str(),
        Some("10.0.1.6:18233")
    );
    assert_eq!(
        config["rpc"]["listen_addr"].as_str(),
        Some("127.0.0.1:18234")
    );
    assert!(report["paths"]["stateDir"]
        .as_str()
        .unwrap()
        .starts_with("/srv/zdn/"));
    let saved = directory.path().join("candidate runtime.toml");
    let before = fs::read(&saved).unwrap();
    assert_eq!(before, report["configToml"].as_str().unwrap().as_bytes());
    let failed = command(directory.path())
        .args(["--output", "candidate runtime.toml"])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("never replaced"));
    assert_eq!(fs::read(&saved).unwrap(), before);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn invalid_runtime_settings_fail_before_publication() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    for args in [
        vec!["--role", "producer"],
        vec!["--reward-address", REWARD],
        vec!["--role", "producer", "--reward-address", "invalid-address"],
        vec!["--rpc-listen-addr", "10.0.1.5:18232"],
        vec!["--rpc-listen-addr", "127.0.0.1:18233"],
        vec!["--data-root", "/srv/../other"],
        vec!["--data-root", "relative"],
        vec!["--role", "unsupported"],
        // Storage namespace is derived; a label cannot choose a different database.
        vec!["--network-name", "different_chain_label"],
    ] {
        let output = command(directory.path())
            .args(&args)
            .args(["--output", "rejected.toml"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let mut value: Value = serde_json::from_str(MANIFEST).unwrap();
    value["difficulty"]["proofOfWork"] = "equihash".into();
    fs::write(
        directory.path().join("candidate.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let output = command(directory.path())
        .args([
            "--role",
            "producer",
            "--reward-address",
            REWARD,
            "--output",
            "rejected.toml",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn runtime_requires_explicit_deployment_and_node_identity() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    for args in [
        vec![],
        vec!["--deployment-id", DEPLOYMENT],
        vec![
            "--deployment-id",
            "00000000-0000-0000-0000-000000000000",
            "--node-id",
            "node-0",
        ],
        vec![
            "--deployment-id",
            DEPLOYMENT,
            "--node-id",
            "../another-node",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .current_dir(directory.path())
            .args(["chain", "render-runtime", "--manifest", "candidate.json"])
            .args(args)
            .args(["--output", "rejected.toml"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
