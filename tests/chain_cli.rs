//! Read-only manifest inspection with synthetic, unqualified consensus inputs.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn inspect(directory: &Path, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(directory)
        .args(["chain", "inspect", "--manifest"])
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn chain_inspection_normalizes_without_state_tools_or_qualification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("candidate chain.json");
    let mut candidate: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    candidate["genesis"]["hash"] = candidate["genesis"]["hash"]
        .as_str()
        .unwrap()
        .to_uppercase()
        .into();
    let bytes = serde_json::to_vec_pretty(&candidate).unwrap();
    fs::write(&path, &bytes).unwrap();
    let output = inspect(directory.path(), &path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["apiVersion"], "zdn-chain-inspection/v1alpha1");
    assert_eq!(report["structurallyValid"], true);
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["qualification"], "pending");
    assert_eq!(
        report["consensusFingerprint"],
        include_str!("fixtures/chain-manifest/sha256.txt").trim()
    );
    assert_eq!(
        report["normalizedManifest"]["genesis"]["hash"],
        "ab".repeat(32)
    );
    assert!(!report["remaining"].as_array().unwrap().is_empty());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn invalid_chain_manifests_fail_without_publishing_an_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("candidate.json");
    let valid: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let mut invalid = Vec::new();
    let mut candidate = valid.clone();
    candidate.as_object_mut().unwrap().remove("genesis");
    invalid.push(serde_json::to_vec(&candidate).unwrap());
    let mut candidate = valid.clone();
    candidate["apiVersion"] = "future-version".into();
    invalid.push(serde_json::to_vec(&candidate).unwrap());
    let mut candidate = valid;
    candidate["deploymentUuid"] = "not-a-consensus-input".into();
    invalid.push(serde_json::to_vec(&candidate).unwrap());
    invalid.push(b"{broken JSON".to_vec());
    invalid.push(vec![b' '; 2 * 1024 * 1024 + 1]);
    for bytes in invalid {
        fs::write(&path, &bytes).unwrap();
        let output = inspect(directory.path(), &path);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    fs::remove_file(&path).unwrap();
    assert!(!inspect(directory.path(), &path).status.success());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}
