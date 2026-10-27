//! CLI boundaries for an offline, unqualified network configuration fragment.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

const MANIFEST: &str = include_str!("fixtures/chain-manifest/valid.json");

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
    command.env_clear().current_dir(directory).args([
        "chain",
        "render-config",
        "--manifest",
        "candidate.json",
    ]);
    command
}

fn report(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn renders_without_tools_credentials_or_files_and_keeps_qualification_pending() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    let output = command(directory.path())
        .args([
            "--network-name",
            "branch_42",
            "--listen-addr",
            "10.0.1.5:18233",
            "--peer",
            "10.0.1.7:18233",
            "--peer",
            "10.0.1.6:18233",
        ])
        .output()
        .unwrap();
    let report = report(&output);
    assert_eq!(report["apiVersion"], "zdn-zakura-config/v1alpha1");
    assert_eq!(report["adapter"], "zakura-network-toml/v1alpha1");
    assert_eq!(report["scope"], "network");
    assert_eq!(report["nodeConfigValidated"], false);
    assert_eq!(report["qualification"], "pending");
    assert_eq!(report["launchReady"], false);
    assert_eq!(
        report["consensusFingerprint"],
        include_str!("fixtures/chain-manifest/sha256.txt").trim()
    );
    let config = report["configToml"].as_str().unwrap();
    assert_eq!(
        report["configSha256"],
        hex::encode(Sha256::digest(config.as_bytes()))
    );
    let config: toml::Value = toml::from_str(config).unwrap();
    assert_eq!(
        config["network"]["network"]["network_name"].as_str(),
        Some("branch_42")
    );
    assert_eq!(
        config["network"]["listen_addr"].as_str(),
        Some("10.0.1.5:18233")
    );
    let peers = config["network"]["initial_testnet_peers"]
        .as_array()
        .unwrap();
    assert_eq!(peers[0].as_str(), Some("10.0.1.6:18233"));
    assert_eq!(peers[1].as_str(), Some("10.0.1.7:18233"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(directory.path().join("candidate.json")).unwrap(),
        MANIFEST
    );
}

#[test]
fn publishes_exact_toml_and_preserves_existing_paths() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    let output = command(directory.path())
        .args(["--output", "candidate network.toml"])
        .output()
        .unwrap();
    let report = report(&output);
    let saved = directory.path().join("candidate network.toml");
    assert_eq!(
        fs::read_to_string(&saved).unwrap(),
        report["configToml"].as_str().unwrap()
    );
    let original = fs::read(&saved).unwrap();
    fs::create_dir(directory.path().join("existing-directory")).unwrap();
    for output in [
        "candidate network.toml",
        "candidate.json",
        "existing-directory",
    ] {
        let result = command(directory.path())
            .args(["--output", output])
            .output()
            .unwrap();
        assert!(!result.status.success(), "unexpectedly replaced {output}");
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("never replaced"));
    }
    assert_eq!(fs::read(&saved).unwrap(), original);
    assert_eq!(
        fs::read_to_string(directory.path().join("candidate.json")).unwrap(),
        MANIFEST
    );
    assert!(directory.path().join("existing-directory").is_dir());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn rejects_unsupported_inputs_before_writing_and_does_not_create_output_parents() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("candidate.json");
    fs::write(&path, MANIFEST).unwrap();
    for args in [
        vec!["--network-name", "name\n[malicious]"],
        vec!["--peer", "public-seed.example:18233"],
        vec!["--listen-addr", "0.0.0.0:18233"],
        vec!["--peer", "127.0.0.1:0"],
    ] {
        let output = command(directory.path())
            .args(args)
            .args(["--output", "rejected.toml"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let output = command(directory.path())
        .args(["--output", "missing-parent/config.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

    let mut unsupported: Value = serde_json::from_str(MANIFEST).unwrap();
    unsupported["temporaryOrchardDisablingHeight"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
    let output = command(directory.path())
        .args(["--output", "rejected.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Orchard"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn refuses_output_symlinks_without_touching_targets_or_directory_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    symlink("candidate.json", directory.path().join("existing-link")).unwrap();
    symlink("missing-target", directory.path().join("dangling-link")).unwrap();
    for path in ["existing-link", "dangling-link"] {
        let output = command(directory.path())
            .args(["--output", path])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(directory
            .path()
            .join(path)
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }
    assert_eq!(
        fs::read_to_string(directory.path().join("candidate.json")).unwrap(),
        MANIFEST
    );
    assert!(!directory.path().join("missing-target").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
    assert_eq!(
        fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn concurrent_writers_publish_only_one_complete_configuration() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("candidate.json"), MANIFEST).unwrap();
    let children: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|name| {
            command(directory.path())
                .args(["--network-name", name, "--output", "winner.toml"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    let winner = report(
        outputs
            .iter()
            .find(|output| output.status.success())
            .unwrap(),
    );
    let loser = outputs
        .iter()
        .find(|output| !output.status.success())
        .unwrap();
    assert!(loser.stdout.is_empty());
    assert!(String::from_utf8_lossy(&loser.stderr).contains("never replaced"));
    assert_eq!(
        fs::read_to_string(directory.path().join("winner.toml")).unwrap(),
        winner["configToml"].as_str().unwrap()
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}
