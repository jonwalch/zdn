//! CLI checks use synthetic bytes, never a real or qualified chain.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn command(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(directory)
        .args(args)
        .output()
        .unwrap()
}

fn fixture(directory: &Path) {
    let bytes = b"Synthetic bytes: this is not a decoded Zcash block.";
    fs::create_dir(directory.join("raw blocks")).unwrap();
    fs::write(directory.join("raw blocks/0000000000.bin"), bytes).unwrap();
    let mut manifest: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    manifest["genesis"]["bytesSha256"] = hex::encode(Sha256::digest(bytes)).into();
    manifest["genesis"]["bytesLength"] = (bytes.len() as u64).into();
    fs::write(
        directory.join("candidate.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn import(directory: &Path) -> Output {
    command(
        directory,
        &[
            "chain",
            "import",
            "--manifest",
            "candidate.json",
            "--blocks-dir",
            "raw blocks",
            "--output",
            "saved chain.tar",
        ],
    )
}

fn verify(directory: &Path) -> Output {
    command(
        directory,
        &[
            "chain",
            "verify",
            "--manifest",
            "candidate.json",
            "--bundle",
            "saved chain.tar",
        ],
    )
}

fn success(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn import_and_recheck_need_no_tools_and_never_claim_chain_validation() {
    let directory = tempfile::tempdir().unwrap();
    fixture(directory.path());
    let source = fs::read(directory.path().join("raw blocks/0000000000.bin")).unwrap();
    let imported = success(&import(directory.path()));
    assert_eq!(imported["apiVersion"], "zdn-chain-artifact-check/v1alpha1");
    assert_eq!(imported["byteIntegrityVerified"], true);
    assert_eq!(imported["blockDecodingVerified"], false);
    assert_eq!(imported["consensusVerified"], false);
    assert_eq!(imported["launchReady"], false);
    assert_eq!(imported["qualification"], "pending");
    assert_eq!(imported["blockCount"], 1);
    assert_eq!(imported["blockBytes"], source.len());
    let bundle = fs::read(directory.path().join("saved chain.tar")).unwrap();
    assert_eq!(
        imported["bundleSha256"],
        hex::encode(Sha256::digest(&bundle))
    );
    assert_eq!(imported["bundleBytes"], bundle.len());
    assert_eq!(success(&verify(directory.path())), imported);
    assert_eq!(
        fs::read(directory.path().join("raw blocks/0000000000.bin")).unwrap(),
        source
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);

    // Verification depends only on the saved bundle and an expected manifest.
    fs::remove_dir_all(directory.path().join("raw blocks")).unwrap();
    let path = directory.path().join("candidate.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["genesis"]["bytesSha256"] = manifest["genesis"]["bytesSha256"]
        .as_str()
        .unwrap()
        .to_uppercase()
        .into();
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(success(&verify(directory.path())), imported);
    assert_eq!(
        fs::read(directory.path().join("saved chain.tar")).unwrap(),
        bundle
    );
}

#[test]
fn failed_import_never_overwrites_existing_bundle_or_leaves_a_partial_output() {
    let directory = tempfile::tempdir().unwrap();
    fixture(directory.path());
    let raw = directory.path().join("raw blocks/0000000000.bin");
    let original = fs::read(&raw).unwrap();
    fs::write(&raw, b"wrong source bytes").unwrap();
    let failed = import(directory.path());
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(!directory.path().join("saved chain.tar").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);

    fs::write(&raw, original).unwrap();
    success(&import(directory.path()));
    let bundle = fs::read(directory.path().join("saved chain.tar")).unwrap();
    let failed = import(directory.path());
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert_eq!(
        fs::read(directory.path().join("saved chain.tar")).unwrap(),
        bundle
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn recheck_rejects_a_different_expected_chain_and_changed_saved_bytes() {
    let directory = tempfile::tempdir().unwrap();
    fixture(directory.path());
    success(&import(directory.path()));
    let path = directory.path().join("candidate.json");
    let original = fs::read(&path).unwrap();
    let mut different: Value = serde_json::from_slice(&original).unwrap();
    different["networkMagic"] = "d1d2d3d4".into();
    fs::write(&path, serde_json::to_vec(&different).unwrap()).unwrap();
    let failed = verify(directory.path());
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());

    fs::write(path, original).unwrap();
    let bundle_path = directory.path().join("saved chain.tar");
    let mut bytes = fs::read(&bundle_path).unwrap();
    bytes.push(0);
    fs::write(&bundle_path, &bytes).unwrap();
    let failed = verify(directory.path());
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read(bundle_path).unwrap(), bytes);
}

#[test]
fn invalid_manifests_fail_before_creating_bundle_files() {
    let directory = tempfile::tempdir().unwrap();
    fixture(directory.path());
    fs::write(directory.path().join("candidate.json"), b"{invalid JSON}").unwrap();
    let failed = import(directory.path());
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}
