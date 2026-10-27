#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output},
};

fn keys() -> Value {
    json!({"schema_version":1,"network":"test","reward_address":bs58::encode([vec![0x1d,0x25],vec![1;20]].concat()).with_check().into_string(),"p2pkh_public_key_hex":format!("02{}", "11".repeat(32)),"ironwood_address_hex":"22".repeat(43)})
}

fn backend(root: &Path, response: &Value, behavior: &str) -> String {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    native_tool::install(
        &root.join("backend"),
        "backend_worker",
        &json!({"response":response,"behavior":behavior}),
    );
    hex::encode(Sha256::digest(fs::read(root.join("backend")).unwrap()))
}

#[test]
fn backend_worker() {
    use std::os::unix::fs::OpenOptionsExt;
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    assert!(matches!(
        args[0].as_str(),
        "key-create" | "key-public" | "key-import" | "scan"
    ));
    match payload["behavior"].as_str().unwrap() {
        "fail" => native_tool::reply(&work, b"", b"SECRET-DIAGNOSTIC\n", 1),
        "flood" => native_tool::reply(
            &work,
            format!("{}\n", "SECRET-DIAGNOSTIC".repeat(80000)).as_bytes(),
            b"",
            0,
        ),
        behavior => {
            if args[0] != "key-public" {
                let path = args.last().unwrap();
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .unwrap()
                    .write_all(b"backend-owned-file")
                    .unwrap();
                if behavior == "public-file" {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            native_tool::reply(
                &work,
                format!("{}\n", payload["response"]).as_bytes(),
                b"",
                0,
            );
        }
    }
}

fn run(root: &Path, hash: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .current_dir(root)
        .args(["wallet", "--backend", "./backend", "--backend-sha256", hash])
        .args(args)
        .output()
        .unwrap()
}

fn rejected(output: Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET-DIAGNOSTIC"));
}

#[test]
fn saved_backend_defaults_are_explicit_private_and_reverified_without_loading_for_list() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let hash = backend(root, &keys(), "ok");
    network(root, "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153");
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zdn"))
            .current_dir(root)
            .env("PATH", root)
            .args(["wallet", "--wallet-dir", "wallets"])
            .args(args)
            .output()
            .unwrap()
    };
    rejected(invoke(&["key-create", "missing-settings"]));
    rejected(invoke(&[
        "backend",
        "set",
        "--backend",
        "backend",
        "--backend-sha256",
        &"00".repeat(32),
    ]));
    assert!(!root.join("wallets").exists());
    public(invoke(&[
        "backend",
        "set",
        "--backend",
        "backend",
        "--backend-sha256",
        &hash.to_uppercase(),
    ]));
    let settings_path = root.join("wallets/backend.json");
    let settings: Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    assert_eq!(settings["backend"], root.join("backend").to_str().unwrap());
    assert_eq!(settings["backend_sha256"], hash);
    assert_eq!(
        fs::metadata(&settings_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(public(invoke(&["key-create", "default-key"])), keys());
    for flags in [
        vec!["--backend", "backend"],
        vec!["--backend-sha256", &hash],
    ] {
        let mut args = flags;
        args.extend(["key-create", "partial"]);
        let output = invoke(&args);
        assert!(String::from_utf8_lossy(&output.stderr).contains("supplied together"));
        rejected(output);
    }
    // Changed bytes must fail even when the persisted path still exists.
    let changed_hash = backend(root, &keys(), "public-file");
    rejected(invoke(&["key-public", "default-key"]));
    assert_ne!(hash, changed_hash);
    // A complete explicit override does not consult damaged persisted settings.
    fs::write(&settings_path, b"not-json").unwrap();
    assert_eq!(
        public(invoke(&[
            "--backend",
            "backend",
            "--backend-sha256",
            &changed_hash,
            "key-public",
            "default-key"
        ])),
        keys()
    );
    rejected(invoke(&["key-public", "default-key"]));
    public(named(root, None, &["list"]).output().unwrap());
    assert!(!root.join("aws-was-called").exists());
}

#[test]
fn public_key_commands_preserve_private_file_boundary_and_existing_outputs() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let hash = backend(root, &keys(), "ok");
    for args in [
        vec!["key-create", "key"],
        vec!["key-public", "key"],
        vec!["key-import", "key", "copy"],
    ] {
        let output = run(root, &hash, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            keys()
        );
    }
    rejected(run(root, &hash, &["key-create", "key"]));
    rejected(run(root, &hash, &["key-import", "key", "copy"]));
    assert_eq!(fs::read(root.join("key")).unwrap(), b"backend-owned-file");
    fs::set_permissions(root.join("key"), fs::Permissions::from_mode(0o644)).unwrap();
    rejected(run(root, &hash, &["key-public", "key"]));
    rejected(run(root, &hash, &["key-import", "key", "other"]));
    symlink("copy", root.join("link")).unwrap();
    rejected(run(root, &hash, &["key-public", "link"]));
    assert!(!root.join("other").exists());
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
    rejected(run(root, &hash, &["key-create", "nonprivate-parent"]));
    assert!(!root.join("nonprivate-parent").exists());
}

#[test]
fn selected_backend_and_public_json_fail_closed_without_secret_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let hash = backend(root, &keys(), "ok");
    for bad in ["bad".to_string(), "00".repeat(32)] {
        rejected(run(root, &bad, &["key-create", "new"]));
        assert!(!root.join("new").exists());
    }
    fs::rename(root.join("backend"), root.join("real")).unwrap();
    symlink("real", root.join("backend")).unwrap();
    rejected(run(root, &hash, &["key-create", "new"]));
    fs::remove_file(root.join("backend")).unwrap();
    for mode in ["fail", "flood", "public-file"] {
        let hash = backend(root, &keys(), mode);
        let output = run(root, &hash, &["key-create", mode]);
        if mode == "flood" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("process limits"));
        }
        rejected(output);
    }
    for variant in 0..7 {
        let mut response = keys();
        match variant {
            0 => response["private_key"] = json!("SECRET-DIAGNOSTIC ' quoted\nvalue"),
            1 => response["network"] = json!("main"),
            2 => response["p2pkh_public_key_hex"] = json!("04".repeat(33)),
            3 => response["ironwood_address_hex"] = json!("00"),
            4 => response["schema_version"] = json!(2),
            5 => response["schema_version"] = json!("SECRET-DIAGNOSTIC"),
            _ => {
                response.as_object_mut().unwrap().remove("reward_address");
            }
        }
        let hash = backend(root, &response, "ok");
        rejected(run(
            root,
            &hash,
            &["key-create", &format!("invalid-{variant}")],
        ));
        // Backend writes are intentionally not rolled back after invalid stdout.
        assert!(root.join(format!("invalid-{variant}")).exists());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .args([
            "--format",
            "json",
            "wallet",
            "--backend",
            "/missing",
            "--backend-sha256",
            &hash,
            "key-create",
            "new",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsupported-format-command"));
}

#[test]
fn scan_accepts_only_bounded_public_note_and_provenance_contract() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("key"), b"opaque-private-input-not-parsed-by-zdn").unwrap();
    fs::set_permissions(root.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("history"), b"backend-validates-history").unwrap();
    let scan = json!({"schema_version":1,"tip_height":1,"tip_hash":"ab".repeat(32),"history_sha256":"cd".repeat(32),"anchor_hex":"ef".repeat(32),"commitment_count":2,"notes":[{"txid":"12".repeat(32),"action_index":0,"position":1,"value_zat":50,"spent":false}]});
    let hash = backend(root, &scan, "ok");
    let output = run(root, &hash, &["scan", "key", "history", "scan"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        scan
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a current network balance"));
    rejected(run(root, &hash, &["scan", "key", "history", "scan"]));
    for variant in 0..12 {
        let mut bad = scan.clone();
        match variant {
            0 => bad["notes"][0]["private"] = json!("SECRET-DIAGNOSTIC"),
            1 => bad["history_sha256"] = json!("wrong"),
            2 => bad["notes"][0]["position"] = json!(2),
            3 => bad["commitment_count"] = json!(16385),
            4 => bad["secret"] = json!("SECRET-DIAGNOSTIC"),
            5 => bad["notes"][0]["value_zat"] = json!(0),
            6 => bad["notes"][0]["value_zat"] = json!(2_100_000_000_000_001u64),
            7 => bad["notes"][0]["action_index"] = json!(16384),
            8 => bad["tip_height"] = json!(4096),
            9 => bad["notes"] = json!([scan["notes"][0], scan["notes"][0]]),
            10 => bad["notes"][0]["spent"] = json!("SECRET-DIAGNOSTIC"),
            _ => {
                bad.as_object_mut().unwrap().remove("anchor_hex");
            }
        }
        let hash = backend(root, &bad, "ok");
        rejected(run(
            root,
            &hash,
            &["scan", "key", "history", &format!("bad-{variant}")],
        ));
    }
}

fn network(root: &Path, id: &str) {
    let mut manifest: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    manifest["genesis"]["hash"] =
        json!("05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38");
    let parsed: zdn::chain::manifest::ConsensusManifest =
        serde_json::from_value(manifest.clone()).unwrap();
    fs::write(root.join("manifest.json"), manifest.to_string()).unwrap();
    fs::write(root.join("endpoints.json"), json!({
        "apiVersion":"zdn-endpoints/v1alpha1","networkId":id,
        "scope":{"team_id":"test","account_id":"123456789012","region":"us-east-1"},
        "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec","consensusFingerprint":parsed.fingerprint().unwrap(),"nodeCount":1,
        "targets":[{"service":"node-rpc","nodeId":"node-1","instanceId":"i-00000000000000001"}]
    }).to_string()).unwrap();
    executable::write(
        root.join("aws"),
        "#!/bin/sh\ntouch aws-was-called\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(root.join("aws"), fs::Permissions::from_mode(0o700)).unwrap();
}

fn named(root: &Path, hash: Option<&str>, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
    command
        .current_dir(root)
        .env("PATH", root)
        .args(["wallet", "--wallet-dir", "wallets"]);
    if let Some(hash) = hash {
        command.args(["--backend", "./backend", "--backend-sha256", hash]);
    }
    command.args(args).args([
        "--manifest",
        "manifest.json",
        "--endpoints",
        "endpoints.json",
        "--aws-profile",
        "unused",
    ]);
    command
}

fn public(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn named_wallets_are_private_exclusive_network_scoped_and_rederive_identity() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let hash = backend(root, &keys(), "ok");
    let first = "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153";
    let second = "b81c4e9b-4612-4e0d-a3fa-c4ab68a04153";
    network(root, first);
    let alice = public(
        named(root, Some(&hash), &["create", "--name", "alice"])
            .output()
            .unwrap(),
    );
    assert_eq!(alice["public"], keys());
    assert_eq!(alice["network_id"], first);
    assert_eq!(alice["schema_version"], 2);
    assert_eq!(alice["scan_only"], false);
    assert_eq!(
        alice,
        public(
            named(root, Some(&hash), &["show", "--wallet", "alice"])
                .output()
                .unwrap()
        )
    );
    let path = root.join("wallets").join(first).join("alice");
    for dir in [
        root.join("wallets"),
        path.parent().unwrap().to_path_buf(),
        path.clone(),
    ] {
        assert_eq!(
            fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for file in ["key.json", "wallet.json"] {
        assert_eq!(
            fs::metadata(path.join(file)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    rejected(
        named(root, Some(&hash), &["create", "--name", "alice"])
            .output()
            .unwrap(),
    );
    for name in ["../escape", "Alice", "a/b", ""] {
        rejected(
            named(root, Some(&hash), &["create", "--name", name])
                .output()
                .unwrap(),
        );
    }
    let key = path.join("key.json");
    let bob = public(
        named(
            root,
            Some(&hash),
            &[
                "import",
                "--name",
                "bob",
                "--source-keyfile",
                key.to_str().unwrap(),
            ],
        )
        .output()
        .unwrap(),
    );
    assert_ne!(bob["id"], alice["id"]);
    assert_eq!(bob["schema_version"], 2);
    assert_eq!(bob["scan_only"], true);
    let list = public(named(root, None, &["list"]).output().unwrap());
    assert_eq!(list["wallets"].as_array().unwrap().len(), 2);
    assert_eq!(list["wallets"][0]["name"], "alice");
    assert_eq!(list["wallets"][0]["key_verified"], false);
    assert_eq!(list["wallets"][1]["wallet"]["scan_only"], true);
    let imported_receipt = root.join("wallets").join(first).join("bob/wallet.json");
    for case in ["missing", "null", "wrong-type", "v1-with-policy"] {
        let mut incomplete = bob.clone();
        match case {
            "missing" => {
                incomplete.as_object_mut().unwrap().remove("scan_only");
            }
            "null" => incomplete["scan_only"] = Value::Null,
            "wrong-type" => incomplete["scan_only"] = json!("false"),
            "v1-with-policy" => incomplete["schema_version"] = json!(1),
            _ => unreachable!(),
        }
        fs::write(&imported_receipt, incomplete.to_string()).unwrap();
        rejected(
            named(root, Some(&hash), &["show", "--wallet", "bob"])
                .output()
                .unwrap(),
        );
        rejected(named(root, None, &["list"]).output().unwrap());
    }
    fs::write(imported_receipt, bob.to_string()).unwrap();
    network(root, second);
    assert_eq!(
        public(named(root, None, &["list"]).output().unwrap())["wallets"],
        json!([])
    );
    rejected(
        named(root, Some(&hash), &["show", "--wallet", "alice"])
            .output()
            .unwrap(),
    );
    let other = public(
        named(root, Some(&hash), &["create", "--name", "alice"])
            .output()
            .unwrap(),
    );
    assert_eq!(other["network_id"], second);
    assert_ne!(other["id"], alice["id"]);
    // A copied receipt cannot rebind another network even with the same consensus fingerprint.
    fs::copy(
        path.join("wallet.json"),
        root.join("wallets").join(second).join("alice/wallet.json"),
    )
    .unwrap();
    rejected(
        named(root, Some(&hash), &["show", "--wallet", "alice"])
            .output()
            .unwrap(),
    );
    network(root, first);
    // Compatible backend bytes may change; creation hash is provenance, not a lifetime pin.
    let compatible = backend(root, &keys(), "compatible-new-build");
    assert_ne!(hash, compatible);
    assert_eq!(
        public(
            named(root, Some(&compatible), &["show", "--wallet", "alice"])
                .output()
                .unwrap()
        ),
        alice
    );
    // Preserve the documented `balance NETWORK --wallet NAME` positional form.
    let selected = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .current_dir(root)
        .args([
            "wallet",
            "--wallet-dir",
            "wallets",
            "--backend",
            "./backend",
            "--backend-sha256",
            &compatible,
            "balance",
            "demo",
            "--wallet",
            "alice",
            "--manifest",
            "manifest.json",
            "--state-dir",
            "missing-state",
        ])
        .output()
        .unwrap();
    assert!(!selected.status.success());
    assert!(String::from_utf8_lossy(&selected.stderr).contains("local state is missing"));
    assert!(selected.stdout.is_empty());
    let mut changed = keys();
    changed["ironwood_address_hex"] = json!("33".repeat(43));
    let changed_hash = backend(root, &changed, "ok");
    rejected(
        named(root, Some(&changed_hash), &["show", "--wallet", "alice"])
            .output()
            .unwrap(),
    );
    rejected(
        named(root, Some(&changed_hash), &["balance", "--wallet", "alice"])
            .output()
            .unwrap(),
    );
    // Typed identity consumers must reject malformed/unknown fields just like
    // the public key commands, without echoing backend data into diagnostics.
    for variant in 0..3 {
        let mut invalid = keys();
        match variant {
            0 => invalid["private_key"] = json!("SECRET-DIAGNOSTIC"),
            1 => invalid["schema_version"] = json!("SECRET-DIAGNOSTIC"),
            _ => invalid["network"] = json!("main"),
        }
        let invalid_hash = backend(root, &invalid, "ok");
        for args in [
            vec!["show", "--wallet", "alice"],
            vec!["balance", "--wallet", "alice"],
            vec!["create", "--name", "invalid"],
        ] {
            rejected(named(root, Some(&invalid_hash), &args).output().unwrap());
        }
        // Failed creates leave their reserved directory, not a public receipt.
        let invalid_path = root.join("wallets").join(first).join("invalid");
        assert!(!invalid_path.join("wallet.json").exists());
        fs::remove_dir_all(invalid_path).unwrap();
    }
    assert!(!root.join("aws-was-called").exists());
    assert_eq!(fs::read(key).unwrap(), b"backend-owned-file");
}

#[test]
fn named_creation_before_deployment_uses_the_bound_network_without_endpoints() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = state.path().to_str().unwrap();
    let hash = backend(root, &keys(), "ok");
    network(root, "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153");
    fs::remove_file(root.join("endpoints.json")).unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zdn"))
            .current_dir(root)
            .env_clear()
            .env("HOME", root)
            .env("PATH", root)
            .args(args)
            .output()
            .unwrap()
    };
    public(invoke(&[
        "init",
        "--release",
        "fixture",
        "--profile",
        "local",
    ]));
    let bound = public(invoke(&[
        "identity",
        "bind",
        "--state-dir",
        state_path,
        "--team-id",
        "test",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
    ]));
    let id = bound["network_id"].as_str().unwrap();
    fs::create_dir_all(state.path().join("profiles")).unwrap();
    fs::write(state.path().join("profiles/local.json"), json!({
        "team":{"apiVersion":"zdn-team/v1alpha1","teamId":"test","revision":1,
            "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec",
            "aws":{"accountId":"123456789012","region":"us-east-1"},
            "state":{"backend":"s3://zdn-fixture-state/pulumi/zdn",
                "kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"}},
        "awsProfile":"unused"
    }).to_string()).unwrap();
    // Config selects "local", not the default profile. Partial and contradictory
    // scopes cannot create a second identity or override that saved authority.
    let bind = ["identity", "bind", "--state-dir", state_path];
    assert_eq!(public(invoke(&bind))["network_id"], id);
    rejected(invoke(&[
        "identity",
        "bind",
        "--state-dir",
        state_path,
        "--team-id",
        "test",
    ]));
    rejected(invoke(&[
        "identity",
        "bind",
        "--state-dir",
        state_path,
        "--team-id",
        "other",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
    ]));
    let register = [
        "identity",
        "bind",
        "--state-dir",
        state_path,
        "--manifest",
        "manifest.json",
    ];
    public(invoke(&register));
    public(invoke(&register));
    let reviewed = fs::read(root.join("manifest.json")).unwrap();
    let mut reformatted = reviewed.clone();
    reformatted.push(b'\n');
    fs::write(root.join("manifest.json"), reformatted).unwrap();
    rejected(invoke(&register));
    fs::write(root.join("manifest.json"), &reviewed).unwrap();
    public(invoke(&[
        "wallet",
        "--wallet-dir",
        "wallets",
        "backend",
        "set",
        "--backend",
        "./backend",
        "--backend-sha256",
        &hash,
    ]));
    let create = |selector: &str, name: &str| {
        invoke(&[
            "wallet",
            "--wallet-dir",
            "wallets",
            "create",
            selector,
            "--name",
            name,
            "--state-dir",
            state_path,
            "--profile",
            "local",
        ])
    };
    rejected(create("00000000-0000-4000-8000-000000000001", "funding"));
    assert!(!root.join("wallets").join(id).exists());
    let created = public(create(id, "funding"));
    assert_eq!(created["network_id"], id);
    assert_eq!(created["scan_only"], false);
    assert_eq!(created["public"], keys());
    assert!(!root.join("endpoints.json").exists());
    assert!(!state.path().join("foundation").exists());
    rejected(create(id, "funding"));
    // Existing corrupt deployment authority must never fall back to the
    // predeployment path, even though the local binding itself is valid.
    let deployment = state.path().join("foundation").join(id);
    fs::create_dir_all(&deployment).unwrap();
    fs::write(deployment.join("deployment.json"), b"not-json").unwrap();
    rejected(create(id, "must-not-fallback"));
    fs::remove_file(deployment.join("deployment.json")).unwrap();
    rejected(create(id, "missing-deployment-must-not-fallback"));
    assert!(!root
        .join("wallets")
        .join(id)
        .join("must-not-fallback")
        .exists());
    // Once actual routing is supplied, the same immutable wallet receipt works
    // unchanged; no key import or receipt-policy edit is part of onboarding.
    network(root, id);
    assert_eq!(
        public(
            named(root, Some(&hash), &["show", "--wallet", "funding"])
                .output()
                .unwrap()
        ),
        created
    );
    assert!(!root.join("aws-was-called").exists());
}

#[test]
fn named_creation_preserves_failures_and_serializes_competing_creates() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let id = "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153";
    network(root, id);
    let hash = backend(root, &keys(), "fail");
    rejected(
        named(root, Some(&hash), &["create", "--name", "failed"])
            .output()
            .unwrap(),
    );
    let list = public(named(root, None, &["list"]).output().unwrap());
    assert_eq!(
        list["wallets"],
        json!([{"name":"failed","status":"incomplete","key_verified":false}])
    );
    let hash = backend(root, &keys(), "ok");
    rejected(
        named(root, Some(&hash), &["create", "--name", "failed"])
            .output()
            .unwrap(),
    );
    let a = named(root, Some(&hash), &["create", "--name", "racing"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let b = named(root, Some(&hash), &["create", "--name", "racing"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let a = a.wait_with_output().unwrap();
    let b = b.wait_with_output().unwrap();
    assert_ne!(a.status.success(), b.status.success());
    let list = public(named(root, None, &["list"]).output().unwrap());
    assert_eq!(list["wallets"][1]["status"], "complete");
    let directory = root.join("wallets").join(id).join("racing");
    fs::rename(&directory, root.join("original-wallet")).unwrap();
    symlink(root.join("original-wallet"), &directory).unwrap();
    rejected(
        named(root, Some(&hash), &["show", "--wallet", "racing"])
            .output()
            .unwrap(),
    );
    rejected(named(root, None, &["list"]).output().unwrap());
    assert!(!root.join("aws-was-called").exists());
}
