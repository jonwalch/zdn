//! Public named-wallet sync over local, proof-free transport/backend fixtures.
use super::*;

fn sync(f: &Fixture, mode: &str, backend: &str, batches: &str) -> Command {
    let mut c = payment_command(
        f,
        "ok",
        &[
            "wallet",
            "sync",
            "--wallet",
            "alice",
            "--max-batches",
            batches,
        ],
    );
    c.env("ZDN_CONNECT_MODE", mode)
        .env("ZDN_SYNC_BACKEND", backend);
    c
}

fn wallet(f: &Fixture) -> std::path::PathBuf {
    f.root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string())
        .join("alice")
}

fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn refusal(output: std::process::Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("opaque-private-input"));
}

fn raw_count(f: &Fixture) -> usize {
    fs::read_to_string(f.root.path().join("rpc-requests"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["body"]["method"] == "getblock")
        .count()
}

fn snapshot_send(f: &Fixture, operation: Option<&str>, node: &str) -> std::process::Output {
    let mut c = payment_command(
        f,
        node,
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    );
    c.env("ZDN_SYNC_BACKEND", "v2");
    if let Some(id) = operation {
        c.args(["--operation-id", id]);
    }
    c.output().unwrap()
}

#[test]
fn snapshot_payment_prepares_signs_and_recovers_exact_original_without_scan_database() {
    let f = payment_fixture();
    let first = snapshot_send(&f, None, "lost");
    let public = payment_json(&first);
    let id = public["operation_id"].as_str().unwrap();
    let scope = wallet(&f).parent().unwrap().to_owned();
    let data = scope.join("payment-data").join(id);
    let plan: Value = serde_json::from_slice(&fs::read(data.join("plan.json")).unwrap()).unwrap();
    assert_eq!(plan["schema_version"], 2);
    assert!(plan.get("history_sha256").is_none());
    assert!(!data.join("history.json").exists());
    let signed = fs::read(data.join("transaction.json")).unwrap();
    assert_eq!(public["txid"], "ab".repeat(32));
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert!(calls.contains("construct-snapshot-payment"), "{calls}");
    assert!(!calls.lines().any(|s| s == "prepare-payment"));
    let raw_before = raw_count(&f);
    fs::remove_file(wallet(&f).join("scan-v2.sqlite")).unwrap();
    let snapshot = fs::read(data.join("snapshot.json")).unwrap();
    fs::remove_file(data.join("snapshot.json")).unwrap();
    let refused = snapshot_send(&f, Some(id), "ok");
    assert!(!refused.status.success());
    assert_eq!(fs::read(data.join("transaction.json")).unwrap(), signed);
    fs::write(data.join("snapshot.json"), snapshot).unwrap();
    fs::set_permissions(
        data.join("snapshot.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let resumed = snapshot_send(&f, Some(id), "ok");
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(payment_json(&resumed)["txid"], public["txid"]);
    assert_eq!(fs::read(data.join("transaction.json")).unwrap(), signed);
    assert_eq!(raw_count(&f), raw_before);
    assert_eq!(
        fs::read_to_string(f.root.path().join("backend-calls"))
            .unwrap()
            .lines()
            .filter(|s| *s == "construct-snapshot-payment")
            .count(),
        1
    );
    f.assert_rpc_closed();
}

#[test]
fn imported_wallet_rejects_untrusted_scan_starts_and_scans_from_genesis() {
    let f = payment_fixture();
    let imported = success(
        payment_command(
            &f,
            "ok",
            &[
                "wallet",
                "import",
                "--name",
                "recovered",
                "--source-keyfile",
                wallet(&f).join("key.json").to_str().unwrap(),
            ],
        )
        .output()
        .unwrap(),
    );
    let directory = wallet(&f).parent().unwrap().join("recovered");
    let receipt = fs::read(directory.join("wallet.json")).unwrap();
    let command = || {
        let mut c = payment_command(
            &f,
            "ok",
            &[
                "wallet",
                "sync",
                "--wallet",
                "recovered",
                "--max-batches",
                "1",
            ],
        );
        c.env("ZDN_CONNECT_MODE", "wallet-sync")
            .env("ZDN_SYNC_BACKEND", "v2")
            .env("ZDN_SYNC_HEIGHT", "257");
        c
    };
    for flag in ["--birthday", "--start-height", "--checkpoint"] {
        let output = command().args([flag, "200"]).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
        assert!(f.calls().is_empty());
        assert!(!directory.join("scan-v2.initialized").exists());
    }
    // Imported public metadata cannot introduce a silently trusted scan offset either.
    for field in ["birthday", "start_height", "checkpoint"] {
        let mut supplied = imported.clone();
        supplied[field] = json!(200);
        fs::write(directory.join("wallet.json"), supplied.to_string()).unwrap();
        let output = command().output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid public wallet receipt"));
        assert!(f.calls().is_empty());
        assert!(!directory.join("scan-v2.initialized").exists());
    }
    fs::write(directory.join("wallet.json"), receipt).unwrap();
    let first = success(command().output().unwrap());
    assert_eq!(first["committed_height"], 255);
    assert_eq!(first["blocks_processed"], 256);
    assert_eq!(first["outcome"], "incomplete");
    let next = success(command().output().unwrap());
    assert_eq!(next["committed_height"], 257);
    assert_eq!(next["blocks_processed"], 2);
    assert_eq!(next["outcome"], "current_at_observation");
    let blocks: Vec<_> = fs::read_to_string(f.root.path().join("rpc-requests"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|request| request["body"]["method"] == "getblock")
        .map(|request| request["body"]["params"][0].clone())
        .collect();
    assert_eq!(blocks.len(), 258);
    assert_eq!(
        blocks[0],
        "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
    );
    for (height, hash) in blocks.iter().enumerate().skip(1) {
        assert_eq!(hash, &json!(format!("{height:064x}")));
    }
    f.assert_rpc_closed();
}

#[test]
fn bare_key_imports_refuse_fund_send_and_resume_before_payment_effects() {
    let f = payment_fixture();
    let original = payment_json(&snapshot_send(&f, None, "accepted-lost"));
    assert_eq!(original["outcome"]["kind"], "outcome_unknown");
    let id = original["operation_id"].as_str().unwrap();
    let key = f.root.path().join("key-only.json");
    fs::copy(wallet(&f).join("key.json"), &key).unwrap();
    let unavailable = f.root.path().join("unavailable-original");
    fs::rename(f.root.path().join("wallets"), &unavailable).unwrap();
    let original_data = unavailable
        .join(f.endpoints.network_id.to_string())
        .join("payment-data")
        .join(id);
    let signed = fs::read(original_data.join("transaction.json")).unwrap();
    for name in ["alice", "alias"] {
        success(
            payment_command(
                &f,
                "ok",
                &[
                    "wallet",
                    "import",
                    "--name",
                    name,
                    "--source-keyfile",
                    key.to_str().unwrap(),
                ],
            )
            .output()
            .unwrap(),
        );
    }
    let calls = f.calls();
    let backend = fs::read(f.root.path().join("backend-calls")).unwrap();
    let dispatches = fs::read(f.root.path().join("dispatches")).unwrap();
    for sender in ["alice", "alias"] {
        for verb in ["fund", "send"] {
            let mut command = payment_command(
                &f,
                "ok",
                &[
                    verb,
                    if verb == "fund" {
                        "--funding-wallet"
                    } else {
                        "--from"
                    },
                    sender,
                    if verb == "fund" { "--address" } else { "--to" },
                    &"22".repeat(43),
                    "--amount",
                    "0.00000002",
                    "--wait-secs",
                    "1",
                ],
            );
            for backend in ["", "v2"] {
                let output = command.env("ZDN_SYNC_BACKEND", backend).output().unwrap();
                assert!(String::from_utf8_lossy(&output.stderr).contains("scan-only"));
                refusal(output);
            }
        }
    }
    let resumed = snapshot_send(&f, Some(id), "ok");
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("scan-only"));
    refusal(resumed);
    assert_eq!(f.calls(), calls);
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend
    );
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatches
    );
    assert_eq!(
        fs::read(original_data.join("transaction.json")).unwrap(),
        signed
    );
    let scope = wallet(&f).parent().unwrap().to_owned();
    assert!(!scope.join("payments").exists());
    assert!(!scope.join("payment-data").exists());
    for name in ["alice", "alias"] {
        let shown = success(
            payment_command(&f, "ok", &["wallet", "show", "--wallet", name])
                .output()
                .unwrap(),
        );
        assert_eq!(shown["scan_only"], true);
    }
    success(sync(&f, "wallet-sync", "v2", "1").output().unwrap());
    let after_sync = snapshot_send(&f, None, "ok");
    assert!(String::from_utf8_lossy(&after_sync.stderr).contains("scan-only"));
    refusal(after_sync);
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend
    );
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatches
    );
    f.assert_rpc_closed();

    // The restriction belongs to the sender, not to a named receiving wallet.
    for verb in ["fund", "send"] {
        let f = payment_fixture();
        success(
            payment_command(
                &f,
                "ok",
                &[
                    "wallet",
                    "import",
                    "--name",
                    "receiver",
                    "--source-keyfile",
                    wallet(&f).join("key.json").to_str().unwrap(),
                ],
            )
            .output()
            .unwrap(),
        );
        let paid = success(
            payment_command(
                &f,
                "ok",
                &[
                    verb,
                    if verb == "fund" {
                        "--funding-wallet"
                    } else {
                        "--from"
                    },
                    "alice",
                    if verb == "fund" { "--wallet" } else { "--to" },
                    "receiver",
                    "--amount",
                    "0.00000002",
                    "--wait-secs",
                    "1",
                ],
            )
            .env("ZDN_SYNC_BACKEND", "v2")
            .output()
            .unwrap(),
        );
        assert_eq!(paid["outcome"]["kind"], "confirmed");
        f.assert_rpc_closed();
    }
}

#[test]
fn coherent_restore_preserves_pending_original_and_incomplete_copy_refuses() {
    fn copy_private(source: &std::path::Path, target: &std::path::Path) {
        fs::create_dir(target).unwrap();
        fs::set_permissions(target, fs::metadata(source).unwrap().permissions()).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_private(&entry.path(), &destination);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                fs::copy(entry.path(), destination).unwrap();
            }
        }
    }

    let f = payment_fixture();
    let lost = snapshot_send(&f, None, "accepted-lost");
    assert!(!lost.status.success());
    let first = payment_json(&lost);
    assert_eq!(first["outcome"]["kind"], "outcome_unknown");
    let id = first["operation_id"].as_str().unwrap();
    let command = |directory: &str, args: &[&str]| {
        let mut command = f.command();
        if args[0] == "wallet" {
            command
                .args(["wallet", "--wallet-dir", directory])
                .args(&args[1..])
                .args([
                    "--manifest",
                    "manifest.json",
                    "--endpoints",
                    "endpoints.json",
                    "--aws-profile",
                    "participant",
                    "--startup-timeout-secs",
                    "10",
                ]);
        } else {
            let template = payment_command(&f, "ok", args);
            command.args(template.get_args().map(|arg| {
                if arg == "wallets" {
                    std::ffi::OsStr::new(directory)
                } else {
                    arg
                }
            }));
        }
        command
            .env("ZDN_CONNECT_MODE", "wallet-classified-payment-ok")
            .env("ZDN_SYNC_BACKEND", "v2");
        command
    };
    let journal = |directory: &str, operation: Option<&str>| {
        let mut command = command(directory, &["wallet", "journal"]);
        if let Some(id) = operation {
            command.args(["--operation-id", id]);
        }
        success(command.output().unwrap())
    };
    for maintenance in ["journal-migrate", "journal-enable-settlements"] {
        let preview = success(
            command("wallets", &["wallet", maintenance])
                .output()
                .unwrap(),
        );
        success(
            command("wallets", &["wallet", maintenance])
                .args(["--apply", preview["proposal_sha256"].as_str().unwrap()])
                .output()
                .unwrap(),
        );
    }
    success(
        command("wallets", &["wallet", "journal-reconcile"])
            .output()
            .unwrap(),
    );
    let before = journal("wallets", Some(id));
    assert_eq!(before["attempts"], 1);
    let originals = [
        "identity.json",
        "request.json",
        "context.json",
        "snapshot.json",
        "plan.json",
        "transaction.json",
    ];
    let data = wallet(&f).parent().unwrap().join("payment-data").join(id);
    let bytes: Vec<_> = originals
        .iter()
        .map(|name| fs::read(data.join(name)).unwrap())
        .collect();
    let dispatched = fs::read(f.root.path().join("dispatches")).unwrap();
    let backend = fs::read(f.root.path().join("backend-calls")).unwrap();
    f.assert_rpc_closed(); // All public CLI commands have exited before copying.
    let root = f.root.path().join("wallets");
    let backup = f.root.path().join("quiesced-backup");
    copy_private(&root, &backup);
    let unavailable = f.root.path().join("unavailable-original");
    fs::rename(&root, &unavailable).unwrap();
    fs::set_permissions(&unavailable, fs::Permissions::from_mode(0o000)).unwrap();
    let root = f.root.path().join("restored-wallets");
    copy_private(&backup, &root);
    let scope = root.join(f.endpoints.network_id.to_string());
    let data = scope.join("payment-data").join(id);
    assert!(scope.join("payments.catalog.sqlite").is_file());
    assert!(scope.join("payments/.catalog-v1").is_file());
    assert!(scope.join("alice/scan-v2.sqlite").is_file());
    assert_eq!(journal("restored-wallets", Some(id)), before);
    let send = |sender: &str, operation: Option<&str>| {
        let mut c = command(
            "restored-wallets",
            &[
                "send",
                "--from",
                sender,
                "--to",
                &"22".repeat(43),
                "--amount",
                "0.00000002",
                "--wait-secs",
                "1",
            ],
        );
        if let Some(id) = operation {
            c.args(["--operation-id", id]);
        }
        c.output().unwrap()
    };

    // An incomplete authoritative catalog must not fall back to retained legacy records.
    fs::remove_file(scope.join("payments.catalog.sqlite")).unwrap();
    let refused = command("restored-wallets", &["wallet", "journal"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("authoritative catalog missing"));
    fs::copy(
        backup
            .join(f.endpoints.network_id.to_string())
            .join("payments.catalog.sqlite"),
        scope.join("payments.catalog.sqlite"),
    )
    .unwrap();

    // Missing immutable evidence cannot be reconstructed or authorize a replacement.
    fs::remove_file(data.join("snapshot.json")).unwrap();
    assert!(!send("alice", Some(id)).status.success());
    for sender in ["alice", "alias"] {
        let refused = send(sender, None);
        assert!(!refused.status.success());
        let error = String::from_utf8_lossy(&refused.stderr);
        assert!(error.contains("unresolved payment"), "{sender}: {error}");
    }
    assert!(!data.join("snapshot.json").exists());
    assert_eq!(journal("restored-wallets", Some(id)), before);
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatched
    );
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend
    );

    fs::remove_dir_all(&root).unwrap();
    copy_private(&backup, &root);
    assert_eq!(journal("restored-wallets", Some(id)), before);
    let resumed = success(send("alice", Some(id)));
    assert_eq!(resumed["operation_id"], first["operation_id"]);
    assert_eq!(resumed["txid"], first["txid"]);
    assert_eq!(resumed["outcome"]["kind"], "confirmed");
    let after = journal("restored-wallets", Some(id));
    for field in [
        "operation_id",
        "request",
        "plan",
        "inputs",
        "signed",
        "attempts",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    // A complete legacy store remains recoverable; v1 never recorded key origin.
    let receipt = scope.join("alice/wallet.json");
    let mut legacy: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    legacy["schema_version"] = json!(1);
    legacy.as_object_mut().unwrap().remove("scan_only");
    fs::write(receipt, legacy.to_string()).unwrap();
    let resumed = success(send("alice", Some(id)));
    assert_eq!(resumed["operation_id"], first["operation_id"]);
    assert_eq!(resumed["outcome"]["kind"], "confirmed");
    assert_eq!(journal("restored-wallets", Some(id)), after);
    for (name, original) in originals.iter().zip(bytes) {
        assert_eq!(fs::read(data.join(name)).unwrap(), original, "{name}");
    }
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatched
    );
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|s| *s == "construct-snapshot-payment")
            .count(),
        1
    );
    f.assert_rpc_closed();
    fs::set_permissions(&unavailable, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn snapshot_payment_incomplete_sync_is_resumable_without_preparation_or_signing() {
    let f = payment_fixture();
    let mut c = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    );
    c.env("ZDN_SYNC_BACKEND", "v2")
        .env("ZDN_CONNECT_MODE", "wallet-sync-long");
    let output = c.output().unwrap();
    assert!(!output.status.success());
    let id = payment_json(&output)["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let data = wallet(&f).parent().unwrap().join("payment-data").join(&id);
    assert!(!data.join("plan.json").exists());
    assert!(!data.join("snapshot.json").exists());
    assert_eq!(raw_count(&f), 1024);
    assert!(!f.root.path().join("backend-calls").exists());
    f.assert_rpc_closed();
    success(sync(&f, "wallet-sync-long", "v2", "16").output().unwrap());
    assert_eq!(raw_count(&f), 4098);
    let resumed = c.args(["--operation-id", &id]).output().unwrap();
    // This sync-only RPC fixture intentionally has no transaction observation
    // contract. It must nevertheless reach signing without any history refetch.
    assert!(!resumed.status.success());
    assert_eq!(payment_json(&resumed)["txid"], "ab".repeat(32));
    let plan: Value = serde_json::from_slice(&fs::read(data.join("plan.json")).unwrap()).unwrap();
    assert_eq!(plan["tip_height"], 4097);
    assert_eq!(plan["schema_version"], 2);
    assert!(!data.join("history.json").exists());
    assert_eq!(raw_count(&f), 4098);
    f.assert_rpc_closed();
}

#[test]
fn snapshot_payment_signing_crash_quarantines_missing_envelope_and_rejects_bad_checks() {
    let f = payment_fixture();
    let output = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_SYNC_BACKEND", "v2")
    .env("ZDN_WALLET_BACKEND", "crash-after-envelope")
    .output()
    .unwrap();
    assert!(!output.status.success());
    let scope = wallet(&f).parent().unwrap().to_owned();
    let path = fs::read_dir(scope.join("payments"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(record["outcome"]["kind"], "signing");
    assert!(record["signed"].is_null());
    let id = record["operation_id"].as_str().unwrap();
    let data = scope.join("payment-data").join(id);
    let envelope_path = data.join("transaction.json");
    let envelope = fs::read(&envelope_path).unwrap();
    fs::remove_file(&envelope_path).unwrap();
    let output = snapshot_send(&f, Some(id), "ok");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("envelope is missing"));
    assert!(!payment_send(&f, "ok", "alias", None, "1").status.success());
    fs::write(&envelope_path, &envelope).unwrap();
    fs::set_permissions(&envelope_path, fs::Permissions::from_mode(0o600)).unwrap();
    for mode in [
        "check-v1",
        "check-extra",
        "check-plan",
        "check-canonicality",
    ] {
        let output = payment_command(
            &f,
            "ok",
            &[
                "send",
                "--from",
                "alice",
                "--to",
                &"22".repeat(43),
                "--amount",
                "0.00000002",
                "--wait-secs",
                "1",
                "--operation-id",
                id,
            ],
        )
        .env("ZDN_SYNC_BACKEND", "v2")
        .env("ZDN_WALLET_BACKEND", mode)
        .output()
        .unwrap();
        assert!(!output.status.success(), "{mode}");
        let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["attempts"], 0);
        assert!(saved["signed"].is_null());
        assert_eq!(fs::read(&envelope_path).unwrap(), envelope);
    }
    assert!(snapshot_send(&f, Some(id), "ok").status.success());
    assert_eq!(fs::read(&envelope_path).unwrap(), envelope);
    assert_eq!(
        fs::read_to_string(f.root.path().join("backend-calls"))
            .unwrap()
            .lines()
            .filter(|s| *s == "construct-snapshot-payment")
            .count(),
        1
    );
}

#[test]
fn snapshot_capable_backend_preserves_legacy_recovery_and_funding_uses_v2() {
    let f = payment_fixture();
    let first = payment_send(&f, "lost", "alice", None, "1");
    let public = payment_json(&first);
    let id = public["operation_id"].as_str().unwrap();
    let path = wallet(&f)
        .parent()
        .unwrap()
        .join("payment-data")
        .join(id)
        .join("transaction.json");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["schema_version"],
        1
    );
    assert!(snapshot_send(&f, Some(id), "ok").status.success());
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert!(!wallet(&f).join("scan-v2.sqlite").exists());
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert!(calls.lines().any(|s| s == "check-transaction"));
    assert!(!calls.contains("snapshot"));

    let f = payment_fixture();
    let output = payment_command(
        &f,
        "ok",
        &[
            "fund",
            "--funding-wallet",
            "alice",
            "--address",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_SYNC_BACKEND", "v2")
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let public = payment_json(&output);
    let plan: Value = serde_json::from_slice(
        &fs::read(
            wallet(&f)
                .parent()
                .unwrap()
                .join("payment-data")
                .join(public["operation_id"].as_str().unwrap())
                .join("plan.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(plan["schema_version"], 2);
    assert_eq!(plan["allocation"]["kind"], "fund");
}

#[test]
fn sync_resumes_past_4096_with_exact_bounded_work_and_no_unchanged_raw_refetch() {
    let f = payment_fixture();
    for (expected, blocks, outcome) in [
        (2047, 2048, "incomplete"),
        (4095, 2048, "incomplete"),
        (4097, 2, "current_at_observation"),
    ] {
        let result = success(sync(&f, "wallet-sync-long", "", "8").output().unwrap());
        assert_eq!(result["committed_height"], expected);
        assert_eq!(result["blocks_processed"], blocks);
        assert_eq!(result["batches_committed"], if blocks == 2 { 1 } else { 8 });
        assert_eq!(result["outcome"], outcome);
        assert_eq!(result["spendability_checked"], false);
        assert_eq!(result["payment_enabled"], false);
        let text = result.to_string();
        for private in ["notes", "address", "sqlite", "key.json", "wallets"] {
            assert!(!text.contains(private));
        }
        f.assert_rpc_closed();
    }
    assert_eq!(raw_count(&f), 4098);
    let result = success(sync(&f, "wallet-sync-long", "", "8").output().unwrap());
    assert_eq!(result["blocks_processed"], 0);
    assert_eq!(result["batches_committed"], 0);
    assert_eq!(raw_count(&f), 4098);
    let calls = fs::read_to_string(f.root.path().join("sync-calls")).unwrap();
    assert_eq!(calls.lines().filter(|l| *l == "state-init").count(), 1);
    assert_eq!(calls.lines().filter(|l| *l == "state-append").count(), 17);
    f.assert_rpc_closed();
}

#[test]
fn sync_capability_and_network_lock_refuse_before_database_or_external_effects() {
    use fs2::FileExt;
    let f = payment_fixture();
    refusal(sync(&f, "wallet-sync", "old", "1").output().unwrap());
    assert!(f.calls().is_empty());
    assert!(!wallet(&f).join("scan-v2.initialized").exists());
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(wallet(&f).parent().unwrap().join("payments.lock"))
        .unwrap();
    fs::set_permissions(
        wallet(&f).parent().unwrap().join("payments.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    lock.try_lock_exclusive().unwrap();
    refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert!(f.calls().is_empty());
    assert!(!wallet(&f).join("scan-v2.initialized").exists());
    assert_eq!(
        fs::read_to_string(f.root.path().join("sync-calls")).unwrap(),
        "capabilities\ncapabilities\n"
    );
}

#[test]
fn sync_combined_backend_and_cleanup_failure_retains_safe_primary_diagnostic() {
    let f = payment_fixture();
    let output = sync(&f, "wallet-sync-cleanup-fails", "lost", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stage=backend-append; class=backend-failure"),
        "{stderr}"
    );
    assert!(
        stderr.contains("remote SSM termination is unconfirmed"),
        "{stderr}"
    );
    assert!(!stderr.contains("injected lost commit reply"));
    assert!(!stderr.contains("SECRET-WALLET-DIAGNOSTIC"));
    refusal(output);
    f.assert_rpc_closed();
    let database = wallet(&f).join("scan-v2.sqlite");
    let committed = fs::read(&database).unwrap();
    let state: Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(state["tip_height"], 2);
    assert_eq!(state["generation"], 1);
    let prior = raw_count(&f);
    let result = success(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert_eq!(result["outcome"], "current_at_observation");
    assert_eq!(result["batches_committed"], 0);
    assert_eq!(result["payment_enabled"], false);
    assert_eq!(result["spendability_checked"], false);
    assert_eq!(raw_count(&f), prior);
    assert_eq!(fs::read(database).unwrap(), committed);
    f.assert_rpc_closed();
}

#[test]
fn sync_interruption_and_transport_loss_preserve_commit_and_resume_one_batch() {
    for (node, backend, diagnostic) in [
        (
            "wallet-sync",
            "interrupt",
            "stage=session-check; class=cancelled",
        ),
        (
            "wallet-sync-drop",
            "",
            "stage=rpc-read; class=rpc-transport",
        ),
    ] {
        let f = payment_fixture();
        let output = sync(&f, node, backend, "2")
            .env("ZDN_SYNC_HEIGHT", "257")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(
            stderr.contains("No current or spendable result"),
            "{stderr}"
        );
        refusal(output);
        f.assert_rpc_closed();
        let committed: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(committed["tip_height"], 255);
        assert_eq!(committed["generation"], 1);
        // Transport loss occurs during collection of the next batch, not at
        // a height ceiling: its first raw read is attempted but not committed.
        let prior_raw = raw_count(&f);
        assert_eq!(prior_raw, if backend == "interrupt" { 256 } else { 257 });
        let resumed = success(
            sync(&f, "wallet-sync", "", "1")
                .env("ZDN_SYNC_HEIGHT", "257")
                .output()
                .unwrap(),
        );
        assert_eq!(resumed["outcome"], "current_at_observation");
        assert_eq!(resumed["starting_height"], 255);
        assert_eq!(resumed["committed_height"], 257);
        assert_eq!(resumed["generation"], 2);
        assert_eq!(resumed["batches_committed"], 1);
        assert_eq!(resumed["blocks_processed"], 2);
        assert_eq!(resumed["payment_enabled"], false);
        assert_eq!(resumed["spendability_checked"], false);
        assert_eq!(raw_count(&f) - prior_raw, 2);
        let committed: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(committed["tip_height"], 257);
        assert_eq!(committed["generation"], 2);
        f.assert_rpc_closed();
    }
}

#[test]
fn sync_commit_failures_revalidate_candidates_and_cleanup_without_reset() {
    for (node, backend, height) in [
        ("wallet-sync", "before", Value::Null),
        ("wallet-sync", "lost", json!(2)),
        ("wallet-sync", "receipt", json!(2)),
        ("wallet-sync-after", "", json!(2)),
        ("wallet-sync-cleanup-fails", "", json!(2)),
    ] {
        let f = payment_fixture();
        let output = sync(&f, node, backend, "1").output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if backend == "receipt" {
            assert!(
                stderr.contains("stage=backend-receipt; class=invalid-backend-receipt"),
                "{stderr}"
            );
        } else if !backend.is_empty() {
            assert!(
                stderr.contains("stage=backend-append; class=backend-failure"),
                "{stderr}"
            );
        }
        assert!(!stderr.contains("SECRET-WALLET-DIAGNOSTIC"));
        refusal(output);
        f.assert_rpc_closed();
        let state: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(state["tip_height"], height);
        let prior = raw_count(&f);
        let result = success(sync(&f, "wallet-sync", "", "1").output().unwrap());
        assert_eq!(result["outcome"], "current_at_observation");
        assert_eq!(raw_count(&f) - prior, if height.is_null() { 3 } else { 0 });
        f.assert_rpc_closed();
    }
}

#[test]
fn sync_refuses_forks_rollback_and_bad_collection_without_destructive_recovery() {
    let f = payment_fixture();
    success(sync(&f, "wallet-sync", "", "1").output().unwrap());
    let bytes = fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap();
    for mode in ["wallet-sync-reorg", "wallet-sync-rollback"] {
        let count = raw_count(&f);
        let output = sync(&f, mode, "", "1").output().unwrap();
        assert!(String::from_utf8_lossy(&output.stderr).contains("canonical sync tip conflict"));
        refusal(output);
        assert_eq!(raw_count(&f), count);
        assert_eq!(fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap(), bytes);
        f.assert_rpc_closed();
    }
    for mode in [
        "wallet-sync-malformed",
        "wallet-sync-bytes",
        "wallet-sync-tree",
        "wallet-sync-large",
    ] {
        let f = payment_fixture();
        refusal(sync(&f, mode, "", "1").output().unwrap());
        let s: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(s["generation"], 0);
        f.assert_rpc_closed();
    }
    let f = payment_fixture();
    let p = success(sync(&f, "wallet-sync-moving", "", "1").output().unwrap());
    assert_eq!(p["outcome"], "incomplete");
    assert_eq!(p["committed_height"], 2);
    let latest: u64 = fs::read_to_string(f.root.path().join("sync-observed-height"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(latest > 2);
    assert_eq!(p["observed_height"], latest);
    assert_eq!(p["scan_lag_blocks"], latest - 2);
    f.assert_rpc_closed();
}

#[test]
fn sync_missing_corrupt_incompatible_scope_and_public_identity_fail_before_aws() {
    let f = payment_fixture();
    success(sync(&f, "wallet-sync", "", "1").output().unwrap());
    f.assert_rpc_closed();
    let calls = f.calls();
    let db = wallet(&f).join("scan-v2.sqlite");
    let saved = fs::read(&db).unwrap();
    for mode in ["schema", "scope"] {
        refusal(sync(&f, "wallet-sync", mode, "1").output().unwrap());
        assert_eq!(f.calls(), calls);
        assert_eq!(fs::read(&db).unwrap(), saved);
    }
    fs::write(&db, b"corrupt").unwrap();
    refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert_eq!(fs::read(&db).unwrap(), b"corrupt");
    fs::remove_file(&db).unwrap();
    refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert!(!db.exists());
    assert_eq!(f.calls(), calls);
    let mut public: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("public.json")).unwrap()).unwrap();
    public["ironwood_address_hex"] = json!("33".repeat(43));
    fs::write(f.root.path().join("public.json"), public.to_string()).unwrap();
    refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert_eq!(f.calls(), calls);
}

#[test]
fn sync_raw_byte_bound_splits_before_block_bound_and_resumes_exactly() {
    for (terminal_bytes, total_bytes) in [
        (1_048_572, 67_108_863),
        (1_048_573, 67_108_864),
        (1_048_574, 67_108_865),
    ] {
        let f = payment_fixture();
        // Capture the actual process-boundary input, then delegate unchanged to
        // the existing backend (including its independent 64 MiB ceiling check).
        // These are transport contract controls, not real backend storage tests.
        let backend = f.root.path().join("wallet-backend");
        fs::rename(&backend, f.root.path().join("raw-byte-wallet-backend")).unwrap();
        executable::write(
            &backend,
            r#"#!/bin/sh
set -eu
if [ "$1" = state-append ]; then
    /bin/cp "$4" "$ZDN_CONNECT_FIXTURE/raw-batch.json"
fi
exec "$ZDN_CONNECT_FIXTURE/raw-byte-wallet-backend" "$@"
"#,
        )
        .unwrap();
        fs::set_permissions(&backend, fs::Permissions::from_mode(0o700)).unwrap();
        let command = || {
            let mut c = sync(&f, "wallet-sync-byte-limit", "", "1");
            c.env("ZDN_SYNC_HEIGHT", "22")
                .env("ZDN_SYNC_TERMINAL_BYTES", terminal_bytes.to_string());
            c
        };
        let batch_lengths = |start, count| {
            let batch: Value =
                serde_json::from_slice(&fs::read(f.root.path().join("raw-batch.json")).unwrap())
                    .unwrap();
            assert_eq!(batch["start_height"], start);
            let blocks = batch["blocks"].as_array().unwrap();
            assert_eq!(blocks.len(), count);
            blocks
                .iter()
                .map(|block| hex::decode(block.as_str().unwrap()).unwrap().len())
                .collect::<Vec<_>>()
        };
        let above = total_bytes > 67_108_864;
        let first = success(command().output().unwrap());
        assert_eq!(first["batches_committed"], 1);
        assert_eq!(first["committed_height"], if above { 21 } else { 22 });
        assert_eq!(first["blocks_processed"], if above { 22 } else { 23 });
        assert_eq!(
            first["outcome"],
            if above {
                "incomplete"
            } else {
                "current_at_observation"
            }
        );
        let lengths = batch_lengths(0, if above { 22 } else { 23 });
        assert_eq!(lengths[0], 3);
        assert_eq!(&lengths[1..22], &[3 * 1024 * 1024; 21]);
        let decoded_first: usize = lengths.iter().sum();
        if above {
            assert_eq!(decoded_first, 66_060_291);
            assert_eq!(decoded_first + terminal_bytes, total_bytes);
        } else {
            assert_eq!(lengths[22], terminal_bytes);
            assert_eq!(decoded_first, total_bytes);
        }
        assert_eq!(raw_count(&f), 23); // Includes the excluded lookahead above the limit.
        f.assert_rpc_closed();
        let second = success(command().output().unwrap());
        assert_eq!(second["committed_height"], 22);
        assert_eq!(second["batches_committed"], usize::from(above));
        assert_eq!(second["blocks_processed"], usize::from(above));
        assert_eq!(second["outcome"], "current_at_observation");
        if above {
            assert_eq!(batch_lengths(22, 1), vec![terminal_bytes]);
        }
        let state: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(state["generation"], if above { 2 } else { 1 });
        assert_eq!(state["tip_height"], 22);
        let calls = fs::read_to_string(f.root.path().join("sync-calls")).unwrap();
        assert_eq!(
            calls.lines().filter(|line| *line == "state-append").count(),
            if above { 2 } else { 1 }
        );
        let hashes: Vec<_> = fs::read_to_string(f.root.path().join("rpc-requests"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|request| request["body"]["method"] == "getblock")
            .map(|request| request["body"]["params"][0].clone())
            .collect();
        assert_eq!(hashes.len(), if above { 24 } else { 23 });
        assert_eq!(
            hashes[0],
            "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
        );
        for (height, hash) in hashes[1..23].iter().enumerate() {
            assert_eq!(hash, &json!(format!("{:064x}", height + 1)));
        }
        if above {
            assert_eq!(hashes[23], hashes[22]); // Only the excluded suffix is refetched.
        }
        f.assert_rpc_closed();
        println!(
            "raw candidate={total_bytes}; decoded first batch={decoded_first}; terminal={terminal_bytes}; resumed blocks={}",
            usize::from(above)
        );
    }
}

#[test]
fn sync_interrupted_init_and_wrong_receipt_scope_never_recreate_or_contact_aws() {
    let f = payment_fixture();
    let receipt_path = wallet(&f).join("wallet.json");
    let original = fs::read(&receipt_path).unwrap();
    for (field, value) in [
        ("network_id", json!("b81c4e9b-4612-4e0d-a3fa-c4ab68a04153")),
        ("consensus_fingerprint", json!("00".repeat(32))),
        ("name", json!("other")),
    ] {
        let mut receipt: Value = serde_json::from_slice(&original).unwrap();
        receipt[field] = value;
        fs::write(&receipt_path, receipt.to_string()).unwrap();
        refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
        assert!(f.calls().is_empty());
        assert!(!wallet(&f).join("scan-v2.initialized").exists());
    }
    fs::write(receipt_path, original).unwrap();
    refusal(sync(&f, "wallet-sync", "init-fail", "1").output().unwrap());
    assert!(wallet(&f).join("scan-v2.initialized").exists());
    assert!(!wallet(&f).join("scan-v2.sqlite").exists());
    refusal(sync(&f, "wallet-sync", "", "1").output().unwrap());
    assert!(f.calls().is_empty());
    assert_eq!(
        fs::read_to_string(f.root.path().join("sync-calls"))
            .unwrap()
            .lines()
            .filter(|l| *l == "state-init")
            .count(),
        1
    );
}

fn checkpoint_sync(f: &Fixture, height: u32, fork: Option<u32>, backend: &str) -> Command {
    let mut c = sync(f, "wallet-sync", backend, "1");
    c.env("ZDN_SYNC_HEIGHT", height.to_string());
    if let Some(from) = fork {
        c.env("ZDN_SYNC_FORK_FROM", from.to_string());
    }
    c
}

fn checkpoint_chain(f: &Fixture, last: u32) {
    for h in 1..=last {
        let mut c = checkpoint_sync(f, h, None, "rewind");
        if h == 1 {
            c.arg("--enable-rewind");
        }
        success(c.output().unwrap());
        f.assert_rpc_closed();
    }
}

#[test]
fn checkpoint_recovery_same_height_shallow_fork_and_rollback_select_latest_canonical() {
    for (height, fork, restored, blocks) in
        [(3, Some(3), 2, 1), (4, Some(3), 2, 2), (1, None, 1, 0)]
    {
        let f = payment_fixture();
        checkpoint_chain(&f, 3);
        let before = raw_count(&f);
        let result = success(
            checkpoint_sync(&f, height, fork, "rewind")
                .output()
                .unwrap(),
        );
        assert_eq!(result["recovery"]["rewound"], true);
        assert_eq!(result["recovery"]["restored_height"], restored);
        assert_eq!(result["recovery"]["replayed_from_genesis"], false);
        assert_eq!(result["committed_height"], height);
        assert_eq!(raw_count(&f) - before, blocks);
        let request: Value =
            serde_json::from_slice(&fs::read(f.root.path().join("rewind-request")).unwrap())
                .unwrap();
        assert_eq!(request["target"]["tip_height"], restored);
        f.assert_rpc_closed();
    }
}

#[test]
fn checkpoint_recovery_deep_window_miss_requires_explicit_replay() {
    let f = payment_fixture();
    checkpoint_chain(&f, 6);
    let db = wallet(&f).join("scan-v2.sqlite");
    let bytes = fs::read(&db).unwrap();
    let before = raw_count(&f);
    let output = checkpoint_sync(&f, 6, Some(1), "rewind").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("no retained canonical checkpoint"));
    refusal(output);
    assert_eq!(fs::read(&db).unwrap(), bytes);
    assert_eq!(raw_count(&f), before);
    assert!(!f.root.path().join("rewind-request").exists());
    let result = success(
        checkpoint_sync(&f, 6, Some(1), "rewind")
            .arg("--replay-from-genesis")
            .output()
            .unwrap(),
    );
    assert_eq!(result["recovery"]["replayed_from_genesis"], true);
    assert!(result["recovery"]["restored_height"].is_null());
    assert_eq!(raw_count(&f) - before, 7);
    f.assert_rpc_closed();
}

#[test]
fn checkpoint_recovery_bad_receipts_and_lost_reply_preserve_candidate_and_resume() {
    for mode in [
        "rewind-lost",
        "rewind-stale",
        "rewind-wrong",
        "rewind-missing",
    ] {
        let f = payment_fixture();
        checkpoint_chain(&f, 3);
        let before = raw_count(&f);
        refusal(checkpoint_sync(&f, 3, Some(3), mode).output().unwrap());
        assert_eq!(raw_count(&f), before, "{mode}");
        let candidate: Value =
            serde_json::from_slice(&fs::read(wallet(&f).join("scan-v2.sqlite")).unwrap()).unwrap();
        assert_eq!(candidate["generation"], 4);
        assert_eq!(candidate["tip_height"], 2);
        f.assert_rpc_closed();
        let result = success(checkpoint_sync(&f, 3, Some(3), "rewind").output().unwrap());
        assert_eq!(result["recovery"]["rewound"], false);
        assert_eq!(raw_count(&f) - before, 1);
        let calls = fs::read_to_string(f.root.path().join("sync-calls")).unwrap();
        assert_eq!(calls.lines().filter(|l| *l == "state-rewind").count(), 1);
        f.assert_rpc_closed();
    }
}

#[test]
fn checkpoint_recovery_explicit_unsupported_flags_refuse_before_aws() {
    for flag in ["--enable-rewind", "--replay-from-genesis"] {
        let f = payment_fixture();
        refusal(
            sync(&f, "wallet-sync", "v2", "1")
                .arg(flag)
                .output()
                .unwrap(),
        );
        assert!(f.calls().is_empty());
        assert!(!wallet(&f).join("scan-v2.initialized").exists());
    }
}

#[test]
fn checkpoint_recovery_preserves_original_payment_evidence_without_rebroadcast() {
    let f = payment_fixture();
    let output = payment_send(&f, "lost", "alice", None, "1");
    let public = payment_json(&output);
    let id = public["operation_id"].as_str().unwrap();
    let scope = wallet(&f).parent().unwrap().to_owned();
    let journal = scope.join("payments").join(format!("{id}.json"));
    let data = scope.join("payment-data").join(id);
    let evidence: Vec<_> = fs::read_dir(&data)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    let record = fs::read(&journal).unwrap();
    let broadcasts = || {
        fs::read_to_string(f.root.path().join("rpc-requests"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["body"]["method"] == "sendrawtransaction")
            .count()
    };
    let before = broadcasts();
    assert_eq!(before, 1);
    checkpoint_chain(&f, 3);
    success(checkpoint_sync(&f, 3, Some(3), "rewind").output().unwrap());
    assert_eq!(fs::read(journal).unwrap(), record);
    for (path, bytes) in evidence {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(broadcasts(), before);
    f.assert_rpc_closed();
}

#[test]
fn checkpoint_recovery_capable_backend_requires_stored_enablement() {
    let f = payment_fixture();
    success(checkpoint_sync(&f, 2, None, "rewind").output().unwrap());
    let db = wallet(&f).join("scan-v2.sqlite");
    let bytes = fs::read(&db).unwrap();
    let output = checkpoint_sync(&f, 2, None, "rewind")
        .arg("--enable-rewind")
        .env("ZDN_SYNC_ENABLE_CHANGED_ANCHOR", "1")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("enablement changed state summary"));
    refusal(output);
    assert_eq!(fs::read(&db).unwrap(), bytes);
    fs::remove_file(db.with_extension("checkpoints")).unwrap();
    let output = checkpoint_sync(&f, 2, Some(2), "rewind").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicitly enable rewind"));
    refusal(output);
    assert_eq!(fs::read(db).unwrap(), bytes);
    assert!(!f.root.path().join("rewind-request").exists());
    f.assert_rpc_closed();
}

#[test]
fn checkpoint_recovery_normal_payment_uses_enabled_retained_checkpoint_before_signing() {
    let f = payment_fixture();
    checkpoint_chain(&f, 3);
    let output = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_SYNC_BACKEND", "rewind")
    .env("ZDN_CONNECT_MODE", "wallet-sync")
    .env("ZDN_SYNC_HEIGHT", "3")
    .env("ZDN_SYNC_FORK_FROM", "3")
    .output()
    .unwrap();
    // The sync RPC fixture deliberately cannot observe payments. Reaching an
    // exact signed envelope proves recovery completed before preparation; it
    // does not pretend the fixture confirmed a real payment.
    assert!(!output.status.success());
    assert_eq!(payment_json(&output)["txid"], "ab".repeat(32));
    let request: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("rewind-request")).unwrap()).unwrap();
    assert_eq!(request["target"]["tip_height"], 2);
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|l| *l == "construct-snapshot-payment")
            .count(),
        1
    );
    f.assert_rpc_closed();
}
