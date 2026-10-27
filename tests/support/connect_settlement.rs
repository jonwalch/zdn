//! Public CLI coverage of explicit settlement maintenance; no Store internals.
use super::*;
use std::{collections::BTreeMap, path::Path, process::Output};

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    payment_json(&output)
}

// These maintenance commands deliberately have no backend selection.
fn local(f: &Fixture, command: &str, extra: &[&str]) -> Output {
    f.command()
        .args([
            "wallet",
            "--wallet-dir",
            "wallets",
            command,
            "--manifest",
            "manifest.json",
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "participant",
            "--startup-timeout-secs",
            "10",
        ])
        .args(extra)
        .env("ZDN_CONNECT_MODE", "wallet-classified-payment-settlement")
        .output()
        .unwrap()
}

fn enable(f: &Fixture) {
    for command in ["journal-migrate", "journal-enable-settlements"] {
        let preview = success(local(f, command, &[]));
        let token = preview["proposal_sha256"].as_str().unwrap();
        assert!(!local(f, command, &["--apply", &"00".repeat(32)])
            .status
            .success());
        success(local(f, command, &["--apply", token]));
    }
}

fn archive(f: &Fixture, id: &str, mode: &str, depth: &str, token: Option<&str>) -> Output {
    let mut cmd = payment_command(
        f,
        "ok",
        &[
            "wallet",
            "archive-payment",
            "--wallet",
            "alice",
            "--operation-id",
            id,
            "--settlement-depth",
            depth,
        ],
    );
    cmd.env(
        "ZDN_CONNECT_MODE",
        format!("wallet-classified-payment-{mode}"),
    );
    if let Some(token) = token {
        cmd.args(["--apply", token]);
    }
    cmd.output().unwrap()
}

fn scope(f: &Fixture) -> std::path::PathBuf {
    f.root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string())
}

fn snapshot(path: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn collect(base: &Path, path: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(base, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(base).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(path, path, &mut files);
    files
}

fn confirmed(f: &Fixture) -> String {
    let output = success(payment_send(f, "ok", "alice", None, "1"));
    assert_eq!(output["outcome"]["kind"], "confirmed");
    output["operation_id"].as_str().unwrap().to_owned()
}

fn unsigned(f: &Fixture) -> Value {
    let mut command = payment_command(
        f,
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
    command.env("ZDN_CONNECT_MODE", "wallet-classified-changed");
    let interrupted = command.output().unwrap();
    assert!(!interrupted.status.success());
    let receipt = payment_json(&interrupted);
    let original = success(local(
        f,
        "journal",
        &["--operation-id", receipt["operation_id"].as_str().unwrap()],
    ));
    assert_eq!(original["outcome"]["kind"], "reserved");
    assert!(!original["inputs"].as_array().unwrap().is_empty());
    original
}

#[test]
fn settlement_enable_is_explicit_local_and_reconcile_is_backend_free_authenticated() {
    let f = payment_fixture();
    confirmed(&f);
    let calls = f.calls();
    let backend = fs::read(f.root.path().join("backend-calls")).unwrap();
    assert!(!local(&f, "journal-enable-settlements", &[])
        .status
        .success());
    enable(&f);
    assert_eq!(f.calls(), calls);
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend
    );
    for _ in 0..2 {
        let result = success(local(&f, "journal-reconcile", &[]));
        assert_eq!(result["reconciled"], true);
        assert_eq!(result["broadcast"], false);
        f.assert_rpc_closed();
    }
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend
    );
    let calls = f.calls();
    assert_eq!(
        calls
            .lines()
            .filter(|s| s.contains("start-session"))
            .count(),
        3
    ); // send + two fresh reconciliations
       // Authentication is the participant's AWS session plus chain identity,
       // not HTTP Basic auth (the loopback node deliberately receives none).
    for action in ["get-caller-identity", "get-document", "terminate-session"] {
        assert_eq!(calls.lines().filter(|s| s.contains(action)).count(), 3);
    }
}

#[test]
fn settlement_archive_depth_tokens_and_immutable_queryable_history() {
    let f = payment_fixture();
    let id = confirmed(&f);
    let original = fs::read(scope(&f).join("payments").join(format!("{id}.json"))).unwrap();
    let data = snapshot(&scope(&f).join("payment-data"));
    enable(&f);
    assert!(!archive(&f, &id, "settlement", "5", None).status.success());
    let preview = success(archive(&f, &id, "settlement", "4", None));
    assert_eq!(preview["depth"], 4);
    assert_eq!(preview["archived"], false);
    let token = preview["proposal_sha256"].as_str().unwrap();
    assert!(!archive(&f, &id, "settlement", "4", Some(&"00".repeat(32)))
        .status
        .success());
    assert!(!archive(&f, &id, "settlement", "3", Some(token))
        .status
        .success());
    let shallow = success(archive(&f, &id, "settlement", "1", None));
    let stale = archive(
        &f,
        &id,
        "settlement-low",
        "1",
        Some(shallow["proposal_sha256"].as_str().unwrap()),
    );
    assert!(!stale.status.success()); // Only the fresh tip changed, not requested depth.
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale settlement archive proposal"));
    assert_eq!(
        success(archive(&f, &id, "settlement", "4", Some(token)))["archived"],
        true
    );
    assert_eq!(
        success(local(&f, "journal", &["--operation-id", &id])),
        serde_json::from_slice::<Value>(&original).unwrap()
    );
    let inventory = success(local(&f, "journal", &[]));
    assert_eq!(inventory["total_operations"], 1);
    assert_eq!(inventory["active_operations"], 0);
    assert_eq!(inventory["operations"][0]["disposition"], "archived");
    assert_eq!(snapshot(&scope(&f).join("payment-data")), data);
    assert_eq!(
        fs::read(scope(&f).join("payments").join(format!("{id}.json"))).unwrap(),
        original
    );
    assert!(!payment_send(&f, "ok", "alice", Some(&id), "1")
        .status
        .success());
    f.assert_rpc_closed();
}

#[test]
fn settlement_archive_rejects_missing_wrong_and_duplicate_block_inclusion() {
    let f = payment_fixture();
    let id = confirmed(&f);
    enable(&f);
    let data = snapshot(&scope(&f).join("payment-data"));
    let preview = success(archive(&f, &id, "settlement", "1", None));
    for mode in [
        "settlement-missing-inclusion",
        "settlement-wrong-inclusion",
        "settlement-duplicate-inclusion",
        "lost",
        "stale",
    ] {
        let output = archive(
            &f,
            &id,
            mode,
            "1",
            Some(preview["proposal_sha256"].as_str().unwrap()),
        );
        assert!(!output.status.success(), "{mode}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(if mode.starts_with("settlement-") {
                "canonical block does not contain"
            } else if mode == "lost" {
                "inclusion unavailable"
            } else {
                "recorded canonical block"
            }),
            "{mode}: {error}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("\"archived\": true"));
        f.assert_rpc_closed();
    }
    assert_eq!(snapshot(&scope(&f).join("payment-data")), data);
    // Failures did not remove the active record: the original proposal still applies.
    success(archive(
        &f,
        &id,
        "settlement",
        "1",
        Some(preview["proposal_sha256"].as_str().unwrap()),
    ));
}

#[test]
fn settlement_archive_cleanup_failure_never_reports_success() {
    let f = payment_fixture();
    let id = confirmed(&f);
    enable(&f);
    let preview = success(archive(&f, &id, "settlement", "4", None));
    let output = archive(
        &f,
        &id,
        "settlement-cleanup-fails",
        "4",
        Some(preview["proposal_sha256"].as_str().unwrap()),
    );
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\"archived\": true"));
    // Local commit can precede transport cleanup; exact history must remain queryable.
    assert_eq!(
        success(local(&f, "journal", &["--operation-id", &id]))["operation_id"],
        id
    );
    f.assert_rpc_closed();
}

#[test]
fn settlement_archive_requires_backend_and_exact_original_transaction_before_rpc() {
    let f = payment_fixture();
    let id = confirmed(&f);
    enable(&f);
    let calls = f.calls();
    assert!(!local(
        &f,
        "archive-payment",
        &[
            "--wallet",
            "alice",
            "--operation-id",
            &id,
            "--settlement-depth",
            "1"
        ]
    )
    .status
    .success());
    let directory = scope(&f).join("payment-data").join(&id);
    let original = snapshot(&directory);
    let path = directory.join("transaction.json");
    let bytes = fs::read(&path).unwrap();
    let mut transaction: Value = serde_json::from_slice(&bytes).unwrap();
    transaction["raw_transaction_hex"] = json!("0000");
    fs::write(&path, serde_json::to_vec(&transaction).unwrap()).unwrap();
    assert!(!archive(&f, &id, "settlement", "1", None).status.success());
    fs::write(&path, &bytes).unwrap();
    fs::rename(&path, directory.join("saved-transaction")).unwrap();
    assert!(!archive(&f, &id, "settlement", "1", None).status.success());
    fs::rename(directory.join("saved-transaction"), &path).unwrap();
    assert_eq!(f.calls(), calls); // Invalid originals never reach the node.
    assert_eq!(snapshot(&directory), original);
    success(archive(&f, &id, "settlement", "1", None));
}

#[test]
fn settlement_archived_reorg_restores_alias_guard_before_selection_or_signing() {
    let f = payment_fixture();
    let id = confirmed(&f);
    enable(&f);
    let preview = success(archive(&f, &id, "settlement", "4", None));
    success(archive(
        &f,
        &id,
        "settlement",
        "4",
        Some(preview["proposal_sha256"].as_str().unwrap()),
    ));
    let backend = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    let dispatches = fs::read(f.root.path().join("dispatches")).unwrap();
    let output = payment_send(&f, "settlement-fork", "alias", None, "1");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("quarantine") || error.contains("unresolved"),
        "{error}"
    );
    let after = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    let inventory = success(local(&f, "journal", &[]));
    let restored = inventory["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["operation_id"] == id)
        .unwrap();
    assert_eq!(restored["disposition"], "reorg_quarantine");
    assert!(restored["reserved_inputs"].as_u64().unwrap() > 0);
    for action in ["prepare-payment", "construct-payment"] {
        assert_eq!(
            after.lines().filter(|s| *s == action).count(),
            backend.lines().filter(|s| *s == action).count(),
            "{action}"
        );
    }
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatches
    );
    assert!(!payment_send(&f, "ok", "alice", Some(&id), "1")
        .status
        .success());
    let result = success(local(&f, "journal-reconcile", &[]));
    assert_eq!(result["broadcast"], false);
    assert_eq!(
        fs::read(f.root.path().join("dispatches")).unwrap(),
        dispatches
    );
    f.assert_rpc_closed();
}

#[test]
fn catalog_write_failure_preserves_unsigned_reservations_and_migration_originals() {
    for limit in [0, 4096] {
        for action in [
            "journal-migrate",
            "cancel-payment",
            "journal-enable-settlements",
        ] {
            let f = payment_fixture();
            let original = unsigned(&f);
            let id = original["operation_id"].as_str().unwrap();
            let originals = snapshot(&scope(&f).join("payments"));
            let indexed = action != "journal-migrate";
            if indexed {
                let preview = success(local(&f, "journal-migrate", &[]));
                success(local(
                    &f,
                    "journal-migrate",
                    &["--apply", preview["proposal_sha256"].as_str().unwrap()],
                ));
            }
            let selection = if action == "cancel-payment" {
                vec!["--operation-id", id]
            } else {
                vec![]
            };
            let preview = success(local(&f, action, &selection));
            let mut extra = selection.clone();
            extra.extend(["--apply", preview["proposal_sha256"].as_str().unwrap()]);
            let calls = f.calls();
            let backend = fs::read(f.root.path().join("backend-calls")).unwrap();
            let mut command = f.command();
            command
                .args([
                    "wallet",
                    "--wallet-dir",
                    "wallets",
                    action,
                    "--manifest",
                    "manifest.json",
                    "--endpoints",
                    "endpoints.json",
                    "--aws-profile",
                    "participant",
                ])
                .args(&extra);
            // Real SQLite I/O fails under a child-only file-growth limit. This
            // is not a simulated receipt, whole-filesystem exhaustion or ENOSPC.
            let failed = native_exec::command(f.root.path(), command.get_program(), Some(limit))
                .args(command.get_args())
                .env_clear()
                .envs(command.get_envs().map(|(key, value)| (key, value.unwrap())))
                .current_dir(f.root.path())
                .output()
                .unwrap();
            assert!(failed.status.code().is_some());
            assert!(!failed.status.success());
            let error = String::from_utf8_lossy(&failed.stderr);
            assert!(
                error.contains("disk I/O error")
                    || error.contains("database or disk is full")
                    || error.contains("File too large"),
                "limit={limit} action={action}: {error}"
            );
            assert_eq!(f.calls(), calls);
            assert_eq!(
                fs::read(f.root.path().join("backend-calls")).unwrap(),
                backend
            );
            assert!(!f.root.path().join("dispatches").exists());
            if indexed {
                assert_eq!(
                    success(local(&f, "journal", &["--operation-id", id])),
                    original
                );
                let retained = success(local(&f, action, &selection));
                if action == "cancel-payment" {
                    assert_eq!(retained["eligible"], true);
                }
                assert_eq!(retained["proposal_sha256"], preview["proposal_sha256"]);
                success(local(&f, action, &extra));
                assert_eq!(
                    success(local(&f, "journal", &["--operation-id", id]))["outcome"]["kind"],
                    if action == "cancel-payment" {
                        "cancelled"
                    } else {
                        "reserved"
                    }
                );
                let inventory = success(local(&f, "journal", &[]));
                assert_eq!(inventory["total_operations"], 1);
                assert_eq!(
                    inventory["active_operations"],
                    u32::from(action != "cancel-payment")
                );
                if action == "journal-enable-settlements" {
                    assert_eq!(inventory["reconciliation_pending"], true);
                    assert_eq!(
                        inventory["operations"][0]["reserved_inputs"],
                        original["inputs"].as_array().unwrap().len()
                    );
                }
            } else {
                assert!(scope(&f).join("payments.catalog.sqlite").exists());
                assert!(!scope(&f).join("payments/.catalog-v1").exists());
                assert!(!local(&f, "journal", &[]).status.success());
                let refused = local(&f, action, &extra);
                assert!(!refused.status.success());
                assert!(String::from_utf8_lossy(&refused.stderr).contains("retain originals"));
            }
            // A failed catalog write never rewrites or removes legacy evidence;
            // the only extra payment-directory file is the successful barrier.
            let mut retained = snapshot(&scope(&f).join("payments"));
            retained.remove(Path::new(".catalog-v1"));
            assert_eq!(retained, originals);
            assert_eq!(f.calls(), calls);
            assert_eq!(
                fs::read(f.root.path().join("backend-calls")).unwrap(),
                backend
            );
        }
    }
}

#[test]
fn journal_record_and_aggregate_byte_boundaries_are_preserved_by_migration() {
    // JRN-04: compact typed metadata, not expensive transactions or a fake
    // catalog. Only the public migration command creates SQLite authority.
    for aggregate in [false, true] {
        for delta in [-1_i64, 0, 1] {
            let f = payment_fixture();
            let mut record = unsigned(&f);
            let first_id = record["operation_id"].as_str().unwrap().to_owned();
            record["plan"] = Value::Null;
            record["inputs"] = json!([]);
            record["outcome"] = json!({"kind":"prepared"});
            record["request"] = json!({"fixture_payload":""});
            let count = if aggregate { 17 } else { 1 };
            let bound = if aggregate {
                64 * 1024 * 1024
            } else {
                4 * 1024 * 1024
            };
            let mut total = 0;
            for index in 0..count {
                let id = if index == 0 {
                    first_id.clone()
                } else {
                    uuid::Uuid::from_u128(index as u128).to_string()
                };
                record["operation_id"] = json!(id);
                record["request"]["fixture_payload"] = json!("");
                // Keep every aggregate-test record strictly below 4 MiB, so
                // the +1 refusal discriminates the aggregate bound itself.
                let size = if !aggregate {
                    (bound + delta) as usize
                } else if index < 16 {
                    4 * 1024 * 1024 - 1024
                } else {
                    (16 * 1024 + delta) as usize
                };
                let overhead = serde_json::to_vec(&record).unwrap().len();
                record["request"]["fixture_payload"] = json!("x".repeat(size - overhead));
                let bytes = serde_json::to_vec(&record).unwrap();
                assert_eq!(bytes.len(), size);
                total += bytes.len();
                zdn::foundation::write_private(
                    &scope(&f).join("payments").join(format!("{id}.json")),
                    &bytes,
                )
                .unwrap();
            }
            assert_eq!(total as i64, bound + delta);
            let originals = snapshot(&scope(&f).join("payments"));
            let calls = f.calls();
            let backend = fs::read(f.root.path().join("backend-calls")).unwrap();
            let inventory = local(&f, "journal", &["--limit", "1"]);
            if delta == 1 {
                assert!(!inventory.status.success());
                assert!(
                    String::from_utf8_lossy(&inventory.stderr).contains(if aggregate {
                        "payment journal exceeds size limit"
                    } else {
                        "payment record exceeds size limit"
                    })
                );
                assert!(!local(&f, "journal-migrate", &[]).status.success());
                assert!(!scope(&f).join("payments.catalog.sqlite").exists());
                assert!(!scope(&f).join("payments/.catalog-v1").exists());
            } else {
                let inventory = success(inventory);
                assert_eq!(inventory["total_operations"], count);
                assert_eq!(inventory["active_record_bytes"], total);
                assert_eq!(inventory["operations"].as_array().unwrap().len(), 1);
                let preview = success(local(&f, "journal-migrate", &[]));
                success(local(
                    &f,
                    "journal-migrate",
                    &["--apply", preview["proposal_sha256"].as_str().unwrap()],
                ));
                let indexed = success(local(&f, "journal", &["--limit", "1"]));
                assert_eq!(indexed["total_operations"], count);
                assert_eq!(indexed["active_record_bytes"], total);
                assert_eq!(indexed["operations"], inventory["operations"]);
                assert_eq!(indexed["active_byte_limit"], 64 * 1024 * 1024);
            }
            let mut retained = snapshot(&scope(&f).join("payments"));
            retained.remove(Path::new(".catalog-v1"));
            assert_eq!(retained, originals);
            assert_eq!(f.calls(), calls);
            assert_eq!(
                fs::read(f.root.path().join("backend-calls")).unwrap(),
                backend
            );
        }
    }
}
