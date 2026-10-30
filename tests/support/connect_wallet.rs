//! Proof-free wallet responses for connection/payment CLI orchestration tests.

use super::native_tool;
use eyre::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn private(path: &str, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn framed_digest<'a>(prefix: &[u8], entries: impl Iterator<Item = &'a str>) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(prefix);
    for entry in entries {
        let raw = hex::decode(entry)?;
        digest.update((raw.len() as u64).to_le_bytes());
        digest.update(raw);
    }
    Ok(hex::encode(digest.finalize()))
}

fn mempool(path: &str) -> Result<String> {
    let pending = read_json(path)?;
    let mut entries: Vec<_> = pending["transactions"].as_array().unwrap().iter().collect();
    entries.sort_by_key(|entry| entry["txid"].as_str().unwrap());
    framed_digest(
        b"ironwood-wallet-mempool/v1\0",
        entries
            .into_iter()
            .map(|e| e["raw_transaction_hex"].as_str().unwrap()),
    )
}

fn response(root: &Path, args: &[String]) -> Result<Value> {
    let action = args[0].as_str();
    if action == "capabilities" || action.starts_with("state-") {
        let mode = std::env::var("ZDN_SYNC_BACKEND").unwrap_or_default();
        writeln!(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("sync-calls"))?,
            "{action}"
        )?;
        if action == "capabilities" {
            if mode.starts_with("rewind") {
                return Ok(
                    json!({"schema_version":1,"capabilities":["ironwood-wallet-state/v2","ironwood-wallet-snapshot-payment/v2","ironwood-wallet-state-rewind/v2"]}),
                );
            }
            if mode == "transparent" {
                return Ok(
                    json!({"schema_version":1,"capabilities":["ironwood-wallet-state/v2","ironwood-wallet-snapshot-payment/v2","transparent-wallet-payments/v1"]}),
                );
            }
            if mode == "v2" {
                return Ok(
                    json!({"schema_version":1,"capabilities":["ironwood-wallet-state/v2","ironwood-wallet-snapshot-payment/v2"]}),
                );
            }
            return Ok(
                json!({"schema_version":1,"capabilities":if mode == "old" { vec!["ironwood-wallet-state/v1"] } else { vec!["ironwood-wallet-state/v2"] }}),
            );
        }
        if action == "state-init" {
            if mode == "init-fail" {
                bail!("injected interrupted initialization");
            }
            let identity = read_json(&args[2])?;
            let s = json!({"schema_version":2,"capability":"ironwood-wallet-state/v2",
                "network_id":identity["network_id"],"generation":0,"state_sha256":"00".repeat(32),
                "parent_state_sha256":null,"index_root_sha256":"00".repeat(32),
                "tip_height":null,"tip_hash":null,"anchor_hex":"00".repeat(32),
                "commitment_count":0,"owned_transparent_zat":0,"notes":[],
                "canonicality":"caller_attested_not_live_checked"});
            private(&args[3], &serde_json::to_vec(&s)?)?;
            return Ok(s);
        }
        let db = if action == "state-status" || action.contains("rewind") {
            &args[3]
        } else {
            &args[2]
        };
        let mut s = read_json(db)?;
        if mode == "schema" {
            s["schema_version"] = json!(1);
        }
        if mode == "scope" {
            s["network_id"] = json!("b81c4e9b-4612-4e0d-a3fa-c4ab68a04153");
        }
        if action == "state-status" {
            return Ok(s);
        }
        // This is a transport fixture, not an implementation of authenticated
        // storage: the backend's checkpoint algorithm has independent tests.
        let checkpoints_path = Path::new(db).with_extension("checkpoints");
        let checkpoint = |s: &Value| {
            json!({"generation":s["generation"],
            "state_sha256":s["state_sha256"],"tip_height":s["tip_height"],"tip_hash":s["tip_hash"]})
        };
        if action == "state-enable-rewind" {
            assert_eq!(args[4], s["state_sha256"].as_str().unwrap());
            if !checkpoints_path.exists() {
                fs::write(&checkpoints_path, b"[]")?;
            }
            if std::env::var("ZDN_SYNC_ENABLE_CHANGED_ANCHOR").as_deref() == Ok("1") {
                s["anchor_hex"] = json!("ee".repeat(32));
            }
            return Ok(s);
        }
        if action == "state-inspect-rewind" {
            assert_eq!(read_json(&args[4])?, json!([]));
            return Ok(
                json!({"current":checkpoint(&s),"rewind_enabled":checkpoints_path.exists(),
                "max_checkpoints":4,"checkpoints":if checkpoints_path.exists() {read_json(&checkpoints_path)?} else {json!([])},
                "blocks":[],"canonicality":"caller_attested_not_live_checked"}),
            );
        }
        if action == "state-rewind" {
            let request = read_json(&args[4])?;
            assert_eq!(request["expected"], checkpoint(&s));
            assert_eq!(request.as_object().unwrap().len(), 2);
            let target = &request["target"];
            if !target.is_null() {
                assert!(read_json(&checkpoints_path)?
                    .as_array()
                    .unwrap()
                    .contains(target));
            }
            fs::write(root.join("rewind-request"), serde_json::to_vec(&request)?)?;
            let prior = s.clone();
            s["generation"] = json!(s["generation"].as_u64().unwrap() + 1);
            s["parent_state_sha256"] = prior["state_sha256"].clone();
            s["state_sha256"] = json!(format!("{:064x}", s["generation"].as_u64().unwrap()));
            s["tip_height"] = target["tip_height"].clone();
            s["tip_hash"] = target["tip_hash"].clone();
            fs::write(db, serde_json::to_vec(&s)?)?;
            match mode.as_str() {
                "rewind-lost" => bail!("injected lost rewind reply"),
                "rewind-stale" => return Ok(prior),
                "rewind-wrong" => s["tip_hash"] = json!("ee".repeat(32)),
                "rewind-missing" => {
                    s.as_object_mut().unwrap().remove("parent_state_sha256");
                }
                _ => {}
            }
            return Ok(s);
        }
        let b = read_json(&args[3])?;
        let blocks = b["blocks"].as_array().unwrap();
        assert!(!blocks.is_empty() && blocks.len() <= 256);
        assert_eq!(b["expected_state_sha256"], s["state_sha256"]);
        assert_eq!(
            b["start_height"].as_u64().unwrap(),
            s["tip_height"].as_u64().map_or(0, |h| h + 1)
        );
        assert_eq!(b["identity"]["network_id"], s["network_id"]);
        assert!(
            blocks
                .iter()
                .map(|b| b.as_str().unwrap().len() / 2)
                .sum::<usize>()
                <= 64 * 1024 * 1024
        );
        if mode == "before" {
            bail!("injected precommit failure");
        }
        if checkpoints_path.exists() {
            let mut retained = read_json(&checkpoints_path)?.as_array().unwrap().clone();
            retained.push(checkpoint(&s));
            if retained.len() > 4 {
                retained.remove(0);
            }
            fs::write(&checkpoints_path, serde_json::to_vec(&retained)?)?;
        }
        s["parent_state_sha256"] = s["state_sha256"].clone();
        let generation = s["generation"].as_u64().unwrap() + 1;
        s["generation"] = json!(generation);
        s["state_sha256"] = json!(format!("{generation:064x}"));
        s["tip_height"] = b["treestate"]["height"].clone();
        s["tip_hash"] = b["treestate"]["hash"].clone();
        s["anchor_hex"] = b["treestate"]["ironwood"]["commitments"]["finalRoot"].clone();
        fs::write(db, serde_json::to_vec(&s)?)?;
        if root.join("sync-after-commit").exists() {
            fs::write(root.join("sync-committed"), b"yes")?;
        }
        if mode == "lost" {
            bail!("injected lost commit reply: opaque-private-input SECRET-WALLET-DIAGNOSTIC");
        }
        if mode == "interrupt" {
            // The native-tool launcher records its controller, not the test
            // worker's immediate shell parent. Interrupt only this CLI fixture
            // after the durable commit and before it accepts the receipt.
            let controller: i32 = std::env::var("ZDN_TEST_CALLER")?.parse()?;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(controller),
                nix::sys::signal::Signal::SIGINT,
            )?;
        }
        if mode == "receipt" {
            s["parent_state_sha256"] = json!("ff".repeat(32));
        }
        return Ok(s);
    }
    if matches!(action, "key-create" | "key-public" | "key-import") {
        if action != "key-public" {
            private(args.last().unwrap(), b"opaque-private-input")?;
        }
        return read_json(root.join("public.json"));
    }
    if action.contains("snapshot") {
        return snapshot_response(root, args);
    }
    let payment = matches!(
        action,
        "prepare-payment" | "construct-payment" | "check-transaction" | "inventory"
    );
    if payment {
        writeln!(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("backend-calls"))?,
            "{action}"
        )?;
    }
    let result = match action {
        "construct-payment" => {
            json!({"schema_version":1,"plan":read_json(&args[4])?,"broadcast":false,"txid":"ab".repeat(32),"raw_transaction_hex":"01020304"})
        }
        "check-transaction" => {
            let plan = read_json(&args[3])?;
            let envelope = read_json(&args[4])?;
            json!({"schema_version":1,"valid":true,"broadcast":false,"txid":envelope["txid"],"request_sha256":plan["request_sha256"],"plan_authorization_hex":plan["plan_authorization_hex"]})
        }
        "scan" | "balance" | "balance-reserved" | "prepare-payment" | "inventory" => {
            if !payment {
                assert_eq!(
                    fs::metadata(Path::new(&args[3]).parent().unwrap())?
                        .permissions()
                        .mode()
                        & 0o077,
                    0
                );
            }
            let history = read_json(&args[2])?;
            let blocks = history["blocks"].as_array().unwrap();
            let hd = framed_digest(b"", blocks.iter().map(|raw| raw.as_str().unwrap()))?;
            if action == "prepare-payment" {
                // CLI request files are compact JSON in their typed digest order.
                // Bind the actual input bytes without importing production types.
                let bytes = fs::read(&args[4])?;
                let request: Value = serde_json::from_slice(&bytes)?;
                writeln!(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(root.join("requests"))?,
                    "{request}"
                )?;
                json!({"schema_version":1,"kind":request["kind"],"amount_zat":request["amount_zat"],"fee_zat":1,"history_sha256":hd,"mempool_sha256":mempool(&args[3])?,"tip_hash":history["treestate"]["hash"],"request_sha256":hex::encode(Sha256::digest(&bytes)),"plan_authorization_hex":"aa".repeat(32),"inputs":[{"kind":"ironwood","txid":"12".repeat(32),"action_index":0}]})
            } else {
                let mut scan = json!({"schema_version":1,"tip_height":blocks.len()-1,"tip_hash":history["treestate"]["hash"],"history_sha256":hd,"anchor_hex":history["treestate"]["ironwood"]["commitments"]["finalRoot"]});
                if action == "inventory" {
                    scan["mempool_sha256"] = json!(mempool(&args[3])?);
                    scan["rewards"] = json!([{"txid":"66".repeat(32),"output_index":2,"height":1,"value_zat":123,"mature":false,"mempool_spent":false}]);
                } else {
                    let mode = std::env::var("ZDN_WALLET_BACKEND").unwrap_or_else(|_| "ok".into());
                    scan["commitment_count"] = json!(3);
                    scan["notes"] = json!([
                        {"txid":"12".repeat(32),"action_index":0,"position":0,"value_zat":17,"spent":false},
                        {"txid":"34".repeat(32),"action_index":1,"position":1,"value_zat":91,"spent":true},
                        {"txid":"56".repeat(32),"action_index":0,"position":2,"value_zat":29,"spent":false}
                    ]);
                    match mode.as_str() {
                        "digest" => scan["history_sha256"] = json!("00".repeat(32)),
                        "tip" => scan["tip_hash"] = json!("00".repeat(32)),
                        "height" => scan["tip_height"] = json!(0),
                        "anchor" => scan["anchor_hex"] = json!("00".repeat(32)),
                        "duplicate" => scan["notes"][2]["position"] = json!(0),
                        "total" => scan["notes"][0]["value_zat"] = json!(2_100_000_000_000_000_u64),
                        "empty" => scan["notes"] = json!([]),
                        "fail" => bail!("SECRET-WALLET-DIAGNOSTIC"),
                        _ => {}
                    }
                    if action != "scan" {
                        scan.as_object_mut().unwrap().remove("notes");
                        let object = scan.as_object_mut().unwrap();
                        for (key, value) in [
                            ("mempool_sha256", json!(mempool(&args[3])?)),
                            ("confirmed_unspent_zat", json!(46)),
                            ("spendable_zat", json!(29)),
                            ("pending_spent_zat", json!(17)),
                            ("pending_zat", json!(7)),
                            ("immature_zat", json!(0)),
                        ] {
                            object.insert(key.into(), value);
                        }
                        if action == "balance-reserved" {
                            let excluded = read_json(&args[4])?;
                            let reserved = if excluded.as_array().unwrap().contains(
                                &json!({"kind":"ironwood","txid":"56".repeat(32),"action_index":0}),
                            ) {
                                29
                            } else {
                                0
                            };
                            scan["reserved_zat"] = json!(reserved);
                            scan["spendable_zat"] = json!(29 - reserved);
                        }
                        match mode.as_str() {
                            "mempool" => scan["mempool_sha256"] = json!("00".repeat(32)),
                            "total" => scan["spendable_zat"] = json!(30),
                            "immature" => scan["immature_zat"] = json!(1),
                            "leak" => scan["secret"] = json!("SECRET-WALLET-DIAGNOSTIC"),
                            _ => {}
                        }
                    }
                }
                scan
            }
        }
        _ => bail!("unexpected wallet fixture action"),
    };
    if action != "check-transaction" {
        private(args.last().unwrap(), &serde_json::to_vec(&result)?)?;
    }
    if matches!(action, "construct-payment" | "check-transaction") {
        // Check the durable boundary from the external signer's point of view.
        let envelope = Path::new(&args[if action == "construct-payment" { 5 } else { 4 }]);
        let id = envelope.parent().unwrap().file_name().unwrap();
        let scope = envelope
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let record = read_json(
            scope
                .join("payments")
                .join(format!("{}.json", id.to_str().unwrap())),
        )?;
        if action == "construct-payment" || record["signed"].is_null() {
            assert_eq!(record["outcome"]["kind"], "signing");
            assert_eq!(record["signed"], Value::Null);
        }
        if action == "construct-payment"
            && std::env::var("ZDN_WALLET_BACKEND").as_deref() == Ok("crash-after-envelope")
        {
            assert!(std::process::Command::new("/bin/kill")
                .args(["-KILL", &std::env::var("ZDN_TEST_CALLER").unwrap()])
                .status()?
                .success());
        }
    }
    Ok(result)
}

// Independent field-order reference: no production plan types or hashing APIs.
fn ordered(v: &Value, keys: &[&str]) -> String {
    format!(
        "{{{}}}",
        keys.iter()
            .map(|k| format!("{}:{}", json!(k), v[*k]))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn plan_hash(p: &Value) -> String {
    let transparent = matches!(
        p["allocation"]["kind"].as_str(),
        Some("transparent" | "unshield")
    );
    let identity = ordered(
        &p["identity"],
        &[
            "network_id",
            "consensus_fingerprint",
            "network",
            "genesis_hash",
        ],
    );
    let mut allocation = ordered(
        &p["allocation"],
        &[
            "kind",
            if transparent {
                "recipient_transparent_address"
            } else {
                "recipient_ironwood_address_hex"
            },
            "amount_zat",
            "fee_zat",
            "change_zat",
            "inputs",
            "outputs",
            "request_sha256",
        ],
    );
    let inputs = p["allocation"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            ordered(
                i,
                &[
                    "kind",
                    "txid",
                    if i["kind"] == "p2pkh" {
                        "output_index"
                    } else {
                        "action_index"
                    },
                ],
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    allocation = allocation.replace(
        &p["allocation"]["inputs"].to_string(),
        &format!("[{inputs}]"),
    );
    let outputs = p["allocation"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            ordered(
                o,
                &[
                    if transparent {
                        "transparent_address"
                    } else {
                        "ironwood_address_hex"
                    },
                    "value_zat",
                ],
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    allocation = allocation.replace(
        &p["allocation"]["outputs"].to_string(),
        &format!("[{outputs}]"),
    );
    let mut unsigned = p.clone();
    unsigned["plan_authorization_hex"] = json!("");
    let bytes = ordered(
        &unsigned,
        &[
            "schema_version",
            "identity",
            "snapshot_sha256",
            "state_sha256",
            "generation",
            "tip_height",
            "tip_hash",
            "anchor_hex",
            "mempool_sha256",
            "allocation",
            "plan_authorization_hex",
        ],
    )
    .replace(&p["identity"].to_string(), &identity)
    .replace(&p["allocation"].to_string(), &allocation);
    let mut h = Sha256::new();
    h.update(b"ironwood-wallet-snapshot-payment-plan/v2\0");
    h.update(bytes.as_bytes());
    hex::encode(h.finalize())
}
fn snapshot_response(root: &Path, args: &[String]) -> Result<Value> {
    let action = args[0].as_str();
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("backend-calls"))?,
        "{action}"
    )?;
    if action == "snapshot-create" {
        let state = read_json(&args[3])?;
        let context = read_json(&args[4])?;
        let snapshot = json!({"state":state,"context":context,"identity":read_json(&args[2])?});
        private(&args[5], &serde_json::to_vec(&snapshot)?)?;
        let mut result = state;
        let pending_path = Path::new(&args[4])
            .parent()
            .unwrap()
            .join("fixture-mempool");
        fs::write(&pending_path, serde_json::to_vec(&context["mempool"])?)?;
        result["mempool_sha256"] = json!(mempool(pending_path.to_str().unwrap())?);
        fs::remove_file(pending_path)?;
        return Ok(result);
    }
    let snapshot = read_json(&args[3])?;
    assert_eq!(snapshot["identity"], read_json(&args[2])?);
    if action == "prepare-snapshot-payment" {
        let s = &snapshot["state"];
        let r = &snapshot["context"]["request"];
        let request_bytes = fs::read(Path::new(&args[3]).parent().unwrap().join("request.json"))?;
        let mut p = json!({"schema_version":2,"identity":snapshot["identity"],"snapshot_sha256":hex::encode(Sha256::digest(fs::read(&args[3])?)),
            "state_sha256":s["state_sha256"],"generation":s["generation"],"tip_height":s["tip_height"],"tip_hash":s["tip_hash"],"anchor_hex":s["anchor_hex"],
            "mempool_sha256":framed_digest(b"ironwood-wallet-mempool/v1\0",std::iter::empty())?,
            "allocation":{"kind":r["kind"],"recipient_ironwood_address_hex":r["recipient"],"amount_zat":r["amount_zat"],"fee_zat":1,"change_zat":7,
            "inputs":[{"kind":"ironwood","txid":"12".repeat(32),"action_index":0}],"outputs":[{"ironwood_address_hex":r["recipient"],"value_zat":r["amount_zat"]}],"request_sha256":hex::encode(Sha256::digest(request_bytes))},"plan_authorization_hex":"aa".repeat(64)});
        if matches!(r["kind"].as_str(), Some("transparent" | "unshield")) {
            let a = &mut p["allocation"];
            a.as_object_mut()
                .unwrap()
                .remove("recipient_ironwood_address_hex");
            a["recipient_transparent_address"] = r["recipient"].clone();
            a["outputs"] =
                json!([{"transparent_address":r["recipient"],"value_zat":r["amount_zat"]}]);
            if r["kind"] == "transparent" {
                a["inputs"] = json!([{"kind":"p2pkh","txid":"34".repeat(32),"output_index":2}]);
            }
            match std::env::var("ZDN_TRANSPARENT_PLAN_MODE")
                .unwrap_or_default()
                .as_str()
            {
                "mixed" => a["recipient_ironwood_address_hex"] = json!("22".repeat(43)),
                "kind" => a["kind"] = json!("send"),
                "amount" => a["amount_zat"] = json!(3),
                _ => {}
            }
        }
        private(&args[4], &serde_json::to_vec(&p)?)?;
        return Ok(p);
    }
    let p = read_json(&args[4])?;
    if action == "check-snapshot-plan" {
        return Ok(
            json!({"schema_version":2,"capability":"ironwood-wallet-snapshot-payment-plan/v2","plan_verified":true,"payment_enabled":false,"generation":p["generation"],"plan_sha256":plan_hash(&p),"snapshot_sha256":p["snapshot_sha256"],"state_sha256":p["state_sha256"],"canonicality":"original_preparation_only_not_live_checked"}),
        );
    }
    if action == "construct-snapshot-payment" {
        let envelope = Path::new(&args[5]);
        let id = envelope
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let scope = envelope
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let record = read_json(scope.join("payments").join(format!("{id}.json")))?;
        assert_eq!(record["outcome"]["kind"], "signing");
        let e = json!({"schema_version":2,"plan":p,"broadcast":false,"txid":"ab".repeat(32),"raw_transaction_hex":"01020304"});
        private(&args[5], &serde_json::to_vec(&e)?)?;
        if std::env::var("ZDN_WALLET_BACKEND").as_deref() == Ok("crash-after-envelope") {
            assert!(std::process::Command::new("/bin/kill")
                .args(["-KILL", &std::env::var("ZDN_TEST_CALLER").unwrap()])
                .status()?
                .success());
        }
        return Ok(e);
    }
    assert_eq!(action, "check-snapshot-transaction");
    let e = read_json(&args[5])?;
    let mut result = json!({"schema_version":2,"valid":true,"broadcast":false,"txid":e["txid"],"plan_sha256":plan_hash(&p),"snapshot_sha256":p["snapshot_sha256"],"state_sha256":p["state_sha256"],"request_sha256":p["allocation"]["request_sha256"],"canonicality":"original_preparation_only_not_live_checked"});
    match std::env::var("ZDN_WALLET_BACKEND")
        .unwrap_or_default()
        .as_str()
    {
        "check-v1" => result["schema_version"] = json!(1),
        "check-extra" => result["extra"] = json!(true),
        "check-plan" => result["plan_sha256"] = json!("00".repeat(32)),
        "check-canonicality" => result["canonicality"] = json!("live_checked"),
        _ => {}
    }
    Ok(result)
}

#[test]
fn worker() {
    let Some((work, args, _)) = native_tool::invocation() else {
        return;
    };
    let root = std::env::var_os("ZDN_CONNECT_FIXTURE").unwrap();
    match response(Path::new(&root), &args) {
        Ok(value) => native_tool::reply(&work, format!("{value}\n").as_bytes(), b"", 0),
        Err(error) => native_tool::reply(&work, b"", format!("{error}\n").as_bytes(), 1),
    }
}
