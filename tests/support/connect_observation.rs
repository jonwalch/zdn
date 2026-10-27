//! Public observation tests; the backend values are independently chosen fixtures.
use super::*;
use sha2::{Digest, Sha256};

fn fixture() -> Fixture {
    let f = payment_fixture();
    fs::rename(
        f.root.path().join("wallet-backend"),
        f.root.path().join("original-backend"),
    )
    .unwrap();
    native_tool::install(
        &f.root.path().join("wallet-backend"),
        "connect_observation::backend_worker",
        &json!(null),
    );
    f
}

fn command(f: &Fixture, args: &[&str]) -> Command {
    let mut c = payment_command(f, "ok", args);
    c.env("ZDN_CONNECT_MODE", "wallet-sync-long");
    c
}

fn success(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rpc_count(f: &Fixture, method: &str) -> usize {
    fs::read_to_string(f.root.path().join("rpc-requests"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|v| v["body"]["method"] == method)
        .count()
}

fn caught_up(f: &Fixture) {
    for name in ["alice", "alias"] {
        success(
            command(
                f,
                &["wallet", "sync", "--wallet", name, "--max-batches", "16"],
            )
            .output()
            .unwrap(),
        );
        let result = success(
            command(
                f,
                &["wallet", "sync", "--wallet", name, "--max-batches", "1"],
            )
            .output()
            .unwrap(),
        );
        assert_eq!(result["outcome"], "current_at_observation");
    }
}

#[test]
fn state_observations_cross_limit_classify_alias_reservations_and_reward_maturity() {
    let f = fixture();
    let incomplete = command(&f, &["wallet", "balance", "--wallet", "alice"])
        .output()
        .unwrap();
    assert!(!incomplete.status.success());
    assert!(incomplete.stdout.is_empty());
    assert_eq!(rpc_count(&f, "getblock"), 1024);
    caught_up(&f);
    let scope = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string());
    let id = "a0000000-0000-4000-8000-000000000001";
    let record = json!({"schema_version":1,"operation_id":id,
        "network_id":f.endpoints.network_id,"consensus_fingerprint":f.endpoints.consensus_fingerprint,
        "wallet_id":"b0000000-0000-4000-8000-000000000001","request":{"amount_zat":1},"plan":{"fixture":true},
        "inputs":[{"kind":"ironwood","txid":"56".repeat(32),"action_index":0},
            {"kind":"p2pkh","txid":"67".repeat(32),"output_index":3}],
        "signed":null,"attempts":0,"outcome":{"kind":"reserved"}});
    let path = scope.join("payments").join(format!("{id}.json"));
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let raw = rpc_count(&f, "getblock");
    for name in ["alice", "alias"] {
        let result = success(
            command(&f, &["wallet", "balance", "--wallet", name])
                .output()
                .unwrap(),
        );
        assert_eq!(result["tip_height"], 4097);
        assert_eq!(result["schema_version"], 2);
        assert_eq!(result["balance"]["confirmed_unspent_zat"], 31);
        assert_eq!(result["balance"]["spendable_zat"], 24);
        assert_eq!(result["balance"]["reserved_zat"], 7);
        assert_eq!(result["local_reservations_checked"], true);
        assert!(!result.to_string().contains("history_sha256"));
    }
    let rewards = success(
        command(&f, &["wallet", "rewards", "--wallet", "alice"])
            .output()
            .unwrap(),
    );
    assert_eq!(rewards["rewards"][0]["value_zat"], 23);
    assert_eq!(rewards["rewards"][0]["mature"], true);
    assert_eq!(rewards["rewards"][0]["locally_reserved"], true);
    assert_eq!(rewards["rewards"][1]["value_zat"], 41);
    assert_eq!(rewards["rewards"][1]["mature"], false);
    assert_eq!(rewards["rewards"][1]["locally_reserved"], false);
    let pending = rpc_count(&f, "getrawmempool");
    let confirmed = success(
        command(
            &f,
            &["wallet", "balance", "--wallet", "alice", "--confirmed-only"],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(confirmed["balance"]["confirmed_unspent_zat"], 31);
    for key in [
        "spendable_zat",
        "pending_zat",
        "pending_spent_zat",
        "immature_zat",
        "reserved_zat",
        "mempool_sha256",
    ] {
        assert!(confirmed["balance"][key].is_null());
    }
    assert_eq!(confirmed["local_reservations_checked"], false);
    assert_eq!(rpc_count(&f, "getrawmempool"), pending);
    assert_eq!(rpc_count(&f, "getblock"), raw);
    assert_eq!(
        fs::read(&path).unwrap(),
        serde_json::to_vec(&record).unwrap()
    );
    f.assert_rpc_closed();
}

#[test]
fn state_observations_refuse_wrong_provenance_classification_and_cleanup() {
    let f = fixture();
    caught_up(&f);
    for mode in [
        "scope",
        "generation",
        "tip",
        "anchor",
        "mempool",
        "balance-version",
        "balance-sum",
        "reward-maturity",
        "reward-duplicate",
        "extra",
        "missing",
    ] {
        let output = command(&f, &["wallet", "balance", "--wallet", "alice"])
            .env("ZDN_OBSERVATION_MODE", mode)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {mode}");
        assert!(output.stdout.is_empty(), "published {mode}");
        f.assert_rpc_closed();
    }
    let output = command(&f, &["wallet", "balance", "--wallet", "alice"])
        .env("ZDN_CONNECT_MODE", "wallet-sync-cleanup-fails")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn backend_worker() {
    let Some((work, args, _)) = native_tool::invocation() else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("ZDN_CONNECT_FIXTURE").unwrap());
    let read = |p: &str| -> Value { serde_json::from_slice(&fs::read(p).unwrap()).unwrap() };
    let mut value = if args[0] == "capabilities" {
        json!({"schema_version":1,"capabilities":["ironwood-wallet-state/v2","ironwood-wallet-state-observation/v2"]})
    } else if args[0] == "state-observe" {
        let state = read(&args[3]);
        let reserved = read(&args[5])
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "ironwood") as u64
            * 7;
        assert!(read(&args[4])["transactions"]
            .as_array()
            .unwrap()
            .is_empty());
        let digest = hex::encode(Sha256::digest(b"ironwood-wallet-mempool/v1\0"));
        let height = state["tip_height"].as_u64().unwrap();
        json!({"schema_version":2,"capability":"ironwood-wallet-state-observation/v2",
            "identity":read(&args[2]),"generation":state["generation"],"state_sha256":state["state_sha256"],
            "tip_height":height,"tip_hash":state["tip_hash"],"anchor_hex":state["anchor_hex"],"mempool_sha256":digest,
            "balance":{"schema_version":2,"tip_height":height,"tip_hash":state["tip_hash"],"anchor_hex":state["anchor_hex"],
                "commitment_count":5,"mempool_sha256":digest,"confirmed_unspent_zat":31,"spendable_zat":31-reserved,
                "pending_zat":0,"pending_spent_zat":0,"immature_zat":0,"reserved_zat":reserved},
            "rewards":[{"txid":"67".repeat(32),"output_index":3,"height":height-99,"value_zat":23,"mature":true,"mempool_spent":false},
                {"txid":"78".repeat(32),"output_index":1,"height":height-98,"value_zat":41,"mature":false,"mempool_spent":false}],
            "canonicality":"caller_attested_not_live_checked"})
    } else {
        let output = Command::new(root.join("original-backend"))
            .args(&args)
            .output()
            .unwrap();
        native_tool::reply(
            &work,
            &output.stdout,
            &output.stderr,
            output.status.code().unwrap_or(1) as u8,
        );
        return;
    };
    if args[0] == "state-observe" {
        match std::env::var("ZDN_OBSERVATION_MODE")
            .unwrap_or_default()
            .as_str()
        {
            "scope" => value["identity"]["consensus_fingerprint"] = json!("ff".repeat(32)),
            "generation" => value["generation"] = json!(999),
            "tip" => value["tip_hash"] = json!("ff".repeat(32)),
            "anchor" => value["anchor_hex"] = json!("ff".repeat(32)),
            "mempool" => value["mempool_sha256"] = json!("ff".repeat(32)),
            "balance-version" => value["balance"]["schema_version"] = json!(1),
            "balance-sum" => value["balance"]["spendable_zat"] = json!(32),
            "reward-maturity" => value["rewards"][1]["mature"] = json!(true),
            "reward-duplicate" => value["rewards"][1] = value["rewards"][0].clone(),
            "extra" => value["history_sha256"] = json!("ff".repeat(32)),
            "missing" => {
                value.as_object_mut().unwrap().remove("state_sha256");
            }
            _ => {}
        }
    }
    native_tool::reply(&work, format!("{value}\n").as_bytes(), b"", 0);
}
