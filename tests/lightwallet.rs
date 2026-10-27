#[path = "support/lightwallet/mod.rs"]
mod support;
use serde_json::json;
use std::{
    sync::{atomic::Ordering, Mutex},
    time::{Duration, Instant},
};
use support::*;
use zdn::{
    chain::rpc::{Clock, NodeRpc, RpcError, SystemClock},
    lightwallet::{
        check_readiness, wire, GrpcLightwalletRpc, LightwalletError, LightwalletRpc,
        ReadinessOptions,
    },
};

fn options() -> ReadinessOptions {
    ReadinessOptions {
        request_timeout: Duration::from_millis(100),
        deadline: Duration::from_millis(500),
        poll_interval: Duration::from_millis(10),
        ..Default::default()
    }
}
fn error(wallet: &Wallet) -> String {
    format!(
        "{:#}",
        check_readiness(
            &manifest(),
            &Node::default(),
            wallet,
            &FakeClock::default(),
            &options()
        )
        .unwrap_err()
    )
}

#[test]
fn verifies_ironwood_payload_and_trees_without_claiming_payment_success() {
    let node = Node::default();
    let report = check_readiness(
        &manifest(),
        &node,
        &Wallet::default(),
        &FakeClock::default(),
        &options(),
    )
    .unwrap();
    assert_eq!(report.checked_compact_blocks, 3);
    assert_eq!(report.checked_ironwood_actions, 2);
    assert_eq!(report.lightwallet_tip.hash, hash(3));
    assert!(report.compact_data_verified && report.ironwood_tree_verified);
    assert!(!report.launch_ready);
    assert_eq!(report.payment_qualification, "pending");
    assert!(node
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(method, _, _)| !matches!(
            method.as_str(),
            "generate" | "submitblock" | "sendrawtransaction"
        )));
}
#[test]
fn rejects_wrong_chain_rules_branch_and_protocol() {
    let mut wallet = Wallet::default();
    wallet.info.chain_name = "main".into();
    assert!(error(&wallet).contains("not Testnet"));
    let mut wallet = Wallet::default();
    wallet.info.sapling_activation_height = 2;
    assert!(error(&wallet).contains("Sapling activation"));
    let mut wallet = Wallet::default();
    wallet.info.consensus_branch_id = "00000000".into();
    assert!(error(&wallet).contains("consensus branch"));
    let mut wallet = Wallet::default();
    wallet.info.lightwallet_protocol_version.clear();
    assert!(error(&wallet).contains("unsupported light-wallet protocol"));
    let node = Node {
        hook: Mutex::new(Box::new(|method, _, _| {
            (method == "getchainrules").then(|| {
                let mut value = rules();
                value["rules"]["networkMagic"] = json!("deadbeef");
                Ok(value)
            })
        })),
        ..Default::default()
    };
    let wallet = Wallet::default();
    assert!(check_readiness(
        &manifest(),
        &node,
        &wallet,
        &FakeClock::default(),
        &options()
    )
    .is_err());
    assert_eq!(*wallet.calls.lock().unwrap(), 0);
}
#[test]
fn detects_little_endian_hash_mismatch_and_other_chain_with_same_test_label() {
    let mut wallet = Wallet::default();
    wallet.latest.hash.reverse();
    assert!(error(&wallet).contains("tip hash differs"));
    let mut wallet = Wallet::default();
    wallet.blocks.get_mut(&0).unwrap().hash = vec![44; 32];
    assert!(error(&wallet).contains("differs from node best chain"));
}
#[test]
fn advisory_fees_are_accepted_without_masking_transaction_mismatches() {
    let mut wallet = Wallet::default();
    for block in wallet.blocks.values_mut() {
        for tx in &mut block.vtx {
            tx.fee = u32::MAX;
        }
    }
    let report = check_readiness(
        &manifest(),
        &Node::default(),
        &wallet,
        &FakeClock::default(),
        &options(),
    )
    .unwrap();
    assert_eq!(report.checked_ironwood_actions, 2);
    wallet.blocks.get_mut(&3).unwrap().vtx[0].ironwood_actions[0].ciphertext[0] ^= 1;
    assert!(error(&wallet).contains("compact shielded transaction data differs"));
}

#[test]
fn rejects_malformed_ciphertext_suffix_in_every_shielded_pool() {
    for pool in ["sapling", "orchard", "ironwood"] {
        let node = Node {
            hook: Mutex::new(Box::new(move |method, params, _| {
                (method == "getblock" && params[0] == hash(2)).then(|| {
                    let mut block = node_block(2);
                    let mut ciphertext = "64".repeat(580);
                    // The compact 52-byte prefix is valid; only the final nibble is bad.
                    ciphertext.replace_range(1159..1160, "g");
                    if pool == "sapling" {
                        block["tx"][0]["vShieldedOutput"] = json!([{
                            "cmu": "42".repeat(32),
                            "ephemeralKey": "53".repeat(32),
                            "encCiphertext": ciphertext,
                        }]);
                    } else {
                        let mut action = block["tx"][0]["ironwood"]["actions"][0].clone();
                        action["encCiphertext"] = json!(ciphertext);
                        block["tx"][0][pool] = json!({"actions": [action]});
                    }
                    Ok(block)
                })
            })),
            ..Default::default()
        };
        let err = check_readiness(
            &manifest(),
            &node,
            &Wallet::default(),
            &FakeClock::default(),
            &options(),
        )
        .unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("ciphertext hex"), "{pool}: {err}");
    }
}

#[test]
fn rejects_wrong_missing_or_mutated_ironwood_payload_and_sizes() {
    for mutation in 0..7 {
        let mut wallet = Wallet::default();
        let block = wallet.blocks.get_mut(&3).unwrap();
        match mutation {
            0 => block.vtx.clear(),
            1 => block.vtx[0].ironwood_actions.clear(),
            2 => block.vtx[0].ironwood_actions[0].ciphertext[3] ^= 1,
            3 => block.vtx[0].ironwood_actions[0]
                .nullifier
                .pop()
                .map(|_| ())
                .unwrap(),
            4 => block.vtx[0].index = 1,
            5 => {
                block
                    .chain_metadata
                    .as_mut()
                    .unwrap()
                    .ironwood_commitment_tree_size = 0
            }
            _ => block.vtx[0].txid.reverse(),
        };
        let err = error(&wallet);
        assert!(
            err.contains("compact shielded") || err.contains("tree sizes"),
            "{mutation}: {err}"
        );
    }
}
#[test]
fn rejects_wrong_tree_network_height_hash_time_and_missing_ironwood() {
    for mutation in 0..6 {
        let mut wallet = Wallet::default();
        match mutation {
            0 => wallet.tree.network = "main".into(),
            1 => wallet.tree.height = 2,
            2 => wallet.tree.hash = hash(2),
            3 => wallet.tree.time = 4,
            4 => wallet.tree.ironwood_tree.clear(),
            _ => wallet.tree.ironwood_tree = "ffff".into(),
        };
        assert!(error(&wallet).contains("tree"));
    }
}
#[test]
fn lag_is_explicit_bounded_and_does_not_skip_tree_verification() {
    let wallet = Wallet {
        info: wire::LightdInfo {
            block_height: 2,
            ..wallet_info()
        },
        latest: wire::BlockId {
            height: 2,
            hash: wire_hash(2),
        },
        tree: tree(2),
        ..Default::default()
    };
    assert!(error(&wallet).contains("deadline expired"));
    let report = check_readiness(
        &manifest(),
        &Node::default(),
        &wallet,
        &FakeClock::default(),
        &ReadinessOptions {
            max_lag_blocks: 1,
            ..options()
        },
    )
    .unwrap();
    assert_eq!(report.lag_blocks, 1);
    assert_eq!(report.lightwallet_tip.height, 2);
}
#[test]
fn retries_transient_status_but_fails_unsupported_and_authentication() {
    for failure in [
        LightwalletError::Transport,
        LightwalletError::Status(tonic::Code::Unavailable),
        LightwalletError::Status(tonic::Code::Aborted),
    ] {
        let wallet = Wallet::default();
        *wallet.error.lock().unwrap() = Some(failure);
        let clock = FakeClock::default();
        let report =
            check_readiness(&manifest(), &Node::default(), &wallet, &clock, &options()).unwrap();
        assert_eq!(report.attempts, 2);
        assert_eq!(clock.elapsed(), Duration::from_millis(10));
    }
    for code in [
        tonic::Code::Unimplemented,
        tonic::Code::Unauthenticated,
        tonic::Code::PermissionDenied,
        tonic::Code::InvalidArgument,
    ] {
        let wallet = Wallet::default();
        *wallet.error.lock().unwrap() = Some(LightwalletError::Status(code));
        assert!(error(&wallet).contains("light-wallet"));
        assert_eq!(*wallet.calls.lock().unwrap(), 1);
    }
}

#[test]
fn final_rule_transport_failure_retries_the_complete_observation() {
    let node = Node {
        hook: Mutex::new(Box::new(|method, _, count| {
            (method == "getchainrules" && count == 3)
                .then(|| Err(RpcError::Transport("single dropped reply".into())))
        })),
        ..Default::default()
    };
    let wallet = Wallet::default();
    let clock = FakeClock::default();
    let report = check_readiness(&manifest(), &node, &wallet, &clock, &options()).unwrap();
    assert_eq!(report.attempts, 2);
    assert_eq!(clock.elapsed(), options().poll_interval);
    assert_eq!(*wallet.calls.lock().unwrap(), 2);
    let calls = node.calls.lock().unwrap();
    // Each attempt checks node rules before and after node readiness, then
    // rechecks them after comparing the light-wallet data.
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.0 == "getchainrules")
            .count(),
        6
    );
    assert_eq!(calls.iter().filter(|call| call.0 == "getblock").count(), 6);
}

#[test]
fn final_rule_transport_failures_remain_bounded_by_the_shared_deadline() {
    let node = Node {
        hook: Mutex::new(Box::new(|method, _, count| {
            (method == "getchainrules" && count.is_multiple_of(3))
                .then(|| Err(RpcError::Transport("dropped final reply".into())))
        })),
        ..Default::default()
    };
    let wallet = Wallet::default();
    let clock = FakeClock::default();
    let options = ReadinessOptions {
        request_timeout: Duration::from_millis(10),
        deadline: Duration::from_millis(30),
        ..options()
    };
    let error = check_readiness(&manifest(), &node, &wallet, &clock, &options).unwrap_err();
    assert!(
        format!("{error:#}").contains("deadline expired"),
        "{error:#}"
    );
    assert_eq!(clock.elapsed(), options.deadline);
    assert_eq!(*wallet.calls.lock().unwrap(), 3);
}

#[test]
fn final_rule_authentication_protocol_and_rule_mismatches_are_not_retried() {
    let mut changed_rules = rules();
    changed_rules["rules"]["networkMagic"] = json!("deadbeef");
    for failure in [
        Err(RpcError::Unauthorized),
        Err(RpcError::Protocol("malformed final reply".into())),
        Err(RpcError::Remote {
            code: -32601,
            message: "method unavailable".into(),
        }),
        Ok(changed_rules),
    ] {
        let node = Node {
            hook: Mutex::new(Box::new(move |method, _, count| {
                (method == "getchainrules" && count == 3).then(|| failure.clone())
            })),
            ..Default::default()
        };
        let wallet = Wallet::default();
        let clock = FakeClock::default();
        assert!(check_readiness(&manifest(), &node, &wallet, &clock, &options()).is_err());
        assert_eq!(clock.elapsed(), Duration::ZERO);
        assert_eq!(*wallet.calls.lock().unwrap(), 1);
        assert_eq!(
            node.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.0 == "getchainrules")
                .count(),
            3
        );
    }
}

#[test]
fn complete_observation_deadline_is_relative_and_rejects_late_response() {
    let clock = FakeClock::default();
    clock.0.store(55_000, Ordering::SeqCst);
    let report = check_readiness(
        &manifest(),
        &Node::default(),
        &Wallet::default(),
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(report.elapsed_millis, 0);
    struct Late<'a>(&'a FakeClock);
    impl LightwalletRpc for Late<'_> {
        fn info(&self, _: Duration) -> Result<wire::LightdInfo, LightwalletError> {
            self.0.sleep(Duration::from_secs(1));
            Ok(wallet_info())
        }
        fn latest_block(&self, _: Duration) -> Result<wire::BlockId, LightwalletError> {
            panic!()
        }
        fn block_range(
            &self,
            _: u32,
            _: u32,
            _: Duration,
        ) -> Result<Vec<wire::CompactBlock>, LightwalletError> {
            panic!()
        }
        fn tree_state(&self, _: u32, _: Duration) -> Result<wire::TreeState, LightwalletError> {
            panic!()
        }
    }
    assert!(check_readiness(
        &manifest(),
        &Node::default(),
        &Late(&clock),
        &clock,
        &options()
    )
    .unwrap_err()
    .to_string()
    .contains("deadline expired"));
}
#[test]
fn rechecks_node_history_after_stream_before_reporting_success() {
    let node = Node {
        hook: Mutex::new(Box::new(|method, params, count| {
            (method == "getblockhash" && params[0] == 2 && count > 8).then(|| Ok(json!(hash(99))))
        })),
        ..Default::default()
    };
    let result = check_readiness(
        &manifest(),
        &node,
        &Wallet::default(),
        &FakeClock::default(),
        &options(),
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("history changed"));
}
#[test]
fn bounded_loopback_grpc_checks_complete_range_and_ironwood_fields() {
    let server = grpc_server(good_reply);
    let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
    let report = check_readiness(
        &manifest(),
        &Node::default(),
        &wallet,
        &SystemClock::default(),
        &ReadinessOptions {
            request_timeout: Duration::from_secs(2),
            deadline: Duration::from_secs(5),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.checked_ironwood_actions, 2);
    assert_eq!(report.checked_compact_blocks, 3);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    // An idle adapter can resume the runtime for another request on that channel.
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        wallet.latest_block(Duration::from_secs(1)).unwrap().height,
        3
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_grpc_calls_are_not_replayed_and_next_call_reconnects() {
    use std::sync::{atomic::AtomicU64, Arc};
    for mutation in 0..3 {
        let calls = Arc::new(AtomicU64::new(0));
        let observed = calls.clone();
        let server = grpc_server(move |path, body| {
            if observed.fetch_add(1, Ordering::SeqCst) != 0 {
                return good_reply(path, body);
            }
            match mutation {
                0 => Reply {
                    status: 14,
                    ..Default::default()
                },
                1 => Reply {
                    raw: Some(vec![0, 0, 0, 0, 2, 0xff, 0xff]),
                    ..Default::default()
                },
                _ => Reply {
                    hang: true,
                    ..Default::default()
                },
            }
        });
        let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
        assert!(wallet.latest_block(Duration::from_millis(200)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            wallet.latest_block(Duration::from_secs(1)).unwrap(),
            wire::BlockId {
                height: 3,
                hash: wire_hash(3),
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn grpc_session_wait_respects_each_call_deadline() {
    use std::sync::{mpsc, Arc};
    let (sent, received) = mpsc::channel();
    let server = grpc_server(move |path, body| {
        let _ = sent.send(());
        let mut reply = good_reply(path, body);
        reply.delay = Duration::from_millis(300);
        reply
    });
    let wallet = Arc::new(GrpcLightwalletRpc::new(&server.endpoint).unwrap());
    std::thread::scope(|scope| {
        let first = scope.spawn(|| wallet.latest_block(Duration::from_secs(2)));
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        assert_eq!(
            wallet.latest_block(Duration::from_millis(20)),
            Err(LightwalletError::Transport)
        );
        assert!(start.elapsed() < Duration::from_millis(200));
        assert_eq!(first.join().unwrap().unwrap().height, 3);
    });
    assert_eq!(
        wallet.latest_block(Duration::from_secs(1)).unwrap().height,
        3
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn cached_grpc_client_still_rejects_async_calls_and_can_drop_in_runtime() {
    let server = grpc_server(good_reply);
    let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
    assert_eq!(
        wallet.latest_block(Duration::from_secs(1)).unwrap().height,
        3
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        assert!(matches!(
            wallet.latest_block(Duration::from_secs(1)),
            Err(LightwalletError::Protocol(_))
        ));
        drop(wallet);
    });
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
#[test]
fn loopback_rejects_truncated_overlong_wrong_order_and_failed_stream() {
    for mutation in 0..7 {
        let server = grpc_server(move |_, _| match mutation {
            0 => Reply {
                messages: vec![prost::Message::encode_to_vec(&compact(2))],
                ..Default::default()
            },
            1 => Reply {
                messages: (1..=3)
                    .map(|h| prost::Message::encode_to_vec(&compact(h)))
                    .collect(),
                ..Default::default()
            },
            2 => Reply {
                messages: vec![
                    prost::Message::encode_to_vec(&compact(2)),
                    prost::Message::encode_to_vec(&compact(3)),
                ],
                status: 13,
                ..Default::default()
            },
            3 => Reply {
                raw: Some(vec![0, 0, 0, 0, 2, 0xff, 0xff]),
                ..Default::default()
            },
            4 => Reply {
                messages: vec![
                    prost::Message::encode_to_vec(&compact(2)),
                    prost::Message::encode_to_vec(&compact(3)),
                ],
                missing_trailers: true,
                ..Default::default()
            },
            5 => Reply {
                raw: Some(vec![0, 0, 64, 0, 1]),
                ..Default::default()
            },
            _ => Reply {
                messages: vec![prost::Message::encode_to_vec(&compact(2))],
                reset: true,
                ..Default::default()
            },
        });
        let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
        assert!(
            wallet.block_range(2, 3, Duration::from_secs(1)).is_err(),
            "mutation {mutation}"
        );
    }
}
#[test]
fn loopback_deadline_includes_stream_body_and_final_trailers() {
    let server = grpc_server(|_, _| Reply {
        messages: vec![
            prost::Message::encode_to_vec(&compact(2)),
            prost::Message::encode_to_vec(&compact(3)),
        ],
        hang: true,
        ..Default::default()
    });
    let start = Instant::now();
    let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
    assert!(wallet
        .block_range(2, 3, Duration::from_millis(100))
        .is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[test]
fn refuses_nonloopback_endpoints_and_invalid_ranges_before_connect() {
    for endpoint in [
        "example.com:9067",
        "http://127.0.0.1:9067",
        "169.254.169.254:80",
        "0.0.0.0:1",
        "127.0.0.1:0",
        "[fe80::1%1]:9067",
    ] {
        assert!(GrpcLightwalletRpc::new(endpoint).is_err(), "{endpoint}");
    }
    let client = GrpcLightwalletRpc::new("127.0.0.1:1").unwrap();
    for (start, end) in [(2, 1), (0, 64), (0, u32::MAX)] {
        assert!(matches!(
            client.block_range(start, end, Duration::from_secs(1)),
            Err(LightwalletError::Protocol(_))
        ));
    }
    assert!(matches!(
        client.info(Duration::ZERO),
        Err(LightwalletError::Protocol(_))
    ));
    assert!(matches!(
        client.tree_state(0, Duration::from_secs(1)),
        Err(LightwalletError::Protocol(_))
    ));
}
#[test]
fn missing_compact_stream_entry_never_becomes_ready() {
    let mut wallet = Wallet::default();
    wallet.blocks.remove(&2);
    assert!(error(&wallet).contains("count differs"));
}

#[test]
fn node_projection_rpc_methods_are_read_only_and_available_over_http() {
    use std::io::{BufRead, BufReader, Read, Write};
    for method in ["getblock", "z_gettreestate"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&mut socket);
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if line.to_lowercase().starts_with("content-length:") {
                    length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["method"], method);
            let response =
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"ok":true}}).to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let cookie = temp.path().join("cookie");
        std::fs::write(&cookie, "__cookie__:fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let rpc = zdn::chain::rpc::HttpNodeRpc::new(&endpoint, &cookie).unwrap();
        assert_eq!(
            rpc.call(method, json!([hash(3)]), Duration::from_secs(2))
                .unwrap(),
            json!({"ok":true})
        );
        handle.join().unwrap();
    }
}

#[test]
fn binary_runs_readiness_against_both_loopback_protocols() {
    let server = grpc_server(good_reply);
    let node = node_server();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("manifest.json");
    std::fs::write(&path, serde_json::to_vec(&manifest()).unwrap()).unwrap();
    let cookie = temp.path().join("cookie");
    std::fs::write(&cookie, "__cookie__:fixture-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .args(["lightwallet", "readiness", "--manifest"])
        .arg(path)
        .args([
            "--rpc-endpoint",
            &node.endpoint,
            "--grpc-endpoint",
            &server.endpoint,
            "--cookie-file",
        ])
        .arg(cookie)
        .args(["--request-timeout-secs", "2", "--deadline-secs", "5"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["apiVersion"], "zdn-lightwallet-readiness/v1alpha1");
    assert_eq!(report["checkedIronwoodActions"], 2);
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["paymentQualification"], "pending");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-secret"));
}

#[test]
fn pinned_proto_hashes_and_ironwood_wire_numbers_match_attribution() {
    use prost::Message;
    use sha2::{Digest, Sha256};
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../protocol/lightwallet-v0.5.0/service.proto"
        ))),
        "6fbfa974081fb02366a3118a25764af289bdbb86688978f5ff2bae661dfa346a"
    );
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../protocol/lightwallet-v0.5.0/compact_formats.proto"
        ))),
        "d8d0c8aaa5ceec7d5dcc188ef25b04011df2ec0254901620fce982fc13aeb32d"
    );
    // Independently encoded protobuf key/length/value bytes: fields 18, 7, 3,
    // and 9 respectively. These detect drift back to the older vendored schema.
    let info = wire::LightdInfo::decode(&hex::decode("92010676302e352e30").unwrap()[..]).unwrap();
    assert_eq!(info.lightwallet_protocol_version, "v0.5.0");
    let tree = wire::TreeState::decode(&hex::decode("3a023031").unwrap()[..]).unwrap();
    assert_eq!(tree.ironwood_tree, "01");
    let metadata = wire::ChainMetadata::decode(&hex::decode("1802").unwrap()[..]).unwrap();
    assert_eq!(metadata.ironwood_commitment_tree_size, 2);
    let transaction = wire::CompactTx::decode(&hex::decode("4a020a00").unwrap()[..]).unwrap();
    assert_eq!(transaction.ironwood_actions.len(), 1);
    assert!(transaction.actions.is_empty());
}

#[test]
fn retry_attempt_count_is_bounded_even_with_a_nonadvancing_transport() {
    let mut wallet = Wallet::default();
    wallet.info.block_height = 2;
    let clock = FakeClock::default();
    let error = check_readiness(
        &manifest(),
        &Node::default(),
        &wallet,
        &clock,
        &ReadinessOptions {
            deadline: Duration::from_secs(3600),
            ..options()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("attempt limit"));
    assert_eq!(*wallet.calls.lock().unwrap(), 256);
    assert_eq!(clock.elapsed(), Duration::from_millis(2560));
}

#[test]
fn received_byte_limit_counts_unknown_protobuf_fields_before_discarding_them() {
    use prost::Message;
    fn varint(mut n: usize, bytes: &mut Vec<u8>) {
        while n >= 128 {
            bytes.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        bytes.push(n as u8);
    }
    let server = grpc_server(|_, _| {
        let messages = (2..=4)
            .map(|height| {
                let mut message = compact(height).encode_to_vec();
                // A valid length-delimited future field, not retained by prost.
                varint((1000 << 3) | 2, &mut message);
                varint(3 * 1024 * 1024, &mut message);
                message.resize(message.len() + 3 * 1024 * 1024, 0);
                message
            })
            .collect();
        Reply {
            messages,
            ..Default::default()
        }
    });
    let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
    let error = wallet
        .block_range(2, 4, Duration::from_secs(3))
        .unwrap_err();
    assert_eq!(
        error,
        LightwalletError::Status(tonic::Code::ResourceExhausted)
    );
}

#[test]
fn reordered_or_duplicate_stream_entries_fail_even_with_success_trailers() {
    for duplicate in [false, true] {
        let server = grpc_server(move |path, body| {
            let mut reply = good_reply(path, body);
            if path.ends_with("/GetBlockRange") && reply.messages.len() == 2 {
                if duplicate {
                    reply.messages[1] = reply.messages[0].clone();
                } else {
                    reply.messages.swap(0, 1);
                }
            }
            reply
        });
        let wallet = GrpcLightwalletRpc::new(&server.endpoint).unwrap();
        let error = check_readiness(
            &manifest(),
            &Node::default(),
            &wallet,
            &SystemClock::default(),
            &ReadinessOptions {
                request_timeout: Duration::from_secs(2),
                deadline: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("compact stream height or hash"),
            "{error:#}"
        );
    }
}

#[test]
fn hexadecimal_case_is_normalized_but_invalid_trees_still_fail() {
    let mut wallet = Wallet::default();
    wallet.tree.hash = wallet.tree.hash.to_uppercase();
    wallet.info.consensus_branch_id = wallet.info.consensus_branch_id.to_uppercase();
    let report = check_readiness(
        &manifest(),
        &Node::default(),
        &wallet,
        &FakeClock::default(),
        &options(),
    )
    .unwrap();
    assert_eq!(report.lightwallet_tip.hash, hash(3));
    wallet.tree.ironwood_tree = " 020000".into();
    assert!(error(&wallet).contains("invalid ironwood tree"));
}
