//! Scripted RPC tests exercise observations and deadlines without node code.
//! The diagnostic fixture is an independently written wire response, and the
//! actual-tip fixture explicitly reverses nonuniform display hash bytes.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zdn::chain::{
    manifest::{
        BlockIdentity, Checkpoint, ConsensusManifest, FundingReceiver, FundingRecipient,
        FundingStream, ProofOfWork,
    },
    readiness::{check_readiness, verify_rules, ReadinessOptions},
    rpc::{Clock, NodeRpc, RpcError},
    runtime_config::NodeRole,
};

const MANIFEST: &str = include_str!("fixtures/chain-manifest/valid.json");
const GENESIS: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const SEED: &str = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa";
const BRANCHES: [(&str, &str); 10] = [
    ("Overwinter", "5ba81b19"),
    ("Sapling", "76b809bb"),
    ("Blossom", "2bb40e60"),
    ("Heartwood", "f5b9230b"),
    ("Canopy", "e9ff75a6"),
    ("NU5", "c2d6d0b4"),
    ("NU6", "c8e71055"),
    ("NU6.1", "4dec4df0"),
    ("NU6.2", "5437f330"),
    ("NU6.3", "37a5165b"),
];

fn manifest() -> ConsensusManifest {
    let mut manifest: ConsensusManifest = serde_json::from_str(MANIFEST).unwrap();
    manifest.genesis.hash = GENESIS.into();
    manifest
}

fn seeded_manifest() -> ConsensusManifest {
    let mut manifest = manifest();
    manifest.seed_blocks.push(BlockIdentity {
        height: 1,
        hash: SEED.into(),
        bytes_sha256: "31".repeat(32),
        bytes_length: 123,
    });
    manifest.checkpoints = vec![
        Checkpoint {
            height: 0,
            hash: GENESIS.into(),
        },
        Checkpoint {
            height: 1,
            hash: SEED.into(),
        },
    ];
    manifest
}

fn diagnostic(manifest: &ConsensusManifest) -> Value {
    let mut checkpoints: Vec<_> = manifest
        .checkpoints
        .iter()
        .map(|c| json!({"height":c.height,"hash":c.hash}))
        .collect();
    if checkpoints.is_empty() {
        checkpoints.push(json!({"height":0,"hash":GENESIS}));
    }
    json!({
        "apiVersion":"zakura-chain-rules/v1", "ruleset":"zakura-configured-testnet/v1",
        "networkKind":"custom-testnet",
        "rules": {
            "networkMagic":"a1b2c3d4", "genesisHash":GENESIS,
            "checkpoints":checkpoints,
            "activationHeights":[{"height":0,"upgrade":"Genesis"},{"height":1,"upgrade":"NU6.3"}],
            "subsidy": {
                "slowStartInterval":0, "slowStartShift":0,
                "preBlossomHalvingInterval":840000, "postBlossomHalvingInterval":1680000,
                "fundingStreams":[],
                "lockboxDisbursements":[{"scriptHash":"1212121212121212121212121212121212121212","amount":0}],
                "initialNsmValueBalance":null, "allowUnshieldedCoinbaseSpends":false
            },
            "difficulty": {"targetDifficultyLimitCompact":"1f07ffff","proofOfWork":"disabled","maxBlockTimeStartHeight":653606},
            "temporaryOrchardDisablingHeight":4048500,
            "experimental":{"pq":null,"sqisign":null}
        }
    })
}

fn chain_info(height: u32, hash: &str) -> Value {
    let upgrades: serde_json::Map<_, _> = BRANCHES.iter().map(|(name, branch)| (
        (*branch).to_owned(), json!({"name":name,"activationheight":1,"status":if height == 0 {"pending"} else {"active"}})
    )).collect();
    json!({
        "chain":"test", "blocks":height, "bestblockhash":hash, "upgrades":upgrades,
        "consensus":{"chaintip":if height == 0 {"00000000"} else {"37a5165b"},"nextblock":"37a5165b"},
        "verificationprogress":0.0
    })
}

fn tip(height: u32, hash: &str) -> Value {
    let mut bytes = hex::decode(hash).unwrap();
    bytes.reverse();
    json!({"height":height,"hash":bytes})
}

#[derive(Clone, Debug)]
struct Call {
    method: String,
    params: Value,
    timeout: Duration,
}
type Hook = Box<dyn FnMut(&Call, usize) -> Option<Result<Value, RpcError>> + Send>;

struct FakeRpc {
    rules: Value,
    info: Value,
    actual_tip: Value,
    history: BTreeMap<u32, String>,
    calls: Mutex<Vec<Call>>,
    counts: Mutex<BTreeMap<String, usize>>,
    hook: Mutex<Hook>,
}

impl FakeRpc {
    fn new(manifest: &ConsensusManifest) -> Self {
        let mut history = BTreeMap::from([(0, manifest.genesis.hash.clone())]);
        for block in &manifest.seed_blocks {
            history.insert(block.height, block.hash.clone());
        }
        let (&height, hash) = history.last_key_value().unwrap();
        Self {
            rules: diagnostic(manifest),
            info: chain_info(height, hash),
            actual_tip: tip(height, hash),
            history,
            calls: Mutex::default(),
            counts: Mutex::default(),
            hook: Mutex::new(Box::new(|_, _| None)),
        }
    }
    fn hook(
        &mut self,
        hook: impl FnMut(&Call, usize) -> Option<Result<Value, RpcError>> + Send + 'static,
    ) {
        self.hook = Mutex::new(Box::new(hook));
    }
    fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.method.clone())
            .collect()
    }
}

impl NodeRpc for FakeRpc {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        let call = Call {
            method: method.into(),
            params,
            timeout,
        };
        self.calls.lock().unwrap().push(call.clone());
        let count = {
            let mut counts = self.counts.lock().unwrap();
            let count = counts.entry(method.into()).or_default();
            *count += 1;
            *count
        };
        if let Some(result) = (self.hook.lock().unwrap())(&call, count) {
            return result;
        }
        Ok(match method {
            "getchainrules" => self.rules.clone(),
            "getbestblockheightandhash" => self.actual_tip.clone(),
            "getblockchaininfo" => self.info.clone(),
            "getblockhash" => {
                let height = call.params[0].as_u64().unwrap() as u32;
                match self.history.get(&height) {
                    Some(hash) => json!(hash),
                    None => {
                        return Err(RpcError::Remote {
                            code: -8,
                            message: "Block not found".into(),
                        })
                    }
                }
            }
            "getblocktemplate" => {
                assert_eq!(call.params, json!([{}]), "template must omit longpollid");
                json!({"height":self.info["blocks"].as_u64().unwrap()+1,"previousblockhash":self.info["bestblockhash"],"transactions":[]})
            }
            _ => panic!("unexpected RPC {method}"),
        })
    }
}

#[derive(Default, Clone)]
struct FakeClock(Arc<AtomicU64>);
impl FakeClock {
    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
    fn sleep(&self, duration: Duration) {
        self.advance(duration.as_millis() as u64);
    }
}

fn options() -> ReadinessOptions {
    ReadinessOptions {
        deadline: Duration::from_secs(3),
        request_timeout: Duration::from_millis(500),
        poll_interval: Duration::from_millis(100),
        ..Default::default()
    }
}

#[test]
fn follower_observes_real_history_and_never_claims_mining_or_payment_readiness() {
    let manifest = seeded_manifest();
    let rpc = FakeRpc::new(&manifest);
    let report = check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap();
    assert_eq!(report.tip.height, 1);
    assert_eq!(report.tip.hash, SEED);
    assert_eq!(report.checked_history, 2);
    assert!(report.history_present);
    assert!(report.effective_rules_verified);
    assert!(!report.mining_ready);
    assert!(!report.launch_ready);
    assert_eq!(report.payment_qualification, "pending");
    assert_eq!(report.attempts, 1);
    assert!(!rpc.methods().iter().any(|m| m == "getblocktemplate"));
    assert!(rpc
        .methods()
        .iter()
        .all(|m| !["generate", "submitblock"].contains(&m.as_str())));
    for height in [0, 1] {
        assert!(
            rpc.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.method == "getblockhash" && call.params == json!([height]))
                .count()
                >= 2
        );
    }
}

#[test]
fn producer_requires_fresh_parent_and_height_but_empty_mempool_does_not_qualify_payments() {
    let manifest = manifest();
    let rpc = FakeRpc::new(&manifest);
    let options = ReadinessOptions {
        role: NodeRole::Producer,
        ..options()
    };
    let report = check_readiness(&manifest, &rpc, &FakeClock::default(), &options).unwrap();
    assert!(report.mining_ready);
    assert_eq!(report.tip.hash, GENESIS);
    assert_eq!(report.payment_qualification, "pending");
    assert!(!report.launch_ready);
    assert_eq!(
        rpc.methods()
            .iter()
            .filter(|m| m.as_str() == "getblocktemplate")
            .count(),
        1
    );
}

#[test]
fn rules_compare_collapsed_upgrades_and_canonical_hex_not_an_echoed_fingerprint() {
    let manifest = manifest();
    let mut rpc = FakeRpc::new(&manifest);
    rpc.rules["rules"]["networkMagic"] = json!("A1B2C3D4");
    rpc.rules["rules"]["genesisHash"] = json!(GENESIS.to_ascii_uppercase());
    rpc.rules["rules"]["difficulty"]["targetDifficultyLimitCompact"] = json!("1F07FFFF");
    verify_rules(&manifest, &rpc, Duration::from_secs(1)).unwrap();
    assert_eq!(rpc.methods(), vec!["getchainrules"]);
    rpc.rules = json!({"consensusFingerprint":manifest.fingerprint().unwrap()});
    assert!(verify_rules(&manifest, &rpc, Duration::from_secs(1)).is_err());
}

#[test]
fn every_rule_family_and_schema_identity_fails_closed_on_drift() {
    let manifest = manifest();
    for (pointer, value) in [
        ("/apiVersion", json!("future")),
        ("/ruleset", json!("future")),
        ("/networkKind", json!("testnet")),
        ("/rules/networkMagic", json!("ffffffff")),
        ("/rules/genesisHash", json!("44".repeat(32))),
        ("/rules/checkpoints/0/hash", json!("55".repeat(32))),
        ("/rules/activationHeights/1/upgrade", json!("NU6.2")),
        ("/rules/subsidy/slowStartInterval", json!(2)),
        ("/rules/subsidy/slowStartShift", json!(1)),
        ("/rules/subsidy/preBlossomHalvingInterval", json!(840001)),
        ("/rules/subsidy/postBlossomHalvingInterval", json!(1680001)),
        ("/rules/subsidy/initialNsmValueBalance", json!(0)),
        ("/rules/subsidy/allowUnshieldedCoinbaseSpends", json!(true)),
        ("/rules/subsidy/fundingStreams", json!([{}])),
        ("/rules/subsidy/lockboxDisbursements/0/amount", json!(1)),
        (
            "/rules/difficulty/targetDifficultyLimitCompact",
            json!("1f00ffff"),
        ),
        ("/rules/difficulty/proofOfWork", json!("equihash")),
        ("/rules/difficulty/maxBlockTimeStartHeight", json!(1)),
        ("/rules/temporaryOrchardDisablingHeight", json!(null)),
        ("/rules/experimental/pq", json!({"enabled":true})),
        ("/rules/experimental/sqisign", json!({"enabled":true})),
    ] {
        let mut rpc = FakeRpc::new(&manifest);
        *rpc.rules.pointer_mut(pointer).unwrap() = value;
        let error =
            check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap_err();
        assert!(
            error.to_string().contains("effective rules"),
            "{pointer}: {error}"
        );
        assert_eq!(rpc.methods(), vec!["getchainrules"], "{pointer}");
    }
}

#[test]
fn malformed_and_unbounded_rule_responses_fail_without_panics() {
    let manifest = manifest();
    for malformed in [
        json!(null),
        json!(false),
        json!("x"),
        json!([]),
        json!({"rules":3}),
        json!({"rules":{"subsidy":false}}),
        json!("x".repeat(2 * 1024 * 1024)),
    ] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.rules = malformed;
        assert!(verify_rules(&manifest, &rpc, Duration::from_secs(1)).is_err());
    }
    let mut rpc = FakeRpc::new(&manifest);
    rpc.rules["rules"]["unknown"] = json!(false);
    assert!(verify_rules(&manifest, &rpc, Duration::from_secs(1)).is_err());
    let mut rpc = FakeRpc::new(&manifest);
    rpc.rules["rules"]["subsidy"]
        .as_object_mut()
        .unwrap()
        .remove("initialNsmValueBalance");
    assert!(verify_rules(&manifest, &rpc, Duration::from_secs(1)).is_err());
}

#[test]
fn explicit_funding_and_lockbox_multiset_projection_preserves_address_periods() {
    let mut manifest = manifest();
    manifest.subsidy.initial_nsm_value_balance = Some(0);
    manifest.subsidy.slow_start_interval = 5;
    manifest.subsidy.funding_streams = vec![FundingStream {
        start_height: 1,
        end_height: 100,
        recipients: vec![
            FundingRecipient {
                receiver: FundingReceiver::ZcashFoundation,
                numerator: 1,
                script_hashes: vec!["ab".repeat(20), "cd".repeat(20)],
            },
            FundingRecipient {
                receiver: FundingReceiver::Deferred,
                numerator: 2,
                script_hashes: vec![],
            },
        ],
    }];
    manifest
        .subsidy
        .lockbox_disbursements
        .push(manifest.subsidy.lockbox_disbursements[0].clone());
    let mut rpc = FakeRpc::new(&manifest);
    rpc.rules["rules"]["subsidy"]["initialNsmValueBalance"] = json!(0);
    rpc.rules["rules"]["subsidy"]["slowStartInterval"] = json!(5);
    rpc.rules["rules"]["subsidy"]["slowStartShift"] = json!(2);
    rpc.rules["rules"]["subsidy"]["fundingStreams"] = json!([{"startHeight":1,"endHeight":100,"recipients":[
        {"receiver":"deferred","numerator":2,"scriptHashes":[]},
        {"receiver":"zcash-foundation","numerator":1,"scriptHashes":["ab".repeat(20),"cd".repeat(20)]}
    ]}]);
    let duplicate = rpc.rules["rules"]["subsidy"]["lockboxDisbursements"][0].clone();
    rpc.rules["rules"]["subsidy"]["lockboxDisbursements"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    verify_rules(&manifest, &rpc, Duration::from_secs(1)).unwrap();
    rpc.rules["rules"]["subsidy"]["fundingStreams"][0]["recipients"][1]["scriptHashes"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(verify_rules(&manifest, &rpc, Duration::from_secs(1)).is_err());
}

#[test]
fn distinct_activation_heights_and_nu7_are_checked_with_next_block_branch() {
    let mut manifest = seeded_manifest();
    manifest.upgrades.nu6_3 = 2;
    manifest.upgrades.nu7 = Some(3);
    let mut rpc = FakeRpc::new(&manifest);
    rpc.rules["rules"]["activationHeights"] = json!([
        {"height":0,"upgrade":"Genesis"},{"height":1,"upgrade":"NU6.2"},
        {"height":2,"upgrade":"NU6.3"},{"height":3,"upgrade":"NU7"}
    ]);
    rpc.info["upgrades"]["37a5165b"]["activationheight"] = json!(2);
    rpc.info["upgrades"]["37a5165b"]["status"] = json!("pending");
    rpc.info["upgrades"]["77190ad9"] =
        json!({"name":"NU7","activationheight":3,"status":"pending"});
    rpc.info["consensus"]["chaintip"] = json!("5437f330");
    check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap();
    rpc.info["consensus"]["nextblock"] = json!("5437f330");
    assert!(
        check_readiness(&manifest, &rpc, &FakeClock::default(), &options())
            .unwrap_err()
            .to_string()
            .contains("nextblock")
    );
}

#[test]
fn fabricated_genesis_chain_info_never_substitutes_for_actual_tip_or_stored_genesis() {
    let manifest = manifest();
    for missing_method in ["getbestblockheightandhash", "getblockhash"] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.hook(move |call, _| {
            (call.method == missing_method).then(|| {
                Err(RpcError::Remote {
                    code: -1,
                    message: "No blocks in state".into(),
                })
            })
        });
        let clock = FakeClock::default();
        let error = check_readiness(&manifest, &rpc, &clock, &options()).unwrap_err();
        assert!(format!("{error:#}").contains("deadline"));
        assert_eq!(clock.elapsed(), options().deadline);
        assert!(!rpc.methods().contains(&"getblockchaininfo".into()));
    }
}

#[test]
fn wrong_genesis_or_seed_hash_is_immediate_failure_including_side_chain_acceptance() {
    let manifest = seeded_manifest();
    for height in [0, 1] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.history.insert(height, "ff".repeat(32));
        let clock = FakeClock::default();
        let error = check_readiness(&manifest, &rpc, &clock, &options()).unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("history mismatch at height {height}")));
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }
}

#[test]
fn missing_history_and_transient_transport_retry_then_observe_real_state() {
    let manifest = manifest();
    let mut rpc = FakeRpc::new(&manifest);
    rpc.hook(|call, count| {
        if call.method == "getchainrules" && count == 1 {
            Some(Err(RpcError::Transport("temporary".into())))
        } else if call.method == "getblockhash" && count == 1 {
            Some(Err(RpcError::Remote {
                code: -8,
                message: "Block not found".into(),
            }))
        } else {
            None
        }
    });
    let clock = FakeClock::default();
    let report = check_readiness(&manifest, &rpc, &clock, &options()).unwrap();
    assert_eq!(report.attempts, 3);
    assert_eq!(report.elapsed_millis, 200);
}

#[test]
fn stale_template_height_parent_or_empty_mining_state_never_passes() {
    let manifest = manifest();
    for response in [
        Ok(json!({"height":2,"previousblockhash":GENESIS})),
        Ok(json!({"height":1,"previousblockhash":"ff".repeat(32)})),
        Err((-10, "not synced")),
        Err((0, "template parent changed; retry")),
    ] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.hook(move |call, _| {
            if call.method == "getblocktemplate" {
                Some(match &response {
                    Ok(value) => Ok(value.clone()),
                    Err((code, message)) => Err(RpcError::Remote {
                        code: *code,
                        message: (*message).into(),
                    }),
                })
            } else {
                None
            }
        });
        let opts = ReadinessOptions {
            role: NodeRole::Producer,
            ..options()
        };
        let error = check_readiness(&manifest, &rpc, &FakeClock::default(), &opts).unwrap_err();
        assert!(format!("{error:#}").contains("deadline"));
    }
}

#[test]
fn transient_template_mismatch_and_end_tip_reorg_force_complete_new_observations() {
    let manifest = manifest();
    let mut rpc = FakeRpc::new(&manifest);
    rpc.hook(|call, count| {
        if call.method == "getblocktemplate" && count == 1 {
            Some(Ok(json!({"height":2,"previousblockhash":GENESIS})))
        } else if call.method == "getbestblockheightandhash" && count == 3 {
            Some(Ok(tip(0, &"ff".repeat(32))))
        } else {
            None
        }
    });
    let opts = ReadinessOptions {
        role: NodeRole::Producer,
        ..options()
    };
    let report = check_readiness(&manifest, &rpc, &FakeClock::default(), &opts).unwrap();
    assert_eq!(report.attempts, 3);
    assert_eq!(report.tip.hash, GENESIS);
}

#[test]
fn late_rule_or_history_change_invalidates_an_otherwise_successful_observation() {
    let manifest = seeded_manifest();
    for change_rules in [false, true] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.hook(move |call, count| {
            if change_rules && call.method == "getchainrules" && count == 2 {
                Some(Ok(json!({"ruleset":"wrong"})))
            } else if !change_rules && call.method == "getblockhash" && count == 4 {
                Some(Ok(json!("ff".repeat(32))))
            } else {
                None
            }
        });
        assert!(check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).is_err());
    }
}

#[test]
fn malformed_rpc_and_nontransient_remote_errors_are_not_retried() {
    let manifest = manifest();
    for error in [
        RpcError::Protocol("bad envelope".into()),
        RpcError::Remote {
            code: -32601,
            message: "method missing".into(),
        },
        RpcError::Remote {
            code: -1,
            message: "disk corrupted".into(),
        },
        RpcError::Remote {
            code: -8,
            message: "unauthorized".into(),
        },
    ] {
        let mut rpc = FakeRpc::new(&manifest);
        let error = Mutex::new(Some(error));
        rpc.hook(move |call, _| {
            if call.method == "getblockhash" {
                Some(Err(error.lock().unwrap().take().unwrap()))
            } else {
                None
            }
        });
        let clock = FakeClock::default();
        assert!(check_readiness(&manifest, &rpc, &clock, &options()).is_err());
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }
    for value in [
        json!({"height":0,"hash":GENESIS}),
        json!({"height":0,"hash":[1,2]}),
        json!({"height":-1,"hash":[]}),
        json!(null),
    ] {
        let mut rpc = FakeRpc::new(&manifest);
        rpc.actual_tip = value;
        assert!(check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).is_err());
    }
}

#[test]
fn malformed_template_or_wrong_upgrade_status_and_branches_fail_closed() {
    let manifest = manifest();
    for field in ["status", "activationheight", "branch"] {
        let mut rpc = FakeRpc::new(&manifest);
        match field {
            "status" => rpc.info["upgrades"]["37a5165b"]["status"] = json!("active"),
            "activationheight" => rpc.info["upgrades"]["37a5165b"]["activationheight"] = json!(2),
            _ => rpc.info["consensus"]["chaintip"] = json!("37a5165b"),
        }
        assert!(check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).is_err());
    }
    let mut rpc = FakeRpc::new(&manifest);
    rpc.hook(|call, _| {
        (call.method == "getblocktemplate")
            .then(|| Ok(json!({"height":1,"previousblockhash":"invalid"})))
    });
    assert!(check_readiness(
        &manifest,
        &rpc,
        &FakeClock::default(),
        &ReadinessOptions {
            role: NodeRole::Producer,
            ..options()
        }
    )
    .is_err());
}

#[test]
fn deadline_caps_each_request_and_rejects_responses_that_arrive_after_it() {
    let manifest = manifest();
    let mut rpc = FakeRpc::new(&manifest);
    let clock = FakeClock::default();
    clock.advance(90_000); // Deadline begins at function entry, not clock origin.
    let advances = clock.clone();
    rpc.hook(move |call, _| {
        if call.method == "getblockchaininfo" {
            advances.advance(2_750);
        }
        None
    });
    check_readiness(&manifest, &rpc, &clock, &options()).unwrap();
    let calls = rpc.calls.lock().unwrap();
    assert_eq!(calls.last().unwrap().timeout, Duration::from_millis(250));
    drop(calls);
    let mut rpc = FakeRpc::new(&manifest);
    let clock = FakeClock::default();
    let advances = clock.clone();
    rpc.hook(move |_, _| {
        advances.advance(3_000);
        None
    });
    let error = check_readiness(&manifest, &rpc, &clock, &options()).unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert_eq!(rpc.methods().len(), 1);
}

#[test]
fn options_and_unsupported_profiles_fail_before_any_rpc() {
    let manifest = manifest();
    let rpc = FakeRpc::new(&manifest);
    for options in [
        ReadinessOptions {
            deadline: Duration::ZERO,
            ..options()
        },
        ReadinessOptions {
            deadline: Duration::from_secs(3601),
            ..options()
        },
        ReadinessOptions {
            request_timeout: Duration::ZERO,
            ..options()
        },
        ReadinessOptions {
            request_timeout: Duration::from_secs(61),
            ..options()
        },
        ReadinessOptions {
            poll_interval: Duration::from_millis(1),
            ..options()
        },
    ] {
        assert!(check_readiness(&manifest, &rpc, &FakeClock::default(), &options).is_err());
    }
    let mut unsupported = manifest.clone();
    unsupported.temporary_orchard_disabling_height = None;
    assert!(check_readiness(&unsupported, &rpc, &FakeClock::default(), &options()).is_err());
    let mut pow = manifest;
    pow.difficulty.proof_of_work = ProofOfWork::Equihash;
    assert!(check_readiness(
        &pow,
        &rpc,
        &FakeClock::default(),
        &ReadinessOptions {
            role: NodeRole::Producer,
            ..options()
        }
    )
    .is_err());
    assert!(rpc.methods().is_empty());
}

#[test]
fn checkpoint_beyond_saved_seed_must_exist_on_the_actual_best_chain() {
    let mut manifest = seeded_manifest();
    let checkpoint_hash = "fe".repeat(32);
    manifest.checkpoints.push(Checkpoint {
        height: 2,
        hash: checkpoint_hash.clone(),
    });
    let mut rpc = FakeRpc::new(&manifest);
    rpc.history.insert(2, checkpoint_hash.clone());
    rpc.actual_tip = tip(2, &checkpoint_hash);
    rpc.info = chain_info(2, &checkpoint_hash);
    let report = check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap();
    assert_eq!(report.checked_history, 3);
    assert_eq!(report.tip.height, 2);
    assert!(
        rpc.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| { call.method == "getblockhash" && call.params == json!([2]) })
            .count()
            >= 2
    );
    rpc.history.insert(2, "a0".repeat(32));
    let error = check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap_err();
    assert!(error.to_string().contains("history mismatch at height 2"));
}

#[test]
fn dense_checkpoint_recipe_accepts_all_4096_distinct_saved_heights() {
    let mut manifest = manifest();
    manifest.seed_blocks = (1..4096)
        .map(|height| BlockIdentity {
            height,
            hash: format!("{height:064x}"),
            bytes_sha256: format!("{:064x}", height + 10_000),
            bytes_length: 1,
        })
        .collect();
    manifest.checkpoints = std::iter::once(&manifest.genesis)
        .chain(&manifest.seed_blocks)
        .map(|block| Checkpoint {
            height: block.height,
            hash: block.hash.clone(),
        })
        .collect();
    let rpc = FakeRpc::new(&manifest);
    let report = check_readiness(&manifest, &rpc, &FakeClock::default(), &options()).unwrap();
    assert_eq!(report.checked_history, 4096);
    assert_eq!(report.tip.height, 4095);
}
