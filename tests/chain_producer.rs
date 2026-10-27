//! Controller contracts use an independent fake node and monotonic clock.
//! No payload is a consensus block and these tests do not qualify Ironwood.
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tempfile::TempDir;
use uuid::Uuid;
use zdn::chain::{
    manifest::ConsensusManifest,
    producer::{read_status, run_producer, ProducerIdentity, ProducerOptions},
    rpc::{Clock, NodeRpc, RpcError},
};

const GENESIS: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
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
    let mut manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    manifest.genesis.hash = GENESIS.into();
    manifest
}

fn block_hash(height: u32) -> String {
    if height == 0 {
        GENESIS.into()
    } else {
        format!("{:064x}", height + 4096)
    }
}

fn rules() -> Value {
    // Literal node-owned wire projection, independently maintained from the
    // production renderer and rules comparison implementation.
    json!({
        "apiVersion":"zakura-chain-rules/v1", "ruleset":"zakura-configured-testnet/v1",
        "networkKind":"custom-testnet",
        "rules": {
            "networkMagic":"a1b2c3d4", "genesisHash":GENESIS,
            "checkpoints":[{"height":0,"hash":GENESIS}],
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

fn info(height: u32, hash: &str) -> Value {
    let upgrades: serde_json::Map<_, _> = BRANCHES
        .iter()
        .map(|(name, branch)| {
            (
                (*branch).into(),
                json!({"name":name,"activationheight":1,"status":if height == 0 {"pending"} else {"active"}}),
            )
        })
        .collect();
    json!({
        "chain":"test", "blocks":height, "bestblockhash":hash, "upgrades":upgrades,
        "consensus":{"chaintip":if height == 0 {"00000000"} else {"37a5165b"},"nextblock":"37a5165b"},
        "verificationprogress":1.0
    })
}

type CancelAt = Arc<Mutex<Option<(u64, Arc<AtomicBool>)>>>;

#[derive(Clone, Default)]
struct FakeClock {
    milliseconds: Arc<AtomicU64>,
    cancel_at: CancelAt,
}

impl FakeClock {
    fn advance(&self, duration: Duration) {
        let now = self
            .milliseconds
            .fetch_add(duration.as_millis().try_into().unwrap(), Ordering::SeqCst)
            + u64::try_from(duration.as_millis()).unwrap();
        if let Some((when, flag)) = &*self.cancel_at.lock().unwrap() {
            if now >= *when {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }
}

impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.milliseconds.load(Ordering::SeqCst))
    }
    fn sleep(&self, duration: Duration) {
        assert!(!duration.is_zero(), "controller must not busy-poll");
        self.advance(duration);
    }
}

#[derive(Clone)]
enum Generate {
    Commit { delay: Duration },
    Later { after: Duration },
    Absent,
    WrongHash,
    WrongParent,
    AdvanceTwo,
    Return(Value),
    Error(RpcError),
}

struct Sim {
    chain: BTreeMap<u32, String>,
    rules: Value,
    calls: Vec<(String, Value, Duration)>,
    generate_times: Vec<Duration>,
    modes: VecDeque<Generate>,
    pending: Option<(Duration, u32)>,
    wrong_parent: bool,
    force_error: Option<(String, RpcError)>,
    on_generate: Option<Box<dyn FnMut() + Send>>,
    reconciliation_delay: Option<(String, Duration)>,
}

struct FakeNode {
    clock: FakeClock,
    sim: Mutex<Sim>,
    in_flight: AtomicBool,
}

impl FakeNode {
    fn new(clock: &FakeClock) -> Self {
        Self {
            clock: clock.clone(),
            sim: Mutex::new(Sim {
                chain: BTreeMap::from([(0, GENESIS.into())]),
                rules: rules(),
                calls: Vec::new(),
                generate_times: Vec::new(),
                modes: VecDeque::new(),
                pending: None,
                wrong_parent: false,
                force_error: None,
                on_generate: None,
                reconciliation_delay: None,
            }),
            in_flight: AtomicBool::new(false),
        }
    }

    fn generate_times(&self) -> Vec<Duration> {
        self.sim.lock().unwrap().generate_times.clone()
    }

    fn modes(&self, modes: impl IntoIterator<Item = Generate>) {
        self.sim.lock().unwrap().modes = modes.into_iter().collect();
    }
}

impl NodeRpc for FakeNode {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        assert!(
            !self.in_flight.swap(true, Ordering::SeqCst),
            "overlapping RPC calls"
        );
        assert!(!timeout.is_zero() && timeout <= Duration::from_secs(60));
        let mut sim = self.sim.lock().unwrap();
        sim.calls.push((method.into(), params.clone(), timeout));
        if let Some((when, height)) = sim.pending {
            if self.clock.elapsed() >= when {
                sim.chain.insert(height, block_hash(height));
                sim.pending = None;
            }
        }
        if !sim.generate_times.is_empty() {
            if let Some((delayed_method, delay)) = &sim.reconciliation_delay {
                if delayed_method == method {
                    self.clock.advance(*delay);
                }
            }
        }
        let (&height, hash) = sim.chain.last_key_value().unwrap();
        let hash = hash.clone();
        let result = if let Some((target, error)) = &sim.force_error {
            if target == method {
                Some(Err(error.clone()))
            } else {
                None
            }
        } else {
            None
        };
        let result = result.unwrap_or_else(|| match method {
            "getchainrules" => Ok(sim.rules.clone()),
            "getbestblockheightandhash" => {
                let mut bytes = hex::decode(&hash).unwrap();
                bytes.reverse();
                Ok(json!({"height":height,"hash":bytes}))
            }
            "getblockchaininfo" => Ok(info(height, &hash)),
            "getblockhash" => {
                let requested = u32::try_from(params[0].as_u64().unwrap()).unwrap();
                sim.chain.get(&requested).map(|v| json!(v)).ok_or_else(|| RpcError::Remote {
                    code: -32602,
                    message: "Provided index is greater than the current tip".into(),
                })
            }
            "getblocktemplate" => {
                assert_eq!(params, json!([{}]));
                Ok(json!({"height":height+1,"previousblockhash":hash}))
            }
            "getblockheader" => {
                let requested = params[0].as_str().unwrap();
                let (&at, _) = sim.chain.iter().find(|(_, h)| h.as_str() == requested).unwrap();
                Ok(json!({
                    "hash":requested,"height":at,
                    "previousblockhash":if sim.wrong_parent {"ee".repeat(32)} else {block_hash(at-1)},
                    "confirmations":height-at+1,
                }))
            }
            "generate" => {
                assert_eq!(params, json!([1]), "only one block per mutation");
                sim.generate_times.push(self.clock.elapsed());
                if let Some(hook) = &mut sim.on_generate {
                    hook();
                }
                let mode = sim.modes.pop_front().unwrap_or(Generate::Commit { delay: Duration::ZERO });
                let next = height + 1;
                match mode {
                    Generate::Commit { delay } => {
                        self.clock.advance(delay);
                        sim.chain.insert(next, block_hash(next));
                        Ok(json!([block_hash(next)]))
                    }
                    Generate::Later { after } => {
                        sim.pending = Some((self.clock.elapsed()+after,next));
                        Err(RpcError::Transport("response was lost".into()))
                    }
                    Generate::Absent => Err(RpcError::Transport("request outcome unknown".into())),
                    Generate::WrongHash => {
                        sim.chain.insert(next, block_hash(next));
                        Ok(json!(["ee".repeat(32)]))
                    }
                    Generate::WrongParent => {
                        sim.chain.insert(next, block_hash(next));
                        sim.wrong_parent = true;
                        Ok(json!([block_hash(next)]))
                    }
                    Generate::AdvanceTwo => {
                        sim.chain.insert(next, block_hash(next));
                        sim.chain.insert(next+1, block_hash(next+1));
                        Ok(json!([block_hash(next)]))
                    }
                    Generate::Return(value) => Ok(value),
                    Generate::Error(error) => Err(error),
                }
            }
            other => panic!("unexpected node RPC: {other} {params}"),
        });
        self.in_flight.store(false, Ordering::SeqCst);
        result
    }
}

struct Fixture {
    _root: TempDir,
    manifest: ConsensusManifest,
    options: ProducerOptions,
    clock: FakeClock,
    node: FakeNode,
    cancelled: Arc<AtomicBool>,
}

impl Fixture {
    fn new(blocks: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let manifest = manifest();
        let identity = ProducerIdentity {
            deployment_id: Uuid::parse_str("d1b8f1a7-b228-421f-984b-82eebf73b67e").unwrap(),
            node_id: "node-1".into(),
            consensus_fingerprint: manifest.fingerprint().unwrap(),
        };
        let mut options = ProducerOptions::new(root.path().join("producer"), identity);
        options.max_blocks = Some(blocks);
        let clock = FakeClock::default();
        let node = FakeNode::new(&clock);
        Self {
            _root: root,
            manifest,
            options,
            clock,
            node,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn run(&self) -> eyre::Result<Value> {
        let report = run_producer(
            &self.manifest,
            &self.node,
            &self.clock,
            &self.options,
            &self.cancelled,
        )?;
        Ok(serde_json::to_value(report)?)
    }

    fn status(&self) -> Value {
        serde_json::to_value(read_status(&self.options.state_dir, &self.options.identity).unwrap())
            .unwrap()
    }
}

#[test]
fn targets_twenty_five_seconds_and_only_one_block_per_tick() {
    let fixture = Fixture::new(3);
    let report = fixture.run().unwrap();
    assert_eq!(
        fixture.node.generate_times(),
        [25, 50, 75].map(Duration::from_secs)
    );
    assert_eq!(fixture.node.sim.lock().unwrap().chain.len(), 4);
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["paymentQualification"], "pending");
}

#[test]
fn unpaced_production_has_no_scheduled_wait_and_persists_each_block_within_its_bound() {
    let mut fixture = Fixture::new(3);
    fixture.options.unpaced = true;
    fixture
        .node
        .modes([2, 3, 0].map(|seconds| Generate::Commit {
            delay: Duration::from_secs(seconds),
        }));
    let state_dir = fixture.options.state_dir.clone();
    let identity = fixture.options.identity.clone();
    let mut expected = 1;
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        let status = read_status(&state_dir, &identity).unwrap();
        assert!(status.controller_locked);
        assert_eq!(status.journal.confirmed_blocks, expected - 1);
        let pending = status.journal.pending.unwrap();
        assert_eq!(pending.sequence, expected);
        assert_eq!(u64::from(pending.parent.height), expected - 1);
        assert_eq!(pending.parent.hash, block_hash((expected - 1) as u32));
        assert!(pending.returned_hash.is_none());
        if expected > 1 {
            let receipt: Value = serde_json::from_slice(
                &fs::read(state_dir.join(format!("blocks/{:020}.json", expected - 1))).unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["tip"]["hash"], pending.parent.hash);
        }
        expected += 1;
    }));
    let report = fixture.run().unwrap();
    assert_eq!(
        fixture.node.generate_times(),
        [0, 2, 5].map(Duration::from_secs)
    );
    assert_eq!(fixture.clock.elapsed(), Duration::from_secs(5));
    assert_eq!(report["confirmedBlocks"], 3);
    assert_eq!(report["lastConfirmedTip"]["height"], 3);
    assert_eq!(report["pending"], Value::Null);
    assert_eq!(report["phase"], "stopped");
    assert_eq!(
        fs::read_dir(fixture.options.state_dir.join("blocks"))
            .unwrap()
            .count(),
        3
    );
    // Switching back to scheduled production uses the same history, not a reset.
    fixture.node.sim.lock().unwrap().on_generate = None;
    fixture.options.unpaced = false;
    fixture.options.max_blocks = Some(1);
    assert_eq!(fixture.run().unwrap()["confirmedBlocks"], 4);
    assert_eq!(
        fixture.node.generate_times(),
        [0, 2, 5, 30].map(Duration::from_secs)
    );
}

#[test]
fn unpaced_requires_a_positive_bound_before_state_creation_or_rpc() {
    for bound in [None, Some(0)] {
        let mut fixture = Fixture::new(1);
        fixture.options.unpaced = true;
        fixture.options.max_blocks = bound;
        assert!(fixture.run().is_err());
        assert!(!fixture.options.state_dir.exists());
        assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
    }
}

#[test]
fn unpaced_lost_response_waits_for_reconciliation_before_the_next_block() {
    let mut fixture = Fixture::new(2);
    fixture.options.unpaced = true;
    fixture.node.modes([Generate::Later {
        after: Duration::from_secs(3),
    }]);
    let report = fixture.run().unwrap();
    assert_eq!(
        fixture.node.generate_times(),
        [0, 3].map(Duration::from_secs)
    );
    assert_eq!(report["confirmedBlocks"], 2);
    assert_eq!(report["lastConfirmedTip"]["hash"], block_hash(2));
    assert_eq!(report["pending"], Value::Null);
}

#[test]
fn unpaced_interruption_retains_unknown_work_and_recovery_counts_toward_the_new_bound() {
    let mut fixture = Fixture::new(3);
    fixture.options.unpaced = true;
    fixture.node.modes([
        Generate::Commit {
            delay: Duration::ZERO,
        },
        Generate::Absent,
    ]);
    let cancel = fixture.cancelled.clone();
    let mut calls = 0;
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        calls += 1;
        if calls == 2 {
            cancel.store(true, Ordering::SeqCst);
        }
    }));
    let report = fixture.run().unwrap();
    assert_eq!(report["confirmedBlocks"], 1);
    assert_eq!(report["pending"]["sequence"], 2);
    assert_eq!(report["phase"], "stopped");
    fixture.cancelled.store(false, Ordering::SeqCst);
    fixture.node.sim.lock().unwrap().on_generate = None;
    assert!(fixture.run().is_err());
    assert_eq!(fixture.node.generate_times().len(), 2);
    assert_eq!(fixture.status()["pending"]["sequence"], 2);
    // The delayed commit becomes observable after the interrupted request.
    fixture
        .node
        .sim
        .lock()
        .unwrap()
        .chain
        .insert(2, block_hash(2));
    fixture.options.max_blocks = Some(1);
    let report = fixture.run().unwrap();
    assert_eq!(report["confirmedBlocks"], 2);
    assert_eq!(report["pending"], Value::Null);
    assert_eq!(fixture.node.generate_times().len(), 2);
    // A later bounded invocation may now append one block to the same journal.
    assert_eq!(fixture.run().unwrap()["confirmedBlocks"], 3);
    assert_eq!(fixture.node.generate_times().len(), 3);
}

#[test]
fn unpaced_conflicting_results_retain_intent_and_external_advances_are_not_adopted() {
    for mode in [
        Generate::WrongHash,
        Generate::WrongParent,
        Generate::AdvanceTwo,
    ] {
        let mut fixture = Fixture::new(3);
        fixture.options.unpaced = true;
        fixture.node.modes([mode]);
        assert!(fixture.run().is_err());
        assert_eq!(fixture.status()["pending"]["sequence"], 1);
        assert_eq!(fixture.status()["confirmedBlocks"], 0);
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
    }
    let mut fixture = Fixture::new(1);
    fixture.options.unpaced = true;
    fixture.run().unwrap();
    fixture
        .node
        .sim
        .lock()
        .unwrap()
        .chain
        .insert(2, block_hash(2));
    assert!(fixture.run().is_err());
    assert_eq!(fixture.node.generate_times().len(), 1);
    assert_eq!(fixture.status()["lastConfirmedTip"]["height"], 1);
    assert_eq!(fixture.status()["pending"], Value::Null);
}

#[test]
fn slow_generation_skips_missed_ticks_without_a_catch_up_burst() {
    let mut fixture = Fixture::new(2);
    fixture.options.request_timeout = Duration::from_secs(60);
    fixture.node.modes([
        Generate::Commit {
            delay: Duration::from_secs(41),
        },
        Generate::Commit {
            delay: Duration::ZERO,
        },
    ]);
    fixture.run().unwrap();
    assert_eq!(
        fixture.node.generate_times(),
        [25, 75].map(Duration::from_secs)
    );
}

#[test]
fn response_finishing_exactly_at_a_tick_waits_until_the_next_tick() {
    let fixture = Fixture::new(2);
    fixture.node.modes([
        Generate::Commit {
            delay: Duration::from_secs(25),
        },
        Generate::Commit {
            delay: Duration::ZERO,
        },
    ]);
    fixture.run().unwrap();
    assert_eq!(
        fixture.node.generate_times(),
        [25, 75].map(Duration::from_secs)
    );
}

#[test]
fn lost_generate_response_reconciles_a_late_exact_descendant_without_resubmitting() {
    let fixture = Fixture::new(1);
    fixture.node.modes([Generate::Later {
        after: Duration::from_secs(3),
    }]);
    let report = fixture.run().unwrap();
    assert_eq!(fixture.node.generate_times(), [Duration::from_secs(25)]);
    assert_eq!(
        fixture.node.sim.lock().unwrap().chain.get(&1),
        Some(&block_hash(1))
    );
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["paymentQualification"], "pending");
}

#[test]
fn an_absent_unknown_outcome_stalls_across_restart_without_another_generate() {
    let fixture = Fixture::new(1);
    fixture.node.modes([Generate::Absent]);
    assert!(fixture.run().is_err());
    let before_restart = fixture.node.generate_times();
    assert_eq!(before_restart.len(), 1);
    assert!(fixture.run().is_err());
    assert_eq!(fixture.node.generate_times(), before_restart);
    assert_eq!(fixture.node.sim.lock().unwrap().chain.len(), 1);
}

#[test]
fn restart_reconciles_a_pending_late_commit_before_authorizing_more_blocks() {
    let fixture = Fixture::new(1);
    fixture.node.modes([Generate::Absent]);
    assert!(fixture.run().is_err());
    fixture
        .node
        .sim
        .lock()
        .unwrap()
        .chain
        .insert(1, block_hash(1));
    fixture.run().unwrap();
    assert_eq!(fixture.node.generate_times().len(), 1);
}

#[test]
fn returned_hash_parent_and_tip_must_all_match_the_single_new_block() {
    for mode in [
        Generate::WrongHash,
        Generate::WrongParent,
        Generate::AdvanceTwo,
    ] {
        let fixture = Fixture::new(1);
        fixture.node.modes([mode]);
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
    }
}

#[test]
fn malformed_generate_result_remains_unresolved_and_never_retries_the_mutation() {
    for result in [
        json!([]),
        json!([block_hash(1), block_hash(2)]),
        json!(true),
        json!([17]),
        json!(["short"]),
    ] {
        let fixture = Fixture::new(1);
        fixture.node.modes([Generate::Return(result)]);
        assert!(fixture.run().is_err());
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
    }
}

#[test]
fn wrong_rules_authentication_and_protocol_fail_before_any_generate() {
    let fixture = Fixture::new(1);
    fixture.node.sim.lock().unwrap().rules["rules"]["networkMagic"] = json!("00112233");
    assert!(fixture.run().is_err());
    assert!(fixture.node.generate_times().is_empty());
    for error in [
        RpcError::Unauthorized,
        RpcError::Protocol("malformed response".into()),
        RpcError::Remote {
            code: -32601,
            message: "missing method".into(),
        },
    ] {
        let fixture = Fixture::new(1);
        fixture.node.sim.lock().unwrap().force_error = Some(("getchainrules".into(), error));
        assert!(fixture.run().is_err());
        assert!(fixture.node.generate_times().is_empty());
    }
}

#[test]
fn a_generate_auth_or_protocol_failure_never_permits_a_new_mutation() {
    for error in [
        RpcError::Unauthorized,
        RpcError::Protocol("bad response".into()),
        RpcError::Remote {
            code: -1,
            message: "failed".into(),
        },
    ] {
        let fixture = Fixture::new(1);
        fixture.node.modes([Generate::Error(error)]);
        assert!(fixture.run().is_err());
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
    }
}

#[test]
fn cancellation_before_start_and_before_first_tick_never_generates() {
    let fixture = Fixture::new(1);
    fixture.cancelled.store(true, Ordering::SeqCst);
    let _ = fixture.run();
    assert!(fixture.node.generate_times().is_empty());
    let fixture = Fixture::new(1);
    *fixture.clock.cancel_at.lock().unwrap() = Some((24_000, fixture.cancelled.clone()));
    let _ = fixture.run();
    assert!(fixture.node.generate_times().is_empty());
}

#[test]
fn cancellation_during_an_unknown_request_preserves_pending_state_for_restart() {
    let fixture = Fixture::new(1);
    fixture.node.modes([Generate::Absent]);
    let cancel = fixture.cancelled.clone();
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        cancel.store(true, Ordering::SeqCst);
    }));
    let _ = fixture.run();
    assert_eq!(fixture.node.generate_times().len(), 1);
    fixture.cancelled.store(false, Ordering::SeqCst);
    fixture.node.sim.lock().unwrap().on_generate = None;
    assert!(fixture.run().is_err());
    assert_eq!(fixture.node.generate_times().len(), 1);
}

#[test]
fn exclusive_local_ownership_refuses_a_second_controller_before_its_first_rpc() {
    let fixture = Fixture::new(1);
    let manifest = fixture.manifest.clone();
    let options = fixture.options.clone();
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        let clock = FakeClock::default();
        let node = FakeNode::new(&clock);
        let error =
            run_producer(&manifest, &node, &clock, &options, &AtomicBool::new(false)).unwrap_err();
        assert!(
            error.to_string().contains("another producer controller"),
            "{error:#}"
        );
        assert!(node.sim.lock().unwrap().calls.is_empty());
    }));
    fixture.run().unwrap();
    assert_eq!(fixture.node.generate_times().len(), 1);
}

#[test]
fn a_journal_cannot_be_rebound_to_another_deployment_node_or_consensus() {
    for field in ["deployment", "node", "consensus"] {
        let mut fixture = Fixture::new(1);
        fixture.run().unwrap();
        match field {
            "deployment" => fixture.options.identity.deployment_id = Uuid::new_v4(),
            "node" => fixture.options.identity.node_id = "node-2".into(),
            "consensus" => fixture.options.identity.consensus_fingerprint = "ee".repeat(32),
            _ => unreachable!(),
        }
        fixture.node.sim.lock().unwrap().calls.clear();
        assert!(fixture.run().is_err());
        assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
        assert_eq!(fixture.node.generate_times().len(), 1);
    }
}

#[test]
fn pending_intent_is_durable_and_the_controller_owns_the_lock_before_generate() {
    let fixture = Fixture::new(1);
    let state_dir = fixture.options.state_dir.clone();
    let identity = fixture.options.identity.clone();
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        let status = serde_json::to_value(read_status(&state_dir, &identity).unwrap()).unwrap();
        assert_eq!(status["controllerLocked"], true);
        assert_eq!(status["phase"], "generating");
        assert_eq!(status["pending"]["sequence"], 1);
        assert_eq!(status["pending"]["parent"]["height"], 0);
        assert_eq!(status["pending"]["parent"]["hash"], GENESIS);
        assert_eq!(status["pending"]["returnedHash"], Value::Null);
        let persisted: Value =
            serde_json::from_slice(&fs::read(state_dir.join("journal.json")).unwrap()).unwrap();
        assert_eq!(persisted["pending"], status["pending"]);
    }));
    fixture.run().unwrap();
    let status = fixture.status();
    assert_eq!(status["controllerLocked"], false);
    assert_eq!(status["phase"], "stopped");
    assert_eq!(status["pending"], Value::Null);
    assert_eq!(status["confirmedBlocks"], 1);
    assert_eq!(status["lastConfirmedTip"]["hash"], block_hash(1));
    assert_eq!(status["paymentQualification"], "pending");
    assert_eq!(status["launchReady"], false);
    let receipt: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .options
                .state_dir
                .join("blocks/00000000000000000001.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["parent"]["hash"], GENESIS);
    assert_eq!(receipt["tip"]["hash"], block_hash(1));
    assert_eq!(receipt["returnedHash"], block_hash(1));
}

#[test]
fn changed_tip_without_a_pending_intent_refuses_to_mine_again() {
    let fixture = Fixture::new(1);
    fixture.run().unwrap();
    fixture
        .node
        .sim
        .lock()
        .unwrap()
        .chain
        .insert(2, block_hash(2));
    assert!(fixture.run().is_err());
    assert_eq!(fixture.node.generate_times().len(), 1);
}

#[test]
fn changed_rules_or_saved_history_after_a_confirmed_block_refuse_more_generation() {
    struct ChangingNode<'a> {
        node: &'a FakeNode,
        generated: AtomicBool,
        rechecking: AtomicBool,
        change_rules: bool,
    }
    impl NodeRpc for ChangingNode<'_> {
        fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
            let mut result = self.node.call(method, params.clone(), timeout)?;
            if method == "generate" {
                self.generated.store(true, Ordering::SeqCst);
            }
            if method == "getchainrules" && self.generated.load(Ordering::SeqCst) {
                self.rechecking.store(true, Ordering::SeqCst);
                if self.change_rules {
                    result["rules"]["networkMagic"] = json!("00112233");
                }
            }
            if !self.change_rules
                && self.rechecking.load(Ordering::SeqCst)
                && method == "getblockhash"
                && params == json!([0])
            {
                result = json!("ee".repeat(32));
            }
            Ok(result)
        }
    }
    for (change_rules, unpaced) in [(true, false), (false, false), (true, true), (false, true)] {
        let mut fixture = Fixture::new(2);
        fixture.options.unpaced = unpaced;
        let node = ChangingNode {
            node: &fixture.node,
            generated: AtomicBool::new(false),
            rechecking: AtomicBool::new(false),
            change_rules,
        };
        let error = run_producer(
            &fixture.manifest,
            &node,
            &fixture.clock,
            &fixture.options,
            &fixture.cancelled,
        )
        .unwrap_err();
        let expected = if change_rules {
            "node effective rules do not match"
        } else {
            "best-chain history mismatch"
        };
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(
            fixture.node.generate_times(),
            [Duration::from_secs(if unpaced { 0 } else { 25 })]
        );
        let status = fixture.status();
        assert_eq!(status["confirmedBlocks"], 1);
        assert_eq!(status["pending"], Value::Null);
        assert_eq!(status["phase"], "stalled");
    }
}

#[test]
fn seed_history_must_exist_before_generation_is_armed() {
    let fixture = Fixture::new(1);
    fixture
        .node
        .sim
        .lock()
        .unwrap()
        .chain
        .insert(0, "ee".repeat(32));
    assert!(fixture.run().is_err());
    assert!(fixture.node.generate_times().is_empty());
    assert_eq!(fixture.status()["pending"], Value::Null);
}

#[cfg(unix)]
#[test]
fn state_files_are_private_and_unsafe_directory_permissions_are_not_changed() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(1);
    fixture.run().unwrap();
    for name in ["", "blocks"] {
        let metadata = fs::metadata(fixture.options.state_dir.join(name)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    for name in [
        "journal.json",
        "controller.lock",
        "blocks/00000000000000000001.json",
    ] {
        let metadata = fs::metadata(fixture.options.state_dir.join(name)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    fs::set_permissions(
        &fixture.options.state_dir,
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fixture.node.sim.lock().unwrap().calls.clear();
    assert!(fixture.run().is_err());
    assert_eq!(
        fs::metadata(&fixture.options.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_or_hardlinked_journal_and_lock_files_fail_before_rpc() {
    use std::os::unix::fs::symlink;
    for name in ["journal.json", "controller.lock"] {
        for hardlink in [false, true] {
            let fixture = Fixture::new(1);
            fixture.run().unwrap();
            let path = fixture.options.state_dir.join(name);
            let outside = fixture._root.path().join("outside");
            fs::rename(&path, &outside).unwrap();
            if hardlink {
                fs::hard_link(&outside, &path).unwrap();
            } else {
                symlink(&outside, &path).unwrap();
            }
            fixture.node.sim.lock().unwrap().calls.clear();
            assert!(fixture.run().is_err());
            assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
        }
    }
}

#[test]
fn corrupt_journal_and_missing_confirmed_receipt_fail_before_rpc() {
    for damage in ["journal", "receipt"] {
        let fixture = Fixture::new(1);
        fixture.run().unwrap();
        if damage == "journal" {
            fs::write(fixture.options.state_dir.join("journal.json"), "{truncated").unwrap();
        } else {
            fs::remove_file(
                fixture
                    .options
                    .state_dir
                    .join("blocks/00000000000000000001.json"),
            )
            .unwrap();
        }
        fixture.node.sim.lock().unwrap().calls.clear();
        assert!(fixture.run().is_err());
        assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
    }
}

#[test]
fn restart_after_receipt_was_saved_but_pending_journal_was_not_cleared_is_idempotent() {
    let fixture = Fixture::new(1);
    let captured = Arc::new(Mutex::new(None));
    let capture = captured.clone();
    let journal_path = fixture.options.state_dir.join("journal.json");
    let path = journal_path.clone();
    fixture.node.sim.lock().unwrap().on_generate = Some(Box::new(move || {
        let journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        *capture.lock().unwrap() = Some(journal);
    }));
    fixture.run().unwrap();
    let receipt_path = fixture
        .options
        .state_dir
        .join("blocks/00000000000000000001.json");
    let receipt = fs::read(&receipt_path).unwrap();
    let mut pending = captured.lock().unwrap().take().unwrap();
    // Crash after successful generate response + receipt persistence, before
    // committing the journal's confirmed count and clearing its intent.
    pending["pending"]["returnedHash"] = json!(block_hash(1));
    fs::write(&journal_path, serde_json::to_vec(&pending).unwrap()).unwrap();
    fixture.node.sim.lock().unwrap().on_generate = None;
    fixture.run().unwrap();
    assert_eq!(fixture.node.generate_times().len(), 1);
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
    assert_eq!(fixture.status()["pending"], Value::Null);
    assert_eq!(fixture.status()["confirmedBlocks"], 1);
}

#[test]
fn deleting_the_journal_cannot_reset_existing_confirmed_receipts() {
    let fixture = Fixture::new(1);
    fixture.run().unwrap();
    fs::remove_file(fixture.options.state_dir.join("journal.json")).unwrap();
    fixture.node.sim.lock().unwrap().calls.clear();
    assert!(fixture.run().is_err());
    assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
    assert_eq!(fixture.node.generate_times().len(), 1);
}

#[test]
fn late_reconciliation_reads_cannot_extend_the_shared_deadline_or_confirm_success() {
    for (method, delay) in [
        ("getbestblockheightandhash", Duration::from_secs(31)),
        ("getblockhash", Duration::from_secs(16)),
    ] {
        let mut fixture = Fixture::new(1);
        fixture.options.request_timeout = Duration::from_secs(60);
        fixture.node.sim.lock().unwrap().reconciliation_delay = Some((method.into(), delay));
        assert!(fixture.run().is_err());
        assert_eq!(fixture.node.generate_times().len(), 1);
        let calls = fixture.node.sim.lock().unwrap().calls.clone();
        let generated = calls
            .iter()
            .position(|(method, _, _)| method == "generate")
            .unwrap();
        let after: Vec<_> = calls[generated + 1..]
            .iter()
            .map(|(method, _, _)| method.as_str())
            .collect();
        if method == "getbestblockheightandhash" {
            assert_eq!(after, ["getbestblockheightandhash"]);
        } else {
            assert_eq!(
                after,
                ["getbestblockheightandhash", "getblockhash", "getblockhash"]
            );
        }
        assert_eq!(fixture.status()["confirmedBlocks"], 0);
        assert_eq!(fixture.status()["pending"]["returnedHash"], block_hash(1));
        assert!(!fixture
            .options
            .state_dir
            .join("blocks/00000000000000000001.json")
            .exists());
    }
}

#[test]
fn deleting_an_unresolved_journal_cannot_authorize_a_second_generate() {
    let fixture = Fixture::new(1);
    fixture.node.modes([Generate::Absent]);
    assert!(fixture.run().is_err());
    assert!(fs::read_dir(fixture.options.state_dir.join("blocks"))
        .unwrap()
        .next()
        .is_none());
    fs::remove_file(fixture.options.state_dir.join("journal.json")).unwrap();
    fixture.node.sim.lock().unwrap().calls.clear();
    assert!(fixture.run().is_err());
    assert!(fixture.node.sim.lock().unwrap().calls.is_empty());
    assert_eq!(fixture.node.generate_times().len(), 1);
}
