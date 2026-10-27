//! Scripted orchestration tests. These payloads are not Zcash blocks and the
//! fake decoder does not establish real node or consensus qualification.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use zdn::chain::artifacts::{import_bundle, snapshot_bundle};
use zdn::chain::bootstrap::{load_seed_history, BootstrapOptions};
use zdn::chain::manifest::ConsensusManifest;
use zdn::chain::rpc::{Clock, NodeRpc, RpcError};

const BASE: &str = include_str!("fixtures/chain-manifest/valid.json");
const PAYLOADS: [&[u8]; 3] = [
    b"synthetic genesis\0",
    b"synthetic block 1\0",
    b"synthetic block 2\0",
];

fn hash(height: usize) -> String {
    format!("{:064x}", height + 1)
}

fn options() -> BootstrapOptions {
    BootstrapOptions {
        producer_stopped: true,
        ..BootstrapOptions::default()
    }
}

struct Fixture {
    root: TempDir,
    manifest: ConsensusManifest,
    bundle: PathBuf,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let root = tempdir().unwrap();
        let sources = root.path().join("blocks");
        fs::create_dir(&sources).unwrap();
        let blocks: Vec<_> = PAYLOADS[..count].iter().enumerate().map(|(height, bytes)| {
            fs::write(sources.join(format!("{height:010}.bin")), bytes).unwrap();
            json!({"height":height,"hash":hash(height),"bytesSha256":hex::encode(Sha256::digest(bytes)),"bytesLength":bytes.len()})
        }).collect();
        let mut value: Value = serde_json::from_str(BASE).unwrap();
        value["genesis"] = blocks[0].clone();
        value["seedBlocks"] = json!(&blocks[1..]);
        value["checkpoints"] = json!(blocks
            .iter()
            .map(|b| json!({"height":b["height"],"hash":b["hash"]}))
            .collect::<Vec<_>>());
        let manifest = serde_json::from_value(value).unwrap();
        let bundle = root.path().join("saved.tar");
        import_bundle(&manifest, &sources, &bundle).unwrap();
        Self {
            root,
            manifest,
            bundle,
        }
    }

    fn reimport(&mut self) {
        fs::remove_file(&self.bundle).unwrap();
        import_bundle(
            &self.manifest,
            &self.root.path().join("blocks"),
            &self.bundle,
        )
        .unwrap();
    }

    fn node(&self, clock: &FakeClock) -> FakeNode {
        FakeNode::new(&self.manifest, clock.clone())
    }
}

#[derive(Clone, Default)]
struct FakeClock(Arc<AtomicU64>);
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
    fn sleep(&self, duration: Duration) {
        self.0
            .fetch_add(duration.as_millis().try_into().unwrap(), Ordering::SeqCst);
    }
}

#[derive(Clone)]
enum Submission {
    Commit(Result<Value, RpcError>),
    Later(u64, Result<Value, RpcError>),
    Absent(Result<Value, RpcError>),
    WrongHash,
    Advance,
    ReplaceParent,
}

struct Sim {
    calls: Vec<(String, Value, Duration)>,
    rules: VecDeque<Value>,
    inspections: Vec<Value>,
    chain: BTreeMap<usize, String>,
    submissions: VecDeque<Submission>,
    pending: Vec<(u64, usize, String)>,
    hash_error: Option<RpcError>,
    hash_override: BTreeMap<i64, Result<Value, RpcError>>,
    hash_reads: u64,
    commit_after_hash_read: Option<(u64, Vec<(usize, String)>)>,
    replace_bundle_after_inspection: Option<PathBuf>,
    replace_chain_at_final_rules: Option<BTreeMap<usize, String>>,
    rule_reads: usize,
    call_millis: u64,
}

struct FakeNode {
    state: Mutex<Sim>,
    clock: FakeClock,
}
impl FakeNode {
    fn new(manifest: &ConsensusManifest, clock: FakeClock) -> Self {
        let manifest = manifest.normalized().unwrap();
        // Literal projection for this fixture; do not use the production adapter
        // or an expected_rules helper to generate the fake node response.
        let rules = json!({
            "apiVersion":"zakura-chain-rules/v1","ruleset":"zakura-configured-testnet/v1","networkKind":"custom-testnet",
            "rules":{
                "networkMagic":"a1b2c3d4","genesisHash":hash(0),"checkpoints":manifest.checkpoints,
                "activationHeights":[{"height":0,"upgrade":"Genesis"},{"height":1,"upgrade":"NU6.3"}],
                "subsidy":{
                    "slowStartInterval":0,"slowStartShift":0,"preBlossomHalvingInterval":840000,"postBlossomHalvingInterval":1680000,
                    "fundingStreams":[],"lockboxDisbursements":[{"scriptHash":"1212121212121212121212121212121212121212","amount":0}],
                    "initialNsmValueBalance":null,"allowUnshieldedCoinbaseSpends":false
                },
                "difficulty":{"targetDifficultyLimitCompact":"1f07ffff","proofOfWork":"disabled","maxBlockTimeStartHeight":653606},
                "temporaryOrchardDisablingHeight":4048500,"experimental":{"pq":null,"sqisign":null}
            }
        });
        let inspections = std::iter::once(&manifest.genesis).chain(&manifest.seed_blocks).enumerate().map(|(height, block)| json!({
            "apiVersion":"zakura-block-inspection/v1","height":height,"hash":block.hash,
            "previousHash":if height == 0 { "00".repeat(32) } else { hash(height - 1) },"bytesLength":block.bytes_length,
        })).collect();
        Self {
            clock,
            state: Mutex::new(Sim {
                calls: Vec::new(),
                rules: VecDeque::from([rules]),
                inspections,
                chain: BTreeMap::new(),
                submissions: VecDeque::new(),
                pending: Vec::new(),
                hash_error: None,
                hash_override: BTreeMap::new(),
                hash_reads: 0,
                commit_after_hash_read: None,
                replace_bundle_after_inspection: None,
                replace_chain_at_final_rules: None,
                rule_reads: 0,
                call_millis: 0,
            }),
        }
    }

    fn set_prefix(&self, count: usize) {
        self.state.lock().unwrap().chain = (0..count).map(|h| (h, hash(h))).collect();
    }

    fn submissions(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(method, _, _)| method == "submitblock")
            .count()
    }

    fn methods(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .map(|(method, _, _)| method.clone())
            .collect()
    }
}

impl NodeRpc for FakeNode {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        assert!(!timeout.is_zero() && timeout <= Duration::from_secs(60));
        let mut sim = self.state.lock().unwrap();
        sim.calls.push((method.into(), params.clone(), timeout));
        self.clock.sleep(Duration::from_millis(sim.call_millis));
        let now = self.clock.elapsed().as_millis() as u64;
        let pending = std::mem::take(&mut sim.pending);
        for (at, height, value) in pending {
            if at <= now {
                sim.chain.insert(height, value);
            } else {
                sim.pending.push((at, height, value));
            }
        }
        match method {
            "getchainrules" => {
                sim.rule_reads += 1;
                if sim.rule_reads == 2 {
                    if let Some(chain) = sim.replace_chain_at_final_rules.take() {
                        sim.chain = chain;
                    }
                }
                Ok(if sim.rules.len() > 1 {
                    sim.rules.pop_front().unwrap()
                } else {
                    sim.rules[0].clone()
                })
            }
            "inspectchainblock" => {
                let bytes = hex::decode(params[0].as_str().unwrap()).unwrap();
                let height = PAYLOADS
                    .iter()
                    .position(|p| *p == bytes)
                    .expect("unexpected submitted bytes");
                if let Some(bundle) = sim.replace_bundle_after_inspection.take() {
                    fs::write(bundle, b"untrusted replacement").unwrap();
                }
                Ok(sim.inspections[height].clone())
            }
            "getblockhash" => {
                let response = (|| {
                    if let Some(error) = &sim.hash_error {
                        return Err(error.clone());
                    }
                    let height = params[0].as_i64().unwrap();
                    if let Some(reply) = sim.hash_override.get(&height) {
                        return reply.clone();
                    }
                    let Some((&tip, _)) = sim.chain.last_key_value() else {
                        return Err(remote(-1, "No blocks in state"));
                    };
                    let height = if height == -1 {
                        tip
                    } else {
                        usize::try_from(height).unwrap()
                    };
                    if height > tip {
                        return Err(remote(
                            -32602,
                            "Provided index is greater than the current tip",
                        ));
                    }
                    sim.chain
                        .get(&height)
                        .cloned()
                        .map(Value::String)
                        .ok_or_else(|| remote(-8, "Block not found"))
                })();
                sim.hash_reads += 1;
                if sim
                    .commit_after_hash_read
                    .as_ref()
                    .is_some_and(|(read, _)| *read == sim.hash_reads)
                {
                    let (_, committed) = sim.commit_after_hash_read.take().unwrap();
                    sim.chain.extend(committed);
                }
                response
            }
            "submitblock" => {
                let bytes = hex::decode(params[0].as_str().unwrap()).unwrap();
                let height = PAYLOADS
                    .iter()
                    .position(|p| *p == bytes)
                    .expect("unexpected submitted bytes");
                match sim
                    .submissions
                    .pop_front()
                    .unwrap_or(Submission::Commit(Ok(Value::Null)))
                {
                    Submission::Commit(response) => {
                        sim.chain.insert(height, hash(height));
                        response
                    }
                    Submission::Later(delay, response) => {
                        sim.pending.push((now + delay, height, hash(height)));
                        response
                    }
                    Submission::Absent(response) => response,
                    Submission::WrongHash => {
                        sim.chain.insert(height, "ee".repeat(32));
                        Ok(Value::Null)
                    }
                    Submission::Advance => {
                        sim.chain.insert(height, hash(height));
                        sim.chain.insert(height + 1, "ee".repeat(32));
                        Ok(Value::Null)
                    }
                    Submission::ReplaceParent => {
                        sim.chain.insert(height, hash(height));
                        sim.chain.insert(height - 1, "ee".repeat(32));
                        Ok(Value::Null)
                    }
                }
            }
            unexpected => panic!("unexpected RPC {unexpected}"),
        }
    }
}

fn remote(code: i64, message: &str) -> RpcError {
    RpcError::Remote {
        code,
        message: message.into(),
    }
}

fn error(
    fixture: &Fixture,
    node: &FakeNode,
    clock: &FakeClock,
    options: &BootstrapOptions,
) -> String {
    format!(
        "{:#}",
        load_seed_history(&fixture.manifest, &fixture.bundle, node, clock, options).unwrap_err()
    )
}

#[test]
fn full_bundle_is_decoded_before_mutation_and_success_is_actual_checkpoint_history() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(report.block_count, 3);
    assert_eq!(report.already_present_blocks, 0);
    assert_eq!(report.submitted_blocks, 3);
    assert_eq!(report.submission_attempts, 3);
    assert_eq!(report.seed_tip_height, 2);
    assert_eq!(report.seed_tip_hash, hash(2));
    assert!(
        report.byte_integrity_verified
            && report.block_decoding_verified
            && report.effective_rules_verified
            && report.seed_history_present
            && report.checkpoint_acceptance
    );
    assert!(!report.full_semantic_validation && !report.launch_ready);
    assert_eq!(report.qualification, "pending");
    let methods = node.methods();
    let submit = methods.iter().position(|m| m == "submitblock").unwrap();
    assert_eq!(
        methods[..submit]
            .iter()
            .filter(|m| *m == "inspectchainblock")
            .count(),
        3
    );
    assert_eq!(methods.iter().filter(|m| *m == "getchainrules").count(), 2);
    assert!(methods.iter().all(|m| [
        "getchainrules",
        "inspectchainblock",
        "getblockhash",
        "submitblock"
    ]
    .contains(&m.as_str())));
    let second = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(second.already_present_blocks, 3);
    assert_eq!(second.submission_attempts, 0);
    assert_eq!(node.submissions(), 3);
}

#[test]
fn restarted_loader_reobserves_prefix_and_submits_only_missing_bytes() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.set_prefix(2);
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(report.already_present_blocks, 2);
    assert_eq!(report.submitted_blocks, 1);
    assert_eq!(node.submissions(), 1);
    let sim = node.state.lock().unwrap();
    let params = &sim
        .calls
        .iter()
        .find(|(m, _, _)| m == "submitblock")
        .unwrap()
        .1;
    assert_eq!(params[0], hex::encode(PAYLOADS[2]));
}

#[test]
fn byte_corruption_and_unsupported_recipe_fail_before_any_rpc() {
    for case in 0..5 {
        let mut fixture = Fixture::new(3);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        match case {
            0 => {
                let mut bytes = fs::read(&fixture.bundle).unwrap();
                let last = bytes.len() - 1;
                bytes[last] = 1;
                fs::write(&fixture.bundle, bytes).unwrap();
            }
            1 => {
                fixture.manifest.checkpoints.remove(1);
                fixture.reimport();
            }
            2 => {
                fixture.manifest.seed_blocks.remove(0);
            }
            3 => {
                fixture.manifest.seed_blocks.pop();
                fixture.reimport();
            }
            4 => {
                fixture.manifest.checkpoints.pop();
                fixture.reimport();
            }
            _ => unreachable!(),
        }
        assert!(
            load_seed_history(
                &fixture.manifest,
                &fixture.bundle,
                &node,
                &clock,
                &options()
            )
            .is_err(),
            "case {case}"
        );
        assert!(node.methods().is_empty(), "case {case}");
    }
}

#[test]
fn wrong_node_decoding_identity_or_ancestry_stops_before_submission() {
    for (field, value) in [
        ("height", json!(99)),
        ("hash", json!("ee".repeat(32))),
        ("hash", json!("not a hash")),
        ("previousHash", json!("00".repeat(32))),
        ("bytesLength", json!(999)),
        ("apiVersion", json!("other")),
        ("extra", json!(true)),
    ] {
        let fixture = Fixture::new(3);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state.lock().unwrap().inspections[2][field] = value;
        assert!(
            load_seed_history(
                &fixture.manifest,
                &fixture.bundle,
                &node,
                &clock,
                &options()
            )
            .is_err(),
            "field {field}"
        );
        assert_eq!(node.submissions(), 0);
    }
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state.lock().unwrap().inspections[0]["previousHash"] = json!(hash(7));
    assert!(error(&fixture, &node, &clock, &options()).contains("ancestry"));
    assert_eq!(node.submissions(), 0);
}

#[test]
fn snapshot_survives_bundle_replacement_without_submitting_unverified_bytes() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state.lock().unwrap().replace_bundle_after_inspection = Some(fixture.bundle.clone());
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert!(report.seed_history_present);
    assert_eq!(node.submissions(), 3);
    assert_eq!(fs::read(&fixture.bundle).unwrap(), b"untrusted replacement");
    assert!(snapshot_bundle(&fixture.manifest, &fixture.bundle).is_err());
}

#[test]
fn snapshot_retains_exact_bytes_and_fingerprint_from_one_verification() {
    let fixture = Fixture::new(3);
    let snapshot = snapshot_bundle(&fixture.manifest, &fixture.bundle).unwrap();
    fs::remove_file(&fixture.bundle).unwrap();
    assert_eq!(
        snapshot.report.consensus_fingerprint,
        fixture.manifest.fingerprint().unwrap()
    );
    for (i, block) in snapshot.blocks.iter().enumerate() {
        assert_eq!(block.bytes, PAYLOADS[i]);
        assert_eq!(block.identity.hash, hash(i));
    }
}

#[test]
fn wrong_existing_hash_or_missing_prefix_or_unknown_tip_never_submits() {
    for case in 0..3 {
        let fixture = Fixture::new(3);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        {
            let mut sim = node.state.lock().unwrap();
            match case {
                0 => {
                    sim.chain.insert(0, "ee".repeat(32));
                }
                1 => {
                    sim.chain.insert(1, hash(1));
                }
                2 => {
                    sim.chain.insert(0, hash(0));
                    sim.chain.insert(3, hash(3));
                }
                _ => unreachable!(),
            }
        }
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 0);
    }
}

#[test]
fn only_precise_known_missing_errors_can_authorize_loading() {
    for rpc_error in [
        remote(-1, "database unavailable"),
        remote(-8, "bad parameter"),
        remote(-32602, "Index conversion failed"),
        remote(-32602, "Provided index is not valid"),
        remote(-1, "No blocks in state "),
        remote(-32601, "method not found"),
        RpcError::Transport("timeout".into()),
        RpcError::Protocol("not JSON".into()),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state.lock().unwrap().hash_error = Some(rpc_error);
        assert!(error(&fixture, &node, &clock, &options()).contains("cannot establish actual"));
        assert_eq!(node.submissions(), 0);
    }
    for reply in [json!(null), json!(0), json!("not a hash")] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .hash_override
            .insert(0, Ok(reply));
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 0);
    }
}

#[test]
fn uncertain_submit_replies_count_as_success_only_after_best_chain_observation() {
    for reply in [
        Ok(Value::Null),
        Ok(json!("duplicate")),
        Ok(json!("inconclusive")),
        Ok(json!("duplicate-inconclusive")),
        Err(RpcError::Transport("lost reply".into())),
        Err(RpcError::Protocol("truncated reply".into())),
        Err(remote(-32603, "response failed")),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .submissions
            .push_back(Submission::Commit(reply));
        let report = load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options(),
        )
        .unwrap();
        assert!(report.seed_history_present);
        assert_eq!(node.submissions(), 1);
    }
}

#[test]
fn delayed_commit_after_lost_response_is_observed_before_resubmission() {
    for reply in [
        Err(RpcError::Transport("timeout".into())),
        Ok(json!("duplicate-inconclusive")),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .submissions
            .push_back(Submission::Later(500, reply));
        let report = load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options(),
        )
        .unwrap();
        assert_eq!(report.submission_attempts, 1);
        assert_eq!(clock.elapsed(), Duration::from_secs(1));
    }
}

#[test]
fn final_allowed_attempt_still_gets_one_delayed_state_observation() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state
        .lock()
        .unwrap()
        .submissions
        .push_back(Submission::Later(
            500,
            Err(RpcError::Transport("timeout".into())),
        ));
    let opts = BootstrapOptions {
        max_submit_attempts: 1,
        ..options()
    };
    assert!(
        load_seed_history(&fixture.manifest, &fixture.bundle, &node, &clock, &opts)
            .unwrap()
            .seed_history_present
    );
    assert_eq!(node.submissions(), 1);
}

#[test]
fn accepted_side_chain_and_repeated_uncertain_absence_never_report_success() {
    for reply in [
        Ok(Value::Null),
        Ok(json!("duplicate")),
        Ok(json!("inconclusive")),
        Ok(json!("duplicate-inconclusive")),
        Err(RpcError::Transport("timeout".into())),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state.lock().unwrap().submissions = vec![Submission::Absent(reply); 3].into();
        assert!(error(&fixture, &node, &clock, &options()).contains("after 3 submission attempts"));
        assert_eq!(node.submissions(), 3);
        assert_eq!(clock.elapsed(), Duration::from_secs(3));
    }
}

#[test]
fn definitive_submit_rejections_reconcile_once_and_do_not_retry() {
    for reply in [
        Ok(json!({"success":true})),
        Err(remote(-32601, "missing method")),
        Err(RpcError::Protocol("invalid response".into())),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .submissions
            .push_back(Submission::Absent(reply));
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 1);
        assert!(node.methods().last().is_some_and(|m| m == "getblockhash"));
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }
}

#[test]
fn rejected_checkpoint_is_observed_after_delayed_peer_commit_without_resubmission() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state
        .lock()
        .unwrap()
        .submissions
        .push_back(Submission::Later(1500, Ok(json!("rejected"))));
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert!(report.seed_history_present);
    assert_eq!(report.submission_attempts, 1);
    assert_eq!(node.submissions(), 1);
    assert_eq!(clock.elapsed(), Duration::from_secs(2));
}

#[test]
fn rejected_checkpoint_remaining_absent_fails_after_bounded_reads_without_resubmission() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state
        .lock()
        .unwrap()
        .submissions
        .push_back(Submission::Absent(Ok(json!("rejected"))));
    assert!(error(&fixture, &node, &clock, &options()).contains("bounded reconciliation"));
    assert_eq!(node.submissions(), 1);
    assert_eq!(clock.elapsed(), Duration::from_secs(3));
}

#[test]
fn rejected_checkpoint_observation_respects_the_total_deadline() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state
        .lock()
        .unwrap()
        .submissions
        .push_back(Submission::Absent(Ok(json!("rejected"))));
    let options = BootstrapOptions {
        request_timeout: Duration::from_millis(100),
        deadline: Duration::from_millis(500),
        ..options()
    };
    assert!(error(&fixture, &node, &clock, &options).contains("deadline"));
    assert_eq!(node.submissions(), 1);
    assert_eq!(clock.elapsed(), Duration::from_millis(500));
}

#[test]
fn delayed_rejection_reconciliation_rejects_wrong_hash_parent_and_advanced_tip() {
    for pending in [
        vec![(500, 1, "ee".repeat(32))],
        vec![(500, 0, "ee".repeat(32))],
        vec![(500, 1, hash(1)), (500, 2, "ee".repeat(32))],
    ] {
        let fixture = Fixture::new(3);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.set_prefix(1);
        {
            let mut state = node.state.lock().unwrap();
            state.pending = pending;
            state
                .submissions
                .push_back(Submission::Absent(Ok(json!("rejected"))));
        }
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 1);
        assert_eq!(clock.elapsed(), Duration::from_secs(1));
    }
}

#[test]
fn genesis_arriving_between_height_and_tip_reads_requires_fresh_exact_observation() {
    // Initial history scan, pre-submission check, and post-submission check.
    for read in [1, 3, 5] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        {
            let mut state = node.state.lock().unwrap();
            state.commit_after_hash_read = Some((read, vec![(0, hash(0))]));
            state
                .submissions
                .push_back(Submission::Absent(Ok(json!("rejected"))));
        }
        let report = load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options(),
        )
        .unwrap();
        assert!(report.seed_history_present);
        assert_eq!(node.submissions(), usize::from(read == 5));
        assert_eq!(clock.elapsed(), Duration::from_secs(1));
    }
}

#[test]
fn concurrent_saved_prefix_progress_is_rechecked_before_any_submission() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state.lock().unwrap().commit_after_hash_read =
        Some((1, (0..3).map(|height| (height, hash(height))).collect()));
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(report.already_present_blocks, 3);
    assert_eq!(node.submissions(), 0);
    assert_eq!(clock.elapsed(), Duration::from_secs(1));
}

#[test]
fn claimed_tip_without_exact_height_or_an_unrelated_tip_never_authorizes_submission() {
    for tip in [hash(0), "ee".repeat(32)] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .hash_override
            .insert(-1, Ok(json!(tip)));
        assert!(error(&fixture, &node, &clock, &options()).contains("observed saved prefix"));
        assert_eq!(node.submissions(), 0);
        assert_eq!(
            clock.elapsed(),
            if tip == hash(0) {
                Duration::from_secs(3)
            } else {
                Duration::ZERO
            }
        );
    }
}

#[test]
fn changed_parent_or_wrong_tip_after_submission_prevents_further_mutations() {
    for action in [
        Submission::WrongHash,
        Submission::Advance,
        Submission::ReplaceParent,
    ] {
        let fixture = Fixture::new(3);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.set_prefix(1);
        node.state.lock().unwrap().submissions.push_back(action);
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 1);
    }
}

#[test]
fn full_saved_history_can_be_observed_without_mutation_on_an_advanced_stable_chain() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.set_prefix(4);
    let report = load_seed_history(
        &fixture.manifest,
        &fixture.bundle,
        &node,
        &clock,
        &options(),
    )
    .unwrap();
    assert_eq!(report.already_present_blocks, 3);
    assert_eq!(report.submission_attempts, 0);
    assert!(!report.launch_ready);
}

#[test]
fn changed_effective_rules_fail_before_mutation_or_at_final_verification() {
    for final_check in [false, true] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        {
            let mut sim = node.state.lock().unwrap();
            let mut wrong = sim.rules[0].clone();
            wrong["rules"]["networkMagic"] = json!("b1b2b3b4");
            if final_check {
                sim.rules.push_back(wrong);
            } else {
                sim.rules[0] = wrong;
            }
        }
        assert!(error(&fixture, &node, &clock, &options()).contains("effective rules"));
        assert_eq!(node.submissions(), usize::from(final_check));
    }
}

#[test]
fn explicit_stopped_producer_and_bounded_options_are_required_before_rpc() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    let invalid = [
        BootstrapOptions::default(),
        BootstrapOptions {
            request_timeout: Duration::ZERO,
            ..options()
        },
        BootstrapOptions {
            request_timeout: Duration::from_secs(61),
            ..options()
        },
        BootstrapOptions {
            deadline: Duration::from_secs(3601),
            ..options()
        },
        BootstrapOptions {
            deadline: Duration::from_secs(1),
            ..options()
        },
        BootstrapOptions {
            retry_delay: Duration::ZERO,
            ..options()
        },
        BootstrapOptions {
            retry_delay: Duration::from_secs(31),
            ..options()
        },
        BootstrapOptions {
            max_submit_attempts: 0,
            ..options()
        },
        BootstrapOptions {
            max_submit_attempts: 11,
            ..options()
        },
    ];
    for opts in invalid {
        assert!(
            load_seed_history(&fixture.manifest, &fixture.bundle, &node, &clock, &opts).is_err()
        );
    }
    assert!(node.methods().is_empty());
}

#[test]
fn deadline_stops_retries_and_bounds_each_request_to_remaining_time() {
    let fixture = Fixture::new(1);
    let clock = FakeClock::default();
    let node = fixture.node(&clock);
    node.state.lock().unwrap().submissions = vec![Submission::Absent(Ok(Value::Null)); 10].into();
    let opts = BootstrapOptions {
        request_timeout: Duration::from_secs(1),
        deadline: Duration::from_millis(1500),
        retry_delay: Duration::from_secs(1),
        max_submit_attempts: 10,
        ..options()
    };
    assert!(error(&fixture, &node, &clock, &opts).contains("deadline expired"));
    assert_eq!(node.submissions(), 2);
    assert_eq!(clock.elapsed(), Duration::from_millis(1500));
    assert!(node
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|(_, _, timeout)| *timeout == Duration::from_millis(500)));
}

#[test]
fn deadline_in_preflight_prevents_submission_and_starts_at_invocation() {
    let fixture = Fixture::new(3);
    let clock = FakeClock::default();
    clock.sleep(Duration::from_secs(10000));
    let node = fixture.node(&clock);
    node.state.lock().unwrap().call_millis = 1000;
    let opts = BootstrapOptions {
        request_timeout: Duration::from_secs(1),
        deadline: Duration::from_millis(2500),
        ..options()
    };
    assert!(error(&fixture, &node, &clock, &opts).contains("deadline expired"));
    assert_eq!(node.submissions(), 0);
    let timeouts: Vec<_> = node
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .map(|(_, _, t)| *t)
        .collect();
    assert_eq!(
        timeouts,
        [
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_millis(500)
        ]
    );
}

#[test]
fn impossible_missing_tip_errors_never_authorize_an_empty_chain() {
    for error in [
        remote(-8, "Block not found"),
        remote(-32602, "Provided index is greater than the current tip"),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state
            .lock()
            .unwrap()
            .hash_override
            .insert(-1, Err(error));
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 0);
    }
}

#[test]
fn final_history_loss_hash_change_or_tip_movement_never_reports_success() {
    for chain in [
        BTreeMap::new(),
        BTreeMap::from([(0, "ee".repeat(32))]),
        BTreeMap::from([(0, hash(0)), (1, hash(1))]),
    ] {
        let fixture = Fixture::new(1);
        let clock = FakeClock::default();
        let node = fixture.node(&clock);
        node.state.lock().unwrap().replace_chain_at_final_rules = Some(chain);
        assert!(load_seed_history(
            &fixture.manifest,
            &fixture.bundle,
            &node,
            &clock,
            &options()
        )
        .is_err());
        assert_eq!(node.submissions(), 1);
    }
}
