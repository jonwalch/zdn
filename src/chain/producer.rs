//! One persistent, locally exclusive producer for a designated private node.
//!
//! `generate(1)` has no idempotency key. Persist an intent before every call,
//! and never retry an unresolved intent, even when the observed tip is unchanged.
//! The host lifecycle must fence replacement hosts and keep the internal miner
//! disabled. This file lock is not a distributed lease or automatic failover.

use super::{
    manifest::ConsensusManifest,
    readiness::{PreparedReadiness, ReadinessOptions},
    rpc::{Clock, NodeRpc, RpcError},
    runtime_config::NodeRole,
};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use uuid::{Uuid, Variant};

pub const API_VERSION: &str = "zdn-block-producer/v1alpha1";
const MAX_JOURNAL_BYTES: u64 = 32 * 1024;
const MAX_RECONCILIATION_POLLS: usize = 3601;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProducerIdentity {
    pub deployment_id: Uuid,
    pub node_id: String,
    pub consensus_fingerprint: String,
}

impl ProducerIdentity {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.producer.identity.new")
    )]
    pub fn new(
        deployment_id: Uuid,
        node_id: impl Into<String>,
        manifest: &ConsensusManifest,
    ) -> Result<Self> {
        let identity = Self {
            deployment_id,
            node_id: node_id.into(),
            consensus_fingerprint: manifest.fingerprint()?,
        };
        identity.validate()?;
        Ok(identity)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.producer.identity.validate")
    )]
    fn validate(&self) -> Result<()> {
        ensure!(
            self.deployment_id.get_version_num() == 4
                && self.deployment_id.get_variant() == Variant::RFC4122,
            "producer deployment ID must be an RFC 4122 version 4 UUID"
        );
        let alpha = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        ensure!(
            !self.node_id.is_empty()
                && self.node_id.len() <= 63
                && self.node_id.bytes().all(|b| alpha(b) || b == b'-')
                && self.node_id.bytes().next().is_some_and(alpha)
                && self.node_id.bytes().last().is_some_and(alpha),
            "invalid producer node ID"
        );
        ensure!(
            canonical_hash(&self.consensus_fingerprint),
            "invalid producer consensus fingerprint"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ProducerOptions {
    pub state_dir: PathBuf,
    pub identity: ProducerIdentity,
    pub interval: Duration,
    pub request_timeout: Duration,
    pub readiness_deadline: Duration,
    pub reconciliation_deadline: Duration,
    pub poll_interval: Duration,
    /// Optional bound for qualification; counts confirmations during this run,
    /// including a recovered intent. The host service leaves this unset.
    pub max_blocks: Option<u64>,
    /// Skip scheduled waits for a bounded qualification run. All per-block
    /// validation and durable reconciliation still apply.
    pub unpaced: bool,
}

impl ProducerOptions {
    pub fn new(state_dir: impl Into<PathBuf>, identity: ProducerIdentity) -> Self {
        Self {
            state_dir: state_dir.into(),
            identity,
            interval: Duration::from_secs(25),
            request_timeout: Duration::from_secs(10),
            readiness_deadline: Duration::from_secs(120),
            reconciliation_deadline: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
            max_blocks: None,
            unpaced: false,
        }
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.producer.options.validate")
    )]
    fn validate(&self, manifest: &ConsensusManifest) -> Result<()> {
        self.identity.validate()?;
        ensure!(
            self.identity.consensus_fingerprint == manifest.fingerprint()?,
            "producer identity does not match the consensus manifest"
        );
        ensure!(
            self.interval >= Duration::from_secs(1)
                && self.interval <= Duration::from_secs(86_400)
                && self.interval.subsec_nanos() == 0,
            "producer interval must be 1 to 86400 whole seconds"
        );
        ensure!(
            !self.request_timeout.is_zero() && self.request_timeout <= Duration::from_secs(60),
            "producer request timeout must be positive and at most 60 seconds"
        );
        ensure!(
            self.readiness_deadline >= self.request_timeout
                && self.readiness_deadline <= Duration::from_secs(3600),
            "producer readiness deadline must cover a request and be at most one hour"
        );
        ensure!(
            !self.reconciliation_deadline.is_zero()
                && self.reconciliation_deadline <= Duration::from_secs(3600),
            "producer reconciliation deadline must be positive and at most one hour"
        );
        ensure!(
            self.poll_interval >= Duration::from_millis(10)
                && self.poll_interval <= Duration::from_secs(10)
                && self.poll_interval <= self.reconciliation_deadline
                && self.poll_interval <= self.readiness_deadline,
            "producer poll interval must be 10 milliseconds to 10 seconds and within deadlines"
        );
        ensure!(
            self.max_blocks != Some(0),
            "producer max blocks must be positive"
        );
        ensure!(
            !self.unpaced || self.max_blocks.is_some(),
            "unpaced production requires a positive max blocks bound"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProducerTip {
    pub height: u32,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProducerPhase {
    Starting,
    Waiting,
    Generating,
    Stalled,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingGeneration {
    pub sequence: u64,
    pub parent: ProducerTip,
    /// Known only after a well-formed successful response. An absent value
    /// never proves that generation did not execute.
    pub returned_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProducerJournal {
    pub api_version: String,
    pub identity: ProducerIdentity,
    pub owner_pid: u32,
    pub owner_session: Uuid,
    pub phase: ProducerPhase,
    pub interval_secs: u64,
    pub last_confirmed_tip: Option<ProducerTip>,
    pub pending: Option<PendingGeneration>,
    pub confirmed_blocks: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerStatus {
    #[serde(flatten)]
    pub journal: ProducerJournal,
    /// A current local lock observation, not a promise about a later instant.
    /// The host also compares ownerPid with the service's current MainPID.
    pub controller_locked: bool,
    pub payment_qualification: &'static str,
    pub launch_ready: bool,
}

pub type ProducerReport = ProducerStatus;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlockReceipt {
    api_version: String,
    identity: ProducerIdentity,
    sequence: u64,
    parent: ProducerTip,
    tip: ProducerTip,
    returned_hash: Option<String>,
}

/// Run synchronously: at most one RPC, and therefore one generation request,
/// can be in progress. A persisted unresolved intent survives every exit path.
/// A stop during a request waits for its bounded timeout, then leaves the
/// outcome for the next owner to reconcile without submitting another call.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.producer.run_producer")
)]
pub fn run_producer(
    manifest: &ConsensusManifest,
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &ProducerOptions,
    cancel: &AtomicBool,
) -> Result<ProducerReport> {
    options.validate(manifest)?;
    let (store, mut journal) = Store::open(options)?;
    let rpc = CancellableRpc { rpc, cancel };
    let result = run_inner(manifest, &rpc, clock, options, cancel, &store, &mut journal);
    match result {
        Ok(()) => {
            journal.phase = ProducerPhase::Stopped;
            store.save(&journal)?;
            Ok(ProducerStatus {
                journal,
                controller_locked: false,
                payment_qualification: "pending",
                launch_ready: false,
            })
        }
        Err(error) => {
            journal.phase = if cancelled(cancel) {
                ProducerPhase::Stopped
            } else {
                ProducerPhase::Stalled
            };
            // The older durable pending intent remains authoritative if this
            // final status write itself fails (for example a full filesystem).
            if let Err(save_error) = store.save(&journal) {
                return Err(
                    error.wrap_err(format!("could not save producer stop status: {save_error}"))
                );
            }
            if cancelled(cancel) {
                Ok(ProducerStatus {
                    journal,
                    controller_locked: false,
                    payment_qualification: "pending",
                    launch_ready: false,
                })
            } else {
                Err(error)
            }
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.producer.run_inner")
)]
fn run_inner(
    manifest: &ConsensusManifest,
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &ProducerOptions,
    cancel: &AtomicBool,
    store: &Store,
    journal: &mut ProducerJournal,
) -> Result<()> {
    if cancelled(cancel) {
        return Ok(());
    }
    let start = clock.elapsed();
    let prepared = PreparedReadiness::new(manifest)
        .context("verify producer rules, saved history and mining readiness")?;
    let initial = ready(&prepared, rpc, clock, options, start)?;
    if cancelled(cancel) {
        return Ok(());
    }
    let started_count = journal.confirmed_blocks;
    if journal.pending.is_some() {
        reconcile(rpc, clock, options, cancel, store, journal)?;
    } else if let Some(saved) = &journal.last_confirmed_tip {
        ensure!(
            saved == &initial,
            "producer tip differs from its last confirmed history; refusing generation"
        );
    } else {
        journal.last_confirmed_tip = Some(initial);
    }
    journal.phase = ProducerPhase::Waiting;
    store.save(journal)?;
    let origin = clock.elapsed();
    let mut next = origin;
    if !options.unpaced {
        next = origin
            .checked_add(options.interval)
            .context("producer schedule overflow")?;
    }
    loop {
        if cancelled(cancel)
            || options
                .max_blocks
                .is_some_and(|maximum| journal.confirmed_blocks - started_count >= maximum)
        {
            return Ok(());
        }
        while !options.unpaced && clock.elapsed() < next {
            if cancelled(cancel) {
                return Ok(());
            }
            clock.sleep(
                next.saturating_sub(clock.elapsed())
                    .min(Duration::from_millis(100)),
            );
        }
        if cancelled(cancel) {
            return Ok(());
        }
        // Recheck parsed rules, saved history, actual tip and a matching fresh
        // template before every request, including after a long pause.
        let parent = ready(&prepared, rpc, clock, options, clock.elapsed())?;
        ensure!(
            journal.last_confirmed_tip.as_ref() == Some(&parent),
            "producer tip moved without a pending generation; refusing generation"
        );
        if cancelled(cancel) {
            return Ok(());
        }
        let sequence = journal
            .confirmed_blocks
            .checked_add(1)
            .context("producer sequence overflow")?;
        journal.pending = Some(PendingGeneration {
            sequence,
            parent,
            returned_hash: None,
        });
        journal.phase = ProducerPhase::Generating;
        store.save(journal)?;
        if !generate_once(rpc, options, cancel, store, journal)? {
            return Ok(());
        }
        reconcile(rpc, clock, options, cancel, store, journal)?;
        journal.phase = ProducerPhase::Waiting;
        store.save(journal)?;
        if options.unpaced {
            continue;
        }
        // Phase-locked ticks strictly after completion: missed ticks never
        // trigger an immediate burst, including a response exactly on a tick.
        let elapsed = clock.elapsed().saturating_sub(origin);
        let ticks = elapsed.as_nanos() / options.interval.as_nanos() + 1;
        let seconds: u64 = ticks
            .checked_mul(options.interval.as_secs() as u128)
            .and_then(|value| value.try_into().ok())
            .context("producer schedule overflow")?;
        next = origin
            .checked_add(Duration::from_secs(seconds))
            .context("producer schedule overflow")?;
    }
}

/// The caller has already durably saved `pending`; no RPC may precede it.
fn generate_once(
    rpc: &impl NodeRpc,
    options: &ProducerOptions,
    cancel: &AtomicBool,
    store: &Store,
    journal: &mut ProducerJournal,
) -> Result<bool> {
    // No call has started yet: this is the only path that can clear an
    // intent without proving its block. After call() begins, retain it.
    if cancelled(cancel) {
        journal.pending = None;
        store.save(journal)?;
        return Ok(false);
    }
    let response = rpc.call("generate", json!([1]), options.request_timeout);
    if let Ok(response) = response {
        let hashes = response
            .as_array()
            .context("invalid generate result: expected one block hash")?;
        ensure!(
            hashes.len() == 1,
            "generate result must contain exactly one block hash"
        );
        let hash = read_hash(&hashes[0], "generated block hash")?;
        journal
            .pending
            .as_mut()
            .expect("durable pending intent")
            .returned_hash = Some(hash);
        store.save(journal)?;
    }
    // Even explicit errors are conservative: a remote error is not a
    // protocol-level guarantee that no block was committed.
    if cancelled(cancel) {
        return Ok(false);
    }
    Ok(true)
}

fn ready(
    prepared: &PreparedReadiness,
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &ProducerOptions,
    start: Duration,
) -> Result<ProducerTip> {
    let report = prepared
        .check(
            rpc,
            clock,
            &ReadinessOptions {
                role: NodeRole::Producer,
                request_timeout: options.request_timeout,
                deadline: options.readiness_deadline,
                poll_interval: options.poll_interval,
            },
            start,
        )
        .context("verify producer rules, saved history and mining readiness")?;
    Ok(ProducerTip {
        height: report.tip.height,
        hash: report.tip.hash,
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.producer.reconcile")
)]
fn reconcile(
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &ProducerOptions,
    cancel: &AtomicBool,
    store: &Store,
    journal: &mut ProducerJournal,
) -> Result<()> {
    let pending = journal
        .pending
        .clone()
        .context("missing generation intent")?;
    let start = clock.elapsed();
    let next_height = pending
        .parent
        .height
        .checked_add(1)
        .context("producer height overflow")?;
    for _ in 0..MAX_RECONCILIATION_POLLS {
        ensure!(
            !cancelled(cancel),
            "producer stopping with generation outcome unresolved"
        );
        let remaining = reconciliation_remaining(clock, options, start)?;
        let timeout = || -> Result<Duration> {
            Ok(options
                .request_timeout
                .min(reconciliation_remaining(clock, options, start)?))
        };
        let tip = match read_tip(rpc, timeout()?) {
            Ok(tip) => tip,
            Err(error)
                if error
                    .downcast_ref::<RpcError>()
                    .is_some_and(|error| matches!(error, RpcError::Transport(_))) =>
            {
                clock.sleep(options.poll_interval.min(remaining));
                continue;
            }
            Err(error) => return Err(error.wrap_err("reconcile generation outcome")),
        };
        if tip == pending.parent {
            clock.sleep(options.poll_interval.min(remaining));
            continue;
        }
        ensure!(
            tip.height == next_height,
            "generation outcome conflicts with the expected next height; pending intent retained"
        );
        if let Some(expected) = &pending.returned_hash {
            ensure!(
                &tip.hash == expected,
                "generated hash is not the actual best-chain tip; pending intent retained"
            );
        }
        ensure!(
            read_hash(
                &rpc.call("getblockhash", json!([pending.parent.height]), timeout()?)?,
                "parent hash"
            )? == pending.parent.hash,
            "generation changed its parent ancestry; pending intent retained"
        );
        ensure!(
            read_hash(
                &rpc.call("getblockhash", json!([tip.height]), timeout()?)?,
                "tip hash"
            )? == tip.hash,
            "generation tip is not in the best chain; pending intent retained"
        );
        let header = rpc.call("getblockheader", json!([tip.hash, true]), timeout()?)?;
        ensure!(read_hash(&header["hash"], "header hash")? == tip.hash
            && header["height"].as_u64() == Some(u64::from(tip.height))
            && read_hash(&header["previousblockhash"], "header parent")? == pending.parent.hash
            && header["confirmations"].as_i64().is_some_and(|count| count >= 1),
            "generated block header does not prove the expected best-chain ancestry; pending intent retained");
        ensure!(
            read_tip(rpc, timeout()?)? == tip,
            "tip moved during generation reconciliation; pending intent retained"
        );
        ensure!(
            clock.elapsed().saturating_sub(start) < options.reconciliation_deadline,
            "generation reconciliation deadline expired; pending intent retained"
        );
        let receipt = BlockReceipt {
            api_version: API_VERSION.into(),
            identity: options.identity.clone(),
            sequence: pending.sequence,
            parent: pending.parent.clone(),
            tip: tip.clone(),
            returned_hash: pending.returned_hash.clone(),
        };
        store.record(&receipt)?;
        journal.last_confirmed_tip = Some(tip);
        journal.confirmed_blocks = pending.sequence;
        journal.pending = None;
        // Both callers immediately save this confirmed state with phase Waiting
        // before any further RPC or generation. The receipt is already durable;
        // do not publish the same journal twice just to change its phase.
        return Ok(());
    }
    bail!("generation reconciliation poll limit reached; pending intent retained")
}

fn reconciliation_remaining(
    clock: &impl Clock,
    options: &ProducerOptions,
    start: Duration,
) -> Result<Duration> {
    options
        .reconciliation_deadline
        .checked_sub(clock.elapsed().saturating_sub(start))
        .filter(|remaining| !remaining.is_zero())
        .context("generation outcome remains unresolved; refusing another generation request")
}

fn read_tip(rpc: &impl NodeRpc, timeout: Duration) -> Result<ProducerTip> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawTip {
        height: u32,
        hash: [u8; 32],
    }
    let raw: RawTip =
        serde_json::from_value(rpc.call("getbestblockheightandhash", json!([]), timeout)?)
            .context("invalid actual producer tip")?;
    ensure!(
        raw.height < i32::MAX as u32,
        "unsupported producer tip height"
    );
    let mut hash = raw.hash;
    hash.reverse();
    Ok(ProducerTip {
        height: raw.height,
        hash: hex::encode(hash),
    })
}

fn read_hash(value: &Value, label: &str) -> Result<String> {
    let hash = value.as_str().with_context(|| format!("invalid {label}"))?;
    ensure!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid {label}"
    );
    Ok(hash.to_ascii_lowercase())
}

fn canonical_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::SeqCst)
}

struct CancellableRpc<'a, R> {
    rpc: &'a R,
    cancel: &'a AtomicBool,
}
impl<R: NodeRpc> NodeRpc for CancellableRpc<'_, R> {
    fn call(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> std::result::Result<Value, RpcError> {
        if cancelled(self.cancel) {
            return Err(RpcError::Protocol("producer stopping".into()));
        }
        self.rpc.call(method, params, timeout)
    }
}

struct Store {
    root: PathBuf,
    lock: File,
}

impl Store {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.producer.store.open")
    )]
    fn open(options: &ProducerOptions) -> Result<(Self, ProducerJournal)> {
        private_directory(&options.state_dir, true)?;
        let lock_path = options.state_dir.join("controller.lock");
        let (lock, fresh) = match open_private_flags(&lock_path, true) {
            Ok(lock) => (lock, true),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                (open_private(&lock_path)?, false)
            }
            Err(error) => return Err(error),
        };
        lock.try_lock_exclusive()
            .context("another producer controller owns this state directory")?;
        let store = Self {
            root: options.state_dir.clone(),
            lock,
        };
        private_directory(&store.root.join("blocks"), true)?;
        let journal_path = store.root.join("journal.json");
        let mut journal = match read_private::<ProducerJournal>(&journal_path) {
            Ok(journal) => {
                validate_journal(&journal, &options.identity)?;
                journal
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                ensure!(fresh, "existing producer ownership file has no journal; generation history is uncertain");
                ensure!(
                    fs::read_dir(store.root.join("blocks"))?.next().is_none(),
                    "producer journal missing while block receipts exist"
                );
                ProducerJournal {
                    api_version: API_VERSION.into(),
                    identity: options.identity.clone(),
                    owner_pid: std::process::id(),
                    owner_session: Uuid::new_v4(),
                    phase: ProducerPhase::Starting,
                    interval_secs: options.interval.as_secs(),
                    last_confirmed_tip: None,
                    pending: None,
                    confirmed_blocks: 0,
                }
            }
            Err(error) => return Err(error.wrap_err("read producer journal")),
        };
        if journal.confirmed_blocks > 0 {
            let receipt: BlockReceipt =
                read_private(&store.receipt_path(journal.confirmed_blocks))?;
            validate_tip(&receipt.parent)?;
            validate_tip(&receipt.tip)?;
            ensure!(
                receipt.parent.height.checked_add(1) == Some(receipt.tip.height)
                    && receipt
                        .returned_hash
                        .as_ref()
                        .is_none_or(|hash| hash == &receipt.tip.hash),
                "invalid saved producer block ancestry or response hash"
            );
            ensure!(
                receipt.api_version == API_VERSION
                    && receipt.identity == journal.identity
                    && receipt.sequence == journal.confirmed_blocks
                    && journal.last_confirmed_tip.as_ref() == Some(&receipt.tip),
                "last producer block receipt does not match the durable journal"
            );
        }
        journal.owner_pid = std::process::id();
        journal.owner_session = Uuid::new_v4();
        journal.phase = ProducerPhase::Starting;
        journal.interval_secs = options.interval.as_secs();
        store.save(&journal)?;
        Ok((store, journal))
    }

    fn save(&self, journal: &ProducerJournal) -> Result<()> {
        validate_journal(journal, &journal.identity)?;
        crate::foundation::write_json(&self.root.join("journal.json"), journal)
    }

    fn receipt_path(&self, sequence: u64) -> PathBuf {
        self.root
            .join("blocks")
            .join(format!("{sequence:020}.json"))
    }

    fn record(&self, receipt: &BlockReceipt) -> Result<()> {
        let path = self.receipt_path(receipt.sequence);
        match read_private::<BlockReceipt>(&path) {
            Ok(saved) => {
                ensure!(
                    &saved == receipt,
                    "saved producer block receipt conflicts with reconciliation"
                );
                Ok(())
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                crate::foundation::write_json(&path, receipt)
            }
            Err(error) => Err(error.wrap_err("read producer block receipt")),
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock);
    }
}

/// Read persisted identity and status without creating files or making RPCs.
/// The lock and MainPID checks establish a bounded observation of ownership;
/// saved phases alone never establish that a controller is alive.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.producer.read_status")
)]
pub fn read_status(state_dir: &Path, identity: &ProducerIdentity) -> Result<ProducerStatus> {
    identity.validate()?;
    private_directory(state_dir, false)?;
    let lock = open_private(&state_dir.join("controller.lock"))?;
    let controller_locked = match lock.try_lock_exclusive() {
        Ok(()) => false,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(error) => return Err(error).context("inspect producer ownership"),
    };
    let journal: ProducerJournal = read_private(&state_dir.join("journal.json"))?;
    validate_journal(&journal, identity)?;
    if !controller_locked {
        FileExt::unlock(&lock)?;
    }
    Ok(ProducerStatus {
        journal,
        controller_locked,
        payment_qualification: "pending",
        launch_ready: false,
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.producer.validate_journal")
)]
fn validate_journal(journal: &ProducerJournal, identity: &ProducerIdentity) -> Result<()> {
    ensure!(
        journal.api_version == API_VERSION && &journal.identity == identity,
        "producer journal identity or version mismatch"
    );
    identity.validate()?;
    ensure!(
        journal.owner_pid > 0
            && journal.owner_session.get_version_num() == 4
            && (1..=86_400).contains(&journal.interval_secs),
        "invalid producer owner or interval"
    );
    if let Some(tip) = &journal.last_confirmed_tip {
        validate_tip(tip)?;
    }
    ensure!(
        journal.confirmed_blocks == 0 || journal.last_confirmed_tip.is_some(),
        "producer confirmed count has no tip"
    );
    if let Some(pending) = &journal.pending {
        validate_tip(&pending.parent)?;
        ensure!(
            journal.confirmed_blocks.checked_add(1) == Some(pending.sequence)
                && journal.last_confirmed_tip.as_ref() == Some(&pending.parent),
            "producer pending sequence or parent mismatch"
        );
        if let Some(hash) = &pending.returned_hash {
            ensure!(canonical_hash(hash), "invalid pending block hash");
        }
    }
    Ok(())
}

fn validate_tip(tip: &ProducerTip) -> Result<()> {
    ensure!(
        tip.height < i32::MAX as u32 && canonical_hash(&tip.hash),
        "invalid saved producer tip"
    );
    Ok(())
}

fn private_directory(path: &Path, create: bool) -> Result<()> {
    if create {
        let was_absent = matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        crate::foundation::private_directory(path)?;
        // Persist a new directory entry before any generation intent can be
        // published underneath it. Existing host-owned directories need no
        // sync of their read-only parent in the systemd mount namespace.
        if was_absent {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                File::open(parent)?.sync_all()?;
            }
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "producer state must use a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "producer state directory must be private (0700)"
        );
    }
    Ok(())
}

fn open_private(path: &Path) -> Result<File> {
    open_private_flags(path, false)
}

fn open_private_flags(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create_new).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "producer state file must be regular");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.permissions().mode() & 0o077 == 0 && metadata.nlink() == 1,
            "producer state file must be private and have one link"
        );
    }
    Ok(file)
}

fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = open_private(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JOURNAL_BYTES,
        "producer state record exceeds 32 KiB"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoRpc;
    impl NodeRpc for NoRpc {
        fn call(&self, _: &str, _: Value, _: Duration) -> std::result::Result<Value, RpcError> {
            panic!("cancellation after the durable intent must precede every RPC");
        }
    }

    #[test]
    fn cancellation_after_intent_sync_clears_only_a_provably_unattempted_call() {
        let directory = tempfile::tempdir().unwrap();
        let manifest: ConsensusManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/chain-manifest/valid.json"
        ))
        .unwrap();
        let identity = ProducerIdentity::new(Uuid::new_v4(), "node-1", &manifest).unwrap();
        let options = ProducerOptions::new(directory.path().join("producer"), identity);
        let (store, mut journal) = Store::open(&options).unwrap();
        let parent = ProducerTip {
            height: 0,
            hash: manifest.genesis.hash,
        };
        journal.last_confirmed_tip = Some(parent.clone());
        journal.pending = Some(PendingGeneration {
            sequence: 1,
            parent,
            returned_hash: None,
        });
        journal.phase = ProducerPhase::Generating;
        store.save(&journal).unwrap();
        let saved: ProducerJournal = read_private(&options.state_dir.join("journal.json")).unwrap();
        assert!(saved.pending.is_some());
        let stop = AtomicBool::new(true);
        assert!(!generate_once(&NoRpc, &options, &stop, &store, &mut journal).unwrap());
        let saved: ProducerJournal = read_private(&options.state_dir.join("journal.json")).unwrap();
        assert!(saved.pending.is_none());
        assert_eq!(saved.confirmed_blocks, 0);
    }
}
