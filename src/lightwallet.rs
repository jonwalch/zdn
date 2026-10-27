//! Read-only lightwalletd diagnostics against independently checked node state.
//!
//! This observes the pinned protocol, compact payloads and tree state. It does
//! not prove wallet scanning, transaction acceptance, or a working payment.
mod projection;
mod transport;
pub mod wire;
pub use transport::{GrpcLightwalletRpc, LightwalletError, LightwalletRpc};

use crate::chain::{
    manifest::ConsensusManifest,
    readiness,
    rpc::{Clock, NodeRpc, RpcError},
    runtime_config::NodeRole,
};
use eyre::{bail, ensure, eyre, Context, ContextCompat, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

pub const API_VERSION: &str = "zdn-lightwallet-readiness/v1alpha1";
pub const PROTOCOL_VERSION: &str = "v0.5.0";
const MAX_ATTEMPTS: u32 = 256;
const MAX_CALLS: usize = 32_768;

#[derive(Clone, Debug)]
pub struct ReadinessOptions {
    pub request_timeout: Duration,
    pub deadline: Duration,
    pub poll_interval: Duration,
    pub max_lag_blocks: u32,
}
impl Default for ReadinessOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(120),
            poll_interval: Duration::from_secs(1),
            max_lag_blocks: 0,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LightwalletReadinessReport {
    pub api_version: String,
    pub consensus_fingerprint: String,
    pub protocol_version: String,
    pub node_tip: readiness::ObservedTip,
    pub lightwallet_tip: readiness::ObservedTip,
    pub lag_blocks: u32,
    pub checked_compact_blocks: usize,
    pub checked_ironwood_actions: usize,
    pub ironwood_tree_verified: bool,
    pub compact_data_verified: bool,
    pub payment_qualification: String,
    pub launch_ready: bool,
    pub attempts: u32,
    pub elapsed_millis: u64,
}

/// Verify a bounded light-wallet observation against the manifest and trusted
/// loopback node. Every response is checked before a report is emitted. The
/// complete stream (including status trailers), not just its first item, must
/// finish within its request timeout and the shared observation deadline.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.check_readiness")
)]
pub fn check_readiness(
    manifest: &ConsensusManifest,
    node: &impl NodeRpc,
    wallet: &impl LightwalletRpc,
    clock: &impl Clock,
    options: &ReadinessOptions,
) -> Result<LightwalletReadinessReport> {
    let start = clock.elapsed();
    validate_options(options)?;
    let manifest = manifest.normalized()?;
    let mut saved = BTreeMap::from([(0, manifest.genesis.hash.clone())]);
    for (height, hash) in manifest
        .seed_blocks
        .iter()
        .map(|v| (v.height, &v.hash))
        .chain(manifest.checkpoints.iter().map(|v| (v.height, &v.hash)))
    {
        if let Some(previous) = saved.insert(height, hash.clone()) {
            ensure!(previous == *hash, "conflicting saved block identity");
        }
    }
    ensure!(
        saved.len() <= 62,
        "light-wallet diagnostic supports at most 62 saved heights plus two recent blocks"
    );
    let prepared = readiness::PreparedReadiness::new(&manifest)?;
    let mut budget = Budget {
        node,
        wallet,
        clock,
        options,
        start,
        calls: AtomicUsize::new(0),
    };
    let mut waiting = String::from("light-wallet service not observed");
    for attempt in 1..=MAX_ATTEMPTS {
        budget.remaining().with_context(|| waiting.clone())?;
        match observe(&manifest, &prepared, &saved, &mut budget) {
            Ok(mut report) => {
                report.attempts = attempt;
                report.elapsed_millis = budget.elapsed().as_millis().try_into()?;
                return Ok(report);
            }
            Err(ObservationError::Fatal(error)) => return Err(error),
            Err(ObservationError::Wait(reason)) => waiting = reason,
        }
        let remaining = budget.remaining().with_context(|| waiting.clone())?;
        clock.sleep(options.poll_interval.min(remaining));
    }
    bail!("light-wallet observation attempt limit reached: {waiting}")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.validate_options")
)]
fn validate_options(options: &ReadinessOptions) -> Result<()> {
    ensure!(
        !options.deadline.is_zero() && options.deadline <= Duration::from_secs(3600),
        "light-wallet deadline must be positive and at most 3600 seconds"
    );
    ensure!(
        !options.request_timeout.is_zero()
            && options.request_timeout <= Duration::from_secs(60)
            && options.request_timeout <= options.deadline,
        "request timeout must be positive, at most 60 seconds, and within the deadline"
    );
    ensure!(
        options.poll_interval >= Duration::from_millis(10)
            && options.poll_interval <= Duration::from_secs(10)
            && options.poll_interval <= options.deadline,
        "poll interval must be 10 milliseconds to 10 seconds and within the deadline"
    );
    ensure!(
        options.max_lag_blocks <= 1024,
        "maximum light-wallet lag exceeds 1024 blocks"
    );
    Ok(())
}

enum ObservationError {
    Wait(String),
    Fatal(eyre::Report),
}
type Observation<T> = std::result::Result<T, ObservationError>;
impl From<eyre::Report> for ObservationError {
    fn from(error: eyre::Report) -> Self {
        Self::Fatal(error)
    }
}
struct Budget<'a, R, W, C> {
    node: &'a R,
    wallet: &'a W,
    clock: &'a C,
    options: &'a ReadinessOptions,
    start: Duration,
    calls: AtomicUsize,
}
impl<R: NodeRpc, W: LightwalletRpc, C: Clock> Budget<'_, R, W, C> {
    fn elapsed(&self) -> Duration {
        self.clock.elapsed().saturating_sub(self.start)
    }
    fn remaining(&self) -> Result<Duration> {
        self.options
            .deadline
            .checked_sub(self.elapsed())
            .filter(|v| !v.is_zero())
            .context("light-wallet readiness deadline expired")
    }
    fn timeout(&mut self) -> Result<Duration> {
        ensure!(
            self.calls.fetch_add(1, Ordering::Relaxed) < MAX_CALLS,
            "light-wallet request count limit reached"
        );
        Ok(self.remaining()?.min(self.options.request_timeout))
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.budget.node")
    )]
    fn node(&mut self, method: &str, params: Value) -> Observation<Value> {
        let timeout = self.timeout()?;
        let result = self.node.call(method, params, timeout);
        self.remaining()?;
        match result {
            Ok(value) => Ok(value),
            Err(RpcError::Transport(_)) => {
                Err(ObservationError::Wait(format!("waiting for node {method}")))
            }
            Err(error) => Err(eyre!(error)
                .wrap_err(format!("node {method} failed"))
                .into()),
        }
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.budget.wallet")
    )]
    fn wallet<T>(
        &mut self,
        call: impl FnOnce(&W, Duration) -> Result<T, LightwalletError>,
    ) -> Observation<T> {
        let timeout = self.timeout()?;
        let result = call(self.wallet, timeout);
        self.remaining()?;
        match result {
            Ok(value) => Ok(value),
            Err(LightwalletError::Transport) => Err(ObservationError::Wait(
                "waiting for light-wallet transport".into(),
            )),
            Err(LightwalletError::Status(code))
                if matches!(
                    code,
                    tonic::Code::Unavailable
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::Aborted
                        | tonic::Code::NotFound
                        | tonic::Code::OutOfRange
                ) =>
            {
                Err(ObservationError::Wait(format!(
                    "waiting for light-wallet state ({code:?})"
                )))
            }
            Err(error) => Err(eyre!(error).into()),
        }
    }
}

/// Include the node readiness adapter's internal requests in our shared cap.
struct CountingNode<'a, R> {
    node: &'a R,
    calls: &'a AtomicUsize,
}
impl<R: NodeRpc> NodeRpc for CountingNode<'_, R> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.counting_node.call")
    )]
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= MAX_CALLS {
            return Err(RpcError::Protocol(
                "light-wallet request count limit reached".into(),
            ));
        }
        self.node.call(method, params, timeout)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.observe")
)]
fn observe(
    manifest: &ConsensusManifest,
    prepared: &readiness::PreparedReadiness,
    saved: &BTreeMap<u32, String>,
    budget: &mut Budget<'_, impl NodeRpc, impl LightwalletRpc, impl Clock>,
) -> Observation<LightwalletReadinessReport> {
    let remaining = budget.remaining()?;
    let node_report = prepared.check(
        &CountingNode {
            node: budget.node,
            calls: &budget.calls,
        },
        budget.clock,
        &readiness::ReadinessOptions {
            role: NodeRole::Follower,
            request_timeout: budget.options.request_timeout.min(remaining),
            deadline: remaining,
            poll_interval: budget.options.poll_interval.min(remaining),
        },
        budget.clock.elapsed(),
    )?;
    budget.remaining()?;
    let node_tip = node_report.tip;
    let info = budget.wallet(|wallet, timeout| wallet.info(timeout))?;
    ensure_fatal(
        info.chain_name == "test",
        "light-wallet service is not Testnet",
    )?;
    ensure_fatal(
        info.lightwallet_protocol_version == PROTOCOL_VERSION,
        "unsupported light-wallet protocol: Ironwood diagnostic requires v0.5.0",
    )?;
    ensure_fatal(
        info.sapling_activation_height == u64::from(manifest.upgrades.sapling),
        "light-wallet Sapling activation does not match manifest",
    )?;
    let node_info = budget.node("getblockchaininfo", json!([]))?;
    if node_info["blocks"].as_u64() != Some(node_tip.height.into())
        || projection::display_hash(&node_info["bestblockhash"], "node tip")? != node_tip.hash
    {
        return Err(ObservationError::Wait(
            "node or light-wallet reported tip changed".into(),
        ));
    }
    let info_height = projection::height(info.block_height)?;
    ensure_fatal(
        info.consensus_branch_id
            .eq_ignore_ascii_case(readiness::branch_at(manifest, info_height)),
        "light-wallet consensus branch does not match checked node rules",
    )?;
    let latest = budget.wallet(|wallet, timeout| wallet.latest_block(timeout))?;
    let height = projection::height(latest.height)?;
    if height != info_height {
        return Err(ObservationError::Wait(
            "light-wallet tip changed between metadata and block requests".into(),
        ));
    }
    if height > node_tip.height {
        return Err(ObservationError::Wait(
            "light-wallet tip advanced beyond observed node tip".into(),
        ));
    }
    let lag = node_tip.height - height;
    if lag > budget.options.max_lag_blocks
        || height < *saved.last_key_value().unwrap().0
        || height < manifest.upgrades.nu6_3
        || height == 0
    {
        return Err(ObservationError::Wait(
            "light-wallet history is behind the required Ironwood checkpoint".into(),
        ));
    }
    let hash = projection::wire_hash(&latest.hash, "light-wallet tip")?;
    let expected_hash = projection::display_hash(
        &budget.node("getblockhash", json!([height]))?,
        "node checkpoint",
    )?;
    ensure_fatal(
        hash == expected_hash,
        "light-wallet tip hash differs from node best chain",
    )?;
    let mut heights: BTreeSet<u32> = saved.keys().copied().collect();
    heights.extend([height - 1, height]);
    let mut ranges = Vec::<(u32, u32)>::new();
    for checked in &heights {
        if let Some((_, end)) = ranges.last_mut().filter(|(_, end)| *end + 1 == *checked) {
            *end = *checked;
        } else {
            ranges.push((*checked, *checked));
        }
    }
    let mut checked_hashes = BTreeMap::new();
    let mut ironwood_actions = 0;
    for (first, last) in ranges {
        let blocks = budget.wallet(|wallet, timeout| wallet.block_range(first, last, timeout))?;
        ensure_fatal(
            blocks.len() == (last - first + 1) as usize,
            "compact stream count differs from requested range",
        )?;
        for (height, block) in (first..=last).zip(blocks) {
            let expected = projection::display_hash(
                &budget.node("getblockhash", json!([height]))?,
                "node compact checkpoint",
            )?;
            if let Some(saved_hash) = saved.get(&height) {
                ensure_fatal(
                    expected == *saved_hash,
                    "saved node history changed during light-wallet observation",
                )?;
            }
            ensure_fatal(
                block.height == u64::from(height)
                    && projection::wire_hash(&block.hash, "compact block")? == expected,
                "compact stream height or hash differs from node best chain",
            )?;
            let node_block = budget.node("getblock", json!([expected, 2]))?;
            ironwood_actions += projection::check_compact(&block, &node_block)?;
            checked_hashes.insert(height, expected);
        }
    }
    let node_tree = budget.node("z_gettreestate", json!([hash]))?;
    let tree = budget.wallet(|wallet, timeout| wallet.tree_state(height, timeout))?;
    projection::check_tree(&tree, &node_tree, height, &hash)?;
    // The node must still have every sampled block in its best chain. We also
    // require its tip to stay fixed, so lag cannot become stale during a slow stream.
    for (height, expected) in &checked_hashes {
        ensure_fatal(
            projection::display_hash(
                &budget.node("getblockhash", json!([height]))?,
                "node checkpoint recheck",
            )? == *expected,
            "node history changed during light-wallet observation",
        )?;
    }
    let timeout = budget.timeout()?;
    let rules_result = prepared.verify_rules(budget.node, timeout);
    budget.remaining()?;
    // A lost final reply must restart the whole observation, just like other
    // node transport failures. Authentication and actual rule mismatches remain
    // fatal; the helper preserves typed RPC errors through its eyre context.
    if let Err(error) = rules_result {
        if matches!(
            error.downcast_ref::<RpcError>(),
            Some(RpcError::Transport(_))
        ) {
            return Err(ObservationError::Wait(
                "waiting for node getchainrules".into(),
            ));
        }
        return Err(error.into());
    }
    let final_info = budget.node("getblockchaininfo", json!([]))?;
    if final_info["blocks"].as_u64() != Some(node_tip.height.into())
        || projection::display_hash(&final_info["bestblockhash"], "node final tip")?
            != node_tip.hash
    {
        return Err(ObservationError::Wait(
            "node tip advanced during light-wallet observation".into(),
        ));
    }
    Ok(LightwalletReadinessReport {
        api_version: API_VERSION.into(),
        consensus_fingerprint: node_report.consensus_fingerprint,
        protocol_version: PROTOCOL_VERSION.into(),
        node_tip,
        lightwallet_tip: readiness::ObservedTip { height, hash },
        lag_blocks: lag,
        checked_compact_blocks: heights.len(),
        checked_ironwood_actions: ironwood_actions,
        ironwood_tree_verified: true,
        compact_data_verified: true,
        payment_qualification: "pending".into(),
        launch_ready: false,
        attempts: 0,
        elapsed_millis: 0,
    })
}
fn ensure_fatal(condition: bool, message: &str) -> Result<()> {
    ensure!(condition, "{message}");
    Ok(())
}
