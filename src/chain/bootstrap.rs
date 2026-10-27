//! Bounded saved-history loading through the selected node's verifier.
//!
//! This first recipe requires a checkpoint at every saved height. It never
//! rewrites checkpoint trust, writes a database, generates blocks, or treats a
//! successful submit response as proof that a block reached the best chain.

use super::artifacts::{snapshot_bundle, VerifiedBlock};
use super::manifest::ConsensusManifest;
use super::readiness::PreparedRules;
use super::rpc::{Clock, NodeRpc, RpcError};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

pub const API_VERSION: &str = "zdn-seed-bootstrap/v1alpha1";
// P2P checkpoint verification can finish before the corresponding state commit
// becomes observable. Reconciliation reads never authorize another submission.
const MAX_OBSERVATION_RETRIES: usize = 3;

#[derive(Clone, Debug)]
pub struct BootstrapOptions {
    /// An external operator/controller precondition, not a distributed lock.
    pub producer_stopped: bool,
    pub request_timeout: Duration,
    pub deadline: Duration,
    pub retry_delay: Duration,
    pub max_submit_attempts: u32,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            producer_stopped: false,
            request_timeout: Duration::from_secs(30),
            deadline: Duration::from_secs(300),
            retry_delay: Duration::from_secs(1),
            max_submit_attempts: 3,
        }
    }
}

impl BootstrapOptions {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.bootstrap.options.validate")
    )]
    fn validate(&self) -> Result<()> {
        ensure!(
            self.producer_stopped,
            "saved-history loading requires an explicitly stopped external producer"
        );
        ensure!(
            !self.request_timeout.is_zero() && self.request_timeout <= Duration::from_secs(60),
            "bootstrap request timeout must be positive and at most 60 seconds"
        );
        ensure!(
            self.deadline >= self.request_timeout && self.deadline <= Duration::from_secs(3600),
            "bootstrap deadline must cover a request and be at most one hour"
        );
        ensure!(
            !self.retry_delay.is_zero() && self.retry_delay <= Duration::from_secs(30),
            "bootstrap retry delay must be positive and at most 30 seconds"
        );
        ensure!(
            (1..=10).contains(&self.max_submit_attempts),
            "bootstrap submit attempts must be between 1 and 10 per block"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapReport {
    pub api_version: String,
    pub consensus_fingerprint: String,
    pub bundle_sha256: String,
    pub block_count: usize,
    pub already_present_blocks: usize,
    pub submitted_blocks: usize,
    pub submission_attempts: u32,
    pub seed_tip_height: u32,
    pub seed_tip_hash: String,
    pub byte_integrity_verified: bool,
    pub block_decoding_verified: bool,
    pub effective_rules_verified: bool,
    pub seed_history_present: bool,
    pub checkpoint_acceptance: bool,
    pub full_semantic_validation: bool,
    pub qualification: String,
    pub launch_ready: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlockInspection {
    api_version: String,
    height: u32,
    hash: String,
    previous_hash: String,
    bytes_length: u64,
}

/// Inspect every saved block and current best-chain history before the first
/// mutation. Reconcile uncertain submissions against actual best-chain hashes.
///
/// The caller must keep all producers stopped throughout this operation. This
/// detects observed incompatible tips but does not replace exclusive controller
/// ownership. A later invocation always inspects state again; no local progress
/// receipt can authorize skipping a chain check.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.bootstrap.load_seed_history")
)]
pub fn load_seed_history(
    manifest: &ConsensusManifest,
    bundle: &Path,
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &BootstrapOptions,
) -> Result<BootstrapReport> {
    options.validate()?;
    let budget = Budget {
        clock,
        started: clock.elapsed(),
        options,
    };
    // snapshot_bundle bounds input allocation before normalization and captures
    // exactly the bytes it hashes. Never reopen the bundle after this point.
    let snapshot = snapshot_bundle(manifest, bundle)?;
    let manifest = manifest.normalized()?;
    check_recipe(&manifest, &snapshot.blocks)?;
    let rules = PreparedRules::new(&manifest).context("verify node rules before bootstrap")?;
    rules
        .verify(rpc, budget.timeout()?)
        .context("verify node rules before bootstrap")?;
    inspect_blocks(&snapshot.blocks, rpc, &budget)?;
    let initial = observe_history(&snapshot.blocks, rpc, &budget)?;
    let mut submission_attempts = 0;
    let mut submitted_blocks = 0;
    for block in &snapshot.blocks[initial.present..] {
        let previous = block
            .identity
            .height
            .checked_sub(1)
            .map(|height| snapshot.blocks[height as usize].identity.hash.as_str());
        let attempts = load_block(block, previous, rpc, &budget)?;
        submission_attempts += attempts;
        submitted_blocks += usize::from(attempts > 0);
    }
    rules
        .verify(rpc, budget.timeout()?)
        .context("verify node rules after bootstrap")?;
    let final_state = observe_history(&snapshot.blocks, rpc, &budget)?;
    ensure!(
        final_state.present == snapshot.blocks.len(),
        "saved history disappeared before final bootstrap verification"
    );
    let seed_tip = &snapshot
        .blocks
        .last()
        .expect("bundle contains genesis")
        .identity;
    let expected_tip = if initial.present == snapshot.blocks.len() {
        initial.tip.as_deref()
    } else {
        Some(seed_tip.hash.as_str())
    };
    ensure!(
        final_state.tip.as_deref() == expected_tip,
        "best-chain tip moved unexpectedly during bootstrap; keep the producer stopped and inspect state"
    );
    budget.timeout()?;
    Ok(BootstrapReport {
        api_version: API_VERSION.into(),
        consensus_fingerprint: snapshot.report.consensus_fingerprint,
        bundle_sha256: snapshot.report.bundle_sha256,
        block_count: snapshot.blocks.len(),
        already_present_blocks: initial.present,
        submitted_blocks,
        submission_attempts,
        seed_tip_height: seed_tip.height,
        seed_tip_hash: seed_tip.hash.clone(),
        byte_integrity_verified: true,
        block_decoding_verified: true,
        effective_rules_verified: true,
        seed_history_present: true,
        checkpoint_acceptance: true,
        full_semantic_validation: false,
        qualification: "pending".into(),
        launch_ready: false,
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.bootstrap.check_recipe")
)]
fn check_recipe(manifest: &ConsensusManifest, blocks: &[VerifiedBlock]) -> Result<()> {
    ensure!(
        manifest.checkpoints.len() == blocks.len(),
        "serial bootstrap requires a checkpoint at every saved height and complete saved history through the final checkpoint"
    );
    for (index, (block, checkpoint)) in blocks.iter().zip(&manifest.checkpoints).enumerate() {
        ensure!(
            block.identity.height as usize == index
                && checkpoint.height == block.identity.height
                && checkpoint.hash == block.identity.hash,
            "serial bootstrap requires contiguous saved blocks and a matching checkpoint at every height"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.bootstrap.inspect_blocks")
)]
fn inspect_blocks(
    blocks: &[VerifiedBlock],
    rpc: &impl NodeRpc,
    budget: &Budget<'_, impl Clock>,
) -> Result<()> {
    let mut previous = "00".repeat(32);
    for block in blocks {
        let response = rpc
            .call(
                "inspectchainblock",
                json!([hex::encode(&block.bytes)]),
                budget.timeout()?,
            )
            .context("node block inspection failed before any submission")?;
        let decoded: BlockInspection =
            serde_json::from_value(response).context("invalid node block-inspection response")?;
        ensure!(
            decoded.api_version == "zakura-block-inspection/v1",
            "unsupported node block-inspection version"
        );
        ensure!(
            decoded.height == block.identity.height
                && normalize_hash(&decoded.hash)? == block.identity.hash
                && decoded.bytes_length == block.identity.bytes_length,
            "node-decoded block identity differs from the saved manifest at height {}",
            block.identity.height
        );
        ensure!(
            normalize_hash(&decoded.previous_hash)? == previous,
            "node-decoded saved block ancestry differs at height {}",
            block.identity.height
        );
        previous.clone_from(&block.identity.hash);
    }
    Ok(())
}

struct ObservedHistory {
    present: usize,
    tip: Option<String>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.bootstrap.observe_history")
)]
fn observe_history(
    blocks: &[VerifiedBlock],
    rpc: &impl NodeRpc,
    budget: &Budget<'_, impl Clock>,
) -> Result<ObservedHistory> {
    for observation in 0..=MAX_OBSERVATION_RETRIES {
        let mut present = 0;
        let mut missing = false;
        let mut gap = false;
        for block in blocks {
            match observe_hash(rpc, i64::from(block.identity.height), budget)? {
                Some(actual) => {
                    ensure!(
                        actual == block.identity.hash,
                        "best-chain hash mismatch at saved height {}; refusing to reset state",
                        block.identity.height
                    );
                    if missing {
                        gap = true;
                    } else {
                        present += 1;
                    }
                }
                None => missing = true,
            }
        }
        let tip = observe_hash(rpc, -1, budget)?;
        if present < blocks.len() {
            let expected = present
                .checked_sub(1)
                .map(|index| blocks[index].identity.hash.as_str());
            // Separate height and tip RPCs are not an atomic snapshot. A peer
            // can commit a saved block between them. A known saved tip permits
            // a bounded fresh scan, never acceptance of an unobserved prefix.
            if observation < MAX_OBSERVATION_RETRIES
                && blocks[present..]
                    .iter()
                    .any(|block| tip.as_deref() == Some(block.identity.hash.as_str()))
            {
                budget.wait()?;
                continue;
            }
            ensure!(!gap, "best-chain saved history has a missing prefix");
            ensure!(
                tip.as_deref() == expected,
                "best-chain tip does not match the observed saved prefix; stop producers and inspect state"
            );
        } else {
            ensure!(
                tip.is_some(),
                "best-chain tip disappeared during observation"
            );
        }
        return Ok(ObservedHistory { present, tip });
    }
    unreachable!("the last observation either returns or rejects inconsistent history")
}

fn load_block(
    block: &VerifiedBlock,
    previous: Option<&str>,
    rpc: &impl NodeRpc,
    budget: &Budget<'_, impl Clock>,
) -> Result<u32> {
    let mut attempts = 0;
    loop {
        // Re-observe before every retry, including one last observation after
        // the final attempt's delay. A detached commit can finish meanwhile.
        if observe_expected(block, previous, rpc, budget)? {
            return Ok(attempts);
        }
        ensure!(
            attempts < budget.options.max_submit_attempts,
            "saved block {} was not observed on the best chain after {} submission attempts; retry by re-observing state",
            block.identity.height,
            attempts
        );
        attempts += 1;
        let submitted = rpc.call(
            "submitblock",
            json!([hex::encode(&block.bytes)]),
            budget.timeout()?,
        );
        // Even null can mean side-chain acceptance. An error or malformed reply
        // can arrive after a successful commit. State is the only success test.
        if observe_expected(block, previous, rpc, budget)? {
            return Ok(attempts);
        }
        match submitted {
            Ok(Value::Null) => {}
            Ok(Value::String(status))
                if matches!(status.as_str(), "duplicate" | "inconclusive" | "duplicate-inconclusive") => {}
            Err(RpcError::Transport(_)) => {}
            Ok(Value::String(status)) if status == "rejected" => {
                // Zakura can reject the RPC's duplicate checkpoint while a
                // peer's verified copy is still committing. Observe only: a
                // rejection never authorizes submitting these bytes again.
                for _ in 0..MAX_OBSERVATION_RETRIES {
                    budget.wait()?;
                    if observe_expected(block, previous, rpc, budget)? {
                        return Ok(attempts);
                    }
                }
                bail!("node rejected saved block {}; bounded reconciliation did not establish best-chain presence", block.identity.height);
            }
            Ok(_) => bail!(
                "node rejected saved block {} or returned an unsupported submit result; best-chain presence was not established",
                block.identity.height
            ),
            Err(error) => return Err(error).context("submit failed and saved block is absent from the best chain"),
        }
        budget.wait()?;
    }
}

fn observe_expected(
    block: &VerifiedBlock,
    previous: Option<&str>,
    rpc: &impl NodeRpc,
    budget: &Budget<'_, impl Clock>,
) -> Result<bool> {
    for observation in 0..=MAX_OBSERVATION_RETRIES {
        let actual = observe_hash(rpc, i64::from(block.identity.height), budget)?;
        if let Some(actual) = &actual {
            ensure!(
                actual == &block.identity.hash,
                "best-chain hash mismatch at saved height {}; refusing to reset state",
                block.identity.height
            );
        }
        if let Some(previous) = previous {
            ensure!(
                observe_hash(rpc, i64::from(block.identity.height) - 1, budget)?.as_deref()
                    == Some(previous),
                "saved block parent changed during bootstrap"
            );
        }
        let tip = observe_hash(rpc, -1, budget)?;
        if actual.is_none()
            && tip.as_deref() == Some(block.identity.hash.as_str())
            && observation < MAX_OBSERVATION_RETRIES
        {
            budget.wait()?;
            continue;
        }
        let expected_tip = actual.as_deref().or(previous);
        ensure!(
            tip.as_deref() == expected_tip,
            "best-chain tip moved unexpectedly during bootstrap; keep the producer stopped and inspect state"
        );
        return Ok(actual.is_some());
    }
    unreachable!("the last observation either returns or rejects an inconsistent tip")
}

fn observe_hash(
    rpc: &impl NodeRpc,
    height: i64,
    budget: &Budget<'_, impl Clock>,
) -> Result<Option<String>> {
    match rpc.call("getblockhash", json!([height]), budget.timeout()?) {
        Ok(Value::String(hash)) => Ok(Some(normalize_hash(&hash)?)),
        Ok(_) => bail!("node getblockhash returned an invalid hash response"),
        Err(RpcError::Remote { code, message })
            if (code == -1 && message == "No blocks in state")
                || (height >= 0
                    && matches!(
                        (code, message.as_str()),
                        (-8, "Block not found")
                            | (-32602, "Provided index is greater than the current tip")
                    )) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("cannot establish actual best-chain block presence"),
    }
}

fn normalize_hash(hash: &str) -> Result<String> {
    ensure!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "node returned an invalid block hash"
    );
    Ok(hash.to_ascii_lowercase())
}

struct Budget<'a, C> {
    clock: &'a C,
    started: Duration,
    options: &'a BootstrapOptions,
}

impl<C: Clock> Budget<'_, C> {
    fn remaining(&self) -> Result<Duration> {
        let elapsed = self
            .clock
            .elapsed()
            .checked_sub(self.started)
            .context("bootstrap clock moved backwards")?;
        let remaining = self
            .options
            .deadline
            .checked_sub(elapsed)
            .context("bootstrap deadline expired; retry by re-observing state")?;
        ensure!(
            !remaining.is_zero(),
            "bootstrap deadline expired; retry by re-observing state"
        );
        Ok(remaining)
    }

    fn timeout(&self) -> Result<Duration> {
        Ok(self.options.request_timeout.min(self.remaining()?))
    }

    fn wait(&self) -> Result<()> {
        self.clock
            .sleep(self.options.retry_delay.min(self.remaining()?));
        self.remaining()?;
        Ok(())
    }
}
