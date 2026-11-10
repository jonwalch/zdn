//! Bounded observations of parsed rules and actual best-chain history.
//!
//! This adapter compares the node-owned `getchainrules` projection, rather than
//! treating a copied manifest digest or an open RPC port as proof of identity.
//! Existing RPC mappings follow Zakura's `methods.rs`, `network_upgrade.rs`, and
//! Testnet `ParametersBuilder`. Same-height upgrades collapse in builder order.
//! A matching template is a mining observation, not payment qualification: a
//! non-long-poll template can omit transactions while the mempool is inactive.
//!
//! Stock Zakura releases have no `getchainrules`. For ordinary manifests, a
//! JSON-RPC `-32601` reply selects the narrower standard-RPC observation: the
//! node's parsed Testnet kind, activation heights and branch IDs from
//! `getblockchaininfo`, and its configured or stored genesis. Network magic,
//! checkpoints, subsidy, difficulty and the Orchard rule remain unobserved, so
//! such reports keep `effectiveRulesVerified` false. External compiled
//! contracts never fall back.

use super::{
    manifest::{ConsensusManifest, ProofOfWork},
    node_config::{render_network_config, RenderOptions},
    rpc::{Clock, NodeRpc, RpcError},
    runtime_config::NodeRole,
};
use eyre::{bail, ensure, eyre, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};

pub const API_VERSION: &str = "zdn-chain-readiness/v1alpha1";
const MAX_HISTORY: usize = 4096;
const MAX_RPC_CALLS: usize = 32_768;
const MAX_ATTEMPTS: u32 = 256;
const MAX_RULE_RESPONSE: usize = 2 * 1024 * 1024;

/// Bound both individual requests and the complete observation. The deadline is
/// relative to entry, not to when the supplied clock was constructed.
#[derive(Clone, Debug)]
pub struct ReadinessOptions {
    pub role: NodeRole,
    pub request_timeout: Duration,
    pub deadline: Duration,
    pub poll_interval: Duration,
}

impl Default for ReadinessOptions {
    fn default() -> Self {
        Self {
            role: NodeRole::Follower,
            request_timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(120),
            poll_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedTip {
    pub height: u32,
    pub hash: String,
}

/// The node interface that established a rule observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulesEvidence {
    /// The complete parsed-rule projection from `getchainrules`.
    ChainRules,
    /// Only `getblockchaininfo` and best-chain genesis, for nodes without
    /// `getchainrules`.
    StandardRpc,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessReport {
    pub api_version: String,
    pub consensus_fingerprint: String,
    pub role: NodeRole,
    /// True only when every `getchainrules` field matched the manifest.
    pub effective_rules_verified: bool,
    pub rules_evidence: RulesEvidence,
    pub history_present: bool,
    pub checked_history: usize,
    pub tip: ObservedTip,
    pub mining_ready: bool,
    pub payment_qualification: String,
    pub launch_ready: bool,
    pub attempts: u32,
    pub elapsed_millis: u64,
}

/// Compare every covered parsed rule, without a state or mutation RPC. Unknown
/// schema fields, omitted null-valued fields, and unsupported profiles fail
/// closed. The transport must honor the supplied timeout, which bounds each
/// request; a node without `getchainrules` needs up to three requests.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.verify_rules")
)]
pub fn verify_rules(
    manifest: &ConsensusManifest,
    rpc: &impl NodeRpc,
    timeout: Duration,
) -> Result<RulesEvidence> {
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(60),
        "rule request timeout must be positive and at most 60 seconds"
    );
    PreparedRules::new(manifest)?.verify(rpc, || Ok(timeout))
}

/// Operation-local immutable expectations, never a cached node observation.
/// Preparation retains the renderer's full compatibility and size checks.
pub(crate) struct PreparedRules {
    expected: Value,
    exact: bool,
    /// The standard-RPC projection; absent where no fallback is allowed.
    standard: Option<StandardRules>,
}

struct StandardRules {
    genesis: String,
    upgrades: Vec<(String, u32, String)>,
}

impl PreparedRules {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.readiness.prepared_rules.new")
    )]
    pub(crate) fn new(manifest: &ConsensusManifest) -> Result<Self> {
        let expected = expected_rules(manifest)?;
        let manifest = manifest.normalized()?;
        Ok(Self {
            expected,
            exact: false,
            standard: Some(StandardRules {
                genesis: manifest.genesis.hash.clone(),
                upgrades: upgrade_branches(&manifest),
            }),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn external(compiled: &crate::public_chain_adapter::contract::Compiled) -> Self {
        Self {
            expected: compiled.expected_rules.clone(),
            exact: true,
            standard: None,
        }
    }

    /// Only an explicit "method not found" selects the standard projection;
    /// every other failure keeps its original meaning.
    pub(crate) fn falls_back(&self, error: &RpcError) -> bool {
        self.standard.is_some() && matches!(error, RpcError::Remote { code: -32601, .. })
    }

    fn compare(&self, actual: Value) -> Result<()> {
        if self.exact {
            ensure!(
                serde_json::to_vec(&actual)?.len() <= MAX_RULE_RESPONSE,
                "node effective-rule response exceeds 2 MiB"
            );
            ensure!(
                actual == self.expected,
                "node effective rules differ from compiled external rules"
            );
            Ok(())
        } else {
            compare_rules(&self.expected, actual)
        }
    }

    /// `timeout` supplies each request's bound, so callers can cap every
    /// request by their remaining deadline.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.readiness.prepared_rules.verify")
    )]
    pub(crate) fn verify(
        &self,
        rpc: &impl NodeRpc,
        timeout: impl Fn() -> Result<Duration>,
    ) -> Result<RulesEvidence> {
        let timeout = || {
            let timeout = timeout()?;
            ensure!(
                !timeout.is_zero() && timeout <= Duration::from_secs(60),
                "rule request timeout must be positive and at most 60 seconds"
            );
            Ok(timeout)
        };
        let actual = match rpc.call("getchainrules", json!([]), timeout()?) {
            Err(error) if self.falls_back(&error) => {
                let standard = self
                    .standard
                    .as_ref()
                    .expect("fallback requires a projection");
                verify_standard(standard, rpc, timeout)?;
                return Ok(RulesEvidence::StandardRpc);
            }
            result => result.context("read node effective rules")?,
        };
        self.compare(actual)?;
        Ok(RulesEvidence::ChainRules)
    }
}

/// With no stored block, Zakura reports its configured genesis as the tip;
/// otherwise height zero is the stored genesis, which must match its config.
fn verify_standard(
    standard: &StandardRules,
    rpc: &impl NodeRpc,
    timeout: impl Fn() -> Result<Duration>,
) -> Result<()> {
    let info = rpc
        .call("getblockchaininfo", json!([]), timeout()?)
        .context("read node chain information")?;
    let tip = ObservedTip {
        height: read_height(&info["blocks"], "blockchain-info height")?,
        hash: read_hash(&info["bestblockhash"], "blockchain-info hash")?,
    };
    check_chain_info(&standard.upgrades, &tip, info)?;
    let genesis = if tip.height == 0 {
        tip.hash
    } else {
        read_hash(
            &rpc.call("getblockhash", json!([0]), timeout()?)
                .context("read node genesis")?,
            "genesis hash",
        )?
    };
    ensure!(
        genesis == standard.genesis,
        "node genesis does not match the supported consensus manifest"
    );
    Ok(())
}

/// Observe a single node. No block is submitted or generated. A report is a
/// bounded observation, not a lock against a later reorg, restart, or config
/// change. Controllers must recheck before starting production.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.check_readiness")
)]
pub fn check_readiness(
    manifest: &ConsensusManifest,
    rpc: &impl NodeRpc,
    clock: &impl Clock,
    options: &ReadinessOptions,
) -> Result<ReadinessReport> {
    let start = clock.elapsed();
    validate_options(options)?;
    PreparedReadiness::new(manifest)?.check(rpc, clock, options, start)
}

/// Immutable manifest-derived expectations for one controller operation. Every
/// check still observes rules, history, tip and (for producers) a fresh template.
pub(crate) struct PreparedReadiness {
    upgrades: Vec<(String, u32, String)>,
    proof_of_work_disabled: bool,
    rules: PreparedRules,
    history: BTreeMap<u32, String>,
    fingerprint: String,
}

impl PreparedReadiness {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.readiness.prepared_readiness.new")
    )]
    pub(crate) fn new(manifest: &ConsensusManifest) -> Result<Self> {
        let rules = PreparedRules::new(manifest)?;
        let manifest = manifest.normalized()?;
        let history = required_history(&manifest)?;
        let fingerprint = manifest.fingerprint()?;
        Ok(Self {
            upgrades: upgrade_branches(&manifest),
            proof_of_work_disabled: manifest.difficulty.proof_of_work == ProofOfWork::Disabled,
            rules,
            history,
            fingerprint,
        })
    }

    /// Only call with an authenticated, independently validated compile result.
    /// No ordinary manifest or placeholder consensus fields are manufactured.
    #[cfg(target_os = "linux")]
    pub(crate) fn external(compiled: &crate::public_chain_adapter::contract::Compiled) -> Self {
        Self {
            upgrades: compiled
                .upgrades
                .iter()
                .map(|u| (u.name.clone(), u.activation_height, u.branch_id.clone()))
                .collect(),
            proof_of_work_disabled: compiled.expected_rules["rules"]["difficulty"]["proofOfWork"]
                == "disabled",
            rules: PreparedRules::external(compiled),
            history: compiled
                .seed_blocks
                .iter()
                .map(|b| (b.height, b.hash.clone()))
                .collect(),
            fingerprint: compiled.native_fingerprint.clone(),
        }
    }

    pub(crate) fn verify_rules(
        &self,
        rpc: &impl NodeRpc,
        timeout: impl Fn() -> Result<Duration>,
    ) -> Result<RulesEvidence> {
        self.rules.verify(rpc, timeout)
    }

    /// `start` precedes preparation on the first check, so that preparation
    /// cannot extend the observation deadline. Later checks use a fresh start.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.readiness.prepared_readiness.check")
    )]
    pub(crate) fn check(
        &self,
        rpc: &impl NodeRpc,
        clock: &impl Clock,
        options: &ReadinessOptions,
        start: Duration,
    ) -> Result<ReadinessReport> {
        validate_options(options)?;
        ensure!(
            options.role != NodeRole::Producer || self.proof_of_work_disabled,
            "producer readiness requires disabled proof of work"
        );
        let mut budget = Budget {
            rpc,
            clock,
            options,
            start,
            calls: 0,
        };
        let mut last_wait = String::from("node has not been observed");
        for attempt in 1..=MAX_ATTEMPTS {
            budget.remaining().with_context(|| last_wait.clone())?;
            match observe(&self.upgrades, &self.rules, &self.history, &mut budget) {
                Ok((tip, rules_evidence)) => {
                    return Ok(ReadinessReport {
                        api_version: API_VERSION.into(),
                        consensus_fingerprint: self.fingerprint.clone(),
                        role: options.role,
                        effective_rules_verified: rules_evidence == RulesEvidence::ChainRules,
                        rules_evidence,
                        history_present: true,
                        checked_history: self.history.len(),
                        tip,
                        mining_ready: options.role == NodeRole::Producer,
                        payment_qualification: "pending".into(),
                        launch_ready: false,
                        attempts: attempt,
                        elapsed_millis: budget.elapsed().as_millis().try_into()?,
                    });
                }
                Err(ObservationError::Fatal(error)) => return Err(error),
                Err(ObservationError::Wait(reason)) => last_wait = reason,
            }
            let remaining = budget.remaining().with_context(|| last_wait.clone())?;
            clock.sleep(options.poll_interval.min(remaining));
        }
        bail!("readiness observation attempt limit reached: {last_wait}")
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.validate_options")
)]
fn validate_options(options: &ReadinessOptions) -> Result<()> {
    ensure!(
        !options.deadline.is_zero() && options.deadline <= Duration::from_secs(3600),
        "readiness deadline must be positive and at most 3600 seconds"
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
    Ok(())
}

/// This is a wire projection, not a consensus implementation. The renderer's
/// coverage checks reject fields the configured-Testnet adapter cannot express.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.expected_rules")
)]
fn expected_rules(manifest: &ConsensusManifest) -> Result<Value> {
    render_network_config(manifest, &RenderOptions::default())?;
    let manifest = manifest.normalized()?;
    let mut subsidy = serde_json::to_value(&manifest.subsidy)?;
    subsidy["slowStartShift"] = json!(manifest.subsidy.slow_start_interval / 2);
    subsidy["postBlossomHalvingInterval"] =
        json!(manifest.subsidy.pre_blossom_halving_interval * 2);
    // The manifest's receiver-key ordering and the diagnostic both use the
    // receiver's wire name. Address-period lists retain their original order.
    for stream in subsidy["fundingStreams"].as_array_mut().unwrap() {
        stream["recipients"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["receiver"].as_str().cmp(&b["receiver"].as_str()));
    }
    let activation_heights: Vec<_> = effective_upgrades(&manifest)
        .into_iter()
        .map(|(height, upgrade)| json!({"height": height, "upgrade": upgrade}))
        .collect();
    Ok(json!({
        "apiVersion": "zakura-chain-rules/v1",
        "ruleset": manifest.ruleset,
        "networkKind": "custom-testnet",
        "rules": {
            "networkMagic": manifest.network_magic,
            "genesisHash": manifest.genesis.hash,
            "checkpoints": manifest.checkpoints,
            "activationHeights": activation_heights,
            "subsidy": subsidy,
            "difficulty": manifest.difficulty,
            "temporaryOrchardDisablingHeight": manifest.temporary_orchard_disabling_height,
            "experimental": {"pq": null, "sqisign": null}
        }
    }))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.compare_rules")
)]
fn compare_rules(expected: &Value, mut actual: Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(&actual)?.len() <= MAX_RULE_RESPONSE,
        "node effective-rule response exceeds 2 MiB"
    );
    // Normalize only the fields defined as hexadecimal, never arbitrary text.
    // Structural comparison afterwards rejects extras, missing fields, numeric
    // type changes, ordering changes, and unsupported experimental settings.
    for pointer in [
        "/rules/networkMagic",
        "/rules/genesisHash",
        "/rules/difficulty/targetDifficultyLimitCompact",
    ] {
        lowercase_at(&mut actual, pointer);
    }
    if let Some(entries) = actual
        .pointer_mut("/rules/checkpoints")
        .and_then(Value::as_array_mut)
    {
        for entry in entries {
            lowercase_at(entry, "/hash");
        }
    }
    if let Some(streams) = actual
        .pointer_mut("/rules/subsidy/fundingStreams")
        .and_then(Value::as_array_mut)
    {
        for stream in streams {
            if let Some(recipients) = stream
                .pointer_mut("/recipients")
                .and_then(Value::as_array_mut)
            {
                for recipient in recipients {
                    if let Some(hashes) = recipient
                        .pointer_mut("/scriptHashes")
                        .and_then(Value::as_array_mut)
                    {
                        for hash in hashes {
                            if let Some(text) = hash.as_str() {
                                *hash = Value::String(text.to_ascii_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(outputs) = actual
        .pointer_mut("/rules/subsidy/lockboxDisbursements")
        .and_then(Value::as_array_mut)
    {
        for output in outputs {
            lowercase_at(output, "/scriptHash");
        }
    }
    ensure!(
        &actual == expected,
        "node effective rules do not match the supported consensus manifest"
    );
    Ok(())
}

fn lowercase_at(value: &mut Value, pointer: &str) {
    if let Some(field) = value.pointer_mut(pointer) {
        if let Some(text) = field.as_str() {
            *field = Value::String(text.to_ascii_lowercase());
        }
    }
}

fn declared_upgrades(manifest: &ConsensusManifest) -> Vec<(&'static str, u32)> {
    let u = &manifest.upgrades;
    let mut upgrades = vec![
        ("Genesis", 0),
        ("BeforeOverwinter", u.before_overwinter),
        ("Overwinter", u.overwinter),
        ("Sapling", u.sapling),
        ("Blossom", u.blossom),
        ("Heartwood", u.heartwood),
        ("Canopy", u.canopy),
        ("NU5", u.nu5),
        ("NU6", u.nu6),
        ("NU6.1", u.nu6_1),
        ("NU6.2", u.nu6_2),
        ("NU6.3", u.nu6_3),
    ];
    if let Some(height) = u.nu7 {
        upgrades.push(("NU7", height));
    }
    upgrades
}

/// Declared upgrades with their branch IDs, as `getblockchaininfo` lists them.
fn upgrade_branches(manifest: &ConsensusManifest) -> Vec<(String, u32, String)> {
    declared_upgrades(manifest)
        .into_iter()
        .map(|(name, height)| (name.into(), height, branch_id(name).into()))
        .collect()
}

fn effective_upgrades(manifest: &ConsensusManifest) -> BTreeMap<u32, &'static str> {
    declared_upgrades(manifest)
        .into_iter()
        .map(|(name, height)| (height, name))
        .collect()
}

fn branch_id(upgrade: &str) -> &'static str {
    match upgrade {
        "Overwinter" => "5ba81b19",
        "Sapling" => "76b809bb",
        "Blossom" => "2bb40e60",
        "Heartwood" => "f5b9230b",
        "Canopy" => "e9ff75a6",
        "NU5" => "c2d6d0b4",
        "NU6" => "c8e71055",
        "NU6.1" => "4dec4df0",
        "NU6.2" => "5437f330",
        "NU6.3" => "37a5165b",
        "NU7" => "77190ad9",
        _ => "00000000",
    }
}

pub(crate) fn branch_at(manifest: &ConsensusManifest, height: u32) -> &'static str {
    branch_id(
        effective_upgrades(manifest)
            .range(..=height)
            .next_back()
            .expect("genesis is always present")
            .1,
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.readiness.required_history")
)]
fn required_history(manifest: &ConsensusManifest) -> Result<BTreeMap<u32, String>> {
    ensure!(
        manifest.seed_blocks.len() < MAX_HISTORY && manifest.checkpoints.len() <= MAX_HISTORY,
        "readiness supports at most {MAX_HISTORY} saved or checkpoint identities"
    );
    let mut history = BTreeMap::from([(0, manifest.genesis.hash.clone())]);
    for (height, hash) in manifest
        .seed_blocks
        .iter()
        .map(|block| (block.height, &block.hash))
        .chain(manifest.checkpoints.iter().map(|c| (c.height, &c.hash)))
    {
        if let Some(previous) = history.insert(height, hash.clone()) {
            ensure!(
                previous == *hash,
                "conflicting history identity at {height}"
            );
        }
    }
    ensure!(
        history.len() <= MAX_HISTORY,
        "readiness supports at most {MAX_HISTORY} distinct history heights"
    );
    Ok(history)
}

struct Budget<'a, R, C> {
    rpc: &'a R,
    clock: &'a C,
    options: &'a ReadinessOptions,
    start: Duration,
    calls: usize,
}

impl<R: NodeRpc, C: Clock> Budget<'_, R, C> {
    fn elapsed(&self) -> Duration {
        self.clock.elapsed().saturating_sub(self.start)
    }

    fn remaining(&self) -> Result<Duration> {
        self.options
            .deadline
            .checked_sub(self.elapsed())
            .filter(|left| !left.is_zero())
            .context("readiness deadline expired")
    }

    fn call(&mut self, method: &str, params: Value) -> ObservationResult<Value> {
        let remaining = self.remaining()?;
        if self.calls >= MAX_RPC_CALLS {
            return Err(eyre!("readiness RPC call limit reached").into());
        }
        self.calls += 1;
        let result = self
            .rpc
            .call(method, params, self.options.request_timeout.min(remaining));
        // A transport that returns late must never produce a successful report.
        self.remaining()?;
        match result {
            Ok(value) => Ok(value),
            Err(RpcError::Transport(_)) => Err(ObservationError::Wait(format!(
                "waiting for {method}: transport unavailable"
            ))),
            Err(RpcError::Remote { code, message })
                if is_missing_state(method, code, &message)
                    || (method == "getblocktemplate" && code == -10) =>
            {
                Err(ObservationError::Wait(format!(
                    "waiting for {method}: node state is not ready"
                )))
            }
            Err(error) => Err(eyre!(error).wrap_err(format!("{method} failed")).into()),
        }
    }
}

fn is_missing_state(method: &str, code: i64, message: &str) -> bool {
    match method {
        "getbestblockheightandhash" => code == -1 && message == "No blocks in state",
        "getblockhash" => {
            (code == -1 && message == "No blocks in state")
                || (code == -8 && message == "Block not found")
                || (code == -32602 && message == "Provided index is greater than the current tip")
        }
        "getblocktemplate" => {
            (code == -1 && message == "no chain tip available yet")
                || (code == 0 && message == "template parent changed; retry")
        }
        _ => false,
    }
}

enum ObservationError {
    Wait(String),
    Fatal(eyre::Report),
}

type ObservationResult<T> = std::result::Result<T, ObservationError>;

impl From<eyre::Report> for ObservationError {
    fn from(value: eyre::Report) -> Self {
        Self::Fatal(value)
    }
}

fn observe(
    upgrades: &[(String, u32, String)],
    rules: &PreparedRules,
    history: &BTreeMap<u32, String>,
    budget: &mut Budget<'_, impl NodeRpc, impl Clock>,
) -> ObservationResult<(ObservedTip, RulesEvidence)> {
    let evidence = observe_rules(rules, budget)?;
    let tip = read_tip(budget)?;
    if tip.height < *history.last_key_value().unwrap().0 {
        return Err(ObservationError::Wait(
            "saved history is not present yet".into(),
        ));
    }
    check_history(history, budget)?;
    check_tip_hash(&tip, budget)?;
    let info = budget.call("getblockchaininfo", json!([]))?;
    if !check_chain_info(upgrades, &tip, info)? {
        return Err(ObservationError::Wait(
            "chain tip moved during observation".into(),
        ));
    }
    if budget.options.role == NodeRole::Producer {
        let template = budget.call("getblocktemplate", json!([{}]))?;
        let height = read_height(&template["height"], "template height")?;
        let parent = read_hash(&template["previousblockhash"], "template parent")?;
        if height != tip.height + 1 || parent != tip.hash {
            return Err(ObservationError::Wait(
                "fresh template does not match observed tip".into(),
            ));
        }
    }
    // Re-read the full declared history and tip after all other readiness work.
    // This never accepts a side-chain submit response in place of best-chain state.
    check_history(history, budget)?;
    check_tip_hash(&tip, budget)?;
    // A node that loses or gains the diagnostic mid-observation is not the
    // node that was checked first.
    if observe_rules(rules, budget)? != evidence {
        return Err(eyre!("node rule diagnostics changed during observation").into());
    }
    if read_tip(budget)? != tip {
        return Err(ObservationError::Wait(
            "chain tip moved during observation".into(),
        ));
    }
    Ok((tip, evidence))
}

/// Every observation also checks `getblockchaininfo` and genesis history,
/// which together cover the standard projection when the node has no
/// `getchainrules`.
fn observe_rules(
    rules: &PreparedRules,
    budget: &mut Budget<'_, impl NodeRpc, impl Clock>,
) -> ObservationResult<RulesEvidence> {
    match budget.call("getchainrules", json!([])) {
        Ok(actual) => {
            rules.compare(actual)?;
            Ok(RulesEvidence::ChainRules)
        }
        Err(ObservationError::Fatal(error))
            if error
                .downcast_ref::<RpcError>()
                .is_some_and(|error| rules.falls_back(error)) =>
        {
            Ok(RulesEvidence::StandardRpc)
        }
        Err(error) => Err(error),
    }
}

fn read_tip(budget: &mut Budget<'_, impl NodeRpc, impl Clock>) -> ObservationResult<ObservedTip> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawTip {
        height: u32,
        // This RPC's raw block::Hash serde uses INTERNAL byte order. Other RPC
        // hashes use display-order hexadecimal. Do not conflate the encodings.
        hash: [u8; 32],
    }
    let raw: RawTip = serde_json::from_value(budget.call("getbestblockheightandhash", json!([]))?)
        .context("invalid actual best-tip response")?;
    ensure_height(raw.height, "best-tip height")?;
    let mut hash = raw.hash;
    hash.reverse();
    Ok(ObservedTip {
        height: raw.height,
        hash: hex::encode(hash),
    })
}

fn check_history(
    history: &BTreeMap<u32, String>,
    budget: &mut Budget<'_, impl NodeRpc, impl Clock>,
) -> ObservationResult<()> {
    for (height, expected) in history {
        let actual = read_hash(
            &budget.call("getblockhash", json!([height]))?,
            "best-chain block hash",
        )?;
        if &actual != expected {
            return Err(eyre!("best-chain history mismatch at height {height}").into());
        }
    }
    Ok(())
}

fn check_tip_hash(
    tip: &ObservedTip,
    budget: &mut Budget<'_, impl NodeRpc, impl Clock>,
) -> ObservationResult<()> {
    let hash = read_hash(
        &budget.call("getblockhash", json!([tip.height]))?,
        "best-chain tip hash",
    )?;
    if hash != tip.hash {
        return Err(ObservationError::Wait(
            "chain tip moved during observation".into(),
        ));
    }
    Ok(())
}

fn check_chain_info(
    upgrades: &[(String, u32, String)],
    tip: &ObservedTip,
    info: Value,
) -> Result<bool> {
    let height = read_height(&info["blocks"], "blockchain-info height")?;
    let hash = read_hash(&info["bestblockhash"], "blockchain-info hash")?;
    if height != tip.height || hash != tip.hash {
        return Ok(false);
    }
    ensure!(
        info["chain"].as_str() == Some("test"),
        "blockchain-info is not Testnet"
    );
    let mut expected_upgrades = serde_json::Map::new();
    for (name, height, branch) in upgrades {
        if branch == "00000000" {
            continue;
        }
        expected_upgrades.insert(
            branch.clone(),
            json!({
                "name": name,
                "activationheight": height,
                "status": if *height <= tip.height { "active" } else { "pending" }
            }),
        );
    }
    ensure!(
        info["upgrades"] == Value::Object(expected_upgrades),
        "blockchain-info upgrade fields do not match the manifest"
    );
    let effective: BTreeMap<_, _> = upgrades
        .iter()
        .map(|(_, height, branch)| (*height, branch))
        .collect();
    let next_height = tip.height.checked_add(1).context("chain height overflow")?;
    for (field, height) in [("chaintip", tip.height), ("nextblock", next_height)] {
        let branch = effective
            .range(..=height)
            .next_back()
            .context("missing genesis branch")?
            .1;
        ensure!(
            info["consensus"][field]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(branch)),
            "blockchain-info {field} branch ID does not match the manifest"
        );
    }
    Ok(true)
}

fn read_hash(value: &Value, label: &str) -> Result<String> {
    let hash = value.as_str().with_context(|| format!("invalid {label}"))?;
    ensure!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid {label}"
    );
    Ok(hash.to_ascii_lowercase())
}

fn ensure_height(height: u32, label: &str) -> Result<()> {
    ensure!(height < i32::MAX as u32, "unsupported {label}");
    Ok(())
}

fn read_height(value: &Value, label: &str) -> Result<u32> {
    let height: u32 = value
        .as_u64()
        .and_then(|number| number.try_into().ok())
        .with_context(|| format!("invalid {label}"))?;
    ensure_height(height, label)?;
    Ok(height)
}

#[cfg(all(test, target_os = "linux"))]
mod external_tests {
    use super::*;

    #[test]
    fn compiled_rules_are_exact_not_ordinary_normalized_expectations() {
        let expected =
            json!({"apiVersion":"native-rules/v2","rules":{"genesisHash":"ab".repeat(32)}});
        let rules = PreparedRules {
            expected: expected.clone(),
            exact: true,
            standard: None,
        };
        rules.compare(expected.clone()).unwrap();
        // Compiled external contracts never accept a node without the diagnostic.
        assert!(!rules.falls_back(&RpcError::Remote {
            code: -32601,
            message: "Method not found".into()
        }));
        let mut changed = expected;
        changed["rules"]["genesisHash"] = "AB".repeat(32).into();
        assert!(rules.compare(changed).is_err());
        assert!(rules
            .compare(json!({"apiVersion":"native-rules/v2"}))
            .is_err());
    }

    #[test]
    fn blockchain_info_uses_companion_schedule_without_an_ordinary_manifest() {
        let upgrades = vec![
            ("Genesis".into(), 0, "00000000".into()),
            ("FutureNativeUpgrade".into(), 1, "aabbccdd".into()),
        ];
        let tip = ObservedTip {
            height: 0,
            hash: "ab".repeat(32),
        };
        let info = json!({"blocks":0,"bestblockhash":tip.hash,"chain":"test",
            "upgrades":{"aabbccdd":{"name":"FutureNativeUpgrade","activationheight":1,"status":"pending"}},
            "consensus":{"chaintip":"00000000","nextblock":"aabbccdd"}});
        assert!(check_chain_info(&upgrades, &tip, info.clone()).unwrap());
        let mut wrong = info;
        wrong["consensus"]["nextblock"] = "00000000".into();
        assert!(check_chain_info(&upgrades, &tip, wrong).is_err());
    }
}
