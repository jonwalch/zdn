//! Backend-authenticated checkpoints; node canonicality stays coordinator-owned.
use super::*;

const CAPABILITY: &str = "ironwood-wallet-state-rewind/v2";

pub(super) fn preflight(executable: &Path) -> Result<()> {
    let caps = backend(executable, &[Path::new("capabilities")])?;
    ensure!(
        caps["schema_version"] == 1
            && caps["capabilities"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v == CAPABILITY)),
        "backend does not support authenticated rewind"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    generation: u64,
    state_sha256: String,
    tip_height: Option<u32>,
    tip_hash: Option<String>,
}

impl Checkpoint {
    fn current(state: &Summary) -> Self {
        Self {
            generation: state.generation,
            state_sha256: state.state_sha256.clone(),
            tip_height: state.tip_height,
            tip_hash: state.tip_hash.clone(),
        }
    }

    fn valid(&self) -> bool {
        hex_bytes(&self.state_sha256, 32)
            && self.tip_height.is_some() == self.tip_hash.is_some()
            && self.tip_height.is_none_or(|h| h < i32::MAX as u32)
            && self.tip_hash.as_ref().is_none_or(|h| hex_bytes(h, 32))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    current: Checkpoint,
    rewind_enabled: bool,
    max_checkpoints: usize,
    checkpoints: Vec<Checkpoint>,
    blocks: Vec<Value>,
    canonicality: String,
}

/// Caller owns the network lock and the checked RPC session. Upgrades and deep
/// genesis replay each require their own explicit CLI choice; ordinary payment
/// callers may only use an already-enabled retained canonical checkpoint.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    executable: &Path,
    key: &Path,
    database: &Path,
    identity: &EndpointFile,
    state: &mut Summary,
    enable: bool,
    replay: bool,
    rpc: &mut super::super::super::connect_cli::WalletRpc<'_>,
) -> Result<Value> {
    let caps = backend(executable, &[Path::new("capabilities")])?;
    let capable = caps["schema_version"] == 1
        && caps["capabilities"]
            .as_array()
            .is_some_and(|v| v.iter().any(|v| v == CAPABILITY));
    ensure!(
        capable || (!enable && !replay),
        "backend does not support authenticated rewind"
    );
    if !capable {
        return Ok(json!({"rewound":false,"replayed_from_genesis":false}));
    }
    let binding = private_json(&json!({"network_id":identity.network_id,
        "consensus_fingerprint":identity.consensus_fingerprint,
        "network":"h0-testnet-nu6.3-at-1","genesis_hash":history::GENESIS}))?;
    if enable {
        rpc.check()?;
        let enabled = Summary::parse(
            backend(
                executable,
                &[
                    Path::new("state-enable-rewind"),
                    key,
                    binding.path(),
                    database,
                    Path::new(&state.state_sha256),
                ],
            )?,
            identity.network_id,
        )?;
        ensure!(
            serde_json::to_value(&enabled)? == serde_json::to_value(&*state)?,
            "rewind enablement changed state summary"
        );
        *state = enabled;
        rpc.check()?;
    }
    let target = history::tip(&mut |m, p| rpc.read(m, p))?;
    ensure!(
        history::block_hash(&mut |m, p| rpc.read(m, p), 0)? == history::GENESIS,
        "sync node genesis mismatch"
    );
    history::observe_tip(&target, &mut |m, p| rpc.read(m, p))?;
    let canonical = match state.tip() {
        Some(previous) if previous.height <= target.height => {
            history::block_hash(&mut |m, p| rpc.read(m, p), previous.height)? == previous.hash
        }
        None => true,
        _ => false,
    };
    if canonical {
        return Ok(json!({"rewound":false,"replayed_from_genesis":false}));
    }
    rpc.check()?;
    let heights = private_json(&json!([]))?;
    let inspection: Inspection = serde_json::from_value(backend(
        executable,
        &[
            Path::new("state-inspect-rewind"),
            key,
            binding.path(),
            database,
            heights.path(),
        ],
    )?)
    .map_err(|_| eyre::eyre!("invalid rewind inspection; diagnostics redacted"))?;
    ensure!(
        inspection.current == Checkpoint::current(state)
            && inspection.current.valid()
            && inspection.max_checkpoints == 4
            && inspection.checkpoints.len() <= 4
            && inspection.blocks.is_empty()
            && inspection.canonicality == "caller_attested_not_live_checked",
        "rewind inspection differs from current state"
    );
    ensure!(
        inspection.rewind_enabled,
        "stored sync tip is orphaned; explicitly enable rewind with wallet sync --enable-rewind; no reset performed"
    );
    let mut candidates = inspection.checkpoints;
    candidates.sort_by_key(|c| std::cmp::Reverse(c.tip_height));
    let mut selected = None;
    for candidate in candidates {
        ensure!(
            candidate.valid() && candidate.generation <= state.generation,
            "invalid rewind checkpoint identity"
        );
        if candidate.tip_height >= state.tip_height {
            continue;
        }
        let canonical = match candidate.tip_height {
            None => true,
            Some(height) if height <= target.height => {
                history::block_hash(&mut |m, p| rpc.read(m, p), height)?
                    == *candidate.tip_hash.as_ref().unwrap()
            }
            _ => false,
        };
        if canonical {
            selected = Some(candidate);
            break;
        }
    }
    ensure!(
        selected.is_some() || replay,
        "no retained canonical checkpoint; explicitly choose wallet sync --replay-from-genesis; keys and payment evidence retained"
    );
    // Recheck the pinned chain before mutating derived state. A later fork can
    // leave a committed candidate, but subsequent drive checks cannot call it current.
    history::observe_tip(&target, &mut |m, p| rpc.read(m, p))?;
    if let Some(c) = &selected {
        if let Some(height) = c.tip_height {
            history::observe_tip(
                &history::Tip {
                    height,
                    hash: c.tip_hash.clone().unwrap(),
                },
                &mut |m, p| rpc.read(m, p),
            )?;
        }
    }
    let request = private_json(&json!({"expected":Checkpoint::current(state),"target":selected}))?;
    rpc.check()?;
    let restored = Summary::parse(
        backend(
            executable,
            &[
                Path::new("state-rewind"),
                key,
                binding.path(),
                database,
                request.path(),
            ],
        )?,
        identity.network_id,
    )?;
    let expected_height = selected.as_ref().and_then(|c| c.tip_height);
    let expected_hash = selected.as_ref().and_then(|c| c.tip_hash.as_ref());
    ensure!(
        restored.generation
            == state
                .generation
                .checked_add(1)
                .context("sync generation overflow")?
            && restored.parent_state_sha256.as_ref() == Some(&state.state_sha256)
            && restored.state_sha256 != state.state_sha256
            && restored.tip_height == expected_height
            && restored.tip_hash.as_ref() == expected_hash,
        "rewind commit receipt mismatch"
    );
    let old_height = state.tip_height;
    *state = restored;
    rpc.check()?;
    history::observe_tip(&target, &mut |m, p| rpc.read(m, p))?;
    if let Some(tip) = state.tip() {
        history::observe_tip(&tip, &mut |m, p| rpc.read(m, p))?;
    }
    Ok(json!({"rewound":true,"previous_height":old_height,
        "restored_height":state.tip_height,"replayed_from_genesis":selected.is_none()}))
}
