//! Explicit append-only derived scanning, isolated from payment authority.
use super::*;
use serde_json::{json, Value};
use std::io::Write;
use tempfile::NamedTempFile;
use zdn::{chain::manifest::ConsensusManifest, endpoints::EndpointFile};

const CAPABILITY: &str = "ironwood-wallet-state/v2";
const RAW_LIMIT: usize = 64 * 1024 * 1024;
const JSON_LIMIT: usize = 129 * 1024 * 1024;

mod rewind;

#[derive(Debug)]
enum SyncStage {
    RpcRead,
    BatchInput,
    BackendAppend,
    BackendReceipt,
}

impl SyncStage {
    fn diagnostic(&self) -> (&'static str, &'static str) {
        match self {
            Self::RpcRead => ("rpc-read", "observation-failure"),
            Self::BatchInput => ("batch-input", "local-input-failure"),
            Self::BackendAppend => ("backend-append", "backend-failure"),
            Self::BackendReceipt => ("backend-receipt", "invalid-backend-receipt"),
        }
    }
}

impl std::fmt::Display for SyncStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.diagnostic().0)
    }
}
impl std::error::Error for SyncStage {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    schema_version: u32,
    capability: String,
    network_id: uuid::Uuid,
    generation: u64,
    state_sha256: String,
    parent_state_sha256: Option<String>,
    index_root_sha256: String,
    tip_height: Option<u32>,
    tip_hash: Option<String>,
    anchor_hex: String,
    commitment_count: u64,
    owned_transparent_zat: u64,
    notes: Vec<Note>,
    canonicality: String,
}

impl Summary {
    fn parse(value: Value, id: uuid::Uuid) -> Result<Self> {
        let s: Self = serde_json::from_value(value)
            .map_err(|_| eyre::eyre!("invalid sync state response; diagnostics redacted"))?;
        ensure!(
            s.schema_version == 2
                && s.capability == CAPABILITY
                && s.network_id == id
                && s.canonicality == "caller_attested_not_live_checked"
                && hex_bytes(&s.state_sha256, 32)
                && hex_bytes(&s.index_root_sha256, 32)
                && hex_bytes(&s.anchor_hex, 32)
                && s.parent_state_sha256
                    .as_ref()
                    .is_none_or(|h| hex_bytes(h, 32))
                && s.tip_height.is_some() == s.tip_hash.is_some()
                && s.tip_height.is_none_or(|h| h < i32::MAX as u32)
                && s.tip_hash.as_ref().is_none_or(|h| hex_bytes(h, 32))
                && s.owned_transparent_zat <= 2_100_000_000_000_000
                && s.notes.len() <= 32768,
            "invalid sync state contract"
        );
        for n in &s.notes {
            ensure!(
                hex_bytes(&n.txid, 32)
                    && (n.position as u64) < s.commitment_count
                    && n.value_zat > 0
                    && n.value_zat <= 2_100_000_000_000_000,
                "invalid sync note contract"
            );
        }
        Ok(s)
    }

    fn tip(&self) -> Option<history::Tip> {
        self.tip_height.map(|height| history::Tip {
            height,
            hash: self.tip_hash.clone().expect("validated tip pair"),
        })
    }
}

pub(super) fn backend(backend: &Path, args: &[&Path]) -> Result<Value> {
    let mut command = Command::new(backend);
    command.args(args);
    serde_json::from_str(&backend_stdout(command)?)
        .map_err(|_| eyre::eyre!("invalid sync backend JSON; diagnostics redacted"))
}

pub(super) fn private_json(value: &Value) -> Result<NamedTempFile> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= JSON_LIMIT,
        "sync batch exceeds 129 MiB JSON limit"
    );
    let mut file = NamedTempFile::new()?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(file)
}

pub(super) fn run(
    executable: &Path,
    root: &Path,
    args: super::super::connect_cli::WalletHistoryArgs,
    name: &str,
    max_batches: u32,
    enable_rewind: bool,
    replay_from_genesis: bool,
) -> Result<()> {
    let (manifest, identity) = args.selection()?;
    history::check_manifest(&manifest)?;
    let (receipt, key) = store::load(root, &identity, name)?;
    payment::verify_wallet(executable, &receipt, &key)?;
    preflight(executable)?;
    if enable_rewind || replay_from_genesis {
        rewind::preflight(executable)?;
    }
    let _network = journal::Store::open(
        &root.join(identity.network_id.to_string()),
        identity.network_id,
        &identity.consensus_fingerprint,
    )?;
    let (mut state, database) = initialize(executable, &key, &identity)?;
    let progress = super::super::connect_cli::with_wallet_rpc(
        args,
        Some(identity.clone()),
        |manifest, _, rpc| {
            let recovery = rewind::prepare(
                executable,
                &key,
                &database,
                &identity,
                &mut state,
                enable_rewind,
                replay_from_genesis,
                rpc,
            )?;
            let mut progress = advance(
                executable,
                &key,
                &database,
                manifest,
                &identity,
                &mut state,
                max_batches,
                rpc,
            )?;
            progress["recovery"] = recovery;
            Ok(progress)
        },
    )?;
    super::super::print_json(&progress)
}

pub(super) fn preflight(executable: &Path) -> Result<()> {
    let caps = backend(executable, &[Path::new("capabilities")])?;
    ensure!(
        caps["schema_version"] == 1
            && caps["capabilities"]
                .as_array()
                .is_some_and(|c| c.iter().any(|v| v == CAPABILITY)),
        "wallet sync requires ironwood-wallet-state/v2; no full-history fallback"
    );
    Ok(())
}

// Caller holds the network journal lock and owns the single checked RPC session.
pub(super) fn current(
    executable: &Path,
    key: &Path,
    manifest: &ConsensusManifest,
    identity: &EndpointFile,
    max_batches: u32,
    rpc: &mut super::super::connect_cli::WalletRpc<'_>,
) -> Result<Value> {
    let (mut state, database) = initialize(executable, key, identity)?;
    let recovery = rewind::prepare(
        executable, key, &database, identity, &mut state, false, false, rpc,
    )?;
    let mut progress = advance(
        executable,
        key,
        &database,
        manifest,
        identity,
        &mut state,
        max_batches,
        rpc,
    )?;
    progress["recovery"] = recovery;
    Ok(progress)
}

fn initialize(
    executable: &Path,
    key: &Path,
    identity: &EndpointFile,
) -> Result<(Summary, PathBuf)> {
    let directory = key.parent().context("missing wallet directory")?;
    let database = directory.join("scan-v2.sqlite");
    let marker = directory.join("scan-v2.initialized");
    let binding = private_json(&json!({"network_id":identity.network_id,
        "consensus_fingerprint":identity.consensus_fingerprint,
        "network":"h0-testnet-nu6.3-at-1","genesis_hash":history::GENESIS}))?;
    let exists = match fs::symlink_metadata(&database) {
        Ok(_) => {
            regular(&database, true)?;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let operation = if exists {
        // Adopt a pre-existing backend store without ever treating its later
        // disappearance as permission to initialize again.
        match fs::symlink_metadata(&marker) {
            Ok(_) => regular(&marker, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                super::super::write_new_file(&marker, b"state/v2 existing store observed\n")?;
            }
            Err(e) => return Err(e.into()),
        }
        "state-status"
    } else {
        // Durable exclusive intent means a deleted/crash-left store is never
        // silently initialized again. Manual inspection/recovery is required.
        super::super::write_new_file(&marker, b"state/v2 initialization attempted\n")
            .map_err(|_| eyre::eyre!("sync store missing after initialization attempt; preserve files and inspect; no automatic recreation"))?;
        "state-init"
    };
    let state = Summary::parse(
        backend(
            executable,
            &[Path::new(operation), key, binding.path(), &database],
        )?,
        identity.network_id,
    )?;
    if !exists {
        ensure!(
            state.generation == 0
                && state.tip_height.is_none()
                && state.parent_state_sha256.is_none(),
            "invalid initial sync state"
        );
    }
    Ok((state, database))
}

#[allow(clippy::too_many_arguments)]
fn advance(
    executable: &Path,
    key: &Path,
    database: &Path,
    manifest: &ConsensusManifest,
    identity: &EndpointFile,
    state: &mut Summary,
    max_batches: u32,
    rpc: &mut super::super::connect_cli::WalletRpc<'_>,
) -> Result<Value> {
    let result = {
        // Both sequential callbacks share the existing session budget;
        // serialization/backend work must not bypass cancellation checks.
        let session = std::cell::RefCell::new(rpc);
        drive(
            manifest,
            identity,
            state,
            max_batches,
            &mut |m, p| session.borrow_mut().read(m, p).wrap_err(SyncStage::RpcRead),
            &mut |batch| {
                session.borrow().check()?;
                let input = private_json(batch).wrap_err(SyncStage::BatchInput)?;
                session.borrow().check()?;
                let result = Summary::parse(
                    backend(
                        executable,
                        &[Path::new("state-append"), key, database, input.path()],
                    )
                    .wrap_err(SyncStage::BackendAppend)?,
                    identity.network_id,
                )
                .wrap_err(SyncStage::BackendReceipt)?;
                session.borrow().check()?;
                Ok(result)
            },
        )
    };
    match result {
        Ok(progress) => Ok(progress),
        Err(error) => {
            eprintln!(
                "Sync incomplete; committed candidate retained (possibly newer than last acknowledged progress); rerun sync to revalidate. No current or spendable result. Diagnostics redacted."
            );
            eprintln!(
                "Last acknowledged committed height: {:?}; generation: {}. Canonicality unchecked after failure.",
                state.tip_height, state.generation
            );
            // Report only local enum labels, never the original error chain:
            // backend/RPC errors may contain arbitrary private input or bodies.
            let (stage, mut class) = error
                .downcast_ref::<SyncStage>()
                .map(SyncStage::diagnostic)
                .unwrap_or(("sync-validation", "invalid-observation-or-commit"));
            let stage = if let Some(session) =
                error.downcast_ref::<super::super::connect_cli::WalletRpcError>()
            {
                class = session.classification();
                if stage == "sync-validation" {
                    "session-check"
                } else {
                    stage
                }
            } else {
                stage
            };
            if error.chain().any(|cause| {
                matches!(
                    cause.to_string().as_str(),
                    "node reorged the history snapshot or observed tip; retry with a new snapshot"
                        | "node rollback or moving target; retry sync"
                )
            }) {
                eyre::bail!(
                    "canonical sync tip conflict: fork or node rollback; preserve state; automatic rewind/reorg recovery is not implemented; stage={stage}; class=canonical-conflict"
                );
            }
            eyre::bail!(
                "wallet sync incomplete; stage={stage}; class={class}; no automatic rewind or reset; diagnostics redacted"
            )
        }
    }
}

fn drive(
    manifest: &ConsensusManifest,
    identity: &EndpointFile,
    state: &mut Summary,
    budget: u32,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
    append: &mut impl FnMut(&Value) -> Result<Summary>,
) -> Result<Value> {
    let target = history::tip(rpc)?;
    ensure!(
        history::block_hash(rpc, 0)? == history::GENESIS,
        "sync node genesis mismatch"
    );
    history::observe_tip(&target, rpc)?;
    if let Some(previous) = state.tip() {
        history::observe_tip(&previous, rpc).wrap_err(
            "stored sync tip is not canonical; rollback/reorg recovery is not implemented",
        )?;
        ensure!(
            previous.height <= target.height,
            "node rollback or moving target; retry sync"
        );
    }
    let starting = state.tip_height;
    let mut batches = 0;
    let mut processed = 0;
    while batches < budget && state.tip_height != Some(target.height) {
        let start = state.tip_height.map_or(0, |h| h + 1);
        let end = target.height.min(start.saturating_add(255));
        let mut blocks = Vec::new();
        let mut bytes_total = 0;
        let mut last = None;
        for height in start..=end {
            let hash = history::block_hash(rpc, height)?;
            let value = rpc("getblock", json!([hash, 0]))?;
            let mut raw = value.as_str().context("invalid raw sync block")?.to_owned();
            ensure!(
                !raw.is_empty() && raw.len().is_multiple_of(2),
                "invalid raw sync encoding"
            );
            ensure!(
                raw.len() / 2 <= RAW_LIMIT,
                "individual sync block exceeds 64 MiB"
            );
            if raw.len() / 2 > RAW_LIMIT - bytes_total {
                break;
            }
            let bytes = hex::decode(&raw).map_err(|_| eyre::eyre!("invalid raw sync encoding"))?;
            if height == 0 {
                ensure!(
                    bytes.len() as u64 == manifest.genesis.bytes_length
                        && hex::encode(Sha256::digest(&bytes)) == manifest.genesis.bytes_sha256,
                    "raw sync genesis differs from reviewed manifest"
                );
            }
            bytes_total += bytes.len();
            raw.make_ascii_lowercase();
            blocks.push(raw);
            last = Some(history::Tip { height, hash });
        }
        let last = last.context("empty sync batch")?;
        let tree = rpc("z_gettreestate", json!([last.hash]))?;
        let anchor = tree["ironwood"]["commitments"]["finalRoot"]
            .as_str()
            .context("missing sync treestate root")?;
        ensure!(
            tree["height"].as_u64() == Some(u64::from(last.height))
                && tree["hash"].as_str() == Some(&last.hash)
                && hex_bytes(anchor, 32),
            "sync treestate identity mismatch"
        );
        let batch = json!({"schema_version":2,"identity":{
            "network_id":identity.network_id,"consensus_fingerprint":identity.consensus_fingerprint,
            "network":"h0-testnet-nu6.3-at-1","genesis_hash":history::GENESIS},
            "expected_state_sha256":state.state_sha256,"start_height":start,
            "blocks":blocks,"treestate":tree});
        ensure!(
            serde_json::to_vec(&batch)?.len() <= JSON_LIMIT,
            "sync batch exceeds JSON limit"
        );
        history::observe_tip(&target, rpc)?;
        if let Some(previous) = state.tip() {
            history::observe_tip(&previous, rpc)?;
        }
        history::observe_tip(&last, rpc)?;
        let candidate = append(&batch)?;
        ensure!(
            candidate.generation
                == state
                    .generation
                    .checked_add(1)
                    .context("sync generation overflow")?
                && candidate.parent_state_sha256.as_ref() == Some(&state.state_sha256)
                && candidate.state_sha256 != state.state_sha256
                && candidate.tip_height == Some(last.height)
                && candidate.tip_hash.as_ref() == Some(&last.hash)
                && candidate.anchor_hex.eq_ignore_ascii_case(anchor),
            SyncStage::BackendReceipt
        );
        *state = candidate;
        batches += 1;
        processed += blocks.len();
        history::observe_tip(&last, rpc)?;
        history::observe_tip(&target, rpc)?;
    }
    let mut observed = history::observe_tip(&target, rpc)?;
    if let Some(committed) = state.tip() {
        // Use the latest actual observation, not the preceding target check:
        // an advancing node can make a just-complete candidate incomplete here.
        observed = history::observe_tip(&committed, rpc)?;
    }
    Ok(
        json!({"schema_version":1,"outcome":if state.tip_height == Some(observed.height) {"current_at_observation"} else {"incomplete"},
        "generation":state.generation,"state_sha256":state.state_sha256,"tip_hash":state.tip_hash,"anchor_hex":state.anchor_hex,
        "starting_height":starting,"committed_height":state.tip_height,"target_height":target.height,
        "observed_height":observed.height,"batches_committed":batches,"blocks_processed":processed,
        "scan_lag_blocks":state.tip_height.map(|h| observed.height-h),
        "resumable":true,"payment_enabled":false,"spendability_checked":false}),
    )
}
