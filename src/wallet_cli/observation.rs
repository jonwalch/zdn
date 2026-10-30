//! Named-wallet observations over authenticated state, never complete-history export.
use super::*;
use serde_json::{json, Value};

const CAPABILITY: &str = "ironwood-wallet-state-observation/v2";
const TRANSPARENT_CAPABILITY: &str = "transparent-wallet-state-observation/v1";
const MAX_MONEY: u64 = 2_100_000_000_000_000;

pub(super) enum Kind {
    Balance { confirmed_only: bool, pool: Pool },
    Rewards,
}

pub(super) fn capable(backend: &Path, pool: Pool) -> Result<bool> {
    let mut command = Command::new(backend);
    command.arg("capabilities");
    let response = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(30))?;
    if !response.success {
        return Ok(false);
    }
    let caps: Value = serde_json::from_str(&response.stdout)
        .map_err(|_| eyre::eyre!("invalid backend capabilities; diagnostics redacted"))?;
    ensure!(
        caps["schema_version"] == 1 && caps["capabilities"].is_array(),
        "invalid backend capabilities"
    );
    Ok(caps["capabilities"].as_array().unwrap().iter().any(|v| {
        v == if pool == Pool::Transparent {
            TRANSPARENT_CAPABILITY
        } else {
            CAPABILITY
        }
    }))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Balance {
    schema_version: u32,
    tip_height: u32,
    tip_hash: String,
    anchor_hex: String,
    commitment_count: u64,
    mempool_sha256: String,
    confirmed_unspent_zat: u64,
    spendable_zat: u64,
    pending_zat: u64,
    pending_spent_zat: u64,
    immature_zat: u64,
    reserved_zat: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reward {
    txid: String,
    output_index: u32,
    height: u32,
    value_zat: u64,
    mature: bool,
    mempool_spent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema_version: u32,
    capability: String,
    identity: Value,
    generation: u64,
    state_sha256: String,
    tip_height: u32,
    tip_hash: String,
    anchor_hex: String,
    mempool_sha256: String,
    balance: Balance,
    rewards: Vec<Reward>,
    canonicality: String,
}

pub(super) fn run(
    backend: &Path,
    root: &Path,
    args: super::super::connect_cli::WalletHistoryArgs,
    name: &str,
    kind: Kind,
) -> Result<()> {
    let (manifest, identity) = args.selection()?;
    history::check_manifest(&manifest)?;
    let (receipt, key) = store::load(root, &identity, name)?;
    payment::verify_wallet(backend, &receipt, &key)?;
    sync::preflight(backend)?;
    let journal = journal::Store::open_maintenance(
        &root.join(identity.network_id.to_string()),
        identity.network_id,
        &identity.consensus_fingerprint,
    )?;
    let confirmed_only = matches!(
        kind,
        Kind::Balance {
            confirmed_only: true,
            ..
        }
    );
    let pool = match kind {
        Kind::Balance { pool, .. } => pool,
        Kind::Rewards => Pool::Ironwood,
    };
    let (action, capability) = match pool {
        Pool::Ironwood => ("state-observe", CAPABILITY),
        Pool::Transparent => ("state-observe-transparent", TRANSPARENT_CAPABILITY),
    };
    let result = super::super::connect_cli::with_wallet_rpc(
        args,
        Some(identity.clone()),
        |manifest, _, rpc| {
            let progress = sync::current(backend, &key, manifest, &identity, 4, rpc)?;
            ensure!(
                progress["outcome"] == "current_at_observation",
                "wallet sync incomplete; run wallet sync again; no classified balance available"
            );
            super::maintenance::reconcile(&journal, rpc)?;
            let reserved = if confirmed_only {
                vec![]
            } else {
                journal.reserved_inputs()?
            };
            let pending = if confirmed_only {
                None
            } else {
                Some(mempool::collect(&mut |m, p| rpc.read(m, p))?)
            };
            let digest = pending
                .as_ref()
                .map(|p| p.digest.clone())
                .unwrap_or_else(|| hex::encode(Sha256::digest(b"ironwood-wallet-mempool/v1\0")));
            let mempool = sync::private_json(&match &pending {
                Some(p) => serde_json::from_slice(&p.bytes)?,
                None => json!({"schema_version":1,"transactions":[]}),
            })?;
            let binding = json!({"network_id":identity.network_id,"consensus_fingerprint":identity.consensus_fingerprint,
            "network":"h0-testnet-nu6.3-at-1","genesis_hash":history::GENESIS});
            let identity_file = sync::private_json(&binding)?;
            let exclusions = sync::private_json(&serde_json::to_value(&reserved)?)?;
            rpc.check()?;
            let value = sync::backend(
                backend,
                &[
                    Path::new(action),
                    &key,
                    identity_file.path(),
                    &key.parent().unwrap().join("scan-v2.sqlite"),
                    mempool.path(),
                    exclusions.path(),
                ],
            )?;
            rpc.check()?;
            let observation: Observation = serde_json::from_value(value)
                .map_err(|_| eyre::eyre!("invalid state observation; diagnostics redacted"))?;
            let b = &observation.balance;
            ensure!(
                observation.schema_version == 2
                    && observation.capability == capability
                    && observation.identity == binding
                    && observation.canonicality == "caller_attested_not_live_checked"
                    && progress["generation"] == observation.generation
                    && progress["state_sha256"] == observation.state_sha256
                    && progress["committed_height"] == observation.tip_height
                    && progress["tip_hash"] == observation.tip_hash
                    && progress["anchor_hex"] == observation.anchor_hex
                    && observation.mempool_sha256 == digest
                    && b.schema_version == 2
                    && b.tip_height == observation.tip_height
                    && b.tip_hash == observation.tip_hash
                    && b.anchor_hex == observation.anchor_hex
                    && b.mempool_sha256 == digest,
                "state observation differs from synced generation or mempool"
            );
            ensure!(
                [
                    b.confirmed_unspent_zat,
                    b.spendable_zat,
                    b.pending_zat,
                    b.pending_spent_zat,
                    b.reserved_zat
                ]
                .iter()
                .all(|n| *n <= MAX_MONEY)
                    && b.immature_zat == 0
                    && b.spendable_zat
                        .checked_add(b.pending_spent_zat)
                        .and_then(|n| n.checked_add(b.reserved_zat))
                        == Some(b.confirmed_unspent_zat),
                "invalid classified state balance"
            );
            ensure!(
                observation.rewards.len() <= 32768,
                "state reward count exceeds bound"
            );
            let mut seen = std::collections::HashSet::new();
            let mut total = 0u64;
            let mut rewards = Vec::new();
            for reward in &observation.rewards {
                ensure!(
                    hex_bytes(&reward.txid, 32)
                        && reward.height <= observation.tip_height
                        && reward.value_zat > 0
                        && reward.value_zat <= MAX_MONEY
                        && reward.mature == (observation.tip_height + 1 - reward.height >= 100)
                        && seen.insert((&reward.txid, reward.output_index)),
                    "invalid state reward inventory"
                );
                total = total
                    .checked_add(reward.value_zat)
                    .context("reward total overflow")?;
                ensure!(total <= MAX_MONEY, "reward total exceeds money bound");
                let mut value = serde_json::to_value(reward)?;
                value["locally_reserved"] = json!(reserved.contains(&journal::Input::P2pkh {
                    txid: reward.txid.clone(),
                    output_index: reward.output_index
                }));
                rewards.push(value);
            }
            if let Some(p) = &pending {
                p.recheck(&mut |m, p| rpc.read(m, p))?;
            }
            let tip = history::Tip {
                height: observation.tip_height,
                hash: observation.tip_hash.clone(),
            };
            let observed = history::observe_tip(&tip, &mut |m, p| rpc.read(m, p))?;
            ensure!(
                confirmed_only || observed.height == tip.height,
                "chain advanced; retry classified observation"
            );
            let mut output = json!({"schema_version":2,"network_id":identity.network_id,
            "consensus_fingerprint":identity.consensus_fingerprint,"wallet":name,
            "tip_height":tip.height,"tip_hash":tip.hash,"observed_height":observed.height,
            "state_sha256":observation.state_sha256,"generation":observation.generation,"anchor_hex":observation.anchor_hex,
            "scan_lag_blocks":observed.height-tip.height,"mempool_snapshot_rechecked":pending.is_some(),
            "local_reservations_checked":!confirmed_only,"trust":"trusted_node_not_independent_consensus"});
            match kind {
                Kind::Rewards => output["rewards"] = json!(rewards),
                Kind::Balance { .. } => {
                    output["balance"] = json!({"pool":pool,"confirmed_unspent_zat":b.confirmed_unspent_zat,
                    "spendable_zat":b.spendable_zat,"pending_zat":b.pending_zat,
                    "pending_spent_zat":b.pending_spent_zat,"immature_zat":b.immature_zat,
                    "reserved_zat":b.reserved_zat,"mempool_sha256":b.mempool_sha256});
                    if confirmed_only {
                        for field in [
                            "spendable_zat",
                            "pending_zat",
                            "pending_spent_zat",
                            "immature_zat",
                            "reserved_zat",
                            "mempool_sha256",
                        ] {
                            output["balance"][field] = Value::Null;
                        }
                    }
                }
            }
            Ok(output)
        },
    )?;
    eprintln!(
        "Authenticated local state with trusted-node observations, not independent consensus or an atomic current balance. Original signed payment evidence and reservations are retained."
    );
    super::super::print_json(&result)
}
