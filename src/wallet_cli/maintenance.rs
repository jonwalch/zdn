//! Fresh read-only chain evidence plus locked local journal maintenance.
use super::*;
use crate::connect_cli::{self, WalletHistoryArgs, WalletRpc};
use serde_json::json;

/// Reconcile before consulting archived-input absence or selecting a payment.
/// Legacy stores remain unchanged; enabling settlement storage is always explicit.
pub(super) fn reconcile(journal: &journal::Store, rpc: &mut WalletRpc<'_>) -> Result<usize> {
    if !journal.settlements_enabled()? {
        return Ok(0);
    }
    let tip = history::tip(&mut |m, p| rpc.read(m, p))?;
    ensure!(
        history::block_hash(&mut |m, p| rpc.read(m, p), 0)? == history::GENESIS,
        "maintenance node genesis mismatch"
    );
    history::observe_tip(&tip, &mut |m, p| rpc.read(m, p))?;
    journal.reconcile_settlements(
        &journal::ChainPoint {
            height: tip.height,
            hash: tip.hash,
        },
        |height| {
            if height > tip.height {
                return Ok(None);
            }
            history::block_hash(&mut |m, p| rpc.read(m, p), height).map(Some)
        },
    )
}

pub(super) fn run_reconcile(root: &Path, args: WalletHistoryArgs) -> Result<()> {
    let (manifest, identity) = args.selection()?;
    history::check_manifest(&manifest)?;
    let journal = journal::Store::open_maintenance(
        &root.join(identity.network_id.to_string()),
        identity.network_id,
        &identity.consensus_fingerprint,
    )?;
    ensure!(
        journal.settlements_enabled()?,
        "enable journal settlements explicitly first"
    );
    let restored = connect_cli::with_wallet_rpc(args, Some(identity.clone()), |_, _, rpc| {
        reconcile(&journal, rpc)
    })?;
    crate::print_json(&json!({"schema_version":1,"network_id":identity.network_id,
        "reorg_quarantines_restored":restored,"reconciled":true,"broadcast":false}))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn archive(
    backend: &Path,
    root: &Path,
    args: WalletHistoryArgs,
    wallet: &str,
    id: uuid::Uuid,
    depth: u32,
    apply: Option<&str>,
) -> Result<()> {
    let (manifest, identity) = args.selection()?;
    history::check_manifest(&manifest)?;
    let (receipt, key) = store::load(root, &identity, wallet)?;
    payment::verify_wallet(backend, &receipt, &key)?;
    let scope = root.join(identity.network_id.to_string());
    let journal = journal::Store::open_maintenance(
        &scope,
        identity.network_id,
        &identity.consensus_fingerprint,
    )?;
    ensure!(
        journal.settlements_enabled()?,
        "enable journal settlements explicitly first"
    );
    let record = journal.load(id)?;
    ensure!(
        record.wallet_id == receipt.id,
        "archive requires the original wallet binding"
    );
    let (height, hash) = match &record.outcome {
        journal::Outcome::Confirmed { height, hash } => (*height, hash.clone()),
        _ => eyre::bail!("only confirmed signed payments can be archived"),
    };
    let directory = scope.join("payment-data").join(id.to_string());
    let plan = record
        .plan
        .as_ref()
        .context("original payment plan missing")?;
    let envelope = record
        .signed
        .as_ref()
        .context("original signed envelope missing")?;
    // Immutable backend evidence must still independently verify. Archival is
    // not a way to hide missing originals or waive the original signature checks.
    payment::check_signed(
        backend,
        &key,
        &directory.join("history.json"),
        &directory.join("plan.json"),
        &directory.join("transaction.json"),
        plan,
        envelope,
    )?;
    let output = connect_cli::with_wallet_rpc(args, Some(identity), |_, _, rpc| {
        reconcile(&journal, rpc)?;
        let tip = history::tip(&mut |m, p| rpc.read(m, p))?;
        let inclusion = journal::ChainPoint { height, hash };
        journal.settlement_archive(
            id,
            &journal::ChainPoint {
                height: tip.height,
                hash: tip.hash,
            },
            &inclusion,
            depth,
            apply,
            |txid, inclusion, tip| {
                history::observe_tip(
                    &history::Tip {
                        height: tip.height,
                        hash: tip.hash.clone(),
                    },
                    &mut |m, p| rpc.read(m, p),
                )?;
                ensure!(
                    history::block_hash(&mut |m, p| rpc.read(m, p), inclusion.height)?
                        == inclusion.hash,
                    "settlement inclusion is not canonical"
                );
                let transaction = rpc
                    .transaction(txid)?
                    .context("original transaction inclusion unavailable; reservations retained")?;
                ensure!(
                    transaction["txid"] == txid
                        && transaction["height"] == inclusion.height
                        && transaction["blockhash"] == inclusion.hash
                        && transaction["confirmations"].as_u64().is_some_and(|n| n > 0)
                        && transaction["in_active_chain"] != false,
                    "original transaction is not confirmed in the recorded canonical block"
                );
                let block = rpc.read("getblock", json!([inclusion.hash, 1]))?;
                ensure!(
                    block["hash"] == inclusion.hash
                        && block["height"] == inclusion.height
                        && block["tx"].as_array().is_some_and(|txs| txs
                            .iter()
                            .filter(|v| *v == txid)
                            .count()
                            == 1),
                    "canonical block does not contain the exact original transaction"
                );
                history::observe_tip(
                    &history::Tip {
                        height: tip.height,
                        hash: tip.hash.clone(),
                    },
                    &mut |m, p| rpc.read(m, p),
                )?;
                Ok(())
            },
        )
    })?;
    crate::print_json(&output)
}
