//! Durable local payments; proofs remain owned by the explicitly pinned backend.
use super::{history, journal, mempool, store, *};
use crate::connect_cli::{self, SubmissionOutcome, WalletHistoryArgs, WalletRpc};
use serde_json::{json, Value};
use uuid::Uuid;

mod snapshot;

const PAYMENT_HELP: &str = "Setup: use zdn wallet backend set with an independently trusted executable/hash; --backend/--backend-sha256 here override that pair together. Use the same --wallet-dir/settings and private controller state throughout. --manifest normally comes from the saved deployment or identity bind registration. Create funding/alice/bob with wallet create: key-only imports cannot sign. Create funding BEFORE launch and select its public reward address; rewards must mature before funding. CLI payments use private full-node RPC, not lightwalletd. No wallet download or automatic backend trust is provided.\n\nExamples (send disposable test coins; NOT previews, no --yes flag):\n  zdn fund NETWORK --wallet alice --amount 1 --fee-zat 15000\n  zdn send NETWORK --from alice --to bob --amount 0.1 --fee-zat 10000\n\nPreserve the returned operation UUID and coherent wallet/journal store. To recover, repeat the original request with --operation-id UUID; do not create a new payment merely because confirmation timed out or the submission reply was lost. Unknown outcomes are not proof of failure or permission to rebroadcast. Keys/signing remain local in the trusted, unsandboxed backend. See docs/wallet.md#first-payment-alice-and-bob for prerequisites, backups and recovery.";

#[derive(Args)]
pub struct PaymentOptions {
    #[command(flatten)]
    history: WalletHistoryArgs,
    /// Override the configured backend together with --backend-sha256; never search PATH.
    #[arg(long)]
    backend: Option<PathBuf>,
    /// Independently trusted executable SHA256 (64 hex); supply with --backend or omit both for this root's saved pair.
    #[arg(long)]
    backend_sha256: Option<String>,
    /// Backend-settings/named-wallet root; default $XDG_DATA_HOME/zdn/wallets or $HOME/.local/share/zdn/wallets.
    #[arg(long)]
    wallet_dir: Option<PathBuf>,
    /// ZEC with at most eight decimal places; never floating point.
    #[arg(long)]
    amount: String,
    /// Explicit integer zatoshis; omit for the backend's conservative fee policy.
    #[arg(long)]
    fee_zat: Option<u64>,
    /// Destination pool; transparent send spends normal UTXOs, while transparent fund unshields Ironwood funds.
    #[arg(long, value_enum, default_value = "ironwood")]
    pool: Pool,
    /// Resume this exact operation, retaining its original request and signed bytes.
    #[arg(long)]
    operation_id: Option<Uuid>,
    /// Canonical inclusion depth to observe (1..=100), counting inclusion as one; policy, not finality.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
    confirmations: u32,
    /// Bounded confirmation-observation wait in seconds (1..=240); timeout does not cancel or undo a payment.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=240))]
    wait_secs: u64,
}

#[derive(Args)]
#[command(after_help = PAYMENT_HELP)]
pub struct SendArgs {
    #[command(flatten)]
    options: PaymentOptions,
    /// Existing local signing-enabled wallet name on this network; scan-only imports refuse even on resume.
    #[arg(long)]
    from: String,
    /// Local wallet name, or an explicit address for the selected pool (Testnet t-address for transparent).
    #[arg(long)]
    to: String,
}

#[derive(Args)]
#[command(after_help = PAYMENT_HELP)]
pub struct FundArgs {
    #[command(flatten)]
    options: PaymentOptions,
    /// Local wallet that owns this network's block rewards.
    #[arg(long, default_value = "funding")]
    funding_wallet: String,
    /// Destination local wallet name; required unless --address is supplied, and conflicts with --address.
    #[arg(long, required_unless_present = "address", conflicts_with = "address")]
    wallet: Option<String>,
    /// Explicit address for the selected pool instead of --wallet; transparent funding requires Ironwood funds first.
    #[arg(long)]
    address: Option<String>,
}

#[derive(Args)]
#[command(allow_missing_positional = true)]
pub struct TxArgs {
    #[command(flatten)]
    history: WalletHistoryArgs,
    /// Transaction ID (64 hex); this observes canonical inclusion/reorg history, never signs or broadcasts.
    txid: String,
    /// Local wallet/journal root; default $XDG_DATA_HOME/zdn/wallets or $HOME/.local/share/zdn/wallets.
    #[arg(long)]
    wallet_dir: Option<PathBuf>,
}

// Keep declared order identical to the backend's typed request digest contract.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    kind: String,
    recipient: String,
    amount_zat: u64,
    fee_zat: Option<u64>,
    excluded_inputs: Vec<journal::Input>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory<'a> {
    schema_version: u32,
    tip_height: u32,
    tip_hash: &'a str,
    history_sha256: &'a str,
    anchor_hex: &'a str,
    mempool_sha256: &'a str,
    #[serde(borrow)]
    rewards: Vec<Reward<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reward<'a> {
    txid: &'a str,
    output_index: u32,
    height: u32,
    value_zat: u64,
    mature: bool,
    #[serde(rename = "mempool_spent")]
    _mempool_spent: bool,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.rewards")
)]
pub(super) fn rewards(
    backend: &Path,
    root: &Path,
    history: WalletHistoryArgs,
    name: &str,
) -> Result<()> {
    let identity = history.selection()?.1;
    let (wallet, key) = store::load(root, &identity, name)?;
    verify_wallet(backend, &wallet, &key)?;
    let journal = journal::Store::open(
        &root.join(identity.network_id.to_string()),
        identity.network_id,
        &identity.consensus_fingerprint,
    )?;
    ensure!(
        !journal.settlements_enabled()?,
        "settlement-enabled reward classification requires a state-observation/v2 backend"
    );
    let reserved = journal.reserved_inputs()?;
    let reserved_rewards: std::collections::HashSet<_> = reserved
        .iter()
        .filter_map(|input| match input {
            journal::Input::P2pkh { txid, output_index } => Some((txid.as_str(), *output_index)),
            journal::Input::Ironwood { .. } => None,
        })
        .collect();
    let (rewards, mut observation) =
        connect_cli::with_wallet_history(history, Some(identity), true, |history, mempool| {
            let pending = mempool.context("reward inventory requires mempool observation")?;
            let directory = tempfile::tempdir()?;
            let input = history.path();
            let mempool = directory.path().join("mempool.json");
            let output = directory.path().join("inventory.json");
            crate::write_new_file(&mempool, &pending.bytes)?;
            let mut value = backend_json(
                backend,
                &[Path::new("inventory"), &key, input, &mempool, &output],
                Some(&output),
            )?;
            let inventory = Inventory::deserialize(&value)
                .map_err(|_| eyre::eyre!("invalid public reward inventory"))?;
            ensure!(
                inventory.schema_version == 1
                    && inventory.tip_height == history.tip.height
                    && inventory.tip_hash == history.tip.hash
                    && inventory.history_sha256 == history.digest
                    && inventory.anchor_hex == history.anchor
                    && inventory.mempool_sha256 == pending.digest
                    && inventory.rewards.len() <= 16384,
                "reward inventory differs from collected snapshot"
            );
            let mut seen = std::collections::HashSet::new();
            let mut total = 0u64;
            let mut reservations = Vec::with_capacity(inventory.rewards.len());
            for reward in inventory.rewards {
                ensure!(
                    hex_bytes(reward.txid, 32)
                        && reward.height <= history.tip.height
                        && reward.value_zat > 0
                        && reward.value_zat <= 2_100_000_000_000_000
                        && reward.mature == (history.tip.height + 1 - reward.height >= 100)
                        && seen.insert((reward.txid, reward.output_index)),
                    "invalid public reward inventory"
                );
                total = total
                    .checked_add(reward.value_zat)
                    .context("reward total overflow")?;
                ensure!(
                    total <= 2_100_000_000_000_000,
                    "reward total exceeds money bound"
                );
                let reserved = reserved_rewards.contains(&(reward.txid, reward.output_index));
                reservations.push(reserved);
            }
            let mut rewards = value["rewards"].take();
            for (reward, reserved) in rewards
                .as_array_mut()
                .expect("validated reward inventory")
                .iter_mut()
                .zip(reservations)
            {
                reward["locally_reserved"] = json!(reserved);
            }
            Ok(rewards)
        })?;
    observation["local_reservations_checked"] = json!(true);
    observation["wallet"] = json!(name);
    observation["rewards"] = rewards;
    crate::print_json(&observation)
}

pub fn send(args: SendArgs) -> Result<()> {
    let kind = match args.options.pool {
        Pool::Ironwood => "send",
        Pool::Transparent => "transparent",
    };
    pay(args.options, kind, &args.from, &args.to, true)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.fund")
)]
pub fn fund(args: FundArgs) -> Result<()> {
    let kind = match args.options.pool {
        Pool::Ironwood => "fund",
        Pool::Transparent => "unshield",
    };
    let named = args.wallet.is_some();
    let recipient = args
        .wallet
        .or(args.address)
        .context("select a destination")?;
    pay(args.options, kind, &args.funding_wallet, &recipient, named)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.amount")
)]
fn amount(value: &str) -> Result<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    ensure!(
        !whole.is_empty()
            && whole.len() <= 8
            && fraction.len() <= 8
            && whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
            && (!value.contains('.') || !fraction.is_empty()),
        "amount must be a positive decimal ZEC amount with at most eight places"
    );
    let zat = whole
        .parse::<u64>()?
        .checked_mul(100_000_000)
        .and_then(|n| {
            n.checked_add(if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u64>().unwrap_or(0) * 10u64.pow(8 - fraction.len() as u32)
            })
        })
        .context("amount overflow")?;
    ensure!(
        zat > 0 && zat <= 2_100_000_000_000_000,
        "amount outside money range"
    );
    Ok(zat)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.backend_json")
)]
fn backend_json(backend: &Path, args: &[&Path], output: Option<&Path>) -> Result<Value> {
    backend_version(backend, args, output, 1)
}

fn backend_version(
    backend: &Path,
    args: &[&Path],
    output: Option<&Path>,
    version: u32,
) -> Result<Value> {
    let mut command = Command::new(backend);
    command.args(args);
    // Proof generation has a separate bounded budget from ordinary key/scan calls.
    let result = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(240))
        .map_err(|_| eyre::eyre!("payment backend failed or exceeded limits; diagnostics redacted; resume the saved operation"))?;
    ensure!(
        result.success,
        "payment backend refused; diagnostics redacted; saved operation retained"
    );
    let value: Value = serde_json::from_str(&result.stdout)
        .map_err(|_| eyre::eyre!("invalid payment backend response; diagnostics redacted"))?;
    ensure!(
        value.is_object() && value["schema_version"] == version,
        "invalid payment backend response"
    );
    if let Some(output) = output {
        regular(output, true)?;
        ensure!(
            fs::metadata(output)?.len() <= 4 * 1024 * 1024,
            "payment output exceeds journal bound"
        );
        let saved: Value = serde_json::from_slice(&fs::read(output)?)
            .map_err(|_| eyre::eyre!("invalid saved payment backend response"))?;
        ensure!(
            saved == value,
            "backend stdout differs from saved payment output"
        );
    }
    Ok(value)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.verify_wallet")
)]
pub(super) fn verify_wallet(backend: &Path, receipt: &store::Wallet, key: &Path) -> Result<()> {
    let mut command = Command::new(backend);
    command.arg("key-public").arg(key);
    receipt.verify(&execute_backend(command, None, Response::Keys)?.into_keys())
}

fn check_sender(journal: &journal::Store, request: &Value, id: Uuid) -> Result<()> {
    for pending in journal.records()? {
        if pending.operation_id == id || pending.cancelled() {
            continue;
        }
        if (pending.request.get("sender_public").is_none()
            || pending.request.get("sender_public") == request.get("sender_public"))
            && (journal.settlement_disposition(pending.operation_id)? == "reorg_quarantine"
                || pending.plan.is_some() && pending.signed.is_none()
                || pending.attempts > 1
                    && matches!(pending.outcome, journal::Outcome::NodeRejected { .. })
                || matches!(
                    pending.outcome,
                    journal::Outcome::Signing
                        | journal::Outcome::Signed
                        | journal::Outcome::OutcomeUnknown
                        | journal::Outcome::Acknowledged
                        | journal::Outcome::Reorged
                ))
        {
            eyre::bail!("sender has an unresolved payment {}; resume or explicitly reconcile that operation before starting another payment", pending.operation_id);
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.pay")
)]
fn pay(
    options: PaymentOptions,
    kind: &str,
    sender: &str,
    destination: &str,
    named: bool,
) -> Result<()> {
    let amount_zat = amount(&options.amount)?;
    if let Some(fee) = options.fee_zat {
        ensure!(
            fee > 0
                && amount_zat
                    .checked_add(fee)
                    .is_some_and(|n| n <= 2_100_000_000_000_000),
            "fee must be positive and amount plus fee must fit the money range"
        );
    }
    let root = crate::data_path(options.wallet_dir, "wallets")?;
    let (backend, _) = settings::resolve(
        &root,
        options.backend.as_deref(),
        options.backend_sha256.as_deref(),
    )?;
    let (_, identity) = options.history.selection()?;
    let (wallet, key) = store::load(&root, &identity, sender)?;
    ensure!(
        wallet.scan_only != Some(true),
        "imported wallet is scan-only; fund/send and payment resume require the complete coherent signing-enabled wallet store, not a key-only import"
    );
    verify_wallet(&backend, &wallet, &key)?;
    // send accepts either a named local wallet or an explicit receiver. A missing
    // name is never silently resolved through another network or an AWS service.
    let transparent = options.pool == Pool::Transparent;
    let explicit = hex_bytes(destination, 43)
        || destination.starts_with("utest1")
        || transparent
            && bs58::decode(destination)
                .with_check(None)
                .into_vec()
                .is_ok_and(|bytes| bytes.len() == 22);
    let recipient = if named && !explicit {
        let (receipt, receiver_key) = store::load(&root, &identity, destination)?;
        verify_wallet(&backend, &receipt, &receiver_key)?;
        if transparent {
            receipt.public.reward_address
        } else {
            receipt.public.ironwood_address_hex
        }
    } else {
        destination.to_owned()
    };
    let scope = root.join(identity.network_id.to_string());
    let mut journal =
        journal::Store::open(&scope, identity.network_id, &identity.consensus_fingerprint)?;
    let id = options.operation_id.unwrap_or_else(Uuid::new_v4);
    let mut intent = json!({"schema_version":1,"kind":kind,"sender":sender,"recipient":recipient,
        "sender_public":wallet.public,"amount_zat":amount_zat,"fee_zat":options.fee_zat});
    let existing = options.operation_id.map(|_| journal.load(id)).transpose()?;
    if existing.is_some() {
        ensure!(journal.settlement_disposition(id)? == "active",
            "archived or reorg-quarantined payment requires explicit maintenance; ordinary resume is refused");
    }
    let original_plan_path = scope
        .join("payment-data")
        .join(id.to_string())
        .join("plan.json");
    let original_plan: Option<Value> =
        if existing.as_ref().is_some_and(|r| r.plan.is_none()) && original_plan_path.exists() {
            regular(&original_plan_path, true)?;
            Some(zdn::foundation::read_json(&original_plan_path)?)
        } else {
            None
        };
    let saved_version = existing
        .as_ref()
        .and_then(|r| r.plan.as_ref())
        .or(original_plan.as_ref())
        .map(|p| &p["schema_version"]);
    let v2 = match saved_version {
        Some(v) if v == 2 => true,
        Some(v) => {
            ensure!(v == 1, "unsupported saved payment plan version");
            false
        }
        None if existing.is_some()
            && original_plan_path.with_file_name("identity.json").exists() =>
        {
            true
        }
        None => snapshot::capable(&backend, transparent)?,
    };
    ensure!(
        !transparent || v2,
        "transparent payments require transparent-wallet-payments/v1 and snapshot/v2; no legacy or Ironwood fallback"
    );
    if v2 {
        snapshot::preflight(&backend, transparent)?;
        history::check_manifest(&options.history.selection()?.0)?;
    }
    let mut record = if options.operation_id.is_some() {
        let record = existing.unwrap();
        ensure!(
            !record.cancelled(),
            "cancelled payment cannot be resumed; use a fresh operation ID"
        );
        // Preserve recovery of records written before public-key identity was
        // added; the original wallet UUID and complete original intent still bind.
        if record.request.get("sender_public").is_none() {
            intent.as_object_mut().unwrap().remove("sender_public");
        }
        ensure!(
            record.wallet_id == wallet.id && record.request == intent,
            "resume request differs from saved wallet/payment intent"
        );
        record
    } else {
        check_sender(&journal, &intent, id)?;
        journal.begin(id, wallet.id, intent)?
    };
    // A legacy planned record may already have invoked the signer. Neither a
    // missing envelope nor zero dispatch attempts proves it was never signed.
    let ambiguous_resume = options.operation_id.is_some()
        && record.plan.is_some()
        && record.outcome != journal::Outcome::Reserved;
    eprintln!(
        "Payment operation {id}; resume only this operation after interruption. Reservations are retained, including after rejection or reorg."
    );
    // Public history is nevertheless private local data. Persist its exact bytes
    // before the authenticated plan; recovery uses this snapshot, not a rescan.
    let data = scope.join("payment-data");
    store::private_dir(&data, true)?;
    let directory = data.join(id.to_string());
    store::private_dir(&directory, true)?;
    let history_path = directory.join("history.json");
    let mempool_path = directory.join("mempool.json");
    let plan_path = directory.join("plan.json");
    let envelope_path = directory.join("transaction.json");
    let request_path = directory.join("request.json");
    let identity_path = directory.join("identity.json");
    let binding = json!({"network_id":identity.network_id,"consensus_fingerprint":identity.consensus_fingerprint,
        "network":"h0-testnet-nu6.3-at-1","genesis_hash":history::GENESIS});
    if v2 {
        if identity_path.exists() {
            regular(&identity_path, true)?;
            let saved: Value = zdn::foundation::read_json(&identity_path)?;
            ensure!(
                saved == binding,
                "saved snapshot identity differs from network"
            );
        } else {
            ensure!(
                record.plan.is_none()
                    && !plan_path.exists()
                    && !directory.join("snapshot.json").exists()
                    && !directory.join("snapshot-started").exists(),
                "original snapshot identity missing; operation quarantined"
            );
            crate::write_new_file(&identity_path, &serde_json::to_vec(&binding)?)?;
        }
    }
    let mut observed_confirmations = None;
    let result = connect_cli::with_wallet_rpc(
        options.history,
        Some(identity.clone()),
        |manifest, _, rpc| {
            super::maintenance::reconcile(&journal, rpc)?;
            if record.plan.is_none() || record.signed.is_none() {
                check_sender(&journal, &record.request, id)?;
            }
            if record.plan.is_none() {
                if v2 {
                    record = snapshot::prepare(
                        &backend,
                        &key,
                        manifest,
                        &identity,
                        rpc,
                        &directory,
                        &binding,
                        &mut journal,
                        id,
                        kind,
                        &recipient,
                        amount_zat,
                        options.fee_zat,
                    )?;
                } else if !plan_path.exists() {
                    let history = history::collect_current(manifest, &mut |m, p| rpc.read(m, p))?;
                    ensure!(
                        history.observe(&mut |m, p| rpc.read(m, p))?["scan_lag_blocks"] == 0,
                        "chain tip changed before payment preparation"
                    );
                    super::maintenance::reconcile(&journal, rpc)?;
                    check_sender(&journal, &record.request, id)?;
                    let pending = mempool::collect(&mut |m, p| rpc.read(m, p))?;
                    // An interrupted pre-plan attempt can leave snapshots but has no
                    // reservations or signed bytes; safely replace only these inputs.
                    history.persist_snapshot(&history_path)?;
                    zdn::foundation::write_private(&mempool_path, &pending.bytes)?;
                    let request = Request {
                        schema_version: 1,
                        kind: kind.into(),
                        recipient: recipient.clone(),
                        amount_zat,
                        fee_zat: options.fee_zat,
                        excluded_inputs: journal.reserved_inputs()?,
                    };
                    zdn::foundation::write_private(&request_path, &serde_json::to_vec(&request)?)?;
                    let plan = backend_json(
                        &backend,
                        &[
                            Path::new("prepare-payment"),
                            &key,
                            &history_path,
                            &mempool_path,
                            &request_path,
                            &plan_path,
                        ],
                        Some(&plan_path),
                    )?;
                    ensure!(
                        plan["kind"] == kind
                            && plan["amount_zat"] == amount_zat
                            && plan["history_sha256"] == history.digest
                            && plan["tip_hash"] == history.tip.hash
                            && plan["mempool_sha256"] == pending.digest,
                        "prepared plan differs from requested snapshot/payment"
                    );
                    // Commit reservations immediately. Recheck failures must never cause
                    // the saved plan/history to be replaced on explicit resume.
                    let inputs: Vec<journal::Input> = Deserialize::deserialize(&plan["inputs"])
                        .map_err(|_| eyre::eyre!("invalid prepared payment inputs"))?;
                    record = journal.reserve(id, plan, inputs)?;
                    pending.recheck(&mut |m, p| rpc.read(m, p))?;
                    ensure!(
                        history.observe(&mut |m, p| rpc.read(m, p))?["scan_lag_blocks"] == 0,
                        "chain tip changed before reservation; resume operation"
                    );
                } else {
                    // Crash after the exclusive backend plan write but before the
                    // journal commit: preserve its original snapshots and inputs.
                    regular(&plan_path, true)?;
                    let plan: Value = zdn::foundation::read_json(&plan_path)?;
                    let inputs = Deserialize::deserialize(&plan["inputs"])
                        .map_err(|_| eyre::eyre!("invalid recovered payment inputs"))?;
                    record = journal.reserve(id, plan, inputs)?;
                }
            }
            if record.signed.is_none() {
                let signing_started = record.outcome == journal::Outcome::Signing;
                record = journal.start_signing(id)?;
                ensure!(
                    !(signing_started || ambiguous_resume) || envelope_path.exists(),
                    "signing may have started but the envelope is missing; operation quarantined; restore original evidence, never construct a replacement"
                );
            }
            let plan = record.plan.as_ref().context("payment plan missing")?;
            regular(&request_path, true)?;
            let request: Request = zdn::foundation::read_json(&request_path)?;
            let allocation = if v2 { &plan["allocation"] } else { plan };
            ensure!(
                request.schema_version == 1
                    && request.kind == kind
                    && request.recipient == recipient
                    && request.amount_zat == amount_zat
                    && request.fee_zat == options.fee_zat
                    && allocation["request_sha256"]
                        == hex::encode(Sha256::digest(serde_json::to_vec(&request)?)),
                "authenticated payment plan differs from saved intent"
            );
            regular(&plan_path, true)?;
            let saved_plan: Value = zdn::foundation::read_json(&plan_path)?;
            ensure!(&saved_plan == plan, "saved plan differs from journal");
            if record.signed.is_none() {
                let envelope = if envelope_path.exists() {
                    regular(&envelope_path, true)?;
                    zdn::foundation::read_json(&envelope_path)?
                } else {
                    if v2 {
                        snapshot::construct(
                            &backend,
                            &key,
                            &identity_path,
                            &directory.join("snapshot.json"),
                            &plan_path,
                            &envelope_path,
                        )?
                    } else {
                        backend_json(
                            &backend,
                            &[
                                Path::new("construct-payment"),
                                &key,
                                &history_path,
                                &mempool_path,
                                &plan_path,
                                &envelope_path,
                            ],
                            Some(&envelope_path),
                        )?
                    }
                };
                check_signed(
                    &backend,
                    &key,
                    &history_path,
                    &plan_path,
                    &envelope_path,
                    plan,
                    &envelope,
                )?;
                record = journal.sign(id, envelope)?;
            }
            let envelope = record.signed.take().context("signed transaction missing")?;
            check_signed(
                &backend,
                &key,
                &history_path,
                &plan_path,
                &envelope_path,
                record.plan.as_ref().unwrap(),
                &envelope,
            )?;
            let txid = envelope["txid"]
                .as_str()
                .context("signed transaction ID missing")?;
            let raw = envelope["raw_transaction_hex"]
                .as_str()
                .context("signed transaction bytes missing")?;
            let seen = confirmation_count(rpc, &mut journal, &mut record, txid)?.is_some();
            if !seen && !matches!(record.outcome, journal::Outcome::NodeRejected { .. }) {
                // Must be on disk BEFORE any possible write to the network. A lost
                // reply, cancellation or crash leaves OutcomeUnknown, never Signed.
                record = journal.dispatch(id)?;
                let outcome = match rpc.submit(raw) {
                    Ok(SubmissionOutcome::Acknowledged { txid: received }) if received == txid => {
                        Some(journal::Outcome::Acknowledged)
                    }
                    Ok(SubmissionOutcome::NodeRejected { code }) => {
                        Some(journal::Outcome::NodeRejected { code })
                    }
                    // Gateway refusal after dispatch is still retained uncertainty;
                    // the next explicit resume observes before reusing exact bytes.
                    _ => None,
                };
                if let Some(outcome) = outcome {
                    record = journal.observe(id, outcome)?;
                }
            }
            let started = std::time::Instant::now();
            loop {
                if matches!(record.outcome, journal::Outcome::NodeRejected { .. }) {
                    break;
                }
                observed_confirmations = confirmation_count(rpc, &mut journal, &mut record, txid)?;
                if let Some(confirmations) = observed_confirmations {
                    if confirmations >= options.confirmations {
                        break;
                    }
                }
                if started.elapsed() >= Duration::from_secs(options.wait_secs) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            Ok(())
        },
    );
    // Publish the durable outcome even when tunnel cleanup or polling failed.
    let current = journal.load(id)?;
    crate::print_json(
        &json!({"schema_version":1,"operation_id":id,"network_id":current.network_id,
        "sender":sender,"recipient":recipient,"amount_zat":amount_zat,
        "fee_zat":current.plan.as_ref().map(|p| if p["schema_version"] == 2 { &p["allocation"]["fee_zat"] } else { &p["fee_zat"] }),
        "txid":current.signed.as_ref().map(|p| &p["txid"]),"outcome":current.outcome,
        "confirmations":observed_confirmations,"required_confirmations":options.confirmations,"reservations_retained":true}),
    )?;
    result?;
    ensure!(
        observed_confirmations.is_some_and(|n| n >= options.confirmations)
            && matches!(current.outcome, journal::Outcome::Confirmed { .. }),
        "payment not confirmed to the requested depth; inspect tx or resume this operation, never create a replacement"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.check_signed")
)]
pub(super) fn check_signed(
    backend: &Path,
    key: &Path,
    history: &Path,
    plan_path: &Path,
    envelope_path: &Path,
    plan: &Value,
    envelope: &Value,
) -> Result<()> {
    if plan["schema_version"] == 2 {
        let directory = plan_path
            .parent()
            .context("missing payment evidence directory")?;
        return snapshot::check(
            backend,
            key,
            &directory.join("identity.json"),
            &directory.join("snapshot.json"),
            plan_path,
            envelope_path,
            plan,
            envelope,
        );
    }
    ensure!(
        plan["schema_version"] == 1,
        "unsupported saved payment version"
    );
    ensure!(
        envelope["plan"] == *plan && envelope["broadcast"] == false,
        "signed envelope differs from saved plan"
    );
    regular(envelope_path, true)?;
    let saved: Value = zdn::foundation::read_json(envelope_path)?;
    ensure!(&saved == envelope, "saved signed bytes differ from journal");
    let checked = backend_json(
        backend,
        &[
            Path::new("check-transaction"),
            key,
            history,
            plan_path,
            envelope_path,
        ],
        None,
    )?;
    ensure!(
        checked["valid"] == true
            && checked["broadcast"] == false
            && checked["txid"] == envelope["txid"]
            && checked["request_sha256"] == plan["request_sha256"]
            && checked["plan_authorization_hex"] == plan["plan_authorization_hex"],
        "backend did not authenticate saved transaction"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.confirmation_count")
)]
fn confirmation_count(
    rpc: &mut WalletRpc<'_>,
    journal: &mut journal::Store,
    record: &mut journal::Record,
    txid: &str,
) -> Result<Option<u32>> {
    let Some(value) = rpc.transaction(txid)? else {
        if matches!(record.outcome, journal::Outcome::Confirmed { .. }) {
            *record = journal.observe(record.operation_id, journal::Outcome::Reorged)?;
        }
        return Ok(None);
    };
    ensure!(
        value["txid"] == txid,
        "node returned a different transaction"
    );
    let confirmations = match value.get("confirmations") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_u64()
            .context("invalid transaction confirmation count")?,
    };
    // The node can retain orphan history outside both the active chain and
    // mempool. Historical presence alone is not current acceptance. A failed
    // or malformed mempool read must still refuse, never authorize dispatch.
    if confirmations == 0
        && value["in_active_chain"] == false
        && !mempool::txids(&mut |m, p| rpc.read(m, p))?.contains(txid)
    {
        if matches!(record.outcome, journal::Outcome::Confirmed { .. }) {
            *record = journal.observe(record.operation_id, journal::Outcome::Reorged)?;
        }
        return Ok(None);
    }
    if confirmations > 0 {
        let height = value["height"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .context("invalid transaction height")?;
        let hash = value["blockhash"]
            .as_str()
            .context("missing transaction block hash")?;
        ensure!(hex_bytes(hash, 32), "invalid transaction block hash");
        let canonical = rpc.read("getblockhash", json!([height]))?;
        ensure!(
            canonical == hash,
            "transaction inclusion is no longer canonical; retry observation"
        );
        if record.attempts > 0 {
            if matches!(&record.outcome, journal::Outcome::Confirmed { height: previous_height, hash: previous_hash }
                if *previous_height != height || previous_hash != hash)
            {
                *record = journal.observe(record.operation_id, journal::Outcome::Reorged)?;
            }
            *record = journal.observe(
                record.operation_id,
                journal::Outcome::Confirmed {
                    height,
                    hash: hash.to_owned(),
                },
            )?;
        }
    } else if matches!(record.outcome, journal::Outcome::Confirmed { .. }) {
        *record = journal.observe(record.operation_id, journal::Outcome::Reorged)?;
    } else if record.attempts > 0 {
        *record = journal.observe(record.operation_id, journal::Outcome::Acknowledged)?;
    }
    Ok(Some(
        u32::try_from(confirmations).context("invalid confirmation count")?,
    ))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.payment.tx")
)]
pub fn tx(args: TxArgs) -> Result<()> {
    ensure!(hex_bytes(&args.txid, 32), "invalid transaction ID");
    let txid = args.txid.to_ascii_lowercase();
    let (_, identity) = args.history.selection()?;
    let root = crate::data_path(args.wallet_dir, "wallets")?;
    store::private_dir(&root, true)?;
    let scope = root.join(identity.network_id.to_string());
    store::private_dir(&scope, true)?;
    let mut journal =
        journal::Store::open(&scope, identity.network_id, &identity.consensus_fingerprint)?;
    let mut record = journal
        .records()?
        .into_iter()
        .find(|r| r.signed.as_ref().is_some_and(|e| e["txid"] == txid));
    let value = connect_cli::with_wallet_rpc(args.history, Some(identity), |_, _, rpc| {
        if let Some(record) = record.as_mut() {
            let confirmations = confirmation_count(rpc, &mut journal, record, &txid)?;
            Ok(
                json!({"schema_version":1,"txid":txid,"operation_id":record.operation_id,"outcome":record.outcome,
                "confirmations":confirmations,"reservations_retained":true}),
            )
        } else {
            Ok(
                json!({"schema_version":1,"txid":txid,"transaction":rpc.transaction(&txid)?,"local_operation":null}),
            )
        }
    })?;
    crate::print_json(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_decimal_amounts() {
        assert_eq!(amount("1.00000001").unwrap(), 100_000_001);
        assert_eq!(amount("0.00000001").unwrap(), 1);
        assert_eq!(amount("21000000").unwrap(), 2_100_000_000_000_000);
        for bad in [
            "0",
            "-1",
            "+1",
            "1e2",
            "1.",
            ".1",
            "0.000000001",
            "21000000.00000001",
            "1.2.3",
        ] {
            assert!(amount(bad).is_err(), "{bad}");
        }
    }
}
