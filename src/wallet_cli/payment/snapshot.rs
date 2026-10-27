//! Versioned snapshot contract; orchestration, reservations and dispatch stay shared.
use super::*;
use zdn::{chain::manifest::ConsensusManifest, endpoints::EndpointFile};

const CAPABILITY: &str = "ironwood-wallet-snapshot-payment/v2";

pub(super) fn capable(backend: &Path) -> Result<bool> {
    // Old pinned backends predate capability discovery. Only an explicit v2
    // advertisement selects v2; saved plans never use this fallback.
    let mut command = Command::new(backend);
    command.arg("capabilities");
    let result = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(30))?;
    if !result.success {
        return Ok(false);
    }
    let value: Value = serde_json::from_str(&result.stdout)
        .map_err(|_| eyre::eyre!("invalid backend capabilities; diagnostics redacted"))?;
    ensure!(
        value["schema_version"] == 1 && value["capabilities"].is_array(),
        "invalid backend capabilities"
    );
    Ok(value["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == CAPABILITY))
}

pub(super) fn preflight(backend: &Path) -> Result<()> {
    ensure!(
        capable(backend)?,
        "saved v2 payment requires ironwood-wallet-snapshot-payment/v2"
    );
    super::super::sync::preflight(backend)
}

// Field order is the backend's canonical typed plan hash contract, not Value's
// alphabetical map order. Keep these types independent of mutable scan state.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    network_id: String,
    consensus_fingerprint: String,
    network: String,
    genesis_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    ironwood_address_hex: String,
    value_zat: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    kind: String,
    recipient_ironwood_address_hex: String,
    amount_zat: u64,
    fee_zat: u64,
    change_zat: u64,
    inputs: Vec<journal::Input>,
    outputs: Vec<Output>,
    request_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    identity: Identity,
    snapshot_sha256: String,
    state_sha256: String,
    generation: u64,
    tip_height: u32,
    tip_hash: String,
    anchor_hex: String,
    mempool_sha256: String,
    allocation: Allocation,
    plan_authorization_hex: String,
}
impl Plan {
    fn parse(value: &Value) -> Result<Self> {
        let p: Self = serde_json::from_value(value.clone())
            .map_err(|_| eyre::eyre!("invalid snapshot payment plan; diagnostics redacted"))?;
        ensure!(
            p.schema_version == 2
                && hex_bytes(&p.snapshot_sha256, 32)
                && hex_bytes(&p.state_sha256, 32)
                && hex_bytes(&p.tip_hash, 32)
                && hex_bytes(&p.anchor_hex, 32)
                && hex_bytes(&p.mempool_sha256, 32)
                && hex_bytes(&p.allocation.request_sha256, 32)
                && hex_bytes(&p.plan_authorization_hex, 64),
            "invalid snapshot payment plan"
        );
        Ok(p)
    }
    fn hash(mut self) -> Result<String> {
        self.plan_authorization_hex.clear();
        let mut h = Sha256::new();
        h.update(b"ironwood-wallet-snapshot-payment-plan/v2\0");
        h.update(serde_json::to_vec(&self)?);
        Ok(hex::encode(h.finalize()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedPlan {
    schema_version: u32,
    capability: String,
    plan_verified: bool,
    plan_sha256: String,
    snapshot_sha256: String,
    state_sha256: String,
    generation: u64,
    payment_enabled: bool,
    canonicality: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    backend: &Path,
    key: &Path,
    manifest: &ConsensusManifest,
    identity: &EndpointFile,
    rpc: &mut WalletRpc<'_>,
    directory: &Path,
    binding: &Value,
    journal: &mut journal::Store,
    id: Uuid,
    kind: &str,
    recipient: &str,
    amount_zat: u64,
    fee_zat: Option<u64>,
) -> Result<journal::Record> {
    let plan_path = directory.join("plan.json");
    let snapshot = directory.join("snapshot.json");
    let identity_path = directory.join("identity.json");
    let request_path = directory.join("request.json");
    let marker = directory.join("snapshot-started");
    let pending = if !snapshot.exists() && !plan_path.exists() {
        ensure!(
            !marker.exists(),
            "original snapshot missing after publication attempt; preserve evidence; operation quarantined"
        );
        let progress = super::super::sync::current(backend, key, manifest, identity, 4, rpc)?;
        ensure!(
            progress["outcome"] == "current_at_observation",
            "wallet sync incomplete; rerun this operation or wallet sync; payment not prepared"
        );
        super::super::maintenance::reconcile(journal, rpc)?;
        super::check_sender(journal, &journal.load(id)?.request, id)?;
        let tip = history::tip(&mut |m, p| rpc.read(m, p))?;
        ensure!(
            progress["committed_height"] == tip.height,
            "chain advanced after sync; resume operation"
        );
        let pending = mempool::collect(&mut |m, p| rpc.read(m, p))?;
        let request = Request {
            schema_version: 1,
            kind: kind.into(),
            recipient: recipient.into(),
            amount_zat,
            fee_zat,
            excluded_inputs: journal.reserved_inputs()?,
        };
        // Only pre-snapshot staging is replaceable. Published snapshot/request
        // pairs and plans are immutable, even if the journal commit was lost.
        zdn::foundation::write_private(&request_path, &serde_json::to_vec(&request)?)?;
        let context = directory.join("context.json");
        zdn::foundation::write_private(
            &context,
            &serde_json::to_vec(
                &json!({"schema_version":2,"request":request,"mempool":serde_json::from_slice::<Value>(&pending.bytes)?}),
            )?,
        )?;
        rpc.check()?;
        crate::write_new_file(&marker, b"snapshot/v2 publication attempted\n")?;
        let frozen = backend_version(
            backend,
            &[
                Path::new("snapshot-create"),
                key,
                &identity_path,
                &key.parent().unwrap().join("scan-v2.sqlite"),
                &context,
                &snapshot,
            ],
            None,
            2,
        )?;
        ensure!(
            frozen["tip_height"] == tip.height
                && frozen["tip_hash"] == tip.hash
                && frozen["mempool_sha256"] == pending.digest,
            "snapshot differs from current preparation observation"
        );
        history::observe_tip(&tip, &mut |m, p| rpc.read(m, p))?;
        Some(pending)
    } else {
        None
    };
    regular(&snapshot, true)?;
    regular(&request_path, true)?;
    if !plan_path.exists() {
        backend_version(
            backend,
            &[
                Path::new("prepare-snapshot-payment"),
                key,
                &identity_path,
                &snapshot,
                &plan_path,
            ],
            Some(&plan_path),
            2,
        )?;
    }
    regular(&plan_path, true)?;
    ensure!(
        fs::metadata(&plan_path)?.len() <= 64 * 1024,
        "snapshot plan exceeds 64 KiB"
    );
    let plan: Value = zdn::foundation::read_json(&plan_path)?;
    let typed = Plan::parse(&plan)?;
    let request: Request = zdn::foundation::read_json(&request_path)?;
    ensure!(
        plan["identity"] == *binding
            && request.schema_version == 1
            && request.kind == kind
            && request.recipient == recipient
            && request.amount_zat == amount_zat
            && request.fee_zat == fee_zat
            && typed.allocation.kind == kind
            && typed.allocation.amount_zat == amount_zat
            && fee_zat.is_none_or(|fee| fee == typed.allocation.fee_zat)
            && typed.allocation.request_sha256
                == hex::encode(Sha256::digest(serde_json::to_vec(&request)?)),
        "snapshot plan differs from original intent"
    );
    let checked: CheckedPlan = serde_json::from_value(backend_version(
        backend,
        &[
            Path::new("check-snapshot-plan"),
            key,
            &identity_path,
            &snapshot,
            &plan_path,
        ],
        None,
        2,
    )?)
    .map_err(|_| eyre::eyre!("invalid snapshot plan check; diagnostics redacted"))?;
    ensure!(
        checked.schema_version == 2
            && checked.capability == "ironwood-wallet-snapshot-payment-plan/v2"
            && checked.plan_verified
            && !checked.payment_enabled
            && checked.canonicality == "original_preparation_only_not_live_checked"
            && checked.snapshot_sha256 == typed.snapshot_sha256
            && checked.state_sha256 == typed.state_sha256
            && checked.generation == typed.generation
            && checked.plan_sha256 == Plan::parse(&plan)?.hash()?,
        "backend did not authenticate original snapshot plan"
    );
    let record = journal.reserve(id, plan, typed.allocation.inputs)?;
    if let Some(pending) = pending {
        pending.recheck(&mut |m, p| rpc.read(m, p))?;
        let tip = history::Tip {
            height: typed.tip_height,
            hash: typed.tip_hash,
        };
        let observed = history::observe_tip(&tip, &mut |m, p| rpc.read(m, p))?;
        ensure!(
            observed.height == tip.height,
            "chain advanced before reservation; resume operation"
        );
    }
    Ok(record)
}

pub(super) fn construct(
    backend: &Path,
    key: &Path,
    identity: &Path,
    snapshot: &Path,
    plan: &Path,
    envelope: &Path,
) -> Result<Value> {
    regular(snapshot, true)?;
    backend_version(
        backend,
        &[
            Path::new("construct-snapshot-payment"),
            key,
            identity,
            snapshot,
            plan,
            envelope,
        ],
        Some(envelope),
        2,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    plan: Plan,
    txid: String,
    raw_transaction_hex: String,
    broadcast: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checked {
    schema_version: u32,
    valid: bool,
    broadcast: bool,
    txid: String,
    plan_sha256: String,
    snapshot_sha256: String,
    state_sha256: String,
    request_sha256: String,
    canonicality: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check(
    backend: &Path,
    key: &Path,
    identity: &Path,
    snapshot: &Path,
    plan_path: &Path,
    envelope_path: &Path,
    plan: &Value,
    envelope: &Value,
) -> Result<()> {
    regular(snapshot, true)?;
    regular(envelope_path, true)?;
    let saved: Value = zdn::foundation::read_json(envelope_path)?;
    let e: Envelope = serde_json::from_value(envelope.clone())
        .map_err(|_| eyre::eyre!("invalid snapshot transaction envelope; diagnostics redacted"))?;
    let p = Plan::parse(plan)?;
    ensure!(
        saved == *envelope
            && envelope["plan"] == *plan
            && e.schema_version == 2
            && e.plan.schema_version == 2
            && !e.broadcast
            && hex_bytes(&e.txid, 32)
            && !e.raw_transaction_hex.is_empty()
            && e.raw_transaction_hex.len().is_multiple_of(2)
            && hex::decode(&e.raw_transaction_hex).is_ok(),
        "invalid original snapshot transaction envelope"
    );
    let c: Checked = serde_json::from_value(backend_version(
        backend,
        &[
            Path::new("check-snapshot-transaction"),
            key,
            identity,
            snapshot,
            plan_path,
            envelope_path,
        ],
        None,
        2,
    )?)
    .map_err(|_| eyre::eyre!("invalid snapshot transaction check; diagnostics redacted"))?;
    ensure!(
        c.schema_version == 2
            && c.valid
            && !c.broadcast
            && c.txid == e.txid
            && c.snapshot_sha256 == p.snapshot_sha256
            && c.state_sha256 == p.state_sha256
            && c.request_sha256 == p.allocation.request_sha256
            && c.plan_sha256 == p.hash()?
            && c.canonicality == "original_preparation_only_not_live_checked",
        "backend did not authenticate original snapshot transaction"
    );
    Ok(())
}
