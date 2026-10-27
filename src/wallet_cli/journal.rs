//! Local payment intent and reservations, serialized by one network-wide lock.
//!
//! The coordinator must retain this store through backend planning/signing and
//! network dispatch. Only a successful `dispatch` authorizes a network write;
//! errors (including fsync errors) never establish that a write did not happen.
//! Request/plan/envelope JSON is opaque public backend data, not key material.
//! As with the wallet store, paths must remain under caller control: these
//! checks are not protection against a hostile owner racing filesystem changes.
use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

mod catalog;
pub use catalog::ChainPoint;

const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Ironwood { txid: String, action_index: usize },
    P2pkh { txid: String, output_index: u32 },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::enum_variant_names)] // Explicit uncertainty is part of the public coordinator API.
pub enum Outcome {
    Prepared,
    Reserved,
    Signing,
    Signed,
    OutcomeUnknown,
    Acknowledged,
    NodeRejected { code: i32 },
    NotDispatched,
    Confirmed { height: u32, hash: String },
    Reorged,
    Cancelled { proposal_sha256: String },
}

impl<'de> Deserialize<'de> for Outcome {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.outcome.deserialize")
    )]
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        // Serde's internally tagged unit variants ignore extra fields even with
        // deny_unknown_fields. Empty struct variants enforce the wire contract
        // without changing the coordinator-facing unit variants.
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Strict {
            Prepared {},
            Reserved {},
            Signing {},
            Signed {},
            OutcomeUnknown {},
            Acknowledged {},
            NodeRejected { code: i32 },
            NotDispatched {},
            Confirmed { height: u32, hash: String },
            Reorged {},
            Cancelled { proposal_sha256: String },
        }
        Ok(match Strict::deserialize(deserializer)? {
            Strict::Prepared {} => Self::Prepared,
            Strict::Reserved {} => Self::Reserved,
            Strict::Signing {} => Self::Signing,
            Strict::Signed {} => Self::Signed,
            Strict::OutcomeUnknown {} => Self::OutcomeUnknown,
            Strict::Acknowledged {} => Self::Acknowledged,
            Strict::NodeRejected { code } => Self::NodeRejected { code },
            Strict::NotDispatched {} => Self::NotDispatched,
            Strict::Confirmed { height, hash } => Self::Confirmed { height, hash },
            Strict::Reorged {} => Self::Reorged,
            Strict::Cancelled { proposal_sha256 } => Self::Cancelled { proposal_sha256 },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub operation_id: Uuid,
    pub network_id: Uuid,
    pub consensus_fingerprint: String,
    pub wallet_id: Uuid,
    pub request: Value,
    pub plan: Option<Value>,
    pub inputs: Vec<Input>,
    pub signed: Option<Value>,
    pub attempts: u32,
    pub outcome: Outcome,
}

pub struct Store {
    network_directory: PathBuf,
    directory: PathBuf,
    network_id: Uuid,
    consensus_fingerprint: String,
    _lock: File,
}

impl Store {
    /// Open an existing private ROOT/NETWORK_UUID scope. The lock is deliberately
    /// outside wallet-name directories: aliases of a key must share reservations.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.open")
    )]
    pub fn open(
        network_directory: &Path,
        network_id: Uuid,
        consensus_fingerprint: &str,
    ) -> Result<Self> {
        Self::open_mode(network_directory, network_id, consensus_fingerprint, false)
    }

    pub fn open_maintenance(
        network_directory: &Path,
        network_id: Uuid,
        consensus_fingerprint: &str,
    ) -> Result<Self> {
        Self::open_mode(network_directory, network_id, consensus_fingerprint, true)
    }

    fn open_mode(
        network_directory: &Path,
        network_id: Uuid,
        consensus_fingerprint: &str,
        maintenance: bool,
    ) -> Result<Self> {
        ensure!(!network_id.is_nil(), "invalid journal network identity");
        ensure!(
            canonical_hash(consensus_fingerprint),
            "invalid consensus fingerprint"
        );
        let network_directory = std::path::absolute(network_directory)?;
        private_directory(&network_directory)?;
        private_directory(network_directory.parent().context("missing journal root")?)?;
        let lock_path = network_directory.join("payments.lock");
        no_symlinks(&lock_path)?;
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                private_file(&lock_path)?;
                OpenOptions::new().read(true).write(true).open(&lock_path)?
            }
            Err(error) => return Err(error.into()),
        };
        lock.try_lock_exclusive()
            .context("another local process is using network payments")?;
        lock.sync_all()?;
        File::open(&network_directory)?.sync_all()?;
        let directory = network_directory.join("payments");
        no_symlinks(&directory)?;
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        private_directory(&directory)?;
        File::open(&directory)?.sync_all()?;
        File::open(&network_directory)?.sync_all()?;
        let store = Self {
            network_directory,
            directory,
            network_id,
            consensus_fingerprint: consensus_fingerprint.into(),
            _lock: lock,
        };
        if !maintenance {
            store.records()?;
        }
        Ok(store)
    }

    /// Existing identities are never resumed or reset implicitly. The caller
    /// must load and explicitly match both wallet_id and request when resuming.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.begin")
    )]
    pub fn begin(&mut self, id: Uuid, wallet_id: Uuid, request: Value) -> Result<Record> {
        let record = Record {
            schema_version: SCHEMA_VERSION,
            operation_id: id,
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint.clone(),
            wallet_id,
            request,
            plan: None,
            inputs: Vec::new(),
            signed: None,
            attempts: 0,
            outcome: Outcome::Prepared,
        };
        self.publish(&record, true, &self.records()?)?;
        Ok(record)
    }

    pub fn load(&self, id: Uuid) -> Result<Record> {
        if self.catalog_authority()? {
            return self.catalog_load(id);
        }
        self.records()?
            .into_iter()
            .find(|record| record.operation_id == id)
            .context("payment operation not found")
    }

    /// Validate the entire journal, not just one wallet's view. Unknown files
    /// (including abandoned temporary files) fail closed for manual inspection;
    /// this module never removes arbitrary pre-existing files.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.read_validate")
    )]
    pub fn records(&self) -> Result<Vec<Record>> {
        if self.catalog_authority()? {
            return self.catalog_active();
        }
        self.legacy_records()
    }

    fn legacy_records(&self) -> Result<Vec<Record>> {
        self.check_directories()?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            ensure!(
                paths.len() < MAX_RECORDS,
                "payment operation count exceeds limit"
            );
            paths.push(entry?.path());
        }
        paths.sort();
        let mut records = Vec::new();
        let mut total = 0;
        let mut bytes = Vec::new();
        for path in paths {
            private_file(&path)?;
            let file = File::open(&path)?;
            bytes.clear();
            file.take(MAX_RECORD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= MAX_RECORD_BYTES,
                "payment record exceeds size limit"
            );
            total += bytes.len();
            ensure!(
                total <= MAX_TOTAL_BYTES,
                "payment journal exceeds size limit"
            );
            let record: Record = serde_json::from_slice(&bytes)
                .map_err(|_| eyre::eyre!("invalid payment record; diagnostics redacted"))?;
            self.validate(&record)?;
            ensure!(
                path == self.path(record.operation_id),
                "payment record filename/identity mismatch"
            );
            records.push(record);
        }
        let mut inputs = HashSet::new();
        for record in records.iter().filter(|record| !record.cancelled()) {
            for input in &record.inputs {
                ensure!(
                    inputs.insert(input),
                    "conflicting payment input reservations"
                );
            }
        }
        Ok(records)
    }

    /// Only explicitly cancelled unsigned records release reservations.
    pub fn reserved_inputs(&self) -> Result<Vec<Input>> {
        Ok(self
            .records()?
            .into_iter()
            .filter(|record| !record.cancelled())
            .flat_map(|record| record.inputs)
            .collect())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.reserve")
    )]
    pub fn reserve(&mut self, id: Uuid, plan: Value, inputs: Vec<Input>) -> Result<Record> {
        self.change(id, |record| {
            if let Some(saved) = &record.plan {
                ensure!(
                    saved == &plan && record.inputs == inputs,
                    "payment plan is immutable"
                );
                return Ok(false);
            }
            record.plan = Some(plan);
            record.inputs = inputs;
            // Only a newly committed plan proves that the signer never ran.
            // Idempotently loading a legacy plan must not grant that proof.
            record.outcome = Outcome::Reserved;
            Ok(true)
        })
    }

    /// Local-only proposal; hashes canonical typed JSON, never filesystem paths.
    pub fn cancellation(&self, id: Uuid, apply: Option<&str>) -> Result<Value> {
        let record = self.load(id)?;
        let reason = record.cancellation_reason();
        let mut digest = Sha256::new();
        digest.update(b"zdn.wallet.cancel-payment.v1\0");
        digest.update(serde_json::to_vec(&record)?);
        let proposal = hex::encode(digest.finalize());
        if let Some(token) = apply {
            ensure!(
                canonical_hash(token) && token == proposal,
                "stale or invalid cancellation proposal"
            );
            ensure!(reason.is_none(), "payment is not eligible for cancellation");
            self.change(id, |current| {
                ensure!(*current == record, "stale cancellation proposal");
                ensure!(
                    current.cancellation_reason().is_none(),
                    "payment is not eligible for cancellation"
                );
                current.outcome = Outcome::Cancelled {
                    proposal_sha256: proposal.clone(),
                };
                Ok(true)
            })?;
        }
        Ok(serde_json::json!({
            "operation_id":record.operation_id, "network_id":record.network_id,
            "wallet_id":record.wallet_id, "consensus_fingerprint":record.consensus_fingerprint,
            "request_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&record.request)?)),
            "plan_sha256":record.plan.as_ref().map(|plan| serde_json::to_vec(plan).map(|bytes| hex::encode(Sha256::digest(bytes)))).transpose()?,
            "record_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&record)?)),
            "reviewed_outcome":record.outcome,
            "proposal_sha256":proposal, "eligible":reason.is_none(),
            "reason":reason.unwrap_or("durable unsigned phase; no signing or dispatch"),
            "action":if apply.is_some() { "cancelled" } else if reason.is_none() { "cancel" } else { "refuse" },
            "live_evidence":"unchecked (local-only)",
            "retention":"complete tombstone retained; only indexed unsigned cancellations leave the active budget; no signed settlement archival"
        }))
    }

    /// Persist BEFORE invoking a signer or adopting an existing envelope. Missing
    /// output after this transition is uncertainty, never proof of unsignedness.
    /// The new outcome also makes strict older readers refuse the entire scope.
    pub fn start_signing(&mut self, id: Uuid) -> Result<Record> {
        self.change(id, |record| {
            ensure!(
                record.plan.is_some(),
                "payment must be planned before signing"
            );
            ensure!(record.signed.is_none(), "payment already signed");
            if record.outcome == Outcome::Signing {
                return Ok(false);
            }
            ensure!(
                matches!(
                    record.outcome,
                    Outcome::Prepared | Outcome::Reserved | Outcome::NotDispatched
                ),
                "invalid signing transition"
            );
            record.outcome = Outcome::Signing;
            Ok(true)
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.sign")
    )]
    pub fn sign(&mut self, id: Uuid, envelope: Value) -> Result<Record> {
        self.change(id, |record| {
            if let Some(saved) = &record.signed {
                ensure!(saved == &envelope, "signed payment envelope is immutable");
                return Ok(false);
            }
            ensure!(
                record.outcome == Outcome::Signing,
                "payment signing intent must be durable before signing"
            );
            record.signed = Some(envelope);
            record.outcome = Outcome::Signed;
            Ok(true)
        })
    }

    /// Call immediately BEFORE every network write, including retries of the
    /// same signed envelope. A failed call must not be followed by a write.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.dispatch")
    )]
    pub fn dispatch(&mut self, id: Uuid) -> Result<Record> {
        self.change(id, |record| {
            ensure!(
                record.signed.is_some(),
                "payment must be signed before dispatch"
            );
            ensure!(
                !matches!(record.outcome, Outcome::Confirmed { .. }),
                "confirmed payment requires reorg observation before redispatch"
            );
            record.attempts = record
                .attempts
                .checked_add(1)
                .context("payment attempt count exhausted")?;
            record.outcome = Outcome::OutcomeUnknown;
            Ok(true)
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.observe")
    )]
    pub fn observe(&mut self, id: Uuid, outcome: Outcome) -> Result<Record> {
        self.change(id, |record| {
            match &outcome {
                Outcome::Prepared
                | Outcome::Reserved
                | Outcome::Signing
                | Outcome::Signed
                | Outcome::Cancelled { .. }
                | Outcome::OutcomeUnknown => {
                    eyre::bail!(
                        "use begin/reserve/start_signing/sign/dispatch for payment intent transitions"
                    )
                }
                Outcome::NotDispatched => {
                    if record.outcome == Outcome::Reserved {
                        return Ok(false);
                    }
                    ensure!(
                        record.outcome != Outcome::Signing,
                        "signing uncertainty must be retained"
                    );
                    ensure!(
                        record.attempts == 0,
                        "dispatch attempts cannot be ruled out"
                    );
                }
                Outcome::Reorged => {
                    ensure!(
                        matches!(record.outcome, Outcome::Confirmed { .. } | Outcome::Reorged),
                        "reorg observation requires prior confirmation"
                    );
                }
                _ => {
                    ensure!(
                        record.attempts > 0,
                        "outcome requires prior dispatch intent"
                    );
                }
            }
            if matches!(record.outcome, Outcome::Confirmed { .. }) {
                ensure!(
                    outcome == record.outcome || outcome == Outcome::Reorged,
                    "confirmation must be reorged before changing outcome"
                );
            }
            if record.outcome == outcome {
                return Ok(false);
            }
            record.outcome = outcome;
            Ok(true)
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.change")
    )]
    fn change(&self, id: Uuid, change: impl FnOnce(&mut Record) -> Result<bool>) -> Result<Record> {
        if self.catalog_authority()? {
            let mut record = self.catalog_load(id)?;
            ensure!(
                self.settlement_disposition(id)? == "active",
                "archived or reorg-quarantined payment cannot implicitly resume"
            );
            ensure!(!record.cancelled(), "cancelled payment is terminal");
            if change(&mut record)? {
                self.catalog_publish(&record, false)?;
            }
            return Ok(record);
        }
        // One fresh, globally validated view per transition under the network lock.
        let mut records = self.records()?;
        let index = records
            .iter()
            .position(|record| record.operation_id == id)
            .context("payment operation not found")?;
        ensure!(!records[index].cancelled(), "cancelled payment is terminal");
        if change(&mut records[index])? {
            self.publish(&records[index], false, &records)?;
        }
        Ok(records.swap_remove(index))
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.check_directories")
    )]
    fn check_directories(&self) -> Result<()> {
        private_directory(
            self.network_directory
                .parent()
                .context("missing journal root")?,
        )?;
        private_directory(&self.network_directory)?;
        private_directory(&self.directory)?;
        private_file(&self.network_directory.join("payments.lock"))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.validate")
    )]
    fn validate(&self, record: &Record) -> Result<()> {
        ensure!(
            record.schema_version == SCHEMA_VERSION
                && !record.operation_id.is_nil()
                && !record.wallet_id.is_nil()
                && record.network_id == self.network_id
                && record.consensus_fingerprint == self.consensus_fingerprint,
            "invalid payment record version or identity"
        );
        validate_value(&record.request)?;
        if let Some(plan) = &record.plan {
            validate_value(plan)?;
        } else {
            ensure!(
                record.inputs.is_empty() && record.signed.is_none(),
                "unplanned payment has inputs/envelope"
            );
        }
        if let Some(envelope) = &record.signed {
            validate_value(envelope)?;
        }
        let mut inputs = HashSet::new();
        for input in &record.inputs {
            let (Input::Ironwood { txid, .. } | Input::P2pkh { txid, .. }) = input;
            ensure!(canonical_hash(txid), "invalid payment input transaction ID");
            ensure!(inputs.insert(input), "duplicate payment input selector");
        }
        match &record.outcome {
            Outcome::Cancelled { proposal_sha256 } => ensure!(
                canonical_hash(proposal_sha256) && record.signed.is_none() && record.attempts == 0,
                "invalid cancelled payment"
            ),
            Outcome::Reserved | Outcome::Signing => ensure!(
                record.plan.is_some() && record.signed.is_none() && record.attempts == 0,
                "invalid reserved/signing payment"
            ),
            Outcome::Prepared => ensure!(
                record.signed.is_none() && record.attempts == 0,
                "invalid prepared payment"
            ),
            Outcome::Signed => ensure!(
                record.signed.is_some() && record.attempts == 0,
                "invalid signed payment"
            ),
            Outcome::NotDispatched => {
                ensure!(record.attempts == 0, "invalid nondispatch observation")
            }
            Outcome::Confirmed { hash, .. } => {
                ensure!(canonical_hash(hash), "invalid confirmation block hash");
                ensure!(
                    record.signed.is_some() && record.attempts > 0,
                    "invalid dispatched payment"
                );
            }
            _ => ensure!(
                record.signed.is_some() && record.attempts > 0,
                "invalid dispatched payment"
            ),
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.journal.store.publish")
    )]
    fn publish(&self, record: &Record, create: bool, records: &[Record]) -> Result<()> {
        if self.catalog_authority()? {
            return self.catalog_publish(record, create);
        }
        self.validate(record)?;
        let existing = records
            .iter()
            .find(|saved| saved.operation_id == record.operation_id);
        ensure!(
            existing.is_none() == create,
            "payment operation already exists or is missing"
        );
        ensure!(
            !create || records.len() < MAX_RECORDS,
            "payment operation count exceeds limit"
        );
        let mut total = 0;
        let inputs: HashSet<_> = record.inputs.iter().collect();
        for saved in records {
            if saved.operation_id != record.operation_id {
                // Account for actual on-disk bytes, including whitespace.
                total += fs::metadata(self.path(saved.operation_id))?.len();
                ensure!(
                    record.cancelled()
                        || saved.cancelled()
                        || !saved.inputs.iter().any(|input| inputs.contains(input)),
                    "payment input is already reserved by another operation"
                );
            }
        }
        let bytes = serde_json::to_vec(record)
            .map_err(|_| eyre::eyre!("invalid payment record; diagnostics redacted"))?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "payment record exceeds size limit"
        );
        ensure!(
            total + bytes.len() as u64 <= MAX_TOTAL_BYTES as u64,
            "payment journal exceeds size limit"
        );
        let path = self.path(record.operation_id);
        if create {
            // Publish a complete intent exclusively; never truncate an existing
            // operation, including a malformed one left by external tools.
            let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(&path)?;
            File::open(&self.directory)?.sync_all()?;
        } else {
            private_file(&path)?;
            zdn::foundation::write_private(&path, &bytes)?;
        }
        Ok(())
    }
}

impl Record {
    pub fn cancelled(&self) -> bool {
        matches!(self.outcome, Outcome::Cancelled { .. })
    }

    fn cancellation_reason(&self) -> Option<&'static str> {
        if self.cancelled() {
            Some("cancelled payment is terminal")
        } else if self.signed.is_some() || self.attempts != 0 {
            Some("signed or dispatched payment cannot be cancelled")
        } else {
            match self.outcome {
                Outcome::Reserved => None,
                Outcome::Prepared | Outcome::NotDispatched if self.plan.is_none() => None,
                Outcome::Prepared | Outcome::NotDispatched => {
                    Some("legacy planned payment has ambiguous signing history")
                }
                _ => Some("signing uncertainty or ineligible payment phase"),
            }
        }
    }
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Limit nesting even for in-memory Values; serialization has no depth limit.
// The same bound is checked after parsing and before every durable write.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.journal.validate_value")
)]
fn validate_value(value: &Value) -> Result<()> {
    fn check_depth(value: &Value, depth: usize) -> Result<()> {
        ensure!(depth <= 64, "payment JSON nesting exceeds limit");
        match value {
            Value::Array(values) => {
                for value in values {
                    check_depth(value, depth + 1)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    check_depth(value, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    check_depth(value, 0)?;
    // Option<Value> cannot distinguish Some(Null) from None when deserialized.
    ensure!(!value.is_null(), "payment JSON must not be null");
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.journal.no_symlinks")
)]
fn no_symlinks(path: &Path) -> Result<()> {
    for ancestor in std::path::absolute(path)?.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "payment paths must not contain symlinks"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.journal.private_directory")
)]
fn private_directory(path: &Path) -> Result<()> {
    no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "payment directories must be private real directories"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.journal.private_file")
)]
fn private_file(path: &Path) -> Result<()> {
    no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "payment files must be private regular files"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        scope: PathBuf,
        network: Uuid,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let network = Uuid::new_v4();
            let root = temporary.path().join("wallets");
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let scope = root.join(network.to_string());
            fs::DirBuilder::new().mode(0o700).create(&scope).unwrap();
            Self {
                _temporary: temporary,
                root,
                scope,
                network,
            }
        }

        fn open(&self) -> Store {
            Store::open(&self.scope, self.network, &"ab".repeat(32)).unwrap()
        }

        fn path(&self, id: Uuid) -> PathBuf {
            self.scope.join("payments").join(format!("{id}.json"))
        }
    }

    fn ironwood(index: usize) -> Input {
        Input::Ironwood {
            txid: "12".repeat(32),
            action_index: index,
        }
    }

    fn p2pkh(index: u32) -> Input {
        Input::P2pkh {
            txid: "12".repeat(32),
            output_index: index,
        }
    }

    fn migrate(store: &Store) {
        let preview = store.migrate(None).unwrap();
        store
            .migrate(Some(preview["proposal_sha256"].as_str().unwrap()))
            .unwrap();
    }

    #[test]
    fn settlement_full_legacy_upgrade_and_over_capacity_reorg_guards() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::from_u128(1);
        let wallet = Uuid::new_v4();
        store
            .begin(id, wallet, json!({"sender_public":"key"}))
            .unwrap();
        store
            .reserve(id, json!({"fee":2}), vec![ironwood(1)])
            .unwrap();
        store.start_signing(id).unwrap();
        store
            .sign(id, json!({"txid":"aa".repeat(32),"raw":"ff"}))
            .unwrap();
        store.dispatch(id).unwrap();
        let point = ChainPoint {
            height: 7,
            hash: "bb".repeat(32),
        };
        let first = store
            .observe(
                id,
                Outcome::Confirmed {
                    height: point.height,
                    hash: point.hash.clone(),
                },
            )
            .unwrap();
        for n in 2..=1024 {
            let mut record = first.clone();
            record.operation_id = Uuid::from_u128(n);
            record.inputs = vec![ironwood(n as usize)];
            zdn::foundation::write_private(
                &fixture.path(record.operation_id),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        migrate(&store);
        let preview = store.upgrade_settlements(None).unwrap();
        store
            .upgrade_settlements(Some(preview["proposal_sha256"].as_str().unwrap()))
            .unwrap();
        store
            .reconcile_settlements(&point, |_| Ok(Some(point.hash.clone())))
            .unwrap();
        let preview = store
            .settlement_archive(id, &point, &point, 1, None, |_, _, _| Ok(()))
            .unwrap();
        store
            .settlement_archive(
                id,
                &point,
                &point,
                1,
                Some(preview["proposal_sha256"].as_str().unwrap()),
                |_, _, _| Ok(()),
            )
            .unwrap();
        store
            .begin(Uuid::from_u128(1025), wallet, json!({}))
            .unwrap();
        let last = Uuid::from_u128(1025);
        store
            .reserve(last, json!({"fee":2}), vec![ironwood(1025)])
            .unwrap();
        store.start_signing(last).unwrap();
        store
            .sign(last, json!({"txid":"dd".repeat(32),"raw":"abcd"}))
            .unwrap();
        store.dispatch(last).unwrap();
        store
            .observe(
                last,
                Outcome::Confirmed {
                    height: 7,
                    hash: point.hash.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            store.inventory(None, 1, None).unwrap()["total_operations"],
            1025
        );
        assert_eq!(store.load(id).unwrap(), first);
        let rollback = ChainPoint {
            height: 6,
            hash: "cc".repeat(32),
        };
        assert_eq!(
            store
                .reconcile_settlements(&rollback, |_| Ok(Some(rollback.hash.clone())))
                .unwrap(),
            1
        );
        assert_eq!(store.records().unwrap().len(), 1025);
        assert!(store.reserved_inputs().unwrap().contains(&ironwood(1)));
        assert!(store
            .begin(Uuid::from_u128(1026), wallet, json!({}))
            .is_err());
        drop(store);
        assert_eq!(fixture.open().records().unwrap().len(), 1025);
    }

    #[test]
    fn settled_archive_exact_evidence_depth_fork_and_interruption() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        let wallet = Uuid::new_v4();
        store
            .begin(id, wallet, json!({"sender_public":"same-key"}))
            .unwrap();
        store
            .reserve(id, json!({"fee":3}), vec![ironwood(1)])
            .unwrap();
        store.start_signing(id).unwrap();
        store
            .sign(id, json!({"txid":"aa".repeat(32),"raw":"abcd"}))
            .unwrap();
        store.dispatch(id).unwrap();
        let inclusion = ChainPoint {
            height: 7,
            hash: "bb".repeat(32),
        };
        let tip = ChainPoint {
            height: 8,
            hash: "cc".repeat(32),
        };
        let original = store
            .observe(
                id,
                Outcome::Confirmed {
                    height: 7,
                    hash: inclusion.hash.clone(),
                },
            )
            .unwrap();
        migrate(&store);
        let upgrade = store.upgrade_settlements(None).unwrap();
        store
            .upgrade_settlements(Some(upgrade["proposal_sha256"].as_str().unwrap()))
            .unwrap();
        assert!(store.records().is_err());
        let canonical = |height| {
            Ok(Some(if height == 7 {
                inclusion.hash.clone()
            } else {
                tip.hash.clone()
            }))
        };
        store.reconcile_settlements(&tip, canonical).unwrap();
        assert!(store
            .settlement_archive(id, &tip, &inclusion, 3, None, |_, _, _| Ok(()))
            .is_err());
        assert!(store
            .settlement_archive(id, &tip, &inclusion, 2, None, |_, _, _| eyre::bail!(
                "not included"
            ))
            .is_err());
        let preview = store
            .settlement_archive(id, &tip, &inclusion, 2, None, |txid, _, _| {
                assert_eq!(txid, "aa".repeat(32));
                Ok(())
            })
            .unwrap();
        let token = preview["proposal_sha256"].as_str().unwrap();
        assert!(store
            .settlement_archive(id, &tip, &inclusion, 1, Some(token), |_, _, _| Ok(()))
            .is_err());
        store
            .settlement_archive(id, &tip, &inclusion, 2, Some(token), |_, _, _| Ok(()))
            .unwrap();
        assert_eq!(store.load(id).unwrap(), original);
        assert!(store.records().unwrap().is_empty());
        assert!(store.reserved_inputs().unwrap().is_empty());
        assert!(store.dispatch(id).is_err());
        assert!(store.sign(id, original.signed.clone().unwrap()).is_err());
        assert!(store.begin(id, wallet, json!({})).is_err());
        let inventory = store.inventory(None, 1, None).unwrap();
        assert_eq!(inventory["archived_settlements"], 1);
        assert_eq!(inventory["operations"][0]["disposition"], "archived");
        assert_eq!(inventory["operations"][0]["reserved_inputs"], 0);
        // Append-only cursor needs no archived inclusion-height observation.
        let later = ChainPoint {
            height: 9,
            hash: "dd".repeat(32),
        };
        store
            .reconcile_settlements(&later, |h| {
                assert_ne!(h, 7);
                Ok(Some(if h == 8 {
                    tip.hash.clone()
                } else {
                    later.hash.clone()
                }))
            })
            .unwrap();
        let fork = ChainPoint {
            height: 9,
            hash: "ee".repeat(32),
        };
        assert!(store
            .reconcile_settlements(&fork, |h| if h == 7 {
                eyre::bail!("interrupted")
            } else {
                Ok(Some(fork.hash.clone()))
            })
            .is_err());
        assert!(store.records().is_err());
        assert_eq!(store.load(id).unwrap(), original);
        drop(store);
        assert!(Store::open(&fixture.scope, fixture.network, &"ab".repeat(32)).is_err());
        let mut store =
            Store::open_maintenance(&fixture.scope, fixture.network, &"ab".repeat(32)).unwrap();
        let inventory = store.inventory(None, 1, None).unwrap();
        assert_eq!(inventory["reconciliation_pending"], true);
        assert_eq!(inventory["operations"][0]["operation_id"], id.to_string());
        assert_eq!(
            store.inventory(None, 1, Some(id)).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert_eq!(
            store
                .reconcile_settlements(&fork, |_| Ok(Some(fork.hash.clone())))
                .unwrap(),
            1
        );
        assert_eq!(
            store.inventory(None, 1, None).unwrap()["reconciliation_pending"],
            false
        );
        assert_eq!(
            store.settlement_disposition(id).unwrap(),
            "reorg_quarantine"
        );
        let inventory = store.inventory(None, 1, None).unwrap();
        assert_eq!(
            inventory["operations"][0]["disposition"],
            "reorg_quarantine"
        );
        assert_eq!(inventory["operations"][0]["reserved_inputs"], 1);
        assert_eq!(store.records().unwrap(), vec![original.clone()]);
        assert_eq!(store.reserved_inputs().unwrap(), vec![ironwood(1)]);
        assert!(store.dispatch(id).is_err());
        let replacement = Uuid::new_v4();
        assert!(store
            .begin(replacement, wallet, json!({"sender_public":"same-key"}))
            .is_err());
        store
            .begin(
                replacement,
                Uuid::new_v4(),
                json!({"sender_public":"other-key"}),
            )
            .unwrap();
        assert!(store
            .reserve(replacement, json!({}), vec![ironwood(1)])
            .is_err());
    }

    #[test]
    fn catalog_tombstones_do_not_become_a_lifetime_in_memory_limit() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let first = store
            .begin(Uuid::from_u128(1), Uuid::new_v4(), json!({}))
            .unwrap();
        for n in 2..=1024 {
            let mut record = first.clone();
            record.operation_id = Uuid::from_u128(n);
            zdn::foundation::write_private(
                &fixture.path(record.operation_id),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        migrate(&store);
        assert!(store
            .begin(Uuid::from_u128(1025), first.wallet_id, json!({}))
            .is_err());
        let preview = store.cancellation(first.operation_id, None).unwrap();
        store
            .cancellation(
                first.operation_id,
                Some(preview["proposal_sha256"].as_str().unwrap()),
            )
            .unwrap();
        store
            .begin(Uuid::from_u128(1025), first.wallet_id, json!({}))
            .unwrap();
        assert_eq!(store.records().unwrap().len(), 1024);
        assert_eq!(
            store.inventory(None, 1, None).unwrap()["total_operations"],
            1025
        );
        assert!(store.load(first.operation_id).unwrap().cancelled());
        assert!(store
            .begin(first.operation_id, first.wallet_id, json!({}))
            .is_err());
        assert!(store.migrate(Some(&"00".repeat(32))).is_err());
    }

    #[test]
    fn catalog_preserves_identity_uncertainty_reservations_and_terminal_tombstones() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let wallet = Uuid::new_v4();
        for n in 1..=6 {
            let id = Uuid::from_u128(n);
            store.begin(id, wallet, json!({"amount":n})).unwrap();
            store
                .reserve(id, json!({"fee":n}), vec![ironwood(n as usize)])
                .unwrap();
            if n == 1 {
                let mut legacy = store.load(id).unwrap();
                legacy.outcome = Outcome::Prepared;
                fs::write(fixture.path(id), serde_json::to_vec(&legacy).unwrap()).unwrap();
            } else if n >= 3 {
                store.start_signing(id).unwrap();
                if n >= 4 {
                    store
                        .sign(id, json!({"raw":"aabb","txid":"ab".repeat(32)}))
                        .unwrap();
                }
                if n >= 5 {
                    store.dispatch(id).unwrap();
                }
                if n == 6 {
                    store
                        .observe(
                            id,
                            Outcome::Confirmed {
                                height: 7,
                                hash: "cd".repeat(32),
                            },
                        )
                        .unwrap();
                }
            }
        }
        let before = store.records().unwrap();
        let reservations = store.reserved_inputs().unwrap();
        migrate(&store);
        assert_eq!(store.records().unwrap(), before);
        assert_eq!(store.reserved_inputs().unwrap(), reservations);
        assert_eq!(
            store.cancellation(Uuid::from_u128(1), None).unwrap()["eligible"],
            false
        );
        assert_eq!(
            store.cancellation(Uuid::from_u128(3), None).unwrap()["eligible"],
            false
        );
        for record in &before {
            assert!(store.begin(record.operation_id, wallet, json!({})).is_err());
        }
        let id = Uuid::from_u128(2);
        let preview = store.cancellation(id, None).unwrap();
        store
            .cancellation(id, Some(preview["proposal_sha256"].as_str().unwrap()))
            .unwrap();
        assert!(store.load(id).unwrap().cancelled());
        assert_eq!(store.records().unwrap().len(), 5);
        assert!(!store.reserved_inputs().unwrap().contains(&ironwood(2)));
        assert!(store.begin(id, wallet, json!({})).is_err());
        assert!(store.reserve(id, json!({}), vec![]).is_err());
        assert_eq!(
            store.inventory(None, 2, None).unwrap()["total_operations"],
            6
        );
        let page = store.inventory(Some(Uuid::from_u128(1)), 2, None).unwrap();
        assert_eq!(page["operations"][0]["operation_id"], id.to_string());
        assert_eq!(page["operations"][0]["outcome"]["kind"], "cancelled");
        drop(store);
        assert!(fixture.open().load(id).unwrap().cancelled());
    }

    #[test]
    fn catalog_interrupted_authority_resumes_only_matching_complete_stage() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        let preview = store.migrate(None).unwrap();
        let token = preview["proposal_sha256"].as_str().unwrap();
        migrate(&store);
        let barrier = fixture.scope.join("payments/.catalog-v1");
        fs::remove_file(&barrier).unwrap(); // committed staging DB, authority not yet published
        assert!(store.load(id).is_err());
        let mut changed = store.catalog_load(id).unwrap();
        changed.request = json!({"changed":true});
        fs::write(fixture.path(id), serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(store.migrate(Some(token)).is_err());
        let newer = store.migrate(None).unwrap();
        assert!(store
            .migrate(Some(newer["proposal_sha256"].as_str().unwrap()))
            .is_err());
        changed.request = json!({});
        fs::write(fixture.path(id), serde_json::to_vec(&changed).unwrap()).unwrap();
        store.migrate(Some(token)).unwrap();
        assert_eq!(store.load(id).unwrap(), changed);
        // A durable authority with missing or corrupt storage never resurrects legacy inputs.
        let database = fixture.scope.join("payments.catalog.sqlite");
        let bytes = fs::read(&database).unwrap();
        fs::remove_file(&database).unwrap();
        assert!(store.records().is_err());
        assert!(store.migrate(None).is_err());
        zdn::foundation::write_private(&database, b"corrupt").unwrap();
        assert!(store.records().is_err());
        zdn::foundation::write_private(&database, &bytes).unwrap();
        let marker = fs::read(&barrier).unwrap();
        fs::write(&barrier, b"unsupported").unwrap();
        assert!(store.records().is_err());
        fs::write(&barrier, marker).unwrap();
        assert_eq!(store.load(id).unwrap(), changed);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute_batch("PRAGMA user_version=2").unwrap();
        assert!(store.records().is_err());
        connection.execute_batch("PRAGMA user_version=1; BEGIN IMMEDIATE; UPDATE operations SET data=x'7b7d'; ROLLBACK;").unwrap();
        assert_eq!(store.load(id).unwrap(), changed);
        connection
            .execute("UPDATE operations SET data=?1", [b"{}".as_slice()])
            .unwrap();
        assert!(store.records().is_err());
        assert!(store.reserved_inputs().is_err());
        drop(connection);
        zdn::foundation::write_private(&database, &bytes).unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute("DELETE FROM operations", []).unwrap();
        assert!(store.records().is_err());
        drop(connection);
        zdn::foundation::write_private(&database, &bytes).unwrap();
        let orphan = fixture
            .scope
            .join("payments")
            .join(format!("{}.json", Uuid::new_v4()));
        // A non-canonical filename is never accepted as an original.
        zdn::foundation::write_private(&orphan.with_extension("unknown"), b"{}").unwrap();
        assert!(store.records().is_err());
        fs::remove_file(orphan.with_extension("unknown")).unwrap();
        zdn::foundation::write_private(&orphan, b"{}").unwrap();
        assert!(store.records().is_err());
    }

    #[test]
    fn catalog_incomplete_stage_is_non_destructive_and_requires_inspection() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        let original = fs::read(fixture.path(id)).unwrap();
        let token = store.migrate(None).unwrap()["proposal_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let database = fixture.scope.join("payments.catalog.sqlite");
        zdn::foundation::write_private(&database, b"").unwrap();
        assert!(store.records().is_err());
        let error = store.migrate(Some(&token)).unwrap_err();
        assert!(format!("{error:#}").contains("retain originals"));
        assert_eq!(fs::read(fixture.path(id)).unwrap(), original);
        assert!(!fixture.scope.join("payments/.catalog-v1").exists());
    }

    #[test]
    fn signer_transition_invalidates_cancellation_and_signed_nondispatch_stays_locked() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        store.reserve(id, json!({}), vec![ironwood(0)]).unwrap();
        let proposal = store.cancellation(id, None).unwrap();
        store.start_signing(id).unwrap();
        assert!(store
            .cancellation(id, Some(proposal["proposal_sha256"].as_str().unwrap()))
            .is_err());
        assert_eq!(store.cancellation(id, None).unwrap()["eligible"], false);
        store.sign(id, json!({"raw":"1234"})).unwrap();
        store.observe(id, Outcome::NotDispatched).unwrap();
        let proposal = store.cancellation(id, None).unwrap();
        assert_eq!(proposal["eligible"], false);
        assert!(store
            .cancellation(id, Some(proposal["proposal_sha256"].as_str().unwrap()))
            .is_err());
        assert_eq!(store.reserved_inputs().unwrap(), vec![ironwood(0)]);
    }

    #[test]
    fn cancellation_scope_unsigned_eligibility_and_terminal_contract() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let wallet = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        store.begin(first, wallet, json!({"amount":1})).unwrap();
        store.begin(second, wallet, json!({"amount":1})).unwrap();
        let preview = store.cancellation(first, None).unwrap();
        let token = preview["proposal_sha256"].as_str().unwrap();
        assert!(store.cancellation(second, Some(token)).is_err());
        let other_fixture = Fixture::new();
        let mut other = other_fixture.open();
        other.begin(first, wallet, json!({"amount":1})).unwrap();
        assert!(other.cancellation(first, Some(token)).is_err());
        store.cancellation(first, Some(token)).unwrap();
        let cancelled = store.load(first).unwrap();
        assert!(store.begin(first, wallet, json!({"amount":1})).is_err());
        assert!(store.reserve(first, json!({}), vec![]).is_err());
        assert!(store.start_signing(first).is_err());
        assert!(store.sign(first, json!({})).is_err());
        assert!(store.dispatch(first).is_err());
        assert!(store.observe(first, Outcome::NotDispatched).is_err());
        assert_eq!(store.load(first).unwrap(), cancelled);
        store.observe(second, Outcome::NotDispatched).unwrap();
        let proposal = store.cancellation(second, None).unwrap();
        assert_eq!(proposal["eligible"], true);
        store
            .cancellation(second, Some(proposal["proposal_sha256"].as_str().unwrap()))
            .unwrap();
        // Cancelled wire objects remain strict, including the nested outcome.
        let mut invalid = serde_json::to_value(&cancelled).unwrap();
        invalid["outcome"]["extra"] = json!(true);
        assert!(serde_json::from_value::<Record>(invalid).is_err());
    }

    #[test]
    fn scans_preserve_owned_records_across_varying_file_sizes_and_reread_changes() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let wallet = Uuid::new_v4();
        let mut expected = Vec::new();
        for (index, size) in [8192, 1, 16384, 4096].into_iter().enumerate() {
            expected.push(
                store
                    .begin(
                        Uuid::from_u128(index as u128 + 1),
                        wallet,
                        json!({"payload": index.to_string().repeat(size)}),
                    )
                    .unwrap(),
            );
        }
        let records = store.records().unwrap();
        assert_eq!(records, expected);

        let mut changed = expected[1].clone();
        changed.request = json!({"payload":"changed"});
        fs::write(
            fixture.path(changed.operation_id),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        expected[1] = changed;
        assert_eq!(store.records().unwrap(), expected);
        assert_ne!(records[1], expected[1]);
        assert_eq!(records[0], expected[0]);
        assert_eq!(records[2..], expected[2..]);
    }

    #[test]
    fn recovery_preserves_planned_signed_and_unknown_operations_exactly() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let ids = [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)];
        let wallet = Uuid::new_v4();
        for (index, id) in ids.into_iter().enumerate() {
            store
                .begin(
                    id,
                    wallet,
                    json!({"recipient":"public", "amount":index + 7}),
                )
                .unwrap();
            store
                .reserve(
                    id,
                    json!({"fee":11,"inputs":[index]}),
                    vec![ironwood(index)],
                )
                .unwrap();
        }
        let envelope = json!({"raw":"a4".repeat(1100 * 1024),"txid":"34".repeat(32)});
        store.start_signing(ids[1]).unwrap();
        store.sign(ids[1], envelope.clone()).unwrap();
        store.start_signing(ids[2]).unwrap();
        store.sign(ids[2], json!({"raw":"123456"})).unwrap();
        let unknown = store.dispatch(ids[2]).unwrap();
        assert_eq!(unknown.attempts, 1);
        assert_eq!(unknown.outcome, Outcome::OutcomeUnknown);
        let before = store.records().unwrap();
        drop(store);
        let store = fixture.open();
        assert_eq!(store.records().unwrap(), before);
        assert_eq!(store.load(ids[0]).unwrap().outcome, Outcome::Reserved);
        assert_eq!(store.load(ids[1]).unwrap().signed, Some(envelope));
        assert_eq!(store.load(ids[2]).unwrap(), unknown);
        assert_eq!(
            store.reserved_inputs().unwrap(),
            vec![ironwood(0), ironwood(1), ironwood(2)]
        );
        for path in [fixture.scope.join("payments.lock"), fixture.path(ids[1])] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(fixture.scope.join("payments"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn duplicate_operation_never_resets_wallet_request_or_reservations() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        let wallet = Uuid::new_v4();
        let request = json!({"amount":37});
        store.begin(id, wallet, request.clone()).unwrap();
        let before = store.reserve(id, json!({"fee":3}), vec![p2pkh(5)]).unwrap();
        for (wallet, request) in [
            (wallet, request.clone()),
            (Uuid::new_v4(), request),
            (wallet, json!({"amount":38})),
        ] {
            assert!(store.begin(id, wallet, request).is_err());
            assert_eq!(store.load(id).unwrap(), before);
        }
        drop(store);
        let mut store = fixture.open();
        assert!(store.begin(id, wallet, json!({"amount":37})).is_err());
        assert_eq!(store.load(id).unwrap(), before);
    }

    #[test]
    fn selectors_conflict_across_wallets_but_distinguish_pool_and_index() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        store
            .begin(first, Uuid::new_v4(), json!({"amount":1}))
            .unwrap();
        let unreserved = store
            .begin(second, Uuid::new_v4(), json!({"amount":2}))
            .unwrap();
        let first_saved = store
            .reserve(first, json!({"plan":1}), vec![ironwood(4)])
            .unwrap();
        assert!(store
            .reserve(second, json!({"plan":2}), vec![p2pkh(4), ironwood(4)])
            .is_err());
        assert_eq!(store.load(second).unwrap(), unreserved);
        assert_eq!(store.load(first).unwrap(), first_saved);
        assert!(store
            .reserve(second, json!({"plan":2}), vec![p2pkh(4), p2pkh(4)])
            .is_err());
        assert_eq!(store.load(second).unwrap(), unreserved);
        store
            .reserve(second, json!({"plan":2}), vec![p2pkh(4), ironwood(5)])
            .unwrap();
        assert_eq!(
            store.reserved_inputs().unwrap(),
            vec![ironwood(4), p2pkh(4), ironwood(5)]
        );
    }

    #[test]
    fn plans_and_signed_envelopes_are_immutable_and_idempotent() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store
            .begin(id, Uuid::new_v4(), json!({"amount":31}))
            .unwrap();
        let plan = json!({"fee":7});
        let inputs = vec![ironwood(1), p2pkh(2)];
        let planned = store.reserve(id, plan.clone(), inputs.clone()).unwrap();
        assert_eq!(
            store.reserve(id, plan.clone(), inputs.clone()).unwrap(),
            planned
        );
        for (plan, inputs) in [
            (json!({"fee":8}), inputs.clone()),
            (plan.clone(), vec![p2pkh(2), ironwood(1)]),
            (plan, vec![]),
        ] {
            assert!(store.reserve(id, plan, inputs).is_err());
            assert_eq!(store.load(id).unwrap(), planned);
        }
        store.start_signing(id).unwrap();
        let signed = store
            .sign(id, json!({"raw":"abcdef", "txid":"aa".repeat(32)}))
            .unwrap();
        assert!(store
            .sign(id, json!({"raw":"abcdee", "txid":"aa".repeat(32)}))
            .is_err());
        assert_eq!(store.load(id).unwrap(), signed);
        let unknown = store.dispatch(id).unwrap();
        assert_eq!(store.sign(id, signed.signed.unwrap()).unwrap(), unknown);
        assert_eq!(store.load(id).unwrap(), unknown);
    }

    #[test]
    fn invalid_transitions_leave_durable_state_unchanged() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        let initial = store
            .begin(id, Uuid::new_v4(), json!({"amount":19}))
            .unwrap();
        assert!(store.sign(id, json!({"raw":"1234"})).is_err());
        assert!(store.start_signing(id).is_err());
        assert!(store.dispatch(id).is_err());
        for outcome in [
            Outcome::Prepared,
            Outcome::Reserved,
            Outcome::Signing,
            Outcome::Signed,
            Outcome::OutcomeUnknown,
            Outcome::Acknowledged,
            Outcome::NodeRejected { code: -26 },
            Outcome::Reorged,
            Outcome::Confirmed {
                height: 3,
                hash: "ab".repeat(32),
            },
        ] {
            assert!(store.observe(id, outcome).is_err());
            assert_eq!(store.load(id).unwrap(), initial);
        }
        assert!(store.reserve(id, Value::Null, vec![]).is_err());
        assert!(store
            .reserve(
                id,
                json!({}),
                vec![Input::Ironwood {
                    txid: "AB".repeat(32),
                    action_index: 0
                }]
            )
            .is_err());
        assert_eq!(store.load(id).unwrap(), initial);
        let not_dispatched = store.observe(id, Outcome::NotDispatched).unwrap();
        assert_eq!(not_dispatched.attempts, 0);
        let reserved = store
            .reserve(id, json!({"fee":1}), vec![ironwood(9)])
            .unwrap();
        assert_eq!(reserved.outcome, Outcome::Reserved);
        assert_eq!(store.observe(id, Outcome::NotDispatched).unwrap(), reserved);
        assert!(store.sign(id, json!({"raw":"abcd"})).is_err());
        assert_eq!(store.load(id).unwrap(), reserved);
        store.start_signing(id).unwrap();
        let planned = store.load(id).unwrap();
        assert_eq!(store.start_signing(id).unwrap(), planned);
        assert!(store.observe(id, Outcome::NotDispatched).is_err());
        assert_eq!(store.load(id).unwrap(), planned);
        assert!(store.sign(id, Value::Null).is_err());
        assert_eq!(store.load(id).unwrap(), planned);
        assert_eq!(
            store.sign(id, json!({"raw":"abcd"})).unwrap().outcome,
            Outcome::Signed
        );
    }

    #[test]
    fn outcomes_retries_and_reorgs_never_release_reservations() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store
            .begin(id, Uuid::new_v4(), json!({"amount":17}))
            .unwrap();
        store
            .reserve(id, json!({"fee":2}), vec![ironwood(8)])
            .unwrap();
        store.start_signing(id).unwrap();
        store.sign(id, json!({"raw":"ef1234"})).unwrap();
        store.observe(id, Outcome::NotDispatched).unwrap();
        let first = store.dispatch(id).unwrap();
        assert_eq!(first.attempts, 1);
        assert!(store.observe(id, Outcome::NotDispatched).is_err());
        assert_eq!(store.load(id).unwrap(), first);
        assert!(store.observe(id, Outcome::Reorged).is_err());
        assert_eq!(store.load(id).unwrap(), first);
        store
            .observe(id, Outcome::NodeRejected { code: -26 })
            .unwrap();
        assert_eq!(store.reserved_inputs().unwrap(), vec![ironwood(8)]);
        assert_eq!(store.dispatch(id).unwrap().attempts, 2);
        store.observe(id, Outcome::Acknowledged).unwrap();
        let confirmed = store
            .observe(
                id,
                Outcome::Confirmed {
                    height: 42,
                    hash: "cd".repeat(32),
                },
            )
            .unwrap();
        assert!(store.dispatch(id).is_err());
        assert!(store.observe(id, Outcome::Acknowledged).is_err());
        assert_eq!(store.load(id).unwrap(), confirmed);
        assert_eq!(
            store.observe(id, confirmed.outcome.clone()).unwrap(),
            confirmed
        );
        drop(store);
        let mut store = fixture.open();
        assert_eq!(store.load(id).unwrap(), confirmed);
        assert_eq!(store.reserved_inputs().unwrap(), vec![ironwood(8)]);
        let other = Uuid::new_v4();
        let other_initial = store
            .begin(other, Uuid::new_v4(), json!({"amount":18}))
            .unwrap();
        assert!(store
            .reserve(other, json!({"fee":2}), vec![ironwood(8)])
            .is_err());
        assert_eq!(store.load(other).unwrap(), other_initial);
        store.observe(id, Outcome::Reorged).unwrap();
        let retried = store.dispatch(id).unwrap();
        assert_eq!(retried.attempts, 3);
        assert_eq!(retried.signed, confirmed.signed);
        assert_eq!(retried.plan, confirmed.plan);
        assert_eq!(store.reserved_inputs().unwrap(), vec![ironwood(8)]);
        assert!(store
            .observe(
                id,
                Outcome::Confirmed {
                    height: 43,
                    hash: "bad".into()
                }
            )
            .is_err());
        assert_eq!(store.load(id).unwrap(), retried);
    }

    #[test]
    fn network_lock_is_nonblocking_and_released_on_drop() {
        let fixture = Fixture::new();
        let store = fixture.open();
        let scope = fixture.scope.clone();
        let network = fixture.network;
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(Store::open(&scope, network, &"ab".repeat(32)).is_err())
                .unwrap();
        });
        assert!(receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap());
        worker.join().unwrap();
        drop(store);
        assert!(fixture.open().records().unwrap().is_empty());
    }

    #[test]
    fn nonprivate_directories_and_files_fail_closed_without_chmod() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        drop(store);
        for path in [
            fixture.root.clone(),
            fixture.scope.clone(),
            fixture.scope.join("payments"),
            fixture.scope.join("payments.lock"),
            fixture.path(id),
        ] {
            let original = fs::metadata(&path).unwrap().permissions();
            fs::set_permissions(&path, fs::Permissions::from_mode(original.mode() | 0o040))
                .unwrap();
            assert!(Store::open(&fixture.scope, fixture.network, &"ab".repeat(32)).is_err());
            assert_ne!(fs::metadata(&path).unwrap().permissions().mode() & 0o040, 0);
            fs::set_permissions(&path, original).unwrap();
        }
        assert!(fixture.open().load(id).is_ok());
    }

    #[test]
    fn symlinked_ancestors_lock_directory_and_record_are_rejected() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        drop(store);
        for path in [
            fixture.path(id),
            fixture.scope.join("payments.lock"),
            fixture.scope.join("payments"),
            fixture.scope.clone(),
            fixture.root.clone(),
        ] {
            let backup = path.with_extension("backup");
            fs::rename(&path, &backup).unwrap();
            symlink(&backup, &path).unwrap();
            assert!(Store::open(&fixture.scope, fixture.network, &"ab".repeat(32)).is_err());
            assert!(fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink());
            fs::remove_file(&path).unwrap();
            fs::rename(&backup, &path).unwrap();
        }
        assert!(fixture.open().load(id).is_ok());
    }

    #[test]
    fn malformed_records_identity_mismatches_and_unknown_fields_cannot_reset() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store
            .begin(id, Uuid::new_v4(), json!({"amount":13}))
            .unwrap();
        store.reserve(id, json!({"fee":1}), vec![p2pkh(2)]).unwrap();
        store.start_signing(id).unwrap();
        let valid = store.sign(id, json!({"raw":"aabb"})).unwrap();
        let original = serde_json::to_value(&valid).unwrap();
        let mut malformed = Vec::new();
        for (field, value) in [
            ("schema_version", json!(2)),
            ("operation_id", json!(Uuid::new_v4())),
            ("wallet_id", json!(Uuid::nil())),
            ("network_id", json!(Uuid::new_v4())),
            ("consensus_fingerprint", json!("cd".repeat(32))),
            ("attempts", json!(1)),
            ("plan", Value::Null),
            ("signed", Value::Null),
            ("extra", json!("sensitive sentinel")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            malformed.push(serde_json::to_vec(&changed).unwrap());
        }
        for changed in [
            json!({"kind":"signed", "unexpected":"sensitive sentinel"}),
            json!({"kind":"confirmed","height":1,"hash":"ab".repeat(32)}),
        ] {
            let mut record = original.clone();
            record["outcome"] = changed;
            malformed.push(serde_json::to_vec(&record).unwrap());
        }
        let mut input_unknown = original.clone();
        input_unknown["inputs"][0]["nullifier"] = json!("sensitive sentinel");
        malformed.push(serde_json::to_vec(&input_unknown).unwrap());
        let mut invalid_txid = original.clone();
        invalid_txid["inputs"][0]["txid"] = json!("12".repeat(31));
        malformed.push(serde_json::to_vec(&invalid_txid).unwrap());
        let mut duplicate_input = original.clone();
        duplicate_input["inputs"] = json!([p2pkh(2), p2pkh(2)]);
        malformed.push(serde_json::to_vec(&duplicate_input).unwrap());
        malformed.push(br#"{"sensitive sentinel":"#.to_vec());
        for bytes in malformed {
            fs::write(fixture.path(id), &bytes).unwrap();
            let error = store.load(id).unwrap_err();
            assert!(!format!("{error:#}").contains("sensitive sentinel"));
            assert!(store
                .begin(id, valid.wallet_id, valid.request.clone())
                .is_err());
            assert_eq!(fs::read(fixture.path(id)).unwrap(), bytes);
        }
        fs::write(fixture.path(id), serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(store.load(id).unwrap(), valid);
        drop(store);
        assert!(Store::open(&fixture.scope, Uuid::new_v4(), &"ab".repeat(32)).is_err());
        assert!(Store::open(&fixture.scope, fixture.network, &"cd".repeat(32)).is_err());
        assert_eq!(fixture.open().load(id).unwrap(), valid);
    }

    #[test]
    fn bounded_records_values_and_operation_count_fail_without_partial_writes() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        let initial = store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        assert!(store
            .reserve(
                id,
                json!({"large":"x".repeat(4 * 1024 * 1024)}),
                vec![ironwood(0)]
            )
            .is_err());
        assert_eq!(store.load(id).unwrap(), initial);
        let mut deep = json!(true);
        for _ in 0..65 {
            deep = json!([deep]);
        }
        assert!(store.reserve(id, deep, vec![]).is_err());
        assert_eq!(store.load(id).unwrap(), initial);
        let mut bytes = serde_json::to_vec(&initial).unwrap();
        bytes.resize(4 * 1024 * 1024, b' ');
        fs::write(fixture.path(id), &bytes).unwrap();
        assert_eq!(store.load(id).unwrap(), initial);
        bytes.push(b' ');
        fs::write(fixture.path(id), &bytes).unwrap();
        assert!(store.load(id).is_err());
        assert_eq!(
            fs::metadata(fixture.path(id)).unwrap().len(),
            4 * 1024 * 1024 + 1
        );
        fs::write(fixture.path(id), serde_json::to_vec(&initial).unwrap()).unwrap();
        // Populate valid fixtures directly, avoiding quadratic fsync-heavy setup.
        for number in 1..1024 {
            let mut record = initial.clone();
            record.operation_id = Uuid::from_u128(number);
            zdn::foundation::write_private(
                &fixture.path(record.operation_id),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(store.records().unwrap().len(), 1024);
        assert!(store
            .begin(Uuid::new_v4(), Uuid::new_v4(), json!({}))
            .is_err());
        assert_eq!(store.records().unwrap().len(), 1024);
        zdn::foundation::write_private(&fixture.scope.join("payments/unrecognized"), b"{}")
            .unwrap();
        assert!(store.records().is_err());
    }

    #[test]
    fn conflicting_durable_records_and_unrecognized_files_block_all_operations() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        store.begin(first, Uuid::new_v4(), json!({})).unwrap();
        let planned = store
            .reserve(first, json!({"fee":3}), vec![ironwood(2)])
            .unwrap();
        store.observe(first, Outcome::NotDispatched).unwrap();
        let unplanned = store.begin(second, Uuid::new_v4(), json!({})).unwrap();
        let mut conflict = planned;
        conflict.operation_id = second;
        conflict.wallet_id = unplanned.wallet_id;
        let path = fixture.path(second);
        let bytes = serde_json::to_vec(&conflict).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(store.reserved_inputs().is_err());
        assert!(store.sign(first, json!({"raw":"ab"})).is_err());
        assert!(store.observe(first, Outcome::NotDispatched).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::write(&path, serde_json::to_vec(&unplanned).unwrap()).unwrap();
        let stray = fixture.scope.join("payments/.tmp-abandoned");
        zdn::foundation::write_private(&stray, &serde_json::to_vec(&unplanned).unwrap()).unwrap();
        assert!(store.records().is_err());
        assert!(store
            .begin(Uuid::new_v4(), Uuid::new_v4(), json!({}))
            .is_err());
        assert!(stray.exists());
    }

    #[test]
    fn attempt_count_cannot_overflow_and_erase_dispatch_uncertainty() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let id = Uuid::new_v4();
        store.begin(id, Uuid::new_v4(), json!({})).unwrap();
        store.reserve(id, json!({}), vec![]).unwrap();
        store.start_signing(id).unwrap();
        store.sign(id, json!({"raw":"12"})).unwrap();
        let mut exhausted = store.dispatch(id).unwrap();
        exhausted.attempts = u32::MAX;
        fs::write(fixture.path(id), serde_json::to_vec(&exhausted).unwrap()).unwrap();
        assert!(store.dispatch(id).is_err());
        assert!(store.observe(id, Outcome::NotDispatched).is_err());
        assert_eq!(store.load(id).unwrap(), exhausted);
    }

    #[test]
    fn aggregate_byte_limit_counts_actual_file_bytes_and_blocks_growth() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let mut record = store
            .begin(Uuid::from_u128(1), Uuid::new_v4(), json!({}))
            .unwrap();
        for number in 1..=16 {
            record.operation_id = Uuid::from_u128(number);
            let mut bytes = serde_json::to_vec(&record).unwrap();
            bytes.resize(4 * 1024 * 1024, b' ');
            zdn::foundation::write_private(&fixture.path(record.operation_id), &bytes).unwrap();
        }
        assert_eq!(store.records().unwrap().len(), 16);
        let next = Uuid::from_u128(17);
        assert!(store.begin(next, Uuid::new_v4(), json!({})).is_err());
        assert!(!fixture.path(next).exists());
        record.operation_id = next;
        zdn::foundation::write_private(&fixture.path(next), &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(store.records().is_err());
        drop(store);
        assert!(Store::open(&fixture.scope, fixture.network, &"ab".repeat(32)).is_err());
    }
}
