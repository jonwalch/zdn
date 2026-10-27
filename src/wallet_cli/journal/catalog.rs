//! Indexed local catalog. SQLite rollback journals and EXTRA synchronous commits
//! supply atomic record/index updates; the network lock remains the coordinator.
use super::*;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

mod settlement;
pub use settlement::ChainPoint;

const DATABASE: &str = "payments.catalog.sqlite";
const BARRIER: &str = ".catalog-v1";
const FORMAT: &str = "zdn.wallet.catalog.v1";

impl Store {
    fn database_path(&self) -> PathBuf {
        self.network_directory.join(DATABASE)
    }

    fn barrier_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "format":FORMAT, "network_id":self.network_id,
            "consensus_fingerprint":self.consensus_fingerprint
        }))?)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.catalog.authority")
    )]
    pub(super) fn catalog_authority(&self) -> Result<bool> {
        self.check_directories()?;
        let barrier = self.directory.join(BARRIER);
        no_symlinks(&barrier)?;
        for suffix in ["", "-journal", "-wal", "-shm"] {
            no_symlinks(&self.network_directory.join(format!("{DATABASE}{suffix}")))?;
        }
        if barrier.try_exists()? {
            private_file(&barrier)?;
            private_file(&self.database_path()).context("authoritative catalog missing/unsafe; restore coherent backup, never remove the barrier")?;
            let connection = self.connection()?;
            for entry in fs::read_dir(&self.directory)? {
                let path = entry?.path();
                if path == barrier {
                    continue;
                }
                private_file(&path)?;
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("unknown retained legacy file; inspect without deleting")?;
                let id = Uuid::parse_str(name)
                    .context("unknown retained legacy file; inspect without deleting")?;
                ensure!(
                    path == self.path(id),
                    "unknown retained legacy file; inspect without deleting"
                );
                let present: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
                    [id.to_string()],
                    |r| r.get(0),
                )?;
                ensure!(
                    present,
                    "retained legacy identity missing from catalog; restore coherent backup, retain all files"
                );
            }
            ensure!(
                fs::metadata(&barrier)?.len() <= 1024,
                "invalid catalog authority barrier"
            );
            ensure!(
                fs::read(barrier)? == self.barrier_bytes()?,
                "unsupported catalog authority; retain all files and restore a compatible backup"
            );
            return Ok(true);
        }
        ensure!(
            !self.database_path().try_exists()?,
            "interrupted catalog migration; run journal-migrate preview/apply to resume, retain all files"
        );
        for suffix in ["-journal", "-wal", "-shm"] {
            ensure!(
                !self
                    .network_directory
                    .join(format!("{DATABASE}{suffix}"))
                    .try_exists()?,
                "orphan catalog recovery file; restore coherent backup, retain all files"
            );
        }
        Ok(false)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.catalog.connection")
    )]
    fn connection(&self) -> Result<Connection> {
        private_file(&self.database_path())?;
        // SQLite recovery may consult these files. Never follow an injected link.
        for suffix in ["-journal", "-wal", "-shm"] {
            let path = self.network_directory.join(format!("{DATABASE}{suffix}"));
            no_symlinks(&path)?;
            if path.try_exists()? {
                private_file(&path)?;
            }
        }
        let connection =
            Connection::open_with_flags(self.database_path(), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        // Bound allocation before row.get materializes a corrupt blob. Leave
        // space for the ID and SQLite row overhead in addition to record bytes.
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_RECORD_BYTES + 1024) as i32,
        )?;
        connection.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF;")?;
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        ensure!(
            mode == "delete",
            "unsupported catalog journal mode; retain all recovery files"
        );
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let application: u32 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        ensure!(
            (version == 1 || version == 2) && application == 0x5a444e31,
            "unsupported catalog schema/application; restore compatible storage"
        );
        let format: Vec<u8> =
            connection.query_row("SELECT binding FROM metadata WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        ensure!(
            format == self.barrier_bytes()?,
            "unsupported or mismatched catalog scope"
        );
        if version == 1 {
            let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            ensure!(
                integrity == "ok",
                "corrupt authoritative catalog; restore coherent backup"
            );
        } else {
            // Bounded schema checks, not a lifetime integrity scan. SQLite's
            // transactional indexes are trusted local authority, not independent
            // authenticated proofs against hostile DB edits or backup rollback.
            let mut schema = connection
                .prepare("SELECT type,name FROM sqlite_schema ORDER BY type,name LIMIT 9")?;
            let objects = schema
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let expected = [
                ("index", "live_operations"),
                ("index", "operations_active"),
                ("index", "settlement_heights"),
                ("index", "sqlite_autoindex_operations_1"),
                ("table", "chain_cursor"),
                ("table", "metadata"),
                ("table", "operations"),
            ]
            .map(|(a, b)| (a.to_owned(), b.to_owned()));
            ensure!(
                objects == expected,
                "unsupported settlement catalog schema/indexes"
            );
            for (name, expected) in [
                ("live_operations", "CREATE INDEX live_operations ON operations(id) WHERE cancelled=0 AND placement!=1"),
                ("settlement_heights", "CREATE INDEX settlement_heights ON operations(inclusion_height,id) WHERE placement=1")
            ] {
                let sql: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE name=?1", [name], |r| r.get(0))?;
                ensure!(sql == expected, "settlement index definition mismatch");
            }
        }
        Ok(connection)
    }

    fn decode(&self, id: String, data: Vec<u8>, cancelled: bool) -> Result<Record> {
        ensure!(
            data.len() <= MAX_RECORD_BYTES,
            "catalog record exceeds limit"
        );
        let record: Record = serde_json::from_slice(&data)
            .map_err(|_| eyre::eyre!("invalid catalog record; diagnostics redacted"))?;
        self.validate(&record)?;
        ensure!(
            id == record.operation_id.to_string() && cancelled == record.cancelled(),
            "catalog identity/index mismatch"
        );
        Ok(record)
    }

    pub(super) fn catalog_load(&self, id: Uuid) -> Result<Record> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT id,data,cancelled FROM operations WHERE id=?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .context("payment operation not found")?;
        let record = self.decode(row.0, row.1, row.2)?;
        if Self::settlement_version(&connection)? {
            self.validate_settlement_index(&connection, &record)?;
        }
        Ok(record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.catalog.active")
    )]
    pub(super) fn catalog_active(&self) -> Result<Vec<Record>> {
        let connection = self.connection()?;
        let upgraded = Self::settlement_version(&connection)?;
        if upgraded {
            Self::require_reconciled(&connection)?;
        }
        let mut statement = connection.prepare(if upgraded {
            "SELECT id,data,cancelled FROM operations WHERE cancelled=0 AND placement!=1 ORDER BY id"
        } else { "SELECT id,data,cancelled FROM operations ORDER BY id" })?;
        let mut rows = statement.query([])?;
        let mut records = Vec::new();
        let mut total = 0;
        let mut ordinary_count = 0;
        let mut quarantine_count = 0;
        let mut quarantine_bytes = 0;
        let mut inputs = HashSet::new();
        while let Some(row) = rows.next()? {
            // v2 reads only indexed live reservations, not historical payloads.
            let record = self.decode(row.get(0)?, row.get(1)?, row.get(2)?)?;
            if record.cancelled() {
                continue;
            }
            let quarantine = if upgraded {
                self.validate_settlement_index(&connection, &record)? == "reorg_quarantine"
            } else {
                false
            };
            if quarantine {
                quarantine_count += 1;
                quarantine_bytes += serde_json::to_vec(&record)?.len();
                ensure!(quarantine_count <= MAX_RECORDS && quarantine_bytes <= MAX_TOTAL_BYTES,
                    "reorg quarantine read capacity exceeded; all guards retained; inspect paginated journal and reconcile settlements");
            } else {
                total += serde_json::to_vec(&record)?.len();
                ordinary_count += 1;
            }
            ensure!(
                ordinary_count <= MAX_RECORDS && total <= MAX_TOTAL_BYTES,
                "active catalog capacity exceeded"
            );
            for input in &record.inputs {
                ensure!(
                    inputs.insert(input.clone()),
                    "conflicting payment input reservations"
                );
            }
            records.push(record);
        }
        Ok(records)
    }

    pub(super) fn catalog_publish(&self, record: &Record, create: bool) -> Result<()> {
        self.validate(record)?;
        let active = self.catalog_active()?;
        let data = serde_json::to_vec(record)?;
        ensure!(
            data.len() <= MAX_RECORD_BYTES,
            "payment record exceeds size limit"
        );
        let mut count = usize::from(!record.cancelled());
        let mut bytes = if record.cancelled() { 0 } else { data.len() };
        let connection = self.connection()?;
        let upgraded = Self::settlement_version(&connection)?;
        for saved in &active {
            if saved.operation_id == record.operation_id {
                continue;
            }
            if upgraded && !record.cancelled() {
                let placement: u32 = connection.query_row(
                    "SELECT placement FROM operations WHERE id=?1",
                    [saved.operation_id.to_string()],
                    |r| r.get(0),
                )?;
                if placement == 2 {
                    ensure!(
                        saved.request.get("sender_public").is_some()
                            && record.request.get("sender_public").is_some()
                            && saved.request.get("sender_public")
                                != record.request.get("sender_public"),
                        "sender has a reorg-quarantined archived signature; explicit recovery required"
                    );
                }
            }
            count += 1;
            bytes += serde_json::to_vec(saved)?.len();
            ensure!(
                record.cancelled()
                    || !saved
                        .inputs
                        .iter()
                        .any(|input| record.inputs.contains(input)),
                "payment input is already reserved by another operation"
            );
        }
        ensure!(
            count <= MAX_RECORDS && bytes <= MAX_TOTAL_BYTES,
            "active catalog capacity exceeded"
        );
        drop(connection);
        let mut connection = self.connection()?;
        if Self::settlement_version(&connection)? && !create {
            let placement: u32 = connection.query_row(
                "SELECT placement FROM operations WHERE id=?1",
                [record.operation_id.to_string()],
                |r| r.get(0),
            )?;
            ensure!(
                placement == 0,
                "archived or reorg-quarantined payment requires explicit recovery"
            );
        }
        let transaction = connection.transaction()?;
        if create {
            transaction.execute(
                "INSERT INTO operations(id,data,cancelled) VALUES(?1,?2,?3)",
                params![record.operation_id.to_string(), data, record.cancelled()],
            )?;
        } else {
            ensure!(
                transaction.execute(
                    "UPDATE operations SET data=?2,cancelled=?3 WHERE id=?1 AND cancelled=0",
                    params![record.operation_id.to_string(), data, record.cancelled()]
                )? == 1,
                "missing or terminal payment operation"
            );
        }
        transaction.commit()?;
        File::open(&self.network_directory)?.sync_all()?;
        Ok(())
    }

    /// Bounded keyset inventory; complete records are available by exact ID.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.catalog.inventory")
    )]
    pub fn inventory(&self, after: Option<Uuid>, limit: usize, id: Option<Uuid>) -> Result<Value> {
        ensure!((1..=100).contains(&limit), "inventory limit must be 1..100");
        let indexed = self.catalog_authority()?;
        if let Some(id) = id {
            return Ok(serde_json::to_value(self.load(id)?)?);
        }
        let active = if indexed { vec![] } else { self.records()? };
        let (count, page) = if indexed {
            let connection = self.connection()?;
            let upgraded = Self::settlement_version(&connection)?;
            let count: u64 =
                connection.query_row("SELECT count(*) FROM operations", [], |r| r.get(0))?;
            let mut statement = connection.prepare(
                "SELECT id,data,cancelled FROM operations WHERE id>?1 ORDER BY id LIMIT ?2",
            )?;
            let mut rows = statement.query(params![
                after.map(|v| v.to_string()).unwrap_or_default(),
                limit
            ])?;
            let mut page = Vec::new();
            while let Some(row) = rows.next()? {
                let record = self.decode(row.get(0)?, row.get(1)?, row.get(2)?)?;
                let mut entry = summary(&record)?;
                if upgraded {
                    // Reuse the disposition just validated on this connection,
                    // not a fresh full authority scan for every summary row.
                    let disposition = self.validate_settlement_index(&connection, &record)?;
                    entry["disposition"] = serde_json::json!(disposition);
                    if disposition == "archived" {
                        entry["reserved_inputs"] = serde_json::json!(0);
                    }
                }
                page.push(entry);
            }
            (count, page)
        } else {
            (
                active.len() as u64,
                active
                    .iter()
                    .filter(|r| after.is_none_or(|id| r.operation_id > id))
                    .take(limit)
                    .map(summary)
                    .collect::<Result<Vec<_>>>()?,
            )
        };
        let (active_count, active_bytes, cancelled, unresolved, pending) = if indexed {
            let c = self.connection()?;
            let upgraded = Self::settlement_version(&c)?;
            let live = if upgraded {
                "cancelled=0 AND placement!=1"
            } else {
                "cancelled=0"
            };
            let (count, bytes): (u64, u64) = c.query_row(
                &format!(
                    "SELECT count(*),coalesce(sum(length(data)),0) FROM operations WHERE {live}"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let cancelled: u64 = c.query_row(
                "SELECT count(*) FROM operations WHERE cancelled=1",
                [],
                |r| r.get(0),
            )?;
            let unresolved: u64 = c.query_row(&format!(
                "SELECT count(*) FROM operations WHERE {live} AND (json_extract(data,'$.outcome.kind')!='confirmed'{})",
                if upgraded { " OR placement=2" } else { "" }), [], |r| r.get(0))?;
            let pending = if upgraded {
                c.query_row(
                    "SELECT pending FROM chain_cursor WHERE singleton=1",
                    [],
                    |r| r.get::<_, bool>(0),
                )?
            } else {
                false
            };
            (count, bytes, cancelled, unresolved, pending)
        } else {
            let live: Vec<_> = active.iter().filter(|r| !r.cancelled()).collect();
            (
                live.len() as u64,
                live.iter().try_fold(0u64, |sum, r| -> Result<u64> {
                    Ok(sum + serde_json::to_vec(r)?.len() as u64)
                })?,
                (active.len() - live.len()) as u64,
                live.iter()
                    .filter(|r| !matches!(r.outcome, Outcome::Confirmed { .. }))
                    .count() as u64,
                false,
            )
        };
        let mut original_bytes = 0u64;
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if path != self.directory.join(BARRIER) {
                original_bytes += fs::metadata(path)?.len();
            }
        }
        let (archived, quarantined) = if indexed {
            let c = self.connection()?;
            if Self::settlement_version(&c)? {
                (
                    c.query_row(
                        "SELECT count(*) FROM operations WHERE placement=1",
                        [],
                        |r| r.get::<_, u64>(0),
                    )?,
                    c.query_row(
                        "SELECT count(*) FROM operations WHERE placement=2",
                        [],
                        |r| r.get::<_, u64>(0),
                    )?,
                )
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };
        Ok(
            serde_json::json!({"format":if indexed { FORMAT } else { "legacy" },
            "total_operations":count,"active_operations":active_count,
            "cancelled_operations":cancelled,"unresolved_operations":unresolved,"reconciliation_pending":pending,
            "active_record_bytes":active_bytes,"retained_legacy_bytes":original_bytes,"archived_settlements":archived,"reorg_quarantines":quarantined,
            "active_limit":MAX_RECORDS,"active_byte_limit":MAX_TOTAL_BYTES,
            "catalog_bytes":if indexed { fs::metadata(self.database_path())?.len() } else { 0 },
            "next_after":page.last().map(|v| v["operation_id"].clone()),"operations":page,
            "settlement_archival":"explicit upgrade, fresh canonical inclusion and depth required"}),
        )
    }

    /// Explicit migration only. A staged DB without a barrier is resumable only
    /// when every original record still exactly matches the staged transaction.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.catalog.migrate")
    )]
    pub fn migrate(&self, apply: Option<&str>) -> Result<Value> {
        no_symlinks(&self.directory.join(BARRIER))?;
        no_symlinks(&self.database_path())?;
        if self.directory.join(BARRIER).try_exists()? {
            self.catalog_authority()?;
            self.catalog_active()?;
            ensure!(
                apply.is_none(),
                "catalog already authoritative; migration proposal is no longer applicable"
            );
            return Ok(serde_json::json!({"state":"indexed", "action":"none"}));
        }
        let records = self.legacy_records().context("migration blocked by invalid, unknown or over-limit legacy files; retain originals and crash-left files for inspection, never delete payment records to bypass a refusal")?;
        let mut hash = Sha256::new();
        hash.update(b"zdn.wallet.journal-migrate.v1\0");
        hash.update(self.barrier_bytes()?);
        for record in &records {
            let data = serde_json::to_vec(record)?;
            hash.update((data.len() as u64).to_be_bytes());
            hash.update(data);
        }
        let proposal = hex::encode(hash.finalize());
        if let Some(token) = apply {
            ensure!(
                canonical_hash(token) && token == proposal,
                "stale or invalid migration proposal"
            );
            if !self.database_path().try_exists()? {
                for suffix in ["-journal", "-wal", "-shm"] {
                    let path = self.network_directory.join(format!("{DATABASE}{suffix}"));
                    no_symlinks(&path)?;
                    ensure!(
                        !path.try_exists()?,
                        "orphan catalog recovery file; retain for inspection before migration"
                    );
                }
                // Exclusive creation: never overwrite an unknown interrupted file.
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(self.database_path())?;
                file.sync_all()?;
                let mut connection = Connection::open(self.database_path())?;
                connection
                    .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;")?;
                let transaction = connection.transaction()?;
                transaction
                    .execute_batch("PRAGMA application_id=1514425905; PRAGMA user_version=1;")?;
                transaction.execute_batch("CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binding BLOB NOT NULL,proposal TEXT NOT NULL); CREATE TABLE operations(id TEXT PRIMARY KEY NOT NULL,data BLOB NOT NULL CHECK(length(data)<=4194304),cancelled INTEGER NOT NULL CHECK(cancelled IN (0,1))); CREATE INDEX operations_active ON operations(cancelled,id);")?;
                transaction.execute(
                    "INSERT INTO metadata VALUES(1,?1,?2)",
                    params![self.barrier_bytes()?, proposal],
                )?;
                for record in &records {
                    transaction.execute(
                        "INSERT INTO operations VALUES(?1,?2,?3)",
                        params![
                            record.operation_id.to_string(),
                            serde_json::to_vec(record)?,
                            record.cancelled()
                        ],
                    )?;
                }
                transaction.commit()?;
            }
            let connection = self.connection().context("incomplete staged catalog; retain originals and catalog, move staged catalog aside for inspection before retrying migration")?;
            let saved: String = connection.query_row(
                "SELECT proposal FROM metadata WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            let count: usize =
                connection.query_row("SELECT count(*) FROM operations", [], |r| r.get(0))?;
            ensure!(
                saved == proposal && count == records.len(),
                "staged catalog differs from legacy proposal; retain both for inspection"
            );
            for record in &records {
                let row = connection.query_row(
                    "SELECT id,data,cancelled FROM operations WHERE id=?1",
                    [record.operation_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                ensure!(
                    self.decode(row.0, row.1, row.2)? == *record,
                    "staged catalog differs from legacy record; retain both for inspection"
                );
            }
            drop(connection);
            File::open(self.database_path())?.sync_all()?;
            File::open(&self.network_directory)?.sync_all()?;
            // Not a payment slot. The actual strict prior reader parses every
            // directory entry as Record and refuses this incompatible object.
            zdn::foundation::write_private(&self.directory.join(BARRIER), &self.barrier_bytes()?)?;
            File::open(&self.directory)?.sync_all()?;
            self.catalog_authority()?;
        }
        Ok(
            serde_json::json!({"state":if apply.is_some() { "indexed" } else { "legacy" },
            "proposal_sha256":proposal,"operations":records.len(),"network_id":self.network_id,
            "consensus_fingerprint":self.consensus_fingerprint,"originals":"retained unchanged; no cleanup or signed settlement release",
            "action":if apply.is_some() { "migrated" } else { "preview" }}),
        )
    }
}

fn summary(record: &Record) -> Result<Value> {
    Ok(
        serde_json::json!({"operation_id":record.operation_id,"wallet_id":record.wallet_id,
        "outcome":record.outcome,"attempts":record.attempts,"record_bytes":serde_json::to_vec(record)?.len(),
        "reserved_inputs":if record.cancelled() { 0 } else { record.inputs.len() }}),
    )
}
