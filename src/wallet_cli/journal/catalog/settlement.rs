//! Trusted local SQLite indexes are authority, not an authenticated hostile-storage
//! proof. Consulted payloads are strictly decoded; unconsulted damage can remain
//! latent. Backup/rollback and a malicious local controller remain out of scope.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainPoint {
    pub height: u32,
    pub hash: String,
}

impl ChainPoint {
    fn validate(&self) -> Result<()> {
        ensure!(canonical_hash(&self.hash), "invalid canonical block hash");
        Ok(())
    }
}

impl Store {
    pub fn settlements_enabled(&self) -> Result<bool> {
        if !self.catalog_authority()? {
            return Ok(false);
        }
        Self::settlement_version(&self.connection()?)
    }

    pub(super) fn validate_settlement_index(
        &self,
        c: &Connection,
        record: &Record,
    ) -> Result<&'static str> {
        let (p, height, hash, receipt): (u32, Option<u32>, Option<String>, Option<Vec<u8>>) = c.query_row(
            "SELECT placement,inclusion_height,inclusion_hash,settlement_receipt FROM operations WHERE id=?1",
            [record.operation_id.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if p == 0 {
            ensure!(
                height.is_none() && hash.is_none() && receipt.is_none(),
                "active settlement index mismatch"
            );
        } else {
            ensure!(p == 1 || p == 2, "invalid settlement placement");
            let receipt = receipt.context("missing settlement evidence")?;
            ensure!(receipt.len() <= 2048, "invalid settlement receipt size");
            let (tip, inclusion, depth, proposal): (ChainPoint, ChainPoint, u32, String) =
                serde_json::from_slice(&receipt)?;
            tip.validate()?;
            inclusion.validate()?;
            ensure!(
                height == Some(inclusion.height)
                    && hash.as_ref() == Some(&inclusion.hash)
                    && record.outcome
                        == Outcome::Confirmed {
                            height: inclusion.height,
                            hash: inclusion.hash.clone()
                        }
                    && depth > 0
                    && tip
                        .height
                        .checked_sub(inclusion.height)
                        .is_some_and(|n| u64::from(n) + 1 >= u64::from(depth)),
                "settlement index mismatch"
            );
            let mut digest = Sha256::new();
            digest.update(b"zdn.wallet.settlement-archive.v2\0");
            digest.update(serde_json::to_vec(&(record, tip, inclusion, depth, 0u32))?);
            ensure!(
                hex::encode(digest.finalize()) == proposal,
                "settlement evidence mismatch"
            );
        }
        Ok(match p {
            0 => "active",
            1 => "archived",
            2 => "reorg_quarantine",
            _ => unreachable!(), // Placement was checked with its evidence above.
        })
    }

    /// Separate storage disposition, never a replacement economic outcome.
    /// Callers MUST treat `reorg_quarantine` as a same-key replacement guard
    /// regardless of the retained historical Confirmed outcome in `load`.
    pub fn settlement_disposition(&self, id: Uuid) -> Result<&'static str> {
        if !self.catalog_authority()? {
            return Ok("active");
        }
        let c = self.connection()?;
        if !Self::settlement_version(&c)? {
            return Ok("active");
        }
        let p: u32 = c.query_row(
            "SELECT placement FROM operations WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )?;
        Ok(match p {
            0 => "active",
            1 => "archived",
            2 => "reorg_quarantine",
            _ => eyre::bail!("invalid settlement disposition"),
        })
    }

    pub(super) fn settlement_version(c: &Connection) -> Result<bool> {
        Ok(c.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))? == 2)
    }

    pub(super) fn require_reconciled(c: &Connection) -> Result<()> {
        let pending: bool = c.query_row(
            "SELECT pending FROM chain_cursor WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            !pending,
            "settlement reconciliation incomplete; open maintenance and reconcile before payment selection"
        );
        Ok(())
    }

    /// Explicit, atomic format upgrade. The v1 reader rejects user_version=2
    /// before using its old active index. Existing legacy migration remains a
    /// separate prerequisite and works at exactly full capacity.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.settlement.upgrade")
    )]
    pub fn upgrade_settlements(&self, apply: Option<&str>) -> Result<Value> {
        ensure!(self.catalog_authority()?, "migrate journal first");
        let mut c = self.connection()?;
        ensure!(
            !Self::settlement_version(&c)?,
            "settlement format already enabled"
        );
        self.catalog_active()?;
        let mut hash = Sha256::new();
        hash.update(b"zdn.wallet.settlement-upgrade.v2\0");
        hash.update(self.barrier_bytes()?);
        let mut query = c.prepare("SELECT id,data,cancelled FROM operations ORDER BY id")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let record = self.decode(row.get(0)?, row.get(1)?, row.get(2)?)?;
            let bytes = serde_json::to_vec(&record)?;
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        drop(rows);
        drop(query);
        let proposal = hex::encode(hash.finalize());
        if let Some(token) = apply {
            ensure!(token == proposal, "stale settlement upgrade proposal");
            let tx = c.transaction()?;
            tx.execute_batch("ALTER TABLE operations ADD COLUMN placement INTEGER NOT NULL DEFAULT 0 CHECK(placement IN (0,1,2));
                ALTER TABLE operations ADD COLUMN inclusion_height INTEGER;
                ALTER TABLE operations ADD COLUMN inclusion_hash TEXT;
                ALTER TABLE operations ADD COLUMN settlement_receipt BLOB;
                CREATE INDEX settlement_heights ON operations(inclusion_height,id) WHERE placement=1;
                CREATE INDEX live_operations ON operations(id) WHERE cancelled=0 AND placement!=1;
                CREATE TABLE chain_cursor(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB,pending INTEGER NOT NULL CHECK(pending IN (0,1)));
                INSERT INTO chain_cursor VALUES(1,NULL,1);
                PRAGMA user_version=2;")?;
            tx.commit()?;
        }
        Ok(serde_json::json!({"proposal_sha256":proposal,"applied":apply.is_some()}))
    }

    /// Read-only RPC callbacks must be fresh, identity-checked canonical-height
    /// observations from one stable chosen tip. Hold this Store/network lock for
    /// the entire call and before ANY payment selection, even on unchanged tips.
    /// `None` means above tip/absent canonical height, never transport failure.
    /// Errors leave a durable pending marker; only a complete transaction clears
    /// it. No payload history is read on unchanged/append-only canonical cursors.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.settlement.reconcile")
    )]
    pub fn reconcile_settlements(
        &self,
        tip: &ChainPoint,
        mut canonical: impl FnMut(u32) -> Result<Option<String>>,
    ) -> Result<usize> {
        tip.validate()?;
        ensure!(self.catalog_authority()?, "indexed journal required");
        let mut c = self.connection()?;
        ensure!(
            Self::settlement_version(&c)?,
            "upgrade settlement format first"
        );
        let saved: Option<Vec<u8>> =
            c.query_row("SELECT tip FROM chain_cursor WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        c.execute("UPDATE chain_cursor SET pending=1 WHERE singleton=1", [])?;
        ensure!(
            canonical(tip.height)?.as_ref() == Some(&tip.hash),
            "chosen tip is not canonical"
        );
        let old: Option<ChainPoint> = saved.map(|v| serde_json::from_slice(&v)).transpose()?;
        let append = if let Some(old) = old {
            old.validate()?;
            old.height <= tip.height && canonical(old.height)?.as_ref() == Some(&old.hash)
        } else {
            false
        };
        let tx = c.transaction()?;
        let mut restored = 0;
        if !append {
            let mut last: Option<(u32, Option<String>)> = None;
            let mut after = (0u32, String::new());
            loop {
                let next: Option<(String,u32,String)> = tx.query_row(
                    "SELECT id,inclusion_height,inclusion_hash FROM operations WHERE placement=1 AND (inclusion_height,id)>(?1,?2) ORDER BY inclusion_height,id LIMIT 1",
                    params![after.0,after.1], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                let Some((id, height, hash)) = next else {
                    break;
                };
                ensure!(canonical_hash(&hash), "invalid settlement hash index");
                after = (height, id.clone());
                if last.as_ref().is_none_or(|(h, _)| *h != height) {
                    last = Some((
                        height,
                        if height > tip.height {
                            None
                        } else {
                            canonical(height)?
                        },
                    ));
                }
                if last.as_ref().unwrap().1.as_ref() != Some(&hash) {
                    let row = tx.query_row(
                        "SELECT id,data,cancelled FROM operations WHERE id=?1",
                        [&id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )?;
                    let record = self.decode(row.0, row.1, row.2)?;
                    self.validate_settlement_index(&tx, &record)?;
                    // Keep exact economic history; disposition 2 restores guards
                    // even beyond active quotas, and is never dispatch authority.
                    tx.execute(
                        "UPDATE operations SET placement=2 WHERE id=?1",
                        [record.operation_id.to_string()],
                    )?;
                    restored += 1;
                }
            }
        }
        ensure!(
            canonical(tip.height)?.as_ref() == Some(&tip.hash),
            "tip changed during reconciliation"
        );
        tx.execute(
            "UPDATE chain_cursor SET tip=?1,pending=0 WHERE singleton=1",
            [serde_json::to_vec(tip)?],
        )?;
        tx.commit()?;
        Ok(restored)
    }

    /// Preview/apply archival of ONE exact confirmed signed/dispatched record.
    /// The inclusion callback MUST independently verify this exact signed txid
    /// in the specified canonical block (not merely trust Outcome::Confirmed).
    /// Reinvoke with fresh observations for apply; depth counts inclusion as 1.
    /// No age, absence, rejection or zero attempts permits archival.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "journal.settlement.archive")
    )]
    pub fn settlement_archive(
        &self,
        id: Uuid,
        tip: &ChainPoint,
        inclusion: &ChainPoint,
        depth: u32,
        apply: Option<&str>,
        mut verify: impl FnMut(&str, &ChainPoint, &ChainPoint) -> Result<()>,
    ) -> Result<Value> {
        tip.validate()?;
        inclusion.validate()?;
        ensure!(
            depth > 0
                && tip
                    .height
                    .checked_sub(inclusion.height)
                    .is_some_and(|n| u64::from(n) + 1 >= u64::from(depth)),
            "insufficient explicit settlement depth"
        );
        ensure!(self.catalog_authority()?, "indexed journal required");
        let mut c = self.connection()?;
        ensure!(
            Self::settlement_version(&c)?,
            "upgrade settlement format first"
        );
        Self::require_reconciled(&c)?;
        let cursor: Vec<u8> =
            c.query_row("SELECT tip FROM chain_cursor WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        ensure!(
            serde_json::from_slice::<ChainPoint>(&cursor)? == *tip,
            "reconcile at chosen tip before archival"
        );
        let record = self.catalog_load(id)?;
        let placement: u32 = c.query_row(
            "SELECT placement FROM operations WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )?;
        ensure!(
            placement == 0
                && record.outcome
                    == Outcome::Confirmed {
                        height: inclusion.height,
                        hash: inclusion.hash.clone()
                    }
                && record.attempts > 0,
            "only active exact confirmed dispatches qualify"
        );
        let txid = record
            .signed
            .as_ref()
            .and_then(|v| v["txid"].as_str())
            .context("signed transaction identity missing")?;
        ensure!(canonical_hash(txid), "invalid signed transaction identity");
        verify(txid, inclusion, tip)?;
        let mut hash = Sha256::new();
        hash.update(b"zdn.wallet.settlement-archive.v2\0");
        hash.update(serde_json::to_vec(&(
            &record, tip, inclusion, depth, placement,
        ))?);
        let proposal = hex::encode(hash.finalize());
        if let Some(token) = apply {
            ensure!(token == proposal, "stale settlement archive proposal");
            let tx = c.transaction()?;
            let receipt = serde_json::to_vec(&(tip, inclusion, depth, &proposal))?;
            ensure!(tx.execute("UPDATE operations SET placement=1,inclusion_height=?2,inclusion_hash=?3,settlement_receipt=?4 WHERE id=?1 AND placement=0", params![id.to_string(), inclusion.height, inclusion.hash, receipt])? == 1, "stale archive disposition");
            tx.commit()?;
        }
        Ok(
            serde_json::json!({"operation_id":id,"proposal_sha256":proposal,"archived":apply.is_some(),"depth":depth,"tip":tip,"inclusion":inclusion}),
        )
    }
}
