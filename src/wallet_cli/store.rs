//! Network-scoped public receipts; private key bytes remain backend-owned.
use super::*;
use std::os::unix::fs::DirBuilderExt;
use uuid::Uuid;
use zdn::endpoints::EndpointFile;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Wallet {
    schema_version: u32,
    pub(super) id: Uuid,
    name: String,
    network_id: Uuid,
    consensus_fingerprint: String,
    creation_backend_sha256: String,
    // Only legacy v1 may omit this; an incomplete v2 receipt must not enable signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) scan_only: Option<bool>,
    pub(super) public: PublicKeys,
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.store.private_dir")
)]
pub(super) fn private_dir(path: &Path, create: bool) -> Result<()> {
    no_symlinks(path)?;
    if create {
        let absolute = std::path::absolute(path)?;
        let missing: Vec<_> = absolute.ancestors().take_while(|p| !p.exists()).collect();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        // Persist every newly created directory entry before generating private keys.
        for directory in missing.into_iter().rev() {
            fs::File::open(
                directory
                    .parent()
                    .context("wallet directory has no parent")?,
            )?
            .sync_all()?;
        }
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
        "wallet store directories must be private (no group/other permissions)"
    );
    Ok(())
}

fn directory(root: &Path, network_id: Uuid, name: &str) -> Result<PathBuf> {
    ensure!(
        name_valid(name) && !matches!(name, "payments" | "payment-data"),
        "wallet name must start with a-z and contain only a-z, 0-9 or - (maximum 64 bytes); payments and payment-data are reserved"
    );
    Ok(root.join(network_id.to_string()).join(name))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.store.reserve")
)]
pub(super) fn reserve(root: &Path, network_id: Uuid, name: &str) -> Result<PathBuf> {
    let path = directory(root, network_id, name)?;
    private_dir(root, true)?;
    let scope = path.parent().context("missing wallet scope")?;
    private_dir(scope, true)?;
    // Exclusive directory creation serializes duplicate names, including failed creates.
    fs::DirBuilder::new().mode(0o700).create(&path).context(
        "wallet name already exists or cannot be created; incomplete wallets are never overwritten",
    )?;
    fs::File::open(scope)?.sync_all()?;
    Ok(path)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.store.publish")
)]
pub(super) fn publish(
    path: &Path,
    network_id: Uuid,
    consensus_fingerprint: &str,
    name: &str,
    hash: &str,
    public: PublicKeys,
    scan_only: bool,
) -> Result<Wallet> {
    let wallet = Wallet {
        schema_version: 2,
        id: Uuid::new_v4(),
        name: name.into(),
        network_id,
        consensus_fingerprint: consensus_fingerprint.into(),
        creation_backend_sha256: hash.to_ascii_lowercase(),
        scan_only: Some(scan_only),
        public,
    };
    super::super::write_new_file(
        &path.join("wallet.json"),
        &serde_json::to_vec_pretty(&wallet)?,
    )?;
    Ok(wallet)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.store.load")
)]
pub(super) fn load(root: &Path, identity: &EndpointFile, name: &str) -> Result<(Wallet, PathBuf)> {
    let path = directory(root, identity.network_id, name)?;
    private_dir(root, false)?;
    private_dir(path.parent().context("missing wallet scope")?, false)?;
    private_dir(&path, false)?;
    let metadata = path.join("wallet.json");
    regular(&metadata, true)?;
    ensure!(
        fs::metadata(&metadata)?.len() <= 16384,
        "wallet receipt exceeds size bound"
    );
    let wallet: Wallet = serde_json::from_slice(&fs::read(metadata)?)
        .map_err(|_| eyre::eyre!("invalid public wallet receipt; diagnostics redacted"))?;
    wallet.public.validate()?;
    ensure!(
        matches!(
            (wallet.schema_version, wallet.scan_only),
            (1, None) | (2, Some(_))
        ) && !wallet.id.is_nil()
            && wallet.name == name
            && wallet.network_id == identity.network_id
            && wallet.consensus_fingerprint == identity.consensus_fingerprint
            && hex_bytes(&wallet.creation_backend_sha256, 32),
        "wallet receipt does not match the selected name/network/consensus"
    );
    let key = path.join("key.json");
    regular(&key, true)?;
    Ok((wallet, key))
}

impl Wallet {
    pub(super) fn verify(&self, public: &PublicKeys) -> Result<()> {
        ensure!(
            self.public == *public,
            "wallet public identity differs from its private key"
        );
        Ok(())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.store.list")
)]
pub(super) fn list(root: &Path, identity: &EndpointFile) -> Result<serde_json::Value> {
    let scope = root.join(identity.network_id.to_string());
    no_symlinks(&scope)?;
    let mut wallets = std::collections::BTreeMap::new();
    if scope.exists() {
        private_dir(root, false)?;
        private_dir(&scope, false)?;
        for entry in fs::read_dir(scope)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| eyre::eyre!("invalid wallet directory name"))?;
            if matches!(
                name.as_str(),
                "payments.lock"
                    | "payments.catalog.sqlite"
                    | "payments.catalog.sqlite-journal"
                    | "payments.catalog.sqlite-wal"
                    | "payments.catalog.sqlite-shm"
            ) {
                regular(&entry.path(), true)?;
                continue;
            }
            if matches!(name.as_str(), "payments" | "payment-data") {
                private_dir(&entry.path(), false)?;
                ensure!(
                    !entry.path().join("wallet.json").exists()
                        && !entry.path().join("key.json").exists(),
                    "legacy wallet collides with payment storage; preserve its files and migrate explicitly"
                );
                continue;
            }
            ensure!(name_valid(&name), "invalid wallet directory name");
            private_dir(&entry.path(), false)?;
            let receipt = entry.path().join("wallet.json");
            let value = if fs::symlink_metadata(&receipt)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                serde_json::json!({"name":name,"status":"incomplete","key_verified":false})
            } else {
                let (wallet, _) = load(root, identity, &name)?;
                serde_json::json!({"name":name,"status":"complete","key_verified":false,"wallet":wallet})
            };
            wallets.insert(name, value);
        }
    }
    Ok(
        serde_json::json!({"schema_version":1,"network_id":identity.network_id,
        "consensus_fingerprint":identity.consensus_fingerprint,"wallets":wallets.into_values().collect::<Vec<_>>() }),
    )
}
