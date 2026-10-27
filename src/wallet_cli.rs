//! Narrow public-JSON bridge to the separately selected Ironwood executable.
use clap::{Args, Subcommand};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub(super) mod history;
mod journal;
mod maintenance;
pub(super) mod mempool;
mod observation;
pub(super) mod payment;
pub(crate) mod settings;
mod store;
mod sync;

const BACKEND_HELP: &str = "Backend selection: first configure the trusted pair for this wallet root:\n  zdn wallet backend set --backend /absolute/path/ironwood-wallet --backend-sha256 INDEPENDENTLY_TRUSTED_HASH\nBackend-using commands recheck those bytes on every use. For one command place BOTH overrides BEFORE the leaf:\n  zdn wallet --backend PATH --backend-sha256 HASH <command> ...\nPartial overrides refuse; there is no PATH search, download or automatic trust-by-hashing. --wallet-dir selects the settings AND named-wallet root; use the same root throughout. Journal/list/history-export commands refuse backend overrides and do not read saved backend settings; history-export still contacts the network.\n\nKeys are plaintext. Keep keyfiles, private output parents and coherent wallet backups under your control, outside Git/node source/build archives; symlinks and nonprivate paths refuse. Hash identity is not publisher trust and the backend is not sandboxed. A backend failure may leave an output: inspect it and choose a new destination rather than overwriting/deleting blindly. Key-only import is scan-only and does not restore signing authority. Never edit receipts to bypass recovery/signing policy. See docs/wallet.md for full backup/recovery and first-payment instructions.";

#[derive(Args)]
#[command(after_help = BACKEND_HELP)]
pub struct WalletArgs {
    /// Override the configured executable together with --backend-sha256; never resolved through PATH.
    #[arg(long)]
    backend: Option<PathBuf>,
    /// Exact executable SHA256, 64 hexadecimal characters.
    #[arg(long)]
    backend_sha256: Option<String>,
    /// Settings/named-wallet root; default $XDG_DATA_HOME/zdn/wallets or $HOME/.local/share/zdn/wallets. Global within wallet; reuse for recovery.
    #[arg(long, global = true)]
    wallet_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Explicitly configure the pinned executable for this wallet root.
    Backend {
        #[command(subcommand)]
        command: BackendCommand,
    },
    /// Resume bounded derived state/v2 scanning; never a spendability claim.
    #[command(after_help = BACKEND_HELP)]
    Sync {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Existing local named wallet in the selected network UUID; sync does not authorize signing.
        #[arg(long)]
        wallet: String,
        /// At most 256 blocks per batch; at most 16 batches per invocation.
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=16))]
        max_batches: u32,
        /// Explicitly upgrade derived storage to retain authenticated rewind checkpoints.
        #[arg(long)]
        enable_rewind: bool,
        /// Permit a pre-genesis replay when an orphaned tip has no retained canonical checkpoint.
        #[arg(long)]
        replay_from_genesis: bool,
    },
    /// Local bounded journal inventory/status or exact operation lookup; no backend/RPC.
    Journal {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Pagination cursor: last operation UUID from the preceding inventory page.
        #[arg(long)]
        after: Option<uuid::Uuid>,
        /// Maximum inventory entries to return (1..=100); does not limit network history scanning.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Inspect this exact payment operation instead of the inventory page.
        #[arg(long)]
        operation_id: Option<uuid::Uuid>,
    },
    /// Preview/apply explicit legacy-to-indexed migration under the network lock.
    JournalMigrate {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Exact proposal digest from a fresh preview; omission previews only. Preserve the coherent store before applying.
        #[arg(long, value_name = "PREVIEW_SHA256")]
        apply: Option<String>,
    },
    /// Explicit local format upgrade; preview/apply before settled archival.
    JournalEnableSettlements {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Exact fresh preview digest to apply the explicit storage upgrade; omission previews, not a rollback path.
        #[arg(long, value_name = "PREVIEW_SHA256")]
        apply: Option<String>,
    },
    /// Reconcile archived inclusion hashes through read-only RPC; never broadcast.
    JournalReconcile {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
    },
    /// Preview/apply settled archival; retain exact original evidence and reorg guards.
    #[command(after_help = BACKEND_HELP)]
    ArchivePayment {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Existing local named wallet bound to the payment/network.
        #[arg(long)]
        wallet: String,
        /// Exact settled payment operation UUID, not a transaction ID.
        #[arg(long)]
        operation_id: uuid::Uuid,
        /// Explicit policy, not finality; inclusion counts as the first block.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        settlement_depth: u32,
        /// Exact fresh preview digest to apply archival; omission previews. Archival is local policy, not chain finality.
        #[arg(long, value_name = "PREVIEW_SHA256")]
        apply: Option<String>,
    },
    /// Preview or apply local unsigned-payment cancellation; no backend, key or RPC calls.
    CancelPayment {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Exact UNSIGNED local payment operation UUID; cancellation never rolls back an on-chain transaction.
        #[arg(long)]
        operation_id: uuid::Uuid,
        /// Exact proposal_sha256 from a fresh preview.
        #[arg(long, value_name = "PREVIEW_SHA256")]
        apply: Option<String>,
    },
    /// Create a named wallet scoped to the selected network; no AWS calls.
    #[command(after_help = BACKEND_HELP)]
    Create {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// New lowercase wallet name (letter first, then letters/digits/hyphens, at most 64 bytes); existing names are never replaced.
        #[arg(long)]
        name: String,
    },
    /// Import a private key into a new scan-only named wallet; no AWS calls or payment signing.
    #[command(after_help = BACKEND_HELP)]
    Import {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// New local scan-only wallet name; cannot send/fund, even after sync. Restore a coherent signing store for signing recovery.
        #[arg(long)]
        name: String,
        /// Existing private backend JSON keyfile, never inline/WIF data; import does not confer signing authority.
        #[arg(long)]
        source_keyfile: PathBuf,
    },
    /// List local public receipts, including incomplete creates; no AWS/backend calls.
    List {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
    },
    /// Re-derive and verify a named wallet's public identity; no AWS calls.
    #[command(after_help = BACKEND_HELP)]
    Show {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Existing local wallet name whose key-derived public identity is verified; not a balance check.
        #[arg(long)]
        wallet: String,
    },
    /// Generate a new plaintext private key file; print only public addresses.
    #[command(after_help = BACKEND_HELP)]
    KeyCreate {
        /// New plaintext backend JSON keyfile in an existing private parent; never replaced or uploaded.
        keyfile: PathBuf,
    },
    /// Print the public addresses of an existing private key file.
    #[command(after_help = BACKEND_HELP)]
    KeyPublic {
        /// Existing private backend JSON keyfile; only its public addresses are printed.
        keyfile: PathBuf,
    },
    /// Import the backend's private JSON file, never WIF or inline secrets.
    #[command(after_help = BACKEND_HELP)]
    KeyImport {
        /// Existing private backend JSON keyfile, not WIF or a mnemonic.
        source_keyfile: PathBuf,
        /// New private destination keyfile; preserve original coherent stores for named-wallet recovery.
        new_keyfile: PathBuf,
    },
    /// Scan a trusted exported history, NOT a current network balance.
    #[command(after_help = BACKEND_HELP)]
    Scan {
        /// Existing private backend JSON keyfile used only by the explicitly trusted local backend.
        keyfile: PathBuf,
        /// Trusted full-block exported history JSON, not a scan result; caller must trust the validating node.
        history_json: PathBuf,
        /// New private scan-summary JSON file. An as-of classification is not current spendability or consensus verification.
        new_scan_json: PathBuf,
    },
    /// Export bounded full-block history from a trusted verified private node.
    HistoryExport {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// New private JSON file; published only after successful session cleanup.
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect owned coinbase rewards, maturity, mempool spends and local reservations.
    #[command(after_help = BACKEND_HELP)]
    Rewards {
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
        /// Local wallet owning the reward key; output distinguishes maturity, mempool use and local reservations.
        #[arg(long, default_value = "funding")]
        wallet: String,
    },
    /// Classify a pinned chain/mempool snapshot; never broadcast or reserve funds.
    #[command(after_help = BACKEND_HELP)]
    #[command(mut_arg("network", |arg| arg.required_unless_present(clap::builder::Resettable::Reset)))]
    Balance {
        /// KEYFILE followed by NETWORK, or NETWORK alone with --wallet; omit NETWORK with --endpoints.
        #[arg(required_unless_present = "wallet", value_name = "KEYFILE_OR_NETWORK")]
        keyfile: Option<PathBuf>,
        /// Select a named local wallet instead of a keyfile; the first positional then means NETWORK.
        #[arg(long)]
        wallet: Option<String>,
        /// As-of scan only, with unknown classifications; supports older scan-only backends.
        #[arg(long)]
        confirmed_only: bool,
        #[command(flatten)]
        history: super::connect_cli::WalletHistoryArgs,
    },
}

#[derive(Subcommand)]
enum BackendCommand {
    /// Verify and privately save an explicit executable path and trusted SHA256.
    #[command(
        after_help = "Example: zdn wallet backend set --backend /absolute/path/ironwood-wallet --backend-sha256 INDEPENDENTLY_TRUSTED_HASH. This replaces the selected wallet root's saved backend pair after verification; no download or PATH lookup occurs. Obtain the hash from independently trusted provenance, not from hashing arbitrary downloaded bytes. Keys are not migrated or uploaded. See docs/wallet.md."
    )]
    Set {
        /// Trusted regular local executable, never a symlink; resolved to an absolute path and rehashed on each use.
        #[arg(long)]
        backend: PathBuf,
        /// Independently trusted executable SHA256 (64 hex characters); supplying it explicitly authorizes these bytes, not all backends.
        #[arg(long)]
        backend_sha256: String,
    },
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicKeys {
    schema_version: u32,
    network: String,
    reward_address: String,
    p2pkh_public_key_hex: String,
    ironwood_address_hex: String,
}

impl PublicKeys {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.public_keys.validate")
    )]
    fn validate(&self) -> Result<()> {
        let address = bs58::decode(&self.reward_address)
            .with_check(None)
            .into_vec()
            .map_err(|_| eyre::eyre!("invalid Testnet public key contract"))?;
        ensure!(
            self.schema_version == 1
                && self.network == "test"
                && hex_bytes(&self.p2pkh_public_key_hex, 33)
                && matches!(&self.p2pkh_public_key_hex[..2], "02" | "03")
                && hex_bytes(&self.ironwood_address_hex, 43)
                && address.len() == 22
                && address[..2] == [0x1d, 0x25],
            "invalid Testnet public key contract"
        );
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scan {
    schema_version: u32,
    tip_height: u32,
    tip_hash: String,
    history_sha256: String,
    anchor_hex: String,
    commitment_count: usize,
    notes: Vec<Note>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Note {
    txid: String,
    action_index: usize,
    position: usize,
    value_zat: u64,
    spent: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedBalance {
    schema_version: u32,
    tip_height: u32,
    tip_hash: String,
    history_sha256: String,
    anchor_hex: String,
    commitment_count: usize,
    mempool_sha256: String,
    confirmed_unspent_zat: u64,
    spendable_zat: u64,
    pending_zat: u64,
    pending_spent_zat: u64,
    immature_zat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reserved_zat: Option<u64>,
}

#[derive(Clone, Copy)]
enum Response {
    Keys,
    Scan,
    Balance,
    ReservedBalance,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PublicResponse {
    Keys(PublicKeys),
    Scan(Scan),
    Balance(ClassifiedBalance),
}

impl PublicResponse {
    fn into_keys(self) -> PublicKeys {
        match self {
            Self::Keys(value) => value,
            _ => unreachable!("Keys response requested"),
        }
    }

    fn into_scan(self) -> Scan {
        match self {
            Self::Scan(value) => value,
            _ => unreachable!("Scan response requested"),
        }
    }

    fn into_balance(self) -> ClassifiedBalance {
        match self {
            Self::Balance(value) => value,
            _ => unreachable!("Balance response requested"),
        }
    }
}

pub(super) fn hex_bytes(value: &str, count: usize) -> bool {
    value.len() == count * 2 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

// Reject symlinks in parents too. Paths must remain under caller control during
// the check/exec interval; this is not a sandbox for a malicious selected backend.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.no_symlinks")
)]
fn no_symlinks(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    for ancestor in absolute.ancestors() {
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            ensure!(
                !meta.file_type().is_symlink(),
                "wallet paths must not contain symlinks"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.regular")
)]
fn regular(path: &Path, private: bool) -> Result<()> {
    no_symlinks(path)?;
    let meta = fs::symlink_metadata(path).context("wallet input is unavailable")?;
    ensure!(meta.is_file(), "wallet input must be a regular file");
    ensure!(
        !private || meta.permissions().mode() & 0o077 == 0,
        "key/output must be a regular private file (no group/other permissions)"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.new_output")
)]
fn new_output(path: &Path) -> Result<()> {
    no_symlinks(path)?;
    ensure!(
        matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "wallet output must not already exist"
    );
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let meta = fs::metadata(parent)?;
    ensure!(
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
        "wallet output requires a private parent directory"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.run")
)]
pub fn run(args: WalletArgs) -> Result<()> {
    let wallet_root = super::data_path(args.wallet_dir, "wallets")?;
    let command = match args.command {
        WalletCommand::Backend {
            command:
                BackendCommand::Set {
                    backend,
                    backend_sha256,
                },
        } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "place backend selection after wallet backend set"
            );
            return super::print_json(&settings::set(&wallet_root, &backend, &backend_sha256)?);
        }
        WalletCommand::Journal {
            history,
            after,
            limit,
            operation_id,
        } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "journal is local only; omit backend selection"
            );
            let identity = history.selection()?.1;
            let scope = wallet_root.join(identity.network_id.to_string());
            let journal = journal::Store::open_maintenance(
                &scope,
                identity.network_id,
                &identity.consensus_fingerprint,
            )?;
            return super::print_json(&journal.inventory(after, limit, operation_id)?);
        }
        WalletCommand::JournalMigrate { history, apply } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "journal-migrate is local only; omit backend selection"
            );
            let identity = history.selection()?.1;
            let scope = wallet_root.join(identity.network_id.to_string());
            let journal = journal::Store::open_maintenance(
                &scope,
                identity.network_id,
                &identity.consensus_fingerprint,
            )?;
            return super::print_json(&journal.migrate(apply.as_deref())?);
        }
        WalletCommand::JournalEnableSettlements { history, apply } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "journal-enable-settlements is local only; omit backend selection"
            );
            let identity = history.selection()?.1;
            let journal = journal::Store::open_maintenance(
                &wallet_root.join(identity.network_id.to_string()),
                identity.network_id,
                &identity.consensus_fingerprint,
            )?;
            return super::print_json(&journal.upgrade_settlements(apply.as_deref())?);
        }
        WalletCommand::JournalReconcile { history } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "journal-reconcile needs read-only RPC, not a backend"
            );
            return maintenance::run_reconcile(&wallet_root, history);
        }
        WalletCommand::CancelPayment {
            history,
            operation_id,
            apply,
        } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "cancel-payment is local only; omit backend selection"
            );
            let identity = history.selection()?.1;
            let scope = wallet_root.join(identity.network_id.to_string());
            let journal =
                journal::Store::open(&scope, identity.network_id, &identity.consensus_fingerprint)?;
            return super::print_json(&journal.cancellation(operation_id, apply.as_deref())?);
        }
        WalletCommand::List { history } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "list is local receipt inspection only; omit backend selection (use show to verify keys)"
            );
            return super::print_json(&store::list(&wallet_root, &history.selection()?.1)?);
        }
        WalletCommand::HistoryExport { history, output } => {
            ensure!(
                args.backend.is_none() && args.backend_sha256.is_none(),
                "history-export is transport only; omit backend selection (use scan to validate blocks)"
            );
            new_output(&output)?;
            let (payload, mut observation) =
                super::connect_cli::with_wallet_history(history, None, false, |history, _| {
                    // Move only the payload; final observation still needs the
                    // pinned tip, digest and anchor unchanged.
                    history.payload.take().context("missing history payload")
                })?;
            // Connection cleanup has completed before publishing either file or success.
            let mut input = payload.reopen()?;
            let mut digest = Sha256::new();
            let mut buffer = [0; 8192];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            super::write_new_file_from(&output, &mut payload.reopen()?)?;
            observation["history_file_sha256"] = serde_json::json!(hex::encode(digest.finalize()));
            observation["output"] = serde_json::json!(output);
            eprintln!(
                "Trusted-node history transport only; block parsing, commitments and note validation require the selected backend. Not consensus verification by zdn."
            );
            return super::print_json(&observation);
        }
        command => command,
    };
    let (backend, backend_sha256) = settings::resolve(
        &wallet_root,
        args.backend.as_deref(),
        args.backend_sha256.as_deref(),
    )?;
    let mut backend_command = Command::new(&backend);
    let command = match command {
        WalletCommand::ArchivePayment {
            history,
            wallet,
            operation_id,
            settlement_depth,
            apply,
        } => {
            return maintenance::archive(
                &backend,
                &wallet_root,
                history,
                &wallet,
                operation_id,
                settlement_depth,
                apply.as_deref(),
            );
        }
        WalletCommand::Sync {
            history,
            wallet,
            max_batches,
            enable_rewind,
            replay_from_genesis,
        } => {
            return sync::run(
                &backend,
                &wallet_root,
                history,
                &wallet,
                max_batches,
                enable_rewind,
                replay_from_genesis,
            );
        }
        WalletCommand::Rewards { history, wallet } => {
            if observation::capable(&backend)? {
                return observation::run(
                    &backend,
                    &wallet_root,
                    history,
                    &wallet,
                    observation::Kind::Rewards,
                );
            }
            return payment::rewards(&backend, &wallet_root, history, &wallet);
        }
        WalletCommand::Create {
            ref history,
            ref name,
        }
        | WalletCommand::Import {
            ref history,
            ref name,
            source_keyfile: _,
        } => {
            let (network_id, consensus_fingerprint) = match &command {
                WalletCommand::Create { .. } => history.creation_scope()?,
                _ => {
                    let identity = history.selection()?.1;
                    (identity.network_id, identity.consensus_fingerprint)
                }
            };
            let source = match &command {
                WalletCommand::Import { source_keyfile, .. } => Some(source_keyfile),
                _ => None,
            };
            if let Some(source) = source {
                regular(source, true)?;
            }
            let path = store::reserve(&wallet_root, network_id, name)?;
            let keyfile = path.join("key.json");
            if let Some(source) = source {
                backend_command.arg("key-import").arg(source).arg(&keyfile);
            } else {
                backend_command.arg("key-create").arg(&keyfile);
            }
            let public =
                execute_backend(backend_command, Some(&keyfile), Response::Keys)?.into_keys();
            return super::print_json(&store::publish(
                &path,
                network_id,
                &consensus_fingerprint,
                name,
                &backend_sha256,
                public,
                source.is_some(),
            )?);
        }
        WalletCommand::Show { history, wallet } => {
            let (receipt, keyfile) = store::load(&wallet_root, &history.selection()?.1, &wallet)?;
            backend_command.arg("key-public").arg(keyfile);
            let public = execute_backend(backend_command, None, Response::Keys)?.into_keys();
            receipt.verify(&public)?;
            return super::print_json(&receipt);
        }
        WalletCommand::Balance {
            keyfile,
            wallet,
            confirmed_only,
            mut history,
        } => {
            let (keyfile, identity) = if let Some(name) = wallet {
                history.named_network(keyfile)?;
                if observation::capable(&backend)? {
                    return observation::run(
                        &backend,
                        &wallet_root,
                        history,
                        &name,
                        observation::Kind::Balance { confirmed_only },
                    );
                }
                let identity = history.selection()?.1;
                let (receipt, key) = store::load(&wallet_root, &identity, &name)?;
                let mut verify = Command::new(fs::canonicalize(&backend)?);
                verify.arg("key-public").arg(&key);
                let public = execute_backend(verify, None, Response::Keys)?.into_keys();
                receipt.verify(&public)?;
                (key, Some(identity))
            } else {
                (
                    keyfile.context("select a private key file or --wallet")?,
                    None,
                )
            };
            regular(&keyfile, true)?;
            let journal = identity
                .as_ref()
                .filter(|_| !confirmed_only)
                .map(|identity| {
                    journal::Store::open(
                        &wallet_root.join(identity.network_id.to_string()),
                        identity.network_id,
                        &identity.consensus_fingerprint,
                    )
                })
                .transpose()?;
            ensure!(
                journal
                    .as_ref()
                    .map(journal::Store::settlements_enabled)
                    .transpose()?
                    != Some(true),
                "settlement-enabled named balances require a state-observation/v2 backend"
            );
            let exclusions = journal
                .as_ref()
                .map(journal::Store::reserved_inputs)
                .transpose()?;
            let (balance, mut observation) = super::connect_cli::with_wallet_history(
                history,
                identity,
                !confirmed_only,
                |history, mempool| {
                    let directory = tempfile::Builder::new()
                        .prefix("zdn-wallet-scan-")
                        .tempdir()?;
                    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
                    let input = history.path();
                    let output = directory.path().join("scan.json");
                    if let Some(mempool) = mempool {
                        let pending = directory.path().join("mempool.json");
                        super::write_new_file(&pending, &mempool.bytes)?;
                        backend_command
                            .arg(if exclusions.is_some() {
                                "balance-reserved"
                            } else {
                                "balance"
                            })
                            .arg(&keyfile)
                            .arg(input)
                            .arg(pending);
                        if let Some(exclusions) = &exclusions {
                            let path = directory.path().join("exclusions.json");
                            super::write_new_file(&path, &serde_json::to_vec(exclusions)?)?;
                            backend_command.arg(path);
                        }
                        backend_command.arg(&output);
                        let value = execute_backend(
                            backend_command,
                            Some(&output),
                            if exclusions.is_some() {
                                Response::ReservedBalance
                            } else {
                                Response::Balance
                            },
                        )?
                        .into_balance();
                        ensure!(
                            value.tip_height == history.tip.height
                                && value.tip_hash == history.tip.hash
                                && value.history_sha256 == history.digest
                                && value.anchor_hex == history.anchor
                                && value.mempool_sha256 == mempool.digest,
                            "wallet balance provenance does not match the collected history/mempool"
                        );
                        let mut balance = serde_json::json!({"pool":"ironwood", "confirmed_unspent_zat":value.confirmed_unspent_zat,
                            "spendable_zat":value.spendable_zat,"pending_zat":value.pending_zat,
                            "pending_spent_zat":value.pending_spent_zat,"immature_zat":value.immature_zat,
                            "mempool_sha256":value.mempool_sha256});
                        if let Some(reserved) = value.reserved_zat {
                            balance["reserved_zat"] = serde_json::json!(reserved);
                        }
                        return Ok(balance);
                    }
                    backend_command
                        .arg("scan")
                        .arg(&keyfile)
                        .arg(input)
                        .arg(&output);
                    let scan = execute_backend(backend_command, Some(&output), Response::Scan)?
                        .into_scan();
                    ensure!(
                        scan.tip_height == history.tip.height
                            && scan.tip_hash == history.tip.hash
                            && scan.history_sha256 == history.digest
                            && scan.anchor_hex == history.anchor,
                        "wallet scan provenance does not match the collected history"
                    );
                    let mut amount = 0u64;
                    let mut count = 0usize;
                    for note in scan.notes.iter().filter(|note| !note.spent) {
                        amount = amount
                            .checked_add(note.value_zat)
                            .context("wallet note total overflow")?;
                        ensure!(
                            amount <= 2_100_000_000_000_000,
                            "wallet note total exceeds money bound"
                        );
                        count += 1;
                    }
                    Ok(serde_json::json!({
                        "pool":"ironwood", "confirmed_unspent_zat":amount, "unspent_note_count":count,
                        "spendable_zat":null, "pending_zat":null, "immature_zat":null
                    }))
                },
            )?;
            observation["balance"] = balance;
            observation["local_reservations_checked"] = serde_json::json!(journal.is_some());
            if confirmed_only {
                eprintln!(
                    "As-of trusted-node snapshot only, not an atomic current balance. Spendable/pending/immature are unknown (null); no mempool or local payment-journal classification is available."
                );
            } else {
                eprintln!(
                    "Rechecked chain/mempool observation, not an atomic current balance. Named balances also subtract local reservations. Pending is gross incoming including change; pending-spent is gross confirmed input value, not payment/fee. Transparent rewards are excluded; use wallet rewards."
                );
            }
            return super::print_json(&observation);
        }
        command => command,
    };
    let (output_path, scan) = match &command {
        WalletCommand::KeyCreate { keyfile } => {
            new_output(keyfile)?;
            backend_command.arg("key-create").arg(keyfile);
            (Some(keyfile.as_path()), Response::Keys)
        }
        WalletCommand::KeyPublic { keyfile } => {
            regular(keyfile, true)?;
            backend_command.arg("key-public").arg(keyfile);
            (None, Response::Keys)
        }
        WalletCommand::KeyImport {
            source_keyfile,
            new_keyfile,
        } => {
            regular(source_keyfile, true)?;
            new_output(new_keyfile)?;
            backend_command
                .arg("key-import")
                .arg(source_keyfile)
                .arg(new_keyfile);
            (Some(new_keyfile.as_path()), Response::Keys)
        }
        WalletCommand::Scan {
            keyfile,
            history_json,
            new_scan_json,
        } => {
            regular(keyfile, true)?;
            regular(history_json, false)?;
            new_output(new_scan_json)?;
            backend_command
                .arg("scan")
                .arg(keyfile)
                .arg(history_json)
                .arg(new_scan_json);
            (Some(new_scan_json.as_path()), Response::Scan)
        }
        WalletCommand::Backend { .. }
        | WalletCommand::Balance { .. }
        | WalletCommand::Sync { .. }
        | WalletCommand::Rewards { .. }
        | WalletCommand::HistoryExport { .. }
        | WalletCommand::Create { .. }
        | WalletCommand::Import { .. }
        | WalletCommand::Show { .. }
        | WalletCommand::Journal { .. }
        | WalletCommand::JournalMigrate { .. }
        | WalletCommand::JournalEnableSettlements { .. }
        | WalletCommand::JournalReconcile { .. }
        | WalletCommand::ArchivePayment { .. }
        | WalletCommand::CancelPayment { .. }
        | WalletCommand::List { .. } => unreachable!(),
    };
    let public = serde_json::to_value(execute_backend(backend_command, output_path, scan)?)?;
    if matches!(scan, Response::Scan) {
        eprintln!(
            "Scan covers only the supplied trusted exported history; not a current network balance or consensus/canonical-chain verification."
        );
    }
    super::print_json(&public)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.verified_backend")
)]
fn verified_backend(backend: &Path, expected: &str) -> Result<PathBuf> {
    ensure!(
        hex_bytes(expected, 32),
        "backend SHA256 must be 64 hexadecimal characters"
    );
    regular(backend, false)?;
    ensure!(
        fs::metadata(backend)?.permissions().mode() & 0o111 != 0,
        "backend must be executable"
    );
    let mut file = fs::File::open(backend)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    ensure!(
        hex::encode(hash.finalize()).eq_ignore_ascii_case(expected),
        "backend SHA256 mismatch"
    );
    Ok(fs::canonicalize(backend)?)
}

fn backend_stdout(mut command: Command) -> Result<String> {
    let result = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(60))
        .map_err(|_| eyre::eyre!("wallet backend failed to run within process limits; diagnostics redacted; a new output may remain"))?;
    ensure!(
        result.success,
        "wallet backend failed; diagnostics redacted; a new output may remain (not rolled back)"
    );
    Ok(result.stdout)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.execute_backend")
)]
fn execute_backend(
    command: Command,
    output_path: Option<&Path>,
    response: Response,
) -> Result<PublicResponse> {
    let stdout = backend_stdout(command)?;
    let invalid = || {
        eyre::eyre!(
            "wallet backend returned invalid public JSON; diagnostics redacted; a new output may remain"
        )
    };
    // Deserialize exact structures before serializing anything back to stdout.
    let public = if matches!(response, Response::Scan) {
        let value: Scan = serde_json::from_str(&stdout).map_err(|_| invalid())?;
        ensure!(
            value.schema_version == 1
                && value.tip_height < 4096
                && value.commitment_count <= 16384
                && value.notes.len() <= 32768
                && hex_bytes(&value.tip_hash, 32)
                && hex_bytes(&value.history_sha256, 32)
                && hex_bytes(&value.anchor_hex, 32),
            "invalid public scan contract"
        );
        let mut positions = std::collections::BTreeSet::new();
        for note in &value.notes {
            ensure!(
                hex_bytes(&note.txid, 32)
                    && note.action_index < 16384
                    && note.position < value.commitment_count
                    && positions.insert(note.position)
                    && note.value_zat > 0
                    && note.value_zat <= 2_100_000_000_000_000,
                "invalid public note contract"
            );
        }
        PublicResponse::Scan(value)
    } else if matches!(response, Response::Balance | Response::ReservedBalance) {
        let value: ClassifiedBalance = serde_json::from_str(&stdout).map_err(|_| invalid())?;
        ensure!(
            value.schema_version == 1
                && value.tip_height < 4096
                && value.commitment_count <= 16384
                && hex_bytes(&value.tip_hash, 32)
                && hex_bytes(&value.history_sha256, 32)
                && hex_bytes(&value.anchor_hex, 32)
                && hex_bytes(&value.mempool_sha256, 32)
                && value.immature_zat == 0
                && value.reserved_zat.is_some() == matches!(response, Response::ReservedBalance)
                && [
                    value.confirmed_unspent_zat,
                    value.spendable_zat,
                    value.pending_zat,
                    value.pending_spent_zat,
                    value.reserved_zat.unwrap_or(0)
                ]
                .iter()
                .all(|n| *n <= 2_100_000_000_000_000)
                && value
                    .spendable_zat
                    .checked_add(value.pending_spent_zat)
                    .and_then(|n| n.checked_add(value.reserved_zat.unwrap_or(0)))
                    == Some(value.confirmed_unspent_zat),
            "invalid public balance contract"
        );
        PublicResponse::Balance(value)
    } else {
        let value: PublicKeys = serde_json::from_str(&stdout).map_err(|_| invalid())?;
        value.validate()?;
        PublicResponse::Keys(value)
    };
    if let Some(path) = output_path {
        regular(path, true)?;
    }
    Ok(public)
}
