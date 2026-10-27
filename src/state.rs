//! Durable local identities and operation receipts. This module makes no cloud calls.

use crate::foundation::DeploymentFile;
use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use uuid::Uuid;

const FORMAT_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub team_id: String,
    pub account_id: String,
    pub region: String,
}

impl Scope {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.scope.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_token(&self.team_id),
            "team ID must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens"
        );
        ensure!(
            self.account_id.len() == 12 && self.account_id.bytes().all(|b| b.is_ascii_digit()),
            "AWS account ID must contain exactly 12 digits"
        );
        ensure!(
            !self.region.is_empty()
                && self.region.len() <= 64
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "AWS region must contain lowercase ASCII letters, digits, or hyphens"
        );
        Ok(())
    }
}

/// The label is deliberately absent: renaming a network does not change its ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingContext {
    pub config_path: PathBuf,
    pub worktree: Option<PathBuf>,
    pub branch: Option<String>,
    pub scope: Scope,
}

impl BindingContext {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.binding_context.new")
    )]
    pub fn new(
        config_path: impl AsRef<Path>,
        worktree: Option<PathBuf>,
        branch: Option<String>,
        scope: Scope,
    ) -> Result<Self> {
        let context = Self {
            config_path: fs::canonicalize(config_path.as_ref())
                .context("resolve configuration path before binding a network")?,
            worktree: worktree
                .map(|path| fs::canonicalize(path).context("resolve Git worktree path"))
                .transpose()?,
            branch,
            scope,
        };
        context.validate()?;
        ensure!(
            context.config_path.is_file(),
            "configuration path is not a file"
        );
        if let Some(worktree) = &context.worktree {
            ensure!(worktree.is_dir(), "Git worktree path is not a directory");
        }
        Ok(context)
    }

    /// A stable digest of the complete local context, including account and region.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.binding_context.validate")
    )]
    fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.config_path.is_absolute(),
            "configuration path must be absolute"
        );
        ensure!(
            self.config_path.to_str().is_some(),
            "configuration path must be valid UTF-8"
        );
        if let Some(worktree) = &self.worktree {
            ensure!(worktree.is_absolute(), "worktree path must be absolute");
            ensure!(
                worktree.to_str().is_some(),
                "worktree path must be valid UTF-8"
            );
        }
        ensure!(
            self.worktree.is_some() || self.branch.is_none(),
            "a branch requires a Git worktree"
        );
        if let Some(branch) = &self.branch {
            ensure!(
                !branch.is_empty() && !branch.chars().any(char::is_control),
                "branch must be nonempty and contain no control characters"
            );
        }
        Ok(())
    }
}

/// An offline binding is not a cloud reservation or a claim of resource ownership.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reservation {
    Unreserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub context_key: String,
    pub context: BindingContext,
    pub network_id: Uuid,
    pub label: String,
    pub reservation: Reservation,
}

impl Binding {
    pub fn display_name(&self) -> String {
        format!("{}-{}", self.label, &self.network_id.to_string()[..8])
    }

    /// Keep the entire ID. Reject an excessive name instead of truncating identity.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.binding.resource_name")
    )]
    pub fn resource_name(&self, purpose: &str, max_len: usize) -> Result<String> {
        ensure!(
            !purpose.is_empty()
                && purpose
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !purpose.starts_with('-')
                && !purpose.ends_with('-'),
            "resource purpose must use lowercase letters, digits, and internal hyphens"
        );
        let name = format!("zdn-{}-{purpose}", self.network_id.simple());
        ensure!(
            name.len() <= max_len,
            "resource name exceeds the service limit of {max_len} bytes"
        );
        Ok(name)
    }

    pub fn to_export(&self) -> BindingExport {
        BindingExport {
            version: FORMAT_VERSION,
            network_id: self.network_id,
            scope: self.context.scope.clone(),
            label: self.label.clone(),
            reservation: self.reservation,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.context_key == self.context.fingerprint()?,
            "binding context fingerprint does not match its contents"
        );
        validate_uuid(self.network_id)?;
        validate_label(&self.label)
    }
}

/// Sharing this record permits explicit local attachment; it does not grant IAM access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingExport {
    pub version: u32,
    pub network_id: Uuid,
    pub scope: Scope,
    pub label: String,
    pub reservation: Reservation,
}

impl BindingExport {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.binding_export.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == FORMAT_VERSION,
            "unsupported binding receipt version {}; expected {FORMAT_VERSION}",
            self.version
        );
        validate_uuid(self.network_id)?;
        self.scope.validate()?;
        validate_label(&self.label)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationInput {
    pub config_sha256: String,
    pub source_manifest_sha256: Option<String>,
    pub archive_sha256: Option<String>,
}

impl OperationInput {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.operation_input.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        validate_hash(&self.config_sha256)?;
        ensure!(
            self.source_manifest_sha256.is_some() == self.archive_sha256.is_some(),
            "a source operation requires both source manifest and archive hashes"
        );
        for hash in [&self.source_manifest_sha256, &self.archive_sha256]
            .into_iter()
            .flatten()
        {
            validate_hash(hash)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhaseStatus {
    Pending,
    Running {
        external_ref: Option<String>,
    },
    Succeeded {
        result: serde_json::Value,
    },
    Failed {
        message: String,
        retry_safe: bool,
    },
    Unknown {
        message: String,
        external_ref: Option<String>,
    },
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseRecord {
    pub name: String,
    pub status: PhaseStatus,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub version: u32,
    pub operation_id: Uuid,
    pub network_id: Uuid,
    pub scope: Scope,
    pub kind: String,
    pub inputs: OperationInput,
    pub revision: u64,
    /// Counts non-cancellation changes, including reconciliation and retries.
    /// Legacy receipts start at zero and acquire this counter on their next write.
    #[serde(default)]
    pub state_revision: u64,
    pub cancel_requested: bool,
    pub phases: Vec<PhaseRecord>,
}

impl OperationReceipt {
    /// Decide from this saved snapshot only; no cloud effects or ownership checks.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.operation_receipt.resume_plan")
    )]
    pub fn resume_plan(&self, expected_inputs: &OperationInput) -> Result<ResumePlan> {
        expected_inputs.validate()?;
        if &self.inputs != expected_inputs {
            return Err(crate::immutable_inputs::ImmutableInputError::new(
                "resume inputs differ from the saved configuration or source snapshot; restore the original inputs or start a new operation",
                crate::immutable_inputs::ImmutableInputReport::operation_inputs(&self.inputs, expected_inputs)?,
            ).into());
        }
        let phases = self
            .phases
            .iter()
            .map(|phase| {
                let action = match phase.status {
                    PhaseStatus::Succeeded { .. } => ResumeAction::ReconcileSuccess,
                    PhaseStatus::Running { .. }
                    | PhaseStatus::Unknown { .. }
                    | PhaseStatus::Failed {
                        retry_safe: false, ..
                    } => ResumeAction::ReconcileOutcome,
                    PhaseStatus::Cancelled => ResumeAction::StopCancelled,
                    _ if self.cancel_requested => ResumeAction::StopCancelled,
                    PhaseStatus::Pending => ResumeAction::Run,
                    PhaseStatus::Failed {
                        retry_safe: true, ..
                    } => ResumeAction::Retry,
                };
                PhaseDecision {
                    name: phase.name.clone(),
                    action,
                }
            })
            .collect();
        Ok(ResumePlan {
            operation_id: self.operation_id,
            network_id: self.network_id,
            cancel_requested: self.cancel_requested,
            phases,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.operation_receipt.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == FORMAT_VERSION,
            "unsupported operation receipt version {}; expected {FORMAT_VERSION}",
            self.version
        );
        validate_uuid(self.operation_id)?;
        validate_uuid(self.network_id)?;
        self.scope.validate()?;
        self.inputs.validate()?;
        ensure!(
            self.state_revision <= self.revision,
            "invalid operation state revision"
        );
        ensure!(valid_token(&self.kind), "invalid operation kind");
        ensure!(
            !self.phases.is_empty(),
            "operation must contain at least one phase"
        );
        let mut names = std::collections::BTreeSet::new();
        for phase in &self.phases {
            ensure!(valid_token(&phase.name), "invalid operation phase name");
            ensure!(
                names.insert(&phase.name),
                "duplicate operation phase {}",
                phase.name
            );
        }
        Ok(())
    }
}

/// These are decisions for an adapter, never evidence that a cloud effect happened.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeAction {
    Run,
    Retry,
    ReconcileSuccess,
    ReconcileOutcome,
    StopCancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseDecision {
    pub name: String,
    pub action: ResumeAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResumePlan {
    pub operation_id: Uuid,
    pub network_id: Uuid,
    pub cancel_requested: bool,
    /// Decisions are ordered. Verify each earlier phase before acting on a later one.
    pub phases: Vec<PhaseDecision>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    bindings: Vec<Binding>,
    operations: Vec<OperationReceipt>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            bindings: Vec::new(),
            operations: Vec::new(),
        }
    }
}

impl Ledger {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.ledger.validate")
    )]
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == FORMAT_VERSION,
            "unsupported local state version {}; expected {FORMAT_VERSION}",
            self.version
        );
        let mut keys = std::collections::BTreeSet::new();
        let mut network_scopes = std::collections::BTreeMap::new();
        for binding in &self.bindings {
            binding.validate()?;
            ensure!(
                keys.insert(&binding.context_key),
                "duplicate local binding context"
            );
            if let Some(scope) = network_scopes.insert(binding.network_id, &binding.context.scope) {
                ensure!(
                    scope == &binding.context.scope,
                    "network ID is bound to more than one team, account, or region"
                );
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            ensure!(ids.insert(operation.operation_id), "duplicate operation ID");
            ensure!(
                network_scopes
                    .get(&operation.network_id)
                    .is_some_and(|scope| **scope == operation.scope),
                "operation has no matching local network binding"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct StateStore {
    root: PathBuf,
    lock_timeout: Duration,
}

struct StoreLock(File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        // A concurrent spawn can briefly inherit this open-file description.
        // Release the owner's lock even while that descriptor remains open.
        let _ = FileExt::unlock(&self.0);
    }
}

/// Bounded contention, separate from invalid or unreadable local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateLockBusy;

impl std::fmt::Display for StateLockBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local state is busy; another zdn process holds its lock; retry after that operation finishes")
    }
}

impl std::error::Error for StateLockBusy {}

impl StateStore {
    /// Open a dedicated metadata directory. Callers must keep it outside tracked source.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.open")
    )]
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        reject_symlink(root.as_ref())?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(root.as_ref())
            .context("create local state directory")?;
        // mkdir sets permissions only on directories this call creates. An
        // existing --state-dir can be an unrelated user directory: never chmod it.
        check_private_directory(root.as_ref())?;
        let root = fs::canonicalize(root.as_ref()).context("resolve local state directory")?;
        Ok(Self {
            root,
            lock_timeout: Duration::from_secs(2),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Bound local contention. A zero timeout tries once without waiting.
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Create explicitly or return the existing identity, updating only its label.
    pub fn bind(&self, context: &BindingContext, label: &str) -> Result<Binding> {
        self.bind_with_id(context, label, Uuid::new_v4)
    }

    /// Inject an ID source for deterministic tests. Production callers use `bind`.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.bind_with_id")
    )]
    pub fn bind_with_id(
        &self,
        context: &BindingContext,
        label: &str,
        new_id: impl FnOnce() -> Uuid,
    ) -> Result<Binding> {
        self.check_context(context)?;
        validate_label(label)?;
        let key = context.fingerprint()?;
        self.mutate(|ledger| {
            if let Some(binding) = ledger
                .bindings
                .iter_mut()
                .find(|binding| binding.context_key == key)
            {
                binding.label = label.to_owned();
                return Ok(binding.clone());
            }
            let network_id = new_id();
            validate_uuid(network_id)?;
            ensure!(
                !ledger
                    .bindings
                    .iter()
                    .any(|binding| binding.network_id == network_id),
                "generated network ID already exists; create a new ID or attach explicitly"
            );
            let binding = Binding {
                context_key: key,
                context: context.clone(),
                network_id,
                label: label.to_owned(),
                reservation: Reservation::Unreserved,
            };
            ledger.bindings.push(binding.clone());
            Ok(binding)
        })
    }

    pub fn binding(&self, context: &BindingContext) -> Result<Binding> {
        self.check_context(context)?;
        let key = context.fingerprint()?;
        self.read(|ledger| {
            ledger.bindings.iter().find(|binding| binding.context_key == key).cloned()
                .context("no local binding for this context; create a new binding or explicitly attach a saved receipt")
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.list")
    )]
    pub fn list(&self, scope: &Scope) -> Result<Vec<Binding>> {
        scope.validate()?;
        self.read(|ledger| {
            Ok(ledger
                .bindings
                .iter()
                .filter(|binding| &binding.context.scope == scope)
                .cloned()
                .collect())
        })
    }

    /// Read bindings and operation receipts from one validated ledger version.
    /// The entire ledger is checked before filtering to this scope; the lock is
    /// released before the caller inspects separate deployment files.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.snapshot")
    )]
    pub fn snapshot(&self, scope: &Scope) -> Result<(Vec<Binding>, Vec<OperationReceipt>)> {
        scope.validate()?;
        self.read(|ledger| {
            Ok((
                ledger
                    .bindings
                    .into_iter()
                    .filter(|binding| &binding.context.scope == scope)
                    .collect(),
                ledger
                    .operations
                    .into_iter()
                    .filter(|operation| &operation.scope == scope)
                    .collect(),
            ))
        })
    }

    /// Snapshot every receipt for one still-current binding, including old
    /// cancellation and reconciliation evidence. Makes no cloud calls.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.handoff_operations")
    )]
    pub fn handoff_operations(&self, binding: &Binding) -> Result<Vec<OperationReceipt>> {
        binding.validate()?;
        self.read(|ledger| {
            ensure!(ledger.bindings.contains(binding), "handoff binding changed");
            Ok(ledger
                .operations
                .iter()
                .filter(|operation| {
                    operation.network_id == binding.network_id
                        && operation.scope == binding.context.scope
                })
                .cloned()
                .collect())
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.attach")
    )]
    pub fn attach(
        &self,
        context: &BindingContext,
        expected_network_id: Uuid,
        receipt: &BindingExport,
    ) -> Result<Binding> {
        self.check_context(context)?;
        receipt.validate()?;
        ensure!(
            receipt.network_id == expected_network_id,
            "receipt network ID does not match the explicitly selected ID"
        );
        ensure!(
            receipt.scope == context.scope,
            "receipt team, AWS account, or region does not match this context"
        );
        let key = context.fingerprint()?;
        self.mutate(|ledger| {
            ensure!(
                !ledger.bindings.iter().any(|binding| binding.network_id == receipt.network_id
                    && binding.context.scope != receipt.scope),
                "receipt network ID is already bound to another team, account, or region"
            );
            if let Some(existing) = ledger.bindings.iter().find(|binding| binding.context_key == key) {
                ensure!(existing.network_id == expected_network_id, "this context is already bound to another network; use a different configuration context");
                return Ok(existing.clone());
            }
            let binding = Binding { context_key: key, context: context.clone(), network_id: receipt.network_id, label: receipt.label.clone(), reservation: Reservation::Unreserved };
            ledger.bindings.push(binding.clone());
            Ok(binding)
        })
    }

    /// Publish a verified offline handoff while holding the ledger and staged
    /// deployment writer locks. A crash after rename can leave an undiscoverable
    /// orphan; existing destinations (including such orphans) are never replaced.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.import_handoff")
    )]
    pub fn import_handoff(
        &self,
        context: &BindingContext,
        expected_network_id: Uuid,
        receipt: &BindingExport,
        operations: &[OperationReceipt],
        staging_root: &Path,
    ) -> Result<Binding> {
        self.check_context(context)?;
        receipt.validate()?;
        ensure!(
            receipt.network_id == expected_network_id,
            "handoff network ID differs from selection"
        );
        ensure!(
            receipt.scope == context.scope,
            "handoff scope differs from receiving context"
        );
        let binding = Binding {
            context_key: context.fingerprint()?,
            context: context.clone(),
            network_id: receipt.network_id,
            label: receipt.label.clone(),
            reservation: receipt.reservation,
        };
        let (published, _writer) = self.mutate::<(_, DeploymentFile)>(|ledger| {
            ensure!(
                !ledger
                    .bindings
                    .iter()
                    .any(|b| b.context_key == binding.context_key
                        || b.network_id == expected_network_id),
                "handoff context or network is already bound"
            );
            let mut operation_ids: std::collections::BTreeSet<_> = ledger
                .operations
                .iter()
                .map(|operation| operation.operation_id)
                .collect();
            for operation in operations {
                operation.validate()?;
                ensure!(
                    operation.network_id == expected_network_id && operation.scope == context.scope,
                    "handoff operation scope or network differs"
                );
                ensure!(
                    operation_ids.insert(operation.operation_id),
                    "handoff operation ID already exists"
                );
            }
            ledger.bindings.push(binding.clone());
            ledger.operations.extend_from_slice(operations);
            ledger.validate()?;
            ensure!(
                (serde_json::to_vec_pretty(ledger)?.len() as u64) < MAX_STATE_BYTES,
                "local state exceeds its supported size limit"
            );
            let staged = DeploymentFile::open(staging_root, expected_network_id)?;
            let deployment = staged.load()?;
            ensure!(
                deployment.spec.scope == context.scope,
                "staged deployment scope differs"
            );
            let parent = self.root.join("foundation");
            crate::foundation::private_directory(&parent)?;
            // The staged writer lock moves WITH the directory. Never lock a
            // destination directory and then replace its inode underneath users.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let destination = parent.join(expected_network_id.to_string());
                #[cfg(target_os = "linux")]
                nix::fcntl::renameat2(
                    nix::fcntl::AT_FDCWD,
                    staged.directory(),
                    nix::fcntl::AT_FDCWD,
                    &destination,
                    nix::fcntl::RenameFlags::RENAME_NOREPLACE,
                )
                .context("install handoff deployment without replacing existing state")?;
                #[cfg(target_os = "macos")]
                rustix::fs::renameat_with(
                    rustix::fs::CWD,
                    staged.directory(),
                    rustix::fs::CWD,
                    &destination,
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .context("install handoff deployment without replacing existing state")?;
                File::open(&parent)?.sync_all()?;
                Ok((binding.clone(), staged))
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            bail!("atomic no-replace handoff publication is unsupported on this platform");
        })?;
        Ok(published)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.resolve")
    )]
    pub fn resolve(
        &self,
        scope: &Scope,
        selector: &str,
        current_context: Option<&BindingContext>,
    ) -> Result<Binding> {
        scope.validate()?;
        ensure!(!selector.is_empty(), "network selection must not be empty");
        if let Some(context) = current_context {
            self.check_context(context)?;
            ensure!(
                &context.scope == scope,
                "current binding context has a different team, account, or region"
            );
        }
        let current_key = current_context
            .map(BindingContext::fingerprint)
            .transpose()?;
        self.read(|ledger| {
            let candidates: Vec<_> = ledger.bindings.iter().filter(|binding| &binding.context.scope == scope).collect();
            // An explicit full ID always wins over a human label, including in
            // the current context. Otherwise a UUID-shaped label could redirect it.
            if let Ok(network_id) = Uuid::parse_str(selector) {
                return candidates.iter().find(|binding| binding.network_id == network_id)
                    .map(|binding| (*binding).clone())
                    .context("selected full network ID has no local binding in this team, account, and region");
            }
            if let Some(binding) = candidates.iter().find(|binding| Some(&binding.context_key) == current_key.as_ref()) {
                if binding.label == selector || binding.network_id.to_string() == selector {
                    return Ok((*binding).clone());
                }
            }
            let mut matches = std::collections::BTreeMap::new();
            for binding in candidates {
                if binding.label == selector || binding.network_id.to_string().starts_with(selector) {
                    matches.entry(binding.network_id).or_insert(binding);
                }
            }
            match matches.len() {
                0 => bail!("no network matches {selector:?} in this team, account, and region; create or explicitly attach a binding"),
                1 => Ok(matches.into_values().next().expect("one matching network").clone()),
                _ => bail!("ambiguous network selection {selector:?}; select a full ID: {}", matches.keys().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
            }
        })
    }

    pub fn begin_operation(
        &self,
        binding: &Binding,
        kind: &str,
        inputs: OperationInput,
        phase_names: &[&str],
    ) -> Result<OperationReceipt> {
        self.begin_operation_with_id(binding, kind, inputs, phase_names, Uuid::new_v4())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.begin_operation_with_id")
    )]
    pub fn begin_operation_with_id(
        &self,
        binding: &Binding,
        kind: &str,
        inputs: OperationInput,
        phase_names: &[&str],
        operation_id: Uuid,
    ) -> Result<OperationReceipt> {
        binding.validate()?;
        let receipt = OperationReceipt {
            version: FORMAT_VERSION,
            operation_id,
            network_id: binding.network_id,
            scope: binding.context.scope.clone(),
            kind: kind.to_owned(),
            inputs,
            revision: 0,
            state_revision: 0,
            cancel_requested: false,
            phases: phase_names
                .iter()
                .map(|name| PhaseRecord {
                    name: (*name).to_owned(),
                    status: PhaseStatus::Pending,
                })
                .collect(),
        };
        receipt.validate()?;
        self.mutate(|ledger| {
            ensure!(
                ledger
                    .bindings
                    .iter()
                    .any(|existing| existing.context_key == binding.context_key
                        && existing.network_id == binding.network_id),
                "operation binding is not saved in this local store"
            );
            ensure!(
                !ledger
                    .operations
                    .iter()
                    .any(|existing| existing.operation_id == operation_id),
                "operation ID already exists"
            );
            ledger.operations.push(receipt.clone());
            Ok(receipt)
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.operation")
    )]
    pub fn operation(&self, operation_id: Uuid) -> Result<OperationReceipt> {
        self.read(|ledger| {
            ledger
                .operations
                .iter()
                .find(|receipt| receipt.operation_id == operation_id)
                .cloned()
                .context("operation receipt was not found")
        })
    }

    /// Persist Running before an effect. An interrupted Running phase requires reconciliation.
    /// `expected_revision` prevents a stale reader from overwriting a newer result.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.record_phase")
    )]
    pub fn record_phase(
        &self,
        operation_id: Uuid,
        expected_revision: u64,
        phase_name: &str,
        status: PhaseStatus,
    ) -> Result<OperationReceipt> {
        self.change_operation(operation_id, expected_revision, false, |receipt| {
            let index = receipt
                .phases
                .iter()
                .position(|phase| phase.name == phase_name)
                .context("operation phase was not found")?;
            let previous = &receipt.phases[index].status;
            ensure!(
                allowed_transition(previous, &status),
                "phase transition requires reconciliation or is invalid"
            );
            if matches!(status, PhaseStatus::Running { .. }) {
                ensure!(
                    !receipt.cancel_requested,
                    "operation cancellation was requested; no new effect may start"
                );
                ensure!(
                    receipt.phases[..index]
                        .iter()
                        .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. })),
                    "earlier phases must succeed before starting this phase"
                );
                ensure_later_phases_pending(receipt, index)?;
            }
            receipt.phases[index].status = status;
            Ok(())
        })
    }

    /// Finish an effect while preserving cancellation requested by another process.
    /// Only cancellation/revision changes may be merged; a changed phase or input
    /// still rejects the stale writer. This never authorizes starting another effect.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.record_phase_outcome")
    )]
    pub fn record_phase_outcome(
        &self,
        expected: &OperationReceipt,
        phase_name: &str,
        status: PhaseStatus,
    ) -> Result<OperationReceipt> {
        ensure!(
            matches!(
                status,
                PhaseStatus::Succeeded { .. }
                    | PhaseStatus::Failed { .. }
                    | PhaseStatus::Unknown { .. }
            ),
            "phase outcome must finish an existing effect"
        );
        self.mutate(|ledger| {
            let receipt = ledger
                .operations
                .iter_mut()
                .find(|receipt| receipt.operation_id == expected.operation_id)
                .context("operation receipt was not found")?;
            let mut comparable = receipt.clone();
            comparable.revision = expected.revision;
            comparable.cancel_requested = expected.cancel_requested;
            ensure!(
                receipt.revision >= expected.revision
                    && (!expected.cancel_requested || receipt.cancel_requested)
                    && comparable == *expected,
                "operation changed beyond cancellation; inspect its phase result"
            );
            let phase = receipt
                .phases
                .iter_mut()
                .find(|phase| phase.name == phase_name)
                .context("operation phase was not found")?;
            ensure!(
                matches!(phase.status, PhaseStatus::Running { .. }),
                "phase outcome requires a running effect"
            );
            phase.status = status;
            receipt.state_revision = receipt
                .state_revision
                .checked_add(1)
                .context("operation state revision overflow")?;
            receipt.revision = receipt
                .revision
                .checked_add(1)
                .context("operation revision overflow")?;
            receipt.validate()?;
            Ok(receipt.clone())
        })
    }

    /// Save an adapter's independently checked outcome. This method itself checks no cloud state.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.reconcile_phase")
    )]
    pub fn reconcile_phase(
        &self,
        operation_id: Uuid,
        expected_revision: u64,
        phase_name: &str,
        checked_status: PhaseStatus,
    ) -> Result<OperationReceipt> {
        ensure!(
            matches!(
                checked_status,
                PhaseStatus::Succeeded { .. }
                    | PhaseStatus::Failed { .. }
                    | PhaseStatus::Cancelled
                    | PhaseStatus::Unknown { .. }
            ),
            "reconciliation must report a checked outcome"
        );
        self.change_operation(operation_id, expected_revision, false, |receipt| {
            let index = receipt
                .phases
                .iter()
                .position(|phase| phase.name == phase_name)
                .context("operation phase was not found")?;
            ensure!(
                matches!(
                    receipt.phases[index].status,
                    PhaseStatus::Running { .. }
                        | PhaseStatus::Unknown { .. }
                        | PhaseStatus::Succeeded { .. }
                        | PhaseStatus::Failed {
                            retry_safe: false,
                            ..
                        }
                ),
                "phase does not require reconciliation"
            );
            if matches!(
                checked_status,
                PhaseStatus::Failed {
                    retry_safe: true,
                    ..
                }
            ) {
                ensure_later_phases_pending(receipt, index)?;
            }
            receipt.phases[index].status = checked_status;
            Ok(())
        })
    }

    /// Cancellation is intent only. Active or uncertain effects must still be reconciled.
    pub fn request_cancel(
        &self,
        operation_id: Uuid,
        expected_revision: u64,
    ) -> Result<OperationReceipt> {
        self.change_operation(operation_id, expected_revision, true, |receipt| {
            receipt.cancel_requested = true;
            Ok(())
        })
    }

    pub fn resume(
        &self,
        operation_id: Uuid,
        expected_inputs: &OperationInput,
    ) -> Result<ResumePlan> {
        expected_inputs.validate()?;
        self.operation(operation_id)?.resume_plan(expected_inputs)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.change_operation")
    )]
    fn change_operation(
        &self,
        operation_id: Uuid,
        expected_revision: u64,
        cancellation_only: bool,
        change: impl FnOnce(&mut OperationReceipt) -> Result<()>,
    ) -> Result<OperationReceipt> {
        self.mutate(|ledger| {
            let receipt = ledger
                .operations
                .iter_mut()
                .find(|receipt| receipt.operation_id == operation_id)
                .context("operation receipt was not found")?;
            ensure!(
                receipt.revision == expected_revision,
                "stale operation receipt revision; reload before saving a phase result"
            );
            change(receipt)?;
            if !cancellation_only {
                receipt.state_revision = receipt
                    .state_revision
                    .checked_add(1)
                    .context("operation state revision overflow")?;
            }
            receipt.revision = receipt
                .revision
                .checked_add(1)
                .context("operation revision overflow")?;
            receipt.validate()?;
            Ok(receipt.clone())
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.check_context")
    )]
    fn check_context(&self, context: &BindingContext) -> Result<()> {
        context.validate()?;
        let config_directory = context
            .config_path
            .parent()
            .expect("absolute configuration path has a parent");
        ensure!(
            !self.root.starts_with(config_directory)
                && !context
                    .worktree
                    .as_deref()
                    .is_some_and(|worktree| self.root.starts_with(worktree)),
            "local state must be outside the configuration source directory and Git worktree"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.lock")
    )]
    fn lock(&self) -> Result<StoreLock> {
        reject_symlink(&self.root)?;
        check_private_directory(&self.root)?;
        let path = self.root.join("store.lock");
        reject_symlink(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).context("open local state lock")?;
        check_private_file(&path)?;
        let deadline = Instant::now()
            .checked_add(self.lock_timeout)
            .context("local lock timeout is too large")?;
        loop {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(StoreLock(file)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(StateLockBusy.into());
                    }
                    std::thread::sleep((deadline - now).min(Duration::from_millis(10)));
                }
                Err(error) => return Err(error).context("lock local state"),
            }
        }
    }

    fn read<T>(&self, read: impl FnOnce(Ledger) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        read(self.load()?)
    }

    fn mutate<T>(&self, change: impl FnOnce(&mut Ledger) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let mut ledger = self.load()?;
        let result = change(&mut ledger)?;
        ledger.validate()?;
        self.save(&ledger)?;
        Ok(result)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.load_validate")
    )]
    fn load(&self) -> Result<Ledger> {
        let path = self.root.join("state.json");
        reject_symlink(&path)?;
        // A damaged metadata path must not block while opening a FIFO.
        if path.exists() {
            check_private_file(&path)?;
        }
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Ledger::default());
            }
            Err(error) => return Err(error).context("open local state"),
        };
        check_private_file(&path)?;
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read local state")?;
        ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "local state exceeds its supported size limit"
        );
        let ledger: Ledger = serde_json::from_slice(&bytes)
            .context("local state is malformed; preserve it and recover from a known receipt")?;
        ledger.validate()?;
        Ok(ledger)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "state.state_store.save")
    )]
    fn save(&self, ledger: &Ledger) -> Result<()> {
        let path = self.root.join("state.json");
        reject_symlink(&path)?;
        let bytes = serde_json::to_vec_pretty(ledger)?;
        ensure!(
            (bytes.len() as u64) < MAX_STATE_BYTES,
            "local state exceeds its supported size limit"
        );
        let mut pending = NamedTempFile::new_in(&self.root).context("create pending state file")?;
        pending.write_all(&bytes).context("write pending state")?;
        pending.write_all(b"\n")?;
        pending
            .as_file()
            .sync_all()
            .context("flush pending state")?;
        pending
            .persist(&path)
            .context("replace local state atomically")?;
        File::open(&self.root)?
            .sync_all()
            .context("flush state directory")?;
        Ok(())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.allowed_transition")
)]
fn allowed_transition(previous: &PhaseStatus, next: &PhaseStatus) -> bool {
    matches!(
        (previous, next),
        (
            PhaseStatus::Pending,
            PhaseStatus::Running { .. } | PhaseStatus::Cancelled
        ) | (
            PhaseStatus::Failed {
                retry_safe: true,
                ..
            },
            PhaseStatus::Running { .. } | PhaseStatus::Cancelled
        ) | (
            PhaseStatus::Running { .. },
            PhaseStatus::Succeeded { .. }
                | PhaseStatus::Failed { .. }
                | PhaseStatus::Unknown { .. }
        )
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.ensure_later_phases_pending")
)]
fn ensure_later_phases_pending(receipt: &OperationReceipt, index: usize) -> Result<()> {
    ensure!(
        receipt.phases[index + 1..]
            .iter()
            .all(|phase| matches!(phase.status, PhaseStatus::Pending)),
        "a later phase has already started or finished; reconcile its outcome and start a new operation before retrying an earlier phase"
    );
    Ok(())
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn validate_label(label: &str) -> Result<()> {
    ensure!(
        valid_token(label),
        "network label must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens"
    );
    Ok(())
}

fn validate_uuid(id: Uuid) -> Result<()> {
    ensure!(
        id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
        "network and operation IDs must be UUIDv4 values"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.validate_hash")
)]
fn validate_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "input hashes must be lowercase SHA-256 hex strings"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.reject_symlink")
)]
fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            !metadata.file_type().is_symlink(),
            "local metadata path must not be a symlink: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect local metadata path"),
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.check_private_directory")
)]
fn check_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect local state directory")?;
    ensure!(metadata.is_dir(), "local state path must be a directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "local state directory permissions must exclude group and other users; choose a dedicated private --state-dir: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "state.check_private_file")
)]
fn check_private_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    ensure!(metadata.is_file(), "local metadata must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "local metadata permissions must exclude group and other users: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_reads_resume_after_owner_drop_with_an_inherited_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path().join("state"))
            .unwrap()
            .with_lock_timeout(Duration::ZERO);
        let scope = Scope {
            team_id: "test".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let owner = store.lock().unwrap();
        let inherited = owner.0.try_clone().unwrap();
        assert!(store.list(&scope).unwrap_err().is::<StateLockBusy>());
        drop(owner);
        assert!(store.list(&scope).unwrap().is_empty());
        drop(inherited);
    }
}
