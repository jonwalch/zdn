//! Durable orchestration for the disposable AWS host. No node or wallet runs here.

use crate::{
    aws::TeamDefinition,
    infra::{FoundationOutputs, FoundationSpec},
    state::{Binding, OperationInput, OperationReceipt, PhaseStatus, StateStore},
};
use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub mod update_controller;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foundation_runtime: Option<crate::foundation_runtime::FoundationRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<crate::devnet::ClusterRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<crate::update::RuntimeState>,
    pub spec: FoundationSpec,
    pub team: TeamDefinition,
    /// Stable reservation owner, saved before the first cloud write.
    pub owner_id: Uuid,
    pub stack_initialized: bool,
    pub last_operation: Option<Uuid>,
    #[serde(default)]
    pub unresolved_operation: Option<Uuid>,
    pub outputs: Option<FoundationOutputs>,
    pub destroyed: bool,
    pub cleanup: Option<CleanupReport>,
}

impl Deployment {
    /// Execution admission is separate from historical receipt validation and cleanup.
    pub fn require_native_execution(&self) -> Result<()> {
        let message = "legacy execution is retired; destroy this deployment and recreate fresh with native runtime";
        if let Some(cluster) = &self.cluster {
            ensure!(
                cluster.native_runtime_protocol.as_deref() == Some(crate::host::runtime::PROTOCOL),
                "{message}"
            );
            crate::devnet::validate_native_runtime(
                cluster.native_runtime_protocol.as_deref(),
                cluster
                    .lightwallet
                    .as_ref()
                    .map(|s| s.capacity_protocol.as_deref()),
                cluster.installer_fetch_protocol.as_deref(),
            )?;
            if let Some(intent) = self.runtime.as_ref().and_then(|r| r.update.as_ref()) {
                ensure!(
                    intent.host_runtime_protocol.as_deref()
                        == Some(crate::host::runtime::revision::EXECUTION_PROTOCOL),
                    "{message}; saved legacy updates cannot be converted"
                );
            }
        } else {
            let runtime = self.foundation_runtime.as_ref().context(message)?;
            runtime.validate()?;
        }
        Ok(())
    }

    /// Apply team-level IAM constraints without changing legacy v1 receipts.
    pub fn render(&self) -> Result<crate::infra::PulumiProgram> {
        self.validate()?;
        let base = self.render_base()?;
        match &self.cluster {
            Some(cluster) => cluster.render(base, &self.spec, &self.team),
            None => match &self.foundation_runtime {
                Some(runtime) => runtime.render(base, self),
                None => Ok(base),
            },
        }
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment.render_base")
    )]
    fn render_base(&self) -> Result<crate::infra::PulumiProgram> {
        let program = self.spec.render()?;
        let Some(access) = &self.team.deployment else {
            return Ok(program);
        };
        let mut value = serde_json::to_value(program)?;
        let resources = value["resources"]
            .as_object_mut()
            .context("missing foundation resources")?;
        // The AWS-created default group has no ownership tag at creation.
        // Do not grant developers permission to adopt arbitrary untagged groups.
        // Every zdn instance uses the dedicated, tagged, no-ingress group.
        resources.remove("defaultSecurityGroup");
        for resource in resources.values_mut() {
            for pointer in ["/properties/tags", "/properties/rootBlockDevice/tags"] {
                if let Some(tags) = resource.pointer_mut(pointer).and_then(Value::as_object_mut) {
                    tags.insert(
                        "zdn:bootstrap".into(),
                        serde_json::json!(self.team.bootstrap_id.to_string()),
                    );
                }
            }
        }
        // AWS provider 7.50.0 sends defaultTags with the RunInstances volume
        // request, while rootBlockDevice.tags is a later CreateTags call.
        // Put immutable ownership tags in the former so launch is authorized
        // without replaying protected tags after creation. Keep per-disk tags
        // separate: volumeTags also manages the attached chain disk's tags.
        let ownership = serde_json::json!({
            "zdn:bootstrap": self.team.bootstrap_id.to_string(),
            "zdn:team-id": self.team.team_id,
            "zdn:managed-by": "zdn"
        });
        resources.get_mut("provider").unwrap()["properties"]["defaultTags"] =
            serde_json::json!({"tags": ownership});
        let root_tags = resources
            .get_mut("host")
            .unwrap()
            .pointer_mut("/properties/rootBlockDevice/tags")
            .and_then(Value::as_object_mut)
            .context("missing root volume tags")?;
        for key in ["zdn:bootstrap", "zdn:team-id", "zdn:managed-by"] {
            root_tags.remove(key);
        }
        // Preserve explicit ownership inputs from any pre-fix host. Pulumi
        // restores these saved leaf values during an update, so switching to
        // default tags cannot issue protected DeleteTags. Fresh creates keep
        // the keys absent here, and mutable per-disk metadata stays managed.
        resources.get_mut("host").unwrap()["options"]["ignoreChanges"] = serde_json::json!([
            "rootBlockDevice.tags[\"zdn:bootstrap\"]",
            "rootBlockDevice.tags[\"zdn:team-id\"]",
            "rootBlockDevice.tags[\"zdn:managed-by\"]"
        ]);
        resources.get_mut("hostRole").unwrap()["properties"]["permissionsBoundary"] =
            serde_json::json!(access.runtime_boundary_arn);
        for key in ["hostRole", "hostProfile"] {
            resources.get_mut(key).unwrap()["properties"]["path"] =
                serde_json::json!(crate::access::runtime_path(&self.team));
        }
        let program: crate::infra::PulumiProgram = serde_json::from_value(value)?;
        program.validate_references()?;
        Ok(program)
    }

    pub fn new(spec: FoundationSpec, team: TeamDefinition) -> Result<Self> {
        let deployment = Self {
            schema_version: 1,
            foundation_runtime: None,
            cluster: None,
            runtime: None,
            spec,
            team,
            owner_id: Uuid::new_v4(),
            stack_initialized: false,
            last_operation: None,
            unresolved_operation: None,
            outputs: None,
            destroyed: false,
            cleanup: None,
        };
        deployment.validate()?;
        Ok(deployment)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported foundation receipt version"
        );
        self.spec.validate()?;
        self.team.validate()?;
        ensure!(
            self.spec.scope == self.team.scope(),
            "foundation team/account/region mismatch"
        );
        ensure!(
            self.spec.retain_chain_disk,
            "foundation must retain its chain disk in Pulumi; select deletion explicitly during destroy"
        );
        ensure!(
            self.owner_id.get_version_num() == 4,
            "invalid reservation owner"
        );
        if let Some(outputs) = &self.outputs {
            self.validate_outputs(outputs)?;
        }
        if let Some(runtime) = &self.foundation_runtime {
            runtime.validate()?;
            ensure!(
                self.cluster.is_none() && self.team.deployment.is_some(),
                "native foundation requires foundation-only runtime access setup"
            );
        }
        if let Some(cluster) = &self.cluster {
            cluster.validate(&self.spec, &self.team)?;
            if let Some(runtime) = &self.runtime {
                runtime.validate(self, cluster)?;
            }
        } else {
            ensure!(
                self.runtime.is_none(),
                "foundation cannot contain node runtime revisions"
            );
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment.validate_outputs")
    )]
    pub fn validate_outputs(&self, outputs: &FoundationOutputs) -> Result<()> {
        outputs.validate_for(&self.spec)?;
        if let Some(cluster) = &self.cluster {
            let topology = cluster.topology()?;
            crate::cluster_infra::validate_node_outputs(&outputs.nodes, &topology)?;
            match (&cluster.lightwallet, &outputs.lightwallet) {
                (Some(service), Some(cache)) => {
                    crate::cluster_infra::validate_lightwallet_outputs(
                        cache,
                        &topology,
                        &outputs.nodes,
                    )?;
                    ensure!(
                        cache.cache_size_gib == service.allocation.cache_gib,
                        "lightwallet cache size differs from request"
                    );
                }
                (None, None) => {}
                _ => eyre::bail!("lightwallet outputs differ from the saved service request"),
            }
        } else {
            ensure!(
                outputs.nodes.is_empty() && outputs.lightwallet.is_none(),
                "foundation receipt contains unexpected node or lightwallet outputs"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_artifact_prefixes: Vec<String>,
    pub remaining_resources: Vec<String>,
    pub retained_volumes: Vec<String>,
    pub shared_backend_preserved: bool,
}

impl CleanupReport {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.cleanup_report.validate")
    )]
    pub fn validate(&self, delete_data: bool) -> Result<()> {
        ensure!(
            self.remaining_resources.is_empty(),
            "network cleanup is incomplete: {}",
            self.remaining_resources.join(", ")
        );
        ensure!(
            !delete_data || self.retained_volumes.is_empty(),
            "requested chain disk deletion is incomplete"
        );
        ensure!(
            !delete_data || self.retained_artifact_prefixes.is_empty(),
            "requested deployment artifact deletion is incomplete"
        );
        ensure!(
            self.shared_backend_preserved,
            "cleanup did not confirm shared backend preservation"
        );
        Ok(())
    }
}

/// The live implementation owns lease renewal during every long-running call.
pub trait FoundationBackend {
    fn verify(&mut self, deployment: &Deployment, destroying: bool) -> Result<()>;
    fn reserve(&mut self, deployment: &Deployment) -> Result<()>;
    fn acquire(&mut self, deployment: &Deployment, operation_id: Uuid) -> Result<()>;
    fn prepare(&mut self, deployment: &Deployment, reconcile: bool) -> Result<()>;
    fn preview(&mut self, destroying: bool) -> Result<Value>;
    fn apply(&mut self, deployment: &Deployment) -> Result<FoundationOutputs>;
    fn deploy_runtime(&mut self, _deployment: &Deployment) -> Result<Value> {
        Err(eyre::eyre!(
            "node runtime installation is not implemented by this backend"
        ))
    }
    fn ready(&mut self, deployment: &Deployment) -> Result<Value>;
    fn destroy(&mut self) -> Result<()>;
    fn cleanup(&mut self, deployment: &Deployment, delete_data: bool) -> Result<CleanupReport>;
    fn remove_stack(&mut self) -> Result<()>;
    fn release(&mut self) -> Result<()>;
}

/// One local writer per network. Cloud concurrency is controlled separately by S3.
pub struct DeploymentFile {
    directory: PathBuf,
    _lock: fs::File,
}

impl Drop for DeploymentFile {
    fn drop(&mut self) {
        // A concurrent spawn may still hold this open-file description before
        // exec. Writer ownership ends here, not when that descriptor closes.
        let _ = FileExt::unlock(&self._lock);
    }
}

impl DeploymentFile {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment_file.open")
    )]
    pub fn open(state_root: &Path, network_id: Uuid) -> Result<Self> {
        ensure!(
            network_id.get_version_num() == 4,
            "network ID must be UUIDv4"
        );
        let parent = state_root.join("foundation");
        private_directory(&parent)?;
        let directory = parent.join(network_id.to_string());
        private_directory(&directory)?;
        let path = directory.join("operation.lock");
        reject_symlink(&path)?;
        if path.exists() {
            ensure!(
                fs::symlink_metadata(&path)?.file_type().is_file(),
                "operation lock must be a regular file"
            );
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path)?;
        lock.try_lock_exclusive()
            .context("another local process is using this foundation")?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn load(&self) -> Result<Deployment> {
        load_deployment(&self.directory)
    }
    /// Read one atomically published receipt without locking the writer or
    /// creating directories. The writer can publish a newer receipt afterward.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment_file.read_snapshot")
    )]
    pub fn read_snapshot(state_root: &Path, network_id: Uuid) -> Result<Deployment> {
        ensure!(
            network_id.get_version_num() == 4,
            "network ID must be UUIDv4"
        );
        let parent = state_root.join("foundation");
        let directory = parent.join(network_id.to_string());
        for path in [state_root, parent.as_path(), directory.as_path()] {
            ensure!(
                fs::symlink_metadata(path)
                    .with_context(|| format!("inspect {}", path.display()))?
                    .file_type()
                    .is_dir(),
                "expected a real state directory"
            );
        }
        load_deployment(&directory)
    }
    pub fn exists(&self) -> bool {
        self.directory.join("deployment.json").exists()
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation.deployment_file.save")
    )]
    pub fn save(&self, deployment: &Deployment) -> Result<()> {
        deployment.validate()?;
        ensure!(
            self.directory.file_name().and_then(|n| n.to_str())
                == Some(&deployment.spec.network_id.to_string()),
            "deployment directory identity mismatch"
        );
        write_json(&self.directory.join("deployment.json"), deployment)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.load_deployment")
)]
fn load_deployment(directory: &Path) -> Result<Deployment> {
    let deployment: Deployment = read_json(&directory.join("deployment.json"))?;
    deployment.validate()?;
    ensure!(
        directory.file_name().and_then(|n| n.to_str())
            == Some(&deployment.spec.network_id.to_string()),
        "deployment directory identity mismatch"
    );
    Ok(deployment)
}

struct OperationSpec<'a> {
    kind: &'a str,
    phases: &'a [&'a str],
    reconcile: bool,
    delete_data: Option<bool>,
}

/// The existing reconciliation gate refused to allocate a new operation.
#[derive(Debug)]
pub struct ReconciliationRequired {
    pub operation: OperationReceipt,
}

impl std::fmt::Display for ReconciliationRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("previous operation has an uncertain outcome; inspect foundation status, then retry with --reconcile")
    }
}

impl std::error::Error for ReconciliationRequired {}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.start_operation")
)]
fn start_operation(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    action: OperationSpec<'_>,
) -> Result<OperationReceipt> {
    deployment.validate()?;
    ensure!(
        !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
        "an image update is unresolved; resume that update before up or destroy"
    );
    ensure!(
        deployment.spec.network_id == binding.network_id
            && deployment.spec.scope == binding.context.scope,
        "foundation binding mismatch"
    );
    if let Some(id) = deployment.last_operation {
        let previous = store.operation(id)?;
        let uncertain = previous.phases.iter().any(|phase| {
            matches!(
                phase.status,
                PhaseStatus::Running { .. }
                    | PhaseStatus::Unknown { .. }
                    | PhaseStatus::Failed {
                        retry_safe: false,
                        ..
                    }
            )
        });
        if uncertain && deployment.unresolved_operation.is_none() {
            deployment.unresolved_operation = Some(id);
        }
    }
    if !action.reconcile {
        if let Some(id) = deployment.unresolved_operation {
            return Err(ReconciliationRequired {
                operation: store.operation(id)?,
            }
            .into());
        }
    }
    let inputs = OperationInput {
        config_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&(
            &deployment.spec,
            &deployment.team,
            deployment.owner_id,
            action.delete_data,
            &deployment.cluster,
        ))?)),
        source_manifest_sha256: None,
        archive_sha256: None,
    };
    let operation = store.begin_operation(binding, action.kind, inputs, action.phases)?;
    deployment.last_operation = Some(operation.operation_id);
    file.save(deployment)?;
    Ok(operation)
}

/// Observations follow durable writes. An error stops new effects, but callers
/// must still release any lease. None identifies operation creation.
pub type OperationProgress<'a> = dyn FnMut(&OperationReceipt, Option<&str>) -> Result<()> + 'a;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.phase")
)]
fn phase<T: Serialize>(
    store: &StateStore,
    receipt: &mut OperationReceipt,
    name: &str,
    uncertain_on_error: bool,
    progress: &mut OperationProgress<'_>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    *receipt = store.record_phase(
        receipt.operation_id,
        receipt.revision,
        name,
        PhaseStatus::Running { external_ref: None },
    )?;
    progress(receipt, Some(name))?;
    match action() {
        Ok(result) => {
            *receipt = store.record_phase_outcome(
                receipt,
                name,
                PhaseStatus::Succeeded {
                    result: serde_json::to_value(&result)?,
                },
            )?;
            progress(receipt, Some(name))?;
            Ok(result)
        }
        Err(error) => {
            // Adapter errors must not put raw subprocess output or credentials in receipts.
            let message = format!(
                "{name} failed; inspect the local diagnostics and AWS/Pulumi state before retrying"
            );
            let status = if uncertain_on_error {
                PhaseStatus::Unknown {
                    message,
                    external_ref: None,
                }
            } else {
                PhaseStatus::Failed {
                    message,
                    retry_safe: true,
                }
            };
            *receipt = store.record_phase_outcome(receipt, name, status)?;
            progress(receipt, Some(name))?;
            Err(error)
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.apply")
)]
pub fn apply(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut dyn FoundationBackend,
    reconcile: bool,
) -> Result<OperationReceipt> {
    apply_with_progress(
        store,
        file,
        binding,
        deployment,
        backend,
        reconcile,
        &mut |_, _| Ok(()),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.apply_with_progress")
)]
pub fn apply_with_progress(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut dyn FoundationBackend,
    reconcile: bool,
    progress: &mut OperationProgress<'_>,
) -> Result<OperationReceipt> {
    ensure!(
        !deployment.destroyed,
        "this foundation was destroyed; create a new network binding before provisioning again"
    );
    if let Some(set) = deployment
        .cluster
        .as_ref()
        .and_then(|c| c.artifact_set.as_ref())
    {
        set.require_compatible()?;
    }
    let mut operation = start_operation(
        store,
        file,
        binding,
        deployment,
        OperationSpec {
            kind: if deployment.cluster.is_some() {
                "devnet-up"
            } else {
                "foundation-up"
            },
            phases: if deployment.cluster.is_some() {
                &[
                    "verify",
                    "reserve",
                    "lease",
                    "prepare",
                    "preview",
                    "apply",
                    "install",
                    "readiness",
                ]
            } else {
                &[
                    "verify",
                    "reserve",
                    "lease",
                    "prepare",
                    "preview",
                    "apply",
                    "readiness",
                ]
            },
            reconcile,
            delete_data: None,
        },
    )?;
    let operation_id = operation.operation_id;
    let result: Result<()> = (|| {
        progress(&operation, None)?;
        phase(store, &mut operation, "verify", false, progress, || {
            backend.verify(deployment, false)
        })?;
        phase(store, &mut operation, "reserve", true, progress, || {
            backend.reserve(deployment)
        })?;
        phase(store, &mut operation, "lease", true, progress, || {
            backend.acquire(deployment, operation_id)
        })?;
        phase(store, &mut operation, "prepare", true, progress, || {
            backend.prepare(deployment, reconcile)
        })?;
        deployment.stack_initialized = true;
        file.save(deployment)?;
        phase(store, &mut operation, "preview", false, progress, || {
            backend.preview(false)
        })?;
        let outputs = phase(store, &mut operation, "apply", true, progress, || {
            let outputs = backend.apply(deployment)?;
            deployment.validate_outputs(&outputs)?;
            Ok(outputs)
        })?;
        deployment.outputs = Some(outputs);
        file.save(deployment)?;
        if deployment.cluster.is_some() {
            phase(store, &mut operation, "install", true, progress, || {
                backend.deploy_runtime(deployment)
            })?;
        }
        phase(store, &mut operation, "readiness", false, progress, || {
            backend.ready(deployment)
        })?;
        deployment.unresolved_operation = None;
        file.save(deployment)?;
        Ok(())
    })();
    let released = backend.release();
    result?;
    released?;
    Ok(operation)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.destroy")
)]
pub fn destroy(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut dyn FoundationBackend,
    delete_data: bool,
    reconcile: bool,
) -> Result<OperationReceipt> {
    destroy_with_progress(
        store,
        file,
        binding,
        deployment,
        backend,
        delete_data,
        reconcile,
        &mut |_, _| Ok(()),
    )
}

/// Observe only durable transitions; output failure stops new effects, not cleanup.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.destroy_with_progress")
)]
pub fn destroy_with_progress(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut dyn FoundationBackend,
    delete_data: bool,
    reconcile: bool,
    progress: &mut OperationProgress<'_>,
) -> Result<OperationReceipt> {
    let mut operation = start_operation(
        store,
        file,
        binding,
        deployment,
        OperationSpec {
            kind: if delete_data {
                "foundation-destroy-data"
            } else {
                "foundation-destroy-retain"
            },
            phases: &[
                "verify",
                "reserve",
                "lease",
                "prepare",
                "preview",
                "destroy",
                "cleanup",
                "remove-stack",
            ],
            reconcile,
            delete_data: Some(delete_data),
        },
    )?;
    let operation_id = operation.operation_id;
    let result: Result<()> = (|| {
        progress(&operation, None)?;
        phase(store, &mut operation, "verify", false, progress, || {
            backend.verify(deployment, true)
        })?;
        phase(store, &mut operation, "reserve", true, progress, || {
            backend.reserve(deployment)
        })?;
        phase(store, &mut operation, "lease", true, progress, || {
            backend.acquire(deployment, operation_id)
        })?;
        phase(store, &mut operation, "prepare", true, progress, || {
            backend.prepare(deployment, reconcile)
        })?;
        phase(store, &mut operation, "preview", false, progress, || {
            backend.preview(true)
        })?;
        phase(store, &mut operation, "destroy", true, progress, || {
            backend.destroy()
        })?;
        let cleanup = phase(store, &mut operation, "cleanup", true, progress, || {
            let report = backend.cleanup(deployment, delete_data)?;
            // Keep failed deletion evidence before reporting incomplete cleanup.
            deployment.cleanup = Some(report.clone());
            file.save(deployment)?;
            report.validate(delete_data)?;
            Ok(report)
        })?;
        phase(
            store,
            &mut operation,
            "remove-stack",
            true,
            progress,
            || backend.remove_stack(),
        )?;
        deployment.cleanup = Some(cleanup);
        deployment.destroyed = true;
        deployment.unresolved_operation = None;
        file.save(deployment)?;
        Ok(())
    })();
    let released = backend.release();
    result?;
    released?;
    Ok(operation)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.read_json")
)]
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    reject_symlink(path)?;
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "expected a regular JSON file"
    );
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "expected a regular JSON file");
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 2 * 1024 * 1024,
        "JSON file exceeds 2 MiB limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_private(path, &serde_json::to_vec_pretty(value)?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.write_private")
)]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_symlink(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_file(),
            "state destination must be a regular file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path.parent().context("file needs a parent directory")?;
    ensure!(
        fs::symlink_metadata(parent)?.file_type().is_dir(),
        "file parent must be a real directory"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.private_directory")
)]
pub fn private_directory(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "expected a real state directory"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.reject_symlink")
)]
fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            !metadata.file_type().is_symlink(),
            "refusing symlink at {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_lock_releases_on_drop_with_an_inherited_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let owner = DeploymentFile::open(root.path(), id).unwrap();
        // Model the shared open-file description inherited between fork and exec.
        let inherited = owner._lock.try_clone().unwrap();
        assert!(DeploymentFile::open(root.path(), id).is_err());
        drop(owner);
        let next = DeploymentFile::open(root.path(), id).unwrap();
        drop(inherited);
        assert!(DeploymentFile::open(root.path(), id).is_err());
        drop(next);
        assert!(DeploymentFile::open(root.path(), id).is_ok());
    }
}
