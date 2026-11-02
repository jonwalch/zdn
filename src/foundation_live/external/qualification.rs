//! Saved selected-node qualification, using the existing operation ledger,
//! reservation/lease and durable SSM transport. No infrastructure/build action.
use super::*;
use crate::{
    foundation::{DeploymentFile, FoundationBackend, OperationProgress},
    host::external::runtime::qualification::{Action, Request, SCHEMA},
    state::{Binding, OperationInput, OperationReceipt, PhaseStatus, StateStore},
};

const DIRECTORY: &str = "external-controls";
const PHASES: &[&str] = &["verify", "reserve", "lease", "control", "release"];

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub schema: String,
    pub owner: Pin,
    pub node_id: String,
    pub instance_id: String,
    pub original: Pin,
    pub request: Request,
}

fn owner(deployment: &Deployment) -> Result<Pin> {
    Ok(Pin::of(&serde_json::to_vec(&(
        &deployment.spec,
        &deployment.team,
        deployment.owner_id,
        &deployment.external,
        &deployment.outputs,
    ))?))
}

pub fn read_only(action: &Action) -> bool {
    matches!(action, Action::Read { .. } | Action::GatewayIdentity)
}

fn directory(root: &Path, id: Uuid) -> PathBuf {
    root.join(DIRECTORY).join(id.to_string())
}

fn selected(
    deployment: &Deployment,
    root: &Path,
    node: &str,
) -> Result<(RuntimeRequest, RuntimeRequest)> {
    health::validate_runtime(deployment, root)?;
    let (_, evidence) = load_inventory(deployment, root)?;
    let pin = evidence
        .manifests
        .get(node)
        .context("unknown external control node")?;
    let bytes = devnet::read_bounded(
        &root.join(format!("{node}-external-runtime.json")),
        crate::host::external::runtime::MAX_BYTES,
    )?;
    pin.check(&bytes)?;
    let original = RuntimeRequest::from_slice(&bytes)?;
    ensure!(
        original.provisioning.node_id == node,
        "external control node differs"
    );
    let active = update::effective(root, node, &evidence, &original)?;
    Ok((original, active))
}

pub fn prepare(deployment: &Deployment, root: &Path, node: &str, action: Action) -> Result<Intent> {
    ensure!(
        read_only(&action) || deployment.unresolved_operation.is_none(),
        "reconcile the pending operation before another mutation"
    );
    let (original, active) = selected(deployment, root, node)?;
    ensure!(
        !matches!(action, Action::StopProducer | Action::Produce { .. })
            || active.block_interval_seconds.is_some(),
        "control requires designated producer"
    );
    ensure!(
        !matches!(action, Action::GatewayIdentity) || node == "node-1",
        "gateway identity requires node-1"
    );
    let request = Request {
        schema: SCHEMA.into(),
        id: Uuid::new_v4(),
        runtime: Pin::of(&active.bytes()?),
        action,
    };
    request.validate()?;
    let intent = Intent {
        schema: SCHEMA.into(),
        owner: owner(deployment)?,
        node_id: node.into(),
        instance_id: deployment
            .outputs
            .as_ref()
            .context("external outputs missing")?
            .nodes
            .get(node)
            .context("external node missing")?
            .instance_id
            .clone(),
        original: Pin::of(&original.bytes()?),
        request,
    };
    foundation::private_directory(&root.join(DIRECTORY))?;
    let path = directory(root, intent.request.id);
    foundation::private_directory(&path)?;
    saved_bytes(&path.join("intent.json"), &serde_json::to_vec(&intent)?)?;
    saved_bytes(
        &path.join("control.sh"),
        intent.request.render(&original)?.as_bytes(),
    )?;
    Ok(intent)
}

/// Admission always checks current confirmed evidence. Resume opens no caller
/// action file, companion, source checkout, image artifact or wallet material.
pub fn load(deployment: &Deployment, root: &Path, id: Uuid) -> Result<Intent> {
    ensure!(id.get_version_num() == 4, "invalid external control ID");
    let path = directory(root, id);
    let bytes = devnet::read_bounded(&path.join("intent.json"), 32 * 1024)?;
    let intent: Intent = crate::public_chain_adapter::contract::parse(&bytes)?;
    ensure!(
        serde_json::to_vec(&intent)? == bytes
            && intent.schema == SCHEMA
            && intent.request.id == id
            && intent.owner == owner(deployment)?,
        "external control ownership differs"
    );
    intent.request.validate()?;
    let (original, active) = selected(deployment, root, &intent.node_id)?;
    ensure!(
        !matches!(
            intent.request.action,
            Action::StopProducer | Action::Produce { .. }
        ) || active.block_interval_seconds.is_some(),
        "control requires designated producer"
    );
    ensure!(
        !matches!(intent.request.action, Action::GatewayIdentity) || intent.node_id == "node-1",
        "gateway identity requires node-1"
    );
    intent.original.check(&original.bytes()?)?;
    intent.request.runtime.check(&active.bytes()?)?;
    ensure!(
        deployment
            .outputs
            .as_ref()
            .context("external outputs missing")?
            .nodes[&intent.node_id]
            .instance_id
            == intent.instance_id,
        "external control instance differs"
    );
    ensure!(
        devnet::read_bounded(&path.join("control.sh"), 16 * 1024)?
            == intent.request.render(&original)?.as_bytes(),
        "saved external control script differs"
    );
    Ok(intent)
}

/// Backend construction and all cloud calls happen after pure local admission.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut impl FoundationBackend,
    id: Uuid,
    reconcile: bool,
    progress: &mut OperationProgress<'_>,
) -> Result<Value> {
    let root = file.directory();
    let intent = load(deployment, root, id)?;
    let mutating = !read_only(&intent.request.action);
    ensure!(
        binding.network_id == deployment.spec.network_id
            && binding.context.scope == deployment.spec.scope,
        "foreign external control binding"
    );
    ensure!(
        !mutating
            || deployment.unresolved_operation.is_none()
            || deployment.unresolved_operation == Some(id),
        "another external mutation is unresolved"
    );
    let inputs = OperationInput {
        config_sha256: devnet::sha256(&serde_json::to_vec(&intent)?),
        source_manifest_sha256: None,
        archive_sha256: None,
    };
    let previous = store
        .handoff_operations(binding)?
        .into_iter()
        .find(|r| r.operation_id == id);
    if let Some(receipt) = &previous {
        ensure!(
            receipt.kind == "external-control"
                && receipt.inputs == inputs
                && receipt
                    .phases
                    .iter()
                    .map(|p| p.name.as_str())
                    .eq(PHASES.iter().copied()),
            "external control operation differs"
        );
        let complete = receipt
            .phases
            .iter()
            .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. }));
        ensure!(
            complete || reconcile,
            "resume external control with --reconcile"
        );
        if complete {
            let value = completed(receipt).context("external control result missing")?;
            let (_, active) = selected(deployment, root, &intent.node_id)?;
            intent.request.validate_response(&active, &value)?;
            if mutating && deployment.unresolved_operation == Some(id) {
                deployment.unresolved_operation = None;
                file.save(deployment)?;
            }
            return Ok(value);
        }
    } else if mutating {
        if let Some(previous) = deployment.last_operation {
            ensure!(
                store
                    .operation(previous)?
                    .phases
                    .iter()
                    .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. })),
                "previous operation is not settled"
            );
        }
    }
    let mut receipt = match previous {
        Some(receipt) => receipt,
        None => store.begin_operation_with_id(binding, "external-control", inputs, PHASES, id)?,
    };
    ensure!(!receipt.cancel_requested, "external control is cancelled");
    if mutating {
        deployment.last_operation = Some(id);
        deployment.unresolved_operation = Some(id);
        file.save(deployment)?;
    }
    let result = (|| {
        progress(&receipt, None)?;
        foundation::phase(store, &mut receipt, "verify", false, progress, || {
            backend.verify_external_control(deployment, &intent.node_id)
        })?;
        foundation::phase(store, &mut receipt, "reserve", true, progress, || {
            backend.reserve(deployment)
        })?;
        foundation::phase(store, &mut receipt, "lease", true, progress, || {
            backend.acquire(deployment, id)
        })?;
        let (original, active) = selected(deployment, root, &intent.node_id)?;
        let value = if let Some(value) = completed(&receipt) {
            intent.request.validate_response(&active, &value)?;
            value
        } else {
            foundation::phase(store, &mut receipt, "control", true, progress, || {
                let value = backend.external_control(
                    deployment,
                    &original,
                    &intent.request,
                    &directory(root, id).join("command.json"),
                )?;
                intent.request.validate_response(&active, &value)?;
                Ok(value)
            })?
        };
        Ok::<_, eyre::Report>(value)
    })();
    // A failure never clears unresolved mutation state. Release is attempted
    // even on observer/cancellation errors; remote uncertainty stays journaled.
    let released = backend.release();
    let released = foundation::phase(store, &mut receipt, "release", true, progress, || released);
    let value = result?;
    released?;
    if mutating {
        deployment.unresolved_operation = None;
        file.save(deployment)?;
    }
    Ok(value)
}

fn completed(receipt: &OperationReceipt) -> Option<Value> {
    receipt.phases.iter().find_map(|phase| {
        if phase.name == "control" {
            if let PhaseStatus::Succeeded { result } = &phase.status {
                return Some(result.clone());
            }
        }
        None
    })
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    pub(in crate::foundation_live) fn verify_control(
        &mut self,
        deployment: &Deployment,
        node: &str,
    ) -> Result<()> {
        self.poll()?;
        aws::verify_backend(&self.aws, &self.selection, &deployment.team)?;
        update::preflight(self, deployment, &[node.into()])
    }

    pub(in crate::foundation_live) fn control_external(
        &mut self,
        deployment: &Deployment,
        original: &RuntimeRequest,
        request: &Request,
        journal: &Path,
    ) -> Result<Value> {
        let node = &original.provisioning.node_id;
        update::preflight(self, deployment, std::slice::from_ref(node))?;
        let instance = &deployment
            .outputs
            .as_ref()
            .context("external outputs missing")?
            .nodes[node]
            .instance_id;
        self.remote(instance, &request.render(original)?, journal, 1200)
    }
}
