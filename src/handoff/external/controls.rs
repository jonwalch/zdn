//! Saved controls remain inert evidence, including controls of old revisions.
use super::*;
use crate::{
    foundation_live::external::qualification::{read_only, Intent},
    host::external::runtime::qualification::SCHEMA,
    state::OperationInput,
};

pub(super) const PHASES: &[&str] = &["verify", "reserve", "lease", "control", "release"];

fn ids(manifest: &Manifest) -> Result<BTreeSet<Uuid>> {
    manifest
        .files
        .keys()
        .filter_map(|path| path.strip_prefix("external-controls/"))
        .map(|path| uuid(path.split('/').next().context("missing control UUID")?))
        .collect()
}

pub(super) fn validate(manifest: &Manifest) -> Result<()> {
    let ids = ids(manifest)?;
    for id in &ids {
        manifest.require(&format!("external-controls/{id}/intent.json"))?;
        manifest.require(&format!("external-controls/{id}/control.sh"))?;
    }
    for operation in manifest
        .operations
        .iter()
        .filter(|o| o.kind == "external-control")
    {
        ensure!(
            ids.contains(&operation.operation_id)
                && operation
                    .phases
                    .iter()
                    .map(|p| p.name.as_str())
                    .eq(PHASES.iter().copied())
                && operation.inputs.source_manifest_sha256.is_none()
                && operation.inputs.archive_sha256.is_none(),
            "external control operation inventory differs"
        );
    }
    Ok(())
}

pub(super) fn verify(
    manifest: &Manifest,
    root: &Path,
    evidence: &Evidence,
    runtimes: &BTreeMap<String, runtime::Manifest>,
    updates: &BTreeMap<(Uuid, String), runtime::update::Request>,
) -> Result<()> {
    let deployment = &manifest.deployment;
    let owner = Pin::of(&serde_json::to_vec(&(
        &deployment.spec,
        &deployment.team,
        deployment.owner_id,
        &deployment.external,
        &deployment.outputs,
    ))?);
    for id in ids(manifest)? {
        let prefix = format!("external-controls/{id}");
        let bytes = read(manifest, root, &format!("{prefix}/intent.json"))?;
        let intent: Intent = crate::public_chain_adapter::contract::parse(&bytes)?;
        ensure!(
            serde_json::to_vec(&intent)? == bytes
                && intent.schema == SCHEMA
                && intent.request.id == id
                && intent.owner == owner,
            "external control ownership differs"
        );
        intent.request.validate()?;
        let original = runtimes
            .get(&intent.node_id)
            .context("foreign external control node")?;
        intent.original.check(&original.bytes()?)?;
        let output = deployment
            .outputs
            .as_ref()
            .context("missing external outputs")?
            .nodes
            .get(&intent.node_id)
            .context("missing external control instance")?;
        ensure!(
            intent.instance_id == output.instance_id,
            "external control instance differs"
        );
        // Do not call controller::load: it correctly requires the *current*
        // revision for execution, but historical receipts must remain portable.
        // Only updates whose completion journals were verified by verify_updates
        // can supply historical runtime authority.
        let mut selected = None;
        if intent.request.runtime == Pin::of(&original.bytes()?) {
            selected = Some(original);
        }
        for ((update_id, node), update) in updates {
            let confirmed = evidence.pending_update != Some(*update_id)
                || evidence
                    .active_images
                    .get(node)
                    .is_some_and(|a| a.update_id == *update_id);
            if node == &intent.node_id
                && confirmed
                && intent.request.runtime == Pin::of(&update.target.bytes()?)
            {
                selected = Some(&update.target);
            }
        }
        let selected = selected.context("external control runtime is not a confirmed revision")?;
        use runtime::qualification::Action;
        ensure!(
            (!matches!(
                intent.request.action,
                Action::StopProducer | Action::Produce { .. }
            ) || selected.block_interval_seconds.is_some())
                && (!matches!(intent.request.action, Action::GatewayIdentity)
                    || intent.node_id == "node-1"),
            "external control action target differs"
        );
        let script = intent.request.render(original)?;
        ensure!(
            read(manifest, root, &format!("{prefix}/control.sh"))? == script.as_bytes(),
            "external control script differs"
        );
        let operation = manifest.operations.iter().find(|o| o.operation_id == id);
        let mutating = !read_only(&intent.request.action);
        let unresolved = deployment.unresolved_operation == Some(id);
        let mut result = None;
        if let Some(operation) = operation {
            ensure!(
                operation.kind == "external-control"
                    && operation.inputs
                        == OperationInput {
                            config_sha256: devnet::sha256(&bytes),
                            source_manifest_sha256: None,
                            archive_sha256: None,
                        },
                "external control operation intent differs"
            );
            result = operation.phases.iter().find_map(|phase| {
                if phase.name == "control" {
                    if let PhaseStatus::Succeeded { result } = &phase.status {
                        return Some(result);
                    }
                }
                None
            });
            let complete = operation
                .phases
                .iter()
                .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. }));
            ensure!(
                !mutating || complete || unresolved,
                "unfinished external mutation lost its unresolved binding"
            );
            ensure!(
                mutating || (deployment.last_operation != Some(id) && !unresolved),
                "read-only external control changed deployment operation pointers"
            );
        }
        if unresolved {
            let active = evidence
                .active_images
                .get(&intent.node_id)
                .map(|a| a.runtime.clone())
                .unwrap_or(Pin::of(&original.bytes()?));
            ensure!(
                operation.is_some()
                    && mutating
                    && evidence.pending_update.is_none()
                    && intent.request.runtime == active,
                "unresolved external control no longer binds the active revision"
            );
        }
        let journal = format!("{prefix}/command.json");
        if manifest.files.contains_key(&journal) {
            ensure!(operation.is_some(), "orphan external control command");
            command(
                manifest,
                root,
                &journal,
                &intent.instance_id,
                &script,
                1200,
                result.is_some(),
            )?;
            let value: serde_json::Value =
                serde_json::from_slice(&read(manifest, root, &journal)?)?;
            // Authenticate every retained success, not only a receipt's final
            // result; failed/unknown attempts remain inert recovery evidence.
            for attempt in value["attempts"]
                .as_array()
                .context("missing control attempts")?
            {
                if attempt["state"] == "succeeded" {
                    intent
                        .request
                        .validate_response(selected, &attempt["output"])?;
                }
            }
            if let Some(result) = result {
                intent.request.validate_response(selected, result)?;
                ensure!(
                    *result == successful_output(manifest, root, &journal)?,
                    "external control operation result differs from command result"
                );
            }
        } else {
            ensure!(
                result.is_none(),
                "successful external control lost its command journal"
            );
        }
    }
    Ok(())
}
