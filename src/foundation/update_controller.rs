//! Image-only orchestration. The boundary deliberately has no infrastructure operations.
use super::{Deployment, DeploymentFile};
use crate::update::{self, ImageRevision, NodeTarget, UpdateIntent};
use eyre::{ensure, ContextCompat, Result};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Implementations must settle the exact saved command before returning from dispatch,
/// and observe must issue a new readiness command (never replay a cached success).
pub trait Backend {
    fn pulse(&mut self) -> Result<()>;
    fn stage(&mut self, deployment: &Deployment, revision: &ImageRevision) -> Result<()>;
    fn dispatch(&mut self, deployment: &Deployment, node: &str) -> Result<()>;
    fn observe(
        &mut self,
        deployment: &Deployment,
        node: &str,
        revision: &ImageRevision,
    ) -> Result<()>;
    fn ready(&mut self, deployment: &Deployment) -> Result<()>;
}

/// Prepare authorization in memory. Publish the deployment only after its
/// recovery inputs and candidate/contract binding have been durably saved.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.update_controller.prepare")
)]
pub fn prepare(
    deployment: &mut Deployment,
    targets: &[String],
    acknowledged: bool,
) -> Result<Uuid> {
    deployment.validate()?;
    ensure!(
        acknowledged,
        "--acknowledge-storage-compatibility is required"
    );
    ensure!(
        !deployment.destroyed && deployment.unresolved_operation.is_none(),
        "deployment is destroyed or has an unresolved operation"
    );
    ensure!(
        !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
        "resume the unresolved update before starting another"
    );
    let cluster = deployment
        .cluster
        .as_ref()
        .context("node deployment required")?;
    ensure!(
        cluster.block_interval_seconds.is_some(),
        "legacy deployment has no durable bootstrap-completion contract; image updates are not supported"
    );
    let topology = cluster.topology()?;
    let outputs = deployment
        .outputs
        .as_ref()
        .context("provisioned cluster required")?;
    ensure!(!targets.is_empty(), "select at least one explicit --node");
    let mut selected = BTreeMap::new();
    for node in targets {
        ensure!(!selected.contains_key(node), "duplicate update node");
        ensure!(
            topology.nodes().iter().any(|n| &n.node_id == node),
            "unknown update node"
        );
        ensure!(
            cluster.lightwallet.is_none() || topology.lightwallet_node().node_id != *node,
            "updating the lightwallet host is not supported"
        );
        let output = outputs
            .nodes
            .get(node)
            .context("missing selected host output")?;
        selected.insert(
            node.clone(),
            NodeTarget {
                instance_id: output.instance_id.clone(),
                volume_id: output.volume_id.clone(),
                expected_image: update::active_image(deployment, node)?.image.clone(),
                expected_update_id: deployment
                    .runtime
                    .as_ref()
                    .and_then(|r| r.nodes.get(node))
                    .map(|r| r.update_id),
            },
        );
    }
    let id = Uuid::new_v4();
    let intent = UpdateIntent {
        api_version: update::API_VERSION.into(),
        id,
        baseline_sha256: update::baseline_fingerprint(deployment)?,
        targets: selected,
        storage_compatibility_acknowledged: true,
        build_contract_sha256: None,
        build_exporter_protocol: None,
        host_runtime_protocol: cluster
            .native_runtime_protocol
            .as_ref()
            .map(|_| crate::host::runtime::revision::EXECUTION_PROTOCOL.into()),
        revision: None,
        completed: BTreeSet::new(),
        finished: false,
    };
    deployment
        .runtime
        .get_or_insert_with(Default::default)
        .update = Some(intent);
    Ok(id)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.update_controller.resume")
)]
pub fn resume(deployment: &Deployment, id: Uuid, reconcile: bool) -> Result<()> {
    deployment.validate()?;
    ensure!(reconcile, "--resume requires --reconcile");
    ensure!(
        deployment
            .runtime
            .as_ref()
            .and_then(|r| r.update.as_ref())
            .is_some_and(|u| u.id == id),
        "resume UUID does not match the saved update"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.update_controller.set_revision")
)]
pub fn set_revision(
    file: &DeploymentFile,
    deployment: &mut Deployment,
    revision: ImageRevision,
) -> Result<()> {
    revision.validate()?;
    let before = deployment.runtime.clone();
    let intent = deployment
        .runtime
        .as_mut()
        .and_then(|r| r.update.as_mut())
        .context("missing update intent")?;
    ensure!(
        revision.update_id == intent.id,
        "candidate belongs to another update"
    );
    if let Some(saved) = &intent.revision {
        ensure!(
            serde_json::to_value(saved)? == serde_json::to_value(&revision)?,
            "saved candidate is immutable"
        );
    } else {
        intent.revision = Some(revision);
    }
    if let Err(error) = file.save(deployment) {
        deployment.runtime = before;
        return Err(error);
    }
    Ok(())
}

/// Only node source/build fields may differ, including for pinned-image configs.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.update_controller.validate_source_config")
)]
pub fn validate_source_config(
    original: &crate::config::Config,
    candidate: &crate::config::Config,
) -> Result<()> {
    let mut normalized = candidate.clone();
    normalized.node.source = original.node.source.clone();
    normalized.node.build = original.node.build.clone();
    if serde_json::to_value(original)? != serde_json::to_value(&normalized)? {
        return Err(crate::immutable_inputs::ImmutableInputError::new(
            "update may change only node.source and node.build; chain, runtime, services and topology are immutable",
            crate::immutable_inputs::ImmutableInputReport::config(original, &normalized)?,
        ).into());
    }
    Ok(())
}

pub fn run(
    file: &DeploymentFile,
    deployment: &mut Deployment,
    backend: &mut dyn Backend,
) -> Result<()> {
    run_with_progress(file, deployment, backend, &mut |_, _| Ok(()))
}

/// Some(node) follows fresh observation and durable per-node confirmation;
/// None follows durable finished state. Errors stop later effects, not saved work.
pub type UpdateProgress<'a> = dyn FnMut(&UpdateIntent, Option<&str>) -> Result<()> + 'a;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation.update_controller.run_with_progress")
)]
pub fn run_with_progress(
    file: &DeploymentFile,
    deployment: &mut Deployment,
    backend: &mut dyn Backend,
    progress: &mut UpdateProgress<'_>,
) -> Result<()> {
    deployment.validate()?;
    if let Some(set) = deployment
        .cluster
        .as_ref()
        .and_then(|c| c.artifact_set.as_ref())
    {
        set.require_compatible()?;
    }
    let intent = deployment
        .runtime
        .as_ref()
        .and_then(|r| r.update.as_ref())
        .context("missing update intent")?;
    let revision = intent
        .revision
        .clone()
        .context("candidate build is still pending")?;
    let mut nodes: Vec<_> = intent.targets.keys().cloned().collect();
    // The fixed topology designates node-1 as producer.
    nodes.sort_by_key(|n| (n == "node-1", n.clone()));
    backend.pulse()?;
    backend.stage(deployment, &revision)?;
    for node in nodes {
        backend.pulse()?;
        let completed = deployment
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap()
            .completed
            .contains(&node);
        if !completed {
            backend.dispatch(deployment, &node)?;
        }
        backend.pulse()?;
        backend.observe(deployment, &node, &revision)?;
        if !completed {
            // One atomic deployment write commits both the assignment and its completion.
            // Roll back memory too if persistence fails; never claim a confirmation not saved.
            let before = deployment.runtime.clone();
            let runtime = deployment.runtime.as_mut().unwrap();
            runtime.nodes.insert(node.clone(), revision.clone());
            runtime
                .update
                .as_mut()
                .unwrap()
                .completed
                .insert(node.clone());
            if let Err(error) = file.save(deployment) {
                deployment.runtime = before;
                return Err(error);
            }
        }
        progress(
            deployment
                .runtime
                .as_ref()
                .unwrap()
                .update
                .as_ref()
                .unwrap(),
            Some(&node),
        )?;
    }
    backend.pulse()?;
    backend.ready(deployment)?;
    let mut completed = deployment
        .runtime
        .as_ref()
        .unwrap()
        .update
        .as_ref()
        .unwrap()
        .clone();
    completed.finished = true;
    let updates = file.directory().join("updates");
    super::private_directory(&updates)?;
    let directory = updates.join(completed.id.to_string());
    super::private_directory(&directory)?;
    let path = directory.join("completed.json");
    if path.exists() {
        let saved: UpdateIntent =
            serde_json::from_slice(&crate::devnet::read_bounded(&path, 2 * 1024 * 1024)?)?;
        ensure!(
            serde_json::to_value(&saved)? == serde_json::to_value(&completed)?,
            "saved completed update differs"
        );
    } else {
        super::write_json(&path, &completed)?;
    }
    std::fs::File::open(&directory)?.sync_all()?;
    std::fs::File::open(&updates)?.sync_all()?;
    std::fs::File::open(file.directory())?.sync_all()?;
    let before = deployment.runtime.clone();
    deployment
        .runtime
        .as_mut()
        .unwrap()
        .update
        .as_mut()
        .unwrap()
        .finished = true;
    if let Err(error) = file.save(deployment) {
        deployment.runtime = before;
        return Err(error);
    }
    progress(
        deployment
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap(),
        None,
    )?;
    Ok(())
}
