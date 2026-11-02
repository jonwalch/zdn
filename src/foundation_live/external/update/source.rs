//! Captured external source revisions use the existing native CodeBuild exporter,
//! requirement-bound reuse identity and durable submission recovery unchanged.
use super::*;
use crate::{
    build::BuildContract,
    config::Config,
    source::{CaptureOptions, SnapshotReceipt},
};

const SCHEMA: &str = "zdn-external-source-update/v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Source {
    schema: String,
    id: Uuid,
    deployment_id: Uuid,
    request: Pin,
    pub(super) nodes: Vec<String>,
    original_config: Config,
    candidate_config: Config,
    pub(super) contract: BuildContract,
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.update.source.prepare")
)]
pub fn prepare(
    deployment: &Deployment,
    root: &Path,
    nodes: &[String],
    original: &Config,
    candidate: &Config,
    candidate_path: &Path,
    helper: &Path,
) -> Result<Uuid> {
    validate_saved(deployment, root)?;
    let request = deployment
        .external
        .as_ref()
        .context("external deployment required")?
        .typed_request()?;
    request.require_config(original)?;
    crate::foundation::update_controller::validate_source_config(original, candidate)?;
    let (store, mut evidence) = load_inventory(deployment, root)?;
    ensure!(
        evidence.pending_identity.is_none()
            && evidence.pending_update.is_none()
            && store.read_pinned(&evidence.inventory)?.is_complete(),
        "external cohort must be settled before source selection"
    );
    let unique: std::collections::BTreeSet<_> = nodes.iter().collect();
    ensure!(
        !nodes.is_empty()
            && unique.len() == nodes.len()
            && nodes
                .iter()
                .all(|node| evidence.manifests.contains_key(node)),
        "source update requires explicit unique saved nodes"
    );
    let temporary = tempfile::tempdir_in(root)?;
    let receipt = crate::source::capture(&CaptureOptions {
        source: candidate
            .source_root(candidate_path)?
            .context("external source update requires a local source")?,
        output: temporary.path().join("source-snapshot"),
        revision: candidate.node.source.revision.clone(),
        include: vec![],
    })?;
    let mut contract = BuildContract::new(
        &receipt,
        candidate
            .node
            .build
            .as_ref()
            .context("external source build settings missing")?,
    )?;
    contract.require_external(&request.validate()?)?;
    contract.verify_archive(&temporary.path().join("source-snapshot/source.tar"))?;
    crate::build_job::prepare_native(
        &temporary.path().join("build"),
        &deployment.team,
        &contract,
        helper,
    )?;
    let id = Uuid::new_v4();
    let source = Source {
        schema: SCHEMA.into(),
        id,
        deployment_id: deployment.spec.network_id,
        request: Pin::of(&request.bytes()?),
        nodes: nodes.to_vec(),
        original_config: original.clone(),
        candidate_config: candidate.clone(),
        contract,
    };
    saved_bytes(
        &temporary.path().join("source.json"),
        &serde_json::to_vec(&source)?,
    )?;
    foundation::private_directory(&root.join("external-updates"))?;
    std::fs::rename(temporary.path(), directory(root, id))?;
    std::fs::File::open(root.join("external-updates"))?.sync_all()?;
    evidence.pending_update = Some(id);
    foundation::write_json(&root.join(EVIDENCE), &evidence)?;
    Ok(id)
}

pub(super) fn load(deployment: &Deployment, root: &Path, id: Uuid) -> Result<Option<Source>> {
    let path = directory(root, id).join("source.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let source: Source = foundation::read_json(&path)?;
    let request = deployment
        .external
        .as_ref()
        .context("external deployment required")?
        .typed_request()?;
    ensure!(
        source.schema == SCHEMA
            && source.id == id
            && source.deployment_id == deployment.spec.network_id
            && source.request == Pin::of(&request.bytes()?),
        "saved external source identity differs"
    );
    request.require_config(&source.original_config)?;
    crate::foundation::update_controller::validate_source_config(
        &source.original_config,
        &source.candidate_config,
    )?;
    let receipt: SnapshotReceipt =
        foundation::read_json(&directory(root, id).join("source-snapshot/receipt.json"))?;
    let mut expected = BuildContract::new(
        &receipt,
        source
            .candidate_config
            .node
            .build
            .as_ref()
            .context("saved external build settings missing")?,
    )?;
    expected.require_external(&request.validate()?)?;
    ensure!(
        expected == source.contract,
        "saved external source build contract differs"
    );
    source
        .contract
        .verify_archive(&directory(root, id).join("source-snapshot/source.tar"))?;
    let unique: std::collections::BTreeSet<_> = source.nodes.iter().collect();
    let topology = deployment.node_topology()?;
    ensure!(
        !source.nodes.is_empty()
            && unique.len() == source.nodes.len()
            && source.nodes.iter().all(|node| topology
                .nodes()
                .iter()
                .any(|member| &member.node_id == node)),
        "saved external source node selection differs"
    );
    crate::build_job::validate_preparation(
        &directory(root, id).join("build"),
        &deployment.team,
        &source.contract,
    )?;
    Ok(Some(source))
}
