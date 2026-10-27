//! Image-only runtime revisions, separate from immutable infrastructure inputs.
use crate::{
    build::BuildContract,
    devnet::{Artifact, ClusterRequest},
    foundation::Deployment,
    image::ImageRecord,
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const API_VERSION: &str = "zdn-node-update/v1alpha1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRevision {
    pub update_id: Uuid,
    pub image: ImageRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildContract>,
    pub artifacts: BTreeMap<String, Artifact>,
}

impl ImageRevision {
    /// Read and validate all saved bytes before binding or reusing a revision.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "update.image_revision.read")
    )]
    pub fn read(
        update_id: Uuid,
        build: Option<BuildContract>,
        directory: &std::path::Path,
    ) -> Result<Self> {
        let record = crate::devnet::read_bounded(
            &crate::devnet::artifact_path(directory, "image.json"),
            crate::image::MAX_RECORD_BYTES as u64,
        )?;
        let manifest = crate::devnet::read_bounded(
            &crate::devnet::artifact_path(directory, "image-manifest.json"),
            crate::image::MAX_MANIFEST_BYTES as u64,
        )?;
        let config = crate::devnet::read_bounded(
            &crate::devnet::artifact_path(directory, "image-config.json"),
            crate::image::MAX_CONFIG_BYTES as u64,
        )?;
        let image = ImageRecord::from_json(&record)?;
        let verified = crate::image::validate_manifest_bytes(&image, &manifest)?;
        crate::image::validate_config_bytes(&image, &verified, &config)?;
        let artifacts = [
            ("image.json", record),
            ("image-manifest.json", manifest),
            ("image-config.json", config),
        ]
        .into_iter()
        .map(|(name, bytes)| {
            (
                name.into(),
                Artifact {
                    sha256: crate::devnet::sha256(&bytes),
                    bytes: bytes.len() as u64,
                },
            )
        })
        .collect();
        let revision = Self {
            update_id,
            image,
            build,
            artifacts,
        };
        revision.validate()?;
        Ok(revision)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "update.image_revision.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        uuid4(self.update_id)?;
        self.image.validate()?;
        if let Some(build) = &self.build {
            build.validate_image(&self.image)?;
        }
        ensure!(
            self.artifacts.len() == 3,
            "update requires exactly three image artifacts"
        );
        for (name, max) in [
            ("image.json", crate::image::MAX_RECORD_BYTES),
            ("image-manifest.json", crate::image::MAX_MANIFEST_BYTES),
            ("image-config.json", crate::image::MAX_CONFIG_BYTES),
        ] {
            let artifact = self
                .artifacts
                .get(name)
                .context("missing update image artifact")?;
            crate::devnet::validate_hash(&artifact.sha256)?;
            ensure!(
                (1..=max as u64).contains(&artifact.bytes),
                "update artifact size out of bounds"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeTarget {
    pub instance_id: String,
    pub volume_id: String,
    pub expected_image: String,
    pub expected_update_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateIntent {
    pub api_version: String,
    pub id: Uuid,
    pub baseline_sha256: String,
    pub targets: BTreeMap<String, NodeTarget>,
    /// A human acknowledgement for this exact old→new operation, not a claim
    /// that storage compatibility has been automatically established.
    pub storage_compatibility_acknowledged: bool,
    pub build_contract_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_exporter_protocol: Option<String>,
    /// Explicit host dispatcher choice; absent retains exact legacy histories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_runtime_protocol: Option<String>,
    pub revision: Option<ImageRevision>,
    pub completed: BTreeSet<String>,
    pub finished: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeState {
    pub nodes: BTreeMap<String, ImageRevision>,
    pub update: Option<UpdateIntent>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "update.baseline_fingerprint")
)]
pub fn baseline_fingerprint(deployment: &Deployment) -> Result<String> {
    // Profile is a local credential selection, not a runtime or infrastructure
    // identity. Selecting another valid profile must not invalidate recovery.
    let mut spec = deployment.spec.clone();
    spec.aws_profile.clear();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        spec,
        &deployment.team,
        deployment.owner_id,
        &deployment.cluster,
        &deployment.outputs,
    ))?)))
}

pub fn active_image<'a>(deployment: &'a Deployment, node: &str) -> Result<&'a ImageRecord> {
    if let Some(revision) = deployment.runtime.as_ref().and_then(|r| r.nodes.get(node)) {
        return Ok(&revision.image);
    }
    Ok(&deployment
        .cluster
        .as_ref()
        .context("node deployment required")?
        .image)
}

impl RuntimeState {
    pub fn pending(&self) -> bool {
        self.update.as_ref().is_some_and(|u| !u.finished)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "update.runtime_state.validate")
    )]
    pub fn validate(&self, deployment: &Deployment, cluster: &ClusterRequest) -> Result<()> {
        let topology = cluster.topology()?;
        let nodes: BTreeSet<_> = topology.nodes().into_iter().map(|n| n.node_id).collect();
        for (node, revision) in &self.nodes {
            ensure!(
                nodes.contains(node),
                "runtime revision names an unknown node"
            );
            revision.validate()?;
            let mut request = cluster.clone();
            request.image = revision.image.clone();
            request.ecr_repository(&deployment.team)?;
        }
        let Some(update) = &self.update else {
            return Ok(());
        };
        ensure!(
            update.api_version == API_VERSION,
            "unsupported update intent version"
        );
        ensure!(
            update.host_runtime_protocol.as_deref()
                == cluster
                    .native_runtime_protocol
                    .as_ref()
                    .map(|_| crate::host::runtime::revision::EXECUTION_PROTOCOL),
            "saved update host dispatcher differs from native runtime selection"
        );
        uuid4(update.id)?;
        if let Some(hash) = &update.build_contract_sha256 {
            crate::devnet::validate_hash(hash)?;
        }
        if let Some(protocol) = &update.build_exporter_protocol {
            ensure!(
                protocol == crate::build_export::PROTOCOL && update.build_contract_sha256.is_some(),
                "unsupported source-update exporter selection"
            );
        }
        ensure!(
            update.storage_compatibility_acknowledged,
            "storage compatibility acknowledgement required"
        );
        ensure!(
            update.baseline_sha256 == baseline_fingerprint(deployment)?,
            "update baseline differs from saved deployment"
        );
        ensure!(
            !update.targets.is_empty() && update.targets.len() <= nodes.len(),
            "invalid update targets"
        );
        ensure!(
            update
                .completed
                .iter()
                .all(|n| update.targets.contains_key(n)),
            "completed node outside update targets"
        );
        let outputs = deployment
            .outputs
            .as_ref()
            .context("update requires provisioned nodes")?;
        for (node, target) in &update.targets {
            ensure!(nodes.contains(node), "unknown update target");
            let output = outputs
                .nodes
                .get(node)
                .context("update target output missing")?;
            ensure!(
                output.instance_id == target.instance_id && output.volume_id == target.volume_id,
                "update target host or volume identity changed"
            );
            let host = cluster.host_spec(&deployment.spec, &deployment.team, output)?;
            let mut old = host;
            old.image = target.expected_image.clone();
            old.validate()?;
            if let Some(id) = target.expected_update_id {
                uuid4(id)?;
            }
            if !update.completed.contains(node) {
                ensure!(
                    active_image(deployment, node)?.image == target.expected_image
                        && self.nodes.get(node).map(|r| r.update_id) == target.expected_update_id,
                    "update expected revision differs from confirmed node state"
                );
            } else {
                let confirmed = self
                    .nodes
                    .get(node)
                    .context("completed update missing node revision")?;
                ensure!(
                    Some(confirmed) == update.revision.as_ref(),
                    "completed node revision differs from update"
                );
            }
        }
        if let Some(revision) = &update.revision {
            revision.validate()?;
            ensure!(
                revision
                    .build
                    .as_ref()
                    .map(BuildContract::fingerprint)
                    .transpose()?
                    == update.build_contract_sha256,
                "candidate build contract differs from saved update authorization"
            );
            ensure!(
                revision.update_id == update.id,
                "candidate revision belongs to another update"
            );
            let mut request = cluster.clone();
            request.image = revision.image.clone();
            request.ecr_repository(&deployment.team)?;
        }
        ensure!(
            !update.finished
                || (update.revision.is_some() && update.completed.len() == update.targets.len()),
            "update finished before all targets were confirmed"
        );
        Ok(())
    }
}

/// Validate completed runtime metadata and the entire per-node update ancestry.
/// This is pure: artifact inventories and saved command proofs belong to callers.
pub fn validate_completed_history(
    deployment: &Deployment,
    updates: &BTreeMap<Uuid, UpdateIntent>,
) -> Result<()> {
    validate_history(deployment, updates, false)
}

/// Handoff may preserve the latest interrupted candidate; callers must also
/// validate its operation, artifacts and every target's terminal command proof.
pub(crate) fn validate_handoff_history(
    deployment: &Deployment,
    updates: &BTreeMap<Uuid, UpdateIntent>,
) -> Result<()> {
    validate_history(deployment, updates, true)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "update.validate_history")
)]
fn validate_history(
    deployment: &Deployment,
    updates: &BTreeMap<Uuid, UpdateIntent>,
    allow_pending: bool,
) -> Result<()> {
    let cluster = deployment
        .cluster
        .as_ref()
        .context("missing node request")?;
    let empty = RuntimeState::default();
    let runtime = deployment.runtime.as_ref().unwrap_or(&empty);
    runtime.validate(deployment, cluster)?;
    if let Some(latest) = &runtime.update {
        ensure!(
            allow_pending || latest.finished,
            "unfinished update history"
        );
        ensure!(
            updates.get(&latest.id) == Some(latest),
            "missing latest update history"
        );
    }
    for (id, intent) in updates {
        ensure!(
            *id == intent.id
                && (intent.finished
                    || (allow_pending && runtime.update.as_ref().is_some_and(|u| u.id == *id))),
            "invalid update history identity or status"
        );
        let revision = intent
            .revision
            .as_ref()
            .context("update history lacks revision")?;
        RuntimeState {
            nodes: if intent.finished {
                intent
                    .targets
                    .keys()
                    .map(|node| (node.clone(), revision.clone()))
                    .collect()
            } else {
                runtime.nodes.clone()
            },
            update: Some(intent.clone()),
        }
        .validate(deployment, cluster)?;
        if cluster.lightwallet.is_some() {
            ensure!(
                !intent
                    .targets
                    .contains_key(&cluster.topology()?.lightwallet_node().node_id),
                "lightwallet host updates cannot be handed off"
            );
        }
    }
    let mut accounted = BTreeSet::new();
    for node in cluster.topology()?.nodes() {
        let mut current = runtime.nodes.get(&node.node_id);
        let mut expected_image = current
            .map(|r| r.image.image.as_str())
            .unwrap_or(&cluster.image.image);
        let mut id = current.map(|r| r.update_id);
        while let Some(update_id) = id {
            ensure!(
                accounted.insert((update_id, node.node_id.clone())),
                "cyclic update history"
            );
            let intent = updates
                .get(&update_id)
                .context("missing confirmed update history")?;
            let revision = intent.revision.as_ref().context("missing revision")?;
            ensure!(
                revision.image.image == expected_image,
                "update image chain mismatch"
            );
            if let Some(confirmed) = current.take() {
                ensure!(
                    confirmed == revision,
                    "confirmed revision differs from history"
                );
            }
            let target = intent
                .targets
                .get(&node.node_id)
                .context("confirmed node not targeted by update")?;
            expected_image = &target.expected_image;
            id = target.expected_update_id;
        }
        ensure!(
            expected_image == cluster.image.image,
            "update chain does not reach baseline image"
        );
    }
    ensure!(
        accounted.len() == updates.values().map(|u| u.completed.len()).sum::<usize>(),
        "unaccounted update targets or forked history"
    );
    let mut remaining = BTreeMap::new();
    let mut dependents: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for (id, intent) in updates {
        // Include every target, even those not yet completed in a pending update.
        // Several nodes may name the same predecessor: that is only one edge.
        let predecessors: BTreeSet<_> = intent
            .targets
            .values()
            .filter_map(|target| target.expected_update_id)
            .collect();
        for previous in &predecessors {
            ensure!(
                updates.contains_key(previous),
                "cyclic update dependency or missing predecessor"
            );
            dependents.entry(*previous).or_default().insert(*id);
        }
        remaining.insert(*id, predecessors.len());
        if predecessors.is_empty() {
            ready.insert(*id);
        }
    }
    let mut ordered = 0;
    while let Some(id) = ready.pop_first() {
        ordered += 1;
        if let Some(children) = dependents.remove(&id) {
            for child in children {
                let count = remaining
                    .get_mut(&child)
                    .expect("indexed update dependency");
                *count -= 1;
                if *count == 0 {
                    ready.insert(child);
                }
            }
        }
    }
    ensure!(
        ordered == updates.len(),
        "cyclic update dependency or missing predecessor"
    );
    Ok(())
}

fn uuid4(id: Uuid) -> Result<()> {
    ensure!(
        id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
        "update identity must be UUIDv4"
    );
    Ok(())
}
