//! First-format authority comes from a saved empty-stack intent and the exact
//! newly created Pulumi resource, never from mutable EC2 tags alone.
use super::*;
use crate::{
    cluster_infra::{
        ClusterLightwalletOutputs, ClusterNodeOutputs, LIGHTWALLET_CACHE_ATTACHMENT,
        LIGHTWALLET_CACHE_DEVICE, LIGHTWALLET_CACHE_DISK,
    },
    devnet,
    host::NewVolumeAuthorization,
};
use std::collections::{BTreeMap, BTreeSet};

const INTENT: &str = "new-volume-creation.json";
const CREATION_WINDOW: u64 = 6 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedNode {
    volume_urn: String,
    host_urn: String,
    attachment_urn: String,
    tags: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedCache {
    node_id: String,
    size_gib: u32,
    resource: ExpectedNode,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CreationIntent {
    version: u32,
    request_sha256: String,
    started_at: u64,
    availability_zone: String,
    size_gib: u32,
    nodes: BTreeMap<String, ExpectedNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lightwallet: Option<ExpectedCache>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeReceipt {
    authorization: NewVolumeAuthorization,
    observed_at: u64,
    volume: Value,
}

impl CreationIntent {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.new_volume.creation_intent.for_deployment"
        )
    )]
    fn for_deployment(deployment: &Deployment, started_at: u64) -> Result<Self> {
        let request = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?;
        let program = deployment.render()?;
        let prefix = format!(
            "urn:pulumi:zdn-{}::{}::",
            deployment.spec.network_id.simple(),
            program.name
        );
        let mut nodes = BTreeMap::new();
        for node in request.topology()?.nodes() {
            let volume = serde_json::to_value(&program.resources[&node.volume_key])?;
            nodes.insert(
                node.node_id,
                ExpectedNode {
                    volume_urn: format!(
                        "{prefix}aws:ebs/volume:Volume::{}",
                        program.resources[&node.volume_key].name
                    ),
                    host_urn: format!(
                        "{prefix}aws:ec2/instance:Instance::{}",
                        program.resources[&node.host_key].name
                    ),
                    attachment_urn: format!(
                        "{prefix}aws:ec2/volumeAttachment:VolumeAttachment::{}",
                        program.resources[&node.attachment_key].name
                    ),
                    tags: serde_json::from_value(volume["properties"]["tags"].clone())?,
                },
            );
        }
        let lightwallet = request
            .lightwallet
            .as_ref()
            .map(|service| -> Result<_> {
                let node = request.topology()?.lightwallet_node();
                let volume = serde_json::to_value(&program.resources[LIGHTWALLET_CACHE_DISK])?;
                Ok(ExpectedCache {
                    node_id: node.node_id,
                    size_gib: service.allocation.cache_gib,
                    resource: ExpectedNode {
                        volume_urn: format!(
                            "{prefix}aws:ebs/volume:Volume::{}",
                            program.resources[LIGHTWALLET_CACHE_DISK].name
                        ),
                        host_urn: format!(
                            "{prefix}aws:ec2/instance:Instance::{}",
                            program.resources[&node.host_key].name
                        ),
                        attachment_urn: format!(
                            "{prefix}aws:ec2/volumeAttachment:VolumeAttachment::{}",
                            program.resources[LIGHTWALLET_CACHE_ATTACHMENT].name
                        ),
                        tags: serde_json::from_value(volume["properties"]["tags"].clone())?,
                    },
                })
            })
            .transpose()?;
        Ok(Self {
            version: 1,
            request_sha256: devnet::sha256(&serde_json::to_vec(&(
                deployment.owner_id,
                &deployment.spec,
                &deployment.team,
                request,
            ))?),
            started_at,
            availability_zone: deployment.spec.availability_zone.clone(),
            size_gib: deployment.spec.size.allocation().chain_disk_gib,
            nodes,
            lightwallet,
        })
    }

    fn validate_for(&self, deployment: &Deployment) -> Result<()> {
        ensure!(
            *self == Self::for_deployment(deployment, self.started_at)?,
            "saved new-volume creation intent differs from this deployment"
        );
        Ok(())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.resources")
)]
fn resources(checkpoint: &Value) -> Result<&[Value]> {
    ensure!(
        checkpoint
            .pointer("/deployment/pending_operations")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "new-volume authorization requires a checkpoint without pending operations"
    );
    let deployment = checkpoint
        .get("deployment")
        .context("missing checkpoint deployment")?;
    let resources = match deployment.get("resources") {
        Some(value) => value
            .as_array()
            .context("invalid checkpoint resources")?
            .as_slice(),
        None => &[],
    };
    let mut seen = BTreeSet::new();
    for resource in resources {
        let urn = resource["urn"]
            .as_str()
            .context("checkpoint resource has no URN")?;
        ensure!(seen.insert(urn), "duplicate checkpoint resource URN");
    }
    Ok(resources)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.fresh_resource")
)]
fn fresh_resource<'a>(resources: &'a [Value], urn: &str) -> Result<&'a Value> {
    let resource = resources
        .iter()
        .find(|r| r["urn"] == urn)
        .context("expected new-volume resource missing from checkpoint")?;
    ensure!(
        resource["custom"] == true
            && ["external", "delete", "pendingReplacement", "imported"]
                .iter()
                .all(|key| resource.get(key).is_none_or(|v| v == false))
            && ["importID", "importId"]
                .iter()
                .all(|key| resource.get(key).is_none_or(|v| v == "")),
        "new-volume resource is imported, external, deleted, or pending replacement"
    );
    Ok(resource)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.empty_stack_for_creation")
)]
fn empty_stack_for_creation(checkpoint: &Value, has_outputs: bool) -> Result<bool> {
    let list = resources(checkpoint)?;
    Ok(!has_outputs
        && !list.iter().any(|r| {
            r["type"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("aws:"))
        }))
}

fn timestamp(value: &Value) -> Result<u64> {
    crate::credentials::utc_timestamp(
        value
            .as_str()
            .context("missing volume creation timestamp")?,
    )
}

struct VolumeTarget<'a> {
    expected: &'a ExpectedNode,
    instance_id: &'a str,
    volume_id: &'a str,
    size_gib: u32,
    device_name: &'static str,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.authorize")
)]
fn authorize(
    intent: &CreationIntent,
    node: &ClusterNodeOutputs,
    checkpoint: &Value,
    volume: &Value,
    now: u64,
) -> Result<NewVolumeAuthorization> {
    authorize_target(
        intent,
        VolumeTarget {
            expected: intent
                .nodes
                .get(&node.node_id)
                .context("unknown new-volume node")?,
            instance_id: &node.instance_id,
            volume_id: &node.volume_id,
            size_gib: intent.size_gib,
            device_name: "/dev/sdf",
        },
        checkpoint,
        volume,
        now,
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.authorize_lightwallet")
)]
fn authorize_lightwallet(
    intent: &CreationIntent,
    cache: &ClusterLightwalletOutputs,
    checkpoint: &Value,
    volume: &Value,
    now: u64,
) -> Result<NewVolumeAuthorization> {
    let expected = intent
        .lightwallet
        .as_ref()
        .context("creation intent has no lightwallet cache")?;
    ensure!(
        expected.node_id == cache.node_id && expected.size_gib == cache.cache_size_gib,
        "lightwallet cache differs from the saved creation intent"
    );
    authorize_target(
        intent,
        VolumeTarget {
            expected: &expected.resource,
            instance_id: &cache.instance_id,
            volume_id: &cache.cache_volume_id,
            size_gib: expected.size_gib,
            device_name: LIGHTWALLET_CACHE_DEVICE,
        },
        checkpoint,
        volume,
        now,
    )
}

#[derive(Clone, Copy)]
pub(super) enum AuthorizationTarget<'a> {
    Node(&'a ClusterNodeOutputs),
    Lightwallet(&'a ClusterLightwalletOutputs),
}

impl<'a> AuthorizationTarget<'a> {
    fn stem(self) -> String {
        match self {
            Self::Node(node) => node.node_id.clone(),
            Self::Lightwallet(_) => "lightwallet".into(),
        }
    }

    fn volume_id(self) -> &'a str {
        match self {
            Self::Node(node) => &node.volume_id,
            Self::Lightwallet(cache) => &cache.cache_volume_id,
        }
    }

    fn authorize(
        self,
        intent: &CreationIntent,
        checkpoint: &Value,
        volume: &Value,
        now: u64,
    ) -> Result<NewVolumeAuthorization> {
        match self {
            Self::Node(node) => authorize(intent, node, checkpoint, volume, now),
            Self::Lightwallet(cache) => {
                authorize_lightwallet(intent, cache, checkpoint, volume, now)
            }
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.authorize_target")
)]
fn authorize_target(
    intent: &CreationIntent,
    target: VolumeTarget<'_>,
    checkpoint: &Value,
    volume: &Value,
    now: u64,
) -> Result<NewVolumeAuthorization> {
    ensure!(
        now >= intent.started_at && now - intent.started_at <= CREATION_WINDOW,
        "new-volume creation proof expired; preserve the disk and inspect recovery"
    );
    let VolumeTarget {
        expected,
        instance_id,
        volume_id,
        size_gib,
        device_name,
    } = target;
    let list = resources(checkpoint)?;
    let disk = fresh_resource(list, &expected.volume_urn)?;
    let host = fresh_resource(list, &expected.host_urn)?;
    let attachment = fresh_resource(list, &expected.attachment_urn)?;
    ensure!(
        disk["type"] == "aws:ebs/volume:Volume"
            && host["type"] == "aws:ec2/instance:Instance"
            && attachment["type"] == "aws:ec2/volumeAttachment:VolumeAttachment",
        "new-volume resource type mismatch"
    );
    ensure!(
        disk["id"] == volume_id
            && disk["outputs"]["id"] == volume_id
            && host["id"] == instance_id
            && host["outputs"]["id"] == instance_id,
        "checkpoint new-volume identity differs from saved node outputs"
    );
    for resource in [disk, host, attachment] {
        let created = timestamp(&resource["created"])?;
        ensure!(
            created >= intent.started_at && created <= now,
            "checkpoint resource predates creation intent or is in the future"
        );
    }
    for field in ["inputs", "outputs"] {
        let properties = &disk[field];
        ensure!(
            properties["encrypted"] == true
                && properties["size"] == size_gib
                && properties["availabilityZone"] == intent.availability_zone
                && properties.get("snapshotId").is_none_or(|v| v == ""),
            "checkpoint new-volume size, encryption, zone, or snapshot differs"
        );
        ensure!(
            properties["tags"].as_object().is_some_and(|tags| expected
                .tags
                .iter()
                .all(|(key, value)| tags.get(key).is_some_and(|v| v == value))),
            "checkpoint new-volume ownership differs"
        );
        let properties = &attachment[field];
        ensure!(
            properties["volumeId"] == volume_id
                && properties["instanceId"] == instance_id
                && properties["deviceName"] == device_name,
            "checkpoint new-volume attachment differs"
        );
    }
    let created = timestamp(&volume["CreateTime"])?;
    ensure!(
        created >= intent.started_at
            && created <= now
            && created == timestamp(&disk["outputs"]["createTime"])?,
        "AWS volume creation time differs from new-create checkpoint"
    );
    ensure!(
        volume["VolumeId"] == volume_id
            && volume["Size"] == size_gib
            && volume["Encrypted"] == true
            && volume["AvailabilityZone"] == intent.availability_zone
            && volume["SnapshotId"] == ""
            && volume["State"] == "in-use"
            && volume["KmsKeyId"] == disk["outputs"]["kmsKeyId"],
        "AWS volume identity, size, encryption, zone, or snapshot differs"
    );
    let tags = array(volume, "Tags")?;
    ensure!(
        expected.tags.iter().all(|(key, value)| tags
            .iter()
            .filter(|tag| tag["Key"] == *key)
            .count()
            == 1
            && tags
                .iter()
                .any(|tag| tag["Key"] == *key && tag["Value"] == *value)),
        "AWS new-volume ownership differs"
    );
    let attachments = array(volume, "Attachments")?;
    ensure!(
        attachments.len() == 1
            && attachments[0]["VolumeId"] == volume_id
            && attachments[0]["InstanceId"] == instance_id
            && attachments[0]["Device"] == device_name
            && attachments[0]["State"] == "attached",
        "AWS new-volume attachment differs"
    );
    Ok(NewVolumeAuthorization {
        api_version: crate::host::NEW_VOLUME_API_VERSION.into(),
        volume_id: volume_id.into(),
        instance_id: instance_id.into(),
        created_at: volume["CreateTime"]
            .as_str()
            .context("missing creation time")?
            .into(),
        size_bytes: u64::from(size_gib) * GIB,
        creation_intent_sha256: devnet::sha256(&serde_json::to_vec(intent)?),
        checkpoint_sha256: devnet::sha256(&serde_json::to_vec(checkpoint)?),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.saved_authorization")
)]
pub(super) fn saved_authorization(
    deployment: &Deployment,
    directory: &Path,
    target: AuthorizationTarget<'_>,
) -> Result<Option<NewVolumeAuthorization>> {
    let path = directory.join(format!("{}-new-volume.json", target.stem()));
    if !path.try_exists()? {
        return Ok(None);
    }
    let intent: CreationIntent = foundation::read_json(&directory.join(INTENT))?;
    intent.validate_for(deployment)?;
    let receipt: VolumeReceipt = foundation::read_json(&path)?;
    let checkpoint: Value = foundation::read_json(
        &directory.join(format!("{}-new-volume-checkpoint.json", target.stem())),
    )?;
    let expected = target.authorize(&intent, &checkpoint, &receipt.volume, receipt.observed_at)?;
    ensure!(
        expected == receipt.authorization,
        "saved new-volume authorization differs from its pinned proof"
    );
    Ok(Some(receipt.authorization))
}

/// Verify the original proof chain without creating an AWS/Pulumi backend.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.new_volume.validate_handoff")
)]
pub(super) fn validate_handoff(deployment: &Deployment, directory: &Path) -> Result<()> {
    if directory.join(INTENT).try_exists()? {
        let intent: CreationIntent = foundation::read_json(&directory.join(INTENT))?;
        intent.validate_for(deployment)?;
    }
    if let Some(outputs) = &deployment.outputs {
        for node in outputs.nodes.values() {
            saved_authorization(deployment, directory, AuthorizationTarget::Node(node))?;
        }
        if let Some(cache) = &outputs.lightwallet {
            saved_authorization(
                deployment,
                directory,
                AuthorizationTarget::Lightwallet(cache),
            )?;
        }
    }
    Ok(())
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.new_volume.live_backend.record_volume_creation"
        )
    )]
    pub(super) fn record_volume_creation(
        &mut self,
        deployment: &Deployment,
        checkpoint: &Value,
    ) -> Result<()> {
        let path = self.deployment_directory.join(INTENT);
        if path.try_exists()? {
            let intent: CreationIntent = foundation::read_json(&path)?;
            return intent.validate_for(deployment);
        }
        // Legacy stacks retain the old full-zero scan. Never infer a create
        // intent from an existing AWS resource or from mutable tags.
        if !empty_stack_for_creation(checkpoint, deployment.outputs.is_some())? {
            return Ok(());
        }
        foundation::write_json(
            &path,
            &CreationIntent::for_deployment(deployment, self.runtime.unix_time()?)?,
        )
    }

    pub(super) fn saved_volume_authorization(
        &self,
        deployment: &Deployment,
        node: &ClusterNodeOutputs,
    ) -> Result<Option<NewVolumeAuthorization>> {
        self.saved_authorization_for(deployment, AuthorizationTarget::Node(node))
    }

    pub(super) fn authorize_new_volume(
        &mut self,
        deployment: &Deployment,
        node: &ClusterNodeOutputs,
    ) -> Result<Option<NewVolumeAuthorization>> {
        self.authorize_new_volume_for(deployment, AuthorizationTarget::Node(node))
    }

    pub(super) fn authorize_new_lightwallet_volume(
        &mut self,
        deployment: &Deployment,
        cache: &ClusterLightwalletOutputs,
    ) -> Result<Option<NewVolumeAuthorization>> {
        self.authorize_new_volume_for(deployment, AuthorizationTarget::Lightwallet(cache))
    }

    /// Prepare all first-format receipts for this operation from at most one
    /// fresh export. Saved receipts remain authoritative and are validated
    /// before any new proof is prepared; no checkpoint is cached on the backend.
    pub(super) fn authorize_new_volumes(&mut self, deployment: &Deployment) -> Result<()> {
        let Some(outputs) = &deployment.outputs else {
            return Ok(());
        };
        let targets = outputs.nodes.values().map(AuthorizationTarget::Node).chain(
            outputs
                .lightwallet
                .as_ref()
                .map(AuthorizationTarget::Lightwallet),
        );
        self.authorize_new_volume_targets(deployment, targets)
    }

    fn saved_authorization_for(
        &self,
        deployment: &Deployment,
        target: AuthorizationTarget<'_>,
    ) -> Result<Option<NewVolumeAuthorization>> {
        saved_authorization(deployment, &self.deployment_directory, target)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.new_volume.live_backend.authorize_new_volume_for"
        )
    )]
    fn authorize_new_volume_for(
        &mut self,
        deployment: &Deployment,
        target: AuthorizationTarget<'_>,
    ) -> Result<Option<NewVolumeAuthorization>> {
        self.authorize_new_volume_targets(deployment, [target])?;
        self.saved_authorization_for(deployment, target)
    }

    fn authorize_new_volume_targets<'a>(
        &mut self,
        deployment: &Deployment,
        targets: impl IntoIterator<Item = AuthorizationTarget<'a>>,
    ) -> Result<()> {
        let mut missing = Vec::new();
        for target in targets {
            if self.saved_authorization_for(deployment, target)?.is_none() {
                missing.push(target);
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        let path = self.deployment_directory.join(INTENT);
        if !path.try_exists()? {
            return Ok(());
        }
        let intent: CreationIntent = foundation::read_json(&path)?;
        intent.validate_for(deployment)?;
        for target in &missing {
            ensure!(
                !self
                    .deployment_directory
                    .join(format!("{}-install.sh", target.stem()))
                    .try_exists()?,
                "cannot add new-volume authorization after installer publication"
            );
        }
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        let checkpoint = self.client.foundation_export(&mut progress)?;
        for target in missing {
            self.poll()?;
            self.authorize_new_volume_from_checkpoint(&intent, target, &checkpoint)?;
        }
        Ok(())
    }

    fn authorize_new_volume_from_checkpoint(
        &mut self,
        intent: &CreationIntent,
        target: AuthorizationTarget<'_>,
        checkpoint: &Value,
    ) -> Result<()> {
        let response = self.aws.call(
            "ec2",
            "describe-volumes",
            json!({"VolumeIds":[target.volume_id()]}),
            &[],
        )?;
        let volumes = array(&response, "Volumes")?;
        ensure!(volumes.len() == 1, "expected exactly one new data volume");
        let now = self.runtime.unix_time()?;
        save_new_authorization(
            &self.deployment_directory,
            intent,
            target,
            checkpoint,
            &volumes[0],
            now,
        )
    }
}

fn save_new_authorization(
    directory: &Path,
    intent: &CreationIntent,
    target: AuthorizationTarget<'_>,
    checkpoint: &Value,
    volume: &Value,
    now: u64,
) -> Result<()> {
    let authorization = target.authorize(intent, checkpoint, volume, now)?;
    let proof_path = directory.join(format!("{}-new-volume-checkpoint.json", target.stem()));
    // An interrupted write may leave the proof without its receipt. Reuse
    // it only if it proves exactly this same immutable authorization.
    let checkpoint = if proof_path.try_exists()? {
        let saved: Value = foundation::read_json(&proof_path)?;
        let saved_authorization = target.authorize(intent, &saved, volume, now)?;
        ensure!(
            saved_authorization.volume_id == authorization.volume_id
                && saved_authorization.instance_id == authorization.instance_id,
            "saved new-volume proof retargeted"
        );
        saved
    } else {
        foundation::write_json(&proof_path, checkpoint)?;
        checkpoint.clone()
    };
    let authorization = target.authorize(intent, &checkpoint, volume, now)?;
    foundation::write_json(
        &directory.join(format!("{}-new-volume.json", target.stem())),
        &VolumeReceipt {
            authorization,
            observed_at: now,
            volume: volume.clone(),
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Reusable evidence for controller fixtures. It deliberately traverses the
/// production authorization verifier before publishing any saved proof.
#[cfg(test)]
pub(super) fn write_lightwallet_proof_fixture(
    deployment: &Deployment,
    directory: &std::path::Path,
) -> Result<NewVolumeAuthorization> {
    let started = crate::credentials::utc_timestamp("2026-10-15T17:00:00Z")?;
    let intent = CreationIntent::for_deployment(deployment, started)?;
    let expected = intent
        .lightwallet
        .as_ref()
        .context("fixture requires lightwallet creation intent")?;
    let cache = deployment
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.lightwallet.as_ref())
        .context("fixture requires lightwallet outputs")?;
    let properties = json!({"encrypted":true,"size":cache.cache_size_gib,
        "availabilityZone":deployment.spec.availability_zone,"tags":expected.resource.tags});
    let mut outputs = properties.clone();
    outputs["id"] = json!(cache.cache_volume_id);
    outputs["snapshotId"] = json!("");
    outputs["createTime"] = json!("2026-10-15T17:00:03Z");
    outputs["kmsKeyId"] = json!("arn:aws:kms:us-east-1:123456789012:key/test");
    let attachment = json!({"volumeId":cache.cache_volume_id,"instanceId":cache.instance_id,"deviceName":LIGHTWALLET_CACHE_DEVICE});
    let checkpoint = json!({"version":3,"deployment":{"resources":[
        {"urn":expected.resource.volume_urn,"custom":true,"type":"aws:ebs/volume:Volume","id":cache.cache_volume_id,"created":"2026-10-15T17:00:13.524241Z","inputs":properties,"outputs":outputs},
        {"urn":expected.resource.host_urn,"custom":true,"type":"aws:ec2/instance:Instance","id":cache.instance_id,"created":"2026-10-15T17:01:00Z","outputs":{"id":cache.instance_id}},
        {"urn":expected.resource.attachment_urn,"custom":true,"type":"aws:ec2/volumeAttachment:VolumeAttachment","id":"vai-1","created":"2026-10-15T17:01:03Z","inputs":attachment,"outputs":attachment}
    ]}});
    let volume = json!({"VolumeId":cache.cache_volume_id,"Size":cache.cache_size_gib,"Encrypted":true,
        "AvailabilityZone":deployment.spec.availability_zone,"SnapshotId":"","State":"in-use",
        "KmsKeyId":"arn:aws:kms:us-east-1:123456789012:key/test","CreateTime":"2026-10-15T17:00:03+00:00",
        "Tags":expected.resource.tags.iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>(),
        "Attachments":[{"VolumeId":cache.cache_volume_id,"InstanceId":cache.instance_id,"Device":LIGHTWALLET_CACHE_DEVICE,"State":"attached"}]});
    let authorization = authorize_lightwallet(&intent, cache, &checkpoint, &volume, started + 120)?;
    foundation::write_json(&directory.join(INTENT), &intent)?;
    foundation::write_json(
        &directory.join("lightwallet-new-volume-checkpoint.json"),
        &checkpoint,
    )?;
    foundation::write_json(
        &directory.join("lightwallet-new-volume.json"),
        &VolumeReceipt {
            authorization: authorization.clone(),
            observed_at: started + 120,
            volume,
        },
    )?;
    Ok(authorization)
}
