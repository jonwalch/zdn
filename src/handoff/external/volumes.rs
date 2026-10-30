//! Read-only adaptation of foundation_live/new_volume's proof algorithm. Keep
//! its wire ordering (the creation intent hash covers serialized struct bytes).
//! No first-format permission is created, refreshed, or inferred on import.
use super::*;
use crate::{cluster_infra::ClusterNodeOutputs, host::NewVolumeAuthorization, infra::GIB};
use serde_json::Value;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedNode {
    volume_urn: String,
    host_urn: String,
    attachment_urn: String,
    tags: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationIntent {
    version: u32,
    request_sha256: String,
    started_at: u64,
    availability_zone: String,
    size_gib: u32,
    nodes: BTreeMap<String, ExpectedNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lightwallet: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeReceipt {
    authorization: NewVolumeAuthorization,
    observed_at: u64,
    volume: Value,
}

fn timestamp(value: &Value) -> Result<u64> {
    crate::credentials::utc_timestamp(value.as_str().context("missing volume timestamp")?)
}

fn fresh<'a>(resources: &'a [Value], urn: &str) -> Result<&'a Value> {
    let resource = resources
        .iter()
        .find(|r| r["urn"] == urn)
        .context("missing new-volume checkpoint resource")?;
    ensure!(
        resource["custom"] == true
            && ["external", "delete", "pendingReplacement", "imported"]
                .iter()
                .all(|key| resource.get(key).is_none_or(|v| v == false))
            && ["importID", "importId"]
                .iter()
                .all(|key| resource.get(key).is_none_or(|v| v == "")),
        "new-volume resource is not a fresh managed resource"
    );
    Ok(resource)
}

pub(super) fn verify(
    deployment: &Deployment,
    manifest: &Manifest,
    root: &Path,
    node: &ClusterNodeOutputs,
    saved: Option<&NewVolumeAuthorization>,
) -> Result<()> {
    let path = format!("{}-new-volume.json", node.node_id);
    if !manifest.files.contains_key(&path) {
        ensure!(
            saved.is_none(),
            "external runtime has unproven new-volume authorization"
        );
        return Ok(());
    }
    let intent: CreationIntent =
        serde_json::from_slice(&read(manifest, root, "new-volume-creation.json")?)?;
    let program = deployment.render()?;
    let prefix = format!(
        "urn:pulumi:zdn-{}::{}::",
        deployment.spec.network_id.simple(),
        program.name
    );
    let mut expected_nodes = BTreeMap::new();
    for member in deployment.node_topology()?.nodes() {
        let volume = serde_json::to_value(&program.resources[&member.volume_key])?;
        expected_nodes.insert(
            member.node_id,
            ExpectedNode {
                volume_urn: format!(
                    "{prefix}aws:ebs/volume:Volume::{}",
                    program.resources[&member.volume_key].name
                ),
                host_urn: format!(
                    "{prefix}aws:ec2/instance:Instance::{}",
                    program.resources[&member.host_key].name
                ),
                attachment_urn: format!(
                    "{prefix}aws:ec2/volumeAttachment:VolumeAttachment::{}",
                    program.resources[&member.attachment_key].name
                ),
                tags: serde_json::from_value(volume["properties"]["tags"].clone())?,
            },
        );
    }
    ensure!(
        intent.version == 1
            && intent.request_sha256
                == devnet::sha256(&serde_json::to_vec(&(
                    deployment.owner_id,
                    &deployment.spec,
                    &deployment.team,
                    deployment
                        .external
                        .as_ref()
                        .context("missing external deployment")?
                ))?)
            && intent.availability_zone == deployment.spec.availability_zone
            && intent.size_gib == deployment.spec.size.allocation().chain_disk_gib
            && intent.nodes == expected_nodes
            && intent.lightwallet.is_none(),
        "foreign new-volume creation intent"
    );
    let receipt: VolumeReceipt = serde_json::from_slice(&read(manifest, root, &path)?)?;
    let checkpoint: Value = serde_json::from_slice(&read(
        manifest,
        root,
        &format!("{}-new-volume-checkpoint.json", node.node_id),
    )?)?;
    ensure!(
        receipt.observed_at >= intent.started_at
            && receipt.observed_at - intent.started_at <= 6 * 60 * 60,
        "new-volume creation evidence outside original window"
    );
    ensure!(
        checkpoint
            .pointer("/deployment/pending_operations")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "pending operations in new-volume checkpoint"
    );
    let resources = checkpoint["deployment"]["resources"]
        .as_array()
        .context("missing checkpoint resources")?;
    let mut seen = BTreeSet::new();
    for resource in resources {
        ensure!(
            seen.insert(resource["urn"].as_str().context("missing checkpoint URN")?),
            "duplicate checkpoint URN"
        );
    }
    let expected = &intent.nodes[&node.node_id];
    let disk = fresh(resources, &expected.volume_urn)?;
    let host = fresh(resources, &expected.host_urn)?;
    let attachment = fresh(resources, &expected.attachment_urn)?;
    ensure!(
        disk["type"] == "aws:ebs/volume:Volume"
            && host["type"] == "aws:ec2/instance:Instance"
            && attachment["type"] == "aws:ec2/volumeAttachment:VolumeAttachment"
            && disk["id"] == node.volume_id
            && disk["outputs"]["id"] == node.volume_id
            && host["id"] == node.instance_id
            && host["outputs"]["id"] == node.instance_id,
        "new-volume resource identity differs"
    );
    for resource in [disk, host, attachment] {
        let created = timestamp(&resource["created"])?;
        ensure!(
            created >= intent.started_at && created <= receipt.observed_at,
            "new-volume checkpoint creation timestamp differs"
        );
    }
    for field in ["inputs", "outputs"] {
        let properties = &disk[field];
        ensure!(
            properties["encrypted"] == true
                && properties["size"] == intent.size_gib
                && properties["availabilityZone"] == intent.availability_zone
                && properties.get("snapshotId").is_none_or(|v| v == "")
                && properties["tags"].as_object().is_some_and(|tags| expected
                    .tags
                    .iter()
                    .all(|(key, value)| tags.get(key).is_some_and(|v| v == value))),
            "new-volume checkpoint size/zone/encryption/snapshot/ownership differs"
        );
        let properties = &attachment[field];
        ensure!(
            properties["volumeId"] == node.volume_id
                && properties["instanceId"] == node.instance_id
                && properties["deviceName"] == "/dev/sdf",
            "new-volume checkpoint attachment differs"
        );
    }
    let volume = &receipt.volume;
    let created = timestamp(&volume["CreateTime"])?;
    ensure!(
        created >= intent.started_at
            && created <= receipt.observed_at
            && created == timestamp(&disk["outputs"]["createTime"])?,
        "new-volume AWS/checkpoint creation timestamp differs"
    );
    ensure!(
        volume["VolumeId"] == node.volume_id
            && volume["Size"] == intent.size_gib
            && volume["Encrypted"] == true
            && volume["AvailabilityZone"] == intent.availability_zone
            && volume["SnapshotId"] == ""
            && volume["State"] == "in-use"
            && volume["KmsKeyId"] == disk["outputs"]["kmsKeyId"],
        "new-volume AWS identity differs"
    );
    let tags = volume["Tags"].as_array().context("missing volume tags")?;
    ensure!(
        expected.tags.iter().all(|(key, value)| tags
            .iter()
            .filter(|tag| tag["Key"] == *key)
            .count()
            == 1
            && tags
                .iter()
                .any(|tag| tag["Key"] == *key && tag["Value"] == *value)),
        "new-volume AWS ownership differs"
    );
    let attachments = volume["Attachments"]
        .as_array()
        .context("missing volume attachment")?;
    ensure!(
        attachments.len() == 1
            && attachments[0]["VolumeId"] == node.volume_id
            && attachments[0]["InstanceId"] == node.instance_id
            && attachments[0]["Device"] == "/dev/sdf"
            && attachments[0]["State"] == "attached",
        "new-volume AWS attachment differs"
    );
    let expected = NewVolumeAuthorization {
        api_version: crate::host::NEW_VOLUME_API_VERSION.into(),
        volume_id: node.volume_id.clone(),
        instance_id: node.instance_id.clone(),
        created_at: volume["CreateTime"]
            .as_str()
            .context("missing volume creation time")?
            .into(),
        size_bytes: u64::from(intent.size_gib) * GIB,
        creation_intent_sha256: devnet::sha256(&serde_json::to_vec(&intent)?),
        checkpoint_sha256: devnet::sha256(&serde_json::to_vec(&checkpoint)?),
    };
    ensure!(
        receipt.authorization == expected && saved == Some(&expected),
        "external new-volume authorization differs from original proof"
    );
    Ok(())
}
