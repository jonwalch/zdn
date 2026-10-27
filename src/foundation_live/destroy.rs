//! Narrow teardown recovery from checked Pulumi state, never EC2 tags alone.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const VOLUME_RECEIPT: &str = "cleanup-volume-identities.json";

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.resources")
)]
fn resources(checkpoint: &Value) -> Result<&[Value]> {
    ensure!(
        checkpoint
            .pointer("/deployment/pending_operations")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
        "automatic cleanup recovery refuses pending Pulumi operations"
    );
    let deployment = checkpoint
        .get("deployment")
        .and_then(Value::as_object)
        .context("cleanup checkpoint has no deployment")?;
    let resources = match deployment.get("resources") {
        Some(value) => value
            .as_array()
            .context("invalid cleanup checkpoint resources")?
            .as_slice(),
        None => &[],
    };
    let mut urns = BTreeSet::new();
    for resource in resources {
        let urn = resource["urn"]
            .as_str()
            .context("cleanup resource has no URN")?;
        ensure!(urns.insert(urn), "duplicate cleanup resource URN");
    }
    Ok(resources)
}

fn managed(resource: &Value) -> bool {
    resource["custom"] == true
        && ["external", "delete", "pendingReplacement", "imported"]
            .iter()
            .all(|key| resource.get(key).is_none_or(|value| value == false))
        && ["importID", "importId"]
            .iter()
            .all(|key| resource.get(key).is_none_or(|value| value == ""))
}

fn urn(deployment: &Deployment, kind: &str, name: &str) -> String {
    format!(
        "urn:pulumi:zdn-{}::zdn-foundation::{kind}::{name}",
        deployment.spec.network_id.simple()
    )
}

fn tags_match(actual: &Value, expected: &Value) -> bool {
    expected.as_object().is_some_and(|expected| {
        expected
            .iter()
            .all(|(key, value)| actual.get(key) == Some(value))
    })
}

fn ec2_tags_match(actual: &Value, expected: &Value) -> bool {
    match (actual.as_array(), expected.as_object()) {
        (Some(actual), Some(expected)) => expected.iter().all(|(key, value)| {
            actual.iter().filter(|tag| tag["Key"] == *key).count() == 1
                && actual
                    .iter()
                    .any(|tag| tag["Key"] == *key && &tag["Value"] == value)
        }),
        _ => false,
    }
}

fn address<'a>(deployment: &Deployment, checkpoint: &'a Value) -> Result<Option<&'a Value>> {
    let program = deployment.render()?;
    let expected = &program.resources["natAddress"];
    let urn = urn(deployment, "aws:ec2/eip:Eip", &expected.name);
    Ok(resources(checkpoint)?
        .iter()
        .find(|resource| resource["urn"] == urn))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.stale_nat_address")
)]
pub(super) fn stale_nat_address(
    api: &dyn AwsApi,
    deployment: &Deployment,
    checkpoint: &Value,
    failure: &crate::pulumi::PulumiFailure,
    progress: &mut crate::pulumi::Progress<'_>,
) -> Result<bool> {
    let list = resources(checkpoint)?;
    // The provider must already have finished deleting the NAT. Refreshing an
    // in-flight or still-associated address cannot authorize a second destroy.
    if list
        .iter()
        .any(|resource| resource["type"] == "aws:ec2/natGateway:NatGateway")
    {
        return Ok(false);
    }
    let Some(resource) = address(deployment, checkpoint)? else {
        return Ok(false);
    };
    let (Some(allocation), Some(association)) = (
        resource["id"].as_str(),
        resource
            .pointer("/outputs/associationId")
            .and_then(Value::as_str),
    ) else {
        return Ok(false);
    };
    if !managed(resource)
        || resource["type"] != "aws:ec2/eip:Eip"
        || !failure.is_eip_disassociation(allocation, association)
    {
        return Ok(false);
    }
    crate::infra::validate_aws_id(allocation, "eipalloc-")?;
    crate::infra::validate_aws_id(association, "eipassoc-")?;
    if deployment
        .outputs
        .as_ref()
        .is_some_and(|outputs| outputs.eip_allocation_id != allocation)
    {
        return Ok(false);
    }
    let expected = serde_json::to_value(&deployment.render()?.resources["natAddress"])?;
    let tags = &expected["properties"]["tags"];
    if resource
        .pointer("/outputs/allocationId")
        .is_some_and(|id| id != allocation)
        || !tags_match(&resource["inputs"]["tags"], tags)
        || !tags_match(&resource["outputs"]["tags"], tags)
    {
        return Ok(false);
    }
    ensure!(
        progress()? == RunControl::Continue,
        "foundation operation cancelled"
    );
    let observed = api.call(
        "ec2",
        "describe-addresses",
        json!({"AllocationIds":[allocation]}),
        &[],
    )?;
    let addresses = array(&observed, "Addresses")?;
    if addresses.len() != 1
        || addresses[0]["AllocationId"] != allocation
        || addresses[0]["Domain"] != "vpc"
        || !ec2_tags_match(&addresses[0]["Tags"], tags)
        || [
            "AssociationId",
            "NetworkInterfaceId",
            "InstanceId",
            "PrivateIpAddress",
        ]
        .iter()
        .any(|key| addresses[0].get(key).is_some_and(|value| value != ""))
    {
        return Ok(false);
    }
    let filters = json!([
        {"Name":"tag:zdn:network-id","Values":[deployment.spec.network_id.to_string()]},
        {"Name":"tag:zdn:team-id","Values":[deployment.spec.scope.team_id]},
        {"Name":"tag:zdn:managed-by","Values":["zdn"]}
    ]);
    ensure!(
        progress()? == RunControl::Continue,
        "foundation operation cancelled"
    );
    let nats = api.call(
        "ec2",
        "describe-nat-gateways",
        json!({"Filter":filters}),
        &[],
    )?;
    if array(&nats, "NatGateways")?
        .iter()
        .any(|nat| nat["State"] != "deleted")
    {
        return Ok(false);
    }
    if let Some(outputs) = &deployment.outputs {
        ensure!(
            progress()? == RunControl::Continue,
            "foundation operation cancelled"
        );
        match api.call(
            "ec2",
            "describe-nat-gateways",
            json!({"NatGatewayIds":[outputs.nat_gateway_id]}),
            &[],
        ) {
            Ok(response) => {
                let nats = array(&response, "NatGateways")?;
                if !nats.is_empty()
                    && !(nats.len() == 1
                        && nats[0]["NatGatewayId"] == outputs.nat_gateway_id
                        && nats[0]["State"] == "deleted")
                {
                    return Ok(false);
                }
            }
            Err(error) if aws_error(&error, "NatGatewayNotFound") => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.confirm_address_refreshed")
)]
pub(super) fn confirm_address_refreshed(
    deployment: &Deployment,
    before: &Value,
    after: &Value,
) -> Result<()> {
    let before = address(deployment, before)?
        .context("stale address disappeared from original checkpoint")?;
    let Some(after) = address(deployment, after)? else {
        return Ok(());
    };
    ensure!(
        managed(after)
            && after["type"] == "aws:ec2/eip:Eip"
            && after["id"] == before["id"]
            && ["associationId", "networkInterface", "instance"]
                .iter()
                .all(|key| { after["outputs"].get(key).is_none_or(|value| value == "") }),
        "Pulumi refresh did not clear the verified stale NAT address association"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.record_address_recovery")
)]
pub(super) fn record_address_recovery(
    directory: &Path,
    deployment: &Deployment,
    before: &Value,
    after: &Value,
    destroy_completed: bool,
) -> Result<()> {
    let address = address(deployment, before)?.context("missing proven stale address")?;
    foundation::private_directory(directory)?;
    foundation::write_json(
        &directory.join("stale-address-recovery.json"),
        &json!({
            "schema_version":1,
            "network_id":deployment.spec.network_id,
            "allocation_id":address["id"],
            "stale_association_id":address["outputs"]["associationId"],
            "before_checkpoint_sha256":crate::devnet::sha256(&serde_json::to_vec(before)?),
            "refreshed_checkpoint_sha256":crate::devnet::sha256(&serde_json::to_vec(after)?),
            "refresh_verified":true,
            "destroy_completed":destroy_completed
        }),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeIdentities {
    version: u32,
    request_sha256: String,
    volumes: BTreeMap<String, String>,
}

fn request_sha256(deployment: &Deployment) -> Result<String> {
    Ok(crate::devnet::sha256(&serde_json::to_vec(&(
        &deployment.spec,
        &deployment.team,
        &deployment.cluster,
        deployment.owner_id,
    ))?))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.volume_definitions")
)]
fn volume_definitions(deployment: &Deployment) -> Result<BTreeMap<String, Value>> {
    let program = deployment.render()?;
    let mut result = BTreeMap::new();
    for resource in program.resources.values() {
        let value = serde_json::to_value(resource)?;
        if value["type"] == "aws:ebs:Volume" && value["options"]["retainOnDelete"] == true {
            result.insert(
                urn(deployment, "aws:ebs/volume:Volume", &resource.name),
                value["properties"].clone(),
            );
        }
    }
    Ok(result)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.load_volume_identities")
)]
pub(super) fn load_volume_identities(
    directory: &Path,
    deployment: &Deployment,
) -> Result<BTreeMap<String, String>> {
    let path = directory.join(VOLUME_RECEIPT);
    if !path.try_exists()? {
        return Ok(BTreeMap::new());
    }
    let saved: VolumeIdentities = foundation::read_json(&path)?;
    ensure!(
        saved.version == 1 && saved.request_sha256 == request_sha256(deployment)?,
        "cleanup volume receipt belongs to another deployment request"
    );
    let expected = volume_definitions(deployment)?;
    let mut ids = BTreeSet::new();
    for (urn, id) in &saved.volumes {
        ensure!(
            expected.contains_key(urn) && ids.insert(id),
            "cleanup volume receipt contains an unknown or duplicate volume"
        );
        crate::infra::validate_aws_id(id, "vol-")?;
    }
    Ok(saved.volumes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.save_volume_identities")
)]
pub(super) fn save_volume_identities(
    directory: &Path,
    deployment: &Deployment,
    checkpoint: &Value,
) -> Result<()> {
    let mut volumes = load_volume_identities(directory, deployment)?;
    let expected = volume_definitions(deployment)?;
    for resource in resources(checkpoint)? {
        let urn = resource["urn"]
            .as_str()
            .context("volume resource has no URN")?;
        let Some(properties) = expected.get(urn) else {
            continue;
        };
        ensure!(
            managed(resource)
                && resource["type"] == "aws:ebs/volume:Volume"
                && resource["retainOnDelete"] == true
                && tags_match(&resource["inputs"]["tags"], &properties["tags"])
                && tags_match(&resource["outputs"]["tags"], &properties["tags"]),
            "cleanup volume checkpoint does not match generated ownership"
        );
        for key in ["availabilityZone", "encrypted", "size", "type"] {
            ensure!(
                resource["inputs"][key] == properties[key]
                    && resource["outputs"][key] == properties[key],
                "cleanup volume checkpoint attributes differ from deployment"
            );
        }
        let id = resource["id"]
            .as_str()
            .context("cleanup volume has no saved identity")?;
        crate::infra::validate_aws_id(id, "vol-")?;
        if let Some(saved) = volumes.get(urn) {
            ensure!(
                saved == id,
                "cleanup volume identity changed; inspect state before deleting data"
            );
        }
        volumes.insert(urn.into(), id.into());
    }
    ensure!(
        volumes.values().collect::<BTreeSet<_>>().len() == volumes.len(),
        "cleanup checkpoint aliases multiple resources to one volume"
    );
    let receipt = VolumeIdentities {
        version: 1,
        request_sha256: request_sha256(deployment)?,
        volumes,
    };
    foundation::private_directory(directory)?;
    foundation::write_private(
        &directory.join(VOLUME_RECEIPT),
        &serde_json::to_vec(&receipt)?,
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.destroy.owned_recorded_volume")
)]
pub(super) fn owned_recorded_volume(
    volume: &Value,
    deployment: &Deployment,
    saved: &BTreeMap<String, String>,
) -> Result<bool> {
    if deployment.outputs.is_some() {
        return Ok(false);
    }
    let Some((urn, _)) = saved.iter().find(|(_, id)| volume["VolumeId"] == **id) else {
        return Ok(false);
    };
    let definitions = volume_definitions(deployment)?;
    let properties = definitions
        .get(urn)
        .context("recorded volume has no generated resource")?;
    if !ec2_tags_match(&volume["Tags"], &properties["tags"]) {
        return Ok(false);
    }
    ensure!(
        volume["AvailabilityZone"] == properties["availabilityZone"]
            && volume["Encrypted"] == properties["encrypted"]
            && volume["Size"] == properties["size"]
            && volume["VolumeType"] == properties["type"],
        "recorded volume attributes differ from deployment"
    );
    Ok(true)
}

#[cfg(test)]
mod tests;
