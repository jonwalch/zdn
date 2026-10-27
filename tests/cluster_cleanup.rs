//! Cleanup observations use only local AWS responses; no credentials or cloud writes.

use std::{cell::RefCell, collections::BTreeMap};

use eyre::Result;
use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    access::{DeploymentAccess, TEAM_ROLE_API_VERSION},
    aws::{AwsApi, AwsApiError, TeamAws, TeamDefinition, TeamState},
    cluster_infra::ClusterTopology,
    config::Size,
    devnet::{ClusterRequest, API_VERSION},
    foundation::Deployment,
    foundation_live::inventory,
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
    infra::FoundationSpec,
    state::Scope,
};

fn deployment() -> Deployment {
    let scope = Scope {
        team_id: "private-team".into(),
        account_id: "123456789012".into(),
        region: "us-east-1".into(),
    };
    let mut team = TeamDefinition {
        api_version: TEAM_ROLE_API_VERSION.into(),
        team_id: scope.team_id.clone(),
        revision: 1,
        bootstrap_id: Uuid::parse_str("965f7c13-e186-4d52-b7e3-ef92db98a0ec").unwrap(),
        aws: TeamAws {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
        },
        state: TeamState {
            backend: "s3://zdn-private-team/pulumi/private-team".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
        deployment: None,
    };
    team.deployment = Some(DeploymentAccess::managed(&team));
    let mut deployment = Deployment::new(
        FoundationSpec {
            scope,
            network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap();
    // Only topology/ownership are relevant to inventory. These data-only image
    // and manifest fields do not claim that a deployable image exists.
    deployment.cluster = Some(ClusterRequest {
        build: None,
        artifact_set: None,
        installer_fetch_protocol: None,
        native_runtime_protocol: None,
        client_access: false,
        block_interval_seconds: None,
        lightwallet: None,
        api_version: API_VERSION.into(),
        config_sha256: "a".repeat(64),
        manifest: serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap(),
        image: ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
                "b".repeat(64)
            ),
            config_digest: format!("sha256:{}", "c".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: ImageProvenance::Release {
                revision: "d".repeat(40),
                version: "v0.0.1".into(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
        },
        node_count: 3,
        reward_address: "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB".into(),
        artifacts: BTreeMap::new(),
    });
    let nodes: BTreeMap<_, _> = ClusterTopology::new(3)
        .unwrap()
        .nodes()
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node.node_id.clone(),
                json!({"node_id":node.node_id,"private_ip":node.private_ip,
                    "instance_id":format!("i-{:017x}",index+1),
                    "volume_id":format!("vol-{:017x}",index+1)}),
            )
        })
        .collect();
    deployment.outputs = Some(serde_json::from_value(json!({
        "schema_version":1,"scope":deployment.spec.scope,"network_id":deployment.spec.network_id,
        "availability_zone":"us-east-1a","vpc_id":"vpc-00000000000000001",
        "private_subnet_id":"subnet-00000000000000001","instance_id":"i-00000000000000001",
        "private_ip":"10.90.1.10","chain_volume_id":"vol-00000000000000001",
        "retain_chain_disk":true,"security_group_id":"sg-00000000000000001",
        "nat_gateway_id":"nat-00000000000000001","eip_allocation_id":"eipalloc-00000000000000001",
        "nodes":nodes
    })).unwrap());
    deployment
}

fn lightwallet_deployment() -> Deployment {
    use zdn::{
        cluster_infra::{ClusterLightwalletOutputs, LightwalletAllocation},
        devnet::LightwalletDeployment,
        lightwallet_image,
    };
    let mut deployment = deployment();
    deployment.cluster.as_mut().unwrap().lightwallet = Some(LightwalletDeployment {
        image: lightwallet_image::ImageRecord {
            api_version: lightwallet_image::API_VERSION.into(),
            image: format!("123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/lightwalletd@sha256:{}", "c".repeat(64)),
            config_digest: format!("sha256:{}", "d".repeat(64)),
            platform: "linux/amd64".into(),
            source_revision: lightwallet_image::SOURCE_REVISION.into(),
            source_version: lightwallet_image::SOURCE_VERSION.into(),
            protocol_revision: lightwallet_image::PROTOCOL_REVISION.into(),
            protocol_version: lightwallet_image::PROTOCOL_VERSION.into(),
            binary_path: lightwallet_image::BINARY_PATH.into(),
            environment_launcher: lightwallet_image::ENVIRONMENT_LAUNCHER.into(),
        },
        allocation: LightwalletAllocation::for_size(Size::Medium),
        capacity_protocol: None,
    });
    deployment.outputs.as_mut().unwrap().lightwallet = Some(ClusterLightwalletOutputs {
        node_id: "node-2".into(),
        instance_id: "i-00000000000000002".into(),
        cache_volume_id: "vol-00000000000000004".into(),
        cache_size_gib: 40,
    });
    deployment
}

fn cache_volume(deployment: &Deployment) -> Value {
    let mut volume = owned_volume(deployment, "node-2");
    volume["VolumeId"] = json!(
        deployment
            .outputs
            .as_ref()
            .unwrap()
            .lightwallet
            .as_ref()
            .unwrap()
            .cache_volume_id
    );
    volume["Size"] = json!(40);
    volume["VolumeType"] = json!("gp3");
    let tags = volume["Tags"].as_array_mut().unwrap();
    tags.iter_mut().find(|tag| tag["Key"] == "Name").unwrap()["Value"] = json!(deployment
        .spec
        .resource_name(zdn::cluster_infra::LIGHTWALLET_CACHE_DISK));
    tags.push(json!({"Key":"zdn:service","Value":"lightwalletd"}));
    volume
}

fn owned_volume(deployment: &Deployment, node_id: &str) -> Value {
    let node = ClusterTopology::new(3)
        .unwrap()
        .nodes()
        .into_iter()
        .find(|node| node.node_id == node_id)
        .unwrap();
    let saved = &deployment.outputs.as_ref().unwrap().nodes[node_id];
    json!({
        "VolumeId":saved.volume_id,"State":"available","Attachments":[],
        "AvailabilityZone":deployment.spec.availability_zone,"Encrypted":true,
        "Tags":[
            {"Key":"zdn:network-id","Value":deployment.spec.network_id},
            {"Key":"zdn:team-id","Value":deployment.spec.scope.team_id},
            {"Key":"zdn:managed-by","Value":"zdn"},
            {"Key":"zdn:bootstrap","Value":deployment.team.bootstrap_id},
            {"Key":"zdn:node-id","Value":node_id},
            {"Key":"Name","Value":deployment.spec.resource_name(&node.volume_key)}
        ]
    })
}

#[derive(Default)]
struct FakeAws {
    tagged: BTreeMap<String, Vec<Value>>,
    saved: BTreeMap<(String, String), Value>,
    calls: RefCell<Vec<(String, Value)>>,
}

fn operation_shape(operation: &str) -> (&str, &str, &str, &str) {
    match operation {
        "describe-instances" => (
            "Reservations",
            "InstanceId",
            "InstanceIds",
            "InvalidInstanceID.NotFound",
        ),
        "describe-volumes" => ("Volumes", "VolumeId", "VolumeIds", "InvalidVolume.NotFound"),
        "describe-vpcs" => ("Vpcs", "VpcId", "VpcIds", "InvalidVpcID.NotFound"),
        "describe-addresses" => (
            "Addresses",
            "AllocationId",
            "AllocationIds",
            "InvalidAllocationID.NotFound",
        ),
        "describe-subnets" => (
            "Subnets",
            "SubnetId",
            "SubnetIds",
            "InvalidSubnetID.NotFound",
        ),
        "describe-security-groups" => (
            "SecurityGroups",
            "GroupId",
            "GroupIds",
            "InvalidGroup.NotFound",
        ),
        "describe-nat-gateways" => (
            "NatGateways",
            "NatGatewayId",
            "NatGatewayIds",
            "NatGatewayNotFound",
        ),
        "describe-internet-gateways" => (
            "InternetGateways",
            "InternetGatewayId",
            "InternetGatewayIds",
            "InvalidInternetGatewayID.NotFound",
        ),
        "describe-route-tables" => (
            "RouteTables",
            "RouteTableId",
            "RouteTableIds",
            "InvalidRouteTableID.NotFound",
        ),
        _ => panic!("unexpected operation {operation}"),
    }
}

fn response(list: &str, items: Vec<Value>) -> Value {
    if list == "Reservations" {
        json!({"Reservations":[{"Instances":items}]})
    } else {
        json!({list:items})
    }
}

impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert!(extra.is_empty() || operation == "describe-instances");
        self.calls
            .borrow_mut()
            .push((operation.into(), input.clone()));
        if service == "iam" {
            assert!(matches!(operation, "get-role" | "get-instance-profile"));
            return Err(AwsApiError {
                code: "NoSuchEntity".into(),
            }
            .into());
        }
        assert_eq!(service, "ec2");
        let (list, _, request_key, absent) = operation_shape(operation);
        if let Some(ids) = input.get(request_key) {
            let ids = ids.as_array().unwrap();
            assert_eq!(ids.len(), 1);
            let id = ids[0].as_str().unwrap();
            return match self.saved.get(&(operation.into(), id.into())) {
                Some(resource) => Ok(response(list, vec![resource.clone()])),
                None => Err(AwsApiError {
                    code: absent.into(),
                }
                .into()),
            };
        }
        let filter_key = if operation == "describe-nat-gateways" {
            "Filter"
        } else {
            "Filters"
        };
        assert_eq!(input[filter_key].as_array().unwrap().len(), 3);
        Ok(response(
            list,
            self.tagged.get(operation).cloned().unwrap_or_default(),
        ))
    }
}

impl FakeAws {
    fn save(&mut self, operation: &str, value: Value) {
        let (_, key, _, _) = operation_shape(operation);
        self.saved.insert(
            (operation.into(), value[key].as_str().unwrap().into()),
            value,
        );
    }
}

#[test]
fn all_saved_nodes_are_queried_even_after_every_ownership_tag_disappears() {
    let deployment = deployment();
    let mut aws = FakeAws::default();
    for saved in deployment.outputs.as_ref().unwrap().nodes.values() {
        aws.save(
            "describe-instances",
            json!({"InstanceId":saved.instance_id,"State":{"Name":"running"}}),
        );
        let mut volume = owned_volume(&deployment, &saved.node_id);
        volume.as_object_mut().unwrap().remove("Tags");
        aws.save("describe-volumes", volume);
    }
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources.len(), 6);
    for node in deployment.outputs.as_ref().unwrap().nodes.values() {
        assert!(report
            .remaining_resources
            .contains(&format!("instance:{}", node.instance_id)));
        assert!(report
            .remaining_resources
            .contains(&format!("volume:{}", node.volume_id)));
        assert!(aws.calls.borrow().contains(&(
            "describe-instances".into(),
            json!({"InstanceIds":[node.instance_id]})
        )));
        assert!(aws.calls.borrow().contains(&(
            "describe-volumes".into(),
            json!({"VolumeIds":[node.volume_id]})
        )));
    }
}

#[test]
fn exactly_owned_detached_node_disks_are_all_retained() {
    let deployment = deployment();
    let mut aws = FakeAws::default();
    for node in deployment.outputs.as_ref().unwrap().nodes.values() {
        let volume = owned_volume(&deployment, &node.node_id);
        aws.save("describe-volumes", volume.clone());
        aws.tagged
            .entry("describe-volumes".into())
            .or_default()
            .push(volume);
        aws.save(
            "describe-instances",
            json!({"InstanceId":node.instance_id,"State":{"Name":"terminated"}}),
        );
    }
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.remaining_resources.is_empty());
    assert_eq!(
        report.retained_volumes,
        [
            "vol-00000000000000001",
            "vol-00000000000000002",
            "vol-00000000000000003"
        ]
    );
}

#[test]
fn tag_only_disks_cannot_become_cluster_delete_candidates() {
    let mut deployment = deployment();
    let mut aws = FakeAws::default();
    let mut unknown = owned_volume(&deployment, "node-2");
    unknown["VolumeId"] = json!("vol-00000000000000009");
    aws.tagged.insert("describe-volumes".into(), vec![unknown]);
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-00000000000000009"]);

    let volume = owned_volume(&deployment, "node-3");
    aws.tagged.insert("describe-volumes".into(), vec![volume]);
    deployment.outputs = None;
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-00000000000000003"]);
}

#[test]
fn saved_volume_ids_do_not_bypass_name_node_or_bootstrap_ownership() {
    let deployment = deployment();
    for key in [
        "Name",
        "zdn:node-id",
        "zdn:bootstrap",
        "zdn:team-id",
        "zdn:network-id",
        "zdn:managed-by",
    ] {
        let mut aws = FakeAws::default();
        let mut volume = owned_volume(&deployment, "node-2");
        let tags = volume["Tags"].as_array_mut().unwrap();
        tags.iter_mut().find(|t| t["Key"] == key).unwrap()["Value"] = json!("foreign");
        aws.save("describe-volumes", volume);
        let report = inventory(&aws, &deployment).unwrap();
        assert!(report.retained_volumes.is_empty(), "{key}");
        assert_eq!(
            report.remaining_resources,
            ["volume:vol-00000000000000002"],
            "{key}"
        );
    }
}

#[test]
fn attached_disks_and_nonterminated_hosts_remain_cleanup_failures() {
    let deployment = deployment();
    let mut aws = FakeAws::default();
    let mut volume = owned_volume(&deployment, "node-3");
    volume["State"] = json!("in-use");
    volume["Attachments"] = json!([{"InstanceId":"i-00000000000000003"}]);
    aws.save("describe-volumes", volume);
    aws.save(
        "describe-instances",
        json!({"InstanceId":"i-00000000000000003","State":{"Name":"stopped"}}),
    );
    let report = inventory(&aws, &deployment).unwrap();
    assert_eq!(
        report.remaining_resources,
        [
            "instance:i-00000000000000003",
            "volume:vol-00000000000000003"
        ]
    );
    assert!(report.retained_volumes.is_empty());
}

#[test]
fn malformed_or_inconsistent_node_receipts_fail_before_inventory() {
    let deployment = deployment();
    for mutation in 0..3 {
        let mut changed = deployment.clone();
        let outputs = changed.outputs.as_mut().unwrap();
        match mutation {
            0 => {
                outputs.nodes.remove("node-3");
            }
            1 => {
                outputs.nodes.get_mut("node-2").unwrap().volume_id =
                    outputs.nodes["node-1"].volume_id.clone();
            }
            2 => outputs.instance_id = "i-00000000000000009".into(),
            _ => unreachable!(),
        }
        let aws = FakeAws::default();
        assert!(inventory(&aws, &changed).is_err());
        assert!(aws.calls.borrow().is_empty());
    }
}

#[test]
fn saved_node_reads_reject_a_different_resource_and_wrong_disk_attributes() {
    let deployment = deployment();
    let mut aws = FakeAws::default();
    let mut volume = owned_volume(&deployment, "node-2");
    volume["VolumeId"] = json!("vol-00000000000000009");
    aws.saved.insert(
        ("describe-volumes".into(), "vol-00000000000000002".into()),
        volume,
    );
    assert!(inventory(&aws, &deployment).is_err());
    for (key, value) in [
        ("AvailabilityZone", json!("us-east-1b")),
        ("Encrypted", json!(false)),
    ] {
        let mut aws = FakeAws::default();
        let mut volume = owned_volume(&deployment, "node-2");
        volume[key] = value;
        aws.save("describe-volumes", volume);
        assert!(inventory(&aws, &deployment).is_err(), "{key}");
    }
}

#[test]
fn exact_saved_lightwallet_cache_is_retained_with_the_node_disks() {
    let deployment = lightwallet_deployment();
    let mut aws = FakeAws::default();
    for node in deployment.outputs.as_ref().unwrap().nodes.values() {
        aws.save("describe-volumes", owned_volume(&deployment, &node.node_id));
    }
    let volume = cache_volume(&deployment);
    aws.save("describe-volumes", volume.clone());
    aws.tagged.insert("describe-volumes".into(), vec![volume]);
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.remaining_resources.is_empty());
    assert_eq!(
        report.retained_volumes,
        [
            "vol-00000000000000001",
            "vol-00000000000000002",
            "vol-00000000000000003",
            "vol-00000000000000004"
        ]
    );
    assert!(aws.calls.borrow().contains(&(
        "describe-volumes".into(),
        json!({"VolumeIds":["vol-00000000000000004"]})
    )));
}

#[test]
fn lightwallet_cache_tag_drift_is_still_visible_and_never_authorizes_deletion() {
    let deployment = lightwallet_deployment();
    for key in [
        None,
        Some("Name"),
        Some("zdn:node-id"),
        Some("zdn:service"),
        Some("zdn:bootstrap"),
        Some("zdn:team-id"),
        Some("zdn:network-id"),
        Some("zdn:managed-by"),
    ] {
        let mut aws = FakeAws::default();
        let mut volume = cache_volume(&deployment);
        match key {
            None => {
                volume.as_object_mut().unwrap().remove("Tags");
            }
            Some(key) => {
                volume["Tags"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|tag| tag["Key"] == key)
                    .unwrap()["Value"] = json!("foreign")
            }
        }
        aws.save("describe-volumes", volume);
        let report = inventory(&aws, &deployment).unwrap();
        assert!(report.retained_volumes.is_empty(), "{key:?}");
        assert_eq!(
            report.remaining_resources,
            ["volume:vol-00000000000000004"],
            "{key:?}"
        );
    }
    let mut aws = FakeAws::default();
    let mut duplicate = cache_volume(&deployment);
    duplicate["Tags"]
        .as_array_mut()
        .unwrap()
        .push(json!({"Key":"zdn:service","Value":"other"}));
    aws.save("describe-volumes", duplicate);
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-00000000000000004"]);
}

#[test]
fn lightwallet_cache_delete_candidates_require_recorded_id_and_original_attributes() {
    let deployment = lightwallet_deployment();
    for (key, value) in [
        ("Size", json!(80)),
        ("VolumeType", json!("gp2")),
        ("Encrypted", json!(false)),
        ("AvailabilityZone", json!("us-east-1b")),
    ] {
        let mut aws = FakeAws::default();
        let mut volume = cache_volume(&deployment);
        volume[key] = value;
        aws.save("describe-volumes", volume);
        assert!(inventory(&aws, &deployment).is_err(), "{key}");
    }
    let mut aws = FakeAws::default();
    let mut volume = cache_volume(&deployment);
    volume["VolumeId"] = json!("vol-00000000000000009");
    aws.tagged.insert("describe-volumes".into(), vec![volume]);
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-00000000000000009"]);
    let mut deployment = deployment;
    deployment.outputs = None;
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
}

#[test]
fn cache_receipt_mismatch_fails_before_any_inventory_call() {
    for mutation in 0..6 {
        let mut deployment = lightwallet_deployment();
        match mutation {
            0 => deployment.cluster.as_mut().unwrap().lightwallet = None,
            1 => deployment.outputs.as_mut().unwrap().lightwallet = None,
            2 => {
                deployment
                    .outputs
                    .as_mut()
                    .unwrap()
                    .lightwallet
                    .as_mut()
                    .unwrap()
                    .cache_size_gib = 80
            }
            3 => {
                deployment
                    .outputs
                    .as_mut()
                    .unwrap()
                    .lightwallet
                    .as_mut()
                    .unwrap()
                    .cache_volume_id = "vol-00000000000000002".into()
            }
            4 => {
                deployment
                    .outputs
                    .as_mut()
                    .unwrap()
                    .lightwallet
                    .as_mut()
                    .unwrap()
                    .node_id = "node-3".into()
            }
            5 => {
                deployment
                    .cluster
                    .as_mut()
                    .unwrap()
                    .lightwallet
                    .as_mut()
                    .unwrap()
                    .allocation
                    .cache_gib = 80
            }
            _ => unreachable!(),
        }
        let aws = FakeAws::default();
        assert!(inventory(&aws, &deployment).is_err(), "{mutation}");
        assert!(aws.calls.borrow().is_empty(), "{mutation}");
    }
}

#[test]
fn attached_cache_is_a_remaining_resource_even_when_ownership_matches() {
    let deployment = lightwallet_deployment();
    let mut aws = FakeAws::default();
    let mut volume = cache_volume(&deployment);
    volume["State"] = json!("in-use");
    volume["Attachments"] = json!([{"InstanceId":"i-00000000000000002","Device":"/dev/sdg"}]);
    aws.save("describe-volumes", volume);
    let report = inventory(&aws, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-00000000000000004"]);
}
