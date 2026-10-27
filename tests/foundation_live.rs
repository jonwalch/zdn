use std::{cell::RefCell, collections::BTreeMap};

use eyre::{bail, Result};
use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    aws::{AwsApi, AwsApiError, TeamAws, TeamDefinition, TeamState, TEAM_API_VERSION},
    config::Size,
    foundation::Deployment,
    foundation_live::{inventory, validate_health, validate_host_request},
    infra::{FoundationOutputs, FoundationSpec, FIXTURE_MEMORY_BYTES, GIB},
    state::Scope,
};

fn spec() -> FoundationSpec {
    FoundationSpec {
        scope: Scope {
            team_id: "team-a".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
        aws_profile: "developer".into(),
        ami_id: "ami-0123456789abcdef0".into(),
        availability_zone: "us-east-1a".into(),
        size: Size::Medium,
        retain_chain_disk: true,
    }
}

fn deployment() -> Deployment {
    let spec = spec();
    let team = TeamDefinition {
        deployment: None,
        api_version: TEAM_API_VERSION.into(),
        team_id: spec.scope.team_id.clone(),
        revision: 1,
        bootstrap_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04150").unwrap(),
        aws: TeamAws {
            account_id: spec.scope.account_id.clone(),
            region: spec.scope.region.clone(),
        },
        state: TeamState {
            backend: "s3://zdn-fixture-state/pulumi/team-a".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
    };
    Deployment::new(spec, team).unwrap()
}

struct SavedFixture {
    operation: &'static str,
    fake_key: &'static str,
    request_key: &'static str,
    list: &'static str,
    id_key: &'static str,
    id: &'static str,
    absent_code: &'static str,
}

impl SavedFixture {
    fn response(&self, resources: Vec<Value>) -> Value {
        if self.list == "Reservations" {
            json!({"Reservations":[{"Instances":resources}]})
        } else {
            json!({self.list:resources})
        }
    }

    fn resource(&self, deployment: &Deployment) -> Value {
        let mut resource = volume(deployment, "chain-disk");
        resource.as_object_mut().unwrap().remove("VolumeId");
        resource[self.id_key] = json!(self.id);
        match self.operation {
            "describe-instances" => resource["State"] = json!({"Name":"running"}),
            "describe-nat-gateways" => resource["State"] = json!("available"),
            "describe-volumes" => {}
            _ => {
                resource.as_object_mut().unwrap().remove("State");
            }
        }
        resource
    }

    fn report_entry(&self) -> String {
        let kind = match self.operation {
            "describe-instances" => "instance",
            "describe-nat-gateways" => "nat",
            "describe-volumes" => "volume",
            _ => self.id_key,
        };
        format!("{kind}:{}", self.id)
    }
}

fn saved_fixtures() -> [SavedFixture; 7] {
    [
        SavedFixture {
            operation: "describe-instances",
            fake_key: "describe-known-instance",
            request_key: "InstanceIds",
            list: "Reservations",
            id_key: "InstanceId",
            id: "i-0123456789abcdef0",
            absent_code: "InvalidInstanceID.NotFound",
        },
        SavedFixture {
            operation: "describe-vpcs",
            fake_key: "describe-known-vpc",
            request_key: "VpcIds",
            list: "Vpcs",
            id_key: "VpcId",
            id: "vpc-0123456789abcdef0",
            absent_code: "InvalidVpcID.NotFound",
        },
        SavedFixture {
            operation: "describe-addresses",
            fake_key: "describe-known-address",
            request_key: "AllocationIds",
            list: "Addresses",
            id_key: "AllocationId",
            id: "eipalloc-0123456789abcdef0",
            absent_code: "InvalidAllocationID.NotFound",
        },
        SavedFixture {
            operation: "describe-subnets",
            fake_key: "describe-known-subnet",
            request_key: "SubnetIds",
            list: "Subnets",
            id_key: "SubnetId",
            id: "subnet-0123456789abcdef0",
            absent_code: "InvalidSubnetID.NotFound",
        },
        SavedFixture {
            operation: "describe-security-groups",
            fake_key: "describe-known-security-group",
            request_key: "GroupIds",
            list: "SecurityGroups",
            id_key: "GroupId",
            id: "sg-0123456789abcdef0",
            absent_code: "InvalidGroup.NotFound",
        },
        SavedFixture {
            operation: "describe-nat-gateways",
            fake_key: "describe-known-nat",
            request_key: "NatGatewayIds",
            list: "NatGateways",
            id_key: "NatGatewayId",
            id: "nat-0123456789abcdef0",
            absent_code: "NatGatewayNotFound",
        },
        SavedFixture {
            operation: "describe-volumes",
            fake_key: "describe-known-volume",
            request_key: "VolumeIds",
            list: "Volumes",
            id_key: "VolumeId",
            id: "vol-0123456789abcdef0",
            absent_code: "InvalidVolume.NotFound",
        },
    ]
}

#[derive(Default)]
struct FakeAws {
    responses: BTreeMap<String, Value>,
    errors: BTreeMap<String, String>,
    calls: RefCell<Vec<(String, Value)>>,
}
impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert!(matches!(service, "ec2" | "iam"));
        assert!(
            operation.starts_with("describe-") || operation.starts_with("get-"),
            "contract checks must not mutate AWS: {operation}"
        );
        assert!(extra.is_empty() || operation == "describe-instances");
        self.calls
            .borrow_mut()
            .push((operation.into(), input.clone()));
        for fixture in saved_fixtures() {
            if operation != fixture.operation || input.get(fixture.request_key).is_none() {
                continue;
            }
            assert_eq!(input, json!({fixture.request_key:[fixture.id]}));
            if let Some(code) = self.errors.get(fixture.fake_key) {
                return Err(AwsApiError { code: code.clone() }.into());
            }
            if let Some(value) = self.responses.get(fixture.fake_key) {
                return Ok(value.clone());
            }
            let response = &self.responses[operation];
            let resources: Vec<_> = if fixture.list == "Reservations" {
                response["Reservations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|reservation| reservation["Instances"].as_array().unwrap())
                    .collect()
            } else {
                response[fixture.list].as_array().unwrap().iter().collect()
            };
            let found = resources
                .into_iter()
                .filter(|resource| resource[fixture.id_key] == fixture.id)
                .cloned()
                .collect::<Vec<_>>();
            if found.is_empty() {
                return Err(AwsApiError {
                    code: fixture.absent_code.into(),
                }
                .into());
            }
            return Ok(fixture.response(found));
        }
        if let Some(code) = self.errors.get(operation) {
            return Err(AwsApiError { code: code.clone() }.into());
        }
        if let Some(value) = self.responses.get(operation) {
            return Ok(value.clone());
        }
        bail!("unexpected fake AWS operation {operation}")
    }
}
impl FakeAws {
    fn host() -> Self {
        let spec = spec();
        Self {
            responses: [
                ("describe-images".into(), json!({"Images":[{"ImageId":spec.ami_id, "Architecture":"x86_64", "State":"available", "RootDeviceType":"ebs", "VirtualizationType":"hvm", "Name":"al2023-ami-2023.9.20261012.0-kernel-6.1-x86_64"}]})),
                ("describe-availability-zones".into(), json!({"AvailabilityZones":[{"ZoneName":spec.availability_zone,"RegionName":spec.scope.region,"State":"available"}]})),
                ("describe-instance-type-offerings".into(), json!({"InstanceTypeOfferings":[{"Location":"us-east-1a","InstanceType":"m7a.xlarge"}]})),
            ].into(), ..Self::default()
        }
    }
    fn empty_inventory() -> Self {
        Self {
            responses: [
                ("describe-instances".into(), json!({"Reservations":[]})),
                ("describe-vpcs".into(), json!({"Vpcs":[]})),
                ("describe-addresses".into(), json!({"Addresses":[]})),
                ("describe-subnets".into(), json!({"Subnets":[]})),
                (
                    "describe-security-groups".into(),
                    json!({"SecurityGroups":[]}),
                ),
                (
                    "describe-internet-gateways".into(),
                    json!({"InternetGateways":[]}),
                ),
                ("describe-route-tables".into(), json!({"RouteTables":[]})),
                ("describe-nat-gateways".into(), json!({"NatGateways":[]})),
                ("describe-volumes".into(), json!({"Volumes":[]})),
            ]
            .into(),
            errors: [
                ("get-role".into(), "NoSuchEntity".into()),
                ("get-instance-profile".into(), "NoSuchEntity".into()),
            ]
            .into(),
            ..Self::default()
        }
    }
}

#[test]
fn valid_host_request_restricts_the_image_to_amazon_and_exact_pinned_id() {
    let api = FakeAws::host();
    validate_host_request(&api, &spec()).unwrap();
    let calls = api.calls.borrow();
    let image_request = &calls
        .iter()
        .find(|(op, _)| op == "describe-images")
        .unwrap()
        .1;
    assert_eq!(image_request["Owners"], json!(["amazon"]));
    assert_eq!(image_request["ImageIds"], json!([spec().ami_id]));
    assert!(image_request.get("ExecutableUsers").is_none());
}

#[test]
fn ami_architecture_os_storage_state_and_exact_identity_are_checked() {
    for (field, bad) in [
        ("Architecture", "arm64"),
        ("Name", "ubuntu/images/server"),
        ("State", "pending"),
        ("RootDeviceType", "instance-store"),
        ("VirtualizationType", "paravirtual"),
        ("ImageId", "ami-0123456789abcdef1"),
    ] {
        let mut api = FakeAws::host();
        api.responses.get_mut("describe-images").unwrap()["Images"][0][field] = json!(bad);
        assert!(
            validate_host_request(&api, &spec()).is_err(),
            "accepted incorrect {field}"
        );
        assert!(!api
            .calls
            .borrow()
            .iter()
            .any(|(op, _)| op == "describe-instance-type-offerings"));
    }
    for count in [0, 2] {
        let mut api = FakeAws::host();
        let image = api.responses["describe-images"]["Images"][0].clone();
        api.responses.insert(
            "describe-images".into(),
            json!({"Images":vec![image; count]}),
        );
        assert!(validate_host_request(&api, &spec()).is_err());
    }
}

#[test]
fn zones_and_instance_offerings_must_match_the_selected_region_and_size() {
    for (field, bad) in [
        ("ZoneName", "us-east-1b"),
        ("RegionName", "us-west-2"),
        ("State", "unavailable"),
    ] {
        let mut api = FakeAws::host();
        api.responses
            .get_mut("describe-availability-zones")
            .unwrap()["AvailabilityZones"][0][field] = json!(bad);
        assert!(
            validate_host_request(&api, &spec()).is_err(),
            "accepted wrong {field}"
        );
    }
    for offerings in [
        json!([]),
        json!([{"Location":"us-east-1b","InstanceType":"m7a.xlarge"}]),
        json!([{"Location":"us-east-1a","InstanceType":"m7a.large"}]),
    ] {
        let mut api = FakeAws::host();
        api.responses.insert(
            "describe-instance-type-offerings".into(),
            json!({"InstanceTypeOfferings":offerings}),
        );
        assert!(validate_host_request(&api, &spec()).is_err());
    }
}

#[test]
fn malformed_host_metadata_is_an_error_not_an_empty_success() {
    for (operation, key) in [
        ("describe-images", "Images"),
        ("describe-availability-zones", "AvailabilityZones"),
        ("describe-instance-type-offerings", "InstanceTypeOfferings"),
    ] {
        for value in [json!({}), json!({key:null}), json!({key:{}})] {
            let mut api = FakeAws::host();
            api.responses.insert(operation.into(), value);
            assert!(
                validate_host_request(&api, &spec()).is_err(),
                "accepted malformed {operation}"
            );
        }
    }
}

fn health() -> Value {
    json!({"schema_version":1,"network_id":spec().network_id,"status":"ready",
        "chain_mounted":true,"docker_active":true,"ssm_active":true,
        "effective_memory_bytes":16*GIB,"application_memory_bytes":14*GIB-FIXTURE_MEMORY_BYTES,
        "visible_cpus":4,"visible_cpu_millis":4000,"application_cpu_millis":3500})
}

#[test]
fn valid_health_accepts_measured_limits_and_one_fixture_budget() {
    let mut response = health();
    validate_health(&response.to_string(), &spec()).unwrap();
    response["effective_memory_bytes"] = json!(12 * GIB);
    response["application_memory_bytes"] = json!(10 * GIB - FIXTURE_MEMORY_BYTES);
    response["visible_cpus"] = json!(3);
    response["visible_cpu_millis"] = json!(1500);
    response["application_cpu_millis"] = json!(1000);
    validate_health(&response.to_string(), &spec()).unwrap();
}

#[test]
fn health_rejects_missing_fixture_reservation_and_memory_overcommit() {
    for (effective, application) in [
        (16 * GIB, 14 * GIB),
        (8 * GIB, 6 * GIB),
        (128 * GIB, 20 * GIB),
        (2 * GIB, 1),
        (2 * GIB + FIXTURE_MEMORY_BYTES, 1),
        (16 * GIB, 0),
    ] {
        let mut response = health();
        response["effective_memory_bytes"] = json!(effective);
        response["application_memory_bytes"] = json!(application);
        assert!(
            validate_health(&response.to_string(), &spec()).is_err(),
            "accepted effective={effective} application={application}"
        );
    }
}

#[test]
fn health_rejects_wrong_network_schema_status_and_stopped_services() {
    for (field, value) in [
        ("schema_version", json!(2)),
        ("network_id", json!(Uuid::new_v4())),
        ("status", json!("starting")),
        ("chain_mounted", json!(false)),
        ("docker_active", json!(false)),
        ("ssm_active", json!(false)),
    ] {
        let mut response = health();
        response[field] = value;
        assert!(
            validate_health(&response.to_string(), &spec()).is_err(),
            "accepted incorrect {field}"
        );
    }
    for field in health().as_object().unwrap().keys() {
        let mut response = health();
        response.as_object_mut().unwrap().remove(field);
        assert!(
            validate_health(&response.to_string(), &spec()).is_err(),
            "accepted missing {field}"
        );
    }
    assert!(validate_health(&" ".repeat(16 * 1024 + 1), &spec()).is_err());
}

#[test]
fn health_rejects_cpu_budget_above_visibility_or_below_reserves() {
    for (cpus, visible, application) in [
        (0, 4000, 3500),
        (4, 500, 1),
        (4, 4000, 3501),
        (4, 4000, 0),
        (2, 3000, 2000),
        (8, 8000, 7500),
    ] {
        let mut response = health();
        response["visible_cpus"] = json!(cpus);
        response["visible_cpu_millis"] = json!(visible);
        response["application_cpu_millis"] = json!(application);
        assert!(
            validate_health(&response.to_string(), &spec()).is_err(),
            "accepted {cpus}/{visible}/{application}"
        );
    }
}

fn volume(deployment: &Deployment, purpose: &str) -> Value {
    json!({"VolumeId":"vol-0123456789abcdef0","State":"available","Attachments":[],
        "AvailabilityZone":deployment.spec.availability_zone,"Encrypted":true,
        "Tags":[{"Key":"Name","Value":deployment.spec.resource_name(purpose)},
            {"Key":"zdn:team-id","Value":deployment.spec.scope.team_id},
            {"Key":"zdn:network-id","Value":deployment.spec.network_id.to_string()},
            {"Key":"zdn:managed-by","Value":"zdn"}]})
}
fn set_volumes(api: &mut FakeAws, volumes: Value) {
    api.responses
        .insert("describe-volumes".into(), json!({"Volumes":volumes}));
}

#[test]
fn empty_inventory_requires_scoped_queries_and_does_not_claim_backend_validation() {
    let deployment = deployment();
    let api = FakeAws::empty_inventory();
    let report = inventory(&api, &deployment).unwrap();
    assert!(report.remaining_resources.is_empty());
    assert!(report.retained_volumes.is_empty());
    assert!(!report.shared_backend_preserved);
    for (operation, input) in api.calls.borrow().iter() {
        if operation.starts_with("describe-") {
            let filters = input
                .get("Filters")
                .or_else(|| input.get("Filter"))
                .unwrap()
                .as_array()
                .unwrap();
            for (name, value) in [
                ("tag:zdn:network-id", deployment.spec.network_id.to_string()),
                ("tag:zdn:team-id", deployment.spec.scope.team_id.clone()),
                ("tag:zdn:managed-by", "zdn".into()),
            ] {
                assert!(
                    filters
                        .iter()
                        .any(|f| f["Name"] == name && f["Values"] == json!([value])),
                    "missing {name} in {operation}"
                );
            }
        }
    }
}

#[test]
fn inventory_reports_compute_network_addresses_and_iam_leftovers() {
    let deployment = deployment();
    let mut api = FakeAws::empty_inventory();
    api.responses.insert(
        "describe-instances".into(),
        json!({"Reservations":[{"Instances":[
        {"InstanceId":"i-running","State":{"Name":"running"}},
        {"InstanceId":"i-ended","State":{"Name":"terminated"}}]}]}),
    );
    for (operation, list, id, value) in [
        ("describe-vpcs", "Vpcs", "VpcId", "vpc-left"),
        (
            "describe-addresses",
            "Addresses",
            "AllocationId",
            "eipalloc-left",
        ),
        ("describe-subnets", "Subnets", "SubnetId", "subnet-left"),
        (
            "describe-security-groups",
            "SecurityGroups",
            "GroupId",
            "sg-left",
        ),
        (
            "describe-internet-gateways",
            "InternetGateways",
            "InternetGatewayId",
            "igw-left",
        ),
        (
            "describe-route-tables",
            "RouteTables",
            "RouteTableId",
            "rtb-left",
        ),
    ] {
        api.responses
            .insert(operation.into(), json!({list:[{id:value}]}));
    }
    api.responses.insert("describe-nat-gateways".into(),json!({"NatGateways":[{"NatGatewayId":"nat-left","State":"deleting"},{"NatGatewayId":"nat-ended","State":"deleted"}]}));
    for operation in ["get-role", "get-instance-profile"] {
        api.errors.remove(operation);
        api.responses.insert(operation.into(), json!({}));
    }
    let report = inventory(&api, &deployment).unwrap();
    assert_eq!(report.remaining_resources.len(), 10);
    for expected in [
        "i-running",
        "vpc-left",
        "eipalloc-left",
        "subnet-left",
        "sg-left",
        "igw-left",
        "rtb-left",
        "nat-left",
        "host-role",
        "host-profile",
    ] {
        assert!(
            report
                .remaining_resources
                .iter()
                .any(|resource| resource.contains(expected)),
            "missing {expected}"
        );
    }
    assert!(!report
        .remaining_resources
        .iter()
        .any(|resource| resource.contains("ended")));
    assert!(report.retained_volumes.is_empty());
}

#[test]
fn only_an_owned_detached_chain_disk_is_reported_as_retained() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    let chain = volume(&deployment, "chain-disk");
    let mut root = volume(&deployment, "root-disk");
    root["VolumeId"] = json!("vol-root");
    set_volumes(&mut api, json!([chain, root]));
    let report = inventory(&api, &deployment).unwrap();
    assert_eq!(report.retained_volumes, vec!["vol-0123456789abcdef0"]);
    assert_eq!(report.remaining_resources, vec!["volume:vol-root"]);
    for (field, value) in [
        ("State", json!("in-use")),
        ("Attachments", json!([{"InstanceId":"i-any"}])),
    ] {
        let mut attached = volume(&deployment, "chain-disk");
        attached[field] = value;
        set_volumes(&mut api, json!([attached]));
        let report = inventory(&api, &deployment).unwrap();
        assert!(report.retained_volumes.is_empty());
        assert_eq!(report.remaining_resources.len(), 1);
    }
}

#[test]
fn foreign_volume_tags_do_not_grant_data_deletion_eligibility() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for key in ["Name", "zdn:team-id", "zdn:network-id", "zdn:managed-by"] {
        let mut disk = volume(&deployment, "chain-disk");
        let tag = disk["Tags"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|t| t["Key"] == key)
            .unwrap();
        tag["Value"] = json!("foreign");
        let mut api = FakeAws::empty_inventory();
        set_volumes(&mut api, json!([disk]));
        let report = inventory(&api, &deployment).unwrap();
        assert!(report.retained_volumes.is_empty(), "accepted foreign {key}");
        assert_eq!(report.remaining_resources.len(), 1);
    }
}

#[test]
fn owned_disk_with_changed_az_or_encryption_is_an_error() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for (field, value) in [
        ("AvailabilityZone", json!("us-east-1b")),
        ("Encrypted", json!(false)),
    ] {
        let mut disk = volume(&deployment, "chain-disk");
        disk[field] = value;
        let mut api = FakeAws::empty_inventory();
        set_volumes(&mut api, json!([disk]));
        assert!(
            inventory(&api, &deployment).is_err(),
            "accepted changed {field}"
        );
    }
}

#[test]
fn tags_without_saved_volume_identity_never_authorize_data_deletion() {
    let deployment = deployment();
    let mut api = FakeAws::empty_inventory();
    set_volumes(&mut api, json!([volume(&deployment, "chain-disk")]));
    let report = inventory(&api, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(report.remaining_resources, ["volume:vol-0123456789abcdef0"]);
}

fn record_outputs(deployment: &mut Deployment) {
    deployment.outputs = Some(serde_json::from_value::<FoundationOutputs>(json!({
        "schema_version":1,"scope":deployment.spec.scope,"network_id":deployment.spec.network_id,
        "availability_zone":deployment.spec.availability_zone,
        "vpc_id":"vpc-0123456789abcdef0","private_subnet_id":"subnet-0123456789abcdef0",
        "instance_id":"i-0123456789abcdef0","private_ip":"10.90.1.12",
        "chain_volume_id":"vol-0123456789abcdef0","retain_chain_disk":true,
        "security_group_id":"sg-0123456789abcdef0","nat_gateway_id":"nat-0123456789abcdef0",
        "eip_allocation_id":"eipalloc-0123456789abcdef0"
    })).unwrap());
}

#[test]
fn an_unexpected_second_chain_volume_needs_explicit_recovery() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let first = volume(&deployment, "chain-disk");
    let mut second = first.clone();
    second["VolumeId"] = json!("vol-0123456789abcdef1");
    let mut api = FakeAws::empty_inventory();
    set_volumes(&mut api, json!([first, second]));
    let error = inventory(&api, &deployment).unwrap_err().to_string();
    assert!(error.contains("unexpected second chain volume"));
}

#[test]
fn missing_or_malformed_inventory_lists_cannot_claim_cleanup() {
    let deployment = deployment();
    for (operation, key) in [
        ("describe-instances", "Reservations"),
        ("describe-vpcs", "Vpcs"),
        ("describe-addresses", "Addresses"),
        ("describe-subnets", "Subnets"),
        ("describe-security-groups", "SecurityGroups"),
        ("describe-internet-gateways", "InternetGateways"),
        ("describe-route-tables", "RouteTables"),
        ("describe-nat-gateways", "NatGateways"),
        ("describe-volumes", "Volumes"),
    ] {
        for value in [json!({}), json!({key:null}), json!({key:{}})] {
            let mut api = FakeAws::empty_inventory();
            api.responses.insert(operation.into(), value);
            assert!(
                inventory(&api, &deployment).is_err(),
                "accepted malformed {operation}"
            );
        }
    }
    let mut api = FakeAws::empty_inventory();
    api.responses
        .insert("describe-instances".into(), json!({"Reservations":[{}]}));
    assert!(inventory(&api, &deployment).is_err());
    let mut api = FakeAws::empty_inventory();
    let mut disk = volume(&deployment, "chain-disk");
    disk["Tags"] = json!({});
    set_volumes(&mut api, json!([disk]));
    assert!(inventory(&api, &deployment).is_err());
}

#[test]
fn iam_access_failures_are_not_treated_as_resource_absence() {
    let deployment = deployment();
    for operation in ["get-role", "get-instance-profile"] {
        for code in ["AccessDenied", "ExpiredToken", "Throttling"] {
            let mut api = FakeAws::empty_inventory();
            api.errors.insert(operation.into(), code.into());
            let error = inventory(&api, &deployment).unwrap_err();
            assert_eq!(error.downcast_ref::<AwsApiError>().unwrap().code, code);
        }
    }
}

#[test]
fn saved_volume_stays_in_inventory_when_ownership_tags_disappear() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for tags in [
        None,
        Some(json!([])),
        Some(json!([{"Key":"zdn:team-id","Value":"another-team"}])),
    ] {
        let mut api = FakeAws::empty_inventory();
        let mut known = volume(&deployment, "chain-disk");
        match tags {
            Some(tags) => {
                known["Tags"] = tags;
            }
            None => {
                known.as_object_mut().unwrap().remove("Tags");
            }
        }
        // The tag query legitimately returns no volumes. The separately known
        // ID must still prevent a false clean result and automatic deletion.
        api.responses
            .insert("describe-known-volume".into(), json!({"Volumes":[known]}));
        let report = inventory(&api, &deployment).unwrap();
        assert_eq!(
            report.remaining_resources,
            vec!["volume:vol-0123456789abcdef0"]
        );
        assert!(report.retained_volumes.is_empty());
    }
}

#[test]
fn known_volume_not_found_is_absent_but_query_failure_is_not() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    api.errors.insert(
        "describe-known-volume".into(),
        "InvalidVolume.NotFound".into(),
    );
    let report = inventory(&api, &deployment).unwrap();
    assert!(report.remaining_resources.is_empty());
    assert!(report.retained_volumes.is_empty());
    for code in ["AccessDenied", "ExpiredToken", "Throttling"] {
        api.errors
            .insert("describe-known-volume".into(), code.into());
        assert!(
            inventory(&api, &deployment).is_err(),
            "accepted failed exact-volume lookup: {code}"
        );
    }
}

#[test]
fn known_and_tagged_volume_discovery_does_not_duplicate_retained_disks() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    set_volumes(&mut api, json!([volume(&deployment, "chain-disk")]));
    let report = inventory(&api, &deployment).unwrap();
    assert_eq!(report.retained_volumes, vec!["vol-0123456789abcdef0"]);
    assert!(report.remaining_resources.is_empty());
}

#[test]
fn fresh_saved_volume_lookup_overrides_stale_ownership_tags() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    let stale = volume(&deployment, "chain-disk");
    let mut fresh = stale.clone();
    fresh["Tags"] = json!([]);
    set_volumes(&mut api, json!([stale]));
    api.responses
        .insert("describe-known-volume".into(), json!({"Volumes":[fresh]}));
    let report = inventory(&api, &deployment).unwrap();
    assert!(report.retained_volumes.is_empty());
    assert_eq!(
        report.remaining_resources,
        vec!["volume:vol-0123456789abcdef0"]
    );
}

#[test]
fn exact_saved_volume_lookup_must_return_that_single_volume() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let good = volume(&deployment, "chain-disk");
    let mut wrong = good.clone();
    wrong["VolumeId"] = json!("vol-0123456789abcdef1");
    for response in [
        json!({"Volumes":[wrong]}),
        json!({"Volumes":[good.clone(),good]}),
        json!({}),
    ] {
        let mut api = FakeAws::empty_inventory();
        api.responses
            .insert("describe-known-volume".into(), response);
        assert!(inventory(&api, &deployment).is_err());
    }
}

#[test]
fn every_saved_id_remains_visible_after_tag_removal_or_change() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for fixture in saved_fixtures() {
        for tags in [
            None,
            Some(json!([])),
            Some(json!([{"Key":"zdn:team-id","Value":"another-team"}])),
        ] {
            let mut api = FakeAws::empty_inventory();
            let mut resource = fixture.resource(&deployment);
            if let Some(tags) = tags {
                resource["Tags"] = tags;
            } else {
                resource.as_object_mut().unwrap().remove("Tags");
            }
            api.responses
                .insert(fixture.fake_key.into(), fixture.response(vec![resource]));
            let mut report = inventory(&api, &deployment).unwrap();
            assert_eq!(
                report.remaining_resources,
                vec![fixture.report_entry()],
                "{}",
                fixture.operation
            );
            assert!(report.retained_volumes.is_empty());
            report.shared_backend_preserved = true;
            assert!(report.validate(true).is_err());
            assert!(api
                .calls
                .borrow()
                .iter()
                .any(|(operation, input)| operation == fixture.operation
                    && input == &json!({fixture.request_key:[fixture.id]})));
        }
    }
}

#[test]
fn saved_and_tagged_discovery_merges_each_resource_once() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    for fixture in saved_fixtures() {
        let resource = fixture.resource(&deployment);
        api.responses.insert(
            fixture.operation.into(),
            fixture.response(vec![resource.clone(), resource.clone()]),
        );
        api.responses
            .insert(fixture.fake_key.into(), fixture.response(vec![resource]));
    }
    let report = inventory(&api, &deployment).unwrap();
    let mut expected: Vec<_> = saved_fixtures()
        .iter()
        .filter(|fixture| fixture.operation != "describe-volumes")
        .map(SavedFixture::report_entry)
        .collect();
    expected.sort();
    assert_eq!(report.remaining_resources, expected);
    assert_eq!(report.retained_volumes, vec!["vol-0123456789abcdef0"]);
}

#[test]
fn exact_absence_codes_and_empty_instance_lookups_are_accepted() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    let mut api = FakeAws::empty_inventory();
    for fixture in saved_fixtures() {
        api.errors
            .insert(fixture.fake_key.into(), fixture.absent_code.into());
    }
    let report = inventory(&api, &deployment).unwrap();
    assert!(report.remaining_resources.is_empty());
    assert!(report.retained_volumes.is_empty());
    for fixture in saved_fixtures() {
        assert!(api
            .calls
            .borrow()
            .iter()
            .any(|(operation, input)| operation == fixture.operation
                && input == &json!({fixture.request_key:[fixture.id]})));
    }
    // EC2 eventually forgets terminated instances and can return success with
    // either empty reservation shape for the exact saved InstanceIds lookup.
    for response in [
        json!({"Reservations":[]}),
        json!({"Reservations":[{"Instances":[]}]}),
    ] {
        let mut api = FakeAws::empty_inventory();
        api.responses
            .insert("describe-known-instance".into(), response);
        let report = inventory(&api, &deployment).unwrap();
        assert!(report.remaining_resources.is_empty());
        assert!(report.retained_volumes.is_empty());
    }
}

#[test]
fn saved_lookup_errors_never_hide_permission_transient_or_malformed_failures() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for fixture in saved_fixtures() {
        for code in [
            "AccessDenied",
            "UnauthorizedOperation",
            "ExpiredToken",
            "Throttling",
            "ServiceUnavailable",
            "InvalidParameterValue",
            "NotFound",
            "InvalidAMIID.NotFound",
        ] {
            let mut api = FakeAws::empty_inventory();
            api.errors.insert(fixture.fake_key.into(), code.into());
            let error = inventory(&api, &deployment).unwrap_err();
            assert_eq!(
                error.downcast_ref::<AwsApiError>().unwrap().code,
                code,
                "{}",
                fixture.operation
            );
        }
    }
}

#[test]
fn exact_lookups_require_one_matching_resource_and_complete_response_shape() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for fixture in saved_fixtures() {
        let good = fixture.resource(&deployment);
        let mut wrong = good.clone();
        wrong[fixture.id_key] = json!(format!("{}1", fixture.id));
        let mut missing_id = good.clone();
        missing_id.as_object_mut().unwrap().remove(fixture.id_key);
        let mut responses = vec![
            json!({}),
            json!({fixture.list:null}),
            fixture.response(vec![wrong]),
            fixture.response(vec![missing_id]),
            fixture.response(vec![good.clone(), good.clone()]),
        ];
        if fixture.operation != "describe-instances" {
            responses.push(fixture.response(vec![]));
        } else {
            responses.push(json!({"Reservations":[{}]}));
        }
        for response in responses {
            let mut api = FakeAws::empty_inventory();
            api.responses
                .insert(fixture.fake_key.into(), response.clone());
            assert!(
                inventory(&api, &deployment).is_err(),
                "accepted {} response {response}",
                fixture.operation
            );
        }
    }
}

#[test]
fn exact_terminal_states_replace_stale_active_tagged_resources() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for (operation, terminal) in [
        ("describe-instances", json!({"Name":"terminated"})),
        ("describe-nat-gateways", json!("deleted")),
        ("describe-volumes", json!("deleted")),
    ] {
        let fixture = saved_fixtures()
            .into_iter()
            .find(|fixture| fixture.operation == operation)
            .unwrap();
        let mut api = FakeAws::empty_inventory();
        let active = fixture.resource(&deployment);
        let mut removed = active.clone();
        removed["State"] = terminal;
        api.responses
            .insert(fixture.operation.into(), fixture.response(vec![active]));
        api.responses
            .insert(fixture.fake_key.into(), fixture.response(vec![removed]));
        let report = inventory(&api, &deployment).unwrap();
        assert!(report.remaining_resources.is_empty(), "{operation}");
        assert!(report.retained_volumes.is_empty(), "{operation}");
    }
}

#[test]
fn invalid_or_missing_lifecycle_states_do_not_claim_absence() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for fixture in saved_fixtures().into_iter().filter(|fixture| {
        matches!(
            fixture.operation,
            "describe-instances" | "describe-nat-gateways" | "describe-volumes"
        )
    }) {
        for state in [Value::Null, json!("unknown"), json!({"Name":"unknown"})] {
            let mut api = FakeAws::empty_inventory();
            let mut resource = fixture.resource(&deployment);
            resource["State"] = state;
            api.responses
                .insert(fixture.fake_key.into(), fixture.response(vec![resource]));
            assert!(
                inventory(&api, &deployment).is_err(),
                "{}",
                fixture.operation
            );
        }
    }
}

#[test]
fn an_absent_exact_lookup_does_not_erase_a_contradictory_tagged_leftover() {
    let mut deployment = deployment();
    record_outputs(&mut deployment);
    for fixture in saved_fixtures() {
        let mut api = FakeAws::empty_inventory();
        let mut resource = fixture.resource(&deployment);
        if fixture.operation == "describe-volumes" {
            resource["State"] = json!("in-use");
        }
        api.responses
            .insert(fixture.operation.into(), fixture.response(vec![resource]));
        api.errors
            .insert(fixture.fake_key.into(), fixture.absent_code.into());
        let report = inventory(&api, &deployment).unwrap();
        assert_eq!(report.remaining_resources, vec![fixture.report_entry()]);
        assert!(report.retained_volumes.is_empty());
        if fixture.operation == "describe-instances" {
            api.errors.remove(fixture.fake_key);
            api.responses
                .insert(fixture.fake_key.into(), json!({"Reservations":[]}));
            let report = inventory(&api, &deployment).unwrap();
            assert_eq!(report.remaining_resources, vec![fixture.report_entry()]);
            assert!(report.retained_volumes.is_empty());
        }
    }
}
