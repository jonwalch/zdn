use super::*;
use crate::{
    aws::{TeamAws, TeamState},
    config::Size,
    pulumi::{ProcessOutput, PulumiFailure},
    state::Scope,
};
use std::cell::RefCell;
use std::collections::VecDeque;

fn deployment() -> Deployment {
    let spec = FoundationSpec {
        scope: Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        network_id: Uuid::new_v4(),
        aws_profile: "developer".into(),
        ami_id: "ami-12345678".into(),
        availability_zone: "us-east-1a".into(),
        size: Size::Medium,
        retain_chain_disk: true,
    };
    let team = TeamDefinition {
        api_version: aws::TEAM_API_VERSION.into(),
        team_id: spec.scope.team_id.clone(),
        revision: 1,
        bootstrap_id: Uuid::new_v4(),
        deployment: None,
        aws: TeamAws {
            account_id: spec.scope.account_id.clone(),
            region: spec.scope.region.clone(),
        },
        state: TeamState {
            backend: "s3://zdn-test-foundation/pulumi/test-team".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
    };
    Deployment::new(spec, team).unwrap()
}

fn resource(deployment: &Deployment, key: &str, id: &str) -> Value {
    let rendered = serde_json::to_value(&deployment.render().unwrap().resources[key]).unwrap();
    let kind = match key {
        "natAddress" => "aws:ec2/eip:Eip",
        "natGateway" => "aws:ec2/natGateway:NatGateway",
        "chainDisk" => "aws:ebs/volume:Volume",
        _ => unreachable!(),
    };
    json!({"urn":urn(deployment, kind, rendered["name"].as_str().unwrap()),
        "type":kind, "id":id, "custom":true,
        "retainOnDelete":rendered["options"]["retainOnDelete"],
        "inputs":rendered["properties"], "outputs":rendered["properties"]})
}

fn checkpoint(resource: Value) -> Value {
    json!({"deployment":{"resources":[resource], "pending_operations":[]}})
}

fn stale_checkpoint(deployment: &Deployment) -> Value {
    let mut value = resource(deployment, "natAddress", "eipalloc-12345678");
    value["outputs"]["allocationId"] = json!("eipalloc-12345678");
    value["outputs"]["associationId"] = json!("eipassoc-12345678");
    value["outputs"]["networkInterface"] = json!("eni-12345678");
    checkpoint(value)
}

fn observed_address(deployment: &Deployment) -> Value {
    let rendered =
        serde_json::to_value(&deployment.render().unwrap().resources["natAddress"]).unwrap();
    let tags = rendered["properties"]["tags"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| json!({"Key":key,"Value":value}))
        .collect::<Vec<_>>();
    json!({"Addresses":[{"AllocationId":"eipalloc-12345678","Domain":"vpc","Tags":tags}]})
}

fn failure(text: &str) -> PulumiFailure {
    PulumiFailure::from_output(
        "destroy",
        &ProcessOutput {
            stdout: text.as_bytes().to_vec(),
            stderr: vec![],
            success: false,
            exit_code: Some(1),
        },
    )
}

fn stale_failure() -> PulumiFailure {
    failure("error: disassociating EC2 EIP (eipassoc-12345678): operation error EC2: DisassociateAddress, api error UnauthorizedOperation: denied")
}

#[derive(Default)]
struct Api(RefCell<VecDeque<(&'static str, Value)>>);
impl AwsApi for Api {
    fn call(&self, service: &str, operation: &str, input: Value, _: &[String]) -> Result<Value> {
        assert_eq!(service, "ec2");
        let (expected, response) = self
            .0
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected {operation} {input}"));
        assert_eq!(operation, expected);
        if operation == "describe-addresses" {
            assert_eq!(input, json!({"AllocationIds":["eipalloc-12345678"]}));
        }
        Ok(response)
    }
}

fn check_stale(
    api: &dyn AwsApi,
    deployment: &Deployment,
    checkpoint: &Value,
    failure: &PulumiFailure,
) -> Result<bool> {
    stale_nat_address(api, deployment, checkpoint, failure, &mut || {
        Ok(RunControl::Continue)
    })
}

#[test]
fn only_exact_stale_disassociation_denial_can_be_recovered() {
    let deployment = deployment();
    let checkpoint = stale_checkpoint(&deployment);
    let api = Api(RefCell::new(
        [
            ("describe-addresses", observed_address(&deployment)),
            ("describe-nat-gateways", json!({"NatGateways":[]})),
        ]
        .into(),
    ));
    assert!(check_stale(&api, &deployment, &checkpoint, &stale_failure()).unwrap());
    assert!(api.0.borrow().is_empty());
    for text in [
        "AccessDenied on DeleteVpc",
        "eipalloc-12345678 eipassoc-12345678 DisassociateAddress InternalError",
        "eipalloc-87654321 eipassoc-12345678 DisassociateAddress UnauthorizedOperation",
        "eipalloc-12345678 eipassoc-87654321 DisassociateAddress UnauthorizedOperation",
        "deleting EC2 EIP (eipalloc-87654321): disassociating EC2 EIP (eipassoc-12345678): DisassociateAddress UnauthorizedOperation",
        "disassociating EC2 EIP (eipassoc-87654321): DisassociateAddress UnauthorizedOperation",
        "eipalloc-12345678 eipassoc-12345678 DisassociateAddress\nAccessDenied on a different resource",
    ] {
        assert!(!check_stale(&Api::default(), &deployment, &checkpoint, &failure(text)).unwrap(), "{text}");
    }
}

#[test]
fn checkpoint_ambiguity_and_ownership_never_trigger_a_refresh() {
    let deployment = deployment();
    let original = stale_checkpoint(&deployment);
    for mutation in 0..8 {
        let mut checkpoint = original.clone();
        match mutation {
            0 => checkpoint["deployment"]["pending_operations"] = json!([{}]),
            1 => {
                let duplicate = checkpoint["deployment"]["resources"][0].clone();
                checkpoint["deployment"]["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            2 => checkpoint["deployment"]["resources"][0]["external"] = json!(true),
            3 => {
                checkpoint["deployment"]["resources"][0]["inputs"]["tags"]["zdn:network-id"] =
                    json!(Uuid::new_v4())
            }
            4 => checkpoint["deployment"]["resources"][0]["outputs"]["tags"] = json!({}),
            5 => {
                checkpoint["deployment"]["resources"][0]["outputs"]["allocationId"] =
                    json!("eipalloc-87654321")
            }
            6 => checkpoint["deployment"]["resources"][0]["urn"] = json!("foreign"),
            _ => checkpoint["deployment"]["resources"]
                .as_array_mut()
                .unwrap()
                .push(resource(&deployment, "natGateway", "nat-12345678")),
        }
        assert!(
            !check_stale(&Api::default(), &deployment, &checkpoint, &stale_failure())
                .unwrap_or(false),
            "mutation {mutation}"
        );
    }
}

#[test]
fn aws_address_identity_ownership_and_absent_association_are_required() {
    let deployment = deployment();
    let checkpoint = stale_checkpoint(&deployment);
    for mutation in 0..8 {
        let mut observed = observed_address(&deployment);
        match mutation {
            0 => observed["Addresses"][0]["AssociationId"] = json!("eipassoc-12345678"),
            1 => observed["Addresses"][0]["NetworkInterfaceId"] = json!("eni-12345678"),
            2 => observed["Addresses"][0]["AllocationId"] = json!("eipalloc-87654321"),
            3 => observed["Addresses"][0]["Tags"] = json!([]),
            4 => observed["Addresses"][0]["Domain"] = json!("standard"),
            5 => observed["Addresses"] = json!([]),
            6 => {
                let duplicate = observed["Addresses"][0].clone();
                observed["Addresses"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            _ => {
                let duplicate = observed["Addresses"][0]["Tags"][0].clone();
                observed["Addresses"][0]["Tags"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
        }
        let api = Api(RefCell::new([("describe-addresses", observed)].into()));
        assert!(!check_stale(&api, &deployment, &checkpoint, &stale_failure()).unwrap());
        assert!(api.0.borrow().is_empty());
    }
    let api = Api(RefCell::new(
        [
            ("describe-addresses", observed_address(&deployment)),
            (
                "describe-nat-gateways",
                json!({"NatGateways":[{"State":"deleting"}]}),
            ),
        ]
        .into(),
    ));
    assert!(!check_stale(&api, &deployment, &checkpoint, &stale_failure()).unwrap());
}

#[test]
fn refresh_must_clear_stale_values_before_destroy_retries() {
    let deployment = deployment();
    let before = stale_checkpoint(&deployment);
    assert!(confirm_address_refreshed(&deployment, &before, &before).is_err());
    let mut after = before.clone();
    after["deployment"]["resources"][0]["outputs"]["associationId"] = json!("");
    after["deployment"]["resources"][0]["outputs"]["networkInterface"] = json!("");
    confirm_address_refreshed(&deployment, &before, &after).unwrap();
    after["deployment"]["resources"][0]["id"] = json!("eipalloc-87654321");
    assert!(confirm_address_refreshed(&deployment, &before, &after).is_err());
    after["deployment"]["resources"] = json!([]);
    confirm_address_refreshed(&deployment, &before, &after).unwrap();
}

fn disk(deployment: &Deployment) -> Value {
    let definition =
        serde_json::to_value(&deployment.render().unwrap().resources["chainDisk"]).unwrap();
    let properties = &definition["properties"];
    let tags = properties["tags"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| json!({"Key":key,"Value":value}))
        .collect::<Vec<_>>();
    json!({"VolumeId":"vol-12345678","State":"available","Attachments":[],
        "AvailabilityZone":properties["availabilityZone"],"Encrypted":true,"Size":properties["size"],"VolumeType":"gp3","Tags":tags})
}

#[test]
fn partial_apply_disk_identity_survives_destroy_and_cannot_be_inferred_from_tags() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment();
    let disk = disk(&deployment);
    assert!(!owned_recorded_volume(&disk, &deployment, &BTreeMap::new()).unwrap());
    save_volume_identities(
        directory.path(),
        &deployment,
        &checkpoint(resource(&deployment, "chainDisk", "vol-12345678")),
    )
    .unwrap();
    let saved = load_volume_identities(directory.path(), &deployment).unwrap();
    assert!(owned_recorded_volume(&disk, &deployment, &saved).unwrap());
    save_volume_identities(
        directory.path(),
        &deployment,
        &json!({"deployment":{"resources":[]}}),
    )
    .unwrap();
    assert_eq!(
        load_volume_identities(directory.path(), &deployment).unwrap(),
        saved
    );
    let mut forged = disk.clone();
    forged["VolumeId"] = json!("vol-87654321");
    assert!(!owned_recorded_volume(&forged, &deployment, &saved).unwrap());
    forged = disk.clone();
    forged["Tags"] = json!([]);
    assert!(!owned_recorded_volume(&forged, &deployment, &saved).unwrap());
    forged = disk;
    forged["Encrypted"] = json!(false);
    assert!(owned_recorded_volume(&forged, &deployment, &saved).is_err());
    assert!(load_volume_identities(directory.path(), &self::deployment()).is_err());
}

#[test]
fn volume_receipt_rejects_ambiguous_or_unowned_checkpoint_resources_and_retargeting() {
    let deployment = deployment();
    for mutation in 0..8 {
        let directory = tempfile::tempdir().unwrap();
        let mut checkpoint = checkpoint(resource(&deployment, "chainDisk", "vol-12345678"));
        match mutation {
            0 => checkpoint["deployment"]["pending_operations"] = json!([{}]),
            1 => checkpoint["deployment"]["resources"][0]["external"] = json!(true),
            2 => checkpoint["deployment"]["resources"][0]["retainOnDelete"] = json!(false),
            3 => checkpoint["deployment"]["resources"][0]["outputs"]["encrypted"] = json!(false),
            4 => checkpoint["deployment"]["resources"][0]["inputs"]["tags"] = json!({}),
            5 => checkpoint["deployment"]["resources"][0]["outputs"]["tags"] = json!({}),
            6 => checkpoint["deployment"]["resources"][0]["id"] = json!("not-a-volume"),
            _ => {
                let duplicate = checkpoint["deployment"]["resources"][0].clone();
                checkpoint["deployment"]["resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
        }
        assert!(
            save_volume_identities(directory.path(), &deployment, &checkpoint).is_err(),
            "mutation {mutation}"
        );
        assert!(!directory.path().join(VOLUME_RECEIPT).exists());
    }
    let directory = tempfile::tempdir().unwrap();
    save_volume_identities(
        directory.path(),
        &deployment,
        &checkpoint(resource(&deployment, "chainDisk", "vol-12345678")),
    )
    .unwrap();
    assert!(save_volume_identities(
        directory.path(),
        &deployment,
        &checkpoint(resource(&deployment, "chainDisk", "vol-87654321"))
    )
    .is_err());
}
