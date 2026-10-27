#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;
#[path = "support/iam.rs"]
mod iam;
use iam::{permitted, strings};

use eyre::Result;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};
use uuid::Uuid;
use zdn::{
    access::*,
    aws::*,
    config::Size,
    credentials::{self, CredentialRequest},
    foundation::Deployment,
    infra::FoundationSpec,
};

fn team() -> TeamDefinition {
    serde_json::from_value(json!({
        "apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
        "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-test-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap()
}
fn request() -> AccessRequest {
    AccessRequest {team:team(),administrator:AwsSelection {profile:"administrator".into(),account_id:"123456789012".into(),region:"us-east-1".into()},trusted_principals:vec!["arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_Developer_abc123".into(),"arn:aws:iam::123456789012:user/developer".into()],existing:None}
}

#[test]
fn versioned_contract_preserves_v1_and_requires_complete_v2() {
    let legacy = team();
    legacy.validate().unwrap();
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("deployment")
        .is_none());
    let newer = request().completed_team().unwrap();
    assert_eq!(newer.api_version, TEAM_ROLE_API_VERSION);
    assert_eq!(newer.revision, 2);
    let roundtrip: TeamDefinition =
        serde_yaml::from_str(&serde_yaml::to_string(&newer).unwrap()).unwrap();
    assert_eq!(newer, roundtrip);
    for invalid in [
        TeamDefinition {
            api_version: TEAM_API_VERSION.into(),
            ..newer.clone()
        },
        TeamDefinition {
            deployment: None,
            ..newer.clone()
        },
        TeamDefinition {
            api_version: "zdn-team/v999".into(),
            ..newer.clone()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    let mut unknown = serde_json::to_value(newer).unwrap();
    unknown["deployment"]["accessKeyId"] = json!("never-supported");
    assert!(serde_json::from_value::<TeamDefinition>(unknown).is_err());
}

#[test]
fn rejects_ambiguous_foreign_and_self_trust_before_render() {
    for principal in [
        "*",
        "arn:aws:iam::123456789012:root",
        "arn:aws:iam::999999999999:user/developer",
        "arn:aws:sts::123456789012:assumed-role/developer/session",
        "arn:aws:iam::123456789012:role/*",
        "arn:aws:iam::123456789012:user/../developer",
    ] {
        let mut req = request();
        req.trusted_principals = vec![principal.into()];
        assert!(req.render().is_err(), "accepted {principal}");
    }
    let mut req = request();
    req.trusted_principals = vec![req.access().role_arn];
    assert!(req.validate().is_err());
    let mut req = request();
    req.trusted_principals
        .push(req.trusted_principals[0].clone());
    assert!(req.validate().is_err());
    for prefix in ["zdn-admin", "zdn-admin/v1/other"] {
        let mut req = request();
        req.team.state.backend = format!("s3://zdn-test-state/{prefix}");
        assert!(req.render().is_err());
    }
}

#[test]
fn generated_iam_names_policies_and_trust_are_deterministic() {
    let req = request();
    let mut reordered = req.clone();
    reordered.trusted_principals.reverse();
    assert_eq!(req.render().unwrap(), reordered.render().unwrap());
    let first = req.render().unwrap();
    assert_eq!(
        first["resources"]["provider"]["properties"]["profile"],
        "administrator"
    );
    for (name, resource) in first["resources"].as_object().unwrap() {
        if name == "provider" {
            continue;
        }
        assert_eq!(resource["options"]["provider"], "${provider}");
        assert_eq!(resource["options"]["protect"], true);
        if let Some(document) = resource["properties"]["policy"].as_str() {
            assert!(document.len() <= 6144, "{name}: {}", document.len());
        }
    }
    let mut other = req.clone();
    other.team.bootstrap_id = Uuid::new_v4();
    assert_ne!(req.access().role_arn, other.access().role_arn);
    assert_ne!(
        req.access().runtime_boundary_arn,
        other.access().runtime_boundary_arn
    );
    assert_ne!(
        admin_backend(&req.team).unwrap(),
        admin_backend(&other.team).unwrap()
    );
    assert_eq!(
        req.caller_policy().unwrap()["Statement"][0]["Resource"],
        req.access().role_arn
    );
}

#[test]
fn managed_policies_have_unique_names_and_matching_boundary_references() {
    let req = request();
    let program = req.render().unwrap();
    let resources = program["resources"].as_object().unwrap();
    let mut policy_names = std::collections::BTreeSet::new();
    for (key, resource) in resources {
        if resource["type"] == "aws:iam:Policy" {
            let name = resource["properties"]["name"].as_str().unwrap();
            assert!(
                policy_names.insert(name),
                "duplicate IAM policy name: {key}"
            );
        }
    }
    assert_eq!(policy_names.len(), 9);

    // Keep the management policy name stable so an interrupted bootstrap can
    // reuse the policy it already created. The separate boundary gets its own
    // name; the boundary's document never grants IAM management permissions.
    assert_eq!(
        resources["runtimePolicy"]["properties"]["name"],
        "zdn-a81c4e9b46124e0da3fac4ab68a04153-runtime"
    );
    let boundary = &resources["runtimeBoundary"]["properties"];
    assert_eq!(
        boundary["name"],
        "zdn-a81c4e9b46124e0da3fac4ab68a04153-runtime-boundary"
    );
    assert_eq!(
        serde_json::from_str::<Value>(boundary["policy"].as_str().unwrap()).unwrap(),
        runtime_boundary_for_team(&req.team).unwrap()
    );
    let arn = |kind: &str, properties: &Value| {
        format!(
            "arn:aws:iam::{}:{kind}{}{}",
            req.team.aws.account_id,
            properties["path"].as_str().unwrap(),
            properties["name"].as_str().unwrap()
        )
    };
    let access = req.access();
    assert_eq!(arn("policy", boundary), access.runtime_boundary_arn);
    assert_eq!(
        arn("role", &resources["deploymentRole"]["properties"]),
        access.role_arn
    );
    assert_eq!(
        program["outputs"],
        json!({"roleArn":"${deploymentRole.arn}","runtimeBoundaryArn":"${runtimeBoundary.arn}"})
    );
    let runtime: Value = serde_json::from_str(
        resources["runtimePolicy"]["properties"]["policy"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let create_role = runtime["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .find(|statement| strings(&statement["Action"]).contains(&"iam:CreateRole"))
        .unwrap();
    assert_eq!(
        create_role["Condition"]["StringEquals"]["iam:PermissionsBoundary"],
        access.runtime_boundary_arn
    );
    assert_eq!(req.completed_team().unwrap().deployment, Some(access));
}

#[test]
fn version_deletion_is_limited_to_team_artifacts_and_never_granted_to_hosts() {
    let req = request();
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    let bucket = format!("arn:aws:s3:::{}", req.team.backend_bucket().unwrap());
    let metadata = req.team.metadata_prefix();
    let artifacts = format!("{bucket}/{metadata}/artifacts");
    for resource in [
        format!("{artifacts}/deployment-a/manifest.json"),
        format!("{artifacts}/deployment-b/helper"),
    ] {
        assert!(permitted(
            &policies,
            "s3:DeleteObjectVersion",
            &resource,
            &json!({})
        ));
        for runtime in [
            runtime_data_policy(&req.team).unwrap(),
            runtime_boundary_for_team(&req.team).unwrap(),
        ] {
            assert!(!permitted(
                &[runtime],
                "s3:DeleteObjectVersion",
                &resource,
                &json!({})
            ));
        }
    }
    for resource in [
        format!(
            "{bucket}/{}/.pulumi/stacks/devnet.json",
            req.team.backend_prefix().unwrap()
        ),
        format!("{bucket}/{metadata}/leases/devnet.json"),
        format!("{bucket}/{metadata}/reservations/devnet.json"),
        format!("{bucket}/{metadata}/operations/devnet.json"),
        format!("{bucket}/zdn-admin/state.json"),
        format!("{artifacts}-other/manifest.json"),
        artifacts.clone(),
        format!("{bucket}/zdn-meta/foreign-team/artifacts/manifest.json"),
        format!("arn:aws:s3:::foreign-bucket/{metadata}/artifacts/manifest.json"),
    ] {
        assert!(
            !permitted(&policies, "s3:DeleteObjectVersion", &resource, &json!({})),
            "{resource}"
        );
    }
}

#[test]
fn deployment_policy_denies_self_escalation_and_admin_state() {
    let req = request();
    let access = req.access();
    let policies: Vec<_> = deployment_policies(&req.team, &access)
        .unwrap()
        .into_values()
        .collect();
    let runtime = format!(
        "arn:aws:iam::123456789012:role{}zdn-example-host-role",
        runtime_path(&req.team)
    );
    let good = json!({"aws:RequestTag/zdn:team-id":"test-team","aws:RequestTag/zdn:managed-by":"zdn","aws:RequestTag/zdn:bootstrap":req.team.bootstrap_id.to_string(),"iam:PermissionsBoundary":access.runtime_boundary_arn});
    assert!(permitted(&policies, "iam:CreateRole", &runtime, &good));
    for key in [
        "aws:RequestTag/zdn:team-id",
        "aws:RequestTag/zdn:bootstrap",
        "iam:PermissionsBoundary",
    ] {
        let mut bad = good.clone();
        bad[key] = json!("wrong");
        assert!(
            !permitted(&policies, "iam:CreateRole", &runtime, &bad),
            "{key}"
        );
    }
    assert!(!permitted(
        &policies,
        "iam:CreateRole",
        "arn:aws:iam::123456789012:role/foreign-host-role",
        &good
    ));
    for operation in [
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DeleteRole",
    ] {
        assert!(!permitted(
            &policies,
            operation,
            &access.role_arn,
            &json!({})
        ));
    }
    for operation in [
        "iam:PutRolePermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
    ] {
        assert!(!permitted(&policies, operation, &runtime, &good));
    }
    assert!(permitted(
        &policies,
        "iam:AttachRolePolicy",
        &runtime,
        &json!({"iam:PolicyARN":SSM_CORE_POLICY})
    ));
    assert!(!permitted(
        &policies,
        "iam:AttachRolePolicy",
        &runtime,
        &json!({"iam:PolicyARN":"arn:aws:iam::aws:policy/AdministratorAccess"})
    ));
    assert!(permitted(
        &policies,
        "iam:PassRole",
        &runtime,
        &json!({"iam:PassedToService":"ec2.amazonaws.com"})
    ));
    assert!(!permitted(
        &policies,
        "iam:PassRole",
        &runtime,
        &json!({"iam:PassedToService":"lambda.amazonaws.com"})
    ));
    for action in ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] {
        assert!(permitted(
            &policies,
            action,
            "arn:aws:s3:::zdn-test-state/pulumi/zdn/checkpoint.json",
            &json!({})
        ));
        for denied in [
            "arn:aws:s3:::zdn-test-state/zdn-admin/v1/checkpoint.json",
            "arn:aws:s3:::foreign-state/pulumi/zdn/checkpoint.json",
            "arn:aws:s3:::zdn-test-state/pulumi/other/checkpoint.json",
        ] {
            assert!(
                !permitted(&policies, action, denied, &json!({})),
                "{action}: {denied}"
            );
        }
    }
    assert!(permitted(
        &policies,
        "kms:Decrypt",
        &req.team.state.kms_key_arn,
        &json!({})
    ));
    assert!(!permitted(
        &policies,
        "kms:CreateGrant",
        &req.team.state.kms_key_arn,
        &json!({})
    ));
}

#[test]
fn deleted_host_iam_names_can_be_read_without_widening_mutations_or_inventory() {
    let req = request();
    let access = req.access();
    let policies: Vec<_> = deployment_policies(&req.team, &access)
        .unwrap()
        .into_values()
        .collect();
    let network = "ca89949b-1ac5-4573-84db-b0ab70d6c7a1";
    let context = json!({
        "aws:RequestTag/zdn:team-id":req.team.team_id,
        "aws:RequestTag/zdn:managed-by":"zdn",
        "aws:RequestTag/zdn:bootstrap":req.team.bootstrap_id.to_string(),
        "iam:PermissionsBoundary":access.runtime_boundary_arn,
        "iam:PassedToService":"ec2.amazonaws.com",
        "iam:PolicyARN":SSM_CORE_POLICY
    });
    for (kind, purpose, read) in [
        ("role", "host-role", "iam:GetRole"),
        ("instance-profile", "host-profile", "iam:GetInstanceProfile"),
    ] {
        let name = format!("zdn-{network}-{purpose}");
        let pathless = format!("arn:aws:iam::123456789012:{kind}/{name}");
        let scoped = format!(
            "arn:aws:iam::123456789012:{kind}{}{name}",
            runtime_path(&req.team)
        );
        // IAM resolves an existing name to its actual path, but authorizes a
        // missing name at the default path before returning NoSuchEntity.
        assert!(permitted(&policies, read, &scoped, &json!({})));
        assert!(permitted(&policies, read, &pathless, &json!({})));
        for denied in [
            format!("arn:aws:iam::999999999999:{kind}/{name}"),
            format!("arn:aws:iam::123456789012:{kind}/unrelated-{purpose}"),
            format!("arn:aws:iam::123456789012:{kind}/zdn-{network}-unrelated"),
            format!("arn:aws:iam::123456789012:{kind}/foreign/{name}"),
        ] {
            assert!(!permitted(&policies, read, &denied, &json!({})), "{denied}");
        }
        // Supply every normal mutation condition so rejection is due to the
        // resource scope, rather than a missing ownership tag or service key.
        for action in [
            "iam:CreateRole",
            "iam:DeleteRole",
            "iam:TagRole",
            "iam:AttachRolePolicy",
            "iam:DetachRolePolicy",
            "iam:PassRole",
            "iam:CreateInstanceProfile",
            "iam:DeleteInstanceProfile",
            "iam:TagInstanceProfile",
            "iam:AddRoleToInstanceProfile",
            "iam:RemoveRoleFromInstanceProfile",
            "iam:GetRolePolicy",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:ListInstanceProfileTags",
        ] {
            assert!(
                !permitted(&policies, action, &pathless, &context),
                "unexpected {action} on {pathless}"
            );
        }
    }
    for action in ["iam:ListRoles", "iam:ListInstanceProfiles"] {
        assert!(!permitted(&policies, action, "*", &json!({})), "{action}");
    }
}

#[test]
fn provider_eip_and_vpc_reads_are_allowed_only_in_the_selected_region() {
    let req = request();
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    // AWS 7.50.0's pinned provider reads the EIP PTR attribute after allocation
    // and the VPC's default NACL during refresh, even though neither is managed
    // as a separate zdn resource. These describe APIs use Resource "*" and do
    // not supply ownership-tag context.
    // https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/ec2/ec2_eip.go#L242
    // https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/ec2/vpc_.go#L299
    let region = json!({"aws:RequestedRegion":"us-east-1"});
    for action in ["ec2:DescribeAddressesAttribute", "ec2:DescribeNetworkAcls"] {
        assert!(permitted(&policies, action, "*", &region), "{action}");
        assert!(!permitted(&policies, action, "*", &json!({})), "{action}");
        assert!(
            !permitted(
                &policies,
                action,
                "*",
                &json!({"aws:RequestedRegion":"us-west-2"})
            ),
            "{action}"
        );
    }
    for unrelated in [
        "ec2:DescribeAccountAttributes",
        "ec2:ModifyAddressAttribute",
        "ec2:ReplaceNetworkAclEntry",
    ] {
        assert!(
            !permitted(&policies, unrelated, "*", &region),
            "unexpected permission: {unrelated}"
        );
    }
}

#[test]
fn ec2_mutations_require_ownership_and_cannot_retag_foreign_resources() {
    let req = request();
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    let context = json!({"aws:ResourceTag/zdn:team-id":"test-team","aws:ResourceTag/zdn:managed-by":"zdn","aws:ResourceTag/zdn:bootstrap":req.team.bootstrap_id.to_string(),"aws:TagKeys":["Name"]});
    for action in [
        "ec2:TerminateInstances",
        "ec2:DeleteVolume",
        "ec2:DeleteVpc",
        "ec2:CreateTags",
    ] {
        let resource = "arn:aws:ec2:us-east-1:123456789012:instance/i-fixture";
        assert!(permitted(&policies, action, resource, &context), "{action}");
        assert!(
            !permitted(&policies, action, resource, &json!({})),
            "{action}"
        );
        let mut foreign = context.clone();
        foreign["aws:ResourceTag/zdn:bootstrap"] = json!(Uuid::new_v4());
        assert!(!permitted(&policies, action, resource, &foreign));
        assert!(!permitted(
            &policies,
            action,
            "arn:aws:ec2:us-west-2:123456789012:instance/i-fixture",
            &context
        ));
    }
    for action in ["ec2:CreateTags", "ec2:DeleteTags"] {
        let mut change = context.clone();
        change["aws:TagKeys"] = json!(["zdn:bootstrap"]);
        assert!(!permitted(
            &policies,
            action,
            "arn:aws:ec2:us-east-1:123456789012:volume/vol-fixture",
            &change
        ));
    }
}

#[test]
fn legacy_boundary_contract_preserves_runtime_permissions_and_host_selection() {
    let mut req = request();
    let modern = req.access();
    let mut team = req.completed_team().unwrap();
    let legacy = team.deployment.as_mut().unwrap();
    legacy.runtime_boundary_arn = legacy
        .runtime_boundary_arn
        .strip_suffix("-boundary")
        .unwrap()
        .into();
    let legacy = legacy.clone();
    team.validate().unwrap();
    req.team = team.clone();
    let policies: Vec<_> = deployment_policies(&team, &legacy)
        .unwrap()
        .into_values()
        .collect();
    let runtime = format!(
        "arn:aws:iam::123456789012:role{}zdn-example-host-role",
        runtime_path(&team)
    );
    let mut context = json!({"aws:RequestTag/zdn:team-id":"test-team","aws:RequestTag/zdn:managed-by":"zdn",
        "aws:RequestTag/zdn:bootstrap":team.bootstrap_id.to_string(),"iam:PermissionsBoundary":legacy.runtime_boundary_arn});
    assert!(permitted(&policies, "iam:CreateRole", &runtime, &context));
    context["iam:PermissionsBoundary"] = json!(modern.runtime_boundary_arn);
    assert!(!permitted(&policies, "iam:CreateRole", &runtime, &context));
    for action in [
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
    ] {
        assert!(!permitted(
            &policies,
            action,
            &legacy.runtime_boundary_arn,
            &context
        ));
    }
    let deployment = Deployment::new(
        FoundationSpec {
            scope: team.scope(),
            network_id: Uuid::new_v4(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Small,
            retain_chain_disk: true,
        },
        team.clone(),
    )
    .unwrap();
    let program = serde_json::to_value(deployment.render().unwrap()).unwrap();
    assert_eq!(
        program["resources"]["hostRole"]["properties"]["permissionsBoundary"],
        legacy.runtime_boundary_arn
    );
    let admin = req.render().unwrap();
    assert!(admin["resources"]["runtimePolicy"]["properties"]["name"]
        .as_str()
        .unwrap()
        .ends_with("-runtime-management"));
    assert_eq!(
        serde_json::from_str::<Value>(
            admin["resources"]["runtimeBoundary"]["properties"]["policy"]
                .as_str()
                .unwrap()
        )
        .unwrap(),
        runtime_boundary_for_team(&req.team).unwrap()
    );
    for suffix in ["-management", "-foreign"] {
        let mut foreign = team.clone();
        foreign
            .deployment
            .as_mut()
            .unwrap()
            .runtime_boundary_arn
            .push_str(suffix);
        assert!(foreign.validate().is_err());
    }
}

#[test]
fn runtime_boundary_and_foundation_render_apply_team_constraints() {
    let req = request();
    let team = req.completed_team().unwrap();
    let boundary = vec![runtime_boundary()];
    for action in [
        "s3:GetObject",
        "kms:Decrypt",
        "iam:PassRole",
        "ssm:GetParameter",
    ] {
        assert!(!permitted(&boundary, action, "*", &json!({})));
    }
    assert!(permitted(
        &boundary,
        "ssmmessages:OpenDataChannel",
        "*",
        &json!({})
    ));
    let deployment = Deployment::new(
        FoundationSpec {
            scope: team.scope(),
            network_id: Uuid::new_v4(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Small,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap();
    let program = serde_json::to_value(deployment.render().unwrap()).unwrap();
    let role = &program["resources"]["hostRole"]["properties"];
    assert_eq!(
        role["permissionsBoundary"],
        req.access().runtime_boundary_arn
    );
    assert_eq!(role["path"], runtime_path(&req.team));
    assert!(program["resources"].get("defaultSecurityGroup").is_none());
    assert_eq!(
        program["resources"]["host"]["properties"]["vpcSecurityGroupIds"],
        json!(["${hostSecurityGroup.id}"])
    );
    assert_eq!(
        program["resources"]["provider"]["properties"]["defaultTags"]["tags"]["zdn:bootstrap"],
        req.team.bootstrap_id.to_string()
    );
    assert!(
        program["resources"]["host"]["properties"]["rootBlockDevice"]["tags"]
            .get("zdn:bootstrap")
            .is_none()
    );
    assert_eq!(
        program["resources"]["provider"]["properties"]["profile"],
        "developer"
    );
}

#[test]
fn runtime_data_reads_only_team_artifacts_and_has_no_state_or_write_access() {
    let team = request().completed_team().unwrap();
    let artifact = "arn:aws:s3:::zdn-test-state/zdn-meta/v1/test-team/artifacts/devnet/digest/zdn";
    for policy in [
        runtime_data_policy(&team).unwrap(),
        runtime_boundary_for_team(&team).unwrap(),
    ] {
        let documents = [policy];
        assert!(permitted(&documents, "s3:GetObject", artifact, &json!({})));
        for resource in [
            "arn:aws:s3:::zdn-test-state/pulumi/zdn/checkpoint.json",
            "arn:aws:s3:::zdn-test-state/zdn-admin/v1/checkpoint.json",
            "arn:aws:s3:::zdn-test-state/zdn-meta/v1/test-team/leases/devnet.json",
            "arn:aws:s3:::zdn-test-state/zdn-meta/v1/test-team/artifacts-unrelated/devnet/zdn",
            "arn:aws:s3:::zdn-test-state/zdn-meta/v1/another-team/artifacts/devnet/zdn",
            "arn:aws:s3:::foreign-bucket/zdn-meta/v1/test-team/artifacts/devnet/zdn",
        ] {
            assert!(
                !permitted(&documents, "s3:GetObject", resource, &json!({})),
                "{resource}"
            );
        }
        for action in [
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:PutObjectTagging",
            "s3:GetObjectVersion",
            "s3:ListBucket",
            "s3:PutBucketPolicy",
        ] {
            assert!(
                !permitted(&documents, action, artifact, &json!({})),
                "{action}"
            );
            assert!(
                !permitted(
                    &documents,
                    action,
                    "arn:aws:s3:::zdn-test-state",
                    &json!({})
                ),
                "{action}"
            );
        }
        for action in [
            "iam:PassRole",
            "iam:AttachRolePolicy",
            "iam:CreatePolicyVersion",
            "ssm:GetParameter",
        ] {
            assert!(!permitted(&documents, action, "*", &json!({})), "{action}");
        }
    }
}

#[test]
fn runtime_kms_decryption_requires_s3_in_own_account_and_artifact_encryption_context() {
    let team = request().completed_team().unwrap();
    let good = json!({
        "kms:ViaService":"s3.us-east-1.amazonaws.com", "kms:CallerAccount":"123456789012",
        "kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::zdn-test-state/zdn-meta/v1/test-team/artifacts/devnet/digest/zdn"
    });
    for policy in [
        runtime_data_policy(&team).unwrap(),
        runtime_boundary_for_team(&team).unwrap(),
    ] {
        let documents = [policy];
        assert!(permitted(
            &documents,
            "kms:Decrypt",
            &team.state.kms_key_arn,
            &good
        ));
        // S3 Bucket Keys use the bucket ARN, not the individual object ARN.
        // GetObject remains constrained to the artifact prefix by the S3 policy.
        let mut bucket_keys = good.clone();
        bucket_keys["kms:EncryptionContext:aws:s3:arn"] = json!("arn:aws:s3:::zdn-test-state");
        assert!(permitted(
            &documents,
            "kms:Decrypt",
            &team.state.kms_key_arn,
            &bucket_keys
        ));
        for (key, value) in [
            ("kms:ViaService", "s3.us-west-2.amazonaws.com"),
            ("kms:ViaService", "ec2.us-east-1.amazonaws.com"),
            ("kms:CallerAccount", "999999999999"),
            (
                "kms:EncryptionContext:aws:s3:arn",
                "arn:aws:s3:::foreign-bucket",
            ),
            (
                "kms:EncryptionContext:aws:s3:arn",
                "arn:aws:s3:::zdn-test-state/pulumi/zdn/checkpoint.json",
            ),
            (
                "kms:EncryptionContext:aws:s3:arn",
                "arn:aws:s3:::zdn-test-state/zdn-meta/v1/test-team/leases/devnet.json",
            ),
            (
                "kms:EncryptionContext:aws:s3:arn",
                "arn:aws:s3:::zdn-test-state/zdn-meta/v1/another-team/artifacts/devnet/zdn",
            ),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(
                !permitted(&documents, "kms:Decrypt", &team.state.kms_key_arn, &bad),
                "{key}: {value}"
            );
        }
        for key in good.as_object().unwrap().keys() {
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                !permitted(&documents, "kms:Decrypt", &team.state.kms_key_arn, &missing),
                "missing {key}"
            );
        }
        assert!(!permitted(
            &documents,
            "kms:Decrypt",
            "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000099",
            &good
        ));
        for action in [
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:CreateGrant",
            "kms:PutKeyPolicy",
        ] {
            assert!(
                !permitted(&documents, action, &team.state.kms_key_arn, &good),
                "{action}"
            );
        }
    }
}

#[test]
fn runtime_ecr_reads_are_limited_to_team_repositories_in_the_selected_region() {
    let team = request().completed_team().unwrap();
    let repository = "arn:aws:ecr:us-east-1:123456789012:repository/zdn/test-team/node";
    let region = json!({"aws:RequestedRegion":"us-east-1"});
    for policy in [
        runtime_data_policy(&team).unwrap(),
        runtime_boundary_for_team(&team).unwrap(),
    ] {
        let documents = [policy];
        for action in [
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchCheckLayerAvailability",
        ] {
            assert!(
                permitted(&documents, action, repository, &json!({})),
                "{action}"
            );
            for foreign in [
                "arn:aws:ecr:us-east-1:123456789012:repository/zdn/another-team/node",
                "arn:aws:ecr:us-east-1:123456789012:repository/zdn/test-team-extra/node",
                "arn:aws:ecr:us-east-1:123456789012:repository/public/node",
                "arn:aws:ecr:us-west-2:123456789012:repository/zdn/test-team/node",
                "arn:aws:ecr:us-east-1:999999999999:repository/zdn/test-team/node",
            ] {
                assert!(
                    !permitted(&documents, action, foreign, &json!({})),
                    "{action}: {foreign}"
                );
            }
        }
        assert!(permitted(
            &documents,
            "ecr:GetAuthorizationToken",
            "*",
            &region
        ));
        for denied in [json!({}), json!({"aws:RequestedRegion":"us-west-2"})] {
            assert!(!permitted(
                &documents,
                "ecr:GetAuthorizationToken",
                "*",
                &denied
            ));
        }
        for action in [
            "ecr:PutImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload",
            "ecr:CreateRepository",
            "ecr:DeleteRepository",
            "ecr:SetRepositoryPolicy",
            "ecr:DescribeRepositories",
        ] {
            assert!(
                !permitted(&documents, action, repository, &region),
                "{action}"
            );
        }
    }
}

#[test]
fn data_policy_is_protected_and_attachable_only_to_owned_runtime_roles() {
    let req = request();
    let data_arn = runtime_data_policy_arn(&req.team);
    let program = req.render().unwrap();
    let resource = &program["resources"]["runtimeDataPolicy"];
    assert_eq!(resource["options"]["protect"], true);
    let properties = &resource["properties"];
    assert_eq!(
        format!(
            "arn:aws:iam::{}:policy{}{}",
            req.team.aws.account_id,
            properties["path"].as_str().unwrap(),
            properties["name"].as_str().unwrap()
        ),
        data_arn
    );
    assert_eq!(
        serde_json::from_str::<Value>(properties["policy"].as_str().unwrap()).unwrap(),
        runtime_data_policy(&req.team).unwrap()
    );
    let boundary = runtime_boundary_for_team(&req.team).unwrap();
    assert_eq!(boundary["Statement"][0], runtime_boundary()["Statement"][0]);
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    let role = format!(
        "arn:aws:iam::123456789012:role{}zdn-example-host-role",
        runtime_path(&req.team)
    );
    for action in ["iam:AttachRolePolicy", "iam:DetachRolePolicy"] {
        assert!(permitted(
            &policies,
            action,
            &role,
            &json!({"iam:PolicyARN":data_arn})
        ));
        assert!(!permitted(
            &policies,
            action,
            "arn:aws:iam::123456789012:role/foreign",
            &json!({"iam:PolicyARN":data_arn})
        ));
        let mut another = req.team.clone();
        another.bootstrap_id = Uuid::new_v4();
        assert!(!permitted(
            &policies,
            action,
            &role,
            &json!({"iam:PolicyARN":runtime_data_policy_arn(&another)})
        ));
    }
    for action in [
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:DeletePolicy",
        "iam:TagPolicy",
    ] {
        assert!(
            !permitted(&policies, action, &data_arn, &json!({})),
            "{action}"
        );
    }
}

#[test]
fn deployment_image_preflight_can_only_read_the_selected_team_repository() {
    let req = request();
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    let repository = "arn:aws:ecr:us-east-1:123456789012:repository/zdn/test-team/node";
    assert!(permitted(
        &policies,
        "ecr:BatchGetImage",
        repository,
        &json!({})
    ));
    for foreign in [
        "arn:aws:ecr:us-east-1:123456789012:repository/zdn/another-team/node",
        "arn:aws:ecr:us-east-1:123456789012:repository/zdn/test-team-extra/node",
        "arn:aws:ecr:us-west-2:123456789012:repository/zdn/test-team/node",
        "arn:aws:ecr:us-east-1:999999999999:repository/zdn/test-team/node",
    ] {
        assert!(
            !permitted(&policies, "ecr:BatchGetImage", foreign, &json!({})),
            "{foreign}"
        );
    }
    for action in [
        "ecr:GetAuthorizationToken",
        "ecr:PutImage",
        "ecr:CreateRepository",
        "ecr:SetRepositoryPolicy",
        "ecr:DeleteRepository",
    ] {
        assert!(
            !permitted(&policies, action, repository, &json!({})),
            "{action}"
        );
    }
}

#[test]
fn runtime_policy_preflight_reads_survive_denies_without_allowing_admin_policy_mutations() {
    let req = request();
    let access = req.access();
    let policies: Vec<_> = deployment_policies(&req.team, &access)
        .unwrap()
        .into_values()
        .collect();
    let data = runtime_data_policy_arn(&req.team);
    let mut foreign_team = req.team.clone();
    foreign_team.bootstrap_id = Uuid::new_v4();
    for action in ["iam:GetPolicy", "iam:GetPolicyVersion"] {
        for arn in [&access.runtime_boundary_arn, &data] {
            assert!(
                permitted(&policies, action, arn, &json!({})),
                "{action}: {arn}"
            );
        }
        for foreign in [
            runtime_data_policy_arn(&foreign_team),
            data.replace("-runtime-data", "-state"),
            access.role_arn.clone(),
        ] {
            assert!(
                !permitted(&policies, action, &foreign, &json!({})),
                "{action}: {foreign}"
            );
        }
    }
    // Include a deliberately broad additional grant: the explicit deny must
    // still protect the admin policies and the deployment role from mutation.
    let mut wide = policies;
    wide.push(json!({"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}));
    for action in [
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:DeletePolicy",
        "iam:TagPolicy",
        "iam:UntagPolicy",
        "iam:CreatePolicy",
        "iam:AttachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
    ] {
        for resource in [&access.runtime_boundary_arn, &data, &access.role_arn] {
            assert!(
                !permitted(&wide, action, resource, &json!({})),
                "{action}: {resource}"
            );
        }
    }
}

fn credential_request() -> CredentialRequest {
    CredentialRequest {
        version: 1,
        source: AwsSelection {
            profile: "developer".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        role_arn: request().access().role_arn,
        source_config: "/source/aws/config".into(),
        source_credentials: "/source/aws/credentials".into(),
    }
}
struct Sts {
    calls: Mutex<Vec<String>>,
    wrong_role: bool,
    incomplete: bool,
}
impl AwsApi for Sts {
    fn call(&self, service: &str, operation: &str, input: Value, _: &[String]) -> Result<Value> {
        assert_eq!(service, "sts");
        self.calls.lock().unwrap().push(operation.into());
        if operation == "get-caller-identity" {
            return Ok(
                json!({"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/developer","UserId":"developer"}),
            );
        }
        assert_eq!(input["DurationSeconds"], 3600);
        assert_eq!(input["RoleArn"], credential_request().role_arn);
        let name = if self.wrong_role {
            "administrator"
        } else {
            input["RoleArn"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
        };
        let mut output = json!({"AssumedRoleUser":{"Arn":format!("arn:aws:sts::123456789012:assumed-role/{name}/zdn-deployment"),"AssumedRoleId":"role:session"},"Credentials":{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","SessionToken":"fixture-token","Expiration":"2099-01-01T00:00:00Z"}});
        if self.incomplete {
            output["Credentials"]["Expiration"] = Value::Null;
        }
        Ok(output)
    }
}

#[test]
fn refresh_issues_new_sessions_and_rejects_missing_expiration_and_wrong_roles() {
    let api = Sts {
        calls: Mutex::default(),
        wrong_role: false,
        incomplete: false,
    };
    for _ in 0..2 {
        let result = credentials::issue(&api, &credential_request()).unwrap();
        assert_eq!(result["Version"], 1);
        assert_eq!(result["AccountId"], "123456789012");
        assert_eq!(result["Expiration"], "2099-01-01T00:00:00Z");
    }
    assert_eq!(
        *api.calls.lock().unwrap(),
        [
            "get-caller-identity",
            "assume-role",
            "get-caller-identity",
            "assume-role"
        ]
    );
    for (wrong_role, incomplete) in [(true, false), (false, true)] {
        let error = credentials::issue(
            &Sts {
                calls: Mutex::default(),
                wrong_role,
                incomplete,
            },
            &credential_request(),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("fixture-secret"));
    }
}

#[test]
fn credential_files_contain_only_instructions_and_preserve_source_selection() {
    let dir = tempfile::tempdir().unwrap();
    let team = request().completed_team().unwrap();
    let environment = BTreeMap::from([
        ("HOME".into(), dir.path().to_str().unwrap().into()),
        ("AWS_CONFIG_FILE".into(), "/original/config".into()),
        (
            "AWS_SHARED_CREDENTIALS_FILE".into(),
            "/original/credentials".into(),
        ),
    ]);
    let files = credentials::prepare(
        &team,
        &credential_request().source,
        &dir.path().join("bridge"),
        &PathBuf::from("/Applications/zdn tools/zdn"),
        &environment,
    )
    .unwrap()
    .unwrap();
    let config = fs::read_to_string(&files.config).unwrap();
    assert!(config.contains("[profile developer]"));
    assert!(config.contains("/Applications/zdn\\ tools/zdn __credentials --request /"));
    assert!(fs::read(&files.empty_credentials).unwrap().is_empty());
    let saved: CredentialRequest =
        zdn::foundation::read_json(&files.config.with_file_name("request.json")).unwrap();
    assert_eq!(saved.source_config, PathBuf::from("/original/config"));
    assert_eq!(
        saved.source_credentials,
        PathBuf::from("/original/credentials")
    );
    let mut outer = environment.clone();
    credentials::apply_files(&mut outer, &files).unwrap();
    assert_eq!(outer["AWS_CONFIG_FILE"], files.config.to_str().unwrap());
    let restored = saved.source_environment(outer).unwrap();
    assert_eq!(restored["AWS_CONFIG_FILE"], "/original/config");
    assert_eq!(
        restored["AWS_SHARED_CREDENTIALS_FILE"],
        "/original/credentials"
    );
    for entry in fs::read_dir(files.config.parent().unwrap()).unwrap() {
        let text = fs::read_to_string(entry.unwrap().path()).unwrap();
        for secret in [
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "fixture-token",
        ] {
            assert!(!text.contains(secret));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&files.config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut injected = environment.clone();
    injected.insert("AWS_ACCESS_KEY_ID".into(), "ambient".into());
    assert!(credentials::prepare(
        &team,
        &credential_request().source,
        dir.path(),
        &PathBuf::from("/zdn"),
        &injected
    )
    .is_err());
    assert!(credentials::prepare(
        &team,
        &credential_request().source,
        dir.path(),
        &PathBuf::from("/bad$(exec)/zdn"),
        &environment
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn credential_command_preserves_paths_with_spaces_after_ini_parsing() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let environment = BTreeMap::from([("HOME".into(), dir.path().to_str().unwrap().into())]);
    let executable_directory = dir.path().join("executable directory");
    fs::create_dir(&executable_directory).unwrap();
    for name in ["zdn", "zdn with  spaces "] {
        let executable = executable_directory.join(name);
        executable::write(&executable, "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let files = credentials::prepare(
            &request().completed_team().unwrap(),
            &credential_request().source,
            &dir.path().join("state directory with spaces "),
            &executable,
            &environment,
        )
        .unwrap()
        .unwrap();
        let config = fs::read_to_string(&files.config).unwrap();
        let command = config
            .lines()
            .find_map(|line| line.strip_prefix("credential_process = "))
            .unwrap();
        // AWS CLI preserves the INI value. Go config v1.32.31's legacyStrconv
        // removes matching outer quotes before processcreds passes it to sh -c:
        // https://github.com/aws/aws-sdk-go-v2/blob/config/v1.32.31/config/internal/ini/strings.go
        let go_command = ['\'', '"']
            .into_iter()
            .find_map(|quote| command.strip_prefix(quote)?.strip_suffix(quote))
            .unwrap_or(command);
        for (parser, parsed) in [("unmodified INI", command), ("Go SDK INI", go_command)] {
            let output = Command::new("/bin/sh")
                .args(["-c", parsed])
                .env_clear()
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{parser}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let request_path = files.config.with_file_name("request.json");
            assert_eq!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .collect::<Vec<_>>(),
                vec![
                    executable.to_str().unwrap(),
                    "__credentials",
                    "--request",
                    request_path.to_str().unwrap(),
                ],
                "{parser}"
            );
        }
    }
}

#[test]
fn external_role_contract_does_not_render_owned_resources() {
    let mut req = request();
    req.existing = Some(DeploymentAccess {
        role_arn: "arn:aws:iam::123456789012:role/org/deployment".into(),
        management: RoleManagement::External,
        runtime_boundary_arn: "arn:aws:iam::123456789012:policy/org/runtime-boundary".into(),
    });
    let team = req.completed_team().unwrap();
    assert_eq!(
        team.deployment.unwrap().management,
        RoleManagement::External
    );
    assert!(req.render().is_err());
    req.existing.as_mut().unwrap().role_arn =
        "arn:aws:iam::999999999999:role/org/deployment".into();
    assert!(req.validate().is_err());
}

#[test]
fn expired_and_malformed_sts_sessions_are_rejected() {
    use credentials::validate_expiration;
    // 2024-02-29 00:00:00 UTC, independently recorded Unix timestamp.
    let now = 1_709_164_800;
    for expiration in ["2024-02-29T00:01:01Z", "2024-02-29T00:01:01.123+00:00"] {
        validate_expiration(expiration, now).unwrap();
    }
    for expiration in [
        "2024-02-29T00:01:00Z",
        "2024-02-28T23:59:00Z",
        "2023-02-29T00:00:00Z",
        "2024-00-01T00:00:00Z",
        "2024-13-01T00:00:00Z",
        "2024-02-30T00:00:00Z",
        "2024-03-01T24:00:00Z",
        "2024-03-01T00:00:00",
        "2024-03-01T00:00:00.injectedZ",
        "🔥2024",
    ] {
        assert!(
            validate_expiration(expiration, now).is_err(),
            "{expiration}"
        );
    }
}

#[cfg(unix)]
#[test]
fn credential_process_restores_source_and_redacts_errors() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let aws = dir.path().join("aws");
    let capture = dir.path().join("capture");
    let req = credential_request();
    let path = dir.path().join("request.json");
    zdn::foundation::write_json(&path, &req).unwrap();
    let role = req.role_arn.rsplit('/').next().unwrap();
    let script = format!(
        r#"#!/bin/sh
printf '%s\n' "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE" "$AWS_PROFILE" >> "$CAPTURE"
case "$*" in
  *get-caller-identity*) printf '%s\n' '{{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/developer","UserId":"source"}}' ;;
  *assume-role*)
    if [ "$FAIL_STS" = 1 ]; then
      printf '%s\n' 'An error occurred (AccessDenied): fixture-secret fixture-token' >&2
      exit 1
    fi
    printf '%s\n' '{{"AssumedRoleUser":{{"Arn":"arn:aws:sts::123456789012:assumed-role/{role}/zdn-deployment","AssumedRoleId":"role:session"}},"Credentials":{{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","SessionToken":"fixture-token","Expiration":"2099-01-01T00:00:00Z"}}}}' ;;
  *) exit 99 ;;
esac
"#
    );
    executable::write(&aws, script).unwrap();
    fs::set_permissions(&aws, fs::Permissions::from_mode(0o700)).unwrap();
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_zdn"));
        cmd.env_clear()
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .env("CAPTURE", &capture)
            .env("AWS_PROFILE", "developer")
            .env("AWS_DEFAULT_PROFILE", "developer")
            .env("AWS_CONFIG_FILE", "/bridge/config")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/bridge/empty-credentials")
            .args(["__credentials", "--request"])
            .arg(&path);
        cmd
    };
    for _ in 0..2 {
        let output = command().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let credentials: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(credentials["SessionToken"], "fixture-token");
        assert!(output.stderr.is_empty());
    }
    assert_eq!(
        fs::read_to_string(&capture).unwrap(),
        "/source/aws/config\n/source/aws/credentials\ndeveloper\n".repeat(4)
    );
    let denied = command().env("FAIL_STS", "1").output().unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    let error = String::from_utf8(denied.stderr).unwrap();
    assert!(error.contains("sts:AssumeRole"));
    assert!(!error.contains("fixture-secret") && !error.contains("fixture-token"));
    let ambient = command()
        .env("AWS_ACCESS_KEY_ID", "ambient-secret")
        .output()
        .unwrap();
    assert!(!ambient.status.success());
    assert!(ambient.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&ambient.stderr).contains("ambient-secret"));
}

#[cfg(unix)]
#[test]
fn aws_cli_rejects_a_source_identity_where_a_deployment_role_is_required() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let aws = dir.path().join("aws");
    executable::write(&aws,"#!/bin/sh\nprintf '%s\\n' '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/developer\",\"UserId\":\"source\"}'\n").unwrap();
    fs::set_permissions(&aws, fs::Permissions::from_mode(0o700)).unwrap();
    let request = credential_request();
    let api = AwsCli::with_environment(request.source.clone(), aws, BTreeMap::new())
        .unwrap()
        .expect_role(Some(request.role_arn))
        .unwrap();
    assert!(
        format!("{:#}", api.verify_identity().unwrap_err()).contains("selected deployment role")
    );
}

#[test]
fn private_document_creation_and_mutation_stay_in_the_bootstrap_namespace() {
    let req = request();
    let policies: Vec<_> = deployment_policies(&req.team, &req.access())
        .unwrap()
        .into_values()
        .collect();
    let network = Uuid::new_v4();
    let name = zdn::endpoints::Service::NodeRpc.document_name(req.team.bootstrap_id, network);
    let arn = format!("arn:aws:ssm:us-east-1:123456789012:document/{name}");
    let creation = json!({"aws:RequestTag/zdn:managed-by":"zdn","aws:RequestTag/zdn:team-id":req.team.team_id,
        "aws:RequestTag/zdn:bootstrap":req.team.bootstrap_id.to_string(),"ssm:DocumentType":"Session"});
    assert!(permitted(&policies, "ssm:CreateDocument", &arn, &creation));
    assert!(permitted(
        &policies,
        "ssm:AddTagsToResource",
        &arn,
        &creation
    ));
    let foreign = arn.replace(
        &req.team.bootstrap_id.to_string(),
        &Uuid::new_v4().to_string(),
    );
    for action in [
        "ssm:CreateDocument",
        "ssm:AddTagsToResource",
        "ssm:GetDocument",
        "ssm:DescribeDocument",
    ] {
        assert!(
            !permitted(&policies, action, &foreign, &creation),
            "{action}"
        );
    }
    let owned = json!({"aws:ResourceTag/zdn:managed-by":"zdn","aws:ResourceTag/zdn:team-id":req.team.team_id,
        "aws:ResourceTag/zdn:bootstrap":req.team.bootstrap_id.to_string()});
    for action in [
        "ssm:UpdateDocument",
        "ssm:DeleteDocument",
        "ssm:StartSession",
    ] {
        assert!(permitted(&policies, action, &arn, &owned), "{action}");
        assert!(!permitted(&policies, action, &arn, &json!({})), "{action}");
    }
    assert!(!permitted(
        &policies,
        "ssm:RemoveTagsFromResource",
        &arn,
        &owned
    ));
    assert!(
        permitted(&policies, "ssm:DescribeDocument", &arn, &json!({})),
        "absence remains observable after deletion"
    );
}

#[test]
fn client_session_iam_variables_survive_pulumi_rendering_as_literals() {
    let req = request();
    let raw = deployment_policies(&req.team, &req.access()).unwrap()["client-sessions"].to_string();
    assert!(raw.contains("${aws:userid}"));
    let rendered = req.render().unwrap();
    let text = rendered["resources"]["client-sessionsPolicy"]["properties"]["policy"]
        .as_str()
        .unwrap();
    assert_eq!(text, raw.replace("${", "$${"));
}
