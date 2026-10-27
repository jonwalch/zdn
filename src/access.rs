//! Versioned deployment access and deterministic administrator IAM programs.
//! Rendering is offline; effective AWS authorization remains a live release gate.

use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::aws::{AwsSelection, TeamDefinition};
use crate::infra::AWS_PROVIDER_VERSION;

pub const TEAM_ROLE_API_VERSION: &str = "zdn-team/v1alpha2";
pub const SSM_CORE_POLICY: &str = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RoleManagement {
    Zdn,
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentAccess {
    pub role_arn: String,
    pub management: RoleManagement,
    pub runtime_boundary_arn: String,
}

impl DeploymentAccess {
    pub fn managed(team: &TeamDefinition) -> Self {
        Self {
            role_arn: admin_arn(team, "role", &admin_name(team, "deploy")),
            management: RoleManagement::Zdn,
            runtime_boundary_arn: admin_arn(team, "policy", &admin_name(team, "runtime-boundary")),
        }
    }

    /// Preserve the boundary if it won the original duplicate-name creation.
    /// Its restrictive document and ARN stay unchanged during recovery.
    pub(crate) fn legacy_managed(team: &TeamDefinition) -> Self {
        let mut access = Self::managed(team);
        access.runtime_boundary_arn = admin_arn(team, "policy", &admin_name(team, "runtime"));
        access
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "access.deployment_access.policy_name")
    )]
    pub(crate) fn policy_name(&self, team: &TeamDefinition, policy: &str) -> String {
        admin_name(
            team,
            if *self == Self::legacy_managed(team) && policy == "runtime" {
                "runtime-management"
            } else {
                policy
            },
        )
    }

    pub(crate) fn policy_arn(&self, team: &TeamDefinition, policy: &str) -> String {
        admin_arn(team, "policy", &self.policy_name(team, policy))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "access.deployment_access.validate")
    )]
    pub fn validate(&self, team: &TeamDefinition) -> Result<()> {
        iam_resource(&self.role_arn, &team.aws.account_id, "role")?;
        iam_resource(&self.runtime_boundary_arn, &team.aws.account_id, "policy")?;
        ensure!(
            !self
                .role_arn
                .contains(&format!(":role{}", runtime_path(team))),
            "deployment role must be separate from runtime roles"
        );
        if self.management == RoleManagement::Zdn {
            // This is offline identity validation, not proof of the policy's
            // purpose in AWS. Imported recovered teams have no local admin
            // receipt, so both exact layouts must remain portable. Bootstrap
            // proves legacy boundary ownership/document from its checkpoint;
            // the deployed IAM role enforces the approved boundary ARN. Never
            // infer that an arbitrary edited team file proves recovery.
            ensure!(
                *self == Self::managed(team) || *self == Self::legacy_managed(team),
                "managed IAM identities differ from bootstrap ID"
            );
        }
        Ok(())
    }
}

fn admin_name(team: &TeamDefinition, suffix: &str) -> String {
    format!("zdn-{}-{suffix}", team.bootstrap_id.simple())
}

pub(crate) fn admin_path(team: &TeamDefinition) -> String {
    format!("/zdn-admin/{}/", team.bootstrap_id)
}

pub(crate) fn admin_tags(team: &TeamDefinition) -> Value {
    json!({"zdn:managed-by":"zdn","zdn:team-id":team.team_id,"zdn:bootstrap":team.bootstrap_id})
}

fn admin_arn(team: &TeamDefinition, kind: &str, name: &str) -> String {
    format!(
        "arn:aws:iam::{}:{kind}{}{name}",
        team.aws.account_id,
        admin_path(team)
    )
}

/// Accept explicit IAM identities only, never sessions, roots, patterns or
/// account-wide principals. Cross-account federation is outside this version.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access.iam_resource")
)]
pub fn iam_resource<'a>(arn: &'a str, account: &str, kind: &str) -> Result<&'a str> {
    ensure!(
        account.len() == 12 && account.bytes().all(|c| c.is_ascii_digit()),
        "invalid IAM account"
    );
    let resource = arn
        .strip_prefix(&format!("arn:aws:iam::{account}:{kind}/"))
        .context("IAM ARN has the wrong account, partition or resource type")?;
    ensure!(
        resource.len() <= 576
            && resource.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_+=,.@-".contains(&c))
            }),
        "invalid IAM path or name"
    );
    let name = resource.rsplit('/').next().unwrap();
    ensure!(
        name.len() <= if kind == "policy" { 128 } else { 64 },
        "IAM name is too long"
    );
    Ok(resource)
}

pub fn runtime_path(team: &TeamDefinition) -> String {
    format!("/zdn/{}/", team.bootstrap_id)
}

pub fn admin_backend(team: &TeamDefinition) -> Result<String> {
    Ok(format!(
        "s3://{}/zdn-admin/v1/{}",
        team.backend_bucket()?,
        team.bootstrap_id
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessRequest {
    pub team: TeamDefinition,
    pub administrator: AwsSelection,
    pub trusted_principals: Vec<String>,
    /// An existing role is never adopted into the administrator stack.
    pub existing: Option<DeploymentAccess>,
}

impl AccessRequest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "access.access_request.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        self.team.validate()?;
        let prefix = self.team.backend_prefix()?;
        ensure!(
            prefix != "zdn-admin" && !prefix.starts_with("zdn-admin/"),
            "deployment state overlaps administrator state"
        );
        self.administrator.validate()?;
        ensure!(
            self.administrator.account_id == self.team.aws.account_id
                && self.administrator.region == self.team.aws.region,
            "administrator selection differs from team"
        );
        ensure!(
            !self.trusted_principals.is_empty() && self.trusted_principals.len() <= 20,
            "select 1-20 explicit trusted IAM principals"
        );
        let mut seen = BTreeSet::new();
        for principal in &self.trusted_principals {
            ensure!(seen.insert(principal), "duplicate trusted principal");
            let kind = if principal.contains(":user/") {
                "user"
            } else {
                "role"
            };
            iam_resource(principal, &self.team.aws.account_id, kind)?;
            ensure!(
                principal != &self.access().role_arn,
                "deployment role cannot trust itself"
            );
        }
        if let Some(access) = &self.existing {
            ensure!(
                access.management == RoleManagement::External,
                "existing roles must be externally managed"
            );
            access.validate(&self.team)?;
        }
        if let Some(access) = &self.team.deployment {
            ensure!(
                *access == self.access(),
                "setup cannot retarget existing deployment access"
            );
        }
        Ok(())
    }

    pub fn access(&self) -> DeploymentAccess {
        self.existing
            .clone()
            .or_else(|| {
                self.team
                    .deployment
                    .clone()
                    .filter(|access| access.management == RoleManagement::Zdn)
            })
            .unwrap_or_else(|| DeploymentAccess::managed(&self.team))
    }

    pub fn completed_team(&self) -> Result<TeamDefinition> {
        self.completed_team_with_access(self.access())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "access.access_request.completed_team_with_access")
    )]
    pub(crate) fn completed_team_with_access(
        &self,
        access: DeploymentAccess,
    ) -> Result<TeamDefinition> {
        self.validate()?;
        access.validate(&self.team)?;
        ensure!(
            self.team
                .deployment
                .as_ref()
                .is_none_or(|saved| *saved == access)
                && (self.existing.is_none() || self.existing.as_ref() == Some(&access)),
            "setup cannot retarget existing deployment access"
        );
        let mut team = self.team.clone();
        if team.deployment.is_none() {
            team.revision = team
                .revision
                .checked_add(1)
                .context("team revision overflow")?;
        }
        team.api_version = TEAM_ROLE_API_VERSION.into();
        team.deployment = Some(access);
        team.validate()?;
        Ok(team)
    }

    pub fn trust_policy(&self) -> Result<Value> {
        self.validate()?;
        let mut principals = self.trusted_principals.clone();
        principals.sort();
        Ok(policy(vec![
            json!({"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":principals}}),
        ]))
    }

    /// This policy is a reviewable caller-side grant. Setup deliberately does
    /// not change IAM users, SSO permission sets, or organization controls.
    pub fn caller_policy(&self) -> Result<Value> {
        self.validate()?;
        Ok(policy(vec![allow(
            json!(["sts:AssumeRole"]),
            json!(self.access().role_arn),
        )]))
    }

    pub fn render(&self) -> Result<Value> {
        self.render_with_access(&self.access())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "access.access_request.render_with_access")
    )]
    pub(crate) fn render_with_access(&self, access: &DeploymentAccess) -> Result<Value> {
        self.validate()?;
        ensure!(
            self.existing.is_none(),
            "external deployment roles must not be rendered as owned resources"
        );
        access.validate(&self.team)?;
        ensure!(
            access.management == RoleManagement::Zdn,
            "external deployment roles must not be rendered as owned resources"
        );
        ensure!(
            self.team
                .deployment
                .as_ref()
                .is_none_or(|saved| saved == access),
            "setup cannot retarget existing deployment access"
        );
        let path = admin_path(&self.team);
        let tags = admin_tags(&self.team);
        let mut resources = BTreeMap::new();
        resources.insert("provider".to_string(), json!({"type":"pulumi:providers:aws","properties":{
            "region":self.team.aws.region,"profile":self.administrator.profile,"allowedAccountIds":[self.team.aws.account_id]},
            "options":{"version":AWS_PROVIDER_VERSION}}));
        let resource = |kind: &str, properties: Value| {
            json!({"type":kind,"properties":properties,
            "options":{"provider":"${provider}","protect":true}})
        };
        resources.insert("deploymentRole".into(), resource("aws:iam:Role", json!({
            "name":admin_name(&self.team, "deploy"),"path":path,"assumeRolePolicy":self.trust_policy()?.to_string(),
            "maxSessionDuration":3600,"tags":tags})));
        resources.insert("runtimeBoundary".into(), resource("aws:iam:Policy", json!({
            "name":access.runtime_boundary_arn.rsplit('/').next().unwrap(),"path":path,"policy":runtime_boundary_for_team(&self.team)?.to_string(),"tags":tags})));
        resources.insert("runtimeDataPolicy".into(), resource("aws:iam:Policy", json!({"name":admin_name(&self.team,"runtime-data"),"path":path,"policy":runtime_data_policy(&self.team)?.to_string(),"tags":tags})));
        resources.extend(
            crate::build_infra::BuildInfrastructure::for_team(&self.team)?.resources(&self.team)?,
        );
        for (name, document) in deployment_policies(&self.team, access)? {
            ensure!(
                document.to_string().len() <= 6144,
                "managed policy exceeds IAM size limit"
            );
            let key = format!("{name}Policy");
            resources.insert(key.clone(), resource("aws:iam:Policy", json!({
                "name":access.policy_name(&self.team, &name),"path":path,"policy":document.to_string().replace("${", "$${"),"tags":tags})));
            resources.insert(
                format!("{name}Attachment"),
                resource(
                    "aws:iam:RolePolicyAttachment",
                    json!({
                "role":"${deploymentRole.name}","policyArn":format!("${{{key}.arn}}")}),
                ),
            );
        }
        Ok(
            json!({"name":"zdn-access","runtime":"yaml","resources":resources,
            "outputs":{"roleArn":"${deploymentRole.arn}","runtimeBoundaryArn":"${runtimeBoundary.arn}"}}),
        )
    }
}

fn policy(statements: Vec<Value>) -> Value {
    json!({"Version":"2012-10-17","Statement":statements})
}
fn allow(actions: Value, resources: Value) -> Value {
    json!({"Effect":"Allow","Action":actions,"Resource":resources})
}
fn conditional(actions: Value, resources: Value, condition: Value) -> Value {
    let mut statement = allow(actions, resources);
    statement["Condition"] = condition;
    statement
}

/// Upper bound for the EC2 host: agent registration and message channels only.
/// No parameter store, state, KMS, IAM, or application data permissions.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access.runtime_boundary")
)]
pub fn runtime_boundary() -> Value {
    policy(vec![allow(
        json!([
            "ssm:UpdateInstanceInformation",
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel"
        ]),
        json!("*"),
    )])
}

/// Fixed administrator-owned data policy. Developers may attach this policy,
/// but cannot edit it or grant hosts access to state, leases, or IAM.
pub fn runtime_data_policy_arn(team: &TeamDefinition) -> String {
    format!(
        "arn:aws:iam::{}:policy{}{}",
        team.aws.account_id,
        admin_path(team),
        admin_name(team, "runtime-data")
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access.runtime_data_policy")
)]
pub fn runtime_data_policy(team: &TeamDefinition) -> Result<Value> {
    team.validate()?;
    let bucket = format!("arn:aws:s3:::{}", team.backend_bucket()?);
    let objects = format!("{bucket}/{}/artifacts/*", team.metadata_prefix());
    let repository = format!(
        "arn:aws:ecr:{}:{}:repository/zdn/{}/*",
        team.aws.region, team.aws.account_id, team.team_id
    );
    Ok(policy(vec![
        allow(json!(["s3:GetObject"]), json!(objects)),
        conditional(
            json!(["kms:Decrypt"]),
            json!(team.state.kms_key_arn),
            json!({"StringEquals":{"kms:ViaService":format!("s3.{}.amazonaws.com",team.aws.region),"kms:CallerAccount":team.aws.account_id},"StringLike":{"kms:EncryptionContext:aws:s3:arn":[bucket,objects]}}),
        ),
        conditional(
            json!(["ecr:GetAuthorizationToken"]),
            json!("*"),
            json!({"StringEquals":{"aws:RequestedRegion":team.aws.region}}),
        ),
        allow(
            json!([
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchCheckLayerAvailability"
            ]),
            json!(repository),
        ),
    ]))
}

/// Keep runtime_boundary() unchanged for legacy recovery receipts. The current
/// boundary adds only the team's immutable application-artifact/image reads.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access.runtime_boundary_for_team")
)]
pub fn runtime_boundary_for_team(team: &TeamDefinition) -> Result<Value> {
    let mut boundary = runtime_boundary();
    boundary["Statement"].as_array_mut().unwrap().extend(
        runtime_data_policy(team)?["Statement"]
            .as_array()
            .unwrap()
            .iter()
            .cloned(),
    );
    Ok(boundary)
}

/// Explicit action lists and immutable ownership tags prevent a developer from
/// adopting foreign resources by tagging them. AWS read APIs without resource
/// scoping are regional/account-wide; they do not authorize mutation.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "access.deployment_policies")
)]
pub fn deployment_policies(
    team: &TeamDefinition,
    access: &DeploymentAccess,
) -> Result<BTreeMap<String, Value>> {
    team.validate()?;
    access.validate(team)?;
    let account = &team.aws.account_id;
    let region = &team.aws.region;
    let bucket = format!("arn:aws:s3:::{}", team.backend_bucket()?);
    let prefixes = [team.backend_prefix()?.to_string(), team.metadata_prefix()];
    let objects: Vec<_> = prefixes.iter().map(|p| format!("{bucket}/{p}/*")).collect();
    let list_prefixes: Vec<_> = prefixes
        .iter()
        .flat_map(|p| [p.clone(), format!("{p}/*")])
        .collect();
    let ec2 = format!("arn:aws:ec2:{region}:{account}");
    let runtime = format!(
        "arn:aws:iam::{account}:role{}zdn-*-host-role",
        runtime_path(team)
    );
    let profiles = format!(
        "arn:aws:iam::{account}:instance-profile{}zdn-*-host-profile",
        runtime_path(team)
    );
    let tag_values = json!({"aws:ResourceTag/zdn:team-id":team.team_id,"aws:ResourceTag/zdn:managed-by":"zdn","aws:ResourceTag/zdn:bootstrap":team.bootstrap_id.to_string()});
    let request_tags = json!({"aws:RequestTag/zdn:team-id":team.team_id,"aws:RequestTag/zdn:managed-by":"zdn","aws:RequestTag/zdn:bootstrap":team.bootstrap_id.to_string()});
    let owned = json!({"StringEquals":tag_values});
    let creating = json!({"StringEquals":request_tags});
    let mut role_creation = creating.clone();
    role_creation["StringEquals"]["iam:PermissionsBoundary"] = json!(access.runtime_boundary_arn);
    let mut policies = BTreeMap::from([
        (
            "state".into(),
            policy(vec![
                allow(
                    json!([
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:GetBucketTagging",
                        "s3:GetBucketVersioning",
                        "s3:GetBucketPublicAccessBlock",
                        "s3:GetBucketOwnershipControls",
                        "s3:GetEncryptionConfiguration",
                        "s3:GetBucketPolicy"
                    ]),
                    json!(bucket),
                ),
                conditional(
                    json!(["s3:ListBucketVersions"]),
                    json!(bucket),
                    json!({"StringLike":{"s3:prefix":list_prefixes}}),
                ),
                allow(
                    json!([
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ]),
                    json!(objects),
                ),
                // Permanent version deletion is needed for explicit artifact
                // cleanup, never for Pulumi history or coordination records.
                allow(
                    json!(["s3:DeleteObjectVersion"]),
                    json!(format!("{bucket}/{}/artifacts/*", team.metadata_prefix())),
                ),
                allow(
                    json!([
                        "kms:DescribeKey",
                        "kms:ListResourceTags",
                        "kms:GetKeyRotationStatus",
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKey"
                    ]),
                    json!(team.state.kms_key_arn),
                ),
                json!({"Effect":"Deny","Action":"s3:*","Resource":format!("{bucket}/zdn-admin/*")}),
            ]),
        ),
        (
            "runtime".into(),
            policy(vec![
                conditional(json!(["iam:CreateRole"]), json!(runtime), role_creation),
                conditional(
                    json!(["iam:CreateInstanceProfile"]),
                    json!(profiles),
                    creating.clone(),
                ),
                conditional(json!(["iam:TagRole"]), json!(runtime), creating.clone()),
                conditional(
                    json!(["iam:TagInstanceProfile"]),
                    json!(profiles),
                    creating.clone(),
                ),
                allow(
                    json!([
                        "iam:GetRole",
                        "iam:ListRolePolicies",
                        "iam:GetRolePolicy",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListInstanceProfilesForRole",
                        "iam:ListRoleTags",
                        "iam:DeleteRole"
                    ]),
                    json!(runtime),
                ),
                allow(
                    json!([
                        "iam:GetInstanceProfile",
                        "iam:ListInstanceProfileTags",
                        "iam:DeleteInstanceProfile",
                        "iam:AddRoleToInstanceProfile",
                        "iam:RemoveRoleFromInstanceProfile"
                    ]),
                    json!(profiles),
                ),
                // After deletion IAM authorizes these name-based lookups against
                // pathless ARNs. Permit only reads so cleanup can receive a real
                // NoSuchEntity response; mutations keep the bootstrap path.
                allow(
                    json!(["iam:GetRole"]),
                    json!(format!("arn:aws:iam::{account}:role/zdn-*-host-role")),
                ),
                allow(
                    json!(["iam:GetInstanceProfile"]),
                    json!(format!(
                        "arn:aws:iam::{account}:instance-profile/zdn-*-host-profile"
                    )),
                ),
                conditional(
                    json!(["iam:AttachRolePolicy", "iam:DetachRolePolicy"]),
                    json!(runtime),
                    json!({"ArnEquals":{"iam:PolicyARN":[SSM_CORE_POLICY,runtime_data_policy_arn(team)]}}),
                ),
                conditional(
                    json!(["iam:PassRole"]),
                    json!(runtime),
                    json!({"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}),
                ),
                allow(
                    json!(["iam:GetPolicy", "iam:GetPolicyVersion"]),
                    json!([
                        SSM_CORE_POLICY.to_string(),
                        access.runtime_boundary_arn.clone(),
                        runtime_data_policy_arn(team)
                    ]),
                ),
                json!({"Effect":"Deny","Action":["iam:PutRolePermissionsBoundary","iam:DeleteRolePermissionsBoundary","iam:PutRolePolicy","iam:UpdateAssumeRolePolicy"],"Resource":"*"}),
                json!({"Effect":"Deny","Action":"iam:*","Resource":access.role_arn}),
                // Runtime preflight reads these administrator-owned policies
                // through the narrow GetPolicy/GetPolicyVersion Allow above.
                // Every mutation stays explicitly denied; unrelated policy
                // reads have no Allow. A wildcard iam:* deny would also block
                // the required preflight reads despite that Allow.
                json!({"Effect":"Deny","NotAction":["iam:GetPolicy","iam:GetPolicyVersion"],"Resource":[access.runtime_boundary_arn,format!("arn:aws:iam::{account}:policy/zdn-admin/{}/*",team.bootstrap_id)]}),
            ]),
        ),
        (
            "compute".into(),
            policy(vec![
                conditional(
                    json!([
                        "ec2:DescribeVpcs",
                        "ec2:DescribeVpcAttribute",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeAddressesAttribute",
                        "ec2:DescribeNetworkAcls",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSecurityGroupRules",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceAttribute",
                        "ec2:DescribeInstanceTypes",
                        "ec2:DescribeInstanceTypeOfferings",
                        "ec2:DescribeVolumes",
                        "ec2:DescribeVolumeAttribute",
                        "ec2:DescribeVolumesModifications",
                        "ec2:DescribeImages",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeTags"
                    ]),
                    json!("*"),
                    json!({"StringEquals":{"aws:RequestedRegion":region}}),
                ),
                conditional(
                    json!([
                        "ec2:CreateVpc",
                        "ec2:CreateSubnet",
                        "ec2:CreateRouteTable",
                        "ec2:CreateInternetGateway",
                        "ec2:AllocateAddress",
                        "ec2:CreateNatGateway",
                        "ec2:CreateSecurityGroup",
                        "ec2:CreateVolume",
                        "ec2:RunInstances"
                    ]),
                    json!(format!("{ec2}:*/*")),
                    creating.clone(),
                ),
                conditional(
                    json!([
                        "ec2:CreateSubnet",
                        "ec2:CreateRouteTable",
                        "ec2:CreateSecurityGroup",
                        "ec2:CreateNatGateway",
                        "ec2:RunInstances",
                        "ec2:DeleteVpc",
                        "ec2:ModifyVpcAttribute",
                        "ec2:DeleteSubnet",
                        "ec2:ModifySubnetAttribute",
                        "ec2:AttachInternetGateway",
                        "ec2:DetachInternetGateway",
                        "ec2:DeleteInternetGateway",
                        "ec2:DeleteRouteTable",
                        "ec2:CreateRoute",
                        "ec2:ReplaceRoute",
                        "ec2:DeleteRoute",
                        "ec2:AssociateRouteTable",
                        "ec2:DisassociateRouteTable",
                        "ec2:ReplaceRouteTableAssociation",
                        "ec2:DeleteNatGateway",
                        "ec2:ReleaseAddress",
                        "ec2:DeleteSecurityGroup",
                        "ec2:AuthorizeSecurityGroupEgress",
                        "ec2:RevokeSecurityGroupEgress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:AttachVolume",
                        "ec2:DetachVolume",
                        "ec2:DeleteVolume",
                        "ec2:ModifyVolume",
                        "ec2:StopInstances",
                        "ec2:StartInstances",
                        "ec2:TerminateInstances",
                        "ec2:ModifyInstanceAttribute"
                    ]),
                    json!(format!("{ec2}:*/*")),
                    owned.clone(),
                ),
                // RunInstances authorizes new ENIs as well as the tagged subnet,
                // security group, instance and volumes. Images are read-only inputs.
                allow(
                    json!(["ec2:RunInstances"]),
                    json!([
                        format!("arn:aws:ec2:{region}::image/ami-*"),
                        format!("{ec2}:network-interface/*")
                    ]),
                ),
                conditional(
                    json!(["ec2:CreateTags"]),
                    json!(format!("{ec2}:*/*")),
                    json!({"StringEquals":{"ec2:CreateAction":["CreateVpc","CreateSubnet","CreateRouteTable","CreateInternetGateway","AllocateAddress","CreateNatGateway","CreateSecurityGroup","CreateVolume","RunInstances"]}}),
                ),
                conditional(
                    json!(["ec2:CreateTags", "ec2:DeleteTags"]),
                    json!(format!("{ec2}:*/*")),
                    json!({"StringEquals":tag_values,"ForAllValues:StringNotEquals":{"aws:TagKeys":["zdn:team-id","zdn:managed-by","zdn:bootstrap"]}}),
                ),
            ]),
        ),
        (
            "session".into(),
            policy(vec![
                conditional(
                    json!(["ssm:SendCommand", "ssm:StartSession"]),
                    json!(format!("{ec2}:instance/*")),
                    json!({"StringEquals":{"ssm:resourceTag/zdn:team-id":team.team_id,"ssm:resourceTag/zdn:managed-by":"zdn","ssm:resourceTag/zdn:bootstrap":team.bootstrap_id.to_string()}}),
                ),
                allow(
                    json!(["ssm:SendCommand"]),
                    json!(format!("arn:aws:ssm:{region}::document/AWS-RunShellScript")),
                ),
                allow(
                    json!(["ssm:StartSession"]),
                    json!(format!(
                        "arn:aws:ssm:{region}::document/AWS-StartPortForwardingSession"
                    )),
                ),
                conditional(
                    json!([
                        "ssm:DescribeInstanceInformation",
                        "ssm:GetCommandInvocation",
                        "ssm:ListCommands",
                        "ssm:CancelCommand"
                    ]),
                    json!("*"),
                    json!({"StringEquals":{"aws:RequestedRegion":region}}),
                ),
            ]),
        ),
    ]);
    // Bootstrap UUID reserves a document namespace for this team. The initial
    // tag-on-create authorization cannot depend on tags already being present.
    let documents = format!(
        "arn:aws:ssm:{region}:{account}:document/zdn-{}-*-v1",
        team.bootstrap_id
    );
    policies.insert("client-sessions".into(), policy(vec![
        conditional(json!(["ssm:CreateDocument"]), json!(documents),
            json!({"StringEquals":{
                "aws:RequestTag/zdn:team-id":team.team_id,
                "aws:RequestTag/zdn:managed-by":"zdn",
                "aws:RequestTag/zdn:bootstrap":team.bootstrap_id.to_string(),
                "ssm:DocumentType":"Session"
            }})),
        conditional(json!(["ssm:AddTagsToResource"]), json!(documents), creating.clone()),
        conditional(json!(["ssm:DeleteDocument", "ssm:UpdateDocument", "ssm:UpdateDocumentDefaultVersion"]), json!(documents), owned.clone()),
        // Provider refresh/delete must be able to observe an absent document.
        allow(json!(["ssm:GetDocument", "ssm:DescribeDocument", "ssm:ListDocumentVersions", "ssm:ListTagsForResource", "ssm:DescribeDocumentPermission"]), json!(documents)),
        conditional(json!(["ssm:StartSession"]), json!(documents), owned.clone()),
        allow(json!(["ssmmessages:OpenDataChannel"]), json!(format!("arn:aws:ssm:{region}:{account}:session/${{aws:userid}}-*"))),
        conditional(json!(["ssm:TerminateSession"]), json!(format!("arn:aws:ssm:{region}:{account}:session/*")),
            json!({"StringEquals":{"ssm:resourceTag/aws:ssmmessages:session-id":"${aws:userid}"}})),
    ]));
    policies.insert(
        "images".into(),
        policy(vec![allow(
            json!(["ecr:BatchGetImage"]),
            json!(format!(
                "arn:aws:ecr:{region}:{account}:repository/zdn/{}/*",
                team.team_id
            )),
        )]),
    );
    policies.insert(
        "build".into(),
        crate::build_infra::BuildInfrastructure::for_team(team)?.deployment_policy(),
    );
    Ok(policies)
}
