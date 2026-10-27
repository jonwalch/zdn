//! Administrator-owned, isolated resources for native source-to-image builds.

use eyre::{ensure, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{
    access::{admin_path, admin_tags},
    aws::TeamDefinition,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInfrastructure {
    pub source_bucket: String,
    pub project_name: String,
    pub repository: String,
    pub repository_uri: String,
    pub account_id: String,
    pub region: String,
}

impl BuildInfrastructure {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_infra.for_team")
    )]
    pub fn for_team(team: &TeamDefinition) -> Result<Self> {
        team.validate()?;
        let digest = hex::encode(Sha256::digest(format!(
            "{}:{}:{}:{}",
            team.team_id, team.bootstrap_id, team.aws.account_id, team.aws.region
        )));
        let name = format!("zdn-build-{}", &digest[..32]);
        // Keep the repository within the existing team image-read namespace;
        // the host runtime policy is deliberately not expanded.
        let repository = format!("zdn/{}/build-{}", team.team_id, &digest[..32]);
        Ok(Self {
            source_bucket: name.clone(),
            project_name: name,
            repository_uri: format!(
                "{}.dkr.ecr.{}.amazonaws.com/{repository}",
                team.aws.account_id, team.aws.region
            ),
            repository,
            account_id: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
        })
    }

    fn project_arn(&self) -> String {
        format!(
            "arn:aws:codebuild:{}:{}:project/{}",
            self.region, self.account_id, self.project_name
        )
    }

    fn repository_arn(&self) -> String {
        format!(
            "arn:aws:ecr:{}:{}:repository/{}",
            self.region, self.account_id, self.repository
        )
    }

    /// The developer can submit work, not change the executor or its role.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_infra.deployment_policy")
    )]
    pub fn deployment_policy(&self) -> Value {
        json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":["codebuild:BatchGetProjects","codebuild:BatchGetBuilds","codebuild:ListBuildsForProject","codebuild:StopBuild"],"Resource":self.project_arn()},
            {"Effect":"Allow","Action":["codebuild:StartBuild"],"Resource":self.project_arn(),"Condition":{"Null":{"codebuild:environment":"true","codebuild:serviceRole":"true","codebuild:cache":"true","codebuild:artifacts":"true","codebuild:secondarySources":"true","codebuild:secondaryArtifacts":"true","codebuild:autoRetryLimit":"true"}}},
            {"Effect":"Allow","Action":["s3:PutObject"],"Resource":format!("arn:aws:s3:::{}/sources/*",self.source_bucket),"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"AES256"}}},
            {"Effect":"Allow","Action":["s3:GetObject"],"Resource":format!("arn:aws:s3:::{}/results/*",self.source_bucket)},
            // Missing GetObject keys return NoSuchKey only with ListBucket;
            // GetObject supplies no s3:prefix context for a prefix condition.
            {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":format!("arn:aws:s3:::{}",self.source_bucket)},
            {"Effect":"Allow","Action":["s3:GetObject"],"Resource":format!("arn:aws:s3:::{}/images/*",self.source_bucket)},
            {"Effect":"Allow","Action":["s3:PutObject"],"Resource":format!("arn:aws:s3:::{}/images/*",self.source_bucket),"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"AES256"}}},
            {"Effect":"Allow","Action":["ecr:BatchGetImage"],"Resource":self.repository_arn()}
        ]})
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_infra.resources")
    )]
    pub fn resources(&self, team: &TeamDefinition) -> Result<BTreeMap<String, Value>> {
        ensure!(
            *self == Self::for_team(team)?,
            "build infrastructure differs from team"
        );
        let resource = |kind: &str, properties: Value| json!({"type":kind,"properties":properties,"options":{"provider":"${provider}","protect":true}});
        let bucket = format!("arn:aws:s3:::{}", self.source_bucket);
        let log_group = format!("/aws/codebuild/{}", self.project_name);
        let logs = format!(
            "arn:aws:logs:{}:{}:log-group:{log_group}",
            self.region, self.account_id
        );
        let service_policy = json!({"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":["s3:GetObjectVersion"],"Resource":format!("{bucket}/sources/*")},
            {"Effect":"Allow","Action":["s3:PutObject"],"Resource":format!("{bucket}/results/*")},
            {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":format!("{bucket}/cache/*")},
            {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":bucket,"Condition":{"StringLike":{"s3:prefix":"cache/*"}}},
            {"Effect":"Allow","Action":["s3:GetBucketAcl","s3:GetBucketLocation"],"Resource":bucket},
            {"Effect":"Allow","Action":["ecr:GetAuthorizationToken"],"Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":self.region}}},
            {"Effect":"Allow","Action":["ecr:BatchCheckLayerAvailability","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload","ecr:PutImage","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":self.repository_arn()},
            {"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":format!("{logs}:log-stream:*")}
        ]});
        let mut resources = BTreeMap::new();
        resources.insert(
            "buildBucket".into(),
            resource(
                "aws:s3:BucketV2",
                json!({"bucket":self.source_bucket,"forceDestroy":false,"tags":admin_tags(team)}),
            ),
        );
        resources.insert("buildBucketPublicAccess".into(), resource("aws:s3:BucketPublicAccessBlock", json!({"bucket":"${buildBucket.id}","blockPublicAcls":true,"blockPublicPolicy":true,"ignorePublicAcls":true,"restrictPublicBuckets":true})));
        resources.insert("buildBucketOwnership".into(), resource("aws:s3:BucketOwnershipControls", json!({"bucket":"${buildBucket.id}","rule":{"objectOwnership":"BucketOwnerEnforced"}})));
        resources.insert("buildBucketEncryption".into(), resource("aws:s3:BucketServerSideEncryptionConfigurationV2", json!({"bucket":"${buildBucket.id}","rules":[{"applyServerSideEncryptionByDefault":{"sseAlgorithm":"AES256"}}]})));
        resources.insert("buildBucketVersioning".into(), resource("aws:s3:BucketVersioningV2", json!({"bucket":"${buildBucket.id}","versioningConfiguration":{"status":"Enabled"}})));
        // CodeBuild uses AWS-managed SSE-KMS for caches by default, independently
        // of bucket-default AES256. Permit both and headerless default encryption.
        resources.insert("buildBucketPolicy".into(), resource("aws:s3:BucketPolicy", json!({"bucket":"${buildBucket.id}","policy":json!({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":[bucket,format!("{bucket}/*")],"Condition":{"Bool":{"aws:SecureTransport":"false"}}},{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":format!("{bucket}/cache/*"),"Condition":{"Null":{"s3:x-amz-server-side-encryption":"false"},"StringNotEquals":{"s3:x-amz-server-side-encryption":["AES256","aws:kms"]}}}]}).to_string()})));
        resources.insert("buildRepository".into(), resource("aws:ecr:Repository", json!({"name":self.repository,"imageTagMutability":"IMMUTABLE","imageScanningConfiguration":{"scanOnPush":true},"encryptionConfigurations":[{"encryptionType":"AES256"}],"forceDelete":false,"tags":admin_tags(team)})));
        resources.insert(
            "buildLogs".into(),
            resource(
                "aws:cloudwatch:LogGroup",
                json!({"name":log_group,"retentionInDays":30,"tags":admin_tags(team)}),
            ),
        );
        resources.insert("buildRole".into(), resource("aws:iam:Role", json!({"name":self.project_name,"path":admin_path(team),"tags":admin_tags(team),"assumeRolePolicy":json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":self.account_id},"ArnEquals":{"aws:SourceArn":self.project_arn()}}}]}).to_string()})));
        resources.insert("buildServicePolicy".into(), resource("aws:iam:RolePolicy", json!({"name":self.project_name,"role":"${buildRole.id}","policy":service_policy.to_string()})));
        let mut project = resource(
            "aws:codebuild:Project",
            json!({"name":self.project_name,"serviceRole":"${buildRole.arn}","source":{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - 'false'\n"},"artifacts":{"type":"NO_ARTIFACTS"},"cache":{"type":"S3","location":format!("{}/cache",self.source_bucket),"cacheNamespace":self.project_name},"environment":{"type":"LINUX_CONTAINER","computeType":"BUILD_GENERAL1_MEDIUM","image":"aws/codebuild/standard:7.0","privilegedMode":true,"imagePullCredentialsType":"CODEBUILD"},"buildTimeout":120,"queuedTimeout":60,"logsConfig":{"cloudwatchLogs":{"status":"ENABLED","groupName":"${buildLogs.name}"},"s3Logs":{"status":"DISABLED"}},"tags":admin_tags(team)}),
        );
        project["options"]["dependsOn"] = json!([
            "${buildServicePolicy}",
            "${buildRepository}",
            "${buildBucketVersioning}",
            "${buildBucketEncryption}",
            "${buildBucketPublicAccess}",
            "${buildBucketOwnership}",
            "${buildBucketPolicy}"
        ]);
        resources.insert("buildProject".into(), project);
        Ok(resources)
    }
}
