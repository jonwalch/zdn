//! Offline administrator removal contracts. No AWS credentials or tools needed.
use eyre::{bail, Result};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::PathBuf,
    rc::Rc,
};
use zdn::{
    access::AccessRequest,
    access_bootstrap::AccessReceipt,
    aws::{
        AwsApi, AwsApiError, AwsCall, BootstrapReceipt, BootstrapRequest, LocalProfile,
        TeamDefinition,
    },
    build_infra::BuildInfrastructure,
    foundation,
    removal::{self, RemovalStack, TeamRemovalOptions},
};

fn error(code: &str) -> eyre::Report {
    AwsApiError { code: code.into() }.into()
}
fn team() -> TeamDefinition {
    serde_json::from_value(json!({"apiVersion":"zdn-team/v1alpha1","teamId":"remove-test","revision":1,
        "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153","aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-remove-test/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}})).unwrap()
}

struct Fixture {
    root: tempfile::TempDir,
    profile: PathBuf,
    access: AccessReceipt,
    api: Cloud,
    stack: Stack,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("creator.json");
        let team = team();
        let request = AccessRequest {
            administrator: zdn::aws::AwsSelection {
                profile: "admin".into(),
                account_id: team.aws.account_id.clone(),
                region: team.aws.region.clone(),
            },
            team,
            trusted_principals: vec!["arn:aws:iam::123456789012:user/developer".into()],
            existing: None,
        };
        let access = AccessReceipt {
            version: 1,
            selected_access: Some(request.access()),
            request,
            stack_started: true,
            uncertain: false,
            complete: true,
        };
        let completed = access.request.completed_team().unwrap();
        foundation::write_json(
            &profile,
            &LocalProfile {
                team: completed,
                aws_profile: "developer".into(),
            },
        )
        .unwrap();
        let original = BootstrapReceipt {
            version: 1,
            request: BootstrapRequest {
                team_id: access.request.team.team_id.clone(),
                account_id: "123456789012".into(),
                region: "us-east-1".into(),
                bucket: "zdn-remove-test".into(),
                prefix: "pulumi/zdn".into(),
            },
            bootstrap_id: access.request.team.bootstrap_id,
            key_creation_started: true,
            key_arn: Some(access.request.team.state.kms_key_arn.clone()),
            bucket_creation_started: true,
            bucket_created: true,
            complete: true,
        };
        foundation::write_json(&profile.with_extension("bootstrap.json"), &original).unwrap();
        fs::create_dir(profile.with_extension("access")).unwrap();
        foundation::write_json(
            &profile.with_extension("access").join("access.json"),
            &access,
        )
        .unwrap();
        let checkpoint = checkpoint(&access);
        let alive = Rc::new(Cell::new(true));
        let api = Cloud {
            team: access.request.team.clone(),
            checkpoint: checkpoint.clone(),
            alive: alive.clone(),
            backend: Cell::new(true),
            pending: Cell::new(false),
            calls: RefCell::default(),
            fault: None,
            objects: RefCell::new(Vec::new()),
            object_content: json!({}),
            fail_schedule: Cell::new(false),
            removed_configuration: Vec::new(),
            build_objects: RefCell::default(),
        };
        let stack = Stack {
            checkpoint: Some(checkpoint),
            alive,
            mutations: 0,
            fail: false,
            fail_unprotect: false,
            partial: Vec::new(),
            directory: profile.with_extension("access"),
        };
        Self {
            root,
            profile,
            access,
            api,
            stack,
        }
    }
    fn remove(&mut self, keep: bool, reconcile: bool) -> Result<Value> {
        removal::remove_team(
            &self.api,
            &self.access.request.administrator,
            self.root.path(),
            &self.profile,
            Some(&mut self.stack),
            &TeamRemovalOptions {
                delete_data: true,
                writers_stopped: true,
                reconcile,
                keep_backend: keep,
            },
        )
    }
}

/// Build a provider-like export from the public program, independently of the
/// removal validator. Negative cases then change individual AWS/checkpoint facts.
fn checkpoint(access: &AccessReceipt) -> Value {
    let program = access.request.render().unwrap();
    let values = program["resources"].as_object().unwrap();
    let mut replacements = BTreeMap::new();
    for (name, r) in values {
        let props = &r["properties"];
        if let Some(id) = props["name"].as_str().or(props["bucket"].as_str()) {
            for field in ["id", "name"] {
                replacements.insert(format!("${{{name}.{field}}}"), id.to_owned());
            }
            if ["aws:iam:Role", "aws:iam:Policy"].contains(&r["type"].as_str().unwrap()) {
                let kind = if r["type"] == "aws:iam:Role" {
                    "role"
                } else {
                    "policy"
                };
                replacements.insert(
                    format!("${{{name}.arn}}"),
                    format!(
                        "arn:aws:iam::123456789012:{kind}{}{id}",
                        props["path"].as_str().unwrap()
                    ),
                );
            }
        }
    }
    let stack = format!("zdn-{}", access.request.team.bootstrap_id.simple());
    let mut resources = Vec::new();
    for (name, r) in values {
        let kind = r["type"].as_str().unwrap();
        let parts: Vec<_> = kind.split(':').collect();
        let token = if kind == "pulumi:providers:aws" {
            kind.to_owned()
        } else {
            let title = parts[2];
            format!(
                "{}:{}/{}{}:{}",
                parts[0],
                parts[1],
                title[..1].to_ascii_lowercase(),
                &title[1..],
                title
            )
        };
        let mut encoded = serde_json::to_string(&r["properties"]).unwrap();
        for (key, value) in &replacements {
            encoded = encoded.replace(key, value);
        }
        encoded = encoded.replace("$${", "${");
        let inputs: Value = serde_json::from_str(&encoded).unwrap();
        let mut outputs = json!({});
        let id = match kind {
            "pulumi:providers:aws" => "provider-id".into(),
            "aws:iam:Policy" => {
                let arn = replacements[&format!("${{{name}.arn}}")].clone();
                outputs = json!({"arn":arn,"policyId":format!("policy-{name}")});
                arn
            }
            "aws:iam:Role" => {
                outputs = json!({"arn":replacements[&format!("${{{name}.arn}}")],"uniqueId":format!("role-{name}")});
                inputs["name"].as_str().unwrap().into()
            }
            "aws:iam:RolePolicy" => format!(
                "{}:{}",
                inputs["role"].as_str().unwrap(),
                inputs["name"].as_str().unwrap()
            ),
            "aws:iam:RolePolicyAttachment" => {
                format!("{}-attachment", inputs["role"].as_str().unwrap())
            }
            "aws:codebuild:Project" => format!(
                "arn:aws:codebuild:us-east-1:123456789012:project/{}",
                inputs["name"].as_str().unwrap()
            ),
            _ => inputs["name"]
                .as_str()
                .or(inputs["bucket"].as_str())
                .unwrap()
                .into(),
        };
        resources.push(json!({"urn":format!("urn:pulumi:{stack}::zdn-access::{token}::{name}"),"type":token,"id":id,
            "custom":true,"protect":kind.starts_with("aws:"),"inputs":inputs,"outputs":outputs}));
    }
    json!({"deployment":{"resources":resources}})
}

struct Stack {
    checkpoint: Option<Value>,
    alive: Rc<Cell<bool>>,
    mutations: usize,
    fail: bool,
    fail_unprotect: bool,
    partial: Vec<&'static str>,
    directory: PathBuf,
}
impl RemovalStack for Stack {
    fn checkpoint(&mut self) -> Result<Option<Value>> {
        Ok(self.checkpoint.clone())
    }
    fn unprotect(&mut self, urns: &[&str]) -> Result<()> {
        let saved: Value = foundation::read_json(&self.directory.join("removal.json"))?;
        assert_eq!(saved["uncertain"], true);
        assert!(!urns.is_empty());
        let expected: Vec<_> = self.checkpoint.as_ref().unwrap()["deployment"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["protect"] == true)
            .map(|r| r["urn"].as_str().unwrap())
            .collect();
        assert_eq!(urns, expected);
        self.mutations += 1;
        for r in self.checkpoint.as_mut().unwrap()["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
        {
            if urns.contains(&r["urn"].as_str().unwrap()) {
                r["protect"] = json!(false);
            }
        }
        if self.fail_unprotect {
            bail!("uncertain bulk unprotect reply");
        }
        Ok(())
    }
    fn destroy(&mut self) -> Result<()> {
        self.mutations += 1;
        if !self.partial.is_empty() {
            self.checkpoint.as_mut().unwrap()["deployment"]["resources"]
                .as_array_mut()
                .unwrap()
                .retain(|r| {
                    !self
                        .partial
                        .iter()
                        .any(|name| r["urn"].as_str().unwrap().ends_with(&format!("::{name}")))
                });
            bail!("interrupted provider destruction");
        }
        self.alive.set(false);
        self.checkpoint.as_mut().unwrap()["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["type"] == "pulumi:providers:aws");
        if self.fail {
            bail!("uncertain destroy reply");
        }
        Ok(())
    }
    fn remove(&mut self) -> Result<()> {
        self.mutations += 1;
        self.checkpoint = None;
        Ok(())
    }
}

struct Cloud {
    team: TeamDefinition,
    checkpoint: Value,
    alive: Rc<Cell<bool>>,
    backend: Cell<bool>,
    pending: Cell<bool>,
    calls: RefCell<Vec<String>>,
    fault: Option<&'static str>,
    objects: RefCell<Vec<Value>>,
    object_content: Value,
    fail_schedule: Cell<bool>,
    removed_configuration: Vec<&'static str>,
    build_objects: RefCell<Vec<Value>>,
}
impl Cloud {
    fn resources(&self) -> &[Value] {
        self.checkpoint["deployment"]["resources"]
            .as_array()
            .unwrap()
    }
    fn resource(&self, name: &str) -> &Value {
        self.resources()
            .iter()
            .find(|r| r["urn"].as_str().unwrap().ends_with(&format!("::{name}")))
            .unwrap()
    }
    fn tags(&self, bootstrap: bool, key: &str, val: &str) -> Value {
        let tags = if bootstrap {
            json!({"zdn:project":"zdn","zdn:team":self.team.team_id,"zdn:bootstrap":self.team.bootstrap_id})
        } else {
            json!({"zdn:managed-by":"zdn","zdn:team-id":self.team.team_id,"zdn:bootstrap":self.team.bootstrap_id})
        };
        json!(tags
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| json!({key:k,val:v}))
            .collect::<Vec<_>>())
    }
}
impl AwsApi for Cloud {
    fn batch_call(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        assert_eq!(service, "ec2");
        if calls.len() == 9 {
            // Network cleanup batches the narrower tagged inventory as well.
            for call in calls {
                let key = if call.operation == "describe-nat-gateways" {
                    "Filter"
                } else {
                    "Filters"
                };
                let filters = call.input[key].as_array().unwrap();
                assert_eq!(filters.len(), 3);
                assert_eq!(filters[0]["Name"], "tag:zdn:network-id");
                uuid::Uuid::parse_str(filters[0]["Values"][0].as_str().unwrap()).unwrap();
                assert_eq!(
                    filters[1],
                    json!({"Name":"tag:zdn:team-id","Values":[self.team.team_id]})
                );
                assert_eq!(
                    filters[2],
                    json!({"Name":"tag:zdn:managed-by","Values":["zdn"]})
                );
            }
            return Ok(calls
                .iter()
                .map(|call| {
                    self.call(
                        service,
                        call.operation,
                        call.input.clone(),
                        &call.extra_args,
                    )
                })
                .collect());
        }
        assert_eq!(
            calls.iter().map(|call| call.operation).collect::<Vec<_>>(),
            [
                "describe-instances",
                "describe-volumes",
                "describe-snapshots",
                "describe-vpcs",
                "describe-subnets",
                "describe-security-groups",
                "describe-route-tables",
                "describe-network-interfaces",
                "describe-internet-gateways",
                "describe-addresses",
                "describe-nat-gateways",
                "describe-vpc-endpoints",
            ]
        );
        for call in calls {
            assert!(call.extra_args.is_empty());
            let filter_key = if call.operation == "describe-nat-gateways" {
                "Filter"
            } else {
                "Filters"
            };
            let mut expected = json!({filter_key:[{"Name":"tag:zdn:bootstrap","Values":[self.team.bootstrap_id.to_string()]}]});
            if call.operation == "describe-snapshots" {
                expected["OwnerIds"] = json!([self.team.aws.account_id]);
            }
            assert_eq!(call.input, expected);
        }
        Ok(calls
            .iter()
            .map(|call| {
                self.call(
                    service,
                    call.operation,
                    call.input.clone(),
                    &call.extra_args,
                )
            })
            .collect())
    }

    fn call(&self, service: &str, op: &str, input: Value, extra: &[String]) -> Result<Value> {
        self.calls.borrow_mut().push(format!("{service}:{op}"));
        let build = BuildInfrastructure::for_team(&self.team)?;
        let bootstrap_bucket = input["Bucket"] == "zdn-remove-test";
        let mut value = match (service, op) {
            ("sts", "get-caller-identity") => {
                json!({"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/admin","UserId":"admin"})
            }
            ("s3api", "head-bucket") => {
                if !(if bootstrap_bucket {
                    self.backend.get()
                } else {
                    self.alive.get()
                }) {
                    return Err(error("NoSuchBucket"));
                }
                json!({})
            }
            ("s3api", "get-bucket-location") => json!({"LocationConstraint":null}),
            ("s3api", "get-bucket-tagging") => {
                json!({"TagSet":self.tags(bootstrap_bucket,"Key","Value")})
            }
            ("s3api", "get-bucket-versioning") => {
                json!({"Status":if !bootstrap_bucket && self.removed_configuration.contains(&"buildBucketVersioning") {"Suspended"} else {"Enabled"}})
            }
            ("s3api", "get-object-lock-configuration") => {
                return Err(error("ObjectLockConfigurationNotFoundError"))
            }
            ("s3api", "get-bucket-replication") => {
                return Err(error("ReplicationConfigurationNotFoundError"))
            }
            ("s3api", "get-bucket-policy") => {
                if bootstrap_bucket {
                    json!({"Policy":json!({"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::zdn-remove-test","arn:aws:s3:::zdn-remove-test/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}).to_string()})
                } else {
                    if self.removed_configuration.contains(&"buildBucketPolicy") {
                        return Err(error("NoSuchBucketPolicy"));
                    }
                    json!({"Policy":self.resource("buildBucketPolicy")["inputs"]["policy"]})
                }
            }
            ("s3api", "list-object-versions") => {
                assert_eq!(extra, ["--no-paginate"]);
                assert_eq!(input["ExpectedBucketOwner"], "123456789012");
                assert_eq!(input["MaxKeys"], 1000);
                let mut objects = if bootstrap_bucket {
                    self.objects.borrow().clone()
                } else {
                    self.build_objects.borrow().clone()
                };
                objects.sort_by(|a, b| a["Key"].as_str().cmp(&b["Key"].as_str()));
                let start = if input.get("KeyMarker").is_some() {
                    objects
                        .iter()
                        .position(|v| {
                            v["Key"] == input["KeyMarker"]
                                && v["VersionId"] == input["VersionIdMarker"]
                        })
                        .unwrap()
                        + 1
                } else {
                    0
                };
                let size = if self.fault == Some("short-pages") {
                    1
                } else {
                    1000
                };
                let end = (start + size).min(objects.len());
                let page = &objects[start..end];
                let mut value = json!({"IsTruncated":end < objects.len(),"Versions":page.iter().filter(|v|v["DeleteMarker"] != true).collect::<Vec<_>>(),
                    "DeleteMarkers":page.iter().filter(|v|v["DeleteMarker"] == true).collect::<Vec<_>>()});
                if end < objects.len() {
                    value["NextKeyMarker"] = objects[end - 1]["Key"].clone();
                    value["NextVersionIdMarker"] = objects[end - 1]["VersionId"].clone();
                    if self.fault == Some("missing-page-marker") {
                        value.as_object_mut().unwrap().remove("NextVersionIdMarker");
                    }
                    if self.fault == Some("repeated-page-marker") && start > 0 {
                        value["NextKeyMarker"] = input["KeyMarker"].clone();
                        value["NextVersionIdMarker"] = input["VersionIdMarker"].clone();
                    }
                    if self.fault == Some("duplicate-page-version") && start > 0 {
                        value["Versions"][0] = objects[0].clone();
                    }
                }
                value
            }
            ("s3api", "list-multipart-uploads") => json!({"IsTruncated":false,"Uploads":[]}),
            ("s3api", "get-object") => {
                assert_eq!(input["VersionId"], "backup-v1");
                fs::write(&extra[0], serde_json::to_vec(&self.object_content)?)?;
                json!({"VersionId":"backup-v1"})
            }
            ("s3api", "delete-objects") => {
                assert_eq!(input["ExpectedBucketOwner"], "123456789012");
                if self.fault == Some("partial-delete") {
                    json!({"Errors":[{"Code":"AccessDenied"}]})
                } else {
                    let objects = if bootstrap_bucket {
                        &self.objects
                    } else {
                        &self.build_objects
                    };
                    let deleted = input["Delete"]["Objects"].as_array().unwrap();
                    if deleted.iter().any(|d| {
                        objects.borrow().iter().any(|v| {
                            v["Key"] == d["Key"]
                                && v["VersionId"] == d["VersionId"]
                                && v["IsLatest"] == true
                        })
                    }) {
                        assert!(
                            !objects.borrow().iter().any(|v| v["IsLatest"] == false),
                            "old versions must be acknowledged before current versions are deleted"
                        );
                    }
                    objects.borrow_mut().retain(|v| {
                        !deleted
                            .iter()
                            .any(|d| d["Key"] == v["Key"] && d["VersionId"] == v["VersionId"])
                    });
                    if self.fault == Some("lost-old-delete")
                        && deleted.iter().any(|d| d["VersionId"] == "old")
                    {
                        return Err(error("TransportError"));
                    }
                    if self.fault == Some("missing-delete-ack") {
                        return Ok(json!({}));
                    }
                    json!({"Deleted":input["Delete"]["Objects"]})
                }
            }
            ("s3api", "delete-bucket") => {
                assert!(bootstrap_bucket);
                assert!(self.objects.borrow().is_empty());
                assert!(!self.alive.get());
                self.backend.set(false);
                json!({})
            }
            ("kms", "describe-key") => {
                json!({"KeyMetadata":{"Arn":self.team.state.kms_key_arn,"AWSAccountId":"123456789012","KeyManager":"CUSTOMER","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","KeyState":if self.pending.get(){"PendingDeletion"}else{"Enabled"},"DeletionDate":if self.pending.get(){json!(1900000000)}else{Value::Null}}})
            }
            ("kms", "list-resource-tags") => json!({"Tags":self.tags(true,"TagKey","TagValue")}),
            ("kms", "list-aliases") => json!({"Aliases":[]}),
            ("kms", "list-grants") => json!({"Grants":[]}),
            ("kms", "get-key-policy") => {
                json!({"Policy":json!({"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}]}).to_string()})
            }
            ("kms", "schedule-key-deletion") => {
                assert!(!self.backend.get());
                self.pending.set(true);
                if self.fail_schedule.replace(false) {
                    return Err(error("TransportError"));
                }
                json!({"DeletionDate":1900000000})
            }
            ("iam", "list-roles") => json!({"Roles":[]}),
            ("iam", "list-policies") => json!({"Policies":[]}),
            ("iam", "list-instance-profiles") | ("iam", "list-instance-profiles-for-role") => {
                json!({"InstanceProfiles":[]})
            }
            ("iam", "get-role") => {
                if !self.alive.get() {
                    return Err(error("NoSuchEntity"));
                }
                let Some(r) = self
                    .resources()
                    .iter()
                    .find(|r| r["type"] == "aws:iam/role:Role" && r["id"] == input["RoleName"])
                else {
                    return Err(error("NoSuchEntity"));
                };
                json!({"Role":{"Arn":r["outputs"]["arn"],"RoleId":r["outputs"]["uniqueId"],"Path":r["inputs"]["path"],"Tags":self.tags(false,"Key","Value"),"AssumeRolePolicyDocument":serde_json::from_str::<Value>(r["inputs"]["assumeRolePolicy"].as_str().unwrap())?}})
            }
            ("iam", "list-role-policies") => {
                json!({"PolicyNames":self.resources().iter().filter(|r|r["type"] == "aws:iam/rolePolicy:RolePolicy" && r["inputs"]["role"] == input["RoleName"]).map(|r|r["inputs"]["name"].clone()).collect::<Vec<_>>()})
            }
            ("iam", "get-role-policy") => {
                json!({"PolicyDocument":serde_json::from_str::<Value>(self.resource("buildServicePolicy")["inputs"]["policy"].as_str().unwrap())?})
            }
            ("iam", "list-attached-role-policies") => {
                json!({"AttachedPolicies":self.resources().iter().filter(|r|r["type"] == "aws:iam/rolePolicyAttachment:RolePolicyAttachment" && r["inputs"]["role"] == input["RoleName"]).map(|r|json!({"PolicyArn":r["inputs"]["policyArn"]})).collect::<Vec<_>>()})
            }
            ("iam", "get-policy") => {
                if !self.alive.get() {
                    return Err(error("NoSuchEntity"));
                }
                let r = self
                    .resources()
                    .iter()
                    .find(|r| r["id"] == input["PolicyArn"])
                    .unwrap();
                json!({"Policy":{"Arn":r["id"],"PolicyId":r["outputs"]["policyId"],"Path":r["inputs"]["path"],"DefaultVersionId":"v1"}})
            }
            ("iam", "get-policy-version") => {
                let r = self
                    .resources()
                    .iter()
                    .find(|r| r["id"] == input["PolicyArn"])
                    .unwrap();
                json!({"PolicyVersion":{"Document":serde_json::from_str::<Value>(r["inputs"]["policy"].as_str().unwrap())?}})
            }
            ("iam", "list-entities-for-policy") => {
                json!({"PolicyUsers":[],"PolicyGroups":[],"PolicyRoles":[]})
            }
            ("codebuild", "list-builds-for-project") => {
                json!({"ids":if self.fault == Some("active-build") {json!([format!("{}:unknown",build.project_name)])} else {json!([])}})
            }
            ("codebuild", "batch-get-projects") => {
                assert_eq!(input["names"], json!([build.project_name]));
                if !self.alive.get() {
                    json!({"projects":[],"projectsNotFound":[build.project_name]})
                } else {
                    let r = &self.resource("buildProject")["inputs"];
                    json!({"projectsNotFound":[],"projects":[{"name":build.project_name,"arn":format!("arn:aws:codebuild:us-east-1:123456789012:project/{}",build.project_name),"serviceRole":r["serviceRole"],"cache":r["cache"],"created":"2026-10-19T00:00:00Z","logsConfig":{"cloudWatchLogs":{"groupName":format!("/aws/codebuild/{}",build.project_name)}},"tags":self.tags(false,"key","value")} ]})
                }
            }
            ("ecr", "list-images") => {
                if !self.alive.get() {
                    return Err(error("RepositoryNotFoundException"));
                }
                json!({"imageIds":[]})
            }
            ("ecr", "describe-repositories") => {
                if !self.alive.get() {
                    return Err(error("RepositoryNotFoundException"));
                }
                json!({"repositories":[{"repositoryArn":format!("arn:aws:ecr:us-east-1:123456789012:repository/{}",build.repository),"registryId":"123456789012","repositoryName":build.repository,"repositoryUri":build.repository_uri,"createdAt":1234}]})
            }
            ("ecr", "list-tags-for-resource") => json!({"tags":self.tags(false,"Key","Value")}),
            ("ecr", "get-repository-policy") => {
                if self.fault == Some("repository-policy") {
                    json!({"policyText":"foreign"})
                } else {
                    return Err(error("RepositoryPolicyNotFoundException"));
                }
            }
            ("logs", "describe-log-groups") => {
                json!({"logGroups":if self.alive.get(){json!([{"logGroupName":format!("/aws/codebuild/{}",build.project_name),"retentionInDays":30,"creationTime":1234}])}else{json!([])}})
            }
            ("logs", "list-tags-log-group") => {
                json!({"tags":self.resource("buildLogs")["inputs"]["tags"]})
            }
            ("iam", "get-instance-profile") => return Err(error("NoSuchEntity")),
            ("ssm", "describe-document") => {
                if self.fault == Some("document-error") {
                    return Err(error("InvalidClientTokenId"));
                }
                if self.fault == Some("orphan-document")
                    || (self.fault == Some("orphan-node-document")
                        && input["Name"].as_str().unwrap().ends_with("node-rpc-v1"))
                    || (self.fault == Some("orphan-lightwallet-document")
                        && input["Name"]
                            .as_str()
                            .unwrap()
                            .ends_with("lightwallet-grpc-v1"))
                {
                    json!({})
                } else {
                    return Err(error("InvalidDocument"));
                }
            }
            ("ssm", "describe-sessions") => match self.fault {
                Some("active-session") => json!({"Sessions":[{"SessionId":"still-active"}]}),
                Some("truncated-sessions") => json!({"Sessions":[],"NextToken":"more"}),
                Some("malformed-sessions") => json!({}),
                Some("session-error") => return Err(error("AccessDenied")),
                _ => json!({"Sessions":[]}),
            },
            ("ec2", "describe-instances") if input.get("InstanceIds").is_some() => {
                assert!(input.get("Filters").is_none());
                assert_eq!(input["InstanceIds"].as_array().unwrap().len(), 1);
                let record = json!({"InstanceId":input["InstanceIds"][0],"State":{"Name":"terminated","Code":48}});
                match self.fault {
                    Some("exact-live") => {
                        return Ok(
                            json!({"Reservations":[{"Instances":[{"InstanceId":input["InstanceIds"][0],"State":{"Name":"running","Code":16}}]}]}),
                        )
                    }
                    Some("exact-stopped") => {
                        return Ok(
                            json!({"Reservations":[{"Instances":[{"InstanceId":input["InstanceIds"][0],"State":{"Name":"stopped","Code":80}}]}]}),
                        )
                    }
                    Some("exact-shutting-down") => {
                        return Ok(
                            json!({"Reservations":[{"Instances":[{"InstanceId":input["InstanceIds"][0],"State":{"Name":"shutting-down","Code":32}}]}]}),
                        )
                    }
                    Some("exact-empty") => return Ok(json!({"Reservations":[]})),
                    Some("exact-malformed") => {
                        return Ok(
                            json!({"Reservations":[{"Instances":[{"InstanceId":input["InstanceIds"][0],"State":{"Name":"terminated"}}]}]}),
                        )
                    }
                    Some("exact-wrong") => {
                        return Ok(
                            json!({"Reservations":[{"Instances":[{"InstanceId":"i-00000000000000999","State":{"Name":"terminated","Code":48}}]}]}),
                        )
                    }
                    Some("exact-truncated") => {
                        return Ok(
                            json!({"NextToken":"more","Reservations":[{"Instances":[record]}]}),
                        )
                    }
                    Some("exact-error") => return Err(error("AccessDenied")),
                    Some("exact-invalid-token") => return Err(error("InvalidClientTokenId")),
                    Some("exact-absent") => return Err(error("InvalidInstanceID.NotFound")),
                    _ => json!({"Reservations":[{"Instances":[record]}]}),
                }
            }
            ("ec2", _) => {
                let field = match op {
                    "describe-instances" => "Reservations",
                    "describe-volumes" => "Volumes",
                    "describe-snapshots" => "Snapshots",
                    "describe-vpcs" => "Vpcs",
                    "describe-subnets" => "Subnets",
                    "describe-security-groups" => "SecurityGroups",
                    "describe-route-tables" => "RouteTables",
                    "describe-network-interfaces" => "NetworkInterfaces",
                    "describe-internet-gateways" => "InternetGateways",
                    "describe-addresses" => "Addresses",
                    "describe-nat-gateways" => "NatGateways",
                    "describe-vpc-endpoints" => "VpcEndpoints",
                    _ => panic!("unknown EC2 {op}"),
                };
                if field == "Volumes" {
                    match self.fault {
                        Some("inventory-error") => return Err(error("AccessDenied")),
                        Some("inventory-pagination") => {
                            return Ok(json!({field:[],"NextToken":"more"}))
                        }
                        Some("inventory-malformed") => return Ok(json!({field:{}})),
                        _ => {}
                    }
                }
                json!({field:if self.fault == Some("active-network") && field == "Volumes" {json!([{"VolumeId":"i-owned"}])} else {json!([])}})
            }
            _ => panic!("unexpected API {service} {op}"),
        };
        if self.fault == Some("foreign-consumer") && op == "list-entities-for-policy" {
            value["PolicyRoles"] = json!([{"RoleName":"shared-control"}]);
        }
        if self.fault == Some("replaced-role") && op == "get-role" {
            value["Role"]["RoleId"] = json!("replacement");
        }
        if self.fault == Some("unknown-policy") && op == "list-policies" {
            value["Policies"] = json!([{"Path":"/foreign/","PolicyName":"foreign"}]);
        }
        if self.fault == Some("truncated") && op == "list-object-versions" {
            value["IsTruncated"] = json!(true);
        }
        if self.fault == Some("key-alias") && op == "list-aliases" {
            value["Aliases"] = json!([{"AliasName":"alias/foreign"}]);
        }
        if self.fault == Some("key-grant") && op == "list-grants" {
            value["Grants"] = json!([{"GrantId":"foreign"}]);
        }
        if self.fault == Some("key-policy") && op == "get-key-policy" {
            value["Policy"] = json!("{}");
        }
        Ok(value)
    }
}

#[test]
fn managed_team_removal_preserves_receipts_and_reports_kms_pending_even_on_repeat() {
    let mut f = Fixture::new();
    let before = fs::read(&f.profile).unwrap();
    let result = f.remove(false, false).unwrap();
    assert_eq!(result["status"], "kms-deletion-pending");
    assert_eq!(result["kmsDeleted"], false);
    assert_eq!(result["kmsDeletionDate"], 1900000000);
    assert!(!f.api.alive.get() && !f.api.backend.get());
    assert_eq!(f.stack.mutations, 3); // one bulk unprotect, destroy, remove
    let mutations = f.stack.mutations;
    f.remove(false, false).unwrap();
    assert_eq!(f.stack.mutations, mutations);
    assert_eq!(fs::read(&f.profile).unwrap(), before);
    assert_eq!(
        f.api
            .calls
            .borrow()
            .iter()
            .filter(|s| s.as_str() == "kms:schedule-key-deletion")
            .count(),
        1
    );
}

#[test]
fn provider_nested_default_metadata_does_not_hide_checkpoint_drift() {
    let f = Fixture::new();
    let mut checkpoint = f.api.checkpoint.clone();
    let repository = checkpoint["deployment"]["resources"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["type"] == "aws:ecr/repository:Repository")
        .unwrap();
    repository["inputs"]["encryptionConfigurations"][0]["__defaults"] = json!([]);
    repository["inputs"]["imageScanningConfiguration"]["__defaults"] = json!([]);
    removal::validate_access_checkpoint(&f.access, &checkpoint).unwrap();

    for (property, value) in [
        ("encryptionType", json!("KMS")),
        ("kmsKey", json!("foreign-key")),
        ("__defaults", json!(["encryptionType"])),
    ] {
        let mut changed = checkpoint.clone();
        let repository = changed["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["type"] == "aws:ecr/repository:Repository")
            .unwrap();
        repository["inputs"]["encryptionConfigurations"][0][property] = value;
        assert!(removal::validate_access_checkpoint(&f.access, &changed).is_err());
    }
    for foreign in ["name-only", "wrong-region", "wrong-account"] {
        let mut changed = checkpoint.clone();
        let project = changed["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["type"] == "aws:codebuild/project:Project")
            .unwrap();
        project["id"] = match foreign {
            "name-only" => project["inputs"]["name"].clone(),
            "wrong-region" => json!(project["id"]
                .as_str()
                .unwrap()
                .replace("us-east-1", "us-west-2")),
            _ => json!(project["id"]
                .as_str()
                .unwrap()
                .replace("123456789012", "999999999999")),
        };
        assert!(removal::validate_access_checkpoint(&f.access, &changed).is_err());
    }
}

fn removed_participant(f: &Fixture) -> PathBuf {
    use zdn::participant::{ParticipantReceipt, ParticipantRequest};
    let team = f.access.request.completed_team().unwrap();
    let request: ParticipantRequest = serde_json::from_value(json!({
        "team":team,"administrator":f.access.request.administrator,
        "trustedPrincipals":["arn:aws:iam::123456789012:user/developer"],
        "endpoints":{"apiVersion":"zdn-endpoints/v1alpha1",
            "networkId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec","scope":team.scope(),
            "bootstrapId":team.bootstrap_id,"consensusFingerprint":"ab".repeat(32),"nodeCount":1,
            "targets":[{"service":"node-rpc","nodeId":"node-1","instanceId":"i-00000000000000001"},
                {"service":"lightwallet-grpc","nodeId":"node-1","instanceId":"i-00000000000000001"}]}
    })).unwrap();
    request.validate().unwrap();
    let creation = ParticipantReceipt {
        version: 1,
        request: request.clone(),
        stack_started: true,
        uncertain: false,
        complete: true,
    };
    let ep = &request.endpoints;
    let program = request.render().unwrap();
    let prefix = format!("urn:pulumi:{}::zdn-participant::", request.stack_name());
    let checkpoint = json!({"deployment":{"resources":[
        {"urn":format!("{prefix}aws:iam/role:Role::participantRole"),"type":"aws:iam/role:Role","custom":true,"protect":true,
        "id":ep.participant_role_name(),"inputs":program["resources"]["participantRole"]["properties"],
        "outputs":{"uniqueId":"original-role","arn":ep.participant_role_arn()}}
    ]}});
    zdn::participant::validate_checkpoint(&request, &checkpoint).unwrap();
    let directory = f
        .root
        .path()
        .join("participants")
        .join(team.bootstrap_id.to_string())
        .join(ep.network_id.to_string());
    fs::create_dir_all(&directory).unwrap();
    foundation::write_json(&directory.join("participant.json"), &creation).unwrap();
    foundation::write_json(
        &directory.join("removal.json"),
        &json!({"version":1,"creation":creation,"checkpoint":checkpoint,
        "uncertain":false,"stackRemoved":true,"revocationVerified":false}),
    )
    .unwrap();
    directory
}

#[test]
fn team_removal_accepts_observed_unstarted_grant_closure_and_preflight_only_directories() {
    for has_receipt in [false, true] {
        let mut f = Fixture::new();
        let directory = removed_participant(&f);
        fs::remove_file(directory.join("removal.json")).unwrap();
        if has_receipt {
            let path = directory.join("participant.json");
            let mut creation: zdn::participant::ParticipantReceipt =
                foundation::read_json(&path).unwrap();
            creation.stack_started = false;
            creation.complete = false;
            foundation::write_json(&path, &creation).unwrap();
            assert!(f.remove(true, false).is_err());
            assert_eq!(f.stack.mutations, 0);
            let mut stack = Stack {
                checkpoint: None,
                alive: f.api.alive.clone(),
                mutations: 0,
                fail: false,
                fail_unprotect: false,
                partial: vec![],
                directory: directory.clone(),
            };
            let result =
                removal::remove_participant(&f.api, &directory, &mut stack, false, None).unwrap();
            assert_eq!(result["status"], "not-started");
            assert_eq!(stack.mutations, 0);
        } else {
            fs::remove_file(directory.join("participant.json")).unwrap();
            // CLI project preparation precedes read-only participant preflight.
            fs::create_dir(directory.join("project-v2")).unwrap();
        }
        f.remove(false, false).unwrap();
        assert!(!f.api.backend.get());
        f.remove(false, true).unwrap();
    }
}

#[test]
fn team_requires_fresh_exact_participant_closure_not_cached_token_denial() {
    let mut f = Fixture::new();
    let directory = removed_participant(&f);
    // No network outputs or tag inventory mention this participant's targets.
    let before = fs::read(directory.join("removal.json")).unwrap();
    let result = f.remove(true, false).unwrap();
    assert!(result["participantClosureScope"]
        .as_str()
        .unwrap()
        .contains("resource closure only"));
    let receipt_path = f.profile.with_extension("bootstrap.removal.json");
    let evidence: Value = foundation::read_json(&receipt_path).unwrap();
    assert!(evidence["localEvidence"]["networks"]
        .as_object()
        .unwrap()
        .is_empty());
    f.api.fault = Some("exact-absent");
    f.remove(false, false).unwrap();
    f.remove(false, true).unwrap();
    assert_eq!(fs::read(directory.join("removal.json")).unwrap(), before);
    let resumed: Value = foundation::read_json(&receipt_path).unwrap();
    assert_eq!(evidence["localEvidence"], resumed["localEvidence"]);
}

#[test]
fn team_resume_pins_cleanup_not_operation_ids_or_optional_revocation() {
    let mut f = Fixture::new();
    let participant = removed_participant(&f);
    let team = f.access.request.completed_team().unwrap();
    let mut network = foundation::Deployment::new(
        zdn::infra::FoundationSpec {
            scope: team.scope(),
            network_id: uuid::Uuid::new_v4(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: zdn::config::Size::Medium,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap();
    network.destroyed = true;
    network.last_operation = Some(uuid::Uuid::new_v4());
    network.cleanup = Some(foundation::CleanupReport {
        shared_backend_preserved: true,
        ..Default::default()
    });
    let file = foundation::DeploymentFile::open(f.root.path(), network.spec.network_id).unwrap();
    file.save(&network).unwrap();
    f.remove(true, false).unwrap();
    let receipt_path = f.profile.with_extension("bootstrap.removal.json");
    let saved: Value = foundation::read_json(&receipt_path).unwrap();

    // Repeated destroy writes a new operation ID before its first AWS read.
    // A later optional participant probe also changes bookkeeping, not ownership.
    network.last_operation = Some(uuid::Uuid::new_v4());
    file.save(&network).unwrap();
    let path = participant.join("removal.json");
    let mut removal: Value = foundation::read_json(&path).unwrap();
    removal["revocationVerified"] = json!(true);
    foundation::write_json(&path, &removal).unwrap();
    f.remove(true, false).unwrap();
    let resumed: Value = foundation::read_json(&receipt_path).unwrap();
    assert_eq!(saved["localEvidence"], resumed["localEvidence"]);

    // Neither changed ownership nor a failed live closure check is excused.
    let owner = network.owner_id;
    network.owner_id = uuid::Uuid::new_v4();
    file.save(&network).unwrap();
    assert!(f.remove(false, true).is_err());
    assert!(f.api.backend.get());
    network.owner_id = owner;
    file.save(&network).unwrap();
    f.api.fault = Some("exact-live");
    assert!(f.remove(false, true).is_err());
    assert!(f.api.backend.get());
    f.api.fault = None;
    f.remove(false, true).unwrap();
    assert!(!f.api.backend.get());
}

#[test]
fn exact_participant_observations_fail_closed_before_team_mutations_and_on_retry() {
    for fault in [
        "exact-live",
        "exact-stopped",
        "exact-shutting-down",
        "exact-empty",
        "exact-malformed",
        "exact-wrong",
        "exact-truncated",
        "exact-error",
        "exact-invalid-token",
        "orphan-document",
        "orphan-node-document",
        "orphan-lightwallet-document",
        "document-error",
        "active-session",
        "truncated-sessions",
        "malformed-sessions",
        "session-error",
    ] {
        let mut f = Fixture::new();
        removed_participant(&f);
        f.api.fault = Some(fault);
        assert!(f.remove(false, false).is_err(), "{fault}");
        assert_eq!(f.stack.mutations, 0, "{fault}");
        assert!(!f.profile.with_extension("bootstrap.removal.json").exists());
        f.api.fault = None;
        f.remove(true, false).unwrap();
        let mutations = f.stack.mutations;
        f.api.calls.borrow_mut().clear();
        f.api.fault = Some(fault);
        assert!(f.remove(false, true).is_err(), "retry {fault}");
        assert_eq!(f.stack.mutations, mutations);
        assert!(!f
            .api
            .calls
            .borrow()
            .iter()
            .any(|s| s.contains("delete-") || s.contains("schedule-")));
        f.api.fault = Some("exact-absent");
        f.remove(false, true).unwrap();
    }
}

#[test]
fn post_delete_invalid_client_token_reconciles_without_probe_or_recreation() {
    struct ParticipantCloud<'a> {
        admin: &'a Cloud,
        creation: zdn::participant::ParticipantReceipt,
        alive: Rc<Cell<bool>>,
    }
    impl AwsApi for ParticipantCloud<'_> {
        fn call(&self, service: &str, op: &str, input: Value, extra: &[String]) -> Result<Value> {
            let request = &self.creation.request;
            let ep = &request.endpoints;
            if service != "iam" {
                return self.admin.call(service, op, input, extra);
            }
            Ok(match op {
                "get-role" => {
                    if !self.alive.get() {
                        return Err(error("NoSuchEntity"));
                    }
                    let tags =
                        zdn::endpoints::ownership_tags(&ep.scope, ep.bootstrap_id, ep.network_id);
                    json!({"Role":{"RoleId":"original-role","Arn":ep.participant_role_arn(),
                        "RoleName":ep.participant_role_name(),"Path":ep.participant_role_path(),"MaxSessionDuration":3600,
                        "AssumeRolePolicyDocument":ep.participant_trust_policy(&request.trusted_principals)?,
                        "Tags":tags.as_object().unwrap().iter().map(|(k,v)|json!({"Key":k,"Value":v})).collect::<Vec<_>>()}})
                }
                "list-attached-role-policies" => json!({"AttachedPolicies":[]}),
                "list-role-policies" => json!({"PolicyNames":[zdn::participant::POLICY_NAME]}),
                "get-role-policy" => {
                    json!({"RoleName":ep.participant_role_name(),"PolicyName":zdn::participant::POLICY_NAME,
                    "PolicyDocument":ep.participant_policy()?})
                }
                "list-instance-profiles-for-role" => json!({"InstanceProfiles":[]}),
                _ => panic!("unexpected participant IAM operation {op}"),
            })
        }
    }
    struct InvalidToken;
    impl AwsApi for InvalidToken {
        fn call(&self, service: &str, op: &str, _: Value, _: &[String]) -> Result<Value> {
            assert_eq!((service, op), ("sts", "get-caller-identity"));
            Err(error("InvalidClientTokenId"))
        }
    }
    let mut f = Fixture::new();
    let directory = removed_participant(&f);
    let path = directory.join("removal.json");
    let saved: Value = foundation::read_json(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let cloud = ParticipantCloud {
        admin: &f.api,
        creation: foundation::read_json(&directory.join("participant.json")).unwrap(),
        alive: Rc::new(Cell::new(true)),
    };
    let mut stack = Stack {
        checkpoint: Some(saved["checkpoint"].clone()),
        alive: cloud.alive.clone(),
        mutations: 0,
        fail: false,
        fail_unprotect: false,
        partial: Vec::new(),
        directory: directory.clone(),
    };
    assert!(removal::remove_participant(
        &cloud,
        &directory,
        &mut stack,
        false,
        Some(&InvalidToken)
    )
    .is_err());
    assert!(stack.checkpoint.is_none());
    assert!(!cloud.alive.get());
    assert_eq!(stack.mutations, 3); // unprotect, destroy role, remove stack, then STS fails
    let receipt: Value = foundation::read_json(&directory.join("removal.json")).unwrap();
    assert_eq!(receipt["stackRemoved"], true);
    assert_eq!(receipt["uncertain"], true);
    assert_eq!(receipt["revocationVerified"], false);
    assert!(removal::remove_participant(&cloud, &directory, &mut stack, false, None).is_err());
    let result = removal::remove_participant(&cloud, &directory, &mut stack, true, None).unwrap();
    assert_eq!(result["status"], "revocation-pending");
    assert_eq!(result["revocationVerified"], false);
    assert_eq!(stack.mutations, 3);
    f.remove(false, false).unwrap();
}

#[test]
fn team_validates_participant_requests_and_saved_checkpoints_before_mutation() {
    for mode in ["request", "checkpoint", "creation", "stack-pending"] {
        let mut f = Fixture::new();
        let directory = removed_participant(&f);
        let path = directory.join("removal.json");
        let mut saved: Value = foundation::read_json(&path).unwrap();
        match mode {
            "request" => {
                let creation_path = directory.join("participant.json");
                let mut creation: Value = foundation::read_json(&creation_path).unwrap();
                creation["request"]["endpoints"]["targets"][0]["instanceId"] = json!("malformed");
                foundation::write_json(&creation_path, &creation).unwrap();
                saved["creation"] = creation;
            }
            "checkpoint" => saved["checkpoint"]["deployment"]["pending_operations"] = json!([{}]),
            "creation" => saved["creation"]["complete"] = json!(false),
            _ => saved["stackRemoved"] = json!(false),
        }
        foundation::write_json(&path, &saved).unwrap();
        assert!(f.remove(false, false).is_err(), "{mode}");
        assert_eq!(f.stack.mutations, 0);
        assert!(!f.profile.with_extension("bootstrap.removal.json").exists());
    }
}

#[test]
fn interrupted_provider_configuration_deletion_resumes_only_with_exact_checkpoint_evidence() {
    for deleted in [
        vec!["buildBucketPolicy"],
        vec!["buildBucketVersioning"],
        vec!["buildBucketPolicy", "buildBucketVersioning"],
    ] {
        let mut f = Fixture::new();
        f.stack.partial = deleted.clone();
        assert!(f.remove(true, false).is_err());
        f.api.removed_configuration = deleted.clone();
        f.stack.partial.clear();
        assert_eq!(f.remove(true, true).unwrap()["backendRemoved"], false);
        f.remove(false, false).unwrap();
        assert!(f.api.pending.get());

        // The same live absence without any removal receipt is not authority.
        let mut f = Fixture::new();
        f.api.removed_configuration = deleted.clone();
        assert!(f.remove(true, false).is_err());
        assert_eq!(f.stack.mutations, 0);

        // Nor does a removal receipt authorize config still in the checkpoint.
        let mut f = Fixture::new();
        f.stack.partial = vec!["buildLogs"];
        assert!(f.remove(true, false).is_err());
        f.api.removed_configuration = deleted.clone();
        f.api.calls.borrow_mut().clear();
        let before = f.stack.mutations;
        assert!(f.remove(true, true).is_err());
        assert_eq!(f.stack.mutations, before);
        assert!(!f.api.calls.borrow().iter().any(|s| s.contains("delete-")));

        let mut f = Fixture::new();
        f.stack.partial = deleted.clone();
        assert!(f.remove(true, false).is_err());
        f.api.removed_configuration = deleted;
        *f.api.build_objects.borrow_mut() =
            vec![json!({"Key":"foreign","VersionId":"v1","IsLatest":true})];
        f.api.calls.borrow_mut().clear();
        let before = f.stack.mutations;
        assert!(f
            .remove(true, true)
            .unwrap_err()
            .to_string()
            .contains("surviving build bucket must be empty"));
        assert_eq!(f.stack.mutations, before);
        assert!(!f.api.calls.borrow().iter().any(|s| s.contains("delete-")));
    }
    for (deleted, drift) in [
        ("buildBucketPolicy", "buildBucketVersioning"),
        ("buildBucketVersioning", "buildBucketPolicy"),
    ] {
        let mut f = Fixture::new();
        f.stack.partial = vec![deleted];
        assert!(f.remove(true, false).is_err());
        f.api.removed_configuration = vec![drift];
        f.api.calls.borrow_mut().clear();
        let before = f.stack.mutations;
        assert!(f.remove(true, true).is_err());
        assert_eq!(f.stack.mutations, before);
        assert!(!f.api.calls.borrow().iter().any(|s| s.contains("delete-")));
    }
}

#[test]
fn resumed_team_preflight_rejects_repository_and_key_consumers_without_mutation() {
    for fault in ["repository-policy", "key-policy", "key-alias", "key-grant"] {
        for keep in [false, true] {
            let mut f = Fixture::new();
            f.stack.partial = vec!["buildBucketPolicy"];
            assert!(f.remove(true, false).is_err());
            f.api.removed_configuration = vec!["buildBucketPolicy"];
            f.api.fault = Some(fault);
            f.api.calls.borrow_mut().clear();
            let before = f.stack.mutations;
            assert!(f.remove(keep, true).is_err(), "{fault}");
            assert_eq!(f.stack.mutations, before, "{fault}");
            assert!(
                !f.api
                    .calls
                    .borrow()
                    .iter()
                    .any(|s| s.contains("delete-") || s.contains("schedule-")),
                "{fault}"
            );
            assert!(f.api.backend.get());
        }
    }
    // A clean keep-backend completion must not bypass key validation later.
    for fault in ["key-policy", "key-alias", "key-grant"] {
        for keep in [false, true] {
            let mut f = Fixture::new();
            f.remove(true, false).unwrap();
            f.api.fault = Some(fault);
            f.api.calls.borrow_mut().clear();
            assert!(f.remove(keep, false).is_err(), "{fault}");
            assert!(!f
                .api
                .calls
                .borrow()
                .iter()
                .any(|s| s.contains("delete-") || s.contains("schedule-")));
            assert!(f.api.backend.get());
        }
    }
}

#[test]
fn active_unknown_and_foreign_resources_block_all_cloud_and_pulumi_mutations() {
    for fault in [
        "active-network",
        "inventory-error",
        "inventory-pagination",
        "inventory-malformed",
        "active-build",
        "foreign-consumer",
        "replaced-role",
        "unknown-policy",
        "truncated",
        "repository-policy",
    ] {
        let mut f = Fixture::new();
        f.api.fault = Some(fault);
        assert!(f.remove(false, false).is_err(), "{fault}");
        assert_eq!(f.stack.mutations, 0, "{fault}");
        assert!(
            !f.api
                .calls
                .borrow()
                .iter()
                .any(|s| s.contains("delete-") || s.contains("schedule-")),
            "{fault}"
        );
    }
}

#[test]
fn imported_profile_and_changed_checkpoint_are_not_creation_authority() {
    let mut f = Fixture::new();
    fs::remove_file(f.profile.with_extension("bootstrap.json")).unwrap();
    assert!(removal::team_plan(&f.profile).is_err());
    assert!(f.remove(false, false).is_err());
    assert!(f.api.calls.borrow().is_empty());
    let mut f = Fixture::new();
    f.stack.checkpoint.as_mut().unwrap()["deployment"]["resources"][0]["id"] = json!("foreign");
    assert!(f.remove(false, false).is_err());
    assert_eq!(f.stack.mutations, 0);
}

#[test]
fn network_receipts_data_and_fixed_documents_are_rechecked_before_team_mutation() {
    use sha2::Digest;
    for mode in 0..5 {
        let mut f = Fixture::new();
        let team = f.access.request.completed_team().unwrap();
        let spec = zdn::infra::FoundationSpec {
            scope: team.scope(),
            network_id: uuid::Uuid::new_v4(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: zdn::config::Size::Medium,
            retain_chain_disk: true,
        };
        let mut network = foundation::Deployment::new(spec, team).unwrap();
        network.destroyed = mode != 1;
        network.cleanup = Some(foundation::CleanupReport {
            shared_backend_preserved: true,
            retained_volumes: if mode == 2 {
                vec!["vol-retained".into()]
            } else {
                vec![]
            },
            ..Default::default()
        });
        let file =
            foundation::DeploymentFile::open(f.root.path(), network.spec.network_id).unwrap();
        file.save(&network).unwrap();
        if matches!(mode, 0 | 4) {
            let mut helper = [0; 64];
            helper[..6].copy_from_slice(b"\x7fELF\x02\x01");
            helper[16] = 2;
            helper[18] = 62;
            let input = f.root.path().join("exporter");
            fs::write(&input, helper).unwrap();
            let contract = zdn::build::BuildContract {
                api_version: zdn::build::API_VERSION.into(),
                source_sha256: "a".repeat(64),
                source_bytes: 1,
                revision: "b".repeat(40),
                recipe: zdn::build::BuildRecipe {
                    dockerfile: "Dockerfile".into(),
                    context: ".".into(),
                    target: "runtime".into(),
                },
                platform: "linux/amd64".into(),
                required_capabilities: Default::default(),
            };
            let update = file
                .directory()
                .join("updates")
                .join(uuid::Uuid::new_v4().to_string());
            foundation::private_directory(update.parent().unwrap()).unwrap();
            foundation::private_directory(&update).unwrap();
            zdn::build_job::prepare_native(&update.join("build"), &network.team, &contract, &input)
                .unwrap();
            let attempt: Value = foundation::read_json(&update.join("build/attempt.json")).unwrap();
            let hash = hex::encode(sha2::Sha256::digest(helper));
            // A lost upload reply can leave an owned helper object even with
            // no saved version and no dispatched build. Own only this attempt.
            f.api.build_objects.borrow_mut().push(json!({"Key":format!("sources/runtime/{}/{hash}",attempt["attemptId"].as_str().unwrap()),"VersionId":"runtime-version","IsLatest":true}));
            if mode == 4 {
                f.api.build_objects.borrow_mut().push(json!({"Key":format!("sources/runtime/{}/{hash}",uuid::Uuid::new_v4()),"VersionId":"foreign-version","IsLatest":true}));
            }
        }
        drop(file);
        if mode == 3 {
            f.api.fault = Some("orphan-document");
        }
        let result = f.remove(true, false);
        if mode == 0 {
            assert_eq!(
                result.unwrap()["status"],
                "access-removed-backend-preserved"
            );
            assert!(f.api.build_objects.borrow().is_empty());
        } else {
            assert!(result.is_err(), "{mode}");
            assert_eq!(f.stack.mutations, 0, "{mode}");
            assert!(!f
                .api
                .calls
                .borrow()
                .iter()
                .any(|s| s.contains("delete-") || s.contains("schedule-")));
        }
    }
}

#[test]
fn original_backend_creation_does_not_adopt_external_deployment_roles() {
    let mut f = Fixture::new();
    let external = zdn::access::DeploymentAccess {
        role_arn: "arn:aws:iam::123456789012:role/shared/deploy".into(),
        runtime_boundary_arn: "arn:aws:iam::123456789012:policy/shared/runtime".into(),
        management: zdn::access::RoleManagement::External,
    };
    f.access.request.existing = Some(external.clone());
    f.access.selected_access = Some(external);
    foundation::write_json(
        &f.profile.with_extension("access").join("access.json"),
        &f.access,
    )
    .unwrap();
    foundation::write_json(
        &f.profile,
        &LocalProfile {
            team: f.access.request.completed_team().unwrap(),
            aws_profile: "developer".into(),
        },
    )
    .unwrap();
    // No product-owned administrator/build stack was created for external roles.
    f.api.alive.set(false);
    let result = f.remove(false, false).unwrap();
    assert_eq!(result["externalRolesPreserved"], true);
    assert_eq!(f.stack.mutations, 0);
    assert!(!f
        .api
        .calls
        .borrow()
        .iter()
        .any(|call| call == "iam:get-role" || call == "iam:get-policy"));
}

#[test]
fn bulk_unprotect_failure_preserves_uncertainty_and_requires_reconciliation() {
    let mut f = Fixture::new();
    f.stack.fail_unprotect = true;
    assert!(f.remove(true, false).is_err());
    assert_eq!(f.stack.mutations, 1);
    assert!(f.api.alive.get());
    let receipt: Value = foundation::read_json(&f.stack.directory.join("removal.json")).unwrap();
    assert_eq!(receipt["uncertain"], true);
    assert_eq!(receipt["stackRemoved"], false);
    assert!(f.remove(true, false).is_err());
    assert_eq!(f.stack.mutations, 1);
    f.stack.fail_unprotect = false;
    f.remove(true, true).unwrap();
    // Protection was cleared despite the lost reply: no empty unprotect batch.
    assert_eq!(f.stack.mutations, 3);
}

#[test]
fn access_only_boundary_and_uncertain_destroy_are_recoverable_without_refresh() {
    let mut f = Fixture::new();
    f.stack.fail = true;
    assert!(f.remove(true, false).is_err());
    let count = f.stack.mutations;
    assert!(f.remove(true, false).is_err());
    assert_eq!(f.stack.mutations, count);
    f.stack.fail = false;
    let result = f.remove(true, true).unwrap();
    assert_eq!(result["backendRemoved"], false);
    assert!(f.api.backend.get());
    assert!(!f.api.pending.get());
    f.remove(false, false).unwrap();
    assert!(f.api.pending.get());
}

#[test]
fn lost_kms_schedule_reply_reconciles_observed_pending_date_without_rescheduling() {
    let mut f = Fixture::new();
    f.api.fail_schedule.set(true);
    assert!(f.remove(false, false).is_err());
    assert!(f.remove(false, false).is_err());
    let result = f.remove(false, true).unwrap();
    assert_eq!(result["kmsDeletionDate"], 1900000000);
    assert_eq!(
        f.api
            .calls
            .borrow()
            .iter()
            .filter(|s| s.as_str() == "kms:schedule-key-deletion")
            .count(),
        1
    );
}

#[test]
fn current_backup_requires_exact_empty_inspection_and_partial_s3_delete_is_not_success() {
    for contents in [json!([]), json!([{"type":"aws:ec2/instance:Instance"}])] {
        let mut f = Fixture::new();
        let stack = format!("zdn-{}", f.access.request.team.bootstrap_id.simple());
        let key = format!(
            "zdn-admin/v1/{}/.pulumi/stacks/zdn-access/{stack}.json.bak",
            f.access.request.team.bootstrap_id
        );
        f.api
            .objects
            .borrow_mut()
            .push(json!({"Key":key,"VersionId":"backup-v1","IsLatest":true}));
        f.api.object_content = json!({"version":3,"checkpoint":{"stack":format!("organization/zdn-access/{stack}"),"latest":{"resources":contents}}});
        f.api.fault = Some("partial-delete");
        assert!(f.remove(false, false).is_err());
        assert!(f.api.backend.get());
        assert!(!f.api.pending.get());
        if contents.as_array().unwrap().is_empty() {
            assert!(f
                .api
                .calls
                .borrow()
                .iter()
                .any(|s| s == "s3api:delete-objects"));
        } else {
            assert!(!f
                .api
                .calls
                .borrow()
                .iter()
                .any(|s| s == "s3api:delete-objects"));
        }
    }
}

#[test]
fn lock_history_is_owned_but_current_locks_unknown_keys_and_ambiguous_versions_refuse() {
    for mode in 0..5 {
        let mut f = Fixture::new();
        let boot = f.access.request.team.bootstrap_id;
        let key = format!(
            "zdn-admin/v1/{boot}/.pulumi/locks/organization/zdn-access/zdn-{}/controller.json",
            boot.simple()
        );
        let mut objects = vec![
            json!({"Key":key,"VersionId":"old","IsLatest":false}),
            json!({"Key":key,"VersionId":"marker","IsLatest":true,"DeleteMarker":true}),
        ];
        match mode {
            1 => {
                objects.remove(1);
                objects[0]["IsLatest"] = json!(true);
            }
            2 => objects[0]["Key"] = json!("unexplained/shared-data"),
            3 => {
                objects[0].as_object_mut().unwrap().remove("IsLatest");
            }
            4 => objects[0]["IsLatest"] = json!(true),
            _ => {}
        }
        *f.api.objects.borrow_mut() = objects;
        if mode == 0 {
            assert_eq!(f.remove(false, false).unwrap()["backendRemoved"], true);
        } else {
            assert!(f.remove(false, false).is_err(), "{mode}");
            assert_eq!(f.stack.mutations, 0, "{mode}");
            assert!(f.api.backend.get());
        }
    }
}

#[test]
fn paginated_team_history_is_validated_completely_before_removal() {
    for fault in [
        None,
        Some("foreign-tail"),
        Some("missing-page-marker"),
        Some("repeated-page-marker"),
        Some("duplicate-page-version"),
        Some("short-pages"),
    ] {
        let mut f = Fixture::new();
        let boot = f.access.request.team.bootstrap_id;
        let key = format!(
            "zdn-admin/v1/{boot}/.pulumi/locks/organization/zdn-access/zdn-{}/controller.json",
            boot.simple()
        );
        let mut objects: Vec<_> = (0..2004)
            .map(|i| json!({"Key":key,"VersionId":format!("old-{i}"),"IsLatest":false}))
            .collect();
        objects.push(json!({"Key":key,"VersionId":"marker","IsLatest":true,"DeleteMarker":true}));
        if fault == Some("foreign-tail") {
            objects.push(json!({"Key":"zz-foreign/data","VersionId":"foreign","IsLatest":true}));
        } else {
            f.api.fault = fault;
        }
        *f.api.objects.borrow_mut() = objects;
        if fault.is_none() {
            assert_eq!(f.remove(false, false).unwrap()["backendRemoved"], true);
            assert!(f.api.objects.borrow().is_empty());
        } else {
            assert!(f.remove(false, false).is_err(), "{fault:?}");
            assert_eq!(f.stack.mutations, 0, "{fault:?}");
            assert!(f.api.backend.get() && f.api.alive.get());
            assert!(!f
                .api
                .calls
                .borrow()
                .iter()
                .any(|c| c == "s3api:delete-objects"));
        }
    }
}

#[test]
fn paginated_history_refuses_aggregate_overflow_before_removal() {
    for count in [10_000, 10_001] {
        let mut f = Fixture::new();
        let boot = f.access.request.team.bootstrap_id;
        let key = format!(
            "zdn-admin/v1/{boot}/.pulumi/locks/organization/zdn-access/zdn-{}/controller.json",
            boot.simple()
        );
        *f.api.objects.borrow_mut() = (0..count).map(|i| json!({"Key":key,"VersionId":format!("v{i}"),"IsLatest":i == 0,"DeleteMarker":i == 0})).collect();
        if count == 10_000 {
            assert_eq!(f.remove(false, false).unwrap()["backendRemoved"], true);
            assert!(f.api.objects.borrow().is_empty());
        } else {
            let error = f.remove(false, false).unwrap_err();
            assert!(error.to_string().contains("10000-version bound"));
            assert_eq!(f.stack.mutations, 0);
            assert!(f.api.backend.get() && f.api.alive.get());
        }
    }
}

#[test]
fn interrupted_version_purge_keeps_current_empty_checkpoint_and_requires_reconciliation() {
    for fault in ["lost-old-delete", "missing-delete-ack"] {
        let mut f = Fixture::new();
        let boot = f.access.request.team.bootstrap_id;
        let stack = format!("zdn-{}", boot.simple());
        let key = format!("zdn-admin/v1/{boot}/.pulumi/stacks/zdn-access/{stack}.json.bak");
        *f.api.objects.borrow_mut() = vec![
            json!({"Key":key,"VersionId":"backup-v1","IsLatest":true}),
            json!({"Key":key,"VersionId":"old","IsLatest":false}),
        ];
        f.api.object_content = json!({"version":3,"checkpoint":{"stack":format!("organization/zdn-access/{stack}"),"latest":{"resources":[]}}});
        f.api.fault = Some(fault);
        assert!(f.remove(false, false).is_err());
        assert_eq!(f.api.objects.borrow().len(), 1);
        assert_eq!(f.api.objects.borrow()[0]["VersionId"], "backup-v1");
        assert!(f.api.backend.get() && !f.api.pending.get());
        assert!(f.remove(false, false).is_err());
        f.api.fault = None;
        assert_eq!(f.remove(false, true).unwrap()["backendRemoved"], true);
    }
}

#[test]
fn team_cli_proposal_is_offline_and_destructive_consent_is_required() {
    let f = Fixture::new();
    let store = zdn::state::StateStore::open(f.root.path().join("state")).unwrap();
    let output = |flags: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .args([
                "setup",
                "remove-team",
                "--state-dir",
                store.root().to_str().unwrap(),
                "--profile",
                "creator",
                "--aws-profile",
                "admin",
            ])
            .args(flags)
            .output()
            .unwrap()
    };
    // Product profiles normally live under profiles/, not the public API fixture root.
    fs::create_dir(store.root().join("profiles")).unwrap();
    for suffix in ["json", "bootstrap.json"] {
        fs::copy(
            f.profile.with_extension(suffix),
            store
                .root()
                .join("profiles")
                .join(format!("creator.{suffix}")),
        )
        .unwrap();
    }
    // A bare bootstrap team has no managed access and remains a valid offline proposal.
    foundation::write_json(
        &store.root().join("profiles/creator.json"),
        &LocalProfile {
            team: f.access.request.team.clone(),
            aws_profile: "admin".into(),
        },
    )
    .unwrap();
    let result = output(&[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["cloudChanges"], false);
    assert_eq!(value["liveOwnershipChecked"], false);
    for flags in [
        vec!["--yes"],
        vec!["--yes", "--delete-data"],
        vec!["--yes", "--writers-stopped"],
    ] {
        assert_eq!(output(&flags).status.code(), Some(2));
    }
}
