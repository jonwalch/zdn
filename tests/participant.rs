//! Offline state-machine and IAM observations. These fixtures never access AWS.

use eyre::{bail, Result};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::PathBuf,
    rc::Rc,
};
use zdn::{
    aws::{AwsApi, AwsApiError},
    endpoints::{ownership_tags, Service},
    participant::{self, ParticipantReceipt, ParticipantRequest, ParticipantStack, POLICY_NAME},
};

fn request() -> ParticipantRequest {
    serde_json::from_value(json!({
        "team":{"apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
            "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec",
            "aws":{"accountId":"123456789012","region":"us-east-1"},
            "state":{"backend":"s3://zdn-test-backend/pulumi/test-team","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}},
        "endpoints":{"apiVersion":"zdn-endpoints/v1alpha1","networkId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
            "scope":{"team_id":"test-team","account_id":"123456789012","region":"us-east-1"},
            "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec","consensusFingerprint":"ab".repeat(32),"nodeCount":1,
            "targets":[{"service":"node-rpc","nodeId":"node-1","instanceId":"i-00000000000000001"}]},
        "administrator":{"profile":"administrator","accountId":"123456789012","region":"us-east-1"},
        "trustedPrincipals":["arn:aws:iam::123456789012:user/developer"]
    })).unwrap()
}

fn legacy_trust(req: &ParticipantRequest) -> Value {
    json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":req.trusted_principals}
    }]})
}

#[test]
fn setup_plan_prints_the_enforced_name_for_each_principal_without_aws() {
    let root = tempfile::tempdir().unwrap();
    let mut req = request();
    req.trusted_principals
        .push("arn:aws:iam::123456789012:role/ci".into());
    fs::write(
        root.path().join("team.yaml"),
        serde_yaml::to_string(&req.team).unwrap(),
    )
    .unwrap();
    req.endpoints
        .save_new(&root.path().join("endpoints.json"))
        .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .current_dir(root.path())
        .args([
            "setup",
            "participant",
            "--from",
            "team.yaml",
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "administrator",
            "--trust-principal",
            &req.trusted_principals[0],
            "--trust-principal",
            &req.trusted_principals[1],
            "--plan",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["cloudChanges"], false);
    let program: Value = serde_yaml::from_str(result["pulumiYaml"].as_str().unwrap()).unwrap();
    let policy: Value = serde_json::from_str(
        program["resources"]["participantRole"]["properties"]["assumeRolePolicy"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["roleSessionNames"].as_object().unwrap().len(), 2);
    for statement in policy["Statement"].as_array().unwrap() {
        let principal = statement["Principal"]["AWS"].as_str().unwrap();
        assert_eq!(
            result["roleSessionNames"][principal],
            statement["Condition"]["StringEquals"]["sts:RoleSessionName"]
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn legacy_grant_is_an_upgrade_input_but_never_a_verified_current_grant() {
    let req = request();
    let legacy = legacy_trust(&req);
    let mut export = checkpoint(&req);
    export["deployment"]["resources"][2]["inputs"]["assumeRolePolicy"] = json!(legacy.to_string());
    participant::validate_checkpoint(&req, &export).unwrap();
    for (key, value) in [
        ("Principal", json!({"AWS":"*"})),
        ("Action", json!("sts:*")),
        (
            "Condition",
            json!({"StringEquals":{"sts:RoleSessionName":"changed"}}),
        ),
    ] {
        let mut changed = legacy.clone();
        changed["Statement"][0][key] = value;
        export["deployment"]["resources"][2]["inputs"]["assumeRolePolicy"] =
            json!(changed.to_string());
        assert!(
            participant::validate_checkpoint(&req, &export).is_err(),
            "{key}"
        );
    }
    let mut cloud = Cloud::new(&req);
    cloud.role_exists.set(true);
    cloud.mutation = Some(("get-role", "/Role/AssumeRolePolicyDocument", legacy));
    assert!(participant::verify_role(&cloud, &req)
        .unwrap_err()
        .to_string()
        .contains("trust differs"));
}

#[test]
fn existing_grant_upgrade_preserves_v1_files_and_receipt_and_rejects_retargeting() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("access");
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(directory.clone(), &cloud);
    participant::provision(&cloud, &req, &directory, &mut stack, false).unwrap();
    let receipt = fs::read(directory.join("participant.json")).unwrap();
    let legacy_directory = directory.join("project");
    zdn::foundation::private_directory(&legacy_directory).unwrap();
    let legacy_path = legacy_directory.join("Pulumi.yaml");
    let mut program = req.render().unwrap();
    program["resources"]["participantRole"]["properties"]["assumeRolePolicy"] =
        json!(legacy_trust(&req).to_string());
    let legacy = serde_yaml::to_string(&program).unwrap();
    fs::write(&legacy_path, &legacy).unwrap();
    let config_name = format!("Pulumi.{}.yaml", req.stack_name());
    let config = format!(
        "secretsprovider: {}\nencryptedkey: fixture-encrypted-key\n",
        req.team.secrets_provider()
    );
    fs::write(legacy_directory.join(&config_name), &config).unwrap();
    let project = participant::prepare_project(&req, &directory).unwrap();
    assert_eq!(project, directory.join(participant::PROJECT_DIRECTORY));
    assert_eq!(fs::read(&legacy_path).unwrap(), legacy.as_bytes());
    assert_eq!(
        fs::read(project.join(&config_name)).unwrap(),
        config.as_bytes()
    );
    participant::prepare_project(&req, &directory).unwrap();
    assert_eq!(
        fs::read(legacy_directory.join(&config_name)).unwrap(),
        config.as_bytes()
    );
    assert_eq!(
        fs::read(directory.join("participant.json")).unwrap(),
        receipt
    );
    let current: Value =
        serde_yaml::from_slice(&fs::read(project.join("Pulumi.yaml")).unwrap()).unwrap();
    assert_eq!(current, req.render().unwrap());
    stack.calls.clear();
    participant::provision(&cloud, &req, &directory, &mut stack, false).unwrap();
    assert_eq!(
        stack.calls,
        ["exists", "select", "configure", "apply", "outputs"]
    );
    // A different original project must not be silently bypassed by v2.
    program["resources"]["participantRole"]["properties"]["assumeRolePolicy"] = json!("{}");
    fs::write(&legacy_path, serde_yaml::to_string(&program).unwrap()).unwrap();
    assert!(participant::prepare_project(&req, &directory)
        .unwrap_err()
        .to_string()
        .contains("legacy participant project differs"));
    assert_eq!(
        serde_yaml::from_slice::<Value>(&fs::read(project.join("Pulumi.yaml")).unwrap()).unwrap(),
        current
    );
}

struct Cloud {
    request: ParticipantRequest,
    role_exists: Rc<Cell<bool>>,
    calls: RefCell<Vec<String>>,
    failure: Option<&'static str>,
    mutation: Option<(&'static str, &'static str, Value)>,
}

impl Cloud {
    fn new(request: &ParticipantRequest) -> Self {
        Self {
            request: request.clone(),
            role_exists: Rc::new(Cell::new(false)),
            calls: RefCell::default(),
            failure: None,
            mutation: None,
        }
    }
}

impl AwsApi for Cloud {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert!(extra.is_empty());
        self.calls
            .borrow_mut()
            .push(format!("{service}:{operation}"));
        if self.failure == Some(operation) {
            return Err(AwsApiError {
                code: "AccessDenied".into(),
            }
            .into());
        }
        let req = &self.request;
        let bootstrap = req.team.bootstrap_id.to_string();
        let tags = [
            ("zdn:project", "zdn"),
            ("zdn:team", "test-team"),
            ("zdn:bootstrap", bootstrap.as_str()),
        ];
        let mut response = match (service, operation) {
            ("sts", "get-caller-identity") => {
                json!({"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/administrator","UserId":"fixture"})
            }
            ("s3api", "head-bucket") => {
                assert_eq!(input["ExpectedBucketOwner"], "123456789012");
                json!({})
            }
            ("s3api", "get-bucket-location") => json!({"LocationConstraint":null}),
            ("s3api", "get-bucket-tagging") => {
                json!({"TagSet":tags.iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>()})
            }
            ("s3api", "get-bucket-versioning") => json!({"Status":"Enabled"}),
            ("s3api", "get-public-access-block") => {
                json!({"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}})
            }
            ("s3api", "get-bucket-ownership-controls") => {
                json!({"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}})
            }
            ("s3api", "get-bucket-encryption") => {
                json!({"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":req.team.state.kms_key_arn},"BucketKeyEnabled":true}]}})
            }
            ("s3api", "get-bucket-policy") => {
                json!({"Policy":json!({"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::zdn-test-backend","arn:aws:s3:::zdn-test-backend/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}).to_string()})
            }
            ("kms", "describe-key") => {
                json!({"KeyMetadata":{"Arn":req.team.state.kms_key_arn,"KeyManager":"CUSTOMER","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","KeyState":"Enabled"}})
            }
            ("kms", "list-resource-tags") => {
                json!({"Tags":tags.iter().map(|(key,value)|json!({"TagKey":key,"TagValue":value})).collect::<Vec<_>>()})
            }
            ("kms", "get-key-rotation-status") => json!({"KeyRotationEnabled":true}),
            ("ssm", "get-document") => {
                assert_eq!(input["Name"], req.endpoints.document_arn(Service::NodeRpc));
                json!({"Name":req.endpoints.document_name(Service::NodeRpc),"DocumentType":"Session","DocumentFormat":"JSON","Status":"Active","Content":Service::NodeRpc.session_document().to_string()})
            }
            ("iam", "get-role") => {
                assert_eq!(input["RoleName"], req.endpoints.participant_role_name());
                if !self.role_exists.get() {
                    return Err(AwsApiError {
                        code: "NoSuchEntity".into(),
                    }
                    .into());
                }
                let tags = ownership_tags(
                    &req.endpoints.scope,
                    req.endpoints.bootstrap_id,
                    req.endpoints.network_id,
                );
                json!({"Role":{"Arn":req.endpoints.participant_role_arn(),"RoleName":req.endpoints.participant_role_name(),"Path":req.endpoints.participant_role_path(),"MaxSessionDuration":3600,
                    "AssumeRolePolicyDocument":req.endpoints.participant_trust_policy(&req.trusted_principals).unwrap(),
                    "Tags":tags.as_object().unwrap().iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>()}})
            }
            ("iam", "list-attached-role-policies") => {
                json!({"AttachedPolicies":[],"IsTruncated":false})
            }
            ("iam", "list-role-policies") => {
                json!({"PolicyNames":[POLICY_NAME],"IsTruncated":false})
            }
            ("iam", "get-role-policy") => {
                json!({"RoleName":req.endpoints.participant_role_name(),"PolicyName":POLICY_NAME,"PolicyDocument":req.endpoints.participant_policy().unwrap()})
            }
            _ => panic!("unexpected operation {service} {operation}"),
        };
        if let Some((op, pointer, value)) = &self.mutation {
            if operation == *op {
                if let Some(slot) = response.pointer_mut(pointer) {
                    *slot = value.clone();
                } else {
                    response["Role"].as_object_mut().unwrap().insert(
                        pointer.strip_prefix("/Role/").unwrap().into(),
                        value.clone(),
                    );
                }
            }
        }
        Ok(response)
    }
}

struct Stack {
    directory: PathBuf,
    request: ParticipantRequest,
    calls: Vec<&'static str>,
    exists: bool,
    fail: Option<&'static str>,
    role_exists: Rc<Cell<bool>>,
    wrong_outputs: bool,
}

impl Stack {
    fn new(directory: PathBuf, cloud: &Cloud) -> Self {
        Self {
            directory,
            request: cloud.request.clone(),
            calls: vec![],
            exists: false,
            fail: None,
            role_exists: cloud.role_exists.clone(),
            wrong_outputs: false,
        }
    }
    fn effect(&mut self, name: &'static str) -> Result<()> {
        let receipt: ParticipantReceipt =
            zdn::foundation::read_json(&self.directory.join("participant.json"))?;
        assert!(
            receipt.uncertain && receipt.stack_started,
            "intent saved before {name}"
        );
        assert_eq!(receipt.request, self.request.normalized()?);
        self.calls.push(name);
        if self.fail == Some(name) {
            bail!("injected {name} failure");
        }
        Ok(())
    }
}

impl ParticipantStack for Stack {
    fn exists(&mut self) -> Result<bool> {
        self.calls.push("exists");
        Ok(self.exists)
    }
    fn prepare(&mut self, create: bool) -> Result<()> {
        self.effect(if create { "create" } else { "select" })?;
        self.exists = true;
        Ok(())
    }
    fn refresh(&mut self) -> Result<()> {
        self.effect("refresh")
    }
    fn configure(&mut self, request: &ParticipantRequest) -> Result<()> {
        assert_eq!(*request, self.request.normalized()?);
        self.effect("configure")
    }
    fn apply(&mut self) -> Result<()> {
        self.role_exists.set(true);
        self.effect("apply")
    }
    fn outputs(&mut self) -> Result<Value> {
        self.effect("outputs")?;
        Ok(
            json!({"roleArn":if self.wrong_outputs {"wrong".into()} else {self.request.endpoints.participant_role_arn()}}),
        )
    }
}

#[test]
fn creation_and_repeat_pin_identity_and_verify_scoped_iam_without_extra_cloud_writes() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("access");
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(dir.clone(), &cloud);
    let arn = participant::provision(&cloud, &req, &dir, &mut stack, false).unwrap();
    assert_eq!(arn, req.endpoints.participant_role_arn());
    assert_eq!(
        stack.calls,
        ["exists", "create", "configure", "apply", "outputs"]
    );
    let receipt: ParticipantReceipt =
        zdn::foundation::read_json(&dir.join("participant.json")).unwrap();
    assert!(receipt.complete && !receipt.uncertain);
    stack.calls.clear();
    participant::provision(&cloud, &req, &dir, &mut stack, false).unwrap();
    assert_eq!(
        stack.calls,
        ["exists", "select", "configure", "apply", "outputs"]
    );
    assert!(cloud
        .calls
        .borrow()
        .iter()
        .all(|op| !op.contains(":create-") && !op.contains(":put-") && !op.contains(":delete-")));
}

#[test]
fn lost_apply_reply_requires_reconcile_and_refresh_before_one_retry() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("access");
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(dir.clone(), &cloud);
    stack.fail = Some("apply");
    assert!(participant::provision(&cloud, &req, &dir, &mut stack, false).is_err());
    let receipt: ParticipantReceipt =
        zdn::foundation::read_json(&dir.join("participant.json")).unwrap();
    assert!(receipt.uncertain && !receipt.complete);
    stack.calls.clear();
    let calls = cloud.calls.borrow().len();
    assert!(
        participant::provision(&cloud, &req, &dir, &mut stack, false)
            .unwrap_err()
            .to_string()
            .contains("--reconcile")
    );
    assert!(stack.calls.is_empty());
    assert_eq!(cloud.calls.borrow().len(), calls);
    stack.fail = None;
    participant::provision(&cloud, &req, &dir, &mut stack, true).unwrap();
    assert_eq!(
        stack.calls,
        [
            "exists",
            "select",
            "refresh",
            "configure",
            "apply",
            "outputs"
        ]
    );
}

#[test]
fn every_stack_failure_and_wrong_outputs_leave_a_durable_uncertain_receipt() {
    for failure in ["create", "configure", "apply", "outputs", "wrong-outputs"] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("access");
        let req = request();
        let cloud = Cloud::new(&req);
        let mut stack = Stack::new(dir.clone(), &cloud);
        if failure == "wrong-outputs" {
            stack.wrong_outputs = true;
        } else {
            stack.fail = Some(failure);
        }
        assert!(
            participant::provision(&cloud, &req, &dir, &mut stack, false).is_err(),
            "{failure}"
        );
        let receipt: ParticipantReceipt =
            zdn::foundation::read_json(&dir.join("participant.json")).unwrap();
        assert!(receipt.uncertain && !receipt.complete, "{failure}");
    }
}

#[test]
fn retargeting_and_invalid_team_inputs_fail_before_aws_stack_or_receipt_rewrites() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("access");
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(dir.clone(), &cloud);
    participant::provision(&cloud, &req, &dir, &mut stack, false).unwrap();
    let before = fs::read(dir.join("participant.json")).unwrap();
    let aws_count = cloud.calls.borrow().len();
    let stack_count = stack.calls.len();
    for mode in 0..6 {
        let mut changed = req.clone();
        match mode {
            0 => changed.endpoints.targets[0].instance_id = "i-00000000000000002".into(),
            1 => changed.trusted_principals = vec!["arn:aws:iam::123456789012:user/other".into()],
            2 => changed.endpoints.scope.team_id = "other".into(),
            3 => changed.administrator.account_id = "999999999999".into(),
            4 => changed.endpoints.consensus_fingerprint = "cd".repeat(32),
            _ => changed.team.state.backend = "s3://other-backend/pulumi/state".into(),
        }
        assert!(
            participant::provision(&cloud, &changed, &dir, &mut stack, true).is_err(),
            "{mode}"
        );
        assert_eq!(fs::read(dir.join("participant.json")).unwrap(), before);
        assert_eq!(cloud.calls.borrow().len(), aws_count);
        assert_eq!(stack.calls.len(), stack_count);
    }
}

#[test]
fn foreign_stack_or_orphan_role_is_never_adopted() {
    for existing_stack in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("access");
        let req = request();
        let cloud = Cloud::new(&req);
        cloud.role_exists.set(true);
        let mut stack = Stack::new(dir.clone(), &cloud);
        stack.exists = existing_stack;
        assert!(participant::provision(&cloud, &req, &dir, &mut stack, false).is_err());
        assert_eq!(stack.calls, ["exists"]);
        let receipt: ParticipantReceipt =
            zdn::foundation::read_json(&dir.join("participant.json")).unwrap();
        assert!(!receipt.stack_started && !receipt.uncertain && !receipt.complete);
    }
}

#[test]
fn failed_backend_or_document_checks_do_not_start_a_stack() {
    for operation in [
        "get-caller-identity",
        "head-bucket",
        "describe-key",
        "get-document",
        "get-role",
    ] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("access");
        let req = request();
        let mut cloud = Cloud::new(&req);
        cloud.failure = Some(operation);
        let mut stack = Stack::new(dir.clone(), &cloud);
        assert!(
            participant::provision(&cloud, &req, &dir, &mut stack, false).is_err(),
            "{operation}"
        );
        assert!(stack.calls.is_empty() || stack.calls == ["exists"]);
        if operation == "get-role" {
            let receipt: ParticipantReceipt =
                zdn::foundation::read_json(&dir.join("participant.json")).unwrap();
            assert!(!receipt.stack_started && !receipt.uncertain);
        } else {
            assert!(
                !dir.join("participant.json").exists(),
                "failed {operation} preflight must not leave a creation receipt"
            );
        }
    }
}

#[test]
fn missing_completed_stack_is_not_recreated() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("access");
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(dir.clone(), &cloud);
    participant::provision(&cloud, &req, &dir, &mut stack, false).unwrap();
    stack.calls.clear();
    stack.exists = false;
    assert!(participant::provision(&cloud, &req, &dir, &mut stack, true)
        .unwrap_err()
        .to_string()
        .contains("completed participant stack is missing"));
    assert_eq!(stack.calls, ["exists"]);
}

#[test]
fn iam_verification_rejects_permission_and_ownership_drift() {
    let req = request();
    for (op, pointer, value) in [
        ("get-role", "/Role/Arn", json!("foreign")),
        ("get-role", "/Role/Path", json!("/foreign/")),
        ("get-role", "/Role/MaxSessionDuration", json!(7200)),
        (
            "get-role",
            "/Role/PermissionsBoundary",
            json!({"PermissionsBoundaryArn":"foreign"}),
        ),
        (
            "get-role",
            "/Role/AssumeRolePolicyDocument/Statement/0/Principal/AWS",
            json!(["*"]),
        ),
        (
            "get-role",
            "/Role/AssumeRolePolicyDocument/Statement/0/Condition",
            json!({}),
        ),
        (
            "get-role",
            "/Role/AssumeRolePolicyDocument/Statement/0/Condition/StringEquals/sts:RoleSessionName",
            json!("someone-else"),
        ),
        ("get-role", "/Role/Tags", json!([])),
        (
            "list-attached-role-policies",
            "/AttachedPolicies",
            json!([{"PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]),
        ),
        ("list-attached-role-policies", "/IsTruncated", json!(true)),
        (
            "list-role-policies",
            "/PolicyNames",
            json!([POLICY_NAME, "extra"]),
        ),
        (
            "get-role-policy",
            "/PolicyDocument/Statement/0/Action",
            json!("*"),
        ),
    ] {
        let mut cloud = Cloud::new(&req);
        cloud.role_exists.set(true);
        cloud.mutation = Some((op, pointer, value));
        assert!(
            participant::verify_role(&cloud, &req).is_err(),
            "{op} {pointer}"
        );
    }
}

fn checkpoint(req: &ParticipantRequest) -> Value {
    let prefix = format!("urn:pulumi:{}::zdn-participant::", req.stack_name());
    let ep = &req.endpoints;
    json!({"deployment":{"resources":[
        {"urn":format!("{prefix}pulumi:pulumi:Stack::zdn-participant-{}",req.stack_name()),"type":"pulumi:pulumi:Stack"},
        {"urn":format!("{prefix}pulumi:providers:aws::provider"),"type":"pulumi:providers:aws","inputs":{"region":"us-east-1","profile":"administrator","allowedAccountIds":["123456789012"]}},
        {"urn":format!("{prefix}aws:iam/role:Role::participantRole"),"type":"aws:iam/role:Role","protect":true,"id":ep.participant_role_name(),"inputs":{
            "name":ep.participant_role_name(),"path":ep.participant_role_path(),"maxSessionDuration":3600,
            "tags":ownership_tags(&ep.scope,ep.bootstrap_id,ep.network_id),"assumeRolePolicy":ep.participant_trust_policy(&req.trusted_principals).unwrap().to_string()}},
        {"urn":format!("{prefix}aws:iam/rolePolicy:RolePolicy::participantPolicy"),"type":"aws:iam/rolePolicy:RolePolicy","protect":true,"id":format!("{}:{POLICY_NAME}",ep.participant_role_name()),"inputs":{
            "name":POLICY_NAME,"role":ep.participant_role_name(),"policy":ep.participant_policy().unwrap().to_string()}}
    ]}})
}

mod removal {
    use super::*;
    use zdn::removal::{remove_participant, RemovalStack, StackRemovalReceipt};

    struct RemovalCloud {
        cloud: Cloud,
        active: bool,
        replacement: bool,
        linger: bool,
    }
    impl AwsApi for RemovalCloud {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            match (service, operation) {
                ("ssm", "describe-sessions") => {
                    return Ok(
                        json!({"Sessions":if self.active {json!([{"SessionId":"owned-tunnel"}])} else {json!([])}}),
                    )
                }
                ("iam", "list-instance-profiles-for-role") => {
                    return Ok(json!({"InstanceProfiles":[]}))
                }
                _ => {}
            }
            if self.linger && operation == "get-role" {
                self.cloud.role_exists.set(true);
            }
            let mut value = self.cloud.call(service, operation, input, extra)?;
            if operation == "get-role" {
                value["Role"]["RoleId"] = json!(if self.replacement {
                    "replacement-id"
                } else {
                    "original-id"
                });
            }
            Ok(value)
        }
    }
    struct RemovingStack {
        checkpoint: Option<Value>,
        role: Rc<Cell<bool>>,
        fail: bool,
        mutations: usize,
        directory: PathBuf,
    }
    impl RemovalStack for RemovingStack {
        fn checkpoint(&mut self) -> Result<Option<Value>> {
            Ok(self.checkpoint.clone())
        }
        fn unprotect(&mut self, urns: &[&str]) -> Result<()> {
            let saved: StackRemovalReceipt =
                zdn::foundation::read_json(&self.directory.join("removal.json"))?;
            assert!(saved.uncertain);
            self.mutations += 1;
            for resource in self.checkpoint.as_mut().unwrap()["deployment"]["resources"]
                .as_array_mut()
                .unwrap()
            {
                if urns.iter().any(|urn| resource["urn"] == *urn) {
                    resource["protect"] = json!(false);
                }
            }
            Ok(())
        }
        fn destroy(&mut self) -> Result<()> {
            self.mutations += 1;
            self.role.set(false);
            self.checkpoint.as_mut().unwrap()["deployment"]["resources"]
                .as_array_mut()
                .unwrap()
                .retain(|r| !r["type"].as_str().unwrap().starts_with("aws:"));
            if self.fail {
                bail!("lost destroy response");
            }
            Ok(())
        }
        fn remove(&mut self) -> Result<()> {
            self.mutations += 1;
            self.checkpoint = None;
            Ok(())
        }
    }
    fn fixture() -> (tempfile::TempDir, RemovalCloud, RemovingStack) {
        let root = tempfile::tempdir().unwrap();
        let req = request();
        let cloud = Cloud::new(&req);
        cloud.role_exists.set(true);
        zdn::foundation::write_json(
            &root.path().join("participant.json"),
            &ParticipantReceipt {
                version: 1,
                request: req.clone(),
                stack_started: true,
                uncertain: false,
                complete: true,
            },
        )
        .unwrap();
        let mut export = checkpoint(&req);
        export["deployment"]["resources"][2]["custom"] = json!(true);
        export["deployment"]["resources"][2]["outputs"] =
            json!({"uniqueId":"original-id","arn":req.endpoints.participant_role_arn()});
        let stack = RemovingStack {
            checkpoint: Some(export),
            role: cloud.role_exists.clone(),
            fail: false,
            mutations: 0,
            directory: root.path().into(),
        };
        (
            root,
            RemovalCloud {
                cloud,
                active: false,
                replacement: false,
                linger: false,
            },
            stack,
        )
    }

    struct Probe {
        error: Option<&'static str>,
        wrong_identity: bool,
        wrong_role_id: bool,
    }
    impl AwsApi for Probe {
        fn call(&self, service: &str, operation: &str, _: Value, _: &[String]) -> Result<Value> {
            let req = request();
            match (service, operation) {
                ("sts", "get-caller-identity") => Ok(
                    json!({"Account":req.team.aws.account_id,"UserId":format!("{}:{}",if self.wrong_role_id {"replacement-id"} else {"original-id"},req.endpoints.participant_session_names(&req.trusted_principals).unwrap().values().next().unwrap()),
                    "Arn":if self.wrong_identity {req.trusted_principals[0].clone()} else {format!("arn:aws:sts::{}:assumed-role/{}/{}",req.team.aws.account_id,req.endpoints.participant_role_name(),req.endpoints.participant_session_names(&req.trusted_principals).unwrap().values().next().unwrap())}}),
                ),
                ("ssm", "get-document") => match self.error {
                    Some(code) => Err(AwsApiError { code: code.into() }.into()),
                    None => Ok(json!({"Content":"still authorized"})),
                },
                _ => panic!("probe must remain read-only: {service} {operation}"),
            }
        }
    }

    #[test]
    fn abandoned_preflight_is_closed_only_after_independent_role_and_stack_absence() {
        for fault in ["none", "role", "stack", "denied", "uncertain", "complete"] {
            let (root, mut cloud, mut stack) = fixture();
            let path = root.path().join("participant.json");
            let mut receipt: ParticipantReceipt = zdn::foundation::read_json(&path).unwrap();
            receipt.stack_started = false;
            receipt.complete = fault == "complete";
            receipt.uncertain = fault == "uncertain";
            zdn::foundation::write_json(&path, &receipt).unwrap();
            let before = fs::read(&path).unwrap();
            cloud.cloud.role_exists.set(fault == "role");
            if fault != "stack" {
                stack.checkpoint = None;
            }
            if fault == "denied" {
                cloud.cloud.failure = Some("get-role");
            }
            let plan = zdn::removal::participant_plan(root.path());
            let result = remove_participant(&cloud, root.path(), &mut stack, fault != "none", None);
            if fault == "none" {
                assert!(plan.is_ok());
                let result = result.unwrap();
                assert_eq!(result["status"], "not-started");
                assert_eq!(result["roleAbsent"], true);
                assert_eq!(result["revocationVerified"], false);
                let saved: StackRemovalReceipt =
                    zdn::foundation::read_json(&root.path().join("removal.json")).unwrap();
                assert!(saved.checkpoint.is_null()); // never fabricated ownership
                remove_participant(&cloud, root.path(), &mut stack, false, None).unwrap();
                assert!(
                    remove_participant(&cloud, root.path(), &mut stack, true, Some(&cloud))
                        .is_err()
                );
                // A role appearing later must still refuse, not be deleted.
                cloud.cloud.role_exists.set(true);
                assert!(remove_participant(&cloud, root.path(), &mut stack, true, None).is_err());
            } else {
                assert!(result.is_err(), "{fault}");
                assert!(!root.path().join("removal.json").exists(), "{fault}");
            }
            assert_eq!(stack.mutations, 0, "{fault}");
            assert_eq!(fs::read(&path).unwrap(), before, "{fault}");
        }
    }

    #[test]
    fn removes_observed_grant_but_does_not_fabricate_live_revocation() {
        let (root, cloud, mut stack) = fixture();
        let before = fs::read(root.path().join("participant.json")).unwrap();
        let result = remove_participant(&cloud, root.path(), &mut stack, false, None).unwrap();
        assert_eq!(result["status"], "revocation-pending");
        assert_eq!(result["roleAbsent"], true);
        assert_eq!(result["stackRemoved"], true);
        assert_eq!(result["revocationVerified"], false);
        let mutations = stack.mutations;
        let probe = Probe {
            error: Some("AccessDeniedException"),
            wrong_identity: false,
            wrong_role_id: false,
        };
        let result =
            remove_participant(&cloud, root.path(), &mut stack, false, Some(&probe)).unwrap();
        assert_eq!(result["revocationVerified"], true);
        assert_eq!(stack.mutations, mutations);
        assert_eq!(
            fs::read(root.path().join("participant.json")).unwrap(),
            before
        );
        remove_participant(&cloud, root.path(), &mut stack, false, None).unwrap();
        assert_eq!(stack.mutations, mutations);
    }

    #[test]
    fn refuses_active_tunnels_foreign_checkpoints_and_replaced_roles_before_mutation() {
        for mode in 0..5 {
            let (root, mut cloud, mut stack) = fixture();
            match mode {
                0 => cloud.active = true,
                1 => cloud.replacement = true,
                2 => {
                    stack.checkpoint.as_mut().unwrap()["deployment"]["resources"][2]["inputs"]
                        ["path"] = json!("/foreign/")
                }
                3 => {
                    stack.checkpoint.as_mut().unwrap()["deployment"]["pending_operations"] =
                        json!([{}])
                }
                _ => stack.checkpoint = None,
            }
            assert!(
                remove_participant(&cloud, root.path(), &mut stack, false, None).is_err(),
                "{mode}"
            );
            assert_eq!(stack.mutations, 0, "{mode}");
            assert!(cloud.cloud.role_exists.get());
        }
    }

    #[test]
    fn uncertain_destroy_reconciles_without_adopting_changed_inputs() {
        let (root, cloud, mut stack) = fixture();
        stack.fail = true;
        assert!(remove_participant(&cloud, root.path(), &mut stack, false, None).is_err());
        let mutations = stack.mutations;
        assert!(remove_participant(&cloud, root.path(), &mut stack, false, None).is_err());
        assert_eq!(stack.mutations, mutations);
        stack.fail = false;
        let mut changed = stack.checkpoint.clone().unwrap();
        changed["deployment"]["resources"][1]["inputs"]["profile"] = json!("other-admin");
        let good = stack.checkpoint.replace(changed);
        assert!(remove_participant(&cloud, root.path(), &mut stack, true, None).is_err());
        assert_eq!(stack.mutations, mutations);
        stack.checkpoint = good;
        let result = remove_participant(&cloud, root.path(), &mut stack, true, None).unwrap();
        assert_eq!(result["stackRemoved"], true);
    }

    #[test]
    fn desired_deletion_is_not_live_absence_or_authorization_denial() {
        let (root, mut cloud, mut stack) = fixture();
        cloud.linger = true;
        assert!(remove_participant(&cloud, root.path(), &mut stack, false, None).is_err());
        assert!(
            stack.checkpoint.is_some(),
            "stack must remain until live absence is observed"
        );
        cloud.linger = false;
        cloud.cloud.role_exists.set(false);
        for error in [
            None,
            Some("ExpiredToken"),
            Some("InvalidDocument"),
            Some("TransportError"),
        ] {
            let probe = Probe {
                error,
                wrong_identity: false,
                wrong_role_id: false,
            };
            assert!(
                remove_participant(&cloud, root.path(), &mut stack, true, Some(&probe)).is_err()
            );
            let receipt: StackRemovalReceipt =
                zdn::foundation::read_json(&root.path().join("removal.json")).unwrap();
            assert!(!receipt.revocation_verified);
        }
        let probe = Probe {
            error: Some("AccessDenied"),
            wrong_identity: true,
            wrong_role_id: false,
        };
        assert!(remove_participant(&cloud, root.path(), &mut stack, true, Some(&probe)).is_err());
        let probe = Probe {
            wrong_identity: false,
            wrong_role_id: true,
            ..probe
        };
        assert!(remove_participant(&cloud, root.path(), &mut stack, true, Some(&probe)).is_err());
    }

    #[test]
    fn removal_cli_defaults_to_a_proposal_without_aws_or_file_changes() {
        let (root, _, _) = fixture();
        let before = fs::read_dir(root.path()).unwrap().count();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .args([
                "setup",
                "remove-participant",
                "--receipt-dir",
                root.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["cloudChanges"], false);
        assert_eq!(result["liveOwnershipChecked"], false);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), before);
    }
}

#[test]
fn owned_partial_checkpoint_recovers_but_wrong_or_pending_resources_are_refused() {
    let req = request();
    let good = checkpoint(&req);
    participant::validate_checkpoint(&req, &good).unwrap();
    let mut encoded_provider = good.clone();
    encoded_provider["deployment"]["resources"][1]["inputs"]["allowedAccountIds"] =
        json!("[\"123456789012\"]");
    participant::validate_checkpoint(&req, &encoded_provider).unwrap();
    encoded_provider["deployment"]["resources"][1]["inputs"]["allowedAccountIds"] =
        json!("[\"999999999999\"]");
    assert!(participant::validate_checkpoint(&req, &encoded_provider).is_err());
    participant::validate_checkpoint(&req, &json!({"deployment":{}})).unwrap();
    for count in 1..4 {
        let mut partial = good.clone();
        partial["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
            .truncate(count);
        participant::validate_checkpoint(&req, &partial).unwrap();
    }
    for (pointer, value) in [
        (
            "/deployment/resources/0/urn",
            json!("urn:pulumi:foreign::other"),
        ),
        ("/deployment/resources/1/inputs/profile", json!("other")),
        ("/deployment/resources/2/protect", json!(false)),
        ("/deployment/resources/2/id", json!("other")),
        ("/deployment/resources/2/inputs/path", json!("/other/")),
        ("/deployment/resources/2/inputs/tags", json!({})),
        (
            "/deployment/resources/2/inputs/assumeRolePolicy",
            json!("{}"),
        ),
        ("/deployment/resources/3/protect", json!(false)),
        ("/deployment/resources/3/inputs/role", json!("foreign")),
        ("/deployment/resources/3/inputs/policy", json!("{}")),
        (
            "/deployment/resources/3/type",
            json!("aws:iam/policy:Policy"),
        ),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            participant::validate_checkpoint(&req, &changed).is_err(),
            "{pointer}"
        );
    }
    for field in ["delete", "external"] {
        let mut changed = good.clone();
        changed["deployment"]["resources"][2][field] = json!(true);
        assert!(participant::validate_checkpoint(&req, &changed).is_err());
    }
    let mut duplicate = good.clone();
    duplicate["deployment"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(good["deployment"]["resources"][2].clone());
    assert!(participant::validate_checkpoint(&req, &duplicate).is_err());
    let mut pending = good;
    pending["deployment"]["pending_operations"] = json!([{"type":"creating"}]);
    assert!(participant::validate_checkpoint(&req, &pending).is_err());
}

#[test]
fn local_lock_prevents_parallel_setup_before_aws() {
    use fs2::FileExt;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("access");
    zdn::foundation::private_directory(&dir).unwrap();
    let lock = fs::File::create(dir.join("participant.lock")).unwrap();
    lock.lock_exclusive().unwrap();
    let req = request();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(dir.clone(), &cloud);
    assert!(participant::provision(&cloud, &req, &dir, &mut stack, false).is_err());
    assert!(cloud.calls.borrow().is_empty());
    assert!(stack.calls.is_empty());
}

#[test]
fn first_participant_setup_creates_every_receipt_parent_and_can_complete() {
    let root = tempfile::tempdir().unwrap();
    let store = zdn::state::StateStore::open(root.path().join("fresh-state")).unwrap();
    let req = request();
    assert!(!store.root().join("participants").exists());
    let directory = participant::receipt_directory(&store, &req).unwrap();
    assert_eq!(
        directory,
        store
            .root()
            .join("participants")
            .join(req.team.bootstrap_id.to_string())
            .join(req.endpoints.network_id.to_string())
    );
    assert!(directory.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [
            store.root().join("participants"),
            directory.parent().unwrap().to_path_buf(),
            directory.clone(),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
    participant::prepare_project(&req, &directory).unwrap();
    let cloud = Cloud::new(&req);
    let mut stack = Stack::new(directory.clone(), &cloud);
    participant::provision(&cloud, &req, &directory, &mut stack, false).unwrap();
    let receipt = fs::read(directory.join("participant.json")).unwrap();
    assert_eq!(
        participant::receipt_directory(&store, &req).unwrap(),
        directory
    );
    assert_eq!(
        fs::read(directory.join("participant.json")).unwrap(),
        receipt
    );
}

#[test]
fn participant_directory_validates_request_before_creating_a_namespace() {
    let root = tempfile::tempdir().unwrap();
    let store = zdn::state::StateStore::open(root.path().join("state")).unwrap();
    let mut req = request();
    req.endpoints.scope.team_id = "foreign-team".into();
    assert!(participant::receipt_directory(&store, &req).is_err());
    assert!(!store.root().join("participants").exists());
}

#[cfg(unix)]
#[test]
fn participant_directory_refuses_symlinks_at_every_level_without_writing_targets() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let req = request();
    let components = [
        "participants".to_owned(),
        req.team.bootstrap_id.to_string(),
        req.endpoints.network_id.to_string(),
    ];
    for level in 0..components.len() {
        let store =
            zdn::state::StateStore::open(root.path().join(format!("state-{level}"))).unwrap();
        let outside = root.path().join(format!("outside-{level}"));
        fs::create_dir(&outside).unwrap();
        let mut link = store.root().to_path_buf();
        for component in &components[..level] {
            link.push(component);
            zdn::foundation::private_directory(&link).unwrap();
        }
        link.push(&components[level]);
        symlink(&outside, &link).unwrap();
        assert!(
            participant::receipt_directory(&store, &req).is_err(),
            "level {level}"
        );
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }
}

#[test]
fn participant_directory_preserves_a_non_directory_parent_and_stops() {
    let root = tempfile::tempdir().unwrap();
    let store = zdn::state::StateStore::open(root.path().join("state")).unwrap();
    let path = store.root().join("participants");
    fs::write(&path, b"existing user file").unwrap();
    assert!(participant::receipt_directory(&store, &request()).is_err());
    assert_eq!(fs::read(path).unwrap(), b"existing user file");
}

#[test]
fn project_publication_repeats_identical_inputs_without_overwriting_different_grants() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("access");
    let req = request();
    let project = participant::prepare_project(&req, &directory).unwrap();
    let path = project.join("Pulumi.yaml");
    let initial = fs::read(&path).unwrap();
    #[cfg(unix)]
    let initial_inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&path).unwrap().ino()
    };
    assert_eq!(
        participant::prepare_project(&req, &directory).unwrap(),
        project
    );
    assert_eq!(fs::read(&path).unwrap(), initial);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&path).unwrap().ino(), initial_inode);
    }
    for mode in 0..3 {
        let mut changed = req.clone();
        match mode {
            0 => changed.trusted_principals = vec!["arn:aws:iam::123456789012:user/other".into()],
            1 => changed.endpoints.targets[0].instance_id = "i-00000000000000002".into(),
            _ => changed.administrator.profile = "other-administrator".into(),
        }
        assert!(participant::prepare_project(&changed, &directory)
            .unwrap_err()
            .to_string()
            .contains("not overwritten"));
        assert_eq!(fs::read(&path).unwrap(), initial);
        assert_eq!(
            fs::read_dir(&project).unwrap().count(),
            1,
            "temporary files must be removed"
        );
    }
}

#[test]
fn concurrent_preparation_can_only_publish_one_immutable_program() {
    use std::sync::{Arc, Barrier};
    for identical in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("access");
        let first = request();
        let mut second = first.clone();
        if !identical {
            second.trusted_principals = vec!["arn:aws:iam::123456789012:user/other".into()];
        }
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|threads| {
            let handles = [first, second]
                .into_iter()
                .map(|req| {
                    let barrier = barrier.clone();
                    let directory = directory.clone();
                    threads.spawn(move || {
                        let expected = serde_yaml::to_string(&req.render().unwrap())
                            .unwrap()
                            .into_bytes();
                        barrier.wait();
                        (
                            participant::prepare_project(&req, &directory).is_ok(),
                            expected,
                        )
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|(ok, _)| *ok).count(),
            if identical { 2 } else { 1 }
        );
        let published = fs::read(
            directory
                .join(participant::PROJECT_DIRECTORY)
                .join("Pulumi.yaml"),
        )
        .unwrap();
        for (ok, expected) in results {
            if ok {
                assert_eq!(published, expected);
            }
        }
    }
}

#[test]
fn saved_receipt_is_validated_before_project_preparation() {
    let root = tempfile::tempdir().unwrap();
    let req = request();
    for mode in 0..5 {
        let directory = root.path().join(format!("case-{mode}"));
        zdn::foundation::private_directory(&directory).unwrap();
        let path = directory.join("participant.json");
        let mut receipt = json!({"version":1,"request":req,"stackStarted":false,"uncertain":false,"complete":false});
        match mode {
            0 => {
                receipt["request"]["trustedPrincipals"] =
                    json!(["arn:aws:iam::123456789012:user/other"]);
            }
            1 => {
                receipt["version"] = json!(99);
            }
            2 => {
                receipt["complete"] = json!(true);
            }
            3 => {
                receipt["unexpected"] = json!(true);
            }
            _ => {}
        }
        let bytes = if mode == 4 {
            b"malformed JSON".to_vec()
        } else {
            serde_json::to_vec(&receipt).unwrap()
        };
        fs::write(&path, &bytes).unwrap();
        assert!(
            participant::prepare_project(&req, &directory).is_err(),
            "{mode}"
        );
        assert!(
            !directory.join(participant::PROJECT_DIRECTORY).exists(),
            "{mode}"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn malformed_or_oversized_projects_are_never_replaced() {
    let root = tempfile::tempdir().unwrap();
    let req = request();
    for (name, bytes) in [
        ("malformed", b"invalid YAML [{".to_vec()),
        ("oversized", vec![b'x'; 128 * 1024 + 1]),
    ] {
        let directory = root.path().join(name);
        zdn::foundation::private_directory(&directory).unwrap();
        let project = directory.join(participant::PROJECT_DIRECTORY);
        zdn::foundation::private_directory(&project).unwrap();
        let path = project.join("Pulumi.yaml");
        fs::write(&path, &bytes).unwrap();
        assert!(participant::prepare_project(&req, &directory).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn project_and_receipt_symlinks_are_refused_even_when_target_bytes_match() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let req = request();
    for receipt_link in [false, true] {
        let directory = root.path().join(if receipt_link {
            "receipt-link"
        } else {
            "project-link"
        });
        zdn::foundation::private_directory(&directory).unwrap();
        let target = root.path().join(if receipt_link {
            "receipt-target"
        } else {
            "project-target"
        });
        let bytes = if receipt_link {
            serde_json::to_vec(&json!({"version":1,"request":req,"stackStarted":false,"uncertain":false,"complete":false})).unwrap()
        } else {
            serde_yaml::to_string(&req.render().unwrap())
                .unwrap()
                .into_bytes()
        };
        fs::write(&target, &bytes).unwrap();
        if receipt_link {
            symlink(&target, directory.join("participant.json")).unwrap();
        } else {
            let project = directory.join(participant::PROJECT_DIRECTORY);
            zdn::foundation::private_directory(&project).unwrap();
            symlink(&target, project.join("Pulumi.yaml")).unwrap();
        }
        assert!(participant::prepare_project(&req, &directory).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        if receipt_link {
            assert!(!directory.join(participant::PROJECT_DIRECTORY).exists());
        }
    }
}
