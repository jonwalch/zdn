use eyre::{bail, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
    sync::{Arc, Barrier, Mutex},
};
use tempfile::TempDir;
use uuid::Uuid;
use zdn::{aws::*, state::Scope};

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

const ACCOUNT: &str = "123456789012";
const KEY: &str = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001";
fn selection() -> AwsSelection {
    AwsSelection {
        profile: "developer".into(),
        account_id: ACCOUNT.into(),
        region: "us-east-1".into(),
    }
}
fn request() -> BootstrapRequest {
    BootstrapRequest {
        team_id: "team-a".into(),
        account_id: ACCOUNT.into(),
        region: "us-east-1".into(),
        bucket: "zdn-test-backend".into(),
        prefix: "pulumi/team-a".into(),
    }
}
fn scope() -> Scope {
    Scope {
        team_id: "team-a".into(),
        account_id: ACCOUNT.into(),
        region: "us-east-1".into(),
    }
}
fn reservation() -> NetworkReservation {
    NetworkReservation::new(scope(), Uuid::new_v4(), Uuid::new_v4()).unwrap()
}
fn owner() -> LeaseOwner {
    LeaseOwner {
        operation_id: Uuid::new_v4(),
        holder_id: Uuid::new_v4(),
    }
}
fn error(code: &str) -> eyre::Report {
    AwsApiError { code: code.into() }.into()
}

#[derive(Default)]
struct Memory {
    objects: BTreeMap<String, MetadataObject>,
    revision: u64,
    conflicts: usize,
    writes: usize,
}
#[derive(Default)]
struct MemoryStore(Mutex<Memory>);
impl MetadataStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<MetadataObject>> {
        Ok(self.0.lock().unwrap().objects.get(key).cloned())
    }
    fn put(&self, key: &str, bytes: &[u8], condition: WriteCondition) -> Result<ConditionalWrite> {
        let mut state = self.0.lock().unwrap();
        if state.conflicts > 0 {
            state.conflicts -= 1;
            return Ok(ConditionalWrite::Conflict);
        }
        let allowed = match condition {
            WriteCondition::Absent => !state.objects.contains_key(key),
            WriteCondition::Matches(etag) => state.objects.get(key).is_some_and(|o| o.etag == etag),
        };
        if !allowed {
            return Ok(ConditionalWrite::Conflict);
        }
        state.revision += 1;
        state.writes += 1;
        let etag = format!("\"{}\"", state.revision);
        state.objects.insert(
            key.to_string(),
            MetadataObject {
                bytes: bytes.to_vec(),
                etag: etag.clone(),
            },
        );
        Ok(ConditionalWrite::Written(etag))
    }
}

#[derive(Default)]
struct Cloud {
    calls: Vec<(String, Value)>,
    account: Option<String>,
    fail_sts: bool,
    bucket: bool,
    bucket_owner: Option<String>,
    tags: Option<Value>,
    location: Option<String>,
    policy: Option<Value>,
    block: Option<Value>,
    ownership: Option<Value>,
    encryption: Option<Value>,
    aws_ssec_default_block: bool,
    fail_encryption_verification_once: bool,
    versioning: Option<Value>,
    key_tags: Option<Value>,
    key_metadata: Option<Value>,
    key_rotation: bool,
    key_exists: bool,
    lose_key_reply: bool,
    lose_bucket_reply: bool,
    fail_hardening: Option<&'static str>,
}
struct FakeAws {
    cloud: Mutex<Cloud>,
    receipt: PathBuf,
}
impl FakeAws {
    fn new(receipt: PathBuf) -> Self {
        Self {
            cloud: Mutex::new(Cloud::default()),
            receipt,
        }
    }
    fn mutations(&self) -> Vec<String> {
        self.cloud
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(op, _)| is_mutation(op))
            .map(|(op, _)| op.clone())
            .collect()
    }
    fn count(&self, op: &str) -> usize {
        self.cloud
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(s, _)| s == op)
            .count()
    }
}
fn is_mutation(op: &str) -> bool {
    ["create-", "put-", "enable-", "delete-"]
        .iter()
        .any(|p| op.starts_with(p))
}
impl AwsApi for FakeAws {
    fn call(&self, _service: &str, op: &str, input: Value, _extra: &[String]) -> Result<Value> {
        let mut c = self.cloud.lock().unwrap();
        c.calls.push((op.to_string(), input.clone()));
        if is_mutation(op) {
            let receipt: BootstrapReceipt = serde_json::from_slice(
                &fs::read(&self.receipt).expect("receipt precedes every mutation"),
            )
            .unwrap();
            assert_eq!(receipt.request.account_id, ACCOUNT);
            if op == "create-key" {
                assert!(receipt.key_creation_started);
            }
            if op == "create-bucket" {
                assert!(receipt.bucket_creation_started);
            }
        }
        if c.fail_hardening == Some(op) {
            return Err(error("OperationAborted"));
        }
        Ok(match op {
            "get-caller-identity" => {
                if c.fail_sts {
                    return Err(error("ExpiredToken"));
                }
                let a = c.account.as_deref().unwrap_or(ACCOUNT);
                json!({"Account":a,"Arn":format!("arn:aws:sts::{a}:assumed-role/deploy/test"),"UserId":"fixture"})
            }
            "head-bucket" => {
                if !c.bucket {
                    return Err(error("404"));
                }
                if c.bucket_owner
                    .as_ref()
                    .is_some_and(|owner| input["ExpectedBucketOwner"] != *owner)
                {
                    return Err(error("AccessDenied"));
                }
                json!({})
            }
            "create-bucket" => {
                assert!(!c.bucket, "never create an already observed bucket");
                c.bucket = true;
                c.tags = Some(input["CreateBucketConfiguration"]["Tags"].clone());
                c.location = input
                    .pointer("/CreateBucketConfiguration/LocationConstraint")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if c.lose_bucket_reply {
                    c.lose_bucket_reply = false;
                    return Err(error("RequestTimeout"));
                }
                json!({"Location":"/zdn-test-backend"})
            }
            "get-bucket-tagging" => {
                json!({"TagSet":c.tags.as_ref().ok_or_else(||error("NoSuchTagSet"))?})
            }
            "get-bucket-location" => json!({"LocationConstraint":c.location}),
            "put-public-access-block" => {
                c.block = Some(input["PublicAccessBlockConfiguration"].clone());
                json!({})
            }
            "get-public-access-block" => json!({"PublicAccessBlockConfiguration":c.block}),
            "put-bucket-ownership-controls" => {
                c.ownership = Some(input["OwnershipControls"].clone());
                json!({})
            }
            "get-bucket-ownership-controls" => json!({"OwnershipControls":c.ownership}),
            "get-bucket-policy" => {
                json!({"Policy":serde_json::to_string(c.policy.as_ref().ok_or_else(||error("NoSuchBucketPolicy"))?)?})
            }
            "put-bucket-policy" => {
                c.policy = Some(serde_json::from_str(input["Policy"].as_str().unwrap())?);
                json!({})
            }
            "create-key" => {
                assert!(
                    !c.key_exists,
                    "do not duplicate KMS create after ambiguous response"
                );
                c.key_exists = true;
                c.key_tags = Some(input["Tags"].clone());
                if c.lose_key_reply {
                    c.lose_key_reply = false;
                    return Err(error("RequestTimeout"));
                }
                json!({"KeyMetadata":{"Arn":KEY}})
            }
            "describe-key" => {
                assert_eq!(input["KeyId"], KEY);
                c.key_metadata.clone().unwrap_or_else(|| json!({"KeyMetadata":{"Arn":KEY,"KeyState":"Enabled","KeySpec":"SYMMETRIC_DEFAULT","KeyManager":"CUSTOMER","KeyUsage":"ENCRYPT_DECRYPT"}}))
            }
            "list-resource-tags" => json!({"Tags":c.key_tags,"Truncated":false}),
            "enable-key-rotation" => {
                c.key_rotation = true;
                json!({})
            }
            "get-key-rotation-status" => json!({"KeyRotationEnabled":c.key_rotation}),
            "put-bucket-versioning" => {
                c.versioning = Some(input["VersioningConfiguration"].clone());
                json!({})
            }
            "get-bucket-versioning" => c.versioning.clone().unwrap_or(json!({})),
            "put-bucket-encryption" => {
                c.encryption = Some(input["ServerSideEncryptionConfiguration"].clone());
                json!({})
            }
            "get-bucket-encryption" => {
                if c.encryption.is_some() && c.fail_encryption_verification_once {
                    c.fail_encryption_verification_once = false;
                    return Err(error("ServiceUnavailable"));
                }
                let mut config = c.encryption.clone().unwrap_or(json!({"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}));
                if c.aws_ssec_default_block {
                    config["Rules"][0]["BlockedEncryptionTypes"] =
                        json!({"EncryptionType":["SSE-C"]});
                }
                json!({"ServerSideEncryptionConfiguration":config})
            }
            _ => bail!("unhandled fake AWS operation {op}"),
        })
    }
}

#[test]
fn account_and_expired_session_fail_before_mutation_or_receipt() {
    for expired in [false, true] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        if expired {
            api.cloud.lock().unwrap().fail_sts = true;
        } else {
            api.cloud.lock().unwrap().account = Some("999999999999".into());
        }
        let err = bootstrap(&api, &selection(), &request(), &path, None).unwrap_err();
        assert!(format!("{err:#}").contains(if expired {
            "aws sso login --profile developer"
        } else {
            "account mismatch"
        }));
        assert!(api.mutations().is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn explicit_selection_rejects_ambient_credentials_profiles_regions_and_endpoints() {
    for (key, value) in [
        ("AWS_ACCESS_KEY_ID", "fixture-secret"),
        ("AWS_WEB_IDENTITY_TOKEN_FILE", "/fixture/token"),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://fixture"),
        ("AWS_PROFILE", "other"),
        ("AWS_DEFAULT_PROFILE", "other"),
        ("AWS_REGION", "us-west-2"),
        ("AWS_ENDPOINT_URL_S3", "http://fixture"),
    ] {
        let env = BTreeMap::from([(key.into(), value.into())]);
        let err = selection()
            .validate_environment(&env)
            .unwrap_err()
            .to_string();
        assert!(err.contains(key) || err.contains("endpoint"));
        assert!(!err.contains(value));
    }
    selection()
        .validate_environment(&BTreeMap::from([
            ("AWS_PROFILE".into(), "developer".into()),
            ("AWS_REGION".into(), "us-east-1".into()),
        ]))
        .unwrap();
}

#[test]
fn bootstrap_is_idempotent_and_import_is_read_only() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    let first = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    let saved: BootstrapReceipt = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(saved.complete);
    assert_eq!(saved.key_arn.as_deref(), Some(KEY));
    assert_eq!(first.state.backend, "s3://zdn-test-backend/pulumi/team-a");
    assert!(first
        .secrets_provider()
        .starts_with("awskms:///arn:aws:kms:"));
    let second = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    assert_eq!(first, second);
    assert_eq!(api.count("create-key"), 1);
    assert_eq!(api.count("create-bucket"), 1);
    let before = api.mutations();
    verify_backend(&api, &selection(), &first).unwrap();
    assert_eq!(api.mutations(), before);
}

#[test]
fn either_hardening_failure_blocks_keys_and_recovers_the_owned_bucket() {
    for operation in ["put-public-access-block", "put-bucket-ownership-controls"] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        api.cloud.lock().unwrap().fail_hardening = Some(operation);
        assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
        let saved: BootstrapReceipt = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(saved.bucket_created);
        assert!(!saved.key_creation_started);
        assert!(!saved.complete);
        assert_eq!(api.count("create-key"), 0);
        api.cloud.lock().unwrap().fail_hardening = None;
        bootstrap(&api, &selection(), &request(), &path, None).unwrap();
        assert_eq!(api.count("create-bucket"), 1);
        assert_eq!(api.count("create-key"), 1);
    }
}

#[test]
fn team_exports_are_private_atomic_and_preserve_identical_definitions() {
    let dir = TempDir::new().unwrap();
    let receipt = dir.path().join("recovery.json");
    let team = bootstrap(
        &FakeAws::new(receipt.clone()),
        &selection(),
        &request(),
        &receipt,
        None,
    )
    .unwrap();
    let path = dir.path().join("team.yaml");
    team.save_export(&path).unwrap();
    assert_eq!(TeamDefinition::load(&path).unwrap(), team);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let original = format!(
        "# preserve this formatting\n{}",
        serde_json::to_string_pretty(&team).unwrap()
    );
    fs::write(&path, &original).unwrap();
    team.save_export(&path).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    for field in ["revision", "bootstrap", "key", "backend", "team"] {
        let mut changed = team.clone();
        match field {
            "revision" => changed.revision += 1,
            "bootstrap" => changed.bootstrap_id = Uuid::new_v4(),
            "key" => changed.state.kms_key_arn = KEY.replace("000000000001", "000000000002"),
            "backend" => changed.state.backend = "s3://different-bucket/pulumi/team-a".into(),
            _ => changed.team_id = "other-team".into(),
        }
        assert!(changed.save_export(&path).is_err(), "{field}");
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
    fs::write(&path, "malformed: [").unwrap();
    assert!(team.save_export(&path).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "malformed: [");
    let directory = dir.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(team.save_export(&directory).is_err());
    #[cfg(unix)]
    {
        for dangling in [false, true] {
            let target = dir.path().join(if dangling { "missing" } else { "target" });
            if !dangling {
                fs::write(&target, &original).unwrap();
            }
            let link = dir.path().join(format!("link-{dangling}"));
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(team.save_export(&link).is_err());
            assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
            assert_eq!(target.exists(), !dangling);
            if !dangling {
                assert_eq!(fs::read_to_string(target).unwrap(), original);
            }
        }
    }
}

#[test]
fn concurrent_identical_team_exports_publish_one_complete_definition() {
    let dir = TempDir::new().unwrap();
    let receipt = dir.path().join("recovery.json");
    let team = bootstrap(
        &FakeAws::new(receipt.clone()),
        &selection(),
        &request(),
        &receipt,
        None,
    )
    .unwrap();
    let path = dir.path().join("team.yaml");
    let barrier = Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                team.save_export(&path).unwrap();
            });
        }
    });
    assert_eq!(TeamDefinition::load(&path).unwrap(), team);
}

#[test]
fn cleanup_accepts_backend_settings_drift_without_changing_the_backend() {
    let dir = TempDir::new().unwrap();
    let api = FakeAws::new(dir.path().join("recovery.json"));
    let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
    let mutations = api.mutations();
    {
        let mut cloud = api.cloud.lock().unwrap();
        cloud.policy = Some(json!({"Version":"2012-10-17","Statement":[]}));
        cloud.encryption = Some(
            json!({"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}),
        );
        cloud.versioning = Some(json!({"Status":"Suspended"}));
        cloud.block = None;
        cloud.ownership = None;
        cloud.key_rotation = false;
        cloud.calls.clear();
    }
    verify_backend_for_cleanup(&api, &selection(), &team).unwrap();
    let calls = api.cloud.lock().unwrap().calls.clone();
    assert_eq!(
        calls
            .iter()
            .map(|(operation, _)| operation.as_str())
            .collect::<Vec<_>>(),
        [
            "get-caller-identity",
            "head-bucket",
            "get-bucket-location",
            "get-bucket-tagging",
            "describe-key",
            "list-resource-tags"
        ]
    );
    for (_, input) in &calls[1..4] {
        assert_eq!(input["Bucket"], "zdn-test-backend");
        assert_eq!(input["ExpectedBucketOwner"], ACCOUNT);
    }
    assert!(api.mutations().is_empty());
    assert!(
        !mutations.is_empty(),
        "fixture bootstrap must perform setup"
    );
    assert!(verify_backend(&api, &selection(), &team).is_err());
}

#[test]
fn cleanup_still_rejects_wrong_backend_ownership_identity_and_key() {
    for fault in [
        "account",
        "bucket-owner",
        "region",
        "bucket-tags",
        "key-tags",
        "key-arn",
        "key-disabled",
        "key-use",
    ] {
        let dir = TempDir::new().unwrap();
        let api = FakeAws::new(dir.path().join("recovery.json"));
        let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
        {
            let mut cloud = api.cloud.lock().unwrap();
            match fault {
                "account" => cloud.account = Some("999999999999".into()),
                "bucket-owner" => cloud.bucket_owner = Some("999999999999".into()),
                "region" => cloud.location = Some("us-west-2".into()),
                "bucket-tags" => cloud.tags = Some(json!([])),
                "key-tags" => cloud.key_tags = Some(json!([])),
                _ => {
                    let mut metadata = json!({"KeyMetadata":{"Arn":KEY,"KeyState":"Enabled","KeySpec":"SYMMETRIC_DEFAULT","KeyManager":"CUSTOMER","KeyUsage":"ENCRYPT_DECRYPT"}});
                    match fault {
                        "key-arn" => metadata["KeyMetadata"]["Arn"] = json!("arn:aws:kms:us-east-1:999999999999:key/00000000-0000-4000-8000-000000000001"),
                        "key-disabled" => metadata["KeyMetadata"]["KeyState"] = json!("Disabled"),
                        "key-use" => metadata["KeyMetadata"]["KeyUsage"] = json!("SIGN_VERIFY"),
                        _ => unreachable!(),
                    }
                    cloud.key_metadata = Some(metadata);
                }
            }
            cloud.calls.clear();
        }
        assert!(
            verify_backend_for_cleanup(&api, &selection(), &team).is_err(),
            "{fault}"
        );
        assert!(api.mutations().is_empty(), "{fault}");
    }
    let api = FakeAws::new(PathBuf::new());
    let mut selected = selection();
    selected.account_id = "999999999999".into();
    assert!(verify_backend_for_cleanup(&api, &selected, &fixture_team()).is_err());
    assert!(api.cloud.lock().unwrap().calls.is_empty());
}

#[test]
fn bootstrap_accepts_aws_added_ssec_settings_after_put_and_on_reuse() {
    for explicit_disabled_bucket_key in [false, true] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        {
            let mut cloud = api.cloud.lock().unwrap();
            cloud.aws_ssec_default_block = true;
            if explicit_disabled_bucket_key {
                cloud.encryption = Some(json!({"Rules":[{
                    "ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},
                    "BucketKeyEnabled":false
                }]}));
            }
        }
        let first = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
        assert!(
            serde_json::from_slice::<BootstrapReceipt>(&fs::read(&path).unwrap())
                .unwrap()
                .complete
        );
        for encryption_type in ["SSE-C", "NONE"] {
            {
                let mut cloud = api.cloud.lock().unwrap();
                cloud.aws_ssec_default_block = false;
                cloud.encryption.as_mut().unwrap()["Rules"][0]["BlockedEncryptionTypes"] =
                    json!({"EncryptionType":[encryption_type]});
            }
            let before = api.mutations();
            verify_backend(&api, &selection(), &first).unwrap();
            assert_eq!(api.mutations(), before);
            let reused = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
            assert_eq!(reused, first);
        }
        assert_eq!(api.count("create-bucket"), 1);
        assert_eq!(api.count("create-key"), 1);
    }
}

#[test]
fn bootstrap_recovers_when_verification_failed_after_encryption_put() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    {
        let mut cloud = api.cloud.lock().unwrap();
        cloud.aws_ssec_default_block = true;
        cloud.fail_encryption_verification_once = true;
    }
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    let saved: BootstrapReceipt = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(!saved.complete);
    assert_eq!(saved.key_arn.as_deref(), Some(KEY));
    assert_eq!(api.count("put-bucket-encryption"), 1);
    let team = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    assert_eq!(team.bootstrap_id, saved.bootstrap_id);
    assert_eq!(team.state.kms_key_arn, KEY);
    assert_eq!(api.count("put-bucket-encryption"), 2);
    assert_eq!(api.count("create-bucket"), 1);
    assert_eq!(api.count("create-key"), 1);
    assert!(
        serde_json::from_slice::<BootstrapReceipt>(&fs::read(&path).unwrap())
            .unwrap()
            .complete
    );
}

#[test]
fn bucket_encryption_rejects_wrong_defaults_and_malformed_optional_settings() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    let team = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    let valid = json!({"Rules":[{
        "ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":KEY},
        "BucketKeyEnabled":true,"BlockedEncryptionTypes":{"EncryptionType":["SSE-C"]}
    }]});
    let mut invalid = Vec::new();
    for (pointer, value) in [
        (
            "/Rules/0/ApplyServerSideEncryptionByDefault/KMSMasterKeyID",
            json!("foreign"),
        ),
        (
            "/Rules/0/ApplyServerSideEncryptionByDefault/SSEAlgorithm",
            json!("aws:kms:dsse"),
        ),
        (
            "/Rules/0/ApplyServerSideEncryptionByDefault/SSEAlgorithm",
            json!("AES256"),
        ),
        ("/Rules/0/BucketKeyEnabled", json!(false)),
        ("/Rules/0/BucketKeyEnabled", json!("true")),
        ("/Rules/0/BlockedEncryptionTypes", Value::Null),
        ("/Rules/0/BlockedEncryptionTypes", json!({})),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":[]}),
        ),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":"SSE-C"}),
        ),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":["unknown"]}),
        ),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":["SSE-C","NONE"]}),
        ),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":["SSE-C","SSE-C"]}),
        ),
        (
            "/Rules/0/BlockedEncryptionTypes",
            json!({"EncryptionType":["SSE-C"],"unknown":true}),
        ),
        ("/Rules", json!([])),
        ("/Rules", json!([valid["Rules"][0], valid["Rules"][0]])),
    ] {
        let mut config = valid.clone();
        *config.pointer_mut(pointer).unwrap() = value;
        invalid.push(config);
    }
    let mut missing_bucket_key = valid.clone();
    missing_bucket_key["Rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("BucketKeyEnabled");
    invalid.push(missing_bucket_key);
    let mut unexpected_rule_field = valid.clone();
    unexpected_rule_field["Rules"][0]["UnknownSetting"] = json!(true);
    invalid.push(unexpected_rule_field);
    let mut unexpected_root_field = valid;
    unexpected_root_field["UnknownSetting"] = json!(true);
    invalid.push(unexpected_root_field);
    for config in invalid {
        api.cloud.lock().unwrap().encryption = Some(config.clone());
        let before = api.mutations();
        assert!(
            verify_backend(&api, &selection(), &team).is_err(),
            "{config}"
        );
        assert_eq!(api.mutations(), before);
        let puts = api.count("put-bucket-encryption");
        assert!(
            bootstrap(&api, &selection(), &request(), &path, None).is_err(),
            "{config}"
        );
        assert_eq!(api.count("put-bucket-encryption"), puts, "{config}");
        assert_eq!(api.cloud.lock().unwrap().encryption.as_ref(), Some(&config));
    }
}

#[test]
fn interrupted_bucket_creation_recovers_atomic_tags_without_recreation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    api.cloud.lock().unwrap().lose_bucket_reply = true;
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    assert!(
        !serde_json::from_slice::<BootstrapReceipt>(&fs::read(&path).unwrap())
            .unwrap()
            .bucket_created
    );
    bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    assert_eq!(api.count("create-bucket"), 1);
}

#[test]
fn ambiguous_kms_creation_requires_explicit_tagged_key_recovery() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    api.cloud.lock().unwrap().lose_key_reply = true;
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    let err = bootstrap(&api, &selection(), &request(), &path, None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("explicit recovery"));
    assert_eq!(api.count("create-key"), 1);
    bootstrap(&api, &selection(), &request(), &path, Some(KEY)).unwrap();
    assert_eq!(api.count("create-key"), 1);
}

#[test]
fn key_recovery_cannot_adopt_another_team_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    api.cloud.lock().unwrap().lose_key_reply = true;
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    api.cloud.lock().unwrap().key_tags = Some(json!([]));
    let err = bootstrap(&api, &selection(), &request(), &path, Some(KEY))
        .unwrap_err()
        .to_string();
    assert!(err.contains("different team"));
    assert_eq!(api.count("create-key"), 1);
    assert_eq!(api.count("enable-key-rotation"), 0);
}

#[test]
fn existing_foreign_or_untagged_buckets_are_never_adopted() {
    for tags in [
        None,
        Some(json!([])),
        Some(json!([{"Key":"zdn:team","Value":"foreign"}])),
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        {
            let mut cloud = api.cloud.lock().unwrap();
            cloud.bucket = true;
            cloud.tags = tags;
        }
        assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
        assert!(api.mutations().is_empty());
    }
}

#[test]
fn repeated_setup_preserves_unrelated_bucket_policy_and_encryption() {
    for policy in [false, true] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        bootstrap(&api, &selection(), &request(), &path, None).unwrap();
        let op = if policy {
            "put-bucket-policy"
        } else {
            "put-bucket-encryption"
        };
        let count = api.count(op);
        if policy {
            api.cloud.lock().unwrap().policy = Some(json!({"Statement":[]}));
        } else {
            api.cloud.lock().unwrap().encryption = Some(
                json!({"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"foreign"}}]}),
            );
        }
        let err = bootstrap(&api, &selection(), &request(), &path, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("recover manually"));
        assert_eq!(api.count(op), count);
    }
}

#[test]
fn recovery_receipt_cannot_be_retargeted() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    let before = api.mutations();
    let mut changed = request();
    changed.prefix = "pulumi/another-team".into();
    assert!(bootstrap(&api, &selection(), &changed, &path, None).is_err());
    assert_eq!(before, api.mutations());
}

#[test]
fn imported_team_format_rejects_extra_credentials_and_cross_account_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    let mut team = bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    let mut raw = serde_json::to_value(&team).unwrap();
    raw["credentials"] = json!("not-allowed");
    assert!(serde_json::from_value::<TeamDefinition>(raw).is_err());
    team.state.kms_key_arn = KEY.replace(ACCOUNT, "999999999999");
    assert!(team.validate().is_err());
    team.state.kms_key_arn = KEY.into();
    team.state.backend = "s3://zdn-test-backend/zdn-meta/v1/team-a".into();
    assert!(team.validate().is_err());
}

#[test]
fn wrong_bucket_region_fails_before_resumed_mutations() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    bootstrap(&api, &selection(), &request(), &path, None).unwrap();
    let before = api.mutations();
    api.cloud.lock().unwrap().location = Some("us-west-2".into());
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    assert_eq!(before, api.mutations());
}

#[test]
fn conditional_reservation_retries_keep_immutable_owner() {
    let store = MemoryStore::default();
    let record = reservation();
    store.0.lock().unwrap().conflicts = 2;
    reserve_network(&store, &record).unwrap();
    reserve_network(&store, &record).unwrap();
    let mut collision = record.clone();
    collision.owner_id = Uuid::new_v4();
    assert!(reserve_network(&store, &collision).is_err());
    assert_eq!(store.0.lock().unwrap().writes, 1);
}

#[test]
fn parallel_reservations_have_one_winner() {
    let store = Arc::new(MemoryStore::default());
    let barrier = Arc::new(Barrier::new(2));
    let record = reservation();
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            let mut record = record.clone();
            record.owner_id = Uuid::new_v4();
            std::thread::spawn(move || {
                barrier.wait();
                reserve_network(&*store, &record).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter(|t| t.thread().id() != std::thread::current().id())
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn active_lease_is_exclusive_and_lost_response_can_be_recovered_by_owner() {
    let store = MemoryStore::default();
    let record = reservation();
    reserve_network(&store, &record).unwrap();
    let owner = owner();
    let handle = acquire_lease(&store, &record, owner.clone(), 100, 300).unwrap();
    assert_eq!(
        handle,
        acquire_lease(&store, &record, owner, 101, 300).unwrap()
    );
    assert!(acquire_lease(&store, &record, crate::owner(), 101, 300).is_err());
}

#[test]
fn stale_lease_requires_exact_explicit_recovery_and_blocks_old_owner() {
    let store = MemoryStore::default();
    let record = reservation();
    reserve_network(&store, &record).unwrap();
    let old = acquire_lease(&store, &record, owner(), 100, 300).unwrap();
    assert!(acquire_lease(&store, &record, owner(), 401, 300)
        .unwrap_err()
        .to_string()
        .contains("explicit recovery"));
    assert!(recover_lease(&store, &record, "wrong-etag", owner(), 401, 300).is_err());
    assert!(recover_lease(&store, &record, &old.etag, owner(), 399, 300).is_err());
    let recovered = recover_lease(&store, &record, &old.etag, owner(), 401, 300).unwrap();
    assert!(release_lease(&store, &old, 402).is_err());
    assert_eq!(inspect_lease(&store, &record).unwrap().unwrap(), recovered);
}

#[test]
fn heartbeat_cas_prevents_stale_renewal_or_release() {
    let store = MemoryStore::default();
    let record = reservation();
    reserve_network(&store, &record).unwrap();
    let mut handle = acquire_lease(&store, &record, owner(), 100, 300).unwrap();
    let mut old = handle.clone();
    renew_lease(&store, &mut handle, 130, 300).unwrap();
    assert_ne!(old.etag, handle.etag);
    assert!(renew_lease(&store, &mut old, 140, 300).is_err());
    assert!(release_lease(&store, &old, 140).is_err());
    assert_eq!(inspect_lease(&store, &record).unwrap().unwrap(), handle);
}

#[test]
fn released_tombstone_allows_new_owner_without_delete_race() {
    let store = MemoryStore::default();
    let record = reservation();
    reserve_network(&store, &record).unwrap();
    let old = acquire_lease(&store, &record, owner(), 100, 300).unwrap();
    release_lease(&store, &old, 120).unwrap();
    assert!(
        inspect_lease(&store, &record)
            .unwrap()
            .unwrap()
            .record
            .released
    );
    let next = acquire_lease(&store, &record, owner(), 121, 300).unwrap();
    assert!(release_lease(&store, &old, 122).is_err());
    assert_eq!(inspect_lease(&store, &record).unwrap().unwrap(), next);
}

#[test]
fn lease_requires_reserved_network_valid_ttl_and_no_expired_renewals() {
    let store = MemoryStore::default();
    let record = reservation();
    assert!(acquire_lease(&store, &record, owner(), 100, 300).is_err());
    reserve_network(&store, &record).unwrap();
    assert!(acquire_lease(&store, &record, owner(), 100, 1).is_err());
    let mut handle = acquire_lease(&store, &record, owner(), 100, 60).unwrap();
    assert!(renew_lease(&store, &mut handle, 160, 60).is_err());
    let mut other = record.clone();
    other.owner_id = Uuid::new_v4();
    assert!(acquire_lease(&store, &other, owner(), 100, 300).is_err());
}

#[cfg(unix)]
#[test]
fn aws_batch_process_fixture() {
    use fs2::FileExt;
    use std::io::Write;
    use std::time::{Duration, Instant};

    let Ok(input) = std::env::var("ZDN_BATCH_INPUT") else {
        return;
    };
    let request: Value = serde_json::from_str(&input).unwrap();
    let index = request["index"].as_u64().unwrap();
    assert_eq!(
        std::env::var("ZDN_BATCH_ARGUMENT").unwrap(),
        format!("index {index}")
    );
    let count = request["count"].as_u64().unwrap();
    let group_size = (count - index / 4 * 4).min(4);
    let wait_for_refill = index == 0 && count > 4 && request["fail"] != true;
    let path = PathBuf::from(std::env::var_os("ZDN_EVENTS").unwrap());
    let record = |event| {
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        log.lock_exclusive().unwrap();
        writeln!(log, "{}", json!([event, index])).unwrap();
        FileExt::unlock(&log).unwrap();
    };
    record("start");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = fs::File::open(&path).unwrap();
        FileExt::lock_shared(&log).unwrap();
        let events: Vec<Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect();
        let starts = events
            .iter()
            .filter(|event| event[0] == "start" && event[1].as_u64().unwrap() / 4 == index / 4)
            .count();
        FileExt::unlock(&log).unwrap();
        // Keep the first request alive until a replacement actually starts.
        // A fixed sleep cannot distinguish wave batching from a busy scheduler.
        let refilled = events
            .iter()
            .any(|event| event[0] == "start" && event[1] == 4);
        if starts == group_size as usize && (!wait_for_refill || refilled) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "batch overlap/refill barrier timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    if request["fail"] == true {
        record("end");
        eprintln!("An error occurred (AccessDenied) when calling: fixture");
        std::process::exit(1);
    }
    std::thread::sleep(Duration::from_millis((4 - index % 4) * 30));
    record("end");
    fs::write(
        std::env::var_os("ZDN_BATCH_OUTPUT").unwrap(),
        json!({"index":index}).to_string(),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn aws_cli_batches_bound_overlap_preserve_order_and_join_after_failure() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    executable::write(
        &script,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = '--cli-input-json' ]; then
        export ZDN_BATCH_INPUT="$2"
        shift
    elif [ "$1" = '--fixture-argument' ]; then
        export ZDN_BATCH_ARGUMENT="$2"
        shift
    fi
    shift
done
export ZDN_BATCH_OUTPUT="$ZDN_EVENTS.output-$$"
# Keep test-harness chatter out of the AWS JSON response.
"$ZDN_TEST_EXE" --exact aws_batch_process_fixture --nocapture > /dev/null
status=$?
if [ "$status" -eq 0 ]; then cat "$ZDN_BATCH_OUTPUT"; fi
exit "$status"
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    for (count, failing, all) in [
        (0, false, false),
        (1, false, false),
        (3, false, false),
        (7, false, false),
        (12, false, false),
        (12, true, false),
        (12, true, true),
    ] {
        let events = dir.path().join(format!("events-{count}-{failing}-{all}"));
        let cli = AwsCli::with_environment(
            selection(),
            &script,
            BTreeMap::from([
                ("ZDN_EVENTS".into(), events.to_string_lossy().into_owned()),
                (
                    "ZDN_TEST_EXE".into(),
                    std::env::current_exe()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                ),
            ]),
        )
        .unwrap();
        let calls: Vec<_> = (0..count)
            .map(|index| AwsCall {
                operation: "describe-volumes",
                input: json!({"index":index,"count":count,"fail":failing && index == 0}),
                extra_args: vec!["--fixture-argument".into(), format!("index {index}")],
            })
            .collect();
        let result = if all {
            cli.batch_call_all("ec2", &calls)
        } else {
            cli.batch_call("ec2", &calls)
        }
        .unwrap();
        assert_eq!(result.len(), count);
        if failing {
            assert_eq!(
                result[0]
                    .as_ref()
                    .unwrap_err()
                    .downcast_ref::<AwsApiError>()
                    .unwrap()
                    .code,
                "AccessDenied"
            );
            assert!(
                result[1..4].iter().all(Result::is_ok),
                "retain successful peers"
            );
            if all {
                for (index, outcome) in result.iter().enumerate().skip(4) {
                    assert_eq!(outcome.as_ref().unwrap(), &json!({"index":index}));
                }
            } else {
                assert!(
                    result[4..].iter().all(Result::is_err),
                    "report undispatched requests"
                );
            }
        } else {
            assert_eq!(
                result.into_iter().collect::<Result<Vec<_>>>().unwrap(),
                (0..count)
                    .map(|index| json!({"index":index}))
                    .collect::<Vec<_>>()
            );
        }
        let mut active = 0;
        let mut peak = 0;
        let mut finished = Vec::new();
        let log = if count == 0 {
            String::new()
        } else {
            fs::read_to_string(events).unwrap()
        };
        if count > 4 && !failing {
            let events: Vec<(String, usize)> = log
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let refill = events
                .iter()
                .position(|v| *v == ("start".into(), 4))
                .unwrap();
            let slow_end = events.iter().position(|v| *v == ("end".into(), 0)).unwrap();
            assert!(
                refill < slow_end,
                "refill free slots without waiting for a wave"
            );
        }
        for line in log.lines() {
            let (event, index): (String, usize) = serde_json::from_str(line).unwrap();
            if event == "start" {
                active += 1;
                peak = peak.max(active);
            } else {
                active -= 1;
                finished.push(index);
            }
        }
        assert_eq!(
            peak,
            count.min(4),
            "must overlap without exceeding four subprocesses"
        );
        assert_eq!(
            active, 0,
            "every started subprocess must finish before return"
        );
        finished.sort();
        assert_eq!(
            finished,
            (0..if failing && !all { 4 } else { count }).collect::<Vec<_>>()
        );
    }
}

#[cfg(unix)]
#[test]
fn aws_cli_preserves_arguments_and_selected_environment_without_endpoint_overrides() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws fixture");
    let capture = dir.path().join("args");
    executable::write(&script,r##"#!/bin/sh
if [ "$1" = '--version' ]; then printf '%s\n' 'aws-cli/2.37.4 Python/3 fixture'; exit 0; fi
printf '%s\n' "$@" > "$ZDN_CAPTURE"
printf '%s\n' "$AWS_PROFILE" "$AWS_REGION" "$AWS_IGNORE_CONFIGURED_ENDPOINT_URLS" "$AWS_MAX_ATTEMPTS" > "$ZDN_CAPTURE.env"
printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/deploy/fixture","UserId":"fixture"}'
"##).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let env = BTreeMap::from([
        ("ZDN_CAPTURE".into(), capture.to_string_lossy().into_owned()),
        ("AWS_PROFILE".into(), "developer".into()),
    ]);
    let cli = AwsCli::with_environment(selection(), &script, env).unwrap();
    cli.verify_cli_version().unwrap();
    cli.verify_identity().unwrap();
    let args = fs::read_to_string(&capture).unwrap();
    assert!(args.contains("--profile\ndeveloper\n--region\nus-east-1\n"));
    assert!(args.contains("--output\njson\n--cli-error-format\nlegacy\n"));
    assert!(args.ends_with("sts\nget-caller-identity\n--cli-input-json\n{}\n"));
    assert_eq!(
        fs::read_to_string(capture.with_extension("env")).unwrap(),
        "developer\nus-east-1\ntrue\n1\n"
    );
}

#[cfg(unix)]
#[test]
fn aws_cli_errors_redact_raw_stderr_and_reject_old_cli() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    executable::write(&script,"#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf '%s\\n' 'aws-cli/2.37.3 Python/3'; exit 0; fi\nprintf '%s\\n' 'An error occurred (ExpiredToken) when calling: fixture-secret' >&2\nexit 1\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cli = AwsCli::with_environment(selection(), &script, BTreeMap::new()).unwrap();
    assert!(cli.verify_cli_version().is_err());
    let err = format!("{:#}", cli.verify_identity().unwrap_err());
    assert!(err.contains("ExpiredToken"));
    assert!(!err.contains("fixture-secret"));
}

#[cfg(unix)]
#[test]
fn aws_cli_accepts_bounded_inventory_larger_than_version_command_output() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    let inventory = dir.path().join("inventory.json");
    let expected = json!({"Versions": (0..485).map(|n| json!({
        "Key": format!("pulumi/zdn/history/network/{n:04}-{}", "x".repeat(120)),
        "VersionId": format!("version-{n}"), "IsLatest": true
    })).collect::<Vec<_>>(), "IsTruncated": false});
    fs::write(&inventory, serde_json::to_vec(&expected).unwrap()).unwrap();
    executable::write(&script, "#!/bin/sh\nexec /bin/cat \"$ZDN_INVENTORY\"\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cli = AwsCli::with_environment(
        selection(),
        &script,
        BTreeMap::from([(
            "ZDN_INVENTORY".into(),
            inventory.to_string_lossy().into_owned(),
        )]),
    )
    .unwrap();
    assert_eq!(
        cli.call("s3api", "list-object-versions", json!({}), &[])
            .unwrap(),
        expected
    );
}

#[cfg(unix)]
#[test]
fn aws_cli_keeps_sts_credentials_and_error_diagnostics_in_pipes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    executable::write(
        &script,
        r#"#!/bin/sh
[ -p /dev/fd/1 ] && [ -p /dev/fd/2 ] || exit 99
case "$*" in
  *assume-role*) printf '%s\n' '{"Credentials":{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","SessionToken":"fixture-token"}}' ;;
  *) printf '%s\n' 'An error occurred (AccessDenied): fixture-secret fixture-token' >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cli = AwsCli::with_environment(selection(), &script, BTreeMap::new()).unwrap();
    let credentials = cli.call("sts", "assume-role", json!({}), &[]).unwrap();
    assert_eq!(credentials["Credentials"]["SessionToken"], "fixture-token");
    let error = cli
        .call("sts", "get-caller-identity", json!({}), &[])
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("AccessDenied"));
    assert!(!message.contains("fixture-secret") && !message.contains("fixture-token"));
}

#[cfg(unix)]
#[test]
fn metadata_get_uses_scalar_flags_and_outfile_while_put_keeps_json_and_body() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("zdn s3 args ")
        .tempdir()
        .unwrap();
    let script = dir.path().join("aws");
    let capture = dir.path().join("get-arguments");
    let put_capture = dir.path().join("put-json");
    let body_capture = dir.path().join("put-body");
    executable::write(&script, r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
    case "$1" in get-object|put-object) operation="$1"; shift; break;; esac
    shift
done
case "$operation" in
    get-object)
        [ "$#" = 9 ] || exit 91
        [ "$1" = --bucket ] && [ "$3" = --key ] && [ "$5" = --expected-bucket-owner ] && [ "$7" = --range ] || exit 92
        [ "$2" = zdn-test-backend ] && [ "$6" = 123456789012 ] && [ "$8" = bytes=0-65536 ] || exit 93
        printf '%s\n' "$@" > "$ZDN_GET_CAPTURE"
        printf '{}' > "$9"
        ;;
    put-object)
        [ "$#" = 4 ] && [ "$1" = --cli-input-json ] && [ "$3" = --body ] || exit 94
        printf '%s\n' "$2" > "$ZDN_PUT_CAPTURE"
        /bin/cat "$4" > "$ZDN_BODY_CAPTURE"
        ;;
    *) exit 95;;
esac
printf '%s\n' '{"ETag":"\"fixture-etag\""}'
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let api = AwsCli::with_environment(
        selection(),
        script,
        BTreeMap::from([
            (
                "ZDN_GET_CAPTURE".into(),
                capture.to_string_lossy().into_owned(),
            ),
            (
                "ZDN_PUT_CAPTURE".into(),
                put_capture.to_string_lossy().into_owned(),
            ),
            (
                "ZDN_BODY_CAPTURE".into(),
                body_capture.to_string_lossy().into_owned(),
            ),
        ]),
    )
    .unwrap();
    let key = "zdn-meta/v1/team-a/networks/literal $(never-run); key.json";
    let output_path = dir.path().join("output with spaces.json");
    let reply = api.call("s3api", "get-object", json!({
        "Bucket":"zdn-test-backend","Key":key,"ExpectedBucketOwner":ACCOUNT,"Range":"bytes=0-65536"
    }), &[output_path.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(reply["ETag"], "\"fixture-etag\"");
    assert_eq!(fs::read(&output_path).unwrap(), b"{}");
    assert_eq!(
        fs::read_to_string(capture)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [
            "--bucket",
            "zdn-test-backend",
            "--key",
            key,
            "--expected-bucket-owner",
            ACCOUNT,
            "--range",
            "bytes=0-65536",
            output_path.to_str().unwrap()
        ]
    );
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    assert_eq!(store.get(key).unwrap().unwrap().bytes, b"{}");
    for condition in [
        WriteCondition::Absent,
        WriteCondition::Matches("\"old-etag\"".into()),
    ] {
        assert_eq!(
            store
                .put(key, b"{\"fixture\":true}", condition.clone())
                .unwrap(),
            ConditionalWrite::Written("\"fixture-etag\"".into())
        );
        let input: Value = serde_json::from_slice(&fs::read(&put_capture).unwrap()).unwrap();
        assert_eq!(input["Bucket"], "zdn-test-backend");
        assert_eq!(input["Key"], key);
        assert_eq!(input["ExpectedBucketOwner"], ACCOUNT);
        assert_eq!(input["ServerSideEncryption"], "aws:kms");
        assert_eq!(input["SSEKMSKeyId"], KEY);
        match condition {
            WriteCondition::Absent => {
                assert_eq!(input["IfNoneMatch"], "*");
                assert!(input.get("IfMatch").is_none());
            }
            WriteCondition::Matches(etag) => {
                assert_eq!(input["IfMatch"], etag);
                assert!(input.get("IfNoneMatch").is_none());
            }
        }
        assert_eq!(fs::read(&body_capture).unwrap(), b"{\"fixture\":true}");
    }
}

#[cfg(unix)]
#[test]
fn metadata_get_rejects_unsupported_or_unsafe_arguments_before_execution() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    let called = dir.path().join("called");
    executable::write(
        &script,
        "#!/bin/sh\nprintf called > \"$ZDN_CAPTURE\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let api = AwsCli::with_environment(
        selection(),
        script,
        BTreeMap::from([("ZDN_CAPTURE".into(), called.to_string_lossy().into_owned())]),
    )
    .unwrap();
    let valid = json!({"Bucket":"zdn-test-backend","Key":"zdn-meta/v1/team-a/record.json","ExpectedBucketOwner":ACCOUNT,"Range":"bytes=0-65536"});
    let output = dir.path().join("output").to_string_lossy().into_owned();
    for (field, value) in [
        ("Bucket", json!("--endpoint-url")),
        ("Bucket", json!("zdn-test-backend/foreign")),
        ("Key", json!("file:///private/fixture-secret")),
        ("Key", json!("fileb:///private/fixture-secret")),
        ("Key", json!("--endpoint-url")),
        ("Key", json!("bad\nkey")),
        ("Key", json!([])),
        ("ExpectedBucketOwner", json!("999999999999")),
        ("Range", json!("bytes=0-999999999")),
        ("Unknown", json!("fixture-secret")),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        let error = api
            .call("s3api", "get-object", input, std::slice::from_ref(&output))
            .unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-secret"));
        assert!(!called.exists());
    }
    for field in ["Bucket", "Key", "ExpectedBucketOwner", "Range"] {
        let mut input = valid.clone();
        input.as_object_mut().unwrap().remove(field);
        assert!(api
            .call("s3api", "get-object", input, std::slice::from_ref(&output))
            .is_err());
        assert!(!called.exists());
    }
    for extra in [
        vec![],
        vec!["--debug".into()],
        vec!["relative-output".into()],
        vec![output, "--debug".into()],
    ] {
        assert!(api
            .call("s3api", "get-object", valid.clone(), &extra)
            .is_err());
        assert!(!called.exists());
    }
}

#[cfg(unix)]
#[test]
fn credential_process_aws_children_remain_in_the_enclosing_process_group() {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    use std::process::{Command, Stdio};
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    let groups = dir.path().join("groups");
    executable::write(
        &script,
        r#"#!/bin/sh
[ -p /dev/fd/1 ] && [ -p /dev/fd/2 ] || exit 99
/bin/ps -o pgid= -p "$$" >> "$ZDN_CAPTURE_GROUPS"
case "$*" in
  *get-caller-identity*) printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/developer","UserId":"source"}' ;;
  *assume-role*) printf '%s\n' '{"AssumedRoleUser":{"Arn":"arn:aws:sts::123456789012:assumed-role/deploy/zdn-deployment","AssumedRoleId":"role:session"},"Credentials":{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","SessionToken":"fixture-token","Expiration":"2099-01-01T00:00:00Z"}}' ;;
  *) exit 98 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let request_path = dir.path().join("request.json");
    zdn::foundation::write_json(
        &request_path,
        &zdn::credentials::CredentialRequest {
            version: 1,
            source: selection(),
            role_arn: "arn:aws:iam::123456789012:role/deploy".into(),
            source_config: dir.path().join("original-config"),
            source_credentials: dir.path().join("original-credentials"),
        },
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
    command
        .args(["__credentials", "--request"])
        .arg(&request_path)
        .env_clear()
        .env("HOME", dir.path())
        .env("PATH", dir.path())
        .env("ZDN_CAPTURE_GROUPS", &groups)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = command.spawn().unwrap();
    let enclosing_group = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "Version": 1,
            "AccountId": "123456789012",
            "AccessKeyId": "fixture-key",
            "SecretAccessKey": "fixture-secret",
            "SessionToken": "fixture-token",
            "Expiration": "2099-01-01T00:00:00Z"
        })
    );
    let recorded = fs::read_to_string(groups).unwrap();
    let recorded: Vec<u32> = recorded
        .lines()
        .map(|line| line.trim().parse().unwrap())
        .collect();
    assert_eq!(recorded, [enclosing_group, enclosing_group]);
}

#[derive(Default)]
struct ObjectApi {
    objects: MemoryStore,
    calls: Mutex<Vec<(String, Value)>>,
    denied: bool,
    lease_faults: Mutex<VecDeque<LeaseWriteFault>>,
    lease_bodies: Mutex<Vec<Vec<u8>>>,
    lease_read_failures: Mutex<usize>,
}
#[derive(Clone, Copy)]
enum LeaseWriteFault {
    LostReply(usize),
    Fail(&'static str),
    Alter(fn(&mut LeaseRecord)),
}
impl AwsApi for ObjectApi {
    fn call(&self, service: &str, op: &str, input: Value, extra: &[String]) -> Result<Value> {
        assert_eq!(service, "s3api");
        assert_eq!(input["Bucket"], "zdn-test-backend");
        assert_eq!(input["ExpectedBucketOwner"], ACCOUNT);
        self.calls
            .lock()
            .unwrap()
            .push((op.to_string(), input.clone()));
        if self.denied {
            return Err(error("AccessDenied"));
        }
        let key = input["Key"].as_str().unwrap();
        match op {
            "get-object" => {
                assert_eq!(input["Range"], "bytes=0-65536");
                assert_eq!(extra.len(), 1);
                if key.ends_with("/lease.json") {
                    let mut remaining = self.lease_read_failures.lock().unwrap();
                    if *remaining > 0 {
                        *remaining -= 1;
                        return Err(error("ServiceUnavailable"));
                    }
                }
                let object = self.objects.get(key)?.ok_or_else(|| error("NoSuchKey"))?;
                fs::write(&extra[0], &object.bytes)?;
                Ok(json!({"ETag":object.etag}))
            }
            "put-object" => {
                assert_eq!(extra.len(), 2);
                assert_eq!(extra[0], "--body");
                assert_eq!(input["ServerSideEncryption"], "aws:kms");
                assert_eq!(input["SSEKMSKeyId"], KEY);
                let bytes = fs::read(&extra[1])?;
                let fault = if key.ends_with("/lease.json") {
                    self.lease_bodies.lock().unwrap().push(bytes.clone());
                    self.lease_faults.lock().unwrap().pop_front()
                } else {
                    None
                };
                if let Some(LeaseWriteFault::Fail(code)) = fault {
                    return Err(error(code));
                }
                let condition = match input.get("IfMatch") {
                    Some(value) => WriteCondition::Matches(value.as_str().unwrap().to_string()),
                    None => {
                        assert_eq!(input["IfNoneMatch"], "*");
                        WriteCondition::Absent
                    }
                };
                match self.objects.put(key, &bytes, condition)? {
                    ConditionalWrite::Written(etag) => {
                        match fault {
                            Some(LeaseWriteFault::LostReply(read_failures)) => {
                                *self.lease_read_failures.lock().unwrap() = read_failures;
                                return Err(error("CommandInterrupted"));
                            }
                            Some(LeaseWriteFault::Alter(alter)) => {
                                let mut record: LeaseRecord = serde_json::from_slice(&bytes)?;
                                alter(&mut record);
                                assert!(matches!(
                                    self.objects.put(
                                        key,
                                        &serde_json::to_vec(&record)?,
                                        WriteCondition::Matches(etag)
                                    )?,
                                    ConditionalWrite::Written(_)
                                ));
                                return Err(error("CommandInterrupted"));
                            }
                            _ => {}
                        }
                        Ok(json!({"ETag":etag}))
                    }
                    ConditionalWrite::Conflict => Err(error("PreconditionFailed")),
                }
            }
            _ => bail!("unexpected object API {op}"),
        }
    }
}
fn fixture_team() -> TeamDefinition {
    TeamDefinition {
        deployment: None,
        api_version: TEAM_API_VERSION.into(),
        team_id: "team-a".into(),
        revision: 1,
        bootstrap_id: Uuid::new_v4(),
        aws: TeamAws {
            account_id: ACCOUNT.into(),
            region: "us-east-1".into(),
        },
        state: TeamState {
            backend: "s3://zdn-test-backend/pulumi/team-a".into(),
            kms_key_arn: KEY.into(),
        },
    }
}

#[test]
fn acquire_recovers_lost_s3_reply_in_the_same_attempt_without_extending_or_retargeting() {
    for released in [false, true] {
        for lost_reads in [0, 1] {
            let api = ObjectApi::default();
            let team = fixture_team();
            let store = S3Metadata::new(&api, &team).unwrap();
            let reservation = reservation();
            reserve_network(&store, &reservation).unwrap();
            let old = if released {
                let handle = acquire_lease(&store, &reservation, owner(), 100, 300).unwrap();
                release_lease(&store, &handle, 120).unwrap();
                Some(handle)
            } else {
                None
            };
            api.calls.lock().unwrap().clear();
            api.lease_bodies.lock().unwrap().clear();
            api.lease_faults
                .lock()
                .unwrap()
                .push_back(LeaseWriteFault::LostReply(lost_reads));
            let owner = owner();
            let handle = acquire_lease(&store, &reservation, owner.clone(), 121, 300).unwrap();
            assert_eq!(handle.record.owner, owner);
            assert_eq!(handle.record.expires_at, 421);
            assert_eq!(handle.record.generation, if released { 3 } else { 1 });
            assert_eq!(
                inspect_lease(&store, &reservation).unwrap().unwrap(),
                handle
            );
            let calls = api.calls.lock().unwrap();
            let puts: Vec<_> = calls
                .iter()
                .filter(|(operation, _)| operation == "put-object")
                .collect();
            assert_eq!(puts.len(), 1 + lost_reads);
            assert!(puts.iter().all(|request| request.1 == puts[0].1));
            let bodies = api.lease_bodies.lock().unwrap();
            assert!(bodies.iter().all(|body| *body == bodies[0]));
            drop(calls);
            drop(bodies);
            assert!(acquire_lease(&store, &reservation, crate::owner(), 122, 300).is_err());
            if let Some(old) = old {
                assert!(release_lease(&store, &old, 122).is_err());
            }
            release_lease(&store, &handle, 123).unwrap();
        }
    }
}

#[test]
fn acquisition_retries_are_bounded_and_only_retry_known_transient_errors() {
    for (code, attempts, eventual_success) in [
        ("ServiceUnavailable", 3, false),
        ("TransportError", 3, false),
        ("Throttling", 3, false),
        ("RequestTimeout", 2, true),
        ("AuthenticationExpired", 1, false),
        ("CredentialsUnavailable", 1, false),
        ("ConfigurationError", 1, false),
        ("AccessDenied", 1, false),
        ("CommandFailed", 1, false),
    ] {
        let api = ObjectApi::default();
        let team = fixture_team();
        let store = S3Metadata::new(&api, &team).unwrap();
        let reservation = reservation();
        reserve_network(&store, &reservation).unwrap();
        api.lease_faults
            .lock()
            .unwrap()
            .extend((0..attempts).map(|_| LeaseWriteFault::Fail(code)));
        let result = acquire_lease(&store, &reservation, owner(), 100, 300);
        assert_eq!(result.is_ok(), eventual_success, "{code}: {result:?}");
        let bodies = api.lease_bodies.lock().unwrap();
        assert_eq!(
            bodies.len(),
            attempts + usize::from(eventual_success),
            "{code}"
        );
        assert!(bodies.iter().all(|body| *body == bodies[0]), "{code}");
        assert_eq!(
            inspect_lease(&store, &reservation).unwrap().is_some(),
            eventual_success
        );
    }
}

#[test]
fn acquisition_never_adopts_an_inexact_record_after_a_lost_response() {
    let changes: [fn(&mut LeaseRecord); 5] = [
        |record| record.owner.holder_id = Uuid::new_v4(),
        |record| record.owner.operation_id = Uuid::new_v4(),
        |record| record.generation += 1,
        |record| record.expires_at += 1,
        |record| record.released = true,
    ];
    for alter in changes {
        let api = ObjectApi::default();
        let team = fixture_team();
        let store = S3Metadata::new(&api, &team).unwrap();
        let reservation = reservation();
        reserve_network(&store, &reservation).unwrap();
        api.lease_faults
            .lock()
            .unwrap()
            .push_back(LeaseWriteFault::Alter(alter));
        let error = acquire_lease(&store, &reservation, owner(), 100, 300).unwrap_err();
        assert!(error.is::<LeaseOwnershipChanged>(), "{error:#}");
        assert_eq!(api.lease_bodies.lock().unwrap().len(), 1);
        let attempted: LeaseRecord =
            serde_json::from_slice(&api.lease_bodies.lock().unwrap()[0]).unwrap();
        assert_ne!(
            inspect_lease(&store, &reservation).unwrap().unwrap().record,
            attempted
        );
    }
}

#[test]
fn acquisition_preserves_exclusivity_when_all_lost_reply_reads_fail() {
    let api = ObjectApi::default();
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    let reservation = reservation();
    reserve_network(&store, &reservation).unwrap();
    api.lease_faults
        .lock()
        .unwrap()
        .push_back(LeaseWriteFault::LostReply(3));
    assert!(acquire_lease(&store, &reservation, owner(), 100, 300)
        .unwrap_err()
        .to_string()
        .contains("uncertain"));
    assert_eq!(api.lease_bodies.lock().unwrap().len(), 3);
    let saved = inspect_lease(&store, &reservation).unwrap().unwrap();
    assert!(acquire_lease(&store, &reservation, owner(), 101, 300).is_err());
    assert_eq!(saved, inspect_lease(&store, &reservation).unwrap().unwrap());
}

#[test]
fn explicit_expired_lease_recovery_recovers_a_lost_response_with_the_exact_cas() {
    let api = ObjectApi::default();
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    let reservation = reservation();
    reserve_network(&store, &reservation).unwrap();
    let old = acquire_lease(&store, &reservation, owner(), 100, 300).unwrap();
    api.calls.lock().unwrap().clear();
    api.lease_faults
        .lock()
        .unwrap()
        .push_back(LeaseWriteFault::LostReply(1));
    let recovered = recover_lease(&store, &reservation, &old.etag, owner(), 401, 300).unwrap();
    assert_eq!(recovered.record.expires_at, 701);
    assert_eq!(recovered.record.generation, old.record.generation + 1);
    let calls = api.calls.lock().unwrap();
    let puts: Vec<_> = calls
        .iter()
        .filter(|(operation, _)| operation == "put-object")
        .collect();
    assert_eq!(puts.len(), 2);
    assert!(puts.iter().all(|(_, input)| input["IfMatch"] == old.etag));
    drop(calls);
    assert!(release_lease(&store, &old, 402).is_err());
    assert_eq!(
        inspect_lease(&store, &reservation).unwrap().unwrap(),
        recovered
    );
}

struct FakeAccessStack {
    directory: PathBuf,
    calls: Vec<&'static str>,
    exists: bool,
    fail_apply: bool,
    output: Value,
    selected: Option<zdn::access::DeploymentAccess>,
}
impl zdn::access_bootstrap::AccessStack for FakeAccessStack {
    fn exists(&mut self) -> Result<bool> {
        self.calls.push("exists");
        Ok(self.exists)
    }
    fn prepare(&mut self, create: bool) -> Result<()> {
        let receipt: zdn::access_bootstrap::AccessReceipt =
            zdn::foundation::read_json(&self.directory.join("access.json"))?;
        assert!(
            receipt.stack_started && receipt.uncertain,
            "receipt must precede stack mutation"
        );
        self.calls.push(if create { "init" } else { "select" });
        self.exists = true;
        Ok(())
    }
    fn refresh(&mut self) -> Result<()> {
        self.calls.push("refresh");
        Ok(())
    }
    fn configure(
        &mut self,
        request: &zdn::access::AccessRequest,
        saved: Option<&zdn::access::DeploymentAccess>,
    ) -> Result<zdn::access::DeploymentAccess> {
        self.calls.push("configure");
        Ok(self
            .selected
            .clone()
            .or_else(|| saved.cloned())
            .unwrap_or_else(|| request.access()))
    }
    fn apply(&mut self) -> Result<()> {
        let receipt: zdn::access_bootstrap::AccessReceipt =
            zdn::foundation::read_json(&self.directory.join("access.json"))?;
        assert!(
            receipt.selected_access.is_some(),
            "recovery identity must be saved before apply"
        );
        self.calls.push("apply");
        if self.fail_apply {
            self.fail_apply = false;
            bail!("lost apply response");
        }
        Ok(())
    }
    fn outputs(&mut self) -> Result<Value> {
        self.calls.push("outputs");
        Ok(self.output.clone())
    }
}

#[test]
fn access_bootstrap_orders_backend_checks_and_recovers_without_new_iam_ids() {
    use zdn::{
        access::AccessRequest,
        access_bootstrap::{provision, AccessReceipt},
    };
    let dir = TempDir::new().unwrap();
    let api = FakeAws::new(dir.path().join("backend.json"));
    let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
    let req = AccessRequest {
        team,
        administrator: selection(),
        trusted_principals: vec![format!("arn:aws:iam::{ACCOUNT}:user/developer")],
        existing: None,
    };
    let directory = dir.path().join("access");
    let mut stack = FakeAccessStack {
        directory: directory.clone(),
        calls: vec![],
        exists: false,
        fail_apply: true,
        output: json!({"roleArn":req.access().role_arn,"runtimeBoundaryArn":req.access().runtime_boundary_arn}),
        selected: None,
    };
    let mutations = api.mutations();
    assert!(provision(&api, &req, &directory, &mut stack, false)
        .unwrap_err()
        .to_string()
        .contains("lost apply"));
    assert_eq!(api.mutations(), mutations, "role setup only reads backend");
    assert_eq!(stack.calls, ["exists", "init", "configure", "apply"]);
    let receipt: AccessReceipt =
        zdn::foundation::read_json(&directory.join("access.json")).unwrap();
    assert!(receipt.uncertain && !receipt.complete);
    let before = stack.calls.len();
    assert!(provision(&api, &req, &directory, &mut stack, false).is_err());
    assert_eq!(
        stack.calls.len(),
        before,
        "uncertain retries fail before stack access"
    );
    let completed = provision(&api, &req, &directory, &mut stack, true).unwrap();
    assert_eq!(completed.deployment, Some(req.access()));
    assert_eq!(
        &stack.calls[before..],
        [
            "exists",
            "select",
            "refresh",
            "configure",
            "apply",
            "outputs"
        ]
    );
    assert_eq!(
        provision(&api, &req, &directory, &mut stack, false).unwrap(),
        completed
    );
    assert_eq!(stack.calls.iter().filter(|v| **v == "init").count(), 1);
    let receipt: AccessReceipt =
        zdn::foundation::read_json(&directory.join("access.json")).unwrap();
    assert!(receipt.complete && !receipt.uncertain);
    assert_eq!(receipt.request, req);
    let mut changed = req.clone();
    changed
        .trusted_principals
        .push(format!("arn:aws:iam::{ACCOUNT}:user/other"));
    let before = stack.calls.len();
    assert!(provision(&api, &changed, &directory, &mut stack, true).is_err());
    assert_eq!(stack.calls.len(), before);
}

#[test]
fn legacy_boundary_choice_is_saved_before_apply_and_cannot_change_on_retry() {
    use zdn::{
        access::AccessRequest,
        access_bootstrap::{provision, AccessReceipt},
    };
    let dir = TempDir::new().unwrap();
    let api = FakeAws::new(dir.path().join("backend.json"));
    let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
    let req = AccessRequest {
        team,
        administrator: selection(),
        trusted_principals: vec![format!("arn:aws:iam::{ACCOUNT}:user/developer")],
        existing: None,
    };
    let mut legacy = req.access();
    legacy.runtime_boundary_arn = legacy
        .runtime_boundary_arn
        .strip_suffix("-boundary")
        .unwrap()
        .into();
    let directory = dir.path().join("access");
    zdn::foundation::private_directory(&directory).unwrap();
    // The old receipt format has no selected_access field. Its failed apply
    // created the original boundary but could not create the management policy.
    zdn::foundation::write_json(
        &directory.join("access.json"),
        &json!({
            "version":1,"request":req,"stack_started":true,"uncertain":true,"complete":false
        }),
    )
    .unwrap();
    let mut stack = FakeAccessStack {
        directory: directory.clone(),
        calls: vec![],
        exists: true,
        fail_apply: true,
        output: json!({"roleArn":legacy.role_arn,"runtimeBoundaryArn":legacy.runtime_boundary_arn}),
        selected: Some(legacy.clone()),
    };
    assert!(provision(&api, &req, &directory, &mut stack, true)
        .unwrap_err()
        .to_string()
        .contains("lost apply"));
    let receipt: AccessReceipt =
        zdn::foundation::read_json(&directory.join("access.json")).unwrap();
    assert_eq!(receipt.selected_access, Some(legacy.clone()));
    assert!(receipt.uncertain && !receipt.complete);
    // A changed backend selection is rejected before another apply or receipt rewrite.
    stack.selected = Some(req.access());
    let applies = stack.calls.iter().filter(|v| **v == "apply").count();
    assert!(provision(&api, &req, &directory, &mut stack, true).is_err());
    assert_eq!(
        stack.calls.iter().filter(|v| **v == "apply").count(),
        applies
    );
    let receipt: AccessReceipt =
        zdn::foundation::read_json(&directory.join("access.json")).unwrap();
    assert_eq!(receipt.selected_access, Some(legacy.clone()));
    stack.selected = None;
    let completed = provision(&api, &req, &directory, &mut stack, true).unwrap();
    assert_eq!(completed.deployment, Some(legacy));
    completed.validate().unwrap();
    assert_eq!(
        provision(&api, &req, &directory, &mut stack, false).unwrap(),
        completed
    );
    assert!(!stack.calls.contains(&"init"));
}

#[test]
fn access_bootstrap_rejects_missing_admin_access_foreign_stack_and_wrong_outputs() {
    use zdn::{access::AccessRequest, access_bootstrap::provision};
    let dir = TempDir::new().unwrap();
    let api = FakeAws::new(dir.path().join("backend.json"));
    let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
    let req = AccessRequest {
        team,
        administrator: selection(),
        trusted_principals: vec![format!("arn:aws:iam::{ACCOUNT}:user/developer")],
        existing: None,
    };
    let directory = dir.path().join("access");
    let mut stack = FakeAccessStack {
        directory: directory.clone(),
        calls: vec![],
        exists: true,
        fail_apply: false,
        output: json!({"roleArn":"wrong"}),
        selected: None,
    };
    api.cloud.lock().unwrap().fail_sts = true;
    assert!(provision(&api, &req, &directory, &mut stack, false).is_err());
    assert!(stack.calls.is_empty());
    api.cloud.lock().unwrap().fail_sts = false;
    let error = provision(&api, &req, &directory, &mut stack, false).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("without a local ownership receipt"),
        "{error:#}"
    );
    assert_eq!(stack.calls, ["exists"]);
    stack.exists = false;
    assert!(provision(&api, &req, &directory, &mut stack, false)
        .unwrap_err()
        .to_string()
        .contains("outputs differ"));
    let receipt: zdn::access_bootstrap::AccessReceipt =
        zdn::foundation::read_json(&directory.join("access.json")).unwrap();
    assert!(receipt.uncertain && !receipt.complete);
}

#[test]
fn external_access_checks_trust_without_iam_mutations_or_pulumi_calls() {
    use zdn::{
        access::{AccessRequest, DeploymentAccess, RoleManagement},
        access_bootstrap::{provision, NoStack},
    };
    struct External<'a> {
        backend: &'a FakeAws,
        role: DeploymentAccess,
        principal: String,
        deny_trust: bool,
    }
    impl AwsApi for External<'_> {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            if service != "iam" {
                return self.backend.call(service, operation, input, extra);
            }
            match operation {
                "get-role" => Ok(
                    json!({"Role":{"Arn":self.role.role_arn,"AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":if self.deny_trust {"wrong"} else {&self.principal}}}]}}}),
                ),
                "get-policy" => Ok(json!({"Policy":{"Arn":self.role.runtime_boundary_arn}})),
                _ => panic!("unexpected IAM operation {operation}"),
            }
        }
    }
    let dir = TempDir::new().unwrap();
    let api = FakeAws::new(dir.path().join("backend.json"));
    let team = bootstrap(&api, &selection(), &request(), &api.receipt, None).unwrap();
    let role = DeploymentAccess {
        role_arn: format!("arn:aws:iam::{ACCOUNT}:role/org/deployment"),
        management: RoleManagement::External,
        runtime_boundary_arn: format!("arn:aws:iam::{ACCOUNT}:policy/org/runtime"),
    };
    let principal = format!("arn:aws:iam::{ACCOUNT}:user/developer");
    let req = AccessRequest {
        team,
        administrator: selection(),
        trusted_principals: vec![principal.clone()],
        existing: Some(role.clone()),
    };
    let mut external = External {
        backend: &api,
        role,
        principal,
        deny_trust: true,
    };
    let mutations = api.mutations();
    assert!(provision(
        &external,
        &req,
        &dir.path().join("access"),
        &mut NoStack,
        false
    )
    .is_err());
    external.deny_trust = false;
    let completed = provision(
        &external,
        &req,
        &dir.path().join("access"),
        &mut NoStack,
        false,
    )
    .unwrap();
    assert_eq!(completed.deployment, req.existing);
    assert_eq!(api.mutations(), mutations);
}

#[test]
fn s3_metadata_uses_expected_owner_encryption_and_conditional_headers() {
    let api = ObjectApi::default();
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    let record = reservation();
    assert!(store.get(&record.key()).unwrap().is_none());
    reserve_network(&store, &record).unwrap();
    let mut lease = acquire_lease(&store, &record, owner(), 100, 300).unwrap();
    let old = lease.clone();
    renew_lease(&store, &mut lease, 130, 300).unwrap();
    assert!(release_lease(&store, &old, 140).is_err());
    release_lease(&store, &lease, 140).unwrap();
    let calls = api.calls.lock().unwrap();
    assert!(calls
        .iter()
        .any(|(_, input)| input.get("IfNoneMatch") == Some(&json!("*"))));
    assert!(calls
        .iter()
        .any(|(_, input)| input.get("IfMatch").is_some()));
    assert!(calls.iter().all(|(op, _)| op != "delete-object"));
}

#[test]
fn s3_metadata_rejects_state_or_cross_team_keys_and_oversized_records() {
    let api = ObjectApi::default();
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    for key in [
        "pulumi/team-a/.pulumi/stacks/main.json",
        "zdn-meta/v1/team-b/networks/x",
        "zdn-meta/v1/team-a/../other",
    ] {
        assert!(store.get(key).is_err());
        assert!(store.put(key, b"{}", WriteCondition::Absent).is_err());
    }
    assert!(api.calls.lock().unwrap().is_empty());
    let record = reservation();
    assert!(store
        .put(&record.key(), &vec![0; 65537], WriteCondition::Absent)
        .is_err());
    api.objects
        .put(&record.key(), &vec![0; 65537], WriteCondition::Absent)
        .unwrap();
    assert!(store.get(&record.key()).is_err());
}

#[test]
fn s3_access_denied_is_not_misclassified_as_missing_state() {
    let api = ObjectApi {
        denied: true,
        ..Default::default()
    };
    let team = fixture_team();
    let store = S3Metadata::new(&api, &team).unwrap();
    assert!(store
        .get(&reservation().key())
        .unwrap_err()
        .to_string()
        .contains("AccessDenied"));
    assert!(store
        .put(&reservation().key(), b"{}", WriteCondition::Absent)
        .is_err());
}

#[test]
fn reservation_retry_limit_is_bounded_without_new_owner_or_overwrite() {
    let store = MemoryStore::default();
    let record = reservation();
    store.0.lock().unwrap().conflicts = 3;
    assert!(reserve_network(&store, &record)
        .unwrap_err()
        .to_string()
        .contains("same owner"));
    assert!(store.get(&record.key()).unwrap().is_none());
    reserve_network(&store, &record).unwrap();
}

#[test]
fn new_bootstrap_in_another_region_sets_location_constraint() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let api = FakeAws::new(path.clone());
    let mut request = request();
    request.region = "us-west-2".into();
    let mut selection = selection();
    selection.region = "us-west-2".into();
    // The fake KMS response is intentionally in the original region. The request
    // must stop at that boundary while still proving the S3 location contract.
    assert!(bootstrap(&api, &selection, &request, &path, None).is_err());
    let cloud = api.cloud.lock().unwrap();
    let create = cloud
        .calls
        .iter()
        .find(|(op, _)| op == "create-bucket")
        .unwrap();
    assert_eq!(
        create.1["CreateBucketConfiguration"]["LocationConstraint"],
        "us-west-2"
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_rejects_symlink_recovery_receipt_before_mutations() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("recovery.json");
    let target = dir.path().join("elsewhere");
    fs::write(&target, b"preserve").unwrap();
    symlink(&target, &path).unwrap();
    let api = FakeAws::new(path.clone());
    assert!(bootstrap(&api, &selection(), &request(), &path, None).is_err());
    assert!(api.mutations().is_empty());
    assert_eq!(fs::read(&target).unwrap(), b"preserve");
}

#[test]
fn invalid_team_components_fail_before_aws_calls() {
    for team in [".", ".."] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery.json");
        let api = FakeAws::new(path.clone());
        let mut request = request();
        request.team_id = team.into();
        assert!(bootstrap(&api, &selection(), &request, &path, None).is_err());
        assert!(api.cloud.lock().unwrap().calls.is_empty());
        assert!(!path.exists());
    }
}

#[cfg(unix)]
#[test]
fn aws_cli_reports_operation_and_exit_without_raw_diagnostics() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    for (service, operation, diagnostic, termination, code, exit) in [
        (
            "ec2",
            "describe-volumes",
            "An error occurred (InvalidVolume.NotFound) when calling: fixture-secret",
            "exit 1",
            "InvalidVolume.NotFound",
            "1",
        ),
        (
            "iam",
            "get-policy",
            "unrecognized fixture-secret diagnostic",
            "exit 255",
            "CommandFailed",
            "255",
        ),
        (
            "sts",
            "assume-role",
            "fixture-secret credential-process diagnostic",
            "kill -TERM $$",
            "CommandFailed",
            "none",
        ),
    ] {
        executable::write(
            &script,
            format!("#!/bin/sh\nprintf '%s\\n' 'stdout-secret'\nprintf '%s\\n' '{diagnostic}' >&2\n{termination}\n"),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let cli = AwsCli::with_environment(selection(), &script, BTreeMap::new()).unwrap();
        let error = cli
            .call(service, operation, json!({"request":"request-secret"}), &[])
            .unwrap_err();
        assert_eq!(error.downcast_ref::<AwsApiError>().unwrap().code, code);
        assert_eq!(
            error.to_string(),
            format!("AWS {service} {operation} subprocess failed (exit code {exit})")
        );
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains(&format!("AWS request failed ({code})")));
        for secret in ["fixture-secret", "stdout-secret", "request-secret"] {
            assert!(!diagnostic.contains(secret));
        }
    }
}

#[cfg(unix)]
#[test]
fn aws_cli_classifies_only_known_diagnostics_with_optional_error_prefix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    executable::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' 'stdout-secret'\nprintf '%s\\n' \"$ZDN_DIAGNOSTIC\" >&2\nexit 255\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

    for (diagnostic, code) in [
        ("Your session has expired. fixture-secret", "AuthenticationExpired"),
        (
            "Unable to refresh login credentials because of a change in your password. fixture-secret",
            "AuthenticationExpired",
        ),
        (
            "The SSO session associated with this profile has expired fixture-secret",
            "AuthenticationExpired",
        ),
        ("Error loading SSO Token: fixture-secret", "AuthenticationExpired"),
        (
            "Cannot refresh credentials: MFA token required. fixture-secret",
            "AuthenticationExpired",
        ),
        (
            "Error when retrieving token from fixture-secret: Token has expired and refresh failed",
            "AuthenticationExpired",
        ),
        ("Unable to locate credentials fixture-secret", "CredentialsUnavailable"),
        ("Unable to locate authorization token fixture-secret", "CredentialsUnavailable"),
        ("Partial credentials found in fixture-secret", "CredentialsUnavailable"),
        ("Error when retrieving credentials from fixture-secret", "CredentialsUnavailable"),
        ("Error when retrieving token from fixture-secret", "CredentialsUnavailable"),
        (
            "Unable to create or refresh login credentials due to insufficient permissions. fixture-secret",
            "CredentialsUnavailable",
        ),
        (
            "An unspecified error happened when resolving AWS credentials fixture-secret",
            "CredentialsUnavailable",
        ),
        ("The config profile (fixture-secret) could not be found", "ConfigurationError"),
        ("Unable to parse config file: fixture-secret", "ConfigurationError"),
        (
            "Infinite loop in credential configuration detected. fixture-secret",
            "ConfigurationError",
        ),
        ("You must specify a region. fixture-secret", "ConfigurationError"),
        ("Could not connect to the endpoint URL: fixture-secret", "TransportError"),
        (
            "Connection was closed before we received a valid response fixture-secret",
            "TransportError",
        ),
        ("Read timeout on endpoint URL: fixture-secret", "TransportError"),
        ("Connect timeout on endpoint URL: fixture-secret", "TransportError"),
        ("Failed to connect to proxy URL: fixture-secret", "TransportError"),
        (
            "An error occurred (AccessDenied) when calling: fixture-secret",
            "AccessDenied",
        ),
        ("unknown fixture-secret diagnostic", "CommandFailed"),
        ("fixture-secret: Read timeout on endpoint URL:", "CommandFailed"),
        ("fixture-secret aws: [ERROR]: Read timeout on endpoint URL:", "CommandFailed"),
        ("aws: [ERROR]:Read timeout on endpoint URL: fixture-secret", "CommandFailed"),
        ("aws: [error]: Read timeout on endpoint URL: fixture-secret", "CommandFailed"),
        ("aws: [WARNING]: Read timeout on endpoint URL: fixture-secret", "CommandFailed"),
        ("aws: [ERROR]: aws: [ERROR]: Read timeout on endpoint URL: fixture-secret", "CommandFailed"),
        ("fixture-secret: Unable to locate credentials", "CommandFailed"),
        ("fixture-secret: You must specify a region.", "CommandFailed"),
        (
            "Error when retrieving credentials from fixture-secret: An error occurred (ServiceUnavailable)",
            "CredentialsUnavailable",
        ),
        (
            "Error when retrieving token from fixture-secret: Token has expired and refresh failed\nAn error occurred (ServiceUnavailable)",
            "AuthenticationExpired",
        ),
        (
            "Unable to parse config file: fixture-secret\nAn error occurred (ServiceUnavailable)",
            "ConfigurationError",
        ),
        (
            "An error occurred (AccessDenied)\nRead timeout on endpoint URL: fixture-secret",
            "AccessDenied",
        ),
    ] {
        for prefix in ["", "aws: [ERROR]: "] {
            let cli = AwsCli::with_environment(
                selection(),
                &script,
                BTreeMap::from([(
                    "ZDN_DIAGNOSTIC".into(),
                    format!("\n  {prefix}{diagnostic}  \n"),
                )]),
            )
            .unwrap();
            let error = cli
                .call("s3api", "head-bucket", json!({"request":"request-secret"}), &[])
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<AwsApiError>().unwrap().code,
                code,
                "prefix {prefix:?}, diagnostic {diagnostic:?}"
            );
            assert_eq!(
                error.to_string(),
                "AWS s3api head-bucket subprocess failed (exit code 255)"
            );
            let message = format!("{error:#}");
            assert!(message.contains(&format!("AWS request failed ({code})")));
            for secret in ["fixture-secret", "stdout-secret", "request-secret"] {
                assert!(!message.contains(secret));
            }
        }
    }
}

#[cfg(unix)]
struct ErrorFormatFixture {
    dir: TempDir,
    script: PathBuf,
    capture: PathBuf,
    config: PathBuf,
}

#[cfg(unix)]
impl ErrorFormatFixture {
    fn new(profile_format: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("aws fixture");
        let capture = dir.path().join("calls");
        let config = dir.path().join("config");
        fs::write(
            &config,
            format!("[profile developer]\ncli_error_format = {profile_format}\n"),
        )
        .unwrap();
        // Model AWS CLI 2.37.4's documented flag > environment > profile
        // precedence. Without the explicit flag, these profiles emit a format
        // that the production legacy parser cannot classify.
        executable::write(
            &script,
            r#"#!/bin/sh
if [ "$1" = '--version' ]; then printf '%s\n' 'aws-cli/2.37.4 Python/3 fixture'; exit 0; fi
format=enhanced
while IFS= read -r line; do
    case "$line" in cli_error_format\ =\ *) format="${line#*= }";; esac
done < "$AWS_CONFIG_FILE"
format="${AWS_CLI_ERROR_FORMAT:-$format}"
previous=
operation=
for argument in "$@"; do
    if [ "$previous" = '--cli-error-format' ]; then format="$argument"; fi
    case "$argument" in
        get-caller-identity|head-bucket|create-bucket|get-object|put-object|describe-volumes) operation="$argument";;
    esac
    previous="$argument"
done
printf '%s:%s\n' "$operation" "$format" >> "$ZDN_CAPTURE"
if [ "$operation" = 'get-caller-identity' ]; then
    printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/deploy/fixture","UserId":"fixture"}'
    exit 0
fi
case "$format" in
    legacy|enhanced) printf 'An error occurred (%s) when calling the fixture operation: fixture-secret\n' "$ZDN_ERROR_CODE" >&2;;
    json) printf '{"Code":"%s","Message":"fixture-secret"}\n' "$ZDN_ERROR_CODE" >&2;;
    yaml) printf 'Code: %s\nMessage: fixture-secret\n' "$ZDN_ERROR_CODE" >&2;;
    text) printf '%s\tfixture-secret\n' "$ZDN_ERROR_CODE" >&2;;
    table) printf '| Code | Message |\n| %s | fixture-secret |\n' "$ZDN_ERROR_CODE" >&2;;
    *) exit 2;;
esac
exit 254
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            dir,
            script,
            capture,
            config,
        }
    }

    fn cli(&self, code: &str) -> AwsCli {
        AwsCli::with_environment(
            selection(),
            &self.script,
            BTreeMap::from([
                (
                    "AWS_CONFIG_FILE".into(),
                    self.config.to_string_lossy().into_owned(),
                ),
                ("AWS_CLI_ERROR_FORMAT".into(), "yaml".into()),
                (
                    "ZDN_CAPTURE".into(),
                    self.capture.to_string_lossy().into_owned(),
                ),
                ("ZDN_ERROR_CODE".into(), code.into()),
            ]),
        )
        .unwrap()
    }
}

#[cfg(unix)]
#[test]
fn aws_cli_pins_error_format_across_profile_settings_and_redacts_messages() {
    for format in ["json", "yaml", "text", "table"] {
        let fixture = ErrorFormatFixture::new(format);
        for code in [
            "404",
            "NoSuchKey",
            "PreconditionFailed",
            "InvalidVolume.NotFound",
            "AccessDenied",
        ] {
            let cli = fixture.cli(code);
            cli.verify_cli_version().unwrap();
            let error = cli
                .call("ec2", "describe-volumes", json!({}), &[])
                .unwrap_err();
            assert_eq!(error.downcast_ref::<AwsApiError>().unwrap().code, code);
            assert_eq!(
                error.to_string(),
                "AWS ec2 describe-volumes subprocess failed (exit code 254)"
            );
            assert!(format!("{error:#}").contains(&format!("AWS request failed ({code})")));
            assert!(!format!("{error:#}").contains("fixture-secret"));
        }
        assert_eq!(
            fs::read_to_string(&fixture.capture).unwrap(),
            "describe-volumes:legacy\n".repeat(5)
        );
    }
}

#[cfg(unix)]
#[test]
fn aws_cli_json_profile_missing_bucket_reaches_create_with_durable_receipt() {
    let fixture = ErrorFormatFixture::new("json");
    let receipt_path = fixture.dir.path().join("recovery.json");
    let error = bootstrap(
        &fixture.cli("404"),
        &selection(),
        &request(),
        &receipt_path,
        None,
    )
    .unwrap_err();
    // The fake create fails deliberately. Reaching it proves the missing-bucket
    // API error was classified; the durable receipt still precedes the attempt.
    assert!(format!("{error:#}").contains("bucket creation interrupted"));
    assert!(!format!("{error:#}").contains("fixture-secret"));
    let receipt: BootstrapReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    assert!(receipt.bucket_creation_started);
    assert!(!receipt.bucket_created);
    assert_eq!(
        fs::read_to_string(&fixture.capture).unwrap(),
        "get-caller-identity:legacy\nhead-bucket:legacy\ncreate-bucket:legacy\n"
    );
}

#[cfg(unix)]
#[test]
fn aws_cli_profile_format_preserves_missing_metadata_and_conditional_conflicts() {
    let fixture = ErrorFormatFixture::new("table");
    let team = fixture_team();
    let key = reservation().key();
    for code in ["NoSuchKey", "404"] {
        let api = fixture.cli(code);
        let store = S3Metadata::new(&api, &team).unwrap();
        assert!(store.get(&key).unwrap().is_none());
    }
    for code in [
        "PreconditionFailed",
        "ConditionalRequestConflict",
        "412",
        "409",
    ] {
        let api = fixture.cli(code);
        let store = S3Metadata::new(&api, &team).unwrap();
        assert_eq!(
            store.put(&key, b"{}", WriteCondition::Absent).unwrap(),
            ConditionalWrite::Conflict
        );
    }
    let denied = fixture.cli("AccessDenied");
    let store = S3Metadata::new(&denied, &team).unwrap();
    assert!(store.get(&key).is_err());
    assert!(store.put(&key, b"{}", WriteCondition::Absent).is_err());
}

#[cfg(unix)]
#[test]
fn aws_cli_honors_the_call_budget_and_rejects_zero_before_launch() {
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("aws");
    let marker = dir.path().join("launched");
    executable::write(&script, "#!/bin/sh\nprintf launched > \"$ZDN_MARKER\"\nprintf 'private fixture diagnostic' >&2\nexec /bin/sleep 10\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cli = AwsCli::with_environment(
        selection(),
        &script,
        BTreeMap::from([("ZDN_MARKER".into(), marker.to_string_lossy().into_owned())]),
    )
    .unwrap();
    assert!(cli
        .call_with_timeout(
            "ssm",
            "describe-instance-information",
            json!({}),
            &[],
            Duration::ZERO
        )
        .is_err());
    assert!(!marker.exists());
    let started = Instant::now();
    let error = cli
        .call_with_timeout(
            "ssm",
            "describe-instance-information",
            json!({}),
            &[],
            Duration::from_millis(100),
        )
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "per-call budget must bound the child process, not only CLI socket timeouts"
    );
    assert!(marker.exists());
    assert_eq!(
        error.downcast_ref::<AwsApiError>().unwrap().code,
        "CommandInterrupted"
    );
    assert_eq!(
        error.to_string(),
        "AWS ssm describe-instance-information subprocess did not complete"
    );
    assert!(!format!("{error:#}").contains("private fixture diagnostic"));
}
