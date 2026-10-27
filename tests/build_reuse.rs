//! Offline pointer-only tests: no result files, image records, tags or ECR calls.
use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::VecDeque, fs};
use uuid::Uuid;
use zdn::{
    aws::{AwsApi, AwsApiError},
    build::{BuildContract, BuildRecipe},
    build_infra::BuildInfrastructure,
    build_reuse::{lookup, publish},
    image::ImageCapabilities,
};

enum Step {
    Put(Option<&'static str>),
    UnconfirmedPut,
    Get(Vec<u8>, bool),
    Error(&'static str),
}
struct Script {
    steps: RefCell<VecDeque<Step>>,
    saved: RefCell<Vec<u8>>,
    key: String,
    directory: std::path::PathBuf,
}
impl Script {
    fn new(contract: &BuildContract, directory: &std::path::Path, steps: Vec<Step>) -> Self {
        Self {
            steps: RefCell::new(steps.into()),
            saved: RefCell::new(Vec::new()),
            key: format!("images/{}.json", contract.fingerprint().unwrap()),
            directory: directory.into(),
        }
    }
    fn done(&self) {
        assert!(self.steps.borrow().is_empty());
    }
}
impl AwsApi for Script {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert_eq!(service, "s3api");
        assert_eq!(input["Key"], self.key);
        assert_eq!(input["Bucket"], "zdn-test-build");
        assert_eq!(input["ExpectedBucketOwner"], "123456789012");
        let error = |code: &str| eyre::Report::from(AwsApiError { code: code.into() });
        match self
            .steps
            .borrow_mut()
            .pop_front()
            .expect("unexpected AWS call")
        {
            Step::Put(failure) => {
                assert_eq!(operation, "put-object");
                assert_eq!(input["IfNoneMatch"], "*");
                assert_eq!(input["ServerSideEncryption"], "AES256");
                assert_eq!(extra[0], "--body");
                assert_eq!(
                    std::path::Path::new(&extra[1]).parent(),
                    Some(self.directory.as_path())
                );
                let bytes = fs::read(&extra[1])?;
                assert_eq!(
                    input["ChecksumSHA256"],
                    STANDARD.encode(Sha256::digest(&bytes))
                );
                if failure != Some("PreconditionFailed")
                    && failure != Some("ConditionalRequestConflict")
                {
                    *self.saved.borrow_mut() = bytes;
                }
                if let Some(code) = failure {
                    return Err(error(code));
                }
                Ok(
                    json!({"ServerSideEncryption":"AES256","ChecksumSHA256":input["ChecksumSHA256"]}),
                )
            }
            Step::Get(bytes, encrypted) => {
                assert_eq!(operation, "get-object");
                assert_eq!(input["Range"], "bytes=0-4096");
                assert_eq!(
                    std::path::Path::new(&extra[0]).parent(),
                    Some(self.directory.as_path())
                );
                fs::write(&extra[0], bytes)?;
                Ok(json!({"ServerSideEncryption":if encrypted {"AES256"} else {"aws:kms"}}))
            }
            Step::UnconfirmedPut => {
                assert_eq!(operation, "put-object");
                Ok(json!({"ServerSideEncryption":"AES256","ChecksumSHA256":"wrong"}))
            }
            Step::Error(code) => Err(error(code)),
        }
    }
}
fn fixtures() -> (BuildInfrastructure, BuildContract) {
    (
        BuildInfrastructure {
            source_bucket: "zdn-test-build".into(),
            project_name: "zdn-test-build".into(),
            repository: "zdn/test/build".into(),
            repository_uri: "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/build".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        BuildContract {
            api_version: "zdn-build/v1alpha1".into(),
            source_sha256: "a".repeat(64),
            source_bytes: 1,
            revision: "b".repeat(40),
            recipe: BuildRecipe {
                dockerfile: "Dockerfile".into(),
                context: ".".into(),
                target: "runtime".into(),
            },
            platform: "linux/amd64".into(),
            required_capabilities: ImageCapabilities::default(),
        },
    )
}

#[test]
fn only_typed_no_such_key_is_a_miss() {
    let (infra, contract) = fixtures();
    let dir = tempfile::tempdir().unwrap();
    for code in [
        "NoSuchKey",
        "AccessDenied",
        "404",
        "NoSuchBucket",
        "NotFound",
        "TransportError",
    ] {
        let api = Script::new(&contract, dir.path(), vec![Step::Error(code)]);
        let result = lookup(&api, &infra, &contract, dir.path());
        if code == "NoSuchKey" {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(result.is_err());
        }
        api.done();
    }
}

#[test]
fn round_trip_is_only_a_pointer_and_rejects_unbound_records() {
    let (infra, contract) = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let attempt = Uuid::new_v4();
    let api = Script::new(&contract, dir.path(), vec![Step::Put(None)]);
    publish(&api, &infra, &contract, attempt, dir.path()).unwrap();
    let bytes = api.saved.borrow().clone();
    let read = Script::new(&contract, dir.path(), vec![Step::Get(bytes.clone(), true)]);
    assert_eq!(
        lookup(&read, &infra, &contract, dir.path()).unwrap(),
        Some(attempt)
    );
    read.done();
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    for field in [
        "contractSha256",
        "sourceBucket",
        "projectName",
        "repository",
        "repositoryUri",
        "accountId",
        "region",
        "attempt",
        "version",
        "unknown",
    ] {
        let mut record = original.clone();
        record[field] = if field == "version" {
            json!(2)
        } else if field == "attempt" {
            json!(Uuid::nil())
        } else {
            json!("foreign")
        };
        let read = Script::new(
            &contract,
            dir.path(),
            vec![Step::Get(serde_json::to_vec(&record).unwrap(), true)],
        );
        assert!(
            lookup(&read, &infra, &contract, dir.path()).is_err(),
            "{field}"
        );
        read.done();
    }
    for (bytes, encrypted) in [
        (vec![b' '; 4097], true),
        (b"{".to_vec(), true),
        (bytes, false),
    ] {
        let read = Script::new(&contract, dir.path(), vec![Step::Get(bytes, encrypted)]);
        assert!(lookup(&read, &infra, &contract, dir.path()).is_err());
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn immutable_conflicts_and_lost_outcomes_are_bounded() {
    let (infra, contract) = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let attempt = Uuid::new_v4();
    let lost = Script::new(
        &contract,
        dir.path(),
        vec![Step::Put(Some("TransportError"))],
    );
    assert!(publish(&lost, &infra, &contract, attempt, dir.path()).is_err());
    lost.done();
    let saved = lost.saved.borrow().clone();
    for conflict in ["PreconditionFailed", "ConditionalRequestConflict"] {
        for next_attempt in [attempt, Uuid::new_v4()] {
            let api = Script::new(
                &contract,
                dir.path(),
                vec![Step::Put(Some(conflict)), Step::Get(saved.clone(), true)],
            );
            publish(&api, &infra, &contract, next_attempt, dir.path()).unwrap();
            api.done();
        }
    }
    for step in [
        Step::Error("NoSuchKey"),
        Step::Error("AccessDenied"),
        Step::Get(b"{}".to_vec(), true),
    ] {
        let api = Script::new(
            &contract,
            dir.path(),
            vec![Step::Put(Some("PreconditionFailed")), step],
        );
        assert!(publish(&api, &infra, &contract, attempt, dir.path()).is_err());
        api.done();
    }
    let api = Script::new(&contract, dir.path(), vec![]);
    assert!(publish(&api, &infra, &contract, Uuid::nil(), dir.path()).is_err());
    api.done();
    for step in [
        Step::UnconfirmedPut,
        Step::Error("AccessDenied"),
        Step::Error("404"),
    ] {
        let api = Script::new(&contract, dir.path(), vec![step]);
        assert!(publish(&api, &infra, &contract, attempt, dir.path()).is_err());
        api.done();
    }
}
