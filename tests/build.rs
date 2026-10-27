//! Offline D16 contract and job boundary tests; no builder or node is executed.
#[path = "support/iam.rs"]
mod iam;

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

#[cfg(unix)]
#[path = "support/native_tool.rs"]
mod native_tool;

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::PathBuf,
    process::Command,
    time::Duration,
};
use uuid::Uuid;
use zdn::{
    aws::{AwsApi, AwsCall, TeamDefinition},
    build::{BuildContract, BuildRecipe},
    build_infra::BuildInfrastructure,
    build_job::{self, BuildResult},
    foundation_live::Runtime,
    image::{self, ImageCapabilities, ImageProvenance, ImageRecord},
};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn team() -> TeamDefinition {
    serde_json::from_value(json!({
        "apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
        "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-test-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap()
}

// None is a regular file; Some is a symlink. No extraction is needed.
fn tar_bytes(entries: &[(&str, &[u8], Option<&str>)]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes, link) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(if link.is_some() {
            0
        } else {
            bytes.len() as u64
        });
        if let Some(target) = link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name(target).unwrap();
        }
        header.set_cksum();
        tar.append_data(&mut header, name, *bytes).unwrap();
    }
    tar.into_inner().unwrap()
}

struct Fixture {
    root: tempfile::TempDir,
    archive: PathBuf,
    contract: BuildContract,
    infra: BuildInfrastructure,
    result: Value,
    manifest: Vec<u8>,
    config: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("source.tar");
        let bytes = tar_bytes(&[("docker/Dockerfile", b"FROM scratch\n", None)]);
        fs::write(&archive, &bytes).unwrap();
        let contract = BuildContract {
            api_version: "zdn-build/v1alpha1".into(),
            source_sha256: hash(&bytes),
            source_bytes: bytes.len() as u64,
            revision: "a".repeat(40),
            recipe: BuildRecipe {
                dockerfile: "docker/Dockerfile".into(),
                context: ".".into(),
                target: "runtime".into(),
            },
            platform: "linux/amd64".into(),
            required_capabilities: ImageCapabilities::default(),
        };
        let infra = BuildInfrastructure::for_team(&team()).unwrap();
        // Independent expected export and exact input bytes retained from
        // tests/build.rs::Fixture::new at installer commit 1a946d9.
        // Do not derive these expectations from the native exporter.
        let config = serde_json::to_vec(&json!({
            "architecture":"amd64","os":"linux","config":{},
            "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}", hash(b"uncompressed layer"))]}
        })).unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hash(&config)),"size":config.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}",hash(b"compressed layer")),"size":16}]
        })).unwrap();
        let record = ImageRecord {
            api_version: image::API_VERSION.into(),
            image: format!("{}@sha256:{}", infra.repository_uri, hash(&manifest)),
            config_digest: format!("sha256:{}", hash(&config)),
            platform: contract.platform.clone(),
            provenance: ImageProvenance::Source {
                revision: contract.revision.clone(),
                snapshot_sha256: contract.source_sha256.clone(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        };
        let result =
            json!({"contractSha256":hash(&serde_json::to_vec(&contract).unwrap()),"image":record});
        let fixture = Self {
            root,
            archive,
            contract,
            infra,
            result,
            manifest,
            config,
        };
        fixture.prepare(&fixture.directory());
        fixture
    }

    fn prepare(&self, directory: &std::path::Path) {
        let helper = self.root.path().join("helper");
        let mut bytes = [0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        fs::write(&helper, bytes).unwrap();
        build_job::prepare_native(directory, &team(), &self.contract, &helper).unwrap();
    }

    fn directory(&self) -> PathBuf {
        self.root.path().join("attempt")
    }

    fn run(&self, api: &FakeAws, clock: &Clock) -> Result<BuildResult> {
        build_job::run(
            api,
            &team(),
            &self.contract,
            &self.archive,
            &self.directory(),
            clock,
            || Ok(()),
        )
    }
}

#[derive(Default)]
struct Clock {
    seconds: Cell<u64>,
    jump: bool,
}
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        bail!("wall clock must not bound polling")
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.seconds.get())
    }
    fn sleep(&self, duration: Duration) {
        assert_eq!(duration, Duration::from_secs(5));
        self.seconds
            .set(self.seconds.get() + if self.jump { 11_100 } else { 5 });
    }
}

struct FakeAws {
    infra: BuildInfrastructure,
    source: Vec<u8>,
    result: Value,
    manifest: Vec<u8>,
    config: Vec<u8>,
    status: &'static str,
    uncertain: bool,
    registry_mismatch: bool,
    bad_exporter_ack: bool,
    bad_source_ack: bool,
    fail_upload: Option<bool>, // true: exporter, false: source
    starts: Cell<usize>,
    uploads: Cell<usize>,
    source_upload_attempts: Cell<usize>,
    exporter_uploads: Cell<usize>,
    polls: Cell<usize>,
    stops: RefCell<Vec<String>>,
    attempt: RefCell<Option<String>>,
    spec: RefCell<String>,
    index: RefCell<Option<Vec<u8>>>,
    deployment_policy: Value,
    recovery: &'static str,
}
impl FakeAws {
    fn new(f: &Fixture) -> Self {
        Self {
            infra: f.infra.clone(),
            source: fs::read(&f.archive).unwrap(),
            result: f.result.clone(),
            manifest: f.manifest.clone(),
            config: f.config.clone(),
            status: "SUCCEEDED",
            uncertain: false,
            registry_mismatch: false,
            bad_exporter_ack: false,
            bad_source_ack: false,
            fail_upload: None,
            starts: Cell::new(0),
            uploads: Cell::new(0),
            source_upload_attempts: Cell::new(0),
            exporter_uploads: Cell::new(0),
            polls: Cell::new(0),
            stops: RefCell::new(Vec::new()),
            attempt: RefCell::new(None),
            spec: RefCell::new(String::new()),
            index: RefCell::new(None),
            deployment_policy: f.infra.deployment_policy(),
            recovery: "match",
        }
    }
    fn id(&self) -> String {
        format!(
            "{}:00000000-0000-4000-8000-000000000001",
            self.infra.project_name
        )
    }
    fn job(&self) -> Value {
        json!({"id":self.id(),"projectName":self.infra.project_name,
            "arn":format!("arn:aws:codebuild:{}:{}:build/{}",self.infra.region,self.infra.account_id,self.id()),"buildStatus":self.status,"source":{"buildspec":*self.spec.borrow()}})
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
        let i = &self.infra;
        match (service, operation) {
            ("codebuild", "batch-get-projects") => {
                assert_eq!(input, json!({"names":[i.project_name]}));
                Ok(json!({"projectsNotFound":[],"projects":[{
                    "name":i.project_name,"arn":format!("arn:aws:codebuild:{}:{}:project/{}",i.region,i.account_id,i.project_name),
                    "environment":{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_MEDIUM","privilegedMode":true},
                    "source":{"type":"NO_SOURCE"},"artifacts":{"type":"NO_ARTIFACTS"},"cache":{"type":"S3","location":format!("{}/cache",i.source_bucket),"cacheNamespace":i.project_name}
                }]}))
            }
            ("s3api", "put-object") => {
                if input["Key"].as_str().unwrap().starts_with("images/") {
                    *self.index.borrow_mut() = Some(fs::read(&extra[1])?);
                    return Ok(
                        json!({"ChecksumSHA256":input["ChecksumSHA256"],"ServerSideEncryption":"AES256"}),
                    );
                }
                if input["Key"]
                    .as_str()
                    .unwrap()
                    .starts_with("sources/runtime/")
                {
                    let directory = std::path::Path::new(&extra[1]).parent().unwrap();
                    let saved: Value =
                        serde_json::from_slice(&fs::read(directory.join("attempt.json"))?)?;
                    let bytes = fs::read(&extra[1])?;
                    assert_eq!(
                        input,
                        json!({"Bucket":i.source_bucket,"Key":format!("sources/runtime/{}/{}",saved["attemptId"].as_str().unwrap(),hash(&bytes)),"ExpectedBucketOwner":i.account_id,"ServerSideEncryption":"AES256","ChecksumSHA256":STANDARD.encode(Sha256::digest(&bytes))})
                    );
                    assert_eq!(
                        saved["exporter"]["helper"],
                        json!({"sha256":hash(&bytes),"bytes":bytes.len()})
                    );
                    self.exporter_uploads.set(self.exporter_uploads.get() + 1);
                    if self.fail_upload == Some(true) {
                        bail!("injected exporter upload failure");
                    }
                    return Ok(
                        json!({"ChecksumSHA256":if self.bad_exporter_ack { json!("wrong") } else {input["ChecksumSHA256"].clone()},"ServerSideEncryption":"AES256","VersionId":"runtime'version"}),
                    );
                }
                assert_eq!(
                    input,
                    json!({"Bucket":i.source_bucket,"Key":format!("sources/{}.tar",hash(&self.source)),"ExpectedBucketOwner":i.account_id,"ServerSideEncryption":"AES256","ChecksumSHA256":STANDARD.encode(Sha256::digest(&self.source))})
                );
                assert_eq!(extra.len(), 2);
                assert_eq!(extra[0], "--body");
                assert_eq!(fs::read(&extra[1])?, self.source);
                self.source_upload_attempts
                    .set(self.source_upload_attempts.get() + 1);
                if self.fail_upload == Some(false) {
                    bail!("injected source upload failure");
                }
                if self.bad_source_ack {
                    return Ok(
                        json!({"ChecksumSHA256":"wrong","ServerSideEncryption":"AES256","VersionId":"untrusted"}),
                    );
                }
                assert_eq!(self.uploads.replace(1), 0, "no repeated source mutation");
                Ok(
                    json!({"ChecksumSHA256":input["ChecksumSHA256"],"ServerSideEncryption":"AES256","VersionId":"version-1"}),
                )
            }
            ("codebuild", "start-build") => {
                assert_eq!(self.starts.replace(1), 0, "never resubmit");
                assert_eq!(input["projectName"], i.project_name);
                assert_eq!(input.as_object().unwrap().len(), 3);
                let attempt = input["idempotencyToken"].as_str().unwrap();
                Uuid::parse_str(attempt).unwrap();
                *self.attempt.borrow_mut() = Some(attempt.into());
                *self.spec.borrow_mut() = input["buildspecOverride"].as_str().unwrap().into();
                let spec: Value =
                    serde_json::from_str(input["buildspecOverride"].as_str().unwrap())?;
                assert!(spec["phases"]["build"]["commands"][0]
                    .as_str()
                    .unwrap()
                    .contains("--version-id 'version-1'"));
                if self.uncertain {
                    bail!("lost StartBuild reply")
                }
                Ok(json!({"build":self.job()}))
            }
            ("codebuild", "batch-get-builds") => {
                if self.recovery == "poll-error" {
                    bail!("interrupted poll");
                }
                if self.recovery == "ambiguous" {
                    let other = format!("{}:00000000-0000-4000-8000-000000000002", i.project_name);
                    assert_eq!(input, json!({"ids":[self.id(),other]}));
                    let mut job = self.job();
                    job["id"] = json!(other);
                    job["arn"] = json!(format!(
                        "arn:aws:codebuild:{}:{}:build/{other}",
                        i.region, i.account_id
                    ));
                    return Ok(json!({"buildsNotFound":[],"builds":[self.job(),job]}));
                }
                assert_eq!(input, json!({"ids":[self.id()]}));
                let poll = self.polls.get();
                self.polls.set(poll + 1);
                let mut job = self.job();
                if self.recovery == "wrong" {
                    job["source"]["buildspec"] = json!("other");
                }
                if self.recovery == "arn" {
                    job["arn"] = json!("other");
                }
                if self.recovery == "incomplete" {
                    return Ok(json!({"buildsNotFound":[self.id()],"builds":[]}));
                }
                if poll == 0 {
                    job["buildStatus"] = json!("IN_PROGRESS");
                }
                Ok(json!({"buildsNotFound":[],"builds":[job]}))
            }
            ("codebuild", "list-builds-for-project") => {
                assert_eq!(extra, &["--no-paginate"]);
                assert_eq!(input["projectName"], i.project_name);
                // AWS rejects sortOrder once a project has more than 100 builds.
                if input.get("sortOrder").is_some() {
                    return Err(zdn::aws::AwsApiError {
                        code: "InvalidInputException".into(),
                    }
                    .into());
                }
                Ok(match self.recovery {
                    "paginated" if input.get("nextToken").is_none() => {
                        json!({"ids":[],"nextToken":"second"})
                    }
                    "none" => json!({"ids":[]}),
                    "duplicate" => json!({"ids":[self.id(),self.id()]}),
                    "ambiguous" => {
                        json!({"ids":[self.id(),format!("{}:00000000-0000-4000-8000-000000000002", i.project_name)]})
                    }
                    "pages" => json!({"ids":[self.id()],"nextToken":"again"}),
                    _ => json!({"ids":[self.id()]}),
                })
            }
            ("codebuild", "stop-build") => {
                assert_eq!(input, json!({"id":self.id()}));
                self.stops.borrow_mut().push(self.id());
                Ok(json!({}))
            }
            ("s3api", "get-object") => {
                assert_eq!(input["Bucket"], i.source_bucket);
                assert_eq!(input["ExpectedBucketOwner"], i.account_id);
                if input["Key"].as_str().unwrap().starts_with("images/") {
                    if let Some(bytes) = &*self.index.borrow() {
                        fs::write(&extra[0], bytes)?;
                        return Ok(json!({"ServerSideEncryption":"AES256"}));
                    }
                    return Err(zdn::aws::AwsApiError {
                        // S3 discloses a missing key only with bucket-list permission.
                        // GetObject supplies no s3:prefix condition context.
                        code: if iam::permitted(
                            std::slice::from_ref(&self.deployment_policy),
                            "s3:ListBucket",
                            &format!("arn:aws:s3:::{}", i.source_bucket),
                            &json!({}),
                        ) {
                            "NoSuchKey"
                        } else {
                            "AccessDenied"
                        }
                        .into(),
                    }
                    .into());
                }
                let prefix = format!("results/{}/", self.attempt.borrow().as_ref().unwrap());
                let name = input["Key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix(&prefix)
                    .unwrap();
                let bytes = match name {
                    "result.json" => serde_json::to_vec(&self.result)?,
                    "image-manifest.json" => self.manifest.clone(),
                    "image-config.json" => self.config.clone(),
                    _ => panic!("unexpected result key {name}"),
                };
                assert_eq!(extra.len(), 1);
                fs::write(&extra[0], bytes)?;
                Ok(json!({"ServerSideEncryption":"AES256"}))
            }
            ("ecr", "batch-get-image") => {
                assert_eq!(input["registryId"], i.account_id);
                assert_eq!(input["repositoryName"], i.repository);
                assert_eq!(
                    input["imageIds"],
                    json!([{"imageDigest":format!("sha256:{}",hash(&self.manifest))}])
                );
                Ok(
                    json!({"failures":[],"images":[{"imageId":{"imageDigest":format!("sha256:{}",hash(&self.manifest))},"imageManifest":if self.registry_mismatch { "{}".into() } else { String::from_utf8(self.manifest.clone())? }}]}),
                )
            }
            _ => panic!("unexpected AWS operation {service}/{operation}"),
        }
    }

    fn batch_call(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        let mut failed = false;
        Ok(calls
            .iter()
            .map(|call| {
                // Injected upload failures model both workers already started:
                // their peer still completes. Other cases retain serial fail-stop.
                if failed && self.fail_upload.is_none() {
                    return Err(eyre::eyre!(
                        "AWS batch request not dispatched after peer failure"
                    ));
                }
                let result = self.call(
                    service,
                    call.operation,
                    call.input.clone(),
                    &call.extra_args,
                );
                failed |= result.is_err();
                result
            })
            .collect())
    }
}

#[test]
fn contract_fingerprint_binds_recipe_source_and_revision_and_rejects_other_platforms() {
    let f = Fixture::new();
    let fingerprint = f.contract.fingerprint().unwrap();
    assert_eq!(fingerprint, hash(&serde_json::to_vec(&f.contract).unwrap()));
    for field in ["dockerfile", "context", "source", "size", "revision"] {
        let mut changed = f.contract.clone();
        match field {
            "dockerfile" => changed.recipe.dockerfile = "Dockerfile".into(),
            "context" => changed.recipe.context = "docker".into(),
            "source" => changed.source_sha256 = "b".repeat(64),
            "size" => changed.source_bytes += 1,
            "revision" => changed.revision = "b".repeat(40),
            _ => unreachable!(),
        }
        assert_ne!(changed.fingerprint().unwrap(), fingerprint, "{field}");
    }
    for (platform, target) in [("linux/arm64", "runtime"), ("linux/amd64", "builder")] {
        let mut changed = f.contract.clone();
        changed.platform = platform.into();
        changed.recipe.target = target.into();
        assert!(changed.fingerprint().is_err());
    }
}

#[test]
fn archive_tampering_missing_dockerfile_and_symlink_ancestry_fail_before_aws() {
    let mut valid = Fixture::new();
    let bytes = tar_bytes(&[
        ("docker/Dockerfile", b"FROM scratch", None),
        ("dep", b"", Some("docker")),
        ("dep-neighbor/file", b"local", None),
    ]);
    valid.contract.source_sha256 = hash(&bytes);
    valid.contract.source_bytes = bytes.len() as u64;
    fs::write(&valid.archive, bytes).unwrap();
    valid.contract.verify_archive(&valid.archive).unwrap();
    for case in [
        "hash",
        "size",
        "missing",
        "dockerfile-link",
        "ancestor",
        "context-link",
    ] {
        let mut f = Fixture::new();
        let bytes = match case {
            "missing" => tar_bytes(&[("README", b"local", None)]),
            "dockerfile-link" => tar_bytes(&[("docker/Dockerfile", b"", Some("../real"))]),
            "ancestor" => tar_bytes(&[
                ("docker", b"", Some("real")),
                ("docker/Dockerfile", b"FROM scratch", None),
            ]),
            "context-link" => {
                f.contract.recipe.context = "ctx".into();
                tar_bytes(&[
                    ("docker/Dockerfile", b"FROM scratch", None),
                    ("ctx", b"", Some("docker")),
                ])
            }
            _ => fs::read(&f.archive).unwrap(),
        };
        f.contract.source_sha256 = hash(&bytes);
        f.contract.source_bytes = bytes.len() as u64;
        let mut bytes = bytes;
        if case == "hash" {
            bytes[512] ^= 1;
        }
        if case == "size" {
            bytes.push(0);
        }
        fs::write(&f.archive, bytes).unwrap();
        struct NoAws;
        impl AwsApi for NoAws {
            fn call(&self, _: &str, _: &str, _: Value, _: &[String]) -> Result<Value> {
                panic!("archive must fail before AWS")
            }
        }
        fs::remove_dir_all(f.directory()).unwrap();
        let error = build_job::run(
            &NoAws,
            &team(),
            &f.contract,
            &f.archive,
            &f.directory(),
            &Clock::default(),
            || Ok(()),
        )
        .unwrap_err();
        assert!(!error.to_string().is_empty(), "{case}");
        assert!(!f.directory().exists(), "{case}");
    }
}

#[test]
fn build_observations_distinguish_submission_job_outcome_and_verified_reuse() {
    for case in ["valid", "failed", "uncertain", "invalid", "reuse"] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        if case == "reuse" {
            f.run(&api, &Clock::default()).unwrap();
        }
        api.uncertain = case == "uncertain";
        api.registry_mismatch = case == "invalid";
        if case == "failed" {
            api.status = "FAILED";
        }
        let directory = f.root.path().join("observed");
        f.prepare(&directory);
        let mut observations = Vec::new();
        let result = build_job::run_with_progress(
            &api,
            &team(),
            &f.contract,
            &f.archive,
            &directory,
            &Clock::default(),
            || Ok(()),
            &mut |observation| {
                // Events are delivered only after their identity and transition are durable.
                let saved: Value =
                    serde_json::from_slice(&fs::read(directory.join("attempt.json"))?)?;
                assert_eq!(saved["attemptId"], observation.attempt_id.to_string());
                assert_eq!(saved["dispatched"], observation.submission_recorded);
                assert_eq!(
                    !saved["sourceVersion"].is_null(),
                    observation.source_uploaded
                );
                assert_eq!(!saved["buildId"].is_null(), observation.build_id_known);
                if observation.image_verified {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&fs::read(directory.join("result.json"))?)?,
                        f.result
                    );
                }
                observations.push(observation.clone());
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), matches!(case, "valid" | "reuse"), "{case}");
        let last = observations.last().unwrap();
        assert_eq!(last.image_verified, matches!(case, "valid" | "reuse"));
        assert_eq!(
            last.job_outcome,
            match case {
                "valid" | "invalid" => Some("succeeded"),
                "failed" => Some("failed"),
                _ => None,
            }
        );
        assert_eq!(last.submission_recorded, case != "reuse");
        assert_eq!(last.build_id_known, !matches!(case, "uncertain" | "reuse"));
        assert_eq!(last.reused_from.is_some(), case == "reuse");
        if case == "valid" {
            assert!(observations
                .iter()
                .any(|o| o.job_outcome == Some("succeeded") && !o.image_verified));
        }
        for observation in &observations {
            assert_eq!(observation.contract_sha256, f.result["contractSha256"]);
            assert_eq!(observation.attempt_id, last.attempt_id);
            let exported = serde_json::to_string(observation).unwrap();
            assert!(!exported.contains(&api.id()));
            assert!(!exported.contains(&f.infra.repository_uri));
            assert!(!exported.contains("version-1"));
        }
        assert!(api.stops.borrow().is_empty());
        let cleanup = build_job::removal_evidence(&directory, &team());
        if matches!(case, "valid" | "reuse") {
            let evidence = cleanup.unwrap();
            assert_eq!(
                evidence["imageDigest"],
                format!("sha256:{}", hash(&f.manifest))
            );
            let keys = evidence["keys"].as_array().unwrap();
            assert!(keys.contains(&json!(format!("sources/{}.tar", f.contract.source_sha256))));
            assert!(keys.contains(&json!(format!(
                "images/{}.json",
                f.contract.fingerprint().unwrap()
            ))));
            if let Some(original) = last.reused_from {
                assert!(keys.contains(&json!(format!("results/{original}/result.json"))));
            }
        } else if case == "uncertain" {
            assert!(
                cleanup.is_err(),
                "uncertain submissions are not cleanup authority"
            );
        }
    }
}

#[test]
fn build_observer_failure_stops_effects_and_preserves_exact_recovery() {
    for boundary in [
        "prepared",
        "uploaded",
        "submission",
        "accepted",
        "terminal",
        "verified",
    ] {
        let f = Fixture::new();
        let api = FakeAws::new(&f);
        let error = build_job::run_with_progress(
            &api,
            &team(),
            &f.contract,
            &f.archive,
            &f.directory(),
            &Clock::default(),
            || Ok(()),
            &mut |observation| {
                let stop = match boundary {
                    "prepared" => true,
                    "uploaded" => observation.source_uploaded,
                    "submission" => observation.submission_recorded,
                    "accepted" => observation.build_id_known,
                    "terminal" => observation.job_outcome.is_some(),
                    "verified" => observation.image_verified,
                    _ => unreachable!(),
                };
                if stop {
                    bail!("event sink failed");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "event sink failed");
        let before: Value =
            serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap()).unwrap();
        assert_eq!(
            api.starts.get(),
            usize::from(matches!(boundary, "accepted" | "terminal" | "verified"))
        );
        assert_eq!(api.uploads.get(), usize::from(boundary != "prepared"));
        assert!(api.stops.borrow().is_empty());
        if boundary == "submission" {
            // Intent was saved but no request was sent. Recovery must not invent a job
            // or turn this conservative uncertainty into permission to resubmit.
            assert!(f.run(&api, &Clock::default()).is_err());
            assert_eq!(api.starts.get(), 0);
        } else {
            f.run(&api, &Clock::default()).unwrap();
            let after: Value =
                serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap())
                    .unwrap();
            assert_eq!(before["attemptId"], after["attemptId"]);
            assert_eq!(api.starts.get(), 1);
            assert_eq!(api.uploads.get(), 1);
        }
    }
}

#[test]
fn successful_job_persists_exact_verified_outputs_and_job_identity() {
    let f = Fixture::new();
    let api = FakeAws::new(&f);
    let clock = Clock::default();
    let result = f.run(&api, &clock).unwrap();
    assert_eq!(serde_json::to_value(&result).unwrap(), f.result);
    for (name, bytes) in [
        ("result.json", serde_json::to_vec(&f.result).unwrap()),
        ("image-manifest.json", f.manifest.clone()),
        ("image-config.json", f.config.clone()),
        (
            "image.json",
            serde_json::to_vec_pretty(&result.image).unwrap(),
        ),
    ] {
        assert_eq!(fs::read(f.directory().join(name)).unwrap(), bytes, "{name}");
    }
    let attempt: Value =
        serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap()).unwrap();
    assert_eq!(attempt["buildId"], api.id());
    assert_eq!(
        attempt["attemptId"],
        api.attempt.borrow().as_ref().unwrap().as_str()
    );
    assert_eq!(
        attempt["contract"],
        serde_json::to_value(&f.contract).unwrap()
    );
    assert_eq!(clock.seconds.get(), 5);
    assert!(api.stops.borrow().is_empty());

    // An old role without ListBucket must fail closed, not submit a cold build.
    let f = Fixture::new();
    let mut api = FakeAws::new(&f);
    api.deployment_policy["Statement"]
        .as_array_mut()
        .unwrap()
        .retain(|s| !iam::strings(&s["Action"]).contains(&"s3:ListBucket"));
    let error = f.run(&api, &Clock::default()).unwrap_err();
    assert!(format!("{error:#}").contains("AccessDenied"));
    assert_eq!(api.uploads.get(), 0);
    assert_eq!(api.starts.get(), 0);
}

#[test]
fn failed_or_untrusted_outputs_are_not_persisted_as_verified_files() {
    for (case, message) in [
        ("FAILED", "ended with"),
        ("FAULT", "ended with"),
        ("STOPPED", "ended with"),
        ("TIMED_OUT", "ended with"),
        ("source", "source differs"),
        ("revision", "source differs"),
        ("contract", "contract mismatch"),
        ("repository", "repository differs"),
        ("manifest", "manifest SHA-256"),
        ("config", "configuration SHA-256"),
        ("registry", "ECR differs"),
    ] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        match case {
            "source" => api.result["image"]["provenance"]["snapshotSha256"] = json!("b".repeat(64)),
            "revision" => api.result["image"]["provenance"]["revision"] = json!("b".repeat(40)),
            "contract" => api.result["contractSha256"] = json!("b".repeat(64)),
            "repository" => {
                api.result["image"]["image"] =
                    json!(format!("other.example/repo@sha256:{}", hash(&f.manifest)))
            }
            "manifest" => api.manifest.push(b' '),
            "config" => api.config[0] ^= 1,
            "registry" => api.registry_mismatch = true,
            status => api.status = status,
        }
        let error = f.run(&api, &Clock::default()).unwrap_err();
        assert!(format!("{error:#}").contains(message), "{case}: {error:#}");
        assert!(f.directory().join("attempt.json").exists());
        for name in [
            "image.json",
            "result.json",
            "image-manifest.json",
            "image-config.json",
        ] {
            assert!(!f.directory().join(name).exists(), "{case}: {name}");
        }
    }
}

#[test]
fn cancellation_and_monotonic_deadline_stop_only_the_saved_job() {
    for cancel in [true, false] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        api.status = "IN_PROGRESS";
        let clock = Clock {
            jump: !cancel,
            ..Clock::default()
        };
        let error = build_job::run(
            &api,
            &team(),
            &f.contract,
            &f.archive,
            &f.directory(),
            &clock,
            || {
                if cancel && api.polls.get() > 0 {
                    bail!("cancelled by test")
                }
                Ok(())
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(if cancel {
                "cancelled by test"
            } else {
                "deadline exceeded"
            }),
            "{message}"
        );
        assert!(message.contains("termination is not yet confirmed"));
        assert_eq!(*api.stops.borrow(), vec![api.id()]);
        assert_eq!(api.polls.get(), 2);
        assert!(!f.directory().join("result.json").exists());
    }
}

#[test]
fn legacy_attempts_are_rejected_without_aws_or_receipt_conversion() {
    struct NoAws;
    impl AwsApi for NoAws {
        fn call(&self, service: &str, operation: &str, _: Value, _: &[String]) -> Result<Value> {
            panic!("legacy execution contacted {service}/{operation}");
        }
    }
    for state in [
        "prepared",
        "uploaded",
        "uncertain",
        "running",
        "succeeded",
        "failed",
        "reused",
    ] {
        let f = Fixture::new();
        let path = f.directory().join("attempt.json");
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved.as_object_mut().unwrap().remove("exporter");
        if !matches!(state, "prepared" | "reused") {
            saved["sourceVersion"] = json!("version-1");
        }
        if matches!(state, "uncertain" | "running" | "succeeded" | "failed") {
            saved["dispatched"] = json!(true);
        }
        if matches!(state, "running" | "succeeded" | "failed") {
            saved["buildId"] = json!(FakeAws::new(&f).id());
        }
        if matches!(state, "succeeded" | "failed") {
            saved["terminal"] = json!(if state == "succeeded" {
                "SUCCEEDED"
            } else {
                "FAILED"
            });
        }
        if state == "reused" {
            saved["reused"] = json!(Uuid::new_v4());
        }
        let original = serde_json::to_vec(&saved).unwrap();
        fs::write(&path, &original).unwrap();
        let error = build_job::run_with_progress(
            &NoAws,
            &team(),
            &f.contract,
            &f.archive,
            &f.directory(),
            &Clock::default(),
            || panic!("legacy execution checked cancellation"),
            &mut |_| panic!("legacy execution emitted progress"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("legacy build execution is retired"),
            "{state}: {error:#}"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(build_job::prepare_native(
            &f.directory(),
            &team(),
            &f.contract,
            &f.root.path().join("helper")
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        if matches!(state, "prepared" | "uploaded" | "reused" | "succeeded") {
            build_job::validate_preparation(&f.directory(), &team(), &f.contract).unwrap();
            build_job::removal_evidence(&f.directory(), &team()).unwrap();
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
}

#[test]
fn uncertain_start_is_recovered_without_resubmission() {
    let protocol = zdn::build_export::PROTOCOL;
    let f = Fixture::new();
    {
        let helper = f.root.path().join("helper");
        let mut bytes = [0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        fs::write(&helper, bytes).unwrap();
        build_job::prepare_native(&f.directory(), &team(), &f.contract, &helper).unwrap();
        let original = fs::read(f.directory().join("attempt.json")).unwrap();
        fs::write(&helper, [bytes.as_slice(), b"changed"].concat()).unwrap();
        assert!(build_job::prepare_native(&f.directory(), &team(), &f.contract, &helper).is_err());
        assert_eq!(
            fs::read(f.directory().join("attempt.json")).unwrap(),
            original
        );
        fs::remove_file(helper).unwrap(); // Resume must use its private snapshot.
    }
    let mut api = FakeAws::new(&f);
    api.uncertain = true;
    api.recovery = "paginated";
    assert!(format!("{:#}", f.run(&api, &Clock::default()).unwrap_err())
        .contains("outcome may be unknown"));
    let path = f.directory().join("attempt.json");
    let saved = fs::read(&path).unwrap();
    let attempt: Value = serde_json::from_slice(&saved).unwrap();
    assert!(attempt["buildId"].is_null());
    assert_eq!(
        attempt["attemptId"],
        api.attempt.borrow().as_ref().unwrap().as_str()
    );
    f.run(&api, &Clock::default()).unwrap();
    let recovered: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(recovered["buildId"], api.id());
    assert_eq!(api.starts.get(), 1);
    assert_eq!(api.uploads.get(), 1);
    assert_eq!(api.exporter_uploads.get(), 1);
    let spec = api.spec.borrow();
    assert!(!spec.contains("python3"));
    assert!(spec.contains(&format!("__runtime-capabilities --require {}", protocol)));
    let before = &attempt["exporter"];
    assert_eq!(before["protocol"], protocol);
    assert_eq!(before["version"], "runtime'version");
    assert_eq!(recovered["exporter"], *before);
    let cleanup = build_job::removal_evidence(&f.directory(), &team()).unwrap();
    assert!(cleanup["keys"].as_array().unwrap().contains(&json!(format!(
        "sources/runtime/{}/{}",
        attempt["attemptId"].as_str().unwrap(),
        before["helper"]["sha256"].as_str().unwrap()
    ))));
}

#[test]
fn cleanup_reconciles_only_the_exact_known_terminal_job_without_running_builds() {
    struct ReadOnlyJob<'a> {
        response: Value,
        api: &'a FakeAws,
        job_reads: Cell<usize>,
    }
    impl AwsApi for ReadOnlyJob<'_> {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            match (service, operation) {
                ("codebuild", "batch-get-builds") => {
                    assert_eq!(input, json!({"ids":[self.api.id()]}));
                    assert!(extra.is_empty());
                    self.job_reads.set(self.job_reads.get() + 1);
                    Ok(self.response.clone())
                }
                ("s3api", "get-object") | ("ecr", "batch-get-image") => {
                    self.api.call(service, operation, input, extra)
                }
                _ => panic!("cleanup must not call {service}/{operation}"),
            }
        }
    }
    let f = Fixture::new();
    let mut api = FakeAws::new(&f);
    // Interrupt after the original submission is saved, before terminal polling.
    let _ = build_job::run_with_progress(
        &api,
        &team(),
        &f.contract,
        &f.archive,
        &f.directory(),
        &Clock::default(),
        || Ok(()),
        &mut |observation| {
            if observation.build_id_known {
                bail!("controller interrupted");
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(api.starts.get(), 1);
    let path = f.directory().join("attempt.json");
    let original = fs::read(&path).unwrap();
    let saved: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(saved["buildId"], api.id());
    assert!(saved["terminal"].is_null());
    assert!(build_job::removal_evidence(&f.directory(), &team()).is_err());
    for case in [
        "SUCCEEDED",
        "FAILED",
        "FAULT",
        "STOPPED",
        "TIMED_OUT",
        "IN_PROGRESS",
        "unknown",
        "no-end",
        "missing",
        "duplicate",
        "foreign-id",
        "foreign-arn",
        "foreign-source",
        "unknown-submission",
        "foreign-team",
        "locked",
        "bad-result",
        "bad-ecr",
    ] {
        for name in [
            "result.json",
            "image.json",
            "image-manifest.json",
            "image-config.json",
        ] {
            let _ = fs::remove_file(f.directory().join(name));
        }
        api.result = f.result.clone();
        api.registry_mismatch = case == "bad-ecr";
        if case == "bad-result" {
            api.result["contractSha256"] = json!("0".repeat(64));
        }
        let mut receipt = saved.clone();
        let mut job = api.job();
        job["endTime"] = json!(1234567890);
        let terminal = ["SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"].contains(&case);
        if terminal || case == "IN_PROGRESS" {
            job["buildStatus"] = json!(case);
        }
        match case {
            "unknown" => job["buildStatus"] = json!("NEW_STATUS"),
            "no-end" => job["endTime"] = Value::Null,
            "foreign-id" => {
                job["id"] = json!(format!(
                    "{}:00000000-0000-4000-8000-000000000002",
                    f.infra.project_name
                ))
            }
            "foreign-arn" => {
                job["arn"] = json!("arn:aws:codebuild:us-east-1:999999999999:build/foreign")
            }
            "foreign-source" => job["source"]["buildspec"] = json!("foreign"),
            "unknown-submission" => receipt["buildId"] = Value::Null,
            "foreign-team" => receipt["team"]["bootstrapId"] = json!(Uuid::new_v4()),
            _ => {}
        }
        let bytes = serde_json::to_vec(&receipt).unwrap();
        fs::write(&path, &bytes).unwrap();
        let response = match case {
            "missing" => json!({"builds":[],"buildsNotFound":[api.id()]}),
            "duplicate" => json!({"builds":[job.clone(),job],"buildsNotFound":[]}),
            _ => json!({"builds":[job],"buildsNotFound":[]}),
        };
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.directory().join("attempt.lock"))
            .unwrap();
        if case == "locked" {
            fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        }
        let reader = ReadOnlyJob {
            response,
            api: &api,
            job_reads: Cell::new(0),
        };
        let result = build_job::reconcile_for_removal(&reader, &f.directory(), &team());
        if terminal {
            result.unwrap();
            receipt["terminal"] = json!(case);
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
                receipt
            );
            let evidence = build_job::removal_evidence(&f.directory(), &team()).unwrap();
            assert_eq!(evidence["attempt"]["terminal"], case);
            if case == "SUCCEEDED" {
                assert_eq!(
                    evidence["imageDigest"],
                    format!("sha256:{}", hash(&f.manifest))
                );
                // An interrupted local result write resumes without polling or
                // submitting a job; completed cleanup also needs no live output.
                fs::remove_file(f.directory().join("result.json")).unwrap();
                build_job::reconcile_for_removal(&reader, &f.directory(), &team()).unwrap();
                build_job::reconcile_for_removal(&reader, &f.directory(), &team()).unwrap();
                assert_eq!(reader.job_reads.get(), 1);
            } else {
                assert!(evidence["imageDigest"].is_null());
            }
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(fs::read(&path).unwrap(), bytes, "{case}");
        }
        assert_eq!(
            f.directory().join("result.json").exists(),
            case == "SUCCEEDED"
        );
        assert_eq!(
            f.directory().join("image.json").exists(),
            case == "SUCCEEDED"
        );
    }
}

#[test]
fn native_exporter_tampering_never_dispatches() {
    for case in [
        "bytes",
        "protocol",
        "size",
        "unversioned-dispatch",
        "checksum",
    ] {
        let f = Fixture::new();
        let helper = f.root.path().join("helper");
        let mut bytes = [0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        fs::write(&helper, bytes).unwrap();
        build_job::prepare_native(&f.directory(), &team(), &f.contract, &helper).unwrap();
        let path = f.directory().join("attempt.json");
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match case {
            "bytes" => fs::write(f.directory().join("exporter"), b"changed").unwrap(),
            "protocol" => saved["exporter"]["protocol"] = json!("zdn-build-export/v999"),
            "size" => saved["exporter"]["helper"]["bytes"] = json!(65),
            "unversioned-dispatch" => {
                saved["dispatched"] = json!(true);
                saved["sourceVersion"] = json!("version-1");
            }
            "checksum" => (),
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut api = FakeAws::new(&f);
        api.bad_exporter_ack = case == "checksum";
        assert!(f.run(&api, &Clock::default()).is_err(), "{case}");
        assert_eq!(api.starts.get(), 0, "{case}");
        assert_eq!(
            api.exporter_uploads.get(),
            usize::from(case == "checksum"),
            "{case}"
        );
        assert!(!f.directory().join("result.json").exists());
        if case == "checksum" {
            let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            // Preserve the confirmed peer, never the unacknowledged exporter
            // version, and leave every unrelated receipt field unchanged.
            saved["sourceVersion"] = json!("version-1");
            assert!(after["exporter"]["version"].is_null());
            assert_eq!(after, saved);
            let cleanup = build_job::removal_evidence(&f.directory(), &team()).unwrap();
            assert!(cleanup["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|key| key.as_str().unwrap().starts_with("sources/runtime/")));
            api.bad_exporter_ack = false;
            assert_eq!(
                serde_json::to_value(f.run(&api, &Clock::default()).unwrap()).unwrap(),
                f.result
            );
        }
    }
}

#[test]
fn failed_or_untrusted_peer_preserves_success_without_duplicate_upload_or_dispatch() {
    for fail_helper in [false, true] {
        for corrupt in [false, true] {
            let f = Fixture::new();
            let mut api = FakeAws::new(&f);
            let exporter = f.directory().join("exporter");
            let original = fs::read(&exporter).unwrap();
            fs::write(&exporter, b"changed").unwrap();
            assert!(f.run(&api, &Clock::default()).is_err());
            assert_eq!(
                (api.exporter_uploads.get(), api.source_upload_attempts.get()),
                (0, 0)
            );
            assert_eq!(api.starts.get(), 0);
            fs::write(&exporter, original).unwrap();

            if corrupt {
                api.bad_exporter_ack = fail_helper;
                api.bad_source_ack = !fail_helper;
            } else {
                api.fail_upload = Some(fail_helper);
            }
            assert!(f.run(&api, &Clock::default()).is_err());
            let saved: Value =
                serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap())
                    .unwrap();
            assert_eq!(saved["dispatched"], false);
            assert_eq!(saved["exporter"]["version"].is_null(), fail_helper);
            assert_eq!(saved["sourceVersion"].is_null(), !fail_helper);
            assert_eq!(api.starts.get(), 0);
            assert_eq!(
                (api.exporter_uploads.get(), api.source_upload_attempts.get()),
                (1, 1)
            );

            api.fail_upload = None;
            api.bad_exporter_ack = false;
            api.bad_source_ack = false;
            api.uncertain = true;
            assert!(f.run(&api, &Clock::default()).is_err());
            assert_eq!(api.starts.get(), 1);
            assert_eq!(api.exporter_uploads.get(), if fail_helper { 2 } else { 1 });
            assert_eq!(
                api.source_upload_attempts.get(),
                if fail_helper { 1 } else { 2 }
            );
            assert_eq!(api.uploads.get(), 1);
            assert_eq!(
                serde_json::to_value(f.run(&api, &Clock::default()).unwrap()).unwrap(),
                f.result
            );
            assert_eq!(api.starts.get(), 1);
            assert_eq!(api.exporter_uploads.get(), if fail_helper { 2 } else { 1 });
            assert_eq!(
                api.source_upload_attempts.get(),
                if fail_helper { 1 } else { 2 }
            );
        }
    }
}

#[test]
fn recovery_rejects_no_match_ambiguity_wrong_identity_and_incomplete_scans() {
    for case in [
        "none",
        "wrong",
        "arn",
        "incomplete",
        "duplicate",
        "ambiguous",
        "pages",
    ] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        api.uncertain = true;
        assert!(f.run(&api, &Clock::default()).is_err());
        api.recovery = case;
        assert!(f.run(&api, &Clock::default()).is_err(), "{case}");
        assert_eq!(api.starts.get(), 1, "{case}");
        assert_eq!(api.uploads.get(), 1, "{case}");
        assert!(api.stops.borrow().is_empty(), "{case}");
    }
}

#[test]
fn cancelled_resume_does_not_stop_a_job_with_different_source_identity() {
    let f = Fixture::new();
    let mut api = FakeAws::new(&f);
    api.recovery = "poll-error";
    assert!(f.run(&api, &Clock::default()).is_err());
    api.recovery = "wrong";
    api.status = "IN_PROGRESS";
    assert!(build_job::run(
        &api,
        &team(),
        &f.contract,
        &f.archive,
        &f.directory(),
        &Clock::default(),
        || bail!("cancelled")
    )
    .is_err());
    assert!(api.stops.borrow().is_empty());
    assert_eq!(api.starts.get(), 1);
}

#[test]
fn known_id_resumes_polling_and_failure_remains_terminal() {
    let f = Fixture::new();
    let mut api = FakeAws::new(&f);
    api.recovery = "poll-error";
    let error = f.run(&api, &Clock::default()).unwrap_err();
    assert!(error.to_string().contains("interrupt"));
    api.recovery = "match";
    api.status = "FAILED";
    assert!(format!("{:#}", f.run(&api, &Clock::default()).unwrap_err()).contains("ended with"));
    let polls = api.polls.get();
    api.status = "SUCCEEDED";
    assert!(f
        .run(&api, &Clock::default())
        .unwrap_err()
        .to_string()
        .contains("terminal"));
    assert_eq!(polls, api.polls.get());
    assert_eq!(api.starts.get(), 1);
}

#[test]
fn invalid_reuse_index_never_falls_back_to_a_paid_build() {
    let f = Fixture::new();
    let api = FakeAws::new(&f);
    *api.index.borrow_mut() = Some(b"{}".to_vec());
    assert!(f
        .run(&api, &Clock::default())
        .unwrap_err()
        .to_string()
        .contains("reuse index"));
    assert_eq!(api.uploads.get(), 0);
    assert_eq!(api.starts.get(), 0);
}

#[test]
fn resume_and_reuse_redownload_outputs_and_recheck_ecr_without_start() {
    let f = Fixture::new();
    let mut api = FakeAws::new(&f);
    f.run(&api, &Clock::default()).unwrap();
    let polls = api.polls.get();
    fs::write(f.directory().join("image.json"), b"untrusted local output").unwrap();
    f.run(&api, &Clock::default()).unwrap();
    assert_eq!(api.polls.get(), polls);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(f.directory().join("image.json")).unwrap())
            .unwrap(),
        f.result["image"]
    );
    api.registry_mismatch = true;
    assert!(f
        .run(&api, &Clock::default())
        .unwrap_err()
        .to_string()
        .contains("ECR differs"));
    // A fresh directory selects the checked pointer, not a new paid job.
    let reused = f.root.path().join("reused");
    f.prepare(&reused);
    let run = || {
        build_job::run(
            &api,
            &team(),
            &f.contract,
            &f.archive,
            &reused,
            &Clock::default(),
            || Ok(()),
        )
    };
    assert!(run().unwrap_err().to_string().contains("ECR differs"));
    assert_eq!(api.starts.get(), 1);
    assert_eq!(api.uploads.get(), 1);
    api.registry_mismatch = false;
    build_job::run(
        &api,
        &team(),
        &f.contract,
        &f.archive,
        &reused,
        &Clock::default(),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(api.starts.get(), 1);
}

#[test]
fn interrupted_before_upload_or_start_preserves_attempt_and_source_version() {
    for after_upload in [false, true] {
        let f = Fixture::new();
        let api = FakeAws::new(&f);
        let calls = Cell::new(0);
        let original: Value =
            serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap()).unwrap();
        assert!(build_job::run(
            &api,
            &team(),
            &f.contract,
            &f.archive,
            &f.directory(),
            &Clock::default(),
            || {
                calls.set(calls.get() + 1);
                if (after_upload && api.uploads.get() > 0) || (!after_upload && calls.get() == 2) {
                    bail!("interrupted")
                }
                Ok(())
            }
        )
        .is_err());
        let before: Value =
            serde_json::from_slice(&fs::read(f.directory().join("attempt.json")).unwrap()).unwrap();
        assert_eq!(before["attemptId"], original["attemptId"]);
        assert_eq!(before["sourceVersion"].is_string(), after_upload);
        assert_eq!(api.starts.get(), 0);
        let receiver = tempfile::tempdir().unwrap();
        let archive = receiver.path().join("source.tar");
        fs::copy(&f.archive, &archive).unwrap();
        let directory = receiver.path().join("build");
        zdn::foundation::private_directory(&directory).unwrap();
        fs::copy(
            f.directory().join("attempt.json"),
            directory.join("attempt.json"),
        )
        .unwrap();
        fs::copy(f.directory().join("exporter"), directory.join("exporter")).unwrap();
        fs::remove_dir_all(f.directory()).unwrap();
        fs::remove_file(&f.archive).unwrap();
        build_job::run(
            &api,
            &team(),
            &f.contract,
            &archive,
            &directory,
            &Clock::default(),
            || Ok(()),
        )
        .unwrap();
        let after: Value = zdn::foundation::read_json(&directory.join("attempt.json")).unwrap();
        if after_upload {
            assert_eq!(after["sourceVersion"], before["sourceVersion"]);
        }
        assert_eq!(
            api.attempt.borrow().as_ref().unwrap().as_str(),
            before["attemptId"].as_str().unwrap()
        );
        assert_eq!(api.uploads.get(), 1);
    }
}

#[test]
fn changed_archive_or_receipt_identity_fails_before_aws() {
    for case in [
        "archive", "contract", "team", "project", "schema", "oversize", "missing",
    ] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        api.uncertain = true;
        assert!(f.run(&api, &Clock::default()).is_err());
        let path = f.directory().join("attempt.json");
        let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match case {
            "archive" => fs::write(&f.archive, b"tampered").unwrap(),
            "contract" => receipt["contract"]["revision"] = json!("b".repeat(40)),
            "team" => receipt["team"]["aws"]["accountId"] = json!("999999999999"),
            "project" => receipt["project"] = json!("other"),
            "schema" => receipt["schemaVersion"] = json!(2),
            "oversize" => receipt["project"] = json!("a".repeat(65536)),
            "missing" => fs::remove_file(&path).unwrap(),
            _ => unreachable!(),
        }
        if case != "missing" {
            fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        }
        struct NoAws;
        impl AwsApi for NoAws {
            fn call(&self, _: &str, _: &str, _: Value, _: &[String]) -> Result<Value> {
                panic!("invalid receipt/archive reached AWS")
            }
        }
        assert!(
            build_job::run(
                &NoAws,
                &team(),
                &f.contract,
                &f.archive,
                &f.directory(),
                &Clock::default(),
                || Ok(())
            )
            .is_err(),
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn receipt_lock_symlinks_and_public_files_are_rejected() {
    use fs2::FileExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    for case in ["lock", "symlink", "public", "hardlink"] {
        let f = Fixture::new();
        let mut api = FakeAws::new(&f);
        api.uncertain = true;
        assert!(f.run(&api, &Clock::default()).is_err());
        let path = f.directory().join("attempt.json");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.directory().join("attempt.lock"))
            .unwrap();
        match case {
            "lock" => lock.try_lock_exclusive().unwrap(),
            "symlink" => {
                let target = f.directory().join("target");
                fs::rename(&path, &target).unwrap();
                symlink(target, &path).unwrap();
            }
            "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "hardlink" => fs::hard_link(&path, f.directory().join("alias")).unwrap(),
            _ => unreachable!(),
        }
        assert!(f.run(&api, &Clock::default()).is_err(), "{case}");
        assert_eq!(api.starts.get(), 1);
        assert_eq!(api.polls.get(), 0);
    }
}

#[test]
fn generated_buildspec_parses_and_export_cli_is_bounded() {
    let f = Fixture::new();
    let exporter = build_job::NativeExporter {
        protocol: zdn::build_export::PROTOCOL.into(),
        helper: zdn::devnet::Artifact {
            sha256: hash(b"fixture exporter"),
            bytes: 64,
        },
        version: Some("runtime'version".into()),
    };
    let spec: Value = serde_json::from_str(
        &build_job::native_buildspec(
            &f.contract,
            &f.infra,
            Uuid::nil(),
            "version'quoted",
            &exporter,
        )
        .unwrap(),
    )
    .unwrap();
    let script = spec["phases"]["build"]["commands"][0].as_str().unwrap();
    // Syntax-check only: never execute the shell, its fixed /tmp path, or a build.
    let shell = f.root.path().join("build.sh");
    fs::write(&shell, script).unwrap();
    assert!(Command::new("bash")
        .arg("-n")
        .arg(&shell)
        .status()
        .unwrap()
        .success());
    assert!(!script.contains("python"));
    fs::write(
        f.root.path().join("registry.json"),
        serde_json::to_vec(&json!({"failures":[],"images":[{
            "imageId":{"imageDigest":format!("sha256:{}",hash(&f.manifest))},
            "imageManifest":String::from_utf8(f.manifest.clone()).unwrap()
        }]}))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        f.root.path().join("contract.json"),
        serde_json::to_vec(&f.contract).unwrap(),
    )
    .unwrap();
    // Plain HTTP is rejected before connecting and its presigned secret stays out
    // of the full CLI error chain. Fixture shell successes use an injected
    // downloader, not a production HTTP/security bypass.
    fs::write(
        f.root.path().join("download.json"),
        serde_json::to_vec(&json!({
            "downloadUrl":"http://127.0.0.1:1/config?token=SECRET",
            "layerDigest":format!("sha256:{}", hash(&f.config))
        }))
        .unwrap(),
    )
    .unwrap();
    for (protocol, sources, error) in [
        (
            zdn::build_export::PROTOCOL,
            vec!["--config-download", "download.json"],
            "configuration download failed",
        ),
        (zdn::build_export::PROTOCOL, vec![], "required arguments"),
    ] {
        let native = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args([
                "__build-export",
                "--protocol",
                protocol,
                "--contract",
                "contract.json",
                "--repository",
                &f.infra.repository_uri,
                "--registry",
                "registry.json",
                "--output",
                "metadata-rejected",
            ])
            .args(sources)
            .env_clear()
            .current_dir(f.root.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&native.stderr);
        assert!(!native.status.success());
        assert!(stderr.contains(error), "{stderr}");
        assert!(!stderr.contains("SECRET") && !stderr.contains("127.0.0.1"));
        assert!(!f.root.path().join("metadata-rejected").exists());
    }
}

#[cfg(unix)]
#[test]
fn build_tool_worker() {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("FIXTURE").unwrap());
    let name = payload["name"].as_str().unwrap();
    if name == "uname" {
        native_tool::reply(&work, b"x86_64\n", b"", 0);
        return;
    }
    let mut call = vec![name.to_owned()];
    call.extend(args.iter().cloned());
    // Pipeline commands append concurrently: format the entire record before
    // writing so another process cannot split its JSON from the newline.
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .unwrap()
        .write_all(format!("{}\n", serde_json::to_string(&call).unwrap()).as_bytes())
        .unwrap();
    let flag = |name: &str| args[args.iter().position(|arg| arg == name).unwrap() + 1].as_str();
    let mut stdout = Vec::new();
    let mut code = 0;
    match (name, args[0].as_str(), args.get(1).map(String::as_str)) {
        ("exporter", "__build-export", _) => {
            struct Download(PathBuf);
            impl zdn::dependencies::Downloader for Download {
                fn download(&self, url: &str, file: &mut fs::File, limit: u64) -> Result<()> {
                    assert_eq!(url, "https://example.invalid/config");
                    assert_eq!(limit, image::MAX_CONFIG_BYTES as u64);
                    file.write_all(&fs::read(&self.0)?)?;
                    Ok(())
                }
            }
            assert_eq!(flag("--protocol"), zdn::build_export::PROTOCOL);
            let contract = serde_json::from_slice(&fs::read(flag("--contract")).unwrap()).unwrap();
            if zdn::build_export::export_downloaded_config(
                &contract,
                flag("--repository"),
                std::path::Path::new(flag("--registry")),
                std::path::Path::new(flag("--config-download")),
                std::path::Path::new(flag("--output")),
                &Download(root.join("config.json")),
            )
            .is_err()
            {
                code = 1;
            }
        }
        ("jq", "-er", _) => {
            assert_eq!(
                args[1],
                r#".images[0].imageManifest | fromjson | .config.digest | select(test("^sha256:[0-9a-f]{64}$"))"#
            );
            let registry: Value = serde_json::from_slice(&fs::read(&args[2]).unwrap()).unwrap();
            let manifest: Value =
                serde_json::from_str(registry["images"][0]["imageManifest"].as_str().unwrap())
                    .unwrap();
            stdout = format!("{}\n", manifest["config"]["digest"].as_str().unwrap()).into_bytes();
        }
        ("aws", "s3api", Some("get-object")) => {
            if flag("--key").starts_with("sources/runtime/") {
                assert_eq!(flag("--version-id"), "runtime'version");
                let mut bytes = fs::read(root.join("helper")).unwrap();
                if std::env::var("MODE").unwrap() == "runtime-digest" {
                    bytes[12] ^= 1; // Change only comment text, not executable behavior.
                }
                fs::write(args.last().unwrap(), bytes).unwrap();
            } else {
                fs::copy(root.join("source.tar"), "source.tar").unwrap();
            }
        }
        ("aws", "ecr", Some("get-login-password")) => stdout.extend(b"fake-password\n"),
        ("aws", "ecr", Some("get-download-url-for-layer")) => {
            assert_eq!(flag("--registry-id"), "123456789012");
            assert_eq!(
                flag("--repository-name"),
                BuildInfrastructure::for_team(&team()).unwrap().repository
            );
            let digest = format!(
                "sha256:{}",
                hash(&fs::read(root.join("config.json")).unwrap())
            );
            assert_eq!(flag("--layer-digest"), digest);
            stdout = serde_json::to_vec(
                &json!({"downloadUrl":"https://example.invalid/config", "layerDigest":digest}),
            )
            .unwrap();
            if std::env::var("MODE").unwrap() == "config_failure" {
                code = 1;
            }
        }
        ("aws", "ecr", Some("batch-get-image")) => {
            // Bash creates this after extraction: a global umask 022 would
            // accidentally relax subsequent private writes as well.
            assert_eq!(
                fs::metadata("registry.json").unwrap().permissions().mode() & 0o7777,
                0o600
            );
            stdout = fs::read(root.join("registry.json")).unwrap();
            stdout.push(b'\n');
        }
        ("aws", "s3api", Some("put-object")) => {
            assert!(std::path::Path::new(flag("--body")).is_file());
            // Every upload must finish before the exported cache replaces
            // the previous cache, including when the upload fails.
            let cache = PathBuf::from(std::env::var_os("CACHE").unwrap());
            if std::env::var("MODE").unwrap() == "cold" {
                assert!(!cache.exists());
            } else {
                assert_eq!(
                    fs::read_to_string(cache.join("index.json")).unwrap(),
                    "old cache"
                );
            }
            if std::env::var("MODE").unwrap() == "upload_failure" {
                code = 1;
            }
        }
        ("docker", "buildx", Some("build")) => {
            // Source must retain its public Git modes for non-root Dockerfile
            // users, without relaxing the helper/contract's private umask.
            for (path, mode) in [
                ("source/docker/Dockerfile", 0o644),
                ("source/assets/executable", 0o755),
                ("zdn-runtime", 0o700),
                ("contract.json", 0o600),
            ] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                    mode,
                    "{path}"
                );
            }
            if args.iter().any(|arg| arg == "--cache-from") {
                let cache = PathBuf::from(flag("--cache-from").split_once("src=").unwrap().1);
                assert_eq!(
                    fs::read_to_string(cache.join("index.json")).unwrap(),
                    "old cache"
                );
            }
            let export = args.iter().any(|arg| arg == "--cache-to");
            if export {
                let cache = PathBuf::from(
                    flag("--cache-to")
                        .split_once("dest=")
                        .unwrap()
                        .1
                        .split(',')
                        .next()
                        .unwrap(),
                );
                assert!(!cache.exists());
                fs::create_dir_all(&cache).unwrap();
                fs::write(cache.join("index.json"), "new cache").unwrap();
            }
            let mode = std::env::var("MODE").unwrap();
            if mode == "build_failure"
                || (mode == "push_failure" && args.iter().any(|arg| arg == "--push"))
            {
                code = 1;
            }
            if mode == "cache_failure" && export {
                if flag("--cache-to").ends_with(",ignore-error=true") {
                    // BuildKit reports success despite an optional cache-export
                    // error; no completed cache may replace the restored one.
                    let cache = PathBuf::from(std::env::var_os("CACHE").unwrap());
                    fs::remove_dir_all(format!("{}.next", cache.display())).unwrap();
                } else {
                    code = 1;
                }
            }
        }
        ("docker", "login", _) => {
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        }
        ("docker", "buildx", Some("create" | "inspect")) => {}
        _ => panic!("unexpected fixture invocation: {call:?}"),
    }
    native_tool::reply(&work, &stdout, b"", code);
}

#[cfg(unix)]
#[test]
fn generated_build_cache_is_optional_and_promotes_only_verified_exports() {
    for mode in [
        "cold",
        "warm",
        "cache_failure",
        "invalid_result",
        "build_failure",
        "push_failure",
        "config_failure",
        "upload_failure",
        "runtime-size",
        "runtime-digest",
        "runtime-capability",
    ] {
        let mut f = Fixture::new();
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes, mode) in [
            ("docker/Dockerfile", b"FROM scratch\n".as_slice(), 0o644),
            (
                "assets/executable",
                b"#!/bin/sh\nexit 0\n".as_slice(),
                0o755,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(mode);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, path, bytes).unwrap();
        }
        let bytes = archive.into_inner().unwrap();
        fs::write(&f.archive, &bytes).unwrap();
        f.contract.source_sha256 = hash(&bytes);
        f.contract.source_bytes = bytes.len() as u64;
        f.result["contractSha256"] = hash(&serde_json::to_vec(&f.contract).unwrap()).into();
        f.result["image"]["provenance"]["snapshotSha256"] = f.contract.source_sha256.clone().into();
        // A tiny fixture transport invokes the actual Rust commands. ELF input
        // validation is exercised separately by prepare_native. Native cases
        // need no node/container build, interpreter or large executable copy.
        let helper = if mode == "runtime-capability" {
            "#!/bin/sh\n# Deliberately missing the required runtime protocol.\nexit 69\n".to_owned()
        } else {
            let dispatch = format!(
                "if test \"$1\" = __build-export; then exec '{}/bin/exporter' \"$@\"; fi\n",
                f.root.path().display()
            );
            format!("#!/bin/sh\n# Fixture transport for the native build exporter protocol.\n{dispatch}exec '{}' \"$@\"\n", env!("CARGO_BIN_EXE_zdn").replace('\'', "'\\''"))
        };
        fs::write(f.root.path().join("helper"), &helper).unwrap();
        let attempt = Uuid::new_v4();
        let exporter = build_job::NativeExporter {
            protocol: zdn::build_export::PROTOCOL.into(),
            helper: zdn::devnet::Artifact {
                sha256: hash(helper.as_bytes()),
                bytes: helper.len() as u64 + u64::from(mode == "runtime-size"),
            },
            version: Some("runtime'version".into()),
        };
        let spec: Value = serde_json::from_str(
            &build_job::native_buildspec(&f.contract, &f.infra, attempt, "version-1", &exporter)
                .unwrap(),
        )
        .unwrap();
        let cache_root = f.root.path().join("cache");
        let workspace = f.root.path().join("work");
        let script = spec["phases"]["build"]["commands"][0]
            .as_str()
            .unwrap()
            .replace("/tmp/zdn-build", workspace.to_str().unwrap())
            .replace("/tmp/zdn-layer-cache", cache_root.to_str().unwrap());
        assert!(!script.contains("python3"));
        let cache = PathBuf::from(
            spec["cache"]["paths"][0]
                .as_str()
                .unwrap()
                .trim_end_matches("/**/*")
                .replace("/tmp/zdn-layer-cache", cache_root.to_str().unwrap()),
        );
        if mode != "cold" {
            fs::create_dir_all(&cache).unwrap();
            fs::write(cache.join("index.json"), "old cache").unwrap();
        }
        let digest = if mode == "invalid_result" {
            "sha256:wrong".into()
        } else {
            format!("sha256:{}", hash(&f.manifest))
        };
        fs::write(f.root.path().join("registry.json"), serde_json::to_vec(&json!({
            "failures":[],"images":[{"imageId":{"imageDigest":digest},"imageManifest":String::from_utf8(f.manifest.clone()).unwrap()}]
        })).unwrap()).unwrap();
        let bin = f.root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(f.root.path().join("config.json"), &f.config).unwrap();
        for name in ["aws", "docker", "uname", "jq", "exporter"] {
            native_tool::install(&bin.join(name), "build_tool_worker", &json!({"name":name}));
        }
        #[cfg(target_os = "macos")]
        {
            // Keep the isolated PATH, but expose real tools for the generated
            // Linux script: Apple Bash 3.2 rejects empty arrays under nounset,
            // and macOS does not ship sha256sum in /usr/bin.
            for (name, candidates) in [
                ("bash", &["bash"][..]),
                ("sha256sum", &["sha256sum", "gsha256sum"][..]),
            ] {
                let executable =
                    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                        .flat_map(|dir| candidates.iter().map(move |candidate| dir.join(candidate)))
                        .find(|path| path.is_file())
                        .unwrap_or_else(|| panic!("macOS build fixture requires {name} on PATH"));
                std::os::unix::fs::symlink(executable.canonicalize().unwrap(), bin.join(name))
                    .unwrap();
            }
        }
        let output = Command::new("bash")
            .args(["-c", &script])
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("FIXTURE", f.root.path())
            .env("MODE", mode)
            .env("CACHE", &cache)
            .output()
            .unwrap();
        let runtime_failure = mode.starts_with("runtime-");
        let success = !runtime_failure
            && !matches!(
                mode,
                "invalid_result"
                    | "build_failure"
                    | "push_failure"
                    | "config_failure"
                    | "upload_failure"
            );
        assert_eq!(
            output.status.success(),
            success,
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if success {
            let result: Value =
                serde_json::from_slice(&fs::read(workspace.join("output/result.json")).unwrap())
                    .unwrap();
            assert_eq!(result, f.result);
            assert_eq!(
                fs::read(workspace.join("output/image-manifest.json")).unwrap(),
                f.manifest
            );
            assert_eq!(
                fs::read(workspace.join("output/image-config.json")).unwrap(),
                f.config
            );
        }
        assert_eq!(
            fs::read_to_string(cache.join("index.json")).unwrap(),
            if matches!(mode, "cold" | "warm") {
                "new cache"
            } else {
                "old cache"
            }
        );
        let calls = fs::read_to_string(f.root.path().join("calls")).unwrap();
        let calls: Vec<Vec<String>> = calls
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let builds: Vec<_> = calls
            .iter()
            .filter(|args| args[..3] == ["docker", "buildx", "build"])
            .collect();
        assert_eq!(builds.len(), usize::from(!runtime_failure));
        if let Some(first) = builds.first() {
            assert!(!first.iter().any(|arg| arg == "--load"));
            assert!(first.iter().any(|arg| arg == "--push"));
            assert_eq!(
                first.iter().any(|arg| arg == "--cache-from"),
                mode != "cold"
            );
        }
        assert!(!workspace.join("image.tar").exists());
        assert_eq!(
            calls
                .iter()
                .filter(|args| args[..3] == ["aws", "s3api", "put-object"])
                .count(),
            if success {
                3
            } else if mode == "upload_failure" {
                1
            } else {
                0
            }
        );
    }
}
