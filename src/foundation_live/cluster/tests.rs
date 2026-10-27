//! Offline checks of the live adapter's S3 cleanup contract. The fixture does
//! not execute Pulumi, launch a node, or need AWS credentials.

use super::*;
use crate::{
    aws::{AwsApiError, TeamAws, TeamState},
    config::Size,
    devnet::ClusterRequest,
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
    pulumi::{CommandSpec, ProcessOutput, Progress},
    state::Scope,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    fs,
};
use tempfile::TempDir;

#[path = "../../../tests/support/iam.rs"]
mod iam;

#[derive(Default)]
struct FakeAws {
    script: RefCell<VecDeque<(&'static str, Result<Value>)>>,
    calls: RefCell<Vec<(String, Value)>>,
    bucket: String,
    owner: String,
    prefix: String,
    policies: Vec<Value>,
}

impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert_eq!(service, "s3api");
        assert_eq!(input["Bucket"], self.bucket);
        assert_eq!(input["ExpectedBucketOwner"], self.owner);
        self.calls
            .borrow_mut()
            .push((operation.into(), input.clone()));
        match operation {
            "list-object-versions" => {
                assert_eq!(input["Prefix"], self.prefix);
                assert_eq!(input["MaxKeys"], 50);
                assert_eq!(extra[0..2], ["--no-paginate", "--query"]);
                assert!(extra[2].contains("IsTruncated:IsTruncated"));
            }
            "delete-objects" => {
                assert!(extra.is_empty());
                assert_eq!(input["Delete"]["Quiet"], true);
                // Linux limits each argv entry, including --cli-input-json,
                // to 128 KiB even when the total argv budget is larger.
                assert!(serde_json::to_vec(&input).unwrap().len() < 128 * 1024);
                for object in input["Delete"]["Objects"].as_array().unwrap() {
                    assert!(object["Key"].as_str().unwrap().starts_with(&self.prefix));
                    assert!(object["VersionId"].is_string());
                    // A version-targeted DeleteObjects request needs this
                    // distinct permission, including for delete markers.
                    if !iam::permitted(
                        &self.policies,
                        "s3:DeleteObjectVersion",
                        &format!(
                            "arn:aws:s3:::{}/{}",
                            self.bucket,
                            object["Key"].as_str().unwrap()
                        ),
                        &json!({}),
                    ) {
                        return Err(AwsApiError {
                            code: "AccessDenied".into(),
                        }
                        .into());
                    }
                }
            }
            "head-object" => {
                assert!(input["Key"].as_str().unwrap().starts_with(&self.prefix));
                assert_eq!(input["ChecksumMode"], "ENABLED");
            }
            "put-object" => {
                assert!(input["Key"].as_str().unwrap().starts_with(&self.prefix));
                assert_eq!(input["IfNoneMatch"], "*");
                assert_eq!(extra[0], "--body");
            }
            _ => panic!("unexpected AWS operation {operation}"),
        }
        let (expected, response) = self
            .script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("unscripted {operation}"));
        assert_eq!(operation, expected);
        response
    }
}

struct NoPulumi;
impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("cleanup tests must not run Pulumi")
    }
}

struct Clock;
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        Ok(1000)
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&self, _: Duration) {
        panic!("cleanup fixture must not sleep")
    }
}

struct Fixture {
    _root: TempDir,
    deployment: Deployment,
    backend: LiveBackend<'static, FakeAws, NoPulumi, Clock>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let scope = Scope {
            team_id: "private-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let team = TeamDefinition {
            api_version: aws::TEAM_API_VERSION.into(),
            team_id: scope.team_id.clone(),
            revision: 1,
            bootstrap_id: Uuid::parse_str("965f7c13-e186-4d52-b7e3-ef92db98a0ec").unwrap(),
            aws: TeamAws {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
            },
            state: TeamState {
                backend: "s3://zdn-private-team/pulumi/private-team".into(),
                kms_key_arn:
                    "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"
                        .into(),
            },
            deployment: None,
        };
        let spec = FoundationSpec {
            scope,
            network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        };
        let mut deployment = Deployment::new(spec, team.clone()).unwrap();
        // Artifact cleanup depends on scope and presence of a cluster request,
        // not on availability of local node inputs or a released image.
        deployment.cluster = Some(ClusterRequest {
            build: None,
            artifact_set: None,
            installer_fetch_protocol: Some(crate::host::installer_bootstrap::PROTOCOL.into()),
            native_runtime_protocol: Some(crate::host::runtime::PROTOCOL.into()),
            client_access: false,
            lightwallet: None,
            block_interval_seconds: None,
            api_version: devnet::API_VERSION.into(),
            config_sha256: "a".repeat(64),
            manifest: serde_json::from_str(include_str!(
                "../../../tests/fixtures/chain-manifest/valid.json"
            ))
            .unwrap(),
            image: ImageRecord {
                api_version: crate::image::API_VERSION.into(),
                image: format!(
                    "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
                    "b".repeat(64)
                ),
                config_digest: format!("sha256:{}", "c".repeat(64)),
                platform: "linux/amd64".into(),
                provenance: ImageProvenance::Release {
                    revision: "d".repeat(40),
                    version: "v0.0.1".into(),
                },
                capabilities: ImageCapabilities::default(),
                binary_path: crate::image::NODE_BINARY.into(),
                environment_launcher: crate::image::ENV_ENTRYPOINT.into(),
            },
            node_count: 3,
            reward_address: "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB".into(),
            artifacts: BTreeMap::new(),
        });
        let work = root.path().join("project");
        let tools = root.path().join("tools");
        let directory = root.path().join("deployment");
        for path in [&work, &tools, &directory] {
            fs::create_dir(path).unwrap();
        }
        fs::write(tools.join("pulumi"), "data-only fixture").unwrap();
        fs::write(work.join("Pulumi.yaml"), "name: zdn-test\nruntime: yaml\n").unwrap();
        let selection = AwsSelection {
            profile: "developer".into(),
            account_id: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
        };
        let workspace = PulumiWorkspace {
            tools: ManagedTools {
                executable: tools.join("pulumi"),
                bin_dir: tools.clone(),
                plugins_dir: tools,
            },
            work_dir: work,
            diagnostics_dir: root.path().join("diagnostics"),
            backend_url: team.state.backend.clone(),
            secrets_provider: team.secrets_provider(),
            aws: AwsContext {
                credential_files: None,
                profile: selection.profile.clone(),
                account_id: selection.account_id.clone(),
                region: selection.region.clone(),
            },
            project: "zdn-test".into(),
            stack: "zdn-test".into(),
        };
        let backend = LiveBackend {
            command_progress: None,
            aws: FakeAws {
                bucket: team.backend_bucket().unwrap().into(),
                owner: team.aws.account_id.clone(),
                prefix: devnet::artifact_prefix(&team, &deployment.spec),
                policies: crate::access::deployment_policies(
                    &team,
                    &crate::access::DeploymentAccess::managed(&team),
                )
                .unwrap()
                .into_values()
                .collect(),
                ..Default::default()
            },
            client: PulumiClient::new(workspace, NoPulumi).unwrap(),
            selection,
            runtime: Clock,
            team: team.clone(),
            reservation: NetworkReservation::new(
                deployment.spec.scope.clone(),
                deployment.spec.network_id,
                deployment.owner_id,
            )
            .unwrap(),
            lease: None,
            cancel: Arc::new(AtomicBool::new(false)),
            heartbeat: Heartbeat::default(),
            recovery_etag: None,
            destroying: true,
            destroy_context: None,
            stack_missing: false,
            state_root: root.path().join("state"),
            deployment_directory: directory,
        };
        Self {
            _root: root,
            deployment,
            backend,
        }
    }

    fn step(&self, operation: &'static str, value: Value) {
        self.backend
            .aws
            .script
            .borrow_mut()
            .push_back((operation, Ok(value)));
    }

    fn key(&self, name: &str) -> String {
        format!("{}{name}", self.backend.aws.prefix)
    }
}

#[test]
fn default_destroy_reports_retained_artifact_namespace_without_mutation() {
    let mut f = Fixture::new();
    let retained = f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, false)
        .unwrap();
    assert_eq!(
        retained,
        [format!(
            "s3://{}/{}",
            f.backend.aws.bucket, f.backend.aws.prefix
        )]
    );
    assert!(f.backend.aws.calls.borrow().is_empty());
    f.deployment.cluster = None;
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap()
        .is_empty());
    assert!(f.backend.aws.calls.borrow().is_empty());
}

#[test]
fn explicit_data_deletion_removes_exact_versions_and_markers_then_proves_empty() {
    let mut f = Fixture::new();
    f.deployment
        .cluster
        .as_mut()
        .unwrap()
        .native_runtime_protocol = None;
    f.deployment
        .cluster
        .as_mut()
        .unwrap()
        .installer_fetch_protocol = None;
    assert!(f.deployment.require_native_execution().is_err());
    let first = f.key("old/chain.tar");
    let second = f.key("current/image.json");
    let versions: Vec<_> = (0..49)
        .map(|index| json!({"Key":first,"VersionId":format!("version-{index}")}))
        .collect();
    f.step("list-object-versions",json!({"IsTruncated":true,"Versions":versions,"DeleteMarkers":[{"Key":first,"VersionId":"delete-1"}],"NextKeyMarker":"ignored-after-deleting-page"}));
    f.step("delete-objects", json!({}));
    f.step(
        "list-object-versions",
        json!({"IsTruncated":false,"Versions":[{"Key":second,"VersionId":"version-2"}]}),
    );
    f.step("delete-objects", json!({"Errors":[]}));
    f.step("list-object-versions", json!({"IsTruncated":false}));
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap()
        .is_empty());
    let calls = f.backend.aws.calls.borrow();
    assert_eq!(calls.len(), 5);
    let mut deleted = versions;
    deleted.push(json!({"Key":first,"VersionId":"delete-1"}));
    assert_eq!(calls[1].1["Delete"]["Objects"], json!(deleted));
    assert_eq!(
        calls[3].1["Delete"]["Objects"],
        json!([{"Key":second,"VersionId":"version-2"}])
    );
    assert!(f.backend.aws.script.borrow().is_empty());
}

#[test]
fn artifact_cleanup_handles_escaped_long_identities_without_oversized_cli_arguments() {
    let mut f = Fixture::new();
    let prefix = &f.backend.aws.prefix;
    let key = format!("{prefix}{}", "\u{1}".repeat(1024 - prefix.len()));
    let versions: Vec<_> = (0..20)
        .map(|index| json!({"Key":key,"VersionId":format!("{index:02}{}", "\u{2}".repeat(1022))}))
        .collect();
    f.step(
        "list-object-versions",
        json!({"IsTruncated":false,"Versions":versions}),
    );
    for _ in 0..4 {
        f.step("delete-objects", json!({}));
    }
    f.step("list-object-versions", json!({"IsTruncated":false}));
    f.backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap();
    let deleted: Vec<_> = f
        .backend
        .aws
        .calls
        .borrow()
        .iter()
        .filter(|(operation, _)| operation == "delete-objects")
        .flat_map(|(_, input)| input["Delete"]["Objects"].as_array().unwrap().clone())
        .collect();
    assert_eq!(deleted, versions);
    assert!(f.backend.aws.script.borrow().is_empty());
}

#[test]
fn artifact_cleanup_fails_when_version_deletion_is_removed_from_deployment_policy() {
    let mut f = Fixture::new();
    for policy in &mut f.backend.aws.policies {
        policy["Statement"]
            .as_array_mut()
            .unwrap()
            .retain(|statement| statement["Action"] != json!(["s3:DeleteObjectVersion"]));
    }
    f.step("list-object-versions", json!({"IsTruncated":false,"Versions":[{"Key":f.key("chain.tar"),"VersionId":"version-1"}]}));
    let error = f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<AwsApiError>().unwrap().code,
        "AccessDenied"
    );
    assert_eq!(f.backend.aws.calls.borrow().len(), 2);
}

#[test]
fn foreign_or_malformed_version_rows_never_reach_delete_objects() {
    for mode in 0..5 {
        let mut f = Fixture::new();
        let page = match mode {
            0 => {
                json!({"IsTruncated":false,"Versions":[{"Key":"pulumi/private-team/.pulumi/state","VersionId":"version-1"}]})
            }
            1 => json!({"IsTruncated":false,"Versions":[{"Key":f.key("chain.tar")}]}),
            2 => json!({"IsTruncated":false,"Versions":{}}),
            3 => json!({"IsTruncated":true,"Versions":[]}),
            4 => json!({"Versions":[]}),
            _ => unreachable!(),
        };
        f.step("list-object-versions", page);
        assert!(
            f.backend
                .cleanup_cluster_artifacts(&f.deployment, true)
                .is_err(),
            "mode{mode}"
        );
        assert_eq!(f.backend.aws.calls.borrow().len(), 1);
    }
}

#[test]
fn partial_delete_errors_and_unknown_list_failures_do_not_claim_cleanup() {
    let mut f = Fixture::new();
    f.step("list-object-versions",json!({"IsTruncated":false,"Versions":[{"Key":f.key("chain.tar"),"VersionId":"version-1"}]}));
    f.step(
        "delete-objects",
        json!({"Errors":[{"Code":"AccessDenied"}]}),
    );
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .is_err());
    assert_eq!(f.backend.aws.calls.borrow().len(), 2);

    let mut f = Fixture::new();
    f.backend.aws.script.borrow_mut().push_back((
        "list-object-versions",
        Err(AwsApiError {
            code: "AccessDenied".into(),
        }
        .into()),
    ));
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .is_err());
    assert_eq!(f.backend.aws.calls.borrow().len(), 1);
}

#[test]
fn repeated_version_pages_stop_at_the_explicit_work_bound() {
    let mut f = Fixture::new();
    for _ in 0..100 {
        f.step("list-object-versions",json!({"IsTruncated":true,"Versions":[{"Key":f.key("chain.tar"),"VersionId":"version-1"}]}));
        f.step("delete-objects", json!({}));
    }
    let error = f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap_err();
    assert!(error.to_string().contains("page bound"));
    assert_eq!(f.backend.aws.calls.borrow().len(), 200);
    assert!(f.backend.aws.script.borrow().is_empty());
}

#[test]
fn cancellation_stops_artifact_deletion_before_aws_calls() {
    let mut f = Fixture::new();
    f.backend.cancel.store(true, Ordering::SeqCst);
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .is_err());
    assert!(f.backend.aws.calls.borrow().is_empty());
}

#[test]
fn execution_admission_rejects_legacy_and_incomplete_native_selection_before_aws() {
    let mut f = Fixture::new();
    f.deployment.require_native_execution().unwrap();
    let native = f.deployment.cluster.as_ref().unwrap().clone();
    for (runtime, transport) in [
        (None, native.installer_fetch_protocol.clone()),
        (native.native_runtime_protocol.clone(), None),
        (
            native.native_runtime_protocol.clone(),
            Some("unsupported".into()),
        ),
    ] {
        let request = f.deployment.cluster.as_mut().unwrap();
        request.native_runtime_protocol = runtime;
        request.installer_fetch_protocol = transport;
        assert!(f.deployment.require_native_execution().is_err());
        assert!(f.backend.verify(&f.deployment, false).is_err());
        assert!(f
            .backend
            .acquire_update(&f.deployment, Uuid::new_v4())
            .is_err());
        assert!(f.backend.observe_cluster(&f.deployment).is_err());
        assert!(f.backend.aws.calls.borrow().is_empty());
    }
}

#[test]
fn preflight_refuses_missing_local_inputs_before_ecr_or_iam_calls() {
    let mut f = Fixture::new();
    assert!(f.backend.verify_cluster(&f.deployment).is_err());
    assert!(f.backend.aws.calls.borrow().is_empty());
}

#[test]
fn native_foundation_upload_and_cleanup_keep_the_deployment_namespace() {
    use crate::foundation_runtime::FoundationRuntime;
    use base64::Engine;
    let mut f = Fixture::new();
    f.deployment.cluster = None;
    f.deployment.team.api_version = crate::access::TEAM_ROLE_API_VERSION.into();
    f.deployment.team.deployment =
        Some(crate::access::DeploymentAccess::managed(&f.deployment.team));
    let source = f._root.path().join("helper");
    let mut bytes = vec![0; 64];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[16] = 2;
    bytes[18] = 62;
    fs::write(&source, bytes).unwrap();
    let runtime = FoundationRuntime::stage(&source, &f.backend.deployment_directory).unwrap();
    let object = runtime
        .object(&f.deployment.team, &f.deployment.spec)
        .unwrap();
    f.deployment.foundation_runtime = Some(runtime);
    f.deployment.validate().unwrap();
    f.backend.aws.script.borrow_mut().push_back((
        "head-object",
        Err(AwsApiError {
            code: "NoSuchKey".into(),
        }
        .into()),
    ));
    f.step("put-object", json!({}));
    f.step("head-object", json!({"ContentLength":object.bytes,
        "ChecksumSHA256":base64::engine::general_purpose::STANDARD.encode(hex::decode(&object.sha256).unwrap()),
        "ServerSideEncryption":"aws:kms","SSEKMSKeyId":f.deployment.team.state.kms_key_arn}));
    f.backend.stage_cluster_artifacts(&f.deployment).unwrap();
    assert!(f
        .backend
        .aws
        .calls
        .borrow()
        .iter()
        .all(|(_, input)| input["Key"] == object.key));
    assert_eq!(
        f.backend
            .cleanup_cluster_artifacts(&f.deployment, false)
            .unwrap(),
        [format!("s3://{}/{}", object.bucket, f.backend.aws.prefix)]
    );
    // Teardown must still work when the now-unused private helper is missing.
    fs::remove_file(
        f.backend
            .deployment_directory
            .join(crate::foundation_runtime::HELPER),
    )
    .unwrap();
    f.step("list-object-versions", json!({"IsTruncated":false,"Versions":[{"Key":object.key,"VersionId":"helper-version"}],"DeleteMarkers":[{"Key":object.key,"VersionId":"helper-delete"}]}));
    f.step("delete-objects", json!({}));
    f.step("list-object-versions", json!({"IsTruncated":false}));
    assert!(f
        .backend
        .cleanup_cluster_artifacts(&f.deployment, true)
        .unwrap()
        .is_empty());
    assert!(f.backend.aws.script.borrow().is_empty());
}
