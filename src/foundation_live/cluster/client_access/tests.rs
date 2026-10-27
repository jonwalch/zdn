//! Exercise the real gateway lifecycle against a local SSM protocol fixture.
use super::*;
use crate::{
    aws::AwsApiError,
    client_gateway as gateway,
    endpoints::Service,
    pulumi::{CommandSpec, ProcessOutput, Progress},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
};
use tempfile::TempDir;

struct FakeAws {
    host: HostInstallSpec,
    artifact: Value,
    endpoints: EndpointFile,
    commands: RefCell<Vec<Value>>,
    reports: RefCell<BTreeMap<String, Value>>,
    events: RefCell<Vec<String>>,
    running: Cell<bool>,
    installing: Cell<bool>,
    lost_reply: Cell<bool>,
    recovery_denied: Cell<bool>,
    status_denied: Cell<bool>,
    pending_polls: Cell<usize>,
    stopped_observations: Cell<usize>,
    invalid_install: RefCell<Option<(&'static str, Value)>>,
    invalid_observation: RefCell<Option<(&'static str, Value)>>,
    invalid_document: Cell<bool>,
}

impl FakeAws {
    fn report(&self, install: bool) -> Value {
        let host = &self.host;
        let mut report = json!({
            "apiVersion":gateway::OBSERVATION_API_VERSION,
            "deploymentId":host.deployment_id,"nodeId":host.node_id,
            "consensusFingerprint":host.consensus_fingerprint,
            "serviceSha256":crate::client_gateway::native::service_sha256(&native::node_manifest(Some(crate::host::runtime::PROTOCOL), host).unwrap()).unwrap(),
            "endpoint":gateway::ENDPOINT,"status":if self.running.get() {"ready"} else {"stopped"}
        });
        let mutation = if install {
            &self.invalid_install
        } else {
            &self.invalid_observation
        };
        if let Some((field, value)) = &*mutation.borrow() {
            report[field] = value.clone();
        }
        report
    }

    fn sends(&self, action: &str) -> usize {
        self.events
            .borrow()
            .iter()
            .filter(|event| *event == &format!("send:{action}"))
            .count()
    }
}

impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        _: &[String],
    ) -> Result<Value> {
        if (service, operation) == ("s3api", "head-object") {
            self.events.borrow_mut().push("artifact:checked".into());
            return Ok(self.artifact.clone());
        }
        assert_eq!(service, "ssm", "unexpected AWS service");
        match operation {
            "send-command" => {
                let script = input["Parameters"]["commands"][0].as_str().unwrap();
                let observe = script.ends_with(" observe");
                let action = if observe { "observe" } else { "install" };
                if observe {
                    assert!(
                        !self.installing.get(),
                        "observation raced an unsettled install journal"
                    );
                    let remaining = self.stopped_observations.get();
                    if remaining > 0 {
                        self.stopped_observations.set(remaining - 1);
                        self.running.set(false);
                    }
                } else {
                    assert!(script.contains("ZDN_INSTALLER_BOOTSTRAP"));
                    assert!(!script.contains("python"));
                    self.installing.set(true);
                    self.running.set(true);
                }
                self.events.borrow_mut().push(format!("send:{action}"));
                input["CommandId"] = json!(Uuid::new_v4());
                self.commands.borrow_mut().push(input.clone());
                self.reports.borrow_mut().insert(
                    input["CommandId"].as_str().unwrap().into(),
                    self.report(!observe),
                );
                if !observe && self.lost_reply.replace(false) {
                    return Err(api_error("RequestTimeout"));
                }
                Ok(json!({"Command":input}))
            }
            "list-commands" => {
                self.events.borrow_mut().push("recover:install".into());
                if self.recovery_denied.get() {
                    return Err(api_error("AccessDeniedException"));
                }
                Ok(json!({"Commands":*self.commands.borrow()}))
            }
            "get-command-invocation" => {
                let commands = self.commands.borrow();
                let command = commands
                    .iter()
                    .find(|command| command["CommandId"] == input["CommandId"])
                    .unwrap();
                let install = !command["Parameters"]["commands"][0]
                    .as_str()
                    .unwrap()
                    .ends_with(" observe");
                if install && self.status_denied.get() {
                    return Err(api_error("AccessDeniedException"));
                }
                let mut response = json!({
                    "CommandId":command["CommandId"],"InstanceId":command["InstanceIds"][0],
                    "DocumentName":command["DocumentName"],"DocumentVersion":command["DocumentVersion"],"Comment":command["Comment"],
                    "Status":"Success","ResponseCode":0,
                    "StandardOutputContent":self.reports.borrow()[input["CommandId"].as_str().unwrap()].to_string()
                });
                let pending = self.pending_polls.get();
                if install && pending > 0 {
                    self.pending_polls.set(pending - 1);
                    self.events.borrow_mut().push("poll:install".into());
                    response["Status"] = json!("InProgress");
                    response["ResponseCode"] = json!(-1);
                    response["StandardOutputContent"] = json!("");
                } else {
                    if install {
                        self.installing.set(false);
                    }
                    self.events.borrow_mut().push(format!(
                        "complete:{}",
                        if install { "install" } else { "observe" }
                    ));
                }
                Ok(response)
            }
            "get-document" => {
                assert_eq!(input["Name"], self.endpoints.document_arn(Service::NodeRpc));
                self.events.borrow_mut().push("document:checked".into());
                let mut content = Service::NodeRpc.session_document();
                if self.invalid_document.get() {
                    content["properties"]["portNumber"] = json!("22");
                }
                Ok(
                    json!({"Name":Service::NodeRpc.document_name(self.endpoints.bootstrap_id,self.endpoints.network_id),"DocumentType":"Session","Status":"Active","DocumentFormat":"JSON","Content":content.to_string()}),
                )
            }
            _ => panic!("unexpected SSM operation {operation}"),
        }
    }
}

fn api_error(code: &str) -> eyre::Report {
    AwsApiError { code: code.into() }.into()
}

struct NoPulumi;
impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("client gateway fixture must not execute Pulumi")
    }
}

#[derive(Default)]
struct Clock(Cell<Duration>);
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        Ok(1_800_000_000 + self.0.get().as_secs())
    }
    fn monotonic(&self) -> Duration {
        self.0.get()
    }
    fn sleep(&self, duration: Duration) {
        self.0.set(self.0.get() + duration);
    }
}

struct Fixture {
    _root: TempDir,
    deployment: Deployment,
    backend: LiveBackend<'static, FakeAws, NoPulumi, Clock>,
}

impl Fixture {
    fn new() -> Self {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let root = tempfile::tempdir().unwrap();
        let mut deployment = super::super::producer_tests::fixture_deployment();
        deployment.cluster.as_mut().unwrap().client_access = true;
        let endpoints = EndpointFile::from_deployment(&deployment).unwrap();
        let node = &deployment.outputs.as_ref().unwrap().nodes["node-1"];
        let host = deployment
            .cluster
            .as_ref()
            .unwrap()
            .host_spec(&deployment.spec, &deployment.team, node)
            .unwrap();
        let rendered =
            selected_gateway(root.path(), &host, Some(crate::host::runtime::PROTOCOL)).unwrap();
        let artifact = json!({"ContentLength":rendered.script.len(),
            "ChecksumSHA256":base64::engine::general_purpose::STANDARD.encode(Sha256::digest(rendered.script.as_bytes())),
            "ServerSideEncryption":"aws:kms","SSEKMSKeyId":deployment.team.state.kms_key_arn});
        let work = root.path().join("project");
        let tools = root.path().join("tools");
        let directory = root.path().join("deployment");
        for path in [&work, &tools, &directory] {
            fs::create_dir(path).unwrap();
        }
        fs::write(tools.join("pulumi"), "data-only fixture").unwrap();
        fs::write(work.join("Pulumi.yaml"), "name: zdn-test\nruntime: yaml\n").unwrap();
        let team = deployment.team.clone();
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
                host,
                artifact,
                endpoints,
                commands: RefCell::new(Vec::new()),
                reports: RefCell::new(BTreeMap::new()),
                events: RefCell::new(Vec::new()),
                running: Cell::new(false),
                installing: Cell::new(false),
                lost_reply: Cell::new(false),
                recovery_denied: Cell::new(false),
                status_denied: Cell::new(false),
                pending_polls: Cell::new(0),
                stopped_observations: Cell::new(0),
                invalid_install: RefCell::new(None),
                invalid_observation: RefCell::new(None),
                invalid_document: Cell::new(false),
            },
            client: PulumiClient::new(workspace, NoPulumi).unwrap(),
            selection,
            runtime: Clock::default(),
            team,
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
            destroying: false,
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
    fn install(&mut self) -> Result<Value> {
        self.backend.install_client_access(&self.deployment)
    }
    fn receipt(&self) -> PathBuf {
        self.backend
            .deployment_directory
            .join("client-endpoints.json")
    }
    fn journal(&self) -> Value {
        foundation::read_json(
            &self
                .backend
                .deployment_directory
                .join("client-rpc-install-command.json"),
        )
        .unwrap()
    }
}

#[test]
fn legacy_requests_skip_client_install_without_aws_or_files() {
    let mut f = Fixture::new();
    f.deployment.cluster.as_mut().unwrap().client_access = false;
    assert_eq!(f.install().unwrap(), Value::Null);
    assert!(f.backend.aws.events.borrow().is_empty());
    assert_eq!(
        fs::read_dir(&f.backend.deployment_directory)
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn ready_receipt_requires_install_fresh_observation_and_fixed_document() {
    let mut f = Fixture::new();
    // Installation runs inside an owned operation; public export still checks
    // the persisted deployment's uncertain-operation flag independently.
    f.deployment.unresolved_operation = Some(Uuid::new_v4());
    assert_eq!(f.install().unwrap()["status"], "ready");
    assert_eq!(
        EndpointFile::load(&f.receipt()).unwrap(),
        f.backend.aws.endpoints
    );
    assert_eq!(
        *f.backend.aws.events.borrow(),
        [
            "artifact:checked",
            "send:install",
            "complete:install",
            "send:observe",
            "complete:observe",
            "document:checked"
        ]
    );
    let bytes = fs::read(f.receipt()).unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("credential"));
}

#[test]
fn cached_install_success_still_requires_a_fresh_ready_observation() {
    let mut f = Fixture::new();
    f.install().unwrap();
    let original = f.journal();
    f.backend.aws.events.borrow_mut().clear();
    f.install().unwrap();
    assert_eq!(
        *f.backend.aws.events.borrow(),
        [
            "artifact:checked",
            "send:observe",
            "complete:observe",
            "document:checked"
        ]
    );
    assert_eq!(f.journal(), original);
}

#[test]
fn unsettled_install_finishes_before_observation_without_duplicate_dispatch() {
    for lost_reply in [true, false] {
        let mut f = Fixture::new();
        f.backend.aws.lost_reply.set(lost_reply);
        f.backend.aws.recovery_denied.set(lost_reply);
        f.backend.aws.status_denied.set(!lost_reply);
        f.backend.aws.pending_polls.set(1);
        assert!(f.install().is_err());
        assert!(!f.receipt().exists());
        assert_eq!(f.backend.aws.sends("install"), 1);
        assert_eq!(f.backend.aws.sends("observe"), 0);
        let before = f.journal();
        assert_eq!(before["attempts"][0]["uncertain"], true);
        assert_eq!(before["attempts"][0]["commandId"].is_null(), lost_reply);
        f.backend.aws.recovery_denied.set(false);
        f.backend.aws.status_denied.set(false);
        let start = f.backend.aws.events.borrow().len();
        f.install().unwrap();
        assert_eq!(f.backend.aws.sends("install"), 1);
        let events = f.backend.aws.events.borrow();
        let events = &events[start..];
        let complete = events
            .iter()
            .position(|event| event == "complete:install")
            .unwrap();
        let observe = events
            .iter()
            .position(|event| event == "send:observe")
            .unwrap();
        assert!(complete < observe);
        assert!(events[..complete]
            .iter()
            .any(|event| event == "poll:install"));
        let after = f.journal();
        assert_eq!(after["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(after["attempts"][0]["id"], before["attempts"][0]["id"]);
        assert_eq!(after["attempts"][0]["uncertain"], false);
    }
}

#[test]
fn a_fresh_stopped_report_allows_exactly_one_recorded_restart() {
    for stop_count in [1, 2] {
        let mut f = Fixture::new();
        f.backend.aws.stopped_observations.set(stop_count);
        let result = f.install();
        assert_eq!(result.is_ok(), stop_count == 1);
        assert_eq!(f.receipt().exists(), stop_count == 1);
        assert_eq!(f.backend.aws.sends("install"), 2);
        assert_eq!(f.backend.aws.sends("observe"), 2);
        let journal = f.journal();
        assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
        assert_ne!(journal["attempts"][0]["id"], journal["attempts"][1]["id"]);
    }
}

#[test]
fn invalid_install_or_observation_identity_never_restarts_or_publishes() {
    for install in [true, false] {
        for (field, value) in [
            ("deploymentId", json!(Uuid::new_v4())),
            ("nodeId", json!("node-2")),
            ("consensusFingerprint", json!("0".repeat(64))),
            ("serviceSha256", json!("0".repeat(64))),
            ("endpoint", json!("0.0.0.0:18234")),
            ("status", json!("unknown")),
        ] {
            let mut f = Fixture::new();
            if !install {
                // A mismatched "stopped" report must not authorize a repeat.
                f.backend.aws.stopped_observations.set(1);
            }
            let mutation = if install {
                &f.backend.aws.invalid_install
            } else {
                &f.backend.aws.invalid_observation
            };
            *mutation.borrow_mut() = Some((field, value));
            assert!(f.install().is_err(), "accepted {field} (install={install})");
            assert_eq!(f.backend.aws.sends("install"), 1);
            assert!(!f.receipt().exists());
        }
    }
}

#[test]
fn unexpected_document_or_saved_installer_prevents_endpoint_publication() {
    for installer_changed in [true, false] {
        let mut f = Fixture::new();
        if installer_changed {
            fs::write(
                f.backend.deployment_directory.join("client-rpc-install.sh"),
                "changed",
            )
            .unwrap();
        } else {
            f.backend.aws.invalid_document.set(true);
        }
        assert!(f.install().is_err());
        assert!(!f.receipt().exists());
        assert_eq!(
            f.backend.aws.sends("install"),
            usize::from(!installer_changed)
        );
    }
}
