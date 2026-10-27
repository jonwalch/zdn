//! Local SSM fixtures exercise the actual durable lightwallet adapter.
use super::*;
use crate::{
    aws::AwsApiError,
    cluster_infra::{ClusterLightwalletOutputs, LightwalletAllocation},
    devnet::{Artifact, LightwalletDeployment},
    lightwallet_image,
    pulumi::{CommandSpec, ProcessOutput, Progress},
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fs,
};
use tempfile::TempDir;

#[test]
fn missing_outputs_recover_exact_three_node_and_cache_disk_identities_from_checkpoint() {
    let mut f = Fixture::new();
    f.deployment.outputs = None;
    let program = f.deployment.render().unwrap();
    let prefix = format!(
        "urn:pulumi:zdn-{}::zdn-foundation::aws:ebs/volume:Volume::",
        f.deployment.spec.network_id.simple()
    );
    let mut resources = Vec::new();
    let mut disks = Vec::new();
    for (index, resource) in program
        .resources
        .values()
        .filter(|resource| matches!(resource.definition, crate::infra::Definition::Volume(_)))
        .enumerate()
    {
        let rendered = serde_json::to_value(resource).unwrap();
        let properties = &rendered["properties"];
        let id = format!("vol-{:017x}", index + 1);
        resources.push(json!({"urn":format!("{prefix}{}", resource.name),"type":"aws:ebs/volume:Volume","id":id,"custom":true,"retainOnDelete":true,"inputs":properties,"outputs":properties}));
        disks.push(json!({"VolumeId":id,"State":"available","Attachments":[],"Encrypted":true,
            "AvailabilityZone":properties["availabilityZone"],"Size":properties["size"],"VolumeType":properties["type"],
            "Tags":properties["tags"].as_object().unwrap().iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>() }));
    }
    assert_eq!(resources.len(), 4);
    let checkpoint = json!({"deployment":{"resources":resources,"pending_operations":[]}});
    crate::foundation_live::destroy::save_volume_identities(
        &f.backend.deployment_directory,
        &f.deployment,
        &checkpoint,
    )
    .unwrap();
    let saved = crate::foundation_live::destroy::load_volume_identities(
        &f.backend.deployment_directory,
        &f.deployment,
    )
    .unwrap();
    assert_eq!(saved.len(), 4);
    for disk in disks {
        assert!(crate::foundation_live::destroy::owned_recorded_volume(
            &disk,
            &f.deployment,
            &saved
        )
        .unwrap());
    }
    let mut duplicate = checkpoint;
    duplicate["deployment"]["resources"][1]["id"] =
        duplicate["deployment"]["resources"][0]["id"].clone();
    assert!(crate::foundation_live::destroy::save_volume_identities(
        &f.backend.deployment_directory,
        &f.deployment,
        &duplicate
    )
    .is_err());
}

#[derive(Default)]
struct FakeAws {
    spec: RefCell<Option<LightwalletInstallSpec>>,
    capacity: RefCell<Value>,
    commands: RefCell<Vec<Value>>,
    reports: RefCell<BTreeMap<String, Value>>,
    events: RefCell<Vec<String>>,
    running: Cell<bool>,
    invalid: Cell<bool>,
    lose_start: Cell<bool>,
    recovery_unavailable: Cell<bool>,
    start_status_unavailable: Cell<bool>,
    start_polls_remaining: Cell<usize>,
    start_lock_held: Cell<bool>,
    blocked_observations: RefCell<BTreeSet<String>>,
}
impl FakeAws {
    fn report(&self) -> Value {
        let spec = self.spec.borrow();
        let spec = spec.as_ref().unwrap();
        let manifest =
            native::lightwallet_manifest(Some(crate::host::runtime::PROTOCOL), spec).unwrap();
        let ready = self.running.get();
        let mut report = json!({"apiVersion":service::OBSERVATION_API_VERSION,"deploymentId":spec.host.deployment_id,
            "nodeId":spec.host.node_id,"installSha256":manifest.install_sha256,"serviceSha256":service::render_service(&spec.host, &spec.service).unwrap().service_sha256,
            "cacheVolumeId":spec.service.cache_volume_id,"image":spec.service.image,"status":if ready {"ready"} else {"stopped"},
            "readiness":if ready {json!({"apiVersion":crate::lightwallet::API_VERSION,"consensusFingerprint":spec.host.consensus_fingerprint,
                "protocolVersion":crate::lightwallet::PROTOCOL_VERSION,"launchReady":false,"paymentQualification":"pending",
                "ironwoodTreeVerified":true,"compactDataVerified":true,"lagBlocks":0,"checkedCompactBlocks":4})} else {Value::Null},
            "paymentQualification":"pending","launchReady":false});
        if self.invalid.get() {
            report["serviceSha256"] = json!("0".repeat(64));
        }
        report
    }
    fn sends(&self, action: &str) -> usize {
        self.events
            .borrow()
            .iter()
            .filter(|event| event.as_str() == format!("send:{action}"))
            .count()
    }
}
impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        _extra: &[String],
    ) -> Result<Value> {
        assert_eq!(service, "ssm");
        match operation {
            "describe-instance-information" => Ok(
                json!({"InstanceInformationList":[{"InstanceId":input["Filters"][0]["Values"][0],"PingStatus":"Online"}]}),
            ),
            "send-command" => {
                let script = input["Parameters"]["commands"][0].as_str().unwrap();
                let action = if script.contains("zdn-host-capacity/v1alpha1") {
                    "capacity"
                } else if script.ends_with(" start") {
                    "start"
                } else {
                    assert!(script.ends_with(" observe"));
                    "observe"
                };
                self.events.borrow_mut().push(format!("send:{action}"));
                input["CommandId"] = json!(Uuid::new_v4());
                self.commands.borrow_mut().push(input.clone());
                if action == "start" {
                    self.running.set(true);
                    self.start_lock_held.set(true);
                } else if action == "observe" && self.start_lock_held.get() {
                    // Both host actions use the same nonblocking install lock.
                    self.blocked_observations
                        .borrow_mut()
                        .insert(input["CommandId"].as_str().unwrap().into());
                }
                let report = if action == "capacity" {
                    self.capacity.borrow().clone()
                } else {
                    self.report()
                };
                self.reports
                    .borrow_mut()
                    .insert(input["CommandId"].as_str().unwrap().into(), report);
                if action == "start" && self.lose_start.replace(false) {
                    return Err(AwsApiError {
                        code: "RequestTimeout".into(),
                    }
                    .into());
                }
                Ok(json!({"Command":input}))
            }
            "list-commands" => {
                self.events.borrow_mut().push("recover:start".into());
                if self.recovery_unavailable.get() {
                    return Err(AwsApiError {
                        code: "AccessDeniedException".into(),
                    }
                    .into());
                }
                let commands: Vec<_> = self
                    .commands
                    .borrow()
                    .iter()
                    .filter(|command| command["InstanceIds"][0] == input["InstanceId"])
                    .cloned()
                    .collect();
                Ok(json!({"Commands":commands}))
            }
            "get-command-invocation" => {
                let commands = self.commands.borrow();
                let command = commands
                    .iter()
                    .find(|command| command["CommandId"] == input["CommandId"])
                    .unwrap();
                let mut response = json!({"CommandId":command["CommandId"],"InstanceId":command["InstanceIds"][0],"DocumentName":command["DocumentName"],
                    "DocumentVersion":command["DocumentVersion"],"Comment":command["Comment"],"Status":"Success","ResponseCode":0,
                    "StandardOutputContent":serde_json::to_string(&self.reports.borrow()[input["CommandId"].as_str().unwrap()]).unwrap(),"StandardErrorContent":""});
                if command["Parameters"]["commands"][0]
                    .as_str()
                    .unwrap()
                    .ends_with(" start")
                {
                    if self.start_status_unavailable.get() {
                        return Err(AwsApiError {
                            code: "AccessDeniedException".into(),
                        }
                        .into());
                    }
                    let remaining = self.start_polls_remaining.get();
                    if remaining > 0 {
                        self.start_polls_remaining.set(remaining - 1);
                        self.events
                            .borrow_mut()
                            .push("poll:start:in-progress".into());
                        response["Status"] = json!("InProgress");
                        response["ResponseCode"] = json!(-1);
                        response["StandardOutputContent"] = json!("");
                    } else {
                        self.start_lock_held.set(false);
                        self.events.borrow_mut().push("complete:start".into());
                    }
                } else if self
                    .blocked_observations
                    .borrow()
                    .contains(input["CommandId"].as_str().unwrap())
                {
                    response["Status"] = json!("Failed");
                    response["ResponseCode"] = json!(1);
                    response["StandardOutputContent"] = json!("");
                    response["StandardErrorContent"] =
                        json!("zdn lightwallet operation failed: BlockingIOError");
                }
                Ok(response)
            }
            other => panic!("unexpected SSM action {other}"),
        }
    }
}
struct NoPulumi;
impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("lightwallet fixture must not invoke Pulumi")
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
    fn sleep(&self, amount: Duration) {
        self.0.set(self.0.get() + amount);
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
        let mut deployment = super::super::producer_tests::fixture_deployment();
        let request = deployment.cluster.as_mut().unwrap();
        request.lightwallet=Some(LightwalletDeployment {
            allocation:LightwalletAllocation::for_size(deployment.spec.size),
            capacity_protocol:Some(crate::host::CAPACITY_PROTOCOL.into()),
            image:lightwallet_image::ImageRecord {
                api_version:lightwallet_image::API_VERSION.into(), image:format!("123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/lightwalletd@sha256:{}","a".repeat(64)),
                config_digest:format!("sha256:{}","b".repeat(64)),platform:"linux/amd64".into(),source_revision:lightwallet_image::SOURCE_REVISION.into(),
                source_version:lightwallet_image::SOURCE_VERSION.into(),protocol_revision:lightwallet_image::PROTOCOL_REVISION.into(),protocol_version:lightwallet_image::PROTOCOL_VERSION.into(),
                binary_path:lightwallet_image::BINARY_PATH.into(),environment_launcher:lightwallet_image::ENVIRONMENT_LAUNCHER.into(),
            },
        });
        for name in [
            "lightwallet-image.json",
            "lightwallet-image-manifest.json",
            "lightwallet-image-config.json",
        ] {
            request.artifacts.insert(
                name.into(),
                Artifact {
                    sha256: "f".repeat(64),
                    bytes: 128,
                },
            );
        }
        let selected = request.topology().unwrap().lightwallet_node().node_id;
        let outputs = deployment.outputs.as_mut().unwrap();
        outputs.lightwallet = Some(ClusterLightwalletOutputs {
            node_id: selected.clone(),
            instance_id: outputs.nodes[&selected].instance_id.clone(),
            cache_volume_id: "vol-00000000000000099".into(),
            cache_size_gib: 40,
        });
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
                capacity: RefCell::new(
                    json!({"mem_total_bytes":31*GIB,"ancestor_memory_limits_bytes":[],"online_cpu_count":4,"affinity_cpu_count":4,"ancestor_cpu_quota_millis":[]}),
                ),
                ..Default::default()
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
    fn prepare(&mut self) -> LightwalletInstallSpec {
        self.backend
            .prepare_lightwallet_capacity(&self.deployment)
            .unwrap();
        crate::foundation_live::new_volume::write_lightwallet_proof_fixture(
            &self.deployment,
            &self.backend.deployment_directory,
        )
        .unwrap();
        let spec = self.backend.lightwallet_spec(&self.deployment).unwrap();
        *self.backend.aws.spec.borrow_mut() = Some(spec.clone());
        spec
    }
    fn ensure(&mut self, spec: &LightwalletInstallSpec) -> Result<Value> {
        self.backend
            .ensure_lightwallet_running(&self.deployment, spec)
    }
}

#[test]
fn capacity_is_pinned_once_before_installer_and_allocates_only_selected_node() {
    {
        let mut fixture = Fixture::new();
        fixture
            .backend
            .prepare_lightwallet_capacity(&fixture.deployment)
            .unwrap();
        let commands = fixture.backend.aws.commands.borrow();
        let script = commands[0]["Parameters"]["commands"][0].as_str().unwrap();
        {
            assert!(script.contains("__host-capacity"));
            assert!(!script.contains("python"));
            let helper = fixture
                .deployment
                .cluster
                .as_ref()
                .unwrap()
                .s3_object(&fixture.deployment.team, &fixture.deployment.spec, "zdn")
                .unwrap();
            assert!(script.contains(&helper.key));
            assert!(script.contains(&helper.sha256));
        }
        drop(commands);
        let path = fixture
            .backend
            .deployment_directory
            .join("lightwallet-capacity.json");
        let original = fs::read(&path).unwrap();
        *fixture.backend.aws.capacity.borrow_mut() = json!({"mem_total_bytes":8*GIB});
        fixture
            .backend
            .prepare_lightwallet_capacity(&fixture.deployment)
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(fixture.backend.aws.sends("capacity"), 1);
        let selected = lightwallet_node(&fixture.deployment).unwrap();
        let host = fixture
            .backend
            .cluster_host_spec(&fixture.deployment, selected)
            .unwrap();
        assert_eq!(
            host.memory_bytes,
            fixture
                .backend
                .lightwallet_capacity(&fixture.deployment)
                .unwrap()
                .limits
                .node_memory_bytes
        );
        let follower = &fixture.deployment.outputs.as_ref().unwrap().nodes["node-1"];
        if follower.node_id != selected.node_id {
            let base = fixture
                .deployment
                .cluster
                .as_ref()
                .unwrap()
                .host_spec(&fixture.deployment.spec, &fixture.deployment.team, follower)
                .unwrap();
            assert_eq!(
                fixture
                    .backend
                    .cluster_host_spec(&fixture.deployment, follower)
                    .unwrap()
                    .memory_bytes,
                base.memory_bytes
            );
        }
        fixture
            .deployment
            .cluster
            .as_mut()
            .unwrap()
            .lightwallet
            .as_mut()
            .unwrap()
            .capacity_protocol = Some("unsupported".into());
        assert!(fixture
            .backend
            .prepare_lightwallet_capacity(&fixture.deployment)
            .is_err());
        assert_eq!(fixture.backend.aws.sends("capacity"), 1);
    }
}

#[test]
fn refuses_missing_capacity_after_publication_and_tampered_capacity() {
    for installer in ["lightwallet-install.sh", "node-2-install.sh"] {
        let mut fixture = Fixture::new();
        // Compute the actual selected node; the fixed service file tests the other guard.
        let installer = if installer.starts_with("node-") {
            format!(
                "{}-install.sh",
                lightwallet_node(&fixture.deployment).unwrap().node_id
            )
        } else {
            installer.into()
        };
        fs::write(
            fixture.backend.deployment_directory.join(installer),
            "saved",
        )
        .unwrap();
        assert!(fixture
            .backend
            .prepare_lightwallet_capacity(&fixture.deployment)
            .is_err());
        assert_eq!(fixture.backend.aws.sends("capacity"), 0);
    }
    for field in ["instanceId", "requestSha256", "limits"] {
        let mut fixture = Fixture::new();
        fixture.prepare();
        let path = fixture
            .backend
            .deployment_directory
            .join("lightwallet-capacity.json");
        let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        receipt[field] = if field == "limits" {
            json!({})
        } else {
            json!("different")
        };
        fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(fixture
            .backend
            .prepare_lightwallet_capacity(&fixture.deployment)
            .is_err());
        assert_eq!(fixture.backend.aws.sends("capacity"), 1);
    }
}

#[test]
fn fresh_observation_prevents_cached_start_from_claiming_current_health() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.ensure(&spec).unwrap();
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    let prior = fixture.backend.aws.sends("observe");
    fixture.ensure(&spec).unwrap();
    assert!(fixture.backend.aws.sends("observe") > prior);
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    fixture.backend.aws.invalid.set(true);
    assert!(fixture.ensure(&spec).is_err());
    assert_eq!(fixture.backend.aws.sends("start"), 1);
}

#[test]
fn healthy_install_handoff_needs_no_separate_start_but_pins_install_command() {
    use crate::{
        handoff::Manifest,
        state::{
            BindingExport, OperationInput, OperationReceipt, PhaseRecord, PhaseStatus, Reservation,
        },
    };
    {
        let mut fixture = Fixture::new();
        let spec = fixture.prepare();
        fixture.backend.aws.running.set(true);
        fixture.ensure(&spec).unwrap();
        let directory = &fixture.backend.deployment_directory;
        assert!(!directory.join("lightwallet-start-command.json").exists());
        let rendered =
            selected_lightwallet(directory, &spec, Some(crate::host::runtime::PROTOCOL)).unwrap();
        foundation::write_private(
            &directory.join("lightwallet-install.sh"),
            rendered.script.as_bytes(),
        )
        .unwrap();
        let object = installer_object(
            &fixture.deployment,
            "lightwallet",
            &rendered.script_sha256,
            rendered.script.len(),
        )
        .unwrap();
        let script =
            selected_fetch_installer(&fixture.deployment, &object, INSTALL_TIMEOUT).unwrap();
        let instance = &lightwallet_node(&fixture.deployment).unwrap().instance_id;
        let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],
        "TimeoutSeconds":120,"MaxConcurrency":"1","MaxErrors":"0","CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[script],"executionTimeout":["7200"],"workingDirectory":["/"]}});
        let mut journal: Value =
            foundation::read_json(&directory.join("lightwallet-capacity-command.json")).unwrap();
        journal["requestSha256"] = json!(devnet::sha256(&serde_json::to_vec(&request).unwrap()));
        journal["timeoutSecs"] = json!(7200);
        foundation::write_json(
            &directory.join("lightwallet-install-command.json"),
            &journal,
        )
        .unwrap();
        validate_handoff(&fixture.deployment, directory, ObservationHistory::Validate).unwrap();
        // Rebinding the capacity receipt is not authority to rewrite an already
        // recorded command into the other protocol's history.
        let capacity_path = directory.join("lightwallet-capacity.json");
        let capacity_bytes = fs::read(&capacity_path).unwrap();
        let mut changed = fixture.deployment.clone();
        changed
            .cluster
            .as_mut()
            .unwrap()
            .lightwallet
            .as_mut()
            .unwrap()
            .capacity_protocol = None;
        let mut capacity: Value = serde_json::from_slice(&capacity_bytes).unwrap();
        capacity["requestSha256"] = json!(devnet::sha256(
            &serde_json::to_vec(changed.cluster.as_ref().unwrap()).unwrap()
        ));
        foundation::write_json(&capacity_path, &capacity).unwrap();
        assert!(validate_handoff(&changed, directory, ObservationHistory::Preserve).is_err());
        foundation::write_private(&capacity_path, &capacity_bytes).unwrap();
        let observation = directory.join(format!("lightwallet-observe-{}.json", Uuid::new_v4()));
        let mut uncertain = journal.clone();
        let observe_script =
            native::lightwallet_command(Some(crate::host::runtime::PROTOCOL), &spec, "observe")
                .unwrap();
        let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],
        "TimeoutSeconds":120,"MaxConcurrency":"1","MaxErrors":"0","CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[observe_script],"executionTimeout":[OBSERVATION_TIMEOUT.to_string()],"workingDirectory":["/"]}});
        uncertain["requestSha256"] = json!(devnet::sha256(&serde_json::to_vec(&request).unwrap()));
        uncertain["timeoutSecs"] = json!(OBSERVATION_TIMEOUT);
        uncertain["attempts"][0]["state"] = json!("running");
        uncertain["attempts"][0]["uncertain"] = json!(true);
        uncertain["attempts"][0]["output"] = Value::Null;
        foundation::write_json(&observation, &uncertain).unwrap();
        let before = std::fs::read(&observation).unwrap();
        validate_handoff(&fixture.deployment, directory, ObservationHistory::Preserve).unwrap();
        validate_handoff(&fixture.deployment, directory, ObservationHistory::Validate).unwrap();
        assert_eq!(std::fs::read(&observation).unwrap(), before);
        uncertain["requestSha256"] = json!("0".repeat(64));
        foundation::write_json(&observation, &uncertain).unwrap();
        assert!(
            validate_handoff(&fixture.deployment, directory, ObservationHistory::Validate).is_err()
        );
        foundation::write_private(&observation, &before).unwrap();

        // The transport contract must accept the same healthy path as the adapter.
        let id = Uuid::new_v4();
        fixture.deployment.stack_initialized = true;
        fixture.deployment.last_operation = Some(id);
        let mut files = BTreeMap::new();
        let request = fixture.deployment.cluster.as_ref().unwrap();
        for (name, artifact) in &request.artifacts {
            files.insert(format!("artifacts/{name}"), artifact.clone());
        }
        let mut required = vec![
            "lightwallet-install.sh".to_owned(),
            "lightwallet-install-command.json".into(),
            "lightwallet-capacity.json".into(),
            "lightwallet-capacity-command.json".into(),
            "node-1-start-producer-command.json".into(),
        ];
        for node in fixture.deployment.outputs.as_ref().unwrap().nodes.keys() {
            required.extend([
                format!("{node}-install.sh"),
                format!("{node}-install-command.json"),
            ]);
        }
        if request.client_access {
            required.extend([
                "client-rpc-install.sh".into(),
                "client-rpc-install-command.json".into(),
            ]);
        }
        for name in required {
            files.insert(
                name,
                Artifact {
                    sha256: "a".repeat(64),
                    bytes: 1,
                },
            );
        }
        let manifest = Manifest {
            api_version: crate::handoff::API_VERSION.into(),
            updates: Default::default(),
            binding: BindingExport {
                version: 1,
                network_id: fixture.deployment.spec.network_id,
                scope: fixture.deployment.spec.scope.clone(),
                label: "handoff".into(),
                reservation: Reservation::Unreserved,
            },
            operations: vec![OperationReceipt {
                version: 1,
                operation_id: id,
                network_id: fixture.deployment.spec.network_id,
                scope: fixture.deployment.spec.scope.clone(),
                kind: "devnet-up".into(),
                inputs: OperationInput {
                    config_sha256: request.config_sha256.clone(),
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                revision: 1,
                state_revision: 1,
                cancel_requested: false,
                phases: vec![PhaseRecord {
                    name: "readiness".into(),
                    status: PhaseStatus::Succeeded {
                        result: json!({"ready":true}),
                    },
                }],
            }],
            deployment: fixture.deployment.clone(),
            files,
        };
        manifest.validate().unwrap();
        journal["requestSha256"] = json!("f".repeat(64));
        foundation::write_json(
            &directory.join("lightwallet-install-command.json"),
            &journal,
        )
        .unwrap();
        assert!(
            validate_handoff(&fixture.deployment, directory, ObservationHistory::Validate).is_err()
        );
        assert!(
            validate_handoff(&fixture.deployment, directory, ObservationHistory::Preserve).is_err()
        );
    }
}

#[test]
fn stopped_service_repeats_completed_start_only_after_new_observation() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.ensure(&spec).unwrap();
    fixture.backend.aws.running.set(false);
    let index = fixture.backend.aws.events.borrow().len();
    fixture.ensure(&spec).unwrap();
    assert_eq!(fixture.backend.aws.sends("start"), 2);
    let events = fixture.backend.aws.events.borrow();
    let events = &events[index..];
    assert_eq!(events[0], "send:observe");
    let start = events
        .iter()
        .position(|event| event == "send:start")
        .unwrap();
    assert_eq!(
        events[..start]
            .iter()
            .filter(|event| event.as_str() == "send:observe")
            .count(),
        1
    );
    let journal: Value = foundation::read_json(
        &fixture
            .backend
            .deployment_directory
            .join("lightwallet-start-command.json"),
    )
    .unwrap();
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
}

#[test]
fn lost_start_response_is_recovered_without_duplicate_dispatch() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.backend.aws.lose_start.set(true);
    fixture.ensure(&spec).unwrap();
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    assert!(fixture
        .backend
        .aws
        .events
        .borrow()
        .iter()
        .any(|event| event == "recover:start"));
}

#[test]
fn in_flight_start_is_settled_before_health_observation() {
    for lost_reply in [true, false] {
        let mut fixture = Fixture::new();
        let spec = fixture.prepare();
        fixture.backend.aws.start_polls_remaining.set(1);
        fixture.backend.aws.lose_start.set(lost_reply);
        fixture.backend.aws.recovery_unavailable.set(lost_reply);
        fixture
            .backend
            .aws
            .start_status_unavailable
            .set(!lost_reply);
        assert!(fixture.ensure(&spec).is_err());
        assert!(fixture.backend.aws.start_lock_held.get());
        assert_eq!(fixture.backend.aws.sends("start"), 1);
        let path = fixture
            .backend
            .deployment_directory
            .join("lightwallet-start-command.json");
        let before: Value = foundation::read_json(&path).unwrap();
        assert_eq!(before["attempts"][0]["uncertain"], true);
        assert_eq!(before["attempts"][0]["commandId"].is_null(), lost_reply);

        fixture.backend.aws.recovery_unavailable.set(false);
        fixture.backend.aws.start_status_unavailable.set(false);
        let begin = fixture.backend.aws.events.borrow().len();
        fixture.ensure(&spec).unwrap_or_else(|error| {
            panic!("in-flight start recovery failed (lost_reply={lost_reply}): {error:#}")
        });
        assert_eq!(fixture.backend.aws.sends("start"), 1);
        assert!(!fixture.backend.aws.start_lock_held.get());
        assert!(fixture.backend.aws.blocked_observations.borrow().is_empty());
        let events = fixture.backend.aws.events.borrow();
        let resumed = &events[begin..];
        let poll = resumed
            .iter()
            .position(|event| event == "poll:start:in-progress")
            .unwrap();
        let completed = resumed
            .iter()
            .position(|event| event == "complete:start")
            .unwrap();
        let observation = resumed
            .iter()
            .position(|event| event == "send:observe")
            .unwrap();
        assert!(poll < completed && completed < observation, "{resumed:?}");
        if lost_reply {
            assert_eq!(resumed[0], "recover:start");
        }
        let after: Value = foundation::read_json(&path).unwrap();
        assert_eq!(after["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(after["attempts"][0]["id"], before["attempts"][0]["id"]);
        assert_eq!(after["attempts"][0]["state"], "succeeded");
        assert_eq!(after["attempts"][0]["uncertain"], false);
    }
}

#[test]
fn unresolved_start_receipt_is_not_abandoned_on_retry() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.backend.aws.lose_start.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.ensure(&spec).is_err());
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    fixture.backend.aws.running.set(false);
    fixture.backend.aws.recovery_unavailable.set(false);
    fixture.ensure(&spec).unwrap();
    // Recovery first resolves the prior success; a fresh stopped observation
    // permits exactly one explicit repeat, preserving both attempt records.
    assert_eq!(fixture.backend.aws.sends("start"), 2);
    let journal: Value = foundation::read_json(
        &fixture
            .backend
            .deployment_directory
            .join("lightwallet-start-command.json"),
    )
    .unwrap();
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
}

#[test]
fn wrong_service_or_readiness_refuses_success_before_restart() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.backend.aws.running.set(true);
    fixture.backend.aws.invalid.set(true);
    assert!(fixture.ensure(&spec).is_err());
    assert_eq!(fixture.backend.aws.sends("start"), 0);
    let mut report = fixture.backend.aws.report();
    fixture.backend.aws.invalid.set(false);
    report["serviceSha256"] = json!(
        service::render_service(&spec.host, &spec.service)
            .unwrap()
            .service_sha256
    );
    report["readiness"]["compactDataVerified"] = json!(false);
    assert!(service::validate_observation(&report, &spec).is_err());
}

#[test]
fn healthy_service_cannot_abandon_an_uncertain_start_command() {
    let mut fixture = Fixture::new();
    let spec = fixture.prepare();
    fixture.backend.aws.lose_start.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.ensure(&spec).is_err());
    assert!(fixture.backend.aws.running.get());
    assert_eq!(fixture.backend.aws.sends("start"), 1);

    // Current health is evidence about the service, not the completion of the
    // lost mutation. Keep settling that exact dispatch while it is uncertain.
    assert!(fixture.ensure(&spec).is_err());
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    let path = fixture
        .backend
        .deployment_directory
        .join("lightwallet-start-command.json");
    let uncertain: Value = foundation::read_json(&path).unwrap();
    assert_eq!(uncertain["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(uncertain["attempts"][0]["uncertain"], true);

    fixture.backend.aws.recovery_unavailable.set(false);
    let begin = fixture.backend.aws.events.borrow().len();
    fixture.ensure(&spec).unwrap();
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    let journal: Value = foundation::read_json(&path).unwrap();
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(journal["attempts"][0]["state"], "succeeded");
    assert_eq!(journal["attempts"][0]["uncertain"], false);
    let events = fixture.backend.aws.events.borrow();
    let recovery = events[begin..]
        .iter()
        .position(|event| event == "recover:start")
        .unwrap()
        + begin;
    assert!(events[recovery + 1..]
        .iter()
        .any(|event| event == "send:observe"));
}

#[test]
fn native_service_selection_keeps_capacity_start_and_fresh_observation_native() {
    let mut fixture = Fixture::new();
    let request = fixture.deployment.cluster.as_mut().unwrap();
    request.native_runtime_protocol = Some(crate::host::runtime::PROTOCOL.into());
    request.installer_fetch_protocol = Some(crate::host::installer_bootstrap::PROTOCOL.into());
    request.lightwallet.as_mut().unwrap().capacity_protocol =
        Some(crate::host::CAPACITY_PROTOCOL.into());
    let spec = fixture.prepare();
    fixture.backend.aws.lose_start.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.ensure(&spec).is_err());
    fixture.backend.aws.recovery_unavailable.set(false);
    assert_eq!(fixture.ensure(&spec).unwrap()["status"], "ready");
    assert_eq!(fixture.backend.aws.sends("start"), 1);
    for command in fixture.backend.aws.commands.borrow().iter() {
        let script = command["Parameters"]["commands"][0].as_str().unwrap();
        assert!(!script.contains("python"));
        assert!(
            script.contains("__host-capacity")
                || script
                    .contains("__lightwallet-runtime --protocol zdn-lightwallet-runtime/v1alpha1")
        );
    }
}
