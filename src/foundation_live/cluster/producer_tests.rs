//! Startup-order and recovery contracts exercise the actual cluster adapter,
//! with a data-only SSM service. No AWS process, node, or Docker is invoked.
use super::*;
use crate::{
    access::DeploymentAccess,
    aws::{AwsApiError, TeamAws, TeamState},
    cluster_infra::ClusterNodeOutputs,
    config::Size,
    devnet::{Artifact, ClusterRequest},
    host::HostInstallSpec,
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
    pulumi::{CommandSpec, ProcessOutput, Progress},
    state::Scope,
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    fs,
    rc::Rc,
};
use tempfile::TempDir;

#[derive(Default)]
struct FakeAws {
    hosts: BTreeMap<String, (HostInstallSpec, String)>,
    update_ids: BTreeMap<String, Uuid>,
    commands: RefCell<Vec<Value>>,
    command_reports: RefCell<BTreeMap<String, Value>>,
    events: RefCell<Vec<String>>,
    invalid_node: RefCell<Option<String>>,
    producer_running: Cell<bool>,
    lose_activation_response: Cell<bool>,
    recovery_unavailable: Cell<bool>,
    activation_results: RefCell<VecDeque<(Value, u64)>>,
    activation_status_error: Cell<Option<&'static str>>,
    elapsed: Rc<Cell<Duration>>,
    cancel_on_activation_failure: RefCell<Option<Arc<AtomicBool>>>,
    stop_after_activation_success: Cell<bool>,
    post_activation_observation_pending: Cell<bool>,
    initial_observation_delay: Cell<Duration>,
    ssm_offline: Cell<bool>,
    ssm_online_after: BTreeMap<String, Duration>,
    uploaded_installers: RefCell<BTreeMap<String, Value>>,
    inventory_terminal: Cell<Option<bool>>,
    inventory_calls: RefCell<Vec<(String, Value)>>,
}
impl FakeAws {
    fn report(&self, instance: &str) -> Value {
        let (host, install) = &self.hosts[instance];
        let running = host.role == "producer" && self.producer_running.get();
        let producer = if running {
            json!({
                "apiVersion":"zdn-block-producer/v1alpha1",
                "identity":{"deploymentId":host.deployment_id,"nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint},
                "ownerPid":1234,"ownerSession":"d1b8f1a7-b228-421f-984b-82eebf73b67e",
                "phase":"waiting","intervalSecs":25,"controllerLocked":true,
                "lastConfirmedTip":{"height":0,"hash":"ab".repeat(32)},"pending":null,"confirmedBlocks":0,
                "paymentQualification":"pending","launchReady":false
            })
        } else {
            Value::Null
        };
        let mut report = json!({
            "apiVersion":"zdn-host-observation/v1alpha1","deploymentId":host.deployment_id,
            "nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint,
            "configSha256":host.config_sha256,"image":host.image,"installSha256":install,
            "status":"ready","launchReady":false,"paymentQualification":"pending",
            "scheduledProducer":running,"producer":producer,
            "readiness":{"apiVersion":"zdn-chain-readiness/v1alpha1","consensusFingerprint":host.consensus_fingerprint,
                "role":host.role,"effectiveRulesVerified":true,"historyPresent":true,"miningReady":host.role == "producer",
                "tip":{"height":0,"hash":"ab".repeat(32)},"launchReady":false,"paymentQualification":"pending"},
            "effectiveLimits":{"effectiveMemoryBytes":host.memory_bytes+host.host_reserve_bytes,"visibleCpuMillis":host.cpu_millis+250,
                "nodeMemoryBytes":host.memory_bytes,"nodeCpuMillis":host.cpu_millis,
                "hostReserveBytes":host.host_reserve_bytes,"hostReserveCpuMillis":250}
        });
        if self.invalid_node.borrow().as_ref() == Some(&host.node_id) {
            report["readiness"]["historyPresent"] = json!(false);
        }
        if let Some(update_id) = self.update_ids.get(&host.node_id) {
            report["updateId"] = json!(update_id);
        }
        report
    }
    fn activation_sends(&self) -> usize {
        self.events
            .borrow()
            .iter()
            .filter(|event| event.as_str() == "send:node-1:start-producer")
            .count()
    }
}
impl AwsApi for FakeAws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        extra: &[String],
    ) -> Result<Value> {
        if let Some(terminal) = self.inventory_terminal.get() {
            self.inventory_calls
                .borrow_mut()
                .push((operation.into(), input.clone()));
            if service == "iam" {
                assert!(matches!(operation, "get-role" | "get-instance-profile"));
                return Err(AwsApiError {
                    code: "NoSuchEntity".into(),
                }
                .into());
            }
            assert_eq!(service, "ec2");
            let (list, absent) = match operation {
                "describe-instances" => ("Reservations", "InvalidInstanceID.NotFound"),
                "describe-volumes" => ("Volumes", "InvalidVolume.NotFound"),
                "describe-vpcs" => ("Vpcs", "InvalidVpcID.NotFound"),
                "describe-addresses" => ("Addresses", "InvalidAllocationID.NotFound"),
                "describe-subnets" => ("Subnets", "InvalidSubnetID.NotFound"),
                "describe-security-groups" => ("SecurityGroups", "InvalidGroup.NotFound"),
                "describe-internet-gateways" => ("InternetGateways", "unused"),
                "describe-route-tables" => ("RouteTables", "unused"),
                "describe-nat-gateways" => ("NatGateways", "NatGatewayNotFound"),
                other => panic!("unexpected inventory operation {other}"),
            };
            if input.get("Filters").is_some() || input.get("Filter").is_some() {
                if operation == "describe-instances" && !terminal {
                    // Contradictory tagged evidence must survive exact NotFound.
                    return Ok(json!({"Reservations":[{"Instances":[{
                        "InstanceId":"i-00000000000000003","State":{"Name":"running"}
                    }]}]}));
                }
                return Ok(json!({list:[]}));
            }
            if operation == "describe-instances" {
                let id = &input["InstanceIds"][0];
                if !terminal && id == "i-00000000000000003" {
                    return Err(AwsApiError {
                        code: absent.into(),
                    }
                    .into());
                }
                return Ok(json!({"Reservations":[{"Instances":[{
                    "InstanceId":id,"State":{"Name":if terminal {"terminated"} else {"stopped"}}
                }]}]}));
            }
            if operation == "describe-volumes" {
                return Ok(json!({"Volumes":[{"VolumeId":input["VolumeIds"][0],
                    "State":if terminal {"deleted"} else {"error"}}]}));
            }
            return Err(AwsApiError {
                code: absent.into(),
            }
            .into());
        }
        if service == "s3api" {
            let key = input["Key"].as_str().unwrap().to_owned();
            return match operation {
                "head-object" => self
                    .uploaded_installers
                    .borrow()
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| AwsApiError { code: "404".into() }.into()),
                "put-object" => {
                    assert_eq!(extra[0], "--body");
                    let bytes = fs::read(&extra[1]).unwrap();
                    self.uploaded_installers.borrow_mut().insert(
                        key,
                        json!({"ContentLength":bytes.len(),
                            "ChecksumSHA256":input["ChecksumSHA256"],
                            "ServerSideEncryption":input["ServerSideEncryption"],
                            "SSEKMSKeyId":input["SSEKMSKeyId"]}),
                    );
                    Ok(json!({}))
                }
                other => panic!("unexpected S3 operation {other}"),
            };
        }
        assert_eq!(service, "ssm", "unexpected service: {service}");
        match operation {
            "describe-instance-information" => {
                if self.ssm_offline.get() {
                    return Ok(json!({"InstanceInformationList":[]}));
                }
                let instances: Vec<_> = input["Filters"][0]["Values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|id| {
                        self.elapsed.get()
                            >= self
                                .ssm_online_after
                                .get(id.as_str().unwrap())
                                .copied()
                                .unwrap_or_default()
                    })
                    .map(|id| {
                        assert!(self.hosts.contains_key(id.as_str().unwrap()));
                        json!({"InstanceId":id,"PingStatus":"Online"})
                    })
                    .collect();
                Ok(json!({"InstanceInformationList":instances}))
            }
            "send-command" => {
                let instance = input["InstanceIds"][0].as_str().unwrap().to_owned();
                let node = &self.hosts[&instance].0.node_id;
                let script = input["Parameters"]["commands"][0].as_str().unwrap();
                let action = if script.ends_with(" start-producer") {
                    "start-producer"
                } else if script.ends_with(" observe") {
                    "observe"
                } else {
                    assert!(script.contains("ZDN_INSTALLER_BOOTSTRAP"));
                    "install"
                };
                self.events
                    .borrow_mut()
                    .push(format!("send:{node}:{action}"));
                input["CommandId"] = json!(Uuid::new_v4());
                self.commands.borrow_mut().push(input.clone());
                if action == "start-producer" {
                    self.producer_running.set(true);
                }
                self.command_reports.borrow_mut().insert(
                    input["CommandId"].as_str().unwrap().into(),
                    self.report(&instance),
                );
                if action == "start-producer" && self.lose_activation_response.replace(false) {
                    return Err(AwsApiError {
                        code: "RequestTimeout".into(),
                    }
                    .into());
                }
                Ok(json!({"Command":input}))
            }
            "list-commands" => {
                self.events
                    .borrow_mut()
                    .push("recover:start-producer".into());
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
                let instance = command["InstanceIds"][0].as_str().unwrap();
                let node = &self.hosts[instance].0.node_id;
                let action = if command["Parameters"]["commands"][0]
                    .as_str()
                    .unwrap()
                    .ends_with(" start-producer")
                {
                    "start-producer"
                } else {
                    "observe"
                };
                let mut response = json!({"CommandId":command["CommandId"],"InstanceId":instance,
                    "DocumentName":command["DocumentName"],"DocumentVersion":command["DocumentVersion"],"Comment":command["Comment"],
                    "Status":"Success","ResponseCode":0,"StandardOutputContent":serde_json::to_string(&self.command_reports.borrow()[input["CommandId"].as_str().unwrap()]).unwrap(),"StandardErrorContent":""});
                if action == "start-producer" {
                    if let Some(code) = self.activation_status_error.take() {
                        return Err(AwsApiError { code: code.into() }.into());
                    }
                    if let Some((overrides, seconds)) =
                        self.activation_results.borrow_mut().pop_front()
                    {
                        self.elapsed
                            .set(self.elapsed.get() + Duration::from_secs(seconds));
                        for (key, value) in overrides.as_object().unwrap() {
                            response[key] = value.clone();
                        }
                        if response["Status"] == "Failed" {
                            if let Some(cancel) =
                                self.cancel_on_activation_failure.borrow().as_ref()
                            {
                                cancel.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    // Model a service exiting after SSM captured its healthy
                    // result but before the caller's fresh observation.
                    if response["Status"] == "Success"
                        && self.stop_after_activation_success.replace(false)
                    {
                        self.producer_running.set(false);
                    }
                } else if (self.post_activation_observation_pending.get()
                    && self.activation_sends() > 0)
                    || (self.activation_sends() == 0
                        && self.elapsed.get() < self.initial_observation_delay.get())
                {
                    response["Status"] = json!("InProgress");
                }
                let event = if response["Status"] == "InProgress" {
                    "pending"
                } else {
                    "complete"
                };
                self.events
                    .borrow_mut()
                    .push(format!("{event}:{node}:{action}"));
                Ok(response)
            }
            "cancel-command" => {
                self.events
                    .borrow_mut()
                    .push("cancel:start-producer".into());
                Ok(json!({}))
            }
            other => panic!("unexpected AWS operation {other}"),
        }
    }
}
struct NoPulumi;
impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("producer startup must not run Pulumi")
    }
}
struct Clock(Rc<Cell<Duration>>);
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
        let root = tempfile::tempdir().unwrap();
        let scope = Scope {
            team_id: "private-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let mut team = TeamDefinition {
            api_version: crate::access::TEAM_ROLE_API_VERSION.into(),
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
        team.deployment = Some(DeploymentAccess::managed(&team));
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
        let manifest: crate::chain::manifest::ConsensusManifest = serde_json::from_str(
            include_str!("../../../tests/fixtures/chain-manifest/valid.json"),
        )
        .unwrap();
        let request = ClusterRequest {
            build: None,
            artifact_set: None,
            installer_fetch_protocol: Some(crate::host::installer_bootstrap::PROTOCOL.into()),
            native_runtime_protocol: Some(crate::host::runtime::PROTOCOL.into()),
            client_access: false,
            lightwallet: None,
            block_interval_seconds: Some(25),
            api_version: devnet::API_VERSION.into(),
            config_sha256: "a".repeat(64),
            manifest: manifest.normalized().unwrap(),
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
            artifacts: [
                "manifest.json",
                "chain.tar",
                "image.json",
                "image-manifest.json",
                "image-config.json",
                "zdn",
            ]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    Artifact {
                        sha256: "e".repeat(64),
                        bytes: 123,
                    },
                )
            })
            .collect(),
        };
        let nodes: BTreeMap<_, _> = request
            .topology()
            .unwrap()
            .nodes()
            .into_iter()
            .enumerate()
            .map(|(index, node)| {
                (
                    node.node_id.clone(),
                    ClusterNodeOutputs {
                        node_id: node.node_id,
                        instance_id: format!("i-{:017x}", index + 1),
                        volume_id: format!("vol-{:017x}", index + 1),
                        private_ip: node.private_ip,
                    },
                )
            })
            .collect();
        let first = &nodes["node-1"];
        deployment.outputs = Some(FoundationOutputs {
            lightwallet: None,
            nodes: nodes.clone(),
            schema_version: crate::infra::FOUNDATION_SCHEMA_VERSION,
            scope: deployment.spec.scope.clone(),
            network_id: deployment.spec.network_id,
            availability_zone: deployment.spec.availability_zone.clone(),
            vpc_id: "vpc-0123456789abcdef0".into(),
            private_subnet_id: "subnet-0123456789abcdef0".into(),
            instance_id: first.instance_id.clone(),
            private_ip: first.private_ip,
            chain_volume_id: first.volume_id.clone(),
            retain_chain_disk: true,
            security_group_id: "sg-0123456789abcdef0".into(),
            nat_gateway_id: "nat-0123456789abcdef0".into(),
            eip_allocation_id: "eipalloc-0123456789abcdef0".into(),
        });
        let hosts = nodes
            .values()
            .map(|node| {
                let host = request.host_spec(&deployment.spec, &team, node).unwrap();
                let hash = host.install_sha256().unwrap();
                (node.instance_id.clone(), (host, hash))
            })
            .collect();
        deployment.cluster = Some(request);
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
        let elapsed = Rc::default();
        let backend = LiveBackend {
            command_progress: None,
            aws: FakeAws {
                hosts,
                elapsed: Rc::clone(&elapsed),
                ..Default::default()
            },
            client: PulumiClient::new(workspace, NoPulumi).unwrap(),
            selection,
            runtime: Clock(elapsed),
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
    fn complete(&mut self) -> Result<Value> {
        self.backend.complete_cluster_install(&self.deployment)
    }
    fn activation_journal(&self) -> Value {
        serde_json::from_slice(
            &fs::read(
                self.backend
                    .deployment_directory
                    .join("node-1-start-producer-command.json"),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn inventory_scans_each_family_once_and_reconciles_every_saved_cluster_id() {
    for terminal in [true, false] {
        let fixture = Fixture::new();
        fixture.backend.aws.inventory_terminal.set(Some(terminal));
        let report = inventory(&fixture.backend.aws, &fixture.deployment).unwrap();
        let mut expected = Vec::new();
        let calls = fixture.backend.aws.inventory_calls.borrow();
        let tagged: BTreeMap<_, _> = calls
            .iter()
            .filter(|(_, input)| input.get("Filters").is_some() || input.get("Filter").is_some())
            .fold(BTreeMap::new(), |mut counts, (operation, _)| {
                *counts.entry(operation.as_str()).or_insert(0) += 1;
                counts
            });
        assert_eq!(tagged.len(), 9);
        assert!(tagged.values().all(|count| *count == 1));
        for node in fixture.deployment.outputs.as_ref().unwrap().nodes.values() {
            for (operation, key, id) in [
                ("describe-instances", "InstanceIds", &node.instance_id),
                ("describe-volumes", "VolumeIds", &node.volume_id),
            ] {
                assert_eq!(
                    calls
                        .iter()
                        .filter(|(op, input)| op == operation && input[key] == json!([id]))
                        .count(),
                    1,
                    "missing or repeated exact lookup for {id}"
                );
            }
            if !terminal {
                expected.push(format!("instance:{}", node.instance_id));
                expected.push(format!("volume:{}", node.volume_id));
            }
        }
        expected.sort();
        assert_eq!(report.remaining_resources, expected);
        assert!(report.retained_volumes.is_empty());
    }
}

#[test]
fn install_prepares_all_installers_while_ssm_is_offline_but_never_dispatches() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.ssm_offline.set(true);
    let error = fixture
        .backend
        .install_cluster(&fixture.deployment)
        .unwrap_err();
    assert!(error.to_string().contains("SSM node availability deadline"));
    assert_eq!(fixture.backend.aws.uploaded_installers.borrow().len(), 3);
    for node in ["node-1", "node-2", "node-3"] {
        assert!(fixture
            .backend
            .deployment_directory
            .join(format!("{node}-install.sh"))
            .is_file());
    }
    assert!(fixture.backend.aws.commands.borrow().is_empty());
    assert_eq!(fixture.backend.aws.activation_sends(), 0);
    assert_eq!(
        fixture.backend.runtime.monotonic(),
        Duration::from_secs(900)
    );
}

#[test]
fn install_starts_online_nodes_before_the_slow_first_host_and_keeps_the_producer_gate() {
    for invalid in [false, true] {
        let mut fixture = Fixture::new();
        let slow = fixture.deployment.outputs.as_ref().unwrap().nodes["node-1"]
            .instance_id
            .clone();
        fixture
            .backend
            .aws
            .ssm_online_after
            .insert(slow, Duration::from_secs(8));
        if invalid {
            *fixture.backend.aws.invalid_node.borrow_mut() = Some("node-1".into());
        }
        let result = fixture.backend.install_cluster(&fixture.deployment);
        assert_eq!(result.is_err(), invalid);
        let events = fixture.backend.aws.events.borrow();
        let position = |event: &str| events.iter().position(|e| e == event).unwrap();
        assert!(position("send:node-2:install") < position("send:node-1:install"));
        assert!(position("send:node-3:install") < position("send:node-1:install"));
        assert_eq!(
            fixture.backend.aws.activation_sends(),
            usize::from(!invalid)
        );
        if !invalid {
            for node in ["node-1", "node-2", "node-3"] {
                assert!(
                    position(&format!("complete:{node}:observe"))
                        < position("send:node-1:start-producer")
                );
            }
        }
        assert_eq!(fixture.backend.runtime.monotonic(), Duration::from_secs(8));
    }
}

#[test]
fn a_confirmed_activation_failure_recovers_once_and_preserves_partial_effects_and_history() {
    let mut fixture = Fixture::new();
    let observations = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&observations);
    fixture.backend.observe_commands(move |observation| {
        observed
            .borrow_mut()
            .push(serde_json::to_value(observation)?);
        Ok(())
    });
    fixture
        .backend
        .aws
        .activation_results
        .borrow_mut()
        .push_back((json!({"Status":"Failed","ResponseCode":1}), 7));
    fixture.complete().unwrap();
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    // The first dispatch started the service even though SSM reported failure.
    // Repeating activation must remain safe when effects have already occurred.
    assert!(fixture.backend.aws.producer_running.get());
    let journal = fixture.activation_journal();
    let attempts = journal["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["state"], "failed");
    assert_eq!(attempts[0]["failure"], "failed");
    assert_eq!(attempts[0]["uncertain"], false);
    assert_eq!(attempts[1]["state"], "succeeded");
    for (index, attempt) in attempts.iter().enumerate() {
        let observations = observations.borrow();
        let reported: Vec<_> = observations
            .iter()
            .filter(|o| o["attemptId"] == attempt["id"])
            .collect();
        assert_eq!(reported.first().unwrap()["state"], "prepared");
        assert_eq!(reported.last().unwrap()["state"], attempt["state"]);
        assert!(reported.iter().all(|o| o["attemptNumber"] == index + 1));
    }
    assert_ne!(attempts[0]["commandId"], attempts[1]["commandId"]);
    assert_ne!(attempts[0]["comment"], attempts[1]["comment"]);
    let commands = fixture.backend.aws.commands.borrow();
    let activations: Vec<_> = commands
        .iter()
        .filter(|c| {
            c["Parameters"]["commands"][0]
                .as_str()
                .unwrap()
                .ends_with(" start-producer")
        })
        .collect();
    for key in [
        "InstanceIds",
        "DocumentName",
        "DocumentVersion",
        "Parameters",
        "TimeoutSeconds",
    ] {
        assert_eq!(activations[0][key], activations[1][key]);
    }
}

#[test]
fn activation_reporting_failure_never_authorizes_same_invocation_recovery() {
    for typed_error in [false, true] {
        let mut fixture = Fixture::new();
        fixture
            .backend
            .aws
            .activation_results
            .borrow_mut()
            .push_back((json!({"Status": "Failed"}), 0));
        let path = fixture
            .backend
            .deployment_directory
            .join("node-1-start-producer-command.json");
        fixture.backend.observe_commands(move |observation| {
            if observation.state == "failed" {
                let saved: Value = serde_json::from_slice(&fs::read(&path)?)?;
                assert_eq!(
                    saved["attempts"][0]["id"],
                    observation.attempt_id.to_string()
                );
                assert_eq!(saved["attempts"][0]["state"], "failed");
                if typed_error {
                    return Err(crate::ssm::CommandError::RemoteFailed.into());
                }
                bail!("reporting interrupted");
            }
            Ok(())
        });
        assert!(fixture.complete().is_err());
        assert_eq!(fixture.backend.aws.activation_sends(), 1);
        assert_eq!(
            fixture.activation_journal()["attempts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        fixture.backend.observe_commands(|_| Ok(()));
        fixture.complete().unwrap();
        assert_eq!(fixture.backend.aws.activation_sends(), 2);
        assert_eq!(
            fixture.activation_journal()["attempts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn activation_recovery_stops_after_one_fresh_attempt() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.activation_results.borrow_mut().extend([
        (json!({"Status":"Failed"}), 0),
        (json!({"Status":"Failed"}), 0),
    ]);
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    let journal = fixture.activation_journal();
    let attempts = journal["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(attempts
        .iter()
        .all(|a| a["failure"] == "failed" && a["uncertain"] == false));
}

#[test]
fn activation_status_errors_never_authorize_redispatch() {
    for code in ["AccessDeniedException", "ThrottlingException"] {
        let mut fixture = Fixture::new();
        fixture.backend.aws.activation_status_error.set(Some(code));
        let result = fixture.complete();
        assert_eq!(result.is_ok(), code == "ThrottlingException");
        assert_eq!(fixture.backend.aws.activation_sends(), 1);
        let journal = fixture.activation_journal();
        assert_eq!(journal["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(
            journal["attempts"][0]["uncertain"],
            code == "AccessDeniedException"
        );
    }
}

#[test]
fn recovered_activation_failure_is_settled_before_a_fresh_attempt() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.lose_activation_response.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.complete().is_err());
    let before = fixture.activation_journal();
    fixture.backend.aws.recovery_unavailable.set(false);
    fixture
        .backend
        .aws
        .activation_results
        .borrow_mut()
        .push_back((json!({"Status":"Failed"}), 0));
    fixture.complete().unwrap();
    let after = fixture.activation_journal();
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    assert_eq!(after["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(after["attempts"][0]["id"], before["attempts"][0]["id"]);
    assert_eq!(after["attempts"][0]["failure"], "failed");
    assert_eq!(after["attempts"][0]["uncertain"], false);
    assert_eq!(after["attempts"][1]["state"], "succeeded");
}

#[test]
fn only_confirmed_failed_status_authorizes_activation_recovery() {
    for response in [
        json!({"Status":"Cancelled"}),
        json!({"Status":"TimedOut"}),
        json!({"ResponseCode":1}),
        json!({"StandardOutputContent":"not JSON"}),
        json!({"InstanceId":"i-fffffffffffffffff", "Status":"Failed"}),
    ] {
        let mut fixture = Fixture::new();
        fixture
            .backend
            .aws
            .activation_results
            .borrow_mut()
            .push_back((response.clone(), 0));
        assert!(fixture.complete().is_err(), "{response}");
        assert_eq!(fixture.backend.aws.activation_sends(), 1, "{response}");
        assert_eq!(
            fixture.activation_journal()["attempts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn activation_recovery_keeps_the_original_deadline_and_cancels_unsettled_work() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.activation_results.borrow_mut().extend([
        (json!({"Status":"Failed"}), 718),
        (json!({"Status":"InProgress"}), 0),
    ]);
    assert!(fixture
        .complete()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    assert_eq!(
        fixture.backend.runtime.monotonic(),
        Duration::from_secs(720)
    );
    let journal = fixture.activation_journal();
    assert_eq!(journal["attempts"][0]["failure"], "failed");
    assert_eq!(journal["attempts"][1]["uncertain"], true);
    assert_eq!(journal["attempts"][1]["cancellationRequested"], true);
    assert!(fixture
        .backend
        .aws
        .events
        .borrow()
        .iter()
        .any(|e| e == "cancel:start-producer"));
}

#[test]
fn cancellation_or_deadline_at_terminal_observation_never_restarts_activation() {
    for cancel in [false, true] {
        let mut fixture = Fixture::new();
        if cancel {
            *fixture
                .backend
                .aws
                .cancel_on_activation_failure
                .borrow_mut() = Some(Arc::clone(&fixture.backend.cancel));
        }
        fixture
            .backend
            .aws
            .activation_results
            .borrow_mut()
            .push_back((json!({"Status":"Failed"}), if cancel { 0 } else { 720 }));
        assert!(fixture.complete().is_err());
        assert_eq!(fixture.backend.aws.activation_sends(), 1);
        assert_eq!(
            fixture.activation_journal()["attempts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn activation_and_post_success_restart_share_one_repeat_allowance() {
    for seconds in [0, 350] {
        let mut fixture = Fixture::new();
        fixture.backend.aws.stop_after_activation_success.set(true);
        fixture.backend.aws.activation_results.borrow_mut().extend([
            (json!({"Status":"Failed"}), seconds),
            (json!({"Status":"Success"}), seconds),
            (json!({"Status":"Failed"}), seconds),
            (json!({"Status":"Success"}), seconds),
        ]);
        assert!(fixture.complete().is_err());
        assert_eq!(fixture.backend.aws.activation_sends(), 2);
        assert_eq!(
            fixture.backend.runtime.monotonic(),
            Duration::from_secs(2 * seconds)
        );
        let journal = fixture.activation_journal();
        assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
        assert_eq!(journal["attempts"][0]["failure"], "failed");
        assert_eq!(journal["attempts"][1]["state"], "succeeded");
        assert!(!fixture.backend.aws.producer_running.get());
    }
}

#[test]
fn post_success_restart_consumes_the_repeat_allowance_before_its_failure() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.stop_after_activation_success.set(true);
    fixture.backend.aws.activation_results.borrow_mut().extend([
        (json!({"Status":"Success"}), 0),
        (json!({"Status":"Failed"}), 0),
    ]);
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    let journal = fixture.activation_journal();
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(journal["attempts"][0]["state"], "succeeded");
    assert_eq!(journal["attempts"][1]["failure"], "failed");
}

#[test]
fn post_success_restart_keeps_the_original_activation_deadline() {
    for settles in [false, true] {
        let mut fixture = Fixture::new();
        fixture.backend.aws.stop_after_activation_success.set(true);
        fixture.backend.aws.activation_results.borrow_mut().extend([
            (json!({"Status":"Success"}), 718),
            if settles {
                (json!({"Status":"Success"}), 1)
            } else {
                (json!({"Status":"InProgress"}), 0)
            },
        ]);
        let result = fixture.complete();
        if settles {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("deadline"));
        }
        assert_eq!(fixture.backend.aws.activation_sends(), 2);
        assert_eq!(
            fixture.backend.runtime.monotonic(),
            Duration::from_secs(if settles { 719 } else { 720 })
        );
        let journal = fixture.activation_journal();
        assert_eq!(journal["attempts"][0]["state"], "succeeded");
        assert_eq!(journal["attempts"][1]["uncertain"], !settles);
        assert_eq!(journal["attempts"][1]["cancellationRequested"], !settles);
    }
}

#[test]
fn post_activation_observation_cannot_extend_the_activation_deadline() {
    let mut fixture = Fixture::new();
    fixture
        .backend
        .aws
        .activation_results
        .borrow_mut()
        .push_back((json!({"Status":"Success"}), 718));
    fixture
        .backend
        .aws
        .post_activation_observation_pending
        .set(true);
    assert!(fixture
        .complete()
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(
        fixture.backend.runtime.monotonic(),
        Duration::from_secs(720)
    );
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    let journal = fixture.activation_journal();
    assert_eq!(journal["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(journal["attempts"][0]["state"], "succeeded");
}

#[test]
fn every_node_has_a_fresh_successful_observation_before_the_single_activation() {
    let mut fixture = Fixture::new();
    fixture
        .backend
        .aws
        .initial_observation_delay
        .set(Duration::from_secs(2));
    let report = fixture.complete().unwrap();
    assert_eq!(report["producerActivationRequested"], true);
    assert_eq!(report["launchReady"], false);
    assert_eq!(
        *fixture.backend.aws.events.borrow(),
        [
            "send:node-1:observe",
            "pending:node-1:observe",
            "send:node-2:observe",
            "pending:node-2:observe",
            "send:node-3:observe",
            "pending:node-3:observe",
            "complete:node-1:observe",
            "complete:node-2:observe",
            "complete:node-3:observe",
            "send:node-1:start-producer",
            "complete:node-1:start-producer",
            "send:node-1:observe",
            "complete:node-1:observe"
        ]
    );
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
}

#[test]
fn an_unready_follower_prevents_producer_activation() {
    let mut fixture = Fixture::new();
    *fixture.backend.aws.invalid_node.borrow_mut() = Some("node-2".into());
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 0);
    assert!(!fixture.backend.aws.producer_running.get());
}

#[test]
fn cached_activation_never_bypasses_fresh_node_readiness() {
    let mut fixture = Fixture::new();
    fixture.complete().unwrap();
    fixture.complete().unwrap();
    assert_eq!(
        fixture.backend.ready(&fixture.deployment).unwrap()["scheduledProducer"],
        true
    );
    *fixture.backend.aws.invalid_node.borrow_mut() = Some("node-3".into());
    assert!(fixture.complete().is_err());
    fixture.backend.aws.invalid_node.borrow_mut().take();
    fixture.backend.aws.producer_running.set(false);
    assert!(
        fixture
            .backend
            .observe_cluster(&fixture.deployment)
            .is_err(),
        "cached activation cannot prove current production"
    );
}

#[test]
fn an_unknown_activation_dispatch_recovers_its_saved_command_without_redispatch() {
    let mut fixture = Fixture::new();
    fixture.backend.aws.lose_activation_response.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    let path = fixture
        .backend
        .deployment_directory
        .join("node-1-start-producer-command.json");
    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(before["attempts"][0]["uncertain"], true);
    assert_eq!(before["attempts"][0]["commandId"], Value::Null);
    fixture.backend.aws.recovery_unavailable.set(false);
    fixture.complete().unwrap();
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(before["attempts"][0]["id"], after["attempts"][0]["id"]);
    assert_eq!(after["attempts"][0]["state"], "succeeded");
    assert_eq!(after["attempts"][0]["uncertain"], false);
}

#[test]
fn saved_runtime_recovers_a_stopped_producer_and_preserves_mixed_images() {
    for changed_image in [false, true] {
        let mut fixture = Fixture::new();
        fixture.complete().unwrap();
        let before = fixture.activation_journal();
        let request = fixture.deployment.cluster.as_ref().unwrap();
        let mut runtime = crate::update::RuntimeState::default();
        for node in ["node-1", "node-2"] {
            let update_id = Uuid::new_v4();
            let mut image = request.image.clone();
            if changed_image {
                image.image = image.image.replace(&"b".repeat(64), &"f".repeat(64));
            }
            runtime.nodes.insert(
                node.into(),
                crate::update::ImageRevision {
                    update_id,
                    image: image.clone(),
                    build: None,
                    artifacts: request.artifacts.clone(),
                },
            );
            fixture
                .backend
                .aws
                .update_ids
                .insert(node.into(), update_id);
            for (host, _) in fixture.backend.aws.hosts.values_mut() {
                if host.node_id == node {
                    host.image = image.image.clone();
                }
            }
        }
        fixture.deployment.runtime = Some(runtime);
        let assignments = serde_json::to_value(&fixture.deployment.runtime).unwrap();
        fixture.backend.aws.producer_running.set(false);
        fixture.backend.deploy_runtime(&fixture.deployment).unwrap();
        assert_eq!(
            fixture.backend.ready(&fixture.deployment).unwrap()["scheduledProducer"],
            true
        );
        assert_eq!(
            fixture.activation_journal()["attempts"][0],
            before["attempts"][0]
        );
        assert_eq!(
            serde_json::to_value(&fixture.deployment.runtime).unwrap(),
            assignments
        );
    }
}

#[test]
fn a_stopped_producer_gets_one_new_attempt_after_cached_success() {
    let mut fixture = Fixture::new();
    fixture.complete().unwrap();
    let path = fixture
        .backend
        .deployment_directory
        .join("node-1-start-producer-command.json");
    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    fixture.backend.aws.producer_running.set(false);
    fixture.backend.aws.events.borrow_mut().clear();
    fixture.complete().unwrap();
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    assert!(fixture.backend.aws.producer_running.get());
    let events = fixture.backend.aws.events.borrow();
    assert_eq!(
        events[0..8],
        [
            "send:node-1:observe",
            "complete:node-1:observe",
            "send:node-2:observe",
            "complete:node-2:observe",
            "send:node-3:observe",
            "complete:node-3:observe",
            "send:node-1:observe",
            "complete:node-1:observe",
        ]
    );
    assert_eq!(events[8], "send:node-1:start-producer");
    drop(events);
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(after["attempts"][0], before["attempts"][0]);
    assert_eq!(after["attempts"][1]["state"], "succeeded");
    assert_ne!(after["attempts"][0]["id"], after["attempts"][1]["id"]);
    assert_eq!(
        fixture
            .backend
            .observe_cluster(&fixture.deployment)
            .unwrap()["scheduledProducer"],
        true
    );
    fixture.complete().unwrap();
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
}

#[test]
fn an_uncertain_restart_is_recovered_before_another_start_even_when_stopped() {
    let mut fixture = Fixture::new();
    fixture.complete().unwrap();
    fixture.backend.aws.producer_running.set(false);
    fixture.backend.aws.lose_activation_response.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    // The restart succeeded remotely, then its service exited while its SSM
    // result was still unknown locally. Fresh inactivity cannot authorize a send.
    fixture.backend.aws.producer_running.set(false);
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 2);
    fixture.backend.aws.recovery_unavailable.set(false);
    fixture.backend.aws.events.borrow_mut().clear();
    fixture.complete().unwrap();
    assert!(fixture.backend.aws.producer_running.get());
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    let events = fixture.backend.aws.events.borrow();
    let recovered = events
        .iter()
        .position(|e| e == "complete:node-1:start-producer")
        .unwrap();
    let fresh = events
        .iter()
        .rposition(|e| e == "complete:node-1:observe")
        .unwrap();
    let restarted = events
        .iter()
        .position(|e| e == "send:node-1:start-producer")
        .unwrap();
    assert!(recovered < fresh && fresh < restarted);
    let path = fixture
        .backend
        .deployment_directory
        .join("node-1-start-producer-command.json");
    let saved: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(saved["attempts"].as_array().unwrap().len(), 3);
    assert!(saved["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["state"] == "succeeded"));
}

#[test]
fn an_unready_follower_prevents_restarting_a_previously_activated_producer() {
    let mut fixture = Fixture::new();
    fixture.complete().unwrap();
    fixture.backend.aws.producer_running.set(false);
    *fixture.backend.aws.invalid_node.borrow_mut() = Some("node-3".into());
    assert!(fixture.complete().is_err());
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    assert!(!fixture.backend.aws.producer_running.get());
}

/// Shared data-only deployment for adjacent lifecycle contract fixtures.
pub(in crate::foundation_live) fn fixture_deployment() -> Deployment {
    Fixture::new().deployment
}

#[test]
fn native_activation_recovery_and_fresh_observation_never_dispatch_python() {
    let mut fixture = Fixture::new();
    fixture
        .deployment
        .cluster
        .as_mut()
        .unwrap()
        .native_runtime_protocol = Some(crate::host::runtime::PROTOCOL.into());
    fixture
        .deployment
        .cluster
        .as_mut()
        .unwrap()
        .installer_fetch_protocol = Some(crate::host::installer_bootstrap::PROTOCOL.into());
    fixture.backend.aws.lose_activation_response.set(true);
    fixture.backend.aws.recovery_unavailable.set(true);
    assert!(fixture.complete().is_err());
    fixture.backend.aws.recovery_unavailable.set(false);
    fixture.complete().unwrap();
    fixture
        .backend
        .observe_cluster(&fixture.deployment)
        .unwrap();
    assert_eq!(fixture.backend.aws.activation_sends(), 1);
    for command in fixture.backend.aws.commands.borrow().iter() {
        let script = command["Parameters"]["commands"][0].as_str().unwrap();
        assert!(!script.contains("python"));
        assert!(script.contains("/zdn __host-runtime --protocol zdn-host-runtime/v1alpha1 --manifest /etc/zdn/runtime/manifests/"));
    }
    crate::foundation::update_controller::prepare(
        &mut fixture.deployment,
        &["node-2".into()],
        true,
    )
    .unwrap();
    assert_eq!(
        fixture
            .deployment
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap()
            .host_runtime_protocol
            .as_deref(),
        Some(crate::host::runtime::revision::EXECUTION_PROTOCOL)
    );
    fixture
        .deployment
        .runtime
        .as_mut()
        .unwrap()
        .update
        .as_mut()
        .unwrap()
        .host_runtime_protocol = None;
    assert!(fixture.deployment.validate().is_err());
}
