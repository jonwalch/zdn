use super::*;
use crate::{
    aws::{AwsApiError, MetadataObject, TeamAws, TeamState},
    config::Size,
    pulumi::{CommandSpec, ProcessOutput, Progress},
    state::{BindingContext, OperationInput, StateStore},
};
use fs2::FileExt;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    fs,
    rc::Rc,
};
use tempfile::TempDir;

#[derive(Clone, Default)]
struct Clock(Rc<Cell<u64>>);
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        Ok(1_000 + self.0.get())
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.0.get())
    }
    fn sleep(&self, duration: Duration) {
        self.0.set(self.0.get() + duration.as_secs().max(1));
    }
}

#[derive(Default)]
struct FakeAws {
    clock: Clock,
    delay_seconds: Cell<u64>,
    objects: RefCell<BTreeMap<String, MetadataObject>>,
    puts: Cell<usize>,
    put_errors: RefCell<VecDeque<&'static str>>,
    lost_reply: Cell<bool>,
    read_errors: Cell<usize>,
    script: RefCell<VecDeque<(&'static str, Result<Value>)>>,
    health_commands: RefCell<Vec<Value>>,
}
impl AwsApi for FakeAws {
    fn call(&self, _: &str, operation: &str, input: Value, extra: &[String]) -> Result<Value> {
        if operation == "send-command" {
            self.health_commands.borrow_mut().push(input.clone());
        }
        let key = input["Key"].as_str().unwrap_or_default();
        if matches!(operation, "get-object" | "put-object") {
            self.clock
                .0
                .set(self.clock.0.get() + self.delay_seconds.get());
        }
        match operation {
            "get-object" => {
                if self.read_errors.get() > 0 {
                    self.read_errors.set(self.read_errors.get() - 1);
                    return Err(api_error("ServiceUnavailable"));
                }
                let objects = self.objects.borrow();
                let object = objects.get(key).ok_or_else(|| api_error("NoSuchKey"))?;
                fs::write(&extra[0], &object.bytes)?;
                Ok(json!({"ETag":object.etag}))
            }
            "put-object" => {
                self.puts.set(self.puts.get() + 1);
                if let Some(code) = self.put_errors.borrow_mut().pop_front() {
                    return Err(api_error(code));
                }
                let mut objects = self.objects.borrow_mut();
                let existing = objects.get(key);
                let matches = match input.get("IfMatch") {
                    Some(etag) => existing.is_some_and(|old| old.etag == etag.as_str().unwrap()),
                    None => input["IfNoneMatch"] == "*" && existing.is_none(),
                };
                if !matches {
                    return Err(api_error("PreconditionFailed"));
                }
                let bytes = fs::read(&extra[1])?;
                let etag = format!("etag-{}", self.puts.get());
                objects.insert(
                    key.into(),
                    MetadataObject {
                        bytes,
                        etag: etag.clone(),
                    },
                );
                if self.lost_reply.replace(false) {
                    self.read_errors.set(1);
                    return Err(api_error("CommandInterrupted"));
                }
                Ok(json!({"ETag":etag}))
            }
            _ => {
                let (expected, response) = self
                    .script
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or_else(|| panic!("unexpected AWS call {operation}: {input}"));
                assert_eq!(operation, expected);
                response
            }
        }
    }
}
fn api_error(code: &str) -> eyre::Report {
    AwsApiError { code: code.into() }.into()
}
struct NoPulumi;
impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("this test must not run Pulumi")
    }
}
struct Fixture {
    _root: TempDir,
    store: StateStore,
    deployment: Deployment,
    backend: LiveBackend<'static, FakeAws, NoPulumi, Clock>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("devnet.yaml"), "name: feature\n").unwrap();
        let scope = crate::state::Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let context =
            BindingContext::new(source.join("devnet.yaml"), None, None, scope.clone()).unwrap();
        let store = StateStore::open(root.path().join("state")).unwrap();
        let binding = store.bind(&context, "feature").unwrap();
        let receipt = store
            .begin_operation(
                &binding,
                "foundation-up",
                OperationInput {
                    config_sha256: "a".repeat(64),
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                &["apply"],
            )
            .unwrap();
        let team = TeamDefinition {
            deployment: None,
            api_version: aws::TEAM_API_VERSION.into(),
            team_id: scope.team_id.clone(),
            revision: 1,
            bootstrap_id: Uuid::new_v4(),
            aws: TeamAws {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
            },
            state: TeamState {
                backend: "s3://zdn-test-foundation/pulumi/test-team".into(),
                kms_key_arn:
                    "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"
                        .into(),
            },
        };
        let spec = FoundationSpec {
            scope,
            network_id: binding.network_id,
            aws_profile: "developer".into(),
            ami_id: "ami-1234567890abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        };
        let mut deployment = Deployment::new(spec, team.clone()).unwrap();
        deployment.team.api_version = crate::access::TEAM_ROLE_API_VERSION.into();
        deployment.team.deployment =
            Some(crate::access::DeploymentAccess::managed(&deployment.team));
        deployment.foundation_runtime = Some(crate::foundation_runtime::FoundationRuntime {
            protocol: crate::foundation_host::PROTOCOL.into(),
            helper: crate::devnet::Artifact {
                bytes: 64,
                sha256: "a".repeat(64),
            },
        });
        let work = root.path().join("project");
        let tools = root.path().join("tools");
        fs::create_dir(&work).unwrap();
        fs::create_dir(&tools).unwrap();
        fs::write(tools.join("pulumi"), "fixture only").unwrap();
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
        let api = FakeAws::default();
        let clock = api.clock.clone();
        let mut backend = LiveBackend {
            command_progress: None,
            deployment_directory: store
                .root()
                .join("foundation")
                .join(deployment.spec.network_id.to_string()),
            aws: api,
            client: PulumiClient::new(workspace, NoPulumi).unwrap(),
            selection,
            runtime: clock,
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
            state_root: store.root().into(),
        };
        backend.reserve(&deployment).unwrap();
        backend.acquire(&deployment, receipt.operation_id).unwrap();
        Self {
            _root: root,
            store,
            deployment,
            backend,
        }
    }
    fn at(&self, second: u64) {
        self.backend.runtime.0.set(second);
    }
    fn remote_lease(&self) -> LeaseHandle {
        aws::inspect_lease(
            &S3Metadata::new(&self.backend.aws, &self.backend.team).unwrap(),
            &self.backend.reservation,
        )
        .unwrap()
        .unwrap()
    }
    fn lock(&self) -> fs::File {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.store.root().join("store.lock"))
            .unwrap();
        file.try_lock_exclusive().unwrap();
        file
    }
    fn with_outputs(&mut self) {
        self.deployment.outputs = Some(FoundationOutputs {
            lightwallet: None,
            nodes: Default::default(),
            schema_version: 1,
            scope: self.deployment.spec.scope.clone(),
            network_id: self.deployment.spec.network_id,
            availability_zone: "us-east-1a".into(),
            vpc_id: "vpc-12345678".into(),
            private_subnet_id: "subnet-12345678".into(),
            instance_id: "i-1234567890abcdef0".into(),
            private_ip: "10.90.1.10".parse().unwrap(),
            chain_volume_id: "vol-12345678".into(),
            retain_chain_disk: true,
            security_group_id: "sg-12345678".into(),
            nat_gateway_id: "nat-12345678".into(),
            eip_allocation_id: "eipalloc-12345678".into(),
        });
    }
}

#[test]
fn transient_renewals_back_off_without_stopping_the_operation() {
    let mut f = Fixture::new();
    let initial = f.backend.aws.puts.get();
    f.backend
        .aws
        .put_errors
        .borrow_mut()
        .extend(["SlowDown", "ServiceUnavailable"]);
    f.at(30);
    f.backend.poll().unwrap();
    f.at(31);
    f.backend.poll().unwrap();
    assert_eq!(f.backend.aws.puts.get(), initial + 1);
    f.at(32);
    f.backend.poll().unwrap();
    f.at(35);
    f.backend.poll().unwrap();
    assert_eq!(f.backend.aws.puts.get(), initial + 2);
    f.at(36);
    f.backend.poll().unwrap();
    let handle = f.remote_lease();
    assert_eq!(handle.record.generation, 2);
    assert_eq!(handle.record.expires_at, 1930);
    assert_eq!(f.backend.lease.as_ref(), Some(&handle));
    assert_eq!(f.backend.heartbeat.retry_count, 0);
}

#[test]
fn lost_successful_renewal_and_failed_read_are_recovered_without_new_generation() {
    let mut f = Fixture::new();
    f.backend.aws.lost_reply.set(true);
    f.at(30);
    f.backend.poll().unwrap();
    assert_eq!(f.backend.lease.as_ref().unwrap().record.generation, 1);
    f.at(32);
    f.backend.poll().unwrap();
    let handle = f.remote_lease();
    assert_eq!(handle.record.generation, 2);
    assert_eq!(handle.record.expires_at, 1930);
    assert_eq!(f.backend.lease.as_ref(), Some(&handle));
}

#[test]
fn service_outage_stops_before_lease_expiry_and_never_extends_local_deadline() {
    let mut f = Fixture::new();
    f.backend
        .aws
        .put_errors
        .borrow_mut()
        .extend(std::iter::repeat_n("SlowDown", 100));
    for second in 30..720 {
        f.at(second);
        f.backend.poll().unwrap();
    }
    let calls = f.backend.aws.puts.get();
    f.at(720);
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .to_string()
        .contains("before lease expiry"));
    assert_eq!(f.backend.aws.puts.get(), calls);
    assert_eq!(f.backend.lease.as_ref().unwrap().record.expires_at, 1900);
}

#[test]
fn permission_errors_and_changed_owners_stop_without_retry() {
    let mut f = Fixture::new();
    f.backend
        .aws
        .put_errors
        .borrow_mut()
        .push_back("AccessDenied");
    f.at(30);
    assert!(f.backend.poll().unwrap_err().is::<AwsApiError>());
    assert_eq!(f.backend.heartbeat.retry_count, 0);
    let key = f.backend.reservation.lease_key();
    let mut record = f.remote_lease().record;
    record.owner.holder_id = Uuid::new_v4();
    f.backend.aws.objects.borrow_mut().insert(
        key,
        MetadataObject {
            bytes: serde_json::to_vec(&record).unwrap(),
            etag: "changed-owner".into(),
        },
    );
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .is::<aws::LeaseOwnershipChanged>());
}

#[test]
fn brief_state_contention_keeps_renewing_then_observes_cancellation() {
    let mut f = Fixture::new();
    let lock = f.lock();
    f.at(28);
    f.backend.poll().unwrap();
    f.at(31);
    f.backend.poll().unwrap();
    assert_eq!(f.remote_lease().record.generation, 2);
    FileExt::unlock(&lock).unwrap();
    let id = f.backend.lease.as_ref().unwrap().record.owner.operation_id;
    let receipt = f.store.operation(id).unwrap();
    f.store.request_cancel(id, receipt.revision).unwrap();
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
}

#[test]
fn persistent_state_contention_and_corruption_stop_safely() {
    let mut f = Fixture::new();
    let lock = f.lock();
    f.at(10);
    f.backend.poll().unwrap();
    f.at(39);
    f.backend.poll().unwrap();
    f.at(40);
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .to_string()
        .contains("30 seconds"));
    FileExt::unlock(&lock).unwrap();
    fs::write(f.store.root().join("state.json"), "invalid JSON").unwrap();
    assert!(f.backend.poll().is_err());
    f.backend.cancel.store(true, Ordering::SeqCst);
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
}

#[test]
fn unconfirmed_pulumi_cleanup_keeps_the_lease_owned() {
    let mut f = Fixture::new();
    let marker = f
        .backend
        .client
        .workspace
        .work_dir
        .join(".zdn-pulumi-process.json");
    fs::write(
        &marker,
        serde_json::to_vec(&json!({
            "token": Uuid::new_v4(), "session": 123, "cli_pid": 124, "completion": null,
        }))
        .unwrap(),
    )
    .unwrap();
    let before = f.remote_lease();
    let calls = f.backend.aws.puts.get();
    assert!(f
        .backend
        .release()
        .unwrap_err()
        .to_string()
        .contains("cleanup"));
    assert!(f.backend.lease.is_some());
    assert_eq!(f.backend.aws.puts.get(), calls);
    assert_eq!(f.remote_lease().etag, before.etag);
    assert!(!f.remote_lease().record.released);
    fs::remove_file(marker).unwrap();
    f.backend.release().unwrap();
    assert!(f.remote_lease().record.released);
}

#[test]
fn legacy_foundation_execution_is_rejected_before_aws_but_cleanup_is_admitted() {
    let mut f = Fixture::new();
    f.deployment.foundation_runtime = None;
    f.deployment.validate().unwrap();
    f.deployment.render().unwrap();
    // No AWS script is installed: any unexpected call panics in this fixture.
    let puts = f.backend.aws.puts.get();
    f.at(30); // Admission must precede even the lease heartbeat.
    for result in [
        f.backend.verify(&f.deployment, false),
        f.backend.deploy_runtime(&f.deployment).map(|_| ()),
        f.backend.ready(&f.deployment).map(|_| ()),
    ] {
        assert!(result.unwrap_err().to_string().contains("recreate fresh"));
    }
    assert_eq!(f.backend.aws.puts.get(), puts);
    assert!(super::health::validate(
        &f.deployment,
        &f.backend.deployment_directory,
        crate::health::Options::default()
    )
    .unwrap_err()
    .to_string()
    .contains("recreate fresh"));
    // Cleanup skips execution admission and reaches normal AWS identity checks.
    f.backend.aws.script.borrow_mut().push_back((
        "get-caller-identity",
        Err(api_error("CleanupIdentitySentinel")),
    ));
    assert!(f
        .backend
        .verify(&f.deployment, true)
        .unwrap_err()
        .is::<AwsApiError>());
    assert!(f.backend.aws.script.borrow().is_empty());
}

#[test]
fn readiness_wait_uses_fake_time_and_renews_the_lease() {
    {
        let mut f = Fixture::new();
        f.with_outputs();
        f.deployment.validate().unwrap();
        let instance = f.deployment.outputs.as_ref().unwrap().instance_id.clone();
        let health = json!({"schema_version":1,"network_id":f.deployment.spec.network_id,"status":"ready","chain_mounted":true,"docker_active":true,"ssm_active":true,"effective_memory_bytes":16*GIB,"application_memory_bytes":12*GIB,"visible_cpus":4,"visible_cpu_millis":4000,"application_cpu_millis":3500});
        {
            let mut script = f.backend.aws.script.borrow_mut();
            for _ in 0..4 {
                script.push_back((
                    "describe-instance-information",
                    Ok(json!({"InstanceInformationList":[]})),
                ));
            }
            script.extend([
            ("describe-instance-information",Ok(json!({"InstanceInformationList":[{"InstanceId":instance,"PingStatus":"Online"}]}))),
            ("send-command",Ok(json!({"Command":{"CommandId":Uuid::new_v4()}}))),
            ("get-command-invocation",Err(api_error("InvocationDoesNotExist"))),
            ("get-command-invocation",Ok(json!({"Status":"InProgress"}))),
            ("get-command-invocation",Ok(json!({"Status":"Success","ResponseCode":0,"StandardOutputContent":health.to_string()}))),
        ]);
        }
        assert_eq!(f.backend.ready(&f.deployment).unwrap(), health);
        let commands = f.backend.aws.health_commands.borrow();
        let command = commands[0]["Parameters"]["commands"][0].as_str().unwrap();
        // SSM can be Online before cloud-init has installed the helper. Run
        // the dispatched shell with host effect paths relocated and a local
        // stand-in for Linux's timeout (not installed by default on macOS).
        // These immediate fixtures test initialization ordering, not deadlines;
        // still check the remote timeout arguments before running its command.
        // Even an existing helper must not hide failed cloud initialization.
        for init_exit in [0, 1] {
            let root = tempfile::tempdir().unwrap();
            let helper = root.path().join("helper");
            let init = root.path().join("cloud-init");
            fs::write(
                &init,
                "test \"$1 $2\" = 'status --wait' || exit 3\nprintf '%s\\n' 'printf health-ready' >\"$ZDN_TEST_HELPER\"\nexit \"$ZDN_TEST_INIT_EXIT\"\n",
            )
            .unwrap();
            let mapped = command
                .replace(
                    "cloud-init status",
                    &format!("/bin/sh '{}' status", init.display()),
                )
                .replace(
                    "/opt/zdn/foundation-zdn",
                    &format!("/bin/sh '{}'", helper.display()),
                );
            let mapped = format!(
                "timeout() {{\n\
                 test \"$1 $2 $3\" = '--signal=TERM --kill-after=5s 600s' || return 3\n\
                 shift 3\n\
                 \"$@\"\n\
                 }}\n{mapped}"
            );
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &mapped])
                .env("ZDN_TEST_HELPER", &helper)
                .env("ZDN_TEST_INIT_EXIT", init_exit.to_string())
                .output()
                .unwrap();
            assert_eq!(output.status.success(), init_exit == 0, "{output:?}");
            assert_eq!(
                output.stdout,
                if init_exit == 0 {
                    b"health-ready".as_slice()
                } else {
                    b""
                }
            );
            assert!(helper.exists(), "cloud-init was not awaited");
        }
        assert!(f.remote_lease().record.generation >= 2);
        assert!(f.backend.aws.script.borrow().is_empty());
    }
}

#[test]
fn readiness_error_still_allows_conditional_release_and_release_failure_keeps_handle() {
    let mut f = Fixture::new();
    f.with_outputs();
    f.backend.aws.script.borrow_mut().push_back((
        "describe-instance-information",
        Err(api_error("AccessDenied")),
    ));
    assert!(f.backend.ready(&f.deployment).is_err());
    f.backend.aws.put_errors.borrow_mut().push_back("SlowDown");
    assert!(f.backend.release().is_err());
    assert!(f.backend.lease.is_some());
    f.backend.release().unwrap();
    assert!(f.backend.lease.is_none());
    assert!(f.remote_lease().record.released);
}

#[test]
fn wall_clock_changes_cannot_extend_the_monotonic_lease_budget() {
    struct Skewed {
        wall: u64,
        elapsed: u64,
    }
    impl Runtime for Skewed {
        fn unix_time(&self) -> Result<u64> {
            Ok(self.wall)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(self.elapsed)
        }
        fn sleep(&self, _: Duration) {
            panic!("no waiting required")
        }
    }
    let f = Fixture::new();
    let handle = f.backend.lease.as_ref().unwrap();
    assert!(f
        .backend
        .heartbeat
        .check_budget(
            handle,
            &Skewed {
                wall: 1000,
                elapsed: 719
            }
        )
        .is_ok());
    assert!(f
        .backend
        .heartbeat
        .check_budget(
            handle,
            &Skewed {
                wall: 900,
                elapsed: 720
            }
        )
        .is_err());
    assert!(f
        .backend
        .heartbeat
        .check_budget(
            handle,
            &Skewed {
                wall: 1720,
                elapsed: 10
            }
        )
        .is_err());
}

fn disk(deployment: &Deployment) -> Value {
    json!({"VolumeId":"vol-12345678","State":"available","Attachments":[],"Encrypted":true,"AvailabilityZone":"us-east-1a","Tags":[
        {"Key":"zdn:network-id","Value":deployment.spec.network_id},
        {"Key":"zdn:team-id","Value":deployment.spec.scope.team_id},
        {"Key":"zdn:managed-by","Value":"zdn"},
        {"Key":"Name","Value":deployment.spec.resource_name("chain-disk")}
    ]})
}
fn queue_inventory(api: &FakeAws, volume: Option<Value>) {
    let mut script = api.script.borrow_mut();
    let mut exact = Vec::new();
    for (operation, list, absent) in [
        (
            "describe-instances",
            "Reservations",
            Some("InvalidInstanceID.NotFound"),
        ),
        ("describe-vpcs", "Vpcs", Some("InvalidVpcID.NotFound")),
        (
            "describe-addresses",
            "Addresses",
            Some("InvalidAllocationID.NotFound"),
        ),
        (
            "describe-subnets",
            "Subnets",
            Some("InvalidSubnetID.NotFound"),
        ),
        (
            "describe-security-groups",
            "SecurityGroups",
            Some("InvalidGroup.NotFound"),
        ),
        ("describe-internet-gateways", "InternetGateways", None),
        ("describe-route-tables", "RouteTables", None),
        (
            "describe-nat-gateways",
            "NatGateways",
            Some("NatGatewayNotFound"),
        ),
    ] {
        script.push_back((operation, Ok(json!({list:[]}))));
        if let Some(code) = absent {
            exact.push((operation, Err(api_error(code))));
        }
    }
    let result = volume.map_or_else(
        || json!({"Volumes":[]}),
        |volume| json!({"Volumes":[volume]}),
    );
    script.push_back(("describe-volumes", Ok(result.clone())));
    script.extend(exact);
    script.push_back((
        "describe-volumes",
        if result["Volumes"].as_array().unwrap().is_empty() {
            Err(api_error("InvalidVolume.NotFound"))
        } else {
            Ok(result)
        },
    ));
    script.push_back(("get-role", Err(api_error("NoSuchEntity"))));
    script.push_back(("get-instance-profile", Err(api_error("NoSuchEntity"))));
}

#[test]
fn cleanup_rechecks_saved_disk_before_deletion_then_requires_backend_validation() {
    let mut f = Fixture::new();
    f.with_outputs();
    let disk = disk(&f.deployment);
    queue_inventory(&f.backend.aws, Some(disk.clone()));
    f.backend.aws.script.borrow_mut().extend([
        ("describe-volumes", Ok(json!({"Volumes":[disk]}))),
        ("delete-volume", Ok(json!({}))),
    ]);
    queue_inventory(&f.backend.aws, None);
    // A backend read error after deletion must not become cleanup success.
    f.backend
        .aws
        .script
        .borrow_mut()
        .push_back(("get-caller-identity", Err(api_error("AccessDenied"))));
    assert!(f
        .backend
        .cleanup(&f.deployment, true)
        .unwrap_err()
        .is::<AwsApiError>());
    assert!(f.backend.aws.script.borrow().is_empty());
    f.backend.release().unwrap();
    assert!(f.remote_lease().record.released);
}

#[test]
fn cleanup_refuses_a_disk_whose_tags_change_before_deletion() {
    let mut f = Fixture::new();
    f.with_outputs();
    let mut disk = disk(&f.deployment);
    queue_inventory(&f.backend.aws, Some(disk.clone()));
    disk["Tags"] = json!([]);
    f.backend
        .aws
        .script
        .borrow_mut()
        .push_back(("describe-volumes", Ok(json!({"Volumes":[disk]}))));
    assert!(f
        .backend
        .cleanup(&f.deployment, true)
        .unwrap_err()
        .to_string()
        .contains("ownership changed"));
    assert!(f.backend.aws.script.borrow().is_empty());
}

#[test]
fn slow_aws_attempts_leave_time_for_shutdown_before_lease_expiry() {
    let mut f = Fixture::new();
    f.at(719);
    f.backend.aws.delay_seconds.set(60);
    f.backend
        .aws
        .put_errors
        .borrow_mut()
        .push_back("ServiceUnavailable");
    let puts = f.backend.aws.puts.get();
    assert!(f
        .backend
        .poll()
        .unwrap_err()
        .to_string()
        .contains("before lease expiry"));
    assert_eq!(f.backend.runtime.monotonic(), Duration::from_secs(839));
    assert_eq!(f.backend.heartbeat.deadline, Duration::from_secs(900));
    assert_eq!(f.backend.aws.puts.get(), puts + 1);
    assert!(f.backend.poll().is_err());
    assert_eq!(f.backend.runtime.monotonic(), Duration::from_secs(839));
    assert_eq!(f.backend.aws.puts.get(), puts + 1);
}

struct DestroyPulumi {
    before: Value,
    after: Value,
    exports: Cell<usize>,
    destroys: Cell<usize>,
    calls: Rc<RefCell<Vec<String>>>,
    unrelated_error: bool,
    repeat_error: bool,
}
impl PulumiRunner for DestroyPulumi {
    fn run(&self, command: &CommandSpec, progress: &mut Progress<'_>) -> Result<ProcessOutput> {
        ensure!(progress()? == RunControl::Continue, "cancelled");
        self.calls.borrow_mut().push(command.label.clone());
        let mut output = ProcessOutput {
            stdout: vec![],
            stderr: vec![],
            success: true,
            exit_code: Some(0),
        };
        match command.label.as_str() {
            "stack-select" | "refresh" => {}
            "stack-export" => {
                let exports = self.exports.get();
                self.exports.set(exports + 1);
                output.stdout = serde_json::to_vec(if exports < 2 {
                    &self.before
                } else {
                    &self.after
                })?;
            }
            "destroy" => {
                let attempt = self.destroys.get();
                self.destroys.set(attempt + 1);
                if attempt == 0 || self.repeat_error {
                    output.success = false;
                    output.exit_code = Some(1);
                    output.stdout = if self.unrelated_error {
                        b"AccessDenied on DeleteVpc".to_vec()
                    } else {
                        b"error: disassociating EC2 EIP (eipassoc-12345678): operation error EC2: DisassociateAddress, api error UnauthorizedOperation: denied".to_vec()
                    };
                }
            }
            _ => bail!("unexpected Pulumi operation"),
        }
        Ok(output)
    }
}

#[test]
fn destroy_recovers_exactly_once_after_proving_and_refreshing_stale_nat_address() {
    for (unrelated, repeat_error, refresh_stays_stale) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let f = Fixture::new();
        let mut deployment = f.deployment;
        // Retired receipts still support product-managed destruction.
        deployment.foundation_runtime = None;
        let old = f.backend;
        fs::create_dir_all(&old.deployment_directory).unwrap();
        let program = deployment.render().unwrap();
        let prefix = format!(
            "urn:pulumi:zdn-{}::zdn-foundation::",
            deployment.spec.network_id.simple()
        );
        let provider_urn = format!(
            "{prefix}pulumi:providers:aws::{}",
            program.resources["provider"].name
        );
        let provider = serde_json::to_value(&program.resources["provider"]).unwrap();
        let address = serde_json::to_value(&program.resources["natAddress"]).unwrap();
        let provider_id = "00000000-0000-4000-8000-000000000002";
        let mut before = json!({"version":3,"deployment":{
            "secrets_providers":{"type":"cloud","state":{"url":deployment.team.secrets_provider()}},
            "resources":[
                {"urn":provider_urn,"type":"pulumi:providers:aws","id":provider_id,"inputs":provider["properties"]},
                {"urn":format!("{prefix}aws:ec2/eip:Eip::{}", program.resources["natAddress"].name),"type":"aws:ec2/eip:Eip","custom":true,
                 "id":"eipalloc-12345678","provider":format!("{provider_urn}::{provider_id}"),"inputs":address["properties"],"outputs":address["properties"]}
            ],"pending_operations":[]
        }});
        before["deployment"]["resources"][0]["inputs"]["version"] =
            json!(crate::infra::AWS_PROVIDER_VERSION);
        before["deployment"]["resources"][1]["outputs"]["allocationId"] =
            json!("eipalloc-12345678");
        before["deployment"]["resources"][1]["outputs"]["associationId"] =
            json!("eipassoc-12345678");
        let mut after = before.clone();
        if !refresh_stays_stale {
            after["deployment"]["resources"][1]["outputs"]["associationId"] = json!("");
        }
        let calls = Rc::new(RefCell::new(Vec::new()));
        let runner = DestroyPulumi {
            before,
            after,
            exports: Cell::new(0),
            destroys: Cell::new(0),
            calls: calls.clone(),
            unrelated_error: unrelated,
            repeat_error,
        };
        let mut workspace = old.client.workspace;
        workspace.project = "zdn-foundation".into();
        workspace.stack = format!("zdn-{}", deployment.spec.network_id.simple());
        fs::write(
            workspace.work_dir.join("Pulumi.yaml"),
            program.to_yaml().unwrap(),
        )
        .unwrap();
        fs::write(
            workspace
                .work_dir
                .join(format!("Pulumi.{}.yaml", workspace.stack)),
            format!("secretsprovider: {}\n", deployment.team.secrets_provider()),
        )
        .unwrap();
        let mut client = PulumiClient::new(workspace, runner).unwrap();
        client
            .prepare_stack(false, &mut || Ok(RunControl::Continue))
            .unwrap();
        calls.borrow_mut().clear();
        let mut backend = LiveBackend {
            command_progress: None,
            client,
            aws: old.aws,
            selection: old.selection,
            runtime: old.runtime,
            team: old.team,
            reservation: old.reservation,
            lease: old.lease,
            cancel: old.cancel,
            heartbeat: old.heartbeat,
            recovery_etag: None,
            destroying: true,
            destroy_context: Some(deployment.clone()),
            stack_missing: false,
            state_root: old.state_root,
            deployment_directory: old.deployment_directory,
        };
        if !unrelated {
            let tags = address["properties"]["tags"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| json!({"Key":key,"Value":value}))
                .collect::<Vec<_>>();
            backend.aws.script.borrow_mut().extend([
                ("describe-addresses", Ok(json!({"Addresses":[{"AllocationId":"eipalloc-12345678","Domain":"vpc","Tags":tags}]}))),
                ("describe-nat-gateways", Ok(json!({"NatGateways":[]}))),
            ]);
        }
        let result = backend.destroy();
        assert_eq!(
            result.is_ok(),
            !unrelated && !repeat_error && !refresh_stays_stale,
            "{result:?}"
        );
        let labels = calls.borrow();
        if unrelated {
            assert_eq!(&*labels, &["destroy"]);
        } else {
            let mut expected = vec!["destroy", "stack-export", "refresh", "stack-export"];
            if !refresh_stays_stale {
                expected.push("destroy");
            }
            assert_eq!(&*labels, &expected);
        }
        if !unrelated && !refresh_stays_stale {
            let receipt: Value = foundation::read_json(
                &backend
                    .deployment_directory
                    .join("stale-address-recovery.json"),
            )
            .unwrap();
            assert_eq!(receipt["destroy_completed"], !repeat_error);
            assert_eq!(receipt["allocation_id"], "eipalloc-12345678");
        }
        assert!(backend.aws.script.borrow().is_empty());
        assert!(!backend.lease.as_ref().unwrap().record.released);
        backend.release().unwrap();
    }
}
