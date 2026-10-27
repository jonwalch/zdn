//! The real update adapter and SSM recovery, with data-only AWS responses.
use super::*;
use crate::{
    aws::AwsApiError,
    foundation::{update_controller as controller, DeploymentFile},
    pulumi::{CommandSpec, ProcessOutput, Progress},
};
use base64::Engine;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fs,
};

struct NoPulumi;
fn validate_handoff(
    deployment: &Deployment,
    directory: &Path,
    updates: &BTreeMap<Uuid, crate::update::UpdateIntent>,
) -> Result<()> {
    super::validate_handoff(deployment, directory, updates)
}

impl PulumiRunner for NoPulumi {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        panic!("an image update must never execute Pulumi")
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
        panic!("scripted responses must complete immediately")
    }
}

struct Aws {
    deployment: Deployment,
    revision: ImageRevision,
    manifest: String,
    objects: RefCell<BTreeMap<String, Value>>,
    commands: RefCell<Vec<Value>>,
    reports: RefCell<BTreeMap<String, Value>>,
    installed: RefCell<BTreeSet<String>>,
    unavailable: Cell<bool>,
    unhealthy: Cell<bool>,
    wrong_attachment: Cell<bool>,
}
impl Aws {
    fn report(&self, instance: &str) -> Value {
        let d = &self.deployment;
        let node = d
            .outputs
            .as_ref()
            .unwrap()
            .nodes
            .values()
            .find(|n| n.instance_id == instance)
            .unwrap();
        let host = d
            .cluster
            .as_ref()
            .unwrap()
            .host_spec(&d.spec, &d.team, node)
            .unwrap();
        let producer = host.role == "producer";
        let mut report = json!({
            "apiVersion":"zdn-host-observation/v1alpha1","deploymentId":host.deployment_id,"nodeId":host.node_id,
            "consensusFingerprint":host.consensus_fingerprint,"configSha256":host.config_sha256,
            "image":host.image,"installSha256":host.install_sha256().unwrap(),
            "status":"ready","launchReady":false,"paymentQualification":"pending","scheduledProducer":producer,
            "producer":null,
            "readiness":{"apiVersion":crate::chain::readiness::API_VERSION,"consensusFingerprint":host.consensus_fingerprint,
                "role":host.role,"effectiveRulesVerified":true,"historyPresent":true,"miningReady":producer,
                "tip":{"height":7,"hash":"ab".repeat(32)},"launchReady":false,"paymentQualification":"pending"},
            "effectiveLimits":{"effectiveMemoryBytes":host.memory_bytes+host.host_reserve_bytes,"visibleCpuMillis":host.cpu_millis+250,
                "nodeMemoryBytes":host.memory_bytes,"nodeCpuMillis":host.cpu_millis,"hostReserveBytes":host.host_reserve_bytes,"hostReserveCpuMillis":250}
        });
        if producer {
            report["producer"] = json!({"apiVersion":crate::chain::producer::API_VERSION,
                "identity":{"deploymentId":host.deployment_id,"nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint},
                "ownerPid":1234,"ownerSession":"d1b8f1a7-b228-421f-984b-82eebf73b67e","phase":"waiting","intervalSecs":25,
                "controllerLocked":true,"lastConfirmedTip":{"height":7,"hash":"ab".repeat(32)},"pending":null,"confirmedBlocks":0,
                "paymentQualification":"pending","launchReady":false});
        }
        if self.installed.borrow().contains(&node.node_id) {
            let runtime = d.runtime.as_ref().unwrap();
            let revision = if runtime
                .update
                .as_ref()
                .unwrap()
                .targets
                .contains_key(&node.node_id)
            {
                &self.revision
            } else {
                &runtime.nodes[&node.node_id]
            };
            report["image"] = json!(revision.image.image);
            report["updateId"] = json!(revision.update_id);
            if self.unhealthy.get() {
                report["readiness"]["historyPresent"] = json!(false);
            }
        }
        report
    }
}
impl AwsApi for Aws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        extra: &[String],
    ) -> Result<Value> {
        match (service, operation) {
            ("ec2", "describe-instances") => {
                let d = &self.deployment;
                let node = d
                    .outputs
                    .as_ref()
                    .unwrap()
                    .nodes
                    .values()
                    .find(|n| input["InstanceIds"] == json!([n.instance_id]))
                    .unwrap();
                assert_eq!(input, json!({"InstanceIds":[node.instance_id]}));
                let tags: Vec<_> = [
                    ("zdn:network-id", d.spec.network_id.to_string()),
                    ("zdn:team-id", d.team.team_id.clone()),
                    ("zdn:managed-by", "zdn".into()),
                    ("zdn:bootstrap", d.team.bootstrap_id.to_string()),
                    ("zdn:node-id", node.node_id.clone()),
                ]
                .into_iter()
                .map(|(k, v)| json!({"Key":k,"Value":v}))
                .collect();
                Ok(
                    json!({"Reservations":[{"Instances":[{"InstanceId":node.instance_id,"State":{"Name":"running"},
                    "VpcId":d.outputs.as_ref().unwrap().vpc_id,"SubnetId":d.outputs.as_ref().unwrap().private_subnet_id,"PrivateIpAddress":node.private_ip,"Tags":tags}]}]}),
                )
            }
            ("ec2", "describe-volumes") => {
                let d = &self.deployment;
                let node = d
                    .outputs
                    .as_ref()
                    .unwrap()
                    .nodes
                    .values()
                    .find(|n| input["VolumeIds"] == json!([n.volume_id]))
                    .unwrap();
                assert_eq!(input, json!({"VolumeIds":[node.volume_id]}));
                let topology = d.cluster.as_ref().unwrap().topology()?;
                let disk = topology
                    .nodes()
                    .into_iter()
                    .find(|n| n.node_id == node.node_id)
                    .unwrap();
                let tags: Vec<_> = [
                    ("zdn:network-id", d.spec.network_id.to_string()),
                    ("zdn:team-id", d.team.team_id.clone()),
                    ("zdn:managed-by", "zdn".into()),
                    ("zdn:bootstrap", d.team.bootstrap_id.to_string()),
                    ("zdn:node-id", node.node_id.clone()),
                    ("Name", d.spec.resource_name(&disk.volume_key)),
                ]
                .into_iter()
                .map(|(k, v)| json!({"Key":k,"Value":v}))
                .collect();
                Ok(
                    json!({"Volumes":[{"VolumeId":node.volume_id,"AvailabilityZone":d.spec.availability_zone,"Encrypted":true,
                    "Tags":tags,"State":"in-use","Attachments":[{"State":"attached","InstanceId":if self.wrong_attachment.get(){"i-00000000000000099"}else{&node.instance_id}}]}]}),
                )
            }
            ("ecr", "batch-get-image") => {
                assert_eq!(
                    input["imageIds"],
                    json!([{"imageDigest":self.revision.image.manifest_digest()?}])
                );
                Ok(
                    json!({"failures":[],"images":[{"imageId":{"imageDigest":self.revision.image.manifest_digest()?},"imageManifest":self.manifest}]}),
                )
            }
            ("s3api", "head-object") => self
                .objects
                .borrow()
                .get(input["Key"].as_str().unwrap())
                .cloned()
                .ok_or_else(|| {
                    AwsApiError {
                        code: "NoSuchKey".into(),
                    }
                    .into()
                }),
            ("s3api", "put-object") => {
                assert_eq!(input["IfNoneMatch"], "*");
                assert_eq!(input["ServerSideEncryption"], "aws:kms");
                assert_eq!(extra[0], "--body");
                let bytes = fs::read(&extra[1])?;
                let value = json!({"ContentLength":bytes.len(),"ChecksumSHA256":input["ChecksumSHA256"],
                    "ServerSideEncryption":input["ServerSideEncryption"],"SSEKMSKeyId":input["SSEKMSKeyId"]});
                self.objects
                    .borrow_mut()
                    .insert(input["Key"].as_str().unwrap().into(), value);
                Ok(json!({}))
            }
            ("ssm", "describe-instance-information") => Ok(
                json!({"InstanceInformationList":input["Filters"][0]["Values"].as_array().unwrap().iter().map(|id| json!({"InstanceId":id,"PingStatus":"Online"})).collect::<Vec<_>>()}),
            ),
            ("ssm", "send-command") => {
                let instance = input["InstanceIds"][0].as_str().unwrap().to_owned();
                let script = input["Parameters"]["commands"][0].as_str().unwrap();
                let mutation = script.contains("ZDN_INSTALLER_BOOTSTRAP");
                if mutation {
                    assert!(self
                        .objects
                        .borrow()
                        .keys()
                        .any(|key| script.contains(&format!("--key \"{key}\""))));
                }
                if mutation {
                    let node = self
                        .deployment
                        .outputs
                        .as_ref()
                        .unwrap()
                        .nodes
                        .values()
                        .find(|n| n.instance_id == instance)
                        .unwrap();
                    assert!(self
                        .deployment
                        .runtime
                        .as_ref()
                        .unwrap()
                        .update
                        .as_ref()
                        .unwrap()
                        .targets
                        .contains_key(&node.node_id));
                    assert!(
                        !self
                            .commands
                            .borrow()
                            .iter()
                            .any(|c| c["Parameters"] == input["Parameters"]
                                && c["InstanceIds"] == input["InstanceIds"]),
                        "update command must not be resubmitted"
                    );
                    self.installed.borrow_mut().insert(node.node_id.clone());
                }
                let report = if script.contains("__client-gateway") {
                    let d = &self.deployment;
                    let host = d.cluster.as_ref().unwrap().host_spec(
                        &d.spec,
                        &d.team,
                        &d.outputs.as_ref().unwrap().nodes["node-1"],
                    )?;
                    let manifest = native::node_manifest(
                        d.cluster
                            .as_ref()
                            .unwrap()
                            .native_runtime_protocol
                            .as_deref(),
                        &host,
                    )?;
                    assert_eq!(script, native::gateway_command(&manifest, "observe")?);
                    crate::client_gateway::native::observation(&manifest, "ready")?
                } else {
                    if !mutation
                        && self
                            .deployment
                            .cluster
                            .as_ref()
                            .unwrap()
                            .native_runtime_protocol
                            .is_some()
                    {
                        let d = &self.deployment;
                        let node = d
                            .outputs
                            .as_ref()
                            .unwrap()
                            .nodes
                            .values()
                            .find(|n| n.instance_id == instance)
                            .unwrap();
                        let host = d
                            .cluster
                            .as_ref()
                            .unwrap()
                            .host_spec(&d.spec, &d.team, node)?;
                        assert_eq!(
                            script,
                            native::node_command(
                                d.cluster
                                    .as_ref()
                                    .unwrap()
                                    .native_runtime_protocol
                                    .as_deref(),
                                &host,
                                "observe"
                            )?
                        );
                    }
                    self.report(&instance)
                };
                input["CommandId"] = json!(Uuid::new_v4());
                self.reports
                    .borrow_mut()
                    .insert(input["CommandId"].as_str().unwrap().into(), report);
                self.commands.borrow_mut().push(input.clone());
                if mutation {
                    return Err(AwsApiError {
                        code: "RequestTimeout".into(),
                    }
                    .into());
                }
                Ok(json!({"Command":input}))
            }
            ("ssm", "list-commands") => {
                ensure!(!self.unavailable.get(), "scripted recovery outage");
                Ok(json!({"Commands":*self.commands.borrow()}))
            }
            ("ssm", "get-command-invocation") => {
                let commands = self.commands.borrow();
                let command = commands
                    .iter()
                    .find(|c| c["CommandId"] == input["CommandId"])
                    .unwrap();
                Ok(
                    json!({"CommandId":input["CommandId"],"InstanceId":input["InstanceId"],
                    "DocumentName":command["DocumentName"],"DocumentVersion":command["DocumentVersion"],"Comment":command["Comment"],
                    "Status":"Success","ResponseCode":0,"StandardOutputContent":serde_json::to_string(&self.reports.borrow()[input["CommandId"].as_str().unwrap()])?,"StandardErrorContent":""}),
                )
            }
            _ => panic!("unexpected cloud action {service}.{operation}"),
        }
    }
}

#[test]
fn lost_dispatch_and_stale_success_reconcile_without_host_or_disk_replacement() {
    lost_dispatch_recovery(&["node-2"], false, true);
}

#[test]
fn producer_update_keeps_enabled_client_access_observable() {
    lost_dispatch_recovery(&["node-1"], true, true);
}

#[test]
fn interrupted_multi_target_update_preserves_untouched_preparation_for_recovery() {
    lost_dispatch_recovery(&["node-2", "node-3"], false, true);
}

#[test]
fn legacy_update_execution_is_rejected_before_aws() {
    lost_dispatch_recovery(&["node-1"], false, false);
    lost_dispatch_recovery(&["node-2", "node-3"], false, false);
    lost_dispatch_recovery(&["node-2", "node-3", "node-1"], false, false);
}

#[test]
fn native_updates_recover_lost_replies_and_keep_original_node_and_gateway_manifests() {
    lost_dispatch_recovery(&["node-1"], true, true);
    lost_dispatch_recovery(&["node-2", "node-3"], false, true);
}

fn lost_dispatch_recovery(targets: &[&'static str], client_access: bool, native_runtime: bool) {
    let target = targets[0];
    let root = tempfile::tempdir().unwrap();
    let mut d = super::super::producer_tests::fixture_deployment();
    d.cluster.as_mut().unwrap().client_access = client_access;
    d.cluster.as_mut().unwrap().native_runtime_protocol =
        Some(crate::host::runtime::PROTOCOL.into());
    d.cluster.as_mut().unwrap().installer_fetch_protocol =
        Some(crate::host::installer_bootstrap::PROTOCOL.into());
    let file = DeploymentFile::open(root.path(), d.spec.network_id).unwrap();
    file.save(&d).unwrap();
    let original = d.render().unwrap().to_yaml().unwrap();
    let original_outputs = serde_json::to_value(&d.outputs).unwrap();
    let id = controller::prepare(
        &mut d,
        &targets.iter().map(|n| (*n).into()).collect::<Vec<_>>(),
        true,
    )
    .unwrap();
    let directory = file.directory().join("updates").join(id.to_string());
    foundation::private_directory(&file.directory().join("updates")).unwrap();
    foundation::private_directory(&directory).unwrap();
    foundation::private_directory(&devnet::artifact_path(&directory, "")).unwrap();
    let config = serde_json::to_vec(
        &json!({"architecture":"amd64","os":"linux","config":{"Env":[],"Entrypoint":[],"Cmd":[]},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}}),
    )
    .unwrap();
    let manifest = serde_json::to_string(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",devnet::sha256(&config)),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","d".repeat(64)),"size":42}]})).unwrap();
    let mut image = d.cluster.as_ref().unwrap().image.clone();
    image.image = format!(
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
        devnet::sha256(manifest.as_bytes())
    );
    image.config_digest = format!("sha256:{}", devnet::sha256(&config));
    for (name, bytes) in [
        ("image.json", serde_json::to_vec(&image).unwrap()),
        ("image-manifest.json", manifest.as_bytes().to_vec()),
        ("image-config.json", config),
    ] {
        foundation::write_private(&devnet::artifact_path(&directory, name), &bytes).unwrap();
    }
    let revision = ImageRevision::read(id, None, &directory).unwrap();
    controller::set_revision(&file, &mut d, revision.clone()).unwrap();
    for node in d.outputs.as_ref().unwrap().nodes.values() {
        let host = d
            .cluster
            .as_ref()
            .unwrap()
            .host_spec(&d.spec, &d.team, node)
            .unwrap();
        let install = selected_node(
            file.directory(),
            &host,
            d.cluster
                .as_ref()
                .unwrap()
                .native_runtime_protocol
                .as_deref(),
        )
        .unwrap();
        foundation::write_private(
            &file
                .directory()
                .join(format!("{}-install.sh", node.node_id)),
            install.script.as_bytes(),
        )
        .unwrap();
        if client_access && node.node_id == "node-1" {
            foundation::write_private(
                &file.directory().join("client-rpc-install.sh"),
                selected_gateway(
                    file.directory(),
                    &host,
                    d.cluster
                        .as_ref()
                        .unwrap()
                        .native_runtime_protocol
                        .as_deref(),
                )
                .unwrap()
                .script
                .as_bytes(),
            )
            .unwrap();
        }
    }
    let work = root.path().join("project");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("Pulumi.yaml"), "name: zdn-test\nruntime: yaml\n").unwrap();
    fs::write(root.path().join("pulumi"), "unused test executable").unwrap();
    let selection = AwsSelection {
        profile: "developer".into(),
        account_id: d.team.aws.account_id.clone(),
        region: d.team.aws.region.clone(),
    };
    let workspace = PulumiWorkspace {
        tools: ManagedTools {
            executable: root.path().join("pulumi"),
            bin_dir: root.path().to_owned(),
            plugins_dir: root.path().to_owned(),
        },
        work_dir: work,
        diagnostics_dir: root.path().join("diagnostics"),
        backend_url: d.team.state.backend.clone(),
        secrets_provider: d.team.secrets_provider(),
        aws: AwsContext {
            profile: selection.profile.clone(),
            account_id: selection.account_id.clone(),
            region: selection.region.clone(),
            credential_files: None,
        },
        project: "zdn-test".into(),
        stack: "zdn-test".into(),
    };
    let observations = RefCell::new(Vec::new());
    let mut backend = LiveBackend {
        command_progress: None,
        aws: Aws {
            deployment: d.clone(),
            revision: revision.clone(),
            manifest,
            objects: Default::default(),
            commands: Default::default(),
            reports: Default::default(),
            installed: Default::default(),
            unavailable: Cell::new(true),
            unhealthy: Cell::new(false),
            wrong_attachment: Cell::new(false),
        },
        client: PulumiClient::new(workspace, NoPulumi).unwrap(),
        selection,
        runtime: Clock,
        team: d.team.clone(),
        reservation: NetworkReservation::new(d.spec.scope.clone(), d.spec.network_id, d.owner_id)
            .unwrap(),
        lease: None,
        cancel: Arc::new(AtomicBool::new(false)),
        heartbeat: Heartbeat::default(),
        recovery_etag: None,
        destroying: false,
        destroy_context: None,
        stack_missing: false,
        state_root: root.path().to_owned(),
        deployment_directory: file.directory().to_owned(),
    };
    backend.observe_commands(|observation| {
        observations
            .borrow_mut()
            .push(serde_json::to_value(observation)?);
        Ok(())
    });
    if !native_runtime {
        d.cluster.as_mut().unwrap().native_runtime_protocol = None;
        d.cluster.as_mut().unwrap().installer_fetch_protocol = None;
        d.runtime
            .as_mut()
            .unwrap()
            .update
            .as_mut()
            .unwrap()
            .host_runtime_protocol = None;
        for result in [
            backend.preflight_update(&d, true),
            backend.preflight_update(&d, false),
            backend.acquire_update(&d, id),
            Backend::stage(&mut backend, &d, &revision),
            Backend::dispatch(&mut backend, &d, target),
            Backend::observe(&mut backend, &d, target, &revision),
            Backend::ready(&mut backend, &d),
        ] {
            assert!(result.unwrap_err().to_string().contains("recreate fresh"));
        }
        assert!(backend.aws.commands.borrow().is_empty());
        assert!(!directory
            .join(format!("{target}-recovery-authorization.json"))
            .exists());
        return;
    }
    backend.aws.wrong_attachment.set(true);
    assert!(backend
        .preflight_update(&d, true)
        .unwrap_err()
        .to_string()
        .contains("attachment"));
    assert!(backend.aws.commands.borrow().is_empty());
    backend.aws.wrong_attachment.set(false);
    backend.preflight_update(&d, true).unwrap();
    let sends = backend.aws.commands.borrow().len();
    backend.cancel.store(true, Ordering::SeqCst);
    assert!(controller::Backend::stage(&mut backend, &d, &revision).is_err());
    assert_eq!(backend.aws.commands.borrow().len(), sends);
    assert!(!directory.join(format!("{target}-command.json")).exists());
    backend.cancel.store(false, Ordering::SeqCst);
    if targets.len() > 1 {
        // Interrupt staging after the first target: no mutation is allowed
        // until the remaining target has its own exact preparation evidence.
        let install = file.directory().join(format!("{}-install.sh", targets[1]));
        let bytes = fs::read(&install).unwrap();
        fs::remove_file(&install).unwrap();
        assert!(controller::run(&file, &mut d, &mut backend).is_err());
        assert_eq!(backend.aws.commands.borrow().len(), sends);
        assert!(directory.join(format!("{target}-command.json")).exists());
        assert!(!directory
            .join(format!("{}-command.json", targets[1]))
            .exists());
        foundation::write_private(&install, &bytes).unwrap();
        let updates = BTreeMap::from([(
            id,
            d.runtime.as_ref().unwrap().update.as_ref().unwrap().clone(),
        )]);
        assert!(validate_handoff(&d, file.directory(), &updates).is_err());
    }
    controller::Backend::stage(&mut backend, &d, &revision).unwrap();
    if native_runtime {
        let intent = d.runtime.as_ref().unwrap().update.as_ref().unwrap();
        assert_eq!(
            intent.host_runtime_protocol.as_deref(),
            Some(crate::host::runtime::revision::EXECUTION_PROTOCOL)
        );
        for node in targets {
            let bytes = fs::read(directory.join(format!("{node}-update.sh"))).unwrap();
            let script = std::str::from_utf8(&bytes).unwrap();
            assert!(!script.contains("python"));
            assert!(script
                .contains("__host-update --protocol zdn-native-image-update-execution/v1alpha1"));
            let encoded = script
                .split("\nZDN_NATIVE_UPDATE\n")
                .next()
                .unwrap()
                .lines()
                .last()
                .unwrap();
            let request = crate::host::runtime::revision::Request::from_slice(
                &base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.image.image, revision.image.image);
            assert_ne!(request.image.image, request.original.spec.image);
            assert_eq!(request.expected_image, request.original.spec.image);
            assert_eq!(
                request.original.spec.image,
                d.cluster.as_ref().unwrap().image.image
            );
        }
    }
    assert_eq!(
        backend.aws.commands.borrow().len(),
        sends,
        "staging sends no command"
    );
    let prepared: BTreeMap<_, _> = targets
        .iter()
        .map(|node| {
            let path = directory.join(format!("{node}-command.json"));
            let bytes = fs::read(path).unwrap();
            let journal: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(journal["attempts"].as_array().unwrap().len(), 1);
            assert_eq!(journal["attempts"][0]["state"], "prepared");
            assert_eq!(journal["attempts"][0]["uncertain"], false);
            assert!(journal["attempts"][0]["commandId"].is_null());
            (*node, bytes)
        })
        .collect();
    assert!(controller::run(&file, &mut d, &mut backend).is_err());
    assert_eq!(
        *backend.aws.installed.borrow(),
        BTreeSet::from([target.to_owned()])
    );
    assert!(file.load().unwrap().runtime.unwrap().nodes.is_empty());
    for node in &targets[1..] {
        assert_eq!(
            fs::read(directory.join(format!("{node}-command.json"))).unwrap(),
            prepared[node]
        );
    }
    let updates = BTreeMap::from([(
        id,
        d.runtime.as_ref().unwrap().update.as_ref().unwrap().clone(),
    )]);
    validate_handoff(&d, file.directory(), &updates).unwrap();
    // A real Prepared journal is portable evidence; its absence is not.
    let missing = directory.join(format!("{}-command.json", targets.last().unwrap()));
    let bytes = fs::read(&missing).unwrap();
    fs::remove_file(&missing).unwrap();
    assert!(validate_handoff(&d, file.directory(), &updates).is_err());
    assert!(!missing.exists());
    foundation::write_private(&missing, &bytes).unwrap();
    let uncertain = fs::read(directory.join(format!("{target}-command.json"))).unwrap();
    controller::Backend::stage(&mut backend, &d, &revision).unwrap();
    assert_eq!(
        fs::read(directory.join(format!("{target}-command.json"))).unwrap(),
        uncertain
    );
    backend.aws.unavailable.set(false);
    backend.aws.unhealthy.set(true);
    assert!(controller::run(&file, &mut d, &mut backend).is_err());
    assert!(file.load().unwrap().runtime.unwrap().nodes.is_empty());
    backend.aws.unhealthy.set(false);
    controller::run(&file, &mut d, &mut backend).unwrap();
    let command: Value = serde_json::from_slice(
        &fs::read(directory.join(format!("{target}-command.json"))).unwrap(),
    )
    .unwrap();
    let observations = observations.borrow();
    let reported: Vec<_> = observations
        .iter()
        .filter(|o| o["attemptId"] == command["attempts"][0]["id"])
        .collect();
    assert!(reported
        .iter()
        .any(|o| o["uncertain"] == true && o["commandIdKnown"] == false));
    assert_eq!(reported.last().unwrap()["state"], "succeeded");
    assert!(reported.iter().all(|o| o["attemptNumber"] == 1));
    let saved = file.load().unwrap();
    assert_eq!(saved.render().unwrap().to_yaml().unwrap(), original);
    assert_eq!(
        serde_json::to_value(&saved.outputs).unwrap(),
        original_outputs
    );
    assert_eq!(saved.runtime.as_ref().unwrap().nodes.len(), targets.len());
    assert!(
        saved
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap()
            .finished
    );
    for node in ["node-1", "node-2", "node-3"]
        .into_iter()
        .filter(|node| !targets.contains(node))
    {
        assert_eq!(
            crate::update::active_image(&saved, node).unwrap(),
            &saved.cluster.as_ref().unwrap().image
        );
    }
    for node in targets {
        assert_ne!(
            crate::update::active_image(&saved, node).unwrap(),
            &saved.cluster.as_ref().unwrap().image
        );
        let journal: Value = serde_json::from_slice(
            &fs::read(directory.join(format!("{node}-command.json"))).unwrap(),
        )
        .unwrap();
        let first: Value = serde_json::from_slice(&prepared[node]).unwrap();
        assert_eq!(journal["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(journal["attempts"][0]["id"], first["attempts"][0]["id"]);
        assert_eq!(journal["attempts"][0]["state"], "succeeded");
    }
}
