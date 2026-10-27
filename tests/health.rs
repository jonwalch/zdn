//! Public health checks use data-only SSM responses, never AWS or node processes.
#[cfg(unix)]
#[path = "support/discovery_aws.rs"]
mod discovery_aws;
#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;
#[cfg(unix)]
#[path = "support/native_tool.rs"]
mod native_tool;

use eyre::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use zdn::{
    aws::{AwsApi, AwsApiError, TeamDefinition},
    foundation::Deployment,
    foundation_live::Runtime,
    health::{self, Options, Status},
    host::HostInstallSpec,
};

#[derive(Default)]
struct Clock(Cell<u64>);
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        Ok(1_800_000_000 + self.0.get())
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.0.get())
    }
    fn sleep(&self, duration: Duration) {
        self.0.set(self.0.get() + duration.as_secs());
    }
}

#[derive(Default)]
struct Aws<'a> {
    hosts: BTreeMap<String, (HostInstallSpec, String)>,
    native_commands: Vec<String>,
    services: BTreeMap<String, (String, Value)>,
    stopped_service: Cell<Option<&'static str>>,
    invalid_service: Cell<Option<(&'static str, &'static str)>>,
    commands: RefCell<Vec<Value>>,
    calls: RefCell<Vec<String>>,
    bad_field: Cell<Option<&'static str>>,
    producer_stopped: Cell<bool>,
    unavailable: Cell<u32>,
    recovery_throttles: Cell<u32>,
    send_error: Cell<Option<&'static str>>,
    invocation_error: Cell<Option<&'static str>>,
    recover_after_send: Cell<bool>,
    cancel_after_send: Option<&'a AtomicBool>,
}
impl Aws<'_> {
    fn report(&self, instance: &str) -> Value {
        let (host, install) = &self.hosts[instance];
        let producer = host.role == "producer" && !self.producer_stopped.get();
        let mut report = json!({
            "apiVersion":"zdn-host-observation/v1alpha1","deploymentId":host.deployment_id,
            "nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint,
            "configSha256":host.config_sha256,"image":host.image,"installSha256":install,
            "status":"ready","launchReady":false,"paymentQualification":"pending",
            "scheduledProducer":producer,
            "producer":if producer { json!({
                "apiVersion":"zdn-block-producer/v1alpha1",
                "identity":{"deploymentId":host.deployment_id,"nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint},
                "ownerPid":1234,"ownerSession":"d1b8f1a7-b228-421f-984b-82eebf73b67e",
                "phase":"waiting","intervalSecs":25,"controllerLocked":true,
                "lastConfirmedTip":{"height":0,"hash":"ab".repeat(32)},"pending":null,"confirmedBlocks":0,
                "paymentQualification":"pending","launchReady":false
            }) } else { Value::Null },
            "readiness":{"apiVersion":"zdn-chain-readiness/v1alpha1","consensusFingerprint":host.consensus_fingerprint,
                "role":host.role,"effectiveRulesVerified":true,"historyPresent":true,"miningReady":host.role == "producer",
                "tip":{"height":0,"hash":"ab".repeat(32)},"launchReady":false,"paymentQualification":"pending"},
            "effectiveLimits":{"effectiveMemoryBytes":host.memory_bytes+host.host_reserve_bytes,"visibleCpuMillis":host.cpu_millis+250,
                "nodeMemoryBytes":host.memory_bytes,"nodeCpuMillis":host.cpu_millis,
                "hostReserveBytes":host.host_reserve_bytes,"hostReserveCpuMillis":250}
        });
        if let Some(field) = self.bad_field.get() {
            report[field] = json!("private foreign identity");
        }
        report
    }
}
impl AwsApi for Aws<'_> {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        _: &[String],
    ) -> Result<Value> {
        // An allowlist forbids leases, uploads, EC2 mutation, and all activation/install commands.
        assert_eq!(service, "ssm", "health must not access {service}");
        self.calls.borrow_mut().push(operation.into());
        match operation {
            "send-command" => {
                if let Some(code) = self.send_error.get() {
                    return Err(AwsApiError { code: code.into() }.into());
                }
                if self.unavailable.get() > 0 {
                    self.unavailable.set(self.unavailable.get() - 1);
                    self.recovery_throttles.set(6);
                    return Err(AwsApiError {
                        code: "ThrottlingException".into(),
                    }
                    .into());
                }
                let script = input["Parameters"]["commands"][0].as_str().unwrap();
                assert!(
                    self.native_commands
                        .iter()
                        .any(|expected| expected == script)
                        || self
                            .services
                            .values()
                            .any(|(expected, _)| expected == script),
                    "health may only observe"
                );
                input["CommandId"] = json!(uuid::Uuid::new_v4());
                self.commands.borrow_mut().push(input.clone());
                if let Some(cancel) = self.cancel_after_send {
                    cancel.store(true, Ordering::SeqCst);
                }
                Ok(json!({"Command":input}))
            }
            "list-commands" => {
                assert!(self.recovery_throttles.get() > 0);
                self.recovery_throttles
                    .set(self.recovery_throttles.get() - 1);
                Err(AwsApiError {
                    code: "ThrottlingException".into(),
                }
                .into())
            }
            "get-command-invocation" => {
                if self.invocation_error.get() == Some("denied") {
                    return Err(AwsApiError {
                        code: "AccessDeniedException".into(),
                    }
                    .into());
                }
                if self.invocation_error.get() == Some("unknown") {
                    eyre::bail!("private remote failure");
                }
                let commands = self.commands.borrow();
                let command = commands
                    .iter()
                    .find(|c| c["CommandId"] == input["CommandId"])
                    .unwrap();
                let script = command["Parameters"]["commands"][0].as_str().unwrap();
                let report = if let Some((key, (_, report))) = self
                    .services
                    .iter()
                    .find(|(_, (expected, _))| expected == script)
                {
                    let mut report = report.clone();
                    if self.stopped_service.get() == Some(key.as_str()) {
                        report["status"] = json!("stopped");
                        if key == "lightwallet" {
                            report["readiness"] = Value::Null;
                        }
                    }
                    if let Some((service, field)) = self.invalid_service.get() {
                        if service == key {
                            report[field] = json!("private foreign identity");
                        }
                    }
                    report
                } else {
                    self.report(input["InstanceId"].as_str().unwrap())
                };
                if self.recover_after_send.replace(false) {
                    self.producer_stopped.set(false);
                }
                let mut response = json!({"CommandId":command["CommandId"],"InstanceId":input["InstanceId"],
                    "DocumentName":command["DocumentName"],"DocumentVersion":command["DocumentVersion"],"Comment":command["Comment"],
                    "Status":"Success","ResponseCode":0,"StandardOutputContent":report.to_string(),"StandardErrorContent":"private stderr"});
                match self.invocation_error.get() {
                    Some("identity") => response["InstanceId"] = json!("i-00000000000000999"),
                    Some("malformed") => {
                        response["StandardOutputContent"] = json!("private non-JSON")
                    }
                    Some("failed") => {
                        response["Status"] = json!("Failed");
                        response["ResponseCode"] = json!(1);
                        response["StandardOutputContent"] = json!("");
                    }
                    _ => {}
                }
                Ok(response)
            }
            "cancel-command" => Ok(json!({})),
            other => panic!("forbidden health operation {other}"),
        }
    }
}

fn deployment(directory: &Path) -> Deployment {
    deployment_native(directory)
}

fn node_manifest(host: &HostInstallSpec) -> zdn::host::runtime::Manifest {
    zdn::host::runtime::Manifest::new(
        host.clone(),
        zdn::host::runtime::Selection {
            protocol: zdn::host::runtime::PROTOCOL.into(),
            helper: host.helper.clone(),
        },
    )
    .unwrap()
}

// Independent spelling of the private controller command wire format.
fn native_command(
    host: &HostInstallSpec,
    entrypoint: &str,
    protocol: &str,
    path: &str,
    operation: &str,
) -> String {
    format!(
        "/etc/zdn/runtime/{}/zdn {entrypoint} --protocol {protocol} --manifest {path} {operation}",
        host.helper.sha256
    )
}

fn node_command(
    host: &HostInstallSpec,
    entrypoint: &str,
    protocol: &str,
    operation: &str,
) -> String {
    native_command(
        host,
        entrypoint,
        protocol,
        &format!(
            "/etc/zdn/runtime/manifests/{}",
            node_manifest(host).file_name().unwrap()
        ),
        operation,
    )
}

fn deployment_native(directory: &Path) -> Deployment {
    let mut team: TeamDefinition = serde_json::from_value(json!({
        "apiVersion":zdn::aws::TEAM_API_VERSION,"teamId":"private-team","revision":1,
        "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec",
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-private-team/pulumi/private-team","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap();
    team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
    team.deployment = Some(zdn::access::DeploymentAccess::managed(&team));
    let spec = zdn::infra::FoundationSpec {
        scope: team.scope(),
        network_id: "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153".parse().unwrap(),
        aws_profile: "developer".into(),
        ami_id: "ami-0123456789abcdef0".into(),
        availability_zone: "us-east-1a".into(),
        size: zdn::config::Size::Medium,
        retain_chain_disk: true,
    };
    let mut deployment = Deployment::new(spec, team).unwrap();
    let request = zdn::devnet::ClusterRequest {
        build: None,
        artifact_set: None,
        installer_fetch_protocol: Some(zdn::host::installer_bootstrap::PROTOCOL.into()),
        native_runtime_protocol: Some(zdn::host::runtime::PROTOCOL.into()),
        client_access: false,
        lightwallet: None,
        block_interval_seconds: Some(25),
        api_version: zdn::devnet::API_VERSION.into(),
        config_sha256: "a".repeat(64),
        manifest: serde_json::from_str::<zdn::chain::manifest::ConsensusManifest>(include_str!(
            "fixtures/chain-manifest/valid.json"
        ))
        .unwrap()
        .normalized()
        .unwrap(),
        image: zdn::image::ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
                "b".repeat(64)
            ),
            config_digest: format!("sha256:{}", "c".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: zdn::image::ImageProvenance::Release {
                revision: "d".repeat(40),
                version: "v0.0.1".into(),
            },
            capabilities: zdn::image::ImageCapabilities::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
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
                zdn::devnet::Artifact {
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
                zdn::cluster_infra::ClusterNodeOutputs {
                    node_id: node.node_id,
                    instance_id: format!("i-{:017x}", index + 1),
                    volume_id: format!("vol-{:017x}", index + 1),
                    private_ip: node.private_ip,
                },
            )
        })
        .collect();
    let first = &nodes["node-1"];
    deployment.outputs = Some(zdn::infra::FoundationOutputs {
        lightwallet: None,
        schema_version: zdn::infra::FOUNDATION_SCHEMA_VERSION,
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
        nodes,
    });
    deployment.stack_initialized = true;
    deployment.cluster = Some(request);
    stage(&mut deployment, directory);
    deployment
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// The same tiny synthetic bundle/OCI/ELF pattern used by tests/devnet.rs.
fn stage(deployment: &mut Deployment, directory: &Path) {
    let request = deployment.cluster.as_mut().unwrap();
    let blocks = tempfile::tempdir().unwrap();
    let genesis = b"synthetic genesis, not an encoded block";
    fs::write(blocks.path().join("0000000000.bin"), genesis).unwrap();
    let mut manifest = serde_json::to_value(&request.manifest).unwrap();
    manifest["genesis"] = json!({"height":0,"hash":format!("{:064x}",1),"bytesSha256":sha(genesis),"bytesLength":genesis.len()});
    manifest["seedBlocks"] = json!([]);
    manifest["checkpoints"] = json!([{"height":0,"hash":format!("{:064x}",1)}]);
    request.manifest = serde_json::from_value(manifest).unwrap();
    let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux",
        "config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["zakurad"],"Cmd":[],"Volumes":null,"OnBuild":null},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}})).unwrap();
    let image_manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",sha(&config)),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":123}]})).unwrap();
    request.image.config_digest = format!("sha256:{}", sha(&config));
    request.image.image = format!(
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
        sha(&image_manifest)
    );
    let mut helper = vec![0; 64];
    helper[..4].copy_from_slice(b"\x7fELF");
    helper[4] = 2;
    helper[5] = 1;
    helper[16..18].copy_from_slice(&2_u16.to_le_bytes());
    helper[18..20].copy_from_slice(&62_u16.to_le_bytes());
    let artifacts = directory.join("artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    for (name, bytes) in [
        (
            "manifest.json",
            serde_json::to_vec(&request.manifest).unwrap(),
        ),
        ("image.json", serde_json::to_vec(&request.image).unwrap()),
        ("image-config.json", config),
        ("image-manifest.json", image_manifest),
        ("zdn", helper),
    ] {
        fs::write(artifacts.join(name), bytes).unwrap();
    }
    zdn::chain::artifacts::import_bundle(
        &request.manifest,
        blocks.path(),
        &artifacts.join("chain.tar"),
    )
    .unwrap();
    for (name, artifact) in &mut request.artifacts {
        let bytes = fs::read(artifacts.join(name)).unwrap();
        artifact.sha256 = sha(&bytes);
        artifact.bytes = bytes.len() as u64;
    }
    for node in deployment.outputs.as_ref().unwrap().nodes.values() {
        let host = request
            .host_spec(&deployment.spec, &deployment.team, node)
            .unwrap();
        let script = zdn::host::runtime::bootstrap::render(&node_manifest(&host)).unwrap();
        fs::write(
            directory.join(format!("{}-install.sh", node.node_id)),
            &script,
        )
        .unwrap();
        let object = zdn::host::S3Object {
            bucket: deployment.team.backend_bucket().unwrap().into(),
            key: format!(
                "{}{}/{}-install.sh",
                zdn::devnet::artifact_prefix(&deployment.team, &deployment.spec),
                sha(script.as_bytes()),
                node.node_id
            ),
            sha256: sha(script.as_bytes()),
            bytes: script.len() as u64,
            owner_account: deployment.team.aws.account_id.clone(),
            region: deployment.team.aws.region.clone(),
        };
        saved_command(
            directory,
            &format!("{}-install-command.json", node.node_id),
            &node.instance_id,
            &zdn::host::installer_bootstrap::render_selected(
                zdn::host::installer_bootstrap::PROTOCOL,
                &object,
                7200,
            )
            .unwrap(),
            7200,
        );
    }
    let producer_script = {
        let node = &deployment.outputs.as_ref().unwrap().nodes["node-1"];
        let host = request
            .host_spec(&deployment.spec, &deployment.team, node)
            .unwrap();
        let manifest = zdn::host::runtime::Manifest::new(
            host.clone(),
            zdn::host::runtime::Selection {
                protocol: zdn::host::runtime::PROTOCOL.into(),
                helper: host.helper.clone(),
            },
        )
        .unwrap();
        format!("/etc/zdn/runtime/{}/zdn __host-runtime --protocol zdn-host-runtime/v1alpha1 --manifest /etc/zdn/runtime/manifests/{} start-producer", host.helper.sha256, manifest.file_name().unwrap())
    };
    saved_command(
        directory,
        "node-1-start-producer-command.json",
        &deployment.outputs.as_ref().unwrap().nodes["node-1"].instance_id,
        &producer_script,
        720,
    );
}

// Populate historical receipts through the real public SSM journal writer.
fn saved_command(directory: &Path, name: &str, instance: &str, script: &str, timeout: u32) {
    #[derive(Default)]
    struct Saved(RefCell<Value>);
    impl AwsApi for Saved {
        fn call(&self, _: &str, operation: &str, mut input: Value, _: &[String]) -> Result<Value> {
            match operation {
                "send-command" => {
                    input["CommandId"] = json!(uuid::Uuid::new_v4());
                    *self.0.borrow_mut() = input.clone();
                    Ok(json!({"Command":input}))
                }
                "get-command-invocation" => {
                    let c = self.0.borrow();
                    Ok(
                        json!({"CommandId":c["CommandId"],"InstanceId":input["InstanceId"],
                            "Comment":c["Comment"],"DocumentName":c["DocumentName"],"DocumentVersion":c["DocumentVersion"],
                            "Status":"Success","ResponseCode":0,"StandardOutputContent":"{}"}),
                    )
                }
                _ => panic!("unexpected saved fixture operation"),
            }
        }
    }
    zdn::ssm::execute(
        &Saved::default(),
        instance,
        script,
        &directory.join(name),
        timeout,
        &Clock::default(),
        &mut || Ok(()),
    )
    .unwrap();
}

fn aws(deployment: &Deployment) -> Aws<'_> {
    Aws {
        hosts: deployment
            .outputs
            .as_ref()
            .unwrap()
            .nodes
            .values()
            .map(|node| {
                let host = deployment
                    .cluster
                    .as_ref()
                    .unwrap()
                    .host_spec(&deployment.spec, &deployment.team, node)
                    .unwrap();
                let hash = host.install_sha256().unwrap();
                (node.instance_id.clone(), (host, hash))
            })
            .collect(),
        native_commands: deployment
            .outputs
            .as_ref()
            .unwrap()
            .nodes
            .values()
            .map(|node| {
                let host = deployment
                    .cluster
                    .as_ref()
                    .unwrap()
                    .host_spec(&deployment.spec, &deployment.team, node)
                    .unwrap();
                node_command(
                    &host,
                    "__host-runtime",
                    zdn::host::runtime::PROTOCOL,
                    "observe",
                )
            })
            .collect(),
        ..Default::default()
    }
}

fn stage_service(
    deployment: &Deployment,
    directory: &Path,
    stem: &str,
    instance: &str,
    script: &str,
    timeout: u32,
) {
    fs::write(directory.join(format!("{stem}-install.sh")), script).unwrap();
    let object = zdn::host::S3Object {
        bucket: deployment.team.backend_bucket().unwrap().into(),
        key: format!(
            "{}{}/{stem}-install.sh",
            zdn::devnet::artifact_prefix(&deployment.team, &deployment.spec),
            sha(script.as_bytes())
        ),
        sha256: sha(script.as_bytes()),
        bytes: script.len() as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    };
    saved_command(
        directory,
        &format!("{stem}-install-command.json"),
        instance,
        &zdn::host::installer_bootstrap::render_selected(
            zdn::host::installer_bootstrap::PROTOCOL,
            &object,
            timeout,
        )
        .unwrap(),
        timeout,
    );
}

fn enable_lightwallet(
    deployment: &mut Deployment,
    directory: &Path,
) -> zdn::lightwallet_service::LightwalletInstallSpec {
    use zdn::{cluster_infra::*, lightwallet_image as image, lightwallet_service as service};
    const GIB: u64 = 1024 * 1024 * 1024;
    let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux",
        "config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Entrypoint":["lightwalletd"],"Cmd":["--help"],"WorkingDir":"/srv/lightwalletd"},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","b".repeat(64))]}})).unwrap();
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",sha(&config)),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","c".repeat(64)),"size":1234}]})).unwrap();
    let record = image::ImageRecord {
        api_version: image::API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/lightwalletd@sha256:{}",
            sha(&manifest)
        ),
        config_digest: format!("sha256:{}", sha(&config)),
        platform: "linux/amd64".into(),
        source_revision: image::SOURCE_REVISION.into(),
        source_version: image::SOURCE_VERSION.into(),
        protocol_revision: image::PROTOCOL_REVISION.into(),
        protocol_version: image::PROTOCOL_VERSION.into(),
        binary_path: image::BINARY_PATH.into(),
        environment_launcher: image::ENVIRONMENT_LAUNCHER.into(),
    };
    image::validate_artifacts(&record, &manifest, &config, None).unwrap();
    let request = deployment.cluster.as_mut().unwrap();
    request.lightwallet = Some(zdn::devnet::LightwalletDeployment {
        allocation: LightwalletAllocation::for_size(deployment.spec.size),
        image: record.clone(),
        capacity_protocol: Some(zdn::host::CAPACITY_PROTOCOL.into()),
    });
    for (name, bytes) in [
        (
            "lightwallet-image.json",
            serde_json::to_vec(&record).unwrap(),
        ),
        ("lightwallet-image-manifest.json", manifest),
        ("lightwallet-image-config.json", config),
    ] {
        request.artifacts.insert(
            name.into(),
            zdn::devnet::Artifact {
                sha256: sha(&bytes),
                bytes: bytes.len() as u64,
            },
        );
        fs::write(directory.join("artifacts").join(name), bytes).unwrap();
    }
    let selected = request.topology().unwrap().lightwallet_node().node_id;
    let outputs = deployment.outputs.as_mut().unwrap();
    let cache = ClusterLightwalletOutputs {
        node_id: selected.clone(),
        instance_id: outputs.nodes[&selected].instance_id.clone(),
        cache_volume_id: "vol-00000000000000099".into(),
        cache_size_gib: 40,
    };
    outputs.lightwallet = Some(cache.clone());
    let request = deployment.cluster.as_ref().unwrap();
    let allocation = &request.lightwallet.as_ref().unwrap().allocation;
    // The exact measured host used by the lifecycle fixture, with real allocation validation.
    let observation: zdn::infra::HostObservation = serde_json::from_value(json!({"mem_total_bytes":31*GIB,"ancestor_memory_limits_bytes":[],"online_cpu_count":4,"affinity_cpu_count":4,"ancestor_cpu_quota_millis":[]})).unwrap();
    let limits = allocation
        .effective_limits(deployment.spec.size, &observation)
        .unwrap();
    fs::write(directory.join("lightwallet-capacity.json"), serde_json::to_vec(&json!({"apiVersion":"zdn-lightwallet-capacity/v1alpha1","deploymentId":deployment.spec.network_id,"instanceId":cache.instance_id,"requestSha256":sha(&serde_json::to_vec(request).unwrap()),"observation":observation,"limits":limits})).unwrap()).unwrap();
    let capacity = zdn::host::capacity_bootstrap::render(
        &request
            .s3_object(&deployment.team, &deployment.spec, "zdn")
            .unwrap(),
    )
    .unwrap();
    saved_command(
        directory,
        "lightwallet-capacity-command.json",
        &cache.instance_id,
        &capacity,
        1200,
    );
    let authorization = cache_proof(deployment, directory);
    let mut host = request
        .host_spec(
            &deployment.spec,
            &deployment.team,
            &deployment.outputs.as_ref().unwrap().nodes[&selected],
        )
        .unwrap();
    host.memory_bytes = limits.node_memory_bytes;
    host.cpu_millis = limits.node_cpu_millis;
    let rendered_host = zdn::host::runtime::bootstrap::render(&node_manifest(&host)).unwrap();
    // Re-stage this synthetic installation with its measured allocation before
    // invoking health; the initial node-only journal pins different limits.
    fs::remove_file(directory.join(format!("{selected}-install-command.json"))).unwrap();
    stage_service(
        deployment,
        directory,
        &selected,
        &cache.instance_id,
        &rendered_host,
        7200,
    );
    let spec = service::LightwalletInstallSpec {
        api_version: service::INSTALL_API_VERSION.into(),
        host,
        service: service::LightwalletServiceSpec {
            api_version: service::API_VERSION.into(),
            image: record.image,
            source_revision: record.source_revision,
            cache_volume_id: cache.cache_volume_id,
            cache_bytes: u64::from(cache.cache_size_gib) * GIB,
            memory_bytes: allocation.service_memory_bytes,
            cpu_millis: allocation.service_cpu_millis,
            host_observation: observation,
        },
        new_volume: Some(authorization),
        image_record: request
            .s3_object(&deployment.team, &deployment.spec, "lightwallet-image.json")
            .unwrap(),
        image_manifest: request
            .s3_object(
                &deployment.team,
                &deployment.spec,
                "lightwallet-image-manifest.json",
            )
            .unwrap(),
        image_config: request
            .s3_object(
                &deployment.team,
                &deployment.spec,
                "lightwallet-image-config.json",
            )
            .unwrap(),
    };
    let rendered = service::native::bootstrap(&lightwallet_manifest(&spec)).unwrap();
    stage_service(
        deployment,
        directory,
        "lightwallet",
        &cache.instance_id,
        &rendered,
        7200,
    );
    spec
}

// Same offline empty-stack creation/checkpoint/EC2 evidence as the adapter's
// write_lightwallet_proof_fixture. Field order matters for the intent hash.
fn cache_proof(deployment: &Deployment, directory: &Path) -> zdn::host::NewVolumeAuthorization {
    use serde::Serialize;
    use zdn::cluster_infra::*;
    #[derive(Serialize)]
    struct Resource {
        volume_urn: String,
        host_urn: String,
        attachment_urn: String,
        tags: BTreeMap<String, String>,
    }
    #[derive(Serialize)]
    struct Cache {
        node_id: String,
        size_gib: u32,
        resource: Resource,
    }
    #[derive(Serialize)]
    struct Intent {
        version: u32,
        request_sha256: String,
        started_at: u64,
        availability_zone: String,
        size_gib: u32,
        nodes: BTreeMap<String, Resource>,
        lightwallet: Option<Cache>,
    }
    let request = deployment.cluster.as_ref().unwrap();
    let program = deployment.render().unwrap();
    let prefix = format!(
        "urn:pulumi:zdn-{}::{}::",
        deployment.spec.network_id.simple(),
        program.name
    );
    let resource = |disk: &str, host: &str, attachment: &str| Resource {
        volume_urn: format!(
            "{prefix}aws:ebs/volume:Volume::{}",
            program.resources[disk].name
        ),
        host_urn: format!(
            "{prefix}aws:ec2/instance:Instance::{}",
            program.resources[host].name
        ),
        attachment_urn: format!(
            "{prefix}aws:ec2/volumeAttachment:VolumeAttachment::{}",
            program.resources[attachment].name
        ),
        tags: serde_json::from_value(
            serde_json::to_value(&program.resources[disk]).unwrap()["properties"]["tags"].clone(),
        )
        .unwrap(),
    };
    let nodes = request
        .topology()
        .unwrap()
        .nodes()
        .into_iter()
        .map(|node| {
            (
                node.node_id,
                resource(&node.volume_key, &node.host_key, &node.attachment_key),
            )
        })
        .collect();
    let selected = request.topology().unwrap().lightwallet_node();
    let cache = deployment
        .outputs
        .as_ref()
        .unwrap()
        .lightwallet
        .as_ref()
        .unwrap();
    let intent = Intent {
        version: 1,
        request_sha256: sha(&serde_json::to_vec(&(
            deployment.owner_id,
            &deployment.spec,
            &deployment.team,
            request,
        ))
        .unwrap()),
        started_at: 1_792_083_600,
        availability_zone: deployment.spec.availability_zone.clone(),
        size_gib: deployment.spec.size.allocation().chain_disk_gib,
        nodes,
        lightwallet: Some(Cache {
            node_id: selected.node_id,
            size_gib: cache.cache_size_gib,
            resource: resource(
                LIGHTWALLET_CACHE_DISK,
                &selected.host_key,
                LIGHTWALLET_CACHE_ATTACHMENT,
            ),
        }),
    };
    let expected = &intent.lightwallet.as_ref().unwrap().resource;
    let properties = json!({"encrypted":true,"size":cache.cache_size_gib,"availabilityZone":deployment.spec.availability_zone,"tags":expected.tags});
    let mut outputs = properties.clone();
    outputs["id"] = json!(cache.cache_volume_id);
    outputs["snapshotId"] = json!("");
    outputs["createTime"] = json!("2026-10-15T17:00:03Z");
    outputs["kmsKeyId"] = json!("arn:aws:kms:us-east-1:123456789012:key/test");
    let attachment = json!({"volumeId":cache.cache_volume_id,"instanceId":cache.instance_id,"deviceName":LIGHTWALLET_CACHE_DEVICE});
    let checkpoint = json!({"version":3,"deployment":{"resources":[
        {"urn":expected.volume_urn,"custom":true,"type":"aws:ebs/volume:Volume","id":cache.cache_volume_id,"created":"2026-10-15T17:00:13.524241Z","inputs":properties,"outputs":outputs},
        {"urn":expected.host_urn,"custom":true,"type":"aws:ec2/instance:Instance","id":cache.instance_id,"created":"2026-10-15T17:01:00Z","outputs":{"id":cache.instance_id}},
        {"urn":expected.attachment_urn,"custom":true,"type":"aws:ec2/volumeAttachment:VolumeAttachment","id":"vai-1","created":"2026-10-15T17:01:03Z","inputs":attachment,"outputs":attachment}
    ]}});
    let volume = json!({"VolumeId":cache.cache_volume_id,"Size":cache.cache_size_gib,"Encrypted":true,"AvailabilityZone":deployment.spec.availability_zone,"SnapshotId":"","State":"in-use","KmsKeyId":"arn:aws:kms:us-east-1:123456789012:key/test","CreateTime":"2026-10-15T17:00:03+00:00",
        "Tags":expected.tags.iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>(),
        "Attachments":[{"VolumeId":cache.cache_volume_id,"InstanceId":cache.instance_id,"Device":LIGHTWALLET_CACHE_DEVICE,"State":"attached"}]});
    let authorization = zdn::host::NewVolumeAuthorization {
        api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
        volume_id: cache.cache_volume_id.clone(),
        instance_id: cache.instance_id.clone(),
        created_at: "2026-10-15T17:00:03+00:00".into(),
        size_bytes: u64::from(cache.cache_size_gib) * 1024 * 1024 * 1024,
        creation_intent_sha256: sha(&serde_json::to_vec(&intent).unwrap()),
        checkpoint_sha256: sha(&serde_json::to_vec(&checkpoint).unwrap()),
    };
    for (name, value) in [
        (
            "new-volume-creation.json",
            serde_json::to_value(intent).unwrap(),
        ),
        ("lightwallet-new-volume-checkpoint.json", checkpoint),
        (
            "lightwallet-new-volume.json",
            json!({"authorization":authorization,"observed_at":1_792_083_720_u64,"volume":volume}),
        ),
    ] {
        fs::write(directory.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
    }
    authorization
}

fn enable_gateway(deployment: &mut Deployment, directory: &Path) -> (String, Value) {
    deployment.cluster.as_mut().unwrap().client_access = true;
    let node = &deployment.outputs.as_ref().unwrap().nodes["node-1"];
    let host = deployment
        .cluster
        .as_ref()
        .unwrap()
        .host_spec(&deployment.spec, &deployment.team, node)
        .unwrap();
    let manifest = node_manifest(&host);
    let rendered = node_command(
        &host,
        "__client-gateway",
        zdn::client_gateway::native::PROTOCOL,
        "install",
    );
    stage_service(
        deployment,
        directory,
        "client-rpc",
        &node.instance_id,
        &rendered,
        600,
    );
    // Same service identity and report contract as the lifecycle adapter fixture.
    let report = json!({"apiVersion":zdn::client_gateway::OBSERVATION_API_VERSION,
        "deploymentId":host.deployment_id,"nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint,
        "serviceSha256":zdn::client_gateway::native::service_sha256(&manifest).unwrap(),
        "endpoint":zdn::client_gateway::ENDPOINT,"status":"ready"});
    zdn::client_gateway::native::validate_observation(&report, &manifest).unwrap();
    (
        node_command(
            &host,
            "__client-gateway",
            zdn::client_gateway::native::PROTOCOL,
            "observe",
        ),
        report,
    )
}

fn lightwallet_manifest(
    spec: &zdn::lightwallet_service::LightwalletInstallSpec,
) -> zdn::lightwallet_service::native::Manifest {
    zdn::lightwallet_service::native::Manifest::new(
        spec.clone(),
        node_manifest(&spec.host),
        zdn::host::runtime::Selection {
            protocol: zdn::lightwallet_service::native::PROTOCOL.into(),
            helper: spec.host.helper.clone(),
        },
    )
    .unwrap()
}

#[test]
fn enabled_lightwallet_requires_fresh_service_identity_and_verified_readiness() {
    use zdn::lightwallet_service as service;
    let directory = tempfile::tempdir().unwrap();
    let mut deployment = deployment(directory.path());
    let gateway = enable_gateway(&mut deployment, directory.path());
    let spec = enable_lightwallet(&mut deployment, directory.path());
    let manifest = lightwallet_manifest(&spec);
    let service_sha256 = service::render_service(&spec.host, &spec.service)
        .unwrap()
        .service_sha256;
    let ready = json!({"apiVersion":service::OBSERVATION_API_VERSION,"deploymentId":spec.host.deployment_id,
        "nodeId":spec.host.node_id,"installSha256":manifest.install_sha256,"serviceSha256":service_sha256,
        "cacheVolumeId":spec.service.cache_volume_id,"image":spec.service.image,"status":"ready",
        "readiness":{"apiVersion":zdn::lightwallet::API_VERSION,"consensusFingerprint":spec.host.consensus_fingerprint,
            "protocolVersion":zdn::lightwallet::PROTOCOL_VERSION,"launchReady":false,"paymentQualification":"pending",
            "ironwoodTreeVerified":true,"compactDataVerified":true,"lagBlocks":0,"checkedCompactBlocks":4},
        "paymentQualification":"pending","launchReady":false});
    service::validate_observation(&ready, &spec).unwrap();
    let mut aws = aws(&deployment);
    aws.services.insert("clientGateway".into(), gateway);
    aws.native_commands.push(node_command(
        &spec.host,
        "__host-runtime",
        zdn::host::runtime::PROTOCOL,
        "observe",
    ));
    aws.hosts.insert(
        deployment.outputs.as_ref().unwrap().nodes[&spec.host.node_id]
            .instance_id
            .clone(),
        (spec.host.clone(), spec.host.install_sha256().unwrap()),
    );
    aws.services.insert(
        "lightwallet".into(),
        (
            native_command(
                &spec.host,
                "__lightwallet-runtime",
                service::native::PROTOCOL,
                &format!(
                    "{}/{}",
                    service::native::MANIFEST_DIRECTORY,
                    manifest.file_name().unwrap()
                ),
                "observe",
            ),
            ready,
        ),
    );
    let check = |aws: &Aws<'_>| {
        health::check(
            aws,
            &deployment,
            directory.path(),
            Options::default(),
            &Clock::default(),
            &AtomicBool::new(false),
        )
        .unwrap()
    };
    let report = check(&aws);
    assert!(report.ready);
    assert_eq!(report.checks.len(), 6);
    assert_eq!(report.checks["lightwallet"].status, Status::Ready);
    assert!(report.checks["lightwallet"].fresh);
    assert!(report.checks["lightwallet"].observed_at.is_some());
    let sends = aws.commands.borrow().len();
    aws.stopped_service.set(Some("lightwallet"));
    let report = check(&aws);
    assert!(!report.ready);
    assert_eq!(report.checks["lightwallet"].status, Status::NotReady);
    assert!(aws.commands.borrow().len() > sends);
    for field in [
        "deploymentId",
        "nodeId",
        "installSha256",
        "serviceSha256",
        "cacheVolumeId",
        "image",
    ] {
        aws.invalid_service.set(Some(("lightwallet", field)));
        let report = check(&aws);
        assert!(!report.ready, "{field}");
        assert_eq!(
            report.checks["lightwallet"].status,
            Status::Invalid,
            "{field}"
        );
        for key in ["node-1", "node-2", "node-3", "producer", "clientGateway"] {
            assert_eq!(report.checks[key].status, Status::Ready, "{field}: {key}");
        }
        assert!(!serde_json::to_string(&report).unwrap().contains("private"));
    }
    aws.invalid_service.set(None);
    aws.stopped_service.set(None);
    aws.services.get_mut("lightwallet").unwrap().1["readiness"]["compactDataVerified"] =
        json!(false);
    let report = check(&aws);
    assert!(!report.ready);
    assert_eq!(report.checks["lightwallet"].status, Status::Invalid);
    assert!(!report.launch_ready);
    assert_eq!(report.payment_qualification, "pending");
}

#[test]
fn enabled_gateway_is_fresh_and_stopped_or_foreign_services_do_not_affect_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let mut deployment = deployment(directory.path());
    let gateway = enable_gateway(&mut deployment, directory.path());
    let mut aws = aws(&deployment);
    aws.services.insert("clientGateway".into(), gateway);
    let clock = Clock::default();
    let check = || {
        health::check(
            &aws,
            &deployment,
            directory.path(),
            Options::default(),
            &clock,
            &AtomicBool::new(false),
        )
        .unwrap()
    };
    let ready = check();
    assert!(ready.ready);
    assert_eq!(ready.checks.len(), 5);
    assert_eq!(ready.checks["clientGateway"].status, Status::Ready);
    assert!(ready.checks["clientGateway"].fresh);
    assert!(ready.checks["clientGateway"].observed_at.is_some());
    let sends = aws.commands.borrow().len();
    aws.stopped_service.set(Some("clientGateway"));
    let stopped = check();
    assert!(!stopped.ready);
    assert_eq!(stopped.checks["clientGateway"].status, Status::NotReady);
    assert!(aws.commands.borrow().len() > sends);
    for field in [
        "deploymentId",
        "nodeId",
        "consensusFingerprint",
        "serviceSha256",
        "endpoint",
    ] {
        aws.invalid_service.set(Some(("clientGateway", field)));
        let invalid = check();
        assert!(!invalid.ready, "{field}");
        assert_eq!(
            invalid.checks["clientGateway"].status,
            Status::Invalid,
            "{field}"
        );
        for key in ["node-1", "node-2", "node-3", "producer"] {
            assert_eq!(invalid.checks[key].status, Status::Ready, "{field}: {key}");
        }
        assert!(!serde_json::to_string(&invalid).unwrap().contains("private"));
        assert!(!invalid.launch_ready);
        assert_eq!(invalid.payment_qualification, "pending");
    }
}

#[test]
fn repeated_checks_observe_fresh_commands_and_never_reuse_saved_success() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment(directory.path());
    let aws = aws(&deployment);
    let clock = Clock::default();
    let cancel = AtomicBool::new(false);
    let first = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options::default(),
        &clock,
        &cancel,
    )
    .unwrap();
    assert!(first.ready);
    assert!(first.live_readiness_checked);
    assert_eq!(first.attempts, 1);
    assert_eq!(first.payment_qualification, "pending");
    assert!(!first.launch_ready);
    assert_eq!(first.checks.len(), 4);
    for key in ["node-1", "node-2", "node-3", "producer"] {
        assert_eq!(first.checks[key].status, Status::Ready);
        assert!(first.checks[key].fresh);
        assert!(first.checks[key].observed_at.is_some());
    }
    let sends = aws.commands.borrow().len();
    assert!(sends >= 3);
    aws.producer_stopped.set(true);
    clock.0.set(1);
    let second = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options::default(),
        &clock,
        &cancel,
    )
    .unwrap();
    assert!(!second.ready);
    assert!(aws.commands.borrow().len() > sends);
    assert_eq!(second.checks["producer"].status, Status::NotReady);
    assert!(!second.timed_out);
    assert!(!second.cancelled);
}

#[test]
fn native_health_uses_pinned_observers_and_rejects_legacy_receipt_reinterpretation() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment(directory.path());
    let aws = aws(&deployment);
    let report = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options::default(),
        &Clock::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(report.ready);
    assert_eq!(aws.commands.borrow().len(), 3);
    assert!(aws.commands.borrow().iter().all(|command| aws
        .native_commands
        .iter()
        .any(|s| command["Parameters"]["commands"][0] == *s)));
    let mut reinterpreted = deployment.clone();
    reinterpreted
        .cluster
        .as_mut()
        .unwrap()
        .native_runtime_protocol = None;
    let sends = aws.commands.borrow().len();
    assert!(health::check(
        &aws,
        &reinterpreted,
        directory.path(),
        Options::default(),
        &Clock::default(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert_eq!(aws.commands.borrow().len(), sends);
}

#[test]
fn legacy_metadata_remains_readable_but_health_never_calls_aws_or_changes_evidence() {
    fn snapshot(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(snapshot(&path));
            } else {
                files.insert(path.clone(), fs::read(path).unwrap());
            }
        }
        files
    }
    for missing in ["host", "installer", "capacity", "legacy"] {
        let directory = tempfile::tempdir().unwrap();
        let mut deployment = deployment(directory.path());
        if matches!(missing, "capacity" | "legacy") {
            enable_lightwallet(&mut deployment, directory.path());
        }
        let request = deployment.cluster.as_mut().unwrap();
        match missing {
            "host" => request.native_runtime_protocol = None,
            "installer" => request.installer_fetch_protocol = None,
            "legacy" => {
                request.native_runtime_protocol = None;
                request.installer_fetch_protocol = None;
                request.lightwallet.as_mut().unwrap().capacity_protocol = None;
            }
            _ => request.lightwallet.as_mut().unwrap().capacity_protocol = None,
        }
        // Complete historical selections are valid data; partially stripped native
        // selections are invalid, but neither may execute or rewrite evidence.
        let valid_metadata = matches!(missing, "host" | "legacy");
        assert_eq!(deployment.validate().is_ok(), valid_metadata);
        let bytes = serde_json::to_vec(&deployment).unwrap();
        fs::write(directory.path().join("deployment.json"), &bytes).unwrap();
        let historical: Deployment = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(historical.validate().is_ok(), valid_metadata);
        let before = snapshot(directory.path());
        let aws = Aws::default();
        assert!(
            health::check(
                &aws,
                &historical,
                directory.path(),
                Options::default(),
                &Clock::default(),
                &AtomicBool::new(false)
            )
            .is_err(),
            "{missing}"
        );
        assert!(aws.calls.borrow().is_empty(), "{missing}");
        assert_eq!(snapshot(directory.path()), before, "{missing}");
        assert_eq!(serde_json::to_vec(&historical).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn machine_cli_discovery_preserves_fresh_health_failures_and_inventory_boundaries() {
    use std::process::Command;
    use zdn::{
        foundation::DeploymentFile,
        state::{BindingContext, StateStore},
    };

    for format in ["json", "jsonl"] {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path().join("state")).unwrap();
        let network = "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153".parse().unwrap();
        let file = DeploymentFile::open(store.root(), network).unwrap();
        let deployment = deployment(file.directory());
        file.save(&deployment).unwrap();
        let saved = fs::read(file.directory().join("deployment.json")).unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let config = source.join("deleted-source.yaml");
        fs::write(&config, "fixture").unwrap();
        let context = BindingContext::new(&config, None, None, deployment.team.scope()).unwrap();
        store.bind_with_id(&context, "local", || network).unwrap();
        fs::remove_dir_all(source).unwrap();
        zdn::foundation::private_directory(&store.root().join("profiles")).unwrap();
        zdn::foundation::write_json(
            &store.root().join("profiles/local.json"),
            &json!({"team":deployment.team,"awsProfile":"developer"}),
        )
        .unwrap();
        let aws = aws(&deployment);
        let reports: BTreeMap<_, _> = aws
            .hosts
            .keys()
            .map(|id| (id.clone(), aws.report(id)))
            .collect();
        fs::write(
            root.path().join("reports.json"),
            serde_json::to_vec(&reports).unwrap(),
        )
        .unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        discovery_aws::install(&bin.join("aws"));

        for mode in [
            "ready",
            "not-ready",
            "denied",
            "timeout",
            "cancelled",
            "status",
        ] {
            fs::write(root.path().join("calls.jsonl"), "").unwrap();
            let status = mode == "status";
            let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
            command
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("HOME", root.path())
                .env("ZDN_DISCOVERY_FIXTURE", root.path())
                .env("ZDN_DISCOVERY_MODE", mode)
                .current_dir(root.path())
                .args([
                    "--format",
                    format,
                    "devnet",
                    if status { "status" } else { "health" },
                    "local",
                    "--profile",
                    "local",
                    "--state-dir",
                ])
                .arg(store.root());
            if !status {
                command.args([
                    "--timeout-seconds",
                    if mode == "timeout" { "1" } else { "10" },
                ]);
                if matches!(mode, "timeout" | "cancelled" | "denied") {
                    command.arg("--wait");
                }
            }
            let output = command.output().unwrap();
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.stderr.is_empty(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!text.contains("SECRET"));
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&text).unwrap()]
            } else {
                text.lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
            if format == "jsonl" {
                assert_eq!(records[0]["type"], "command-started");
                assert!(records[0]["networkId"].is_null());
            }
            let result = records.last().unwrap();
            assert_eq!(result["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(result["type"], "result");
            assert_eq!(
                result["command"],
                if status {
                    "devnet status"
                } else {
                    "devnet health"
                }
            );
            assert_eq!(result["networkId"], network.to_string(), "{mode}: {text}");
            assert!(result["operationId"].is_null());
            let data = &result["data"];
            assert_eq!(
                output.status.success(),
                matches!(mode, "ready" | "status"),
                "{mode}: {text}"
            );
            assert_eq!(
                result["outcome"],
                if output.status.success() {
                    "succeeded"
                } else {
                    "failed"
                }
            );
            let calls: Vec<Value> = fs::read_to_string(root.path().join("calls.jsonl"))
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            if status {
                assert_eq!(data["liveReadinessChecked"], false);
                assert_eq!(data["sharedBackendChecked"], false);
                assert!(data["inventory"]["shared_backend_preserved"].is_null());
                assert_eq!(
                    data["inventory"]["remaining_resources"],
                    json!(["instance:i-00000000000000002"])
                );
                assert_eq!(
                    data["savedOutputs"],
                    serde_json::to_value(&deployment.outputs).unwrap()
                );
                assert!(calls.iter().all(|c| c["service"] != "ssm"));
            } else {
                assert_eq!(data["apiVersion"], "zdn-health/v1alpha1");
                assert_eq!(data["ready"], mode == "ready");
                assert_eq!(data["paymentQualification"], "pending");
                assert_eq!(data["launchReady"], false);
                assert_eq!(data["cancelled"], mode == "cancelled");
                assert_eq!(data["timedOut"], mode == "timeout");
                assert_eq!(data["checks"].as_object().unwrap().len(), 4);
                if mode == "ready" {
                    assert_eq!(data["liveReadinessChecked"], true);
                    for check in data["checks"].as_object().unwrap().values() {
                        assert_eq!(check["status"], "ready");
                        assert_eq!(check["fresh"], true);
                    }
                } else {
                    assert_eq!(result["error"]["code"], "health-not-ready");
                    assert_eq!(result["error"]["retryClassification"], "blocked");
                    if mode == "not-ready" {
                        assert_eq!(data["checks"]["node-2"]["status"], "ready");
                        assert_eq!(data["checks"]["producer"]["status"], "not-ready");
                    } else if mode == "denied" {
                        assert_eq!(data["checks"]["node-1"]["status"], "unavailable");
                        assert_eq!(data["checks"]["node-1"]["code"], "authorization-denied");
                        assert_eq!(data["checks"]["node-1"]["fresh"], false);
                    }
                }
                assert!(calls
                    .iter()
                    .all(|c| c["service"] == "sts" || c["service"] == "ssm"));
                assert!(calls.iter().any(|c| c["operation"] == "send-command"));
            }
            assert_eq!(
                fs::read(file.directory().join("deployment.json")).unwrap(),
                saved
            );
        }
    }
}

#[test]
fn wrong_observation_identities_are_invalid_and_diagnostics_are_sanitized() {
    for field in [
        "deploymentId",
        "nodeId",
        "consensusFingerprint",
        "configSha256",
        "image",
        "installSha256",
        "updateId",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let deployment = deployment(directory.path());
        let aws = aws(&deployment);
        aws.bad_field.set(Some(field));
        let report = health::check(
            &aws,
            &deployment,
            directory.path(),
            Options::default(),
            &Clock::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(!report.ready, "accepted wrong {field}");
        assert_eq!(report.checks["node-1"].status, Status::Invalid, "{field}");
        assert!(!serde_json::to_string(&report).unwrap().contains("private"));
    }
}

#[test]
fn a_stopped_producer_does_not_invalidate_ready_nodes_or_request_activation() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment(directory.path());
    let aws = aws(&deployment);
    aws.producer_stopped.set(true);
    let report = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options::default(),
        &Clock::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(!report.ready);
    assert_eq!(report.checks["producer"].status, Status::NotReady);
    for key in ["node-1", "node-2", "node-3"] {
        assert_eq!(report.checks[key].status, Status::Ready);
    }
}

#[test]
fn a_single_unavailable_observation_is_not_ready_and_does_not_echo_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment(directory.path());
    let aws = aws(&deployment);
    aws.unavailable.set(1);
    let report = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options::default(),
        &Clock::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(!report.ready);
    assert_eq!(report.attempts, 1);
    assert_eq!(report.checks["node-1"].status, Status::Unavailable);
    assert!(report.checks["node-1"].code.is_some());
    assert!(!report.timed_out);
    assert!(!serde_json::to_string(&report).unwrap().contains("private"));
}

#[test]
fn wait_retries_not_ready_and_transient_unavailability() {
    for unavailable in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let deployment = deployment(directory.path());
        let aws = aws(&deployment);
        aws.producer_stopped.set(!unavailable);
        aws.recover_after_send.set(true);
        aws.unavailable.set(u32::from(unavailable));
        let clock = Clock::default();
        let report = health::check(
            &aws,
            &deployment,
            directory.path(),
            Options {
                wait: true,
                timeout_secs: 60,
            },
            &clock,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(report.ready);
        assert!(report.attempts > 1);
        assert!(!report.timed_out);
        assert!(clock.0.get() <= 60);
    }
}

#[test]
fn wait_stops_on_denial_invalid_results_and_terminal_remote_failures() {
    for (stage, failure, status, code) in [
        (
            "send",
            "AccessDeniedException",
            Status::Unavailable,
            "authorization-denied",
        ),
        (
            "poll",
            "denied",
            Status::Unavailable,
            "authorization-denied",
        ),
        ("poll", "identity", Status::Invalid, "invalid-invocation"),
        ("poll", "malformed", Status::Invalid, "invalid-output"),
        (
            "poll",
            "failed",
            Status::Unavailable,
            "remote-observation-failed",
        ),
        ("poll", "unknown", Status::Unavailable, "observation-failed"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut deployment = deployment(directory.path());
        let gateway = enable_gateway(&mut deployment, directory.path());
        let mut aws = aws(&deployment);
        aws.services.insert("clientGateway".into(), gateway);
        if stage == "send" {
            aws.send_error.set(Some(failure));
        } else {
            aws.invocation_error.set(Some(failure));
        }
        let clock = Clock::default();
        let report = health::check(
            &aws,
            &deployment,
            directory.path(),
            Options {
                wait: true,
                timeout_secs: 120,
            },
            &clock,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(!report.ready, "{stage}: {failure}");
        assert_eq!(report.attempts, 1, "retried {stage}: {failure}");
        assert!(!report.timed_out);
        assert!(!report.cancelled);
        for check in report.checks.values() {
            assert_eq!(check.status, status, "{stage}: {failure}");
            assert_eq!(check.code.as_deref(), Some(code), "{stage}: {failure}");
            assert!(!check.fresh);
            assert_eq!(check.observed_at, None);
        }
        assert!(clock.0.get() < 120);
        assert!(!serde_json::to_string(&report).unwrap().contains("private"));
    }
}

#[test]
fn wait_has_one_shared_deadline_not_one_timeout_per_node_or_retry() {
    let directory = tempfile::tempdir().unwrap();
    let deployment = deployment(directory.path());
    let aws = aws(&deployment);
    aws.producer_stopped.set(true);
    let clock = Clock::default();
    let report = health::check(
        &aws,
        &deployment,
        directory.path(),
        Options {
            wait: true,
            timeout_secs: 7,
        },
        &clock,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(!report.ready);
    assert!(report.timed_out);
    assert!(!report.cancelled);
    assert!(report.attempts > 1);
    assert_eq!(clock.0.get(), 7);
}

#[test]
fn cancellation_prevents_any_subsequent_observation_sends() {
    for initially_cancelled in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let deployment = deployment(directory.path());
        let cancel = AtomicBool::new(initially_cancelled);
        let mut aws = aws(&deployment);
        aws.cancel_after_send = Some(&cancel);
        let report = health::check(
            &aws,
            &deployment,
            directory.path(),
            Options {
                wait: true,
                timeout_secs: 60,
            },
            &Clock::default(),
            &cancel,
        )
        .unwrap();
        assert!(report.cancelled);
        assert!(!report.ready);
        assert!(!report.launch_ready);
        assert_eq!(
            aws.commands.borrow().len(),
            usize::from(!initially_cancelled)
        );
    }
}

#[test]
fn invalid_local_states_and_options_fail_before_any_aws_call() {
    for state in [
        "destroyed",
        "pending",
        "unprovisioned",
        "timeout-zero",
        "timeout-large",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut deployment = deployment(directory.path());
        let mut options = Options::default();
        match state {
            "destroyed" => deployment.destroyed = true,
            "pending" => deployment.unresolved_operation = Some(uuid::Uuid::new_v4()),
            "unprovisioned" => deployment.outputs = None,
            "timeout-zero" => options.timeout_secs = 0,
            _ => options.timeout_secs = 7201,
        }
        let aws = Aws::default();
        assert!(
            health::check(
                &aws,
                &deployment,
                directory.path(),
                options,
                &Clock::default(),
                &AtomicBool::new(false)
            )
            .is_err(),
            "{state}"
        );
        assert!(aws.calls.borrow().is_empty(), "{state}");
    }
}
