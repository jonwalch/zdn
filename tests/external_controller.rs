#![cfg(target_os = "linux")]
//! Offline controller/local read-only CLI contracts. No companion, node, Docker or AWS.
use serde_json::json;
use std::collections::BTreeMap;
use uuid::Uuid;
use zdn::{
    access::DeploymentAccess,
    aws::{TeamAws, TeamDefinition, TeamState},
    config::Size,
    devnet::{
        external::{artifact_limits, ExternalRequest},
        Artifact,
    },
    foundation::{external::ExternalDeployment, Deployment},
    host::external::{runtime, Manifest, Provisioning},
    image::{self, ImageCapabilities, ImageProvenance, ImageRecord},
    infra::{Definition, FoundationSpec},
    public_chain_adapter::{
        contract::{Compiled, Pin, RenderOptions},
        package::CoreTrust,
    },
    state::Scope,
};

fn request() -> ExternalRequest {
    let compiled = Compiled {
        schema: zdn::public_chain_adapter::contract::SCHEMA.into(),
        native_name: "Fixture".into(),
        native_fingerprint: "ab".repeat(32),
        expected_rules: json!({}),
        upgrades: vec![],
        seed_blocks: vec![],
        cargo_features: vec!["experimental-slh-dsa-b128s".into()],
        required_capabilities: vec![
            "native-managed-identity-v1".into(),
            "slh-dsa-b128s-v2".into(),
        ],
        transport_class: "large-hex-v1".into(),
    };
    let mut artifacts: BTreeMap<_, _> = artifact_limits()
        .into_keys()
        .map(|name| {
            (
                name,
                Artifact {
                    bytes: 1,
                    sha256: "12".repeat(32),
                },
            )
        })
        .collect();
    let compiled_pin = Pin::of(&serde_json::to_vec(&compiled).unwrap());
    artifacts.insert(
        "compiled.json".into(),
        Artifact {
            bytes: compiled_pin.bytes,
            sha256: compiled_pin.sha256,
        },
    );
    let image = ImageRecord {
        api_version: image::FEATURE_API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}",
            "12".repeat(32)
        ),
        config_digest: format!("sha256:{}", "12".repeat(32)),
        platform: "linux/amd64".into(),
        provenance: ImageProvenance::Release {
            revision: "ab".repeat(20),
            version: "v1.0.0".into(),
        },
        capabilities: ImageCapabilities::for_requirements(compiled.image_requirements().unwrap())
            .unwrap(),
        binary_path: image::NODE_BINARY.into(),
        environment_launcher: image::ENV_ENTRYPOINT.into(),
    };
    ExternalRequest {
        schema: zdn::devnet::external::SCHEMA.into(),
        config_sha256: "ab".repeat(32),
        trust: CoreTrust {
            package: Pin {
                bytes: 1,
                sha256: "12".repeat(32),
            },
            executable: Pin {
                bytes: 1,
                sha256: "12".repeat(32),
            },
            adapter_selection_sha256: "34".repeat(32),
        },
        compiled,
        image,
        build: None,
        node_count: 3,
        block_interval_seconds: 25,
        production_limits: None,
        artifacts,
    }
}

fn deployment() -> Deployment {
    let scope = Scope {
        team_id: "private-team".into(),
        account_id: "123456789012".into(),
        region: "us-east-1".into(),
    };
    let mut team = TeamDefinition {
        api_version: "zdn-team/v1alpha1".into(),
        team_id: scope.team_id.clone(),
        revision: 1,
        bootstrap_id: Uuid::new_v4(),
        aws: TeamAws {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
        },
        state: TeamState {
            backend: "s3://zdn-private-fixture/pulumi/private-team".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
        deployment: None,
    };
    team.deployment = Some(DeploymentAccess::managed(&team));
    team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
    Deployment::new(
        FoundationSpec {
            scope,
            network_id: Uuid::new_v4(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap()
}

fn source_preparation(
    deployment: &Deployment,
) -> zdn::foundation::external::source::SourcePreparation {
    use zdn::{
        build::{BuildContract, BuildRecipe},
        config::{ChainSelection, Config, Source},
        foundation::external::source,
    };
    let request = request();
    let mut config = Config::draft(
        "external-fixture".into(),
        "developer".into(),
        Source {
            path: Some("/never-opened/external-source".into()),
            ..Default::default()
        },
        Size::Medium,
    )
    .unwrap();
    config.services = zdn::config::ServicePreset::NodeOnly.services();
    config.chain = Some(ChainSelection::External {
        package_sha256: request.trust.package.sha256.clone(),
        adapter_selection_sha256: request.trust.adapter_selection_sha256.clone(),
        production_limits: None,
    });
    let mut contract = BuildContract {
        api_version: zdn::build::API_VERSION.into(),
        source_sha256: "ab".repeat(32),
        source_bytes: 1024,
        revision: "ab".repeat(20),
        recipe: BuildRecipe {
            dockerfile: "docker/Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
            cargo_features: vec![],
        },
        platform: "linux/amd64".into(),
        required_capabilities: ImageCapabilities::default(),
    };
    contract
        .require_external(&request.compiled.image_requirements().unwrap())
        .unwrap();
    source::SourcePreparation {
        schema: source::SCHEMA.into(),
        deployment_sha256: zdn::devnet::sha256(
            &serde_json::to_vec(&(&deployment.spec, &deployment.team, deployment.owner_id))
                .unwrap(),
        ),
        config,
        trust: serde_json::to_value(&request.trust).unwrap(),
        compiled_json: serde_json::to_string(&request.compiled).unwrap(),
        contract,
        artifacts: source::limits()
            .into_keys()
            .map(|name| (name.clone(), request.artifacts[&name].clone()))
            .collect(),
        native_port: 18233,
        reward_address: "tFixture".into(),
    }
}

#[test]
fn initial_external_source_binds_requirements_scope_and_runtime_before_execution() {
    let mut deployment = deployment();
    assert!(serde_json::to_value(&deployment)
        .unwrap()
        .get("external_source")
        .is_none());
    let preparation = source_preparation(&deployment);
    preparation.validate(&deployment).unwrap();
    deployment.external_source = Some(preparation.clone());
    deployment.validate().unwrap();
    assert!(!deployment.has_nodes());
    assert!(deployment.require_native_execution().is_err());
    let portable: Deployment =
        serde_json::from_slice(&serde_json::to_vec(&deployment).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(portable).unwrap(),
        serde_json::to_value(&deployment).unwrap()
    );

    let mut changed_owner = deployment.clone();
    changed_owner.owner_id = Uuid::new_v4();
    assert!(preparation.validate(&changed_owner).is_err());
    let mut changed = preparation.clone();
    changed.contract.required_capabilities = ImageCapabilities::default();
    assert!(changed.validate(&deployment).is_err());
    let mut changed = preparation.clone();
    changed.config.node.build.as_mut().unwrap().cargo_features = vec!["different-feature".into()];
    // Local archive/recipe admission also binds config; completed-image stage
    // cannot bless an arbitrary recipe merely because its requirements match.
    assert!(changed.validate(&deployment).is_err());
    let mut changed = preparation.clone();
    changed.config.network.mining.interval = "3601s".into();
    assert!(changed.validate(&deployment).is_err());
    let mut changed = preparation.clone();
    changed.config.network.nodes = 256;
    assert!(changed.validate(&deployment).is_err());
    let mut changed = preparation.clone();
    changed.artifacts.insert(
        "wallet.json".into(),
        Artifact {
            bytes: 1,
            sha256: "12".repeat(32),
        },
    );
    assert!(changed.validate(&deployment).is_err());
    let mut changed = preparation;
    changed.trust["adapterSelectionSha256"] = json!("ff".repeat(32));
    assert!(changed.validate(&deployment).is_err());
}

#[test]
fn external_update_operation_inputs_keep_image_and_source_receipt_pairs_valid() {
    use zdn::foundation_live::external::update::operation_inputs;
    let deployment = deployment();
    let input = request().bytes().unwrap();
    let image = operation_inputs(&deployment, &input, None).unwrap();
    image.validate().unwrap();
    assert!(image.source_manifest_sha256.is_none() && image.archive_sha256.is_none());
    // Preserve the established config hash serialization for saved source
    // update receipts while fixing only the invalid image-only source pair.
    assert_eq!(
        image.config_sha256,
        zdn::devnet::sha256(&serde_json::to_vec(&(deployment.spec.clone(), &input)).unwrap())
    );
    let archive = "ab".repeat(32);
    let source = operation_inputs(&deployment, &input, Some(&archive)).unwrap();
    source.validate().unwrap();
    assert_eq!(source.config_sha256, image.config_sha256);
    assert_eq!(
        source.source_manifest_sha256,
        Some(zdn::devnet::sha256(&input))
    );
    assert_eq!(source.archive_sha256, Some(archive));
    assert_ne!(
        operation_inputs(&deployment, b"different immutable image intent", None)
            .unwrap()
            .config_sha256,
        image.config_sha256
    );
    assert!(operation_inputs(&deployment, &input, Some("invalid-archive-pin")).is_err());
}

#[test]
fn initial_external_source_record_recovers_only_exact_atomically_published_owner() {
    use zdn::foundation::external::source::{SourcePreparation, FILE, ROOT};
    let directory = tempfile::tempdir().unwrap();
    assert!(SourcePreparation::read(directory.path()).unwrap().is_none());
    let deployment = deployment();
    let preparation = source_preparation(&deployment);
    std::fs::create_dir(directory.path().join(ROOT)).unwrap();
    std::fs::write(
        directory.path().join(ROOT).join(FILE),
        serde_json::to_vec(&preparation).unwrap(),
    )
    .unwrap();
    let recovered = SourcePreparation::read(directory.path()).unwrap().unwrap();
    recovered.validate(&deployment).unwrap();
    assert!(!directory.path().join(FILE).exists()); // no repair/effect on read
    let mut altered = preparation.clone();
    altered.reward_address = "tOther".into();
    std::fs::write(
        directory.path().join(FILE),
        serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    // Both copies must match before artifact/build admission, even if each is
    // independently well-formed and no companion or checkout exists locally.
    assert!(altered
        .verify_local(&deployment, directory.path())
        .unwrap_err()
        .to_string()
        .contains("published external source preparation differs"));
}

#[test]
fn external_build_cleanup_uses_owned_journals_without_missing_companion_or_exporter() {
    use zdn::foundation::{
        self,
        external::source::{FILE, ROOT},
    };
    struct NoCloud;
    impl zdn::aws::AwsApi for NoCloud {
        fn call(
            &self,
            _: &str,
            _: &str,
            _: serde_json::Value,
            _: &[String],
        ) -> eyre::Result<serde_json::Value> {
            panic!("undispatched cleanup must not invoke AWS");
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let mut deployment = deployment();
    let preparation = source_preparation(&deployment);
    foundation::private_directory(&directory.path().join(ROOT)).unwrap();
    foundation::write_json(&directory.path().join(ROOT).join(FILE), &preparation).unwrap();
    foundation::write_json(&directory.path().join(FILE), &preparation).unwrap();
    let helper = directory.path().join("exporter-input");
    // Header-only, deliberately non-executable bytes: prepare_native only
    // snapshots/authenticates the helper; this test never submits/runs it.
    let mut elf = [0; 64];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[16] = 2;
    elf[18] = 62;
    std::fs::write(&helper, elf).unwrap();
    let build = directory.path().join(ROOT).join("build");
    zdn::build_job::prepare_native(&build, &deployment.team, &preparation.contract, &helper)
        .unwrap();
    deployment.external_source = Some(preparation);
    std::fs::remove_file(helper).unwrap();
    std::fs::remove_file(build.join("exporter")).unwrap();
    // No public package/companion or local checkout exists at all.
    assert!(!directory.path().join(ROOT).join("public").exists());
    let evidence =
        zdn::removal::external_build_evidence(&NoCloud, &deployment, directory.path(), true)
            .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0]["attempt"]["dispatched"], false);
    assert!(evidence[0]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| key.as_str().unwrap().starts_with("sources/runtime/")));
    let attempt_path = build.join("attempt.json");
    let mut attempt: serde_json::Value = foundation::read_json(&attempt_path).unwrap();
    attempt["dispatched"] = json!(true);
    attempt["sourceVersion"] = json!("source-version");
    attempt["exporter"]["version"] = json!("exporter-version");
    foundation::write_json(&attempt_path, &attempt).unwrap();
    assert!(
        zdn::removal::external_build_evidence(&NoCloud, &deployment, directory.path(), false)
            .unwrap_err()
            .to_string()
            .contains("active or uncertain")
    );
}

fn runtime() -> runtime::Manifest {
    let deployment = deployment();
    let request = request();
    let provisioning = Provisioning {
        schema: "zdn-external-provisioning/v1".into(),
        deployment_id: deployment.spec.network_id,
        node_id: "node-1".into(),
        volume_id: "vol-00000000000000001".into(),
        descriptor_sha256: request.artifacts["descriptor.json"].sha256.clone(),
        native_fingerprint: request.compiled.native_fingerprint.clone(),
        request: Pin::of(&request.bytes().unwrap()),
        new_volume: None,
    };
    let root = provisioning.node_root();
    let options = RenderOptions {
        deployment_id: deployment.spec.network_id.to_string(),
        node_id: "node-1".into(),
        role: "producer".into(),
        image_digest: request.image.manifest_digest().unwrap().into(),
        state_dir: format!("{root}/state"),
        identity_dir: format!("{root}/identity"),
        cookie_dir: format!("{root}/rpc"),
        rpc_listen: "127.0.0.1:18232".into(),
        native_listen: "0.0.0.0:18233".into(),
        expected_node_id: "ef".repeat(32),
        peers: vec![],
        reward_address: Some("tFixture".into()),
    };
    let config_toml = "structural fixture, never executed".to_string();
    let manifest = Manifest {
        schema: zdn::host::external::SCHEMA.into(),
        request: provisioning.request.clone(),
        trust: request.trust.clone(),
        objects: request.objects(&deployment.team, &deployment.spec).unwrap(),
        compiled_json: String::from_utf8(serde_json::to_vec(&request.compiled).unwrap()).unwrap(),
        native_inventory: Pin::of(b"complete fixture inventory"),
        options,
        config: Pin::of(config_toml.as_bytes()),
        config_toml,
    };
    runtime::Manifest {
        schema: runtime::SCHEMA.into(),
        provisioning,
        chain: manifest,
        image: request.image,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        cpu_millis: 1000,
        host_reserve_bytes: 1024 * 1024 * 1024,
        block_interval_seconds: Some(25),
        production_limits: None,
    }
}

#[test]
fn ordinary_bytes_omit_external_selection_and_external_ownership_needs_no_companion() {
    let mut deployment = deployment();
    let ordinary = serde_json::to_vec(&deployment).unwrap();
    assert!(serde_json::to_value(&deployment)
        .unwrap()
        .get("external")
        .is_none());
    let roundtrip: Deployment = serde_json::from_slice(&ordinary).unwrap();
    assert_eq!(serde_json::to_vec(&roundtrip).unwrap(), ordinary);
    deployment.external =
        Some(ExternalDeployment::new(request(), 19000, "tFixture".into()).unwrap());
    // All helper/adapter slots are one-byte structural pins, not installed tools.
    deployment.validate().unwrap();
    deployment.require_native_execution().unwrap();
    let program = deployment.render().unwrap();
    let Definition::SecurityGroup(group) = &program.resources["hostSecurityGroup"].definition
    else {
        panic!("group missing")
    };
    let udp = group
        .ingress
        .iter()
        .find(|rule| rule.protocol == "udp")
        .unwrap();
    assert_eq!((udp.from_port, udp.to_port), (19000, 19000));
    assert_eq!(
        udp.cidr_blocks,
        vec!["10.90.1.10/32", "10.90.1.11/32", "10.90.1.12/32"]
    );
    assert!(!group.ingress.iter().any(|rule| rule.protocol == "tcp"));
    assert_eq!(deployment.node_topology().unwrap().node_count(), 3);
    let mut altered = deployment.clone();
    altered.external.as_mut().unwrap().request_sha256 = "ff".repeat(32);
    assert!(altered.validate().is_err());
    let mut altered = deployment.clone();
    altered.external.as_mut().unwrap().node_count = 2;
    assert!(altered.validate().is_err());
    let mut altered = deployment.clone();
    altered.external.as_mut().unwrap().native_port = 0;
    assert!(altered.validate().is_err());
    let mut altered = deployment;
    altered.external.as_mut().unwrap().reward_address = "$(id)".into();
    assert!(altered.validate().is_err());
}

#[test]
fn external_commands_select_real_host_branch_and_readiness_is_fresh_bound_data() {
    use zdn::foundation_live::external::{runtime_script, validate_observation};
    let runtime = runtime();
    runtime.validate().unwrap();
    let install = runtime_script(&runtime, "install").unwrap();
    assert!(install.contains("__external-install --protocol zdn-external-runtime/v1"));
    assert!(!install.contains("__host-install --protocol"));
    let observe = runtime_script(&runtime, "observe").unwrap();
    assert!(observe.trim_end().ends_with(" observe"));
    assert!(!observe.contains("start-producer"));
    assert!(runtime_script(&runtime, "observe; id").is_err());
    let mut response = json!({"observation":runtime.observation("ready").unwrap(),
        "readiness":{"apiVersion":zdn::chain::readiness::API_VERSION,"consensusFingerprint":runtime.provisioning.native_fingerprint,"role":"producer","effectiveRulesVerified":true,"historyPresent":true,"miningReady":true,"launchReady":false},
        "producer":{"controllerLocked":true,"identity":runtime.producer_identity(),"intervalSecs":25,"phase":"waiting"}});
    validate_observation(&runtime, &response, true).unwrap();
    response["producer"]["controllerLocked"] = json!(false);
    assert!(validate_observation(&runtime, &response, true).is_err());
    validate_observation(&runtime, &response, false).unwrap();
    response["readiness"]["effectiveRulesVerified"] = json!(false);
    assert!(validate_observation(&runtime, &response, false).is_err());
    response["readiness"]["effectiveRulesVerified"] = json!(true);
    response["observation"]["runtime"] = json!(Pin::of(b"another runtime"));
    assert!(validate_observation(&runtime, &response, false).is_err());
}

#[test]
fn qualification_requests_bind_revision_query_and_small_response_without_cloud() {
    use zdn::host::external::runtime::qualification::{Action, Query, Request, SCHEMA};
    let runtime = runtime();
    let request = Request {
        schema: SCHEMA.into(),
        id: Uuid::new_v4(),
        runtime: Pin::of(&runtime.bytes().unwrap()),
        action: Action::Read { query: Query::Tip },
    };
    Request::from_slice(&request.bytes().unwrap()).unwrap();
    let script = request.render(&runtime).unwrap();
    assert!(script.contains("__external-qualification --protocol zdn-external-qualification/v1"));
    assert!(!script.contains("__external-install"));
    let response = json!({"schema":SCHEMA,"request":Pin::of(&request.bytes().unwrap()),"runtime":request.runtime,
        "deploymentId":runtime.provisioning.deployment_id,"nodeId":runtime.provisioning.node_id,
        "nativeInventory":runtime.chain.native_inventory,"result":{"height":105,"hash":"ab".repeat(32)}});
    request.validate_response(&runtime, &response).unwrap();
    for field in [
        "request",
        "runtime",
        "deploymentId",
        "nodeId",
        "nativeInventory",
    ] {
        let mut wrong = response.clone();
        wrong[field] = json!("foreign");
        assert!(
            request.validate_response(&runtime, &wrong).is_err(),
            "{field}"
        );
    }
    let mut wrong = request.clone();
    wrong.action = Action::Read {
        query: Query::Transaction {
            txid: "ab".repeat(32),
        },
    };
    assert!(wrong.validate_response(&runtime, &response).is_err());
    let mut large = response.clone();
    large["result"]["raw"] = json!("x".repeat(20 * 1024));
    assert!(request.validate_response(&runtime, &large).is_err());
    let mut raw = serde_json::to_value(&request).unwrap();
    raw["action"] = json!({"kind":"read","query":{"kind":"generate"}});
    assert!(Request::from_slice(&serde_json::to_vec(&raw).unwrap()).is_err());
    raw["action"] = json!({"kind":"read","query":{"kind":"tip","method":"submitblock"}});
    assert!(Request::from_slice(&serde_json::to_vec(&raw).unwrap()).is_err());
    for action in [
        Action::Produce {
            blocks: 0,
            height: 121,
            seconds: 30,
        },
        Action::Produce {
            blocks: 21,
            height: 121,
            seconds: 30,
        },
        Action::Produce {
            blocks: 1,
            height: 0,
            seconds: 30,
        },
        Action::Produce {
            blocks: 1,
            height: 121,
            seconds: 0,
        },
        Action::Produce {
            blocks: 1,
            height: 121,
            seconds: 601,
        },
    ] {
        wrong.action = action;
        assert!(wrong.bytes().is_err());
    }
    let (node, producer, gateway) = runtime.units().unwrap();
    assert!(!node.contains("Wants=zdn-producer.service"));
    assert!(producer.unwrap().contains(" produce\n"));
    let gateway = gateway.unwrap();
    assert!(!gateway.contains("BindsTo=zdn-node.service"));
    assert!(!gateway.contains("PartOf=zdn-node.service"));
    assert!(gateway.contains("After=zdn-node.service"));
}

#[test]
fn qualification_cli_renders_only_and_never_overwrites_a_saved_script() {
    use std::{fs, process::Command};
    use zdn::host::external::runtime::qualification::{Action, Request, SCHEMA};
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let request = Request {
        schema: SCHEMA.into(),
        id: Uuid::new_v4(),
        runtime: Pin::of(&runtime.bytes().unwrap()),
        action: Action::RestartNode,
    };
    fs::write(
        directory.path().join("runtime.json"),
        runtime.bytes().unwrap(),
    )
    .unwrap();
    fs::write(
        directory.path().join("request.json"),
        request.bytes().unwrap(),
    )
    .unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_zdn"))
            .current_dir(directory.path())
            .env_clear()
            .env("PATH", "")
            .args([
                "external",
                "control-script",
                "--manifest",
                "runtime.json",
                "--request",
                "request.json",
                "--output",
                "control.sh",
            ])
            .output()
            .unwrap()
    };
    let output = invoke();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let script = fs::read(directory.path().join("control.sh")).unwrap();
    assert_eq!(receipt["dispatched"], false);
    assert_eq!(
        receipt["request"],
        json!(Pin::of(&request.bytes().unwrap()))
    );
    assert_eq!(receipt["script"], json!(Pin::of(&script)));
    assert_eq!(script, request.render(&runtime).unwrap().as_bytes());
    assert!(!invoke().status.success());
    assert_eq!(
        fs::read(directory.path().join("control.sh")).unwrap(),
        script
    );
    fs::remove_file(directory.path().join("control.sh")).unwrap();
    fs::write(
        directory.path().join("request.json"),
        b"{\"action\":\"shell\"}",
    )
    .unwrap();
    assert!(!invoke().status.success());
    assert!(!directory.path().join("control.sh").exists());
}

#[test]
fn qualification_read_projects_real_wire_shapes_and_keeps_failures_distinct() {
    use std::time::Duration;
    use zdn::{
        chain::rpc::{NodeRpc, RpcError},
        host::external::runtime::qualification::{read, Query},
    };
    struct Rpc(Result<serde_json::Value, RpcError>);
    impl NodeRpc for Rpc {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
            _: Duration,
        ) -> Result<serde_json::Value, RpcError> {
            assert!([
                "getbestblockheightandhash",
                "getblockhash",
                "getrawtransaction",
                "gettxout"
            ]
            .contains(&method));
            if method == "getblockhash" {
                assert_eq!(params, json!([73]));
            }
            self.0.clone()
        }
    }
    let bytes: Vec<u8> = (0..32).collect();
    assert_eq!(
        read(&Query::Tip, &Rpc(Ok(json!({"height":105,"hash":bytes})))).unwrap(),
        json!({"height":105,"hash":"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"})
    );
    assert_eq!(
        read(
            &Query::BlockHash { height: 73 },
            &Rpc(Ok(json!("bc".repeat(32))))
        )
        .unwrap(),
        json!({"height":73,"hash":"bc".repeat(32)})
    );
    assert!(read(
        &Query::BlockHash { height: 73 },
        &Rpc(Ok(json!("BC".repeat(32))))
    )
    .is_err());
    let query = Query::Transaction {
        txid: "ab".repeat(32),
    };
    let tx = json!({"txid":"ab".repeat(32),"hex":"00010203","confirmations":2,"blockhash":"cd".repeat(32),"vout":["not exported"]});
    assert_eq!(
        read(&query, &Rpc(Ok(tx.clone()))).unwrap(),
        json!({"found":true,"txid":"ab".repeat(32),"bytes":4,
        "sha256":"054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8","confirmations":2,"blockHash":"cd".repeat(32)})
    );
    let mut wrong = tx.clone();
    wrong["txid"] = json!("ef".repeat(32));
    assert!(read(&query, &Rpc(Ok(wrong))).is_err());
    let mut wrong = tx;
    wrong["hex"] = json!("not-hex");
    assert!(read(&query, &Rpc(Ok(wrong))).is_err());
    assert_eq!(
        read(
            &query,
            &Rpc(Err(RpcError::Remote {
                code: -5,
                message: "private upstream text".into()
            }))
        )
        .unwrap(),
        json!({"found":false})
    );
    for error in [
        RpcError::Unauthorized,
        RpcError::Transport("private upstream text".into()),
        RpcError::Remote {
            code: -8,
            message: "other failure".into(),
        },
    ] {
        assert!(read(&query, &Rpc(Err(error))).is_err());
    }
    let output = Query::Output {
        txid: "ab".repeat(32),
        index: 3,
    };
    assert_eq!(
        read(&output, &Rpc(Ok(serde_json::Value::Null))).unwrap(),
        json!({"output":null})
    );
    let unspent = json!({"bestblock":"cd".repeat(32),"confirmations":3,"value":0.004,"coinbase":false,"scriptPubKey":{"hex":"5121","asm":"not exported"}});
    assert_eq!(
        read(&output, &Rpc(Ok(unspent))).unwrap(),
        json!({"output":{"bestblock":"cd".repeat(32),"confirmations":3,"value":0.004,"coinbase":false,"scriptHex":"5121"}})
    );
}

#[test]
fn qualification_journal_refuses_unknown_replay_and_returns_completed_original_only() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use zdn::host::{
        external::runtime::qualification::{Action, Request, SCHEMA},
        files::Directory,
    };
    let runtime = runtime();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let records = Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
    let request = Request {
        schema: SCHEMA.into(),
        id: Uuid::new_v4(),
        runtime: Pin::of(&runtime.bytes().unwrap()),
        action: Action::Produce {
            blocks: 1,
            height: 121,
            seconds: 30,
        },
    };
    assert!(request.begin(&records, &runtime).unwrap().is_none());
    drop(records);
    let records = Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
    assert!(request.begin(&records, &runtime).is_err());
    let response = json!({"schema":SCHEMA,"request":Pin::of(&request.bytes().unwrap()),"runtime":request.runtime,
        "deploymentId":runtime.provisioning.deployment_id,"nodeId":runtime.provisioning.node_id,
        "nativeInventory":runtime.chain.native_inventory,"result":{"producer":{"confirmedBlocks":1}}});
    let mut wrong = response.clone();
    wrong["nodeId"] = json!("node-2");
    assert!(request.complete(&records, &runtime, &wrong).is_err());
    request.complete(&records, &runtime, &response).unwrap();
    assert_eq!(
        request.begin(&records, &runtime).unwrap(),
        Some(response.clone())
    );
    let mut changed = request.clone();
    changed.action = Action::RestartNode;
    assert!(changed.begin(&records, &runtime).is_err());
    let mut unknown = request.clone();
    unknown.id = Uuid::new_v4();
    assert!(unknown.complete(&records, &runtime, &response).is_err());
    let mut foreign = runtime.clone();
    foreign.chain.native_inventory = Pin::of(b"wrong cohort");
    assert!(request.begin(&records, &foreign).is_err());
    // Unsafe saved evidence cannot become a cached success.
    let path = root.path().join(request.id.to_string()).join("result.json");
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("request.json", &path).unwrap();
    assert!(request.begin(&records, &runtime).is_err());
}

fn outputs(deployment: &Deployment) -> zdn::infra::FoundationOutputs {
    let nodes: BTreeMap<_, _> = deployment
        .node_topology()
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
                    private_ip: node.private_ip,
                    volume_id: format!("vol-{:017x}", index + 1),
                },
            )
        })
        .collect();
    let first = &nodes["node-1"];
    zdn::infra::FoundationOutputs {
        schema_version: 1,
        scope: deployment.spec.scope.clone(),
        network_id: deployment.spec.network_id,
        availability_zone: deployment.spec.availability_zone.clone(),
        vpc_id: "vpc-12345678".into(),
        private_subnet_id: "subnet-12345678".into(),
        instance_id: first.instance_id.clone(),
        private_ip: first.private_ip,
        chain_volume_id: first.volume_id.clone(),
        retain_chain_disk: true,
        security_group_id: "sg-12345678".into(),
        nat_gateway_id: "nat-12345678".into(),
        eip_allocation_id: "eipalloc-12345678".into(),
        nodes,
        lightwallet: None,
    }
}

#[test]
fn inventory_crash_window_accepts_only_the_single_pending_identity_edge() {
    use zdn::{
        foundation,
        native_peers::{NativeCohort, NativeInventoryStore, IDENTITY_SCHEMA},
    };
    let root = tempfile::tempdir().unwrap();
    let mut deployment = deployment();
    let request = request();
    deployment.external =
        Some(ExternalDeployment::new(request.clone(), 18233, "tFixture".into()).unwrap());
    deployment.outputs = Some(outputs(&deployment));
    let external = deployment.external.as_ref().unwrap();
    let cohort = NativeCohort::new(
        deployment.spec.network_id,
        request.artifacts["descriptor.json"].sha256.clone(),
        request.compiled.native_fingerprint.clone(),
        &external.topology().unwrap(),
        &deployment.outputs.as_ref().unwrap().nodes,
        external.listener().unwrap(),
    )
    .unwrap();
    let store =
        NativeInventoryStore::open(&root.path().join("native-inventory"), cohort.clone()).unwrap();
    let before = store.read().unwrap();
    foundation::private_directory(&root.path().join("artifacts")).unwrap();
    foundation::write_private(
        &root.path().join("artifacts/external-request.json"),
        &request.bytes().unwrap(),
    )
    .unwrap();
    let mut evidence = json!({"schema":"zdn-external-runtime/v1","request":Pin::of(&request.bytes().unwrap()),
        "cohort":cohort.pin().unwrap(),"inventory":before.pin().unwrap(),"inventoryJson":serde_json::to_string(&before).unwrap(),
        "pendingIdentity":"node-1","manifests":{},"pendingUpdate":null,"activeImages":{}});
    let path = root.path().join("external-evidence.json");
    foundation::write_json(&path, &evidence).unwrap();
    let identity = |id: &str| {
        serde_json::to_vec(&json!({"schema":IDENTITY_SCHEMA,"nodeId":id.repeat(64),
        "chainFingerprint":request.compiled.native_fingerprint}))
        .unwrap()
    };
    store.record("node-1", &identity("a")).unwrap();
    // Simulates a crash after create-only inventory publication, before evidence.
    zdn::foundation_live::external::validate_saved(&deployment, root.path()).unwrap();
    store.record("node-2", &identity("b")).unwrap();
    assert!(zdn::foundation_live::external::validate_saved(&deployment, root.path()).is_err());
    let current = store.read().unwrap();
    evidence["inventory"] = json!(current.pin().unwrap());
    evidence["inventoryJson"] = json!(serde_json::to_string(&current).unwrap());
    evidence["pendingIdentity"] = serde_json::Value::Null;
    foundation::write_json(&path, &evidence).unwrap();
    zdn::foundation_live::external::validate_saved(&deployment, root.path()).unwrap();
    evidence["manifests"]["node-1"] = json!(Pin::of(b"premature runtime"));
    foundation::write_json(&path, &evidence).unwrap();
    assert!(zdn::foundation_live::external::validate_saved(&deployment, root.path()).is_err());
}

#[derive(Default)]
struct Lifecycle {
    calls: Vec<&'static str>,
    fail_install: bool,
    controls: Vec<(String, Uuid)>,
    foreign_control: bool,
}
impl zdn::foundation::FoundationBackend for Lifecycle {
    fn verify(&mut self, _: &Deployment, destroying: bool) -> eyre::Result<()> {
        self.calls.push(if destroying {
            "verify-destroy"
        } else {
            "verify-up"
        });
        Ok(())
    }
    fn reserve(&mut self, _: &Deployment) -> eyre::Result<()> {
        self.calls.push("reserve");
        Ok(())
    }
    fn acquire(&mut self, _: &Deployment, _: Uuid) -> eyre::Result<()> {
        self.calls.push("lease");
        Ok(())
    }
    fn prepare(&mut self, _: &Deployment, _: bool) -> eyre::Result<()> {
        self.calls.push("prepare");
        Ok(())
    }
    fn preview(&mut self, _: bool) -> eyre::Result<serde_json::Value> {
        self.calls.push("preview");
        Ok(json!({}))
    }
    fn apply(&mut self, deployment: &Deployment) -> eyre::Result<zdn::infra::FoundationOutputs> {
        self.calls.push("apply");
        Ok(outputs(deployment))
    }
    fn deploy_runtime(&mut self, _: &Deployment) -> eyre::Result<serde_json::Value> {
        self.calls.push("install");
        eyre::ensure!(!self.fail_install, "injected interrupted installation");
        Ok(json!({}))
    }
    fn ready(&mut self, _: &Deployment) -> eyre::Result<serde_json::Value> {
        self.calls.push("readiness");
        Ok(json!({}))
    }
    fn verify_external_control(&mut self, _: &Deployment, _: &str) -> eyre::Result<()> {
        self.calls.push("verify-control");
        Ok(())
    }
    fn external_control(
        &mut self,
        _: &Deployment,
        original: &runtime::Manifest,
        request: &runtime::qualification::Request,
        _: &std::path::Path,
    ) -> eyre::Result<serde_json::Value> {
        self.controls
            .push((original.provisioning.node_id.clone(), request.id));
        Ok(json!({"schema":runtime::qualification::SCHEMA,
            "request":Pin::of(&request.bytes()?),"runtime":request.runtime,
            "deploymentId":original.provisioning.deployment_id,
            "nodeId":if self.foreign_control {"node-99"} else {&original.provisioning.node_id},
            "nativeInventory":original.chain.native_inventory,
            "result":{"height":105,"hash":"ab".repeat(32)}}))
    }
    fn destroy(&mut self) -> eyre::Result<()> {
        self.calls.push("destroy");
        Ok(())
    }
    fn cleanup(&mut self, _: &Deployment, _: bool) -> eyre::Result<zdn::foundation::CleanupReport> {
        self.calls.push("cleanup");
        Ok(zdn::foundation::CleanupReport {
            shared_backend_preserved: true,
            ..Default::default()
        })
    }
    fn remove_stack(&mut self) -> eyre::Result<()> {
        self.calls.push("remove-stack");
        Ok(())
    }
    fn release(&mut self) -> eyre::Result<()> {
        self.calls.push("release");
        Ok(())
    }
}

fn control_fixture() -> (
    tempfile::TempDir,
    zdn::state::StateStore,
    zdn::state::Binding,
    zdn::foundation::DeploymentFile,
    Deployment,
) {
    use zdn::{
        foundation::{self, DeploymentFile},
        native_peers::{NativeCohort, NativeInventoryStore, IDENTITY_SCHEMA},
        state::{BindingContext, StateStore},
    };
    let root = tempfile::tempdir().unwrap();
    let config_root = root.path().join("config");
    std::fs::create_dir(&config_root).unwrap();
    let config = config_root.join("devnet.yaml");
    std::fs::write(&config, "fixture only").unwrap();
    let mut deployment = deployment();
    let store = StateStore::open(root.path().join("state")).unwrap();
    let binding = store
        .bind(
            &BindingContext::new(config, None, None, deployment.spec.scope.clone()).unwrap(),
            "external-control",
        )
        .unwrap();
    deployment.spec.network_id = binding.network_id;
    let mut request = request();
    request.node_count = 2;
    deployment.external =
        Some(ExternalDeployment::new(request.clone(), 18233, "tFixture".into()).unwrap());
    deployment.outputs = Some(outputs(&deployment));
    deployment.stack_initialized = true;
    let file = DeploymentFile::open(store.root(), binding.network_id).unwrap();
    let path = file.directory();
    let external = deployment.external.as_ref().unwrap();
    let cohort = NativeCohort::new(
        binding.network_id,
        request.artifacts["descriptor.json"].sha256.clone(),
        request.compiled.native_fingerprint.clone(),
        &external.topology().unwrap(),
        &deployment.outputs.as_ref().unwrap().nodes,
        external.listener().unwrap(),
    )
    .unwrap();
    let inventory =
        NativeInventoryStore::open(&path.join("native-inventory"), cohort.clone()).unwrap();
    for (index, member) in cohort.members().iter().enumerate() {
        inventory.record(&member.node_id, &serde_json::to_vec(&json!({"schema":IDENTITY_SCHEMA,"nodeId":format!("{:064x}",index+1),"chainFingerprint":request.compiled.native_fingerprint})).unwrap()).unwrap();
    }
    let inventory = inventory.read().unwrap();
    foundation::private_directory(&path.join("artifacts")).unwrap();
    foundation::write_private(
        &path.join("artifacts/external-request.json"),
        &request.bytes().unwrap(),
    )
    .unwrap();
    let mut manifests = BTreeMap::new();
    for member in cohort.members() {
        let mut manifest = runtime();
        manifest.provisioning.deployment_id = binding.network_id;
        manifest.provisioning.node_id = member.node_id.clone();
        manifest.provisioning.volume_id = deployment.outputs.as_ref().unwrap().nodes
            [&member.node_id]
            .volume_id
            .clone();
        manifest.provisioning.request = Pin::of(&request.bytes().unwrap());
        manifest.chain.request = manifest.provisioning.request.clone();
        manifest.chain.objects = request.objects(&deployment.team, &deployment.spec).unwrap();
        manifest.chain.native_inventory = inventory.pin().unwrap();
        manifest.chain.options.deployment_id = binding.network_id.to_string();
        manifest.chain.options.node_id = member.node_id.clone();
        let node_root = manifest.provisioning.node_root();
        manifest.chain.options.state_dir = format!("{node_root}/state");
        manifest.chain.options.identity_dir = format!("{node_root}/identity");
        manifest.chain.options.cookie_dir = format!("{node_root}/rpc");
        manifest.chain.options.role = if member.node_id == "node-1" {
            "producer"
        } else {
            "follower"
        }
        .into();
        manifest.chain.options.reward_address =
            (member.node_id == "node-1").then(|| "tFixture".into());
        let allocation = deployment.spec.size.allocation();
        manifest.memory_bytes = u64::from(allocation.max_node_gib) << 30;
        manifest.cpu_millis = allocation.vcpus * 1000 - zdn::infra::HOST_CPU_RESERVE_MILLIS;
        manifest.host_reserve_bytes = u64::from(allocation.host_reserve_gib) << 30;
        manifest.block_interval_seconds = (member.node_id == "node-1").then_some(25);
        inventory
            .bind_render_options(&mut manifest.chain.options)
            .unwrap();
        manifests.insert(member.node_id.clone(), Pin::of(&manifest.bytes().unwrap()));
        foundation::write_private(
            &path.join(format!("{}-external-runtime.json", member.node_id)),
            &manifest.bytes().unwrap(),
        )
        .unwrap();
        foundation::write_private(
            &path.join(format!("{}-external-provisioning.json", member.node_id)),
            &manifest.provisioning.bytes().unwrap(),
        )
        .unwrap();
    }
    foundation::write_json(&path.join("external-evidence.json"), &json!({"schema":"zdn-external-runtime/v1","request":Pin::of(&request.bytes().unwrap()),"cohort":cohort.pin().unwrap(),"inventory":inventory.pin().unwrap(),"inventoryJson":serde_json::to_string(&inventory).unwrap(),"pendingIdentity":null,"manifests":manifests,"pendingUpdate":null,"activeImages":{}})).unwrap();
    foundation::private_directory(&store.root().join("profiles")).unwrap();
    foundation::write_json(
        &store.root().join("profiles/devnet.json"),
        &json!({"team":deployment.team,"awsProfile":deployment.spec.aws_profile}),
    )
    .unwrap();
    file.save(&deployment).unwrap();
    (root, store, binding, file, deployment)
}

#[test]
fn saved_control_cli_prepares_each_selected_node_and_resumes_without_cloud_or_caller_input() {
    use std::{fs, process::Command};
    let (root, store, _, file, deployment) = control_fixture();
    let action = root.path().join("action.json");
    fs::write(&action, r#"{"kind":"read","query":{"kind":"tip"}}"#).unwrap();
    drop(file);
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("PATH", "")
            .current_dir(root.path())
            .args(["devnet", "control", "external-control", "--state-dir"])
            .arg(store.root());
        command
    };
    for node in ["node-1", "node-2"] {
        let output = command()
            .args(["--node", node, "--action"])
            .arg(&action)
            .arg("--prepare-only")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["dispatched"], false);
        assert_eq!(value["nodeId"], node);
        let id = value["controlId"].as_str().unwrap();
        let saved_action = root.path().join("saved-action.json");
        fs::rename(&action, &saved_action).unwrap();
        let resumed = command()
            .args(["--resume", id, "--reconcile", "--prepare-only"])
            .output()
            .unwrap();
        assert!(
            resumed.status.success(),
            "{}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&resumed.stdout).unwrap(),
            value
        );
        fs::rename(saved_action, &action).unwrap();
    }
    let denied = command()
        .args(["--node", "node-2", "--action"])
        .arg(&action)
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(store
        .handoff_operations(
            &store
                .resolve(&deployment.spec.scope, "external-control", None)
                .unwrap()
        )
        .unwrap()
        .is_empty());
    assert!(zdn::foundation::DeploymentFile::read_snapshot(
        store.root(),
        deployment.spec.network_id
    )
    .unwrap()
    .unresolved_operation
    .is_none());
}

#[test]
fn saved_control_keeps_unknown_mutations_fenced_and_reuses_only_a_bound_completed_result() {
    use zdn::{
        foundation_live::external::qualification as controller,
        host::external::runtime::qualification::{Action, Query},
        state::PhaseStatus,
    };
    let (_root, store, binding, file, mut deployment) = control_fixture();
    let intent =
        controller::prepare(&deployment, file.directory(), "node-1", Action::RestartNode).unwrap();
    let id = intent.request.id;
    let mut backend = Lifecycle::default();
    // Fail reporting after the durable successful action but before normal return.
    let error = controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        id,
        false,
        &mut |receipt, phase| {
            if phase == Some("control")
                && receipt.phases.iter().any(|p| {
                    p.name == "control" && matches!(p.status, PhaseStatus::Succeeded { .. })
                })
            {
                eyre::bail!("lost local observer");
            }
            Ok(())
        },
    );
    assert!(error.is_err());
    assert_eq!(deployment.unresolved_operation, Some(id));
    assert_eq!(backend.controls.len(), 1);
    assert_eq!(backend.calls.last(), Some(&"release"));
    assert!(controller::prepare(
        &deployment,
        file.directory(),
        "node-1",
        Action::StopProducer
    )
    .is_err());
    let observation = controller::prepare(
        &deployment,
        file.directory(),
        "node-2",
        Action::Read { query: Query::Tip },
    )
    .unwrap();
    controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        observation.request.id,
        false,
        &mut |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(deployment.unresolved_operation, Some(id));
    assert_eq!(backend.controls[1].0, "node-2");
    let result = controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        id,
        true,
        &mut |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(result["nodeId"], "node-1");
    assert!(deployment.unresolved_operation.is_none());
    assert_eq!(
        backend.controls.len(),
        2,
        "completed action must not execute again"
    );
    assert!(!backend
        .calls
        .iter()
        .any(|c| matches!(*c, "apply" | "prepare" | "install" | "preview")));
    let fresh =
        controller::prepare(&deployment, file.directory(), "node-1", Action::RestartNode).unwrap();
    backend.foreign_control = true;
    assert!(controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        fresh.request.id,
        false,
        &mut |_, _| Ok(())
    )
    .is_err());
    assert_eq!(deployment.unresolved_operation, Some(fresh.request.id));
}

#[test]
fn saved_control_rejects_stale_or_unsafe_selection_before_backend_dispatch() {
    use zdn::{
        foundation_live::external::qualification as controller,
        host::external::runtime::qualification::{Action, Query},
    };
    let (_root, store, binding, file, mut deployment) = control_fixture();
    for (node, action) in [
        ("node-99", Action::Read { query: Query::Tip }),
        ("node-2", Action::StopProducer),
        ("node-2", Action::GatewayIdentity),
        (
            "node-1",
            Action::Produce {
                blocks: 21,
                height: 121,
                seconds: 30,
            },
        ),
    ] {
        assert!(controller::prepare(&deployment, file.directory(), node, action).is_err());
    }
    let intent = controller::prepare(
        &deployment,
        file.directory(),
        "node-2",
        Action::Read { query: Query::Tip },
    )
    .unwrap();
    let script = file.directory().join(format!(
        "external-controls/{}/control.sh",
        intent.request.id
    ));
    let saved = std::fs::read(&script).unwrap();
    std::fs::write(&script, b"echo unsafe").unwrap();
    let mut backend = Lifecycle::default();
    assert!(controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        intent.request.id,
        false,
        &mut |_, _| Ok(())
    )
    .is_err());
    std::fs::write(script, saved).unwrap();
    let evidence = file.directory().join("external-evidence.json");
    let saved = std::fs::read(&evidence).unwrap();
    let mut pending: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    pending["pendingUpdate"] = json!(Uuid::new_v4());
    zdn::foundation::write_json(&evidence, &pending).unwrap();
    assert!(controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        intent.request.id,
        false,
        &mut |_, _| Ok(())
    )
    .is_err());
    std::fs::write(evidence, saved).unwrap();
    deployment.destroyed = true;
    assert!(controller::execute(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        intent.request.id,
        false,
        &mut |_, _| Ok(())
    )
    .is_err());
    assert!(backend.calls.is_empty() && backend.controls.is_empty());
    assert!(store.handoff_operations(&binding).unwrap().is_empty());
}

#[test]
fn external_dispatch_reuses_journaled_lifecycle_and_cleanup_ignores_missing_companion() {
    use zdn::{
        foundation::{self, DeploymentFile},
        state::{BindingContext, StateStore},
    };
    let config_root = tempfile::tempdir().unwrap();
    let state_root = tempfile::tempdir().unwrap();
    let config = config_root.path().join("config.yaml");
    std::fs::write(&config, "fixture").unwrap();
    let mut deployment = deployment();
    let context = BindingContext::new(config, None, None, deployment.spec.scope.clone()).unwrap();
    let store = StateStore::open(state_root.path().join("state")).unwrap();
    let binding = store.bind(&context, "external-fixture").unwrap();
    deployment.spec.network_id = binding.network_id;
    foundation::private_directory(&store.root().join("profiles")).unwrap();
    foundation::write_json(
        &store.root().join("profiles/local.json"),
        &json!({"team":deployment.team,"awsProfile":deployment.spec.aws_profile}),
    )
    .unwrap();
    let list = || {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .current_dir(config_root.path())
            .args(["devnet", "list", "--profile", "local", "--state-dir"])
            .arg(store.root())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["awsChecked"], false);
        assert_eq!(report["liveReadinessChecked"], false);
        assert_eq!(report["artifactIntegrityChecked"], false);
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["networkId"] == binding.network_id.to_string())
            .unwrap()
            .clone()
    };
    let file = DeploymentFile::open(store.root(), binding.network_id).unwrap();
    deployment.external_source = Some(source_preparation(&deployment));
    file.save(&deployment).unwrap();
    let row = list();
    assert_eq!(row["requestKind"], "external-source-build");
    assert!(!row["blockers"]
        .as_array()
        .unwrap()
        .contains(&json!("missing_node_request")));
    assert_eq!(row["cleanup"]["steps"][0]["arguments"][1], "devnet");
    let mut backend = Lifecycle::default();
    assert!(foundation::apply(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        false
    )
    .is_err());
    assert!(backend.calls.is_empty());
    assert!(store.handoff_operations(&binding).unwrap().is_empty());
    deployment.external_source = None;
    deployment.external =
        Some(ExternalDeployment::new(request(), 18233, "tFixture".into()).unwrap());
    file.save(&deployment).unwrap();
    let row = list();
    assert_eq!(row["requestKind"], "external-nodes");
    assert!(!row["blockers"]
        .as_array()
        .unwrap()
        .contains(&json!("missing_node_request")));
    assert_eq!(row["cleanup"]["steps"][0]["arguments"][1], "devnet");
    let prefix = format!(
        "s3://zdn-private-fixture/zdn-meta/v1/private-team/artifacts/{}/",
        binding.network_id
    );
    deployment.cleanup = Some(foundation::CleanupReport {
        retained_artifact_prefixes: vec![prefix.clone()],
        shared_backend_preserved: true,
        ..Default::default()
    });
    file.save(&deployment).unwrap();
    let row = list();
    assert_eq!(row["cleanup"]["receiptState"], "valid");
    assert_eq!(row["cleanup"]["retainedArtifactPrefixes"], json!([prefix]));
    assert_eq!(row["cleanup"]["steps"][2]["arguments"][1], "devnet");
    deployment.cleanup = None;
    file.save(&deployment).unwrap();
    let mut backend = Lifecycle {
        fail_install: true,
        ..Default::default()
    };
    assert!(foundation::apply(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        false
    )
    .is_err());
    assert_eq!(backend.calls.last(), Some(&"release"));
    assert!(!backend.calls.contains(&"readiness"));
    let operation = store.operation(deployment.last_operation.unwrap()).unwrap();
    assert_eq!(operation.kind, "external-up");
    backend.fail_install = false;
    backend.calls.clear();
    foundation::apply(&store, &file, &binding, &mut deployment, &mut backend, true).unwrap();
    assert_eq!(
        backend.calls,
        vec![
            "verify-up",
            "reserve",
            "lease",
            "prepare",
            "preview",
            "apply",
            "install",
            "readiness",
            "release"
        ]
    );
    // There is no local companion/helper/artifact directory. Even a pending
    // external update does not demand companion execution to remove ownership.
    std::fs::write(
        file.directory().join("external-evidence.json"),
        b"not execution authority",
    )
    .unwrap();
    backend.calls.clear();
    foundation::destroy(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        true,
        true,
    )
    .unwrap();
    assert!(deployment.destroyed);
    assert_eq!(
        backend.calls,
        vec![
            "verify-destroy",
            "reserve",
            "lease",
            "prepare",
            "preview",
            "destroy",
            "cleanup",
            "remove-stack",
            "release"
        ]
    );
}
