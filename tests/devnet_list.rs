use serde_json::{json, Value};
use std::{fs, process::Command};
use uuid::Uuid;
use zdn::{
    aws::{TeamAws, TeamDefinition, TeamState},
    config::Size,
    foundation::{self, Deployment, DeploymentFile},
    infra::FoundationSpec,
    state::{Binding, BindingContext, OperationInput, PhaseStatus, StateStore},
};

struct Fixture {
    root: tempfile::TempDir,
    store: StateStore,
    team: TeamDefinition,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(root.path().join("state")).unwrap();
        let mut team = TeamDefinition {
            api_version: zdn::access::TEAM_ROLE_API_VERSION.into(),
            team_id: "local-team".into(),
            revision: 1,
            bootstrap_id: Uuid::new_v4(),
            aws: TeamAws {
                account_id: "123456789012".into(),
                region: "us-east-1".into(),
            },
            state: TeamState {
                backend: "s3://local-bucket/pulumi".into(),
                kms_key_arn:
                    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                        .into(),
            },
            deployment: None,
        };
        team.deployment = Some(zdn::access::DeploymentAccess::managed(&team));
        foundation::private_directory(&store.root().join("profiles")).unwrap();
        foundation::write_json(
            &store.root().join("profiles/local.json"),
            &json!({"team":team,"awsProfile":"unused"}),
        )
        .unwrap();
        Self { root, store, team }
    }

    fn binding(&self, label: &str) -> Binding {
        let source = self.root.path().join(label);
        fs::create_dir(&source).unwrap();
        let config = source.join("devnet.yaml");
        fs::write(&config, "not needed").unwrap();
        let context = BindingContext::new(&config, None, None, self.team.scope()).unwrap();
        let binding = self.store.bind(&context, label).unwrap();
        fs::remove_dir_all(source).unwrap();
        binding
    }

    fn saved(&self, binding: &Binding) -> (DeploymentFile, Deployment) {
        let deployment = Deployment::new(
            FoundationSpec {
                scope: self.team.scope(),
                network_id: binding.network_id,
                aws_profile: "unused".into(),
                ami_id: "ami-0123456789abcdef0".into(),
                availability_zone: "us-east-1a".into(),
                size: Size::Medium,
                retain_chain_disk: true,
            },
            self.team.clone(),
        )
        .unwrap();
        let file = DeploymentFile::open(self.store.root(), binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        (file, deployment)
    }

    fn list(&self) -> Value {
        let human = self.list_format("human");
        for format in ["json", "jsonl"] {
            assert_eq!(self.list_format(format), human);
        }
        human
    }

    fn list_format(&self, format: &str) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .current_dir(self.root.path())
            .args(["--format", format])
            .args(["devnet", "list", "--profile", "local", "--state-dir"])
            .arg(self.store.root())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("safe-to-retry"));
        assert!(output.stderr.is_empty());
        let value: Value = if format == "human" {
            serde_json::from_str(&text).unwrap()
        } else {
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
            }
            let result = records.last().unwrap();
            assert_eq!(result["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(result["command"], "devnet list");
            assert_eq!(result["type"], "result");
            assert_eq!(result["outcome"], "succeeded");
            assert!(result["networkId"].is_null());
            assert!(result["operationId"].is_null());
            assert!(result["error"].is_null());
            result["data"].clone()
        };
        assert_eq!(value["apiVersion"], "zdn-deployment-list/v1alpha1");
        assert_eq!(value["scope"], "local");
        for key in [
            "awsChecked",
            "liveReadinessChecked",
            "artifactIntegrityChecked",
        ] {
            assert_eq!(value[key], false);
        }
        value
    }
}

fn row(value: &Value, binding: &Binding) -> Value {
    value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["networkId"] == binding.network_id.to_string())
        .unwrap()
        .clone()
}

#[test]
fn deleted_sources_dedup_scope_and_bad_receipts_do_not_hide_locked_snapshot() {
    let f = Fixture::new();
    let healthy = f.binding("healthy");
    let (_writer_lock, _) = f.saved(&healthy);
    let missing = f.binding("missing");
    let broken = f.binding("broken");
    let (broken_file, _) = f.saved(&broken);
    foundation::write_private(
        &broken_file.directory().join("deployment.json"),
        b"SECRET malformed",
    )
    .unwrap();
    let mut context = healthy.context.clone();
    context.config_path = f.root.path().join("deleted-second-checkout/config.yaml");
    let mut export = healthy.to_export();
    export.label = "alias".into();
    f.store
        .attach(&context, healthy.network_id, &export)
        .unwrap();
    let mut foreign = context.clone();
    foreign.scope.region = "us-west-2".into();
    f.store.bind(&foreign, "foreign").unwrap();
    let value = f.list();
    assert_eq!(value["entries"].as_array().unwrap().len(), 3);
    assert_eq!(row(&value, &healthy)["labels"], json!(["alias", "healthy"]));
    assert_eq!(row(&value, &healthy)["receiptState"], "valid");
    assert_eq!(row(&value, &healthy)["recoveryState"], "blocked");
    assert_eq!(
        row(&value, &healthy)["blockers"],
        json!(["missing_node_request"])
    );
    assert_eq!(row(&value, &missing)["receiptState"], "missing");
    assert_eq!(row(&value, &broken)["receiptState"], "invalid");
}

#[test]
fn initial_source_build_discovery_withholds_cleanup_without_reading_build_inputs() {
    let f = Fixture::new();
    let binding = f.binding("building");
    let (file, _) = f.saved(&binding);
    for (marker, directory) in [
        ("source-preparation.json", false),
        ("source-build-inputs.json", false),
        ("source-preparation", true),
        ("source-snapshot", true),
        ("build", true),
    ] {
        let path = file.directory().join(marker);
        let payload = if directory {
            fs::create_dir(&path).unwrap();
            path.join("unverified")
        } else {
            path.clone()
        };
        let bytes = b"SECRET incomplete preparation, not a verified build";
        foundation::write_private(&payload, bytes).unwrap();
        let observed = row(&f.list(), &binding);
        assert_eq!(observed["requestKind"], "source-build");
        assert_eq!(observed["recoveryState"], "blocked");
        assert_eq!(
            observed["blockers"],
            json!(["source_build_preflight_required"])
        );
        assert!(observed["cleanup"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["mutates"] == false));
        assert_eq!(fs::read(&payload).unwrap(), bytes);
        if directory {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }
    let observed = row(&f.list(), &binding);
    assert_eq!(observed["requestKind"], "foundation");
    assert_eq!(observed["blockers"], json!(["missing_node_request"]));
}

#[test]
fn cleanup_discovery_reports_saved_retention_and_conditional_exact_commands() {
    let f = Fixture::new();
    let binding = f.binding("retained");
    let (file, mut deployment) = f.saved(&binding);
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["cleanup"]["receiptState"], "missing");
    assert!(saved["cleanup"]["retainedVolumeIds"].is_null());
    deployment.destroyed = true;
    deployment.cleanup = Some(foundation::CleanupReport {
        retained_volumes: vec!["vol-12345678".into(), "vol-00000000000000002".into()],
        shared_backend_preserved: true,
        ..Default::default()
    });
    file.save(&deployment).unwrap();
    let before = fs::read(file.directory().join("deployment.json")).unwrap();
    let saved = row(&f.list(), &binding);
    let cleanup = &saved["cleanup"];
    assert_eq!(
        cleanup["retainedVolumeIds"],
        json!(["vol-12345678", "vol-00000000000000002"])
    );
    assert_eq!(cleanup["receiptState"], "valid");
    assert_eq!(cleanup["liveStateChecked"], false);
    assert_eq!(cleanup["executionAuthorized"], false);
    assert_eq!(cleanup["retentionDefault"], true);
    assert_eq!(cleanup["retainedDiskRestoreSupported"], false);
    assert_eq!(cleanup["cost"]["estimateStatus"], "not-estimated");
    assert!(cleanup["cost"]["monthlyUsd"].is_null());
    assert_eq!(cleanup["cost"]["billingChecked"], false);
    assert_eq!(
        cleanup["steps"][0]["arguments"],
        json!([
            "zdn",
            "foundation",
            "status",
            binding.network_id.to_string(),
            "--profile",
            "local",
            "--state-dir",
            f.store.root()
        ])
    );
    for (index, delete_data) in [(1, false), (2, true)] {
        let step = &cleanup["steps"][index];
        let mut expected = json!([
            "zdn",
            "foundation",
            "destroy",
            binding.network_id.to_string(),
            "--profile",
            "local",
            "--state-dir",
            f.store.root(),
            "--yes"
        ]);
        if delete_data {
            expected
                .as_array_mut()
                .unwrap()
                .push(json!("--delete-data"));
        }
        assert_eq!(step["arguments"], expected);
        assert_eq!(step["mutates"], true);
        assert_eq!(step["requiresAuthorization"], true);
        assert_eq!(step["requiresFreshInventory"], true);
        let arguments: Vec<_> = step["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .map(|arg| arg.as_str().unwrap())
            .filter(|arg| *arg != "--yes")
            .collect();
        let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("pass --yes"));
    }
    assert_eq!(
        fs::read(file.directory().join("deployment.json")).unwrap(),
        before
    );
    for incomplete in ["resources", "backend"] {
        let mut failed = deployment.clone();
        if incomplete == "resources" {
            failed.cleanup.as_mut().unwrap().remaining_resources =
                vec!["SECRET-private-diagnostic".into()];
        } else {
            failed.cleanup.as_mut().unwrap().shared_backend_preserved = false;
        }
        file.save(&failed).unwrap();
        let saved = row(&f.list(), &binding);
        assert!(saved["cleanup"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["mutates"] == false));
        assert_eq!(
            saved["cleanup"]["remainingResourceCount"],
            usize::from(incomplete == "resources")
        );
    }
    deployment
        .cleanup
        .as_mut()
        .unwrap()
        .retained_volumes
        .push("SECRET-invalid-id".into());
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["cleanup"]["receiptState"], "invalid");
    assert!(saved["cleanup"]["retainedVolumeIds"].is_null());
    assert!(saved["cleanup"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["mutates"] == false));
}

#[test]
fn operation_observations_are_sanitized_and_never_authorize_retry() {
    let f = Fixture::new();
    let binding = f.binding("operation");
    let (file, mut deployment) = f.saved(&binding);
    let mut operation = f
        .store
        .begin_operation(
            &binding,
            "up",
            OperationInput {
                config_sha256: "a".repeat(64),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &["apply"],
        )
        .unwrap();
    deployment.last_operation = Some(operation.operation_id);
    file.save(&deployment).unwrap();
    assert_eq!(
        row(&f.list(), &binding)["lastOperation"]["status"],
        "incomplete"
    );
    operation = f
        .store
        .record_phase(
            operation.operation_id,
            operation.revision,
            "apply",
            PhaseStatus::Running {
                external_ref: Some("SECRET".into()),
            },
        )
        .unwrap();
    assert_eq!(
        row(&f.list(), &binding)["blockers"],
        json!(["missing_node_request", "reconcile_required"])
    );
    assert!(row(&f.list(), &binding)["cleanup"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["mutates"] == false));
    operation = f
        .store
        .record_phase(
            operation.operation_id,
            operation.revision,
            "apply",
            PhaseStatus::Succeeded {
                result: json!({"SECRET":"credentials"}),
            },
        )
        .unwrap();
    let observed = row(&f.list(), &binding);
    assert_eq!(observed["lastOperation"]["status"], "succeeded");
    assert_eq!(observed["lastOperation"]["phases"][0]["name"], "apply");
    assert_eq!(observed["blockers"], json!(["missing_node_request"]));
    deployment.unresolved_operation = Some(operation.operation_id);
    deployment.destroyed = true;
    file.save(&deployment).unwrap();
    assert_eq!(
        row(&f.list(), &binding)["blockers"],
        json!(["destroyed", "missing_node_request", "reconcile_required"])
    );
    deployment.last_operation = Some(Uuid::new_v4());
    file.save(&deployment).unwrap();
    assert_eq!(
        row(&f.list(), &binding)["lastOperation"]["receiptState"],
        "inaccessible"
    );

    let other = f.binding("other");
    let (other_file, mut other_deployment) = f.saved(&other);
    let wrong = f
        .store
        .begin_operation(&other, "SECRET", operation.inputs, &["SECRET"])
        .unwrap();
    other_deployment.last_operation = Some(wrong.operation_id);
    other_file.save(&other_deployment).unwrap();
    deployment.last_operation = Some(wrong.operation_id);
    file.save(&deployment).unwrap();
    let value = f.list();
    assert_eq!(
        row(&value, &binding)["lastOperation"]["receiptState"],
        "inaccessible"
    );
    assert_eq!(row(&value, &other)["receiptState"], "valid");
    assert!(row(&value, &other)["lastOperation"]["phases"][0]["name"].is_null());

    // Even an internally consistent receipt is not presented as this profile's
    // saved request when its team definition differs.
    deployment.team.revision += 1;
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["receiptState"], "invalid");
    assert!(saved["destroyed"].is_null());
    assert!(saved["lastOperationId"].is_null());
    assert!(saved["cleanup"].is_null());
}

#[test]
fn helper_version_mismatch_keeps_saved_node_request_visible_without_artifact_files() {
    use zdn::{
        artifact_set::{ArtifactSet, Compatibility, Provenance},
        devnet::{Artifact, ClusterRequest},
        image::{ImageCapabilities, ImageProvenance, ImageRecord},
    };
    let f = Fixture::new();
    let binding = f.binding("nodes");
    let (file, mut deployment) = f.saved(&binding);
    let mut manifest: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    manifest["checkpoints"] = json!([{"height":0,"hash":manifest["genesis"]["hash"]}]);
    let manifest: zdn::chain::manifest::ConsensusManifest =
        serde_json::from_value(manifest).unwrap();
    let image = ImageRecord {
        api_version: zdn::image::API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/local-team/node@sha256:{}",
            "a".repeat(64)
        ),
        config_digest: format!("sha256:{}", "b".repeat(64)),
        platform: "linux/amd64".into(),
        provenance: ImageProvenance::Release {
            revision: "c".repeat(40),
            version: "v1".into(),
        },
        capabilities: ImageCapabilities::default(),
        binary_path: zdn::image::NODE_BINARY.into(),
        environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
    };
    let artifacts = zdn::artifact_set::artifact_limits(false)
        .into_keys()
        .map(|name| {
            (
                name,
                Artifact {
                    sha256: "a".repeat(64),
                    bytes: 1,
                },
            )
        })
        .collect();
    let mut compatibility = Compatibility::current(false);
    compatibility.helper_version = "999.0.0".into();
    let set = ArtifactSet {
        api_version: zdn::artifact_set::API_VERSION.into(),
        platform: "linux/amd64".into(),
        consensus_fingerprint: manifest.fingerprint().unwrap(),
        node_image: image.clone(),
        build: None,
        lightwallet_image: None,
        compatibility,
        provenance: ["chain", "node", "helper"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    Provenance {
                        source_url: "https://example.com/source".into(),
                        revision: "c".repeat(40),
                        license: "MIT".into(),
                    },
                )
            })
            .collect(),
        artifacts,
    };
    deployment.cluster = Some(ClusterRequest {
        api_version: zdn::devnet::API_VERSION.into(),
        config_sha256: "d".repeat(64),
        installer_fetch_protocol: None,
        native_runtime_protocol: None,
        build: None,
        artifacts: set.artifacts.clone(),
        artifact_set: Some(set),
        manifest,
        image,
        node_count: 3,
        client_access: false,
        reward_address: "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB".into(),
        block_interval_seconds: Some(25),
        lightwallet: None,
    });
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["receiptState"], "valid");
    assert_eq!(saved["requestKind"], "nodes");
    assert_eq!(saved["blockers"], json!(["incompatible_package_helper"]));
    assert!(!file.directory().join("artifacts").exists());

    deployment
        .cluster
        .as_mut()
        .unwrap()
        .artifact_set
        .as_mut()
        .unwrap()
        .compatibility
        .helper_version = env!("CARGO_PKG_VERSION").into();
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["recoveryState"], "ready-for-preflight");
    assert_eq!(saved["blockers"], json!([]));
    let prefix = format!(
        "s3://local-bucket/zdn-meta/v1/local-team/artifacts/{}/",
        binding.network_id
    );
    deployment.cleanup = Some(foundation::CleanupReport {
        retained_artifact_prefixes: vec![prefix.clone()],
        shared_backend_preserved: true,
        ..Default::default()
    });
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(
        saved["cleanup"]["retainedArtifactPrefixes"],
        json!([prefix])
    );
    assert_eq!(saved["cleanup"]["steps"][2]["arguments"][1], "devnet");
    deployment
        .cleanup
        .as_mut()
        .unwrap()
        .retained_artifact_prefixes = vec!["s3://other-bucket/SECRET".into()];
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["cleanup"]["receiptState"], "invalid");
    assert!(saved["cleanup"]["retainedArtifactPrefixes"].is_null());
    deployment.cleanup = None;
    deployment.spec.aws_profile = "different-credential-profile".into();
    file.save(&deployment).unwrap();
    assert_eq!(
        row(&f.list(), &binding)["blockers"],
        json!(["aws_profile_mismatch"])
    );
    deployment.spec.aws_profile = "unused".into();
    deployment
        .cluster
        .as_mut()
        .unwrap()
        .artifact_set
        .as_mut()
        .unwrap()
        .compatibility
        .helper_version = "999.0.0".into();

    // A tiny provisioned-output observation is enough for an unfinished update;
    // no instance, image bytes, or installation is needed for discovery.
    let nodes: std::collections::BTreeMap<_, _> = deployment
        .cluster
        .as_ref()
        .unwrap()
        .topology()
        .unwrap()
        .nodes()
        .into_iter()
        .enumerate()
        .map(|(i, node)| {
            (
                node.node_id.clone(),
                zdn::cluster_infra::ClusterNodeOutputs {
                    node_id: node.node_id,
                    private_ip: node.private_ip,
                    instance_id: format!("i-{:017x}", i + 1),
                    volume_id: format!("vol-{:017x}", i + 1),
                },
            )
        })
        .collect();
    let first = &nodes["node-1"];
    let target = zdn::update::NodeTarget {
        instance_id: first.instance_id.clone(),
        volume_id: first.volume_id.clone(),
        expected_image: deployment.cluster.as_ref().unwrap().image.image.clone(),
        expected_update_id: None,
    };
    deployment.outputs = Some(zdn::infra::FoundationOutputs {
        nodes: nodes.clone(),
        lightwallet: None,
        schema_version: 1,
        scope: f.team.scope(),
        network_id: binding.network_id,
        availability_zone: "us-east-1a".into(),
        vpc_id: "vpc-12345678".into(),
        private_subnet_id: "subnet-12345678".into(),
        instance_id: first.instance_id.clone(),
        private_ip: first.private_ip,
        chain_volume_id: first.volume_id.clone(),
        retain_chain_disk: true,
        security_group_id: "sg-12345678".into(),
        nat_gateway_id: "nat-12345678".into(),
        eip_allocation_id: "eipalloc-12345678".into(),
    });
    let update_id = Uuid::new_v4();
    deployment.runtime = Some(zdn::update::RuntimeState {
        nodes: Default::default(),
        update: Some(zdn::update::UpdateIntent {
            api_version: zdn::update::API_VERSION.into(),
            id: update_id,
            baseline_sha256: zdn::update::baseline_fingerprint(&deployment).unwrap(),
            targets: [("node-1".into(), target)].into(),
            storage_compatibility_acknowledged: true,
            build_contract_sha256: None,
            build_exporter_protocol: None,
            host_runtime_protocol: None,
            revision: None,
            completed: Default::default(),
            finished: false,
        }),
    });
    file.save(&deployment).unwrap();
    let saved = row(&f.list(), &binding);
    assert_eq!(saved["pendingUpdateId"], update_id.to_string());
    assert_eq!(
        saved["blockers"],
        json!(["incompatible_package_helper", "pending_update"])
    );
    assert_eq!(saved["recoveryState"], "blocked");
    assert!(saved["cleanup"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["mutates"] == false));
}
