use eyre::{bail, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use uuid::Uuid;
use zdn::aws::{TeamAws, TeamDefinition, TeamState};
use zdn::config::Size;
use zdn::foundation::{self, CleanupReport, Deployment, DeploymentFile, FoundationBackend};
use zdn::infra::{FoundationOutputs, FoundationSpec};
use zdn::state::{Binding, BindingContext, OperationReceipt, PhaseStatus, Scope, StateStore};

#[test]
fn source_update_diagnostics_redact_values_and_ignore_allowed_changes() {
    use zdn::config::{Config, Source};
    use zdn::foundation::update_controller::validate_source_config;
    use zdn::immutable_inputs::ImmutableInputError;

    let original = Config::draft(
        "original".into(),
        "devnet".into(),
        Source {
            path: Some("/private/original-checkout".into()),
            ..Source::default()
        },
        Size::Medium,
    )
    .unwrap();
    let before = serde_json::to_value(&original).unwrap();
    let mut candidate = original.clone();
    candidate.node.source.path = Some("/private/candidate-checkout".into());
    candidate.node.build.as_mut().unwrap().dockerfile = "private/Dockerfile".into();
    validate_source_config(&original, &candidate).unwrap();
    // Changing source kind and dropping build settings is also allowed.
    candidate.node.source = Source {
        image: Some(format!("private.example/image@sha256:{}", "a".repeat(64))),
        ..Source::default()
    };
    candidate.node.build = None;
    validate_source_config(&original, &candidate).unwrap();
    candidate.name = "private-candidate-name".into();
    candidate
        .network
        .activation_heights
        .insert("private-map-key".into(), 42);
    candidate.node.resources.preset = Size::Large;
    candidate.services.lightwallet = false;
    let error = validate_source_config(&original, &candidate).unwrap_err();
    assert!(error
        .to_string()
        .contains("update may change only node.source and node.build"));
    let mismatch = error.downcast_ref::<ImmutableInputError>().unwrap();
    let report = serde_json::to_value(&mismatch.report).unwrap();
    assert_eq!(
        report["changedFields"],
        json!([
            {"field": "name", "changeKind": "modified"},
            {"field": "network.activationHeights", "changeKind": "modified"},
            {"field": "node.resources.preset", "changeKind": "modified"},
            {"field": "services.lightwallet", "changeKind": "modified"}
        ])
    );
    assert_eq!(report["immutable"], true);
    assert_eq!(report["executionAuthorized"], false);
    assert_eq!(report["liveStateChecked"], false);
    let rendered = format!("{mismatch:?} {mismatch} {report}");
    for secret in [
        "/private/",
        "private/Dockerfile",
        "private.example",
        "private-candidate-name",
        "private-map-key",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert_eq!(serde_json::to_value(&original).unwrap(), before);
}

#[test]
fn immutable_cluster_report_exposes_schema_fields_not_nested_keys_or_values() {
    use zdn::devnet::{Artifact, ClusterRequest};
    use zdn::image::{ImageCapabilities, ImageProvenance, ImageRecord};
    use zdn::immutable_inputs::ImmutableInputReport;

    // Data-only request: no image execution or artifact staging.
    let original = ClusterRequest {
        api_version: zdn::devnet::API_VERSION.into(),
        config_sha256: "a".repeat(64),
        installer_fetch_protocol: None,
        native_runtime_protocol: None,
        build: None,
        artifact_set: None,
        manifest: serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap(),
        image: ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: format!("private.example/old@sha256:{}", "b".repeat(64)),
            config_digest: format!("sha256:{}", "c".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: ImageProvenance::Release {
                revision: "d".repeat(40),
                version: "v1".into(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
        },
        node_count: 3,
        client_access: false,
        reward_address: "private-original-reward".into(),
        block_interval_seconds: None,
        lightwallet: None,
        artifacts: Default::default(),
    };
    assert!(ImmutableInputReport::cluster_request(&original, &original)
        .unwrap()
        .changed_fields
        .is_empty());
    let mut candidate = original.clone();
    candidate.artifacts.insert(
        "/private/arbitrary-artifact-key".into(),
        Artifact {
            sha256: "e".repeat(64),
            bytes: 17,
        },
    );
    candidate.block_interval_seconds = Some(25);
    candidate.reward_address = "private-changed-reward".into();
    let report = ImmutableInputReport::cluster_request(&original, &candidate).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap()["changedFields"],
        json!([
            {"field": "artifacts", "changeKind": "modified"},
            {"field": "blockIntervalSeconds", "changeKind": "added"},
            {"field": "rewardAddress", "changeKind": "modified"}
        ])
    );
    assert!(!format!("{report:?}").contains("private"));
    assert_eq!(
        serde_json::to_value(ImmutableInputReport::config_fingerprint()).unwrap()["changedFields"],
        json!([
            {"field": "configSha256", "changeKind": "modified"}
        ])
    );
}

struct Fixture {
    _root: TempDir,
    store: StateStore,
    binding: Binding,
    file: DeploymentFile,
    deployment: Deployment,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("devnet.yaml"), "name: feature\n").unwrap();
        let scope = Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let context =
            BindingContext::new(source.join("devnet.yaml"), None, None, scope.clone()).unwrap();
        let store = StateStore::open(root.path().join("state")).unwrap();
        let binding = store.bind(&context, "feature").unwrap();
        let team = TeamDefinition {
            deployment: None,
            api_version: "zdn-team/v1alpha1".into(),
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
        let deployment = Deployment::new(spec, team).unwrap();
        let file = DeploymentFile::open(store.root(), binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        Self {
            _root: root,
            store,
            binding,
            file,
            deployment,
        }
    }
    fn backend(&self) -> FakeBackend {
        FakeBackend {
            state: self.store.root().to_owned(),
            deployment_file: self.file.directory().join("deployment.json"),
            calls: Vec::new(),
            fail: None,
            output: output_for(&self.deployment.spec),
            cleanup: None,
            delete_choices: Vec::new(),
            reconcile_choices: Vec::new(),
            release_failure: false,
            cancel_at: None,
        }
    }
    fn apply(&mut self, backend: &mut FakeBackend, reconcile: bool) -> Result<OperationReceipt> {
        foundation::apply(
            &self.store,
            &self.file,
            &self.binding,
            &mut self.deployment,
            backend,
            reconcile,
        )
    }
    fn destroy(
        &mut self,
        backend: &mut FakeBackend,
        delete_data: bool,
        reconcile: bool,
    ) -> Result<OperationReceipt> {
        foundation::destroy(
            &self.store,
            &self.file,
            &self.binding,
            &mut self.deployment,
            backend,
            delete_data,
            reconcile,
        )
    }
    fn last(&self) -> OperationReceipt {
        self.store
            .operation(self.deployment.last_operation.unwrap())
            .unwrap()
    }
}

#[test]
fn legacy_render_preserves_provider_and_root_volume_tagging() {
    let fixture = Fixture::new();
    let deployment = fixture.deployment;
    let rendered = serde_json::to_value(deployment.render().unwrap()).unwrap();
    assert_eq!(
        rendered,
        serde_json::to_value(deployment.spec.render().unwrap()).unwrap()
    );
    assert!(rendered["resources"]["provider"]["properties"]
        .get("defaultTags")
        .is_none());
    assert!(rendered["resources"]["host"]["options"]
        .get("ignoreChanges")
        .is_none());
    assert_eq!(
        rendered["resources"]["host"]["properties"]["rootBlockDevice"]["tags"]["zdn:team-id"],
        deployment.team.team_id
    );
}

#[test]
fn role_launch_tags_authorize_new_volumes_without_retagging_owned_disks() {
    let fixture = Fixture::new();
    let mut deployment = fixture.deployment;
    deployment.team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
    deployment.team.deployment = Some(zdn::access::DeploymentAccess::managed(&deployment.team));
    let rendered = serde_json::to_value(deployment.render().unwrap()).unwrap();
    let resources = &rendered["resources"];
    // AWS 7.50.0's pinned provider sends defaultTags with RunInstances, then
    // sends rootBlockDevice.tags separately. volumeTags would also manage the
    // independently attached chain disk. These are distinct provider paths:
    // https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/ec2/ec2_instance.go
    let launch_volume_tags = &resources["provider"]["properties"]["defaultTags"]["tags"];
    assert_eq!(
        launch_volume_tags,
        &json!({
            "zdn:team-id": deployment.team.team_id,
            "zdn:managed-by": "zdn",
            "zdn:bootstrap": deployment.team.bootstrap_id.to_string()
        })
    );
    let policies = zdn::access::deployment_policies(
        &deployment.team,
        deployment.team.deployment.as_ref().unwrap(),
    )
    .unwrap();
    let conditions = policies["compute"]["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .find(|statement| {
            statement["Action"]
                .as_array()
                .unwrap()
                .contains(&json!("ec2:RunInstances"))
                && statement["Condition"]["StringEquals"]
                    .get("aws:RequestTag/zdn:bootstrap")
                    .is_some()
        })
        .unwrap()["Condition"]["StringEquals"]
        .as_object()
        .unwrap();
    for (condition, expected) in conditions {
        let key = condition.strip_prefix("aws:RequestTag/").unwrap();
        assert_eq!(&launch_volume_tags[key], expected, "{condition}");
        assert!(resources["host"]["properties"]["rootBlockDevice"]["tags"]
            .get(key)
            .is_none());
    }
    assert!(resources["host"]["properties"].get("volumeTags").is_none());
    // Keep only these immutable leaves from an earlier host's inputs. Pulumi
    // 3.268.0 restores a removed leaf from old state; it also preserves absence
    // when the old input omitted it. Name and all other host properties must
    // remain managed rather than ignoring the entire root tag map.
    // https://github.com/pulumi/pulumi/blob/v3.268.0/sdk/go/common/resource/properties_path.go#L510-L541
    assert_eq!(
        resources["host"]["options"]["ignoreChanges"],
        json!([
            "rootBlockDevice.tags[\"zdn:bootstrap\"]",
            "rootBlockDevice.tags[\"zdn:team-id\"]",
            "rootBlockDevice.tags[\"zdn:managed-by\"]"
        ])
    );
    for (name, resource) in resources.as_object().unwrap() {
        if name != "host" {
            assert!(resource["options"].get("ignoreChanges").is_none());
        }
    }
    assert_eq!(
        resources["host"]["properties"]["rootBlockDevice"]["tags"]["Name"],
        deployment.spec.resource_name("root-disk")
    );
    assert_eq!(
        resources["chainDisk"]["properties"]["tags"]["Name"],
        deployment.spec.resource_name("chain-disk")
    );
    let roundtrip: zdn::infra::PulumiProgram =
        serde_yaml::from_str(&deployment.render().unwrap().to_yaml().unwrap()).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), rendered);
}

fn output_for(spec: &FoundationSpec) -> FoundationOutputs {
    FoundationOutputs {
        lightwallet: None,
        nodes: Default::default(),
        schema_version: 1,
        scope: spec.scope.clone(),
        network_id: spec.network_id,
        availability_zone: spec.availability_zone.clone(),
        vpc_id: "vpc-12345678".into(),
        private_subnet_id: "subnet-12345678".into(),
        instance_id: "i-1234567890abcdef0".into(),
        private_ip: "10.90.1.10".parse().unwrap(),
        chain_volume_id: "vol-12345678".into(),
        retain_chain_disk: true,
        security_group_id: "sg-12345678".into(),
        nat_gateway_id: "nat-12345678".into(),
        eip_allocation_id: "eipalloc-12345678".into(),
    }
}

struct FakeBackend {
    state: PathBuf,
    deployment_file: PathBuf,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    output: FoundationOutputs,
    cleanup: Option<CleanupReport>,
    delete_choices: Vec<bool>,
    reconcile_choices: Vec<bool>,
    release_failure: bool,
    cancel_at: Option<&'static str>,
}
impl FakeBackend {
    fn step(&mut self, name: &'static str) -> Result<()> {
        self.calls.push(name);
        // Assert the durability boundary at the point an external effect would
        // begin. This is intentionally a separate read of the on-disk records.
        let deployment: Deployment = foundation::read_json(&self.deployment_file)?;
        let store = StateStore::open(&self.state)?;
        let operation = store.operation(deployment.last_operation.unwrap())?;
        let phase = operation
            .phases
            .iter()
            .find(|phase| phase.name == name)
            .unwrap();
        assert!(
            matches!(phase.status, PhaseStatus::Running { .. }),
            "{name} was not durably marked running before its callback"
        );
        assert_eq!(operation.network_id, deployment.spec.network_id);
        if self.cancel_at == Some(name) {
            store.request_cancel(operation.operation_id, operation.revision)?;
        }
        if self.fail == Some(name) {
            bail!("fixture failure with private-provider-message");
        }
        Ok(())
    }
}
impl FoundationBackend for FakeBackend {
    fn verify(&mut self, _: &Deployment, _: bool) -> Result<()> {
        self.step("verify")
    }
    fn reserve(&mut self, deployment: &Deployment) -> Result<()> {
        self.step("reserve")?;
        let saved: Deployment = foundation::read_json(&self.deployment_file)?;
        assert_eq!(saved.owner_id, deployment.owner_id);
        Ok(())
    }
    fn acquire(&mut self, deployment: &Deployment, operation_id: Uuid) -> Result<()> {
        self.step("lease")?;
        assert_eq!(deployment.last_operation, Some(operation_id));
        Ok(())
    }
    fn prepare(&mut self, _: &Deployment, reconcile: bool) -> Result<()> {
        self.reconcile_choices.push(reconcile);
        self.step("prepare")
    }
    fn preview(&mut self, _: bool) -> Result<Value> {
        self.step("preview")?;
        Ok(json!({"schema_version":1,"changes":{"same":1}}))
    }
    fn apply(&mut self, _: &Deployment) -> Result<FoundationOutputs> {
        self.step("apply")?;
        Ok(self.output.clone())
    }
    fn ready(&mut self, deployment: &Deployment) -> Result<Value> {
        self.step("readiness")?;
        let saved: Deployment = foundation::read_json(&self.deployment_file)?;
        assert_eq!(
            saved.outputs.as_ref().unwrap().instance_id,
            deployment.outputs.as_ref().unwrap().instance_id
        );
        Ok(json!({"schema_version":1,"status":"ready"}))
    }
    fn destroy(&mut self) -> Result<()> {
        self.step("destroy")
    }
    fn cleanup(&mut self, _: &Deployment, delete_data: bool) -> Result<CleanupReport> {
        self.delete_choices.push(delete_data);
        self.step("cleanup")?;
        Ok(self.cleanup.clone().unwrap_or_else(|| CleanupReport {
            retained_artifact_prefixes: vec![],
            remaining_resources: vec![],
            retained_volumes: if delete_data {
                vec![]
            } else {
                vec!["vol-12345678".into()]
            },
            shared_backend_preserved: true,
        }))
    }
    fn remove_stack(&mut self) -> Result<()> {
        self.step("remove-stack")
    }
    fn release(&mut self) -> Result<()> {
        self.calls.push("release");
        if self.release_failure {
            bail!("fixture lease release failure");
        }
        Ok(())
    }
}

fn phase_status<'a>(receipt: &'a OperationReceipt, name: &str) -> &'a PhaseStatus {
    &receipt
        .phases
        .iter()
        .find(|phase| phase.name == name)
        .unwrap()
        .status
}

#[test]
fn lifecycle_observations_follow_durable_state_and_stop_after_scripted_failures() {
    for (mutation, failure) in [
        ("apply", None),
        ("apply", Some("verify")),
        ("apply", Some("apply")),
        ("destroy", None),
        ("destroy", Some("verify")),
        ("destroy", Some("destroy")),
    ] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        backend.fail = failure;
        let mut observations = Vec::new();
        let mut observe = |receipt: &OperationReceipt, phase: Option<&str>| {
            assert_eq!(fixture.store.operation(receipt.operation_id)?, *receipt);
            assert_eq!(
                fixture.file.load()?.last_operation,
                Some(receipt.operation_id)
            );
            observations.push((phase.map(str::to_owned), receipt.clone()));
            Ok(())
        };
        let result = if mutation == "destroy" {
            foundation::destroy_with_progress(
                &fixture.store,
                &fixture.file,
                &fixture.binding,
                &mut fixture.deployment,
                &mut backend,
                false,
                false,
                &mut observe,
            )
        } else {
            foundation::apply_with_progress(
                &fixture.store,
                &fixture.file,
                &fixture.binding,
                &mut fixture.deployment,
                &mut backend,
                false,
                &mut observe,
            )
        };
        assert_eq!(result.is_err(), failure.is_some());
        assert!(observations[0].0.is_none());
        assert!(observations[0]
            .1
            .phases
            .iter()
            .all(|p| matches!(p.status, PhaseStatus::Pending)));
        let phases: &[&str] = if mutation == "destroy" {
            &[
                "verify",
                "reserve",
                "lease",
                "prepare",
                "preview",
                "destroy",
                "cleanup",
                "remove-stack",
            ]
        } else {
            &[
                "verify",
                "reserve",
                "lease",
                "prepare",
                "preview",
                "apply",
                "readiness",
            ]
        };
        let completed = failure.map_or(phases.len(), |name| {
            phases.iter().position(|p| *p == name).unwrap() + 1
        });
        assert_eq!(observations.len(), 1 + 2 * completed);
        for (index, name) in phases[..completed].iter().enumerate() {
            let (started_name, started) = &observations[1 + 2 * index];
            let (finished_name, finished) = &observations[2 + 2 * index];
            assert_eq!(started_name.as_deref(), Some(*name));
            assert_eq!(finished_name.as_deref(), Some(*name));
            assert!(matches!(
                phase_status(started, name),
                PhaseStatus::Running { .. }
            ));
            match (failure, *name) {
                (Some("verify"), "verify") => assert!(matches!(
                    phase_status(finished, name),
                    PhaseStatus::Failed {
                        retry_safe: true,
                        ..
                    }
                )),
                (Some("apply"), "apply") | (Some("destroy"), "destroy") => assert!(matches!(
                    phase_status(finished, name),
                    PhaseStatus::Unknown { .. }
                )),
                _ => assert!(matches!(
                    phase_status(finished, name),
                    PhaseStatus::Succeeded { .. }
                )),
            }
        }
        assert_eq!(fixture.last(), observations.last().unwrap().1);
    }
}

#[test]
fn broken_progress_stops_new_effects_and_still_releases_the_lease() {
    for (mutation, stop) in [
        ("apply", None),
        ("apply", Some(("verify", false))),
        ("apply", Some(("apply", false))),
        ("apply", Some(("apply", true))),
        ("destroy", None),
        ("destroy", Some(("verify", false))),
        ("destroy", Some(("destroy", false))),
        ("destroy", Some(("destroy", true))),
    ] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        let mut observe = |receipt: &OperationReceipt, phase: Option<&str>| {
            let should_stop = match (stop, phase) {
                (None, None) => true,
                (Some((name, finished)), Some(phase)) if name == phase => {
                    matches!(phase_status(receipt, name), PhaseStatus::Succeeded { .. }) == finished
                }
                _ => false,
            };
            if should_stop {
                bail!("fixture stream closed");
            }
            Ok(())
        };
        let result = if mutation == "destroy" {
            foundation::destroy_with_progress(
                &fixture.store,
                &fixture.file,
                &fixture.binding,
                &mut fixture.deployment,
                &mut backend,
                false,
                false,
                &mut observe,
            )
        } else {
            foundation::apply_with_progress(
                &fixture.store,
                &fixture.file,
                &fixture.binding,
                &mut fixture.deployment,
                &mut backend,
                false,
                &mut observe,
            )
        };
        assert!(result.unwrap_err().to_string().contains("stream closed"));
        let receipt = fixture.last();
        assert!(!backend.calls.contains(&"readiness"));
        assert!(!backend.calls.contains(&"cleanup"));
        assert_eq!(backend.calls.last(), Some(&"release"));
        if let Some((name, finished)) = stop {
            assert_eq!(backend.calls.contains(&name), finished);
            assert_eq!(
                matches!(phase_status(&receipt, name), PhaseStatus::Succeeded { .. }),
                finished
            );
        } else {
            assert!(receipt
                .phases
                .iter()
                .all(|p| matches!(p.status, PhaseStatus::Pending)));
            assert_eq!(backend.calls, vec!["release"]);
        }
    }
}

#[test]
fn cancellation_during_apply_preserves_the_outcome_and_stops_later_effects() {
    for fail in [false, true] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        backend.cancel_at = Some("apply");
        backend.fail = fail.then_some("apply");
        let error = fixture.apply(&mut backend, false).unwrap_err().to_string();
        let receipt = fixture.last();
        assert!(receipt.cancel_requested);
        assert_eq!(backend.calls.last(), Some(&"release"));
        assert!(!backend.calls.contains(&"readiness"));
        if fail {
            assert!(error.contains("fixture failure"), "{error}");
            assert!(matches!(
                phase_status(&receipt, "apply"),
                PhaseStatus::Unknown { .. }
            ));
        } else {
            assert!(error.contains("cancellation was requested"), "{error}");
            assert!(matches!(
                phase_status(&receipt, "apply"),
                PhaseStatus::Succeeded { .. }
            ));
            assert!(fixture.file.load().unwrap().outputs.is_some());
        }
        assert!(matches!(
            phase_status(&receipt, "readiness"),
            PhaseStatus::Pending
        ));
    }
}

#[test]
fn complete_apply_saves_outputs_before_readiness_and_each_effect_before_execution() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    let receipt = fixture.apply(&mut backend, false).unwrap();
    assert!(receipt
        .phases
        .iter()
        .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. })));
    let saved = fixture.file.load().unwrap();
    assert!(saved.stack_initialized);
    assert_eq!(
        saved.outputs.unwrap().network_id,
        fixture.binding.network_id
    );
    assert!(!saved.destroyed);
    assert_eq!(backend.calls.last(), Some(&"release"));
    assert!(saved.unresolved_operation.is_none());
}

#[test]
fn unchanged_apply_checks_cloud_and_readiness_again() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    let first = fixture.apply(&mut backend, false).unwrap();
    let second = fixture.apply(&mut backend, false).unwrap();
    assert_ne!(first.operation_id, second.operation_id);
    for name in [
        "verify",
        "reserve",
        "lease",
        "preview",
        "apply",
        "readiness",
        "release",
    ] {
        assert_eq!(
            backend.calls.iter().filter(|call| **call == name).count(),
            2
        );
    }
    assert_eq!(
        fixture.file.load().unwrap().outputs.unwrap().instance_id,
        backend.output.instance_id
    );
}

#[test]
fn readiness_failure_preserves_outputs_and_does_not_claim_a_ready_host() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    backend.fail = Some("readiness");
    assert!(fixture.apply(&mut backend, false).is_err());
    assert!(fixture.file.load().unwrap().outputs.is_some());
    let receipt = fixture.last();
    assert!(matches!(
        phase_status(&receipt, "apply"),
        PhaseStatus::Succeeded { .. }
    ));
    assert!(matches!(
        phase_status(&receipt, "readiness"),
        PhaseStatus::Failed {
            retry_safe: true,
            ..
        }
    ));
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains("private-provider-message"));
    assert_eq!(backend.calls.last(), Some(&"release"));
}

#[test]
fn partial_apply_stops_before_readiness_and_requires_explicit_reconciliation() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    backend.fail = Some("apply");
    assert!(fixture.apply(&mut backend, false).is_err());
    let failed = fixture.last();
    assert!(matches!(
        phase_status(&failed, "apply"),
        PhaseStatus::Unknown { .. }
    ));
    assert!(fixture.file.load().unwrap().outputs.is_none());
    assert!(!backend.calls.contains(&"readiness"));
    let mut retry = fixture.backend();
    assert!(fixture.apply(&mut retry, false).is_err());
    assert!(retry.calls.is_empty());
    fixture.apply(&mut retry, true).unwrap();
    assert_eq!(retry.reconcile_choices, [true]);
    assert!(fixture.file.load().unwrap().unresolved_operation.is_none());
}

#[test]
fn an_early_failed_reconcile_cannot_erase_an_older_uncertain_apply() {
    let mut fixture = Fixture::new();
    let mut partial = fixture.backend();
    partial.fail = Some("apply");
    assert!(fixture.apply(&mut partial, false).is_err());
    let original = fixture.deployment.last_operation.unwrap();
    let mut reconcile = fixture.backend();
    reconcile.fail = Some("verify");
    assert!(fixture.apply(&mut reconcile, true).is_err());
    assert_ne!(fixture.deployment.last_operation.unwrap(), original);
    assert!(fixture.file.load().unwrap().unresolved_operation.is_some());
    let mut retry = fixture.backend();
    let error = fixture.apply(&mut retry, false).unwrap_err().to_string();
    assert!(error.contains("reconcile"));
    assert!(retry.calls.is_empty());
    fixture.apply(&mut retry, true).unwrap();
    assert!(fixture.file.load().unwrap().unresolved_operation.is_none());
}

#[test]
fn every_entered_failure_path_releases_the_lease_and_preserves_failure_status() {
    for failed_phase in [
        "verify",
        "reserve",
        "lease",
        "prepare",
        "preview",
        "apply",
        "readiness",
    ] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        backend.fail = Some(failed_phase);
        assert!(
            fixture.apply(&mut backend, false).is_err(),
            "{failed_phase}"
        );
        assert_eq!(backend.calls.last(), Some(&"release"));
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|call| **call == "release")
                .count(),
            1
        );
        let receipt = fixture.last();
        assert!(matches!(
            phase_status(&receipt, failed_phase),
            PhaseStatus::Unknown { .. } | PhaseStatus::Failed { .. }
        ));
        assert!(fixture.file.load().is_ok());
    }
}

#[test]
fn malformed_or_foreign_outputs_are_an_uncertain_apply_and_never_become_saved_readiness() {
    for mutation in [
        "version",
        "network",
        "account",
        "region",
        "retention",
        "missing-instance",
    ] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        match mutation {
            "version" => backend.output.schema_version = 99,
            "network" => backend.output.network_id = Uuid::new_v4(),
            "account" => backend.output.scope.account_id = "999999999999".into(),
            "region" => backend.output.scope.region = "us-west-2".into(),
            "retention" => backend.output.retain_chain_disk = false,
            _ => backend.output.instance_id.clear(),
        }
        assert!(fixture.apply(&mut backend, false).is_err());
        assert!(matches!(
            phase_status(&fixture.last(), "apply"),
            PhaseStatus::Unknown { .. }
        ));
        assert!(fixture.file.load().unwrap().outputs.is_none());
        assert!(!backend.calls.contains(&"readiness"));
    }
}

#[test]
fn default_destroy_preserves_chain_data_and_removes_stack_only_after_cleanup() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    fixture.apply(&mut backend, false).unwrap();
    backend.calls.clear();
    let receipt = fixture.destroy(&mut backend, false, false).unwrap();
    assert!(receipt
        .phases
        .iter()
        .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. })));
    let saved = fixture.file.load().unwrap();
    assert!(saved.destroyed);
    assert_eq!(saved.cleanup.unwrap().retained_volumes, ["vol-12345678"]);
    assert_eq!(backend.delete_choices, [false]);
    assert!(
        backend
            .calls
            .iter()
            .position(|step| *step == "cleanup")
            .unwrap()
            < backend
                .calls
                .iter()
                .position(|step| *step == "remove-stack")
                .unwrap()
    );
    assert!(fixture.apply(&mut backend, false).is_err());
}

#[test]
fn delete_data_is_explicit_and_changes_the_saved_operation_input() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    let retain = fixture.destroy(&mut backend, false, false).unwrap();
    let delete = fixture.destroy(&mut backend, true, false).unwrap();
    assert_eq!(backend.delete_choices, [false, true]);
    assert_ne!(retain.inputs.config_sha256, delete.inputs.config_sha256);
    assert!(fixture
        .file
        .load()
        .unwrap()
        .cleanup
        .unwrap()
        .retained_volumes
        .is_empty());
}

#[test]
fn incomplete_cleanup_keeps_inventory_evidence_and_does_not_remove_stack() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    backend.cleanup = Some(CleanupReport {
        retained_artifact_prefixes: vec![],
        remaining_resources: vec!["instance:i-1234567890abcdef0".into()],
        retained_volumes: vec!["vol-12345678".into()],
        shared_backend_preserved: true,
    });
    assert!(fixture.destroy(&mut backend, false, false).is_err());
    assert!(!backend.calls.contains(&"remove-stack"));
    let saved = fixture.file.load().unwrap();
    assert!(!saved.destroyed);
    assert_eq!(saved.cleanup.unwrap().remaining_resources.len(), 1);
    assert!(matches!(
        phase_status(&fixture.last(), "cleanup"),
        PhaseStatus::Unknown { .. }
    ));
    assert_eq!(backend.calls.last(), Some(&"release"));
}

#[test]
fn requested_disk_deletion_and_backend_preservation_must_be_confirmed() {
    for report in [
        CleanupReport {
            retained_artifact_prefixes: vec!["s3://test/deployment-artifacts/".into()],
            remaining_resources: vec![],
            retained_volumes: vec![],
            shared_backend_preserved: true,
        },
        CleanupReport {
            retained_artifact_prefixes: vec![],
            remaining_resources: vec![],
            retained_volumes: vec!["vol-12345678".into()],
            shared_backend_preserved: true,
        },
        CleanupReport {
            retained_artifact_prefixes: vec![],
            remaining_resources: vec![],
            retained_volumes: vec![],
            shared_backend_preserved: false,
        },
    ] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        backend.cleanup = Some(report);
        assert!(fixture.destroy(&mut backend, true, false).is_err());
        assert!(!fixture.file.load().unwrap().destroyed);
        assert!(!backend.calls.contains(&"remove-stack"));
        assert_eq!(backend.calls.last(), Some(&"release"));
    }
}

#[test]
fn failed_destroy_or_stack_removal_is_not_reported_as_complete() {
    for phase in ["destroy", "cleanup", "remove-stack"] {
        let mut fixture = Fixture::new();
        let mut backend = fixture.backend();
        backend.fail = Some(phase);
        assert!(fixture.destroy(&mut backend, false, false).is_err());
        assert!(!fixture.file.load().unwrap().destroyed);
        assert!(matches!(
            phase_status(&fixture.last(), phase),
            PhaseStatus::Unknown { .. }
        ));
        assert_eq!(backend.calls.last(), Some(&"release"));
        if phase != "remove-stack" {
            assert!(!backend.calls.contains(&"remove-stack"));
        }
    }
}

#[test]
fn lease_release_failure_is_returned_even_after_successful_cloud_phases() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    backend.release_failure = true;
    assert!(fixture
        .apply(&mut backend, false)
        .unwrap_err()
        .to_string()
        .contains("release"));
    assert!(fixture.file.load().unwrap().outputs.is_some());
    assert_eq!(backend.calls.last(), Some(&"release"));
}

#[test]
fn deployment_binding_scope_and_retention_are_validated_before_external_effects() {
    let mut fixture = Fixture::new();
    let mut backend = fixture.backend();
    fixture.deployment.spec.network_id = Uuid::new_v4();
    assert!(fixture.apply(&mut backend, false).is_err());
    assert!(backend.calls.is_empty());
    fixture.deployment.spec.network_id = fixture.binding.network_id;
    fixture.deployment.spec.retain_chain_disk = false;
    assert!(fixture.apply(&mut backend, false).is_err());
    assert!(backend.calls.is_empty());
}

#[test]
fn local_lock_excludes_a_second_writer_and_releases_on_drop() {
    let fixture = Fixture::new();
    assert!(DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).is_err());
    let Fixture {
        store,
        binding,
        file,
        ..
    } = fixture;
    drop(file);
    assert!(DeploymentFile::open(store.root(), binding.network_id).is_ok());
}

#[test]
fn status_snapshots_can_read_while_a_writer_publishes_without_creating_state() {
    let mut fixture = Fixture::new();
    let read =
        || DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).unwrap();
    assert!(read().last_operation.is_none());
    let id = Uuid::new_v4();
    fixture.deployment.last_operation = Some(id);
    fixture.file.save(&fixture.deployment).unwrap();
    assert_eq!(read().last_operation, Some(id));
    assert!(DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).is_err());

    let missing_id = Uuid::new_v4();
    assert!(DeploymentFile::read_snapshot(fixture.store.root(), missing_id).is_err());
    assert!(!fixture
        .store
        .root()
        .join("foundation")
        .join(missing_id.to_string())
        .exists());
    let missing_root = fixture._root.path().join("missing-state");
    assert!(DeploymentFile::read_snapshot(&missing_root, missing_id).is_err());
    assert!(!missing_root.exists());
    assert!(DeploymentFile::read_snapshot(fixture.store.root(), Uuid::nil()).is_err());
}

#[test]
fn deployment_file_rejects_mismatched_directory_identity_and_unknown_schema() {
    let fixture = Fixture::new();
    let path = fixture.file.directory().join("deployment.json");
    let mut wrong = fixture.deployment.clone();
    wrong.spec.network_id = Uuid::new_v4();
    assert!(fixture.file.save(&wrong).is_err());
    foundation::write_json(&path, &wrong).unwrap();
    assert!(fixture.file.load().is_err());
    assert!(
        DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).is_err()
    );
    wrong.spec.network_id = fixture.binding.network_id;
    wrong.schema_version = 99;
    foundation::write_json(&path, &wrong).unwrap();
    assert!(fixture.file.load().is_err());
    assert!(
        DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).is_err()
    );
}

#[cfg(unix)]
#[test]
fn deployment_paths_reject_symlinks_without_touching_the_targets() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let target = fixture._root.path().join("outside.json");
    fs::write(&target, b"original").unwrap();
    let path = fixture.file.directory().join("deployment.json");
    fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();
    assert!(fixture.file.load().is_err());
    assert!(
        DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).is_err()
    );
    assert!(fixture.file.save(&fixture.deployment).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"original");
    let other_id = Uuid::new_v4();
    let linked_dir = fixture
        .store
        .root()
        .join("foundation")
        .join(other_id.to_string());
    symlink(fixture.file.directory(), linked_dir).unwrap();
    assert!(DeploymentFile::open(fixture.store.root(), other_id).is_err());
    assert!(DeploymentFile::read_snapshot(fixture.store.root(), other_id).is_err());

    let alias = fixture._root.path().join("state-alias");
    symlink(fixture.store.root(), &alias).unwrap();
    assert!(DeploymentFile::read_snapshot(&alias, fixture.binding.network_id).is_err());
    let other_root = fixture._root.path().join("other-state");
    fs::create_dir(&other_root).unwrap();
    symlink(
        fixture.store.root().join("foundation"),
        other_root.join("foundation"),
    )
    .unwrap();
    assert!(DeploymentFile::read_snapshot(&other_root, fixture.binding.network_id).is_err());
}

// The subprocess boundary makes a blocking-open regression fail quickly rather
// than leaving the test runner stuck on a FIFO indefinitely.
#[cfg(unix)]
#[test]
fn special_file_probe() {
    let Some(path) = std::env::var_os("ZDN_FOUNDATION_FIFO_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let mode = std::env::var("ZDN_FOUNDATION_FIFO_MODE").unwrap();
    if mode == "read" {
        assert!(foundation::read_json::<Value>(&path).is_err());
    } else if mode == "write" {
        assert!(foundation::write_json(&path, &json!({"test":true})).is_err());
    } else if mode == "snapshot" {
        let id = Uuid::parse_str(&std::env::var("ZDN_FOUNDATION_FIFO_ID").unwrap()).unwrap();
        assert!(DeploymentFile::read_snapshot(&path, id).is_err());
    } else {
        let id = Uuid::parse_str(&std::env::var("ZDN_FOUNDATION_FIFO_ID").unwrap()).unwrap();
        assert!(DeploymentFile::open(&path, id).is_err());
    }
}

#[cfg(unix)]
#[test]
fn fifo_state_files_and_locks_are_rejected_without_blocking() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for mode in ["read", "write", "lock", "snapshot"] {
        let root = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let directory = root.path().join("foundation").join(id.to_string());
        fs::create_dir_all(&directory).unwrap();
        let fifo = directory.join(if mode == "lock" {
            "operation.lock"
        } else {
            "deployment.json"
        });
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let path = if matches!(mode, "lock" | "snapshot") {
            root.path()
        } else {
            &fifo
        };
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "special_file_probe", "--nocapture"])
            .env("ZDN_FOUNDATION_FIFO_PATH", path)
            .env("ZDN_FOUNDATION_FIFO_MODE", mode)
            .env("ZDN_FOUNDATION_FIFO_ID", id.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{mode} accepted a special state file");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{mode} blocked on a special state file");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
