use std::fs;
use tempfile::TempDir;
use uuid::Uuid;
use zdn::{
    aws::{LocalProfile, TeamAws, TeamDefinition, TeamState},
    config::Size,
    foundation::{Deployment, DeploymentFile},
    infra::FoundationSpec,
    state::{
        BindingContext, BindingExport, OperationInput, OperationReceipt, PhaseRecord, PhaseStatus,
        Reservation, Scope, StateStore,
    },
};

struct Fixture {
    root: TempDir,
    store: StateStore,
    context: BindingContext,
    receipt: BindingExport,
    profile: LocalProfile,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("network.yaml"), "name: receiver\n").unwrap();
        let scope = Scope {
            team_id: "team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let context =
            BindingContext::new(source.join("network.yaml"), None, None, scope.clone()).unwrap();
        let store = StateStore::open(root.path().join("state")).unwrap();
        let profile = LocalProfile {
            aws_profile: "receiver".into(),
            team: TeamDefinition {
                deployment: None, api_version: "zdn-team/v1alpha1".into(), team_id: scope.team_id.clone(), revision: 1,
                bootstrap_id: Uuid::new_v4(),
                aws: TeamAws { account_id: scope.account_id.clone(), region: scope.region.clone() },
                state: TeamState {
                    backend: "s3://zdn-test-foundation/pulumi/team".into(),
                    kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
                },
            },
        };
        let receipt = BindingExport {
            version: 1,
            network_id: Uuid::new_v4(),
            scope,
            label: "shared".into(),
            reservation: Reservation::Unreserved,
        };
        Self {
            root,
            store,
            context,
            receipt,
            profile,
        }
    }

    fn stage(&self) -> std::path::PathBuf {
        let staging = self.root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let file = DeploymentFile::open(&staging, self.receipt.network_id).unwrap();
        let deployment = Deployment::new(
            FoundationSpec {
                network_id: self.receipt.network_id,
                scope: self.receipt.scope.clone(),
                aws_profile: "receiver".into(),
                ami_id: "ami-1234567890abcdef0".into(),
                availability_zone: "us-east-1a".into(),
                size: Size::Medium,
                retain_chain_disk: true,
            },
            self.profile.team.clone(),
        )
        .unwrap();
        file.save(&deployment).unwrap();
        staging
    }

    fn operation(&self) -> OperationReceipt {
        OperationReceipt {
            version: 1,
            operation_id: Uuid::new_v4(),
            network_id: self.receipt.network_id,
            scope: self.receipt.scope.clone(),
            kind: "devnet-up".into(),
            inputs: OperationInput {
                config_sha256: "a".repeat(64),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            revision: 17,
            state_revision: 12,
            cancel_requested: true,
            phases: vec![PhaseRecord {
                name: "prepare".into(),
                status: PhaseStatus::Cancelled,
            }],
        }
    }
}

#[test]
fn state_publication_preserves_all_receipt_evidence() {
    let f = Fixture::new();
    let staging = f.stage();
    let operation = f.operation();
    let binding = f
        .store
        .import_handoff(
            &f.context,
            f.receipt.network_id,
            &f.receipt,
            std::slice::from_ref(&operation),
            &staging,
        )
        .unwrap();
    assert_eq!(f.store.binding(&f.context).unwrap(), binding);
    assert_eq!(
        f.store.operation(operation.operation_id).unwrap(),
        operation
    );
    assert_eq!(
        DeploymentFile::read_snapshot(f.store.root(), binding.network_id)
            .unwrap()
            .spec
            .aws_profile,
        "receiver"
    );
    assert!(!staging
        .join("foundation")
        .join(binding.network_id.to_string())
        .exists());
}

#[test]
fn existing_orphan_and_its_live_writer_are_never_replaced() {
    let f = Fixture::new();
    let staging = f.stage();
    let live = DeploymentFile::open(f.store.root(), f.receipt.network_id).unwrap();
    fs::write(live.directory().join("sentinel"), "keep").unwrap();
    assert!(f
        .store
        .import_handoff(&f.context, f.receipt.network_id, &f.receipt, &[], &staging)
        .is_err());
    assert!(f.store.binding(&f.context).is_err());
    assert_eq!(
        fs::read_to_string(live.directory().join("sentinel")).unwrap(),
        "keep"
    );
    assert!(staging
        .join("foundation")
        .join(f.receipt.network_id.to_string())
        .join("deployment.json")
        .exists());
}

#[test]
fn binding_collision_fails_before_touching_staging_or_destination() {
    let f = Fixture::new();
    let original = f.store.bind(&f.context, "existing").unwrap();
    let absent = f.root.path().join("not-created");
    assert!(f
        .store
        .import_handoff(&f.context, f.receipt.network_id, &f.receipt, &[], &absent)
        .is_err());
    assert!(!absent.exists());
    assert!(!f.store.root().join("foundation").exists());
    assert_eq!(f.store.binding(&f.context).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn empty_destination_or_symlink_is_never_replaced_or_bound() {
    for kind in ["empty-directory", "symlink"] {
        let f = Fixture::new();
        let staging = f.stage();
        let parent = f.store.root().join("foundation");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join(f.receipt.network_id.to_string());
        if kind == "empty-directory" {
            fs::create_dir(&destination).unwrap();
        } else {
            std::os::unix::fs::symlink("absent", &destination).unwrap();
        }
        assert!(f
            .store
            .import_handoff(&f.context, f.receipt.network_id, &f.receipt, &[], &staging)
            .is_err());
        assert!(f.store.binding(&f.context).is_err());
        if kind == "empty-directory" {
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        } else {
            assert_eq!(
                fs::read_link(&destination).unwrap(),
                std::path::Path::new("absent")
            );
        }
        assert!(staging
            .join("foundation")
            .join(f.receipt.network_id.to_string())
            .join("deployment.json")
            .is_file());
    }
}

#[test]
fn operation_collision_is_rejected_before_any_deployment_write() {
    let f = Fixture::new();
    let second = f.context.config_path.parent().unwrap().join("other.yaml");
    fs::write(&second, "name: other\n").unwrap();
    let context = BindingContext::new(second, None, None, f.receipt.scope.clone()).unwrap();
    let existing = f.store.bind(&context, "other").unwrap();
    let mut incoming = f.operation();
    let saved = f
        .store
        .begin_operation_with_id(
            &existing,
            "devnet-up",
            incoming.inputs.clone(),
            &["prepare"],
            incoming.operation_id,
        )
        .unwrap();
    incoming.network_id = f.receipt.network_id;
    let absent = f.root.path().join("not-created");
    assert!(f
        .store
        .import_handoff(
            &f.context,
            f.receipt.network_id,
            &f.receipt,
            &[incoming],
            &absent
        )
        .is_err());
    assert!(!absent.exists());
    assert!(!f.store.root().join("foundation").exists());
    assert!(f.store.binding(&f.context).is_err());
    assert_eq!(f.store.operation(saved.operation_id).unwrap(), saved);
}

#[test]
fn active_staging_writer_prevents_publication() {
    let f = Fixture::new();
    let staging = f.stage();
    let _writer = DeploymentFile::open(&staging, f.receipt.network_id).unwrap();
    assert!(f
        .store
        .import_handoff(&f.context, f.receipt.network_id, &f.receipt, &[], &staging)
        .is_err());
    assert!(f.store.binding(&f.context).is_err());
    assert!(!f.store.root().join("foundation").exists());
}

#[test]
fn importer_rejects_hash_mismatch_and_symlink_without_binding() {
    let f = Fixture::new();
    let archive = f.root.path().join("archive.tar");
    fs::write(&archive, "not a tar archive").unwrap();
    assert!(zdn::handoff::import::import(
        &f.store,
        &f.context,
        f.receipt.network_id,
        &f.profile,
        &archive,
        &"0".repeat(64)
    )
    .is_err());
    #[cfg(unix)]
    {
        let link = f.root.path().join("link.tar");
        std::os::unix::fs::symlink(&archive, &link).unwrap();
        assert!(zdn::handoff::import::import(
            &f.store,
            &f.context,
            f.receipt.network_id,
            &f.profile,
            &link,
            &zdn::devnet::sha256(b"not a tar archive")
        )
        .is_err());
    }
    assert!(f.store.binding(&f.context).is_err());
    assert!(!f.store.root().join("foundation").exists());
}
