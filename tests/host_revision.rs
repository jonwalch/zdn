#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{
        files::Directory,
        runtime::{
            revision::{self, Journal, Phase, Request, Snapshot},
            Manifest, Selection, PROTOCOL,
        },
        volume::Installation,
        HostInstallSpec, S3Object,
    },
    image,
};

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

fn original() -> Manifest {
    let consensus: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let deployment = Uuid::new_v4();
    let mut options = RuntimeOptions::new(deployment, "node-1");
    options.network.listen_addr = "10.90.1.10:18233".into();
    options.network.peers = vec!["10.90.1.11:18233".into()];
    let runtime = render_runtime_config(&consensus, &options).unwrap();
    let object = |key: &str| S3Object {
        bucket: "zdn-artifacts-test".into(),
        key: format!("team/test/{key}"),
        sha256: "a".repeat(64),
        bytes: 128,
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
    };
    let spec = HostInstallSpec {
        api_version: zdn::host::API_VERSION.into(),
        deployment_id: deployment,
        node_id: "node-1".into(),
        consensus_fingerprint: runtime.consensus_fingerprint,
        volume_id: "vol-0123456789abcdef0".into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/zakura@sha256:{}",
            "b".repeat(64)
        ),
        config_toml: runtime.config_toml,
        config_sha256: runtime.config_sha256,
        role: "follower".into(),
        block_interval_seconds: None,
        memory_bytes: 24 << 30,
        host_reserve_bytes: 4 << 30,
        cpu_millis: 3500,
        manifest: object("manifest"),
        bundle: object("bundle"),
        helper: object("helper"),
        image_record: object("image-record"),
        image_manifest: object("image-manifest"),
        new_volume: None,
    };
    Manifest::new(
        spec,
        Selection {
            protocol: PROTOCOL.into(),
            helper: object("native-helper"),
        },
    )
    .unwrap()
}

fn request(original: &Manifest) -> Request {
    let mut manifest = original.spec.image_manifest.clone();
    manifest.key = "new/manifest".into();
    manifest.sha256 = "c".repeat(64);
    let mut config = manifest.clone();
    config.key = "new/config".into();
    config.sha256 = "d".repeat(64);
    let mut record = original.spec.image_record.clone();
    record.key = "new/record".into();
    record.sha256 = "1".repeat(64);
    Request {
        api_version: revision::API_VERSION.into(),
        original: original.clone(),
        update_id: Uuid::new_v4(),
        expected_image: original.spec.image.clone(),
        expected_update_id: None,
        image: image::ImageRecord {
            api_version: image::API_VERSION.into(),
            image: original
                .spec
                .image
                .replace(&"b".repeat(64), &"c".repeat(64)),
            config_digest: format!("sha256:{}", "d".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: image::ImageProvenance::Source {
                revision: "e".repeat(40),
                snapshot_sha256: "f".repeat(64),
            },
            capabilities: Default::default(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        },
        image_record: record,
        image_manifest: manifest,
        image_config: config,
    }
}

fn directory(root: &tempfile::TempDir) -> Directory {
    Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap()
}

fn finish(journal: &mut Journal<'_, '_>, id: Uuid) {
    journal.advance(id, Phase::Stopping).unwrap();
    journal.advance(id, Phase::Activating).unwrap();
    journal.publish_active(id).unwrap();
    journal.advance(id, Phase::Ready).unwrap();
    journal.release_maintenance(id).unwrap();
    journal.advance(id, Phase::Done).unwrap();
}

#[test]
fn phase_edges_selection_hold_and_original_identity() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("phase_edges_selection_hold_and_original_identity") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let etc = directory(&root);
    let updates = etc.ensure_directory(revision::NAMESPACE, 0o700).unwrap();
    let original = original();
    let before = original.bytes().unwrap();
    let req = request(&original);
    let mut installation = Installation::acquire(&etc, &original.spec).unwrap();
    let identity = installation.identity().to_vec();
    assert!(Installation::acquire(&etc, &original.spec).is_err());
    let mut journal = Journal::open(&updates, &original, &mut installation).unwrap();
    assert!(journal.advance(req.update_id, Phase::Stopping).is_err());
    journal.begin(&req).unwrap();
    let receipt_path = root
        .path()
        .join(revision::NAMESPACE)
        .join(format!("{}.json", req.update_id));
    let receipt_inode = receipt_path.metadata().unwrap().ino();
    journal.begin(&req).unwrap();
    assert_eq!(receipt_path.metadata().unwrap().ino(), receipt_inode);
    assert!(journal.advance(Uuid::new_v4(), Phase::Stopping).is_err());
    for phase in [Phase::Activating, Phase::Ready, Phase::Done] {
        assert!(journal.advance(req.update_id, phase).is_err());
    }
    assert!(journal.publish_active(req.update_id).is_err());
    assert!(journal.release_maintenance(req.update_id).is_err());
    assert!(journal.hold_maintenance(req.update_id).is_err());
    assert!(journal.begin(&request(&original)).is_err());
    let state = journal.advance(req.update_id, Phase::Stopping).unwrap();
    assert!(state.producer_hold && state.active.is_none());
    // Read-only observation does not attempt to take the retained parent lock.
    assert!(Snapshot::load(&updates, &original).unwrap().producer_hold);
    journal.advance(req.update_id, Phase::Stopping).unwrap();
    assert!(journal.advance(req.update_id, Phase::Staging).is_err());
    journal.advance(req.update_id, Phase::Activating).unwrap();
    assert!(journal.advance(req.update_id, Phase::Ready).is_err());
    journal.publish_active(req.update_id).unwrap();
    journal.publish_active(req.update_id).unwrap();
    journal.advance(req.update_id, Phase::Ready).unwrap();
    assert!(journal.advance(req.update_id, Phase::Done).is_err());
    journal.release_maintenance(req.update_id).unwrap();
    journal.release_maintenance(req.update_id).unwrap();
    assert!(journal.hold_maintenance(Uuid::new_v4()).is_err());
    let held = journal.hold_maintenance(req.update_id).unwrap();
    assert!(held.producer_hold);
    assert_eq!(held.transaction.unwrap().phase, Phase::Ready);
    assert!(journal.advance(req.update_id, Phase::Done).is_err());
    journal.release_maintenance(req.update_id).unwrap();
    journal.advance(req.update_id, Phase::Done).unwrap();
    assert!(journal.hold_maintenance(req.update_id).is_err());
    journal.begin(&req).unwrap();
    assert!(journal.publish_active(req.update_id).is_err());
    let state = Snapshot::load(&updates, &original).unwrap();
    assert!(!state.producer_hold);
    assert_eq!(state.active.unwrap().image, req.image);
    assert_eq!(original.bytes().unwrap(), before);
    assert_eq!(etc.read("identity.json", 8192).unwrap(), identity);
    let mut second = request(&original);
    assert!(journal.begin(&second).is_err());
    second.expected_image = req.image.image.clone();
    second.expected_update_id = Some(req.update_id);
    journal.begin(&second).unwrap();
    assert!(journal.begin(&req).is_err());
    finish(&mut journal, second.update_id);
    assert!(journal.begin(&req).is_err());
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.runtime.revision.begin",
                "host.runtime.revision.advance",
                "host.runtime.revision.publish_active",
                "host.runtime.revision.hold_maintenance",
                "host.runtime.revision.release_maintenance",
                "host.files.replace",
            ],
            &[
                root.path().to_str().unwrap(),
                &req.update_id.to_string(),
                &req.image.image,
                &original.spec.config_toml,
            ],
        );
        trace.assert_child("host.files.replace", "host.runtime.revision.advance");
    }
}

#[test]
fn interrupted_transaction_receipt_prefix_recovers_only_exact_request() {
    let root = tempfile::tempdir().unwrap();
    let etc = directory(&root);
    let updates = etc.ensure_directory(revision::NAMESPACE, 0o700).unwrap();
    let original = original();
    let req = request(&original);
    let mut installation = Installation::acquire(&etc, &original.spec).unwrap();
    let mut journal = Journal::open(&updates, &original, &mut installation).unwrap();
    journal.begin(&req).unwrap();
    let receipt = root
        .path()
        .join(revision::NAMESPACE)
        .join(format!("{}.json", req.update_id));
    // Interrupted create-only publication may leave its private staging link.
    let pending = root
        .path()
        .join(revision::NAMESPACE)
        .join(".pending-interrupted");
    fs::hard_link(&receipt, &pending).unwrap();
    journal.begin(&req).unwrap();
    fs::remove_file(pending).unwrap();
    fs::remove_file(&receipt).unwrap(); // durable transaction, receipt not yet published
    assert_eq!(
        Snapshot::load(&updates, &original)
            .unwrap()
            .transaction
            .unwrap()
            .phase,
        Phase::Staging
    );
    assert!(journal.advance(req.update_id, Phase::Stopping).is_err());
    assert!(journal.begin(&request(&original)).is_err());
    let mut conflict = req.clone();
    conflict.image_record.key = "changed/record".into();
    assert!(journal.begin(&conflict).is_err());
    journal.begin(&req).unwrap();
    assert_eq!(fs::read(&receipt).unwrap(), req.bytes().unwrap());
    assert!(journal.begin(&conflict).is_err());
    journal.advance(req.update_id, Phase::Stopping).unwrap();
    fs::remove_file(receipt).unwrap();
    assert!(Snapshot::load(&updates, &original).is_err());
}

#[test]
fn validation_precedes_effects_and_installation_is_exactly_bound() {
    let root = tempfile::tempdir().unwrap();
    let etc = directory(&root);
    let updates = etc.ensure_directory(revision::NAMESPACE, 0o700).unwrap();
    let original = original();
    let req = request(&original);
    let bytes = req.bytes().unwrap();
    assert_eq!(Request::from_slice(&bytes).unwrap().bytes().unwrap(), bytes);
    assert!(Request::from_slice(&bytes[..bytes.len() - 1]).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unknown"] = true.into();
    assert!(Request::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut installation = Installation::acquire(&etc, &original.spec).unwrap();
    let mut foreign = original.clone();
    foreign.spec.cpu_millis += 1;
    foreign.install_sha256 = foreign.spec.install_sha256().unwrap();
    assert!(Journal::open(&updates, &foreign, &mut installation).is_err());
    let mut journal = Journal::open(&updates, &original, &mut installation).unwrap();
    for field in 0..7 {
        let mut bad = req.clone();
        match field {
            0 => bad.image_record.bucket = "foreign-bucket".into(),
            1 => bad.image_manifest.bytes = image::MAX_MANIFEST_BYTES as u64 + 1,
            2 => bad.image_config.sha256 = "0".repeat(64),
            3 => bad.update_id = Uuid::nil(),
            4 => bad.original.runtime.helper.key = "foreign/helper".into(),
            5 => bad.expected_image = bad.image.image.clone(),
            _ => bad.image_config.key = "../config".into(),
        }
        assert!(journal.begin(&bad).is_err(), "case {field}");
        updates.require_absent("state.json").unwrap();
    }
    journal.begin(&req).unwrap();
    let path = root.path().join(revision::NAMESPACE).join("state.json");
    let saved = fs::read(&path).unwrap();
    fs::write(&path, &saved[..saved.len() - 1]).unwrap();
    assert!(Snapshot::load(&updates, &original).is_err());
    fs::write(&path, &saved).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Snapshot::load(&updates, &original).is_err());
    assert!(updates
        .replace("state.json", &saved, saved.len() as u64)
        .is_err());
    fs::remove_file(&path).unwrap();
    symlink("missing", &path).unwrap();
    assert!(Snapshot::load(&updates, &original).is_err());
    assert!(updates
        .replace("state.json", &saved, saved.len() as u64)
        .is_err());
}

#[test]
fn snapshots_recover_phase_prefixes_and_reject_record_disagreement() {
    let root = tempfile::tempdir().unwrap();
    let etc = directory(&root);
    let updates = etc.ensure_directory(revision::NAMESPACE, 0o700).unwrap();
    let original = original();
    let req = request(&original);
    let mut installation = Installation::acquire(&etc, &original.spec).unwrap();
    let mut state = Journal::open(&updates, &original, &mut installation)
        .unwrap()
        .begin(&req)
        .unwrap();
    // Explicit interruption between hold publication and stopping publication.
    state.producer_hold = true;
    let write_state = |state: &Snapshot| {
        let mut bytes = serde_json::to_vec(state).unwrap();
        bytes.push(b'\n');
        updates
            .replace("state.json", &bytes, revision::MAX_REQUEST_BYTES * 2 + 4096)
            .unwrap();
    };
    write_state(&state);
    assert!(Snapshot::load(&updates, &original).unwrap().producer_hold);
    assert!(
        Journal::open(&updates, &original, &mut installation)
            .unwrap()
            .begin(&req)
            .unwrap()
            .producer_hold
    );
    for phase in [Phase::Stopping, Phase::Activating] {
        let mut journal = Journal::open(&updates, &original, &mut installation).unwrap();
        journal.advance(req.update_id, phase).unwrap();
        assert!(journal.release_maintenance(req.update_id).is_err());
    }
    let before_activation = Snapshot::load(&updates, &original).unwrap();
    assert!(before_activation.active.is_none() && before_activation.producer_hold);
    Journal::open(&updates, &original, &mut installation)
        .unwrap()
        .publish_active(req.update_id)
        .unwrap();
    let active = Snapshot::load(&updates, &original).unwrap();
    assert_eq!(
        active.transaction.as_ref().unwrap().phase,
        Phase::Activating
    );
    for case in 0..4 {
        let mut bad = active.clone();
        match case {
            0 => bad.producer_hold = false,
            1 => bad.transaction.as_mut().unwrap().phase = Phase::Stopping,
            2 => bad.active.as_mut().unwrap().image_record.key = "different/record".into(),
            _ => {
                bad.transaction.as_mut().unwrap().phase = Phase::Ready;
                bad.active = None;
            }
        }
        write_state(&bad);
        assert!(Snapshot::load(&updates, &original).is_err(), "case {case}");
    }
    write_state(&active);
    let name = format!("{}.json", req.update_id);
    let receipt = root.path().join(revision::NAMESPACE).join(&name);
    let mut foreign = req.clone();
    foreign.image_record.key = "foreign/receipt".into();
    fs::write(&receipt, foreign.bytes().unwrap()).unwrap();
    assert!(Snapshot::load(&updates, &original).is_err());
    fs::write(&receipt, req.bytes().unwrap()).unwrap();
    Journal::open(&updates, &original, &mut installation)
        .unwrap()
        .advance(req.update_id, Phase::Ready)
        .unwrap();
    let ready = Snapshot::load(&updates, &original).unwrap();
    assert!(ready.producer_hold);
    Journal::open(&updates, &original, &mut installation)
        .unwrap()
        .release_maintenance(req.update_id)
        .unwrap();
    assert!(!Snapshot::load(&updates, &original).unwrap().producer_hold);
    Journal::open(&updates, &original, &mut installation)
        .unwrap()
        .advance(req.update_id, Phase::Done)
        .unwrap();
    assert_eq!(
        Snapshot::load(&updates, &original)
            .unwrap()
            .transaction
            .unwrap()
            .phase,
        Phase::Done
    );
}

#[test]
fn unsafe_replacement_entries_and_bounds_are_not_repaired() {
    let root = tempfile::tempdir().unwrap();
    let directory = directory(&root);
    directory.replace("record", b"one", 3).unwrap();
    directory.replace("record", b"two", 3).unwrap();
    assert_eq!(directory.read("record", 3).unwrap(), b"two");
    assert!(directory.replace("record", b"oversize", 3).is_err());
    fs::hard_link(root.path().join("record"), root.path().join("alias")).unwrap();
    assert!(directory.replace("record", b"new", 3).is_err());
    assert_eq!(directory.read("alias", 3).unwrap(), b"two");
    nix::unistd::mkfifo(&root.path().join("fifo"), nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(directory.replace("fifo", b"new", 3).is_err());
    assert!(directory.replace("../outside", b"new", 3).is_err());
    assert!(!fs::read_dir(root.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".pending-")));
}
