#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zdn::{
    host::{files::Directory, NewVolumeAuthorization},
    lightwallet_service::{cache::Installation, LightwalletInstallSpec, INSTALL_API_VERSION},
};

#[path = "support/lightwallet_service.rs"]
mod fixture;

fn spec() -> LightwalletInstallSpec {
    let (host, service) = fixture::specs();
    let object = |key: &str| {
        let mut object = host.helper.clone();
        object.key = format!("team/test/{key}");
        object
    };
    LightwalletInstallSpec {
        api_version: INSTALL_API_VERSION.into(),
        image_record: object("lightwallet-image.json"),
        image_manifest: object("lightwallet-image-manifest.json"),
        image_config: object("lightwallet-image-config.json"),
        new_volume: Some(NewVolumeAuthorization {
            api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
            volume_id: service.cache_volume_id.clone(),
            size_bytes: service.cache_bytes,
            instance_id: "i-0123456789abcdef0".into(),
            created_at: "2026-10-16T12:00:00Z".into(),
            creation_intent_sha256: "d".repeat(64),
            checkpoint_sha256: "e".repeat(64),
        }),
        host,
        service,
    }
}

fn open(root: &tempfile::TempDir) -> Directory {
    Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap()
}

fn encoded(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn original_cache_identity_intent_and_ordered_claim_survive_exact_retries() {
    let spec = spec();
    let metadata_root = tempfile::tempdir().unwrap();
    let mounted_root = tempfile::tempdir().unwrap();
    let metadata = open(&metadata_root);
    let mounted = open(&mounted_root);
    let mut installation = Installation::acquire(&metadata, &spec).unwrap();
    let hash = |value: &Value| hex::encode(Sha256::digest(serde_json::to_vec(value).unwrap()));
    let service_hash = hash(&json!({"host":spec.host,"service":spec.service}));
    let cache = json!({
        "apiVersion":"zdn-lightwallet-service/v1alpha1",
        "deploymentId":spec.host.deployment_id,"nodeId":spec.host.node_id,
        "consensusFingerprint":spec.host.consensus_fingerprint,
        "volumeId":spec.service.cache_volume_id,"cacheBytes":spec.service.cache_bytes,
        "serviceSha256":service_hash,
    });
    let identity = json!({
        "apiVersion":"zdn-lightwallet-install/v1alpha1",
        "installSha256":hex::encode(Sha256::digest(serde_json::to_vec(&spec).unwrap())),
        "serviceSha256":service_hash,"cacheIdentity":cache,
    });
    assert_eq!(
        metadata.read("identity.json", 16384).unwrap(),
        encoded(identity.clone())
    );
    assert_eq!(installation.cache_identity(), encoded(cache.clone()));
    assert!(Installation::acquire(&metadata, &spec).is_err());
    assert!(installation.record_volume_claim(&mounted).is_err());
    assert!(installation.claim_mounted(&mounted, true).is_err());
    assert!(!mounted_root
        .path()
        .join(".zdn-lightwalletd-volume.json")
        .exists());
    installation.begin_format().unwrap();
    assert_eq!(
        metadata.read("format-intent.json", 16384).unwrap(),
        encoded(json!({
            "apiVersion":"zdn-lightwallet-format/v1alpha1", "identity":identity,
            "newVolume":spec.new_volume,
        }))
    );
    assert!(installation.begin_format().is_err());
    assert!(installation.claim_mounted(&mounted, false).is_err());
    mounted.ensure_directory("lost+found", 0o700).unwrap();
    installation.claim_mounted(&mounted, true).unwrap();
    let claim = mounted_root.path().join(".zdn-lightwalletd-volume.json");
    let inode = claim.metadata().unwrap().ino();
    assert_eq!(fs::read(&claim).unwrap(), encoded(cache.clone()));
    assert_eq!(claim.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        metadata.read("volume-claimed.json", 16384).unwrap(),
        encoded(cache)
    );
    drop(installation);
    // A lost root-disk acknowledgement can be recovered from a retained claim,
    // without another format or adoption of an unclaimed filesystem.
    fs::remove_file(metadata_root.path().join("volume-claimed.json")).unwrap();
    let mut retry = Installation::acquire(&metadata, &spec).unwrap();
    retry.verify_format_intent().unwrap();
    retry.claim_mounted(&mounted, false).unwrap();
    assert_eq!(claim.metadata().unwrap().ino(), inode);
    assert!(retry.begin_format().is_err());
}

#[test]
fn changed_installations_and_creation_authority_fail_before_record_mutation() {
    let spec = spec();
    let root = tempfile::tempdir().unwrap();
    let directory = open(&root);
    let installation = Installation::acquire(&directory, &spec).unwrap();
    drop(installation);
    let identity = fs::read(root.path().join("identity.json")).unwrap();
    for changed in [0, 1, 2, 3] {
        let mut other = spec.clone();
        match changed {
            0 => other.new_volume = None,
            1 => other.new_volume.as_mut().unwrap().checkpoint_sha256 = "f".repeat(64),
            2 => other.service.memory_bytes += 1024,
            _ => other.new_volume.as_mut().unwrap().volume_id = spec.host.volume_id.clone(),
        }
        assert!(Installation::acquire(&directory, &other).is_err());
        assert_eq!(
            fs::read(root.path().join("identity.json")).unwrap(),
            identity
        );
        assert!(!root.path().join("format-intent.json").exists());
    }
    let pristine = tempfile::tempdir().unwrap();
    let mut invalid = spec.clone();
    invalid.new_volume = None;
    assert!(Installation::acquire(&open(&pristine), &invalid).is_err());
    assert!(fs::read_dir(pristine.path()).unwrap().next().is_none());
    Installation::acquire(&directory, &spec).unwrap();
}

#[test]
fn unclaimed_foreign_or_linked_filesystems_never_receive_an_acknowledgement() {
    for case in [
        "data",
        "lost+found-data",
        "lost+found-link",
        "foreign-claim",
        "noncanonical-claim",
        "linked-claim",
        "unsafe-claim",
    ] {
        let metadata_root = tempfile::tempdir().unwrap();
        let mounted_root = tempfile::tempdir().unwrap();
        let foreign_root = tempfile::tempdir().unwrap();
        let metadata = open(&metadata_root);
        let mounted = open(&mounted_root);
        let mut installation = Installation::acquire(&metadata, &spec()).unwrap();
        installation.begin_format().unwrap();
        match case {
            "data" => fs::write(mounted_root.path().join("foreign"), b"data").unwrap(),
            "lost+found-data" => {
                let lost_found = mounted.ensure_directory("lost+found", 0o700).unwrap();
                lost_found.publish("foreign", b"data", 0o600).unwrap();
            }
            "lost+found-link" => {
                symlink(foreign_root.path(), mounted_root.path().join("lost+found")).unwrap()
            }
            "foreign-claim" => mounted
                .publish(".zdn-lightwalletd-volume.json", b"{}\n", 0o600)
                .unwrap(),
            "noncanonical-claim" => mounted
                .publish(
                    ".zdn-lightwalletd-volume.json",
                    installation.cache_identity().strip_suffix(b"\n").unwrap(),
                    0o600,
                )
                .unwrap(),
            "linked-claim" => {
                fs::write(
                    foreign_root.path().join("claim"),
                    installation.cache_identity(),
                )
                .unwrap();
                symlink(
                    foreign_root.path().join("claim"),
                    mounted_root.path().join(".zdn-lightwalletd-volume.json"),
                )
                .unwrap();
            }
            _ => {
                mounted
                    .publish(
                        ".zdn-lightwalletd-volume.json",
                        installation.cache_identity(),
                        0o600,
                    )
                    .unwrap();
                fs::set_permissions(
                    mounted_root.path().join(".zdn-lightwalletd-volume.json"),
                    fs::Permissions::from_mode(0o666),
                )
                .unwrap();
            }
        }
        assert!(
            installation.claim_mounted(&mounted, true).is_err(),
            "{case}"
        );
        assert!(
            !metadata_root.path().join("volume-claimed.json").exists(),
            "{case}"
        );
        assert!(installation.begin_format().is_err());
    }
}

#[test]
fn uncertain_history_and_conflicting_acknowledgements_are_preserved() {
    for name in ["format-intent.json", "volume-claimed.json"] {
        let metadata_root = tempfile::tempdir().unwrap();
        let mounted_root = tempfile::tempdir().unwrap();
        let metadata = open(&metadata_root);
        let mounted = open(&mounted_root);
        let mut installation = Installation::acquire(&metadata, &spec()).unwrap();
        metadata.publish(name, b"foreign\n", 0o600).unwrap();
        let before = fs::read(metadata_root.path().join(name)).unwrap();
        assert!(installation.begin_format().is_err());
        assert!(installation.claim_mounted(&mounted, true).is_err());
        if name == "volume-claimed.json" {
            mounted
                .publish(
                    ".zdn-lightwalletd-volume.json",
                    installation.cache_identity(),
                    0o600,
                )
                .unwrap();
            assert!(installation.record_volume_claim(&mounted).is_err());
        }
        assert_eq!(fs::read(metadata_root.path().join(name)).unwrap(), before);
    }
}
