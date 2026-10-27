#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt};
use zdn::{
    host::{files::Directory, runtime, NewVolumeAuthorization},
    lightwallet_service::{
        cache::Installation, native, LightwalletInstallSpec, INSTALL_API_VERSION,
    },
};

#[path = "support/lightwallet_service.rs"]
mod fixture;

fn manifest() -> native::Manifest {
    let (host, service) = fixture::specs();
    let object = |key: &str| {
        let mut object = host.helper.clone();
        object.key = format!("team/test/{key}");
        object
    };
    let node = runtime::Manifest::new(
        host.clone(),
        runtime::Selection {
            protocol: runtime::PROTOCOL.into(),
            helper: host.helper.clone(),
        },
    )
    .unwrap();
    native::Manifest::new(
        LightwalletInstallSpec {
            api_version: INSTALL_API_VERSION.into(),
            image_record: object("image.json"),
            image_manifest: object("manifest.json"),
            image_config: object("config.json"),
            new_volume: Some(NewVolumeAuthorization {
                api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
                volume_id: service.cache_volume_id.clone(),
                size_bytes: service.cache_bytes,
                instance_id: "i-0123456789abcdef0".into(),
                created_at: "2026-10-16T12:00:00Z".into(),
                creation_intent_sha256: "d".repeat(64),
                checkpoint_sha256: "e".repeat(64),
            }),
            host: host.clone(),
            service,
        },
        node,
        runtime::Selection {
            protocol: native::PROTOCOL.into(),
            helper: host.helper,
        },
    )
    .unwrap()
}

fn open(root: &tempfile::TempDir) -> Directory {
    Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap()
}

#[test]
fn canonical_role_manifest_pins_original_install_node_and_executable() {
    let manifest = manifest();
    let bytes = manifest.bytes().unwrap();
    assert_eq!(
        native::Manifest::from_slice(&bytes)
            .unwrap()
            .bytes()
            .unwrap(),
        bytes
    );
    assert!(native::Manifest::from_slice(&bytes[..bytes.len() - 1]).is_err());
    let mut alternate = bytes.clone();
    alternate.push(b'\n');
    assert!(native::Manifest::from_slice(&alternate).is_err());
    let mut foreign = manifest.clone();
    foreign.runtime.protocol = runtime::PROTOCOL.into();
    assert!(foreign.bytes().is_err());
    let mut foreign = manifest.clone();
    foreign.runtime.helper.sha256 = "f".repeat(64);
    assert!(foreign.bytes().is_err());
    let mut foreign = manifest.clone();
    foreign.spec.host.node_id = "other".into();
    assert!(foreign.bytes().is_err());
    let mut foreign = manifest.clone();
    foreign.spec.host.memory_bytes -= 1024 * 1024 * 1024;
    foreign.install_sha256 =
        hex::encode(Sha256::digest(serde_json::to_vec(&foreign.spec).unwrap()));
    assert!(foreign.spec.validate().is_ok());
    assert!(foreign.node.validate().is_ok());
    assert!(foreign.bytes().is_err());
    let mut foreign = manifest.clone();
    foreign.install_sha256 = "0".repeat(64);
    assert!(foreign.bytes().is_err());
    let root = tempfile::tempdir().unwrap();
    let directory = open(&root);
    directory
        .publish(&manifest.file_name().unwrap(), &bytes, 0o600)
        .unwrap();
    assert!(native::Manifest::load(&directory, &manifest.file_name().unwrap()).is_ok());
    directory.publish("foreign.json", &bytes, 0o600).unwrap();
    assert!(native::Manifest::load(&directory, "foreign.json").is_err());
    assert!(native::Manifest::from_slice(&manifest.node.bytes().unwrap()).is_err());
}

#[test]
fn native_intent_recovers_forward_preserves_identity_and_refuses_legacy() {
    let manifest = manifest();
    let legacy = tempfile::tempdir().unwrap();
    let legacy_directory = open(&legacy);
    let legacy_install = Installation::acquire(&legacy_directory, &manifest.spec).unwrap();
    let original_cache = legacy_install.cache_identity().to_vec();
    let original_identity = fs::read(legacy.path().join("identity.json")).unwrap();
    drop(legacy_install);
    assert!(Installation::acquire_native(&legacy_directory, &manifest).is_err());
    assert!(!legacy.path().join("native-install-intent.json").exists());

    let root = tempfile::tempdir().unwrap();
    let directory = open(&root);
    // Durable intent without identity models interruption at the publication
    // boundary. Recovery must not need a migration/adoption override.
    directory
        .publish(
            "native-install-intent.json",
            &manifest.bytes().unwrap(),
            0o600,
        )
        .unwrap();
    let intent_inode = fs::metadata(root.path().join("native-install-intent.json"))
        .unwrap()
        .ino();
    let installation = Installation::acquire_native(&directory, &manifest).unwrap();
    assert_eq!(installation.cache_identity(), original_cache);
    assert_eq!(
        fs::read(root.path().join("identity.json")).unwrap(),
        original_identity
    );
    assert!(Installation::acquire_native(&directory, &manifest).is_err());
    drop(installation);
    let identity_inode = fs::metadata(root.path().join("identity.json"))
        .unwrap()
        .ino();
    drop(Installation::acquire_native(&directory, &manifest).unwrap());
    assert_eq!(
        fs::metadata(root.path().join("identity.json"))
            .unwrap()
            .ino(),
        identity_inode
    );
    assert_eq!(
        fs::metadata(root.path().join("native-install-intent.json"))
            .unwrap()
            .ino(),
        intent_inode
    );
    assert!(!root.path().join("producer-enabled.json").exists());
    assert!(!root.path().join("format-intent.json").exists());

    let conflict = tempfile::tempdir().unwrap();
    let conflict_directory = open(&conflict);
    conflict_directory
        .publish("native-install-intent.json", b"foreign\n", 0o600)
        .unwrap();
    assert!(Installation::acquire_native(&conflict_directory, &manifest).is_err());
    assert!(!conflict.path().join("identity.json").exists());
}
