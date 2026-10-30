#![cfg(target_os = "linux")]

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    cluster_infra::{ClusterNodeOutputs, ClusterTopology, NativeListener},
    native_peers::{
        NativeCohort, NativeIdentity, NativeInventoryStore, IDENTITY_SCHEMA, MAX_IDENTITY_BYTES,
    },
    public_chain_adapter::contract::RenderOptions,
};

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn cohort(count: u8) -> NativeCohort {
    let topology = ClusterTopology::new(count).unwrap();
    let outputs: BTreeMap<_, _> = topology
        .nodes()
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node.node_id.clone(),
                ClusterNodeOutputs {
                    node_id: node.node_id,
                    instance_id: format!("i-{:017x}", index + 1),
                    private_ip: node.private_ip,
                    volume_id: format!("vol-{:017x}", index + 1),
                },
            )
        })
        .collect();
    NativeCohort::new(
        Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
        "d".repeat(64),
        "f".repeat(64),
        &topology,
        &outputs,
        NativeListener::new("0.0.0.0:28333".parse().unwrap(), &topology).unwrap(),
    )
    .unwrap()
}

fn identity(id: char) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema": IDENTITY_SCHEMA, "nodeId": id.to_string().repeat(64), "chainFingerprint": "f".repeat(64)})).unwrap()
}

fn options(node: &str) -> RenderOptions {
    RenderOptions {
        deployment_id: "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153".into(),
        node_id: node.into(),
        role: "follower".into(),
        image_digest: format!("sha256:{}", "e".repeat(64)),
        state_dir: "/var/lib/zdn/node/state".into(),
        identity_dir: "/var/lib/zdn/node/identity".into(),
        cookie_dir: "/var/lib/zdn/node/cookie".into(),
        rpc_listen: "127.0.0.1:18232".into(),
        native_listen: "0.0.0.0:28333".into(),
        expected_node_id: String::new(),
        peers: vec![],
        reward_address: None,
    }
}

#[test]
fn interrupted_provisioning_is_observable_durable_and_exactly_retryable() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("public-peers");
    let binding = cohort(3);
    let store = NativeInventoryStore::open(&directory, binding.clone()).unwrap();
    let empty = store.read().unwrap();
    assert_eq!(empty.completed_count(), 0);
    assert!(!empty.is_complete());
    assert!(empty.peers("node-1").is_err());
    assert!(empty.expected_node_id("node-1").is_err());
    let partial = store.record("node-2", &identity('b')).unwrap();
    assert_eq!(partial.completed_count(), 1);
    assert!(!partial.is_complete());
    assert!(partial.peers("node-2").is_err());
    let pin = partial.pin().unwrap();
    let bytes = fs::read(directory.join("node-2.json")).unwrap();
    drop(store);

    // An abandoned unpublished tempfile is not a completed identity.
    fs::write(directory.join(".pending-native-interrupted"), b"partial").unwrap();
    let store = NativeInventoryStore::open_existing(&directory, binding.clone()).unwrap();
    assert_eq!(store.read_pinned(&pin).unwrap(), partial);
    let retry =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&identity('b')).unwrap())
            .unwrap();
    assert_eq!(store.record("node-2", &retry).unwrap(), partial);
    assert_eq!(fs::read(directory.join("node-2.json")).unwrap(), bytes);
    store.record("node-1", &identity('a')).unwrap();
    let complete = store.record("node-3", &identity('c')).unwrap();
    assert_eq!(complete.completed_count(), 3);
    assert!(complete.is_complete());
    complete
        .require_chain(&"d".repeat(64), &"f".repeat(64))
        .unwrap();
    assert!(complete
        .require_chain(&"e".repeat(64), &"f".repeat(64))
        .is_err());
    assert!(complete
        .require_chain(&"d".repeat(64), &"e".repeat(64))
        .is_err());
    let peers = complete.peers("node-2").unwrap();
    assert_eq!(
        peers
            .iter()
            .map(|peer| peer.endpoint.as_str())
            .collect::<Vec<_>>(),
        ["10.90.1.10:28333", "10.90.1.12:28333"]
    );
    assert_eq!(peers[0].node_id, "a".repeat(64));
    assert_eq!(peers[1].node_id, "c".repeat(64));
    assert!(complete.peers("node-4").is_err());
    let complete_pin = complete.pin().unwrap();
    assert!(store.read_pinned(&pin).is_err());
    drop(store);
    let store = NativeInventoryStore::open_existing(&directory, binding).unwrap();
    assert_eq!(store.read_pinned(&complete_pin).unwrap(), complete);
    let public = serde_json::to_string(&complete).unwrap();
    assert!(!public.contains("identityDir"));
    assert!(!public.contains("secret"));
}

#[test]
fn changed_foreign_duplicate_or_wrong_chain_responses_never_change_saved_bytes() {
    let temp = private_tempdir();
    let store = NativeInventoryStore::open(temp.path(), cohort(3)).unwrap();
    let partial = store.record("node-1", &identity('a')).unwrap();
    let saved = fs::read(temp.path().join("node-1.json")).unwrap();
    for (node, bytes) in [
        ("node-1", identity('b')),
        ("node-2", identity('a')),
        ("node-4", identity('c')),
        ("../node-2", identity('c')),
        ("node-2", serde_json::to_vec(&json!({"schema": IDENTITY_SCHEMA, "nodeId": "b".repeat(64), "chainFingerprint": "e".repeat(64)})).unwrap()),
        ("node-2", serde_json::to_vec(&json!({"schema": IDENTITY_SCHEMA, "nodeId": "b".repeat(64), "chainFingerprint": null})).unwrap()),
    ] {
        assert!(store.record(node, &bytes).is_err());
        assert_eq!(store.read().unwrap(), partial);
        assert_eq!(fs::read(temp.path().join("node-1.json")).unwrap(), saved);
    }
    assert!(!temp.path().join("node-2.json").exists());
}

#[test]
fn machine_schema_is_bounded_strict_and_private_values_never_enter_errors() {
    assert!(NativeIdentity::from_json(&identity('a')).is_ok());
    let temp = private_tempdir();
    let store = NativeInventoryStore::open(temp.path(), cohort(1)).unwrap();
    let empty_pin = store.read().unwrap().pin().unwrap();
    let null =
        json!({"schema": IDENTITY_SCHEMA, "nodeId": "a".repeat(64), "chainFingerprint": null});
    assert_eq!(
        NativeIdentity::from_json(&serde_json::to_vec(&null).unwrap())
            .unwrap()
            .chain_fingerprint,
        None
    );
    let canary = "DO-NOT-RETAIN-THIS-PRIVATE-VALUE";
    let valid: Value = serde_json::from_slice(&identity('a')).unwrap();
    for field in [
        "secretKey",
        "privateKey",
        "seed",
        "identityDir",
        "logs",
        "path",
    ] {
        let mut value = valid.clone();
        value[field] = json!(canary);
        let error = NativeIdentity::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(!format!("{error:?}").contains(canary));
        assert!(store
            .record("node-1", &serde_json::to_vec(&value).unwrap())
            .is_err());
        store.read_pinned(&empty_pin).unwrap();
        assert!(!temp.path().join("node-1.json").exists());
    }
    for (field, value) in [
        ("schema", json!(canary)),
        ("nodeId", json!(canary)),
        ("chainFingerprint", json!(canary)),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        let error = NativeIdentity::from_json(&serde_json::to_vec(&input).unwrap()).unwrap_err();
        assert!(!format!("{error:?}").contains(canary));
    }
    for invalid in [
        format!("{}\nlog text", String::from_utf8(identity('a')).unwrap()).into_bytes(),
        format!(r#"{{"schema":"{IDENTITY_SCHEMA}","nodeId":"{}","nodeId":"{}","chainFingerprint":null}}"#, "a".repeat(64), "b".repeat(64)).into_bytes(),
        serde_json::to_vec(&json!({"schema": IDENTITY_SCHEMA, "nodeId": "a".repeat(64)})).unwrap(),
        vec![b' '; MAX_IDENTITY_BYTES + 1],
        b"[]".to_vec(), b"not JSON".to_vec(),
    ] { assert!(NativeIdentity::from_json(&invalid).is_err()); }
}

#[test]
fn exact_complete_inventory_binds_only_identity_and_peer_render_slots() {
    for count in 1..=3 {
        let temp = private_tempdir();
        let store = NativeInventoryStore::open(temp.path(), cohort(count)).unwrap();
        let mut render = options("node-1");
        let before = serde_json::to_value(&render).unwrap();
        assert!(store
            .read()
            .unwrap()
            .bind_render_options(&mut render)
            .is_err());
        assert_eq!(serde_json::to_value(&render).unwrap(), before);
        for index in 1..=count {
            store
                .record(
                    &format!("node-{index}"),
                    &identity(char::from(b'a' + index - 1)),
                )
                .unwrap();
        }
        let inventory = store.read().unwrap();
        inventory.bind_render_options(&mut render).unwrap();
        assert_eq!(render.expected_node_id, "a".repeat(64));
        assert_eq!(render.peers.len(), usize::from(count - 1));
        let mut after = serde_json::to_value(&render).unwrap();
        after["expectedNodeId"] = before["expectedNodeId"].clone();
        after["peers"] = before["peers"].clone();
        assert_eq!(after, before);
        for (field, value) in [
            ("deploymentId", json!(Uuid::new_v4())),
            ("nodeId", json!("node-4")),
            ("nativeListen", json!("0.0.0.0:18233")),
            ("nativeListen", json!("10.90.1.99:28333")),
        ] {
            let mut invalid = serde_json::to_value(&render).unwrap();
            invalid[field] = value;
            let mut invalid: RenderOptions = serde_json::from_value(invalid).unwrap();
            let original = serde_json::to_value(&invalid).unwrap();
            assert!(inventory.bind_render_options(&mut invalid).is_err());
            assert_eq!(serde_json::to_value(&invalid).unwrap(), original);
        }
    }
}

#[test]
fn deployment_descriptor_fingerprint_host_endpoint_and_topology_cannot_be_rebound() {
    let temp = private_tempdir();
    let binding = cohort(2);
    NativeInventoryStore::open(temp.path(), binding.clone()).unwrap();
    let original = fs::read(temp.path().join("cohort.json")).unwrap();
    for (pointer, value) in [
        ("/deploymentId", json!(Uuid::new_v4())),
        ("/publicDescriptorSha256", json!("e".repeat(64))),
        ("/nativeFingerprint", json!("e".repeat(64))),
        ("/members/0/instanceId", json!("i-00000000000000009")),
        ("/members/0/endpoint", json!("10.90.1.10:28334")),
        ("/members/0/hostKey", json!("foreign-host")),
    ] {
        let mut value_to_change = serde_json::to_value(&binding).unwrap();
        *value_to_change.pointer_mut(pointer).unwrap() = value;
        let foreign: NativeCohort = serde_json::from_value(value_to_change).unwrap();
        assert!(NativeInventoryStore::open(temp.path(), foreign).is_err());
        assert_eq!(fs::read(temp.path().join("cohort.json")).unwrap(), original);
    }
    assert!(NativeInventoryStore::open(temp.path(), cohort(3)).is_err());
}

#[test]
fn tampering_and_missing_pinned_entries_fail_closed_without_repair() {
    for tamper in [
        "nodeId",
        "chainFingerprint",
        "endpoint",
        "host",
        "cohort",
        "private",
        "delete",
        "duplicate-json",
        "encoding",
    ] {
        let temp = private_tempdir();
        let store = NativeInventoryStore::open(temp.path(), cohort(2)).unwrap();
        let inventory = store.record("node-1", &identity('a')).unwrap();
        let pin = inventory.pin().unwrap();
        let path = temp.path().join("node-1.json");
        let original = fs::read(&path).unwrap();
        let mut value: Value = serde_json::from_slice(&original).unwrap();
        match tamper {
            "nodeId" => value["identity"]["nodeId"] = json!("b".repeat(64)),
            "chainFingerprint" => value["identity"]["chainFingerprint"] = json!("e".repeat(64)),
            "endpoint" => value["member"]["endpoint"] = json!("8.8.8.8:28333"),
            "host" => value["member"]["instanceId"] = json!("i-00000000000000009"),
            "cohort" => value["cohortSha256"] = json!("e".repeat(64)),
            "private" => value["identity"]["secretKey"] = json!("never accepted"),
            "delete" => {
                fs::remove_file(&path).unwrap();
                assert!(store.read_pinned(&pin).is_err());
                continue;
            }
            "duplicate-json" => {
                fs::write(&path, b"{\"member\":null,\"member\":null}").unwrap();
                assert!(store.read().is_err());
                continue;
            }
            "encoding" => {
                fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
                assert!(store.read_pinned(&pin).is_err());
                continue;
            }
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(store.read_pinned(&pin).is_err());
        assert!(store.record("node-1", &identity('a')).is_err());
        assert_ne!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn duplicate_ids_in_saved_records_and_foreign_files_are_rejected() {
    let temp = private_tempdir();
    let store = NativeInventoryStore::open(temp.path(), cohort(2)).unwrap();
    store.record("node-1", &identity('a')).unwrap();
    store.record("node-2", &identity('b')).unwrap();
    let path = temp.path().join("node-2.json");
    let mut entry: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    entry["identity"]["nodeId"] = json!("a".repeat(64));
    fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
    assert!(store.read().is_err());
    fs::remove_file(&path).unwrap();
    fs::write(temp.path().join("node-4.json"), b"{}").unwrap();
    assert!(store.read().is_err());
}

#[test]
fn recovery_refuses_missing_or_damaged_binding() {
    let temp = private_tempdir();
    assert!(NativeInventoryStore::open_existing(temp.path(), cohort(1)).is_err());
    assert!(!temp.path().join("cohort.json").exists());
    NativeInventoryStore::open(temp.path(), cohort(1)).unwrap();
    fs::write(temp.path().join("cohort.json"), b"truncated").unwrap();
    assert!(NativeInventoryStore::open_existing(temp.path(), cohort(1)).is_err());
    assert!(NativeInventoryStore::open(temp.path(), cohort(1)).is_err());
    assert_eq!(
        fs::read(temp.path().join("cohort.json")).unwrap(),
        b"truncated"
    );
    let lost = temp.path().join("lost");
    let store = NativeInventoryStore::open(&lost, cohort(1)).unwrap();
    fs::remove_dir_all(&lost).unwrap();
    assert!(store.read().is_err());
    assert!(!lost.exists());
}

#[cfg(unix)]
#[test]
fn unsafe_files_modes_links_and_directory_are_not_followed_or_repaired() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for kind in ["symlink", "fifo", "hardlink", "mode", "directory"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("inventory");
        let store = NativeInventoryStore::open(&root, cohort(1)).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        let path = root.join("node-1.json");
        match kind {
            "symlink" => symlink(&outside, &path).unwrap(),
            "fifo" => nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap(),
            "hardlink" => {
                store.record("node-1", &identity('a')).unwrap();
                fs::hard_link(&path, temp.path().join("linked")).unwrap();
            }
            "mode" => {
                store.record("node-1", &identity('a')).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "directory" => fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap(),
            _ => unreachable!(),
        }
        assert!(store.read().is_err());
        assert!(store.record("node-1", &identity('a')).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}
