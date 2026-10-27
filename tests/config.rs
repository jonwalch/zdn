use std::{fs, path::PathBuf};
use zdn::{
    chain::{ChainRequest, CompatibilityRecord, ComponentPin},
    config::{Config, Size, SnapshotMode, Source, Visibility},
};

fn local() -> Config {
    Config::draft(
        "my-feature".into(),
        "devnet".into(),
        Source {
            path: Some(".".into()),
            snapshot: Some(SnapshotMode::Worktree),
            ..Source::default()
        },
        Size::Medium,
    )
    .unwrap()
}

#[test]
fn defaults_match_the_user_contract() {
    let config = local();
    assert_eq!(config.api_version, "zdn/v1alpha1");
    assert_eq!(config.network.nodes, 3);
    assert_eq!(config.network.mining.interval_seconds().unwrap(), 25);
    assert_eq!(config.node.resources.preset, Size::Medium);
    assert_eq!(config.access.visibility, Visibility::Private);
    assert!(config.services.wallet && config.services.lightwallet && config.services.faucet);
    let build = config.node.build.unwrap();
    assert_eq!(build.executor, "aws-codebuild");
    assert_eq!(build.platform, "linux/amd64");
    assert_eq!(build.target, "runtime");
}

#[test]
fn omitted_services_preserve_legacy_defaults_and_fingerprints() {
    let original = local();
    let expected = original.fingerprint().unwrap();
    let complete = serde_json::to_value(&original).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devnet.yaml");
    for services in [
        None,
        Some(serde_json::json!({})),
        Some(serde_json::json!({"wallet": true})),
        Some(serde_json::json!({"lightwallet": true, "faucet": true})),
    ] {
        let mut value = complete.clone();
        if let Some(services) = services {
            value["services"] = services;
        } else {
            value.as_object_mut().unwrap().remove("services");
        }
        fs::write(&path, serde_yaml::to_string(&value).unwrap()).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert!(loaded.services.wallet && loaded.services.lightwallet && loaded.services.faucet);
        assert_eq!(loaded.fingerprint().unwrap(), expected);
    }
    let mut value = complete;
    value["services"] = serde_json::json!({"faucet": false});
    fs::write(&path, serde_yaml::to_string(&value).unwrap()).unwrap();
    let loaded = Config::load(&path).unwrap();
    assert!(loaded.services.wallet && loaded.services.lightwallet);
    assert!(!loaded.services.faucet);
    let mut explicit = original;
    explicit.services.faucet = false;
    assert_eq!(
        loaded.fingerprint().unwrap(),
        explicit.fingerprint().unwrap()
    );
}

#[test]
fn allocation_distinguishes_host_memory_and_node_budget() {
    for (size, host, reserve, node, disk) in [
        (Size::Small, 8, 2, 6, 40),
        (Size::Medium, 16, 2, 14, 80),
        (Size::Large, 32, 4, 28, 160),
    ] {
        let allocation = size.allocation();
        assert_eq!(
            (
                allocation.host_gib,
                allocation.host_reserve_gib,
                allocation.max_node_gib,
                allocation.chain_disk_gib
            ),
            (host, reserve, node, disk)
        );
        assert_eq!(allocation.root_disk_gib, 32);
        assert!(!allocation.qualified);
    }
}

#[test]
fn new_config_never_overwrites_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devnet.yaml");
    local().write_new(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let mut changed = local();
    changed.name = "changed".into();
    assert!(changed.write_new(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(Config::load(&path).unwrap().name, "my-feature");
}

#[test]
fn unknown_fields_and_versions_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devnet.yaml");
    let yaml = serde_yaml::to_string(&local()).unwrap();
    for invalid in [
        format!("{yaml}extraField: true\n"),
        yaml.replace("zdn/v1alpha1", "zdn/v9"),
        yaml.replace("adapter: zakura", "adapter: zebra"),
        yaml.replace("interval: 25s", "interval: 0s"),
        yaml.replace("visibility: private", "visibility: everyone"),
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(Config::load(&path).is_err());
    }
}

#[test]
fn release_and_local_source_cannot_be_mixed() {
    let mut config = local();
    config.node.source.release = Some("v1.2.3".into());
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("exactly one"));
    let release = Config::draft(
        "release".into(),
        "devnet".into(),
        Source {
            release: Some("v1.2.3".into()),
            ..Source::default()
        },
        Size::Small,
    )
    .unwrap();
    assert!(release.node.build.is_none());
    assert!(Config::draft(
        "release".into(),
        "devnet".into(),
        Source {
            release: Some("latest".into()),
            ..Source::default()
        },
        Size::Small
    )
    .is_err());
}

#[test]
fn build_platform_and_runtime_target_are_enforced() {
    let mut config = local();
    config.node.build.as_mut().unwrap().platform = "linux/arm64".into();
    assert!(config.validate().is_err());
    config.node.build.as_mut().unwrap().platform = "linux/amd64".into();
    config.node.build.as_mut().unwrap().target = "zcashd-compat".into();
    assert!(config.validate().is_err());
}

#[test]
fn revision_requires_explicit_snapshot_mode() {
    let mut config = local();
    config.node.source.revision = Some("HEAD".into());
    assert!(config.validate().is_err());
    config.node.source.snapshot = Some(SnapshotMode::Revision);
    config.validate().unwrap();
    config.node.source.revision = Some("--help".into());
    assert!(config.validate().is_err());
}

#[test]
fn source_paths_are_relative_to_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("config");
    let source = dir.path().join("checkout");
    fs::create_dir(&source).unwrap();
    let mut config = local();
    config.node.source.path = Some(PathBuf::from("../checkout"));
    let path = nested.join("devnet.yaml");
    config.write_new(&path).unwrap();
    assert_eq!(
        config.source_root(&path).unwrap(),
        Some(fs::canonicalize(source).unwrap())
    );
}

#[test]
fn upgrade_order_and_pool_requirements_are_checked() {
    let mut config = local();
    let upgrades = config.resolved_upgrades().unwrap();
    assert_eq!(upgrades.len(), 10);
    assert!(upgrades.values().all(|height| *height == 1));
    config.network.activation_heights.insert("NU6.2".into(), 20);
    assert!(config.validate().is_err());
    config.network.activation_heights.insert("NU6.3".into(), 21);
    config.validate().unwrap();
    config.network.activation_heights.insert("NU7".into(), 22);
    assert!(config.validate().is_err());
}

#[test]
fn services_and_producer_must_match_configured_resources() {
    let mut config = local();
    config.network.mining.producer = "node-4".into();
    assert!(config.validate().is_err());
    config.network.mining.producer = "node-1".into();
    config.services.wallet = false;
    assert!(config.validate().is_err());
    config.services.faucet = false;
    config.validate().unwrap();
}

#[test]
fn draft_chain_is_not_qualified_by_structural_validation() {
    let request = ChainRequest::from_config(&local()).unwrap();
    assert_eq!(request.kind, "custom-testnet");
    assert_eq!(request.payment_pool, "ironwood");
    assert!(!request.public_seeds);
    assert!(!request.unresolved.is_empty());
    let record = CompatibilityRecord::pending(&request).unwrap();
    record.validate().unwrap();
    assert!(record
        .require_complete_evidence(&request.fingerprint().unwrap())
        .is_err());
}

#[test]
fn evidence_must_cover_each_component_and_exact_chain() {
    let request = ChainRequest::from_config(&local()).unwrap();
    let mut record = CompatibilityRecord::pending(&request).unwrap();
    let pin = ComponentPin {
        version: "v1.0.0".into(),
        artifact_sha256: "ab".repeat(32),
    };
    record.zakura = Some(pin.clone());
    record.wallet = Some(pin.clone());
    record.lightwalletd = Some(pin);
    record
        .capabilities
        .values_mut()
        .for_each(|value| *value = true);
    assert!(record
        .require_complete_evidence(&request.fingerprint().unwrap())
        .is_err());
    record.human_evidence_sha256 = Some("cd".repeat(32));
    record
        .require_complete_evidence(&request.fingerprint().unwrap())
        .unwrap();
    assert!(record.require_complete_evidence(&"00".repeat(32)).is_err());
    record
        .capabilities
        .insert("unsupported-future-pool".into(), true);
    assert!(record.validate().is_err());
}

#[test]
fn chain_request_identity_excludes_label_and_vm_size() {
    let config = local();
    let before = ChainRequest::from_config(&config)
        .unwrap()
        .fingerprint()
        .unwrap();
    let mut resized = config.clone();
    resized.name = "another-label".into();
    resized.node.resources.preset = Size::Large;
    assert_eq!(
        before,
        ChainRequest::from_config(&resized)
            .unwrap()
            .fingerprint()
            .unwrap()
    );
    resized
        .network
        .activation_heights
        .insert("NU6.3".into(), 10);
    assert_ne!(
        before,
        ChainRequest::from_config(&resized)
            .unwrap()
            .fingerprint()
            .unwrap()
    );
}

#[test]
fn build_paths_cannot_escape_the_source_snapshot() {
    for path in [
        "../Dockerfile",
        "/tmp/Dockerfile",
        "docker/../../Dockerfile",
    ] {
        let mut config = local();
        config.node.build.as_mut().unwrap().dockerfile = path.into();
        assert!(config.validate().is_err());
        let mut config = local();
        config.node.build.as_mut().unwrap().context = path.into();
        assert!(config.validate().is_err());
    }
}

#[test]
fn duplicate_upgrade_keys_are_not_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devnet.yaml");
    let yaml = serde_yaml::to_string(&local())
        .unwrap()
        .replace("NU6.3: 1", "NU6.3: 1\n    NU6.3: 2");
    fs::write(&path, yaml).unwrap();
    let error = Config::load(&path).unwrap_err();
    assert!(format!("{error:#}").contains("duplicate upgrade"));
}

#[test]
fn large_config_and_directory_inputs_fail_before_deserialization() {
    let dir = tempfile::tempdir().unwrap();
    assert!(Config::load(dir.path()).is_err());
    let path = dir.path().join("large.yaml");
    fs::write(&path, vec![b' '; 1_048_577]).unwrap();
    assert!(Config::load(&path)
        .unwrap_err()
        .to_string()
        .contains("exceeds"));
}
