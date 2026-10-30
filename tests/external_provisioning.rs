#![cfg(target_os = "linux")]
//! Structural/argv tests only: no executable, node, Docker or cloud work.
use serde_json::json;
use zdn::{
    devnet::{
        external::{artifact_limits, ExternalRequest},
        Artifact,
    },
    host::{
        external::{identity, Objects, Provisioning},
        S3Object,
    },
    image,
    public_chain_adapter::{contract::*, package::CoreTrust},
};

fn fixture() -> identity::Manifest {
    let compiled = Compiled {
        schema: SCHEMA.into(),
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
    let requirements = compiled.image_requirements().unwrap();
    let mut artifacts = artifact_limits()
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
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = Pin::of(&serde_json::to_vec(&compiled).unwrap());
    artifacts.insert(
        "compiled.json".into(),
        Artifact {
            bytes: result.bytes,
            sha256: result.sha256,
        },
    );
    let image_digest = format!("sha256:{}", "12".repeat(32));
    let request = ExternalRequest {
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
        image: image::ImageRecord {
            api_version: image::FEATURE_API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@{image_digest}"
            ),
            config_digest: image_digest.clone(),
            platform: "linux/amd64".into(),
            provenance: image::ImageProvenance::Release {
                revision: "ab".repeat(20),
                version: "v1.0.0".into(),
            },
            capabilities: image::ImageCapabilities::for_requirements(requirements).unwrap(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        },
        build: None,
        node_count: 1,
        block_interval_seconds: 25,
        production_limits: None,
        artifacts,
    };
    request.validate().unwrap();
    let object = |name: &str| {
        let a = &request.artifacts[name];
        S3Object {
            bucket: "zdn-private-fixture".into(),
            key: format!("inputs/{name}"),
            bytes: a.bytes,
            sha256: a.sha256.clone(),
            owner_account: "123456789012".into(),
            region: "us-east-1".into(),
        }
    };
    let sources = Objects {
        package: object("package.json"),
        descriptor: object("descriptor.json"),
        native_rules: object("native-rules.json"),
        wallet_profile: object("wallet-profile.json"),
        seed_bundle: object("seed-blocks.bin"),
        host_adapter: object("host-adapter"),
        compiled_result: object("compiled.json"),
        image_record: object("image.json"),
        image_manifest: object("image-manifest.json"),
        image_config: object("image-config.json"),
        host_helper: object("zdn"),
    };
    let provisioning = Provisioning {
        schema: "zdn-external-provisioning/v1".into(),
        deployment_id: "00000000-0000-4000-8000-000000000000".parse().unwrap(),
        node_id: "node-1".into(),
        volume_id: "vol-00000000000000001".into(),
        descriptor_sha256: "12".repeat(32),
        native_fingerprint: "ab".repeat(32),
        request: Pin::of(&request.bytes().unwrap()),
        new_volume: None,
    };
    let root = provisioning.node_root();
    let options = RenderOptions {
        deployment_id: provisioning.deployment_id.to_string(),
        node_id: "node-1".into(),
        role: "follower".into(),
        image_digest,
        state_dir: format!("{root}/state"),
        identity_dir: format!("{root}/identity"),
        cookie_dir: format!("{root}/rpc"),
        rpc_listen: "127.0.0.1:18232".into(),
        native_listen: "0.0.0.0:18233".into(),
        expected_node_id: String::new(),
        peers: vec![],
        reward_address: None,
    };
    // No render/prepare is invoked: this is deliberately only structural data.
    let config_toml = "not an executable configuration".to_string();
    let manifest = identity::Manifest {
        schema: identity::SCHEMA.into(),
        provisioning,
        request,
        sources,
        options,
        config: Pin::of(config_toml.as_bytes()),
        config_toml,
    };
    manifest.validate().unwrap();
    manifest
}

#[test]
fn provisioning_command_is_peerless_and_mounts_only_config_and_key_directory() {
    use identity::runtime::arguments;
    let mut manifest = fixture();
    let bytes = manifest.bytes().unwrap();
    identity::Manifest::from_slice(&bytes).unwrap();
    let script = zdn::host::runtime::bootstrap::render_external_identity(&manifest).unwrap();
    assert!(script.contains("__runtime-capabilities --require zdn-external-native-provisioning/v1"));
    assert!(script
        .contains("__external-native-identity --protocol zdn-external-native-provisioning/v1"));
    assert!(!script.contains("__host-install --protocol"));
    let args = arguments(&manifest, "native-identity.toml").unwrap();
    assert!(args.windows(2).any(|w| w == ["--network", "none"]));
    assert!(args.windows(2).any(|w| w == ["--user", "10001:10001"]));
    assert!(args.iter().any(|a| a == "native-identity"));
    assert!(!args
        .iter()
        .any(|a| a == "start" || a == "generate" || a.contains("/rpc") || a.contains("/state")));
    let mounts: Vec<_> = args
        .windows(2)
        .filter(|w| w[0] == "--mount")
        .map(|w| &w[1])
        .collect();
    assert_eq!(mounts.len(), 2);
    assert!(mounts[0].ends_with("/native-identity.toml,readonly"));
    assert!(mounts[1].ends_with("/identity"));
    assert!(arguments(&manifest, "zakura.toml").is_err());
    manifest.options.expected_node_id = "ef".repeat(32);
    assert!(manifest.validate().is_err());
    manifest.options.expected_node_id.clear();
    manifest.sources.host_adapter.owner_account = "111111111111".into();
    assert!(manifest.validate().is_err());
    manifest.sources.host_adapter.owner_account = "123456789012".into();
    manifest
        .request
        .compiled
        .required_capabilities
        .push("shell-hooks".into());
    assert!(manifest.validate().is_err());
}

#[test]
fn provisioning_json_refuses_unknown_duplicate_and_noncanonical_fields() {
    let manifest = fixture();
    let mut v = serde_json::to_value(&manifest).unwrap();
    v["provisioning"]["privateKey"] = "forbidden".into();
    assert!(identity::Manifest::from_slice(&serde_json::to_vec(&v).unwrap()).is_err());
    let bytes = manifest.bytes().unwrap();
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen('{', "{\"schema\":\"wrong\",", 1);
    assert!(identity::Manifest::from_slice(duplicate.as_bytes()).is_err());
}

fn runtime_fixture() -> zdn::host::external::runtime::Manifest {
    use zdn::host::external::{runtime, Manifest};
    let source = fixture();
    let mut options = source.options;
    options.expected_node_id =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into();
    let chain = Manifest {
        schema: zdn::host::external::SCHEMA.into(),
        request: source.provisioning.request.clone(),
        trust: source.request.trust,
        objects: source.sources,
        compiled_json: serde_json::to_string(&source.request.compiled).unwrap(),
        native_inventory: Pin::of(b"public peer inventory"),
        options,
        config_toml: source.config_toml,
        config: source.config,
    };
    let runtime = runtime::Manifest {
        schema: runtime::SCHEMA.into(),
        provisioning: source.provisioning,
        chain,
        image: source.request.image,
        memory_bytes: 2 << 30,
        cpu_millis: 1500,
        host_reserve_bytes: 1 << 30,
        block_interval_seconds: None,
        production_limits: None,
    };
    runtime.validate().unwrap();
    runtime
}

#[test]
fn final_runtime_has_distinct_supervisor_and_exact_volume_ownership() {
    use zdn::host::{external::runtime, volume::VolumeSpec};
    let manifest = runtime_fixture();
    let bytes = manifest.bytes().unwrap();
    runtime::Manifest::from_slice(&bytes).unwrap();
    assert_eq!(
        manifest.volume_identity().unwrap(),
        manifest.provisioning.volume_identity().unwrap()
    );
    let (node, producer, gateway) = manifest.units().unwrap();
    assert!(node.contains("__external-runtime --protocol zdn-external-runtime/v1"));
    for action in ["prepare", "run", "ready", "stop"] {
        assert!(node.contains(&format!("{} {action}", manifest.command().unwrap())));
    }
    assert!(!node.contains("__host-runtime"));
    assert!(producer.is_none());
    let gateway = gateway.unwrap();
    assert!(gateway.contains("gateway-serve"));
    assert!(gateway.contains("ProtectSystem=strict"));
    assert!(gateway.contains("CAP_SETUID CAP_SETGID CAP_SETPCAP"));
    assert!(gateway.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"));
    assert!(gateway.contains("After=zdn-node.service"));
    assert!(!gateway.contains("BindsTo=zdn-node.service"));
    assert!(!gateway.contains("PartOf=zdn-node.service"));
    let script = zdn::host::runtime::bootstrap::render_external(&manifest).unwrap();
    assert!(script.contains("__external-install --protocol zdn-external-runtime/v1"));
    assert!(!script.contains("__external-native-identity"));
    let mut changed = manifest.clone();
    changed.chain.options.expected_node_id.clear();
    assert!(changed.validate().is_err());
    let mut raw = serde_json::to_value(&manifest).unwrap();
    raw["chain"]["privateKey"] = json!("no");
    assert!(runtime::Manifest::from_slice(&serde_json::to_vec(&raw).unwrap()).is_err());
    let observation = json!({"observation":manifest.observation("ready").unwrap(),"readiness":{
        "apiVersion":zdn::chain::readiness::API_VERSION,"consensusFingerprint":manifest.provisioning.native_fingerprint,
        "role":"follower","effectiveRulesVerified":true,"historyPresent":true,"launchReady":false}});
    manifest.validate_ready_observation(&observation).unwrap();
    let mut changed = observation.clone();
    changed["readiness"]["effectiveRulesVerified"] = json!(false);
    assert!(manifest.validate_ready_observation(&changed).is_err());
    let mut changed = observation;
    changed["observation"]["nativeInventory"] = json!(Pin::of(b"foreign inventory"));
    assert!(manifest.validate_ready_observation(&changed).is_err());
    let observation = zdn::infra::HostObservation {
        mem_total_bytes: 4 << 30,
        ancestor_memory_limits_bytes: vec![],
        online_cpu_count: 2,
        affinity_cpu_count: 2,
        ancestor_cpu_quota_millis: vec![],
    };
    let argv =
        zdn::host::container::arguments(&manifest, &manifest.image.image, &observation).unwrap();
    assert!(argv.windows(2).any(|p| p == ["--network", "host"]));
    assert!(argv.windows(2).any(|p| p == ["--user", "10001:10001"]));
    assert!(argv.contains(&"start".into()));
    assert!(zdn::host::container::arguments(&manifest, "unselected-image", &observation).is_err());
}

fn revision_fixture(
    original: &zdn::host::external::runtime::Manifest,
) -> zdn::host::external::runtime::update::Request {
    use zdn::host::external::runtime::update;
    let mut target = original.clone();
    target.chain.options.image_digest = format!("sha256:{}", "34".repeat(32));
    target.image.image = target
        .image
        .image
        .replace(&"12".repeat(32), &"34".repeat(32));
    target.image.config_digest = format!("sha256:{}", "56".repeat(32));
    target.chain.objects.image_manifest.sha256 = "34".repeat(32);
    target.chain.objects.image_config.sha256 = "56".repeat(32);
    target.chain.objects.image_record.sha256 = "78".repeat(32);
    update::Request {
        schema: update::SCHEMA.into(),
        original: original.clone(),
        update_id: uuid::Uuid::new_v4(),
        expected_image: original.image.image.clone(),
        expected_update_id: None,
        target,
    }
}

#[test]
fn external_revision_reuses_forward_journal_and_never_reauthorizes_keys_or_consensus() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use zdn::host::{
        external::runtime::update::{Journal, Request, Snapshot},
        files::Directory,
        runtime::revision::Phase,
    };
    let original = runtime_fixture();
    let request = revision_fixture(&original);
    request.validate().unwrap();
    Request::from_slice(&request.bytes().unwrap()).unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
    let mut installation = original.provisioning.acquire(&directory).unwrap();
    let updates = directory
        .ensure_directory("external-updates", 0o700)
        .unwrap();
    let mut journal = Journal::open(&updates, &original, &mut installation).unwrap();
    assert_eq!(
        journal.begin(&request).unwrap().transaction.unwrap().phase,
        Phase::Staging
    );
    assert!(
        journal
            .advance(request.update_id, Phase::Stopping)
            .unwrap()
            .producer_hold
    );
    journal
        .advance(request.update_id, Phase::Activating)
        .unwrap();
    journal.publish_active(request.update_id).unwrap();
    journal.advance(request.update_id, Phase::Ready).unwrap();
    assert!(journal.advance(request.update_id, Phase::Done).is_err());
    journal.release_maintenance(request.update_id).unwrap();
    journal.advance(request.update_id, Phase::Done).unwrap();
    assert!(!Snapshot::load(&updates, &original).unwrap().producer_hold);
    for field in ["expectedNodeId", "rpcListen", "identityDir"] {
        let mut raw = serde_json::to_value(&request).unwrap();
        raw["target"]["chain"]["options"][field] = json!("changed");
        assert!(Request::from_slice(&serde_json::to_vec(&raw).unwrap()).is_err());
    }
    let mut altered = request.clone();
    altered.target.chain.native_inventory = Pin::of(b"different inventory");
    assert!(altered.validate().is_err());
    let mut altered = request.clone();
    altered.target.provisioning.native_fingerprint = "ef".repeat(32);
    assert!(altered.validate().is_err());
    let mut altered = request.clone();
    altered.target.chain.config_toml.push('\n');
    altered.target.chain.config = Pin::of(altered.target.chain.config_toml.as_bytes());
    assert!(altered.validate().is_err());
}

fn limited_producer() -> zdn::host::external::runtime::Manifest {
    let mut runtime = runtime_fixture();
    runtime.chain.options.role = "producer".into();
    runtime.chain.options.reward_address = Some("tFixture".into());
    runtime.block_interval_seconds = Some(25);
    runtime.production_limits = Some(zdn::config::ExternalProductionLimits {
        max_height: 42,
        lifetime_seconds: 600,
    });
    runtime.validate().unwrap();
    runtime
}

fn production_directory() -> (tempfile::TempDir, zdn::host::files::Directory) {
    use std::os::unix::fs::MetadataExt;
    let root = tempfile::tempdir().unwrap();
    let directory =
        zdn::host::files::Directory::open(root.path(), root.path().metadata().unwrap().uid())
            .unwrap();
    (root, directory)
}

fn set_activation_times(path: &std::path::Path, start: u64, deadline: u64) {
    // Preserve the contract's struct field order, not Value's sorted map order.
    let bytes = std::fs::read_to_string(path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
    let bytes = bytes
        .replace(
            &format!("\"activatedUnixSeconds\":{}", value["activatedUnixSeconds"]),
            &format!("\"activatedUnixSeconds\":{start}"),
        )
        .replace(
            &format!("\"deadlineUnixSeconds\":{}", value["deadlineUnixSeconds"]),
            &format!("\"deadlineUnixSeconds\":{deadline}"),
        );
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn first_launch_limits_are_optional_canonical_and_bound_to_config_and_request() {
    use zdn::config::{
        ChainSelection, Config, ExternalProductionLimits, ServicePreset, Size, Source,
    };
    let mut request = fixture().request;
    let legacy = request.bytes().unwrap();
    assert!(!String::from_utf8(legacy.clone())
        .unwrap()
        .contains("productionLimits"));
    assert_eq!(
        ExternalRequest::from_slice(&legacy)
            .unwrap()
            .bytes()
            .unwrap(),
        legacy
    );
    let mut config = Config::draft(
        "fixture".into(),
        "fixture".into(),
        Source {
            image: Some(request.image.image.clone()),
            ..Default::default()
        },
        Size::Medium,
    )
    .unwrap();
    config.services = ServicePreset::NodeOnly.services();
    config.network.nodes = 1;
    config.chain = Some(ChainSelection::External {
        package_sha256: request.trust.package.sha256.clone(),
        adapter_selection_sha256: request.trust.adapter_selection_sha256.clone(),
        production_limits: None,
    });
    assert_eq!(
        serde_json::to_string(config.chain.as_ref().unwrap()).unwrap(),
        format!(
            "{{\"kind\":\"external\",\"packageSha256\":\"{}\",\"adapterSelectionSha256\":\"{}\"}}",
            request.trust.package.sha256, request.trust.adapter_selection_sha256
        )
    );
    let legacy_config_pin = config.fingerprint().unwrap();
    request.config_sha256 = legacy_config_pin.clone();
    request.require_config(&config).unwrap();
    let limits = ExternalProductionLimits {
        max_height: 42,
        lifetime_seconds: 600,
    };
    if let Some(ChainSelection::External {
        production_limits, ..
    }) = &mut config.chain
    {
        *production_limits = Some(limits.clone());
    }
    assert_ne!(legacy_config_pin, config.fingerprint().unwrap());
    // Even an otherwise matching config pin cannot conceal different limits.
    request.config_sha256 = config.fingerprint().unwrap();
    assert!(request.require_config(&config).is_err());
    request.production_limits = Some(limits);
    request.require_config(&config).unwrap();
    let bytes = request.bytes().unwrap();
    assert_eq!(
        ExternalRequest::from_slice(&bytes)
            .unwrap()
            .bytes()
            .unwrap(),
        bytes
    );
    for (height, seconds) in [(0, 600), (1, 0), (1, 3601)] {
        request.production_limits = Some(ExternalProductionLimits {
            max_height: height,
            lifetime_seconds: seconds,
        });
        assert!(request.bytes().is_err());
    }
    let mut value = serde_json::to_value(&config).unwrap();
    value["chain"]["productionLimits"]["maxBlocks"] = json!(1);
    assert!(serde_json::from_value::<Config>(value).is_err());
}

#[test]
fn first_launch_activation_and_deadline_survive_service_and_image_restarts() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use zdn::{chain::producer::ProducerOptions, host::external::runtime::ProductionAdmission};
    let runtime = limited_producer();
    let (root, directory) = production_directory();
    assert!(ProductionAdmission::load(&runtime, &directory).is_err());
    runtime.activate_production(&directory).unwrap();
    let path = root.path().join("production-activation.json");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Age the retained fixture without sleeping or invoking a real service.
    set_activation_times(&path, now - 100, now + 500);
    let bytes = std::fs::read(&path).unwrap();
    directory
        .publish(
            "producer-authorized.json",
            &runtime.producer_authorization().unwrap(),
            0o600,
        )
        .unwrap();
    runtime.activate_production(&directory).unwrap();
    let target = revision_fixture(&runtime).target;
    target.activate_production(&directory).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    for manifest in [&runtime, &target] {
        let admission = ProductionAdmission::load(manifest, &directory).unwrap();
        let mut scheduled =
            ProducerOptions::new(root.path().join("producer"), manifest.producer_identity());
        admission.constrain(&mut scheduled);
        assert_eq!(scheduled.max_height, Some(42));
        assert!(scheduled.max_duration.unwrap() <= Duration::from_secs(500));
        assert!(scheduled.max_duration.unwrap() > Duration::from_secs(450));
        let mut qualification = scheduled.clone();
        qualification.max_blocks = Some(3);
        qualification.max_height = Some(10);
        qualification.max_duration = Some(Duration::from_secs(5));
        qualification.unpaced = true;
        admission.constrain(&mut qualification);
        assert_eq!(qualification.max_blocks, Some(3));
        assert_eq!(qualification.max_height, Some(10));
        assert_eq!(qualification.max_duration, Some(Duration::from_secs(5)));
        qualification.max_height = Some(999);
        qualification.max_duration = Some(Duration::from_secs(600));
        admission.constrain(&mut qualification);
        assert_eq!(qualification.max_height, Some(42));
        assert!(qualification.max_duration.unwrap() <= Duration::from_secs(500));
    }
    let mut changed = revision_fixture(&runtime);
    changed
        .target
        .production_limits
        .as_mut()
        .unwrap()
        .max_height += 1;
    assert!(changed.validate().is_err());
    assert!(ProductionAdmission::load(&changed.target, &directory).is_err());
    let mut changed = revision_fixture(&runtime);
    changed.target.production_limits = None;
    assert!(changed.validate().is_err());
    // Missing retained activation must never be repaired into a fresh budget.
    std::fs::remove_file(&path).unwrap();
    assert!(runtime.activate_production(&directory).is_err());
    assert!(!path.exists());
}

#[test]
fn first_launch_expired_or_future_activation_blocks_generate_but_allows_reconciliation_reads() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use zdn::{
        chain::{
            producer::ProducerOptions,
            rpc::{NodeRpc, RpcError},
        },
        host::external::runtime::ProductionAdmission,
    };
    struct Rpc(AtomicUsize);
    impl NodeRpc for Rpc {
        fn call(
            &self,
            _: &str,
            _: serde_json::Value,
            _: Duration,
        ) -> Result<serde_json::Value, RpcError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!("read or generation forwarded"))
        }
    }
    for future in [false, true] {
        let runtime = limited_producer();
        let (root, directory) = production_directory();
        runtime.activate_production(&directory).unwrap();
        let path = root.path().join("production-activation.json");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = if future { now + 100 } else { now - 700 };
        set_activation_times(&path, start, start + 600);
        let admission = ProductionAdmission::load(&runtime, &directory).unwrap();
        let mut options =
            ProducerOptions::new(root.path().join("producer"), runtime.producer_identity());
        options.max_blocks = Some(20);
        admission.constrain(&mut options);
        assert_eq!(options.max_height, Some(0));
        let rpc = Rpc(AtomicUsize::new(0));
        let guarded = admission.guard(&rpc);
        assert!(guarded
            .call("generate", json!([1]), Duration::from_secs(1))
            .is_err());
        assert_eq!(rpc.0.load(Ordering::SeqCst), 0);
        for method in [
            "getblockhash",
            "getblockheader",
            "getbestblockheightandhash",
        ] {
            guarded
                .call(method, json!([]), Duration::from_secs(1))
                .unwrap();
        }
        assert_eq!(rpc.0.load(Ordering::SeqCst), 3);
        runtime.activate_production(&directory).unwrap();
        let mut retry =
            ProducerOptions::new(root.path().join("producer"), runtime.producer_identity());
        ProductionAdmission::load(&runtime, &directory)
            .unwrap()
            .constrain(&mut retry);
        assert_eq!(retry.max_height, Some(0));
    }
}

#[test]
fn first_launch_omitted_limits_keep_legacy_runtime_authorization_and_unbounded_options() {
    use zdn::{chain::producer::ProducerOptions, host::external::runtime::ProductionAdmission};
    let mut runtime = limited_producer();
    runtime.production_limits = None;
    let bytes = runtime.bytes().unwrap();
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains("productionLimits"));
    assert_eq!(runtime.producer_authorization().unwrap(), serde_json::to_vec(&json!({
        "schema":"zdn-external-producer-authorization/v1",
        "provisioning":Pin::of(&runtime.provisioning.bytes().unwrap()),
        "nativeInventory":runtime.chain.native_inventory,"intervalSeconds":runtime.block_interval_seconds
    })).unwrap());
    let (root, directory) = production_directory();
    runtime.activate_production(&directory).unwrap();
    assert!(!root.path().join("production-activation.json").exists());
    let mut options =
        ProducerOptions::new(root.path().join("producer"), runtime.producer_identity());
    ProductionAdmission::load(&runtime, &directory)
        .unwrap()
        .constrain(&mut options);
    assert_eq!(options.max_height, None);
    assert_eq!(options.max_duration, None);
}
