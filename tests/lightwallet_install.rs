use serde_json::json;
use sha2::{Digest, Sha256};
use zdn::{
    host::NewVolumeAuthorization,
    lightwallet_service::{
        render_service, validate_observation, LightwalletInstallSpec, INSTALL_API_VERSION,
    },
};
#[path = "support/lightwallet_service.rs"]
mod fixture;

fn spec() -> LightwalletInstallSpec {
    let (host, service) = fixture::specs();
    let artifact = |name: &str| {
        let mut object = host.helper.clone();
        object.key = format!("team/test/{name}");
        object
    };
    LightwalletInstallSpec {
        api_version: INSTALL_API_VERSION.into(),
        image_record: artifact("lightwallet-image.json"),
        image_manifest: artifact("lightwallet-image-manifest.json"),
        image_config: artifact("lightwallet-image-config.json"),
        new_volume: Some(NewVolumeAuthorization {
            api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
            volume_id: service.cache_volume_id.clone(),
            instance_id: "i-0123456789abcdef0".into(),
            created_at: "2026-10-16T12:00:00Z".into(),
            size_bytes: service.cache_bytes,
            creation_intent_sha256: "d".repeat(64),
            checkpoint_sha256: "e".repeat(64),
        }),
        host,
        service,
    }
}
#[test]
fn native_unit_preserves_node_lifecycle_and_host_mount_namespace() {
    let spec = spec();
    let helper = spec.host.helper.clone();
    let node = zdn::host::runtime::Manifest::new(
        spec.host.clone(),
        zdn::host::runtime::Selection {
            protocol: zdn::host::runtime::PROTOCOL.into(),
            helper: helper.clone(),
        },
    )
    .unwrap();
    let manifest = zdn::lightwallet_service::native::Manifest::new(
        spec,
        node,
        zdn::host::runtime::Selection {
            protocol: zdn::lightwallet_service::native::PROTOCOL.into(),
            helper,
        },
    )
    .unwrap();
    let unit = zdn::lightwallet_service::native::unit(&manifest).unwrap();
    assert!(unit.contains("BindsTo=zdn-node.service\nPartOf=zdn-node.service"));
    assert!(unit.contains("WantedBy=zdn-node.service"));
    assert!(unit.contains(" prepare\nExecStart="));
    assert!(unit.contains(" serve\n"));
    // The main process must reap its child supervisors before systemd's final
    // group kill; SIGTERM to every child leaves durable cleanup unconfirmed.
    assert!(unit.contains("KillSignal=SIGTERM\nKillMode=mixed\n"));
    assert!(unit.contains("TimeoutStopSec=120\n"));
    for directive in [
        "ProtectHome=",
        "PrivateMounts=",
        "ProtectSystem=",
        "ReadWritePaths=",
        "BindPaths=",
        "PrivateTmp=",
    ] {
        assert!(
            !unit.contains(directive),
            "cache remount must be visible to the host Docker daemon: {directive}"
        );
    }
    assert_eq!(
        manifest.install_sha256,
        hex::encode(Sha256::digest(serde_json::to_vec(&manifest.spec).unwrap()))
    );
}

#[test]
fn requires_exact_creation_authorization_and_owned_bounded_artifacts() {
    let mut bad = spec();
    bad.new_volume = None;
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.new_volume.as_mut().unwrap().volume_id = bad.host.volume_id.clone();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.new_volume.as_mut().unwrap().size_bytes += 1024 * 1024 * 1024;
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.image_config.owner_account = "123456789013".into();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.image_config.bytes = 16 * 1024 * 1024 + 1;
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.image_config.key = bad.image_record.key.clone();
    assert!(bad.validate().is_err());
}

#[test]
fn validates_current_reports_without_upgrading_wallet_qualification() {
    let spec = spec();
    let render = render_service(&spec.host, &spec.service).unwrap();
    let install_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&spec).unwrap()));
    let stopped = json!({"apiVersion":"zdn-lightwallet-host-observation/v1alpha1","deploymentId":spec.host.deployment_id,
        "nodeId":spec.host.node_id,"installSha256":install_sha256,"serviceSha256":render.service_sha256,
        "cacheVolumeId":spec.service.cache_volume_id,"image":spec.service.image,"status":"stopped","readiness":null,
        "paymentQualification":"pending","launchReady":false});
    validate_observation(&stopped, &spec).unwrap();
    let mut ready = stopped.clone();
    ready["status"] = json!("ready");
    ready["readiness"] = json!({"apiVersion":zdn::lightwallet::API_VERSION,
        "consensusFingerprint":spec.host.consensus_fingerprint,"protocolVersion":zdn::lightwallet::PROTOCOL_VERSION,
        "launchReady":false,"paymentQualification":"pending","ironwoodTreeVerified":true,"compactDataVerified":true,
        "lagBlocks":2,"checkedCompactBlocks":4});
    validate_observation(&ready, &spec).unwrap();
    for (field, value) in [
        ("launchReady", json!(true)),
        ("status", json!("running")),
        ("installSha256", json!("a".repeat(64))),
    ] {
        let mut bad = ready.clone();
        bad[field] = value;
        assert!(validate_observation(&bad, &spec).is_err());
    }
    let mut bad = ready.clone();
    bad["readiness"]["lagBlocks"] = json!(3);
    assert!(validate_observation(&bad, &spec).is_err());
    let mut bad = ready;
    bad["readiness"]["consensusFingerprint"] = json!("f".repeat(64));
    assert!(validate_observation(&bad, &spec).is_err());
}
