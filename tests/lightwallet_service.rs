use sha2::{Digest, Sha256};
use std::{fs, process::Command};
use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{HostInstallSpec, S3Object},
    infra::HostObservation,
    lightwallet_service::{render_service, LightwalletServiceSpec, API_VERSION, SOURCE_REVISION},
};

const GIB: u64 = 1024 * 1024 * 1024;

fn specs() -> (HostInstallSpec, LightwalletServiceSpec) {
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let deployment_id = Uuid::parse_str("12345678-1234-4123-8123-123456789abc").unwrap();
    let mut options = RuntimeOptions::new(deployment_id, "node-2");
    options.network.listen_addr = "10.90.1.11:18233".into();
    options.network.peers = vec!["10.90.1.10:18233".into()];
    let runtime = render_runtime_config(&manifest, &options).unwrap();
    let object = |key: &str| S3Object {
        bucket: "zdn-artifacts-test".into(),
        key: format!("team/test/{key}"),
        sha256: "a".repeat(64),
        bytes: 128,
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
    };
    (
        HostInstallSpec {
            api_version: zdn::host::API_VERSION.into(),
            deployment_id,
            node_id: "node-2".into(),
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
            memory_bytes: 5 * GIB,
            host_reserve_bytes: 2 * GIB,
            cpu_millis: 1250,
            manifest: object("manifest"),
            bundle: object("bundle"),
            helper: object("helper"),
            image_record: object("image-record"),
            image_manifest: object("image-manifest"),
            new_volume: None,
        },
        LightwalletServiceSpec {
            api_version: API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/lightwalletd@sha256:{}",
                "c".repeat(64)
            ),
            source_revision: SOURCE_REVISION.into(),
            cache_volume_id: "vol-1123456789abcdef0".into(),
            cache_bytes: 8 * GIB,
            memory_bytes: GIB / 2,
            cpu_millis: 500,
            host_observation: HostObservation {
                mem_total_bytes: 8 * GIB,
                ancestor_memory_limits_bytes: vec![],
                online_cpu_count: 2,
                affinity_cpu_count: 2,
                ancestor_cpu_quota_millis: vec![],
            },
        },
    )
}

// Lifecycle behavior is exercised through the public native runtime APIs.
#[test]
fn renders_only_private_digest_pinned_bounded_service_with_pending_gates() {
    let (host, service) = specs();
    let rendered = render_service(&host, &service).unwrap();
    assert!(!rendered.launch_ready && !rendered.deployment_ready);
    assert_eq!(rendered.qualification, "pending");
    assert_eq!(rendered.grpc_endpoint, "127.0.0.1:9067");
    assert_eq!(rendered.http_endpoint, "127.0.0.1:9068");
    let args = &rendered.docker_arguments;
    let value = |key| args[args.iter().position(|value| value == key).unwrap() + 1].as_str();
    assert_eq!(value("--user"), "10001:10001");
    assert_eq!(value("--network"), "host");
    assert_eq!(value("--cpus"), "0.500");
    assert_eq!(value("--memory"), value("--memory-swap"));
    assert_eq!(
        value("--zcash-conf-path"),
        "/run/zdn-lightwalletd/zcash.conf"
    );
    assert!(args.contains(&"--read-only".into()) && args.contains(&service.image));
    for forbidden in [
        "--rpcpassword",
        "--rpcuser",
        "--no-backend-check",
        "--redownload",
        "--nocache",
        "--privileged",
        "--publish",
    ] {
        assert!(!args.iter().any(|arg| arg == forbidden), "{forbidden}");
    }
    assert!(rendered
        .cache_root
        .contains(&host.deployment_id.to_string()));
    assert!(rendered.cache_root.ends_with(&host.consensus_fingerprint));
    assert!(rendered
        .cache_identity_json
        .contains(&service.cache_volume_id));
    assert_eq!(
        rendered.service_sha256,
        hex::encode(Sha256::digest(
            serde_json::to_vec(&serde_json::json!({"host": host, "service": service})).unwrap()
        ))
    );
    assert_eq!(
        serde_json::to_value(rendered).unwrap(),
        serde_json::to_value(render_service(&host, &service).unwrap()).unwrap()
    );
}

#[test]
fn validates_source_image_and_separate_cache_identity() {
    let (host, service) = specs();
    for image in [
        "docker.io/lightwalletd:latest".into(),
        service.image.replace("us-east-1", "us-east-2"),
        service.image.replace("123456789012", "123456789013"),
        service.image.replace("/zdn/", "/other/"),
        service.image.replace("/test/", "/../"),
        service.image.replace(&"c".repeat(64), &"C".repeat(64)),
    ] {
        let mut bad = service.clone();
        bad.image = image;
        assert!(render_service(&host, &bad).is_err());
    }
    let mut bad = service.clone();
    bad.source_revision = "a".repeat(40);
    assert!(render_service(&host, &bad).is_err());
    bad = service.clone();
    bad.cache_volume_id.clone_from(&host.volume_id);
    assert!(render_service(&host, &bad).is_err());
    for size in [0, GIB - 1, GIB + 1, 2049 * GIB] {
        bad = service.clone();
        bad.cache_bytes = size;
        assert!(render_service(&host, &bad).is_err());
    }
}

#[test]
fn requires_explicit_node_budget_and_all_ancestor_resource_limits() {
    let (mut host, service) = specs();
    host.memory_bytes = 6 * GIB;
    assert!(render_service(&host, &service)
        .unwrap_err()
        .to_string()
        .contains("effective memory"));
    host.memory_bytes = 5 * GIB;
    let mut bad = service.clone();
    bad.host_observation.ancestor_memory_limits_bytes = vec![16 * GIB, 7 * GIB];
    assert!(render_service(&host, &bad).is_err());
    bad = service.clone();
    bad.host_observation.ancestor_cpu_quota_millis = vec![4000, 1999];
    assert!(render_service(&host, &bad).is_err());
    bad = service.clone();
    bad.host_observation.affinity_cpu_count = 1;
    assert!(render_service(&host, &bad).is_err());
    host.cpu_millis = 1750;
    assert!(render_service(&host, &service)
        .unwrap_err()
        .to_string()
        .contains("effective CPU"));
}

#[test]
fn hashes_bind_budgets_image_and_expected_cache_and_node_install() {
    let (host, mut service) = specs();
    let initial = render_service(&host, &service).unwrap();
    service.cache_bytes += GIB;
    assert_ne!(
        initial.service_sha256,
        render_service(&host, &service).unwrap().service_sha256
    );
    service.image = service.image.replace(&"c".repeat(64), &"d".repeat(64));
    assert_ne!(
        initial.service_sha256,
        render_service(&host, &service).unwrap().service_sha256
    );
    service.memory_bytes /= 2;
    assert_ne!(
        initial.service_sha256,
        render_service(&host, &service).unwrap().service_sha256
    );
}

#[test]
fn service_report_does_not_copy_unused_node_configuration() {
    let (mut host, service) = specs();
    host.config_toml
        .push_str("\n# sensitive-note-not-needed-by-lightwalletd\n");
    host.config_sha256 = hex::encode(Sha256::digest(host.config_toml.as_bytes()));
    let rendered = render_service(&host, &service).unwrap();
    let report = serde_json::to_string(&rendered).unwrap();
    assert!(!report.contains("sensitive-note-not-needed-by-lightwalletd"));
}

#[test]
fn service_cli_renders_a_new_recipe_and_refuses_to_replace_existing_output() {
    let root = tempfile::tempdir().unwrap();
    let (mut host, service) = specs();
    let sentinel = "private-node-comment-must-not-appear-in-output";
    host.config_toml.push_str(&format!("\n# {sentinel}\n"));
    host.config_sha256 = hex::encode(Sha256::digest(host.config_toml.as_bytes()));
    fs::write(
        root.path().join("host.json"),
        serde_json::to_vec(&host).unwrap(),
    )
    .unwrap();
    fs::write(
        root.path().join("service.json"),
        serde_json::to_vec(&service).unwrap(),
    )
    .unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .current_dir(root.path())
            .args([
                "lightwallet",
                "render-service",
                "--host-spec",
                "host.json",
                "--service-spec",
                "service.json",
                "--output",
                "recipe.json",
            ])
            .output()
            .unwrap()
    };
    let output = invoke();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["deploymentReady"], false);
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["qualification"], "pending");
    let initial = fs::read(root.path().join("recipe.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&initial).unwrap(),
        report
    );
    assert!(report.get("supervisor").is_none());
    assert!(report.get("systemdUnit").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(sentinel));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(sentinel));
    assert!(!String::from_utf8_lossy(&initial).contains(sentinel));
    let repeat = invoke();
    assert!(!repeat.status.success());
    assert!(repeat.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&repeat.stderr).contains(sentinel));
    assert_eq!(fs::read(root.path().join("recipe.json")).unwrap(), initial);
}
