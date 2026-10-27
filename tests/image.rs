//! Image fixtures are data only. These tests never require Docker, credentials,
//! a registry, executable images, or a node dependency.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zdn::image::{
    validate_config_bytes, validate_docker_inspect, validate_manifest_bytes, ImageCapabilities,
    ImageProvenance, ImageRecord, API_VERSION, ENV_ENTRYPOINT, LAUNCH_HOME, LAUNCH_PATH,
    MAX_CONFIG_BYTES, MAX_INSPECT_BYTES, MAX_MANIFEST_BYTES, MAX_RECORD_BYTES, NODE_BINARY,
};

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn runtime() -> Value {
    json!({
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "FEATURES=default-release-binaries", "UID=10001", "GID=10001",
            "USER=zebra", "HOME=/home/zebra"
        ],
        "Entrypoint": ["entrypoint.sh"], "Cmd": ["zakurad"],
        "User": "", "WorkingDir": "/home/zebra",
        "Volumes": null, "OnBuild": null
    })
}

fn registry_config() -> Value {
    json!({
        "architecture": "amd64", "os": "linux", "config": runtime(),
        "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", "b".repeat(64))]},
        "history": [{"created_by": "fixture only, never executed"}]
    })
}

fn fixture_with_config(config: &Value) -> (ImageRecord, Vec<u8>, Vec<u8>, Value) {
    let config_bytes = serde_json::to_vec(config).unwrap();
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(&config_bytes), "size": config_bytes.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": format!("sha256:{}", "c".repeat(64)), "size": 1234}]
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let record = ImageRecord {
        api_version: API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/team/zakura@{}",
            digest(&manifest_bytes)
        ),
        config_digest: digest(&config_bytes),
        platform: "linux/amd64".into(),
        provenance: ImageProvenance::Release {
            revision: "d".repeat(40),
            version: "v1.2.3".into(),
        },
        capabilities: ImageCapabilities::default(),
        binary_path: NODE_BINARY.into(),
        environment_launcher: ENV_ENTRYPOINT.into(),
    };
    let inspect = json!([{
        "Id": record.config_digest,
        "RepoDigests": [record.image],
        "Os": "linux", "Architecture": "amd64", "Config": config["config"],
        "DockerVersion": "fixture", "Size": 1234,
        "RootFS": {"Type":"layers", "Layers":[format!("sha256:{}", "b".repeat(64))]}
    }]);
    (record, manifest_bytes, config_bytes, inspect)
}

fn fixture() -> (ImageRecord, Vec<u8>, Vec<u8>, Value) {
    fixture_with_config(&registry_config())
}

fn repin(record: &mut ImageRecord, manifest: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(manifest).unwrap();
    record.image = format!("ghcr.io/example/zakura@{}", digest(&bytes));
    bytes
}

#[test]
fn verifies_saved_child_manifest_config_and_pulled_image_without_qualifying_node() {
    let (record, manifest, config, inspect) = fixture();
    let verified = validate_manifest_bytes(&record, &manifest).unwrap();
    validate_config_bytes(&record, &verified, &config).unwrap();
    let report =
        validate_docker_inspect(&record, &verified, &serde_json::to_vec(&inspect).unwrap())
            .unwrap();
    assert!(
        report.manifest_bytes_verified
            && report.single_platform_manifest
            && report.docker_metadata_verified
    );
    assert!(!report.capabilities_observed && !report.launch_ready);
    assert_eq!(report.qualification, "pending");
    assert_eq!(report.required_launch.entrypoint, "/usr/bin/env");
    assert!(
        report.required_launch.clear_environment
            && report.required_launch.override_command
            && report.required_launch.disable_image_healthcheck
    );
    assert_eq!(report.required_launch.binary_path, "/usr/local/bin/zakurad");
    assert_eq!(report.required_launch.path, LAUNCH_PATH);
    assert_eq!(report.required_launch.home, LAUNCH_HOME);
    assert_eq!(
        (report.required_launch.uid, report.required_launch.gid),
        (10001, 10001)
    );
    assert_eq!(report.required_launch.working_directory, "/");
    assert_eq!(report.required_launch.stop_signal, "SIGINT");
}

#[test]
fn accepts_docker_v2_child_manifest_and_valid_source_provenance() {
    let (mut record, bytes, config, _) = fixture();
    record.provenance = ImageProvenance::Source {
        revision: "e".repeat(64),
        snapshot_sha256: "f".repeat(64),
    };
    let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
    manifest["mediaType"] = json!("application/vnd.docker.distribution.manifest.v2+json");
    manifest["config"]["mediaType"] = json!("application/vnd.docker.container.image.v1+json");
    manifest["layers"][0]["mediaType"] = json!("application/vnd.docker.image.rootfs.diff.tar.gzip");
    let bytes = repin(&mut record, &manifest);
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    validate_config_bytes(&record, &verified, &config).unwrap();
    assert_eq!(
        ImageRecord::from_json(&serde_json::to_vec(&record).unwrap()).unwrap(),
        record
    );
}

#[test]
fn record_schema_rejects_missing_unknown_or_unsupported_capabilities() {
    let (record, _, _, _) = fixture();
    let good = serde_json::to_value(record).unwrap();
    for (path, value) in [
        ("apiVersion", json!("zdn-zakura-image/v999")),
        ("platform", json!("linux/arm64")),
        ("binaryPath", json!("/bin/sh")),
        ("environmentLauncher", json!("env")),
        ("unsupported", json!(true)),
    ] {
        let mut input = good.clone();
        input[path] = value;
        assert!(
            ImageRecord::from_json(&serde_json::to_vec(&input).unwrap()).is_err(),
            "{path}"
        );
    }
    for (key, _) in good["capabilities"].as_object().unwrap() {
        let mut missing = good.clone();
        missing["capabilities"].as_object_mut().unwrap().remove(key);
        assert!(
            ImageRecord::from_json(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "missing {key}"
        );
        let mut bad = good.clone();
        bad["capabilities"][key] = if good["capabilities"][key].is_boolean() {
            json!(false)
        } else {
            json!("unknown/v2")
        };
        assert!(
            ImageRecord::from_json(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "bad {key}"
        );
    }
}

#[test]
fn reference_rejects_tags_implicit_registries_and_command_syntax() {
    let (record, _, _, _) = fixture();
    for repository in [
        "zakura",
        "example/zakura",
        "ghcr.io/Example/zakura",
        "https://ghcr.io/example/zakura",
        "ghcr.io/example/zakura:latest",
        "ghcr.io/example/zakura --privileged",
        "ghcr.io/example/$(id)",
        "ghcr.io/example/`id`",
        "ghcr.io/example/zakura;id",
        "ghcr.io/example/../zakura",
        "ghcr.io//zakura",
        "ghcr.io:/example/zakura",
        "ghcr.io:0/example/zakura",
        "ghcr.io:65536/example/zakura",
        "-ghcr.io/example/zakura",
        "ghcr.io./example/zakura",
        "user@ghcr.io/example/zakura",
    ] {
        let mut bad = record.clone();
        bad.image = format!("{repository}@sha256:{}", "a".repeat(64));
        assert!(bad.validate().is_err(), "accepted {repository}");
    }
    for suffix in [
        "latest".to_string(),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
    ] {
        let mut bad = record.clone();
        bad.image = format!("ghcr.io/example/zakura@{suffix}");
        assert!(bad.validate().is_err(), "accepted {suffix}");
    }
    for repository in [
        "ghcr.io/example/zakura",
        "localhost:5000/example/zakura",
        "registry.example.com:443/team/node-v1",
    ] {
        let mut good = record.clone();
        good.image = format!("{repository}@sha256:{}", "a".repeat(64));
        good.validate().unwrap();
    }
}

#[test]
fn provenance_requires_full_revision_and_explicit_snapshot_or_release() {
    let (record, _, _, _) = fixture();
    for provenance in [
        ImageProvenance::Source {
            revision: "main".into(),
            snapshot_sha256: "a".repeat(64),
        },
        ImageProvenance::Source {
            revision: "A".repeat(40),
            snapshot_sha256: "a".repeat(64),
        },
        ImageProvenance::Source {
            revision: "a".repeat(40),
            snapshot_sha256: "b".repeat(63),
        },
        ImageProvenance::Release {
            revision: "b".repeat(40),
            version: "latest".into(),
        },
        ImageProvenance::Release {
            revision: "b".repeat(40),
            version: "v1\nsecret".into(),
        },
    ] {
        let mut bad = record.clone();
        bad.provenance = provenance;
        assert!(bad.validate().is_err());
    }
    let mut unknown = serde_json::to_value(record).unwrap();
    unknown["provenance"]["unverifiedBuild"] = json!(true);
    assert!(ImageRecord::from_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn manifest_validation_is_bound_to_exact_raw_bytes() {
    let (record, bytes, _, _) = fixture();
    let mut mutated = bytes.clone();
    mutated.push(b'\n');
    assert!(validate_manifest_bytes(&record, &mutated).is_err());
    assert!(validate_manifest_bytes(&record, b"not json").is_err());
}

#[test]
fn refuses_index_or_manifest_list_even_when_the_digest_matches() {
    for media_type in [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ] {
        let (mut record, _, _, _) = fixture();
        let index = json!({"schemaVersion": 2, "mediaType": media_type, "manifests": [{"platform":{"architecture":"amd64","os":"linux"}}]});
        let bytes = repin(&mut record, &index);
        assert!(validate_manifest_bytes(&record, &bytes).is_err());
    }
}

#[test]
fn refuses_wrong_config_identity_foreign_layers_and_unbounded_descriptors() {
    let (record, bytes, _, _) = fixture();
    let good: Value = serde_json::from_slice(&bytes).unwrap();
    let mut bad_cases = Vec::new();
    for (pointer, value) in [
        ("/schemaVersion", json!(1)),
        (
            "/config/digest",
            json!(format!("sha256:{}", "d".repeat(64))),
        ),
        ("/config/mediaType", json!("application/octet-stream")),
        ("/config/size", json!(0)),
        ("/config/size", json!(MAX_CONFIG_BYTES + 1)),
        (
            "/layers/0/mediaType",
            json!("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"),
        ),
        ("/layers/0/size", json!(0)),
        ("/layers/0/size", json!(16_u64 * 1024 * 1024 * 1024 + 1)),
        ("/layers", json!([])),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        bad_cases.push(bad);
    }
    let mut foreign = good.clone();
    foreign["layers"][0]["urls"] = json!(["https://untrusted.example/object"]);
    bad_cases.push(foreign);
    let mut artifact = good.clone();
    artifact["artifactType"] = json!("application/vnd.example.artifact");
    bad_cases.push(artifact);
    for bad in bad_cases {
        let mut record = record.clone();
        let bytes = repin(&mut record, &bad);
        assert!(validate_manifest_bytes(&record, &bytes).is_err());
    }
}

#[test]
fn configuration_is_bound_to_manifest_size_and_digest() {
    let (record, bytes, config, _) = fixture();
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    let mut bad = config.clone();
    bad.push(b' ');
    assert!(validate_config_bytes(&record, &verified, &bad).is_err());
    let mut changed = config;
    let position = changed
        .windows(5)
        .position(|window| window == b"amd64")
        .unwrap();
    changed[position..position + 5].copy_from_slice(b"arm64");
    assert!(validate_config_bytes(&record, &verified, &changed).is_err());
}

#[test]
fn rejects_wrong_platform_and_rootfs_in_exact_registry_config() {
    for (pointer, value) in [
        ("/architecture", json!("arm64")),
        ("/os", json!("windows")),
        ("/rootfs/type", json!("unsupported")),
        ("/rootfs/diff_ids", json!([])),
        ("/rootfs/diff_ids/0", json!("sha256:bad")),
    ] {
        let mut config = registry_config();
        *config.pointer_mut(pointer).unwrap() = value;
        let (record, bytes, config, _) = fixture_with_config(&config);
        let verified = validate_manifest_bytes(&record, &bytes).unwrap();
        assert!(
            validate_config_bytes(&record, &verified, &config).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn receipt_cannot_be_reused_for_another_record() {
    let (mut record, bytes, config, inspect) = fixture();
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    record.provenance = ImageProvenance::Release {
        revision: "f".repeat(40),
        version: "v9".into(),
    };
    record.validate().unwrap();
    assert!(validate_config_bytes(&record, &verified, &config).is_err());
    assert!(
        validate_docker_inspect(&record, &verified, &serde_json::to_vec(&inspect).unwrap())
            .is_err()
    );
}

#[test]
fn pulled_image_must_match_exact_child_repo_digest_config_and_platform() {
    let (record, bytes, _, inspect) = fixture();
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    for (key, value) in [
        ("Id", json!(format!("sha256:{}", "f".repeat(64)))),
        ("RepoDigests", json!([])),
        (
            "RepoDigests",
            json!([format!(
                "unrelated.example/repo@{}",
                record.manifest_digest().unwrap()
            )]),
        ),
        ("RepoDigests", json!([format!("{}:latest", record.image)])),
        ("Os", json!("windows")),
        ("Architecture", json!("arm64")),
        ("Variant", json!("v8")),
    ] {
        let mut bad = inspect.clone();
        bad[0][key] = value;
        assert!(
            validate_docker_inspect(&record, &verified, &serde_json::to_vec(&bad).unwrap())
                .is_err(),
            "{key}"
        );
    }
    for bad in [
        json!([]),
        json!([inspect[0], inspect[0]]),
        inspect[0].clone(),
    ] {
        assert!(
            validate_docker_inspect(&record, &verified, &serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
}

#[test]
fn unexpected_environment_fails_before_any_entrypoint_can_start() {
    for env in [
        "ZAKURA_NETWORK__NETWORK=Mainnet",
        "ZEBRA_RPC__ENABLE_COOKIE_AUTH=false",
        "OTEL_ENDPOINT=https://secret.example",
        "LD_PRELOAD=/tmp/secret.so",
        "LD_LIBRARY_PATH=/tmp",
        "RUST_LOG=trace",
        "HTTP_PROXY=https://secret.example",
        "PATH=/tmp:/usr/bin",
        "HOME=/root",
        "USER=root",
        "UID=0",
        "GID=0",
        "FEATURES=default;id",
        "NO_EQUALS",
    ] {
        let mut input = registry_config();
        input["config"]["Env"] = json!([env]);
        let (record, bytes, config, inspect) = fixture_with_config(&input);
        let verified = validate_manifest_bytes(&record, &bytes).unwrap();
        let error = validate_config_bytes(&record, &verified, &config).unwrap_err();
        assert!(!error.to_string().contains("secret"));
        assert!(
            validate_docker_inspect(&record, &verified, &serde_json::to_vec(&inspect).unwrap())
                .is_err(),
            "{env}"
        );
    }
}

#[test]
fn rejects_duplicate_environment_assignments_and_anonymous_volumes() {
    for (key, value) in [
        ("Env", json!(["USER=zebra", "USER=zebra"])),
        ("Volumes", json!({"/var/lib/zdn":{}})),
        ("OnBuild", json!(["RUN curl https://untrusted.example"])),
    ] {
        let mut input = registry_config();
        input["config"][key] = value;
        let (record, bytes, config, inspect) = fixture_with_config(&input);
        let verified = validate_manifest_bytes(&record, &bytes).unwrap();
        assert!(
            validate_config_bytes(&record, &verified, &config).is_err(),
            "{key}"
        );
        assert!(
            validate_docker_inspect(&record, &verified, &serde_json::to_vec(&inspect).unwrap())
                .is_err(),
            "{key}"
        );
    }
}

#[test]
fn startup_defaults_are_overridden_and_labels_never_attest_capabilities() {
    let mut config = registry_config();
    config["config"]["Entrypoint"] = json!(["/bin/sh", "-c", "untrusted; command"]);
    config["config"]["Cmd"] = json!(["malicious arguments"]);
    config["config"]["User"] = json!("root");
    config["config"]["WorkingDir"] = json!("/tmp");
    config["config"]["StopSignal"] = json!("SIGKILL");
    config["config"]["Healthcheck"] =
        json!({"Test":["CMD-SHELL", "curl https://untrusted.example"]});
    config["config"]["Labels"] = json!({"zdn.qualified": "true", "zdn.walletReady": "true"});
    let (record, bytes, config, inspect) = fixture_with_config(&config);
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    validate_config_bytes(&record, &verified, &config).unwrap();
    let report =
        validate_docker_inspect(&record, &verified, &serde_json::to_vec(&inspect).unwrap())
            .unwrap();
    assert!(!report.capabilities_observed && !report.launch_ready);
    assert_eq!(report.required_launch.entrypoint, "/usr/bin/env");
    assert_eq!(report.required_launch.stop_signal, "SIGINT");
    assert!(report.required_launch.disable_image_healthcheck);
}

#[test]
fn malformed_or_oversized_inputs_fail_without_external_work() {
    let (record, bytes, _, _) = fixture();
    let verified = validate_manifest_bytes(&record, &bytes).unwrap();
    assert!(ImageRecord::from_json(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    assert!(validate_manifest_bytes(&record, &vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    assert!(validate_config_bytes(&record, &verified, &vec![b' '; MAX_CONFIG_BYTES + 1]).is_err());
    assert!(
        validate_docker_inspect(&record, &verified, &vec![b' '; MAX_INSPECT_BYTES + 1]).is_err()
    );
    for invalid in [b"".as_slice(), b"{}", b"null", b"not JSON"] {
        assert!(validate_docker_inspect(&record, &verified, invalid).is_err());
    }
}
