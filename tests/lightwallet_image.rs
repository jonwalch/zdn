//! Registry data fixtures only: no Docker, AWS, network, or image execution.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zdn::{aws::TeamDefinition, lightwallet_image::*};

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn config() -> Value {
    json!({"architecture":"amd64","os":"linux",
        "config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Entrypoint":["lightwalletd"],"Cmd":["--help"],"WorkingDir":"/srv/lightwalletd"},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","b".repeat(64))]}})
}

fn fixture_with_config(config: Value) -> (ImageRecord, Vec<u8>, Vec<u8>, Value) {
    let bytes = serde_json::to_vec(&config).unwrap();
    let manifest = json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&bytes),"size":bytes.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","c".repeat(64)),"size":1234}]});
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let record = ImageRecord {
        api_version: API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test-team/lightwalletd@{}",
            digest(&manifest_bytes)
        ),
        config_digest: digest(&bytes),
        platform: "linux/amd64".into(),
        source_revision: SOURCE_REVISION.into(),
        source_version: SOURCE_VERSION.into(),
        protocol_revision: PROTOCOL_REVISION.into(),
        protocol_version: PROTOCOL_VERSION.into(),
        binary_path: BINARY_PATH.into(),
        environment_launcher: ENVIRONMENT_LAUNCHER.into(),
    };
    let inspect = json!([{"Id":record.config_digest,"RepoDigests":[record.image],"Os":"linux","Architecture":"amd64","Config":config["config"]}]);
    (record, manifest_bytes, bytes, inspect)
}

fn fixture() -> (ImageRecord, Vec<u8>, Vec<u8>, Value) {
    fixture_with_config(config())
}

fn repin(record: &mut ImageRecord, manifest: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(manifest).unwrap();
    let repository = record.image.rsplit_once('@').unwrap().0;
    record.image = format!("{repository}@{}", digest(&bytes));
    bytes
}

fn team() -> TeamDefinition {
    serde_json::from_value(json!({"apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
        "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-test-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}})).unwrap()
}

#[test]
fn verifies_exact_saved_artifacts_and_reports_only_observed_metadata() {
    let (record, manifest, config, inspect) = fixture();
    let offline = validate_artifacts(&record, &manifest, &config, None).unwrap();
    assert!(
        offline.manifest_bytes_verified
            && offline.config_bytes_verified
            && offline.single_platform_manifest
    );
    assert!(
        !offline.docker_metadata_verified
            && !offline.source_provenance_verified
            && !offline.binary_contents_verified
            && !offline.launch_ready
    );
    let host = validate_artifacts(
        &record,
        &manifest,
        &config,
        Some(&serde_json::to_vec(&inspect).unwrap()),
    )
    .unwrap();
    assert!(host.docker_metadata_verified);
    assert!(
        !host.source_provenance_verified && !host.binary_contents_verified && !host.launch_ready
    );
    assert_eq!(host.qualification, "pending");
    assert_eq!(host.declared_source_revision, SOURCE_REVISION);
    assert_eq!(host.declared_protocol_version, PROTOCOL_VERSION);
    assert_eq!(host.required_launch.binary_path, BINARY_PATH);
    assert_eq!(host.required_launch.entrypoint, ENVIRONMENT_LAUNCHER);
    assert_eq!(host.required_launch.uid, 10001);
    assert_eq!(host.required_launch.stop_signal, "SIGTERM");
    assert!(
        host.required_launch.clear_environment
            && host.required_launch.override_command
            && host.required_launch.disable_image_healthcheck
    );
    assert_eq!(
        ImageRecord::from_json(&serde_json::to_vec(&record).unwrap()).unwrap(),
        record
    );
}

#[test]
fn accepts_docker_distribution_child_manifest_with_matching_config_type() {
    let (mut record, bytes, config, _) = fixture();
    let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
    manifest["mediaType"] = json!("application/vnd.docker.distribution.manifest.v2+json");
    manifest["config"]["mediaType"] = json!("application/vnd.docker.container.image.v1+json");
    manifest["layers"][0]["mediaType"] = json!("application/vnd.docker.image.rootfs.diff.tar.gzip");
    let bytes = repin(&mut record, &manifest);
    validate_artifacts(&record, &bytes, &config, None).unwrap();
}

#[test]
fn rejects_unknown_missing_and_unpinned_record_fields() {
    let (record, _, _, _) = fixture();
    let value = serde_json::to_value(record).unwrap();
    for (field, bad) in [
        ("apiVersion", "v999"),
        ("platform", "linux/arm64"),
        ("sourceRevision", "main"),
        ("sourceVersion", "latest"),
        ("protocolRevision", SOURCE_REVISION),
        ("protocolVersion", "v0.4.0"),
        ("binaryPath", "/bin/sh"),
        ("environmentLauncher", "env"),
        ("qualification", "passed"),
    ] {
        let mut mutated = value.clone();
        mutated[field] = json!(bad);
        assert!(
            ImageRecord::from_json(&serde_json::to_vec(&mutated).unwrap()).is_err(),
            "accepted {field}"
        );
    }
    for field in value.as_object().unwrap().keys() {
        let mut mutated = value.clone();
        mutated.as_object_mut().unwrap().remove(field);
        assert!(
            ImageRecord::from_json(&serde_json::to_vec(&mutated).unwrap()).is_err(),
            "missing {field}"
        );
    }
    let mut duplicate = serde_json::to_string(&value).unwrap();
    duplicate.insert_str(1, "\"sourceVersion\":\"v0.5.5\",");
    assert!(ImageRecord::from_json(duplicate.as_bytes()).is_err());
}

#[test]
fn rejects_mutable_implicit_and_shell_sensitive_references() {
    let (record, _, _, _) = fixture();
    for repository in [
        "lightwalletd",
        "example/lightwalletd",
        "ghcr.io/Example/lightwalletd",
        "https://ghcr.io/example/lightwalletd",
        "ghcr.io/example/lightwalletd:latest",
        "ghcr.io/example/../lightwalletd",
        "ghcr.io//lightwalletd",
        "ghcr.io/example/$(id)",
        "ghcr.io/example/`id`",
        "ghcr.io/example/image;id",
        "user@ghcr.io/example/lightwalletd",
        "ghcr.io:0/example/lightwalletd",
        "ghcr.io:65536/example/lightwalletd",
        "ghcr.io./example/lightwalletd",
    ] {
        let mut bad = record.clone();
        bad.image = format!("{repository}@sha256:{}", "a".repeat(64));
        assert!(bad.validate().is_err(), "accepted {repository}");
    }
    for suffix in [
        "latest".into(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
    ] {
        let mut bad = record.clone();
        bad.image = format!("ghcr.io/example/lightwalletd@{suffix}");
        assert!(bad.validate().is_err(), "accepted {suffix}");
    }
}

#[test]
fn deployment_requires_exact_team_account_region_and_namespace() {
    let (record, _, _, _) = fixture();
    assert_eq!(
        record.ecr_repository(&team()).unwrap(),
        "zdn/test-team/lightwalletd"
    );
    for (from, to) in [
        ("123456789012", "999999999999"),
        ("us-east-1", "us-west-2"),
        ("/test-team/", "/test-team-other/"),
        ("/zdn/", "/other/"),
        ("amazonaws.com/", "amazonaws.com.evil.example/"),
    ] {
        let mut bad = record.clone();
        bad.image = bad.image.replace(from, to);
        bad.validate().unwrap();
        assert!(bad.ecr_repository(&team()).is_err(), "accepted {to}");
    }
    let mut external = record;
    external.image = format!(
        "docker.io/electriccoinco/lightwalletd@{}",
        external.manifest_digest().unwrap()
    );
    external.validate().unwrap();
    assert!(external.ecr_repository(&team()).is_err());
}

#[test]
fn rejects_manifest_or_config_bytes_changed_after_recording() {
    let (record, mut manifest, config, _) = fixture();
    let verified = validate_manifest_bytes(&record, &manifest).unwrap();
    manifest.push(b' ');
    assert!(validate_manifest_bytes(&record, &manifest).is_err());
    let mut changed = config.clone();
    changed.push(b' ');
    assert!(validate_config_bytes(&record, &verified, &changed).is_err());
    let mut changed = config;
    changed[0] = b' ';
    assert!(validate_config_bytes(&record, &verified, &changed).is_err());
}

#[test]
fn rejects_cross_record_verification_tokens() {
    let (record, manifest, config, inspect) = fixture();
    let verified = validate_manifest_bytes(&record, &manifest).unwrap();
    let image = validate_config_bytes(&record, &verified, &config).unwrap();
    let mut substituted = record;
    substituted.image = substituted.image.replace("test-team", "another-team");
    assert!(validate_config_bytes(&substituted, &verified, &config).is_err());
    assert!(
        validate_docker_inspect(&substituted, &image, &serde_json::to_vec(&inspect).unwrap())
            .is_err()
    );
}

#[test]
fn rejects_indexes_foreign_layers_extra_descriptors_and_wrong_sizes() {
    let (record, bytes, _, _) = fixture();
    let good: Value = serde_json::from_slice(&bytes).unwrap();
    let mut cases = Vec::new();
    for (field, value) in [
        ("schemaVersion", json!(1)),
        (
            "mediaType",
            json!("application/vnd.oci.image.index.v1+json"),
        ),
        ("manifests", json!([])),
        ("artifactType", json!("application/example")),
        ("layers", json!([])),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        cases.push(bad);
    }
    for (field, value) in [
        (
            "mediaType",
            json!("application/vnd.docker.container.image.v1+json"),
        ),
        ("size", json!(0)),
        ("size", json!(MAX_CONFIG_BYTES + 1)),
        ("digest", json!(format!("sha256:{}", "f".repeat(64)))),
    ] {
        let mut bad = good.clone();
        bad["config"][field] = value;
        cases.push(bad);
    }
    for (field, value) in [
        (
            "mediaType",
            json!("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"),
        ),
        ("urls", json!(["https://untrusted.example/layer"])),
        ("size", json!(0)),
        ("size", json!(16 * 1024u64.pow(3) + 1)),
    ] {
        let mut bad = good.clone();
        bad["layers"][0][field] = value;
        cases.push(bad);
    }
    let mut bad = good.clone();
    bad["layers"] = json!(vec![good["layers"][0].clone(); 129]);
    cases.push(bad);
    for bad in cases {
        let mut record = record.clone();
        let bytes = repin(&mut record, &bad);
        assert!(
            validate_manifest_bytes(&record, &bytes).is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn rejects_wrong_platform_or_unbound_rootfs() {
    let good = config();
    let mut cases = Vec::new();
    for (field, value) in [
        ("os", json!("windows")),
        ("architecture", json!("arm64")),
        ("variant", json!("v8")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        cases.push(bad);
    }
    for (field, value) in [
        ("type", json!("unknown")),
        ("diff_ids", json!([])),
        ("diff_ids", json!(["not-a-digest"])),
    ] {
        let mut bad = good.clone();
        bad["rootfs"][field] = value;
        cases.push(bad);
    }
    for bad in cases {
        let (record, manifest, config, _) = fixture_with_config(bad);
        assert!(validate_artifacts(&record, &manifest, &config, None).is_err());
    }
}

#[test]
fn rejects_unsafe_runtime_defaults_in_registry_and_host_inspection() {
    for (field, value) in [
        ("Env", json!(["LD_PRELOAD=/tmp/loader"])),
        (
            "Env",
            json!([
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "HTTP_PROXY=http://proxy"
            ]),
        ),
        (
            "Env",
            json!([
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "PATH=/usr/local/bin:/usr/bin:/bin"
            ]),
        ),
        ("Env", json!([])),
        ("Entrypoint", json!(["/bin/sh", "-c", "lightwalletd"])),
        ("Cmd", json!(["--no-tls-very-insecure"])),
        ("WorkingDir", json!("/")),
        ("Volumes", json!({"/var/lib/lightwalletd":{}})),
        ("OnBuild", json!(["RUN ignored"])),
        ("StopSignal", json!("bad\u{0}signal")),
    ] {
        let mut bad = config();
        bad["config"][field] = value.clone();
        let (record, manifest, config, _) = fixture_with_config(bad);
        assert!(
            validate_artifacts(&record, &manifest, &config, None).is_err(),
            "registry accepted {field}={value}"
        );
        let (record, manifest, config, mut inspect) = fixture();
        inspect[0]["Config"][field] = value.clone();
        assert!(
            validate_artifacts(
                &record,
                &manifest,
                &config,
                Some(&serde_json::to_vec(&inspect).unwrap())
            )
            .is_err(),
            "host accepted {field}={value}"
        );
    }
}

#[test]
fn rejects_host_metadata_from_another_image_or_platform() {
    let (record, manifest, config, inspect) = fixture();
    for (field, value) in [
        ("Id", json!(format!("sha256:{}", "f".repeat(64)))),
        ("RepoDigests", json!([])),
        (
            "RepoDigests",
            json!([record.image.replace("test-team", "another-team")]),
        ),
        ("Os", json!("windows")),
        ("Architecture", json!("arm64")),
        ("Variant", json!("v8")),
    ] {
        let mut bad = inspect.clone();
        bad[0][field] = value;
        assert!(
            validate_artifacts(
                &record,
                &manifest,
                &config,
                Some(&serde_json::to_vec(&bad).unwrap())
            )
            .is_err(),
            "accepted {field}"
        );
    }
    for bad in [
        json!([]),
        json!([inspect[0], inspect[0]]),
        json!({"Config":inspect[0]["Config"]}),
    ] {
        assert!(validate_artifacts(
            &record,
            &manifest,
            &config,
            Some(&serde_json::to_vec(&bad).unwrap())
        )
        .is_err());
    }
}

#[test]
fn publisher_labels_cannot_promote_provenance_or_payment_qualification() {
    let mut config = config();
    config["config"]["Labels"] = json!({"org.opencontainers.image.revision":SOURCE_REVISION,
        "org.opencontainers.image.version":SOURCE_VERSION,"zdn.qualification":"passed","zdn.launchReady":"true"});
    let (record, manifest, config, inspect) = fixture_with_config(config);
    let report = validate_artifacts(
        &record,
        &manifest,
        &config,
        Some(&serde_json::to_vec(&inspect).unwrap()),
    )
    .unwrap();
    assert!(
        !report.source_provenance_verified
            && !report.binary_contents_verified
            && !report.launch_ready
    );
    assert_eq!(report.qualification, "pending");
}

#[test]
fn bounds_record_manifest_config_and_inspection_inputs() {
    let (record, manifest, config, _) = fixture();
    assert!(ImageRecord::from_json(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    assert!(validate_manifest_bytes(&record, &vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    let verified = validate_manifest_bytes(&record, &manifest).unwrap();
    assert!(validate_config_bytes(&record, &verified, &vec![b' '; MAX_CONFIG_BYTES + 1]).is_err());
    let image = validate_config_bytes(&record, &verified, &config).unwrap();
    assert!(validate_docker_inspect(&record, &image, &vec![b' '; MAX_INSPECT_BYTES + 1]).is_err());
}
