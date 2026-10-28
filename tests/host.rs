use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{base_user_data, HostInstallSpec, S3Object, API_VERSION},
};

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

#[cfg(target_os = "linux")]
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

fn spec() -> HostInstallSpec {
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let deployment = Uuid::parse_str("12345678-1234-4123-8123-123456789abc").unwrap();
    let mut options = RuntimeOptions::new(deployment, "node-1");
    options.network.listen_addr = "10.90.1.10:18233".into();
    options.network.peers = vec!["10.90.1.11:18233".into()];
    let runtime = render_runtime_config(&manifest, &options).unwrap();
    let object = |key: &str| S3Object {
        bucket: "zdn-artifacts-test".into(),
        key: format!("team/test/{key}"),
        sha256: "a".repeat(64),
        bytes: 128,
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
    };
    HostInstallSpec {
        api_version: API_VERSION.into(),
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
        memory_bytes: 24 * 1024 * 1024 * 1024,
        host_reserve_bytes: 4 * 1024 * 1024 * 1024,
        cpu_millis: 3500,
        manifest: object("manifest"),
        bundle: object("bundle"),
        helper: object("helper"),
        image_record: object("image-record"),
        image_manifest: object("image-manifest"),
        new_volume: None,
    }
}

#[test]
fn install_identity_is_deterministic_and_binds_the_spec() {
    let spec = spec();
    let first = spec.install_sha256().unwrap();
    let expected_hash = hex::encode(Sha256::digest(serde_json::to_vec(&spec).unwrap()));
    assert_eq!(first, expected_hash);
    assert_eq!(spec.install_sha256().unwrap(), expected_hash);
    let mut changed = spec;
    changed.memory_bytes += 1024;
    assert_ne!(first, changed.install_sha256().unwrap());
    changed
        .config_toml
        .push_str("\n# escaped: \"quote\" \\ tab\t Unicode: café 雪\n");
    changed.config_sha256 = hex::encode(Sha256::digest(changed.config_toml.as_bytes()));
    let expected_hash = hex::encode(Sha256::digest(serde_json::to_vec(&changed).unwrap()));
    assert_eq!(changed.install_sha256().unwrap(), expected_hash);
}

#[test]
fn rejects_wrong_host_artifact_and_aws_identities() {
    type Mutation = Box<dyn Fn(&mut HostInstallSpec)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|s| s.api_version = "next".into()),
        Box::new(|s| s.node_id = "../node".into()),
        Box::new(|s| s.volume_id = "vol-abc;echo x".into()),
        Box::new(|s| s.consensus_fingerprint = "A".repeat(64)),
        Box::new(|s| s.config_sha256 = "0".repeat(64)),
        Box::new(|s| s.helper.key = "x/../helper".into()),
        Box::new(|s| s.bundle.owner_account = "222222222222".into()),
        Box::new(|s| s.image_record.region = "us-west-2".into()),
        Box::new(|s| s.helper.bytes = 0),
        Box::new(|s| s.image = "zakura:latest".into()),
        Box::new(|s| s.image = s.image.replace("us-east-1", "us-west-2")),
        Box::new(|s| s.memory_bytes = 1),
        Box::new(|s| s.cpu_millis = 0),
        Box::new(|s| s.role = "admin".into()),
    ];
    for mutation in mutations {
        let mut candidate = spec();
        mutation(&mut candidate);
        assert!(candidate.validate().is_err(), "invalid candidate accepted");
        assert!(
            candidate.install_sha256().is_err(),
            "invalid candidate hashed"
        );
    }
}

#[test]
fn rejects_unsafe_runtime_paths_listeners_and_mining() {
    for (from, to) in [
        ("127.0.0.1:18232", "0.0.0.0:18232"),
        ("10.90.1.10:18233", "8.8.8.8:18233"),
        ("10.90.1.11:18233", "example.com:18233"),
        ("/var/lib/zdn/deployments", "/tmp/deployments"),
        ("enable_cookie_auth = true", "enable_cookie_auth = false"),
        ("internal_miner = false", "internal_miner = true"),
    ] {
        let mut candidate = spec();
        assert!(candidate.config_toml.contains(from));
        candidate.config_toml = candidate.config_toml.replace(from, to);
        candidate.config_sha256 = hex::encode(Sha256::digest(candidate.config_toml.as_bytes()));
        assert!(candidate.validate().is_err(), "accepted {from} -> {to}");
        assert!(candidate.install_sha256().is_err(), "hashed {from} -> {to}");
    }
}

#[test]
fn userdata_does_not_touch_a_disk_or_start_a_node() {
    let script = base_user_data();
    assert!(script.contains("VERSION_ID\" = 2023"));
    assert!(script.contains("docker awscli-2"));
    for forbidden in ["python", "mkfs", "mount ", "zakurad", "zdn-node", "/dev/"] {
        assert!(!script.contains(forbidden));
    }
}

#[cfg(unix)]
#[test]
fn userdata_publishes_private_readiness_marker_only_after_prerequisites_succeed() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    fs::write(root.path().join("os-release"), "ID=amzn\nVERSION_ID=2023\n").unwrap();
    for (name, body) in [
        ("uname", "printf '%s\\n' x86_64\n"),
        (
            "dnf",
            "printf '%s\\n' dnf >>\"$ZDN_TEST_LOG\"\nexit \"$ZDN_TEST_FAIL_DNF\"\n",
        ),
        (
            "systemctl",
            "printf '%s\\n' systemctl >>\"$ZDN_TEST_LOG\"\nexit \"$ZDN_TEST_FAIL_SYSTEMCTL\"\n",
        ),
        (
            "chown",
            "test \"$1\" = root:root\nprintf '%s\\n' chown >>\"$ZDN_TEST_LOG\"\n",
        ),
    ] {
        let path = bin.join(name);
        executable::write(&path, format!("#!/bin/bash\nset -eu\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Execute the real shell flow with a temporary /etc and fake prerequisites.
    let script = base_user_data()
        .replace(". /etc/os-release", ". \"$ZDN_TEST_ETC/os-release\"")
        .replace(
            "ready=/etc/zdn-prerequisites-ready",
            "ready=\"$ZDN_TEST_ETC/zdn-prerequisites-ready\"",
        )
        .replace(
            "mktemp /etc/.zdn-prerequisites-ready.XXXXXXXX",
            "mktemp \"$ZDN_TEST_ETC/.zdn-prerequisites-ready.XXXXXXXX\"",
        )
        // BSD mv has no -T. The destination here is absent on every attempt.
        .replace("mv -T --", "mv --");
    let script_path = root.path().join("userdata.sh");
    fs::write(&script_path, script).unwrap();
    let marker = root.path().join("zdn-prerequisites-ready");
    let log = root.path().join("log");
    for (dnf_failure, service_failure, expected_log) in [
        (1, 0, "dnf\n"),
        (0, 1, "dnf\nsystemctl\n"),
        (0, 0, "dnf\nsystemctl\nchown\n"),
    ] {
        fs::write(&log, "").unwrap();
        let output = Command::new("bash")
            .arg(&script_path)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("ZDN_TEST_ETC", root.path())
            .env("ZDN_TEST_LOG", &log)
            .env("ZDN_TEST_FAIL_DNF", dnf_failure.to_string())
            .env("ZDN_TEST_FAIL_SYSTEMCTL", service_failure.to_string())
            .output()
            .unwrap();
        let success = dnf_failure == 0 && service_failure == 0;
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(&log).unwrap(), expected_log);
        assert_eq!(marker.exists(), success);
        if success {
            assert_eq!(
                fs::read_to_string(&marker).unwrap(),
                "zdn-host-prerequisites/v1alpha1\n"
            );
            assert_eq!(
                fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".zdn-prerequisites-ready.")));
    }
}

#[test]
fn serialized_contract_rejects_unknown_fields() {
    let mut value = serde_json::to_value(spec()).unwrap();
    value["deleteData"] = json!(true);
    assert!(serde_json::from_value::<HostInstallSpec>(value).is_err());
}

#[test]
fn controller_interval_is_immutable_and_legacy_install_does_not_enable_it() {
    let mut candidate = spec();
    let legacy = candidate.install_sha256().unwrap();
    let legacy_json = serde_json::to_value(&candidate).unwrap();
    assert!(legacy_json.get("blockIntervalSeconds").is_none());
    assert_eq!(
        serde_json::from_value::<HostInstallSpec>(legacy_json)
            .unwrap()
            .block_interval_seconds,
        None
    );
    candidate.block_interval_seconds = Some(25);
    let first = candidate.install_sha256().unwrap();
    assert_ne!(legacy, first);
    candidate.block_interval_seconds = Some(75);
    assert_ne!(first, candidate.install_sha256().unwrap());
    for invalid in [0, 86_401, u64::MAX] {
        candidate.block_interval_seconds = Some(invalid);
        assert!(candidate.validate().is_err());
        assert!(candidate.install_sha256().is_err());
    }
}

fn new_volume_authorization() -> zdn::host::NewVolumeAuthorization {
    zdn::host::NewVolumeAuthorization {
        api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
        volume_id: spec().volume_id,
        instance_id: "i-0123456789abcdef0".into(),
        created_at: "2026-10-15T17:01:03.208Z".into(),
        size_bytes: 1024 * 1024 * 1024,
        creation_intent_sha256: "c".repeat(64),
        checkpoint_sha256: "d".repeat(64),
    }
}

#[test]
fn new_volume_authorization_is_exact_optional_and_pinned_in_the_install_identity() {
    let legacy = spec();
    let value = serde_json::to_value(&legacy).unwrap();
    assert!(value.get("newVolume").is_none());
    let decoded: HostInstallSpec = serde_json::from_value(value).unwrap();
    assert!(decoded.new_volume.is_none());
    let mut authorized = legacy.clone();
    authorized.new_volume = Some(new_volume_authorization());
    assert_ne!(
        authorized.install_sha256().unwrap(),
        legacy.install_sha256().unwrap()
    );
    for (field, value) in [
        ("apiVersion", json!("future")),
        ("volumeId", json!("vol-11111111111111111")),
        ("instanceId", json!("i-other")),
        ("sizeBytes", json!(1024)),
        ("createdAt", json!("unknown")),
        ("creationIntentSha256", json!("")),
        ("checkpointSha256", json!("not-a-digest")),
    ] {
        let mut changed = serde_json::to_value(&authorized).unwrap();
        changed["newVolume"][field] = value;
        let changed: HostInstallSpec = serde_json::from_value(changed).unwrap();
        assert!(changed.validate().is_err(), "{field}");
        assert!(changed.install_sha256().is_err(), "{field}");
    }
}

#[cfg(target_os = "linux")]
mod native_inputs {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use zdn::{host::files::Directory, host::inputs::verify, image};

    fn save(root: &std::path::Path, name: &str, bytes: &[u8], object: &mut S3Object) {
        fs::write(root.join(name), bytes).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        object.bytes = bytes.len() as u64;
        object.sha256 = hex::encode(Sha256::digest(bytes));
    }

    pub(super) fn fixture() -> (tempfile::TempDir, Directory, HostInstallSpec) {
        let root = tempfile::tempdir().unwrap();
        let directory =
            Directory::open(root.path(), fs::metadata(root.path()).unwrap().uid()).unwrap();
        let mut host = spec();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", "a".repeat(64)), "size": 123},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{}", "c".repeat(64)), "size": 456}]
        }))
        .unwrap();
        host.image = format!(
            "{}@sha256:{}",
            host.image.split_once('@').unwrap().0,
            hex::encode(Sha256::digest(&manifest))
        );
        let record = image::ImageRecord {
            api_version: image::API_VERSION.into(),
            image: host.image.clone(),
            config_digest: format!("sha256:{}", "a".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: image::ImageProvenance::Release {
                revision: "d".repeat(40),
                version: "v1.2.3".into(),
            },
            capabilities: Default::default(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        };
        let mut helper = [0; 64];
        helper[..6].copy_from_slice(b"\x7fELF\x02\x01");
        helper[16] = 2;
        helper[18] = 62;
        save(
            root.path(),
            "manifest.json",
            include_bytes!("fixtures/chain-manifest/valid.json"),
            &mut host.manifest,
        );
        // Only the byte pin is checked at this stage. Canonical TAR/block
        // validation remains bootstrap's job, not a new implicit claim here.
        save(
            root.path(),
            "chain.tar",
            b"opaque pinned bundle fixture",
            &mut host.bundle,
        );
        // This header is deliberately not executable: preflight must not run it.
        save(root.path(), "zdn", &helper, &mut host.helper);
        save(
            root.path(),
            "image.json",
            &serde_json::to_vec(&record).unwrap(),
            &mut host.image_record,
        );
        save(
            root.path(),
            "image-manifest.json",
            &manifest,
            &mut host.image_manifest,
        );
        (root, directory, host)
    }

    #[test]
    fn exact_runtime_preflight_is_read_only_and_does_not_execute_the_helper() {
        let (root, directory, mut host) = fixture();
        for role in ["follower", "producer"] {
            if role == "producer" {
                let manifest: ConsensusManifest =
                    serde_json::from_slice(include_bytes!("fixtures/chain-manifest/valid.json"))
                        .unwrap();
                let mut options = RuntimeOptions::new(host.deployment_id, &host.node_id);
                options.network.listen_addr = "10.90.1.12:18233".into();
                options.network.peers = vec!["10.90.1.13:18233".into(), "10.90.1.14:18234".into()];
                options.rpc_listen_addr = "127.0.0.2:18332".into();
                options.role = zdn::chain::runtime_config::NodeRole::Producer;
                options.reward_address = Some("tm9iNYCVAhLLa4rJtfqqHauR5xL1REdpiDs".into());
                let rendered = render_runtime_config(&manifest, &options).unwrap();
                host.config_toml = rendered.config_toml;
                host.config_sha256 = rendered.config_sha256;
                host.role = role.into();
                host.block_interval_seconds = Some(37);
            }
            let rendered = verify(&host, &directory).unwrap();
            assert_eq!(rendered.config_toml, host.config_toml);
            assert_eq!(rendered.config_sha256, host.config_sha256);
            assert_eq!(rendered.consensus_fingerprint, host.consensus_fingerprint);
            assert_eq!(rendered.paths.node_root, host.node_root());
            assert!(!rendered.launch_ready && !rendered.node_config_validated);
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 5);
    }

    #[test]
    fn preflight_rejects_changed_bytes_even_when_they_remain_valid_metadata() {
        let (root, directory, host) = fixture();
        for name in [
            "manifest.json",
            "chain.tar",
            "zdn",
            "image.json",
            "image-manifest.json",
        ] {
            let original = fs::read(root.path().join(name)).unwrap();
            let mut changed = original.clone();
            match name {
                "manifest.json" => *changed.iter_mut().find(|b| **b == b'\n').unwrap() = b' ',
                "image.json" => {
                    let index = changed.windows(6).position(|v| v == b"v1.2.3").unwrap();
                    changed[index + 5] = b'4';
                }
                "image-manifest.json" => {
                    let index = changed.windows(3).position(|v| v == b"123").unwrap();
                    changed[index + 2] = b'4';
                }
                "zdn" => changed[63] = 1,
                _ => changed[0] ^= 1,
            }
            fs::write(root.path().join(name), &changed).unwrap();
            assert!(
                verify(&host, &directory).is_err(),
                "accepted changed {name}"
            );
            fs::write(root.path().join(name), &original).unwrap();
        }
        verify(&host, &directory).unwrap();
        let mut changed = host.clone();
        changed
            .config_toml
            .push_str("\n# valid TOML, but not the exact rendered bytes\n");
        changed.config_sha256 = hex::encode(Sha256::digest(changed.config_toml.as_bytes()));
        changed.validate().unwrap();
        assert!(verify(&changed, &directory).is_err());
    }

    #[test]
    fn repinning_cannot_bypass_helper_image_or_metadata_limits() {
        let (root, directory, mut host) = fixture();
        let mut helper = fs::read(root.path().join("zdn")).unwrap();
        let original = helper.clone();
        helper[16] = 1; // Relocatable ELF is not a runnable host helper.
        save(root.path(), "zdn", &helper, &mut host.helper);
        assert!(verify(&host, &directory).is_err());
        save(root.path(), "zdn", &original, &mut host.helper);
        verify(&host, &directory).unwrap();

        let original_record = fs::read(root.path().join("image.json")).unwrap();
        let mut record: image::ImageRecord = serde_json::from_slice(&original_record).unwrap();
        // A valid but foreign image identity must fail independently of its file pin.
        record.image = format!(
            "{}@sha256:{}",
            host.image.split_once('@').unwrap().0,
            "e".repeat(64)
        );
        save(
            root.path(),
            "image.json",
            &serde_json::to_vec(&record).unwrap(),
            &mut host.image_record,
        );
        assert!(verify(&host, &directory).is_err());
        save(
            root.path(),
            "image.json",
            &original_record,
            &mut host.image_record,
        );
        verify(&host, &directory).unwrap();

        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join("image-manifest.json")).unwrap())
                .unwrap();
        manifest["schemaVersion"] = json!(1);
        let manifest = serde_json::to_vec(&manifest).unwrap();
        host.image = format!(
            "{}@sha256:{}",
            host.image.split_once('@').unwrap().0,
            hex::encode(Sha256::digest(&manifest))
        );
        record = serde_json::from_slice(&original_record).unwrap();
        record.image = host.image.clone();
        save(
            root.path(),
            "image-manifest.json",
            &manifest,
            &mut host.image_manifest,
        );
        save(
            root.path(),
            "image.json",
            &serde_json::to_vec(&record).unwrap(),
            &mut host.image_record,
        );
        assert!(verify(&host, &directory).is_err());

        let (root, directory, mut host) = fixture();
        let mut manifest = include_bytes!("fixtures/chain-manifest/valid.json").to_vec();
        manifest.resize(2 * 1024 * 1024 + 1, b' ');
        save(root.path(), "manifest.json", &manifest, &mut host.manifest);
        assert!(verify(&host, &directory).is_err());
    }
}

#[cfg(target_os = "linux")]
mod native_volume {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::{
        path::{Path, PathBuf},
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::host::{
        command::Executor,
        files::Directory,
        volume::{
            probe::{observe, Filesystem, Tools},
            Installation,
        },
        NewVolumeAuthorization, NEW_VOLUME_API_VERSION,
    };

    #[test]
    fn volume_tool_worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let expected: Vec<String> = serde_json::from_value(payload["args"].clone()).unwrap();
        assert_eq!(args, expected);
        let mut stdout = payload["stdout"].as_str().unwrap().as_bytes().to_vec();
        stdout.resize(
            stdout.len() + payload["padding"].as_u64().unwrap_or(0) as usize,
            b' ',
        );
        native_tool::reply(
            &work,
            &stdout,
            b"PRIVATE TOOL DIAGNOSTIC",
            payload["code"].as_u64().unwrap() as u8,
        );
    }

    fn tool(path: &Path, args: &[&str], stdout: &str, code: u8) {
        native_tool::install(
            path,
            "native_volume::volume_tool_worker",
            &json!({"args":args,"stdout":stdout,"code":code}),
        );
    }

    fn probe_fixture() -> (tempfile::TempDir, HostInstallSpec, Tools, Executor) {
        let (root, _, host) = fixture(false);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let commands = root.path().join("commands");
        fs::create_dir(&commands).unwrap();
        fs::set_permissions(&commands, fs::Permissions::from_mode(0o700)).unwrap();
        let tools = Tools {
            lsblk: root.path().join("lsblk"),
            findmnt: root.path().join("findmnt"),
            blkid: root.path().join("blkid"),
            wipefs: root.path().join("wipefs"),
            blockdev: root.path().join("blockdev"),
        };
        let inventory = json!({"blockdevices":[
            {"path":"/dev/nvme0n1","serial":"foreign","type":"disk","mountpoints":["/"]},
            {"path":"/dev/nvme12n3","serial":"vol0123456789abcdef0","type":"disk","mountpoints":[null]}
        ]});
        tool(
            &tools.lsblk,
            &[
                "--json",
                "--paths",
                "--output",
                "PATH,TYPE,SERIAL,FSTYPE,MOUNTPOINTS",
            ],
            &inventory.to_string(),
            0,
        );
        tool(
            &tools.findmnt,
            &[
                "--json",
                "--target",
                "/var/lib/zdn",
                "--output",
                "SOURCE,TARGET,FSTYPE",
            ],
            r#"{"filesystems":[{"source":"/dev/root","target":"/","fstype":"xfs"}]}"#,
            0,
        );
        tool(
            &tools.blkid,
            &["-p", "-o", "export", "/dev/nvme12n3"],
            "TYPE=ext4\nUUID=asymmetric-fixture\n",
            0,
        );
        tool(
            &tools.wipefs,
            &["--no-act", "--json", "/dev/nvme12n3"],
            r#"{"signatures":[]}"#,
            0,
        );
        tool(
            &tools.blockdev,
            &["--getsize64", "/dev/nvme12n3"],
            "7516192768\n",
            0,
        );
        let executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            commands,
            host.helper.region.clone(),
            Instant::now() + Duration::from_secs(90),
        )
        .unwrap();
        (root, host, tools, executor)
    }

    #[test]
    fn native_tool_observations_preserve_unmounted_filesystems_without_authorizing_format() {
        #[cfg(feature = "profiling")]
        if std::env::var_os("ZDN_VOLUME_TRACE_TEST").is_none() {
            // Isolate subscriber/callsite state from concurrently running tests.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_volume::native_tool_observations_preserve_unmounted_filesystems_without_authorizing_format",
                    "--nocapture",
                ])
                .env("ZDN_VOLUME_TRACE_TEST", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let (root, mut host, tools, mut executor) = probe_fixture();
        #[cfg(feature = "profiling")]
        let trace = root.path().join("trace.jsonl");
        #[cfg(feature = "profiling")]
        let _subscriber = {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&trace)
                .unwrap();
            tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .json()
                    .with_writer(std::sync::Mutex::new(file))
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                    .finish(),
            )
        };
        let cancel = AtomicBool::new(false);
        let observation = observe(&host, &tools, &mut executor, &cancel, false).unwrap();
        assert_eq!(observation.device, PathBuf::from("/dev/nvme12n3"));
        assert_eq!(observation.filesystem, Filesystem::UnmountedExt4);

        // Exit 1 means no mount, not a JSON parse failure; ignore its output.
        tool(
            &tools.findmnt,
            &[
                "--json",
                "--target",
                "/var/lib/zdn",
                "--output",
                "SOURCE,TARGET,FSTYPE",
            ],
            "not JSON",
            1,
        );
        tool(
            &tools.blkid,
            &["-p", "-o", "export", "/dev/nvme12n3"],
            "no recognized filesystem",
            2,
        );
        for signatures in [r#"{"signatures":[]}"#, r#"{"signatures":null}"#, "{}"] {
            tool(
                &tools.wipefs,
                &["--no-act", "--json", "/dev/nvme12n3"],
                signatures,
                0,
            );
            assert_eq!(
                observe(&host, &tools, &mut executor, &cancel, false)
                    .unwrap()
                    .filesystem,
                Filesystem::NoRecognizedFilesystem {
                    size_bytes: 7 * 1024 * 1024 * 1024
                }
            );
        }
        for size in [1024 * 1024 * 1024, 2 * 1024u64.pow(4)] {
            tool(
                &tools.blockdev,
                &["--getsize64", "/dev/nvme12n3"],
                &format!(" {size}\n"),
                0,
            );
            assert_eq!(
                observe(&host, &tools, &mut executor, &cancel, false)
                    .unwrap()
                    .filesystem,
                Filesystem::NoRecognizedFilesystem { size_bytes: size }
            );
        }
        let (_, _, authorized) = fixture(true);
        host.new_volume = authorized.new_volume;
        tool(
            &tools.blockdev,
            &["--getsize64", "/dev/nvme12n3"],
            "7516192768",
            0,
        );
        assert!(observe(&host, &tools, &mut executor, &cancel, false).is_ok());
        tool(
            &tools.blockdev,
            &["--getsize64", "/dev/nvme12n3"],
            "8589934592",
            0,
        );
        assert!(observe(&host, &tools, &mut executor, &cancel, false).is_err());
        // Probe results never publish install identity, format intent or claims.
        for name in ["identity.json", "format-intent.json", "volume-claimed.json"] {
            assert!(!root.path().join(name).exists());
        }
        #[cfg(feature = "profiling")]
        {
            let text = fs::read_to_string(&trace).unwrap();
            for private in [
                root.path().to_str().unwrap(),
                "/dev/nvme12n3",
                "vol0123456789abcdef0",
                "PRIVATE TOOL DIAGNOSTIC",
            ] {
                assert!(!text.contains(private));
            }
            let records: Vec<serde_json::Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            for (name, count) in [
                ("host.volume.probe.inventory", 8),
                ("host.volume.probe.chain_mount", 8),
                ("host.volume.probe.filesystem", 8),
                ("host.volume.probe.signatures", 7),
                ("host.volume.probe.size", 7),
            ] {
                let spans: Vec<_> = records
                    .iter()
                    .filter(|record| record["span"]["name"] == name)
                    .collect();
                assert_eq!(spans.len(), count, "{name}");
                for record in spans {
                    assert_eq!(record["span"].as_object().unwrap().len(), 1);
                    assert!(record["fields"]["time.busy"].is_string());
                    assert!(record["spans"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|span| span["name"] == "host.volume.probe.observe"));
                }
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record["span"]["name"] == "host.command.execute"
                            && record["spans"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|span| span["name"] == name))
                        .count(),
                    count,
                    "command not nested in {name}"
                );
            }
            assert!(!text.contains("host.volume.probe.producer_mount"));
        }
    }

    #[test]
    fn native_tool_observations_reject_ambiguous_signatures_sizes_and_provider_failures() {
        let (_root, host, tools, mut executor) = probe_fixture();
        let cancel = AtomicBool::new(false);
        let blkid_args = ["-p", "-o", "export", "/dev/nvme12n3"];
        for raw in [
            "TYPE=xfs\n",
            "UUID=missing-type\n",
            "TYPE=ext4\nPTTYPE=\n",
            "TYPE=ext4\nTYPE=xfs\n",
            "TYPE=ext4\nTYPE=ext4\n",
            "TYPE=ext4\nPRIVATE=秘密\n",
        ] {
            tool(&tools.blkid, &blkid_args, raw, 0);
            let error = observe(&host, &tools, &mut executor, &cancel, false).unwrap_err();
            assert!(!format!("{error:#}").contains("秘密"));
        }
        for code in [1, 8] {
            tool(&tools.blkid, &blkid_args, "TYPE=ext4\n", code);
            assert!(observe(&host, &tools, &mut executor, &cancel, false).is_err());
        }
        tool(&tools.blkid, &blkid_args, "", 2);
        let wipefs_args = ["--no-act", "--json", "/dev/nvme12n3"];
        for raw in [
            r#"{"signatures":[{"type":"unknown"}]}"#,
            r#"{"signatures":false}"#,
            r#"{"signatures":[],"signatures":[{}]}"#,
            "PRIVATE TOOL DIAGNOSTIC",
        ] {
            tool(&tools.wipefs, &wipefs_args, raw, 0);
            let error = observe(&host, &tools, &mut executor, &cancel, false).unwrap_err();
            assert!(!format!("{error:#}").contains("PRIVATE TOOL DIAGNOSTIC"));
        }
        tool(&tools.wipefs, &wipefs_args, r#"{"signatures":[]}"#, 0);
        for raw in [
            "1073741823",
            "2199023255553",
            "+1073741824",
            "-1073741824",
            "18446744073709551616",
            "",
            "１073741824",
        ] {
            tool(&tools.blockdev, &["--getsize64", "/dev/nvme12n3"], raw, 0);
            assert!(observe(&host, &tools, &mut executor, &cancel, false).is_err());
        }
        // Keep later evidence valid: a broken mount-status implementation must
        // not pass these negatives by falling through to the previous bad size.
        tool(
            &tools.blockdev,
            &["--getsize64", "/dev/nvme12n3"],
            "7516192768",
            0,
        );
        let mount_args = [
            "--json",
            "--target",
            "/var/lib/zdn",
            "--output",
            "SOURCE,TARGET,FSTYPE",
        ];
        for (raw, code) in [
            ("", 3),
            ("PRIVATE TOOL DIAGNOSTIC", 0),
            (
                r#"{"filesystems":[{"target":"/var/lib/zdn","fstype":"xfs"}]}"#,
                0,
            ),
            (
                r#"{"filesystems":[{"target":"/var/lib/zdn","source":"/nonexistent-probe-source","fstype":"ext4"}]}"#,
                0,
            ),
        ] {
            tool(&tools.findmnt, &mount_args, raw, code);
            assert!(observe(&host, &tools, &mut executor, &cancel, false).is_err());
        }
        // Valid JSON plus whitespace must hit the capture bound, not be
        // accepted after truncation or mistaken for a missing attached volume.
        native_tool::install(
            &tools.lsblk,
            "native_volume::volume_tool_worker",
            &json!({"args":["--json","--paths","--output","PATH,TYPE,SERIAL,FSTYPE,MOUNTPOINTS"],
                "stdout":"{\"blockdevices\":[]}", "code":0, "padding":16 * 1024 * 1024}),
        );
        let error = observe(&host, &tools, &mut executor, &cancel, false).unwrap_err();
        assert!(error.to_string().contains("output exceeded its bound"));
        let error =
            observe(&host, &tools, &mut executor, &AtomicBool::new(true), false).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }

    fn fixture(authorized: bool) -> (tempfile::TempDir, Directory, HostInstallSpec) {
        let root = tempfile::tempdir().unwrap();
        let directory =
            Directory::open(root.path(), fs::metadata(root.path()).unwrap().uid()).unwrap();
        let mut host = spec();
        if authorized {
            host.new_volume = Some(NewVolumeAuthorization {
                api_version: NEW_VOLUME_API_VERSION.into(),
                volume_id: host.volume_id.clone(),
                instance_id: "i-0123456789abcdef0".into(),
                created_at: "2026-10-20T12:34:56Z".into(),
                size_bytes: 7 * 1024 * 1024 * 1024,
                creation_intent_sha256: "c".repeat(64),
                checkpoint_sha256: "d".repeat(64),
            });
        }
        (root, directory, host)
    }

    #[test]
    fn native_records_preserve_historical_exact_encoding() {
        // Captured once from the unchanged historical runner's encoded(IDENTITY)
        // and encoded(format_intent()). This test does not execute Python or
        // derive its expected pins from the native persistence implementation.
        for authorized in [false, true] {
            let (root, directory, host) = fixture(authorized);
            let hash = if authorized {
                "c6e0933a58d9fdab63aaae155ddcd390b281e4b0abcba5ac299d95103df8c380"
            } else {
                "938d9d35cfc66e6a752441619f1aa5a2512225af8f915298b51679e8938092e6"
            };
            let identity = r#"{"apiVersion":"zdn-host-volume/v1alpha1","consensusFingerprint":"70a3a94fb951f9b7f8455e7316d63671b97402a7200ed548b14fe7edbaecbd45","deploymentId":"12345678-1234-4123-8123-123456789abc","installSha256":"INSTALL","nodeId":"node-1","volumeId":"vol-0123456789abcdef0"}"#.replace("INSTALL", hash);
            let authorization = if authorized {
                r#"{"apiVersion":"zdn-new-ebs-volume/v1alpha1","checkpointSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","createdAt":"2026-10-20T12:34:56Z","creationIntentSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","instanceId":"i-0123456789abcdef0","sizeBytes":7516192768,"volumeId":"vol-0123456789abcdef0"}"#
            } else {
                "null"
            };
            let intent = format!("{{\"apiVersion\":\"zdn-host-format/v1alpha1\",\"identity\":{identity},\"newVolume\":{authorization}}}\n");
            let mut install = Installation::acquire(&directory, &host).unwrap();
            assert_eq!(install.identity(), format!("{identity}\n").as_bytes());
            assert_eq!(
                fs::read(root.path().join("identity.json")).unwrap(),
                install.identity()
            );
            install.begin_format().unwrap();
            assert_eq!(
                fs::read(root.path().join("format-intent.json")).unwrap(),
                intent.as_bytes()
            );
        }
    }

    #[test]
    fn native_disk_selection_requires_exact_serial_whole_disk_and_namespace_mounts() {
        use zdn::host::volume::evidence::attached_device;
        let host = spec();
        let selected = |value: &serde_json::Value, producer| {
            attached_device(&host, &serde_json::to_vec(value).unwrap(), producer)
        };
        let disk = json!({"path":"/dev/nvme12n3", "type":"disk",
            "serial":" vol-0123456789abcdef0 ", "fstype":"ext4",
            "mountpoints":[null, "", "/var/lib/zdn"]});
        let inventory = |disk: serde_json::Value| json!({"blockdevices":[disk]});
        assert_eq!(
            selected(&inventory(disk.clone()), false).unwrap(),
            std::path::Path::new("/dev/nvme12n3")
        );
        let nested = inventory(
            json!({"path":"/dev/nvme0n1", "serial":"unrelated", "type":"disk", "children":[disk.clone()]}),
        );
        assert!(selected(&nested, false).is_ok());
        let duplicate = json!({"blockdevices":[disk.clone(), nested["blockdevices"][0].clone()]});
        assert!(selected(&duplicate, false).is_err());
        assert!(selected(&json!({"blockdevices":[]}), false).is_err());
        for (field, value) in [
            ("serial", json!("vol0123456789abcdef1")),
            ("type", json!("part")),
            ("children", json!([{"path":"/dev/nvme12n3p1"}])),
            ("mountpoints", json!(["/"])),
            ("mountpoints", json!(null)),
            ("path", json!("/dev/sdf")),
            ("path", json!("/dev/nvme12n3p1")),
            ("path", json!("/dev/nvmen3")),
            ("path", json!("/dev/nvme12n")),
            ("path", json!("/dev/nvme12n3/extra")),
        ] {
            let mut changed = disk.clone();
            changed[field] = value;
            assert!(selected(&inventory(changed), false).is_err(), "{field}");
        }
        let producer = format!("{}/producer", host.node_root());
        let mut bound = disk.clone();
        bound["mountpoints"] = json!(["/var/lib/zdn", producer]);
        assert!(selected(&inventory(bound.clone()), false).is_err());
        assert!(selected(&inventory(bound.clone()), true).is_ok());
        for target in [
            format!("{producer}/extra"),
            format!("{}/rpc", host.node_root()),
            "/elsewhere".into(),
        ] {
            bound["mountpoints"] = json!(["/var/lib/zdn", producer, target]);
            assert!(selected(&inventory(bound.clone()), true).is_err());
        }
        // Neither device selection nor a filesystem label establishes blankness.
        let mut xfs = disk;
        xfs["fstype"] = json!("xfs");
        assert!(selected(&inventory(xfs), false).is_ok());
        let mut oversized = serde_json::to_vec(&nested).unwrap();
        oversized.resize(16 * 1024 * 1024, b' ');
        assert!(attached_device(&host, &oversized, false).is_ok());
        oversized.push(b' ');
        assert!(attached_device(&host, &oversized, false).is_err());
        let error = attached_device(&host, br#"{"blockdevices":"SECRET"}"#, false).unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET"));
    }

    #[test]
    fn native_mount_checks_bind_root_aliases_and_exact_producer_namespace() {
        use zdn::host::volume::evidence::{chain_mounted, verify_producer_mount};
        let (root, _, host) = fixture(false);
        let device = root.path().join("disk");
        fs::write(&device, b"synthetic source, not a real block device").unwrap();
        let device = device.canonicalize().unwrap();
        let alias = root.path().join("source-alias");
        symlink(&device, &alias).unwrap();
        let other = root.path().join("other-disk");
        fs::write(&other, b"foreign").unwrap();
        let encode = |mount: &serde_json::Value| {
            serde_json::to_vec(&json!({"filesystems":[mount]})).unwrap()
        };
        let chain = json!({"source":alias, "target":"/var/lib/zdn", "fstype":"ext4"});
        assert!(chain_mounted(&encode(&chain), &device).unwrap());
        let mut changed = chain.clone();
        changed["target"] = json!("/");
        // findmnt can report the covering parent; it is not the chain mount.
        assert!(!chain_mounted(&encode(&changed), &device).unwrap());
        for (field, value) in [
            ("source", json!(other)),
            ("source", json!(root.path().join("missing"))),
            ("fstype", json!("xfs")),
            ("target", json!(null)),
        ] {
            changed = chain.clone();
            changed[field] = value;
            assert!(
                chain_mounted(&encode(&changed), &device).is_err(),
                "{field}"
            );
        }
        let target = format!("{}/producer", host.node_root());
        let fsroot = format!(
            "/deployments/{}/nodes/{}/chains/{}/producer",
            host.deployment_id, host.node_id, host.consensus_fingerprint
        );
        let producer = json!({"source":format!("{}[{fsroot}]", device.display()), "target":target,
            "fstype":"ext4", "fsroot":fsroot, "options":"relatime,rw,noexec,nosuid,nodev,seclabel"});
        verify_producer_mount(&host, &encode(&producer), &device).unwrap();
        for (field, value) in [
            ("source", json!(format!("{}[{fsroot}]", other.display()))),
            ("source", json!(format!("{}[/other]", device.display()))),
            ("target", json!("/var/lib/zdn")),
            ("fsroot", json!("/other")),
            ("fstype", json!("xfs")),
            ("options", json!(null)),
        ] {
            changed = producer.clone();
            changed[field] = value;
            assert!(
                verify_producer_mount(&host, &encode(&changed), &device).is_err(),
                "{field}"
            );
        }
        for options in [
            "ro,nosuid,nodev,noexec",
            "rw,nosuid,nodev",
            "rw,nosuid,noexec",
            "rw,nodev,noexec",
            "rw,ro,nosuid,nodev,noexec",
        ] {
            changed = producer.clone();
            changed["options"] = json!(options);
            assert!(
                verify_producer_mount(&host, &encode(&changed), &device).is_err(),
                "{options}"
            );
        }
        let mut bounded = encode(&chain);
        bounded.resize(16 * 1024 * 1024, b' ');
        assert!(chain_mounted(&bounded, &device).unwrap());
        bounded.push(b' ');
        assert!(chain_mounted(&bounded, &device).is_err());
        assert!(verify_producer_mount(&host, &bounded, &device).is_err());
        for mounts in [json!([]), json!([chain.clone(), chain])] {
            let raw = serde_json::to_vec(&json!({"filesystems":mounts})).unwrap();
            assert!(chain_mounted(&raw, &device).is_err());
            assert!(verify_producer_mount(&host, &raw, &device).is_err());
        }
        let invalid = br#"{"filesystems":[{"source":123,"target":"SECRET"}]}"#;
        let error = chain_mounted(invalid, &device).unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET"));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn native_kernel_counter_guard_accepts_reads_but_rejects_every_mutating_counter() {
        use zdn::host::volume::evidence::require_unused_counters;
        // Asymmetric nonzero read/time/flush diagnostics are legal. The exact
        // seven write/discard/in-flight fields, not "all counters", must be zero.
        let fields = [29, 3, 160, 5, 0, 0, 0, 7, 0, 11, 13, 0, 0, 0, 17, 19, 23];
        let encode = |values: &[u64]| {
            values
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" ")
                .into_bytes()
        };
        let raw = encode(&fields);
        require_unused_counters(&raw).unwrap();
        require_unused_counters(&encode(&fields[..15])).unwrap();
        assert!(require_unused_counters(&encode(&fields[..14])).is_err());
        for index in [4, 5, 6, 8, 11, 12, 13] {
            let mut changed = fields;
            changed[index] = 1;
            assert!(
                require_unused_counters(&encode(&changed)).is_err(),
                "{index}"
            );
        }
        let mut boundary = raw.clone();
        boundary.resize(4096, b' ');
        require_unused_counters(&boundary).unwrap();
        boundary.push(b' ');
        assert!(require_unused_counters(&boundary).is_err());
        for token in ["-0", "+0", "0.0", "18446744073709551616", "０", "SECRET"] {
            let mut changed = format!("{token} ").into_bytes();
            // Replace only the read count: shifting all fields would let a
            // broken lexer fail for unrelated nonzero write counters instead.
            changed.extend_from_slice(&raw[raw.iter().position(|b| *b == b' ').unwrap() + 1..]);
            let error = require_unused_counters(&changed).unwrap_err();
            assert!(!format!("{error:#}").contains("SECRET"));
        }
        let mut maximum = fields;
        maximum[0] = u64::MAX;
        require_unused_counters(&encode(&maximum)).unwrap();
    }

    #[test]
    fn zero_content_evidence_requires_exact_length_every_chunk_and_read_boundaries() {
        use std::io::{self, Cursor, Read};
        use std::sync::atomic::Ordering;
        use zdn::host::volume::evidence::require_zero_contents;

        struct Reader<F>(F);
        impl<F: FnMut(&mut [u8]) -> io::Result<usize>> Read for Reader<F> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                (self.0)(buffer)
            }
        }
        let cancelled = AtomicBool::new(false);
        let scan = |reader: &mut dyn Read, size| {
            require_zero_contents(
                &mut &mut *reader,
                size,
                Instant::now() + Duration::from_secs(10),
                &cancelled,
            )
        };
        let size = 8 * 1024 * 1024 + 17;
        let zeros = vec![0; size];
        scan(&mut Cursor::new(&zeros), size as u64).unwrap();
        for changed in [0, 8 * 1024 * 1024, size - 1] {
            let mut bytes = zeros.clone();
            bytes[changed] = 91;
            assert!(scan(&mut Cursor::new(bytes), size as u64).is_err());
        }
        assert!(scan(&mut Cursor::new(&zeros), size as u64 - 1).is_err());
        assert!(scan(&mut Cursor::new(&zeros), size as u64 + 1).is_err());
        assert!(scan(&mut io::empty(), u64::MAX).is_err());
        let mut source = Cursor::new([0; 31]);
        let mut interrupted = false;
        let mut short = Reader(|buffer: &mut [u8]| {
            if !interrupted {
                interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = buffer.len().min(13);
            source.read(&mut buffer[..count])
        });
        scan(&mut short, 31).unwrap();
        let mut broken = Reader(|_: &mut [u8]| Err(io::Error::other("PRIVATE RAW DATA")));
        let error = scan(&mut broken, 1).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE RAW DATA"));
        let mut stop_at_eof = Reader(|_: &mut [u8]| {
            cancelled.store(true, Ordering::SeqCst);
            Ok(0)
        });
        let error = scan(&mut stop_at_eof, 0).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        cancelled.store(false, Ordering::SeqCst);
        let mut late_eof = Reader(|_: &mut [u8]| {
            std::thread::sleep(Duration::from_millis(100));
            Ok(0)
        });
        let error = require_zero_contents(
            &mut late_eof,
            0,
            Instant::now() + Duration::from_millis(50),
            &cancelled,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn opened_device_evidence_rejects_files_links_fifos_and_character_devices() {
        use zdn::host::volume::device::BlockDevice;
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("disk");
        fs::write(&file, b"PRIVATE RAW DATA").unwrap();
        symlink(&file, root.path().join("alias")).unwrap();
        symlink("missing", root.path().join("dangling")).unwrap();
        nix::unistd::mkfifo(&root.path().join("fifo"), nix::sys::stat::Mode::S_IRUSR).unwrap();
        for path in [
            file,
            root.path().join("alias"),
            root.path().join("dangling"),
            root.path().join("fifo"),
            root.path().into(),
            PathBuf::from("/dev/null"),
            PathBuf::from("relative-device"),
        ] {
            let error = BlockDevice::open(&path).err().expect("not a block device");
            assert!(!format!("{error:#}").contains("PRIVATE RAW DATA"));
        }
        assert_eq!(
            fs::read(root.path().join("disk")).unwrap(),
            b"PRIVATE RAW DATA"
        );
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn interrupted_format_intent_is_durable_but_never_authorizes_reformatting() {
        for authorized in [false, true] {
            let (root, directory, host) = fixture(authorized);
            let mut install = Installation::acquire(&directory, &host).unwrap();
            assert!(!root.path().join("format-intent.json").exists());
            assert!(install.verify_format_intent().is_err());
            install.begin_format().unwrap();
            install.verify_format_intent().unwrap();
            let original = fs::read(root.path().join("format-intent.json")).unwrap();
            assert!(install.begin_format().is_err());
            let identity_inode = fs::metadata(root.path().join("identity.json"))
                .unwrap()
                .ino();
            drop(install); // Simulated interruption after the durable intent.
            let mut resumed = Installation::acquire(&directory, &host).unwrap();
            resumed.verify_format_intent().unwrap();
            assert!(resumed.begin_format().is_err());
            assert_eq!(
                fs::read(root.path().join("format-intent.json")).unwrap(),
                original
            );
            assert_eq!(
                fs::metadata(root.path().join("identity.json"))
                    .unwrap()
                    .ino(),
                identity_inode
            );
            assert!(!root.path().join("volume-claimed.json").exists());
            // JSON equivalence is insufficient for a saved exact-byte intent.
            let mut changed = original.clone();
            changed.insert(0, b' ');
            fs::write(root.path().join("format-intent.json"), changed).unwrap();
            assert!(resumed.verify_format_intent().is_err());
        }
    }

    #[test]
    fn claims_require_exact_on_volume_evidence_and_preserve_foreign_state() {
        let (root, directory, host) = fixture(true);
        let mount = directory.ensure_directory("volume", 0o700).unwrap();
        let mut install = Installation::acquire(&directory, &host).unwrap();
        assert!(Installation::acquire(&directory, &host).is_err());
        assert!(install.record_volume_claim(&mount).is_err());
        assert!(!root.path().join("volume-claimed.json").exists());
        mount
            .publish(".zdn-volume.json", b"foreign identity\n", 0o600)
            .unwrap();
        assert!(install.record_volume_claim(&mount).is_err());
        assert!(!root.path().join("volume-claimed.json").exists());
        fs::remove_file(root.path().join("volume/.zdn-volume.json")).unwrap();
        mount
            .publish(".zdn-volume.json", install.identity(), 0o600)
            .unwrap();
        directory
            .publish("volume-claimed.json", b"foreign identity\n", 0o600)
            .unwrap();
        assert!(install.record_volume_claim(&mount).is_err());
        assert_eq!(
            fs::read(root.path().join("volume-claimed.json")).unwrap(),
            b"foreign identity\n"
        );
        fs::remove_file(root.path().join("volume-claimed.json")).unwrap();
        install.record_volume_claim(&mount).unwrap();
        install.record_volume_claim(&mount).unwrap();
        assert_eq!(
            fs::read(root.path().join("volume-claimed.json")).unwrap(),
            install.identity()
        );
        // A claimed filesystem cannot be formatted even without a format intent.
        assert!(install.begin_format().is_err());
        assert!(!root.path().join("format-intent.json").exists());
        drop(install);
        let mut other = host.clone();
        other.volume_id = "vol-0123456789abcdef1".into();
        other.new_volume.as_mut().unwrap().volume_id = other.volume_id.clone();
        assert!(Installation::acquire(&directory, &other).is_err());
        let retry = Installation::acquire(&directory, &host).unwrap();
        retry.record_volume_claim(&mount).unwrap(); // Failed acquisition releases lock.
    }

    #[test]
    fn mounted_claims_resume_first_install_but_never_adopt_on_restart() {
        for authorized in [false, true] {
            for with_lost_found in [false, true] {
                let (root, directory, host) = fixture(authorized);
                let mounted = directory.ensure_directory("volume", 0o700).unwrap();
                if with_lost_found {
                    mounted.ensure_directory("lost+found", 0o700).unwrap();
                }
                let mut install = Installation::acquire(&directory, &host).unwrap();
                assert!(install.claim_mounted(&mounted, false).is_err());
                assert!(!root.path().join("volume/.zdn-volume.json").exists());
                assert!(!root.path().join("volume-claimed.json").exists());
                if authorized {
                    assert!(install.claim_mounted(&mounted, true).is_err());
                    assert!(!root.path().join("volume/.zdn-volume.json").exists());
                    install.begin_format().unwrap();
                }
                drop(install); // Resume after durable intent, before claim.
                let install = Installation::acquire(&directory, &host).unwrap();
                // A renamed pathname must not redirect inspection/publication.
                fs::rename(root.path().join("volume"), root.path().join("retained")).unwrap();
                fs::create_dir(root.path().join("volume")).unwrap();
                fs::write(root.path().join("volume/foreign"), b"preserve me").unwrap();
                install.claim_mounted(&mounted, true).unwrap();
                let claim = root.path().join("retained/.zdn-volume.json");
                assert_eq!(fs::read(&claim).unwrap(), install.identity());
                assert_eq!(fs::metadata(&claim).unwrap().mode() & 0o777, 0o600);
                assert_eq!(
                    fs::read(root.path().join("volume-claimed.json")).unwrap(),
                    install.identity()
                );
                let inode = fs::metadata(&claim).unwrap().ino();
                fs::write(
                    root.path().join("retained/chain-data"),
                    b"existing database",
                )
                .unwrap();
                install.claim_mounted(&mounted, false).unwrap();
                assert_eq!(fs::metadata(&claim).unwrap().ino(), inode);
                assert_eq!(
                    fs::read(root.path().join("volume/foreign")).unwrap(),
                    b"preserve me"
                );
                assert!(!root.path().join("volume/.zdn-volume.json").exists());
                assert_eq!(root.path().join("format-intent.json").exists(), authorized);
            }
        }
    }

    #[test]
    fn mounted_claims_preserve_foreign_data_unsafe_entries_and_changed_intents() {
        for case in [
            "data",
            "lost-found-data",
            "lost-found-file",
            "lost-found-link",
            "lost-found-writable",
            "claim-link",
            "claim-fifo",
            "foreign-claim",
            "changed-identity",
            "changed-intent",
        ] {
            let (root, directory, host) = fixture(true);
            let mounted = directory.ensure_directory("volume", 0o700).unwrap();
            let mut install = Installation::acquire(&directory, &host).unwrap();
            install.begin_format().unwrap();
            let volume = root.path().join("volume");
            match case {
                "data" => fs::write(volume.join("private-data"), b"preserve me").unwrap(),
                "lost-found-data" => {
                    fs::create_dir(volume.join("lost+found")).unwrap();
                    fs::write(volume.join("lost+found/recovered"), b"preserve me").unwrap();
                }
                "lost-found-file" => fs::write(volume.join("lost+found"), b"").unwrap(),
                "lost-found-link" => {
                    fs::create_dir(root.path().join("empty")).unwrap();
                    symlink(root.path().join("empty"), volume.join("lost+found")).unwrap();
                }
                "lost-found-writable" => {
                    fs::create_dir(volume.join("lost+found")).unwrap();
                    fs::set_permissions(
                        volume.join("lost+found"),
                        fs::Permissions::from_mode(0o777),
                    )
                    .unwrap();
                }
                "claim-link" => symlink("missing", volume.join(".zdn-volume.json")).unwrap(),
                "claim-fifo" => nix::unistd::mkfifo(
                    &volume.join(".zdn-volume.json"),
                    nix::sys::stat::Mode::S_IRUSR,
                )
                .unwrap(),
                "foreign-claim" => fs::write(volume.join(".zdn-volume.json"), b"foreign").unwrap(),
                "changed-identity" => {
                    fs::write(root.path().join("identity.json"), b"foreign").unwrap()
                }
                "changed-intent" => {
                    fs::write(root.path().join("format-intent.json"), b"foreign").unwrap()
                }
                _ => unreachable!(),
            }
            let before = fs::read_dir(&volume).unwrap().count();
            assert!(install.claim_mounted(&mounted, true).is_err(), "{case}");
            assert!(!root.path().join("volume-claimed.json").exists(), "{case}");
            assert_eq!(fs::read_dir(&volume).unwrap().count(), before, "{case}");
            match case {
                "data" => assert_eq!(
                    fs::read(volume.join("private-data")).unwrap(),
                    b"preserve me"
                ),
                "lost-found-data" => assert_eq!(
                    fs::read(volume.join("lost+found/recovered")).unwrap(),
                    b"preserve me"
                ),
                "foreign-claim" => assert_eq!(
                    fs::read(volume.join(".zdn-volume.json")).unwrap(),
                    b"foreign"
                ),
                _ => {}
            }
        }
    }

    #[test]
    fn unsafe_records_and_invalid_specs_fail_before_authorizing_progress() {
        let (root, directory, mut host) = fixture(false);
        host.role = "invalid".into();
        assert!(Installation::acquire(&directory, &host).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        for record in ["format-intent.json", "volume-claimed.json"] {
            let (root, directory, host) = fixture(false);
            let mut install = Installation::acquire(&directory, &host).unwrap();
            symlink("missing", root.path().join(record)).unwrap();
            assert!(install.begin_format().is_err());
            assert!(!root.path().join("missing").exists());
        }
        let (root, directory, host) = fixture(false);
        let install = Installation::acquire(&directory, &host).unwrap();
        let identity = install.identity().to_vec();
        drop(install);
        fs::set_permissions(
            root.path().join("identity.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Installation::acquire(&directory, &host).is_err());
        assert_eq!(
            fs::read(root.path().join("identity.json")).unwrap(),
            identity
        );
        assert_eq!(
            fs::metadata(root.path().join("identity.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
    }
}

#[cfg(target_os = "linux")]
mod native_container {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::{
        host::{command::Executor, container},
        infra::HostObservation,
    };

    struct Fixture {
        _root: tempfile::TempDir,
        spec: HostInstallSpec,
        resources: HostObservation,
        docker: PathBuf,
        state: PathBuf,
        executor: Executor,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let commands = root.path().join("commands");
            fs::create_dir(&commands).unwrap();
            fs::set_permissions(&commands, fs::Permissions::from_mode(0o700)).unwrap();
            let spec = spec();
            let node = spec.node_root();
            let name = format!("zdn-{}-{}", spec.deployment_id, spec.node_id);
            let mut mounts =
                vec![json!({"Type":"bind","Source":node,"Destination":node,"RW":false})];
            for child in ["state", "identity", "rpc"] {
                let path = format!("{node}/{child}");
                mounts.push(json!({"Type":"bind","Source":path,"Destination":path,"RW":true}));
            }
            mounts.push(json!({"Type":"tmpfs","Destination":"/tmp","RW":true}));
            let state = root.path().join("docker-state.json");
            fs::write(&state, serde_json::to_vec(&json!({"exists":true,"id":"abc012def3456789",
                "name":name,"record":{"Name":format!("/{name}"),"State":{"Running":true},
                "Config":{"Image":spec.image,"Labels":{"zdn.install":spec.install_sha256().unwrap()},
                    "User":"10001:10001","WorkingDir":"/","Entrypoint":["/usr/bin/env"],
                    "Cmd":["-i","PATH=/usr/local/bin:/usr/bin:/bin","HOME=/nonexistent",
                        "/usr/local/bin/zakurad","--config",format!("{node}/zakura.toml"),"start"],
                    "StopSignal":"SIGINT","Healthcheck":{"Test":["NONE"]}},
                "HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,
                    "CapAdd":null,"CapDrop":["ALL"],"PidsLimit":1024,"PidMode":"",
                    "LogConfig":{"Type":"journald"},"SecurityOpt":["no-new-privileges:true"],
                    "Memory":8589934592u64,"MemorySwap":8589934592u64,"NanoCpus":3375000000u64},
                "Mounts":mounts}})).unwrap()).unwrap();
            let docker = root.path().join("docker");
            native_tool::install(
                &docker,
                "native_container::docker_worker",
                &json!({"state":state}),
            );
            let executor = Executor::new(
                env!("CARGO_BIN_EXE_zdn").into(),
                commands,
                spec.helper.region.clone(),
                Instant::now() + Duration::from_secs(120),
            )
            .unwrap();
            Self {
                _root: root,
                spec,
                resources: HostObservation {
                    mem_total_bytes: 64 << 30,
                    ancestor_memory_limits_bytes: vec![12 << 30, 17 << 30],
                    online_cpu_count: 1,
                    affinity_cpu_count: 8,
                    ancestor_cpu_quota_millis: vec![3625, 7500],
                },
                docker,
                state,
                executor,
            }
        }
        fn read(&self) -> serde_json::Value {
            serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap()
        }
        fn save(&self, state: &serde_json::Value) {
            fs::write(&self.state, serde_json::to_vec(state).unwrap()).unwrap();
        }
        fn observe(&mut self) -> eyre::Result<container::EffectiveLimits> {
            container::running_limits(
                &self.spec,
                &self.spec.image,
                &self.resources,
                &self.docker,
                &mut self.executor,
                &AtomicBool::new(false),
            )
        }
        fn cleanup(&mut self) -> eyre::Result<()> {
            container::cleanup(
                &self.spec,
                &self.spec.image,
                &self.docker,
                &mut self.executor,
                &AtomicBool::new(false),
            )
        }
    }

    #[test]
    fn docker_worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let path = PathBuf::from(payload["state"].as_str().unwrap());
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let id = state["id"].as_str().unwrap().to_owned();
        let name = state["name"].as_str().unwrap().to_owned();
        let filter = format!("name=^/{name}$");
        let mut output = Vec::new();
        let mut code = 0;
        let argv: Vec<_> = args.iter().map(String::as_str).collect();
        match argv.as_slice() {
            ["container", "ls", "--all", "--filter", found, "--format", "{{.ID}}"]
                if *found == filter =>
            {
                if state["exists"] == true {
                    output = state
                        .get("listing")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&id)
                        .as_bytes()
                        .to_vec();
                }
            }
            ["container", "inspect", target] if *target == id || *target == name => {
                output = state
                    .get("raw")
                    .and_then(|v| v.as_str())
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_else(|| serde_json::to_vec(&json!([state["record"]])).unwrap());
            }
            ["stop", "--time", "60", target] if *target == id => {
                if state["stopFail"] == true {
                    code = 1;
                } else {
                    state["record"]["State"]["Running"] = json!(false);
                    if state["autoRemove"] == true {
                        state["exists"] = json!(false);
                    }
                }
            }
            ["container", "rm", "--force", target] if *target == id => {
                if state["exists"] == false {
                    code = 1;
                }
                if state["keepOnRemove"] != true {
                    state["exists"] = json!(false);
                }
            }
            _ => code = 99,
        }
        fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
        native_tool::reply(&work, &output, b"PRIVATE DOCKER DIAGNOSTICS", code);
    }

    #[test]
    fn node_limits_and_launch_arguments_preserve_reserved_budgets_and_isolation() {
        let mut f = Fixture::new();
        let limits = container::effective_limits(&f.spec, &f.resources).unwrap();
        assert_eq!(
            serde_json::to_value(&limits).unwrap(),
            json!({"effectiveMemoryBytes":12884901888u64,
            "visibleCpuMillis":3625,"hostReserveBytes":4294967296u64,"hostReserveCpuMillis":250,
            "nodeMemoryBytes":8589934592u64,"nodeCpuMillis":3375})
        );
        assert_eq!(f.observe().unwrap(), limits);
        let args = container::arguments(&f.spec, &f.spec.image, &f.resources).unwrap();
        for pair in [
            ["--network", "host"],
            ["--user", "10001:10001"],
            ["--workdir", "/"],
            ["--cap-drop", "ALL"],
            ["--security-opt", "no-new-privileges:true"],
            ["--stop-signal", "SIGINT"],
            ["--stop-timeout", "60"],
            ["--pids-limit", "1024"],
            ["--memory", "8589934592"],
            ["--memory-swap", "8589934592"],
            ["--cpus", "3.375"],
            ["--log-driver", "journald"],
            ["--entrypoint", "/usr/bin/env"],
        ] {
            assert!(args.windows(2).any(|window| window == pair));
        }
        for flag in ["--rm", "--read-only", "--no-healthcheck"] {
            assert!(args.iter().any(|arg| arg == flag));
        }
        assert_eq!(args.iter().filter(|arg| *arg == "--mount").count(), 4);
        let image = args.iter().position(|arg| arg == &f.spec.image).unwrap();
        assert_eq!(
            args[image + 1..],
            [
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "HOME=/nonexistent",
                "/usr/local/bin/zakurad",
                "--config",
                &format!("{}/zakura.toml", f.spec.node_root()),
                "start"
            ]
        );
        f.resources.ancestor_memory_limits_bytes = vec![5 << 30];
        f.resources.ancestor_cpu_quota_millis = vec![500];
        let minimum = container::effective_limits(&f.spec, &f.resources).unwrap();
        assert_eq!(minimum.node_memory_bytes, 1 << 30);
        assert_eq!(minimum.node_cpu_millis, 250);
        f.resources.ancestor_cpu_quota_millis = vec![499];
        assert!(container::effective_limits(&f.spec, &f.resources).is_err());
        f.resources.ancestor_cpu_quota_millis = vec![500];
        f.resources.ancestor_memory_limits_bytes = vec![(5 << 30) - 1];
        assert!(container::effective_limits(&f.spec, &f.resources).is_err());
    }

    #[test]
    fn selected_image_preserves_original_ownership_for_launch_observation_and_cleanup() {
        let mut f = Fixture::new();
        let original = f.spec.install_sha256().unwrap();
        let selected = format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/zakura@sha256:{}",
            "7".repeat(64)
        );
        assert_ne!(selected, f.spec.image);
        let args = container::arguments(&f.spec, &selected, &f.resources).unwrap();
        assert!(args.iter().any(|arg| arg == &selected));
        assert!(!args.iter().any(|arg| arg == &f.spec.image));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--label", &format!("zdn.install={original}")]));
        let mut state = f.read();
        state["record"]["Config"]["Image"] = json!(selected);
        f.save(&state);
        assert!(f.observe().is_err());
        container::running_limits(
            &f.spec,
            &selected,
            &f.resources,
            &f.docker,
            &mut f.executor,
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut fictitious = f.spec.clone();
        fictitious.image = selected.clone();
        let rekeyed = fictitious.install_sha256().unwrap();
        assert_ne!(original, rekeyed);
        state["record"]["Config"]["Labels"]["zdn.install"] = json!(rekeyed);
        f.save(&state);
        assert!(container::running_limits(
            &f.spec,
            &selected,
            &f.resources,
            &f.docker,
            &mut f.executor,
            &AtomicBool::new(false),
        )
        .is_err());
        assert!(container::cleanup(
            &f.spec,
            &selected,
            &f.docker,
            &mut f.executor,
            &AtomicBool::new(false),
        )
        .is_err());
        assert_eq!(f.read(), state);
        state["record"]["Config"]["Labels"]["zdn.install"] = json!(original);
        f.save(&state);
        container::cleanup(
            &f.spec,
            &selected,
            &f.docker,
            &mut f.executor,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(f.read()["exists"], false);
        assert_eq!(f.spec.install_sha256().unwrap(), original);
        for invalid in ["unpinned", &selected.replace("us-east-1", "us-west-2")] {
            assert!(container::arguments(&f.spec, invalid, &f.resources).is_err());
        }
    }

    #[test]
    fn running_observer_rejects_substituted_settings_and_duplicate_or_foreign_mounts() {
        let mut f = Fixture::new();
        let good = f.read();
        for (path, changed) in [
            ("/record/State/Running", json!(false)),
            ("/record/Config/Image", json!("foreign")),
            ("/record/Config/User", json!("0:0")),
            ("/record/Config/Labels/zdn.install", json!("foreign")),
            ("/record/Config/Cmd/0", json!("SECRET")),
            ("/record/HostConfig/Privileged", json!(true)),
            ("/record/HostConfig/ReadonlyRootfs", json!(false)),
            ("/record/HostConfig/MemorySwap", json!(-1)),
            ("/record/HostConfig/NanoCpus", json!(3376000000u64)),
            ("/record/HostConfig/CapAdd", json!(["SYS_ADMIN"])),
            ("/record/HostConfig/CapDrop", json!([])),
            ("/record/HostConfig/PidMode", json!("host")),
            (
                "/record/HostConfig/SecurityOpt",
                json!(["no-new-privileges:true", "seccomp=unconfined"]),
            ),
            ("/record/Mounts/1/Source", json!("/var/run/docker.sock")),
            ("/record/Mounts/0/RW", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = changed;
            f.save(&bad);
            let error = f.observe().unwrap_err();
            assert!(!format!("{error:#}").contains("SECRET"));
            assert_eq!(f.read(), bad);
        }
        let mut duplicate = good.clone();
        duplicate["record"]["Mounts"][1] = duplicate["record"]["Mounts"][2].clone();
        f.save(&duplicate);
        assert!(f.observe().is_err());
        f.save(&good);
        assert!(f.observe().is_ok());
    }

    #[test]
    fn cleanup_removes_only_verified_ids_and_requires_confirmed_absence() {
        let mut f = Fixture::new();
        let good = f.read();
        f.cleanup().unwrap();
        assert_eq!(f.read()["exists"], false);
        f.cleanup().unwrap();
        let mut auto = good.clone();
        auto["autoRemove"] = json!(true);
        f.save(&auto);
        f.cleanup().unwrap();
        assert_eq!(f.read()["exists"], false);
        for (path, value) in [
            ("/record/Config/Image", json!("foreign")),
            ("/record/Config/Labels/zdn.install", json!("foreign")),
            ("/record/Name", json!("/foreign")),
            ("/record/State/Running", json!(null)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = value;
            f.save(&bad);
            assert!(f.cleanup().is_err());
            assert_eq!(f.read(), bad);
        }
        for (key, value) in [
            ("stopFail", json!(true)),
            ("keepOnRemove", json!(true)),
            ("listing", json!("abc012def3456789\n0123456789ab")),
            ("raw", json!("SECRET")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            f.save(&bad);
            let error = f.cleanup().unwrap_err();
            assert!(!format!("{error:#}").contains("SECRET"));
            assert_eq!(f.read()["exists"], true);
        }
    }
}

#[cfg(target_os = "linux")]
mod native_firewall {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::host::{command::Executor, firewall::ensure_rules};

    struct Fixture {
        _root: tempfile::TempDir,
        executor: Executor,
        v4: PathBuf,
        v6: PathBuf,
        state: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let commands = root.path().join("commands");
            fs::create_dir(&commands).unwrap();
            fs::set_permissions(&commands, fs::Permissions::from_mode(0o700)).unwrap();
            let state = root.path().join("rules.json");
            fs::write(&state, b"{\"v4\":false,\"v6\":false,\"insertions\":0}").unwrap();
            let v4 = root.path().join("iptables");
            let v6 = root.path().join("ip6tables");
            for (path, family) in [(&v4, "v4"), (&v6, "v6")] {
                native_tool::install(
                    path,
                    "native_firewall::worker",
                    &json!({"state":state,"family":family}),
                );
            }
            let executor = Executor::new(
                env!("CARGO_BIN_EXE_zdn").into(),
                commands,
                "us-east-1".into(),
                Instant::now() + Duration::from_secs(120),
            )
            .unwrap();
            Self {
                _root: root,
                executor,
                v4,
                v6,
                state,
            }
        }
        fn read(&self) -> serde_json::Value {
            serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap()
        }
        fn save(&self, state: &serde_json::Value) {
            fs::write(&self.state, serde_json::to_vec(state).unwrap()).unwrap();
        }
        fn run(&mut self, install: bool) -> eyre::Result<()> {
            ensure_rules(
                &self.v4,
                &self.v6,
                install,
                &mut self.executor,
                &AtomicBool::new(false),
            )
        }
    }

    #[test]
    fn worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let path = PathBuf::from(payload["state"].as_str().unwrap());
        let family = payload["family"].as_str().unwrap();
        let address = if family == "v4" {
            "169.254.169.254/32"
        } else {
            "fd00:ec2::254/128"
        };
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let tail = [
            "-m",
            "owner",
            "--uid-owner",
            "10001",
            "-d",
            address,
            "-j",
            "REJECT",
        ];
        let mut check = vec!["--wait", "5", "--check", "OUTPUT"];
        check.extend(tail);
        let mut insert = vec!["--wait", "5", "--insert", "OUTPUT", "1"];
        insert.extend(tail);
        let mut code = 0;
        if args == check {
            if state["checkFailure"] == family {
                code = 2;
            } else if state[family] != true {
                code = 1;
            }
        } else if args == insert {
            if state["insertFailure"] == family {
                code = 1;
            } else {
                state["insertions"] = json!(state["insertions"].as_u64().unwrap() + 1);
                if state["noEffect"] != family {
                    state[family] = json!(true);
                }
            }
        } else {
            code = 99;
        }
        fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
        native_tool::reply(
            &work,
            b"PRIVATE FIREWALL OUTPUT",
            b"PRIVATE FIREWALL DIAGNOSTICS",
            code,
        );
    }

    #[test]
    fn observations_do_not_repair_and_installation_preserves_existing_protections() {
        for (v4, v6) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut f = Fixture::new();
            f.save(&json!({"v4":v4,"v6":v6,"insertions":0}));
            let before = f.read();
            assert_eq!(f.run(false).is_ok(), v4 && v6);
            assert_eq!(f.read(), before);
            f.run(true).unwrap();
            assert_eq!(
                f.read(),
                json!({"v4":true,"v6":true,"insertions":u8::from(!v4)+u8::from(!v6)})
            );
            let installed = f.read();
            f.run(false).unwrap();
            f.run(true).unwrap();
            assert_eq!(f.read(), installed);
        }
    }

    #[test]
    fn failed_checks_insertions_and_rechecks_never_claim_protection() {
        for family in ["v4", "v6"] {
            for failure in ["checkFailure", "insertFailure", "noEffect"] {
                let mut f = Fixture::new();
                let mut state = f.read();
                state[failure] = json!(family);
                f.save(&state);
                let error = f.run(true).unwrap_err();
                assert!(!format!("{error:#}").contains("PRIVATE FIREWALL"));
                assert_eq!(f.read()[family], false);
                if family == "v6" {
                    assert_eq!(f.read()["v4"], true);
                }
            }
        }
        let mut f = Fixture::new();
        let before = f.read();
        assert!(ensure_rules(
            &f.v4,
            Path::new("ip6tables"),
            true,
            &mut f.executor,
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(f.read(), before);
        assert!(ensure_rules(&f.v4, &f.v6, true, &mut f.executor, &AtomicBool::new(true)).is_err());
        assert_eq!(f.read(), before);
    }
}

#[cfg(target_os = "linux")]
mod native_producer {
    use super::*;
    use fs2::FileExt;
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::{
        chain::producer::{ProducerIdentity, ProducerJournal, ProducerPhase},
        host::{command::Executor, files::Directory, producer},
    };

    #[test]
    fn tool_worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        assert_eq!(
            args,
            [
                "show",
                "zdn-producer.service",
                "--property=LoadState,ActiveState,SubState,MainPID"
            ]
        );
        native_tool::reply(
            &work,
            payload["stdout"].as_str().unwrap().as_bytes(),
            b"",
            payload["code"].as_u64().unwrap() as u8,
        );
    }

    struct Fixture {
        root: tempfile::TempDir,
        node: Directory,
        spec: HostInstallSpec,
        executor: Executor,
        systemctl: PathBuf,
        state: PathBuf,
        journal: ProducerJournal,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let node =
                Directory::open(root.path(), fs::metadata(root.path()).unwrap().uid()).unwrap();
            node.ensure_directory("commands", 0o700).unwrap();
            node.ensure_directory("producer", 0o700).unwrap();
            let mut spec = spec();
            spec.role = "producer".into();
            spec.block_interval_seconds = Some(37);
            // Retain valid producer runtime policy while changing only the observation contract.
            let manifest: ConsensusManifest =
                serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
            let mut options = RuntimeOptions::new(spec.deployment_id, "node-1");
            options.network.listen_addr = "10.90.1.10:18233".into();
            options.network.peers = vec!["10.90.1.11:18233".into()];
            options.role = zdn::chain::runtime_config::NodeRole::Producer;
            options.reward_address = Some("tm9iNYCVAhLLa4rJtfqqHauR5xL1REdpiDs".into());
            let runtime = render_runtime_config(&manifest, &options).unwrap();
            spec.config_toml = runtime.config_toml;
            spec.config_sha256 = runtime.config_sha256;
            spec.validate().unwrap();
            let executor = Executor::new(
                PathBuf::from(env!("CARGO_BIN_EXE_zdn")),
                root.path().join("commands"),
                "us-east-1".into(),
                Instant::now() + Duration::from_secs(120),
            )
            .unwrap();
            let journal = ProducerJournal {
                api_version: zdn::chain::producer::API_VERSION.into(),
                identity: ProducerIdentity {
                    deployment_id: spec.deployment_id,
                    node_id: spec.node_id.clone(),
                    consensus_fingerprint: spec.consensus_fingerprint.clone(),
                },
                owner_pid: std::process::id(),
                owner_session: Uuid::new_v4(),
                phase: ProducerPhase::Waiting,
                interval_secs: 37,
                last_confirmed_tip: None,
                pending: None,
                confirmed_blocks: 0,
            };
            let systemctl = root.path().join("systemctl");
            let state = root.path().join("producer");
            Self {
                root,
                node,
                spec,
                executor,
                systemctl,
                state,
                journal,
            }
        }
        fn tool(&self, active: &str, sub: &str, pid: u32) {
            self.raw_tool(
                &format!("LoadState=loaded\nActiveState={active}\nSubState={sub}\nMainPID={pid}\n"),
                0,
            );
        }
        fn raw_tool(&self, stdout: &str, code: u8) {
            native_tool::install(
                &self.systemctl,
                "native_producer::tool_worker",
                &json!({"stdout":stdout,"code":code}),
            );
        }
        fn save(&self) {
            let path = self.state.join("journal.json");
            fs::write(&path, serde_json::to_vec(&self.journal).unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn observe(&mut self, starting: bool) -> eyre::Result<producer::Observation> {
            producer::observe(
                &self.spec,
                &self.node,
                &self.state,
                &self.systemctl,
                &mut self.executor,
                &AtomicBool::new(false),
                starting,
            )
        }
        fn stopped(&mut self) -> eyre::Result<()> {
            producer::require_stopped(
                &self.spec,
                &self.systemctl,
                &mut self.executor,
                &AtomicBool::new(false),
            )
        }
    }

    #[test]
    fn ownership_cadence_and_starting_are_real_lock_observations() {
        let mut f = Fixture::new();
        f.tool("active", "running", f.journal.owner_pid);
        assert!(f.observe(false).is_err());
        f.node
            .publish(
                "producer-authorized.json",
                &producer::authorization(&f.spec).unwrap(),
                0o600,
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(f.observe(true).unwrap()).unwrap(),
            json!({"scheduledProducer":false,"producer":null})
        );
        assert!(f.observe(false).is_err());
        let lock = fs::File::create(f.state.join("controller.lock")).unwrap();
        fs::set_permissions(
            f.state.join("controller.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        lock.lock_exclusive().unwrap();
        f.save();
        let observed = f.observe(false).unwrap();
        assert!(observed.scheduled_producer);
        let report = observed.producer.unwrap();
        assert_eq!(report.journal.owner_pid, f.journal.owner_pid);
        assert_eq!(report.journal.interval_secs, 37);
        assert_eq!(report.payment_qualification, "pending");
        assert!(report.controller_locked && !report.launch_ready);
        f.journal.phase = ProducerPhase::Generating;
        f.save();
        assert!(f.observe(false).unwrap().scheduled_producer);
        f.tool("active", "running", f.journal.owner_pid + 19);
        assert!(f.observe(false).is_err());
        assert!(!f.observe(true).unwrap().scheduled_producer);
        f.journal.interval_secs = 41;
        f.save();
        assert!(f.observe(true).is_err());
        f.journal.interval_secs = 37;
        f.tool("active", "running", f.journal.owner_pid);
        f.journal.phase = ProducerPhase::Starting;
        f.save();
        assert!(!f.observe(true).unwrap().scheduled_producer);
        assert!(f.observe(false).is_err());
        f.journal.phase = ProducerPhase::Waiting;
        f.save();
        for phase in [ProducerPhase::Stalled, ProducerPhase::Stopped] {
            f.journal.phase = phase;
            f.save();
            assert!(f.observe(true).is_err());
        }
        f.journal.phase = ProducerPhase::Waiting;
        f.save();
        FileExt::unlock(&lock).unwrap();
        assert!(!f.observe(true).unwrap().scheduled_producer);
        assert!(f.observe(false).is_err());
        f.journal.identity.node_id = "node-2".into();
        f.save();
        assert!(f.observe(true).is_err());
        fs::write(f.state.join("journal.json"), b"{}").unwrap();
        assert!(f.observe(true).is_err());
    }

    #[test]
    fn followers_legacy_properties_authorization_and_stopped_gate() {
        let mut f = Fixture::new();
        assert!(!producer::authorized(&f.spec, &f.node).unwrap());
        let auth = producer::authorization(&f.spec).unwrap();
        let expected = format!("{{\"apiVersion\":\"zdn-producer-authorization/v1alpha1\",\"identity\":{{\"apiVersion\":\"zdn-host-volume/v1alpha1\",\"consensusFingerprint\":\"{}\",\"deploymentId\":\"{}\",\"installSha256\":\"{}\",\"nodeId\":\"node-1\",\"volumeId\":\"{}\"}},\"intervalSeconds\":37}}\n", f.spec.consensus_fingerprint, f.spec.deployment_id, f.spec.install_sha256().unwrap(), f.spec.volume_id);
        assert_eq!(auth, expected.as_bytes());
        f.node
            .publish("producer-authorized.json", &auth, 0o600)
            .unwrap();
        assert!(producer::authorized(&f.spec, &f.node).unwrap());
        f.spec.node_id = "node-2".into();
        assert!(producer::authorized(&f.spec, &f.node).is_err());
        f.spec.node_id = "node-1".into();
        for bytes in [b"{}".as_slice(), &auth[..auth.len() - 1], b"foreign\n"] {
            fs::write(f.root.path().join("producer-authorized.json"), bytes).unwrap();
            assert!(producer::authorized(&f.spec, &f.node).is_err());
        }
        f.spec = spec();
        f.spec.block_interval_seconds = Some(37);
        f.spec.validate().unwrap();
        f.tool("inactive", "dead", 0);
        assert!(f.observe(false).is_err());
        fs::remove_file(f.root.path().join("producer-authorized.json")).unwrap();
        assert!(!f.observe(false).unwrap().scheduled_producer);
        f.stopped().unwrap();
        for active in ["active", "activating", "reloading"] {
            f.tool(active, "running", 73);
            assert!(f.observe(false).is_err());
            assert!(f.stopped().is_err());
        }
        f.tool("failed", "failed", 0);
        f.stopped().unwrap();
        f.raw_tool(
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n",
            1,
        );
        f.stopped().unwrap();
        for raw in [
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=-1\n",
            "LoadState=loaded\nActiveState=inactive\nMainPID=0\nMainPID=0\n",
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nextra=x\n",
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=4294967296\n",
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=０\n",
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nBogus=0\n",
        ] {
            f.raw_tool(raw, 0);
            assert!(f.observe(false).is_err());
            assert!(f.stopped().is_err());
        }
        f.raw_tool(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n",
            1,
        );
        assert!(f.stopped().is_err());
        f.spec.block_interval_seconds = None;
        fs::remove_file(&f.systemctl).unwrap();
        assert!(!f.observe(false).unwrap().scheduled_producer);
        f.stopped().unwrap();
    }
}

#[cfg(target_os = "linux")]
mod native_image_delivery {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    use zdn::host::{
        command::Executor,
        files::Directory,
        image_delivery::{self, Tools},
    };

    fn password(size: usize) -> Vec<u8> {
        let mut bytes = vec![b'P'; size];
        if size > 1 {
            bytes[size - 1] = b'\n';
        }
        bytes
    }

    #[test]
    fn worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let mode = fs::read_to_string(payload["mode"].as_str().unwrap()).unwrap();
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(payload["log"].as_str().unwrap())
            .unwrap();
        writeln!(log, "{}", json!({"tool":payload["tool"],"args":args})).unwrap();
        let token = password(payload["passwordSize"].as_u64().unwrap() as usize);
        let mut code = 0;
        let stdout = if payload["tool"] == "aws" {
            assert_eq!(args, ["ecr", "get-login-password", "--region", "us-east-1"]);
            if mode == "aws-fails" {
                code = 1;
            }
            token
        } else if args[0] == "--config" {
            let directory = PathBuf::from(&args[1]);
            assert_eq!(
                directory.parent().unwrap(),
                payload["scratch"].as_str().unwrap()
            );
            assert_eq!(
                fs::symlink_metadata(&directory).unwrap().mode() & 0o7777,
                0o700
            );
            assert_eq!(
                fs::metadata(&directory).unwrap().uid(),
                fs::metadata("/proc/self").unwrap().uid()
            );
            match args[2].as_str() {
                "login" => {
                    assert_eq!(
                        args[3..],
                        [
                            "--username",
                            "AWS",
                            "--password-stdin",
                            payload["registry"].as_str().unwrap()
                        ]
                    );
                    let mut received = Vec::new();
                    std::io::stdin().read_to_end(&mut received).unwrap();
                    assert_eq!(received, token);
                    fs::write(directory.join("config.json"), &received).unwrap();
                    if mode == "login-fails" {
                        code = 1;
                    }
                }
                "pull" => {
                    assert_eq!(
                        args[3..],
                        [
                            "--platform",
                            "linux/amd64",
                            payload["image"].as_str().unwrap()
                        ]
                    );
                    assert_eq!(fs::read(directory.join("config.json")).unwrap(), token);
                    if mode == "pull-fails" {
                        code = 1;
                    }
                    if mode == "pull-stalls" {
                        fs::write(payload["started"].as_str().unwrap(), b"started").unwrap();
                        loop {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                }
                _ => panic!("unexpected Docker action"),
            }
            b"provider-secret-do-not-report".to_vec()
        } else {
            assert_eq!(
                args,
                ["image", "inspect", payload["image"].as_str().unwrap()]
            );
            assert!(fs::read_dir(payload["scratch"].as_str().unwrap())
                .unwrap()
                .next()
                .is_none());
            if mode == "inspect-fails" {
                code = 1;
            }
            let mut image = payload["inspection"].clone();
            match mode.as_str() {
                "foreign-config" => image[0]["Id"] = json!(format!("sha256:{}", "9".repeat(64))),
                "foreign-repository" => image[0]["RepoDigests"] = json!([]),
                "foreign-platform" => image[0]["Architecture"] = json!("arm64"),
                "unsafe-defaults" => {
                    image[0]["Config"]["Env"] = json!(["SECRET=provider-secret-do-not-report"])
                }
                _ => {}
            }
            serde_json::to_vec(&image).unwrap()
        };
        native_tool::reply(&work, &stdout, b"provider-secret-do-not-report", code);
    }

    struct Fixture {
        root: tempfile::TempDir,
        artifacts: Directory,
        spec: HostInstallSpec,
        scratch: PathBuf,
        tools: Tools,
        executor: Executor,
    }

    impl Fixture {
        fn new(size: usize) -> Self {
            let (root, artifacts, spec) = native_inputs::fixture();
            artifacts.ensure_directory("credentials", 0o700).unwrap();
            artifacts.ensure_directory("commands", 0o700).unwrap();
            let scratch = root.path().join("credentials");
            let tools = Tools {
                aws: root.path().join("aws"),
                docker: root.path().join("docker"),
            };
            let inspection = json!([{
                "Id":format!("sha256:{}", "a".repeat(64)),
                "RepoDigests":[spec.image], "Os":"linux", "Architecture":"amd64",
                "Config":{"Env":[]}
            }]);
            for (path, tool) in [(&tools.aws, "aws"), (&tools.docker, "docker")] {
                native_tool::install(
                    path,
                    "native_image_delivery::worker",
                    &json!({
                        "tool":tool, "mode":root.path().join("mode"), "log":root.path().join("log"),
                        "started":root.path().join("started"), "scratch":scratch,
                        "passwordSize":size, "image":spec.image, "inspection":inspection,
                        "registry":spec.image.split('/').next().unwrap()
                    }),
                );
            }
            fs::write(root.path().join("mode"), b"success").unwrap();
            let executor = Executor::new(
                env!("CARGO_BIN_EXE_zdn").into(),
                root.path().join("commands"),
                "us-east-1".into(),
                Instant::now() + Duration::from_secs(120),
            )
            .unwrap();
            Self {
                root,
                artifacts,
                spec,
                scratch,
                tools,
                executor,
            }
        }

        fn pull(
            &mut self,
            cancelled: &AtomicBool,
        ) -> eyre::Result<zdn::image::ImageInspectionReport> {
            image_delivery::pull(
                &self.spec,
                &self.artifacts,
                &self.scratch,
                &self.tools,
                &mut self.executor,
                cancelled,
            )
        }

        fn clean(&self) {
            assert!(fs::read_dir(&self.scratch).unwrap().next().is_none());
            let log = fs::read_to_string(self.root.path().join("log")).unwrap_or_default();
            assert!(!log.contains("PPPPP") && !log.contains("provider-secret"));
            for entry in fs::read_dir(self.root.path().join("commands")).unwrap() {
                assert_eq!(entry.unwrap().file_name(), "command.lock");
            }
        }
    }

    #[test]
    fn exact_pinned_pull_is_secret_safe_and_inspection_is_not_readiness() {
        #[cfg(feature = "profiling")]
        let Some(trace) = super::trace::capture("native_image_delivery::exact_pinned_pull_is_secret_safe_and_inspection_is_not_readiness") else {
            return;
        };
        for size in [1, 29, 8191] {
            let mut f = Fixture::new(size);
            let report = f.pull(&AtomicBool::new(false)).unwrap();
            assert_eq!(report.image, f.spec.image);
            assert_eq!(report.config_digest, format!("sha256:{}", "a".repeat(64)));
            assert!(report.manifest_bytes_verified && report.docker_metadata_verified);
            assert!(!report.launch_ready && !report.capabilities_observed);
            assert_eq!(report.qualification, "pending");
            f.clean();
            let log = fs::read_to_string(f.root.path().join("log")).unwrap();
            assert_eq!(log.lines().count(), 4);
            // Read-only reinspection never performs login or pull.
            image_delivery::inspect(
                &f.spec,
                &f.artifacts,
                &f.tools.docker,
                &mut f.executor,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(
                fs::read_to_string(f.root.path().join("log"))
                    .unwrap()
                    .lines()
                    .count(),
                5
            );
        }
        #[cfg(feature = "profiling")]
        {
            trace.assert_spans(
                &[
                    "host.image_delivery.pull",
                    "host.image_delivery.preflight",
                    "host.image_delivery.password",
                    "host.image_delivery.login",
                    "host.image_delivery.pull_command",
                    "host.image_delivery.credential_cleanup",
                    "host.image_delivery.inspect",
                    "host.inputs.verified_image",
                ],
                &[
                    "PPPPP",
                    "provider-secret",
                    "12345678-1234-4123-8123-123456789abc",
                    "sha256:",
                ],
            );
            for phase in [
                "host.image_delivery.preflight",
                "host.image_delivery.password",
                "host.image_delivery.login",
                "host.image_delivery.pull_command",
                "host.image_delivery.credential_cleanup",
                "host.image_delivery.inspect",
            ] {
                trace.assert_child(phase, "host.image_delivery.pull");
            }
        }
    }

    #[test]
    fn failures_bound_credentials_and_reject_foreign_images_without_leaks() {
        for size in [0, 8192] {
            let mut f = Fixture::new(size);
            assert!(f.pull(&AtomicBool::new(false)).is_err());
            f.clean();
            assert_eq!(
                fs::read_to_string(f.root.path().join("log"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
        }
        let mut f = Fixture::new(29);
        for mode in [
            "aws-fails",
            "login-fails",
            "pull-fails",
            "inspect-fails",
            "foreign-config",
            "foreign-repository",
            "foreign-platform",
            "unsafe-defaults",
        ] {
            fs::write(f.root.path().join("mode"), mode).unwrap();
            let error = format!("{:?}", f.pull(&AtomicBool::new(false)).unwrap_err());
            assert!(
                !error.contains("PPPPP") && !error.contains("provider-secret"),
                "{mode}: {error}"
            );
            f.clean();
        }
        // Byte pins and scratch/tool trust must fail before AWS is invoked.
        for case in ["pin", "scratch-mode", "scratch-symlink", "relative-tool"] {
            let mut f = Fixture::new(29);
            match case {
                "pin" => fs::write(f.root.path().join("image.json"), b"{}").unwrap(),
                "scratch-mode" => {
                    fs::set_permissions(&f.scratch, fs::Permissions::from_mode(0o755)).unwrap()
                }
                "scratch-symlink" => {
                    let alias = f.root.path().join("alias");
                    std::os::unix::fs::symlink(&f.scratch, &alias).unwrap();
                    f.scratch = alias;
                }
                "relative-tool" => f.tools.docker = "docker".into(),
                _ => unreachable!(),
            }
            assert!(f.pull(&AtomicBool::new(false)).is_err(), "{case}");
            assert!(!f.root.path().join("log").exists(), "{case}");
        }
    }

    #[test]
    fn cancellation_during_pull_removes_credentials_and_allows_retry() {
        let mut f = Fixture::new(29);
        fs::write(f.root.path().join("mode"), b"pull-stalls").unwrap();
        let cancelled = AtomicBool::new(false);
        let started = f.root.path().join("started");
        std::thread::scope(|scope| {
            let cancelled = &cancelled;
            scope.spawn(move || {
                let until = Instant::now() + Duration::from_secs(10);
                while !started.exists() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                }
                cancelled.store(true, Ordering::Relaxed);
            });
            assert!(f.pull(cancelled).is_err());
        });
        assert!(f.root.path().join("started").exists());
        f.clean();
        fs::write(f.root.path().join("mode"), b"success").unwrap();
        f.pull(&AtomicBool::new(false)).unwrap();
        f.clean();
    }
}

#[cfg(target_os = "linux")]
mod native_node_paths {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use zdn::host::{files::Directory, node_paths, volume::Installation};

    fn directory(path: &std::path::Path) -> Directory {
        Directory::open(path, fs::metadata("/proc/self").unwrap().uid()).unwrap()
    }

    fn scheduled_spec(producer: bool) -> HostInstallSpec {
        let mut spec = spec();
        spec.block_interval_seconds = Some(37);
        if producer {
            spec.role = "producer".into();
            let manifest: ConsensusManifest =
                serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
            let mut options = RuntimeOptions::new(spec.deployment_id, "node-1");
            options.network.listen_addr = "10.90.1.10:18233".into();
            options.network.peers = vec!["10.90.1.11:18233".into()];
            options.role = zdn::chain::runtime_config::NodeRole::Producer;
            options.reward_address = Some("tm9iNYCVAhLLa4rJtfqqHauR5xL1REdpiDs".into());
            let rendered = render_runtime_config(&manifest, &options).unwrap();
            spec.config_toml = rendered.config_toml;
            spec.config_sha256 = rendered.config_sha256;
        }
        spec
    }

    #[test]
    fn creates_exact_paths_without_replacing_retained_data_or_configuration() {
        #[cfg(feature = "profiling")]
        let Some(trace) = super::trace::capture("native_node_paths::creates_exact_paths_without_replacing_retained_data_or_configuration") else {
            return;
        };
        let mut legacy_producer = scheduled_spec(true);
        legacy_producer.block_interval_seconds = None;
        for spec in [
            spec(),
            scheduled_spec(false),
            scheduled_spec(true),
            legacy_producer,
        ] {
            let root = tempfile::tempdir().unwrap();
            let anchor = directory(root.path());
            let etc = anchor.ensure_directory("etc", 0o700).unwrap();
            let volume = anchor.ensure_directory("volume", 0o700).unwrap();
            let guard = Installation::acquire(&etc, &spec).unwrap();
            guard.claim_mounted(&volume, true).unwrap();
            let uid = fs::metadata(root.path()).unwrap().uid();
            let node = node_paths::create(&spec, &volume, &guard, uid).unwrap();
            let relative = spec
                .node_root()
                .strip_prefix("/var/lib/zdn/")
                .unwrap()
                .to_owned();
            let path = root.path().join("volume").join(relative);
            for name in ["state", "identity", "rpc"] {
                let metadata = fs::metadata(path.join(name)).unwrap();
                assert_eq!(metadata.uid(), uid);
                assert_eq!(metadata.mode() & 0o7777, 0o700);
                fs::write(path.join(name).join("retained"), name).unwrap();
            }
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o755);
            assert_eq!(
                path.join("producer").exists(),
                spec.role == "producer" && spec.block_interval_seconds.is_some()
            );
            let before = fs::metadata(path.join("zakura.toml")).unwrap();
            assert_eq!(before.uid(), uid);
            assert_eq!(before.mode() & 0o7777, 0o444);
            assert_eq!(
                node.read("zakura.toml", 8 << 20).unwrap(),
                spec.config_toml.as_bytes()
            );
            node_paths::create(&spec, &volume, &guard, uid).unwrap();
            assert_eq!(
                before.ino(),
                fs::metadata(path.join("zakura.toml")).unwrap().ino()
            );
            for name in ["state", "identity", "rpc"] {
                assert_eq!(
                    fs::read(path.join(name).join("retained")).unwrap(),
                    name.as_bytes()
                );
            }
            let mut changed = spec.clone();
            changed.cpu_millis += 17;
            assert!(node_paths::create(&changed, &volume, &guard, uid).is_err());
        }
        #[cfg(feature = "profiling")]
        {
            trace.assert_spans(
                &[
                    "host.node_paths.create",
                    "host.files.ensure_owned_directory",
                ],
                &["zakura.toml", "node-1", &spec().config_toml],
            );
            trace.assert_child(
                "host.files.ensure_owned_directory",
                "host.node_paths.create",
            );
        }
    }

    #[test]
    fn rejects_unsafe_ancestors_leaves_claims_and_changed_configuration_without_repair() {
        for case in ["claim", "ancestor", "leaf", "mode", "owner", "config"] {
            let spec = spec();
            let root = tempfile::tempdir().unwrap();
            let anchor = directory(root.path());
            let etc = anchor.ensure_directory("etc", 0o700).unwrap();
            let volume = anchor.ensure_directory("volume", 0o700).unwrap();
            let guard = Installation::acquire(&etc, &spec).unwrap();
            let uid = fs::metadata(root.path()).unwrap().uid();
            if case == "claim" {
                volume
                    .publish(".zdn-volume.json", b"foreign\n", 0o600)
                    .unwrap();
            } else {
                guard.claim_mounted(&volume, true).unwrap();
            }
            if case == "ancestor" {
                symlink(root.path(), root.path().join("volume/deployments")).unwrap();
            } else if case != "claim" {
                node_paths::create(&spec, &volume, &guard, uid).unwrap();
                let path = root
                    .path()
                    .join("volume")
                    .join(spec.node_root().strip_prefix("/var/lib/zdn/").unwrap());
                if case == "leaf" {
                    fs::remove_dir(path.join("state")).unwrap();
                    symlink(root.path(), path.join("state")).unwrap();
                } else if case == "mode" {
                    fs::set_permissions(path.join("state"), fs::Permissions::from_mode(0o755))
                        .unwrap();
                } else if case == "config" {
                    fs::remove_file(path.join("zakura.toml")).unwrap();
                    fs::write(path.join("zakura.toml"), b"foreign configuration\n").unwrap();
                    fs::set_permissions(
                        path.join("zakura.toml"),
                        fs::Permissions::from_mode(0o444),
                    )
                    .unwrap();
                }
            }
            assert!(
                node_paths::create(&spec, &volume, &guard, uid + u32::from(case == "owner"))
                    .is_err(),
                "{case}"
            );
            if case == "claim" {
                assert!(!root.path().join("volume/deployments").exists());
            }
            if case == "config" {
                let path = root
                    .path()
                    .join("volume")
                    .join(spec.node_root().strip_prefix("/var/lib/zdn/").unwrap());
                assert_eq!(
                    fs::read(path.join("zakura.toml")).unwrap(),
                    b"foreign configuration\n"
                );
            }
        }
    }

    #[test]
    fn distinct_node_uid_owns_only_writable_leaves_when_root() {
        if nix::unistd::geteuid().as_raw() != 0 {
            return;
        }
        let spec = scheduled_spec(true);
        let root = tempfile::tempdir().unwrap();
        let anchor = directory(root.path());
        let etc = anchor.ensure_directory("etc", 0o700).unwrap();
        let volume = anchor.ensure_directory("volume", 0o700).unwrap();
        let guard = Installation::acquire(&etc, &spec).unwrap();
        guard.claim_mounted(&volume, true).unwrap();
        node_paths::create(&spec, &volume, &guard, 10001).unwrap();
        let path = root
            .path()
            .join("volume")
            .join(spec.node_root().strip_prefix("/var/lib/zdn/").unwrap());
        for name in ["state", "identity", "rpc"] {
            let metadata = fs::metadata(path.join(name)).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
                (10001, 10001, 0o700)
            );
        }
        for name in ["", "producer", "zakura.toml"] {
            assert_eq!(fs::metadata(path.join(name)).unwrap().uid(), 0);
        }
        node_paths::create(&spec, &volume, &guard, 10001).unwrap();
        assert!(node_paths::create(&spec, &volume, &guard, 10002).is_err());
        assert_eq!(fs::metadata(path.join("state")).unwrap().uid(), 10001);
    }
}

#[test]
fn native_runtime_selection_preserves_original_identity_and_rejects_ambiguous_data() {
    use zdn::host::runtime::{Manifest, Selection, PROTOCOL};
    let original = spec();
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let mut helper = original.helper.clone();
    helper.key = "team/test/native-runtime".into();
    helper.sha256 = "e".repeat(64);
    let manifest = Manifest::new(
        original.clone(),
        Selection {
            protocol: PROTOCOL.into(),
            helper,
        },
    )
    .unwrap();
    assert_eq!(
        manifest.install_sha256,
        "938d9d35cfc66e6a752441619f1aa5a2512225af8f915298b51679e8938092e6"
    );
    let bytes = manifest.bytes().unwrap();
    assert_eq!(
        Manifest::from_slice(&bytes).unwrap().bytes().unwrap(),
        bytes
    );
    assert_eq!(serde_json::to_vec(&manifest.spec).unwrap(), original_bytes);
    let native_service = zdn::client_gateway::native::service_sha256(&manifest).unwrap();
    let ready = zdn::client_gateway::native::observation(&manifest, "ready").unwrap();
    assert!(zdn::client_gateway::native::validate_observation(&ready, &manifest).is_ok());
    let unit = zdn::client_gateway::native::unit(&manifest).unwrap();
    assert!(!unit.contains("python"));
    for setting in [
        "ProtectSystem=strict",
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
        "TasksMax=16",
        "LimitCORE=0",
        "Type=exec",
        "WantedBy=zdn-node.service",
    ] {
        assert!(unit.contains(setting));
    }
    assert!(!unit.contains("ReadWritePaths"));
    let mut changed = manifest.clone();
    changed.runtime.helper.sha256 = "f".repeat(64);
    assert_ne!(manifest.file_name().unwrap(), changed.file_name().unwrap());
    assert_ne!(
        native_service,
        zdn::client_gateway::native::service_sha256(&changed).unwrap()
    );
    assert!(zdn::client_gateway::native::validate_observation(&ready, &changed).is_err());
    assert_eq!(changed.install_sha256, manifest.install_sha256);
    for field in ["installSha256", "apiVersion", "runtime"] {
        let prefix = format!("{{\"{field}\":null,");
        let mut duplicate = prefix.into_bytes();
        duplicate.extend_from_slice(&bytes[1..]);
        assert!(Manifest::from_slice(&duplicate).is_err());
    }
    let mut value = serde_json::to_value(&manifest).unwrap();
    value["runtime"]["unexpected"] = json!("PRIVATE-VALUE");
    let error = Manifest::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert!(!format!("{error:#}").contains("PRIVATE-VALUE"));
    assert!(Manifest::from_slice(&serde_json::to_vec_pretty(&manifest).unwrap()).is_err());
    changed.runtime.protocol = "unimplemented".into();
    assert!(changed.validate().is_err());
    changed = manifest.clone();
    changed.spec.cpu_millis += 1;
    assert!(changed.validate().is_err());
    changed = manifest.clone();
    changed.runtime.helper.owner_account = "987654321098".into();
    assert!(changed.validate().is_err());
    changed = manifest;
    changed.runtime.helper.bytes = zdn::devnet::MAX_HELPER_BYTES + 1;
    assert!(changed.validate().is_err());
}

// These fixtures execute the deployed Linux x86-64 helper, whose real ELF
// header is checked before invocation. ARM controllers must reject their own
// native binary here; portable input/manifest tests above still run on ARM.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod native_runtime {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        io::Write,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::{atomic::AtomicBool, OnceLock},
    };
    use zdn::host::{
        files::Directory,
        node_paths, producer,
        runtime::{
            control::{self, Config, Operation},
            Manifest, Selection, PROTOCOL,
        },
        volume::Installation,
    };

    // An actual ELF fake chain helper is required: a script would skip the
    // production pin/ELF boundary. Compile once, keeping only bytes in memory;
    // all compiler scratch is removed before the first invocation.
    fn chain_helper() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            let scratch = tempfile::tempdir().unwrap();
            let source = scratch.path().join("worker.rs");
            fs::write(&source, r#"
use std::{fs, io::Write};
fn main() {
    let exe = std::env::current_exe().unwrap();
    let root = exe.parent().unwrap();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut calls = fs::OpenOptions::new().append(true).create(true).open(root.join("worker-calls")).unwrap();
    writeln!(calls, "{}", args.join("\0")).unwrap();
    if args.get(1).is_some_and(|a| a == "produce") || args.first().is_some_and(|a| a == "run") {
        fs::write(root.join("worker-pid"), std::process::id().to_string()).unwrap();
        let mut env: Vec<_> = std::env::vars().collect();
        env.sort();
        fs::write(root.join("worker-env"), format!("{env:?}")).unwrap();
    }
    println!("{{\"launchReady\":false,\"fixture\":37}}");
}
"#).unwrap();
            let result = Command::new("rustc").args(["--edition=2021", "-C", "debuginfo=0", "-o"])
                .arg(scratch.path().join("worker")).arg(source).output().unwrap();
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
            fs::read(scratch.path().join("worker")).unwrap()
        })
    }

    struct Fixture {
        root: tempfile::TempDir,
        manifest: Manifest,
        owner: u32,
    }

    struct StopOnDrop<'a>(&'a AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl Fixture {
        fn new(producer: bool) -> Self {
            Self::new_scheduled(producer, producer)
        }

        fn new_scheduled(producer: bool, scheduled: bool) -> Self {
            let (inputs, _, mut spec) = native_inputs::fixture();
            let root = tempfile::tempdir().unwrap();
            let owner = fs::metadata(root.path()).unwrap().uid();
            for path in [
                "etc/zdn/artifacts",
                "var/lib/zdn",
                "usr/bin",
                "usr/sbin",
                "dev",
                "run/zdn-producer",
            ] {
                fs::create_dir_all(root.path().join(path)).unwrap();
            }
            if producer {
                let chain: ConsensusManifest =
                    serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json"))
                        .unwrap();
                let mut options = RuntimeOptions::new(spec.deployment_id, "node-1");
                options.network.listen_addr = "10.90.1.10:18233".into();
                options.network.peers = vec!["10.90.1.11:18233".into()];
                options.rpc_listen_addr = "127.0.0.2:18339".into();
                options.role = zdn::chain::runtime_config::NodeRole::Producer;
                options.reward_address = Some("tm9iNYCVAhLLa4rJtfqqHauR5xL1REdpiDs".into());
                let runtime = render_runtime_config(&chain, &options).unwrap();
                spec.config_toml = runtime.config_toml;
                spec.config_sha256 = runtime.config_sha256;
                spec.role = "producer".into();
                spec.block_interval_seconds = Some(37);
            }
            if scheduled {
                spec.block_interval_seconds = Some(37);
            }
            for name in [
                "manifest.json",
                "chain.tar",
                "image.json",
                "image-manifest.json",
            ] {
                fs::copy(
                    inputs.path().join(name),
                    root.path().join("etc/zdn/artifacts").join(name),
                )
                .unwrap();
            }
            fs::write(root.path().join("etc/zdn/artifacts/zdn"), chain_helper()).unwrap();
            fs::set_permissions(
                root.path().join("etc/zdn/artifacts/zdn"),
                fs::Permissions::from_mode(0o555),
            )
            .unwrap();
            spec.helper.bytes = chain_helper().len() as u64;
            spec.helper.sha256 = hex::encode(Sha256::digest(chain_helper()));
            let binary = fs::read(env!("CARGO_BIN_EXE_zdn")).unwrap();
            let mut helper = spec.helper.clone();
            helper.sha256 = hex::encode(Sha256::digest(&binary));
            helper.bytes = binary.len() as u64;
            helper.key = "team/test/native-runtime".into();
            let manifest = Manifest::new(
                spec,
                Selection {
                    protocol: PROTOCOL.into(),
                    helper,
                },
            )
            .unwrap();
            let runtime = root.path().join(format!(
                "etc/zdn/runtime/{}",
                manifest.runtime.helper.sha256
            ));
            fs::create_dir_all(&runtime).unwrap();
            fs::write(runtime.join("zdn"), binary).unwrap();
            fs::set_permissions(runtime.join("zdn"), fs::Permissions::from_mode(0o555)).unwrap();
            let metadata = Directory::open(&root.path().join("etc/zdn"), owner).unwrap();
            let guard = Installation::acquire(&metadata, &manifest.spec).unwrap();
            let volume = Directory::open(&root.path().join("var/lib/zdn"), owner).unwrap();
            guard.claim_mounted(&volume, true).unwrap();
            node_paths::create(&manifest.spec, &volume, &guard, owner).unwrap();
            fs::write(
                root.path().join("dev/nvme12n3"),
                b"fixture mount source, not a block device",
            )
            .unwrap();
            for (path, bytes) in [
                ("proc/meminfo", "MemTotal: 67108864 kB\n"),
                ("proc/self/status", "Cpus_allowed_list: 0-7\n"),
                ("proc/self/cgroup", "0::/leaf\n"),
                ("sys/devices/system/cpu/online", "0-7\n"),
                ("sys/fs/cgroup/memory.max", "18253611008\n"),
                ("sys/fs/cgroup/cpu.max", "750000 100000\n"),
                ("sys/fs/cgroup/leaf/memory.max", "12884901888\n"),
                ("sys/fs/cgroup/leaf/cpu.max", "362500 100000\n"),
            ] {
                let path = root.path().join(path);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, bytes).unwrap();
            }
            let node = manifest.spec.node_root();
            let mounts: Vec<_> = ["", "/state", "/identity", "/rpc"]
                .into_iter()
                .map(|suffix| {
                    let path = format!("{node}{suffix}");
                    json!({"Type":"bind","Source":path,"Destination":path,"RW":!suffix.is_empty()})
                })
                .collect();
            let state = json!({"mounted":true, "service":"LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n", "failStop":false,
                "image":[{"Id":format!("sha256:{}", "a".repeat(64)),"RepoDigests":[manifest.spec.image],"Os":"linux","Architecture":"amd64","Config":{"Env":[]}}],
                "container":[{"Name":format!("/zdn-{}-node-1", manifest.spec.deployment_id),"State":{"Running":true},
                    "Config":{"Image":manifest.spec.image,"Labels":{"zdn.install":manifest.install_sha256},"User":"10001:10001","WorkingDir":"/","Entrypoint":["/usr/bin/env"],"Cmd":["-i","PATH=/usr/local/bin:/usr/bin:/bin","HOME=/nonexistent","/usr/local/bin/zakurad","--config",format!("{node}/zakura.toml"),"start"],"StopSignal":"SIGINT","Healthcheck":{"Test":["NONE"]}},
                    "HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"PidsLimit":1024,"PidMode":"","LogConfig":{"Type":"journald"},"SecurityOpt":["no-new-privileges:true"],"Memory":8589934592u64,"MemorySwap":8589934592u64,"NanoCpus":3375000000u64},"Mounts":mounts}]});
            fs::write(root.path().join("state.json"), state.to_string()).unwrap();
            for name in [
                "docker",
                "systemctl",
                "lsblk",
                "findmnt",
                "blkid",
                "wipefs",
                "blockdev",
                "mkfs.ext4",
                "mount",
                "iptables",
                "ip6tables",
            ] {
                native_tool::install(
                    &root.path().join("usr/bin").join(name),
                    "native_runtime::tool_worker",
                    &json!({"root":root.path(),"name":name,"node":node}),
                );
            }
            Self {
                root,
                manifest,
                owner,
            }
        }

        fn run(&self, operation: Operation) -> eyre::Result<Option<serde_json::Value>> {
            control::dispatch(
                &self.manifest,
                Config {
                    root: self.root.path(),
                    owner: self.owner,
                    node_owner: self.owner,
                },
                operation,
                &AtomicBool::new(false),
            )
        }
        fn node(&self) -> PathBuf {
            self.root
                .path()
                .join(self.manifest.spec.node_root().trim_start_matches('/'))
        }
        fn set(&self, key: &str, value: serde_json::Value) {
            let path = self.root.path().join("state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            state[key] = value;
            fs::write(path, state.to_string()).unwrap();
        }
        fn calls(&self) -> String {
            fs::read_to_string(self.root.path().join("calls")).unwrap_or_default()
        }

        fn revision_fixture(&self) -> zdn::host::runtime::revision::Request {
            use zdn::host::runtime::revision::{self, Request};
            let config = serde_json::to_vec(&json!({
                "architecture":"amd64", "os":"linux", "config":{},
                "rootfs":{"type":"layers", "diff_ids":[format!("sha256:{}", "9".repeat(64))]}
            }))
            .unwrap();
            let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
            let manifest = serde_json::to_vec(&json!({
                "schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json",
                "config":{"mediaType":"application/vnd.oci.image.config.v1+json",
                    "digest":format!("sha256:{}", digest(&config)), "size":config.len()},
                "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest":format!("sha256:{}", "8".repeat(64)), "size":731}]
            }))
            .unwrap();
            let mut image = zdn::image::ImageRecord::from_json(
                &fs::read(self.root.path().join("etc/zdn/artifacts/image.json")).unwrap(),
            )
            .unwrap();
            image.image = format!(
                "{}@sha256:{}",
                image.image.split_once('@').unwrap().0,
                digest(&manifest)
            );
            image.config_digest = format!("sha256:{}", digest(&config));
            let record = serde_json::to_vec(&image).unwrap();
            let pin = |name: &str, bytes: &[u8]| {
                let mut pin = self.manifest.spec.image_record.clone();
                pin.key = format!("team/test/update/{name}");
                pin.bytes = bytes.len() as u64;
                pin.sha256 = digest(bytes);
                pin
            };
            let request = Request {
                api_version: revision::API_VERSION.into(),
                original: self.manifest.clone(),
                update_id: Uuid::new_v4(),
                expected_image: self.manifest.spec.image.clone(),
                expected_update_id: None,
                image,
                image_record: pin("image.json", &record),
                image_manifest: pin("image-manifest.json", &manifest),
                image_config: pin("image-config.json", &config),
            };
            request.validate().unwrap();
            let metadata = Directory::open(&self.root.path().join("etc/zdn"), self.owner).unwrap();
            metadata
                .publish(
                    "native-install-intent.json",
                    &self.manifest.bytes().unwrap(),
                    0o600,
                )
                .unwrap();
            let artifacts = metadata
                .ensure_directory(revision::NAMESPACE, 0o700)
                .unwrap()
                .ensure_directory(&request.update_id.to_string(), 0o700)
                .unwrap();
            for (name, bytes) in [
                ("image.json", record),
                ("image-manifest.json", manifest),
                ("image-config.json", config),
            ] {
                artifacts.publish(name, &bytes, 0o600).unwrap();
            }
            request
        }

        fn updater(producer: bool) -> (Self, zdn::host::runtime::revision::Request) {
            let fixture = Self::initialize_install(Self::new_scheduled(producer, true));
            fixture.install().unwrap();
            let request = fixture.revision_fixture();
            fs::write(
                fixture.root.path().join("update-request.json"),
                request.bytes().unwrap(),
            )
            .unwrap();
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(fixture.root.path().join("state.json")).unwrap())
                    .unwrap();
            let mut image = state["image"].clone();
            image[0]["Id"] = json!(request.image.config_digest);
            image[0]["RepoDigests"] = json!([request.image.image]);
            fixture.set("image", image);
            fixture.set("nativeUpdate", true.into());
            fixture.set("updateNodeRunning", true.into());
            (fixture, request)
        }

        fn update(
            &self,
            request: &zdn::host::runtime::revision::Request,
        ) -> eyre::Result<serde_json::Value> {
            zdn::host::runtime::update::dispatch(
                request,
                Config {
                    root: self.root.path(),
                    owner: self.owner,
                    node_owner: self.owner,
                },
                &AtomicBool::new(false),
            )
        }

        fn first_install(producer: bool) -> Self {
            Self::initialize_install(Self::new(producer))
        }

        fn initialize_install(fixture: Self) -> Self {
            let root = fixture.root.path();
            fs::remove_file(root.join("etc/zdn/identity.json")).unwrap();
            fs::remove_file(root.join("etc/zdn/volume-claimed.json")).unwrap();
            fs::remove_dir_all(root.join("var/lib/zdn")).unwrap();
            fs::create_dir(root.join("var/lib/zdn")).unwrap();
            fs::remove_dir_all(root.join("etc/zdn/runtime")).unwrap();
            for directory in ["etc/zdn", "etc/zdn/artifacts"] {
                fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
            fs::write(
                root.join("etc/zdn-prerequisites-ready"),
                b"zdn-host-prerequisites/v1alpha1\n",
            )
            .unwrap();
            fs::set_permissions(
                root.join("etc/zdn-prerequisites-ready"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::write(
                root.join("install-manifest.json"),
                fixture.manifest.bytes().unwrap(),
            )
            .unwrap();
            let source = root.join("source-artifacts");
            fs::rename(root.join("etc/zdn/artifacts"), &source).unwrap();
            fs::create_dir(root.join("etc/zdn/artifacts")).unwrap();
            fs::set_permissions(
                root.join("etc/zdn/artifacts"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let pins = &fixture.manifest.spec;
            fs::write(root.join("artifact-map.json"), serde_json::to_vec(&json!({
                pins.manifest.key.clone():"manifest.json", pins.bundle.key.clone():"chain.tar", pins.helper.key.clone():"zdn",
                pins.image_record.key.clone():"image.json", pins.image_manifest.key.clone():"image-manifest.json"
            })).unwrap()).unwrap();
            native_tool::install(
                &root.join("usr/bin/aws"),
                "native_runtime::tool_worker",
                &json!({"root":root,"name":"aws"}),
            );
            fixture.set("nativeInstall", true.into());
            fixture
        }

        fn install(&self) -> eyre::Result<serde_json::Value> {
            zdn::host::runtime::install::install(
                &self.manifest,
                Config {
                    root: self.root.path(),
                    owner: self.owner,
                    node_owner: self.owner,
                },
                fs::File::open(env!("CARGO_BIN_EXE_zdn"))?,
                &AtomicBool::new(false),
            )
        }
    }

    #[test]
    fn tool_worker() {
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let root = Path::new(payload["root"].as_str().unwrap());
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("state.json")).unwrap()).unwrap();
        let name = payload["name"].as_str().unwrap();
        let mut log = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(root.join("calls"))
            .unwrap();
        writeln!(log, "{}", json!({"tool":name,"args":args})).unwrap();
        let argv: Vec<_> = args.iter().map(String::as_str).collect();
        let mut code = 0;
        let out = match (name, argv.as_slice()) {
            ("aws", ["ecr", "get-login-password", ..]) => b"OFFLINE-PRIVATE-PASSWORD\n".to_vec(),
            ("aws", ["s3api", "get-object", ..]) => {
                let map: serde_json::Value = serde_json::from_slice(&fs::read(root.join("artifact-map.json")).unwrap()).unwrap();
                let key = &args[args.iter().position(|a| a == "--key").unwrap() + 1];
                let source = root.join("source-artifacts").join(map[key].as_str().unwrap());
                let count = fs::copy(source, args.last().unwrap()).unwrap();
                serde_json::to_vec(&json!({"ContentLength":count})).unwrap()
            }
            ("docker", ["--config", _, "login", ..]) => Vec::new(),
            ("docker", ["--config", _, "pull", ..]) => {
                if state["failImagePull"] == true { code = 1; }
                Vec::new()
            }
            ("iptables" | "ip6tables", _) => Vec::new(),
            ("lsblk", _) => serde_json::to_vec(&json!({"blockdevices":[{"path":"/dev/nvme12n3","type":"disk","serial":"vol0123456789abcdef0","mountpoints":["/var/lib/zdn"]}]})).unwrap(),
            ("findmnt", _) => {
                if state["mounted"] == false { code = 1; Vec::new() }
                else {
                    let target = &args[2];
                    let producer = target.ends_with("/producer");
                    let suffix = if producer { target.strip_prefix("/var/lib/zdn").unwrap() } else { "" };
                    serde_json::to_vec(&json!({"filesystems":[{"target":target,"source":format!("{}{suffix}", root.join("dev/nvme12n3").display(), suffix=if producer {format!("[{suffix}]")} else {String::new()}),"fstype":"ext4","fsroot":if producer {suffix} else {"/"},"options":"rw,nodev,nosuid,noexec"}]})).unwrap()
                }
            }
            ("blkid", _) => { code = 2; Vec::new() }
            ("wipefs", _) => b"{\"signatures\":[]}".to_vec(),
            ("blockdev", _) => b"7516192768".to_vec(),
            ("docker", ["container", "ls", ..]) => Vec::new(),
            ("docker", ["container", "inspect", ..]) => serde_json::to_vec(&state["container"]).unwrap(),
            ("docker", ["image", "inspect", ..]) => serde_json::to_vec(&state["image"]).unwrap(),
            ("systemctl", ["show", "zdn-client-rpc.service", properties]) => {
                state[if properties.contains("FragmentPath") { "gatewayLoad" } else { "gatewayState" }].as_str().unwrap().as_bytes().to_vec()
            }
            ("systemctl", ["start", "zdn-client-rpc.service"]) => {
                let manifest = Manifest::from_slice(&fs::read(root.join("install-manifest.json")).unwrap()).unwrap();
                let owner = root.metadata().unwrap().uid();
                let metadata = Directory::open(&root.join("etc/zdn"), owner).unwrap();
                assert!(metadata.lock("install.lock").is_err());
                // Startup validates its native configuration while the parent
                // retains the install lock. The read-only daemon cannot take it.
                zdn::host::runtime::gateway::serve(&manifest, Config { root, owner, node_owner: owner }, std::net::TcpListener::bind("127.0.0.1:0").unwrap(), &AtomicBool::new(true)).unwrap();
                if state["gatewayStartStopped"] != true {
                    state["gatewayState"] = "ActiveState=active\nSubState=running\nMainPID=37\n".into();
                }
                fs::write(root.join("state.json"), state.to_string()).unwrap();
                Vec::new()
            }
            ("systemctl", ["show", unit, properties]) if state["nativeUpdate"] == true && properties.contains("FragmentPath") => {
                let status = if *unit == "zdn-node.service" {
                    if state["updateNodeRunning"] == true { "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=47\n" }
                    else { "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n" }
                } else { state["service"].as_str().unwrap() };
                format!("FragmentPath=/etc/systemd/system/{unit}\nDropInPaths={}\n{status}", state["updateDropIns"].as_str().unwrap_or("")).into_bytes()
            }
            ("systemctl", ["stop", unit]) if state["nativeUpdate"] == true => {
                if state["failStop"] == true { code = 1; }
                else if *unit == "zdn-node.service" {
                    let manifest = Manifest::from_slice(&fs::read(root.join("install-manifest.json")).unwrap()).unwrap();
                    let owner = root.metadata().unwrap().uid();
                    let metadata = Directory::open(&root.join("etc/zdn"), owner).unwrap();
                    drop(metadata.lock("install.lock").unwrap());
                    state["updateNodeRunning"] = false.into();
                    fs::write(root.join("state.json"), state.to_string()).unwrap();
                    control::dispatch(&manifest, Config { root, owner, node_owner: owner }, Operation::Stop, &AtomicBool::new(false)).unwrap();
                } else {
                    state["service"] = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n".into();
                    fs::write(root.join("state.json"), state.to_string()).unwrap();
                }
                Vec::new()
            }
            ("systemctl", ["show", ..]) => state["service"].as_str().unwrap().as_bytes().to_vec(),
            ("systemctl", ["stop", ..]) => { if state["failStop"] == true { code = 1; } Vec::new() }
            ("systemctl", ["start", "zdn-producer.service"]) if state["nativeUpdate"] == true => {
                let manifest = Manifest::from_slice(&fs::read(root.join("install-manifest.json")).unwrap()).unwrap();
                let metadata = Directory::open(&root.join("etc/zdn"), root.metadata().unwrap().uid()).unwrap();
                assert!(!zdn::host::runtime::revision::Snapshot::from_installation(&metadata, &manifest).unwrap().unwrap().producer_hold);
                if state["failProducerStart"] == true { code = 1; }
                else {
                    state["service"] = state["startedService"].clone();
                    fs::write(root.join("state.json"), state.to_string()).unwrap();
                }
                Vec::new()
            }
            ("systemctl", ["start", ..]) => {
                if state["nativeInstall"] == true {
                    let manifest = Manifest::from_slice(&fs::read(root.join("install-manifest.json")).unwrap()).unwrap();
                    let owner = root.metadata().unwrap().uid();
                    // Simulate systemd's public service operations in a separate
                    // process. These must acquire the original installation
                    // lock while the installer waits for startup to finish.
                    let metadata = Directory::open(&root.join("etc/zdn"), owner).unwrap();
                    drop(metadata.lock("install.lock").unwrap());
                    if state["failStart"] == true {
                        native_tool::reply(&work, b"", b"PRIVATE-START-FAILURE", 1);
                        return;
                    }
                    if state["nativeUpdate"] == true {
                        let request = zdn::host::runtime::revision::Request::from_slice(&fs::read(root.join("update-request.json")).unwrap()).unwrap();
                        state["container"][0]["Config"]["Image"] = json!(request.image.image);
                        state["updateNodeRunning"] = true.into();
                        fs::write(root.join("state.json"), state.to_string()).unwrap();
                    }
                    if state["skipStartup"] != true {
                        for operation in [Operation::Prepare, Operation::Ready] {
                            control::dispatch(&manifest, Config { root, owner, node_owner: owner }, operation, &AtomicBool::new(false)).unwrap();
                        }
                    }
                }
                if state["startedService"].is_string() && state["nativeUpdate"] != true {
                    state["service"] = state["startedService"].clone();
                    fs::write(root.join("state.json"), state.to_string()).unwrap();
                }
                Vec::new()
            }
            ("systemctl", ["enable" | "reset-failed" | "daemon-reload" | "is-active", ..]) => Vec::new(),
            _ => panic!("unexpected side effect {name} {args:?}"),
        };
        native_tool::reply(&work, &out, b"PRIVATE-TOOL-DIAGNOSTIC", code);
    }

    #[test]
    fn native_gateway_installs_observes_and_recovers_without_node_bootstrap() {
        #[cfg(feature = "profiling")]
        let Some(trace) = super::trace::capture(
            "native_runtime::native_gateway_installs_observes_and_recovers_without_node_bootstrap",
        ) else {
            return;
        };
        use std::{
            io::{BufRead, BufReader},
            net::TcpListener,
            sync::atomic::Ordering,
            thread,
            time::Duration,
        };
        use zdn::{
            client_gateway::{native, runtime},
            host::runtime::gateway::{self, Operation as GatewayOperation},
        };
        let fixture = Fixture::new(false);
        let root = fixture.root.path();
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        let metadata = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
        metadata
            .publish(
                "native-install-intent.json",
                &fixture.manifest.bytes().unwrap(),
                0o600,
            )
            .unwrap();
        fs::write(
            root.join("install-manifest.json"),
            fixture.manifest.bytes().unwrap(),
        )
        .unwrap();
        fixture.set("gatewayLoad", "FragmentPath=/etc/systemd/system/zdn-client-rpc.service\nDropInPaths=\nLoadState=loaded\n".into());
        fixture.set(
            "gatewayState",
            "ActiveState=failed\nSubState=failed\nMainPID=0\n".into(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = AtomicBool::new(false);
        let expected = native::observation(&fixture.manifest, "ready").unwrap();
        thread::scope(|scope| {
            let _shutdown = StopOnDrop(&stop);
            let stop = &stop;
            let body = expected.to_string();
            scope.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let mut input = BufReader::new(socket.try_clone().unwrap());
                            let mut line = String::new();
                            assert!(input.read_line(&mut line).unwrap() > 0);
                            assert_eq!(line, "GET /health HTTP/1.1\r\n");
                            loop {
                                line.clear();
                                if input.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                                    break;
                                }
                            }
                            write!(
                                socket,
                                "HTTP/1.1 200 RPC\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .unwrap();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
            });
            let run = |op| {
                gateway::dispatch(
                    &fixture.manifest,
                    Config {
                        root,
                        owner: fixture.owner,
                        node_owner: fixture.owner,
                    },
                    op,
                    endpoint,
                    &AtomicBool::new(false),
                )
            };
            assert_eq!(run(GatewayOperation::Install).unwrap().unwrap(), expected);
            assert_eq!(run(GatewayOperation::Observe).unwrap().unwrap(), expected);
            assert_eq!(run(GatewayOperation::Install).unwrap().unwrap(), expected);
            assert_eq!(
                fixture
                    .calls()
                    .lines()
                    .filter(|s| s.contains("\"start\",\"zdn-client-rpc.service\""))
                    .count(),
                1
            );
            let unit_path = root.join("etc/systemd/system/zdn-client-rpc.service");
            let unit_inode = unit_path.metadata().unwrap().ino();
            fixture.set(
                "gatewayState",
                "ActiveState=inactive\nSubState=dead\nMainPID=0\n".into(),
            );
            assert_eq!(
                run(GatewayOperation::Observe).unwrap().unwrap()["status"],
                "stopped"
            );
            // A responding endpoint is insufficient if systemd never made the
            // service active. In particular, do not reuse its pre-start state.
            fixture.set("gatewayStartStopped", true.into());
            assert!(run(GatewayOperation::Install).is_err());
            fixture.set("gatewayStartStopped", false.into());
            assert_eq!(run(GatewayOperation::Install).unwrap().unwrap(), expected);
            for malformed in [
                "ActiveState=active\nSubState=running\nMainPID=-1\n",
                "ActiveState=active\nSubState=running\nMainPID=37\nMainPID=38\n",
            ] {
                fixture.set("gatewayState", malformed.into());
                assert!(run(GatewayOperation::Observe).is_err());
            }
            fixture.set("gatewayLoad", "FragmentPath=/etc/systemd/system/zdn-client-rpc.service\nDropInPaths=/etc/foreign.conf\nLoadState=loaded\n".into());
            let calls = fixture
                .calls()
                .lines()
                .filter(|s| s.contains("\"enable\""))
                .count();
            assert!(run(GatewayOperation::Install).is_err());
            assert_eq!(
                fixture
                    .calls()
                    .lines()
                    .filter(|s| s.contains("\"enable\""))
                    .count(),
                calls
            );
            assert_eq!(unit_path.metadata().unwrap().ino(), unit_inode);
            assert!(!fixture.node().join("bootstrap-complete.json").exists());
            assert!(!fixture.node().join("producer-authorized.json").exists());
            assert!(
                !fs::read_to_string(root.join("etc/zdn/artifacts/worker-calls"))
                    .unwrap()
                    .contains("bootstrap")
            );
            // The health fetch is also usable directly and rejects cancellation.
            assert_eq!(
                runtime::health(
                    endpoint,
                    std::time::Instant::now() + Duration::from_secs(1),
                    &AtomicBool::new(false)
                )
                .unwrap(),
                expected
            );
            assert!(runtime::health(
                endpoint,
                std::time::Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true)
            )
            .is_err());
            // A selected node image changes neither the gateway recipe nor its
            // health identity. The old running image must nevertheless fail.
            fixture.set("gatewayLoad", "FragmentPath=/etc/systemd/system/zdn-client-rpc.service\nDropInPaths=\nLoadState=loaded\n".into());
            fixture.set(
                "gatewayState",
                "ActiveState=active\nSubState=running\nMainPID=37\n".into(),
            );
            let request = fixture.revision_fixture();
            {
                use zdn::host::runtime::revision::{self, Journal, Phase};
                let updates = metadata.open_directory(revision::NAMESPACE).unwrap();
                let mut guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
                let mut journal = Journal::open(&updates, &fixture.manifest, &mut guard).unwrap();
                journal.begin(&request).unwrap();
                journal.advance(request.update_id, Phase::Stopping).unwrap();
                journal
                    .advance(request.update_id, Phase::Activating)
                    .unwrap();
                journal.publish_active(request.update_id).unwrap();
            }
            assert!(run(GatewayOperation::Observe).is_err());
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("state.json")).unwrap()).unwrap();
            state["container"][0]["Config"]["Image"] = json!(request.image.image);
            fixture.set("container", state["container"].clone());
            assert_eq!(run(GatewayOperation::Observe).unwrap().unwrap(), expected);
            assert_eq!(unit_path.metadata().unwrap().ino(), unit_inode);
            assert!(!fixture.node().join("bootstrap-complete.json").exists());
            assert!(!fixture.node().join("producer-authorized.json").exists());
            fs::remove_file(root.join("etc/zdn/native-install-intent.json")).unwrap();
            let before = fixture.calls();
            assert!(run(GatewayOperation::Observe).is_err());
            assert_eq!(fixture.calls(), before);
            stop.store(true, Ordering::Relaxed);
        });
        #[cfg(feature = "profiling")]
        {
            trace.assert_spans(
                &[
                    "host.runtime.gateway.install",
                    "host.runtime.gateway.observe",
                    "host.runtime.gateway.health_gate",
                    "client_gateway.runtime.health",
                ],
                &[root.to_str().unwrap(), "PRIVATE-TOOL-DIAGNOSTIC"],
            );
            trace.assert_child(
                "client_gateway.runtime.health",
                "host.runtime.gateway.health_gate",
            );
        }
    }

    #[test]
    fn native_gateway_daemon_binds_manifest_identity_cookie_and_upstream_without_writes() {
        use std::{
            io::{BufRead, BufReader},
            net::TcpListener,
            sync::mpsc,
            thread,
            time::{Duration, Instant},
        };
        use zdn::{
            client_gateway::{native, runtime},
            host::runtime::gateway,
        };
        let mut fixture = Fixture::new(false);
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let old = native::upstream(&fixture.manifest).unwrap().to_string();
        fixture.manifest.spec.config_toml = fixture
            .manifest
            .spec
            .config_toml
            .replace(&old, &upstream.local_addr().unwrap().to_string());
        fixture.manifest.spec.config_sha256 =
            hex::encode(Sha256::digest(fixture.manifest.spec.config_toml.as_bytes()));
        fixture.manifest.install_sha256 = fixture.manifest.spec.install_sha256().unwrap();
        // Serve authenticates but does not execute the selected helper. Pin the
        // small real ELF fixture so hashing a full debug controller cannot use
        // up the loopback health deadline before the daemon starts accepting.
        fixture.manifest.runtime.helper = fixture.manifest.spec.helper.clone();
        let root = fixture.root.path();
        let runtime = root.join(format!(
            "etc/zdn/runtime/{}",
            fixture.manifest.runtime.helper.sha256
        ));
        fs::create_dir_all(&runtime).unwrap();
        fs::copy(root.join("etc/zdn/artifacts/zdn"), runtime.join("zdn")).unwrap();
        for name in [
            "etc/zdn/identity.json",
            "etc/zdn/volume-claimed.json",
            "var/lib/zdn/.zdn-volume.json",
        ] {
            fs::remove_file(root.join(name)).unwrap();
        }
        let metadata = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
        let installation = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
        let volume = Directory::open(&root.join("var/lib/zdn"), fixture.owner).unwrap();
        volume
            .publish(".zdn-volume.json", installation.identity(), 0o600)
            .unwrap();
        installation.record_volume_claim(&volume).unwrap();
        metadata
            .publish(
                "native-install-intent.json",
                &fixture.manifest.bytes().unwrap(),
                0o600,
            )
            .unwrap();
        let cookie = fixture.node().join("rpc/.cookie");
        let secret = format!("__cookie__:{}=", "N".repeat(43));
        fs::write(&cookie, &secret).unwrap();
        fs::set_permissions(cookie, fs::Permissions::from_mode(0o600)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            let _shutdown = StopOnDrop(&stop);
            let (tx, rx) = mpsc::channel();
            upstream.set_nonblocking(true).unwrap();
            scope.spawn(move || {
                let until = Instant::now() + Duration::from_secs(6);
                let (mut socket, _) = loop {
                    match upstream.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < until,
                                "gateway never contacted its pinned upstream"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut headers = String::new();
                let length = loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break headers
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                    }
                    headers.push_str(&line);
                };
                let mut body = vec![0; length];
                std::io::Read::read_exact(&mut reader, &mut body).unwrap();
                tx.send((
                    headers,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                ))
                .unwrap();
                let reply = r#"{"id":"zdn-health","result":{"blocks":69}}"#;
                write!(
                    socket,
                    "HTTP/1.1 200 RPC\r\nContent-Length: {}\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            });
            let daemon = scope.spawn(|| {
                gateway::serve(
                    &fixture.manifest,
                    Config {
                        root,
                        owner: fixture.owner,
                        node_owner: fixture.owner,
                    },
                    listener,
                    &stop,
                )
            });
            let report = runtime::health(
                endpoint,
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(report["nodeId"], fixture.manifest.spec.node_id);
            assert_eq!(
                report["serviceSha256"],
                native::service_sha256(&fixture.manifest).unwrap()
            );
            let (headers, call) = rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(headers.contains(&format!(
                "Authorization: Basic {}",
                STANDARD.encode(&secret)
            )));
            assert_eq!(call["method"], "getblockchaininfo");
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            daemon.join().unwrap().unwrap();
        });
        assert!(!root.join("etc/zdn/commands/gateway").exists());
        assert!(metadata.lock("install.lock").is_err());
    }

    #[test]
    fn first_native_install_stages_pins_and_starts_units_without_lock_deadlock() {
        #[cfg(feature = "profiling")]
        let Some(trace) = super::trace::capture("native_runtime::first_native_install_stages_pins_and_starts_units_without_lock_deadlock") else {
            return;
        };
        for producer in [false, true] {
            let fixture = Fixture::first_install(producer);
            let root = fixture.root.path();
            // Distro multicall tools dispatch on the invoked alias, not the
            // canonical target basename (iptables -> xtables-nft-multi).
            for name in ["iptables", "ip6tables"] {
                let alias = root.join("usr/bin").join(name);
                let target = alias.with_file_name(format!("multicall-{name}"));
                let script = fs::read_to_string(&alias).unwrap().replacen(
                    "#!/bin/sh\n",
                    &format!("#!/bin/sh\ncase \"$0\" in */{name}) ;; *) exit 42;; esac\n"),
                    1,
                );
                crate::executable::write(&alias, script).unwrap();
                fs::rename(&alias, &target).unwrap();
                symlink(target.file_name().unwrap(), &alias).unwrap();
            }
            let report = fixture.install().unwrap();
            assert_eq!(report["status"], "ready");
            assert_eq!(report["launchReady"], false);
            assert_eq!(report["paymentQualification"], "pending");
            let (node, controller) =
                zdn::host::runtime::install::units_for(&fixture.manifest).unwrap();
            assert_eq!(
                fs::read_to_string(root.join("etc/systemd/system/zdn-node.service")).unwrap(),
                node
            );
            assert!(!node.contains("python"));
            assert!(node.contains("Type=notify\nNotifyAccess=main\n"));
            for operation in ["prepare", "run", "ready", "stop"] {
                assert!(node.contains(&format!(
                    "{} {operation}\n",
                    fixture.manifest.file_name().unwrap()
                )));
            }
            if let Some(unit) = controller {
                assert_eq!(
                    fs::read_to_string(root.join("etc/systemd/system/zdn-producer.service"))
                        .unwrap(),
                    unit
                );
                for guard in [
                    "After=zdn-node.service\n",
                    "BindsTo=zdn-node.service\n",
                    "PartOf=zdn-node.service\n",
                    "ProtectSystem=strict",
                    "RuntimeDirectory=zdn-producer",
                    "RuntimeDirectoryMode=0700",
                    "KillSignal=SIGINT",
                    "KillMode=control-group",
                    "MemoryMax=128M",
                    "CPUQuota=10%",
                    "Type=exec",
                    "Restart=on-failure",
                ] {
                    assert!(unit.contains(guard));
                }
                assert!(unit.contains(&format!(
                    "ConditionPathExists={}/producer-authorized.json\n",
                    fixture.manifest.spec.node_root()
                )));
                assert!(unit.contains(&format!(
                    "ReadWritePaths={}/producer\n",
                    fixture.manifest.spec.node_root()
                )));
                assert!(node.contains("Wants=zdn-producer.service\n"));
                assert!(!fixture.node().join("producer-authorized.json").exists());
            } else {
                assert!(!root
                    .join("etc/systemd/system/zdn-producer.service")
                    .exists());
            }
            let identity = fs::read(root.join("etc/zdn/identity.json")).unwrap();
            assert_eq!(
                fs::read(root.join("var/lib/zdn/.zdn-volume.json")).unwrap(),
                identity
            );
            assert_eq!(
                fs::read(root.join("etc/zdn/native-install-intent.json")).unwrap(),
                fixture.manifest.bytes().unwrap()
            );
            let installed = root.join(format!(
                "etc/zdn/runtime/{}/zdn",
                fixture.manifest.runtime.helper.sha256
            ));
            assert_eq!(fs::metadata(&installed).unwrap().mode() & 0o777, 0o555);
            assert_eq!(
                hex::encode(Sha256::digest(fs::read(&installed).unwrap())),
                fixture.manifest.runtime.helper.sha256
            );
            let inode = fs::metadata(&installed).unwrap().ino();
            let calls = fixture.calls();
            for line in calls.lines() {
                let call: serde_json::Value = serde_json::from_str(line).unwrap();
                if call["tool"] == "systemctl"
                    && matches!(call["args"][0].as_str(), Some("enable" | "start"))
                {
                    assert!(!call["args"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("zdn-producer.service")));
                }
            }
            assert_eq!(
                calls
                    .lines()
                    .filter(|line| line.contains("get-object"))
                    .count(),
                5
            );
            let worker = root.join("etc/zdn/artifacts/worker-calls");
            let seeds = fs::read_to_string(&worker)
                .unwrap()
                .matches("bootstrap")
                .count();
            assert_eq!(seeds, 1);
            fixture.set("skipStartup", true.into());
            fixture.install().unwrap();
            assert_eq!(fs::metadata(&installed).unwrap().ino(), inode);
            assert_eq!(
                fixture
                    .calls()
                    .lines()
                    .filter(|line| line.contains("get-object"))
                    .count(),
                5
            );
            assert_eq!(
                fs::read_to_string(worker)
                    .unwrap()
                    .matches("bootstrap")
                    .count(),
                seeds
            );
            assert_eq!(
                fs::read(root.join("etc/zdn/identity.json")).unwrap(),
                identity
            );
            #[cfg(feature = "profiling")]
            {
                trace.assert_spans(
                    &[
                        "host.runtime.install.total",
                        "host.runtime.install.activate",
                        "host.runtime.install.verify",
                        "host.volume.acquire",
                    ],
                    &[
                        root.to_str().unwrap(),
                        "PRIVATE-TOOL-DIAGNOSTIC",
                        &fixture.manifest.spec.config_toml,
                    ],
                );
                trace.assert_child(
                    "host.runtime.install.activate",
                    "host.runtime.install.total",
                );
                trace.assert_child("host.volume.acquire", "host.runtime.install.verify");
            }
        }
    }

    #[test]
    fn first_native_install_rejects_changed_inputs_without_claiming_volume() {
        for name in ["manifest.json", "zdn", "image.json", "image-manifest.json"] {
            let fixture = Fixture::first_install(false);
            let root = fixture.root.path();
            let path = root.join("source-artifacts").join(name);
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, bytes).unwrap();

            let error = fixture.install().unwrap_err();
            assert_eq!(
                error.to_string(),
                "native host installation failed at stage artifact-delivery",
                "{name}"
            );
            for record in [
                "etc/zdn/format-intent.json",
                "etc/zdn/volume-claimed.json",
                "var/lib/zdn/.zdn-volume.json",
                "etc/systemd/system/zdn-node.service",
            ] {
                assert!(!root.join(record).exists(), "{name}: {record}");
            }
            assert!(fs::read_dir(root.join("var/lib/zdn"))
                .unwrap()
                .next()
                .is_none());
            assert!(!fixture.calls().contains("mkfs"));
        }
    }

    #[test]
    fn native_install_image_failure_reports_its_stage_without_claiming_volume() {
        let fixture = Fixture::first_install(false);
        fixture.set("failImagePull", true.into());
        let error = fixture.install().unwrap_err();
        assert_eq!(
            error.to_string(),
            "native host installation failed at stage image-delivery"
        );
        let diagnostic = format!("{error:#}");
        assert!(!diagnostic.contains("PRIVATE-TOOL-DIAGNOSTIC"));
        assert!(!diagnostic.contains("OFFLINE-PRIVATE-PASSWORD"));
        assert!(!fixture
            .root
            .path()
            .join("var/lib/zdn/.zdn-volume.json")
            .exists());
        assert!(!fixture
            .root
            .path()
            .join("etc/systemd/system/zdn-node.service")
            .exists());
    }

    #[test]
    fn native_installer_rejects_legacy_authority_and_recovers_only_exact_intent() {
        for phase in [
            "legacy-identity",
            "legacy-program",
            "foreign-intent",
            "unsafe-marker",
            "changed-runtime",
        ] {
            let mut fixture = Fixture::first_install(false);
            let root = fixture.root.path();
            match phase {
                "legacy-identity" => {
                    let directory = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
                    drop(Installation::acquire(&directory, &fixture.manifest.spec).unwrap());
                }
                "legacy-program" => {
                    fs::create_dir_all(root.join("usr/local/libexec")).unwrap();
                    fs::write(root.join("usr/local/libexec/zdn-host.py"), b"historical").unwrap();
                }
                "foreign-intent" => {
                    fs::write(
                        root.join("etc/zdn/native-install-intent.json"),
                        b"another manifest",
                    )
                    .unwrap();
                }
                "unsafe-marker" => fs::set_permissions(
                    root.join("etc/zdn-prerequisites-ready"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
                "changed-runtime" => fixture.manifest.runtime.helper.sha256 = "c".repeat(64),
                _ => unreachable!(),
            }
            assert!(fixture.install().is_err(), "{phase}");
            assert!(fixture.calls().is_empty(), "{phase}");
            assert!(!root.join("etc/systemd/system/zdn-node.service").exists());
        }
        let fixture = Fixture::first_install(true);
        let root = fixture.root.path();
        // Crash between durable native intent and original identity is safe
        // to finish forward. No legacy installation gets this intent silently.
        let metadata = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
        metadata
            .publish(
                "native-install-intent.json",
                &fixture.manifest.bytes().unwrap(),
                0o600,
            )
            .unwrap();
        fixture.set("failStart", true.into());
        let error = format!("{:#}", fixture.install().unwrap_err());
        assert!(error.starts_with("native host installation failed at stage service-activation"));
        assert!(!error.contains("PRIVATE-START-FAILURE"));
        assert!(root.join("etc/zdn/identity.json").exists());
        assert!(root.join("etc/systemd/system/zdn-node.service").exists());
        assert!(!fixture.node().join("bootstrap-complete.json").exists());
        fixture.set("failStart", false.into());
        fixture.install().unwrap();
        assert!(fixture.node().join("bootstrap-complete.json").exists());
        assert!(!fixture.node().join("producer-authorized.json").exists());
        assert!(!fixture.calls().contains("mkfs"));
    }

    #[test]
    fn bootstrap_worker() {
        use std::io::Read;
        let Some((work, args, payload)) = native_tool::invocation() else {
            return;
        };
        let root = Path::new(payload["root"].as_str().unwrap());
        let mut code = 0;
        let mut out = b"{}\n".to_vec();
        match payload["tool"].as_str().unwrap() {
            "aws" => {
                assert_eq!(&args[..2], ["s3api", "get-object"]);
                fs::write(
                    root.join("bootstrap-args.json"),
                    serde_json::to_vec(&args).unwrap(),
                )
                .unwrap();
                fs::copy(root.join("bootstrap-helper"), args.last().unwrap()).unwrap();
            }
            "helper" => {
                assert_eq!(args.last().unwrap(), zdn::host::runtime::INSTALL_PROTOCOL);
                if args[0] == "__runtime-capabilities" {
                    assert_eq!(args[1], "--require");
                    code = u8::from(root.join("unsupported").exists());
                } else {
                    assert_eq!(&args[..2], ["__host-install", "--protocol"]);
                    let mut stdin = Vec::new();
                    std::io::stdin().read_to_end(&mut stdin).unwrap();
                    fs::write(root.join("bootstrap-manifest"), stdin).unwrap();
                    if root.join("install-failure").exists() {
                        let mut child = Command::new(env!("CARGO_BIN_EXE_zdn"))
                            .args([
                                "__host-install",
                                "--protocol",
                                zdn::host::runtime::INSTALL_PROTOCOL,
                            ])
                            .env_clear()
                            .stdin(std::process::Stdio::piped())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .spawn()
                            .unwrap();
                        child
                            .stdin
                            .take()
                            .unwrap()
                            .write_all(b"PRIVATE-INSTALL-INPUT")
                            .unwrap();
                        let result = child.wait_with_output().unwrap();
                        assert!(!result.status.success());
                        code = 1;
                        out = result.stdout;
                    }
                }
                let args_file = root.join("bootstrap-args.json");
                if args_file.exists() {
                    let aws: Vec<String> =
                        serde_json::from_slice(&fs::read(args_file).unwrap()).unwrap();
                    let scratch = Path::new(aws.last().unwrap()).parent().unwrap();
                    assert_eq!(scratch.metadata().unwrap().mode() & 0o777, 0o700);
                    fs::write(root.join("bootstrap-scratch"), scratch.to_str().unwrap()).unwrap();
                }
            }
            _ => unreachable!(),
        }
        native_tool::reply(&work, &out, b"PRIVATE-BOOTSTRAP-DETAILS", code);
    }

    #[test]
    fn native_install_shell_verifies_runtime_before_passing_canonical_stdin() {
        for mode in [
            "valid",
            "bad-size",
            "bad-digest",
            "unsupported",
            "install-failure",
        ] {
            let fixture = Fixture::new(false);
            let root = fixture.root.path();
            let mut manifest = fixture.manifest.clone();
            let helper = root.join("bootstrap-helper");
            native_tool::install(
                &helper,
                "native_runtime::bootstrap_worker",
                &json!({"root":root,"tool":"helper"}),
            );
            let bytes = fs::read(helper).unwrap();
            manifest.runtime.helper.bytes = bytes.len() as u64;
            manifest.runtime.helper.sha256 = hex::encode(Sha256::digest(&bytes));
            if mode == "bad-size" {
                manifest.runtime.helper.bytes += 1;
            }
            if mode == "bad-digest" {
                manifest.runtime.helper.sha256 = "c".repeat(64);
            }
            if mode == "unsupported" {
                fs::write(root.join("unsupported"), b"").unwrap();
            }
            if mode == "install-failure" {
                fs::write(root.join("install-failure"), b"").unwrap();
            }
            native_tool::install(
                &root.join("usr/bin/aws"),
                "native_runtime::bootstrap_worker",
                &json!({"root":root,"tool":"aws"}),
            );
            let script = root.join("bootstrap.sh");
            fs::write(
                &script,
                zdn::host::runtime::bootstrap::render(&manifest).unwrap(),
            )
            .unwrap();
            let output = Command::new("/bin/bash")
                .arg(script)
                .env_clear()
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", root.join("usr/bin").display()),
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                mode == "valid",
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-BOOTSTRAP-DETAILS"));
            let args: Vec<String> =
                serde_json::from_slice(&fs::read(root.join("bootstrap-args.json")).unwrap())
                    .unwrap();
            for (flag, expected) in [
                ("--bucket", &manifest.runtime.helper.bucket),
                ("--key", &manifest.runtime.helper.key),
                (
                    "--expected-bucket-owner",
                    &manifest.runtime.helper.owner_account,
                ),
                ("--region", &manifest.runtime.helper.region),
            ] {
                let index = args.iter().position(|s| s == flag).unwrap();
                assert_eq!(&args[index + 1], expected);
            }
            assert!(!Path::new(args.last().unwrap()).parent().unwrap().exists());
            if matches!(mode, "valid" | "install-failure") {
                assert_eq!(
                    fs::read(root.join("bootstrap-manifest")).unwrap(),
                    manifest.bytes().unwrap()
                );
                if mode == "install-failure" {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
                        json!({"apiVersion":"zdn-host-install-failure/v1alpha1", "stage":"preflight"})
                    );
                }
            } else {
                assert!(!root.join("bootstrap-manifest").exists());
            }
        }
    }

    #[test]
    fn immutable_manifest_publication_binds_guard_name_and_original_records() {
        let fixture = Fixture::new(false);
        let metadata =
            Directory::open(&fixture.root.path().join("etc/zdn"), fixture.owner).unwrap();
        let guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
        let manifests = metadata.ensure_directory("manifests", 0o700).unwrap();
        let name = fixture.manifest.publish(&manifests, &guard).unwrap();
        let path = fixture.root.path().join("etc/zdn/manifests").join(&name);
        let inode = fs::metadata(&path).unwrap().ino();
        fixture.manifest.publish(&manifests, &guard).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert_eq!(
            Manifest::load(&manifests, &name).unwrap().install_sha256,
            fixture.manifest.install_sha256
        );
        let mut different = fixture.manifest.clone();
        different.spec.cpu_millis += 1;
        different.install_sha256 = different.spec.install_sha256().unwrap();
        assert!(different.publish(&manifests, &guard).is_err());
        manifests
            .publish("wrong.json", &fixture.manifest.bytes().unwrap(), 0o600)
            .unwrap();
        assert!(Manifest::load(&manifests, "wrong.json").is_err());
        fs::remove_file(&path).unwrap();
        symlink(
            fixture.root.path().join("etc/zdn/manifests/wrong.json"),
            &path,
        )
        .unwrap();
        assert!(Manifest::load(&manifests, &name).is_err());
        assert_eq!(
            fs::read(fixture.root.path().join("etc/zdn/identity.json")).unwrap(),
            guard.identity()
        );
    }

    #[test]
    fn observe_and_ready_use_fresh_native_gates_without_granting_authority() {
        let fixture = Fixture::new(true);
        let observation = fixture.run(Operation::Observe).unwrap().unwrap();
        assert_eq!(
            observation["effectiveLimits"]["nodeMemoryBytes"],
            8589934592u64
        );
        assert_eq!(observation["effectiveLimits"]["nodeCpuMillis"], 3375);
        assert_eq!(
            observation["installSha256"],
            fixture.manifest.install_sha256
        );
        assert_eq!(observation["scheduledProducer"], false);
        assert_eq!(observation["launchReady"], false);
        assert!(!fixture.node().join("bootstrap-complete.json").exists());
        assert!(!fixture.node().join("producer-authorized.json").exists());
        fixture.run(Operation::Ready).unwrap();
        assert!(fixture.node().join("bootstrap-complete.json").exists());
        let calls =
            fs::read_to_string(fixture.root.path().join("etc/zdn/artifacts/worker-calls")).unwrap();
        assert_eq!(calls.matches("chain\0bootstrap\0").count(), 1);
        fixture.run(Operation::Ready).unwrap();
        let calls =
            fs::read_to_string(fixture.root.path().join("etc/zdn/artifacts/worker-calls")).unwrap();
        assert_eq!(calls.matches("chain\0bootstrap\0").count(), 1);
        assert!(calls.contains("--rpc-endpoint\x00127.0.0.2:18339\0--cookie-file"));
        assert_eq!(calls.matches("chain\0wait-rpc\0").count(), 3);
        fixture.set("mounted", json!(false));
        assert!(fixture.run(Operation::Observe).is_err());
        assert!(!fixture.node().join("producer-authorized.json").exists());
    }

    #[test]
    fn revision_selection_blocks_partial_startup_and_preserves_original_bootstrap() {
        use zdn::host::runtime::revision::{self, Journal, Phase};
        let fixture = Fixture::first_install(true);
        fixture.install().unwrap();
        let original_identity =
            fs::read(fixture.root.path().join("etc/zdn/identity.json")).unwrap();
        let marker = fs::read(fixture.node().join("bootstrap-complete.json")).unwrap();
        let request = fixture.revision_fixture();
        assert_ne!(request.image.image, fixture.manifest.spec.image);
        let metadata =
            Directory::open(&fixture.root.path().join("etc/zdn"), fixture.owner).unwrap();
        let updates = metadata.open_directory(revision::NAMESPACE).unwrap();
        {
            let mut guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
            Journal::open(&updates, &fixture.manifest, &mut guard)
                .unwrap()
                .begin(&request)
                .unwrap();
        }
        assert_eq!(
            fixture.run(Operation::Observe).unwrap().unwrap()["image"],
            fixture.manifest.spec.image
        );
        let calls = fixture.calls();
        assert!(fixture
            .install()
            .unwrap_err()
            .to_string()
            .contains("native image update"));
        assert_eq!(fixture.calls(), calls);
        for phase in [Phase::Stopping, Phase::Activating] {
            {
                let mut guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
                Journal::open(&updates, &fixture.manifest, &mut guard)
                    .unwrap()
                    .advance(request.update_id, phase)
                    .unwrap();
            }
            let calls = fixture.calls();
            for operation in [
                Operation::Prepare,
                Operation::Run,
                Operation::Ready,
                Operation::StartProducer,
                Operation::Produce,
            ] {
                assert!(fixture.run(operation).is_err(), "{phase:?}: {operation:?}");
            }
            assert_eq!(fixture.calls(), calls);
        }
        {
            let mut guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
            Journal::open(&updates, &fixture.manifest, &mut guard)
                .unwrap()
                .publish_active(request.update_id)
                .unwrap();
        }
        // Neither a cached helper response nor a new journal qualifies the old image.
        assert!(fixture.run(Operation::Observe).is_err());
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("state.json")).unwrap())
                .unwrap();
        state["container"][0]["Config"]["Image"] = json!(request.image.image);
        state["image"][0]["Id"] = json!(request.image.config_digest);
        state["image"][0]["RepoDigests"] = json!([request.image.image]);
        fixture.set("container", state["container"].clone());
        fixture.set("image", state["image"].clone());
        let observation = fixture.run(Operation::Observe).unwrap().unwrap();
        assert_eq!(observation["image"], request.image.image);
        assert_eq!(observation["updateId"], request.update_id.to_string());
        assert_eq!(
            observation["installSha256"],
            fixture.manifest.install_sha256
        );
        assert_eq!(
            fs::read(fixture.root.path().join("etc/zdn/identity.json")).unwrap(),
            original_identity
        );
        assert_eq!(
            fs::read(fixture.node().join("bootstrap-complete.json")).unwrap(),
            marker
        );
        assert!(fixture.run(Operation::StartProducer).is_err());
        fixture.run(Operation::Ready).unwrap();
        let helper_calls =
            fs::read_to_string(fixture.root.path().join("etc/zdn/artifacts/worker-calls")).unwrap();
        assert_eq!(helper_calls.matches("chain\0bootstrap\0").count(), 1);
        fs::remove_file(fixture.node().join("bootstrap-complete.json")).unwrap();
        assert!(fixture.run(Operation::Ready).is_err());
        assert!(!fixture.node().join("bootstrap-complete.json").exists());
        let after =
            fs::read_to_string(fixture.root.path().join("etc/zdn/artifacts/worker-calls")).unwrap();
        assert_eq!(after, helper_calls);
        fs::write(fixture.node().join("bootstrap-complete.json"), marker).unwrap();
        fs::remove_file(
            fixture
                .root
                .path()
                .join("etc/zdn/native-install-intent.json"),
        )
        .unwrap();
        let before = fixture.calls();
        assert!(fixture.run(Operation::Observe).is_err());
        assert_eq!(fixture.calls(), before);
    }

    #[test]
    fn revision_executor_preserves_identity_units_and_never_authorizes_production() {
        use zdn::host::runtime::revision::{Phase, Snapshot};
        for producer in [false, true] {
            let (fixture, request) = Fixture::updater(producer);
            let root = fixture.root.path();
            let identity = fs::read(root.join("etc/zdn/identity.json")).unwrap();
            let marker = fs::read(fixture.node().join("bootstrap-complete.json")).unwrap();
            let unit = fs::read(root.join("etc/systemd/system/zdn-node.service")).unwrap();
            let report = fixture.update(&request).unwrap();
            assert_eq!(report["image"], request.image.image);
            assert_eq!(report["installSha256"], fixture.manifest.install_sha256);
            assert_eq!(report["updateId"], request.update_id.to_string());
            assert_eq!(report["scheduledProducer"], false);
            assert_eq!(report["launchReady"], false);
            let metadata = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
            let snapshot = Snapshot::from_installation(&metadata, &fixture.manifest)
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.transaction.unwrap().phase, Phase::Done);
            assert!(!snapshot.producer_hold);
            assert!(!fixture.node().join("producer-authorized.json").exists());
            assert_eq!(
                fs::read(root.join("etc/zdn/identity.json")).unwrap(),
                identity
            );
            assert_eq!(
                fs::read(fixture.node().join("bootstrap-complete.json")).unwrap(),
                marker
            );
            assert_eq!(
                fs::read(root.join("etc/systemd/system/zdn-node.service")).unwrap(),
                unit
            );
            let before = fixture
                .calls()
                .lines()
                .filter(|line| line.contains("\"start\"") || line.contains("\"stop\""))
                .count();
            fixture.update(&request).unwrap();
            assert_eq!(
                fixture
                    .calls()
                    .lines()
                    .filter(|line| line.contains("\"start\"") || line.contains("\"stop\""))
                    .count(),
                before
            );
            let helper = fs::read_to_string(root.join("etc/zdn/artifacts/worker-calls")).unwrap();
            assert_eq!(helper.matches("chain\0bootstrap\0").count(), 1);
        }
    }

    #[test]
    fn revision_executor_stages_before_downtime_and_recovers_forward_after_failures() {
        use zdn::host::runtime::revision::{Phase, Snapshot};
        for failure in ["metadata", "failStop", "failStart"] {
            let (fixture, request) = Fixture::updater(true);
            let root = fixture.root.path();
            let target = root
                .join("etc/zdn/native-updates")
                .join(request.update_id.to_string())
                .join("image-config.json");
            let bytes = fs::read(&target).unwrap();
            if failure == "metadata" {
                fs::write(&target, b"unsafe retained metadata").unwrap();
            } else {
                fixture.set(failure, true.into());
            }
            let error = format!("{:#}", fixture.update(&request).unwrap_err());
            assert!(!error.contains("PRIVATE-"));
            let metadata = Directory::open(&root.join("etc/zdn"), fixture.owner).unwrap();
            let snapshot = Snapshot::from_installation(&metadata, &fixture.manifest)
                .unwrap()
                .unwrap();
            let expected = match failure {
                "metadata" => Phase::Staging,
                "failStop" => Phase::Stopping,
                _ => Phase::Activating,
            };
            assert_eq!(snapshot.transaction.unwrap().phase, expected);
            assert_eq!(snapshot.producer_hold, failure != "metadata");
            assert_eq!(snapshot.active.is_some(), failure == "failStart");
            assert!(!fixture.node().join("producer-authorized.json").exists());
            if failure == "metadata" {
                assert!(fixture
                    .calls()
                    .lines()
                    .all(|line| !line.contains("\"stop\"")));
                fs::write(target, bytes).unwrap();
            } else {
                fixture.set(failure, false.into());
            }
            let report = fixture.update(&request).unwrap();
            assert_eq!(report["image"], request.image.image);
            assert!(
                !Snapshot::from_installation(&metadata, &fixture.manifest)
                    .unwrap()
                    .unwrap()
                    .producer_hold
            );
        }
    }

    #[test]
    fn revision_executor_reholds_failed_authorized_restart_then_reuses_original_journal() {
        #[cfg(feature = "profiling")]
        let Some(trace) = super::trace::capture("native_runtime::revision_executor_reholds_failed_authorized_restart_then_reuses_original_journal") else {
            return;
        };
        use fs2::FileExt;
        use zdn::{
            chain::producer::{ProducerIdentity, ProducerJournal, ProducerPhase},
            host::runtime::revision::{Phase, Snapshot},
        };
        let (fixture, request) = Fixture::updater(true);
        let node = Directory::open(&fixture.node(), fixture.owner).unwrap();
        node.publish(
            "producer-authorized.json",
            &producer::authorization(&fixture.manifest.spec).unwrap(),
            0o600,
        )
        .unwrap();
        let state = fixture.node().join("producer");
        let lock = fs::File::create(state.join("controller.lock")).unwrap();
        fs::set_permissions(
            state.join("controller.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        lock.lock_exclusive().unwrap();
        let journal = ProducerJournal {
            api_version: zdn::chain::producer::API_VERSION.into(),
            identity: ProducerIdentity {
                deployment_id: fixture.manifest.spec.deployment_id,
                node_id: "node-1".into(),
                consensus_fingerprint: fixture.manifest.spec.consensus_fingerprint.clone(),
            },
            owner_pid: std::process::id(),
            owner_session: Uuid::new_v4(),
            phase: ProducerPhase::Waiting,
            interval_secs: 37,
            last_confirmed_tip: None,
            pending: None,
            confirmed_blocks: 0,
        };
        let journal_bytes = serde_json::to_vec(&journal).unwrap();
        fs::write(state.join("journal.json"), &journal_bytes).unwrap();
        fs::set_permissions(
            state.join("journal.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fixture.set(
            "startedService",
            json!(format!(
                "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID={}\n",
                std::process::id()
            )),
        );
        fixture.set("failProducerStart", true.into());
        assert!(fixture.update(&request).is_err());
        let metadata =
            Directory::open(&fixture.root.path().join("etc/zdn"), fixture.owner).unwrap();
        let snapshot = Snapshot::from_installation(&metadata, &fixture.manifest)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.transaction.unwrap().phase, Phase::Ready);
        assert!(snapshot.producer_hold);
        assert!(fixture.run(Operation::StartProducer).is_err());
        fixture.set("failProducerStart", false.into());
        let report = fixture.update(&request).unwrap();
        assert_eq!(report["scheduledProducer"], true);
        assert_eq!(fs::read(state.join("journal.json")).unwrap(), journal_bytes);
        let snapshot = Snapshot::from_installation(&metadata, &fixture.manifest)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.transaction.unwrap().phase, Phase::Done);
        assert!(!snapshot.producer_hold);
        #[cfg(feature = "profiling")]
        {
            trace.assert_spans(
                &[
                    "host.runtime.update.dispatch",
                    "host.runtime.update.stage",
                    "host.runtime.update.stop",
                    "host.runtime.update.activate",
                    "host.runtime.update.readiness",
                    "host.runtime.update.observe",
                    "host.runtime.update.producer_restart",
                    "host.runtime.update.failure_maintenance",
                    "host.producer.start",
                ],
                &[
                    fixture.root.path().to_str().unwrap(),
                    &request.update_id.to_string(),
                    "PRIVATE-TOOL-DIAGNOSTIC",
                    "PRIVATE-START-FAILURE",
                ],
            );
            for phase in [
                "stage",
                "stop",
                "activate",
                "readiness",
                "producer_restart",
                "failure_maintenance",
            ] {
                trace.assert_child(
                    &format!("host.runtime.update.{phase}"),
                    "host.runtime.update.dispatch",
                );
            }
            trace.assert_child(
                "host.producer.start",
                "host.runtime.update.producer_restart",
            );
        }
    }

    #[test]
    fn revision_executor_rejects_foreign_effective_units_and_missing_native_intent() {
        let (fixture, request) = Fixture::updater(false);
        let root = fixture.root.path();
        fixture.set("updateDropIns", "/etc/systemd/system/foreign.conf".into());
        assert!(fixture.update(&request).is_err());
        let state = root.join("etc/zdn/native-updates/state.json");
        assert!(!state.exists());
        assert!(fixture
            .calls()
            .lines()
            .all(|line| !line.contains("\"stop\"")));
        fixture.set("updateDropIns", "".into());
        fs::remove_file(root.join("etc/zdn/native-install-intent.json")).unwrap();
        let before = fixture.calls();
        assert!(fixture.update(&request).is_err());
        assert_eq!(fixture.calls(), before);
        assert!(!state.exists());
        let capability = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args([
                "__runtime-capabilities",
                "--require",
                zdn::host::runtime::update::PROTOCOL,
            ])
            .output()
            .unwrap();
        assert!(capability.status.success());
        let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args([
                "__host-update",
                "--protocol",
                zdn::host::runtime::update::PROTOCOL,
                "--manifest",
                "/tmp/PRIVATE-UPDATE-MANIFEST.json",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("native image update failed"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-UPDATE"));
    }

    #[test]
    fn install_reuses_authenticated_running_helper_only_for_both_matching_pins() {
        for mismatch in [None, Some("bytes"), Some("sha256")] {
            let mut fixture = Fixture::first_install(false);
            fixture.manifest.spec.helper.bytes = fixture.manifest.runtime.helper.bytes;
            fixture.manifest.spec.helper.sha256 = fixture.manifest.runtime.helper.sha256.clone();
            match mismatch {
                Some("bytes") => fixture.manifest.spec.helper.bytes -= 1,
                Some("sha256") => fixture.manifest.spec.helper.sha256 = "a".repeat(64),
                _ => {}
            }
            fixture.manifest.install_sha256 = fixture.manifest.spec.install_sha256().unwrap();
            // Stop at tool authentication, after trusted local publication but
            // before downloads or host effects. Differing pins must not stage
            // running bytes as the chain helper; the normal install test
            // exercises their five-object fetch path.
            fs::set_permissions(
                fixture.root.path().join("usr/bin/aws"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap();
            assert!(fixture.install().is_err());
            let helper = fixture.root.path().join("etc/zdn/artifacts/zdn");
            if mismatch.is_none() {
                assert_eq!(
                    fs::read(&helper).unwrap(),
                    fs::read(env!("CARGO_BIN_EXE_zdn")).unwrap()
                );
                assert_eq!(fs::metadata(helper).unwrap().mode() & 0o777, 0o555);
            } else {
                assert!(!helper.exists());
            }
            assert!(fixture.calls().is_empty());
        }
    }

    #[test]
    fn prepare_retains_owned_data_and_rejects_a_disappearing_mount() {
        let fixture = Fixture::new(false);
        fs::write(
            fixture.node().join("state/retained"),
            b"retained chain data",
        )
        .unwrap();
        fixture.run(Operation::Prepare).unwrap();
        assert_eq!(
            fs::read(fixture.node().join("state/retained")).unwrap(),
            b"retained chain data"
        );
        assert!(!fixture.calls().contains("mkfs.ext4"));
        fixture.set("mounted", json!(false));
        assert!(fixture.run(Operation::Prepare).is_err());
        assert!(!fixture.calls().contains("mkfs.ext4"));
        assert!(!fixture
            .root
            .path()
            .join("etc/zdn/format-intent.json")
            .exists());
    }

    #[test]
    fn stop_requires_controller_shutdown_and_trusted_tool_but_not_chain_artifacts() {
        let fixture = Fixture::new(true);
        fs::remove_dir_all(fixture.root.path().join("etc/zdn/artifacts")).unwrap();
        fixture.set("failStop", json!(true));
        let error = fixture.run(Operation::Stop).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-TOOL-DIAGNOSTIC"));
        assert!(!fixture.calls().contains("docker"));
        fixture.set("failStop", json!(false));
        fixture.run(Operation::Stop).unwrap();
        assert!(fixture.calls().contains("docker"));
        fs::set_permissions(
            fixture.root.path().join("usr/bin/docker"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(fixture.run(Operation::Stop).is_err());
        fs::remove_file(fixture.root.path().join("usr/bin/docker")).unwrap();
        symlink("/bin/true", fixture.root.path().join("usr/bin/docker")).unwrap();
        assert!(fixture.run(Operation::Stop).is_err());
    }

    #[test]
    fn tool_aliases_require_trusted_intermediate_directories() {
        let fixture = Fixture::new(true);
        let root = fixture.root.path();
        let alias = root.join("usr/bin/docker");
        fs::rename(&alias, alias.with_file_name("docker-real")).unwrap();
        let alternatives = root.join("etc/alternatives");
        fs::create_dir(&alternatives).unwrap();
        symlink("../../usr/bin/docker-real", alternatives.join("docker")).unwrap();
        symlink(alternatives.join("docker"), &alias).unwrap();
        fixture.run(Operation::Stop).unwrap();
        // The final executable stays trusted; the alias route must be too.
        fs::set_permissions(&alternatives, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(fixture.run(Operation::Stop).is_err());
    }

    #[test]
    fn control_rejects_changed_runtime_identity_and_cancelled_work_before_tools() {
        let mut fixture = Fixture::new(false);
        fixture.manifest.runtime.helper.bytes -= 1;
        assert!(fixture.run(Operation::Stop).is_err());
        assert!(fixture.calls().is_empty());
        let fixture = Fixture::new(false);
        fs::remove_file(fixture.root.path().join("etc/zdn/identity.json")).unwrap();
        assert!(fixture.run(Operation::Stop).is_err());
        assert!(!fixture.root.path().join("etc/zdn/identity.json").exists());
        assert!(fixture.calls().is_empty());
        assert!(control::dispatch(
            &fixture.manifest,
            Config {
                root: fixture.root.path(),
                owner: fixture.owner,
                node_owner: fixture.owner
            },
            Operation::Stop,
            &AtomicBool::new(true)
        )
        .is_err());
        assert!(fixture.calls().is_empty());
    }

    #[test]
    fn native_exec_worker() {
        let Some(root) = std::env::var_os("ZDN_RUNTIME_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        #[cfg(feature = "profiling")]
        {
            use std::{os::unix::fs::OpenOptionsExt, sync::Mutex};
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("preflight-trace.jsonl"))
                .unwrap();
            tracing_subscriber::fmt()
                .json()
                .with_writer(Mutex::new(file))
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .try_init()
                .unwrap();
        }
        let manifest =
            Manifest::from_slice(&fs::read(root.join("exec-manifest.json")).unwrap()).unwrap();
        let operation = if std::env::var_os("ZDN_RUNTIME_PRODUCE").is_some() {
            Operation::Produce
        } else {
            Operation::Run
        };
        control::dispatch(
            &manifest,
            Config {
                root: &root,
                owner: fs::metadata(&root).unwrap().uid(),
                node_owner: fs::metadata(&root).unwrap().uid(),
            },
            operation,
            &AtomicBool::new(false),
        )
        .unwrap();
        panic!("exec returned");
    }

    #[test]
    fn producer_activation_requires_bootstrap_then_fresh_lock_and_owner_observation() {
        use fs2::FileExt;
        use zdn::chain::producer::{ProducerIdentity, ProducerJournal, ProducerPhase};
        let fixture = Fixture::new(true);
        assert!(fixture.run(Operation::StartProducer).is_err());
        assert!(!fixture.node().join("producer-authorized.json").exists());
        assert!(!fixture.calls().contains("\"start\""));
        fixture.run(Operation::Ready).unwrap();
        let state = fixture.node().join("producer");
        let lock = fs::File::create(state.join("controller.lock")).unwrap();
        fs::set_permissions(
            state.join("controller.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        lock.lock_exclusive().unwrap();
        let journal = ProducerJournal {
            api_version: zdn::chain::producer::API_VERSION.into(),
            identity: ProducerIdentity {
                deployment_id: fixture.manifest.spec.deployment_id,
                node_id: "node-1".into(),
                consensus_fingerprint: fixture.manifest.spec.consensus_fingerprint.clone(),
            },
            owner_pid: std::process::id(),
            owner_session: Uuid::new_v4(),
            phase: ProducerPhase::Waiting,
            interval_secs: 37,
            last_confirmed_tip: None,
            pending: None,
            confirmed_blocks: 0,
        };
        fs::write(
            state.join("journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            state.join("journal.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fixture.set(
            "startedService",
            json!(format!(
                "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID={}\n",
                std::process::id()
            )),
        );
        let observation = fixture.run(Operation::StartProducer).unwrap().unwrap();
        assert_eq!(observation["scheduledProducer"], true);
        assert_eq!(observation["producer"]["intervalSecs"], 37);
        assert_eq!(
            fs::read(fixture.node().join("producer-authorized.json")).unwrap(),
            producer::authorization(&fixture.manifest.spec).unwrap()
        );
        assert!(fixture.calls().contains("reset-failed"));
        // An active retry neither clears failure state nor resubmits seeds.
        fs::remove_file(fixture.root.path().join("calls")).unwrap();
        fixture.run(Operation::StartProducer).unwrap();
        assert!(!fixture.calls().contains("reset-failed"));
        let calls =
            fs::read_to_string(fixture.root.path().join("etc/zdn/artifacts/worker-calls")).unwrap();
        assert_eq!(calls.matches("chain\0bootstrap\0").count(), 1);
    }

    #[test]
    fn executable_capability_is_distinct_from_permission_to_control_a_host() {
        let capability = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args(["__runtime-capabilities", "--require", PROTOCOL])
            .output()
            .unwrap();
        assert!(capability.status.success());
        let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args([
                "__host-runtime",
                "--protocol",
                PROTOCOL,
                "--manifest",
                "/tmp/PRIVATE-MANIFEST.json",
                "observe",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("native host operation failed"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-MANIFEST"));
    }

    #[test]
    fn final_exec_preserves_pid_and_environment_without_inheriting_install_lock() {
        for produce in [false, true] {
            let fixture = Fixture::new(produce);
            let metadata =
                Directory::open(&fixture.root.path().join("etc/zdn"), fixture.owner).unwrap();
            let guard = Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
            let child_output = if produce {
                let node = Directory::open(&fixture.node(), fixture.owner).unwrap();
                node.publish(
                    "producer-authorized.json",
                    &producer::authorization(&fixture.manifest.spec).unwrap(),
                    0o600,
                )
                .unwrap();
                // No archive reads are permitted in the small producer service.
                fs::remove_file(fixture.root.path().join("etc/zdn/artifacts/chain.tar")).unwrap();
                fixture.root.path().join("etc/zdn/artifacts")
            } else {
                drop(guard);
                fs::write(fixture.root.path().join("usr/bin/docker"), chain_helper()).unwrap();
                fixture.root.path().join("usr/bin")
            };
            fs::write(
                fixture.root.path().join("exec-manifest.json"),
                fixture.manifest.bytes().unwrap(),
            )
            .unwrap();
            let notify_path = fixture.root.path().join("notify.sock");
            let notify = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
            notify
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "native_runtime::native_exec_worker",
                    "--nocapture",
                ])
                .env("ZDN_RUNTIME_FIXTURE", fixture.root.path())
                .env("NOTIFY_SOCKET", &notify_path)
                .env("AWS_SECRET_ACCESS_KEY", "PRIVATE-INHERITED-KEY");
            if produce {
                command.env("ZDN_RUNTIME_PRODUCE", "1");
            }
            let child = command.spawn().unwrap();
            let pid = child.id();
            assert!(child.wait_with_output().unwrap().status.success());
            let mut notification = [0; 64];
            let received = notify.recv(&mut notification);
            if produce {
                assert!(received.is_err(), "producer must not release node startup");
            } else {
                assert_eq!(&notification[..received.unwrap()], b"READY=1");
            }
            #[cfg(feature = "profiling")]
            {
                let trace =
                    fs::read_to_string(fixture.root.path().join("preflight-trace.jsonl")).unwrap();
                assert!(
                    trace.lines().any(|line| {
                        let record: serde_json::Value = serde_json::from_str(line).unwrap();
                        record["span"]["name"] == "host.runtime.control.dispatch"
                            && record["fields"]["message"] == "close"
                    }),
                    "preflight must close before successful exec"
                );
                assert!(!trace.contains("PRIVATE-INHERITED-KEY"));
                assert!(!trace.contains(fixture.root.path().to_str().unwrap()));
            }
            assert_eq!(
                fs::read_to_string(child_output.join("worker-pid")).unwrap(),
                pid.to_string()
            );
            let environment = fs::read_to_string(child_output.join("worker-env")).unwrap();
            assert!(!environment.contains("PRIVATE-INHERITED-KEY"));
            assert!(!environment.contains("ZDN_RUNTIME_FIXTURE"));
            assert!(!environment.contains("NOTIFY_SOCKET"));
            assert!(environment.contains("AWS_MAX_ATTEMPTS"));
            let calls = fs::read_to_string(child_output.join("worker-calls")).unwrap();
            if produce {
                assert!(calls.contains("--interval-secs\x0037\0--request-timeout-secs\x0010"));
                assert!(!fixture
                    .root
                    .path()
                    .join("etc/zdn/commands/produce")
                    .exists());
            } else {
                assert!(calls.starts_with("run\0--rm\0--name\0zdn-"));
                Installation::acquire(&metadata, &fixture.manifest.spec).unwrap();
            }
        }
    }
}
