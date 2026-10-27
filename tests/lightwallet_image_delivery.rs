#![cfg(target_os = "linux")]
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{symlink, MetadataExt},
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use zdn::{
    host::{command::Executor, files::Directory, NewVolumeAuthorization},
    lightwallet_image as image,
    lightwallet_service::{image_delivery::*, LightwalletInstallSpec, INSTALL_API_VERSION},
};
#[path = "support/executable.rs"]
mod executable;
#[path = "support/lightwallet_service.rs"]
mod fixture;
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

struct Fixture {
    root: tempfile::TempDir,
    dir: Directory,
    spec: LightwalletInstallSpec,
    executor: Executor,
    tools: Tools,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
        dir.ensure_directory("artifacts", 0o700).unwrap();
        dir.ensure_directory("commands", 0o700).unwrap();
        dir.ensure_directory("scratch", 0o700).unwrap();
        let (host, mut service) = fixture::specs();
        let runtime = json!({"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Entrypoint":["lightwalletd"],"Cmd":["--help"],"WorkingDir":"/srv/lightwalletd"});
        let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux","config":runtime,"rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","b".repeat(64))]},"padding":"x".repeat(196739)})).unwrap();
        let digest = |bytes: &[u8]| format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config),"size":config.len()},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","c".repeat(64)),"size":1234}]})).unwrap();
        service.image = format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/lightwalletd@{}",
            digest(&manifest)
        );
        let record = serde_json::to_vec(&image::ImageRecord {
            api_version: image::API_VERSION.into(),
            image: service.image.clone(),
            config_digest: digest(&config),
            platform: "linux/amd64".into(),
            source_revision: image::SOURCE_REVISION.into(),
            source_version: image::SOURCE_VERSION.into(),
            protocol_revision: image::PROTOCOL_REVISION.into(),
            protocol_version: image::PROTOCOL_VERSION.into(),
            binary_path: image::BINARY_PATH.into(),
            environment_launcher: image::ENVIRONMENT_LAUNCHER.into(),
        })
        .unwrap();
        let inspect = json!([{"Id":digest(&config),"RepoDigests":[service.image],"Os":"linux","Architecture":"amd64","Config":runtime}]);
        fs::write(root.path().join("inspection"), inspect.to_string()).unwrap();
        let object = |name: &str, bytes: &[u8]| {
            fs::write(root.path().join(name), bytes).unwrap();
            let mut pin = host.helper.clone();
            pin.key = format!("team/test/{name}");
            pin.bytes = bytes.len() as u64;
            pin.sha256 = hex::encode(Sha256::digest(bytes));
            pin
        };
        let spec = LightwalletInstallSpec {
            api_version: INSTALL_API_VERSION.into(),
            image_record: object("record", &record),
            image_manifest: object("manifest", &manifest),
            image_config: object("config", &config),
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
        };
        let tools = Tools {
            aws: root.path().join("aws"),
            docker: root.path().join("docker"),
        };
        for tool in [&tools.aws, &tools.docker] {
            native_tool::install(
                tool,
                "tool_worker",
                &json!({"root":root.path(),"mode":mode,"image":spec.service.image}),
            );
        }
        let executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            root.path().join("commands"),
            "us-east-1".into(),
            Instant::now() + Duration::from_secs(90),
        )
        .unwrap();
        let dir = dir.open_directory("artifacts").unwrap();
        Self {
            root,
            dir,
            spec,
            executor,
            tools,
        }
    }
    fn fetch(&mut self, kind: Artifact) -> eyre::Result<()> {
        fetch_artifact(
            &self.spec,
            kind,
            &self.dir,
            &self.tools.aws,
            &mut self.executor,
            &AtomicBool::new(false),
        )
    }
    fn all(&mut self) {
        for kind in [
            Artifact::ImageRecord,
            Artifact::ImageManifest,
            Artifact::ImageConfig,
        ] {
            self.fetch(kind).unwrap();
        }
    }
    fn pull(&mut self) -> eyre::Result<image::ImageValidationReport> {
        pull_image(
            &self.spec,
            &self.dir,
            &self.root.path().join("scratch"),
            &self.tools,
            &mut self.executor,
            &AtomicBool::new(false),
        )
    }
    fn clean(&self) {
        assert_eq!(
            fs::read_dir(self.root.path().join("scratch"))
                .unwrap()
                .count(),
            0
        );
        assert!(fs::read_dir(self.root.path().join("artifacts"))
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.')));
    }
}

#[test]
fn tool_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .unwrap();
    use std::io::Write;
    writeln!(log, "{}", args.join(" ")).unwrap();
    if args[0] == "s3api" {
        assert_eq!(
            &args[..4],
            &["s3api", "get-object", "--bucket", "zdn-artifacts-test"]
        );
        assert_eq!(
            &args[6..12],
            &[
                "--expected-bucket-owner",
                "123456789012",
                "--region",
                "us-east-1",
                "--output",
                "json"
            ]
        );
        let name = args[5].strip_prefix("team/test/").unwrap();
        let mut bytes = fs::read(root.join(name)).unwrap();
        let size = bytes.len();
        if mode == "bad-hash" {
            bytes[0] ^= 1;
        }
        fs::write(&args[12], bytes).unwrap();
        native_tool::reply(
            &work,
            json!({"ContentLength":if mode=="bad-size" {size+1} else {size}})
                .to_string()
                .as_bytes(),
            b"",
            0,
        );
    } else if args[0] == "ecr" {
        assert_eq!(args, ["ecr", "get-login-password", "--region", "us-east-1"]);
        native_tool::reply(&work, b"private-password\n", b"", 0);
    } else if args[0] == "--config" {
        let credentials = Path::new(&args[1]);
        assert_eq!(credentials.metadata().unwrap().mode() & 0o777, 0o700);
        if args[2] == "login" {
            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password).unwrap();
            assert_eq!(password, "private-password\n");
            assert_eq!(
                &args[3..],
                &[
                    "--username",
                    "AWS",
                    "--password-stdin",
                    "123456789012.dkr.ecr.us-east-1.amazonaws.com"
                ]
            );
            fs::write(credentials.join("config.json"), "private-password").unwrap();
        } else {
            assert_eq!(&args[2..5], &["pull", "--platform", "linux/amd64"]);
            assert_eq!(args[5], payload["image"]);
            if mode == "stall" {
                fs::write(root.join("started"), b"").unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            if mode == "cleanup-fail" {
                fs::remove_dir_all(credentials).unwrap();
                fs::write(credentials, b"obstruct cleanup").unwrap();
            }
        }
        native_tool::reply(
            &work,
            b"",
            b"",
            if mode == "login-fail" || (mode == "pull-fail" && args[2] == "pull") {
                1
            } else {
                0
            },
        );
    } else {
        assert_eq!(
            args,
            ["image", "inspect", payload["image"].as_str().unwrap()]
        );
        assert_eq!(fs::read_dir(root.join("scratch")).unwrap().count(), 0);
        let raw = if mode == "bad-inspect" {
            b"[]".to_vec()
        } else {
            fs::read(root.join("inspection")).unwrap()
        };
        native_tool::reply(&work, &raw, b"", 0);
    }
}

#[test]
fn pins_multichunk_retry_and_native_inspection() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("pins_multichunk_retry_and_native_inspection") else {
        return;
    };
    let mut f = Fixture::new("ok");
    f.all();
    let calls = fs::read(f.root.path().join("calls")).unwrap();
    f.all();
    assert_eq!(calls, fs::read(f.root.path().join("calls")).unwrap());
    let bytes = check_artifact(
        &f.spec,
        Artifact::ImageConfig,
        &f.dir,
        &f.executor,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(bytes, fs::read(f.root.path().join("config")).unwrap());
    let report = f.pull().unwrap();
    assert!(report.docker_metadata_verified);
    assert!(!report.launch_ready && !report.source_provenance_verified);
    assert_eq!(report.qualification, "pending");
    f.clean();
    assert!(
        !String::from_utf8(fs::read(f.root.path().join("calls")).unwrap())
            .unwrap()
            .contains("private-password")
    );
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "lightwallet.image_delivery.fetch_artifact",
                "lightwallet.image_delivery.check_artifact",
                "lightwallet.image_delivery.verify_image",
                "lightwallet.image_delivery.pull_image",
                "host.artifact_delivery.fetch_object",
                "host.image_delivery.pull_image",
                "host.files.read_verified",
            ],
            &[
                f.root.path().to_str().unwrap(),
                &f.spec.service.image,
                "private-password",
            ],
        );
        trace.assert_child(
            "host.artifact_delivery.fetch_object",
            "lightwallet.image_delivery.fetch_artifact",
        );
        trace.assert_child(
            "host.files.read_verified",
            "lightwallet.image_delivery.check_artifact",
        );
        trace.assert_child(
            "host.image_delivery.pull_image",
            "lightwallet.image_delivery.pull_image",
        );
    }
}

#[test]
fn rejects_invalid_downloads_and_cleans_failed_delivery() {
    for mode in ["bad-hash", "bad-size"] {
        let mut f = Fixture::new(mode);
        assert!(f.fetch(Artifact::ImageConfig).is_err());
        assert!(!f.root.path().join("artifacts/image-config.json").exists());
        f.clean();
    }
    for mode in ["login-fail", "pull-fail", "bad-inspect"] {
        let mut f = Fixture::new(mode);
        f.all();
        assert!(f.pull().is_err());
        f.clean();
    }
}

#[test]
fn full_preflight_unsafe_retry_wrong_image_and_cancellation() {
    let mut f = Fixture::new("ok");
    let original = f.spec.clone();
    f.spec.image_config.bytes = 16 * 1024 * 1024 + 1;
    assert!(f.fetch(Artifact::ImageRecord).is_err());
    assert!(!f.root.path().join("calls").exists());
    f.spec = original;
    symlink(
        f.root.path().join("record"),
        f.root.path().join("artifacts/image.json"),
    )
    .unwrap();
    assert!(f.fetch(Artifact::ImageRecord).is_err());
    assert!(!f.root.path().join("calls").exists());
    fs::remove_file(f.root.path().join("artifacts/image.json")).unwrap();
    f.all();
    f.spec.service.image = f.spec.service.image.replace("/test/", "/other/");
    assert!(f.pull().is_err());
    f.clean();
    let f = Fixture::new("ok");
    assert!(check_artifact(
        &f.spec,
        Artifact::ImageRecord,
        &f.dir,
        &f.executor,
        &AtomicBool::new(true)
    )
    .is_err());
    assert!(!f.root.path().join("calls").exists());
}

#[test]
fn all_metadata_policy_and_immutable_retry_fail_closed() {
    for field in [
        "owner",
        "bucket",
        "region",
        "key",
        "hash",
        "parser",
        "authorization",
    ] {
        let mut f = Fixture::new("ok");
        match field {
            "owner" => f.spec.image_config.owner_account = "999999999999".into(),
            "bucket" => f.spec.image_config.bucket = "another-bucket".into(),
            "region" => f.spec.image_config.region = "us-west-2".into(),
            "key" => f.spec.image_config.key = f.spec.image_manifest.key.clone(),
            "hash" => f.spec.image_config.sha256 = "bad".into(),
            "parser" => f.spec.image_record.bytes = image::MAX_RECORD_BYTES as u64 + 1,
            "authorization" => f.spec.new_volume = None,
            _ => unreachable!(),
        }
        assert!(f.fetch(Artifact::ImageManifest).is_err(), "{field}");
        assert!(!f.root.path().join("calls").exists(), "{field}");
    }
    for mode in ["bytes", "mode", "directory"] {
        let mut f = Fixture::new("ok");
        f.all();
        let calls = fs::read(f.root.path().join("calls")).unwrap();
        let path = f.root.path().join("artifacts/image-config.json");
        match mode {
            "bytes" => fs::write(&path, b"different").unwrap(),
            "mode" => {
                fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
                    .unwrap()
            }
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(f.fetch(Artifact::ImageConfig).is_err());
        assert!(check_artifact(
            &f.spec,
            Artifact::ImageConfig,
            &f.dir,
            &f.executor,
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(calls, fs::read(f.root.path().join("calls")).unwrap());
    }
}

#[test]
fn cancellation_and_cumulative_deadline_remove_credentials_before_inspect() {
    use std::sync::atomic::Ordering;
    for deadline in [false, true] {
        let mut f = Fixture::new("stall");
        f.all();
        if deadline {
            let commands = f.root.path().join("deadline-commands");
            fs::create_dir(&commands).unwrap();
            fs::set_permissions(
                &commands,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            f.executor = Executor::new(
                env!("CARGO_BIN_EXE_zdn").into(),
                commands,
                "us-east-1".into(),
                Instant::now() + Duration::from_millis(11000),
            )
            .unwrap();
        }
        let cancelled = AtomicBool::new(false);
        let started = f.root.path().join("started");
        std::thread::scope(|scope| {
            if !deadline {
                let cancelled = &cancelled;
                let started = &started;
                scope.spawn(move || {
                    let until = Instant::now() + Duration::from_secs(10);
                    while !started.exists() && Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    cancelled.store(true, Ordering::Relaxed);
                });
            }
            let before = Instant::now();
            assert!(pull_image(
                &f.spec,
                &f.dir,
                &f.root.path().join("scratch"),
                &f.tools,
                &mut f.executor,
                &cancelled
            )
            .is_err());
            assert!(before.elapsed() < Duration::from_secs(10));
        });
        assert!(started.exists());
        f.clean();
        assert!(!fs::read_to_string(f.root.path().join("calls"))
            .unwrap()
            .contains("image inspect"));
    }
}

#[test]
fn cleanup_failure_is_explicit_and_never_inspects() {
    let mut f = Fixture::new("cleanup-fail");
    f.all();
    let error = format!("{:?}", f.pull().unwrap_err());
    assert!(error.contains("credential cleanup failed"), "{error}");
    assert!(!fs::read_to_string(f.root.path().join("calls"))
        .unwrap()
        .contains("image inspect"));
}
