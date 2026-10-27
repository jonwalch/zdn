#![cfg(target_os = "linux")]
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zdn::{
    host::{
        command::Executor,
        files::Directory,
        runtime::{
            revision::{Request, API_VERSION},
            revision_delivery::{stage, verify, Tools},
            Manifest, Selection, PROTOCOL,
        },
    },
    image,
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

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
struct Fixture {
    root: tempfile::TempDir,
    dir: Directory,
    request: Request,
    executor: Executor,
    tools: Tools,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory =
            Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
        directory.ensure_directory("commands", 0o700).unwrap();
        directory.ensure_directory("scratch", 0o700).unwrap();
        let (host, _) = fixture::specs();
        let original = Manifest::new(
            host.clone(),
            Selection {
                protocol: PROTOCOL.into(),
                helper: host.helper.clone(),
            },
        )
        .unwrap();
        let runtime = json!({"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["zakurad"]});
        let config = serde_json::to_vec(&json!({"os":"linux","architecture":"amd64","config":runtime,"rootfs":{"type":"layers","diff_ids":[format!("sha256:{}", "c".repeat(64))]},"padding":"x".repeat(196739)})).unwrap();
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hash(&config)),"size":config.len()},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","d".repeat(64)),"size":42}]})).unwrap();
        let image = image::ImageRecord {
            api_version: image::API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/new@sha256:{}",
                hash(&manifest)
            ),
            config_digest: format!("sha256:{}", hash(&config)),
            platform: "linux/amd64".into(),
            provenance: image::ImageProvenance::Source {
                revision: "e".repeat(40),
                snapshot_sha256: "f".repeat(64),
            },
            capabilities: Default::default(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        };
        let record = serde_json::to_vec(&image).unwrap();
        fs::write(root.path().join("inspection"), json!([{"Id":image.config_digest,"RepoDigests":[image.image],"Os":"linux","Architecture":"amd64","Config":runtime}]).to_string()).unwrap();
        let object = |name: &str, bytes: &[u8]| {
            fs::write(root.path().join(name), bytes).unwrap();
            let mut pin = host.helper.clone();
            pin.key = format!("new/{name}");
            pin.bytes = bytes.len() as u64;
            pin.sha256 = hash(bytes);
            pin
        };
        let request = Request {
            api_version: API_VERSION.into(),
            expected_image: host.image.clone(),
            expected_update_id: None,
            original,
            update_id: Uuid::new_v4(),
            image,
            image_record: object("record", &record),
            image_manifest: object("manifest", &manifest),
            image_config: object("config", &config),
        };
        request.bytes().unwrap();
        let dir = directory
            .ensure_directory(&request.update_id.to_string(), 0o700)
            .unwrap();
        let tools = Tools {
            aws: root.path().join("aws"),
            docker: root.path().join("docker"),
        };
        for tool in [&tools.aws, &tools.docker] {
            native_tool::install(
                tool,
                "tool_worker",
                &json!({"root":root.path(),"mode":mode,"image":request.image.image}),
            );
        }
        let executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            root.path().join("commands"),
            "us-east-1".into(),
            Instant::now() + Duration::from_secs(90),
        )
        .unwrap();
        Self {
            root,
            dir,
            request,
            executor,
            tools,
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.root
            .path()
            .join(self.request.update_id.to_string())
            .join(name)
    }
    fn stage(&mut self, cancelled: &AtomicBool) -> eyre::Result<image::ImageInspectionReport> {
        stage(
            &self.request,
            &self.dir,
            &self.root.path().join("scratch"),
            &self.tools,
            &mut self.executor,
            cancelled,
        )
    }
    fn retain(&self) {
        for (source, name) in [
            ("record", "image.json"),
            ("manifest", "image-manifest.json"),
            ("config", "image-config.json"),
        ] {
            self.dir
                .publish(
                    name,
                    &fs::read(self.root.path().join(source)).unwrap(),
                    0o600,
                )
                .unwrap();
        }
    }
    fn clean(&self) {
        assert_eq!(
            fs::read_dir(self.root.path().join("scratch"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read_dir(self.path("")).unwrap().count(), 3);
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.root.path().join("calls")).unwrap_or_default()
    }
}

#[test]
fn tool_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    use std::io::Write;
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("calls"))
            .unwrap(),
        "{}",
        args.join(" ")
    )
    .unwrap();
    if args[0] == "s3api" {
        assert_eq!(
            &args[..4],
            ["s3api", "get-object", "--bucket", "zdn-artifacts-test"]
        );
        assert_eq!(
            &args[6..12],
            [
                "--expected-bucket-owner",
                "123456789012",
                "--region",
                "us-east-1",
                "--output",
                "json"
            ]
        );
        let bytes = fs::read(root.join(args[5].strip_prefix("new/").unwrap())).unwrap();
        fs::write(&args[12], &bytes).unwrap();
        native_tool::reply(
            &work,
            json!({"ContentLength":bytes.len()}).to_string().as_bytes(),
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
                [
                    "--username",
                    "AWS",
                    "--password-stdin",
                    "123456789012.dkr.ecr.us-east-1.amazonaws.com"
                ]
            );
            fs::write(credentials.join("config.json"), password).unwrap();
        } else {
            assert_eq!(&args[2..5], ["pull", "--platform", "linux/amd64"]);
            assert_eq!(args[5], payload["image"]);
            if mode == "stall" {
                fs::write(root.join("started"), b"").unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
        }
        native_tool::reply(
            &work,
            b"",
            b"",
            u8::from(mode == "pull-fail" && args[2] == "pull"),
        );
    } else {
        assert_eq!(
            args,
            ["image", "inspect", payload["image"].as_str().unwrap()]
        );
        assert_eq!(fs::read_dir(root.join("scratch")).unwrap().count(), 0);
        native_tool::reply(&work, &fs::read(root.join("inspection")).unwrap(), b"", 0);
    }
}

#[test]
fn exact_new_pins_original_unchanged_and_offline_retry() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("exact_new_pins_original_unchanged_and_offline_retry") else {
        return;
    };
    let mut f = Fixture::new("ok");
    let original = f.request.original.bytes().unwrap();
    let request = f.request.bytes().unwrap();
    fs::write(f.root.path().join("identity"), &original).unwrap();
    let report = f.stage(&AtomicBool::new(false)).unwrap();
    assert!(
        report.docker_metadata_verified && !report.launch_ready && !report.capabilities_observed
    );
    assert_eq!(report.qualification, "pending");
    assert_eq!(report.image, f.request.image.image);
    assert_ne!(report.image, f.request.original.spec.image);
    assert_eq!(f.request.bytes().unwrap(), request);
    assert_eq!(fs::read(f.root.path().join("identity")).unwrap(), original);
    let calls = f.calls();
    assert_eq!(calls.matches("s3api").count(), 3);
    assert!(!calls.contains("team/test/"));
    assert!(!calls.contains("private-password"));
    fs::remove_file(&f.tools.aws).unwrap();
    fs::remove_file(&f.tools.docker).unwrap();
    assert!(verify(
        &f.request,
        &f.dir,
        None,
        &mut f.executor,
        &AtomicBool::new(false)
    )
    .unwrap()
    .is_none());
    assert_eq!(calls, f.calls());
    f.clean();
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.runtime.revision_delivery.stage",
                "host.runtime.revision_delivery.verify",
                "host.artifact_delivery.fetch_object",
                "host.image_delivery.pull_image",
                "host.files.read_verified",
            ],
            &[
                f.root.path().to_str().unwrap(),
                &f.request.update_id.to_string(),
                &f.request.image.image,
                "private-password",
            ],
        );
        trace.assert_child(
            "host.artifact_delivery.fetch_object",
            "host.runtime.revision_delivery.stage",
        );
        trace.assert_child(
            "host.runtime.revision_delivery.verify",
            "host.runtime.revision_delivery.stage",
        );
    }
}

#[test]
fn retained_retry_never_redownloads_and_failed_pull_cleans() {
    for mode in ["ok", "pull-fail"] {
        let mut f = Fixture::new(mode);
        f.retain();
        assert_eq!(f.stage(&AtomicBool::new(false)).is_ok(), mode == "ok");
        assert!(!f.calls().contains("s3api"));
        f.clean();
        if mode == "pull-fail" {
            assert!(!f.calls().contains("image inspect"));
        }
    }
}

#[test]
fn invalid_request_and_private_or_corrupt_partial_entries_precede_network() {
    for kind in [
        "bound",
        "scope",
        "record",
        "config",
        "manifest",
        "mode",
        "symlink",
        "directory",
    ] {
        let mut f = Fixture::new("ok");
        match kind {
            "bound" => f.request.image_config.bytes = image::MAX_CONFIG_BYTES as u64 + 1,
            "scope" => f.request.image_config.owner_account = "999999999999".into(),
            "record" => {
                f.retain();
                if let image::ImageProvenance::Source { revision, .. } =
                    &mut f.request.image.provenance
                {
                    *revision = "1".repeat(40);
                }
            }
            "config" | "manifest" => {
                f.retain();
                fs::write(
                    f.path(if kind == "config" {
                        "image-config.json"
                    } else {
                        "image-manifest.json"
                    }),
                    b"bad",
                )
                .unwrap();
            }
            "mode" => {
                f.retain();
                fs::set_permissions(
                    f.path("image-config.json"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            "symlink" => {
                symlink(f.root.path().join("config"), f.path("image-config.json")).unwrap()
            }
            "directory" => fs::create_dir(f.path("image-config.json")).unwrap(),
            _ => unreachable!(),
        }
        assert!(f.stage(&AtomicBool::new(false)).is_err(), "{kind}");
        assert!(f.calls().is_empty(), "{kind}");
    }
}

#[test]
fn cryptographically_pinned_but_inconsistent_metadata_is_rejected() {
    for kind in ["config-platform", "config-size", "manifest-config"] {
        let mut f = Fixture::new("ok");
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(f.root.path().join("config")).unwrap()).unwrap();
        if kind == "config-platform" {
            config["architecture"] = json!("arm64");
        }
        let config = serde_json::to_vec(&config).unwrap();
        f.request.image_config.bytes = config.len() as u64;
        f.request.image_config.sha256 = hash(&config);
        f.request.image.config_digest = format!("sha256:{}", hash(&config));
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(f.root.path().join("manifest")).unwrap()).unwrap();
        manifest["config"]["digest"] = json!(if kind == "manifest-config" {
            format!("sha256:{}", "9".repeat(64))
        } else {
            f.request.image.config_digest.clone()
        });
        manifest["config"]["size"] = json!(config.len() + usize::from(kind == "config-size"));
        let manifest = serde_json::to_vec(&manifest).unwrap();
        f.request.image_manifest.bytes = manifest.len() as u64;
        f.request.image_manifest.sha256 = hash(&manifest);
        f.request.image.image = format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/new@sha256:{}",
            hash(&manifest)
        );
        let record = serde_json::to_vec(&f.request.image).unwrap();
        f.request.image_record.bytes = record.len() as u64;
        f.request.image_record.sha256 = hash(&record);
        f.request.bytes().unwrap();
        for (name, bytes) in [
            ("image.json", record),
            ("image-manifest.json", manifest),
            ("image-config.json", config),
        ] {
            f.dir.publish(name, &bytes, 0o600).unwrap();
        }
        assert!(
            verify(
                &f.request,
                &f.dir,
                None,
                &mut f.executor,
                &AtomicBool::new(false)
            )
            .is_err(),
            "{kind}"
        );
        assert!(f.stage(&AtomicBool::new(false)).is_err(), "{kind}");
        assert!(f.calls().is_empty());
    }
}

#[test]
fn cancellation_and_shared_deadline_cleanup_before_inspection() {
    for deadline in [false, true] {
        let mut f = Fixture::new("stall");
        f.retain();
        if deadline {
            let commands = f.root.path().join("deadline-commands");
            fs::create_dir(&commands).unwrap();
            fs::set_permissions(&commands, fs::Permissions::from_mode(0o700)).unwrap();
            f.executor = Executor::new(
                env!("CARGO_BIN_EXE_zdn").into(),
                commands,
                "us-east-1".into(),
                Instant::now() + Duration::from_secs(11),
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
            assert!(f.stage(&cancelled).is_err());
            assert!(before.elapsed() < Duration::from_secs(10));
        });
        assert!(started.exists());
        f.clean();
        assert!(!f.calls().contains("image inspect"));
    }
}
