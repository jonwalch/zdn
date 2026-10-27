#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{
        command::Executor,
        files::Directory,
        volume::{
            prepare::{self, Root, Tools},
            probe, Installation,
        },
        HostInstallSpec, NewVolumeAuthorization, S3Object, API_VERSION, NEW_VOLUME_API_VERSION,
    },
};

#[path = "support/executable.rs"]
mod executable;
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
        memory_bytes: 24 << 30,
        host_reserve_bytes: 4 << 30,
        cpu_millis: 3500,
        manifest: object("manifest"),
        bundle: object("bundle"),
        helper: object("helper"),
        image_record: object("image-record"),
        image_manifest: object("image-manifest"),
        new_volume: None,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    spec: HostInstallSpec,
    tools: Tools,
}

impl Fixture {
    fn new(mounted: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        for path in ["etc/zdn", "var/lib/zdn", "dev", "commands"] {
            fs::create_dir_all(root.path().join(path)).unwrap();
        }
        fs::set_permissions(
            root.path().join("commands"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        // A source-resolution fixture ONLY. It must never become format authority.
        fs::write(root.path().join("dev/nvme12n3"), b"retained raw data").unwrap();
        fs::write(
            root.path().join("state"),
            json!({"mounted":mounted,"blank":false,"calls":0}).to_string(),
        )
        .unwrap();
        let tool = |name| {
            let path = root.path().join(name);
            native_tool::install(
                &path,
                "volume_tool_worker",
                &json!({"root":root.path(),"kind":name}),
            );
            path
        };
        let tools = Tools {
            probe: probe::Tools {
                lsblk: tool("lsblk"),
                findmnt: tool("findmnt"),
                blkid: tool("blkid"),
                wipefs: tool("wipefs"),
                blockdev: tool("blockdev"),
            },
            mount: tool("mount"),
            mkfs_ext4: tool("mkfs"),
        };
        Self {
            root,
            spec: spec(),
            tools,
        }
    }
    fn path(&self, path: &str) -> std::path::PathBuf {
        self.root.path().join(path)
    }
    fn directory(&self, path: &str) -> Directory {
        Directory::open(
            &self.path(path),
            fs::metadata(self.root.path()).unwrap().uid(),
        )
        .unwrap()
    }
    fn state(&self, key: &str, value: Value) {
        let mut state: Value =
            serde_json::from_slice(&fs::read(self.path("state")).unwrap()).unwrap();
        state[key] = value;
        fs::write(self.path("state"), state.to_string()).unwrap();
    }
    fn run(&self, create: bool, cancelled: bool) -> eyre::Result<()> {
        self.run_with(create, &AtomicBool::new(cancelled))
    }
    fn run_with(&self, create: bool, cancelled: &AtomicBool) -> eyre::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            self.path("commands"),
            "us-east-1".into(),
            deadline,
        )?;
        let metadata = self.directory("etc/zdn");
        let mut installation = Installation::acquire(&metadata, &self.spec)?;
        prepare::prepare(
            &self.spec,
            Root {
                path: self.root.path(),
                owner: fs::metadata(self.root.path())?.uid(),
            },
            &self.tools,
            &mut installation,
            &mut executor,
            cancelled,
            create,
        )
    }
    fn seed(&self, intent: bool, claim: bool) {
        let etc = self.directory("etc/zdn");
        let mut install = Installation::acquire(&etc, &self.spec).unwrap();
        if intent {
            install.begin_format().unwrap();
        }
        if claim {
            install
                .claim_mounted(&self.directory("var/lib/zdn"), true)
                .unwrap();
        }
    }
    fn no_mutation(&self) {
        let log = fs::read_to_string(self.path("log")).unwrap_or_default();
        assert!(!log.contains("mkfs"), "{log}");
        assert!(!self.path("etc/zdn/volume-claimed.json").exists());
        assert!(!self.path("var/lib/zdn/.zdn-volume.json").exists());
    }
}

#[test]
fn volume_tool_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let kind = payload["kind"].as_str().unwrap();
    let mut state: Value = serde_json::from_slice(&fs::read(root.join("state")).unwrap()).unwrap();
    use std::io::Write;
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("log"))
            .unwrap(),
        "{kind} {args:?}"
    )
    .unwrap();
    let mut code = 0;
    let output = match kind {
        "lsblk" => {
            let calls = state["calls"].as_u64().unwrap() + 1;
            state["calls"] = calls.into();
            let device = if state["change_attachment"] == true && calls > 1 {
                "/dev/nvme99n1"
            } else {
                "/dev/nvme12n3"
            };
            json!({"blockdevices":[{"path":device,"type":"disk","serial":"vol0123456789abcdef0","mountpoints":[null]}]}).to_string()
        }
        "findmnt" => {
            assert_eq!(args[2], "/var/lib/zdn");
            if state["mounted"] == true {
                json!({"filesystems":[{"source":root.join("dev/nvme12n3"),"target":"/var/lib/zdn","fstype":"ext4"}]}).to_string()
            } else {
                code = 1;
                String::new()
            }
        }
        "blkid" => {
            if state["blank"] == true {
                code = 2;
                String::new()
            } else if state["unknown"] == true {
                "TYPE=xfs\n".into()
            } else {
                "TYPE=ext4\n".into()
            }
        }
        "wipefs" => {
            if state["signature"] == true {
                json!({"signatures":[{"type":"unknown"}]}).to_string()
            } else {
                json!({"signatures":[]}).to_string()
            }
        }
        "blockdev" => "1073741824\n".into(),
        "mount" => {
            assert_eq!(&args[..4], &["-t", "ext4", "-o", "nodev,nosuid,noexec"]);
            assert_eq!(args[4], root.join("dev/nvme12n3").to_str().unwrap());
            assert_eq!(args[5], root.join("var/lib/zdn").to_str().unwrap());
            assert!(!root.join("etc/zdn/volume-claimed.json").exists());
            if state["sleep_mount"] == true {
                fs::write(root.join("mount-started"), b"started").unwrap();
                std::thread::sleep(Duration::from_secs(20));
                panic!("cancellation did not stop mount");
            }
            if state["fail_mount"] == true {
                code = 1;
            } else if state["no_mount"] != true {
                // Model a mount transition by replacing, not populating, the old
                // directory. Claiming a retained pre-mount fd would fail here.
                fs::rename(root.join("var/lib/zdn"), root.join("underlay")).unwrap();
                fs::create_dir(root.join("var/lib/zdn")).unwrap();
                if let Some(identity) = state["mount_claim"].as_str() {
                    let target = root.join("var/lib/zdn/.zdn-volume.json");
                    fs::write(&target, identity).unwrap();
                    fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(root.join("var/lib/zdn/retained"), b"retained").unwrap();
                }
                state["mounted"] = true.into();
            }
            String::new()
        }
        "mkfs" => panic!("offline fixtures must never reach mkfs"),
        _ => panic!("unexpected tool"),
    };
    fs::write(root.join("state"), state.to_string()).unwrap();
    native_tool::reply(&work, output.as_bytes(), b"", code);
}

#[test]
fn mounted_claim_retry_and_retained_restart() {
    let f = Fixture::new(true);
    f.run(true, false).unwrap();
    let identity = fs::read(f.path("var/lib/zdn/.zdn-volume.json")).unwrap();
    assert_eq!(
        identity,
        fs::read(f.path("etc/zdn/volume-claimed.json")).unwrap()
    );
    fs::write(f.path("var/lib/zdn/retained"), b"data").unwrap();
    f.run(false, false).unwrap();
    assert_eq!(fs::read(f.path("var/lib/zdn/retained")).unwrap(), b"data");
    assert!(!fs::read_to_string(f.path("log"))
        .unwrap()
        .contains("mount ["));
}

#[test]
fn unmounted_ext4_reopens_and_claims_then_retries() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("unmounted_ext4_reopens_and_claims_then_retries") else {
        return;
    };
    let f = Fixture::new(false);
    f.seed(true, false);
    f.run(true, false).unwrap();
    assert!(!f.path("underlay/.zdn-volume.json").exists());
    assert!(f.path("var/lib/zdn/.zdn-volume.json").exists());
    f.run(false, false).unwrap();
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.volume.prepare",
                "host.volume.prepare.mount",
                "host.volume.prepare.claim",
            ],
            &[
                f.root.path().to_str().unwrap(),
                &f.spec.config_toml,
                &f.spec.volume_id,
                &f.spec.consensus_fingerprint,
            ],
        );
        trace.assert_child("host.volume.prepare.mount", "host.volume.prepare");
        trace.assert_child("host.volume.prepare.claim", "host.volume.prepare");
    }
}

#[test]
fn unmounted_retained_claim_allows_restart() {
    let f = Fixture::new(false);
    f.seed(false, false);
    let identity = fs::read_to_string(f.path("etc/zdn/identity.json")).unwrap();
    f.state("mount_claim", identity.into());
    f.run(false, false).unwrap();
    assert!(f.path("var/lib/zdn/retained").exists());
}

#[test]
fn blank_unknown_and_uncertain_history_never_format() {
    for case in ["restart", "raw", "signature", "intent", "previous"] {
        let f = Fixture::new(false);
        f.state("blank", true.into());
        if case == "signature" {
            f.state("signature", true.into());
        }
        if case == "intent" {
            f.seed(true, false);
        }
        if case == "previous" {
            f.directory("etc/zdn")
                .publish("volume-claimed.json", b"foreign\n", 0o600)
                .unwrap();
        }
        assert!(f.run(case != "restart", false).is_err(), "{case}");
        let log = fs::read_to_string(f.path("log")).unwrap();
        assert!(
            !log.contains("mkfs") && !log.contains("mount ["),
            "{case}: {log}"
        );
        assert!(!f.path("var/lib/zdn/.zdn-volume.json").exists());
        assert_eq!(
            f.path("etc/zdn/format-intent.json").exists(),
            case == "intent"
        );
    }
}

#[test]
fn failed_or_changed_mount_and_attachment_do_not_claim() {
    for case in ["fail_mount", "no_mount", "change_attachment", "unknown"] {
        let f = Fixture::new(false);
        f.state(case, true.into());
        assert!(f.run(true, false).is_err(), "{case}");
        f.no_mutation();
        if case == "change_attachment" {
            assert!(!fs::read_to_string(f.path("log"))
                .unwrap()
                .contains("mount ["));
        }
    }
}

#[test]
fn unsafe_unclaimed_foreign_and_cancelled_are_rejected() {
    for case in [
        "data",
        "restart",
        "foreign_claim",
        "foreign_identity",
        "cancel",
        "busy",
    ] {
        let f = Fixture::new(case != "busy");
        if case == "data" || case == "busy" {
            fs::write(f.path("var/lib/zdn/data"), b"data").unwrap();
        }
        if case == "foreign_identity" {
            f.directory("etc/zdn")
                .publish("identity.json", b"foreign\n", 0o600)
                .unwrap();
        }
        if case == "foreign_claim" {
            f.directory("var/lib/zdn")
                .publish(".zdn-volume.json", b"foreign\n", 0o600)
                .unwrap();
        }
        assert!(
            f.run(case != "restart", case == "cancel").is_err(),
            "{case}"
        );
        assert!(!f.path("etc/zdn/volume-claimed.json").exists());
        assert!(!fs::read_to_string(f.path("log"))
            .unwrap_or_default()
            .contains("mkfs"));
    }
}

#[test]
fn install_lock_is_not_bypassed() {
    let f = Fixture::new(true);
    let etc = f.directory("etc/zdn");
    let mut guard = Installation::acquire(&etc, &f.spec).unwrap();
    assert!(f.run(true, false).is_err());
    f.no_mutation();
    let mut executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.path("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    prepare::prepare(
        &f.spec,
        Root {
            path: f.root.path(),
            owner: fs::metadata(f.root.path()).unwrap().uid(),
        },
        &f.tools,
        &mut guard,
        &mut executor,
        &AtomicBool::new(false),
        true,
    )
    .unwrap();
    assert!(
        Installation::acquire(&etc, &f.spec).is_err(),
        "the caller still owns the action lock"
    );
    let before = fs::read(f.path("log")).unwrap();
    let mut changed = f.spec.clone();
    changed.cpu_millis += 1;
    assert!(prepare::prepare(
        &changed,
        Root {
            path: f.root.path(),
            owner: fs::metadata(f.root.path()).unwrap().uid()
        },
        &f.tools,
        &mut guard,
        &mut executor,
        &AtomicBool::new(false),
        false,
    )
    .is_err());
    assert_eq!(fs::read(f.path("log")).unwrap(), before);
    drop(executor);
    let mut executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.path("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(9),
    )
    .unwrap();
    assert!(
        prepare::prepare(
            &f.spec,
            Root {
                path: f.root.path(),
                owner: fs::metadata(f.root.path()).unwrap().uid()
            },
            &f.tools,
            &mut guard,
            &mut executor,
            &AtomicBool::new(false),
            false,
        )
        .is_err(),
        "evidence must preserve the executor's cleanup reserve"
    );
    assert_eq!(fs::read(f.path("log")).unwrap(), before);
}

fn authorize(f: &mut Fixture) {
    f.spec.new_volume = Some(NewVolumeAuthorization {
        api_version: NEW_VOLUME_API_VERSION.into(),
        volume_id: f.spec.volume_id.clone(),
        instance_id: "i-0123456789abcdef0".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        size_bytes: 1 << 30,
        creation_intent_sha256: "a".repeat(64),
        checkpoint_sha256: "b".repeat(64),
    });
    f.spec.validate().unwrap();
}

#[test]
fn pinned_creation_requires_matching_intent_to_claim_but_never_makes_files_devices() {
    for case in ["retry", "missing", "foreign", "raw", "size"] {
        let mut f = Fixture::new(true);
        authorize(&mut f);
        if case == "retry" {
            f.seed(true, false);
        }
        if case == "foreign" {
            f.directory("etc/zdn")
                .publish("format-intent.json", b"foreign\n", 0o600)
                .unwrap();
        }
        if case == "raw" || case == "size" {
            f.state("mounted", false.into());
            f.state("blank", true.into());
            if case == "size" {
                f.spec.new_volume.as_mut().unwrap().size_bytes = 2 << 30;
            }
        }
        let result = f.run(true, false);
        if case == "retry" {
            result.unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            if case == "raw" {
                assert!(error.contains("real block device"), "{error}");
            }
            if case == "size" {
                assert!(error.contains("disk size"), "{error}");
            }
            f.no_mutation();
        }
        assert!(!fs::read_to_string(f.path("log")).unwrap().contains("mkfs"));
    }
}

#[test]
fn root_acknowledgement_failure_preserves_volume_claim_for_retry() {
    let f = Fixture::new(true);
    // An existing root record is never repaired. Claim publication precedes
    // this failed acknowledgement, and a retry can verify retained contents.
    f.directory("etc/zdn")
        .publish("volume-claimed.json", b"foreign\n", 0o600)
        .unwrap();
    assert!(f.run(true, false).is_err());
    assert!(f.path("var/lib/zdn/.zdn-volume.json").exists());
    assert_eq!(
        fs::read(f.path("etc/zdn/volume-claimed.json")).unwrap(),
        b"foreign\n"
    );
    fs::remove_file(f.path("etc/zdn/volume-claimed.json")).unwrap();
    fs::write(f.path("var/lib/zdn/retained"), b"retained").unwrap();
    f.run(false, false).unwrap();
}

#[test]
fn cancellation_during_mount_never_claims() {
    let f = Fixture::new(false);
    f.state("sleep_mount", true.into());
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !f.path("mount-started").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            cancelled.store(true, Ordering::SeqCst);
        });
        assert!(f.run_with(true, &cancelled).is_err());
    });
    f.no_mutation();
}
