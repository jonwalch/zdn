#![cfg(target_os = "linux")]

use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
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
        artifact_delivery::{fetch, Artifact},
        command::Executor,
        files::Directory,
        HostInstallSpec, S3Object, API_VERSION,
    },
};

#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

fn bytes() -> Vec<u8> {
    (0..196_739)
        .map(|i| ((i * 37 + i / 7919) % 251) as u8)
        .collect()
}

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
        sha256: zdn::devnet::sha256(&bytes()),
        bytes: bytes().len() as u64,
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
        memory_bytes: 8 << 30,
        host_reserve_bytes: 4 << 30,
        cpu_millis: 3500,
        manifest: object("manifest"),
        bundle: object("bundle"),
        helper: object("helper"),
        image_record: S3Object {
            bytes: 128,
            ..object("image-record")
        },
        image_manifest: object("image-manifest"),
        new_volume: None,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    directory: Directory,
    executor: Executor,
    spec: HostInstallSpec,
    aws: PathBuf,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory =
            Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
        directory.ensure_directory("artifacts", 0o700).unwrap();
        directory.ensure_directory("commands", 0o700).unwrap();
        let aws = root.path().join("aws");
        native_tool::install(
            &aws,
            "aws_worker",
            &json!({"root": root.path(), "mode":mode}),
        );
        let executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            root.path().join("commands"),
            "us-east-1".into(),
            Instant::now() + Duration::from_secs(90),
        )
        .unwrap();
        let directory = directory.open_directory("artifacts").unwrap();
        Self {
            root,
            directory,
            executor,
            spec: spec(),
            aws,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join("artifacts").join(name)
    }
    fn fetch(&mut self, artifact: Artifact) -> eyre::Result<()> {
        fetch(
            &self.spec,
            artifact,
            &self.directory,
            &self.aws,
            &mut self.executor,
            &AtomicBool::new(false),
        )
    }
    fn clean(&self) {
        assert!(fs::read_dir(self.path("")).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".download-")));
    }
}

#[test]
fn aws_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    assert_eq!(args.len(), 13);
    assert_eq!(
        &args[..12],
        [
            "s3api",
            "get-object",
            "--bucket",
            "zdn-artifacts-test",
            "--key",
            if mode.ends_with("helper") {
                "team/test/helper"
            } else if mode == "manifest" {
                "team/test/manifest"
            } else if mode == "image-record" {
                "team/test/image-record"
            } else if mode == "image-manifest" {
                "team/test/image-manifest"
            } else {
                "team/test/bundle"
            },
            "--expected-bucket-owner",
            "123456789012",
            "--region",
            "us-east-1",
            "--output",
            "json"
        ]
    );
    fs::write(root.join("called"), b"yes").unwrap();
    let destination = Path::new(&args[12]);
    assert_eq!(
        destination.parent().unwrap().metadata().unwrap().mode() & 0o7777,
        0o700
    );
    if mode == "wait" {
        loop {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let mut data = bytes();
    if mode == "image-record" {
        data.truncate(128);
    }
    match mode {
        "changed" => data[130_003] ^= 1,
        "oversize" => data.push(42),
        "short" => {
            data.pop();
        }
        "helper" => {
            data[..6].copy_from_slice(b"\x7fELF\x02\x01");
            data[16..20].copy_from_slice(&[2, 0, 62, 0]);
        }
        _ => {}
    }
    match mode {
        "symlink" => symlink(root.join("outside"), destination).unwrap(),
        "fifo" => nix::unistd::mkfifo(destination, nix::sys::stat::Mode::S_IRUSR).unwrap(),
        "unsafe" => {
            fs::write(destination, &data).unwrap();
            fs::set_permissions(destination, fs::Permissions::from_mode(0o666)).unwrap();
        }
        _ => fs::write(destination, &data).unwrap(),
    }
    if mode.starts_with("race") {
        let target = root.join("artifacts/chain.tar");
        let winner = if mode == "race-different" {
            b"foreign winner".as_slice()
        } else {
            data.as_slice()
        };
        fs::write(&target, winner).unwrap();
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(if mode == "race-mode" { 0o400 } else { 0o600 }),
        )
        .unwrap();
    }
    let metadata = match mode {
        "malformed" => b"not json".to_vec(),
        "missing-length" => b"{}".to_vec(),
        "duplicate-length" => {
            format!("{{\"ContentLength\":1,\"ContentLength\":{}}}", data.len()).into_bytes()
        }
        "metadata-large" => vec![b' '; 65537],
        "length" => json!({"ContentLength": 1}).to_string().into_bytes(),
        "length-string" => json!({"ContentLength": "private provider diagnostic"})
            .to_string()
            .into_bytes(),
        _ => json!({"ContentLength": if mode == "image-record" {128} else {bytes().len()}})
            .to_string()
            .into_bytes(),
    };
    native_tool::reply(
        &work,
        &metadata,
        b"private provider diagnostic",
        if mode == "failed" { 1 } else { 0 },
    );
}

#[test]
fn streams_asymmetric_bytes_and_retains_without_network() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("streams_asymmetric_bytes_and_retains_without_network") else {
        return;
    };
    let mut f = Fixture::new("ok");
    f.fetch(Artifact::Bundle).unwrap();
    assert_eq!(fs::read(f.path("chain.tar")).unwrap(), bytes());
    assert_eq!(
        f.path("chain.tar").metadata().unwrap().mode() & 0o7777,
        0o600
    );
    f.clean();
    fs::remove_file(&f.aws).unwrap();
    f.fetch(Artifact::Bundle).unwrap();
    f.clean();
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.artifact_delivery.fetch",
                "host.artifact_delivery.download",
                "host.artifact_delivery.cleanup",
                "host.files.artifact_matches",
                "host.files.publish_download",
                "host.files.digest_file",
            ],
            &[
                f.root.path().to_str().unwrap(),
                "zdn-artifacts-test",
                "team/test/bundle",
                "private provider diagnostic",
                &f.spec.bundle.sha256,
            ],
        );
        trace.assert_child(
            "host.artifact_delivery.download",
            "host.artifact_delivery.fetch",
        );
        trace.assert_child("host.files.digest_file", "host.files.publish_download");
    }
}

#[test]
fn helper_requires_elf_and_publishes_executable_mode() {
    let mut f = Fixture::new("helper");
    let mut data = bytes();
    data[..6].copy_from_slice(b"\x7fELF\x02\x01");
    data[16..20].copy_from_slice(&[2, 0, 62, 0]);
    f.spec.helper.sha256 = zdn::devnet::sha256(&data);
    f.fetch(Artifact::Helper).unwrap();
    assert_eq!(fs::read(f.path("zdn")).unwrap(), data);
    assert_eq!(f.path("zdn").metadata().unwrap().mode() & 0o7777, 0o555);
    fs::remove_file(&f.aws).unwrap();
    f.fetch(Artifact::Helper).unwrap();
    // A byte-pinned non-ELF must also be rejected on the retained path.
    fs::set_permissions(f.path("zdn"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(f.path("zdn"), bytes()).unwrap();
    fs::set_permissions(f.path("zdn"), fs::Permissions::from_mode(0o555)).unwrap();
    f.spec.helper.sha256 = zdn::devnet::sha256(&bytes());
    assert!(f.fetch(Artifact::Helper).is_err());
    f.clean();
}

#[test]
fn rejects_failed_malformed_changed_and_unsafe_downloads_with_cleanup() {
    for mode in [
        "changed",
        "oversize",
        "short",
        "malformed",
        "missing-length",
        "duplicate-length",
        "metadata-large",
        "length",
        "length-string",
        "failed",
        "symlink",
        "fifo",
        "unsafe",
    ] {
        let mut f = Fixture::new(mode);
        fs::write(f.root.path().join("outside"), b"unchanged").unwrap();
        let error = format!("{:?}", f.fetch(Artifact::Bundle).unwrap_err());
        assert!(
            !error.contains("private provider diagnostic"),
            "{mode}: {error}"
        );
        assert!(!f.path("chain.tar").exists(), "{mode}");
        assert_eq!(
            fs::read(f.root.path().join("outside")).unwrap(),
            b"unchanged"
        );
        f.clean();
    }
    let mut f = Fixture::new("invalid-helper");
    let error = f.fetch(Artifact::Helper).unwrap_err().to_string();
    assert!(error.contains("ELF"), "{error}");
    assert!(!f.path("zdn").exists());
    f.clean();
}

#[test]
fn unsafe_retained_entries_are_never_repaired_or_downloaded() {
    for mode in [
        "symlink",
        "dangling",
        "fifo",
        "directory",
        "mode",
        "changed",
    ] {
        let mut f = Fixture::new("ok");
        let target = f.path("chain.tar");
        match mode {
            "symlink" => {
                fs::write(f.path("other"), bytes()).unwrap();
                symlink("other", &target).unwrap();
            }
            "dangling" => symlink("missing", &target).unwrap(),
            "fifo" => nix::unistd::mkfifo(&target, nix::sys::stat::Mode::S_IRUSR).unwrap(),
            "directory" => fs::create_dir(&target).unwrap(),
            _ => {
                fs::write(
                    &target,
                    if mode == "mode" {
                        bytes()
                    } else {
                        vec![3; bytes().len()]
                    },
                )
                .unwrap();
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(if mode == "mode" { 0o400 } else { 0o600 }),
                )
                .unwrap();
            }
        }
        let before = fs::symlink_metadata(&target).unwrap();
        assert!(f.fetch(Artifact::Bundle).is_err(), "{mode}");
        let after = fs::symlink_metadata(&target).unwrap();
        assert_eq!(
            (before.ino(), before.mode(), before.len()),
            (after.ino(), after.mode(), after.len())
        );
        assert!(!f.root.path().join("called").exists());
        f.clean();
    }
}

#[test]
fn validates_all_pins_and_bounds_before_subprocess_effects() {
    for case in 0..5 {
        let mut f = Fixture::new("ok");
        match case {
            0 => f.spec.bundle.owner_account = "bad".into(),
            1 => f.spec.bundle.key = "../bad".into(),
            2 => f.spec.bundle.region = "other-1".into(),
            3 => f.spec.image_record.bytes = 65537,
            _ => f.spec.manifest.bytes = 2 * 1024 * 1024 + 1,
        }
        assert!(f.fetch(Artifact::Bundle).is_err());
        assert!(!f.root.path().join("called").exists());
        f.clean();
    }
}

#[test]
fn publication_accepts_only_exact_concurrent_winner() {
    for mode in ["race", "race-different", "race-mode"] {
        let mut f = Fixture::new(mode);
        assert_eq!(f.fetch(Artifact::Bundle).is_ok(), mode == "race");
        let expected = if mode == "race-different" {
            b"foreign winner".to_vec()
        } else {
            bytes()
        };
        assert_eq!(fs::read(f.path("chain.tar")).unwrap(), expected);
        assert_eq!(
            f.path("chain.tar").metadata().unwrap().mode() & 0o7777,
            if mode == "race-mode" { 0o400 } else { 0o600 }
        );
        f.clean();
    }
}

#[test]
fn metadata_artifacts_use_their_pinned_names_and_private_modes() {
    for (kind, key, name) in [
        (Artifact::Manifest, "manifest", "manifest.json"),
        (Artifact::ImageRecord, "image-record", "image.json"),
        (
            Artifact::ImageManifest,
            "image-manifest",
            "image-manifest.json",
        ),
    ] {
        let mut f = Fixture::new(key);
        let mut expected = bytes();
        if key == "image-record" {
            expected.truncate(128);
            f.spec.image_record.sha256 = zdn::devnet::sha256(&expected);
        }
        f.fetch(kind).unwrap();
        assert_eq!(fs::read(f.path(name)).unwrap(), expected);
        assert_eq!(f.path(name).metadata().unwrap().mode() & 0o7777, 0o600);
        fs::remove_file(&f.aws).unwrap();
        f.fetch(kind).unwrap();
        f.clean();
    }
}

#[test]
fn publication_uses_pinned_directory_not_replaced_ancestor_path() {
    let mut f = Fixture::new("ok");
    let retained = f.root.path().join("retained");
    fs::rename(f.path(""), &retained).unwrap();
    let outside = f.root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, f.root.path().join("artifacts")).unwrap();
    f.fetch(Artifact::Bundle).unwrap();
    assert_eq!(fs::read(retained.join("chain.tar")).unwrap(), bytes());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&retained).unwrap().count(), 1);
}

#[test]
fn cancellation_and_cumulative_deadline_leave_no_artifact_or_pending_directory() {
    let mut f = Fixture::new("wait");
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let until = Instant::now() + Duration::from_secs(10);
            while !f.root.path().join("called").exists() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            cancelled.store(true, Ordering::Relaxed);
        });
        assert!(fetch(
            &f.spec,
            Artifact::Bundle,
            &f.directory,
            &f.aws,
            &mut f.executor,
            &cancelled
        )
        .is_err());
    });
    assert!(!f.path("chain.tar").exists());
    f.clean();
    // A pre-cancelled retry must not start another tool.
    fs::remove_file(f.root.path().join("called")).unwrap();
    assert!(fetch(
        &f.spec,
        Artifact::Bundle,
        &f.directory,
        &f.aws,
        &mut f.executor,
        &cancelled
    )
    .is_err());
    assert!(!f.root.path().join("called").exists());
    drop(f.executor);
    f.executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.root.path().join("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    assert!(f.fetch(Artifact::Bundle).is_err());
    assert!(!f.root.path().join("called").exists());
    f.clean();
    drop(f.executor);
    f.executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.root.path().join("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(11),
    )
    .unwrap();
    assert!(f.fetch(Artifact::Bundle).is_err());
    assert!(f.root.path().join("called").exists());
    assert!(!f.path("chain.tar").exists());
    f.clean();
}
