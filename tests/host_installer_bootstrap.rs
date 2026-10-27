#![cfg(target_os = "linux")]

use zdn::host::{installer_bootstrap, S3Object};
#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// Adapted from host_capacity_bootstrap's native worker transport. Only stat's
// root ownership observation is simulated; real dd/cmp/hash/bash/timeout run.
#[test]
fn transport_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    let mut output;
    let mut code = 0;
    match payload["name"].as_str().unwrap() {
        "stat" => {
            let result = Command::new("/usr/bin/stat").args(&args).output().unwrap();
            code = u8::from(!result.status.success());
            output = result.stdout;
            if args.last().unwrap() == root.join("marker").to_str().unwrap() {
                let text = String::from_utf8(output).unwrap();
                output = if mode == "owner" {
                    b"1234:600:8180\n".to_vec()
                } else if matches!(mode, "open-symlink" | "open-fifo") {
                    // Simulate replacement after lstat; actual GNU dd must
                    // reject a symlink or read a FIFO without blocking.
                    b"0:600:8180\n".to_vec()
                } else {
                    text.replacen(
                        &format!(
                            "{}:",
                            fs::symlink_metadata(root.join("marker")).unwrap().uid()
                        ),
                        "0:",
                        1,
                    )
                    .into_bytes()
                };
            }
        }
        "aws" => {
            fs::write(root.join("aws-called"), "yes").unwrap();
            assert_eq!(
                &args[..10],
                [
                    "s3api",
                    "get-object",
                    "--bucket",
                    "test-bucket",
                    "--key",
                    "installers/host.sh",
                    "--expected-bucket-owner",
                    "123456789012",
                    "--region",
                    "us-east-1"
                ]
            );
            let destination = Path::new(args.last().unwrap());
            assert_eq!(
                fs::metadata(destination.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            fs::write(
                root.join("temporary"),
                destination.parent().unwrap().to_str().unwrap(),
            )
            .unwrap();
            if mode == "download-stall" {
                let mut child = Command::new("/bin/bash")
                    .args(["-c", "trap '' TERM; exec sleep 20"])
                    .spawn()
                    .unwrap();
                fs::write(root.join("descendant"), child.id().to_string()).unwrap();
                child.wait().unwrap();
            } else if mode == "growth" {
                use std::io::Write;
                let mut signals = nix::sys::signal::SigSet::empty();
                signals.add(nix::sys::signal::Signal::SIGXFSZ);
                signals.thread_block().unwrap();
                let mut file = fs::File::create(destination).unwrap();
                for _ in 0..1024 {
                    if file.write_all(&[0; 4096]).is_err() {
                        break;
                    }
                }
                let limit = fs::metadata(root.join("source"))
                    .unwrap()
                    .len()
                    .div_ceil(1024)
                    * 1024;
                assert_eq!(file.metadata().unwrap().len(), limit);
                fs::write(root.join("growth-bounded"), "yes").unwrap();
                code = 1;
            } else {
                let mut bytes = fs::read(root.join("source")).unwrap();
                if mode == "size" {
                    bytes.pop();
                }
                if mode == "digest" {
                    bytes[0] ^= 1;
                }
                fs::write(destination, bytes).unwrap();
                code = u8::from(mode == "download");
            }
            output = b"SECRET-AWS-RESPONSE".to_vec();
        }
        _ => panic!("unexpected native tool"),
    }
    native_tool::reply(&work, &output, b"SECRET-PROVIDER-DIAGNOSTIC", code);
}

struct Fixture {
    root: tempfile::TempDir,
    script: String,
}

impl Fixture {
    fn new(mode: &str, timeout: u32) -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for name in ["stat", "aws"] {
            native_tool::install(
                &bin.join(name),
                "transport_worker",
                &json!({"root": root.path(), "mode": mode, "name": name}),
            );
        }
        let marker = root.path().join("marker");
        fs::write(
            &marker,
            match mode {
                "content" => b"zdn-host-prerequisites/v1alpha1".as_slice(),
                "extra" => b"zdn-host-prerequisites/v1alpha1\n\n".as_slice(),
                _ => b"zdn-host-prerequisites/v1alpha1\n".as_slice(),
            },
        )
        .unwrap();
        fs::set_permissions(
            &marker,
            fs::Permissions::from_mode(if mode == "mode" { 0o644 } else { 0o600 }),
        )
        .unwrap();
        if matches!(mode, "symlink" | "open-symlink") {
            fs::rename(&marker, root.path().join("target")).unwrap();
            std::os::unix::fs::symlink(root.path().join("target"), &marker).unwrap();
        }
        if matches!(mode, "fifo" | "open-fifo" | "directory") {
            fs::remove_file(&marker).unwrap();
            if matches!(mode, "fifo" | "open-fifo") {
                nix::unistd::mkfifo(
                    &marker,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            } else {
                fs::create_dir(&marker).unwrap();
            }
        }
        let body = if mode == "installer-stall" {
            format!(
                "trap '' TERM\nsleep 20 &\nprintf '%s' $! > '{}/descendant'\nwait\n",
                root.path().display()
            )
        } else {
            format!("[[ $(stat -c '%a' -- \"$0\") == 600 ]] || exit 91\nprintf 'installer-output\\n'\nprintf SECRET-INSTALLER >&2\nexit {}\n", if mode == "status" { 42 } else { 0 })
        };
        fs::write(root.path().join("source"), &body).unwrap();
        let object = S3Object {
            bucket: "test-bucket".into(),
            key: "installers/host.sh".into(),
            owner_account: "123456789012".into(),
            region: "us-east-1".into(),
            bytes: body.len() as u64,
            sha256: hex::encode(Sha256::digest(body.as_bytes())),
        };
        // Relocate only marker and scratch effects; leave all timing, limits,
        // control flow and commands exactly as the public renderer produced.
        let script = installer_bootstrap::render(&object, timeout)
            .unwrap()
            .replace("/etc/zdn-prerequisites-ready", marker.to_str().unwrap())
            .replace(
                "/tmp/zdn-installer.XXXXXXXXXX",
                &format!("{}/scratch.XXXXXXXXXX", root.path().display()),
            );
        Self { root, script }
    }

    fn command(&self, watchdog: bool) -> Command {
        let mut command = Command::new(if watchdog {
            "/usr/bin/timeout"
        } else {
            "/bin/bash"
        });
        if watchdog {
            // A broken bounded read must fail the test, not wait for the
            // production transport's deadline. Generated bytes stay unchanged.
            command.args(["--kill-after=1s", "8s", "/bin/bash"]);
        }
        command
            .args(["-c", &self.script])
            .env(
                "PATH",
                format!("{}/bin:/usr/bin:/bin", self.root.path().display()),
            )
            .env("POSIXLY_CORRECT", "1");
        command
    }

    fn assert_cleanup(&self) {
        assert!(!fs::read_dir(self.root.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("scratch.")));
    }
}

#[test]
fn output_integrity_permissions_and_fail_closed_marker() {
    assert_eq!(
        installer_bootstrap::PROTOCOL,
        "zdn-installer-fetch/v1alpha2"
    );
    for mode in [
        "valid",
        "status",
        "owner",
        "mode",
        "content",
        "extra",
        "symlink",
        "fifo",
        "open-symlink",
        "open-fifo",
        "directory",
        "size",
        "digest",
        "download",
        "growth",
    ] {
        let fixture = Fixture::new(mode, if mode == "valid" { 600 } else { 7200 });
        let output = fixture.command(true).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if mode == "valid" {
                0
            } else if mode == "status" {
                42
            } else {
                1
            }),
            "{mode}: {output:?}"
        );
        assert_eq!(
            output.stdout,
            if matches!(mode, "valid" | "status") {
                b"installer-output\n".as_slice()
            } else {
                b""
            },
            "{mode}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("SECRET"),
            "{mode}: {output:?}"
        );
        if [
            "owner",
            "mode",
            "content",
            "extra",
            "symlink",
            "fifo",
            "open-symlink",
            "open-fifo",
            "directory",
        ]
        .contains(&mode)
        {
            assert!(!fixture.root.path().join("aws-called").exists());
        }
        if mode == "growth" {
            assert!(fixture.root.path().join("growth-bounded").exists());
        }
        fixture.assert_cleanup();
    }
}

#[test]
fn cancellation_reaches_both_phase_descendants() {
    for (mode, timeout, interrupt, repeat_term) in [
        ("download-stall", 7200, true, false),
        ("installer-stall", 7200, true, false),
        ("installer-stall", 30, false, false),
        ("download-stall", 7200, true, true),
        ("installer-stall", 7200, true, true),
    ] {
        let mut fixture = Fixture::new(mode, timeout);
        if repeat_term {
            // GNU timeout can deliver TERM directly and then to the group.
            // Force the second delivery at EXIT entry rather than relying on
            // scheduler timing. The cancellation handler must already ignore it.
            fixture.script = fixture
                .script
                .replace("cleanup() { ", "cleanup() { kill -TERM \"$BASHPID\"; ");
        }
        let mut child = fixture
            .command(false)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(if interrupt { 6 } else { 16 });
        let pid_file = fixture.root.path().join("descendant");
        // Existence alone can observe the file before its PID bytes are written.
        let pid = loop {
            if let Some(pid) = fs::read_to_string(&pid_file)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
            {
                assert!(pid > 1);
                break pid;
            }
            assert!(Instant::now() < deadline, "{mode}");
            std::thread::sleep(Duration::from_millis(10));
        };
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let group: i32 = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(2)
            .unwrap()
            .parse()
            .unwrap();
        assert!(group > 1);
        assert_ne!(group, nix::unistd::getpgrp().as_raw());
        if interrupt {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
        }
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "cancellation stalled: {mode}");
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().unwrap();
        assert!(!status.success());
        if !interrupt {
            assert_eq!(
                status.code(),
                Some(124),
                "cumulative deadline did not expire"
            );
        }
        let clean = !fs::read_dir(fixture.root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("scratch.")
        });
        let status = fs::read_to_string(format!("/proc/{pid}/status"));
        let stopped = status.is_err()
            || status
                .unwrap()
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("Z (zombie)"));
        if !clean || !stopped {
            // Failure teardown must not strand the deliberately stubborn child.
            // Assertions use the observations from BEFORE this cleanup.
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(group),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(clean, "{mode}, repeat TERM {repeat_term}: scratch remains");
        assert!(
            stopped,
            "{mode}, repeat TERM {repeat_term}: descendant still live"
        );
    }
}

#[test]
fn invalid_objects_are_rejected() {
    let valid = S3Object {
        bucket: "test-bucket".into(),
        key: "installers/host.sh".into(),
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
        bytes: 1,
        sha256: "a".repeat(64),
    };
    for field in ["bucket", "key", "owner", "region", "bytes", "digest"] {
        let mut object = valid.clone();
        match field {
            "bucket" => object.bucket = "bad;bucket".into(),
            "key" => object.key = "../bad".into(),
            "owner" => object.owner_account.clear(),
            "region" => object.region = "us-gov-west-1".into(),
            "bytes" => object.bytes = 0,
            _ => object.sha256 = "bad".into(),
        }
        assert!(
            installer_bootstrap::render(&object, 7200).is_err(),
            "{field}"
        );
    }
    for timeout in [0, 29, 7201] {
        assert!(installer_bootstrap::render(&valid, timeout).is_err());
    }
}

#[test]
fn published_v1_transport_bytes_remain_frozen() {
    let object = S3Object {
        bucket: "test-bucket".into(),
        key: "installers/host.sh".into(),
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
        bytes: 1,
        sha256: "a".repeat(64),
    };
    // Captured from the published v1alpha1 renderer before the cancellation fix.
    for (timeout, expected) in [
        (
            30,
            "350ededd058e48113f52fcba02fb4fbd54b71f7f954a01e9b4785fc1ac6333c5",
        ),
        (
            600,
            "7a140d1ef9f2fa99f3cd4e6ee10603056dbbcf07689595fb09f83e63ed8dce1a",
        ),
        (
            7200,
            "7e6504906c505ab2ff3636b738e9352fcc86d01927984f5eed491f0457857091",
        ),
    ] {
        let legacy = installer_bootstrap::render_selected(
            installer_bootstrap::LEGACY_PROTOCOL,
            &object,
            timeout,
        )
        .unwrap();
        assert_eq!(hex::encode(Sha256::digest(legacy.as_bytes())), expected);
        let current = installer_bootstrap::render(&object, timeout).unwrap();
        assert_ne!(legacy, current);
        assert_eq!(
            current,
            installer_bootstrap::render_selected(installer_bootstrap::PROTOCOL, &object, timeout)
                .unwrap()
        );
    }
    assert!(installer_bootstrap::render_selected("unknown", &object, 7200).is_err());
}
