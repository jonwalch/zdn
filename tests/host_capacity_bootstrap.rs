#![cfg(target_os = "linux")]

#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use zdn::host::{capacity_bootstrap::render, S3Object};

const OBSERVATION: &[u8] = b"{\"mem_total_bytes\":123}\n";

#[test]
fn transport_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    let name = payload["name"].as_str().unwrap();
    let mut output = Vec::new();
    let mut code = 0;
    match name {
        "mktemp" => {
            let result = Command::new("/usr/bin/mktemp")
                .args(&args)
                .output()
                .unwrap();
            assert!(result.status.success());
            output = result.stdout;
            fs::write(root.join("temporary"), &output).unwrap();
            let directory = String::from_utf8(output.clone()).unwrap();
            assert_eq!(
                fs::metadata(directory.trim()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        "stat" if args.last().unwrap() == "/etc/zdn-prerequisites-ready" => {
            output = match mode {
                "owner" => b"1000:600:8180\n".to_vec(),
                "mode" => b"0:644:81a4\n".to_vec(),
                "symlink" => b"0:600:a180\n".to_vec(),
                "fifo" => b"0:600:1180\n".to_vec(),
                "directory" => b"0:600:4180\n".to_vec(),
                _ => b"0:600:8180\n".to_vec(),
            };
        }
        "stat" => {
            let result = Command::new("/usr/bin/stat").args(&args).output().unwrap();
            assert!(result.status.success());
            output = result.stdout;
        }
        "dd" => {
            assert!(args.contains(&"count=33".into()));
            assert!(args.contains(&"iflag=nofollow,nonblock".into()));
            // Exercise real GNU dd's bounded/no-follow/nonblocking read, with
            // only the fixed /etc path mapped to a fixture-owned regular file.
            let source = root.join("marker");
            let mapped: Vec<_> = args
                .iter()
                .map(|arg| {
                    if arg.starts_with("if=") {
                        format!("if={}", source.display())
                    } else {
                        arg.clone()
                    }
                })
                .collect();
            let status = Command::new("/usr/bin/dd").args(mapped).status().unwrap();
            code = u8::from(!status.success());
        }
        "aws" => {
            fs::write(root.join("aws-called"), "yes").unwrap();
            assert_eq!(&args[..2], ["s3api", "get-object"]);
            for (flag, value) in [
                ("--bucket", "test-bucket"),
                ("--key", "helpers/zdn"),
                ("--expected-bucket-owner", "123456789012"),
                ("--region", "us-east-1"),
            ] {
                let index = args.iter().position(|arg| arg == flag).unwrap();
                assert_eq!(args[index + 1], value);
            }
            let destination = args.last().unwrap();
            if mode == "stall" {
                let mut child = Command::new("/usr/bin/sleep").arg("20").spawn().unwrap();
                fs::write(root.join("descendant"), child.id().to_string()).unwrap();
                child.wait().unwrap();
            } else if mode == "growth" {
                use std::io::Write;
                let mut blocked = nix::sys::signal::SigSet::empty();
                blocked.add(nix::sys::signal::Signal::SIGXFSZ);
                blocked.thread_block().unwrap();
                let mut file = fs::File::create(destination).unwrap();
                for _ in 0..1024 {
                    if file.write_all(&[0; 4096]).is_err() {
                        break;
                    }
                }
                let maximum = fs::metadata(root.join("helper-source"))
                    .unwrap()
                    .len()
                    .div_ceil(1024)
                    * 1024;
                assert_eq!(file.metadata().unwrap().len(), maximum);
                fs::write(root.join("growth-bounded"), "yes").unwrap();
                code = 1;
            } else {
                fs::copy(root.join("helper-source"), destination).unwrap();
                if mode == "size" {
                    fs::write(destination, "short").unwrap();
                }
                if mode == "digest" {
                    let mut bytes = fs::read(destination).unwrap();
                    bytes[0] ^= 1;
                    fs::write(destination, bytes).unwrap();
                }
                code = u8::from(mode == "download");
            }
            output = b"SECRET-AWS-RESPONSE\n".to_vec();
        }
        "helper" => {
            let directory = fs::read_to_string(root.join("temporary")).unwrap();
            assert_eq!(
                fs::metadata(Path::new(directory.trim()).join("helper"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            if args[0] == "__runtime-capabilities" {
                assert_eq!(
                    args,
                    [
                        "__runtime-capabilities",
                        "--require",
                        "zdn-host-capacity/v1alpha1"
                    ]
                );
                output = b"SECRET-CAPABILITY-JSON\n".to_vec();
                code = u8::from(mode == "capability");
            } else {
                assert_eq!(
                    args,
                    [
                        "__host-capacity",
                        "--protocol",
                        "zdn-host-capacity/v1alpha1"
                    ]
                );
                output = OBSERVATION.to_vec();
                code = u8::from(mode == "observation");
            }
        }
        _ => panic!("unexpected tool"),
    }
    let diagnostic: &[u8] = if matches!(name, "aws" | "helper") {
        b"SECRET-PROVIDER-DIAGNOSTIC\n"
    } else {
        b""
    };
    native_tool::reply(&work, &output, diagnostic, code);
}

struct Fixture {
    root: tempfile::TempDir,
    script: String,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for name in ["stat", "dd", "aws", "mktemp", "helper"] {
            let path = if name == "helper" {
                root.path().join("helper-source")
            } else {
                bin.join(name)
            };
            native_tool::install(
                &path,
                "transport_worker",
                &json!({"root": root.path(), "name": name, "mode": mode}),
            );
        }
        let marker: &[u8] = match mode {
            "content" => b"zdn-host-prerequisites/v1alpha1",
            "extra" => b"zdn-host-prerequisites/v1alpha1\n\n",
            _ => b"zdn-host-prerequisites/v1alpha1\n",
        };
        fs::write(root.path().join("marker"), marker).unwrap();
        if mode == "open-symlink" {
            fs::rename(root.path().join("marker"), root.path().join("target")).unwrap();
            std::os::unix::fs::symlink(root.path().join("target"), root.path().join("marker"))
                .unwrap();
        }
        if mode == "open-fifo" {
            fs::remove_file(root.path().join("marker")).unwrap();
            nix::unistd::mkfifo(&root.path().join("marker"), nix::sys::stat::Mode::S_IRUSR)
                .unwrap();
        }
        let bytes = fs::read(root.path().join("helper-source")).unwrap();
        let object = S3Object {
            bucket: "test-bucket".into(),
            key: "helpers/zdn".into(),
            owner_account: "123456789012".into(),
            region: "us-east-1".into(),
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        Self {
            root,
            script: render(&object).unwrap(),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("/bin/bash");
        command.args(["-c", &self.script]).env(
            "PATH",
            format!("{}/bin:/usr/bin:/bin", self.root.path().display()),
        );
        command
    }

    fn assert_cleanup(&self) {
        let path = fs::read_to_string(self.root.path().join("temporary")).unwrap();
        assert!(!Path::new(path.trim()).exists(), "private work survived");
    }
}

#[test]
fn observation_only_and_fail_closed_cleanup() {
    for mode in [
        "valid",
        "owner",
        "mode",
        "symlink",
        "fifo",
        "directory",
        "content",
        "extra",
        "open-symlink",
        "open-fifo",
        "download",
        "growth",
        "size",
        "digest",
        "capability",
        "observation",
    ] {
        let fixture = Fixture::new(mode);
        let output = fixture.command().output().unwrap();
        assert_eq!(
            output.status.success(),
            mode == "valid",
            "{mode}: {output:?}"
        );
        assert_eq!(
            output.stdout,
            if mode == "valid" { OBSERVATION } else { b"" },
            "{mode}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("SECRET"),
            "{mode}: {output:?}"
        );
        if [
            "owner",
            "mode",
            "symlink",
            "fifo",
            "directory",
            "content",
            "extra",
            "open-symlink",
            "open-fifo",
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
fn cancellation_terminates_download_descendant_and_cleans_private_work() {
    let fixture = Fixture::new("stall");
    let mut child = fixture.command().spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid_file = fixture.root.path().join("descendant");
    while !pid_file.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    // Signal the wrapper PID, not its group: GNU timeout must propagate it.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert!(!child.wait().unwrap().success());
    fixture.assert_cleanup();
    let pid = fs::read_to_string(pid_file).unwrap();
    let status = fs::read_to_string(format!("/proc/{}/status", pid.trim()));
    assert!(
        status.is_err()
            || status
                .unwrap()
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("Z (zombie)")),
        "descendant remained live"
    );
}

#[test]
fn rejects_invalid_objects_before_rendering() {
    let valid = S3Object {
        bucket: "test-bucket".into(),
        key: "helpers/zdn".into(),
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
        assert!(render(&object).is_err(), "{field}");
    }
}
