//! Real exec children for stream, environment, signal and descendant cleanup tests.

use crate::executable;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Case {
    Streams(i32),
    Signal,
    Quiet,
    Started,
    Counted,
    Environment(i32),
    Finished,
    Stubborn,
}

pub fn install(root: &Path, case: Case) -> PathBuf {
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let executable = quote(std::env::current_exe().unwrap().to_str().unwrap());
    let args = quote(root.join("child.args").to_str().unwrap());
    let log = quote(root.join("child.harness.log").to_str().unwrap());
    let payload = quote(&serde_json::to_string(&case).unwrap());
    let ignore = if matches!(case, Case::Stubborn) {
        "trap '' INT\n"
    } else {
        ""
    };
    let path = root.join("child");
    executable::write(
        &path,
        format!(
            r#"#!/bin/sh
set -eu
{ignore}printf '%s\0' "$@" > {args}
exec 3>&1 4>&2
ZDN_TEST_CHILD={payload} exec {executable} --exact connect_child::worker --nocapture > {log} 2>&1
"#
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[expect(
    clippy::zombie_processes,
    reason = "the test requires a descendant to outlive this child; zdn must clean its group"
)]
fn descendant(stdout: &File, stderr: &File) {
    // Inherit the child's process group and streams, just like an ordinary
    // subprocess. Product cleanup must stop it even after the direct child exits.
    let child = Command::new("/bin/sleep")
        .arg("60")
        .stdout(Stdio::from(stdout.try_clone().unwrap()))
        .stderr(Stdio::from(stderr.try_clone().unwrap()))
        .spawn()
        .unwrap();
    fs::write("descendant.pid", child.id().to_string()).unwrap();
}

#[test]
fn worker() {
    let Ok(payload) = std::env::var("ZDN_TEST_CHILD") else {
        return;
    };
    let case: Case = serde_json::from_str(&payload).unwrap();
    assert_eq!(fs::read("child.args").unwrap(), b"--literal-argument\0");
    let mut stdout = OpenOptions::new().write(true).open("/dev/fd/3").unwrap();
    let mut stderr = OpenOptions::new().write(true).open("/dev/fd/4").unwrap();
    for fd in [3, 4] {
        nix::unistd::close(fd).unwrap();
    }
    let code = match case {
        Case::Streams(code) => {
            writeln!(stdout, "child stdout").unwrap();
            writeln!(stderr, "child stderr").unwrap();
            code
        }
        Case::Signal => {
            nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGTERM)
                .unwrap();
            unreachable!("SIGTERM must terminate the exec child")
        }
        Case::Quiet => 0,
        Case::Started => {
            fs::write("child-started", b"").unwrap();
            0
        }
        Case::Counted => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("launch-count")
                .unwrap();
            file.write_all(b"x").unwrap();
            writeln!(stdout, "child stdout").unwrap();
            37
        }
        Case::Environment(code) => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap();
            assert!(input.is_empty());
            assert_eq!(
                std::env::var("AWS_CONFIG_FILE").unwrap(),
                "./original-config"
            );
            assert!(std::env::var_os("ZDN_LIGHTWALLET_GRPC_URL").is_none());
            assert_eq!(
                std::env::var("ZDN_CONSENSUS_FINGERPRINT").unwrap(),
                "ab".repeat(32)
            );
            assert_eq!(
                std::env::var("ZDN_NETWORK_ID").unwrap(),
                "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153"
            );
            let url = std::env::var("ZDN_RPC_URL").unwrap();
            let report: serde_json::Value = serde_json::from_reader(
                ureq::get(&format!("{url}/health"))
                    .call()
                    .unwrap()
                    .into_reader(),
            )
            .unwrap();
            assert_eq!(report["status"], "ready");
            fs::write(
                "child-report",
                serde_json::json!({"cwd":std::env::current_dir().unwrap(),"url":url}).to_string(),
            )
            .unwrap();
            descendant(&stdout, &stderr);
            writeln!(stdout, "child stdout").unwrap();
            writeln!(stderr, "child stderr").unwrap();
            code
        }
        Case::Finished => {
            writeln!(stdout, "finished").unwrap();
            0
        }
        Case::Stubborn => {
            descendant(&stdout, &stderr);
            fs::write("child-started", b"").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            0
        }
    };
    std::process::exit(code);
}
