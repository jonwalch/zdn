#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use eyre::{bail, Result};
use nix::unistd::{getpgid, getppid, getsid};
use serde_json::{json, Value};
use tempfile::tempdir;
use zdn::pulumi::{CommandSpec, ProcessLimits, PulumiRunner, RunControl, SystemPulumiRunner};

#[path = "support/executable.rs"]
mod executable;

const MARKER: &str = ".zdn-pulumi-process.json";

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} was not created",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn fixture_command(mode: &str, directory: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "process_fixture", "--nocapture"])
        .env("ZDN_TEST_PROCESS_MODE", mode)
        .env("ZDN_TEST_PROCESS_DIR", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
fn process_fixture() {
    let Some(mode) = std::env::var_os("ZDN_TEST_PROCESS_MODE") else {
        return;
    };
    let directory = std::path::PathBuf::from(std::env::var_os("ZDN_TEST_PROCESS_DIR").unwrap());
    let mode = mode.to_str().unwrap();
    if mode == "other-session" {
        nix::unistd::setsid().unwrap();
    }
    if mode == "provider" || mode == "other-session" {
        // Emulate Pulumi's Setpgid plugins. No setsid escape or cloud calls.
        ctrlc::set_handler(|| {}).unwrap();
        if directory.join("intermediate-pid").exists() {
            let old_parent: i32 = fs::read_to_string(directory.join("intermediate-pid"))
                .unwrap()
                .parse()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while getppid().as_raw() == old_parent {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        zdn::foundation::write_json(
            &directory.join("provider.json"),
            &json!({
                "pid": std::process::id(), "pgid": getpgid(None).unwrap().as_raw(),
                "sid": getsid(None).unwrap().as_raw(), "ppid": getppid().as_raw(),
            }),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(1000));
        fs::write(directory.join("escaped"), "provider still ran").unwrap();
        return;
    }
    if mode == "intermediate" {
        fs::write(
            directory.join("intermediate-pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        let _child = fixture_command("provider", &directory)
            .process_group(0)
            .spawn()
            .unwrap();
        std::process::exit(0);
    }
    let interrupted = directory.join("interrupted");
    ctrlc::set_handler(move || {
        let _ = fs::write(&interrupted, "SIGINT");
    })
    .unwrap();
    let mut provider = fixture_command("intermediate", &directory)
        .process_group(0)
        .spawn()
        .unwrap();
    provider.wait().unwrap();
    wait_for(&directory.join("provider.json"));
    fs::write(directory.join("started"), std::process::id().to_string()).unwrap();
    if mode == "normal" {
        return;
    }
    // Finite even on regression, so an assertion failure cannot leave a worker.
    std::thread::sleep(Duration::from_secs(4));
}

fn spec(directory: &Path, mode: &str) -> CommandSpec {
    CommandSpec {
        label: "detached-plugin".into(),
        program: std::env::current_exe().unwrap(),
        args: ["--exact", "process_fixture", "--nocapture"]
            .into_iter()
            .map(Into::into)
            .collect(),
        env: BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("ZDN_TEST_PROCESS_MODE".into(), mode.into()),
            ("ZDN_TEST_PROCESS_DIR".into(), directory.as_os_str().into()),
        ]),
        cwd: directory.into(),
        diagnostics_dir: directory.join("diagnostics"),
        limits: ProcessLimits {
            shutdown_grace: Duration::from_millis(80),
            poll_interval: Duration::from_millis(5),
            ..ProcessLimits::default()
        },
    }
}

#[test]
fn separate_groups_and_reparented_plugins_stop_before_runner_returns() {
    for mode in ["cancel", "lease-error", "normal"] {
        let root = tempdir().unwrap();
        let outsider = tempdir().unwrap();
        let mut unrelated = fixture_command("provider", outsider.path())
            .process_group(0)
            .spawn()
            .unwrap();
        wait_for(&outsider.path().join("provider.json"));
        let command = spec(root.path(), mode);
        let result =
            SystemPulumiRunner::new(env!("CARGO_BIN_EXE_zdn").into()).run(&command, &mut || {
                if root.path().join("started").exists() {
                    match mode {
                        "cancel" => return Ok(RunControl::Cancel),
                        "lease-error" => bail!("lease no longer owned"),
                        _ => {}
                    }
                }
                Ok(RunControl::Continue)
            });
        if mode == "normal" {
            assert!(result.unwrap().success);
        } else {
            assert!(result.is_err());
        }
        let provider: Value =
            serde_json::from_slice(&fs::read(root.path().join("provider.json")).unwrap()).unwrap();
        assert_eq!(provider["pid"], provider["pgid"]);
        assert_ne!(provider["pgid"], provider["sid"]);
        let old_parent: u32 = fs::read_to_string(root.path().join("intermediate-pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(
            provider["ppid"], old_parent,
            "fixture must really be reparented"
        );
        assert!(
            !root.path().join(MARKER).exists(),
            "cleanup acknowledgement must precede return"
        );
        if mode != "normal" {
            assert!(root.path().join("interrupted").exists());
        }
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            !root.path().join("escaped").exists(),
            "detached provider survived cleanup"
        );
        assert!(unrelated.wait().unwrap().success());
        assert!(
            outsider.path().join("escaped").exists(),
            "another run's process was signalled"
        );
    }
}

#[test]
fn cleanup_helper_refuses_foreign_sessions_and_its_session_leader_group() {
    let session = getsid(None).unwrap().as_raw();
    for requested in [session + 1, session] {
        let status = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .args([
                "__kill-pulumi-group",
                "--session",
                &requested.to_string(),
                "--group",
                &session.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
    }
    let foreign = tempdir().unwrap();
    let mut worker = fixture_command("other-session", foreign.path())
        .spawn()
        .unwrap();
    wait_for(&foreign.path().join("provider.json"));
    let info: Value =
        serde_json::from_slice(&fs::read(foreign.path().join("provider.json")).unwrap()).unwrap();
    assert_ne!(info["sid"], session);
    let status = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .args([
            "__kill-pulumi-group",
            "--session",
            &session.to_string(),
            "--group",
            &worker.id().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "setpgid must reject a foreign/reused group ID"
    );
    assert!(worker.wait().unwrap().success());
    assert!(foreign.path().join("escaped").exists());
}

#[test]
fn missing_cleanup_acknowledgement_blocks_the_next_run() {
    let root = tempdir().unwrap();
    let broken = root.path().join("broken-supervisor");
    executable::write(&broken, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o700)).unwrap();
    let command = spec(root.path(), "normal");
    let error = SystemPulumiRunner::new(broken)
        .run(&command, &mut || Ok(RunControl::Continue))
        .unwrap_err();
    assert!(error.to_string().contains("cleanup"), "{error:#}");
    assert!(root.path().join(MARKER).exists());
    assert!(zdn::pulumi_process::ensure_cleanup(root.path()).is_err());
    assert!(SystemPulumiRunner::new(env!("CARGO_BIN_EXE_zdn").into())
        .run(&command, &mut || Ok(RunControl::Continue))
        .is_err());
    assert!(!root.path().join("started").exists());
}

#[test]
fn a_missing_program_can_fail_without_leaving_an_uncertain_worker() -> Result<()> {
    let root = tempdir()?;
    let mut command = spec(root.path(), "normal");
    command.program = root.path().join("absent-program");
    let output = SystemPulumiRunner::new(env!("CARGO_BIN_EXE_zdn").into())
        .run(&command, &mut || Ok(RunControl::Continue))?;
    assert!(!output.success);
    assert!(!root.path().join(MARKER).exists());
    Ok(())
}

#[test]
fn losing_the_writer_control_pipe_still_cleans_up_the_session() {
    let root = tempdir().unwrap();
    let token = uuid::Uuid::new_v4();
    let marker = root.path().join(MARKER);
    fs::write(
        &marker,
        serde_json::to_vec(&json!({
            "token": token, "session": null, "cli_pid": null, "completion": null,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .args(["__supervise-pulumi", "--marker"])
        .arg(&marker)
        .args([
            "--token",
            &token.to_string(),
            "--grace-ms",
            "80",
            "--timeout-ms",
            "3000",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "process_fixture", "--nocapture"])
        .env("ZDN_TEST_PROCESS_MODE", "cancel")
        .env("ZDN_TEST_PROCESS_DIR", root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for(&root.path().join("started"));
    supervisor.stdin.take();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = supervisor.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let receipt: Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    assert!(receipt["completion"].is_object());
    assert_eq!(receipt["completion"]["success"], false);
    zdn::pulumi_process::ensure_cleanup(root.path()).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!root.path().join("escaped").exists());
}
