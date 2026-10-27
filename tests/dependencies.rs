use eyre::{bail, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use zdn::dependencies::{
    builtin_manifest, doctor, install, verify_installed, Downloader, HttpDownloader, ProcessOutput,
    ProcessRunner, SystemProcessRunner, ToolArtifact, ToolFile, ToolManifest,
};

const PLATFORM: &str = "linux-amd64";

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

#[cfg(unix)]
#[path = "support/machine_failure.rs"]
mod machine_failure;

#[cfg(unix)]
#[test]
fn machine_doctor_keeps_incomplete_checks_and_only_probes_local_versions() {
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;

    for format in ["json", "jsonl"] {
        let root = tempfile::tempdir().unwrap();
        machine_failure::install(root.path());
        for (name, version) in [
            ("git", "git version 2.50.0 SECRET"),
            ("aws", "aws-cli/2.37.4 SECRET"),
            ("session-manager-plugin", "1.2.3.4"),
        ] {
            let path = root.path().join("bin").join(name);
            executable::write(&path, format!("#!/bin/sh\n[ \"$*\" = --version ] || exit 99\nprintf '%s\\n' '{version}'\nprintf SECRET >&2\n")).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        for complete in [true, false] {
            let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
                .env_clear()
                .env(
                    "PATH",
                    root.path()
                        .join(if complete { "bin" } else { "absent-SECRET" }),
                )
                .args(["--format", format, "doctor", "--managed-dir"])
                .arg(root.path().join("tools"))
                .output()
                .unwrap();
            assert_eq!(output.status.success(), complete);
            assert!(output.stderr.is_empty());
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(!text.contains("SECRET"));
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&text).unwrap()]
            } else {
                text.lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
            if format == "jsonl" {
                assert_eq!(records[0]["type"], "command-started");
            }
            let result = records.last().unwrap();
            assert_eq!(result["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(result["command"], "doctor");
            assert_eq!(result["type"], "result");
            assert_eq!(
                result["outcome"],
                if complete { "succeeded" } else { "failed" }
            );
            assert!(result["networkId"].is_null());
            assert!(result["operationId"].is_null());
            assert_eq!(result["data"]["ready"], complete);
            assert_eq!(result["data"]["aws_identity_checked"], false);
            let checks = result["data"]["checks"].as_array().unwrap();
            assert_eq!(checks.len(), 4);
            assert_eq!(
                checks.iter().filter(|c| c["ok"] == true).count(),
                if complete { 4 } else { 1 }
            );
            for check in checks {
                assert_eq!(
                    check["detail"],
                    if check["ok"] == true {
                        "verified"
                    } else {
                        "unavailable-or-invalid"
                    }
                );
            }
            if complete {
                assert!(result["error"].is_null());
            } else {
                assert_eq!(result["error"]["code"], "prerequisites-incomplete");
                assert_eq!(result["error"]["retryClassification"], "blocked");
            }
        }
    }
}

fn archive(entries: &[(&str, u32, tar::EntryType, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    for (path, mode, kind, contents) in entries {
        let mut header = tar::Header::new_gnu();
        // Fill the path directly to create traversal fixtures which tar's safe
        // writer API correctly refuses to produce from a filesystem path.
        assert!(path.len() < 100);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_mode(*mode);
        header.set_entry_type(*kind);
        header.set_size(contents.len() as u64);
        if kind.is_symlink() || kind.is_hard_link() {
            header.set_link_name("outside").unwrap();
        }
        header.set_cksum();
        builder.append(&header, *contents).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn good_archive() -> Vec<u8> {
    archive(&[(
        "tool",
        0o755,
        tar::EntryType::Regular,
        b"fixture executable",
    )])
}

fn manifest(bytes: &[u8]) -> ToolManifest {
    ToolManifest {
        schema_version: 1,
        catalog: "test-catalog".into(),
        sources: vec!["fixture: no network".into()],
        platforms: BTreeMap::from([(
            PLATFORM.into(),
            vec![ToolArtifact {
                name: "fixture-tool".into(),
                version: "1.2.3".into(),
                url: "https://example.invalid/fixture.tar.gz".into(),
                sha256: hex::encode(Sha256::digest(bytes)),
                max_download_bytes: 1024 * 1024,
                max_unpacked_bytes: 1024 * 1024,
                files: vec![ToolFile {
                    archive_path: "tool".into(),
                    install_path: "bin/tool".into(),
                }],
                allowed_unused_executables: Vec::new(),
            }],
        )]),
    }
}

struct BytesDownloader(Vec<u8>);

impl Downloader for BytesDownloader {
    fn download(&self, _: &str, destination: &mut File, _: u64) -> Result<()> {
        destination.write_all(&self.0)?;
        Ok(())
    }
}

struct NoDownload;

impl Downloader for NoDownload {
    fn download(&self, _: &str, _: &mut File, _: u64) -> Result<()> {
        panic!("a verified installed version must not download again")
    }
}

#[test]
fn builtin_catalog_has_exact_reviewed_pins_for_all_supported_platforms() {
    let catalog = builtin_manifest().unwrap();
    assert_eq!(catalog.platforms.len(), 4);
    for tools in catalog.platforms.values() {
        assert_eq!(tools.len(), 3);
        assert_eq!(
            (tools[0].name.as_str(), tools[0].version.as_str()),
            ("pulumi", "3.268.0")
        );
        assert_eq!(
            (tools[1].name.as_str(), tools[1].version.as_str()),
            ("pulumi-language-yaml", "1.38.10")
        );
        assert_eq!(
            (tools[2].name.as_str(), tools[2].version.as_str()),
            ("pulumi-resource-aws", "7.50.0")
        );
        assert!(tools
            .iter()
            .all(|tool| tool.url.starts_with("https://github.com/pulumi/")));
    }
    assert_eq!(
        catalog.platforms["darwin-arm64"][0].sha256,
        "ef509a84f0ad8f4ed0ec04be957e6688f094eb9a1cdc676a4864103d66d8a4e9"
    );
    assert_eq!(
        catalog.platforms["linux-amd64"][2].sha256,
        "fc468cf6e1b9494d8d6a98b9ef1db73c7d180af436f4241b8fdb123a46f72e3d"
    );
}

struct Versions {
    aws: &'static str,
    missing_ssm: bool,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl ProcessRunner for Versions {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<ProcessOutput> {
        assert!(timeout <= Duration::from_secs(5));
        self.calls
            .lock()
            .unwrap()
            .push((program.into(), args.iter().map(|s| s.to_string()).collect()));
        let text = match program {
            "git" => "git version 2.49.0",
            "aws" => self.aws,
            "session-manager-plugin" if self.missing_ssm => {
                bail!("session-manager-plugin was not found")
            }
            "session-manager-plugin" => "1.2.707.0",
            _ => panic!("doctor must not invoke other commands"),
        };
        Ok(ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: text.into(),
            stderr: String::new(),
        })
    }
}

#[test]
fn doctor_only_probes_local_versions_and_reports_v1_or_missing_ssm() {
    let versions = Versions {
        aws: "aws-cli/1.38.0 Python/3",
        missing_ssm: true,
        calls: Mutex::default(),
    };
    let report = doctor(&versions, None);
    assert!(!report.ready);
    assert!(!report.aws_identity_checked);
    assert!(report.checks[0].ok);
    assert!(!report.checks[1].ok);
    assert!(!report.checks[2].ok);
    let calls = versions.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|(_, args)| args == &["--version"]));
}

#[test]
fn doctor_missing_managed_tools_does_not_create_a_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("not-created");
    let versions = Versions {
        aws: "aws-cli/2.37.4 Python/3",
        missing_ssm: false,
        calls: Mutex::default(),
    };
    let report = doctor(&versions, Some(&root));
    assert!(report.checks[..3].iter().all(|check| check.ok));
    assert!(!report.checks[3].ok);
    assert!(!root.exists());
}

#[test]
fn doctor_rejects_aws_v2_before_the_foundation_api_minimum() {
    let versions = Versions {
        aws: "aws-cli/2.30.0 Python/3",
        missing_ssm: false,
        calls: Mutex::default(),
    };
    let report = doctor(&versions, None);
    assert!(!report.ready);
    assert!(
        !report
            .checks
            .iter()
            .find(|check| check.name == "aws")
            .unwrap()
            .ok
    );
    assert!(!report.aws_identity_checked);
}

#[cfg(unix)]
#[test]
fn process_runner_executes_a_fake_binary_with_literal_arguments_and_a_deadline() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::Builder::new()
        .prefix("zdn tool ")
        .tempdir()
        .unwrap();
    let path = temp.path().join("aws fake");
    executable::write(&path, b"#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 3\nprintf 'aws-cli/2.30.0\\n'\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let output = SystemProcessRunner
        .run(
            path.to_str().unwrap(),
            &["--version"],
            Duration::from_secs(1),
        )
        .unwrap();
    assert!(output.success);
    assert_eq!(output.stdout.trim(), "aws-cli/2.30.0");
    executable::write(&path, b"#!/bin/sh\nwhile :; do :; done\n").unwrap();
    let error = SystemProcessRunner
        .run(
            path.to_str().unwrap(),
            &["--version"],
            Duration::from_millis(20),
        )
        .unwrap_err();
    assert!(error.to_string().contains("limit"));
}

#[cfg(unix)]
#[test]
fn prepared_commands_keep_their_environment_and_working_directory() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let program = temp.path().join("probe");
    executable::write(&program, b"#!/bin/sh\n[ \"$ZDN_PROBE_VALUE\" = 'literal value' ] || exit 2\n[ -z \"$ZDN_PROBE_REMOVED\" ] || exit 3\n[ \"$1\" = '--literal' ] || exit 4\ncat marker\n").unwrap();
    fs::write(temp.path().join("marker"), "selected working directory\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = Command::new(program);
    command
        .arg("--literal")
        .current_dir(temp.path())
        .env("ZDN_PROBE_VALUE", "literal value")
        .env("ZDN_PROBE_REMOVED", "must not survive")
        .env_remove("ZDN_PROBE_REMOVED");
    let output = zdn::dependencies::run_command(&mut command, Duration::from_secs(1)).unwrap();
    assert!(output.success);
    assert_eq!(output.stdout, "selected working directory\n");
}

#[cfg(unix)]
#[test]
fn memory_capture_uses_pipes_and_drains_both_streams_at_the_limit() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        r#"[ -p /dev/fd/1 ] && [ -p /dev/fd/2 ] || exit 99
dd if=/dev/zero bs=1048576 count=1 2>/dev/null &
(dd if=/dev/zero bs=1048576 count=1 2>/dev/null) >&2 &
wait
"#,
    ]);
    let output =
        zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(3)).unwrap();
    assert!(output.success, "stdout and stderr must be pipes, not files");
    assert_eq!(output.stdout.as_bytes(), vec![0; 1048576]);
    assert_eq!(output.stderr.as_bytes(), vec![0; 1048576]);
}

#[cfg(unix)]
#[test]
fn memory_capture_bounds_either_stream_and_does_not_echo_its_contents() {
    for redirect in ["", ">&2"] {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            &format!("(dd if=/dev/zero bs=1048563 count=1 2>/dev/null; printf fixture-secret) {redirect}"),
        ]);
        let started = Instant::now();
        let error = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_secs(3))
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.to_string().contains("output limit"));
        assert!(!format!("{error:#}").contains("fixture-secret"));
    }
}

#[cfg(unix)]
#[test]
fn memory_capture_kills_inherited_helpers_on_timeout_and_normal_exit() {
    for wait_for_helper in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let late = temp.path().join("late");
        let started_marker = temp.path().join("started");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                &format!(
                    "(sleep 0.3; printf late > \"$1\") &\nprintf started > \"$2\"\n{}",
                    if wait_for_helper { "wait" } else { "exit 0" }
                ),
                "fixture",
            ])
            .arg(&late)
            .arg(&started_marker);
        let started = Instant::now();
        let result =
            zdn::dependencies::run_command_in_memory(&mut command, Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(started_marker.exists(), "helper must have started");
        if wait_for_helper {
            assert!(result.unwrap_err().to_string().contains("time limit"));
        } else {
            assert!(result.unwrap().success);
        }
        std::thread::sleep(Duration::from_millis(350));
        assert!(!late.exists(), "inherited helper survived group cleanup");
    }
}

#[cfg(unix)]
#[test]
#[allow(
    clippy::zombie_processes,
    reason = "fixture must exit before its detached helper; parent test kills the helper group"
)]
fn memory_capture_detached_child_fixture() {
    use std::os::unix::process::CommandExt;
    let Some(pid_file) = std::env::var_os("ZDN_MEMORY_CAPTURE_PID_FILE") else {
        return;
    };
    let mut helper = Command::new("/bin/sh");
    helper
        .args(["-c", "sleep 10"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    let child = helper.spawn().unwrap();
    fs::write(pid_file, child.id().to_string()).unwrap();
    // This fixture intentionally leaves a helper in another process group with
    // both pipes open. The parent test owns and kills this detached helper.
}

#[cfg(unix)]
#[test]
fn memory_capture_deadline_includes_eof_from_a_detached_helper() {
    struct DetachedCleanup(std::path::PathBuf);
    impl Drop for DetachedCleanup {
        fn drop(&mut self) {
            use nix::{sys::signal::killpg, sys::signal::Signal, unistd::Pid};
            if let Ok(pid) = fs::read_to_string(&self.0) {
                let _ = killpg(Pid::from_raw(pid.parse().unwrap()), Signal::SIGKILL);
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let cleanup = DetachedCleanup(temp.path().join("pid"));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "memory_capture_detached_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZDN_MEMORY_CAPTURE_PID_FILE", &cleanup.0);
    let started = Instant::now();
    let error = zdn::dependencies::run_command_in_memory(&mut command, Duration::from_millis(250))
        .unwrap_err();
    assert!(cleanup.0.exists(), "detached helper must have started");
    assert!(error.to_string().contains("time limit"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn verified_install_is_atomic_and_reused_without_network() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let pins = manifest(&bytes);
    let receipt = install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).unwrap();
    assert_eq!(
        fs::read(temp.path().join(&receipt.installation).join("bin/tool")).unwrap(),
        b"fixture executable"
    );
    assert_eq!(
        verify_installed(&pins, PLATFORM, temp.path()).unwrap(),
        receipt
    );
    assert_eq!(
        install(&pins, PLATFORM, temp.path(), &NoDownload).unwrap(),
        receipt
    );
}

#[test]
fn checksum_and_partial_download_failures_preserve_the_working_installation() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let original = manifest(&bytes);
    install(
        &original,
        PLATFORM,
        temp.path(),
        &BytesDownloader(bytes.clone()),
    )
    .unwrap();
    let active = fs::read(temp.path().join("active.json")).unwrap();
    let mut changed = original.clone();
    changed.catalog = "new-catalog".into();
    let error = install(
        &changed,
        PLATFORM,
        temp.path(),
        &BytesDownloader(b"corrupt".to_vec()),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("SHA256"),
        "actual error: {error:#}"
    );
    struct Interrupted;
    impl Downloader for Interrupted {
        fn download(&self, _: &str, file: &mut File, _: u64) -> Result<()> {
            file.write_all(b"partial")?;
            bail!("download interrupted")
        }
    }
    assert!(install(&changed, PLATFORM, temp.path(), &Interrupted).is_err());
    assert_eq!(fs::read(temp.path().join("active.json")).unwrap(), active);
    verify_installed(&original, PLATFORM, temp.path()).unwrap();
}

#[test]
fn archive_traversal_links_modes_and_unexpected_executables_are_rejected() {
    for (path, mode, kind, data) in [
        (
            "../outside",
            0o755,
            tar::EntryType::Regular,
            b"x".as_slice(),
        ),
        ("/absolute", 0o755, tar::EntryType::Regular, b"x".as_slice()),
        (
            "a/../../outside",
            0o755,
            tar::EntryType::Regular,
            b"x".as_slice(),
        ),
        ("tool/", 0o755, tar::EntryType::Regular, b"x".as_slice()),
        ("tool", 0o755, tar::EntryType::Symlink, b"".as_slice()),
        ("tool", 0o755, tar::EntryType::Link, b"".as_slice()),
        ("tool", 0o4755, tar::EntryType::Regular, b"x".as_slice()),
        ("tool", 0o644, tar::EntryType::Regular, b"x".as_slice()),
        ("surprise", 0o755, tar::EntryType::Regular, b"x".as_slice()),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let bytes = archive(&[(path, mode, kind, data)]);
        let pins = manifest(&bytes);
        assert!(
            install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).is_err(),
            "accepted {path} mode={mode:o} kind={kind:?}"
        );
        assert!(!temp.path().join("active.json").exists());
        assert!(!temp.path().join("outside").exists());
    }
}

#[test]
fn duplicate_missing_truncated_and_oversized_archives_fail_before_activation() {
    let good = (
        "tool",
        0o755,
        tar::EntryType::Regular,
        b"content".as_slice(),
    );
    let mut truncated = good_archive();
    truncated.truncate(truncated.len() - 8);
    for bytes in [archive(&[good, good]), archive(&[]), truncated] {
        let temp = tempfile::tempdir().unwrap();
        let pins = manifest(&bytes);
        assert!(install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).is_err());
        assert!(!temp.path().join("active.json").exists());
    }
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let mut pins = manifest(&bytes);
    pins.platforms.get_mut(PLATFORM).unwrap()[0].max_unpacked_bytes = 16;
    assert!(install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).is_err());
}

#[test]
fn only_required_files_are_installed_from_a_trusted_archive() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = archive(&[
        ("tool", 0o755, tar::EntryType::Regular, b"content"),
        (
            "LICENSE",
            0o644,
            tar::EntryType::Regular,
            b"fixture license",
        ),
        ("unused-tool", 0o755, tar::EntryType::Regular, b"unused"),
    ]);
    let mut pins = manifest(&bytes);
    pins.platforms.get_mut(PLATFORM).unwrap()[0]
        .allowed_unused_executables
        .push("unused-tool".into());
    let receipt = install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).unwrap();
    let location = temp.path().join(receipt.installation);
    assert!(location.join("bin/tool").is_file());
    assert!(!location.join("unused-tool").exists());
    assert!(!location.join("LICENSE").exists());
}

#[test]
fn changing_an_installed_binary_is_detected_and_not_silently_reused() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let pins = manifest(&bytes);
    let receipt = install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).unwrap();
    fs::write(
        temp.path().join(receipt.installation).join("bin/tool"),
        b"changed",
    )
    .unwrap();
    assert!(verify_installed(&pins, PLATFORM, temp.path()).is_err());
    assert!(install(&pins, PLATFORM, temp.path(), &NoDownload).is_err());
}

#[cfg(unix)]
#[test]
fn special_file_verification_child_helper() {
    let Ok(root) = std::env::var("ZDN_TEST_SPECIAL_TOOL_ROOT") else {
        return;
    };
    let pins = manifest(&good_archive());
    let root = Path::new(&root);
    assert!(verify_installed(&pins, PLATFORM, root)
        .unwrap_err()
        .to_string()
        .contains("regular file"));
    assert!(install(&pins, PLATFORM, root, &NoDownload)
        .unwrap_err()
        .to_string()
        .contains("regular file"));
}

#[cfg(unix)]
#[test]
fn fifo_replacing_a_tool_is_rejected_before_opening_or_reinstalling() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let pins = manifest(&bytes);
    let receipt = install(&pins, PLATFORM, temp.path(), &BytesDownloader(bytes)).unwrap();
    let active_before = fs::read(temp.path().join("active.json")).unwrap();
    let binary = temp.path().join(&receipt.installation).join("bin/tool");
    fs::remove_file(&binary).unwrap();
    assert!(Command::new("mkfifo")
        .arg(&binary)
        .status()
        .unwrap()
        .success());
    // A watchdog makes a future regression fail rather than block the whole suite.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "special_file_verification_child_helper",
            "--nocapture",
        ])
        .env("ZDN_TEST_SPECIAL_TOOL_ROOT", temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("managed-tool verification blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read(temp.path().join("active.json")).unwrap(),
        active_before
    );
}

#[test]
fn a_concurrent_installer_cannot_enter_an_active_installation() {
    struct PausedDownload {
        bytes: Vec<u8>,
        started: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    impl Downloader for PausedDownload {
        fn download(&self, _: &str, output: &mut File, _: u64) -> Result<()> {
            self.started.send(())?;
            self.resume.recv_timeout(Duration::from_secs(5))?;
            output.write_all(&self.bytes)?;
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let pins = manifest(&bytes);
    let (started_tx, started_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let path = temp.path().to_path_buf();
    let first_pins = pins.clone();
    let worker = std::thread::spawn(move || {
        install(
            &first_pins,
            PLATFORM,
            &path,
            &PausedDownload {
                bytes,
                started: started_tx,
                resume: resume_rx,
            },
        )
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = install(&pins, PLATFORM, temp.path(), &NoDownload).unwrap_err();
    assert!(second.to_string().contains("another managed-tool install"));
    resume_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    verify_installed(&pins, PLATFORM, temp.path()).unwrap();
}

fn serve_once(
    status: &str,
    extra_headers: &str,
    body: Vec<u8>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tool.tar.gz", listener.local_addr().unwrap());
    let response = format!("HTTP/1.1 {status}\r\n{extra_headers}\r\n");
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            request.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
    });
    (url, thread)
}

#[test]
fn loopback_download_checks_http_lengths_and_checksums_without_external_network() {
    let bytes = good_archive();
    let (url, server) = serve_once(
        "200 OK",
        &format!("Content-Length: {}\r\n", bytes.len()),
        bytes.clone(),
    );
    let temp = tempfile::tempdir().unwrap();
    let mut pins = manifest(&bytes);
    pins.platforms.get_mut(PLATFORM).unwrap()[0].url = url;
    install(
        &pins,
        PLATFORM,
        temp.path(),
        &HttpDownloader::for_loopback_tests(),
    )
    .unwrap();
    server.join().unwrap();

    let (url, server) = serve_once("200 OK", "Content-Length: 1000\r\n", b"short".to_vec());
    let mut output = tempfile::tempfile().unwrap();
    assert!(HttpDownloader::for_loopback_tests()
        .download(&url, &mut output, 1000)
        .is_err());
    server.join().unwrap();
}

#[test]
fn production_http_requires_tls_and_redirects_cannot_escape_that_rule() {
    let mut output = tempfile::tempfile().unwrap();
    assert!(HttpDownloader::default()
        .download("http://127.0.0.1:1234/file", &mut output, 100)
        .is_err());
    let (url, server) = serve_once(
        "302 Found",
        "Location: http://example.invalid/file\r\nContent-Length: 0\r\n",
        vec![],
    );
    let error = HttpDownloader::for_loopback_tests()
        .download(&url, &mut output, 100)
        .unwrap_err();
    assert!(error.to_string().contains("HTTPS"));
    server.join().unwrap();
}

#[test]
fn unsafe_catalog_paths_and_unknown_versions_fail_without_creating_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("uncreated");
    let bytes = good_archive();
    let mut pins = manifest(&bytes);
    pins.platforms.get_mut(PLATFORM).unwrap()[0].files[0].install_path = "../outside".into();
    assert!(install(&pins, PLATFORM, &root, &NoDownload).is_err());
    assert!(!root.exists());
    let mut pins = manifest(&bytes);
    pins.schema_version = 9000;
    assert!(install(&pins, PLATFORM, &root, &NoDownload).is_err());
    assert!(!root.exists());
}

#[cfg(unix)]
#[test]
fn managed_paths_must_not_be_symlinks() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), temp.path().join("versions")).unwrap();
    let bytes = good_archive();
    assert!(install(
        &manifest(&bytes),
        PLATFORM,
        temp.path(),
        &BytesDownloader(bytes)
    )
    .is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn staging_interruption_child_helper() {
    let Ok(path) = std::env::var("ZDN_DEPENDENCY_CHILD_ROOT") else {
        return;
    };
    struct WaitForKill;
    impl Downloader for WaitForKill {
        fn download(&self, _: &str, file: &mut File, _: u64) -> Result<()> {
            file.write_all(b"interrupted download")?;
            file.sync_all()?;
            println!("ZDN_INSTALL_STAGING_READY");
            std::io::stdout().flush()?;
            std::io::stdin().read_exact(&mut [0_u8])?;
            bail!("child should have been killed")
        }
    }
    let mut pins = manifest(&good_archive());
    pins.catalog = "new-release".into();
    install(&pins, PLATFORM, Path::new(&path), &WaitForKill).unwrap();
}

#[test]
fn killing_an_installer_preserves_active_tools_and_next_install_removes_staging() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = good_archive();
    let pins = manifest(&bytes);
    install(
        &pins,
        PLATFORM,
        temp.path(),
        &BytesDownloader(bytes.clone()),
    )
    .unwrap();
    let active = fs::read(temp.path().join("active.json")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "staging_interruption_child_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZDN_DEPENDENCY_CHILD_ROOT", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let reader = BufReader::new(child.stdout.take().unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let ready = reader
            .lines()
            .any(|line| line.is_ok_and(|line| line.contains("ZDN_INSTALL_STAGING_READY")));
        let _ = ready_tx.send(ready);
    });
    let ready = ready_rx.recv_timeout(Duration::from_secs(5));
    child.kill().unwrap();
    child.wait().unwrap();
    reader_thread.join().unwrap();
    assert!(
        ready.is_ok_and(|ready| ready),
        "installer helper did not reach staging"
    );
    assert_eq!(fs::read(temp.path().join("active.json")).unwrap(), active);
    verify_installed(&pins, PLATFORM, temp.path()).unwrap();
    let mut changed = pins;
    changed.catalog = "new-release".into();
    install(&changed, PLATFORM, temp.path(), &BytesDownloader(bytes)).unwrap();
    verify_installed(&changed, PLATFORM, temp.path()).unwrap();
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".zdn-install-")));
}
