#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use fs2::FileExt;
use tempfile::TempDir;
use zdn::host::command::{Executor, HostCommand};

#[path = "support/executable.rs"]
mod executable;

const LIMIT: usize = 16 * 1024 * 1024;
const SECRET: &[u8] = b"host-command-private-input-9fb27e10";

fn tempdir() -> std::io::Result<TempDir> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn executor(directory: &Path) -> eyre::Result<Executor> {
    Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        directory.into(),
        "us-east-2".into(),
        Instant::now() + Duration::from_secs(30),
    )
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// Like support/native_tool.rs, run a libtest worker as an executable. Unlike
// that disk-backed transport, fd 3 carries binary output directly to the real
// command pipe: neither input nor output is ever spooled to a fixture file.
fn worker(root: &Path, mode: &str) -> PathBuf {
    let path = root.join(format!("worker-{mode}"));
    executable::write(
        &path,
        format!(
            "#!/bin/bash\nset -o pipefail\n(export ZDN_COMMAND_WORKER={} ZDN_COMMAND_ROOT={}\nexec 3>&1\nexec {} --exact host_command_worker --nocapture >/dev/null) | /bin/cat\n",
            quote(mode),
            quote(root.to_str().unwrap()),
            quote(std::env::current_exe().unwrap().to_str().unwrap()),
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn command<'a>(program: &'a Path, input: Option<&'a [u8]>) -> HostCommand<'a> {
    HostCommand {
        program,
        args: &[],
        stdin: input,
        timeout: Duration::from_secs(10),
        allowed: &[0],
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "missing {}", path.display());
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_stopped(pid: u32) {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => assert!(
            stat.rsplit_once(") ").unwrap().1.starts_with('Z'),
            "process {pid} still running when execute returned"
        ),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
    }
}

fn assert_no_secret(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            assert_no_secret(&entry.path());
        } else if kind.is_file() {
            let bytes = match fs::read(entry.path()) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("cannot inspect fixture: {error}"),
            };
            assert!(!bytes.windows(SECRET.len()).any(|s| s == SECRET));
        }
    }
}

#[test]
fn host_command_worker() {
    let Some(mode) = std::env::var_os("ZDN_COMMAND_WORKER") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("ZDN_COMMAND_ROOT").unwrap());
    let mode = mode.to_str().unwrap();
    if mode == "descendant" {
        // Same session, genuinely separate process group; ignore graceful
        // shutdown so tests also discriminate kill/escalation regressions.
        ctrlc::set_handler(|| {}).unwrap();
        fs::write(
            root.join("descendant"),
            format!(
                "{} {} {}",
                std::process::id(),
                nix::unistd::getpgid(None).unwrap(),
                nix::unistd::getsid(None).unwrap()
            ),
        )
        .unwrap();
        std::thread::sleep(Duration::from_secs(8));
        fs::write(root.join("escaped"), b"survived").unwrap();
        std::process::exit(0);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .unwrap();
    match mode {
        "duplex" => {
            // Output first, before reading input: sequential write-then-read
            // implementations deadlock once both kernel buffers fill.
            let writer = std::thread::spawn(move || {
                for _ in 0..513 {
                    output
                        .write_all(&[0x00, 0xff, 0x81, 0x0a].repeat(1024))
                        .unwrap();
                }
            });
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            assert_eq!(input.len(), 3 * 1024 * 1024 + 17);
            for (index, byte) in input.into_iter().enumerate() {
                assert_eq!(byte, ((index * 37 + 11) % 256) as u8);
            }
            writer.join().unwrap();
        }
        "eof" => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
            output.write_all(b"EOF\0\xff").unwrap();
        }
        "boundary" => {
            std::io::stderr().write_all(SECRET).unwrap();
            output.write_all(&vec![0xa7; LIMIT]).unwrap();
        }
        "secret-fail" => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            output.write_all(&input).unwrap();
            std::io::stderr().write_all(&input).unwrap();
            std::process::exit(23);
        }
        "cancel" | "timeout" | "overflow" | "leader-exit" => {
            // Do not keep the leader's output pipe open in the descendant:
            // the leader-exit case must reach supervisor cleanup via exit,
            // rather than accidentally waiting for EOF or its timeout.
            let script = format!(
                "exec 3>&-; exec {} --exact host_command_worker --nocapture",
                quote(std::env::current_exe().unwrap().to_str().unwrap())
            );
            let mut child = Command::new("/bin/sh")
                .args(["-c", &script])
                .env("ZDN_COMMAND_WORKER", "descendant")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            wait_for(&root.join("descendant"));
            fs::write(root.join("leader"), std::process::id().to_string()).unwrap();
            fs::write(root.join("ready"), b"ready").unwrap();
            if mode == "leader-exit" {
                std::process::exit(0);
            }
            if mode == "overflow" {
                // Include input-like secret data in diagnostics without ever
                // putting it in a worker file, argument or environment.
                output.write_all(SECRET).unwrap();
                std::io::stderr().write_all(SECRET).unwrap();
                let _ = output.write_all(&vec![0xa7; LIMIT + 1 - SECRET.len()]);
            }
            // Deliberately never read stdin; finite even on a regression.
            std::thread::sleep(Duration::from_secs(8));
            child.wait().unwrap();
        }
        _ => panic!("unknown worker mode"),
    }
    std::process::exit(0);
}

#[test]
fn binary_duplex_eof_and_exact_output_limit() {
    #[cfg(feature = "profiling")]
    if std::env::var_os("ZDN_COMMAND_TRACE_TEST").is_none() {
        // Isolate subscriber/callsite state from concurrently running tests.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "binary_duplex_eof_and_exact_output_limit",
                "--nocapture",
            ])
            .env("ZDN_COMMAND_TRACE_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let root = tempdir().unwrap();
    #[cfg(feature = "profiling")]
    let trace = root.path().join("timings.jsonl");
    #[cfg(feature = "profiling")]
    let _subscriber = {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
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
    let mut executor = executor(root.path()).unwrap();
    let cancel = AtomicBool::new(false);
    let program = worker(root.path(), "duplex");
    let input: Vec<_> = (0..3 * 1024 * 1024 + 17)
        .map(|i| ((i * 37 + 11) % 256) as u8)
        .collect();
    let result = executor
        .execute(command(&program, Some(&input)), &cancel)
        .unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, [0x00, 0xff, 0x81, 0x0a].repeat(513 * 1024));
    let program = worker(root.path(), "eof");
    for input in [None, Some(&[][..])] {
        let result = executor.execute(command(&program, input), &cancel).unwrap();
        assert_eq!(result.stdout, b"EOF\0\xff");
    }
    let program = worker(root.path(), "boundary");
    let result = executor.execute(command(&program, None), &cancel).unwrap();
    assert_eq!(result.stdout.len(), LIMIT);
    assert!(result.stdout.iter().all(|&byte| byte == 0xa7));
    #[cfg(feature = "profiling")]
    {
        let text = fs::read_to_string(&trace).unwrap();
        assert!(!text.contains(root.path().to_str().unwrap()));
        assert!(!text.contains(std::str::from_utf8(SECRET).unwrap()));
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for name in [
            "host.command.execute",
            "host.command.io",
            "host.command.cleanup",
            "pulumi_process.supervisor.spawn_host",
            "pulumi_process.supervisor.finish_status",
        ] {
            let spans: Vec<_> = records
                .iter()
                .filter(|record| record["span"]["name"] == name)
                .collect();
            // One event per phase, even for large duplex/boundary output.
            assert_eq!(spans.len(), 4, "{name}");
            for record in spans {
                assert_eq!(record["span"].as_object().unwrap().len(), 1);
                assert!(record["fields"]["time.busy"].is_string());
                assert!(record["fields"]["time.idle"].is_string());
                if name != "host.command.execute" {
                    assert!(record["spans"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|span| { span["name"] == "host.command.execute" }));
                }
            }
        }
        assert!(records
            .iter()
            .any(|record| record["span"]["name"] == "host.command.new"));
    }
}

#[test]
fn literal_arguments_environment_and_explicit_exit_policy() {
    if std::env::var_os("ZDN_COMMAND_ENV_PROBE").is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "literal_arguments_environment_and_explicit_exit_policy",
                "--nocapture",
            ])
            .env("ZDN_COMMAND_ENV_PROBE", "must-not-be-inherited")
            .env("AWS_ACCESS_KEY_ID", "offline-test-not-a-credential")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = tempdir().unwrap();
    let mut executor = executor(root.path()).unwrap();
    let cancel = AtomicBool::new(false);
    let literal = format!(
        "$(touch {}) ; * $HOME ' \"\n",
        root.path().join("injected").display()
    );
    let args = [OsString::from("%s"), literal.clone().into()];
    let mut request = command(Path::new("/usr/bin/printf"), None);
    request.args = &args;
    assert_eq!(
        executor.execute(request, &cancel).unwrap().stdout,
        literal.as_bytes()
    );
    assert!(!root.path().join("injected").exists());

    // The isolated test process above adds poison variables without mutating
    // the environment shared by concurrent tests.
    let args = [OsString::from("-0")];
    let mut request = command(Path::new("/usr/bin/env"), None);
    request.args = &args;
    let output = executor.execute(request, &cancel).unwrap().stdout;
    let environment: std::collections::BTreeMap<_, _> = output
        .split(|&byte| byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (key, value) = std::str::from_utf8(entry).unwrap().split_once('=').unwrap();
            (key.to_owned(), value.to_owned())
        })
        .collect();
    let expected = [
        "AWS_DEFAULT_REGION",
        "AWS_MAX_ATTEMPTS",
        "AWS_PAGER",
        "AWS_REGION",
        "AWS_RETRY_MODE",
        "HOME",
        "PATH",
    ];
    assert_eq!(
        environment.keys().map(String::as_str).collect::<Vec<_>>(),
        expected
    );
    for (key, value) in [
        ("PATH", "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/root"),
        ("AWS_REGION", "us-east-2"),
        ("AWS_DEFAULT_REGION", "us-east-2"),
        ("AWS_PAGER", ""),
        ("AWS_RETRY_MODE", "standard"),
        ("AWS_MAX_ATTEMPTS", "5"),
    ] {
        assert_eq!(environment[key], value);
    }

    let args = [OsString::from("-c"), OsString::from("exit 23")];
    let mut request = command(Path::new("/bin/sh"), None);
    request.args = &args;
    request.allowed = &[23];
    assert_eq!(executor.execute(request, &cancel).unwrap().exit_code, 23);
    let program = worker(root.path(), "secret-fail");
    let error = executor
        .execute(command(&program, Some(SECRET)), &cancel)
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error:#}").contains(std::str::from_utf8(SECRET).unwrap()));
    assert_no_secret(root.path());
    let args = [OsString::from("-c"), OsString::from("kill -KILL $$")];
    let all_codes: Vec<i32> = (0..=255).collect();
    let mut request = command(Path::new("/bin/sh"), None);
    request.args = &args;
    request.allowed = &all_codes;
    assert!(executor.execute(request, &cancel).is_err());
    for allowed in [&[-1][..], &[256][..], &[][..]] {
        let mut request = command(Path::new("/bin/true"), None);
        request.allowed = allowed;
        assert!(executor.execute(request, &cancel).is_err());
    }
    assert!(executor
        .execute(command(Path::new("true"), None), &cancel)
        .is_err());
}

#[test]
fn lock_lifetime_and_directory_preconditions() {
    let root = tempdir().unwrap();
    let instance = executor(root.path()).unwrap();
    let lock = File::open(root.path().join("command.lock")).unwrap();
    assert!(lock.try_lock_exclusive().is_err());
    drop(instance);
    lock.try_lock_exclusive().unwrap();
    FileExt::unlock(&lock).unwrap();
    assert!(executor(Path::new("relative-directory")).is_err());
    assert!(executor(&root.path().join("does-not-exist")).is_err());
    let public = tempdir().unwrap();
    fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(executor(public.path()).is_err());
}

#[test]
fn cumulative_deadline_reserves_cleanup_and_unconfirmed_receipt_blocks_retry() {
    let root = tempdir().unwrap();
    let cancel = AtomicBool::new(false);
    let mut executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        root.path().into(),
        "us-east-2".into(),
        Instant::now() + Duration::from_secs(12),
    )
    .unwrap();
    let args = [
        OsString::from("-c"),
        OsString::from("sleep 0.1; printf done"),
    ];
    let mut request = command(Path::new("/bin/sh"), None);
    request.args = &args;
    assert_eq!(executor.execute(request, &cancel).unwrap().stdout, b"done");
    let args = [OsString::from("-c"), OsString::from("sleep 3; printf done")];
    let mut request = command(Path::new("/bin/sh"), None);
    request.args = &args;
    assert!(executor.execute(request, &cancel).is_err());
    assert!(!root.path().join(".zdn-pulumi-process.json").exists());
    drop(executor);

    // A helper which exits without acknowledging session cleanup is not a
    // substitute for the pinned supervisor, even when its exit status is 0.
    let mut executor = Executor::new(
        "/bin/true".into(),
        root.path().into(),
        "us-east-2".into(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let target = root.path().join("must-not-run");
    let args = [target.as_os_str().to_owned()];
    let mut request = command(Path::new("/usr/bin/touch"), None);
    request.args = &args;
    let error = executor.execute(request, &cancel).err().unwrap();
    assert!(error.to_string().contains("cleanup is unconfirmed"));
    let receipt = fs::read(root.path().join(".zdn-pulumi-process.json")).unwrap();
    assert!(!target.exists());
    assert!(executor
        .execute(command(Path::new("/bin/true"), None), &cancel)
        .is_err());
    assert_eq!(
        fs::read(root.path().join(".zdn-pulumi-process.json")).unwrap(),
        receipt
    );
    drop(executor);
    assert!(Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        root.path().into(),
        "us-east-2".into(),
        Instant::now() + Duration::from_secs(30),
    )
    .is_err());
}

#[test]
fn cancellation_delivers_term_but_a_graceful_zero_exit_is_not_success() {
    let root = tempdir().unwrap();
    let mut executor = executor(root.path()).unwrap();
    let cancelled = AtomicBool::new(false);
    let args = [
        OsString::from("-c"),
        OsString::from("trap 'printf TERM > signal; exit 0' TERM; trap 'printf INT > signal; exit 0' INT; : > ready; while :; do sleep 0.05; done"),
    ];
    std::thread::scope(|scope| {
        scope.spawn(|| {
            wait_for(&root.path().join("ready"));
            cancelled.store(true, Ordering::SeqCst);
        });
        let mut request = command(Path::new("/bin/sh"), None);
        request.args = &args;
        assert!(executor.execute(request, &cancelled).is_err());
    });
    assert_eq!(fs::read(root.path().join("signal")).unwrap(), b"TERM");
    assert!(!root.path().join(".zdn-pulumi-process.json").exists());
}

#[test]
fn blocked_input_and_separate_group_descendants_are_cleaned_before_return() {
    for mode in ["cancel", "timeout", "overflow", "leader-exit"] {
        let root: TempDir = tempdir().unwrap();
        let mut executor = executor(root.path()).unwrap();
        let program = worker(root.path(), mode);
        let cancel = AtomicBool::new(false);
        let mut input = vec![0x91; 3 * 1024 * 1024];
        input[..SECRET.len()].copy_from_slice(SECRET);
        let start = Instant::now();
        let result = std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                wait_for(&root.path().join("ready"));
                assert_no_secret(root.path());
                let leader = fs::read_to_string(root.path().join("leader")).unwrap();
                if mode != "leader-exit" && mode != "overflow" {
                    assert!(root.path().join(".zdn-pulumi-process.json").is_file());
                    for name in ["cmdline", "environ"] {
                        let bytes = fs::read(format!("/proc/{leader}/{name}")).unwrap();
                        assert!(!bytes.windows(SECRET.len()).any(|s| s == SECRET));
                    }
                }
                if mode == "cancel" {
                    cancel.store(true, Ordering::SeqCst);
                }
            });
            let mut request = command(&program, Some(&input));
            if mode == "timeout" {
                request.timeout = Duration::from_secs(2);
            }
            let result = executor.execute(request, &cancel);
            observer.join().unwrap();
            result
        });
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "{mode} did not bound cleanup"
        );
        if mode == "leader-exit" {
            assert_eq!(result.unwrap().exit_code, 0);
        } else {
            let error = result.err().expect("command should fail");
            assert!(!format!("{error:?} {error:#}").contains(std::str::from_utf8(SECRET).unwrap()));
        }
        let info = fs::read_to_string(root.path().join("descendant")).unwrap();
        let ids: Vec<u32> = info
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ids[0], ids[1], "fixture must have a separate process group");
        assert_ne!(ids[1], ids[2], "fixture must not be session leader");
        assert_stopped(ids[0]);
        assert_stopped(
            fs::read_to_string(root.path().join("leader"))
                .unwrap()
                .parse()
                .unwrap(),
        );
        assert!(!root.path().join("escaped").exists());
        assert!(!root.path().join(".zdn-pulumi-process.json").exists());
        assert_no_secret(root.path());
        // A fresh request proves successful cleanup did not leave a receipt
        // that prevents further commands under the same executor lock.
        assert_eq!(
            executor
                .execute(
                    command(Path::new("/bin/true"), None),
                    &AtomicBool::new(false)
                )
                .unwrap()
                .exit_code,
            0
        );
    }
}
