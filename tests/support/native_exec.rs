//! Test-only exec launcher: change child limits without unsafe pre_exec or Python.

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::Command,
};

pub fn command(
    root: &Path,
    program: impl AsRef<std::ffi::OsStr>,
    file_limit: Option<u64>,
) -> Command {
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let executable = quote(std::env::current_exe().unwrap().to_str().unwrap());
    let temporary = quote(root.join(".native-exec.XXXXXXXX").to_str().unwrap());
    let limit = file_limit
        .map(|limit| limit.to_string())
        .unwrap_or_default();
    let launcher = root.join(format!("native-exec-{limit}"));
    // Preserve the launcher's PID and original output streams across both execs.
    // libtest chatter goes to a separate file, never to the command's output.
    // The owning TempDir collects scratch even when the target is killed.
    fs::write(&launcher, format!(r#"#!/bin/sh
set -eu
work=$(/usr/bin/mktemp -d {temporary})
printf '%s\0' "$@" > "$work/args"
exec 3>&1 4>&2
ZDN_TEST_EXEC_FSIZE='{limit}' ZDN_TEST_EXEC_WORK="$work" exec {executable} --exact native_exec::worker --nocapture > "$work/harness.log" 2>&1
"#)).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    // Read the temporary script as data: executing a freshly written script can
    // report ETXTBSY during concurrent subprocess tests.
    let mut command = Command::new("/bin/sh");
    command.arg(launcher).arg(program);
    command
}

#[test]
fn worker() {
    let Some(root) = std::env::var_os("ZDN_TEST_EXEC_WORK") else {
        return;
    };
    let bytes = fs::read(Path::new(&root).join("args")).unwrap();
    let args: Vec<_> = bytes
        .strip_suffix(&[0])
        .unwrap()
        .split(|&b| b == 0)
        .map(std::ffi::OsStr::from_bytes)
        .collect();
    let mut command = Command::new(args[0]);
    let stdout = fs::OpenOptions::new()
        .write(true)
        .open("/dev/fd/3")
        .unwrap();
    let stderr = fs::OpenOptions::new()
        .write(true)
        .open("/dev/fd/4")
        .unwrap();
    // Only the remapped standard streams should survive the next exec.
    for fd in [3, 4] {
        nix::unistd::close(fd).unwrap();
    }
    command
        .args(&args[1..])
        .env_remove("ZDN_TEST_EXEC_WORK")
        .env_remove("ZDN_TEST_EXEC_FSIZE")
        .stdout(stdout)
        .stderr(stderr);
    let mut blocked = nix::sys::signal::SigSet::empty();
    blocked.add(nix::sys::signal::Signal::SIGXFSZ);
    blocked.thread_block().unwrap();
    let limit = std::env::var("ZDN_TEST_EXEC_FSIZE").unwrap();
    if !limit.is_empty() {
        let limit = limit.parse().unwrap();
        rustix::process::setrlimit(
            rustix::process::Resource::Fsize,
            rustix::process::Rlimit {
                current: Some(limit),
                maximum: Some(limit),
            },
        )
        .unwrap();
    }
    panic!("test exec failed: {}", command.exec());
}
