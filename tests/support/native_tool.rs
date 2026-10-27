//! Transport for native fake executables implemented by subprocess test workers.
//! No additional Cargo target, production command, or interpreter is needed.

use crate::executable;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub fn install(path: &Path, worker: &str, payload: &Value) {
    let executable = std::env::current_exe().unwrap();
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let executable = quote(executable.to_str().unwrap());
    let worker = quote(worker);
    let payload = quote(&payload.to_string());
    let temporary = path.parent().unwrap().join(".native-tool.XXXXXXXX");
    let temporary = quote(temporary.to_str().unwrap());
    // Shell only transports argv and output. Keep test-harness chatter separate
    // from the tool's stdout/stderr, including when a worker fails unexpectedly.
    // Keep work inside the owning fixture, whose TempDir also collects files
    // when process-limit/cancellation tests kill the launcher before its trap.
    executable::write(
        path,
        format!(
            r#"#!/bin/sh
set -eu
work=$(/usr/bin/mktemp -d {temporary})
trap '/bin/rm -rf -- "$work"' EXIT
printf '%s\0' "$@" > "$work/args"
ZDN_TEST_INVOCATION="$work" ZDN_TEST_CALLER="$PPID" ZDN_TEST_PAYLOAD={payload} \
  {executable} --exact {worker} --nocapture > "$work/harness.log" 2>&1 || {{
    /bin/cat "$work/harness.log" >&2
    exit 99
  }}
/bin/cat "$work/stdout"
/bin/cat "$work/stderr" >&2
exit "$(/bin/cat "$work/status")"
"#
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

pub fn invocation() -> Option<(PathBuf, Vec<String>, Value)> {
    let work = PathBuf::from(std::env::var_os("ZDN_TEST_INVOCATION")?);
    let bytes = fs::read(work.join("args")).unwrap();
    let args = bytes
        .strip_suffix(&[0])
        .unwrap()
        .split(|&byte| byte == 0)
        .map(|arg| String::from_utf8(arg.to_vec()).unwrap())
        .collect();
    let payload = serde_json::from_str(&std::env::var("ZDN_TEST_PAYLOAD").unwrap()).unwrap();
    Some((work, args, payload))
}

pub fn reply(work: &Path, stdout: &[u8], stderr: &[u8], code: u8) {
    fs::write(work.join("stdout"), stdout).unwrap();
    fs::write(work.join("stderr"), stderr).unwrap();
    fs::write(work.join("status"), code.to_string()).unwrap();
}
