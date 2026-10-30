#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zdn::public_chain_adapter::{
    Failure, Operation, TrustedExecutable, VerifiedExecutable, PROTOCOL, PROTOCOL_ARGUMENT,
};

const PRELUDE: &str = r#"#!/usr/bin/python3
import json, os, sys, time
assert sys.argv[1:] == ['--zdn-public-chain-adapter-v1']
assert set(os.environ) <= {'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE'}
assert os.environ['HOME'] == '/nonexistent'
request = json.load(sys.stdin)
assert request['protocol'] == 'zdn-public-chain-adapter/v1'
assert request['operation'] == 'describe'
assert 'context' not in request
response = {k: request[k] for k in ('protocol', 'operation', 'requestId', 'adapterSelectionSha256')}
response['result'] = dict(request['input'], runtimeFamily='zakura-custom-testnet', operations=['describe', 'compile', 'render'])
"#;

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    selection: TrustedExecutable,
}

impl Fixture {
    fn new(body: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("untrusted-input");
        let bytes = format!("{PRELUDE}\n{body}\n");
        fs::write(&path, &bytes).unwrap();
        let selection = TrustedExecutable {
            adapter_id: "fixture".into(),
            adapter_version: "1".into(),
            prepared_input_schema: "fixture/v1".into(),
            adapter_selection_sha256: "a".repeat(64),
            executable_sha256: hex::encode(Sha256::digest(bytes.as_bytes())),
            executable_bytes: bytes.len() as u64,
        };
        Self {
            _directory: directory,
            path,
            selection,
        }
    }

    fn verify(&self) -> VerifiedExecutable {
        VerifiedExecutable::verify(&self.path, self.selection.clone()).unwrap()
    }

    fn invoke(&self) -> Result<zdn::public_chain_adapter::Description, Failure> {
        self.verify().invoke(
            Operation::Describe,
            Instant::now() + Duration::from_secs(4),
            &AtomicBool::new(false),
        )
    }
}

#[test]
fn handshake_uses_verified_snapshot_fixed_argv_scrubbed_environment_and_fresh_request() {
    let directory = tempfile::tempdir().unwrap();
    let requests = directory.path().join("requests");
    let fixture = Fixture::new(&format!(
        "with open({requests:?}, 'a') as f: f.write(request['requestId'] + '\\n')\nprint(json.dumps(response))"
    ));
    let original = fs::read(&fixture.path).unwrap();
    let executable = fixture.verify();
    fs::write(&fixture.path, "not the pinned executable").unwrap();
    let result = executable
        .invoke(
            Operation::Describe,
            Instant::now() + Duration::from_secs(4),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(result.adapter_id, "fixture");
    assert_eq!(
        result.operations,
        [Operation::Describe, Operation::Compile, Operation::Render]
    );
    assert_eq!(PROTOCOL, "zdn-public-chain-adapter/v1");
    assert_eq!(PROTOCOL_ARGUMENT, "--zdn-public-chain-adapter-v1");
    fs::write(&fixture.path, original).unwrap();
    fixture
        .verify()
        .invoke(
            Operation::Describe,
            Instant::now() + Duration::from_secs(4),
            &AtomicBool::new(false),
        )
        .unwrap();
    let requests = fs::read_to_string(requests).unwrap();
    let ids: Vec<_> = requests.lines().collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert_eq!(uuid::Uuid::parse_str(ids[0]).unwrap().get_version_num(), 4);
}

#[test]
fn inspection_and_unsupported_operations_never_execute() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("executed");
    let fixture = Fixture::new(&format!("open({:?}, 'w').close()", marker));
    let executable = fixture.verify();
    assert!(!marker.exists());
    drop(executable);
    for operation in [Operation::Compile, Operation::Render] {
        assert_eq!(
            fixture.verify().invoke(
                operation,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false)
            ),
            Err(Failure::Incompatible)
        );
    }
    assert!(!marker.exists());
    for (deadline, cancelled) in [
        (Instant::now(), false),
        (Instant::now() + Duration::from_secs(1), true),
    ] {
        assert_eq!(
            fixture
                .verify()
                .invoke(Operation::Describe, deadline, &AtomicBool::new(cancelled)),
            Err(Failure::Deadline)
        );
    }
    assert!(!marker.exists());
}

#[test]
fn invalid_executable_pins_and_non_regular_paths_refuse() {
    let fixture = Fixture::new("print(json.dumps(response))");
    for selection in [
        TrustedExecutable {
            executable_sha256: "b".repeat(64),
            ..fixture.selection.clone()
        },
        TrustedExecutable {
            executable_bytes: fixture.selection.executable_bytes + 1,
            ..fixture.selection.clone()
        },
        TrustedExecutable {
            executable_bytes: 0,
            ..fixture.selection.clone()
        },
        TrustedExecutable {
            executable_bytes: 128 * 1024 * 1024 + 1,
            ..fixture.selection.clone()
        },
        TrustedExecutable {
            adapter_selection_sha256: "A".repeat(64),
            ..fixture.selection.clone()
        },
        TrustedExecutable {
            adapter_id: "bad\nname".into(),
            ..fixture.selection.clone()
        },
    ] {
        assert!(matches!(
            VerifiedExecutable::verify(&fixture.path, selection),
            Err(Failure::InvalidPublicInput)
        ));
    }
    assert!(matches!(
        VerifiedExecutable::verify(std::path::Path::new("adapter"), fixture.selection.clone()),
        Err(Failure::InvalidPublicInput)
    ));
    assert!(
        VerifiedExecutable::verify(fixture.path.parent().unwrap(), fixture.selection.clone())
            .is_err()
    );
    let link = fixture.path.with_extension("link");
    std::os::unix::fs::symlink(&fixture.path, &link).unwrap();
    assert!(VerifiedExecutable::verify(&link, fixture.selection.clone()).is_err());
    let fifo = fixture.path.with_extension("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(VerifiedExecutable::verify(&fifo, fixture.selection.clone()).is_err());
}

#[test]
fn exact_envelope_and_typed_result_reject_mismatch_duplicates_unknown_and_trailing_data() {
    for mutation in [
        "response['protocol'] = 'other/v1'",
        "response['operation'] = 'render'",
        "response['requestId'] = '00000000-0000-0000-0000-000000000000'",
        "response['requestId'] = response['requestId'].replace('-', '')",
        "response['adapterSelectionSha256'] = 'b' * 64",
        "response['extra'] = True",
        "response['context'] = {}",
        "response['result']['extra'] = True",
        "del response['result']['adapterVersion']",
        "response['result']['adapterVersion'] = 1.0",
        "response['result']['operations'] = ['arbitrary']",
    ] {
        assert_eq!(
            Fixture::new(&format!("{mutation}\nprint(json.dumps(response))")).invoke(),
            Err(Failure::InvalidOutput),
            "{mutation}"
        );
    }
    for body in [
        "print(json.dumps(response) + '{}')",
        "print(json.dumps(list(response.values())))",
        "response['result'] = list(response['result'].values()); print(json.dumps(response))",
        "response['result'] = list(response['result'].values()); print(json.dumps(list(response.values())))",
        "print(json.dumps(response).replace('{', '{\"protocol\":\"duplicate\",', 1))",
        "print(json.dumps(response).replace('\"result\": {', '\"result\": {\"adapterId\":\"duplicate\",'))",
        "sys.stdout.buffer.write(b'\\xff')",
        "print('not JSON')",
        "pass",
    ] {
        assert_eq!(Fixture::new(body).invoke(), Err(Failure::InvalidOutput), "{body}");
    }
}

#[test]
fn unsupported_identity_schema_runtime_and_capabilities_refuse() {
    for mutation in [
        "response['result']['adapterId'] = 'other'",
        "response['result']['adapterVersion'] = '2'",
        "response['result']['preparedInputSchema'] = 'other/v1'",
        "response['result']['runtimeFamily'] = 'other'",
        "response['result']['operations'] = ['describe']",
        "response['result']['operations'].reverse()",
        "response['result']['operations'].append('describe')",
    ] {
        assert_eq!(
            Fixture::new(&format!("{mutation}\nprint(json.dumps(response))")).invoke(),
            Err(Failure::Incompatible),
            "{mutation}"
        );
    }
}

#[test]
fn nonzero_signal_and_secret_diagnostics_fail_without_echo() {
    for body in [
        "print(json.dumps(response)); sys.stderr.write('fixture-secret'); sys.exit(7)",
        "os.kill(os.getpid(), 9)",
    ] {
        let failure = Fixture::new(body).invoke().unwrap_err();
        assert_eq!(failure, Failure::Unavailable);
        assert!(!failure.to_string().contains("fixture-secret"));
    }
}

#[test]
fn stdout_and_stderr_have_independent_finite_bounds() {
    for body in [
        "sys.stdout.write(' ' * (4 * 1024 * 1024 + 1)); print(json.dumps(response))",
        "sys.stderr.write('x' * (16 * 1024 + 1)); print(json.dumps(response))",
    ] {
        assert_eq!(Fixture::new(body).invoke(), Err(Failure::InvalidOutput));
    }
    // Full stderr cap and trailing JSON whitespace remain valid.
    assert!(
        Fixture::new("sys.stderr.write('x' * (16 * 1024)); print(json.dumps(response))")
            .invoke()
            .is_ok()
    );
    assert!(Fixture::new(
        "s = json.dumps(response); sys.stdout.write(s + ' ' * (4 * 1024 * 1024 - len(s)))"
    )
    .invoke()
    .is_ok());
}

#[test]
fn deadline_and_running_cancellation_kill_and_reap_child() {
    for cancel in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("pid");
        let fixture = Fixture::new(&format!(
            "open({:?}, 'w').write(str(os.getpid()))\ntime.sleep(30)",
            marker
        ));
        let executable = fixture.verify();
        let cancelled = AtomicBool::new(false);
        std::thread::scope(|scope| {
            if cancel {
                let cancelled = &cancelled;
                let marker = &marker;
                scope.spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !marker.exists() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    cancelled.store(true, Ordering::Relaxed);
                });
            }
            assert_eq!(
                executable.invoke(
                    Operation::Describe,
                    Instant::now() + Duration::from_secs(3),
                    &cancelled
                ),
                Err(Failure::Deadline)
            );
        });
        let pid = fs::read_to_string(&marker).unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child was not reaped"
        );
    }
}

#[test]
fn inherited_descendant_pipe_is_bounded_and_same_group_is_killed() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("pid");
    let fixture = Fixture::new(&format!(
        r#"
pid = os.fork()
if pid == 0:
    open({marker:?}, 'w').write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
print(json.dumps(response))
"#
    ));
    assert_eq!(
        fixture.verify().invoke(
            Operation::Describe,
            Instant::now() + Duration::from_secs(3),
            &AtomicBool::new(false)
        ),
        Err(Failure::Deadline)
    );
    let pid = fs::read_to_string(marker).unwrap();
    let stopped = || {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_or(true, |s| s.split_whitespace().nth(2) == Some("Z"))
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while !stopped() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(stopped(), "descendant remains running");
}
