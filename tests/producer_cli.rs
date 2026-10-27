//! The producer transport uses current node cookies and numeric loopback only.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    thread::{self, JoinHandle},
    time::Duration,
};
use uuid::Uuid;
use zdn::chain::rpc::{HttpNodeRpc, NodeRpc};

fn private_file(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("manifest.json"),
        include_str!("fixtures/chain-manifest/valid.json"),
    )
    .unwrap();
    private_file(
        &directory.path().join("cookie"),
        &format!("__cookie__:{}", Uuid::new_v4()),
    );
    directory
}

fn server(
    respond: impl FnOnce(String, Value) -> (u16, Value) + Send + 'static,
) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let worker = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "fixture did not receive request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        // BSD/macOS can inherit the listener's nonblocking flag on accept.
        // Poll only the listener; partial HTTP requests must wait for bytes
        // on the accepted stream, bounded by the socket timeouts below.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            headers.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        let (status, result) = respond(headers, request.clone());
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
            .unwrap();
        write!(stream,"HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
    });
    (endpoint, worker)
}

#[test]
fn generate_authenticates_with_the_current_cookie_and_exactly_one_requested_block() {
    let directory = fixture();
    let cookie = directory.path().join("cookie");
    // A host reboot rotates the cookie. Constructing the next controller reads
    // the current file rather than a credential stored in its producer journal.
    let old = fs::read_to_string(&cookie).unwrap();
    let current = format!("__cookie__:{}", Uuid::new_v4());
    private_file(&cookie, &current);
    let expected = format!("Authorization: Basic {}", STANDARD.encode(&current));
    let stale = format!("Authorization: Basic {}", STANDARD.encode(old));
    let (endpoint, worker) = server(move |headers, request| {
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&expected)));
        assert!(!headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&stale)));
        assert_eq!(request["method"], "generate");
        assert_eq!(request["params"], json!([1]));
        (200, json!(["12".repeat(32)]))
    });
    let result = HttpNodeRpc::new(&endpoint, &cookie)
        .unwrap()
        .call("generate", json!([1]), Duration::from_secs(2))
        .unwrap();
    assert_eq!(result, json!(["12".repeat(32)]));
    worker.join().unwrap();
}

const DEPLOYMENT: &str = "d1b8f1a7-b228-421f-984b-82eebf73b67e";

fn produce(directory: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(directory)
        .args([
            "chain",
            "produce",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
            "--state-dir",
            "producer",
            "--deployment-id",
            DEPLOYMENT,
            "--node-id",
            "node-1",
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn failed(output: Output, cookie: &str) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains(cookie));
    assert!(!error.contains(&STANDARD.encode(cookie)));
    error
}

#[test]
fn invalid_producer_options_fail_before_creating_state_or_contacting_a_node() {
    for flags in [
        vec!["--rpc-endpoint", "192.0.2.1:18232"],
        vec!["--rpc-endpoint", "http://127.0.0.1:18232"],
        vec!["--interval-secs", "0"],
        vec!["--interval-secs", "86401"],
        vec!["--max-blocks", "0"],
        vec!["--unpaced"],
        vec!["--unpaced", "--max-blocks", "0"],
        vec!["--request-timeout-secs", "0"],
        vec!["--request-timeout-secs", "61"],
        vec!["--deadline-secs", "0"],
        vec!["--reconciliation-deadline-secs", "0"],
    ] {
        let directory = fixture();
        let cookie = fs::read_to_string(directory.path().join("cookie")).unwrap();
        failed(produce(directory.path(), &flags), &cookie);
        assert!(
            !directory.path().join("producer").exists(),
            "createdstate for{flags:?}"
        );
    }
}

#[test]
fn producer_cli_authenticates_before_rules_check_and_stops_on_wrong_rules() {
    let directory = fixture();
    let cookie = fs::read_to_string(directory.path().join("cookie")).unwrap();
    let authorization = format!("Authorization: Basic {}", STANDARD.encode(&cookie));
    let (endpoint, worker) = server(move |headers, request| {
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&authorization)));
        assert_eq!(request["method"], "getchainrules");
        assert_eq!(request["params"], json!([]));
        (200, json!({"apiVersion":"unsupported"}))
    });
    let error = failed(
        produce(
            directory.path(),
            &[
                "--rpc-endpoint",
                &endpoint,
                "--unpaced",
                "--max-blocks",
                "2",
                "--interval-secs",
                "1",
            ],
        ),
        &cookie,
    );
    assert!(error.contains("effective rules"), "{error}");
    worker.join().unwrap();
    let journal: Value =
        serde_json::from_slice(&fs::read(directory.path().join("producer/journal.json")).unwrap())
            .unwrap();
    assert_eq!(journal["pending"], Value::Null);
    assert_eq!(journal["confirmedBlocks"], 0);
    assert_eq!(journal["phase"], "stalled");
    assert!(!serde_json::to_string(&journal).unwrap().contains(&cookie));
}

#[test]
fn status_is_read_only_and_cannot_invent_a_running_controller() {
    let directory = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(directory.path())
        .args([
            "chain",
            "producer-status",
            "--manifest",
            "manifest.json",
            "--state-dir",
            "missing",
            "--deployment-id",
            DEPLOYMENT,
            "--node-id",
            "node-1",
        ])
        .output()
        .unwrap();
    let cookie = fs::read_to_string(directory.path().join("cookie")).unwrap();
    failed(output, &cookie);
    assert!(!directory.path().join("missing").exists());
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_cli_gracefully_without_claiming_blocks_or_exposing_the_cookie() {
    use std::{process::Stdio, sync::mpsc};
    let directory = fixture();
    let cookie = fs::read_to_string(directory.path().join("cookie")).unwrap();
    let authorization = format!("Authorization: Basic {}", STANDARD.encode(&cookie));
    let (request_seen, request_received) = mpsc::sync_channel(1);
    let (signal_sent, signal_received) = mpsc::sync_channel(1);
    let (endpoint, worker) = server(move |headers, request| {
        assert!(headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&authorization)));
        assert_eq!(request["method"], "getchainrules");
        request_seen.send(()).unwrap();
        signal_received
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        // Let the process's signal handler run before this in-flight response.
        thread::sleep(Duration::from_millis(50));
        (200, json!({"apiVersion":"interrupted-observation"}))
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(directory.path())
        .args([
            "chain",
            "produce",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
            "--state-dir",
            "producer",
            "--deployment-id",
            DEPLOYMENT,
            "--node-id",
            "node-1",
            "--rpc-endpoint",
            &endpoint,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = request_received.recv_timeout(Duration::from_secs(5)) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("producer did not reach first RPC: {error}");
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().try_into().unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    signal_sent.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("producer did not exit after SIGTERM");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    worker.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["phase"], "stopped");
    assert_eq!(report["pending"], Value::Null);
    assert_eq!(report["confirmedBlocks"], 0);
    assert_eq!(report["controllerLocked"], false);
    assert_eq!(report["paymentQualification"], "pending");
    assert_eq!(report["launchReady"], false);
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(&cookie));
        assert!(!text.contains(&STANDARD.encode(&cookie)));
    }
}
