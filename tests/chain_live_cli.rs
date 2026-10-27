//! CLI safety boundaries use local files and one loopback fixture only.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("manifest.json"),
        include_str!("fixtures/chain-manifest/valid.json"),
    )
    .unwrap();
    fs::write(dir.path().join("cookie"), "__cookie__:private-test-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path().join("cookie"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(dir)
        .arg("chain")
        .args(args)
        .output()
        .unwrap()
}

fn failed(output: Output) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains("private-test-secret"));
    error
}

#[test]
fn bootstrap_requires_an_explicit_stopped_producer_before_io() {
    let dir = fixture();
    let error = failed(run(
        dir.path(),
        &[
            "bootstrap",
            "--manifest",
            "manifest.json",
            "--bundle",
            "absent.tar",
            "--cookie-file",
            "cookie",
        ],
    ));
    assert!(error.contains("--producer-stopped"));
    let error = failed(run(
        dir.path(),
        &[
            "bootstrap",
            "--manifest",
            "manifest.json",
            "--bundle",
            "absent.tar",
            "--cookie-file",
            "cookie",
            "--producer-stopped",
        ],
    ));
    assert!(error.contains("chain artifact bundle"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn readiness_rejects_unsafe_endpoints_and_invalid_timeouts_before_any_rpc() {
    let dir = fixture();
    for extra in [
        vec!["--rpc-endpoint", "10.0.0.1:18232"],
        vec!["--rpc-endpoint", "http://127.0.0.1:18232"],
        vec!["--request-timeout-secs", "0"],
        vec!["--request-timeout-secs", "61"],
        vec!["--deadline-secs", "0"],
        vec!["--deadline-secs", "3601"],
    ] {
        let mut args = vec![
            "readiness",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
        ];
        args.extend(extra);
        failed(run(dir.path(), &args));
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn readiness_uses_the_requested_endpoint_and_fails_closed_on_unmatched_rules() {
    let dir = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut length = None;
        let mut auth = false;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
                if key.eq_ignore_ascii_case("authorization") {
                    auth = value.trim().starts_with("Basic ");
                }
            }
        }
        assert!(auth);
        let mut bytes = vec![0; length.unwrap()];
        reader.read_exact(&mut bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["method"], "getchainrules");
        assert_eq!(request["params"], json!([]));
        let body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":request["id"],"result":{"apiVersion":"unsupported"}}),
        )
        .unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });
    let error = failed(run(
        dir.path(),
        &[
            "readiness",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
            "--rpc-endpoint",
            &endpoint,
            "--role",
            "producer",
            "--deadline-secs",
            "10",
        ],
    ));
    assert!(error.contains("effective rules"), "{error}");
    worker.join().unwrap();
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}
