//! Local RPC fixtures only. The diagnostic JSON is written independently of
//! the production renderer; no node, Docker, credentials, or real sleep is used.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    thread::{self, JoinHandle},
    time::Duration,
};
use zdn::chain::{manifest::ConsensusManifest, rpc::Clock, startup::wait_for_rpc};

const STALE: &str = "__cookie__:stale-secret";
const FRESH: &str = "__cookie__:fresh-secret";

#[derive(Default)]
struct FakeClock {
    now: Cell<Duration>,
    on_sleep: RefCell<Option<Box<dyn FnMut()>>>,
}
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.now.get()
    }
    fn sleep(&self, duration: Duration) {
        self.now.set(self.now.get() + duration);
        if let Some(callback) = self.on_sleep.borrow_mut().as_mut() {
            callback();
        }
    }
}

fn cookie(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn manifest() -> ConsensusManifest {
    serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap()
}

fn rules() -> Value {
    serde_json::from_str(include_str!("fixtures/chain-rules.json")).unwrap()
}

fn request(stream: &mut TcpStream) -> (String, Value) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
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
    assert_eq!(request["method"], "getchainrules");
    assert_eq!(request["params"], json!([]));
    (headers, request)
}

fn reply(stream: &mut TcpStream, status: u16, id: &Value, result: Value) {
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
    write!(
        stream,
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
}

fn server(f: impl FnOnce(TcpListener) + Send + 'static) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    (endpoint, thread::spawn(move || f(listener)))
}

fn wait(endpoint: &str, path: &Path, clock: &FakeClock, seconds: u64) -> eyre::Result<()> {
    wait_for_rpc(
        &manifest(),
        endpoint,
        path,
        clock,
        Duration::from_secs(1),
        Duration::from_secs(seconds),
    )
}

#[test]
fn retained_cookie_survives_transport_failure_and_is_reloaded_after_401() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    cookie(&path, STALE);
    let rotated = path.clone();
    let (endpoint, worker) = server(move |listener| {
        for attempt in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, req) = request(&mut stream);
            let expected = if attempt == 2 { FRESH } else { STALE };
            assert!(headers.contains(&format!("Basic {}", STANDARD.encode(expected))));
            match attempt {
                0 => {} // Listener has not started answering RPC yet.
                1 => {
                    // Atomic rotation models the new process replacing a retained cookie.
                    let temporary = rotated.with_extension("new");
                    cookie(&temporary, FRESH);
                    fs::rename(temporary, &rotated).unwrap();
                    reply(&mut stream, 401, &req["id"], Value::Null);
                }
                _ => reply(&mut stream, 200, &req["id"], rules()),
            }
        }
    });
    let clock = FakeClock::default();
    wait(&endpoint, &path, &clock, 10).unwrap();
    worker.join().unwrap();
    assert_eq!(clock.elapsed(), Duration::from_secs(2));
}

#[test]
fn missing_cookie_is_retried_until_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (_, req) = request(&mut stream);
        reply(&mut stream, 200, &req["id"], rules());
    });
    let created = path.clone();
    let clock = FakeClock {
        on_sleep: RefCell::new(Some(Box::new(move || cookie(&created, FRESH)))),
        ..Default::default()
    };
    wait(&endpoint, &path, &clock, 10).unwrap();
    worker.join().unwrap();
    assert_eq!(clock.elapsed(), Duration::from_secs(1));
}

#[test]
fn persistent_auth_failure_stops_at_the_deadline_without_exposing_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    cookie(&path, STALE);
    let (endpoint, worker) = server(|listener| {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let (_, req) = request(&mut stream);
            reply(&mut stream, 401, &req["id"], Value::Null);
        }
    });
    let clock = FakeClock::default();
    let error = format!("{:#}", wait(&endpoint, &path, &clock, 2).unwrap_err());
    worker.join().unwrap();
    assert!(error.contains("startup deadline"), "{error}");
    assert!(!error.contains("secret"));
    assert_eq!(clock.elapsed(), Duration::from_secs(2));
}

#[test]
fn missing_cookie_also_has_a_deadline_relative_to_entry() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock {
        now: Cell::new(Duration::from_secs(100)),
        ..Default::default()
    };
    let error = wait("127.0.0.1:1", &dir.path().join("missing"), &clock, 2).unwrap_err();
    assert!(error.to_string().contains("startup deadline"));
    assert_eq!(clock.elapsed(), Duration::from_secs(102));
}

#[test]
fn mismatched_rules_and_non_auth_http_errors_fail_without_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    cookie(&path, FRESH);
    for status in [200, 403, 500] {
        let (endpoint, worker) = server(move |listener| {
            let (mut stream, _) = listener.accept().unwrap();
            let (_, req) = request(&mut stream);
            let mut wrong_rules = rules();
            wrong_rules["rules"]["networkMagic"] = json!("01020304");
            reply(&mut stream, status, &req["id"], wrong_rules);
        });
        let clock = FakeClock::default();
        assert!(wait(&endpoint, &path, &clock, 10).is_err());
        worker.join().unwrap();
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }
}

#[test]
fn malformed_cookies_and_unsafe_endpoints_fail_before_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    cookie(&path, "malformed-secret");
    let clock = FakeClock::default();
    assert!(wait("127.0.0.1:1", &path, &clock, 10).is_err());
    fs::remove_file(&path).unwrap();
    assert!(wait("10.0.0.1:18232", &path, &clock, 10).is_err());
    assert_eq!(clock.elapsed(), Duration::ZERO);
}

#[cfg(unix)]
#[test]
fn symlinks_and_shared_cookies_fail_before_retry() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookie");
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    let clock = FakeClock::default();
    assert!(wait("127.0.0.1:1", &link, &clock, 10).is_err());
    cookie(&path, FRESH);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(wait("127.0.0.1:1", &path, &clock, 10).is_err());
    assert_eq!(clock.elapsed(), Duration::ZERO);
}

#[test]
fn cli_startup_gate_is_read_only_and_does_not_claim_chain_readiness() {
    let dir = tempfile::tempdir().unwrap();
    cookie(&dir.path().join("cookie"), FRESH);
    fs::write(
        dir.path().join("manifest.json"),
        include_str!("fixtures/chain-manifest/valid.json"),
    )
    .unwrap();
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (_, req) = request(&mut stream);
        reply(&mut stream, 200, &req["id"], rules());
    });
    let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(dir.path())
        .args([
            "chain",
            "wait-rpc",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
            "--rpc-endpoint",
            &endpoint,
        ])
        .output()
        .unwrap();
    worker.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "apiVersion":"zdn-chain-rpc-startup/v1alpha1", "effectiveRulesVerified":true, "launchReady":false
        })
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn startup_limits_and_invalid_manifests_fail_before_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let clock = FakeClock::default();
    for (request, deadline) in [(0, 10), (61, 120), (2, 1), (1, 0), (1, 3601)] {
        assert!(wait_for_rpc(
            &manifest(),
            "127.0.0.1:1",
            &dir.path().join("missing"),
            &clock,
            Duration::from_secs(request),
            Duration::from_secs(deadline)
        )
        .is_err());
    }
    let mut invalid = manifest();
    invalid.network_magic = "invalid".into();
    assert!(wait_for_rpc(
        &invalid,
        "127.0.0.1:1",
        &dir.path().join("missing"),
        &clock,
        Duration::from_secs(1),
        Duration::from_secs(10)
    )
    .is_err());
    assert_eq!(clock.elapsed(), Duration::ZERO);
}
