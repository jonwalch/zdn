#![cfg(unix)]
//! Offline contract tests through the native serve boundary, not private helpers.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zdn::client_gateway::runtime::{serve, Config};

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

const CALL: &str = r#"{"method":"getblock","params":["aBc",17,{"height":9}],"id":"client-29"}"#;
const SUBMIT: &str = r#"{"method":"sendrawtransaction","params":["01ab"],"id":"client-29"}"#;

#[derive(Clone)]
enum Mode {
    Reply(u16, String, String),
    Close(String),
    Drop,
    Stall,
}
struct Fixture {
    root: tempfile::TempDir,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    mode: Arc<Mutex<Mode>>,
    calls: mpsc::Receiver<(Value, String)>,
    gateway: Option<thread::JoinHandle<eyre::Result<()>>>,
    node: Option<thread::JoinHandle<()>>,
}
fn put(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn secret(letter: char) -> String {
    format!("__cookie__:{}=", letter.to_string().repeat(43))
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["etc", "volume", "volume/rpc"] {
            fs::create_dir(root.path().join(dir)).unwrap();
            fs::set_permissions(root.path().join(dir), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity =
            json!({"deploymentId":"dev-32","nodeId":"node-7","consensusFingerprint":"fp-23"});
        for name in ["etc/identity.json", "volume/identity.json"] {
            put(
                &root.path().join(name),
                &serde_json::to_vec(&identity).unwrap(),
            );
        }
        put(
            &root.path().join("volume/rpc/.cookie"),
            secret('A').as_bytes(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let uid = root.path().metadata().unwrap().uid();
        let config = Config {
            anchor: File::open(root.path()).unwrap(),
            identity_paths: ["etc/identity.json".into(), "volume/identity.json".into()],
            cookie_path: "volume/rpc/.cookie".into(),
            root_uid: uid,
            node_uid: uid,
            identity,
            service_sha256: "service-54".into(),
            upstream: upstream.local_addr().unwrap(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let gateway_stop = stop.clone();
        let mode = Arc::new(Mutex::new(Mode::Reply(
            200,
            r#"{"id":"client-29","result":{"blocks":27,"hash":"a1B2"}}"#.into(),
            String::new(),
        )));
        let (tx, calls) = mpsc::channel();
        let node_stop = stop.clone();
        let node_mode = mode.clone();
        let node = thread::spawn(move || {
            thread::scope(|scope| {
                while !node_stop.load(Ordering::Acquire) {
                    match upstream.accept() {
                        Ok((mut stream, _)) => {
                            let tx = tx.clone();
                            let mode = node_mode.lock().unwrap().clone();
                            scope.spawn(move || {
                                // Darwin inherits the listener's nonblocking mode.
                                stream.set_nonblocking(false).unwrap();
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(20)))
                                    .unwrap();
                                let mut reader = BufReader::new(stream.try_clone().unwrap());
                                let mut headers = String::new();
                                loop {
                                    let mut line = String::new();
                                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                        return;
                                    }
                                    if line == "\r\n" {
                                        break;
                                    }
                                    headers.push_str(&line);
                                }
                                let length: usize = headers
                                    .lines()
                                    .find_map(|l| l.strip_prefix("Content-Length: "))
                                    .unwrap()
                                    .parse()
                                    .unwrap();
                                let mut body = vec![0; length];
                                reader.read_exact(&mut body).unwrap();
                                tx.send((serde_json::from_slice(&body).unwrap(), headers))
                                    .unwrap();
                                match mode {
                                    Mode::Drop => {}
                                    Mode::Close(body) => {
                                        let _ = stream.write_all(
                                            format!("HTTP/1.0 200 OK\r\n\r\n{body}").as_bytes(),
                                        );
                                    }
                                    Mode::Stall => {
                                        let mut byte = [0];
                                        assert_eq!(reader.read(&mut byte).unwrap(), 0);
                                    }
                                    Mode::Reply(status, body, extra) => {
                                        let framing =
                                            if extra.contains("Transfer-Encoding: chunked") {
                                                String::new()
                                            } else {
                                                format!("Content-Length: {}\r\n", body.len())
                                            };
                                        let wire = format!(
                                            "HTTP/1.1 {status} Node\r\n{framing}{extra}\r\n{body}"
                                        );
                                        let _ = stream.write_all(wire.as_bytes());
                                    }
                                }
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            })
        });
        let gateway = thread::spawn(move || serve(listener, config, &gateway_stop));
        Self {
            root,
            addr,
            stop,
            mode,
            calls,
            gateway: Some(gateway),
            node: Some(node),
        }
    }
    fn mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn raw(&self, bytes: &[u8]) -> (u16, Value) {
        let mut stream = TcpStream::connect(self.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(18)))
            .unwrap();
        stream.write_all(bytes).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&raw[..split])
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, serde_json::from_slice(&raw[split + 4..]).unwrap())
    }
    fn rpc(&self, body: &str) -> (u16, Value) {
        self.raw(request(body, "").as_bytes())
    }
    fn received(&self) -> (Value, String) {
        self.calls.recv_timeout(Duration::from_secs(2)).unwrap()
    }
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.gateway.take() {
            t.join().unwrap().unwrap();
        }
        if let Some(t) = self.node.take() {
            t.join().unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}
fn request(body: &str, extra: &str) -> String {
    format!("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",body.len())
}

#[test]
fn asymmetric_forwarding_rotation_chunked_health_and_sanitization() {
    #[cfg(feature = "profiling")]
    let Some(trace) =
        trace::capture("asymmetric_forwarding_rotation_chunked_health_and_sanitization")
    else {
        return;
    };
    let mut f = Fixture::new();
    assert_eq!(
        f.raw(
            request(
                CALL,
                "Authorization: Basic EVIL\r\nX-Upstream-Host: evil\r\n"
            )
            .as_bytes()
        ),
        (
            200,
            json!({"jsonrpc":"2.0","id":"client-29","result":{"blocks":27,"hash":"a1B2"}})
        )
    );
    let (call, headers) = f.received();
    assert_eq!(
        call,
        json!({"jsonrpc":"2.0","method":"getblock","params":["aBc",17,{"height":9}],"id":"client-29"})
    );
    assert!(headers.contains(&format!(
        "Authorization: Basic {}",
        STANDARD.encode(secret('A'))
    )));
    assert!(!headers.contains("EVIL") && !headers.contains("X-Upstream"));
    for method in ["getblockchaininfo", "z_gettreestate"] {
        assert_eq!(f.rpc(&CALL.replace("getblock", method)).0, 200);
        assert_eq!(f.received().0["method"], method);
    }
    let replacement = f.root.path().join("volume/rpc/new");
    put(&replacement, secret('B').as_bytes());
    fs::rename(replacement, f.root.path().join("volume/rpc/.cookie")).unwrap();
    let body = r#"{"id":"client-29","result":[17,"Case"]}"#;
    f.mode(Mode::Reply(
        200,
        format!("{:x};name=value\r\n{}\r\n0\r\n\r\n", body.len(), body),
        "Transfer-Encoding: chunked\r\n".into(),
    ));
    assert_eq!(f.rpc(CALL).1["result"], json!([17, "Case"]));
    assert!(f.received().1.contains(&STANDARD.encode(secret('B'))));
    f.mode(Mode::Reply(
        200,
        r#"{"id":"zdn-health","result":{"blocks":12}}"#.into(),
        String::new(),
    ));
    let (status, health) = f.raw(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert_eq!(health["nodeId"], "node-7");
    assert_eq!(health["deploymentId"], "dev-32");
    assert_eq!(health["consensusFingerprint"], "fp-23");
    assert_eq!(health["serviceSha256"], "service-54");
    assert_eq!(health["apiVersion"], "zdn-client-rpc-observation/v1alpha1");
    f.received();
    assert_eq!(
        zdn::client_gateway::runtime::health(
            f.addr,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false)
        )
        .unwrap(),
        health
    );
    f.received();
    f.mode(Mode::Reply(500,r#"{"id":"client-29","result":null,"error":{"code":-26,"message":"private failure","data":"private data"}}"#.into(),String::new()));
    assert_eq!(
        f.rpc(SUBMIT),
        (
            200,
            json!({"jsonrpc":"2.0","id":"client-29","error":{"code":-26,"message":"node rejected the request","data":{"apiVersion":"zdn-submission/v1alpha1","outcome":"node-rejected"}}})
        )
    );
    f.received();
    assert!(f.calls.try_recv().is_err());
    #[cfg(feature = "profiling")]
    {
        // Request/phase spans close while the listener is still serving.
        trace.assert_spans(
            &[
                "client_gateway.runtime.request",
                "client_gateway.runtime.request_headers",
                "client_gateway.runtime.request_body",
                "client_gateway.runtime.decode",
                "client_gateway.runtime.health",
                "client_gateway.runtime.identities",
                "client_gateway.runtime.forward",
                "client_gateway.runtime.upstream_connect",
                "client_gateway.runtime.upstream_write",
                "client_gateway.runtime.upstream_headers",
                "client_gateway.runtime.upstream_body",
                "client_gateway.runtime.reply",
            ],
            &[
                f.root.path().to_str().unwrap(),
                &secret('A'),
                &secret('B'),
                &STANDARD.encode(secret('A')),
                &STANDARD.encode(secret('B')),
                "client-29",
                "node-7",
                "aBc",
                "private failure",
                "private data",
                "EVIL",
            ],
        );
        trace.assert_child(
            "client_gateway.runtime.request",
            "client_gateway.runtime.serve",
        );
        trace.assert_child(
            "client_gateway.runtime.forward",
            "client_gateway.runtime.request",
        );
        trace.assert_child(
            "client_gateway.runtime.upstream_body",
            "client_gateway.runtime.forward",
        );
    }
    f.shutdown();
    #[cfg(feature = "profiling")]
    trace.assert_spans(&["client_gateway.runtime.serve"], &[]);
}

#[test]
fn rejects_malformed_json_and_http_atomically() {
    let f = Fixture::new();
    for raw in [
        r#"[{"method":"getblock","id":1}]"#,
        r#"{"method":"getblock"}"#,
        r#"{"method":"getblock","id":true}"#,
        r#"{"method":"getblock","id":1.0}"#,
        r#"{"method":"getblock","id":9223372036854775808}"#,
        r#"{"method":"getblock","method":"generate","id":1}"#,
        r#"{"method":"getblock","id":1,"params":{"x":1,"\u0078":2}}"#,
        r#"{"method":"getblock","id":1,"params":[NaN]}"#,
        r#"{"method":"getblock","id":1,"params":[1e999]}"#,
        r#"{"method":"getblock","id":1,"params":[1234567890123456789012]}"#,
        r#"{"method":"getblock","id":1,"params":[18446744073709551616]}"#,
        r#"{"method":"getblock","id":1,"url":"http://evil"}"#,
    ] {
        assert_eq!(f.rpc(raw).0, 400, "{raw}");
    }
    let deep = format!(
        "{{\"method\":\"getblock\",\"id\":1,\"params\":{}0{}}}",
        "[".repeat(64),
        "]".repeat(64)
    );
    assert_eq!(f.rpc(&deep).0, 400);
    let many = format!(
        "{{\"method\":\"getblock\",\"id\":1,\"params\":[{}0]}}",
        "0,".repeat(200000)
    );
    assert_eq!(f.rpc(&many).0, 400);
    for method in [
        "generate",
        "getblocktemplate",
        "submitblock",
        "stop",
        "getchainrules",
        "inspectchainblock",
        "invalidateblock",
        "reconsiderblock",
        "addnode",
        "z_sendmany",
        "dumpwallet",
        "getBlock",
        "sendrawtransaction ",
    ] {
        assert_eq!(f.rpc(&format!(r#"{{"method":"{method}","id":1}}"#)).0, 403);
    }
    for (from, to) in [
        ("POST / ", "POST http://169.254.169.254/ "),
        ("POST / ", "POST /wallet/test "),
        ("POST / ", "POST /?url=other "),
        ("Host: localhost", "Host: evil.test"),
        ("application/json", "text/plain"),
    ] {
        assert_eq!(f.raw(request(CALL, "").replace(from, to).as_bytes()).0, 400);
    }
    for extra in [
        "Content-Length: 2\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Origin: https://evil\r\n",
        "Host: localhost\r\n",
        "Content-Encoding: gzip\r\n",
        " folded: bad\r\n",
    ] {
        assert_eq!(f.raw(request(CALL, extra).as_bytes()).0, 400);
    }
    assert_eq!(
        f.raw(request(CALL, "Expect: 100-continue\r\n").as_bytes())
            .0,
        417
    );
    assert_eq!(f.raw(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 8388609\r\n\r\n").0,413);
    assert!(f.calls.try_recv().is_err());

    f.mode(Mode::Reply(
        200,
        r#"{"id":1,"result":"accepted"}"#.into(),
        String::new(),
    ));
    // Root object plus 63 array levels is exactly the permitted depth 64.
    let at_depth = format!(
        "{{\"method\":\"getblock\",\"id\":1,\"params\":{}0{}}}",
        "[".repeat(63),
        "]".repeat(63)
    );
    assert_eq!(f.rpc(&at_depth).1["result"], "accepted");
    f.received();
    // Root + method + id + params array consume four of the 200000 values.
    let at_count = format!(
        "{{\"method\":\"getblock\",\"id\":1,\"params\":[{}0]}}",
        "0,".repeat(199995)
    );
    assert_eq!(f.rpc(&at_count).1["result"], "accepted");
    assert_eq!(f.received().0["params"].as_array().unwrap().len(), 199996);
    assert_eq!(
        f.rpc(r#"{"method":"getblock","id":1,"params":[0.125]}"#).0,
        200
    );
    assert_eq!(f.received().0["params"], json!([0.125]));
}

#[test]
fn submission_uncertainty_and_upstream_validation_never_retry() {
    let f = Fixture::new();
    f.mode(Mode::Drop);
    assert_eq!(
        f.rpc(SUBMIT).1["error"]["data"]["outcome"],
        "outcome-unknown"
    );
    f.received();
    for (body, extra) in [
        (r#"{"id":29,"result":"abcd"}"#.to_owned(), String::new()),
        (
            r#"{"id":"client-29","result":1,"result":2}"#.to_owned(),
            String::new(),
        ),
        (
            r#"{"id":"client-29","result":"invalid-txid"}"#.to_owned(),
            String::new(),
        ),
        (
            format!(
                r#"{{"id":"client-29","error":{{"code":-1,"message":"{}"}}}}"#,
                secret('A')
            ),
            String::new(),
        ),
        (
            r#"{"id":"client-29","result":3}"#.to_owned(),
            "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n".into(),
        ),
        ("{}".into(), "Location: http://evil\r\n".into()),
    ] {
        f.mode(Mode::Reply(200, body, extra));
        let (status, reply) = f.rpc(SUBMIT);
        assert_eq!(status, 502);
        assert_eq!(reply["error"]["data"]["outcome"], "outcome-unknown");
        assert_eq!(reply["error"]["message"], "node RPC is unavailable");
        f.received();
    }
    fs::remove_file(f.root.path().join("volume/rpc/.cookie")).unwrap();
    assert_eq!(
        f.rpc(SUBMIT).1["error"]["data"]["outcome"],
        "not-dispatched"
    );
    assert!(f.calls.try_recv().is_err());
}

#[test]
fn refused_upstream_is_not_dispatched_and_health_requires_node_authentication() {
    let mut f = Fixture::new();
    f.mode(Mode::Reply(401, "{}".into(), String::new()));
    assert_eq!(
        f.raw(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").0,
        503
    );
    assert_eq!(f.received().0["method"], "getblockchaininfo");
    assert_eq!(
        f.rpc(SUBMIT).1["error"]["data"]["outcome"],
        "outcome-unknown"
    );
    f.received();
    assert_eq!(
        f.raw(b"GET /cookie HTTP/1.1\r\nHost: localhost\r\n\r\n").0,
        404
    );
    assert!(f.calls.try_recv().is_err());
    // Reuse the trusted files with a non-listening upstream. Join both original
    // threads before restarting so their cancellation cannot race the new serve.
    f.stop.store(true, Ordering::Release);
    f.node.take().unwrap().join().unwrap();
    f.gateway.take().unwrap().join().unwrap().unwrap();
    f.stop.store(false, Ordering::Release);
    // A fresh serve invocation below has a deliberately non-listening endpoint.
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    f.addr = listener.local_addr().unwrap();
    let config = Config {
        anchor: File::open(f.root.path()).unwrap(),
        identity_paths: ["etc/identity.json".into(), "volume/identity.json".into()],
        cookie_path: "volume/rpc/.cookie".into(),
        root_uid: f.root.path().metadata().unwrap().uid(),
        node_uid: f.root.path().metadata().unwrap().uid(),
        identity: json!({"deploymentId":"dev-32","nodeId":"node-7","consensusFingerprint":"fp-23"}),
        service_sha256: "service-54".into(),
        upstream: unavailable.local_addr().unwrap(),
    };
    drop(unavailable);
    let stop = f.stop.clone();
    f.gateway = Some(thread::spawn(move || serve(listener, config, &stop)));
    let (status, answer) = f.rpc(SUBMIT);
    assert_eq!(status, 502);
    assert_eq!(answer["id"], "client-29");
    assert_eq!(answer["error"]["data"]["outcome"], "not-dispatched");
    assert!(f.calls.try_recv().is_err());
}

#[test]
fn fresh_identity_and_descriptor_relative_file_trust_fail_closed() {
    let f = Fixture::new();
    let cookie = f.root.path().join("volume/rpc/.cookie");
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(f.rpc(CALL).0, 502);
    put(&cookie, secret('A').as_bytes());
    let link = f.root.path().join("linked");
    fs::hard_link(&cookie, &link).unwrap();
    assert_eq!(f.rpc(CALL).0, 502);
    fs::remove_file(link).unwrap();
    fs::remove_file(&cookie).unwrap();
    symlink("missing", &cookie).unwrap();
    assert_eq!(f.rpc(CALL).0, 502);
    fs::remove_file(&cookie).unwrap();
    put(&cookie, b"__cookie__:bad\nAuthorization: injected");
    assert_eq!(f.rpc(CALL).0, 502);
    put(&cookie, secret('A').as_bytes());
    let rpc = f.root.path().join("volume/rpc");
    let saved = f.root.path().join("volume/saved");
    fs::rename(&rpc, &saved).unwrap();
    symlink("saved", &rpc).unwrap();
    assert_eq!(f.rpc(CALL).0, 502);
    fs::remove_file(&rpc).unwrap();
    fs::rename(saved, rpc).unwrap();
    for path in ["etc/identity.json", "volume/identity.json"] {
        let file = f.root.path().join(path);
        let original = fs::read(&file).unwrap();
        put(&file, b"{}");
        assert_eq!(f.rpc(CALL).0, 502);
        put(&file, &original);
    }
    put(&cookie, &vec![b'x'; 1025]);
    assert_eq!(f.rpc(CALL).0, 502);
    put(&cookie, secret('A').as_bytes());
    let parent = f.root.path().join("volume/rpc");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(f.rpc(CALL).0, 502);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(f.calls.try_recv().is_err());
    assert_eq!(f.rpc(CALL).0, 200);
    f.received();
}

#[test]
fn four_slow_clients_bound_admission_and_cancellation_closes_both_sides() {
    let mut f = Fixture::new();
    f.mode(Mode::Stall);
    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(f.addr).unwrap();
        stream.write_all(request(CALL, "").as_bytes()).unwrap();
        clients.push(stream);
        f.received();
    }
    let mut extra = TcpStream::connect(f.addr).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(extra.read(&mut [0]).unwrap(), 0);
    let start = Instant::now();
    f.shutdown();
    assert!(start.elapsed() < Duration::from_secs(2));
    for mut client in clients {
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn cumulative_request_and_upstream_deadlines_release_slots() {
    let mut f = Fixture::new();
    // A trickled header cannot reset the cumulative accepted-client deadline.
    let mut slow = TcpStream::connect(f.addr).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(18)))
        .unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\n").unwrap();
    let start = Instant::now();
    f.mode(Mode::Stall);
    assert_eq!(f.rpc(CALL).0, 502);
    f.received();
    assert!(start.elapsed() >= Duration::from_secs(9) && start.elapsed() < Duration::from_secs(13));
    // The original slow client has only its original 15s budget, not a fresh one.
    slow.write_all(b"Host: localhost\r\n").unwrap();
    assert_eq!(slow.read(&mut [0]).unwrap(), 0);
    assert!(
        start.elapsed() >= Duration::from_secs(14) && start.elapsed() < Duration::from_secs(18)
    );
    f.mode(Mode::Reply(
        200,
        r#"{"id":"client-29","result":123}"#.into(),
        String::new(),
    ));
    assert_eq!(f.rpc(CALL).1["result"], 123);
    f.received();
    f.shutdown();
}

#[test]
fn exact_typed_ids_successful_submission_and_bounded_upstream_bodies() {
    let f = Fixture::new();
    for id in [
        "null",
        "-0",
        "-9223372036854775808",
        "9223372036854775807",
        "\"Mixed-42\"",
    ] {
        f.mode(Mode::Close(format!(
            r#"{{"id":{id},"result":{{"ok":true}}}}"#
        )));
        let (status, answer) = f.rpc(&format!(r#"{{"method":"getinfo","id":{id}}}"#));
        assert_eq!(status, 200);
        assert_eq!(answer["result"], json!({"ok":true}));
        let expected: Value = if id == "-0" {
            json!(0)
        } else {
            serde_json::from_str(id).unwrap()
        };
        assert_eq!(answer["id"], expected);
        assert_eq!(f.received().0["id"], expected);
    }
    for id in ["true", "1.0", "\"1\""] {
        f.mode(Mode::Reply(
            200,
            format!(r#"{{"id":{id},"result":5}}"#),
            String::new(),
        ));
        assert_eq!(f.rpc(r#"{"method":"getinfo","id":1}"#).0, 502);
        f.received();
    }
    let txid = "aB".repeat(32);
    f.mode(Mode::Reply(
        200,
        format!(r#"{{"id":"client-29","result":"{txid}"}}"#),
        String::new(),
    ));
    assert_eq!(f.rpc(SUBMIT).1["result"], txid);
    f.received();
    for (status, body, headers) in [
        (401, "{}".into(), String::new()),
        (200, " ".repeat(8 * 1024 * 1024 + 1), String::new()),
        (
            200,
            "Z\r\nnot-a-chunk\r\n".into(),
            "Transfer-Encoding: chunked\r\n".into(),
        ),
        (
            200,
            "3\r\n{} \r\n0\r\n".into(),
            "Transfer-Encoding: chunked\r\n".into(),
        ),
        (
            200,
            format!(
                r#"{{"id":"client-29","result":"Basic {}"}}"#,
                STANDARD.encode(secret('A'))
            ),
            String::new(),
        ),
        (
            200,
            format!(
                r#"{{"id":"client-29","result":"{}"}}"#,
                secret('A').replace('_', "\\u005f")
            ),
            String::new(),
        ),
        (
            200,
            format!(
                r#"{{"id":"client-29","result":"\u0042asic {}"}}"#,
                STANDARD.encode(secret('A'))
            ),
            String::new(),
        ),
    ] {
        f.mode(Mode::Reply(status, body, headers));
        assert_eq!(f.rpc(CALL).0, 502);
        f.received();
    }
}

#[test]
fn startup_rejects_wrong_owner_unsafe_identity_and_unanchored_paths() {
    let root = tempfile::tempdir().unwrap();
    put(&root.path().join("identity"), b"{}");
    let uid = root.path().metadata().unwrap().uid();
    let stop = AtomicBool::new(true);
    for (owner, path, mode) in [
        (uid + 1, "identity", 0o600),
        (uid, "identity", 0o644),
        (uid, "../identity", 0o600),
        (uid, "/identity", 0o600),
    ] {
        fs::set_permissions(
            root.path().join("identity"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = Config {
            anchor: File::open(root.path()).unwrap(),
            identity_paths: [path.into(), path.into()],
            cookie_path: "rpc/cookie".into(),
            root_uid: owner,
            node_uid: uid,
            identity: json!({}),
            service_sha256: "fixture".into(),
            upstream: "127.0.0.1:1".parse().unwrap(),
        };
        assert_eq!(
            serve(listener, c, &stop).unwrap_err().to_string(),
            "private RPC service failed"
        );
    }
}

#[test]
fn cancellation_also_interrupts_incomplete_client_headers() {
    let mut f = Fixture::new();
    let mut slow = TcpStream::connect(f.addr).unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\nHost: local").unwrap();
    // A completed asymmetric call proves acceptance is running without filling
    // the other slots or waiting for the slow client's deadline.
    assert_eq!(f.rpc(CALL).0, 200);
    f.received();
    let start = Instant::now();
    f.shutdown();
    slow.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(slow.read(&mut [0]).unwrap(), 0);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn sigterm_closes_native_listener_clients_and_upstream() {
    use nix::{
        sys::signal::{kill, Signal},
        unistd::Pid,
    };
    use std::process::{Command, Stdio};
    const CHILD: &str = "ZDN_GATEWAY_SIGNAL_FIXTURE";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let mut f = Fixture::new();
        // serve intentionally accepts caller-owned cancellation; use the same
        // termination-enabled adapter as the CLI, without privileged CLI roots.
        let stop = f.stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)).unwrap();
        f.mode(Mode::Stall);
        fs::write(root.join("ready.tmp"), f.addr.to_string()).unwrap();
        fs::rename(root.join("ready.tmp"), root.join("ready")).unwrap();
        f.received();
        fs::write(root.join("dispatched"), b"yes").unwrap();
        while !f.stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(5));
        }
        f.shutdown(); // joins the stalled upstream only after it observes EOF
        return;
    }
    let root = tempfile::tempdir().unwrap();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sigterm_closes_native_listener_clients_and_upstream",
                "--nocapture",
            ])
            .env(CHILD, root.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let wait_file = |name: &str| {
        let start = Instant::now();
        while !root.path().join(name).exists() {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "child never published {name}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    };
    wait_file("ready");
    let addr: SocketAddr = fs::read_to_string(root.path().join("ready"))
        .unwrap()
        .parse()
        .unwrap();
    let mut slow = TcpStream::connect(addr).unwrap();
    slow.write_all(b"POST / HTTP/1.1\r\nHost: local").unwrap();
    let mut active = TcpStream::connect(addr).unwrap();
    active.write_all(request(CALL, "").as_bytes()).unwrap();
    wait_file("dispatched");
    kill(
        Pid::from_raw(child.0.id().try_into().unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "SIGTERM did not stop gateway"
        );
        thread::sleep(Duration::from_millis(5));
    };
    let mut output = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(status.success(), "{output}");
    assert!(!output.contains(&secret('A')) && !output.contains(&STANDARD.encode(secret('A'))));
    for mut client in [slow, active] {
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
    assert!(TcpStream::connect(addr).is_err());
    TcpListener::bind(addr).unwrap();
}

#[test]
fn native_health_rejects_ambiguous_oversized_and_duplicate_replies_and_cancels_reads() {
    use zdn::client_gateway::runtime::health;
    for response in [
        "HTTP/1.1 200 RPC\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 RPC\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        "HTTP/1.1 200 RPC\r\nContent-Length: 8193\r\n\r\n",
        "HTTP/1.1 302 Redirect\r\nLocation: http://private.invalid\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 RPC\r\nContent-Length: 13\r\n\r\n{\"x\":1,\"x\":2}",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        thread::scope(|scope| {
            scope.spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut input = [0; 1024];
                assert!(socket.read(&mut input).unwrap() > 0);
                let _ = socket.write_all(response.as_bytes());
            });
            assert_eq!(
                format!(
                    "{}",
                    health(
                        endpoint,
                        Instant::now() + Duration::from_secs(1),
                        &AtomicBool::new(false)
                    )
                    .unwrap_err()
                ),
                "native gateway health unavailable"
            );
        });
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let server = scope.spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut input = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if input.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 RPC\r\nContent-Length: 4096\r\n\r\npartial")
                .unwrap();
            tx.send(()).unwrap();
            assert_eq!(socket.read(&mut [0; 1]).unwrap(), 0);
        });
        let client =
            scope.spawn(|| health(endpoint, Instant::now() + Duration::from_secs(10), &stop));
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let start = Instant::now();
        stop.store(true, Ordering::Release);
        assert!(client.join().unwrap().is_err());
        server.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    });
}
