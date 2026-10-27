use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread::{self, JoinHandle},
    time::Duration,
};
use zdn::chain::rpc::{HttpNodeRpc, NodeRpc, RpcError};

fn cookie() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cookie");
    fs::write(&path, "__cookie__:s3cret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (directory, path)
}

fn server(
    respond: impl FnOnce(String, Value) -> (u16, String, Vec<u8>) + Send + 'static,
) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
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
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        let (status, extra, body) = respond(headers, request);
        let _ = write!(stream,"HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", body.len());
        let _ = stream.write_all(&body);
    });
    (endpoint, thread)
}

#[test]
fn authenticated_request_uses_numeric_loopback_and_matching_response_id() {
    let (_directory, path) = cookie();
    let (endpoint, worker) =
        server(|headers, request| {
            assert!(headers
                .lines()
                .any(|line| line
                    .eq_ignore_ascii_case("Authorization: Basic X19jb29raWVfXzpzM2NyZXQ=")));
            assert_eq!(request["method"], "getblockhash");
            assert_eq!(request["params"], json!([0]));
            (
                200,
                String::new(),
                serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":"ab".repeat(32)}),
                )
                .unwrap(),
            )
        });
    let client = HttpNodeRpc::new(&endpoint, &path).unwrap();
    assert_eq!(
        client
            .call("getblockhash", json!([0]), Duration::from_secs(2))
            .unwrap(),
        "ab".repeat(32)
    );
    worker.join().unwrap();
}

#[test]
fn explicit_null_result_is_preserved_with_or_without_a_null_error() {
    let (_directory, path) = cookie();
    for error in [None, Some(Value::Null)] {
        let (endpoint, worker) = server(move |_, request| {
            let mut body = json!({"jsonrpc":"2.0","id":request["id"],"result":null});
            if let Some(error) = error {
                body["error"] = error;
            }
            (200, String::new(), serde_json::to_vec(&body).unwrap())
        });
        assert_eq!(
            HttpNodeRpc::new(&endpoint, &path)
                .unwrap()
                .call("getchainrules", json!([]), Duration::from_secs(2))
                .unwrap(),
            Value::Null
        );
        worker.join().unwrap();
    }
}

#[test]
fn remote_error_identity_is_preserved_without_printing_its_message() {
    let (_directory, path) = cookie();
    let (endpoint, worker) = server(|_, request| {
        (500, String::new(), serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-1,"message":"No blocks in state"}})).unwrap())
    });
    let error = HttpNodeRpc::new(&endpoint, &path)
        .unwrap()
        .call("getblockhash", json!([0]), Duration::from_secs(2))
        .unwrap_err();
    assert_eq!(
        error,
        RpcError::Remote {
            code: -1,
            message: "No blocks in state".into()
        }
    );
    assert!(!error.to_string().contains("No blocks"));
    worker.join().unwrap();
}

#[test]
fn refuses_invalid_response_ids_shapes_and_ambiguous_results() {
    let (_directory, path) = cookie();
    for body in [
        json!({"jsonrpc":"2.0","id":99,"result":null}),
        json!({"id":1,"result":null}),
        json!({"jsonrpc":"2.0","id":1}),
        json!({"jsonrpc":"2.0","id":1,"result":true,"error":{"code":-1,"message":"bad"}}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":"wrong","message":"bad"}}),
    ] {
        let (endpoint, worker) =
            server(move |_, _| (200, String::new(), serde_json::to_vec(&body).unwrap()));
        assert!(matches!(
            HttpNodeRpc::new(&endpoint, &path).unwrap().call(
                "getchainrules",
                json!([]),
                Duration::from_secs(2)
            ),
            Err(RpcError::Protocol(_))
        ));
        worker.join().unwrap();
    }
}

#[test]
fn redirects_do_not_forward_the_cookie() {
    let (_directory, path) = cookie();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let location = format!("Location: http://{}/\r\n", trap.local_addr().unwrap());
    let (endpoint, worker) = server(move |_, _| (302, location, Vec::new()));
    assert!(matches!(
        HttpNodeRpc::new(&endpoint, &path).unwrap().call(
            "getchainrules",
            json!([]),
            Duration::from_secs(2)
        ),
        Err(RpcError::Protocol(_))
    ));
    worker.join().unwrap();
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn request_deadline_and_response_limit_are_enforced() {
    let (_directory, path) = cookie();
    let (endpoint, worker) = server(|_, _| {
        thread::sleep(Duration::from_millis(150));
        (200, String::new(), b"{}".to_vec())
    });
    assert!(matches!(
        HttpNodeRpc::new(&endpoint, &path).unwrap().call(
            "getchainrules",
            json!([]),
            Duration::from_millis(30)
        ),
        Err(RpcError::Transport(_))
    ));
    worker.join().unwrap();
    let (endpoint, worker) = server(|_, _| (200, String::new(), vec![b' '; 8 * 1024 * 1024 + 1]));
    assert!(matches!(
        HttpNodeRpc::new(&endpoint, &path).unwrap().call(
            "getchainrules",
            json!([]),
            Duration::from_secs(3)
        ),
        Err(RpcError::Protocol(_))
    ));
    worker.join().unwrap();
}

#[test]
fn unsafe_endpoints_and_methods_fail_without_contacting_a_server() {
    let (_directory, path) = cookie();
    for endpoint in [
        "localhost:18232",
        "https://127.0.0.1:18232",
        "127.0.0.1:0",
        "0.0.0.0:18232",
        "10.0.0.1:18232",
        "[::ffff:10.0.0.1]:18232",
        "[::1%1]:18232",
    ] {
        assert!(
            HttpNodeRpc::new(endpoint, &path).is_err(),
            "accepted {endpoint}"
        );
    }
    let client = HttpNodeRpc::new("[::ffff:127.0.0.1]:1", &path).unwrap();
    assert!(matches!(
        client.call("sendrawtransaction", json!(["00"]), Duration::from_secs(1)),
        Err(RpcError::Protocol(_))
    ));
    assert!(matches!(
        client.call("getchainrules", json!({}), Duration::from_secs(1)),
        Err(RpcError::Protocol(_))
    ));
    assert!(matches!(
        client.call("getchainrules", json!([]), Duration::ZERO),
        Err(RpcError::Protocol(_))
    ));
    assert!(matches!(
        client.call("getchainrules", json!([]), Duration::from_secs(61)),
        Err(RpcError::Protocol(_))
    ));
}

#[test]
fn malformed_or_shared_cookies_are_rejected_without_leaking_contents() {
    let (_directory, path) = cookie();
    for value in [
        "",
        "secret-without-user",
        "user:",
        ":secret",
        "user:secret\nInjected: header",
        "user:a:b",
    ] {
        fs::write(&path, value).unwrap();
        assert!(HttpNodeRpc::new("127.0.0.1:1", &path).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        fs::write(&path, "__cookie__:s3cret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(HttpNodeRpc::new("127.0.0.1:1", &path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(HttpNodeRpc::new("127.0.0.1:1", &link).is_err());
    }
}

#[test]
fn generation_requests_one_block_and_checks_ancestry_over_authenticated_rpc() {
    let (_directory, path) = cookie();
    for (method, params, result) in [
        ("generate", json!([1]), json!(["ab".repeat(32)])),
        (
            "getblockheader",
            json!(["ab".repeat(32), true]),
            json!({"hash":"ab".repeat(32),"height":1,"previousblockhash":"cd".repeat(32),"confirmations":1}),
        ),
    ] {
        let expected_params = params.clone();
        let expected_result = result.clone();
        let (endpoint, worker) = server(move |headers, request| {
            assert!(headers.contains("Authorization: Basic "));
            assert_eq!(request["method"], method);
            assert_eq!(request["params"], expected_params);
            (
                200,
                String::new(),
                serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":expected_result}),
                )
                .unwrap(),
            )
        });
        let client = HttpNodeRpc::new(&endpoint, &path).unwrap();
        assert_eq!(
            client.call(method, params, Duration::from_secs(2)).unwrap(),
            result
        );
        worker.join().unwrap();
    }
    let client = HttpNodeRpc::new("127.0.0.1:1", &path).unwrap();
    for params in [json!([0]), json!([2]), json!([1, 2]), json!(["1"])] {
        assert!(matches!(
            client.call("generate", params, Duration::from_secs(1)),
            Err(RpcError::Protocol(_))
        ));
    }
}
