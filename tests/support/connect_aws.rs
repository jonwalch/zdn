//! Streaming, process-owned AWS and loopback RPC fixture for connect_cli.
//! The launcher execs libtest: the server PID and its supervisor ancestry remain
//! identical to a directly executed fake AWS tool. No production RPC helpers.

use crate::executable;
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

pub fn install(path: &Path) {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let executable = quote(std::env::current_exe().unwrap().to_str().unwrap());
    let scratch = quote(
        path.parent()
            .unwrap()
            .join(".connect-aws.XXXXXXXX")
            .to_str()
            .unwrap(),
    );
    executable::write(path, format!(r#"#!/bin/sh
set -eu
work=$(/usr/bin/mktemp -d {scratch})
printf '%s\0' "$@" > "$work/args"
exec 3>&1 4>&2
trap '' INT
ZDN_TEST_CONNECT_AWS_WORK="$work" exec {executable} --exact connect_aws::worker --nocapture > "$work/harness.log" 2>&1
"#)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn append(root: &Path, name: &str, value: Value) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join(name))
        .unwrap();
    file.write_all(format!("{value}\n").as_bytes()).unwrap();
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn output(value: impl std::fmt::Display) {
    // The real process runner supplies a socket, which cannot be reopened via
    // /dev/fd. Shell transports literal bytes to the inherited descriptor without
    // an unsafe raw-fd conversion or changing the server's PID/ownership.
    assert!(Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s\\n' \"$1\" >&3",
            "fixture-output",
            &value.to_string()
        ])
        .status()
        .unwrap()
        .success());
}

fn fail(message: &str) -> ! {
    assert!(Command::new("/bin/sh")
        .args(["-c", "printf '%s\\n' \"$1\" >&4", "fixture-error", message])
        .status()
        .unwrap()
        .success());
    std::process::exit(1)
}

#[test]
fn worker() {
    let Some(work) = std::env::var_os("ZDN_TEST_CONNECT_AWS_WORK") else {
        return;
    };
    let bytes = fs::read(Path::new(&work).join("args")).unwrap();
    let args: Vec<String> = bytes
        .strip_suffix(&[0])
        .unwrap()
        .split(|b| *b == 0)
        .map(|s| String::from_utf8(s.to_vec()).unwrap())
        .collect();
    let root = PathBuf::from(std::env::var_os("ZDN_CONNECT_FIXTURE").unwrap());
    append(&root, "calls", json!(args));
    let mode = std::env::var("ZDN_CONNECT_MODE").unwrap_or_else(|_| "ready".into());
    let endpoint = read_json(root.join("endpoints.json"));
    let has = |arg: &str| args.iter().any(|s| s == arg);
    if has("--version") {
        output("aws-cli/2.37.9 Python/3.13");
        std::process::exit(0);
    }
    if mode == "paths" {
        for (key, name) in [
            ("AWS_CONFIG_FILE", "config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "credentials"),
            ("AWS_CA_BUNDLE", "ca.pem"),
        ] {
            let path = std::env::var(key).unwrap();
            let path = if path == "~" {
                PathBuf::from(std::env::var_os("HOME").unwrap())
            } else if let Some(rest) = path.strip_prefix("~/") {
                PathBuf::from(std::env::var_os("HOME").unwrap()).join(rest)
            } else {
                PathBuf::from(path)
            };
            if fs::read_to_string(path).ok().as_deref() != Some(&format!("fixture {name}")) {
                fail(&format!("AWS configuration file does not resolve: {key}"));
            }
        }
        let plugin = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("session-manager-plugin"))
            .find(|p| {
                fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            });
        if plugin.and_then(|p| p.canonicalize().ok())
            != root.join("session-manager-plugin").canonicalize().ok()
        {
            fail("Session Manager plugin does not resolve");
        }
        append(
            &root,
            "path-observations",
            json!({"args":args,"cwd":std::env::current_dir().unwrap()}),
        );
    }
    if has("get-caller-identity") {
        let role = std::env::var("ZDN_CONNECT_ROLE").unwrap_or_else(|_| "participant".into());
        output(
            json!({"Account":if mode == "wrong-account" {"999999999999"} else {"123456789012"},"Arn":format!("arn:aws:sts::123456789012:assumed-role/{role}/session"),"UserId":"ROLE:session"}),
        );
        std::process::exit(0);
    }
    if has("get-document") {
        let mut doc = read_json(root.join("document.json"));
        if mode == "changed-document" {
            doc["properties"]["portNumber"] = json!("18232");
        }
        let name = format!(
            "arn:aws:ssm:{}:{}:document/zdn-{}-{}-node-rpc-v1",
            endpoint["scope"]["region"].as_str().unwrap(),
            endpoint["scope"]["account_id"].as_str().unwrap(),
            endpoint["bootstrapId"].as_str().unwrap(),
            endpoint["networkId"].as_str().unwrap()
        );
        output(
            json!({"Name":name,"DocumentType":"Session","Status":"Active","DocumentFormat":"JSON","Content":doc.to_string()}),
        );
        std::process::exit(0);
    }
    if has("terminate-session") {
        let pid: i32 = fs::read_to_string(root.join("server.pid"))
            .unwrap()
            .parse()
            .unwrap();
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        ) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => (),
            Err(error) => panic!("terminate fixture: {error}"),
        }
        if mode == "terminate-fails"
            || mode == "wallet-cleanup-fails"
            || mode == "wallet-sync-cleanup-fails"
            || mode == "wallet-classified-payment-settlement-cleanup-fails"
        {
            std::process::exit(1);
        }
        #[cfg(target_os = "linux")]
        if mode == "terminal-event-fails" {
            // AWS is a direct child of the product supervisor. Its parent is
            // the controller, not libtest's worker thread (all share one PID).
            let parent = nix::unistd::getppid();
            let status = fs::read_to_string(format!("/proc/{parent}/status")).unwrap();
            let controller: i32 = status
                .lines()
                .find_map(|s| s.strip_prefix("PPid:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            rustix::process::prlimit(
                rustix::process::Pid::from_raw(controller),
                rustix::process::Resource::Fsize,
                rustix::process::Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .unwrap();
        }
        output("{}");
        std::process::exit(0);
    }
    if !has("start-session") {
        std::process::exit(2);
    }
    let parameters: Value =
        serde_json::from_str(&args[args.iter().position(|s| s == "--parameters").unwrap() + 1])
            .unwrap();
    let port: u16 = parameters["localPortNumber"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    fs::write(root.join("server.pid"), std::process::id().to_string()).unwrap();
    fs::write(root.join("server.port"), port.to_string()).unwrap();
    output("Starting session with SessionId: participant-fixture1");
    output(format!(
        "Port {port} opened for sessionId participant-fixture1."
    ));
    if mode == "exit-after-child" {
        let root = root.clone();
        thread::spawn(move || {
            wait_for(&root.join("child-started"));
            std::process::exit(3);
        });
    }
    let state = Arc::new(Mutex::new(State::default()));
    for stream in listener.incoming() {
        let (root, mode, endpoint, state) =
            (root.clone(), mode.clone(), endpoint.clone(), state.clone());
        thread::spawn(move || {
            // A client abandoning a large/stalled response is normal here.
            let _ = serve(stream.unwrap(), &root, &mode, &endpoint, port, &state);
        });
    }
}

fn wait_for(path: &Path) {
    while !path.exists() {
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Default)]
struct State {
    tip_reads: u64,
    prefix_reads: u64,
    mempool_reads: u64,
}

fn serve(
    mut stream: TcpStream,
    root: &Path,
    mode: &str,
    endpoint: &Value,
    port: u16,
    state: &Mutex<State>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    if first.is_empty() {
        return Ok(());
    }
    let mut length = 0;
    let mut authorization = Value::Null;
    let mut content_type = Value::Null;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.to_ascii_lowercase().as_str() {
                "content-length" => length = value.parse::<usize>().unwrap(),
                "authorization" => authorization = json!(value),
                "content-type" => content_type = json!(value),
                _ => (),
            }
        }
    }
    if first.starts_with("GET ") {
        if first.split_whitespace().nth(1) == Some("/redirected") {
            File::create(root.join("redirect-followed"))?;
        }
        if mode == "health-wait" {
            File::create(root.join("health-started"))?;
            wait_for(&root.join("health-release"));
        }
        let report = json!({"apiVersion":"zdn-client-rpc-observation/v1alpha1","deploymentId":endpoint["networkId"],"nodeId":"node-1","consensusFingerprint":if mode == "wrong-chain" {json!("0".repeat(64))} else {endpoint["consensusFingerprint"].clone()},"status":"ready"});
        return response(&mut stream, 200, None, report.to_string().as_bytes());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let request: Value = serde_json::from_slice(&body).unwrap();
    append(
        root,
        "rpc-requests",
        json!({"body":request,"authorization":authorization,"contentType":content_type}),
    );
    let method = request["method"].as_str().unwrap();
    let params = &request["params"];
    if mode == "rpc-drop" {
        if method == "sendrawtransaction" {
            fs::write(root.join("accepted-txid"), "ab".repeat(32))?;
        }
        return Ok(());
    }
    let mut result = json!({"method":method,"params":params,"height":73});
    let genesis = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";
    let pinned = hex::encode((1u8..33).collect::<Vec<_>>());
    let advanced = hex::encode((160u8..192).collect::<Vec<_>>());
    if mode.starts_with("wallet-sync") {
        let mut state = state.lock().unwrap();
        let hash = |h: u64| {
            if h == 0 {
                genesis.to_owned()
            } else if std::env::var("ZDN_SYNC_FORK_FROM")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|from| h >= from)
            {
                format!("ff{h:062x}")
            } else {
                format!("{h:064x}")
            }
        };
        let height = if let Ok(height) = std::env::var("ZDN_SYNC_HEIGHT") {
            height.parse::<u64>().unwrap()
        } else if mode == "wallet-sync-long" {
            4097
        } else if mode == "wallet-sync-byte-limit" {
            23
        } else if mode == "wallet-sync-rollback" {
            0
        } else {
            2
        };
        match method {
            "getbestblockheightandhash" => {
                state.tip_reads += 1;
                let h = if mode == "wallet-sync-moving" {
                    state.tip_reads + 1
                } else {
                    height
                };
                fs::write(root.join("sync-observed-height"), h.to_string())?;
                let tip_hash = if mode == "wallet-sync-reorg" {
                    "ff".repeat(32)
                } else {
                    hash(h)
                };
                result = json!({"height":h,"hash":hex::decode(tip_hash).unwrap().into_iter().rev().collect::<Vec<_>>()});
            }
            "getblockhash" => {
                let h = params[0].as_u64().unwrap();
                result = json!(if mode == "wallet-sync-reorg" && h == 2 {
                    "ff".repeat(32)
                } else {
                    hash(h)
                });
            }
            "getblock" => {
                assert_eq!(params[1], 0);
                result = json!(if params[0] == genesis {
                    "001122"
                } else {
                    "33445566"
                });
                if mode == "wallet-sync-malformed" {
                    result = json!("zz");
                }
                if mode == "wallet-sync-bytes" {
                    result = json!("001133");
                }
                if mode == "wallet-sync-large" {
                    result = json!("00".repeat(4 * 1024 * 1024));
                }
                if mode == "wallet-sync-byte-limit" && params[0] != genesis {
                    let terminal = std::env::var("ZDN_SYNC_TERMINAL_BYTES").ok().map(|value| {
                        let bytes = value.parse::<usize>().unwrap();
                        assert!((1_048_572..=1_048_574).contains(&bytes));
                        bytes
                    });
                    let bytes = if params[0] == hash(height) {
                        terminal.unwrap_or(3 * 1024 * 1024)
                    } else {
                        3 * 1024 * 1024
                    };
                    result = json!("00".repeat(bytes));
                }
            }
            "z_gettreestate" => {
                let encoded = params[0].as_str().unwrap();
                let h =
                    u64::from_str_radix(encoded.strip_prefix("ff").unwrap_or(encoded), 16).unwrap();
                result = json!({"height":h,"hash":hash(h),"ironwood":{"commitments":{"finalRoot":"a1".repeat(32)}}});
                if mode == "wallet-sync-tree" {
                    result["height"] = json!(999);
                }
                if mode == "wallet-sync-after" || mode == "wallet-sync-drop" {
                    fs::write(root.join("sync-after-commit"), b"fail")?;
                }
            }
            "getrawmempool" => result = json!([]),
            _ => {}
        }
        if mode == "wallet-sync-after" && root.join("sync-committed").exists() {
            result = json!(null);
        }
        if mode == "wallet-sync-drop"
            && method == "getblock"
            && root.join("sync-committed").exists()
        {
            return Ok(()); // close the transport without an RPC response
        }
    } else if mode.starts_with("wallet-") {
        let mut state = state.lock().unwrap();
        let reads = state.tip_reads;
        match method {
            "getbestblockheightandhash" => {
                state.tip_reads += 1;
                let mut height = if mode == "wallet-too-high" {
                    4096
                } else if mode == "wallet-genesis-only" {
                    0
                } else if reads == 0 {
                    1
                } else {
                    4
                };
                if mode == "wallet-rollback" && reads > 0 {
                    height = 0;
                }
                if mode.starts_with("wallet-classified") {
                    height = 1;
                }
                if mode.starts_with("wallet-classified-payment-settlement") {
                    height = 4;
                }
                if mode == "wallet-classified-payment-settlement-low" {
                    height = 3;
                }
                if (mode == "wallet-classified-advance-before" && reads > 0)
                    || (mode == "wallet-classified-advance-after" && reads > 2)
                    || (mode.starts_with("wallet-classified-payment-advance") && reads > 0)
                {
                    height = 4;
                }
                let selected = if height == 0 {
                    genesis
                } else if height == 1 {
                    &pinned
                } else {
                    &advanced
                };
                let selected = if mode == "wallet-classified-payment-settlement-fork" {
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                } else {
                    selected
                };
                result = json!({"height":height,"hash":hex::decode(selected).unwrap().into_iter().rev().collect::<Vec<_>>()});
            }
            "getblockhash" => {
                let height = params[0].as_u64().unwrap();
                result = json!(if height == 0 {
                    genesis
                } else if height == 1 {
                    &pinned
                } else {
                    &advanced
                });
                if height == 1 {
                    state.prefix_reads += 1;
                    if (mode == "wallet-classified-payment-advance-reorg"
                        && state.prefix_reads >= 3)
                        || (mode == "wallet-reorg" && reads > 1)
                        || (mode == "wallet-classified-reorg" && reads > 3)
                    {
                        result = json!("ff".repeat(32));
                    }
                }
                if mode == "wallet-wrong-genesis" && height == 0 {
                    result = json!("ff".repeat(32));
                }
                if mode == "wallet-classified-payment-settlement-fork" && height > 0 {
                    result = json!("ff".repeat(32));
                }
            }
            "getblock" => {
                if mode.starts_with("wallet-classified-payment-settlement") && params[1] == 1 {
                    result = json!({"hash":pinned,"height":1,"tx":["ab".repeat(32)]});
                    if mode.ends_with("missing-inclusion") {
                        result["tx"] = json!([]);
                    }
                    if mode.ends_with("wrong-inclusion") {
                        result["tx"] = json!(["cd".repeat(32)]);
                    }
                    if mode.ends_with("duplicate-inclusion") {
                        result["tx"] = json!(["ab".repeat(32), "ab".repeat(32)]);
                    }
                } else {
                    assert_eq!(params[1], 0);
                    result = json!(if params[0] == genesis {
                        "001122"
                    } else {
                        "33445566"
                    });
                    if mode == "wallet-malformed" {
                        result = json!("01zz");
                    }
                    if mode == "wallet-wrong-bytes" && params[0] == genesis {
                        result = json!("001133");
                    }
                }
            }
            "z_gettreestate" => {
                let mut height = if mode == "wallet-genesis-only" { 0 } else { 1 };
                if (mode.starts_with("wallet-classified-payment-advance")
                    || mode == "wallet-classified-advance-before")
                    && params == &json!([advanced])
                {
                    height = 4;
                }
                let selected = if height == 0 {
                    genesis
                } else if height == 1 {
                    &pinned
                } else {
                    &advanced
                };
                assert_eq!(params, &json!([selected]));
                result = json!({"height":height,"hash":selected,"time":123,"ironwood":{"commitments":{"finalRoot":"a1".repeat(32),"finalState":"retained-complete-tree"}}});
                if mode == "wallet-tree-mismatch" {
                    result["height"] = json!(7);
                }
            }
            "getrawmempool" => {
                let count = state.mempool_reads;
                state.mempool_reads += 1;
                result = if count == 0 {
                    json!(["22".repeat(32), "11".repeat(32)])
                } else {
                    json!(["11".repeat(32), "22".repeat(32)])
                };
                if mode.starts_with("wallet-classified-payment-orphan") {
                    result = if mode.ends_with("pending") {
                        json!(["ab".repeat(32)])
                    } else {
                        json!([])
                    };
                    if mode.ends_with("malformed") {
                        result = json!({});
                    }
                    if mode.ends_with("error") {
                        return Ok(());
                    }
                }
                if mode == "wallet-classified-changed" && count > 0 {
                    result = json!(["11".repeat(32)]);
                }
                if mode == "wallet-classified-duplicate" {
                    result = json!(["11".repeat(32), "11".repeat(32)]);
                }
                if mode == "wallet-classified-too-many" {
                    result = json!(vec!["11".repeat(32); 1025]);
                }
                if mode == "wallet-classified-malformed" {
                    result = json!(["bad"]);
                }
            }
            "getrawtransaction" => {
                assert!(params[1] == 0 || mode.starts_with("wallet-classified-payment"));
                result = json!(if params[0] == "11".repeat(32) {
                    "0102"
                } else {
                    "aabbcc"
                });
                if mode == "wallet-classified-raw-bad" {
                    result = json!("01zz");
                }
            }
            _ => (),
        }
    }
    if mode.starts_with("wallet-classified-payment") {
        if method == "sendrawtransaction" {
            let wallets = std::env::var("ZDN_CONNECT_WALLETS").unwrap_or_else(|_| "wallets".into());
            let pattern = root.join(wallets).join("*/payments/*.json");
            let matching: Vec<Value> = glob::glob(pattern.to_str().unwrap())
                .unwrap()
                .map(|p| read_json(p.unwrap()))
                .filter(|v| v["signed"]["txid"] == "ab".repeat(32))
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["outcome"]["kind"], "outcome_unknown");
            assert!(matching[0]["attempts"].as_u64().unwrap() > 0);
            append(
                root,
                "dispatches",
                json!({"raw":params[0],"record":matching[0]}),
            );
            if mode.ends_with("lost") && !mode.ends_with("accepted-lost") {
                return Ok(());
            }
            if mode.ends_with("rejected") {
                let answer = json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-26,"message":"fixture","data":{"apiVersion":"zdn-submission/v1alpha1","outcome":"node-rejected"}}});
                return response(&mut stream, 200, None, answer.to_string().as_bytes());
            }
            fs::write(root.join("payment-accepted"), "yes")?;
            if mode == "wallet-classified-payment-orphan" {
                fs::write(root.join("orphan-redispatched"), "yes")?;
            }
            if mode.ends_with("accepted-lost") {
                return Ok(());
            }
        }
        if method == "getrawtransaction" && params[1] == 1 {
            if mode.ends_with("transport")
                || (mode.ends_with("accepted-lost") && root.join("payment-accepted").exists())
            {
                return Ok(());
            }
            let absent = mode.ends_with("lost")
                || mode.ends_with("reorg")
                || !root.join("payment-accepted").exists();
            if absent || (mode.ends_with("error") && !mode.ends_with("orphan-pool-error")) {
                let answer = json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":if mode.ends_with("error") {-8} else {-5},"message":"fixture"}});
                return response(&mut stream, 200, None, answer.to_string().as_bytes());
            }
            result =
                json!({"txid":"ab".repeat(32),"confirmations":1,"height":1,"blockhash":pinned});
            if mode.ends_with("mempool") {
                result = json!({"txid":"ab".repeat(32),"confirmations":0});
            }
            if mode.starts_with("wallet-classified-payment-orphan")
                && !root.join("orphan-redispatched").exists()
            {
                result = json!({"txid":"ab".repeat(32),"confirmations":0,"height":-1,"blockhash":pinned,"in_active_chain":false});
            }
            if mode.ends_with("moved") {
                result = json!({"txid":"ab".repeat(32),"confirmations":3,"height":2,"blockhash":advanced});
            }
            if mode.ends_with("stale") {
                result["blockhash"] = json!("ff".repeat(32));
            }
        }
    }
    if method == "sendrawtransaction" {
        result = json!("Ab".repeat(32));
    }
    if mode == "submit-invalid-txid" {
        result = json!("g".repeat(64));
    }
    if mode == "rpc-null" {
        result = Value::Null;
    }
    if mode == "rpc-wide" {
        result = json!("x".repeat(70000));
    }
    let mut answer = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
    if mode == "rpc-wrong-id" {
        answer["id"] = json!(1);
    }
    if mode == "rpc-missing-result" {
        answer.as_object_mut().unwrap().remove("result");
    }
    if ["rpc-error", "rpc-error-null-data", "rpc-conflict"].contains(&mode) {
        answer["error"] = json!({"code":-8,"message":"DO-NOT-ECHO"});
        if mode != "rpc-conflict" {
            answer["result"] = Value::Null;
        }
        if mode == "rpc-error-null-data" {
            answer["error"]["data"] = Value::Null;
        }
    }
    let mut status = 200;
    if mode.starts_with("submit-") && mode != "submit-invalid-txid" {
        status = if mode == "submit-rejected" || mode == "submit-wrong-status" {
            200
        } else {
            502
        };
        answer = json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":if mode == "submit-rejected" {-26} else {-32000},"message":"DO-NOT-ECHO","data":{"apiVersion":if mode == "submit-bad-version" {"zdn-submission/v999"} else {"zdn-submission/v1alpha1"},"outcome":if mode == "submit-rejected" {"node-rejected"} else if mode == "submit-unknown" {"outcome-unknown"} else {"not-dispatched"}}}});
        if mode == "submit-legacy-unavailable" {
            answer["error"].as_object_mut().unwrap().remove("data");
        }
    }
    let mut body = answer.to_string().into_bytes();
    if mode == "rpc-malformed" {
        body = b"{".to_vec();
    }
    if mode == "rpc-large" {
        body = vec![b'x'; 8 * 1024 * 1024 + 1];
    }
    let location = (mode == "rpc-redirect").then(|| format!("http://127.0.0.1:{port}/redirected"));
    if location.is_some() {
        status = 302;
    }
    // Send headers before waiting, just like BaseHTTPRequestHandler.
    headers(&mut stream, status, location.as_deref(), body.len())?;
    if mode == "rpc-stall" {
        thread::sleep(Duration::from_secs(30));
    }
    if mode == "rpc-wait" || mode == "wallet-wait" {
        wait_for(&root.join("rpc-release"));
    }
    stream.write_all(&body)
}

fn headers(
    stream: &mut TcpStream,
    status: u16,
    location: Option<&str>,
    length: usize,
) -> std::io::Result<()> {
    let reason = match status {
        302 => "Found",
        502 => "Bad Gateway",
        _ => "OK",
    };
    write!(stream, "HTTP/1.0 {status} {reason}\r\n")?;
    if let Some(location) = location {
        write!(stream, "Location: {location}\r\n")?;
    }
    write!(stream, "Content-Length: {length}\r\n\r\n")
}

fn response(
    stream: &mut TcpStream,
    status: u16,
    location: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    headers(stream, status, location, body.len())?;
    stream.write_all(body)
}
