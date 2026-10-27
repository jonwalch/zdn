#![cfg(unix)]
#[path = "support/connect_aws.rs"]
mod connect_aws;
#[path = "support/connect_child.rs"]
mod connect_child;
#[path = "support/connect_observation.rs"]
mod connect_observation;
#[path = "support/connect_settlement.rs"]
mod connect_settlement;
#[path = "support/connect_sync.rs"]
mod connect_sync;
#[path = "support/connect_wallet.rs"]
mod connect_wallet;
#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_exec.rs"]
mod native_exec;
#[path = "support/native_tool.rs"]
mod native_tool;

use connect_child::Case;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use tempfile::TempDir;
use zdn::endpoints::{EndpointFile, Service};

struct Fixture {
    root: TempDir,
    endpoints: EndpointFile,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("home")).unwrap();
        fs::create_dir(root.path().join("tmp")).unwrap();
        fs::set_permissions(root.path().join("tmp"), fs::Permissions::from_mode(0o700)).unwrap();
        let endpoints = EndpointFile::from_json(&serde_json::to_vec(&json!({
            "apiVersion":"zdn-endpoints/v1alpha1", "networkId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
            "scope":{"team_id":"private-team","account_id":"123456789012","region":"us-east-1"},
            "bootstrapId":"965f7c13-e186-4d52-b7e3-ef92db98a0ec","consensusFingerprint":"ab".repeat(32),"nodeCount":1,
            "targets":[{"service":"node-rpc","nodeId":"node-1","instanceId":"i-00000000000000001"}]
        })).unwrap()).unwrap();
        endpoints
            .save_new(&root.path().join("endpoints.json"))
            .unwrap();
        fs::write(
            root.path().join("document.json"),
            serde_json::to_vec(&Service::NodeRpc.session_document()).unwrap(),
        )
        .unwrap();
        connect_aws::install(&root.path().join("aws"));
        let plugin = root.path().join("session-manager-plugin");
        executable::write(&plugin, "#!/bin/sh\nprintf '1.2.764.0\\n'\n").unwrap();
        fs::set_permissions(plugin, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, endpoints }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("HOME", self.root.path().join("home"))
            // Keep internally created wallet files under a physical private parent on macOS.
            .env(
                "TMPDIR",
                self.root.path().join("tmp").canonicalize().unwrap(),
            )
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().display()),
            )
            .env("ZDN_CONNECT_FIXTURE", self.root.path())
            .current_dir(self.root.path());
        command
    }
    fn connect(&self, mode: &str) -> Command {
        let mut command = self.command();
        command
            .args([
                "connect",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--json",
                "--startup-timeout-secs",
                "10",
            ])
            .env("ZDN_CONNECT_MODE", mode);
        command
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.root.path().join("calls")).unwrap_or_default()
    }
    fn rpc(&self, mode: &str, method: &str) -> Command {
        let mut command = self.command();
        command
            .args([
                "rpc",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--startup-timeout-secs",
                "10",
                method,
            ])
            .env("ZDN_CONNECT_MODE", mode);
        command
    }
    fn submit(&self, mode: &str) -> Command {
        fs::write(self.root.path().join("signed-tx.hex"), "00ABfe013579\n").unwrap();
        let mut command = self.command();
        command
            .args([
                "submit",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--startup-timeout-secs",
                "10",
                "--transaction-file",
                "signed-tx.hex",
            ])
            .env("ZDN_CONNECT_MODE", mode);
        command
    }
    fn wallet_history(&mut self, mode: &str, balance: bool) -> Command {
        use sha2::{Digest, Sha256};
        fs::set_permissions(self.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // Deliberately synthetic raw blocks: these test transport, not consensus.
        let mut manifest: Value =
            serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
        manifest["genesis"]["hash"] =
            json!("05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38");
        manifest["genesis"]["bytesLength"] = json!(3);
        manifest["genesis"]["bytesSha256"] = json!(hex::encode(Sha256::digest([0, 0x11, 0x22])));
        let parsed: zdn::chain::manifest::ConsensusManifest =
            serde_json::from_value(manifest.clone()).unwrap();
        self.endpoints.consensus_fingerprint = parsed.fingerprint().unwrap();
        fs::write(self.root.path().join("manifest.json"), manifest.to_string()).unwrap();
        fs::write(
            self.root.path().join("endpoints.json"),
            serde_json::to_vec(&self.endpoints).unwrap(),
        )
        .unwrap();
        let mut command = self.command();
        command.arg("wallet");
        if balance {
            // Public, proof-free payment contract: only orchestration is under test.
            let backend = self.root.path().join("wallet-backend");
            native_tool::install(&backend, "connect_wallet::worker", &json!({}));
            fs::write(self.root.path().join("public.json"), json!({"schema_version":1,"network":"test",
                "reward_address":bs58::encode([vec![0x1d,0x25],vec![1;20]].concat()).with_check().into_string(),
                "p2pkh_public_key_hex":format!("02{}","11".repeat(32)),"ironwood_address_hex":"22".repeat(43)}).to_string()).unwrap();
            fs::write(self.root.path().join("key.json"), "opaque-private-input").unwrap();
            fs::set_permissions(
                self.root.path().join("key.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            command.args([
                "--backend",
                backend.to_str().unwrap(),
                "--backend-sha256",
                &hex::encode(Sha256::digest(fs::read(&backend).unwrap())),
            ]);
            command.args(["balance", "key.json"]);
            if !mode.starts_with("wallet-classified") {
                command.arg("--confirmed-only");
            }
        } else {
            command.args(["history-export", "--output", "history.json"]);
        }
        command
            .args([
                "--manifest",
                "manifest.json",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--startup-timeout-secs",
                "10",
            ])
            .env("ZDN_CONNECT_MODE", mode);
        command
    }
    fn machine(&self, format: &str, command: &str, mode: &str) -> Command {
        let mut process = self.command();
        process.args([
            "--format",
            format,
            command,
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "participant",
            "--startup-timeout-secs",
            "10",
        ]);
        if command == "rpc" {
            process.arg("getblockcount");
        } else {
            fs::write(self.root.path().join("signed-tx.hex"), "00ABfe013579\n").unwrap();
            process.args(["--transaction-file", "signed-tx.hex"]);
        }
        process.env("ZDN_CONNECT_MODE", mode);
        process
    }
    fn assert_rpc_closed(&self) {
        let port: u16 = fs::read_to_string(self.root.path().join("server.port"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
        assert!(self.calls().contains("terminate-session"));
    }
    fn exec(&self, mode: &str, child: Case) -> Command {
        self.exec_reporting(mode, child, None)
    }
    fn exec_reporting(&self, mode: &str, child: Case, events: Option<&str>) -> Command {
        let program = connect_child::install(self.root.path(), child);
        let mut command = self.command();
        command
            .args([
                "exec",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--startup-timeout-secs",
                "10",
            ])
            .env("ZDN_CONNECT_MODE", mode);
        if let Some(path) = events {
            command.args(["--events-file", path]);
        }
        command.arg("--").arg(program).arg("--literal-argument");
        command
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn machine_records(format: &str, stdout: &[u8]) -> Vec<Value> {
    if format == "json" {
        vec![serde_json::from_slice(stdout).unwrap()]
    } else {
        std::str::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[test]
fn machine_one_shot_results_separate_command_status_from_submission_and_cleanup() {
    for format in ["json", "jsonl"] {
        for (command, mode, submission, retry) in [
            ("rpc", "ready", None, None),
            ("rpc", "rpc-null", None, None),
            ("rpc", "rpc-error", None, Some("blocked")),
            ("rpc", "terminate-fails", None, Some("blocked")),
            ("rpc", "wrong-chain", None, Some("blocked")),
            ("submit", "ready", Some("acknowledged"), None),
            (
                "submit",
                "terminate-fails",
                Some("acknowledged"),
                Some("reconcile-required"),
            ),
            (
                "submit",
                "rpc-error",
                Some("node-rejected"),
                Some("blocked"),
            ),
            (
                "submit",
                "rpc-drop",
                Some("outcome-unknown"),
                Some("reconcile-required"),
            ),
            (
                "submit",
                "submit-not-dispatched",
                Some("not-dispatched"),
                Some("blocked"),
            ),
            (
                "submit",
                "submit-bad-version",
                Some("outcome-unknown"),
                Some("reconcile-required"),
            ),
            (
                "submit",
                "wrong-chain",
                Some("not-dispatched"),
                Some("blocked"),
            ),
            (
                "submit",
                "wrong-account",
                Some("not-dispatched"),
                Some("blocked"),
            ),
        ] {
            let f = Fixture::new();
            let output = f.machine(format, command, mode).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(i32::from(retry.is_some())),
                "{format} {command} {mode}"
            );
            assert!(
                output.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let records = machine_records(format, &output.stdout);
            let ready = !["wrong-chain", "wrong-account"].contains(&mode);
            assert_eq!(
                records.len(),
                if format == "json" {
                    1
                } else {
                    2 + usize::from(ready)
                }
            );
            for record in &records {
                assert_eq!(record["apiVersion"], "zdn-cli/v1alpha1");
                assert_eq!(record["command"], command);
                assert!(record["operationId"].is_null());
            }
            if format == "jsonl" {
                assert_eq!(records[0]["type"], "command-started");
                assert!(records[0]["networkId"].is_null());
                if ready {
                    assert_eq!(records[1]["type"], "connection-ready");
                    assert_eq!(records[1]["outcome"], "observed");
                    assert_eq!(records[1]["networkId"], f.endpoints.network_id.to_string());
                    assert_eq!(
                        records[1]["data"],
                        json!({"consensusFingerprint":f.endpoints.consensus_fingerprint,"services":["node-rpc"],"paymentQualified":false})
                    );
                }
            }
            let terminal = records.last().unwrap();
            assert_eq!(terminal["type"], "result");
            assert_eq!(
                terminal["outcome"],
                if retry.is_some() {
                    "failed"
                } else {
                    "succeeded"
                }
            );
            if mode == "wrong-account" {
                assert!(terminal["networkId"].is_null());
            } else {
                assert_eq!(terminal["networkId"], f.endpoints.network_id.to_string());
            }
            if let Some(retry) = retry {
                assert_eq!(terminal["error"]["retryClassification"], retry);
                assert_eq!(
                    terminal["error"]["code"],
                    if command == "rpc" {
                        "rpc-failed"
                    } else {
                        "submission-failed"
                    }
                );
            } else {
                assert!(terminal["error"].is_null());
            }
            if let Some(submission) = submission {
                let report = &terminal["data"]["submission"];
                assert_eq!(report["apiVersion"], "zdn-submission/v1alpha1");
                assert_eq!(report["outcome"], submission);
                assert!(report.get("diagnostic").is_none());
                assert_eq!(
                    report["transactionSha256"],
                    "c19153c15a5a201ae1ac82a6dbab33daf112624c491c44d01b2f4a1dd6d4b680"
                );
                assert_eq!(
                    report["cleanup"],
                    match mode {
                        "terminate-fails" => "incomplete",
                        "wrong-account" => "no-sessions",
                        _ => "complete",
                    }
                );
                if submission == "acknowledged" {
                    assert_eq!(report["txid"], "ab".repeat(32));
                }
                if submission == "node-rejected" {
                    assert_eq!(report["code"], -8);
                }
            } else if retry.is_some() {
                assert!(terminal["data"].is_null());
            } else {
                assert_eq!(
                    terminal["data"],
                    json!({"result":if mode == "rpc-null" { Value::Null } else { json!({"method":"getblockcount","params":[],"height":73}) }})
                );
            }
            let requests =
                fs::read_to_string(f.root.path().join("rpc-requests")).unwrap_or_default();
            assert_eq!(requests.lines().count(), usize::from(ready));
            for private in [
                "DO-NOT-ECHO",
                "00abfe013579",
                "00ABfe013579",
                f.root.path().to_str().unwrap(),
            ] {
                assert!(
                    !String::from_utf8_lossy(&output.stdout).contains(private),
                    "{format} {command} {mode}"
                );
            }
            if mode != "wrong-account" {
                f.assert_rpc_closed();
            }
        }
    }
}

#[test]
fn machine_one_shot_invalid_inputs_fail_before_aws_without_echoing_inputs() {
    for format in ["json", "jsonl"] {
        for command in ["rpc", "submit"] {
            let f = Fixture::new();
            let mut process = f.machine(format, command, "ready");
            if command == "rpc" {
                process.args(["--params", "PRIVATE-INVALID-JSON"]);
            } else {
                fs::write(f.root.path().join("signed-tx.hex"), "PRIVATE-INVALID-HEX").unwrap();
            }
            let output = process.output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stderr.is_empty());
            let records = machine_records(format, &output.stdout);
            assert_eq!(records.len(), if format == "json" { 1 } else { 2 });
            let terminal = records.last().unwrap();
            assert_eq!(terminal["outcome"], "failed");
            assert!(terminal["networkId"].is_null() && terminal["operationId"].is_null());
            assert_eq!(terminal["error"]["retryClassification"], "blocked");
            if command == "submit" {
                assert_eq!(terminal["data"]["submission"]["outcome"], "not-dispatched");
                assert_eq!(terminal["data"]["submission"]["cleanup"], "no-sessions");
            }
            assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-INVALID"));
            assert!(f.calls().is_empty());
        }
        let f = Fixture::new();
        let output = f
            .command()
            .args([
                "--format",
                format,
                "rpc",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "sendrawtransaction",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let records = machine_records(format, &output.stdout);
        let terminal = records.last().unwrap();
        assert_eq!(terminal["error"]["code"], "rpc-failed");
        assert!(terminal["data"].is_null());
        assert!(output.stderr.is_empty());
        assert!(f.calls().is_empty());
    }
}

#[test]
fn machine_cancellation_preserves_a_known_submission_but_not_a_read_result() {
    for format in ["json", "jsonl"] {
        for command in ["rpc", "submit"] {
            let f = Fixture::new();
            let mut child = Running(
                f.machine(format, command, "rpc-wait")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !f.root.path().join("rpc-requests").exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.0.id() as i32),
                nix::sys::signal::Signal::SIGINT,
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(100));
            fs::write(f.root.path().join("rpc-release"), "release").unwrap();
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            };
            let mut stdout = Vec::new();
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut stdout)
                .unwrap();
            let records = machine_records(format, &stdout);
            let terminal = records.last().unwrap();
            assert_eq!(status.code(), Some(1));
            assert_eq!(terminal["outcome"], "failed");
            if command == "submit" {
                assert_eq!(terminal["data"]["submission"]["outcome"], "acknowledged");
                assert_eq!(terminal["data"]["submission"]["txid"], "ab".repeat(32));
                assert_eq!(terminal["data"]["submission"]["cleanup"], "complete");
                assert_eq!(
                    terminal["error"]["retryClassification"],
                    "reconcile-required"
                );
            } else {
                assert!(terminal["data"].is_null());
                assert_eq!(terminal["error"]["retryClassification"], "blocked");
            }
            assert_eq!(
                fs::read_to_string(f.root.path().join("rpc-requests"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
            f.assert_rpc_closed();
        }
    }
}

#[test]
fn broken_machine_streams_gate_dispatch_but_do_not_undo_sent_requests_or_cleanup() {
    for command in ["rpc", "submit"] {
        let f = Fixture::new();
        let (reader, writer) = nix::unistd::pipe().unwrap();
        drop(reader);
        let output = f
            .machine("jsonl", command, "ready")
            .stdout(Stdio::from(writer))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(f.calls().is_empty());

        let f = Fixture::new();
        let mut child = Running(
            f.machine("jsonl", command, "health-wait")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = BufReader::new(child.0.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["type"],
            "command-started"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !f.root.path().join("health-started").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(stdout);
        fs::write(f.root.path().join("health-release"), "release").unwrap();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(1));
        assert!(!f.root.path().join("rpc-requests").exists());
        f.assert_rpc_closed();

        // Once dispatched, losing the terminal stream must not replay the RPC.
        for format in ["json", "jsonl"] {
            let f = Fixture::new();
            let mut child = Running(
                f.machine(format, command, "rpc-wait")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !f.root.path().join("rpc-requests").exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            drop(child.0.stdout.take().unwrap());
            fs::write(f.root.path().join("rpc-release"), "release").unwrap();
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(status.code(), Some(1));
            assert_eq!(
                fs::read_to_string(f.root.path().join("rpc-requests"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
            f.assert_rpc_closed();
        }
    }
}

#[test]
fn submission_reports_outcomes_without_retrying_or_confusing_cleanup_with_acceptance() {
    for (mode, outcome, code) in [
        ("ready", "acknowledged", None),
        ("terminate-fails", "acknowledged", None),
        ("rpc-error", "node-rejected", Some(-8)),
        ("rpc-error-null-data", "outcome-unknown", None),
        ("submit-rejected", "node-rejected", Some(-26)),
        ("submit-not-dispatched", "not-dispatched", None),
        ("submit-unknown", "outcome-unknown", None),
        ("submit-legacy-unavailable", "outcome-unknown", None),
        ("submit-bad-version", "outcome-unknown", None),
        ("submit-wrong-status", "outcome-unknown", None),
        ("submit-invalid-txid", "outcome-unknown", None),
        ("rpc-null", "outcome-unknown", None),
        ("rpc-drop", "outcome-unknown", None),
        ("rpc-wrong-id", "outcome-unknown", None),
        ("rpc-malformed", "outcome-unknown", None),
        ("rpc-conflict", "outcome-unknown", None),
        ("rpc-redirect", "outcome-unknown", None),
        ("rpc-stall", "outcome-unknown", None),
        ("wrong-chain", "not-dispatched", None),
        ("wrong-account", "not-dispatched", None),
    ] {
        let f = Fixture::new();
        let output = f
            .submit(mode)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(i32::from(mode != "ready")),
            "{mode}"
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{mode}: {error}: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(report["apiVersion"], "zdn-submission/v1alpha1");
        assert_eq!(report["outcome"], outcome, "{mode}: {report}");
        assert_eq!(report["code"].as_i64(), code, "{mode}");
        assert_eq!(
            report["transactionSha256"],
            "c19153c15a5a201ae1ac82a6dbab33daf112624c491c44d01b2f4a1dd6d4b680"
        );
        if outcome == "acknowledged" {
            assert_eq!(report["txid"], "ab".repeat(32));
        } else {
            assert!(report.get("txid").is_none(), "{mode}");
        }
        let cleanup = match mode {
            "wrong-account" => "no-sessions",
            "terminate-fails" => "incomplete",
            _ => "complete",
        };
        assert_eq!(report["cleanup"], cleanup, "{mode}");
        let requests = fs::read_to_string(f.root.path().join("rpc-requests")).unwrap_or_default();
        if ["wrong-chain", "wrong-account"].contains(&mode) {
            assert!(requests.is_empty(), "{mode}");
        } else {
            assert_eq!(requests.lines().count(), 1, "{mode}");
            if mode == "rpc-drop" {
                assert_eq!(
                    fs::read_to_string(f.root.path().join("accepted-txid")).unwrap(),
                    "ab".repeat(32)
                );
            }
            let request: Value = serde_json::from_str(requests.trim()).unwrap();
            assert_eq!(
                request["body"],
                json!({"jsonrpc":"2.0","id":"zdn-submit","method":"sendrawtransaction","params":["00abfe013579"]})
            );
            assert!(request["authorization"].is_null());
            assert_eq!(report["networkId"], f.endpoints.network_id.to_string());
            assert_eq!(
                report["consensusFingerprint"],
                f.endpoints.consensus_fingerprint
            );
        }
        for private in ["DO-NOT-ECHO", "00ABfe013579", "00abfe013579"] {
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(private),
                "{mode}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(private),
                "{mode}"
            );
        }
        assert!(!f.root.path().join("redirect-followed").exists());
        if mode == "wrong-account" {
            assert!(!f.calls().contains("start-session"));
        } else {
            f.assert_rpc_closed();
        }
    }
}

#[test]
fn submission_validates_files_before_aws() {
    for bytes in [
        b"".as_slice(),
        b"abc",
        b"ab cd",
        b"0x12",
        b"PRIVATE",
        b"\xff",
        &vec![b'a'; 8 * 1024 * 1024 + 1],
    ] {
        let f = Fixture::new();
        let mut command = f.submit("ready");
        fs::write(f.root.path().join("signed-tx.hex"), bytes).unwrap();
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["outcome"], "not-dispatched");
        assert_eq!(report["cleanup"], "no-sessions");
        assert!(report.get("transactionSha256").is_none());
        assert!(f.calls().is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));
    }
}

#[test]
fn submission_preserves_an_acknowledgement_returned_after_cancellation() {
    let f = Fixture::new();
    let mut child = Running(
        f.submit("rpc-wait")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !f.root.path().join("rpc-requests").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.0.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    fs::write(f.root.path().join("rpc-release"), "release").unwrap();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(status.code(), Some(1));
    assert_eq!(report["outcome"], "acknowledged");
    assert_eq!(report["txid"], "ab".repeat(32));
    assert_eq!(report["cleanup"], "complete");
    assert!(report["diagnostic"].as_str().unwrap().contains("cancelled"));
    assert_eq!(
        fs::read_to_string(f.root.path().join("rpc-requests"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    f.assert_rpc_closed();
}

#[test]
fn one_shot_rpc_returns_only_the_result_after_verified_connection_cleanup() {
    for (mode, params, expected) in [
        (
            "ready",
            None,
            json!({"method":"getblockhash","params":[],"height":73}),
        ),
        (
            "ready",
            Some("[7, false, \"block\\\"name\"]"),
            json!({"method":"getblockhash","params":[7,false,"block\"name"],"height":73}),
        ),
        (
            "ready",
            Some("{\"height\":17,\"verbose\":true}"),
            json!({"method":"getblockhash","params":{"height":17,"verbose":true},"height":73}),
        ),
        ("rpc-null", None, Value::Null),
        ("rpc-wide", None, json!("x".repeat(70_000))),
    ] {
        let f = Fixture::new();
        let mut command = f.rpc(mode, "getblockhash");
        command
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("no_proxy", "");
        if let Some(params) = params {
            command.args(["--params", params]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            expected
        );
        assert!(output.stderr.is_empty());
        let requests = fs::read_to_string(f.root.path().join("rpc-requests")).unwrap();
        assert_eq!(requests.lines().count(), 1);
        let observed: Value = serde_json::from_str(requests.trim()).unwrap();
        assert_eq!(
            observed["body"],
            json!({"jsonrpc":"2.0","id":"zdn-read","method":"getblockhash","params":params.map(|p| serde_json::from_str::<Value>(p).unwrap()).unwrap_or(json!([]))})
        );
        assert!(observed["authorization"].is_null());
        assert_eq!(observed["contentType"], "application/json");
        f.assert_rpc_closed();
    }
}

#[test]
fn one_shot_rpc_rejects_local_inputs_before_aws() {
    for (method, params) in [
        ("sendrawtransaction", "[]"),
        ("stop", "[]"),
        ("getblockcount ", "[]"),
        ("getblockcount", "{"),
        ("getblockcount", "null"),
        ("getblockcount", "7"),
    ] {
        let f = Fixture::new();
        let output = f
            .rpc("ready", method)
            .args(["--params", params])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(f.calls().is_empty());
    }
}

#[test]
fn one_shot_rpc_failures_never_publish_results_or_retry_and_always_clean_up() {
    for mode in [
        "wrong-chain",
        "rpc-error",
        "rpc-wrong-id",
        "rpc-malformed",
        "rpc-missing-result",
        "rpc-conflict",
        "rpc-redirect",
        "rpc-drop",
        "rpc-large",
        "rpc-stall",
        "terminate-fails",
    ] {
        let f = Fixture::new();
        let started = std::time::Instant::now();
        let output = f.rpc(mode, "getblockcount").output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{mode}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("DO-NOT-ECHO"), "{mode}: {error}");
        let requests = fs::read_to_string(f.root.path().join("rpc-requests")).unwrap_or_default();
        assert_eq!(
            requests.lines().count(),
            usize::from(mode != "wrong-chain"),
            "{mode}"
        );
        if mode == "rpc-error" {
            assert!(error.contains("code -8"), "{error}");
        }
        if mode == "rpc-large" {
            assert!(error.contains("size limit"), "{error}");
        }
        if mode == "rpc-stall" {
            assert!(started.elapsed() < Duration::from_secs(15));
        }
        assert!(!f.root.path().join("redirect-followed").exists());
        if mode == "terminate-fails" {
            assert!(error.contains("cleanup was incomplete"), "{error}");
        }
        f.assert_rpc_closed();
    }
}

#[test]
fn one_shot_rpc_cancellation_discards_an_in_flight_successful_response() {
    for operation in ["rpc", "history-export", "balance"] {
        let mut f = Fixture::new();
        let mut command = if operation == "rpc" {
            f.rpc("rpc-wait", "getblockcount")
        } else {
            f.wallet_history("wallet-wait", operation == "balance")
        };
        let mut child = Running(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !f.root.path().join("rpc-requests").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.0.id() as i32),
            nix::sys::signal::Signal::SIGINT,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        fs::write(f.root.path().join("rpc-release"), "release").unwrap();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stdout = Vec::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        assert_eq!(status.code(), Some(1));
        assert!(stdout.is_empty());
        assert!(!f.root.path().join("history.json").exists());
        f.assert_rpc_closed();
    }
}

#[test]
fn scoped_exec_events_keep_streams_and_child_results_separate() {
    for (mode, program, code, child_code, signal, cleanup) in [
        ("ready", Case::Streams(0), 0, Some(0), None, "complete"),
        ("ready", Case::Streams(37), 37, Some(37), None, "complete"),
        ("ready", Case::Signal, 143, None, Some(15), "complete"),
        (
            "terminate-fails",
            Case::Quiet,
            125,
            Some(0),
            None,
            "incomplete",
        ),
    ] {
        let f = Fixture::new();
        let output = f
            .exec_reporting(mode, program, Some("events.jsonl"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if code == 0 || code == 37 {
            assert_eq!(output.stdout, b"child stdout\n");
            assert_eq!(output.stderr, b"child stderr\n");
        } else {
            assert!(output.stdout.is_empty());
        }
        let path = f.root.path().join("events.jsonl");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = fs::read_to_string(path).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            records
                .iter()
                .map(|r| r["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "command-started",
                "connection-ready",
                "child-started",
                "result"
            ]
        );
        for record in &records {
            assert_eq!(record["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(record["command"], "exec");
            assert!(record["operationId"].is_null());
        }
        assert!(records[0]["networkId"].is_null());
        assert_eq!(records[1]["networkId"], f.endpoints.network_id.to_string());
        let terminal = records.last().unwrap();
        assert_eq!(
            terminal["outcome"],
            if code == 0 { "succeeded" } else { "failed" }
        );
        assert_eq!(terminal["data"]["exitCode"], code);
        assert_eq!(
            terminal["data"]["childStatus"],
            json!({"exitCode":child_code, "signal":signal})
        );
        assert_eq!(terminal["data"]["cleanup"], cleanup);
        assert_eq!(terminal["data"]["cancelled"], false);
        assert_eq!(terminal["data"]["tunnelFailed"], false);
        assert_eq!(terminal["data"]["eventsFailed"], false);
        assert!(
            !text.contains("child stdout")
                && !text.contains("DO-NOT-ECHO")
                && !text.contains("--literal-argument")
        );
        f.assert_rpc_closed();
    }
}

#[test]
fn scoped_exec_event_paths_are_new_only_and_preflight_failure_is_terminal() {
    for kind in [
        "file",
        "symlink",
        "directory",
        "missing-parent",
        "wrong-chain",
        "wrong-account",
    ] {
        let f = Fixture::new();
        let path = f.root.path().join("events.jsonl");
        let target = f.root.path().join("existing");
        fs::write(&target, "untouched").unwrap();
        match kind {
            "file" => fs::write(&path, "untouched").unwrap(),
            "symlink" => std::os::unix::fs::symlink(&target, &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            _ => (),
        }
        let mode = if kind.starts_with("wrong-") {
            kind
        } else {
            "ready"
        };
        let output = f
            .exec_reporting(
                mode,
                Case::Started,
                Some(if kind == "missing-parent" {
                    "missing/events.jsonl"
                } else {
                    "events.jsonl"
                }),
            )
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(125));
        assert!(!f.root.path().join("child-started").exists());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        if kind == "file" {
            assert_eq!(fs::read_to_string(&path).unwrap(), "untouched");
        }
        if kind.starts_with("wrong-") {
            let records: Vec<Value> = fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records.len(), 2);
            let terminal = &records[1];
            assert_eq!(terminal["type"], "result");
            assert_eq!(terminal["outcome"], "failed");
            assert!(terminal["data"]["childStatus"].is_null());
            assert_eq!(
                terminal["data"]["cleanup"],
                if kind == "wrong-chain" {
                    "complete"
                } else {
                    "no-sessions"
                }
            );
            assert_eq!(terminal["error"]["code"], "exec-failed");
        } else {
            assert!(f.calls().is_empty());
        }
    }
}

#[test]
fn scoped_exec_initial_event_write_failure_prevents_aws_and_child_launch() {
    let f = Fixture::new();
    let command = f.exec_reporting("ready", Case::Started, Some("events.jsonl"));
    let output = native_exec::command(f.root.path(), command.get_program(), Some(0))
        .args(command.get_args())
        .env_clear()
        .envs(command.get_envs().map(|(key, value)| (key, value.unwrap())))
        .current_dir(f.root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(f.calls().is_empty());
    assert!(!f.root.path().join("child-started").exists());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot write exec events"));
}

#[test]
#[cfg(target_os = "linux")]
fn scoped_exec_terminal_write_failure_keeps_child_result_without_replaying() {
    let f = Fixture::new();
    let command = f.exec_reporting("terminal-event-fails", Case::Counted, Some("events.jsonl"));
    let output = native_exec::command(f.root.path(), command.get_program(), None)
        .args(command.get_args())
        .env_clear()
        .envs(command.get_envs().map(|(key, value)| (key, value.unwrap())))
        .current_dir(f.root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"child stdout\n");
    assert_eq!(
        fs::read_to_string(f.root.path().join("launch-count")).unwrap(),
        "x"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("cannot write terminal exec event"),
        "{error}"
    );
    assert!(error.contains("child exit code Some(37)"), "{error}");
    assert!(!error.contains("cleanup was incomplete"), "{error}");
    let records: Vec<Value> = fs::read_to_string(f.root.path().join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|r| r["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["command-started", "connection-ready", "child-started"]
    );
    f.assert_rpc_closed();
}

#[test]
fn scoped_exec_preserves_executable_symlinks_for_explicit_paths_and_path_search() {
    for selection in ["relative", "absolute", "path"] {
        let f = Fixture::new();
        let target = f.root.path().join("real-tool");
        let link = f.root.path().join("linked-tool");
        executable::write(&target, "#!/bin/sh\nprintf '%s\\n' \"$0\"\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let program = match selection {
            "relative" => std::path::Path::new("./linked-tool"),
            "absolute" => link.as_path(),
            _ => std::path::Path::new("linked-tool"),
        };
        let output = f
            .command()
            .args([
                "exec",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--",
            ])
            .arg(program)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{selection}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, format!("{}\n", link.display()).as_bytes());
        assert!(f.calls().contains("terminate-session"));
    }
}

#[test]
fn scoped_exec_path_search_skips_non_executable_files() {
    for executable_available in [true, false] {
        let f = Fixture::new();
        for directory in ["first", "second"] {
            fs::create_dir(f.root.path().join(directory)).unwrap();
            let tool = f.root.path().join(directory).join("tool");
            executable::write(&tool, "#!/bin/sh\nprintf 'selected-second\\n'\n").unwrap();
            let mode = if directory == "second" && executable_available {
                0o755
            } else {
                0o644
            };
            fs::set_permissions(tool, fs::Permissions::from_mode(mode)).unwrap();
        }
        let output = f
            .command()
            .env(
                "PATH",
                format!(
                    "{0}/first:{0}/second:{0}:/usr/bin:/bin",
                    f.root.path().display()
                ),
            )
            .args([
                "exec",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--",
                "tool",
            ])
            .output()
            .unwrap();
        if executable_available {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"selected-second\n");
            assert!(f.calls().contains("terminate-session"));
        } else {
            assert_eq!(output.status.code(), Some(125));
            assert!(f.calls().is_empty());
        }
    }
}

#[test]
fn scoped_exec_preserves_status_output_cwd_and_original_environment() {
    for code in [0, 37] {
        let f = Fixture::new();
        let output = f
            .exec("ready", Case::Environment(code))
            .env("AWS_CONFIG_FILE", "./original-config")
            .env("ZDN_RPC_URL", "stale")
            .env("ZDN_LIGHTWALLET_GRPC_URL", "stale")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"child stdout\n");
        assert_eq!(output.stderr, b"child stderr\n");
        let report: Value =
            serde_json::from_slice(&fs::read(f.root.path().join("child-report")).unwrap()).unwrap();
        assert_eq!(
            report["cwd"],
            fs::canonicalize(f.root.path()).unwrap().to_str().unwrap()
        );
        let address: SocketAddr = report["url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://")
            .unwrap()
            .parse()
            .unwrap();
        assert!(TcpStream::connect(address).is_err());
        assert!(f.calls().contains("terminate-session"));
        assert!(!f.root.path().join(".zdn-pulumi-process.json").exists());
        if cfg!(target_os = "linux") {
            let pid = fs::read_to_string(f.root.path().join("descendant.pid")).unwrap();
            let state = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            assert!(
                state.is_empty() || state.split_whitespace().nth(2) == Some("Z"),
                "{state}"
            );
        }
    }
}

#[test]
fn scoped_exec_never_runs_before_identity_checks_or_with_machine_output() {
    for mode in [
        "wrong-chain",
        "wrong-account",
        "changed-document",
        "machine",
    ] {
        let f = Fixture::new();
        let mut command = f.exec(mode, Case::Started);
        if mode == "machine" {
            command = f.command();
            command.args([
                "--format",
                "json",
                "exec",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--",
                "./child",
            ]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(!f.root.path().join("child-started").exists());
        if mode == "wrong-chain" {
            assert!(f.calls().contains("terminate-session"));
        }
        if mode == "machine" {
            assert!(f.calls().is_empty());
        }
    }
}

#[test]
fn scoped_exec_cleanup_failure_overrides_child_success_and_retains_its_result() {
    let f = Fixture::new();
    let output = f.exec("terminate-fails", Case::Finished).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"finished\n");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("cleanup was incomplete"), "{error}");
    assert!(error.contains("child exit code Some(0)"), "{error}");
}

#[test]
fn scoped_exec_stops_children_on_cancellation_or_tunnel_failure() {
    for mode in ["ready", "exit-after-child"] {
        let f = Fixture::new();
        let mut child = Running(
            f.exec_reporting(mode, Case::Stubborn, Some("events.jsonl"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !f.root.path().join("child-started").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        if mode == "ready" {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.0.id() as i32),
                nix::sys::signal::Signal::SIGINT,
            )
            .unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert_eq!(
            status.code(),
            Some(if mode == "ready" { 130 } else { 125 }),
            "{stderr}"
        );
        let records: Vec<Value> = fs::read_to_string(f.root.path().join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let terminal = records.last().unwrap();
        assert_eq!(terminal["type"], "result");
        assert_eq!(terminal["data"]["cancelled"], mode == "ready");
        assert_eq!(terminal["data"]["tunnelFailed"], mode == "exit-after-child");
        assert_eq!(terminal["data"]["cleanup"], "complete");
        assert!(!terminal["data"]["childStatus"].is_null());
        let pid: i32 = fs::read_to_string(f.root.path().join("descendant.pid"))
            .unwrap()
            .parse()
            .unwrap();
        // A reparented descendant may briefly be a zombie, but cannot remain live.
        let state = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        if cfg!(target_os = "linux") {
            assert!(
                state.is_empty() || state.split_whitespace().nth(2) == Some("Z"),
                "{state}"
            );
        }
        assert!(f.calls().contains("terminate-session"));
    }
}

#[test]
fn scoped_exec_preserves_signal_status_after_cleanup() {
    let f = Fixture::new();
    let output = f.exec("ready", Case::Signal).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(143),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(f.calls().contains("terminate-session"));
}

#[test]
fn participant_connect_uses_no_local_binding_or_state_credentials_and_cleans_up() {
    let f = Fixture::new();
    assert_connection_cleans_up(&f, f.connect("ready"));
}

#[test]
fn aws_file_paths_and_plugin_search_survive_the_session_directory_change() {
    for style in ["relative", "absolute", "home"] {
        let f = Fixture::new();
        let files = f.root.path().join("home/aws files");
        fs::create_dir(&files).unwrap();
        let mut command = f.connect("paths");
        for (key, name) in [
            ("AWS_CONFIG_FILE", "config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "credentials"),
            ("AWS_CA_BUNDLE", "ca.pem"),
        ] {
            fs::write(files.join(name), format!("fixture {name}")).unwrap();
            let value = match style {
                "relative" => format!("./home/aws files/{name}"),
                "home" => format!("~/aws files/{name}"),
                _ => files.join(name).to_str().unwrap().to_owned(),
            };
            command.env(key, value);
        }
        // AWS locates the Session Manager plugin through PATH after changing
        // directories too. Both an empty entry and '.' mean the caller's cwd.
        command.env("PATH", ":.:/usr/bin:/bin");
        assert_connection_cleans_up(&f, command);
        let observations = fs::read_to_string(f.root.path().join("path-observations")).unwrap();
        let records: Vec<Value> = observations
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(records.iter().any(|v| v["args"]
            .as_array()
            .unwrap()
            .contains(&json!("get-caller-identity"))));
        let start = records
            .iter()
            .find(|v| {
                v["args"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("start-session"))
            })
            .unwrap();
        assert_ne!(
            start["cwd"],
            fs::canonicalize(f.root.path()).unwrap().to_str().unwrap()
        );
        assert!(records.iter().any(|v| v["args"]
            .as_array()
            .unwrap()
            .contains(&json!("terminate-session"))));
    }
}

fn assert_connection_cleans_up(f: &Fixture, mut command: Command) {
    let mut child = Running(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let record = serde_json::Deserializer::from_reader(BufReader::new(stdout))
            .into_iter::<Value>()
            .next()
            .expect("readiness record");
        let _ = tx.send(record);
    });
    let ready = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("CLI readiness deadline")
        .unwrap();
    assert_eq!(ready["networkId"], f.endpoints.network_id.to_string());
    assert_eq!(ready["lightwalletEnabled"], false);
    let endpoint = ready["services"][0]["endpoint"].as_str().unwrap();
    let address: SocketAddr = endpoint.strip_prefix("http://").unwrap().parse().unwrap();
    assert!(TcpStream::connect(address).is_ok());
    assert!(!f.root.path().join("home/.local/share/zdn/state").exists());
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.0.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "{stderr}");
    assert!(TcpStream::connect(address).is_err());
    let calls = f.calls();
    assert!(
        calls.contains("get-caller-identity")
            && calls.contains("get-document")
            && calls.contains("terminate-session")
    );
    for forbidden in [
        "s3api",
        "kms",
        "assume-role",
        "send-command",
        "describe-instances",
        "pulumi",
    ] {
        assert!(!calls.contains(forbidden), "{calls}");
    }
}

#[test]
fn wrong_remote_chain_closes_the_started_session_without_publishing_endpoints() {
    let f = Fixture::new();
    let output = f.connect("wrong-chain").output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match"));
    assert!(f.calls().contains("terminate-session"));
}

#[test]
fn endpoint_file_requires_explicit_profile_before_tools_or_state() {
    let f = Fixture::new();
    let output = f
        .command()
        .args(["connect", "--endpoints", "endpoints.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--aws-profile"));
    assert!(f.calls().is_empty());
}

#[test]
fn unusable_plugin_fails_before_any_aws_call_or_session_creation() {
    for case in [
        "missing",
        "not-executable",
        "invalid-binary",
        "nonzero",
        "empty",
        "malformed",
        "old-version",
    ] {
        let f = Fixture::new();
        let plugin = f.root.path().join("session-manager-plugin");
        match case {
            "missing" => fs::remove_file(&plugin).unwrap(),
            "not-executable" => fs::set_permissions(&plugin, fs::Permissions::from_mode(0o600)).unwrap(),
            "invalid-binary" => executable::write(&plugin, b"not an executable format\0").unwrap(),
            "nonzero" => executable::write(&plugin, "#!/bin/sh\nprintf 'SECRET-PLUGIN-OUTPUT\\n'\nprintf 'SECRET-PLUGIN-OUTPUT\\n' >&2\nexit 1\n").unwrap(),
            "empty" => executable::write(&plugin, "#!/bin/sh\nexit 0\n").unwrap(),
            "malformed" => executable::write(&plugin, "#!/bin/sh\nprintf 'SECRET-PLUGIN-OUTPUT\\n'\n").unwrap(),
            "old-version" => executable::write(&plugin, "#!/bin/sh\nprintf '1.2.497.0\\n'\n").unwrap(),
            _ => unreachable!(),
        }
        let output = f.connect("ready").output().unwrap();
        assert!(!output.status.success(), "accepted {case}");
        assert!(output.stdout.is_empty(), "published output for {case}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("Session Manager plugin"), "{case}: {error}");
        assert!(
            !error.contains("SECRET-PLUGIN-OUTPUT"),
            "{case}: exposed process output"
        );
        assert!(
            f.calls().is_empty(),
            "{case}: made AWS calls before plugin validation"
        );
    }
}

#[test]
fn endpoint_and_port_errors_fail_before_any_aws_call() {
    for case in [
        "invalid-json",
        "extra-credential",
        "grpc-disabled",
        "same-ports",
        "missing-local",
    ] {
        let f = Fixture::new();
        let mut command = f.connect("ready");
        match case {
            "invalid-json" => fs::write(f.root.path().join("endpoints.json"), b"no json").unwrap(),
            "extra-credential" => {
                let mut value = serde_json::to_value(&f.endpoints).unwrap();
                value["credentials"] = json!("SECRET");
                fs::write(f.root.path().join("endpoints.json"), value.to_string()).unwrap();
            }
            "grpc-disabled" => {
                command.args(["--grpc-port", "20001"]);
            }
            "same-ports" => {
                command.args(["--rpc-port", "20001", "--grpc-port", "20001"]);
            }
            "missing-local" => {
                command = f.command();
                command.args(["connect", "absent"]);
            }
            _ => unreachable!(),
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{case}");
        assert!(f.calls().is_empty(), "{case}");
    }
}

#[test]
fn wrong_account_and_changed_session_document_stop_before_start_session() {
    for mode in ["wrong-account", "changed-document"] {
        let f = Fixture::new();
        let output = f.connect(mode).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!f.calls().contains("start-session"));
    }
}

#[test]
fn wallet_exports_exact_snapshot_and_balances_only_unspent_notes_as_of_that_snapshot() {
    use sha2::{Digest, Sha256};
    for mode in ["wallet-advance", "wallet-genesis-only"] {
        let mut f = Fixture::new();
        let output = f.wallet_history(mode, false).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected_height = if mode == "wallet-genesis-only" { 0 } else { 1 };
        let expected_hash = if expected_height == 0 {
            "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38".to_string()
        } else {
            hex::encode((1u8..=32).collect::<Vec<_>>())
        };
        assert_eq!(
            observation["as_of"],
            json!({"height":expected_height,"hash":expected_hash})
        );
        assert_eq!(
            observation["scan_lag_blocks"],
            if expected_height == 0 { 0 } else { 3 }
        );
        assert_eq!(observation["snapshot_tip_canonical_at_observation"], true);
        assert_eq!(observation["consensus_validated_by_zdn"], false);
        assert_eq!(
            observation["network_id"],
            f.endpoints.network_id.to_string()
        );
        assert_eq!(
            observation["consensus_fingerprint"],
            f.endpoints.consensus_fingerprint
        );
        let bytes = fs::read(f.root.path().join("history.json")).unwrap();
        assert_eq!(
            observation["history_file_sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
        // Export may move the JSON payload before the final observation, but
        // must preserve its independently collected snapshot metadata.
        let mut preimage = 3u64.to_le_bytes().to_vec();
        preimage.extend([0x00, 0x11, 0x22]);
        if expected_height != 0 {
            preimage.extend(4u64.to_le_bytes());
            preimage.extend([0x33, 0x44, 0x55, 0x66]);
        }
        assert_eq!(
            observation["history_sha256"],
            hex::encode(Sha256::digest(preimage))
        );
        assert_eq!(observation["anchor_hex"], "a1".repeat(32));
        let history: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            history,
            json!({
                "schema_version":1,"network":"h0-testnet-nu6.3-at-1",
                "genesis_hash":"05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
                "blocks":if expected_height==0 { vec!["001122"] } else { vec!["001122","33445566"] },
                "treestate":{"height":expected_height,"hash":expected_hash,"time":123,
                    "ironwood":{"commitments":{"finalRoot":"a1".repeat(32),"finalState":"retained-complete-tree"}}}
            })
        );
        assert_eq!(
            fs::metadata(f.root.path().join("history.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        f.assert_rpc_closed();
        // Never replace an export, including when the new request fails preflight.
        let repeat = f.wallet_history(mode, false).output().unwrap();
        assert!(!repeat.status.success());
        assert_eq!(fs::read(f.root.path().join("history.json")).unwrap(), bytes);
    }
    for empty in [false, true] {
        let mut f = Fixture::new();
        let mut command = f.wallet_history("wallet-advance", true);
        if empty {
            command.env("ZDN_WALLET_BACKEND", "empty");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let balance: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(balance["as_of"]["height"], 1);
        assert_eq!(balance["observed_tip"]["height"], 4);
        assert_eq!(balance["scan_lag_blocks"], 3);
        assert_eq!(
            balance["balance"],
            json!({"pool":"ironwood", "confirmed_unspent_zat":if empty {0} else {46},
            "unspent_note_count":if empty {0} else {2}, "spendable_zat":null,"pending_zat":null,"immature_zat":null})
        );
        f.assert_rpc_closed();
    }
}

#[test]
fn wallet_history_and_balance_fail_closed_on_reorg_bad_data_and_cleanup_failure() {
    for balance in [false, true] {
        for mode in [
            "wallet-reorg",
            "wallet-rollback",
            "wallet-wrong-genesis",
            "wallet-wrong-bytes",
            "wallet-malformed",
            "wallet-tree-mismatch",
            "wallet-too-high",
            "wallet-cleanup-fails",
        ] {
            let mut f = Fixture::new();
            let output = f.wallet_history(mode, balance).output().unwrap();
            assert!(
                !output.status.success(),
                "accepted {mode} balance={balance}"
            );
            assert!(
                output.stdout.is_empty(),
                "published {mode} balance={balance}"
            );
            assert!(!f.root.path().join("history.json").exists());
            f.assert_rpc_closed();
        }
    }
    for mode in [
        "digest",
        "tip",
        "height",
        "anchor",
        "duplicate",
        "total",
        "fail",
    ] {
        let mut f = Fixture::new();
        let output = f
            .wallet_history("wallet-advance", true)
            .env("ZDN_WALLET_BACKEND", mode)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted backend {mode}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET-WALLET-DIAGNOSTIC"));
        f.assert_rpc_closed();
    }
}

#[test]
fn classified_balances_bind_mempool_provenance_and_refuse_changing_observations() {
    use sha2::{Digest, Sha256};
    for mode in ["stable", "advance-before"] {
        let mut f = Fixture::new();
        let output = f
            .wallet_history(&format!("wallet-classified-{mode}"), true)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut preimage = b"ironwood-wallet-mempool/v1\0".to_vec();
        preimage.extend(2u64.to_le_bytes());
        preimage.extend([1, 2]);
        preimage.extend(3u64.to_le_bytes());
        preimage.extend([0xaa, 0xbb, 0xcc]);
        assert_eq!(
            value["balance"],
            json!({"pool":"ironwood","confirmed_unspent_zat":46,
        "spendable_zat":29,"pending_spent_zat":17,"pending_zat":7,"immature_zat":0,
        "mempool_sha256":hex::encode(Sha256::digest(preimage))})
        );
        assert_eq!(value["scan_lag_blocks"], 0);
        assert_eq!(value["mempool_snapshot_rechecked"], true);
        assert_eq!(value["local_reservations_checked"], false);
        f.assert_rpc_closed();
    }
    for mode in [
        "changed",
        "advance-after",
        "reorg",
        "duplicate",
        "too-many",
        "malformed",
        "raw-bad",
    ] {
        let mut f = Fixture::new();
        let output = f
            .wallet_history(&format!("wallet-classified-{mode}"), true)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {mode}");
        assert!(output.stdout.is_empty(), "published {mode}");
        f.assert_rpc_closed();
    }
    for mode in [
        "digest", "tip", "height", "anchor", "mempool", "total", "immature", "leak", "fail",
    ] {
        let mut f = Fixture::new();
        let output = f
            .wallet_history("wallet-classified-stable", true)
            .env("ZDN_WALLET_BACKEND", mode)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted backend {mode}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET-WALLET-DIAGNOSTIC"));
        f.assert_rpc_closed();
    }
}

#[test]
fn named_balance_verifies_local_identity_then_uses_verified_network_snapshot() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    let _ = f.wallet_history("wallet-classified-stable", true);
    let hash = hex::encode(Sha256::digest(
        fs::read(f.root.path().join("wallet-backend")).unwrap(),
    ));
    let command = |subcommand: &[&str]| {
        let mut command = f.command();
        command
            .args([
                "wallet",
                "--wallet-dir",
                "wallets",
                "--backend",
                "./wallet-backend",
                "--backend-sha256",
                &hash,
            ])
            .args(subcommand)
            .args([
                "--manifest",
                "manifest.json",
                "--endpoints",
                "endpoints.json",
                "--aws-profile",
                "participant",
                "--startup-timeout-secs",
                "10",
            ])
            .env("ZDN_CONNECT_MODE", "wallet-classified-stable");
        command
    };
    let create = command(&["create", "--name", "alice"]).output().unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(f.calls().is_empty());
    let output = command(&["balance", "--wallet", "alice"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["network_id"], f.endpoints.network_id.to_string());
    assert_eq!(value["balance"]["spendable_zat"], 29);
    assert_eq!(value["balance"]["reserved_zat"], 0);
    assert_eq!(value["local_reservations_checked"], true);
    f.assert_rpc_closed();
    let receipt: Value = serde_json::from_slice(&create.stdout).unwrap();
    let record = json!({"schema_version":1,"operation_id":"a0000000-0000-4000-8000-000000000001",
        "network_id":f.endpoints.network_id,"consensus_fingerprint":f.endpoints.consensus_fingerprint,
        "wallet_id":receipt["id"],"request":{"amount_zat":1},"plan":{"fixture":true},
        "inputs":[{"kind":"ironwood","txid":"56".repeat(32),"action_index":0}],
        "signed":null,"attempts":0,"outcome":{"kind":"prepared"}});
    let path = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string())
        .join("payments/a0000000-0000-4000-8000-000000000001.json");
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let reserved = command(&["balance", "--wallet", "alice"]).output().unwrap();
    assert!(
        reserved.status.success(),
        "{}",
        String::from_utf8_lossy(&reserved.stderr)
    );
    let reserved: Value = serde_json::from_slice(&reserved.stdout).unwrap();
    assert_eq!(reserved["balance"]["spendable_zat"], 0);
    assert_eq!(reserved["balance"]["reserved_zat"], 29);
    let listed = f
        .command()
        .args([
            "wallet",
            "--wallet-dir",
            "wallets",
            "list",
            "--manifest",
            "manifest.json",
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "participant",
        ])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["wallets"].as_array().unwrap().len(), 1);
    let calls = f.calls();
    fs::set_permissions(
        f.root
            .path()
            .join("wallets")
            .join(f.endpoints.network_id.to_string())
            .join("alice/key.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let rejected = command(&["balance", "--wallet", "alice"]).output().unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(f.calls(), calls);
}

#[test]
fn wallet_manifest_and_local_file_refusals_precede_aws() {
    for case in [
        "fingerprint",
        "schedule",
        "genesis",
        "output-exists",
        "public-parent",
        "public-key",
        "no-backend",
        "machine-format",
    ] {
        let mut f = Fixture::new();
        let mut command = f.wallet_history("wallet-advance", case == "public-key");
        match case {
            "fingerprint" | "schedule" | "genesis" => {
                let path = f.root.path().join("manifest.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                if case == "fingerprint" {
                    value["networkMagic"] = json!("aabbccdd");
                }
                if case == "schedule" {
                    value["upgrades"]["NU7"] = json!(2);
                }
                if case == "genesis" {
                    value["genesis"]["hash"] = json!("ef".repeat(32));
                }
                fs::write(path, value.to_string()).unwrap();
            }
            "output-exists" => fs::write(f.root.path().join("history.json"), "keep").unwrap(),
            "public-parent" => {
                fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o755)).unwrap()
            }
            "public-key" => fs::set_permissions(
                f.root.path().join("key.json"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            "no-backend" => {
                command = f.command();
                command.args(["wallet", "key-create", "new-key"]);
            }
            "machine-format" => {
                command = f.command();
                command.args([
                    "--format",
                    "json",
                    "wallet",
                    "history-export",
                    "--manifest",
                    "manifest.json",
                    "--endpoints",
                    "endpoints.json",
                    "--aws-profile",
                    "participant",
                    "--output",
                    "history.json",
                ]);
            }
            _ => unreachable!(),
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "accepted {case}");
        assert!(f.calls().is_empty(), "AWS called for {case}");
        if case == "output-exists" {
            assert_eq!(
                fs::read(f.root.path().join("history.json")).unwrap(),
                b"keep"
            );
        }
    }
}

// These commands intentionally use no real backend source, credentials or proofs.
#[test]
fn everyday_wallet_commands_use_only_the_explicit_network_saved_manifest_and_backend() {
    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    use zdn::{
        foundation::{Deployment, DeploymentFile},
        state::StateStore,
    };

    let mut f = Fixture::new();
    let _ = f.wallet_history("wallet-classified-payment-ok", true);
    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = state.path().to_str().unwrap();
    payment_json(
        &f.command()
            .args([
                "init",
                "--release",
                "fixture",
                "--name",
                "demo",
                "--nodes",
                "1",
            ])
            .output()
            .unwrap(),
    );
    let binding = payment_json(
        &f.command()
            .args([
                "identity",
                "bind",
                "--state-dir",
                state_path,
                "--team-id",
                "private-team",
                "--account-id",
                "123456789012",
                "--region",
                "us-east-1",
                "--manifest",
                "manifest.json",
            ])
            .output()
            .unwrap(),
    );
    let id: Uuid = binding["network_id"].as_str().unwrap().parse().unwrap();
    f.endpoints.network_id = id;
    fs::write(
        f.root.path().join("endpoints.json"),
        serde_json::to_vec(&f.endpoints).unwrap(),
    )
    .unwrap();
    let mut team: zdn::aws::TeamDefinition = serde_json::from_value(json!({
        "apiVersion":"zdn-team/v1alpha1","teamId":"private-team","revision":1,"bootstrapId":f.endpoints.bootstrap_id,
        "aws":{"accountId":"123456789012","region":"us-east-1"},
        "state":{"backend":"s3://zdn-private-team/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
    })).unwrap();
    team.deployment = Some(zdn::access::DeploymentAccess::managed(&team));
    team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
    let role = team
        .deployment
        .as_ref()
        .unwrap()
        .role_arn
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    fs::write(
        state.path().join("profiles/devnet.json"),
        json!({"team":team,"awsProfile":"participant"}).to_string(),
    )
    .unwrap();
    // Data-only deployment receipt, following tests/endpoints.rs. No node image
    // is built or run; the existing loopback RPC fixture supplies observations.
    let artifacts: std::collections::BTreeMap<_, _> = [
        "manifest.json",
        "chain.tar",
        "image.json",
        "image-manifest.json",
        "image-config.json",
        "zdn",
    ]
    .into_iter()
    .map(|name| (name, json!({"sha256":"a".repeat(64),"bytes":1})))
    .collect();
    let manifest: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("manifest.json")).unwrap()).unwrap();
    let deployment: Deployment = serde_json::from_value(json!({
        "schema_version":1,"team":team,"owner_id":Uuid::new_v4(),"stack_initialized":true,
        "last_operation":Uuid::new_v4(),"destroyed":false,"cleanup":null,
        "cluster":{"apiVersion":"zdn-private-nodes/v1alpha1","configSha256":"a".repeat(64),"manifest":manifest,"clientAccess":true,
            "image":{"apiVersion":zdn::image::API_VERSION,"image":format!("123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/node@sha256:{}","b".repeat(64)),
                "configDigest":format!("sha256:{}","c".repeat(64)),"platform":"linux/amd64",
                "provenance":{"kind":"release","revision":"d".repeat(40),"version":"v0.0.1"},
                "capabilities":zdn::image::ImageCapabilities::default(),"binaryPath":zdn::image::NODE_BINARY,"environmentLauncher":zdn::image::ENV_ENTRYPOINT},
            "nodeCount":1,"rewardAddress":"t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB","artifacts":artifacts},
        "spec":{"scope":f.endpoints.scope,"network_id":id,"aws_profile":"participant","ami_id":"ami-0123456789abcdef0","availability_zone":"us-east-1a","size":"medium","retain_chain_disk":true},
        "outputs":{"schema_version":1,"scope":f.endpoints.scope,"network_id":id,"availability_zone":"us-east-1a",
            "vpc_id":"vpc-00000000000000001","private_subnet_id":"subnet-00000000000000001","instance_id":"i-00000000000000001","private_ip":"10.90.1.10",
            "chain_volume_id":"vol-00000000000000001","retain_chain_disk":true,"security_group_id":"sg-00000000000000001","nat_gateway_id":"nat-00000000000000001","eip_allocation_id":"eipalloc-00000000000000001",
            "nodes":{"node-1":{"node_id":"node-1","instance_id":"i-00000000000000001","private_ip":"10.90.1.10","volume_id":"vol-00000000000000001"}}}
    })).unwrap();
    let store = StateStore::open(state.path()).unwrap();
    let file = DeploymentFile::open(store.root(), id).unwrap();
    file.save(&deployment).unwrap();
    EndpointFile::from_deployment(&deployment)
        .unwrap()
        .save_new(&file.directory().join("client-endpoints.json"))
        .unwrap();
    drop(file);
    let hash = hex::encode(Sha256::digest(
        fs::read(f.root.path().join("wallet-backend")).unwrap(),
    ));
    payment_json(
        &f.command()
            .args([
                "wallet",
                "--wallet-dir",
                "wallets",
                "backend",
                "set",
                "--backend",
                "./wallet-backend",
                "--backend-sha256",
                &hash,
            ])
            .output()
            .unwrap(),
    );
    // Remove the original reviewed file: saved authority, not a guessed filename,
    // must supply every following command's manifest.
    fs::remove_file(f.root.path().join("manifest.json")).unwrap();
    let invoke = |args: &[&str]| {
        // The backend fixture returns identical public keys for every name.
        // Give send its own store so fund's alias reservations stay intact.
        let wallets = if args[0] == "send" {
            "send-wallets"
        } else {
            "wallets"
        };
        f.command()
            .args(args)
            .args(["--state-dir", state_path, "--wallet-dir", wallets])
            .env("ZDN_CONNECT_MODE", "wallet-classified-payment-ok")
            .env("ZDN_CONNECT_ROLE", &role)
            .env("ZDN_CONNECT_WALLETS", wallets)
            .output()
            .unwrap()
    };
    for name in ["alice", "bob", "funding"] {
        let receipt = payment_json(&invoke(&["wallet", "create", "demo", "--name", name]));
        assert_eq!(receipt["network_id"], id.to_string());
    }
    assert_eq!(
        payment_json(&invoke(&["wallet", "show", "demo", "--wallet", "alice"]))["network_id"],
        id.to_string()
    );
    assert!(f.calls().is_empty());
    payment_json(
        &f.command()
            .args([
                "wallet",
                "--wallet-dir",
                "send-wallets",
                "backend",
                "set",
                "--backend",
                "./wallet-backend",
                "--backend-sha256",
                &hash,
            ])
            .output()
            .unwrap(),
    );
    for name in ["alice", "bob"] {
        payment_json(
            &f.command()
                .args([
                    "wallet",
                    "--wallet-dir",
                    "send-wallets",
                    "create",
                    "demo",
                    "--name",
                    name,
                    "--state-dir",
                    state_path,
                ])
                .output()
                .unwrap(),
        );
    }
    for args in [
        vec!["wallet", "balance", "demo", "--wallet", "alice"],
        vec!["wallet", "rewards", "demo", "--wallet", "funding"],
        vec!["wallet", "sync", "demo", "--wallet", "bob"],
        vec![
            "fund",
            "demo",
            "--wallet",
            "alice",
            "--amount",
            "1",
            "--wait-secs",
            "1",
        ],
        vec![
            "send",
            "demo",
            "--from",
            "bob",
            "--to",
            "alice",
            "--amount",
            "0.1",
            "--wait-secs",
            "1",
        ],
    ] {
        if args[0] == "send" {
            // Both synthetic transactions also share a txid; reset only the
            // fixture's network acceptance marker, never payment evidence.
            fs::remove_file(f.root.path().join("payment-accepted")).unwrap();
        }
        let output = invoke(&args);
        assert!(
            output.status.success(),
            "{args:?}: {} {}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let value = payment_json(&output);
        if args.get(1) == Some(&"sync") {
            assert_eq!(value["outcome"], "current_at_observation");
            assert_eq!(value["payment_enabled"], false);
        } else {
            assert_eq!(value["network_id"], id.to_string());
        }
        if ["fund", "send"].contains(&args[0]) {
            assert_eq!(
                value["amount_zat"],
                if args[0] == "fund" {
                    100_000_000
                } else {
                    10_000_000
                }
            );
            assert_eq!(value["outcome"]["kind"], "confirmed");
            assert_eq!(value["reservations_retained"], true);
        }
    }
    payment_json(&invoke(&["tx", "demo", &"ab".repeat(32)]));
    let before = f.calls();
    let mut changed = deployment.clone();
    changed.cluster.as_mut().unwrap().manifest.network_magic = "01020304".into();
    let file = DeploymentFile::open(store.root(), id).unwrap();
    file.save(&changed).unwrap();
    drop(file);
    assert!(!invoke(&["wallet", "show", "demo", "--wallet", "alice"])
        .status
        .success());
    assert_eq!(f.calls(), before);
}

fn payment_fixture() -> Fixture {
    let mut f = Fixture::new();
    let _ = f.wallet_history("wallet-classified-payment-ok", true);
    for name in ["alice", "alias"] {
        let output = payment_command(&f, "ok", &["wallet", "create", "--name", name])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    f
}

fn payment_command(f: &Fixture, mode: &str, args: &[&str]) -> Command {
    use sha2::{Digest, Sha256};
    let mut command = f.command();
    if args[0] == "wallet" {
        command.args([
            "wallet",
            "--wallet-dir",
            "wallets",
            "--backend",
            "./wallet-backend",
            "--backend-sha256",
            &hex::encode(Sha256::digest(
                fs::read(f.root.path().join("wallet-backend")).unwrap(),
            )),
        ]);
        command.args(&args[1..]).args([
            "--manifest",
            "manifest.json",
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "participant",
            "--startup-timeout-secs",
            "10",
        ]);
        return command;
    }
    command
        .args(args)
        .args([
            "--wallet-dir",
            "wallets",
            "--manifest",
            "manifest.json",
            "--endpoints",
            "endpoints.json",
            "--aws-profile",
            "participant",
            "--startup-timeout-secs",
            "10",
        ])
        .env(
            "ZDN_CONNECT_MODE",
            format!("wallet-classified-payment-{mode}"),
        );
    if args[0] != "tx" {
        command.args([
            "--backend",
            "./wallet-backend",
            "--backend-sha256",
            &hex::encode(Sha256::digest(
                fs::read(f.root.path().join("wallet-backend")).unwrap(),
            )),
        ]);
    }
    command
}

fn payment_send(
    f: &Fixture,
    mode: &str,
    sender: &str,
    operation: Option<&str>,
    depth: &str,
) -> std::process::Output {
    let mut command = payment_command(
        f,
        mode,
        &[
            "send",
            "--from",
            sender,
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
            "--confirmations",
            depth,
        ],
    );
    if let Some(id) = operation {
        command.args(["--operation-id", id]);
    }
    command.output().unwrap()
}

fn payment_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn payment_cancellation_preview_apply_releases_alias_and_inputs_without_external_calls() {
    let f = payment_fixture();
    let interrupted = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_CONNECT_MODE", "wallet-classified-changed")
    .output()
    .unwrap();
    let first = payment_json(&interrupted);
    assert_eq!(first["outcome"]["kind"], "reserved");
    let id = first["operation_id"].as_str().unwrap();
    let scope = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string());
    let path = scope.join("payments").join(format!("{id}.json"));
    let original = fs::read(&path).unwrap();
    let cancel = |token: Option<&str>| {
        let mut command = f.command();
        command.args([
            "wallet",
            "--wallet-dir",
            "wallets",
            "cancel-payment",
            "--aws-profile",
            "participant",
            "--manifest",
            "manifest.json",
            "--endpoints",
            "endpoints.json",
            "--operation-id",
            id,
        ]);
        if let Some(token) = token {
            command.args(["--apply", token]);
        }
        command.output().unwrap()
    };
    let calls = fs::read(f.root.path().join("backend-calls")).unwrap();
    let external_calls = f.calls();
    let preview = cancel(None);
    assert!(preview.status.success());
    let proposal = payment_json(&preview);
    assert_eq!(proposal["eligible"], true);
    assert_eq!(proposal["live_evidence"], "unchecked (local-only)");
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(!cancel(Some(&"00".repeat(32))).status.success());
    let token = proposal["proposal_sha256"].as_str().unwrap();
    let before: Value = serde_json::from_slice(&original).unwrap();
    for outcome in [
        json!({"kind":"signing"}),
        json!({"kind":"prepared"}),
        json!({"kind":"not_dispatched"}),
    ] {
        let mut changed = before.clone();
        changed["outcome"] = outcome;
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(payment_json(&cancel(None))["eligible"], false);
        assert!(!cancel(Some(token)).status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            changed
        );
    }
    fs::write(&path, &original).unwrap();
    assert!(cancel(Some(token)).status.success());
    assert!(!cancel(Some(token)).status.success());
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        calls
    );
    assert_eq!(f.calls(), external_calls);
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for field in ["request", "plan", "inputs", "signed", "attempts"] {
        assert_eq!(after[field], before[field]);
    }
    assert_eq!(after["outcome"]["proposal_sha256"], token);
    let resumed = payment_send(&f, "ok", "alice", Some(id), "1");
    assert!(!resumed.status.success());
    assert!(
        String::from_utf8_lossy(&resumed.stderr).contains("cancelled payment cannot be resumed")
    );
    let replacement = payment_send(&f, "ok", "alias", None, "1");
    assert!(
        replacement.status.success(),
        "{}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let records: Vec<Value> = fs::read_dir(scope.join("payments"))
        .unwrap()
        .map(|entry| serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| record["inputs"] == before["inputs"]));
}

#[test]
fn payment_reserved_before_signing_resumes_without_an_envelope() {
    let f = payment_fixture();
    let interrupted = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_CONNECT_MODE", "wallet-classified-changed")
    .output()
    .unwrap();
    assert!(!interrupted.status.success());
    assert!(
        String::from_utf8_lossy(&interrupted.stderr).contains("mempool transaction set changed")
    );
    let first = payment_json(&interrupted);
    assert_eq!(first["outcome"]["kind"], "reserved");
    let id = first["operation_id"].as_str().unwrap();
    let scope = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string());
    let path = scope.join("payments").join(format!("{id}.json"));
    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let envelope = scope.join("payment-data").join(id).join("transaction.json");
    assert!(!envelope.exists());
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert!(!calls.lines().any(|s| s == "construct-payment"));
    let resumed = payment_send(&f, "ok", "alice", Some(id), "1");
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(payment_json(&resumed)["txid"], "ab".repeat(32));
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["plan"], before["plan"]);
    assert_eq!(after["inputs"], before["inputs"]);
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert_eq!(calls.lines().filter(|s| *s == "prepare-payment").count(), 1);
    assert_eq!(
        calls.lines().filter(|s| *s == "construct-payment").count(),
        1
    );
}

#[test]
fn payment_interrupted_signing_quarantines_missing_envelope_and_recovers_original() {
    let f = payment_fixture();
    let interrupted = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .env("ZDN_WALLET_BACKEND", "crash-after-envelope")
    .output()
    .unwrap();
    assert!(!interrupted.status.success());
    let scope = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string());
    let path = fs::read_dir(scope.join("payments"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(before["outcome"]["kind"], "signing");
    assert_eq!(before["signed"], Value::Null);
    assert_eq!(before["attempts"], 0);
    let id = before["operation_id"].as_str().unwrap();
    let envelope = scope.join("payment-data").join(id).join("transaction.json");
    let original = fs::read(&envelope).unwrap();
    for (field, value) in [
        ("plan", Value::Null),
        (
            "signed",
            serde_json::from_slice::<Value>(&original).unwrap(),
        ),
        ("attempts", json!(1)),
        ("outcome", json!({"kind":"signing", "extra":true})),
    ] {
        let mut invalid = before.clone();
        invalid[field] = value;
        let bytes = serde_json::to_vec(&invalid).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(!payment_send(&f, "ok", "alice", Some(id), "1")
            .status
            .success());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    fs::write(&path, serde_json::to_vec(&before).unwrap()).unwrap();
    fs::remove_file(&envelope).unwrap();
    for legacy in [false, true] {
        if legacy {
            let mut record = before.clone();
            record["outcome"]["kind"] = json!("prepared");
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        let preview = f
            .command()
            .args([
                "wallet",
                "--wallet-dir",
                "wallets",
                "cancel-payment",
                "--endpoints",
                "endpoints.json",
                "--manifest",
                "manifest.json",
                "--aws-profile",
                "participant",
                "--operation-id",
                id,
            ])
            .output()
            .unwrap();
        assert!(preview.status.success());
        assert_eq!(payment_json(&preview)["eligible"], false);
        for sender in ["alice", "alias"] {
            let refused = payment_send(&f, "ok", sender, None, "1");
            assert!(!refused.status.success());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("unresolved payment"));
        }
        let refused = payment_send(&f, "ok", "alice", Some(id), "1");
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("envelope is missing"));
        let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(after, before);
    }
    fs::write(&envelope, &original).unwrap();
    fs::set_permissions(&envelope, fs::Permissions::from_mode(0o600)).unwrap();
    // An old record with the original artifact remains recoverable. The new
    // signing boundary must precede the backend's revalidation of that artifact.
    let mut legacy = before.clone();
    legacy["outcome"]["kind"] = json!("prepared");
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let resumed = payment_send(&f, "ok", "alice", Some(id), "1");
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(payment_json(&resumed)["txid"], "ab".repeat(32));
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["inputs"], before["inputs"]);
    assert_eq!(
        after["signed"],
        serde_json::from_slice::<Value>(&original).unwrap()
    );
    let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
    assert_eq!(
        calls.lines().filter(|s| *s == "construct-payment").count(),
        1
    );
}

#[test]
fn payment_redispatch_rejection_keeps_sender_blocked() {
    for (retried, sender) in [
        (false, "alice"),
        (false, "alias"),
        (true, "alice"),
        (true, "alias"),
    ] {
        let f = payment_fixture();
        let first = payment_send(
            &f,
            if retried { "lost" } else { "rejected" },
            "alice",
            None,
            "1",
        );
        assert!(!first.status.success());
        let id = payment_json(&first)["operation_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let rejected = if retried {
            assert_eq!(payment_json(&first)["outcome"]["kind"], "outcome_unknown");
            payment_send(&f, "rejected", "alice", Some(&id), "1")
        } else {
            first
        };
        assert!(!rejected.status.success());
        let result = payment_json(&rejected);
        assert_eq!(result["outcome"]["kind"], "node_rejected");
        assert_eq!(result["outcome"]["code"], -26);
        assert_eq!(result["reservations_retained"], true);
        let before = fs::read_to_string(f.root.path().join("dispatches")).unwrap();
        assert_eq!(before.lines().count(), if retried { 2 } else { 1 });
        // A first-attempt rejection does not block the sender, although its
        // reserved inputs remain unavailable. Rejection after a lost reply
        // cannot rule out the original payment, even through a wallet alias.
        let fresh = payment_send(&f, "ok", sender, None, "1");
        assert!(!fresh.status.success());
        assert_eq!(
            String::from_utf8_lossy(&fresh.stderr).contains("unresolved payment"),
            retried,
            "{}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        assert_eq!(
            fs::read_to_string(f.root.path().join("dispatches")).unwrap(),
            before
        );
        f.assert_rpc_closed();
    }
}

#[test]
fn payment_lost_reply_resume_and_lookup_failures_preserve_exact_transaction() {
    for (mode, expected_attempts) in [("lost", 2), ("accepted-lost", 1)] {
        let f = payment_fixture();
        let lost = payment_send(&f, mode, "alice", None, "1");
        assert!(!lost.status.success());
        let first = payment_json(&lost);
        assert_eq!(first["outcome"]["kind"], "outcome_unknown");
        let id = first["operation_id"].as_str().unwrap();
        let dispatches = || fs::read_to_string(f.root.path().join("dispatches")).unwrap();
        let before = dispatches();
        let dispatched: Value = serde_json::from_str(before.trim()).unwrap();
        assert_eq!(dispatched["record"]["outcome"]["kind"], "outcome_unknown");
        assert_eq!(dispatched["record"]["signed"]["txid"], "ab".repeat(32));
        for mode in ["transport", "error"] {
            let failed = payment_send(&f, mode, "alice", Some(id), "1");
            assert!(!failed.status.success());
            assert_eq!(payment_json(&failed)["outcome"], first["outcome"]);
            assert_eq!(dispatches(), before, "failed lookup must not rebroadcast");
        }
        // A fresh operation must refuse before selection, even through a second
        // receipt with the same public keys: selecting different inputs could pay twice.
        for sender in ["alice", "alias"] {
            let refused = payment_send(&f, "ok", sender, None, "1");
            assert!(!refused.status.success());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("unresolved payment"));
            assert_eq!(dispatches(), before);
        }
        let requests = fs::read_to_string(f.root.path().join("requests")).unwrap();
        assert_eq!(requests.lines().count(), 1);
        // Older durable records did not include sender_public. They must still
        // recover their original bytes, and fail closed on fresh alias payments.
        let record_path = f
            .root
            .path()
            .join("wallets")
            .join(f.endpoints.network_id.to_string())
            .join("payments")
            .join(format!("{id}.json"));
        let mut legacy: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        legacy["request"]
            .as_object_mut()
            .unwrap()
            .remove("sender_public");
        fs::write(&record_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(!payment_send(&f, "ok", "alias", None, "1").status.success());
        let resumed = payment_send(&f, "ok", "alice", Some(id), "1");
        assert!(
            resumed.status.success(),
            "{}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(payment_json(&resumed)["txid"], first["txid"]);
        let attempts: Vec<Value> = dispatches()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(attempts.len(), expected_attempts);
        assert!(attempts
            .iter()
            .all(|attempt| attempt["raw"] == attempts[0]["raw"]
                && attempt["record"]["signed"] == attempts[0]["record"]["signed"]));
        let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
        assert_eq!(
            calls.lines().filter(|s| *s == "construct-payment").count(),
            1
        );
        let tx = payment_command(&f, "reorg", &["tx", &"ab".repeat(32)])
            .output()
            .unwrap();
        assert!(
            tx.status.success(),
            "{}",
            String::from_utf8_lossy(&tx.stderr)
        );
        assert_eq!(payment_json(&tx)["outcome"]["kind"], "reorged");
        assert_eq!(payment_json(&tx)["reservations_retained"], true);
        assert!(!payment_send(&f, "ok", "alias", None, "1").status.success());
        assert_eq!(dispatches().lines().count(), expected_attempts);
        for mode in ["transport", "error"] {
            let failed = payment_send(&f, mode, "alice", Some(id), "1");
            assert!(!failed.status.success());
            assert_eq!(payment_json(&failed)["outcome"]["kind"], "reorged");
            assert_eq!(dispatches().lines().count(), expected_attempts);
        }
        // Only explicit absence permits post-reorg redispatch, using the same envelope.
        fs::remove_file(f.root.path().join("payment-accepted")).unwrap();
        let reconfirmed = payment_send(&f, "ok", "alice", Some(id), "1");
        assert!(
            reconfirmed.status.success(),
            "{}",
            String::from_utf8_lossy(&reconfirmed.stderr)
        );
        assert_eq!(payment_json(&reconfirmed)["outcome"]["kind"], "confirmed");
        assert_eq!(payment_json(&reconfirmed)["txid"], first["txid"]);
        let attempts: Vec<Value> = dispatches()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(attempts.len(), expected_attempts + 1);
        assert!(attempts
            .iter()
            .all(|attempt| attempt["raw"] == attempts[0]["raw"]
                && attempt["record"]["signed"] == attempts[0]["record"]["signed"]));
        let calls = fs::read_to_string(f.root.path().join("backend-calls")).unwrap();
        assert_eq!(
            calls.lines().filter(|s| *s == "construct-payment").count(),
            1
        );
        f.assert_rpc_closed();
    }
}

#[test]
fn payment_recovery_checks_current_canonical_inclusion_before_redispatch() {
    for mode in ["mempool", "moved", "stale"] {
        let f = payment_fixture();
        let sent = payment_send(&f, "ok", "alice", None, "1");
        assert!(sent.status.success());
        let first = payment_json(&sent);
        let id = first["operation_id"].as_str().unwrap();
        let record_path = f
            .root
            .path()
            .join("wallets")
            .join(f.endpoints.network_id.to_string())
            .join("payments")
            .join(format!("{id}.json"));
        let before = fs::read(&record_path).unwrap();
        let dispatches = fs::read(f.root.path().join("dispatches")).unwrap();
        let observed = payment_command(&f, mode, &["tx", &"ab".repeat(32)])
            .output()
            .unwrap();
        if mode == "stale" {
            assert!(!observed.status.success());
            assert!(observed.stdout.is_empty());
            assert!(String::from_utf8_lossy(&observed.stderr).contains("no longer canonical"));
            assert_eq!(fs::read(&record_path).unwrap(), before);
        } else {
            assert!(
                observed.status.success(),
                "{}",
                String::from_utf8_lossy(&observed.stderr)
            );
            let value = payment_json(&observed);
            assert_eq!(value["reservations_retained"], true);
            if mode == "mempool" {
                assert_eq!(value["outcome"]["kind"], "reorged");
                assert_eq!(value["confirmations"], 0);
                let pending = payment_send(&f, mode, "alice", Some(id), "1");
                assert!(!pending.status.success());
                assert_eq!(payment_json(&pending)["outcome"]["kind"], "acknowledged");
                assert_eq!(payment_json(&pending)["confirmations"], 0);
            } else {
                assert_eq!(value["outcome"]["kind"], "confirmed");
                assert_eq!(value["outcome"]["height"], 2);
                assert_eq!(
                    value["outcome"]["hash"],
                    hex::encode((160u8..192).collect::<Vec<_>>())
                );
                assert_eq!(value["confirmations"], 3);
            }
        }
        let resumed = payment_send(
            &f,
            if mode == "moved" { mode } else { "ok" },
            "alice",
            Some(id),
            "1",
        );
        assert!(
            resumed.status.success(),
            "{}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(payment_json(&resumed)["outcome"]["kind"], "confirmed");
        assert_eq!(payment_json(&resumed)["txid"], first["txid"]);
        assert_eq!(
            fs::read(f.root.path().join("dispatches")).unwrap(),
            dispatches
        );
        let saved: Value = serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
        let before: Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(saved["inputs"], before["inputs"]);
        assert_eq!(saved["signed"], before["signed"]);
        assert_eq!(saved["attempts"], 1);
        f.assert_rpc_closed();
    }
}

#[test]
fn orphaned_transaction_requires_mempool_evidence_before_acknowledgment() {
    let f = payment_fixture();
    let sent = payment_send(&f, "ok", "alice", None, "1");
    assert!(sent.status.success());
    let first = payment_json(&sent);
    let id = first["operation_id"].as_str().unwrap();
    let record_path = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string())
        .join("payments")
        .join(format!("{id}.json"));
    let original: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
    let dispatches = || fs::read_to_string(f.root.path().join("dispatches")).unwrap();
    let observed = payment_command(&f, "orphan", &["tx", &"ab".repeat(32)])
        .output()
        .unwrap();
    assert!(observed.status.success());
    assert_eq!(payment_json(&observed)["outcome"]["kind"], "reorged");
    assert_eq!(payment_json(&observed)["confirmations"], Value::Null);
    let before = dispatches();
    let saved = fs::read(&record_path).unwrap();
    for mode in ["orphan-pool-error", "orphan-pool-malformed"] {
        let failed = payment_send(&f, mode, "alice", Some(id), "1");
        assert!(!failed.status.success());
        assert_eq!(fs::read(&record_path).unwrap(), saved);
        assert_eq!(dispatches(), before);
    }
    let pending = payment_send(&f, "orphan-pending", "alice", Some(id), "1");
    assert!(!pending.status.success());
    assert_eq!(payment_json(&pending)["outcome"]["kind"], "acknowledged");
    assert_eq!(dispatches(), before);
    let resumed = payment_send(&f, "orphan", "alice", Some(id), "1");
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(payment_json(&resumed)["outcome"]["kind"], "confirmed");
    assert_eq!(payment_json(&resumed)["txid"], first["txid"]);
    let attempts: Vec<Value> = dispatches()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["raw"], attempts[1]["raw"]);
    let saved: Value = serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
    assert_eq!(saved["signed"], original["signed"]);
    assert_eq!(saved["inputs"], original["inputs"]);
    assert_eq!(saved["attempts"], 2);
    f.assert_rpc_closed();
}

#[test]
fn payment_prepares_from_a_current_snapshot_when_mining_advances() {
    let f = payment_fixture();
    let output = payment_send(&f, "advance", "alice", None, "1");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = payment_json(&output);
    let record: Value = serde_json::from_slice(
        &fs::read(
            f.root
                .path()
                .join("wallets")
                .join(f.endpoints.network_id.to_string())
                .join("payments")
                .join(format!("{}.json", result["operation_id"].as_str().unwrap())),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        record["plan"]["tip_hash"],
        hex::encode((160u8..192).collect::<Vec<_>>())
    );
    assert_eq!(result["outcome"]["kind"], "confirmed");
    f.assert_rpc_closed();

    let f = payment_fixture();
    let reorged = payment_send(&f, "advance-reorg", "alice", None, "1");
    assert!(!reorged.status.success());
    assert_eq!(payment_json(&reorged)["txid"], Value::Null);
    assert!(!f.root.path().join("dispatches").exists());
    f.assert_rpc_closed();
}

#[test]
fn payment_one_confirmation_does_not_satisfy_requested_two() {
    let f = payment_fixture();
    let output = payment_send(&f, "ok", "alice", None, "2");
    let value = payment_json(&output);
    assert_eq!(value["confirmations"], 1);
    assert_eq!(value["required_confirmations"], 2);
    assert_eq!(value["outcome"]["kind"], "confirmed");
    assert!(
        !output.status.success(),
        "one confirmation must not satisfy two"
    );
    f.assert_rpc_closed();
}

#[test]
fn rewards_report_observed_maturity_and_fund_uses_selected_named_destination() {
    let f = payment_fixture();
    let rewards = payment_command(&f, "ok", &["wallet", "rewards", "--wallet", "alice"])
        .env("ZDN_CONNECT_MODE", "wallet-classified-payment-ok")
        .output()
        .unwrap();
    assert!(
        rewards.status.success(),
        "{}",
        String::from_utf8_lossy(&rewards.stderr)
    );
    let value = payment_json(&rewards);
    assert_eq!(value["local_reservations_checked"], true);
    assert_eq!(
        value["rewards"],
        json!([{"txid":"66".repeat(32),"output_index":2,"height":1,
        "value_zat":123,"mature":false,"mempool_spent":false,"locally_reserved":false}])
    );
    assert_eq!(
        rewards.stdout,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()).as_bytes()
    );
    let funding = payment_command(
        &f,
        "ok",
        &[
            "fund",
            "--funding-wallet",
            "alice",
            "--wallet",
            "alias",
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    )
    .output()
    .unwrap();
    assert!(
        funding.status.success(),
        "{}",
        String::from_utf8_lossy(&funding.stderr)
    );
    let request: Value = serde_json::from_str(
        fs::read_to_string(f.root.path().join("requests"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(request["kind"], "fund");
    assert_eq!(request["recipient"], "22".repeat(43));
    assert_eq!(payment_json(&funding)["amount_zat"], 2);
    assert_eq!(payment_json(&funding)["outcome"]["kind"], "confirmed");
    f.assert_rpc_closed();
}

#[test]
fn journal_public_migration_at_exact_capacity_and_bounded_inventory() {
    let f = payment_fixture();
    let mut unsigned = payment_command(
        &f,
        "ok",
        &[
            "send",
            "--from",
            "alice",
            "--to",
            &"22".repeat(43),
            "--amount",
            "0.00000002",
            "--wait-secs",
            "1",
        ],
    );
    unsigned.env("ZDN_CONNECT_MODE", "wallet-classified-changed");
    let interrupted = unsigned.output().unwrap();
    let initial = payment_json(&interrupted);
    let initial_id = initial["operation_id"].as_str().unwrap();
    let scope = f
        .root
        .path()
        .join("wallets")
        .join(f.endpoints.network_id.to_string());
    let original_path = scope.join("payments").join(format!("{initial_id}.json"));
    let original = fs::read(&original_path).unwrap();
    let mut record: Value = serde_json::from_slice(&original).unwrap();
    record["plan"] = Value::Null;
    record["inputs"] = json!([]);
    record["outcome"] = json!({"kind":"prepared"});
    for n in 1..1024 {
        let id = uuid::Uuid::from_u128(n);
        record["operation_id"] = json!(id);
        zdn::foundation::write_private(
            &scope.join("payments").join(format!("{id}.json")),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(fs::read_dir(scope.join("payments")).unwrap().count(), 1024);
    let local = |command: &str, extra: &[&str]| {
        f.command()
            .args([
                "wallet",
                "--wallet-dir",
                "wallets",
                command,
                "--endpoints",
                "endpoints.json",
                "--manifest",
                "manifest.json",
                "--aws-profile",
                "participant",
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    let external_calls = f.calls();
    let backend_calls = fs::read(f.root.path().join("backend-calls")).unwrap();
    let preview = local("journal-migrate", &[]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let proposal = payment_json(&preview);
    assert_eq!(proposal["operations"], 1024);
    let token = proposal["proposal_sha256"].as_str().unwrap();
    assert!(!local("journal-migrate", &["--apply", &"00".repeat(32)])
        .status
        .success());
    // A typed legacy change makes the exact proposal stale.
    let path = scope
        .join("payments")
        .join(format!("{}.json", uuid::Uuid::from_u128(1)));
    let bytes = fs::read(&path).unwrap();
    record["operation_id"] = json!(uuid::Uuid::from_u128(1));
    record["request"] = json!({"changed":true});
    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(!local("journal-migrate", &["--apply", token])
        .status
        .success());
    fs::write(&path, bytes).unwrap();
    let applied = local("journal-migrate", &["--apply", token]);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(fs::read(&original_path).unwrap(), original);
    assert_eq!(fs::read_dir(scope.join("payments")).unwrap().count(), 1025); // 1024 originals + format barrier, not an operation
    assert!(local("list", &[]).status.success());
    let inventory = payment_json(&local("journal", &["--limit", "3"]));
    assert_eq!(inventory["total_operations"], 1024);
    assert_eq!(inventory["operations"].as_array().unwrap().len(), 3);
    let cursor = inventory["next_after"].as_str().unwrap();
    let next = payment_json(&local("journal", &["--limit", "3", "--after", cursor]));
    assert_ne!(inventory["operations"][0], next["operations"][0]);
    assert!(!local("journal", &["--limit", "101"]).status.success());
    let saved = payment_json(&local("journal", &["--operation-id", initial_id]));
    assert_eq!(saved, serde_json::from_slice::<Value>(&original).unwrap());
    assert_eq!(f.calls(), external_calls);
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend_calls
    );
    assert!(!unsigned.output().unwrap().status.success());
    assert_eq!(
        payment_json(&local("journal", &[]))["total_operations"],
        1024
    );
    let cancel = payment_json(&local("cancel-payment", &["--operation-id", initial_id]));
    assert!(local(
        "cancel-payment",
        &[
            "--operation-id",
            initial_id,
            "--apply",
            cancel["proposal_sha256"].as_str().unwrap()
        ]
    )
    .status
    .success());
    assert_eq!(
        payment_json(&local("journal", &["--operation-id", initial_id]))["outcome"]["kind"],
        "cancelled"
    );
    // The known moving-mempool fixture stops after public reservation, before
    // signing. Journal capacity needs no synthetic proof or broadcast.
    let next_output = unsigned.output().unwrap();
    assert!(!next_output.status.success());
    let next_payment = payment_json(&next_output);
    let new_id = next_payment["operation_id"].as_str().unwrap();
    assert_eq!(
        next_payment["outcome"]["kind"],
        "reserved",
        "{}",
        String::from_utf8_lossy(&next_output.stderr)
    );
    assert!(next_payment["txid"].is_null());
    let inventory = payment_json(&local("journal", &[]));
    assert_eq!(inventory["total_operations"], 1025);
    assert_eq!(inventory["active_operations"], 1024);
    assert_eq!(inventory["cancelled_operations"], 1);
    let mut expected = (1..1024)
        .map(|n| uuid::Uuid::from_u128(n).to_string())
        .collect::<std::collections::BTreeSet<_>>();
    expected.extend([initial_id.to_owned(), new_id.to_owned()]);
    let mut seen = std::collections::BTreeSet::new();
    let mut after: Option<String> = None;
    for _ in 0..12 {
        let mut args = vec!["--limit", "100"];
        if let Some(ref cursor) = after {
            args.extend(["--after", cursor]);
        }
        let page = payment_json(&local("journal", &args));
        let rows = page["operations"].as_array().unwrap();
        assert!(rows.len() <= 100);
        for row in rows {
            assert!(seen.insert(row["operation_id"].as_str().unwrap().to_owned()));
        }
        after = page["next_after"].as_str().map(str::to_owned);
        if after.is_none() {
            break;
        }
    }
    assert_eq!(seen, expected);
    assert_eq!(
        payment_json(&local("journal", &["--operation-id", initial_id]))["outcome"]["kind"],
        "cancelled"
    );
    let resumed = payment_json(&local("journal", &["--operation-id", new_id]));
    assert_eq!(resumed["outcome"]["kind"], "reserved");
    assert_eq!(resumed["attempts"], 0);
    assert!(resumed["signed"].is_null());
    assert_eq!(resumed["inputs"], saved["inputs"]);
    let external_calls = f.calls();
    let backend_calls = fs::read(f.root.path().join("backend-calls")).unwrap();
    // Missing authority must not expose retained legacy reserved inputs again.
    fs::rename(
        scope.join("payments.catalog.sqlite"),
        scope.join("catalog.backup"),
    )
    .unwrap();
    assert!(!local("journal", &[]).status.success());
    assert!(!local("journal-migrate", &[]).status.success());
    assert_eq!(fs::read(original_path).unwrap(), original);
    assert_eq!(f.calls(), external_calls);
    assert_eq!(
        fs::read(f.root.path().join("backend-calls")).unwrap(),
        backend_calls
    );
}
