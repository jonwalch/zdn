#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::{tempdir, TempDir};
use zdn::connections::{self, ConnectOptions, TunnelTarget};

#[path = "support/executable.rs"]
mod executable;

const SECRET: &str = "DO-NOT-EXPOSE-SESSION-TOKEN";

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "missing fixture marker {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn flag(args: &[String], key: &str) -> String {
    args[args.iter().position(|arg| arg == key).unwrap() + 1].clone()
}

#[test]
// The parent-exits fixture deliberately orphans a plugin to exercise the
// production supervisor's session containment and reparenting cleanup.
#[allow(clippy::zombie_processes)]
fn session_process_fixture() {
    let Some(root) = std::env::var_os("ZDN_CONNECTION_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let args: Vec<String> =
        fs::read_to_string(std::env::var_os("ZDN_CONNECTION_TEST_ARGS").unwrap())
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
    assert_eq!(flag(&args, "--profile"), "participant");
    assert_eq!(flag(&args, "--region"), "us-east-1");
    assert_eq!(std::env::var("ZDN_SELECTED_ENV").unwrap(), "selected");
    assert_eq!(std::env::var("AWS_MAX_ATTEMPTS").unwrap(), "1");
    let mode = std::env::var("ZDN_CONNECTION_TEST_MODE").unwrap();
    if args[1] == "terminate-session" {
        let id = flag(&args, "--session-id");
        fs::write(root.join(format!("terminated-{id}")), "observed").unwrap();
        if mode == "terminate-fails" {
            eprintln!("{SECRET}");
            std::process::exit(1);
        }
        println!("{{\"SessionId\":\"{id}\"}}");
        return;
    }
    assert_eq!(args[1], "start-session");
    let document = flag(&args, "--document-name");
    let id = format!("fixture-{document}");
    let parameters: Value = serde_json::from_str(&flag(&args, "--parameters")).unwrap();
    assert_eq!(parameters.as_object().unwrap().len(), 1);
    assert!(parameters.get("host").is_none());
    assert!(parameters.get("portNumber").is_none());
    let port: u16 = parameters["localPortNumber"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    if mode.starts_with("diagnostic-") {
        print!("{SECRET}\nhttps://private.invalid/session?token={SECRET}\n");
        std::io::stdout().flush().unwrap();
        let size = match mode.as_str() {
            "diagnostic-zero" => 0,
            "diagnostic-seven" => 37,
            "diagnostic-signal" => 80000,
            _ => unreachable!(),
        };
        std::io::stderr()
            .write_all(&b"private-stderr-token\n".repeat(4000)[..size])
            .unwrap();
        std::io::stderr().flush().unwrap();
        match mode.as_str() {
            "diagnostic-zero" => std::process::exit(0),
            "diagnostic-seven" => std::process::exit(7),
            "diagnostic-signal" => {
                nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL).unwrap();
                unreachable!();
            }
            _ => unreachable!(),
        }
    }
    if std::env::var_os("ZDN_CONNECTION_PLUGIN").is_none() {
        ctrlc::set_handler(|| {}).unwrap();
        fs::write(root.join(format!("started-{document}")), port.to_string()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "session_process_fixture", "--nocapture"])
            .env("ZDN_CONNECTION_PLUGIN", "1")
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        if mode == "parent-exits" {
            wait_file(&root.join(format!("listening-{document}")));
            return;
        }
        child.wait().unwrap();
        return;
    }
    ctrlc::set_handler(|| {}).unwrap();
    fs::write(
        root.join(format!("plugin-{document}")),
        std::process::id().to_string(),
    )
    .unwrap();
    if mode == "late-identity" {
        std::thread::sleep(Duration::from_millis(120));
    }
    if mode != "no-identity" {
        // Deliberately split the notice across writes, just as pipe reads can.
        print!("\nStarting session with ");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        println!("SessionId: {id}");
        std::io::stdout().flush().unwrap();
    }
    println!("{SECRET}");
    eprintln!("{SECRET}");
    if mode == "second-fails" && document.ends_with("grpc") {
        std::process::exit(1);
    }
    if mode == "line-overflow" {
        println!("{}", SECRET.repeat(200));
        std::io::stdout().flush().unwrap();
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    listener.set_nonblocking(true).unwrap();
    if mode != "no-notice" && mode != "no-identity" && mode != "late-identity" {
        let reported_port = if mode == "wrong-port" {
            port.wrapping_add(1)
        } else {
            port
        };
        let reported_id = if mode == "wrong-identity" {
            "foreign-session"
        } else {
            &id
        };
        println!("Port {reported_port} opened for sessionId {reported_id}.");
        std::io::stdout().flush().unwrap();
    }
    fs::write(root.join(format!("listening-{document}")), port.to_string()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !root.join(format!("terminated-{id}")).exists() {
        if mode == "after-ready-exit"
            && document.ends_with("grpc")
            && root.join("published").exists()
        {
            break;
        }
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let mut data = [0; 16];
            if let Ok(count) = stream.read(&mut data) {
                let _ = stream.write_all(&data[..count]);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    fs::write(root.join(format!("plugin-exited-{document}")), "exited").unwrap();
}

struct Fixture {
    root: TempDir,
    options: ConnectOptions,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempdir().unwrap();
        let script = root.path().join("aws-fixture");
        let test_binary = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\'', "'\\''");
        executable::write(&script, format!("#!/bin/sh\nargs=\"$ZDN_CONNECTION_TEST_ROOT/args-$$\"\nprintf '%s\\n' \"$@\" > \"$args\"\nexport ZDN_CONNECTION_TEST_ARGS=\"$args\"\nexec '{test_binary}' --exact session_process_fixture --nocapture\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let options = ConnectOptions {
            aws_program: script,
            helper_program: env!("CARGO_BIN_EXE_zdn").into(),
            profile: "participant".into(),
            region: "us-east-1".into(),
            env: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                (
                    "ZDN_CONNECTION_TEST_ROOT".into(),
                    root.path().to_str().unwrap().into(),
                ),
                ("ZDN_CONNECTION_TEST_MODE".into(), mode.into()),
                ("ZDN_SELECTED_ENV".into(), "selected".into()),
            ]),
            startup_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(250),
        };
        Self { root, options }
    }

    fn assert_closed(&self, targets: &[TunnelTarget]) {
        for target in targets {
            let path = self
                .root
                .path()
                .join(format!("started-{}", target.document_name));
            if path.exists() {
                let port: u16 = fs::read_to_string(path).unwrap().parse().unwrap();
                assert!(
                    TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
                    "left a local listener on {port}"
                );
            }
        }
    }

    fn assert_terminated(&self, targets: &[TunnelTarget]) {
        for target in targets {
            assert!(
                self.root
                    .path()
                    .join(format!("terminated-fixture-{}", target.document_name))
                    .exists(),
                "session was not explicitly terminated"
            );
        }
    }
}

fn targets() -> Vec<TunnelTarget> {
    [("zdn-test-rpc", 18234), ("zdn-test-grpc", 9067)]
        .into_iter()
        .map(|(document_name, remote_port)| TunnelTarget {
            instance_id: "i-0123456789abcdef0".into(),
            document_name: document_name.into(),
            remote_port,
            local_port: None,
        })
        .collect()
}

#[test]
fn both_tunnels_publish_together_forward_bytes_and_terminate_owned_sessions() {
    let fixture = Fixture::new("success");
    let cancelled = AtomicBool::new(false);
    let targets = targets();
    let mut called = false;
    connections::run(&fixture.options, &targets, &cancelled, |endpoints| {
        called = true;
        assert_eq!(endpoints.len(), 2);
        assert_ne!(endpoints[0].address.port(), endpoints[1].address.port());
        for (index, endpoint) in endpoints.iter().enumerate() {
            assert_eq!(endpoint.target_index, index);
            assert_eq!(endpoint.remote_port, targets[index].remote_port);
            assert_eq!(endpoint.address.ip(), Ipv4Addr::LOCALHOST);
            let mut stream = TcpStream::connect(endpoint.address)?;
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            stream.write_all(b"client bytes")?;
            let mut echoed = [0; 12];
            stream.read_exact(&mut echoed)?;
            assert_eq!(&echoed, b"client bytes");
        }
        cancelled.store(true, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();
    assert!(called);
    fixture.assert_closed(&targets);
    fixture.assert_terminated(&targets);
}

#[test]
fn occupied_or_duplicate_requested_ports_fail_before_starting_aws() {
    for duplicate in [false, true] {
        let fixture = Fixture::new("success");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut targets = targets();
        targets[1].local_port = Some(listener.local_addr().unwrap().port());
        if duplicate {
            targets[0].local_port = targets[1].local_port;
        }
        let result = connections::run(&fixture.options, &targets, &AtomicBool::new(false), |_| {
            panic!("must not publish")
        });
        assert!(result.is_err());
        assert_eq!(fs::read_dir(fixture.root.path()).unwrap().count(), 1);
    }
}

#[test]
fn a_listening_port_without_a_matching_plugin_notice_is_not_ready() {
    for mode in ["no-notice", "no-identity", "wrong-port", "wrong-identity"] {
        let fixture = Fixture::new(mode);
        let targets = targets();
        let error = connections::run(&fixture.options, &targets, &AtomicBool::new(false), |_| {
            panic!("must not publish")
        })
        .unwrap_err();
        assert!(!format!("{error:#}").contains(SECRET));
        let message = error.to_string();
        let diagnostic: Value =
            serde_json::from_str(message.split_once("SSM tunnel diagnostics: ").unwrap().1)
                .unwrap();
        if mode == "no-notice" || mode == "no-identity" {
            let diagnostics = diagnostic.as_array().unwrap();
            assert_eq!(diagnostics.len(), 2);
            for item in diagnostics {
                assert_eq!(item["category"], "startup-timeout");
                assert_eq!(item["listenerState"], "before-listener");
                assert!(item["exitCode"].is_null());
                assert!(item["signal"].is_null());
            }
        } else {
            assert_eq!(diagnostic["category"], "output-rejected");
            assert!(diagnostic["exitCode"].is_null());
            assert!(diagnostic["signal"].is_null());
        }
        fixture.assert_closed(&targets);
        if mode != "no-identity" {
            fixture.assert_terminated(&targets);
        }
    }
}

#[test]
fn partial_startup_failure_closes_the_other_tunnel() {
    let fixture = Fixture::new("second-fails");
    let targets = targets();
    let error = connections::run(&fixture.options, &targets, &AtomicBool::new(false), |_| {
        panic!("must not publish")
    })
    .unwrap_err();
    assert!(!format!("{error:#}").contains(SECRET));
    fixture.assert_closed(&targets);
    fixture.assert_terminated(&targets);
}

#[test]
fn tunnel_exit_diagnostics_are_bounded_and_never_retain_raw_output() {
    for (mode, code, signal, stderr_size) in [
        ("diagnostic-zero", Some(0), None, 0),
        ("diagnostic-seven", Some(7), None, 37),
        ("diagnostic-signal", None, Some(9), 80000),
    ] {
        let fixture = Fixture::new(mode);
        let selected = &targets()[..1];
        let error = connections::once(
            &fixture.options,
            selected,
            &AtomicBool::new(false),
            |_| -> eyre::Result<()> { panic!("failed tunnel must not publish readiness") },
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains(SECRET));
        assert!(!error.contains("private-stderr-token"));
        assert!(!error.contains("https://"));
        assert!(!error.contains(fixture.root.path().to_str().unwrap()));
        let diagnostic: Value =
            serde_json::from_str(error.split_once("SSM tunnel diagnostics: ").unwrap().1).unwrap();
        assert_eq!(diagnostic["category"], "process-exited");
        assert_eq!(diagnostic["listenerState"], "before-listener");
        assert_eq!(diagnostic["sessionNoticeObserved"], false);
        assert_eq!(diagnostic["exitCode"], serde_json::json!(code));
        assert_eq!(diagnostic["signal"], serde_json::json!(signal));
        assert_eq!(
            diagnostic["stderr"],
            serde_json::json!({"observedBytes": stderr_size})
        );
        assert!(diagnostic["stdout"]["observedBytes"].as_u64().unwrap() > 0);
        assert_eq!(diagnostic["stdout"].as_object().unwrap().len(), 1);
        assert!(error.len() < 1500);
        fixture.assert_closed(selected);
    }
}

#[test]
fn callback_failure_cleans_up_both_sessions() {
    for cancel_in_callback in [false, true] {
        let fixture = Fixture::new("success");
        let targets = targets();
        let cancelled = AtomicBool::new(false);
        let error = connections::run(&fixture.options, &targets, &cancelled, |_| {
            cancelled.store(cancel_in_callback, Ordering::SeqCst);
            eyre::bail!("client rejected endpoints")
        })
        .unwrap_err();
        assert!(error.to_string().contains("client rejected endpoints"));
        fixture.assert_closed(&targets);
        fixture.assert_terminated(&targets);
    }
}

#[test]
fn callback_and_cleanup_failures_preserve_primary_error_for_run_and_once() {
    #[derive(Debug)]
    struct CallbackFailure;
    impl std::fmt::Display for CallbackFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("client rejected endpoints")
        }
    }
    impl std::error::Error for CallbackFailure {}

    for once in [false, true] {
        let fixture = Fixture::new("terminate-fails");
        let targets = targets();
        let cancelled = AtomicBool::new(false);
        let callback = |_: &[connections::LocalEndpoint]| Err(CallbackFailure.into());
        let error = if once {
            connections::once::<()>(&fixture.options, &targets, &cancelled, callback)
        } else {
            connections::run(&fixture.options, &targets, &cancelled, callback)
        }
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("client rejected endpoints"), "{text}");
        assert!(
            text.contains("remote SSM termination is unconfirmed"),
            "{text}"
        );
        assert!(error.downcast_ref::<CallbackFailure>().is_some());
        assert!(error.downcast_ref::<connections::CleanupError>().is_some());
        assert!(!text.contains(SECRET));
        fixture.assert_closed(&targets);
        fixture.assert_terminated(&targets);
    }
}

#[test]
fn one_shot_work_returns_only_after_both_tunnels_are_cleaned_up() {
    for mode in ["success", "callback-fails", "cancelled", "terminate-fails"] {
        let fixture = Fixture::new(if mode == "terminate-fails" {
            mode
        } else {
            "success"
        });
        let targets = targets();
        let cancelled = AtomicBool::new(false);
        let result = connections::once(&fixture.options, &targets, &cancelled, |local| {
            assert_eq!(local.len(), 2);
            if mode == "callback-fails" {
                eyre::bail!("request failed");
            }
            if mode == "cancelled" {
                cancelled.store(true, Ordering::SeqCst);
            }
            Ok("verified result")
        });
        if mode == "success" {
            assert_eq!(result.unwrap(), "verified result");
        } else {
            let report = result.unwrap_err();
            assert_eq!(
                report.downcast_ref::<connections::CleanupError>().is_some(),
                mode == "terminate-fails"
            );
            let error = report.to_string();
            assert!(
                error.contains(match mode {
                    "callback-fails" => "request failed",
                    "cancelled" => "cancelled",
                    _ => "cleanup was incomplete",
                }),
                "{error}"
            );
            assert!(!error.contains(SECRET));
        }
        fixture.assert_closed(&targets);
        fixture.assert_terminated(&targets);
    }
}

#[test]
fn a_running_tunnel_exit_closes_its_peer_without_republishing() {
    let fixture = Fixture::new("after-ready-exit");
    let targets = targets();
    let mut publications = 0;
    let error = connections::run(&fixture.options, &targets, &AtomicBool::new(false), |_| {
        publications += 1;
        fs::write(fixture.root.path().join("published"), "ready")?;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(publications, 1);
    assert!(error.to_string().contains("exited"));
    let message = error.to_string();
    let diagnostic: Value =
        serde_json::from_str(message.split_once("SSM tunnel diagnostics: ").unwrap().1).unwrap();
    assert_eq!(diagnostic["category"], "process-exited");
    assert_eq!(diagnostic["service"], "grpc");
    assert_eq!(diagnostic["listenerState"], "listener-observed");
    assert_eq!(diagnostic["sessionNoticeObserved"], true);
    assert_eq!(diagnostic["exitCode"], 0);
    assert!(diagnostic["signal"].is_null());
    assert!(!message.contains(SECRET));
    assert!(!message.contains("fixture-zdn-test"));
    fixture.assert_closed(&targets);
    fixture.assert_terminated(&targets);
}

#[test]
fn cancellation_during_startup_terminates_a_late_observed_session() {
    let fixture = Fixture::new("late-identity");
    let targets = &targets()[..1];
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            wait_file(&fixture.root.path().join("plugin-zdn-test-rpc"));
            cancelled.store(true, Ordering::SeqCst);
        });
        connections::run(&fixture.options, targets, &cancelled, |_| {
            panic!("must not publish")
        })
        .unwrap();
    });
    fixture.assert_closed(targets);
    fixture.assert_terminated(targets);
}

#[test]
fn early_cli_exit_does_not_leave_its_separate_group_plugin_running() {
    let fixture = Fixture::new("parent-exits");
    let targets = &targets()[..1];
    let error = connections::run(&fixture.options, targets, &AtomicBool::new(false), |_| {
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("exited"));
    fixture.assert_closed(targets);
    fixture.assert_terminated(targets);
}

#[test]
fn remote_termination_failure_is_reported_after_local_cleanup() {
    let fixture = Fixture::new("terminate-fails");
    let cancelled = AtomicBool::new(false);
    let targets = &targets()[..1];
    let error = connections::run(&fixture.options, targets, &cancelled, |_| {
        cancelled.store(true, Ordering::SeqCst);
        Ok(())
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("remote SSM termination is unconfirmed"));
    assert!(!format!("{error:#}").contains(SECRET));
    fixture.assert_closed(targets);
    fixture.assert_terminated(targets);
}

#[test]
fn overlong_plugin_output_is_bounded_and_redacted() {
    let fixture = Fixture::new("line-overflow");
    let targets = &targets()[..1];
    let error = connections::run(&fixture.options, targets, &AtomicBool::new(false), |_| {
        panic!("must not publish")
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("line limit"));
    assert!(!format!("{error:#}").contains(SECRET));
    fixture.assert_closed(targets);
    fixture.assert_terminated(targets);
}

#[test]
fn invalid_targets_and_precancelled_calls_do_not_start_aws() {
    let fixture = Fixture::new("success");
    for (field, value) in [
        ("document", "AWS-StartPortForwardingSession"),
        ("instance", "i-unknown"),
        ("port", "22"),
    ] {
        let mut targets = targets();
        match field {
            "document" => targets[0].document_name = value.into(),
            "instance" => targets[0].instance_id = value.into(),
            _ => targets[0].remote_port = value.parse().unwrap(),
        }
        assert!(connections::run(
            &fixture.options,
            &targets,
            &AtomicBool::new(false),
            |_| panic!("must not publish")
        )
        .is_err());
    }
    connections::run(&fixture.options, &targets(), &AtomicBool::new(true), |_| {
        panic!("must not publish")
    })
    .unwrap();
    let error = connections::exec(&fixture.options, &targets(), &AtomicBool::new(true), |_| {
        panic!("must not start a command")
    })
    .unwrap_err();
    let error = error.downcast_ref::<connections::ExecError>().unwrap();
    assert!(error.cancelled);
    assert!(error.child_status.is_none());
    assert!(
        connections::once::<()>(&fixture.options, &targets(), &AtomicBool::new(true), |_| {
            panic!("must not run one-shot work")
        })
        .is_err()
    );
    assert_eq!(fs::read_dir(fixture.root.path()).unwrap().count(), 1);
}

#[test]
fn exec_progress_failures_and_cancellation_stop_work_and_clean_up() {
    use connections::ExecEvent;
    for (fail_at, cancel) in [
        (ExecEvent::ConnectionReady, false),
        (ExecEvent::ChildStarted, false),
        (ExecEvent::ConnectionReady, true),
    ] {
        let fixture = Fixture::new("success");
        let cancelled = AtomicBool::new(false);
        let mut observed = Vec::new();
        let error = connections::exec_with_progress(
            &fixture.options,
            &targets(),
            &cancelled,
            |_| {
                Ok(zdn::pulumi::CommandSpec {
                    label: "test-scoped-command".into(),
                    program: "/bin/sh".into(),
                    args: ["-c", "echo $$ > child.pid; exec sleep 60"]
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
                    cwd: fixture.root.path().into(),
                    diagnostics_dir: fixture.root.path().into(),
                    limits: zdn::pulumi::ProcessLimits {
                        timeout: Duration::from_secs(10),
                        shutdown_grace: Duration::from_millis(100),
                        ..Default::default()
                    },
                })
            },
            &mut |event| {
                observed.push(event);
                if event == ExecEvent::ChildStarted {
                    wait_file(&fixture.root.path().join("child.pid"));
                }
                if event == fail_at {
                    if cancel {
                        cancelled.store(true, Ordering::SeqCst);
                    } else {
                        eyre::bail!("scripted event write failure");
                    }
                }
                Ok(())
            },
        )
        .unwrap_err();
        let error = error.downcast_ref::<connections::ExecError>().unwrap();
        assert_eq!(error.cancelled, cancel);
        assert!(!error.tunnel_failed && !error.cleanup_incomplete, "{error}");
        assert_eq!(
            error.child_status.is_some(),
            fail_at == ExecEvent::ChildStarted
        );
        assert_eq!(observed.last(), Some(&fail_at));
        let marker = fixture.root.path().join("child.pid");
        if fail_at == ExecEvent::ConnectionReady {
            assert!(!marker.exists());
        } else {
            let pid: i32 = fs::read_to_string(marker).unwrap().trim().parse().unwrap();
            assert!(nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err());
        }
        fixture.assert_closed(&targets());
        fixture.assert_terminated(&targets());
    }
}

#[test]
fn exec_does_not_report_child_started_when_only_the_helper_started() {
    let fixture = Fixture::new("success");
    let mut observed = Vec::new();
    let error = connections::exec_with_progress(
        &fixture.options,
        &targets(),
        &AtomicBool::new(false),
        |_| {
            Ok(zdn::pulumi::CommandSpec {
                label: "missing-child".into(),
                program: fixture.root.path().join("missing-program"),
                args: Vec::new(),
                env: BTreeMap::new(),
                cwd: fixture.root.path().into(),
                diagnostics_dir: fixture.root.path().into(),
                limits: zdn::pulumi::ProcessLimits::default(),
            })
        },
        &mut |event| {
            observed.push(event);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(observed, [connections::ExecEvent::ConnectionReady]);
    let error = error.downcast_ref::<connections::ExecError>().unwrap();
    assert!(!error.cleanup_incomplete);
    assert!(error
        .child_status
        .as_ref()
        .is_none_or(|status| status.exit_code.is_none() && status.signal.is_none()));
    fixture.assert_closed(&targets());
    fixture.assert_terminated(&targets());
}

#[test]
fn scoped_timeout_and_cancellation_after_readiness_clean_up_both_tunnels() {
    for cancel_after_ready in [false, true] {
        let fixture = Fixture::new("success");
        let cancelled = AtomicBool::new(false);
        let error = connections::exec(&fixture.options, &targets(), &cancelled, |local| {
            assert_eq!(local.len(), 2);
            if cancel_after_ready {
                cancelled.store(true, Ordering::SeqCst);
            }
            Ok(zdn::pulumi::CommandSpec {
                label: "test-scoped-command".into(),
                program: "/bin/sh".into(),
                args: ["-c", "printf started > command-started; sleep 60"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
                cwd: fixture.root.path().into(),
                diagnostics_dir: fixture.root.path().into(),
                limits: zdn::pulumi::ProcessLimits {
                    timeout: Duration::from_millis(300),
                    shutdown_grace: Duration::from_millis(100),
                    ..Default::default()
                },
            })
        })
        .unwrap_err();
        let error = error.downcast_ref::<connections::ExecError>().unwrap();
        assert_eq!(error.cancelled, cancel_after_ready);
        assert!(!error.cleanup_incomplete, "{error}");
        assert_eq!(
            fixture.root.path().join("command-started").exists(),
            !cancel_after_ready
        );
        if !cancel_after_ready {
            assert!(error.to_string().contains("deadline"));
        }
        fixture.assert_closed(&targets());
        fixture.assert_terminated(&targets());
    }
}
