//! Public diagnostics must fail before network activity on invalid inputs.
use std::{
    fs,
    path::Path,
    process::{Command, Output},
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

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .current_dir(root)
        .arg("lightwallet")
        .args(args)
        .output()
        .unwrap()
}

fn failure(output: Output) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains("private-test-secret"));
    error
}

#[test]
fn help_distinguishes_read_only_checks_from_service_installation() {
    let dir = fixture();
    for name in ["readiness", "render-service"] {
        let output = run(dir.path(), &[name, "--help"]);
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--help"));
        if name == "readiness" {
            assert!(help.contains("--grpc-endpoint"));
            assert!(help.contains("--cookie-file"));
            assert!(help.contains("read-only"));
        } else {
            assert!(help.contains("--host-spec"));
            assert!(help.contains("--service-spec"));
            assert!(help.contains("installs and starts nothing"));
        }
    }
}

#[test]
fn grpc_endpoint_rejects_remote_destinations_urls_names_and_zero_ports() {
    let dir = fixture();
    for endpoint in [
        "10.0.0.1:9067",
        "http://127.0.0.1:9067",
        "localhost:9067",
        "127.0.0.1:0",
        "[::ffff:10.0.0.1]:9067",
        "[::1%1]:9067",
    ] {
        let error = failure(run(
            dir.path(),
            &[
                "readiness",
                "--manifest",
                "absent.json",
                "--cookie-file",
                "absent-cookie",
                "--grpc-endpoint",
                endpoint,
            ],
        ));
        assert!(
            !error.contains("absent.json") && !error.contains("absent-cookie"),
            "endpoint {endpoint:?} must be rejected before reading inputs: {error}"
        );
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn invalid_readiness_bounds_and_node_endpoints_never_emit_a_report() {
    let dir = fixture();
    for extra in [
        vec!["--rpc-endpoint", "10.0.0.1:18232"],
        vec!["--request-timeout-secs", "0"],
        vec!["--request-timeout-secs", "61"],
        vec!["--deadline-secs", "0"],
        vec!["--deadline-secs", "3601"],
        vec!["--max-lag-blocks", "4294967295"],
    ] {
        let mut args = vec![
            "readiness",
            "--manifest",
            "manifest.json",
            "--cookie-file",
            "cookie",
        ];
        args.extend(extra);
        failure(run(dir.path(), &args));
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn invalid_service_input_does_not_publish_a_supervisor() {
    let dir = fixture();
    fs::write(dir.path().join("host.json"), "{}").unwrap();
    fs::write(dir.path().join("service.json"), "{}").unwrap();
    failure(run(
        dir.path(),
        &[
            "render-service",
            "--host-spec",
            "host.json",
            "--service-spec",
            "service.json",
            "--output",
            "supervisor.py",
        ],
    ));
    assert!(!dir.path().join("supervisor.py").exists());
}
