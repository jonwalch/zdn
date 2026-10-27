//! Native foundation delivery uses only local files, fake tools and loopback.
#[cfg(target_os = "linux")]
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{path::Path, process::Command};
use uuid::Uuid;
use zdn::{
    access::{DeploymentAccess, TEAM_ROLE_API_VERSION},
    aws::{TeamAws, TeamDefinition, TeamState},
    config::Size,
    foundation::Deployment,
    foundation_runtime::{fetch, FoundationRuntime, HELPER},
    infra::FoundationSpec,
    state::Scope,
};
#[cfg(target_os = "linux")]
#[path = "support/executable.rs"]
mod executable;
#[cfg(target_os = "linux")]
#[path = "support/native_tool.rs"]
mod native_tool;

fn deployment() -> Deployment {
    let mut team = TeamDefinition {
        api_version: TEAM_ROLE_API_VERSION.into(),
        team_id: "private-team".into(),
        revision: 1,
        bootstrap_id: Uuid::parse_str("965f7c13-e186-4d52-b7e3-ef92db98a0ec").unwrap(),
        aws: TeamAws {
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        state: TeamState {
            backend: "s3://zdn-private-team/pulumi/private-team".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
        deployment: None,
    };
    team.deployment = Some(DeploymentAccess::managed(&team));
    Deployment::new(
        FoundationSpec {
            scope: Scope {
                team_id: team.team_id.clone(),
                account_id: team.aws.account_id.clone(),
                region: team.aws.region.clone(),
            },
            network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap()
}

#[test]
fn native_delivery_is_python_free_and_rejects_changed_helper() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("input");
    let mut elf = vec![0; 64];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[16] = 2;
    elf[18] = 62;
    fs::write(&source, &elf).unwrap();
    let mut d = deployment();
    d.foundation_runtime = Some(FoundationRuntime::stage(&source, root.path()).unwrap());
    let runtime = d.foundation_runtime.as_ref().unwrap();
    runtime.verify_local(root.path()).unwrap();
    let object = runtime.object(&d.team, &d.spec).unwrap();
    assert!(object
        .key
        .starts_with(&zdn::devnet::artifact_prefix(&d.team, &d.spec)));
    let program = serde_json::to_value(d.render().unwrap()).unwrap();
    let script = program["resources"]["host"]["properties"]["userData"]
        .as_str()
        .unwrap();
    assert!(!script.contains("python"));
    assert!(!script.contains("foundation.py"));
    assert!(script.starts_with(&d.spec.cloud_init().unwrap()));
    assert_eq!(
        script
            .matches("cat >/etc/systemd/system/zdn-foundation.service")
            .count(),
        1
    );
    assert!(script.contains(&object.sha256) && script.contains(&object.key));
    assert!(script.contains("__foundation-serve") && script.len() <= 16384);
    let canonical = d.render().unwrap().to_yaml().unwrap();
    let restored: Deployment = serde_json::from_value(serde_json::to_value(&d).unwrap()).unwrap();
    assert_eq!(restored.render().unwrap().to_yaml().unwrap(), canonical);
    assert_eq!(
        program["resources"]["hostArtifactsPolicy"]["properties"]["policyArn"],
        zdn::access::runtime_data_policy_arn(&d.team)
    );
    assert!(zdn::build::preparation::initial_shape(&d).is_err());
    elf[63] = 1;
    fs::write(&source, elf).unwrap();
    assert!(FoundationRuntime::stage(&source, root.path()).is_err());
    runtime.verify_local(root.path()).unwrap();
    fs::remove_file(root.path().join(HELPER)).unwrap();
    assert!(runtime.verify_local(root.path()).is_err());
    d.foundation_runtime.as_mut().unwrap().protocol = "unsupported".into();
    assert!(d.render().is_err());
}

#[test]
fn bounded_loopback_fetch_preserves_bytes_and_never_follows_redirects() {
    for (status, body, expected) in [
        ("200 OK", " {\"x\":1} \n".into(), true),
        ("200 OK", "x".repeat(16384), true),
        ("200 OK", "x".repeat(16385), false),
        ("302 Found", "".into(), false),
        ("503 Service Unavailable", "SECRET".into(), false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let bytes = body.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/elsewhere\r\nConnection: close\r\n\r\n{bytes}", bytes.len());
            let _ = stream.write_all(response.as_bytes());
        });
        let started = Instant::now();
        let result = fetch(endpoint, Duration::from_millis(200));
        assert_eq!(result.is_ok(), expected, "{result:?}");
        if expected {
            assert_eq!(result.unwrap(), body);
        } else {
            assert!(!format!("{:#}", result.unwrap_err()).contains("SECRET"));
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
    }
    assert!(fetch("10.1.1.1:18080".parse().unwrap(), Duration::from_secs(1)).is_err());
    assert!(fetch("127.0.0.1:18080".parse().unwrap(), Duration::ZERO).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn bootstrap_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let mode = payload["mode"].as_str().unwrap();
    let name = payload["name"].as_str().unwrap();
    match name {
        "uname" => native_tool::reply(&work, b"x86_64\n", b"", 0),
        "dnf" | "systemctl" => native_tool::reply(&work, b"", b"", 0),
        "aws" => {
            fs::write(root.join("aws-called"), "yes").unwrap();
            assert_eq!(&args[..2], ["s3api", "get-object"]);
            let destination = args.last().unwrap();
            fs::copy(root.join("helper"), destination).unwrap();
            if mode == "size" {
                fs::write(destination, "short").unwrap();
            }
            if mode == "digest" {
                let mut b = fs::read(destination).unwrap();
                b[0] ^= 1;
                fs::write(destination, b).unwrap();
            }
            native_tool::reply(
                &work,
                b"SECRET-AWS",
                b"SECRET-AWS",
                u8::from(mode == "download"),
            );
        }
        "helper" => {
            assert_eq!(
                args,
                [
                    "__runtime-capabilities",
                    "--require",
                    "zdn-foundation-health/v1alpha1"
                ]
            );
            native_tool::reply(
                &work,
                b"SECRET-CAPABILITY",
                b"SECRET-CAPABILITY",
                u8::from(mode == "capability"),
            );
        }
        _ => panic!("unexpected tool"),
    }
}

#[test]
#[cfg(target_os = "linux")]
fn rendered_bootstrap_verifies_before_publishing_unit() {
    for mode in ["valid", "size", "digest", "download", "capability"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        fs::create_dir(path.join("bin")).unwrap();
        for name in ["uname", "dnf", "systemctl", "aws", "helper"] {
            native_tool::install(
                &if name == "helper" {
                    path.join(name)
                } else {
                    path.join("bin").join(name)
                },
                "bootstrap_worker",
                &json!({"root":path, "mode":mode, "name":name}),
            );
        }
        fs::create_dir(path.join("units")).unwrap();
        fs::write(path.join("os-release"), "ID=amzn\nVERSION_ID=2023\n").unwrap();
        let helper = fs::read(path.join("helper")).unwrap();
        let mut d = deployment();
        d.foundation_runtime = Some(FoundationRuntime {
            protocol: zdn::foundation_host::PROTOCOL.into(),
            helper: zdn::devnet::Artifact {
                bytes: helper.len() as u64,
                sha256: hex::encode(Sha256::digest(&helper)),
            },
        });
        let program: Value = serde_json::to_value(d.render().unwrap()).unwrap();
        let script = program["resources"]["host"]["properties"]["userData"]
            .as_str()
            .unwrap();
        // Only absolute effect paths are relocated. The actual generated shell,
        // integrity checks, timeout and capability invocation execute unchanged.
        let mut mapped = script.to_owned();
        for (from, to) in [
            ("/var/log/zdn-foundation-setup.log", "setup.log"),
            ("/etc/os-release", "os-release"),
            ("/opt/zdn", "opt"),
            ("/var/lib/zdn-chain", "chain"),
            ("/var/lib/zdn", "state"),
            ("/etc/systemd/system", "units"),
        ] {
            mapped = mapped.replace(from, path.join(to).to_str().unwrap());
        }
        let output = Command::new("/bin/bash")
            .args(["-c", &mapped])
            .env("PATH", format!("{}/bin:/usr/bin:/bin", path.display()))
            .env("POSIXLY_CORRECT", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            mode == "valid",
            "{mode}: {output:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SECRET"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET"));
        assert_eq!(
            path.join("units/zdn-foundation.service").exists(),
            mode == "valid"
        );
        assert_eq!(path.join("opt/foundation-zdn").exists(), mode == "valid");
        assert!(path.join("aws-called").exists());
        assert!(!fs::read_dir(path.join("opt")).unwrap().any(|p| p
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".foundation.")));
    }
}
