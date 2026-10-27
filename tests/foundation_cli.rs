//! CLI integration uses local config/profile fixtures and a fake AWS executable.
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};
use uuid::Uuid;
use zdn::{
    foundation::DeploymentFile,
    state::{OperationInput, PhaseStatus, StateStore},
};

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

#[cfg(unix)]
#[path = "support/machine_failure.rs"]
mod machine_failure;

#[cfg(target_os = "linux")]
#[path = "support/native_exec.rs"]
mod native_exec;

struct Fixture {
    _temp: tempfile::TempDir,
    source: PathBuf,
    state: PathBuf,
}

#[test]
fn repeated_setup_accepts_only_the_saved_team_export_before_aws() {
    for kind in ["identical", "different", "malformed", "missing-profile"] {
        let f = Fixture::new();
        let export = f._temp.path().join("team.json");
        if kind == "different" {
            let mut team: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
            team["bootstrapId"] = json!(Uuid::new_v4());
            fs::write(&export, serde_json::to_vec(&team).unwrap()).unwrap();
        } else if kind == "malformed" {
            fs::write(&export, "invalid: [").unwrap();
        } else if kind == "missing-profile" {
            fs::remove_file(f.state.join("profiles/devnet.json")).unwrap();
        }
        let before = fs::read(&export).unwrap();
        let output = f
            .command()
            .env_clear()
            .env("PATH", "")
            .args([
                "setup",
                "bootstrap",
                "--state-dir",
                f.state.to_str().unwrap(),
                "--aws-profile",
                "fixture",
                "--team-id",
                "fixture",
                "--account-id",
                "123456789012",
                "--region",
                "us-east-1",
                "--bucket",
                "zdn-fixture-state",
                "--export",
                export.to_str().unwrap(),
                "--yes",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        let expected = match kind {
            "identical" => "cannot run",
            "different" => "team export has different settings",
            "malformed" => "read versioned team definition",
            _ => "matching saved local profile",
        };
        assert!(error.contains(expected), "{kind}: {error}");
        assert_eq!(fs::read(&export).unwrap(), before);
        assert!(!f.state.join("profiles/devnet.bootstrap.json").exists());
    }
}

#[test]
fn administrator_role_plan_is_offline_and_exposes_no_credential_fields() {
    let f = Fixture::new();
    let output = f.ok(&[
        "setup",
        "role-plan",
        "--from",
        f._temp.path().join("team.json").to_str().unwrap(),
        "--aws-profile",
        "setup-admin",
        "--trust-principal",
        "arn:aws:iam::123456789012:user/developer",
    ]);
    assert_eq!(output["cloudChanges"], false);
    assert_eq!(output["proposalOnly"], true);
    assert_eq!(output["checkpointChecked"], false);
    assert_eq!(output["namingSource"], "defaults");
    assert!(output["recoveryNotice"]
        .as_str()
        .unwrap()
        .contains("different policy names"));
    assert!(output["backend"]
        .as_str()
        .unwrap()
        .contains("/zdn-admin/v1/"));
    let program: Value = serde_yaml::from_str(output["pulumiYaml"].as_str().unwrap()).unwrap();
    assert_eq!(
        program["resources"]["provider"]["properties"]["profile"],
        "setup-admin"
    );
    assert_eq!(
        output["callerPolicy"]["Statement"][0]["Action"],
        json!(["sts:AssumeRole"])
    );
    assert!(!output.to_string().contains("SecretAccessKey"));
    assert!(!f.state.join("profiles/devnet.access").exists());
}

#[test]
fn recovered_team_role_plan_uses_recorded_names_without_claiming_cloud_validation() {
    let f = Fixture::new();
    let path = f._temp.path().join("team.json");
    let mut team: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let id = Uuid::parse_str(team["bootstrapId"].as_str().unwrap()).unwrap();
    let base = format!("zdn-{}", id.simple());
    team["apiVersion"] = json!("zdn-team/v1alpha2");
    team["deployment"] = json!({"management":"zdn",
        "roleArn":format!("arn:aws:iam::123456789012:role/zdn-admin/{id}/{base}-deploy"),
        "runtimeBoundaryArn":format!("arn:aws:iam::123456789012:policy/zdn-admin/{id}/{base}-runtime")});
    fs::write(&path, serde_json::to_vec(&team).unwrap()).unwrap();
    let output = f.ok(&[
        "setup",
        "role-plan",
        "--from",
        path.to_str().unwrap(),
        "--aws-profile",
        "setup-admin",
        "--trust-principal",
        "arn:aws:iam::123456789012:user/developer",
    ]);
    assert_eq!(output["proposalOnly"], true);
    assert_eq!(output["checkpointChecked"], false);
    assert_eq!(output["cloudChanges"], false);
    assert_eq!(output["namingSource"], "teamDefinition");
    let program: Value = serde_yaml::from_str(output["pulumiYaml"].as_str().unwrap()).unwrap();
    assert_eq!(
        program["resources"]["runtimeBoundary"]["properties"]["name"],
        format!("{base}-runtime")
    );
    assert_eq!(
        program["resources"]["runtimePolicy"]["properties"]["name"],
        format!("{base}-runtime-management")
    );
    assert!(!f.state.join("profiles/devnet.access").exists());
}

#[test]
fn role_setup_invalid_principals_and_missing_consent_fail_before_aws() {
    let f = Fixture::new();
    let mut args = vec![
        "setup",
        "bootstrap",
        "--state-dir",
        f.state.to_str().unwrap(),
        "--aws-profile",
        "admin",
        "--developer-aws-profile",
        "developer",
        "--team-id",
        "fixture",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--bucket",
        "zdn-fixture-state",
        "--trust-principal",
        "arn:aws:iam::123456789012:root",
    ];
    assert!(f.fail(&args).contains("--yes"));
    args.push("--yes");
    assert!(f.fail(&args).contains("IAM ARN"));
    assert!(!f.state.join("profiles/devnet.bootstrap.json").exists());
}

#[cfg(unix)]
#[test]
fn bootstrap_source_identity_rejects_root_and_untrusted_callers_before_backend_authority() {
    use std::os::unix::fs::PermissionsExt;

    for (resource, user_id, principal, diagnostic) in [
        (
            "root",
            "123456789012",
            "user/developer",
            Some("root AWS caller is not supported"),
        ),
        (
            "user/other",
            "AIDAOTHER",
            "user/developer",
            Some("source caller does not match any selected trusted principal"),
        ),
        (
            "assumed-role/admin/session",
            "AROAEXAMPLE:session",
            "role/expected/admin",
            Some("source caller does not match any selected trusted principal"),
        ),
        (
            "assumed-role/admin/session",
            "AROAOTHER:session",
            "role/actual/admin",
            Some("source role identity mismatch"),
        ),
        ("user/admin", "AIDAEXAMPLE", "user/admin", None),
        ("user/root", "AIDAEXAMPLE", "user/root", None),
        ("user/developer", "AIDAEXAMPLE", "user/developer", None),
        (
            "assumed-role/admin/session",
            "AROAEXAMPLE:session",
            "role/actual/admin",
            None,
        ),
    ] {
        let fixture = Fixture::new();
        let bin = fixture._temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let service = if resource.starts_with("assumed-role/") {
            "sts"
        } else {
            "iam"
        };
        let identity = json!({
            "Account": "123456789012",
            "Arn": format!("arn:aws:{service}::123456789012:{resource}"),
            "UserId": user_id,
        });
        let split = resource == "user/developer";
        let aws = bin.join("aws");
        executable::write(
            &aws,
            format!(
                r#"#!/bin/sh
if [ "$#" = 1 ] && [ "$1" = --version ]; then
    printf '%s\n' 'aws-cli/2.37.4'
    exit 0
fi
profile=$2
shift 13
case "$1 $2" in
    'sts get-caller-identity')
        printf '%s\n' 'sts get-caller-identity' >> aws-calls.txt
        if [ "$profile" = admin ] && [ '{split}' = true ]; then
            printf '%s\n' '{{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/bootstrap-admin","UserId":"AIDAADMIN"}}'
        else
            printf '%s\n' '{identity}'
        fi
        ;;
    'iam get-role')
        printf '%s\n' 'iam get-role' >> aws-calls.txt
        printf '%s\n' '{{"Role":{{"Arn":"arn:aws:iam::123456789012:role/actual/admin","RoleName":"admin","RoleId":"AROAEXAMPLE","Path":"/actual/"}}}}'
        ;;
    's3api head-bucket')
        printf '%s\n' 's3api head-bucket' >> aws-calls.txt
        printf '%s\n' 'An error occurred (AccessDenied) when calling the HeadBucket operation: closed fixture preflight' >&2
        exit 99
        ;;
    *)
        printf '%s\n' "UNEXPECTED $*" >> aws-calls.txt
        exit 99
        ;;
esac
"#
            ),
        )
        .unwrap();
        fs::set_permissions(&aws, fs::Permissions::from_mode(0o755)).unwrap();
        let export = fixture._temp.path().join("root-check-team.json");
        let output = fixture
            .command()
            .env_clear()
            .env("PATH", &bin)
            .args([
                "setup",
                "bootstrap",
                "--state-dir",
                fixture.state.to_str().unwrap(),
                "--profile",
                "root-check",
                "--aws-profile",
                "admin",
                "--team-id",
                "fixture",
                "--account-id",
                "123456789012",
                "--region",
                "us-east-1",
                "--bucket",
                "zdn-fixture-state",
                "--existing-role-arn",
                "arn:aws:iam::123456789012:role/external",
                "--runtime-boundary-arn",
                "arn:aws:iam::123456789012:policy/runtime",
                "--trust-principal",
                &format!("arn:aws:iam::123456789012:{principal}"),
                "--export",
                export.to_str().unwrap(),
                "--yes",
            ])
            .args(if split {
                vec!["--developer-aws-profile", "developer"]
            } else {
                vec![]
            })
            .output()
            .unwrap();
        let error = String::from_utf8_lossy(&output.stderr);
        let calls = fs::read_to_string(fixture.source.join("aws-calls.txt")).unwrap();
        let receipt = fixture.state.join("profiles/root-check.bootstrap.json");
        eprintln!(
            "source={resource}; exit={:?}; receipt={}; calls={calls:?}\n{error}",
            output.status.code(),
            receipt.exists(),
        );
        assert_eq!(output.status.code(), Some(1), "{error}");
        if let Some(diagnostic) = diagnostic {
            assert!(error.contains(diagnostic), "{error}");
            assert!(!calls.contains("s3api"));
            assert!(!calls.contains("UNEXPECTED"));
            assert!(!receipt.exists());
            assert!(!fixture
                .state
                .join("profiles/root-check.bootstrap.lock")
                .exists());
        } else {
            assert!(
                error.contains("cannot establish state bucket ownership"),
                "{error}"
            );
            assert!(calls.ends_with("s3api head-bucket\n"));
            assert!(!calls.contains("UNEXPECTED"));
            assert!(receipt.exists());
        }
        for path in ["profiles/root-check.access", "profiles/root-check.json"] {
            assert!(!fixture.state.join(path).exists(), "created {path}");
        }
        assert!(!export.exists());
    }
}

#[test]
fn shared_source_profile_accepts_explicit_iam_trust_but_not_root_or_sessions() {
    let f = Fixture::new();
    for (source, principal, valid) in [
        (None, "arn:aws:iam::123456789012:user/admin", true),
        (Some("admin"), "arn:aws:iam::123456789012:user/admin", true),
        (
            Some("developer"),
            "arn:aws:iam::123456789012:user/admin",
            true,
        ),
        (None, "arn:aws:iam::123456789012:role/sso/Admin", true),
        (None, "arn:aws:iam::123456789012:root", false),
        (Some("admin"), "arn:aws:iam::123456789012:root", false),
        (
            None,
            "arn:aws:sts::123456789012:assumed-role/Admin/session",
            false,
        ),
        (None, "arn:aws:iam::999999999999:user/admin", false),
    ] {
        // External-role mode avoids managed-tool discovery. With an empty PATH,
        // valid inputs reach the first AWS identity read but cannot mutate AWS.
        let output = f
            .command()
            .env_clear()
            .env("PATH", "")
            .args([
                "setup",
                "bootstrap",
                "--state-dir",
                f.state.to_str().unwrap(),
                "--profile",
                "single-login",
                "--aws-profile",
                "admin",
                "--team-id",
                "fixture",
                "--account-id",
                "123456789012",
                "--region",
                "us-east-1",
                "--bucket",
                "zdn-fixture-state",
                "--existing-role-arn",
                "arn:aws:iam::123456789012:role/deployment",
                "--runtime-boundary-arn",
                "arn:aws:iam::123456789012:policy/runtime",
                "--trust-principal",
                principal,
                "--yes",
            ])
            .args(
                source
                    .into_iter()
                    .flat_map(|profile| ["--developer-aws-profile", profile]),
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        let expected = if valid { "cannot run" } else { "IAM ARN" };
        assert!(error.contains(expected), "{source:?} {principal}: {error}");
        assert!(!f
            .state
            .join("profiles/single-login.bootstrap.json")
            .exists());
        assert!(!f.state.join("profiles/single-login.json").exists());
    }
}

#[cfg(unix)]
#[test]
fn external_role_self_trust_fails_before_any_aws_call_or_bootstrap_receipt() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let bin = fixture._temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let aws = bin.join("aws");
    executable::write(
        &aws,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> aws-calls.txt\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&aws, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = fixture.command();
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AWS_") {
            command.env_remove(key);
        }
    }
    let role = "arn:aws:iam::123456789012:role/external";
    let output = command
        .env("PATH", &bin)
        .args([
            "setup",
            "bootstrap",
            "--state-dir",
            fixture.state.to_str().unwrap(),
            "--profile",
            "self-trust",
            "--aws-profile",
            "admin",
            "--developer-aws-profile",
            "developer",
            "--team-id",
            "fixture",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
            "--bucket",
            "zdn-fixture-state",
            "--existing-role-arn",
            role,
            "--runtime-boundary-arn",
            "arn:aws:iam::123456789012:policy/runtime",
            "--trust-principal",
            "arn:aws:iam::123456789012:user/developer",
            "--trust-principal",
            role,
            "--yes",
        ])
        .output()
        .unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{error}");
    assert!(
        error.contains("deployment role cannot trust itself"),
        "{error}"
    );
    assert!(!fixture.source.join("aws-calls.txt").exists());
    for path in [
        "profiles/self-trust.bootstrap.json",
        "profiles/self-trust.access",
        "profiles/self-trust.json",
    ] {
        assert!(!fixture.state.join(path).exists(), "created {path}");
    }
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let state = temp.path().join("state");
        fs::create_dir(&source).unwrap();
        StateStore::open(&state).unwrap();
        fs::create_dir_all(state.join("profiles")).unwrap();
        let team = json!({"apiVersion":"zdn-team/v1alpha1","teamId":"fixture","revision":1,"bootstrapId":Uuid::new_v4(),
            "aws":{"accountId":"123456789012","region":"us-east-1"},
            "state":{"backend":"s3://zdn-fixture-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"}});
        fs::write(
            state.join("profiles/devnet.json"),
            serde_json::to_vec(&json!({"team":team,"awsProfile":"fixture"})).unwrap(),
        )
        .unwrap();
        fs::write(
            temp.path().join("team.json"),
            serde_json::to_vec(&team).unwrap(),
        )
        .unwrap();
        let fixture = Self {
            _temp: temp,
            source,
            state,
        };
        fixture.ok(&["init", "--release", "candidate-v1"]);
        fixture
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .current_dir(&self.source)
            .env("PATH", "")
            .env("XDG_DATA_HOME", self._temp.path().join("xdg"));
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn fail(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(!output.status.success());
        String::from_utf8(output.stderr).unwrap()
    }
    fn foundation_helper(&self) -> PathBuf {
        let path = self.state.join("profiles/devnet.json");
        let mut profile: zdn::aws::LocalProfile =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        profile.team.api_version = zdn::access::TEAM_ROLE_API_VERSION.into();
        profile.team.deployment = Some(zdn::access::DeploymentAccess::managed(&profile.team));
        fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let helper = self._temp.path().join("helper");
        let mut bytes = vec![0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        fs::write(&helper, bytes).unwrap();
        helper
    }
    fn render(&self) -> Value {
        let helper = self.foundation_helper();
        self.ok(&[
            "foundation",
            "render",
            "--state-dir",
            self.state.to_str().unwrap(),
            "--ami-id",
            "ami-0123456789abcdef0",
            "--availability-zone",
            "us-east-1a",
            "--host-helper",
            helper.to_str().unwrap(),
        ])
    }
}

#[test]
fn renders_private_foundation_without_aws_or_managed_tools_and_preserves_identity() {
    let fixture = Fixture::new();
    let first = fixture.render();
    assert_eq!(first["createsZakura"], false);
    assert_eq!(first["accountId"], "123456789012");
    assert_eq!(first["backend"], "s3://zdn-fixture-state/pulumi/zdn");
    let program: serde_yaml::Value =
        serde_yaml::from_str(first["pulumiYaml"].as_str().unwrap()).unwrap();
    assert_eq!(
        program["resources"]["host"]["properties"]["associatePublicIpAddress"].as_bool(),
        Some(false)
    );
    let path = fixture.source.join("devnet.yaml");
    let mut config: serde_yaml::Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["name"] = "renamed".into();
    fs::write(path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let again = fixture.ok(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert_eq!(again["networkId"], first["networkId"]);
    assert_eq!(again["pulumiYaml"], first["pulumiYaml"]);
    let id = first["networkId"].as_str().unwrap();
    let saved: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .state
                .join("foundation")
                .join(id)
                .join("deployment.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(saved["stack_initialized"], false);
    assert!(saved["last_operation"].is_null());
}

#[test]
fn host_settings_and_backend_cannot_retarget_a_saved_foundation() {
    let fixture = Fixture::new();
    fixture.render();
    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
        "--ami-id",
        "ami-11111111111111111",
    ]);
    assert!(error.contains("are fixed"), "{error}");
    let path = fixture.state.join("profiles/devnet.json");
    let mut profile: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    profile["team"]["state"]["backend"] = "s3://another-state-bucket/pulumi/zdn".into();
    fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(error.contains("saved settings"), "{error}");
}

#[test]
fn cloud_mutations_require_explicit_choice_before_tools_or_profiles_are_read() {
    let fixture = Fixture::new();
    for args in [
        vec!["foundation", "up"],
        vec!["foundation", "destroy", "missing"],
        vec![
            "setup",
            "bootstrap",
            "--aws-profile",
            "fixture",
            "--team-id",
            "fixture",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
            "--bucket",
            "zdn-fixture-state",
        ],
    ] {
        let error = fixture.fail(&args);
        assert!(error.contains("--yes"), "{error}");
        assert!(!error.contains("cannot run"));
    }
    for (family, action, format) in [
        ("foundation", "up", "json"),
        ("foundation", "up", "jsonl"),
        ("foundation", "destroy", "json"),
        ("foundation", "destroy", "jsonl"),
        ("devnet", "destroy", "json"),
        ("devnet", "destroy", "jsonl"),
    ] {
        let mut command = fixture.command();
        command.args(["--format", format, family, action]);
        if action == "destroy" {
            command.arg("missing");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let records: Vec<Value> = if format == "json" {
            vec![serde_json::from_str(&stdout).unwrap()]
        } else {
            stdout
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        assert_eq!(records.len(), if format == "json" { 1 } else { 2 });
        let result = records.last().unwrap();
        assert_eq!(result["error"]["code"], format!("{family}-{action}-failed"));
        assert_eq!(result["error"]["retryClassification"], "blocked");
        assert!(result["networkId"].is_null());
        assert!(result["operationId"].is_null());
    }
    assert!(!fixture.state.join("state.json").exists());
    assert!(!fixture.state.join("foundation").exists());
}

#[test]
fn import_cannot_replace_existing_profile_before_calling_aws() {
    let fixture = Fixture::new();
    let team = fixture._temp.path().join("team.json");
    let error = fixture.fail(&[
        "setup",
        "import",
        "--from",
        team.to_str().unwrap(),
        "--aws-profile",
        "another",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(error.contains("already has different settings"), "{error}");
    let profile: Value =
        serde_json::from_slice(&fs::read(fixture.state.join("profiles/devnet.json")).unwrap())
            .unwrap();
    assert_eq!(profile["awsProfile"], "fixture");
}

#[test]
fn setup_profile_lock_prevents_concurrent_import_before_cloud_reads() {
    use fs2::FileExt;
    let fixture = Fixture::new();
    let lock = fs::File::create(fixture.state.join("profiles/devnet.profile.lock")).unwrap();
    lock.lock_exclusive().unwrap();
    let team = fixture._temp.path().join("team.json");
    let error = fixture.fail(&[
        "setup",
        "import",
        "--from",
        team.to_str().unwrap(),
        "--aws-profile",
        "fixture",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(error.contains("another setup"), "{error}");
}

#[cfg(unix)]
#[test]
fn machine_foundation_flushes_durable_progress_before_aws_and_retains_ids_on_failure() {
    use std::io::{BufRead, BufReader, Read};
    use std::process::Stdio;

    for (family, action, format, delete_data, progress) in [
        ("foundation", "up", "json", false, false),
        ("foundation", "up", "jsonl", false, false),
        ("foundation", "destroy", "json", false, false),
        ("foundation", "destroy", "jsonl", false, false),
        ("foundation", "destroy", "json", true, false),
        ("foundation", "destroy", "jsonl", true, false),
        ("foundation", "up", "json", false, true),
        ("foundation", "destroy", "json", true, true),
        ("foundation", "destroy", "jsonl", false, true),
        ("devnet", "destroy", "json", true, false),
        ("devnet", "destroy", "jsonl", false, false),
    ] {
        let fixture = Fixture::new();
        let selector = (action == "destroy")
            .then(|| fixture.render()["networkId"].as_str().unwrap().to_owned());
        if family == "devnet" {
            let id = Uuid::parse_str(selector.as_ref().unwrap()).unwrap();
            let mut deployment = DeploymentFile::read_snapshot(&fixture.state, id).unwrap();
            let refused = fixture.fail(&[
                "devnet",
                "destroy",
                selector.as_ref().unwrap(),
                "--yes",
                "--state-dir",
                fixture.state.to_str().unwrap(),
            ]);
            assert!(refused.contains("health-test foundation"), "{refused}");
            let file = DeploymentFile::open(&fixture.state, id).unwrap();
            deployment.foundation_runtime = None;
            file.save(&deployment).unwrap();
            zdn::foundation::write_json(
                &file.directory().join("source-build-inputs.json"),
                &OperationInput {
                    config_sha256: "a".repeat(64),
                    source_manifest_sha256: Some("b".repeat(64)),
                    archive_sha256: Some("c".repeat(64)),
                },
            )
            .unwrap();
        }
        let managed = fixture._temp.path().join("tools");
        machine_failure::install(fixture._temp.path());
        let bin = fixture._temp.path().join("bin");
        let release = fixture._temp.path().join("release");
        let waiting = fixture._temp.path().join("waiting");
        let stderr = fixture._temp.path().join("stderr");
        let progress_path = fixture._temp.path().join("progress.jsonl");
        if format == "json" && !progress {
            fs::write(&release, b"ready").unwrap();
        }
        let mut command = fixture.command();
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AWS_") {
                command.env_remove(key);
            }
        }
        command
            .env("PATH", &bin)
            .env("ZDN_FIXTURE_WAITING", &waiting)
            .env("ZDN_FIXTURE_RELEASE", &release)
            .args(["--format", format]);
        if progress {
            command.arg("--progress-file").arg(&progress_path);
        }
        command.args([
            family,
            action,
            "--yes",
            "--state-dir",
            fixture.state.to_str().unwrap(),
            "--managed-dir",
            managed.to_str().unwrap(),
        ]);
        if action == "up" {
            command.args([
                "--ami-id",
                "ami-0123456789abcdef0",
                "--availability-zone",
                "us-east-1a",
            ]);
            command
                .arg("--host-helper")
                .arg(fixture.foundation_helper());
        }
        if let Some(selector) = selector {
            command.arg(selector);
        }
        if delete_data {
            command.arg("--delete-data");
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut records = Vec::<Value>::new();
        let mut file_records = Vec::<Value>::new();
        if format == "jsonl" {
            for expected in ["command-started", "operation-started", "phase-started"] {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let event: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(event["type"], expected, "{event}");
                records.push(event);
            }
        } else if progress {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let text = fs::read_to_string(&progress_path).unwrap_or_default();
                file_records = text
                    .split_inclusive('\n')
                    .filter(|line| line.ends_with('\n'))
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                if file_records.len() >= 3 {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "{text}");
                assert!(child.try_wait().unwrap().is_none());
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(
                file_records
                    .iter()
                    .map(|r| r["type"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec!["command-started", "operation-started", "phase-started"]
            );
        }
        if format == "jsonl" || progress {
            assert!(child.try_wait().unwrap().is_none());
            let started = if format == "jsonl" {
                &records
            } else {
                &file_records
            };
            let id = Uuid::parse_str(started[1]["operationId"].as_str().unwrap()).unwrap();
            let saved = StateStore::open(&fixture.state)
                .unwrap()
                .operation(id)
                .unwrap();
            assert!(matches!(
                saved.phases[0].status,
                PhaseStatus::Running { .. }
            ));
            fs::write(&release, b"ready").unwrap();
        }
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        assert!(fs::read(&stderr).unwrap().is_empty());
        assert!(waiting.exists());
        assert!(!rest.contains("fixture-diagnostic-not-for-export"));
        if format == "jsonl" {
            records.extend(
                rest.lines()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap()),
            );
            assert_eq!(records.len(), 5);
            assert_eq!(records[3]["type"], "phase-result");
            assert_eq!(records[3]["outcome"], "failed");
            assert_eq!(records[3]["data"]["phase"]["name"], "verify");
        } else {
            records.push(serde_json::from_str(&rest).unwrap());
        }
        let result = records.last().unwrap();
        if progress {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&progress_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let text = fs::read_to_string(&progress_path).unwrap();
            assert!(!text.contains("fixture-diagnostic-not-for-export"));
            let file_records: Vec<Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(file_records.len(), 5);
            assert_eq!(file_records.last().unwrap(), result);
        }
        assert_eq!(result["error"]["code"], format!("{family}-{action}-failed"));
        assert_eq!(result["error"]["retryClassification"], "blocked");
        let id = Uuid::parse_str(result["operationId"].as_str().unwrap()).unwrap();
        let saved = StateStore::open(&fixture.state)
            .unwrap()
            .operation(id)
            .unwrap();
        assert_eq!(
            saved.kind,
            match (action, delete_data) {
                ("up", _) => "foundation-up",
                (_, true) => "foundation-destroy-data",
                _ => "foundation-destroy-retain",
            }
        );
        assert_eq!(result["networkId"], saved.network_id.to_string());
        assert_eq!(
            result["data"]["savedReceipt"]["phases"][0]["status"],
            "failed"
        );
        assert!(matches!(
            saved.phases[0].status,
            PhaseStatus::Failed {
                retry_safe: true,
                ..
            }
        ));
        assert!(saved.phases[1..]
            .iter()
            .all(|p| matches!(p.status, PhaseStatus::Pending)));
        for event in records.iter().skip(usize::from(format == "jsonl")) {
            assert_eq!(event["operationId"], id.to_string());
            assert_eq!(event["networkId"], saved.network_id.to_string());
        }

        // A refusal to reconcile an earlier operation is not a newly started
        // operation. Preserve its identity as blocking context, without events.
        let store = StateStore::open(&fixture.state).unwrap();
        let saved = store
            .record_phase(
                id,
                saved.revision,
                "verify",
                PhaseStatus::Running { external_ref: None },
            )
            .unwrap();
        let saved = store
            .record_phase(
                id,
                saved.revision,
                "verify",
                PhaseStatus::Succeeded {
                    result: json!({"untrusted": "fixture-diagnostic-not-for-export"}),
                },
            )
            .unwrap();
        let saved = store
            .record_phase(
                id,
                saved.revision,
                "reserve",
                PhaseStatus::Running { external_ref: None },
            )
            .unwrap();
        let saved = store
            .record_phase_outcome(
                &saved,
                "reserve",
                PhaseStatus::Unknown {
                    message: "fixture-diagnostic-not-for-export".into(),
                    external_ref: Some("fixture-diagnostic-not-for-export".into()),
                },
            )
            .unwrap();
        fs::remove_file(&waiting).unwrap();
        if progress {
            fs::remove_file(&progress_path).unwrap();
        }
        let refused = command.output().unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert!(fs::read(&stderr).unwrap().is_empty());
        let stdout = String::from_utf8(refused.stdout).unwrap();
        assert!(!stdout.contains("fixture-diagnostic-not-for-export"));
        let records: Vec<Value> = if format == "jsonl" {
            stdout
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        } else {
            vec![serde_json::from_str(&stdout).unwrap()]
        };
        assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
        let result = records.last().unwrap();
        assert_eq!(result["error"]["retryClassification"], "reconcile-required");
        assert_eq!(result["error"]["code"], format!("{family}-{action}-failed"));
        assert!(result["operationId"].is_null());
        assert_eq!(result["networkId"], saved.network_id.to_string());
        let blocking = &result["data"]["blockingReceipt"];
        assert_eq!(blocking["operationId"], id.to_string());
        assert_eq!(blocking["revision"], saved.revision);
        assert_eq!(blocking["phases"][1]["status"], "unknown");
        assert_eq!(store.operation(id).unwrap(), saved);
        let ledger: Value =
            serde_json::from_slice(&fs::read(fixture.state.join("state.json")).unwrap()).unwrap();
        assert_eq!(ledger["operations"].as_array().unwrap().len(), 1);
        assert!(!waiting.exists(), "refused operation contacted STS");
    }
}

#[cfg(unix)]
#[test]
#[cfg(target_os = "linux")]
fn failed_progress_after_allocation_retains_identity_and_stops_later_effects() {
    use std::{io::Read, process::Stdio};
    let f = Fixture::new();
    let rendered = f.render();
    let network = rendered["networkId"].as_str().unwrap();
    machine_failure::install(f._temp.path());
    let waiting = f._temp.path().join("waiting");
    let release = f._temp.path().join("release");
    let progress = f._temp.path().join("progress.jsonl");
    let mut child = native_exec::command(f._temp.path(), env!("CARGO_BIN_EXE_zdn"), None)
        .args(["--format", "json", "--progress-file"])
        .arg(&progress)
        .args(["foundation", "destroy", network, "--yes", "--state-dir"])
        .arg(&f.state)
        .arg("--managed-dir")
        .arg(f._temp.path().join("tools"))
        .current_dir(&f.source)
        .env_clear()
        .env("HOME", f._temp.path())
        .env("PATH", f._temp.path().join("bin"))
        .env("ZDN_FIXTURE_WAITING", &waiting)
        .env("ZDN_FIXTURE_RELEASE", &release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !waiting.exists() {
        assert!(child.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let records: Vec<Value> = fs::read_to_string(&progress)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    let id = Uuid::parse_str(records[1]["operationId"].as_str().unwrap()).unwrap();
    // Only this disposable controller gets a zero file limit. Its stdout pipe
    // remains writable, so a reporting failure must not hide the known receipt.
    rustix::process::prlimit(
        Some(rustix::process::Pid::from_child(&child)),
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    fs::write(release, b"ready").unwrap();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(1));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty(), "{stderr}");
    let result: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["error"]["code"], "progress-write-failed");
    assert_eq!(result["error"]["retryClassification"], "reconcile-required");
    assert_eq!(result["operationId"], id.to_string());
    assert_eq!(result["networkId"], network);
    assert!(!stdout.contains("fixture-diagnostic-not-for-export"));
    let saved = StateStore::open(&f.state).unwrap().operation(id).unwrap();
    assert!(matches!(
        saved.phases[0].status,
        PhaseStatus::Running { .. }
    ));
    assert!(saved.phases[1..]
        .iter()
        .all(|p| matches!(p.status, PhaseStatus::Pending)));
    assert!(
        !DeploymentFile::read_snapshot(&f.state, saved.network_id)
            .unwrap()
            .destroyed
    );
}

#[cfg(unix)]
#[test]
fn status_handles_large_instance_metadata_and_exposes_the_operation_while_locked() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let rendered = fixture.render();
    let id = Uuid::parse_str(rendered["networkId"].as_str().unwrap()).unwrap();
    let writer = DeploymentFile::open(&fixture.state, id).unwrap();
    let mut deployment = writer.load().unwrap();
    let store = StateStore::open(&fixture.state).unwrap();
    let binding = store
        .resolve(&deployment.spec.scope, &id.to_string(), None)
        .unwrap();
    let operation = store
        .begin_operation(
            &binding,
            "foundation-up",
            OperationInput {
                config_sha256: "a".repeat(64),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &["apply"],
        )
        .unwrap();
    store
        .record_phase(
            operation.operation_id,
            operation.revision,
            "apply",
            PhaseStatus::Running { external_ref: None },
        )
        .unwrap();
    deployment.last_operation = Some(operation.operation_id);
    writer.save(&deployment).unwrap();
    let receipt_path = writer.directory().join("deployment.json");
    let before = fs::read(&receipt_path).unwrap();
    let state_before = fs::read(fixture.state.join("state.json")).unwrap();

    let bin = fixture._temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let aws = bin.join("aws");
    // No real AWS executable is on PATH. Fail any command other than the
    // read-only status calls, including any attempted cloud mutation.
    executable::write(&aws, r#"#!/bin/sh
printf '%s\n' "$*" >> aws-calls.txt
case "$*" in
  --version) printf 'aws-cli/2.37.4 Python/3.13 fixture\n' ;;
  *'sts get-caller-identity'*) printf '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/%s/fixture","UserId":"fixture"}' "$ZDN_FIXTURE_ROLE" ;;
  *'s3api get-object'*) printf 'An error occurred (NoSuchKey) when calling the GetObject operation: fixture\n' >&2; exit 254 ;;
  *'ec2 describe-instances'*)
    instances='{"Reservations":[{"Instances":[{"InstanceId":"i-0123456789abcdef0","State":{"Name":"running"}},{"InstanceId":"i-0123456789abcdef1","State":{"Name":"stopped"}},{"InstanceId":"i-0123456789abcdef2","State":{"Name":"terminated"}}]}]}'
    case "$*" in
      *'--query {Reservations: Reservations[].{Instances: Instances[].{InstanceId: InstanceId, State: {Name: State.Name}}}}'*) printf '%s' "$instances" ;;
      *) printf '{"UnusedMetadata":"%020000d",' 0; printf '%s' "${instances#?}" ;;
    esac ;;
  *'ec2 describe-vpcs'*) printf '{"Vpcs":[]}' ;;
  *'ec2 describe-addresses'*) printf '{"Addresses":[]}' ;;
  *'ec2 describe-subnets'*) printf '{"Subnets":[]}' ;;
  *'ec2 describe-security-groups'*) printf '{"SecurityGroups":[]}' ;;
  *'ec2 describe-internet-gateways'*) printf '{"InternetGateways":[]}' ;;
  *'ec2 describe-route-tables'*) printf '{"RouteTables":[]}' ;;
  *'ec2 describe-nat-gateways'*) printf '{"NatGateways":[]}' ;;
  *'ec2 describe-volumes'*) printf '{"Volumes":[]}' ;;
  *'iam get-role'*|*'iam get-instance-profile'*) printf 'An error occurred (NoSuchEntity) when calling a read operation: fixture\n' >&2; exit 254 ;;
  *) printf 'unexpected fake AWS command\n' >&2; exit 99 ;;
esac
"#).unwrap();
    fs::set_permissions(&aws, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = fixture.command();
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AWS_") {
            command.env_remove(key);
        }
    }
    let output = command
        .env("PATH", &bin)
        .env(
            "ZDN_FIXTURE_ROLE",
            deployment
                .team
                .deployment
                .as_ref()
                .unwrap()
                .role_arn
                .rsplit('/')
                .next()
                .unwrap(),
        )
        .args([
            "foundation",
            "status",
            &id.to_string(),
            "--state-dir",
            fixture.state.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["lastOperation"], operation.operation_id.to_string());
    assert_eq!(status["networkId"], id.to_string());
    assert!(status["lease"].is_null());
    assert_eq!(
        status["inventory"]["remaining_resources"],
        json!([
            "instance:i-0123456789abcdef0",
            "instance:i-0123456789abcdef1"
        ])
    );
    assert_eq!(status["inventory"]["shared_backend_preserved"], Value::Null);
    assert_eq!(status["sharedBackendChecked"], false);
    assert_eq!(status["liveReadinessChecked"], false);
    assert_eq!(fs::read(&receipt_path).unwrap(), before);
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        state_before
    );
    assert!(fs::read_to_string(fixture.source.join("aws-calls.txt"))
        .unwrap()
        .contains("describe-instances"));

    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(error.contains("another local process"), "{error}");
    fixture.ok(&[
        "receipt",
        "cancel",
        status["lastOperation"].as_str().unwrap(),
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(
        store
            .operation(operation.operation_id)
            .unwrap()
            .cancel_requested
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), before);
}

#[test]
fn render_keeps_local_state_outside_source_and_requires_pinned_host_inputs() {
    let fixture = Fixture::new();
    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
    ]);
    assert!(error.contains("--ami-id"), "{error}");
    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        fixture.state.to_str().unwrap(),
        "--ami-id",
        "latest",
        "--availability-zone",
        "us-east-1a",
    ]);
    assert!(error.contains("ami-"), "{error}");
    let forbidden = fixture.source.join("local-state");
    StateStore::open(&forbidden).unwrap();
    fs::create_dir_all(forbidden.join("profiles")).unwrap();
    fs::copy(
        fixture.state.join("profiles/devnet.json"),
        forbidden.join("profiles/devnet.json"),
    )
    .unwrap();
    let error = fixture.fail(&[
        "foundation",
        "render",
        "--state-dir",
        forbidden.to_str().unwrap(),
        "--ami-id",
        "ami-0123456789abcdef0",
        "--availability-zone",
        "us-east-1a",
    ]);
    assert!(error.contains("outside the configuration"), "{error}");
}
