#![cfg(unix)]

use eyre::{bail, Result};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use uuid::Uuid;
use zdn::config::Size;
use zdn::infra::FoundationSpec;
use zdn::pulumi::*;
use zdn::state::Scope;

#[path = "support/executable.rs"]
mod executable;

const KEY: &str = "awskms:///arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1";
const STACK: &str = "zdn-test";
const SECRET: &str = "test-secret-never-log-this";

fn runner() -> SystemPulumiRunner {
    SystemPulumiRunner::new(env!("CARGO_BIN_EXE_zdn").into())
}

fn keep_going() -> Result<RunControl> {
    Ok(RunControl::Continue)
}

#[test]
fn role_credential_files_apply_to_every_pulumi_command() {
    let (root, mut workspace) = fixture();
    let files = zdn::credentials::CredentialFiles {
        config: root.path().join("role-config"),
        empty_credentials: root.path().join("empty-credentials"),
    };
    fs::write(
        &files.config,
        "[profile devnet]\ncredential_process = /zdn __credentials --request /request\n",
    )
    .unwrap();
    fs::write(&files.empty_credentials, "").unwrap();
    workspace.aws.credential_files = Some(files.clone());
    for args in [
        vec!["stack", "ls"],
        vec!["stack", "init"],
        vec!["preview"],
        vec!["up"],
        vec!["destroy"],
    ] {
        let command = workspace
            .command("role-contract", &args, ProcessLimits::default())
            .unwrap();
        assert_eq!(
            command.env[&OsString::from("AWS_CONFIG_FILE")],
            files.config.as_os_str()
        );
        assert_eq!(
            command.env[&OsString::from("AWS_SHARED_CREDENTIALS_FILE")],
            files.empty_credentials.as_os_str()
        );
        assert_eq!(command.env[&OsString::from("AWS_PROFILE")], "devnet");
        assert_eq!(command.env[&OsString::from("AWS_SDK_LOAD_CONFIG")], "1");
        for forbidden in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ] {
            assert!(!command.env.contains_key(&OsString::from(forbidden)));
        }
    }
}

#[test]
fn sanitized_pulumi_command_runs_the_real_credential_bridge() {
    use std::collections::BTreeMap;
    use zdn::{access::AccessRequest, aws::AwsSelection, credentials};

    const SENSITIVE: [&str; 9] = [
        "fixture-role-key",
        "fixture-role-secret",
        "fixture-role-token",
        "fixture-error-secret",
        "fixture-error-token",
        "ambient-custom-secret",
        "ambient-access-key",
        "ambient-secret-key",
        "ambient-session-token",
    ];

    let Some(source) = std::env::var_os("ZDN_TEST_BRIDGE_SOURCE") else {
        // Only this worker inherits hostile ambient values; parallel tests do not.
        let root = tempdir().unwrap();
        let source = root.path().join("source with spaces");
        fs::create_dir(&source).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sanitized_pulumi_command_runs_the_real_credential_bridge",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", &source)
            .env("ZDN_TEST_BRIDGE_SOURCE", &source)
            .env("ZDN_CUSTOM_SECRET", "ambient-custom-secret")
            .env("AWS_ACCESS_KEY_ID", "ambient-access-key")
            .env("AWS_SECRET_ACCESS_KEY", "ambient-secret-key")
            .env("AWS_SESSION_TOKEN", "ambient-session-token")
            .env("AWS_CONFIG_FILE", source.join("config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", source.join("credentials"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "worker failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    let source = Path::new(&source);
    fs::write(
        source.join("config"),
        "[profile devnet]\nregion = us-east-1\n",
    )
    .unwrap();
    fs::write(source.join("credentials"), "[devnet]\n").unwrap();
    let (root, mut workspace) = fixture();
    let request: AccessRequest = serde_json::from_value(json!({
        "team":{"apiVersion":"zdn-team/v1alpha1","teamId":"bridge","revision":1,
            "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
            "aws":{"accountId":"123456789012","region":"us-east-1"},
            "state":{"backend":"s3://zdn-bridge/pulumi/zdn",
                "kmsKeyArn":KEY.strip_prefix("awskms:///").unwrap().split('?').next().unwrap()}},
        "administrator":{"profile":"administrator","accountId":"123456789012","region":"us-east-1"},
        "trustedPrincipals":["arn:aws:iam::123456789012:user/developer"],"existing":null
    }))
    .unwrap();
    let team = request.completed_team().unwrap();
    let selection = AwsSelection {
        profile: workspace.aws.profile.clone(),
        account_id: workspace.aws.account_id.clone(),
        region: workspace.aws.region.clone(),
    };
    let environment = ["HOME", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"]
        .map(|key| (key.into(), std::env::var(key).unwrap()))
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let files = credentials::prepare(
        &team,
        &selection,
        &root.path().join("bridge with spaces"),
        Path::new(env!("CARGO_BIN_EXE_zdn")),
        &environment,
    )
    .unwrap()
    .unwrap();
    workspace.aws.credential_files = Some(files.clone());
    let role = team
        .deployment
        .as_ref()
        .unwrap()
        .role_arn
        .rsplit('/')
        .next()
        .unwrap();
    // This is only an external AWS response fixture. ZDN performs all source
    // restoration, identity/role checks, credential validation and redaction.
    executable(
        &source.join("aws"),
        &format!(
            r#"#!/bin/sh
set -eu
[ -p /dev/stdout ]
base=${{0%/*}}
[ "$AWS_CONFIG_FILE" = "$base/config" ]
[ "$AWS_SHARED_CREDENTIALS_FILE" = "$base/credentials" ]
[ "$AWS_PROFILE" = devnet ]
[ -z "${{ZDN_CUSTOM_SECRET+x}}${{AWS_ACCESS_KEY_ID+x}}${{AWS_SECRET_ACCESS_KEY+x}}${{AWS_SESSION_TOKEN+x}}" ]
printf '%s\n' "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE" "$AWS_PROFILE" >> source-environment.txt
case "$*" in
  *get-caller-identity*)
    printf 'identity\n' >> sts-calls.txt
    if [ -f fail-login ]; then
      printf '%s\n' "Your session has expired. Please reauthenticate using 'aws login'. fixture-error-secret fixture-error-token" >&2
      exit 1
    fi
    printf '%s\n' '{{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/developer","UserId":"source"}}' ;;
  *assume-role*)
    printf 'assume\n' >> sts-calls.txt
    printf '%s\n' '{{"AssumedRoleUser":{{"Arn":"arn:aws:sts::123456789012:assumed-role/{role}/zdn-deployment","AssumedRoleId":"role:session"}},"Credentials":{{"AccessKeyId":"fixture-role-key","SecretAccessKey":"fixture-role-secret","SessionToken":"fixture-role-token","Expiration":"2099-01-01T00:00:00Z"}}}}' ;;
  *) exit 99 ;;
esac
"#
        ),
    );
    // Minimal external SDK fixture: read the generated credential_process
    // instruction and consume its stdout in memory, never forwarding credentials
    // into Pulumi output (which the real runner spools for diagnostics).
    executable(
        &workspace.tools.executable,
        r#"#!/bin/sh
set -eu
[ "$AWS_PROFILE" = devnet ]
[ "$AWS_SDK_LOAD_CONFIG" = 1 ]
[ ! -s "$AWS_SHARED_CREDENTIALS_FILE" ]
[ -z "${ZDN_TEST_BRIDGE_SOURCE+x}${ZDN_CUSTOM_SECRET+x}${AWS_ACCESS_KEY_ID+x}${AWS_SECRET_ACCESS_KEY+x}${AWS_SESSION_TOKEN+x}" ]
command -v aws > aws-path.txt
printf '%s\n' "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE" > sdk-files.txt
credential_process=
while IFS= read -r line; do
  case "$line" in 'credential_process = '*) credential_process=${line#credential_process = } ;; esac
done < "$AWS_CONFIG_FILE"
[ -n "$credential_process" ]
if credentials=$(/bin/sh -c "$credential_process"); then
  for field in '"Version": 1' '"AccountId": "123456789012"' '"AccessKeyId": "fixture-role-key"' '"SecretAccessKey": "fixture-role-secret"' '"SessionToken": "fixture-role-token"' '"Expiration": "2099-01-01T00:00:00Z"'; do
    case "$credentials" in *"$field"*) ;; *) exit 71 ;; esac
  done
  printf 'sdk-consumed-role-credentials\n'
else
  [ -z "$credentials" ] || exit 72
  exit 73
fi
"#,
    );
    for fail in [false, true] {
        if fail {
            fs::write(workspace.work_dir.join("fail-login"), "").unwrap();
        }
        let command = workspace
            .command("credential-bridge", &["preview"], ProcessLimits::default())
            .unwrap();
        let output = runner().run(&command, &mut keep_going).unwrap();
        for stream in [&output.stdout, &output.stderr] {
            for secret in SENSITIVE {
                assert!(!stream
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes()));
            }
        }
        assert_eq!(
            output.success, !fail,
            "unexpected fixture output: {output:?}"
        );
        if fail {
            assert_eq!(output.exit_code, Some(73));
            assert!(output.stdout.is_empty());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("deployment credentials unavailable"),
                "{error}"
            );
            assert!(error.contains("check source profile login"), "{error}");
        } else {
            assert_eq!(output.stdout, b"sdk-consumed-role-credentials\n");
            assert!(output.stderr.is_empty());
        }
        assert_eq!(
            fs::read_to_string(workspace.work_dir.join("sdk-files.txt")).unwrap(),
            format!(
                "{}\n{}\n",
                files.config.display(),
                files.empty_credentials.display()
            )
        );
        assert_eq!(
            fs::read_to_string(workspace.work_dir.join("aws-path.txt")).unwrap(),
            format!("{}\n", source.join("aws").display())
        );
    }
    assert_eq!(
        fs::read_to_string(workspace.work_dir.join("sts-calls.txt")).unwrap(),
        "identity\nassume\nidentity\n"
    );
    assert_eq!(
        fs::read_to_string(workspace.work_dir.join("source-environment.txt")).unwrap(),
        format!(
            "{}\n{}\ndevnet\n",
            source.join("config").display(),
            source.join("credentials").display()
        )
        .repeat(3)
    );
    // Scan every persistent bridge, working and diagnostic file, including
    // supervisor receipts. Fixture scripts intentionally contain fake responses
    // and live outside these directories.
    let mut pending = vec![
        files.config.parent().unwrap().to_path_buf(),
        workspace.work_dir.clone(),
        workspace.diagnostics_dir.clone(),
    ];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else {
            let bytes = fs::read(&path).unwrap();
            for secret in SENSITIVE {
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|part| part == secret.as_bytes()),
                    "secret persisted in {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn administrator_stack_cancellation_stops_before_a_process_starts() {
    use std::sync::{atomic::AtomicBool, Arc};
    use zdn::access_bootstrap::{AccessClient, AccessStack};
    let (_root, workspace) = fixture();
    let calls = workspace.work_dir.join("calls.txt");
    let client = PulumiClient::new(workspace, runner()).unwrap();
    let mut access = AccessClient {
        client,
        cancel: Arc::new(AtomicBool::new(true)),
    };
    assert!(access
        .exists()
        .unwrap_err()
        .to_string()
        .contains("cancelled"));
    assert!(!calls.exists());
}

#[test]
fn administrator_recovery_renders_from_validated_state_and_keeps_the_plan_gate() {
    use std::sync::{atomic::AtomicBool, Arc};
    use zdn::{
        access::AccessRequest,
        access_bootstrap::{AccessClient, AccessStack},
    };
    for boundary_won in [false, true] {
        let (_root, mut workspace) = fixture();
        let request: AccessRequest = serde_json::from_value(json!({
            "team":{"apiVersion":"zdn-team/v1alpha1","teamId":"recovery","revision":1,
                "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
                "aws":{"accountId":"123456789012","region":"us-east-1"},
                "state":{"backend":"s3://zdn-recovery/pulumi/zdn","kmsKeyArn":KEY.strip_prefix("awskms:///").unwrap().split('?').next().unwrap()}},
            "administrator":{"profile":"devnet","accountId":"123456789012","region":"us-east-1"},
            "trustedPrincipals":["arn:aws:iam::123456789012:user/developer"],"existing":null
        })).unwrap();
        workspace.project = "zdn-access".into();
        workspace.stack = "zdn-a81c4e9b46124e0da3fac4ab68a04153".into();
        workspace.backend_url = zdn::access::admin_backend(&request.team).unwrap();
        let project = workspace.work_dir.join("Pulumi.yaml");
        fs::write(
            &project,
            serde_yaml::to_string(&request.render().unwrap()).unwrap(),
        )
        .unwrap();
        let prefix = format!("urn:pulumi:{}::zdn-access::", workspace.stack);
        let provider = format!("{prefix}pulumi:providers:aws::provider");
        let logical = if boundary_won {
            "runtimeBoundary"
        } else {
            "runtimePolicy"
        };
        let old_arn = "arn:aws:iam::123456789012:policy/zdn-admin/a81c4e9b-4612-4e0d-a3fa-c4ab68a04153/zdn-a81c4e9b46124e0da3fac4ab68a04153-runtime";
        let mut export = json!({"version":3,"deployment":{
        "secrets_providers":{"type":"cloud","state":{"url":KEY}},
        "resources":[
            {"urn":provider,"type":"pulumi:providers:aws","id":"provider-id",
                 "inputs":{"region":"us-east-1","profile":"devnet","allowedAccountIds":["123456789012"],"version":zdn::infra::AWS_PROVIDER_VERSION}},
            {"urn":format!("{prefix}aws:iam/policy:Policy::{logical}"),"type":"aws:iam/policy:Policy",
             "id":old_arn,"provider":format!("{provider}::provider-id"),"protect":true,
             "inputs":{"name":"zdn-a81c4e9b46124e0da3fac4ab68a04153-runtime",
                "path":"/zdn-admin/a81c4e9b-4612-4e0d-a3fa-c4ab68a04153/",
                "tags":{"zdn:managed-by":"zdn","zdn:team-id":"recovery","zdn:bootstrap":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153"},
                "policy":zdn::access::runtime_boundary().to_string()}}
        ]}});
        fs::write(
            workspace.work_dir.join("export.json"),
            serde_json::to_vec(&export).unwrap(),
        )
        .unwrap();
        let mut access = AccessClient {
            client: client(workspace.clone()),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        access.prepare(false).unwrap();
        access.refresh().unwrap();
        let selected = access.configure(&request, None).unwrap();
        assert_eq!(
            selected.runtime_boundary_arn,
            if boundary_won {
                old_arn.into()
            } else {
                request.access().runtime_boundary_arn
            }
        );
        let rendered: Value = serde_yaml::from_slice(&fs::read(&project).unwrap()).unwrap();
        assert_eq!(
            rendered["resources"][logical]["properties"]["name"],
            "zdn-a81c4e9b46124e0da3fac4ab68a04153-runtime"
        );
        assert_eq!(rendered["resources"][logical]["options"]["protect"], true);
        fs::write(
            workspace.work_dir.join("preview.json"),
            r#"{"changeSummary":{"create":1,"same":1}}"#,
        )
        .unwrap();
        fs::write(
            workspace.work_dir.join("plan.json"),
            serde_json::to_vec(&json!({"manifest":{},"resourcePlans":{
                format!("{prefix}aws:iam/policy:Policy::{logical}"):{"steps":["same"]}
            }}))
            .unwrap(),
        )
        .unwrap();
        access.apply().unwrap();
        assert_eq!(args(&workspace)[0], "up");
        assert!(args(&workspace).contains(&"--plan".into()));
        fs::write(
            workspace.work_dir.join("preview.json"),
            r#"{"changeSummary":{"replace":1}}"#,
        )
        .unwrap();
        assert!(access
            .apply()
            .unwrap_err()
            .to_string()
            .contains("replacement"));
        assert_eq!(args(&workspace)[0], "preview");
        // Recovery cannot change the provider after prepare captured its
        // selection/defaults, even when the checkpoint itself remains valid.
        let unchanged = fs::read(&project).unwrap();
        let mut changed: Value = serde_yaml::from_slice(&unchanged).unwrap();
        changed["resources"]["provider"]["properties"]["defaultTags"] =
            json!({"tags":{"unexpected":"value"}});
        let changed = serde_yaml::to_string(&changed).unwrap();
        fs::write(&project, &changed).unwrap();
        assert!(access
            .configure(&request, Some(&selected))
            .unwrap_err()
            .to_string()
            .contains("prepared administrator project"));
        assert_eq!(fs::read(&project).unwrap(), changed.as_bytes());
        fs::write(&project, unchanged).unwrap();
        // Recheck the export after refresh; a foreign provider cannot select a
        // naming layout or rewrite the project even if initial prepare passed.
        let before = fs::read(&project).unwrap();
        export["deployment"]["resources"][0]["inputs"]["region"] = json!("us-west-2");
        fs::write(
            workspace.work_dir.join("export.json"),
            serde_json::to_vec(&export).unwrap(),
        )
        .unwrap();
        assert!(access.configure(&request, Some(&selected)).is_err());
        assert_eq!(fs::read(&project).unwrap(), before);
        let mut foreign_request = request.clone();
        foreign_request.team.bootstrap_id = Uuid::new_v4();
        assert!(access
            .configure(&foreign_request, None)
            .unwrap_err()
            .to_string()
            .contains("selected stack"));
    }
}

fn fixture() -> (TempDir, PulumiWorkspace) {
    let root = tempdir().unwrap();
    let work = root.path().join("work");
    let bin = root.path().join("managed/bin");
    let plugins = root.path().join("managed/plugins");
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&plugins).unwrap();
    fs::write(
        work.join("Pulumi.yaml"),
        "name: zdn-foundation\nruntime: yaml\n",
    )
    .unwrap();
    executable(
        &bin.join("pulumi"),
        r#"#!/bin/sh
printf '%s\0' "$@" > args.bin
/usr/bin/env > environment.txt
pwd > cwd.txt
printf '%s\n' "$1 $2" >> calls.txt
case "$1:$2" in
stack:init) printf 'secretsprovider: %s\n' "$5" > "Pulumi.$3.yaml" ;;
stack:export) cat export.json ;;
stack:ls) cat stacks.json ;;
stack:output) cat outputs.json ;;
config:refresh) cp restored-config.yaml "Pulumi.$4.yaml" ;;
preview:*)
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --save-plan ]; then cp plan.json "$2"; break; fi
    shift
  done
  cat preview.json ;;
up:*)
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --plan ]; then test -f "$2" || exit 45; break; fi
    shift
  done ;;
destroy:*) case " $* " in *' --preview-only '*) cat preview.json ;; esac ;;
esac
"#,
    );
    let workspace = PulumiWorkspace {
        tools: ManagedTools {
            executable: bin.join("pulumi"),
            bin_dir: bin,
            plugins_dir: plugins,
        },
        diagnostics_dir: root.path().join("diagnostics"),
        work_dir: work,
        backend_url: "s3://zdn-state-test/team/test".into(),
        secrets_provider: KEY.into(),
        aws: AwsContext {
            credential_files: None,
            profile: "devnet".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        project: "zdn-foundation".into(),
        stack: STACK.into(),
    };
    fs::write(
        workspace.work_dir.join("export.json"),
        serde_json::to_vec(&export_fixture()).unwrap(),
    )
    .unwrap();
    fs::write(
        workspace.work_dir.join("restored-config.yaml"),
        format!("secretsprovider: {KEY}\nencryptedkey: ciphertext\n"),
    )
    .unwrap();
    fs::write(
        workspace.work_dir.join("preview.json"),
        serde_json::to_vec(&preview_fixture()).unwrap(),
    )
    .unwrap();
    fs::write(
        workspace.work_dir.join("plan.json"),
        serde_json::to_vec(&plan_fixture()).unwrap(),
    )
    .unwrap();
    (root, workspace)
}
fn executable(path: &Path, body: &str) {
    executable::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
fn export_fixture() -> Value {
    json!({"version":3,"deployment":{"secrets_providers":{"type":"cloud","state":{"url":KEY,"encryptedkey":"ciphertext"}},"resources":[{"urn":"urn:pulumi:zdn-test::zdn-foundation::pulumi:pulumi:Stack::zdn-foundation-zdn-test","type":"pulumi:pulumi:Stack"}]}})
}
fn preview_fixture() -> Value {
    json!({"changeSummary":{"create":1,"same":1},"steps":[{"op":"create","urn":"urn:pulumi:zdn-test::zdn-foundation::aws:ec2/instance:Instance::host","newState":{"inputs":{"password":SECRET}}}],"config":{"secret":SECRET},"diagnostics":[{"severity":"warning","message":SECRET}]})
}
fn plan_fixture() -> Value {
    // Pulumi v3.268.0 pkg/cmd/pulumi/plan/plan.go serializes DeploymentPlanV1
    // directly. Plan properties can contain secrets and must stay private.
    json!({"manifest":{"version":"v3.268.0"},"resourcePlans":{
        "urn:pulumi:zdn-test::zdn-foundation::aws:ec2/instance:Instance::host":{
            "steps":["create"],"state":{"sensitive":SECRET}
        }
    }})
}
fn args(workspace: &PulumiWorkspace) -> Vec<String> {
    fs::read(workspace.work_dir.join("args.bin"))
        .unwrap()
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|s| String::from_utf8(s.to_vec()).unwrap())
        .collect()
}
fn diagnostics(workspace: &PulumiWorkspace) -> Vec<Value> {
    fs::read_dir(&workspace.diagnostics_dir)
        .unwrap()
        .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect()
}
fn client(workspace: PulumiWorkspace) -> PulumiClient<SystemPulumiRunner> {
    let mut client = PulumiClient::new(workspace, runner()).unwrap();
    client.limits.poll_interval = Duration::from_millis(5);
    client
}

#[test]
fn administrator_unprotect_is_exact_stack_scoped_and_noninteractive() {
    let (_root, mut workspace) = fixture();
    workspace.project = "zdn-access".into();
    fs::write(
        workspace.work_dir.join("Pulumi.yaml"),
        "name: zdn-access\nruntime: yaml\n",
    )
    .unwrap();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    let urn = format!("urn:pulumi:{STACK}::zdn-access::aws:iam/role:Role::deploymentRole");
    let second = format!("urn:pulumi:{STACK}::zdn-access::aws:iam/policy:Policy::deploymentPolicy");
    let calls = workspace.work_dir.join("calls.txt");
    let before = fs::read_to_string(&calls).unwrap().lines().count();
    client.unprotect(&[&urn, &second], &mut keep_going).unwrap();
    assert_eq!(
        fs::read_to_string(&calls).unwrap().lines().count(),
        before + 1
    );
    assert_eq!(
        args(&workspace),
        [
            "state",
            "unprotect",
            &urn,
            &second,
            "--stack",
            STACK,
            "--yes",
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    for foreign in [
        urn.replace(STACK, "other-stack"),
        urn.replace("zdn-access", "zdn-foundation"),
    ] {
        assert!(client
            .unprotect(&[&urn, &second, &foreign], &mut keep_going)
            .is_err());
    }
    client.unprotect(&[], &mut keep_going).unwrap();
    assert_eq!(
        fs::read_to_string(&calls).unwrap().lines().count(),
        before + 1
    );
    assert_eq!(args(&workspace)[2], urn);
}

#[test]
fn stack_commands_use_explicit_selection_and_noninteractive_arguments() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    assert_eq!(
        args(&workspace),
        [
            "stack",
            "init",
            STACK,
            "--secrets-provider",
            KEY,
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    client.preview(&mut keep_going).unwrap();
    let plan_path = args(&workspace)[5].clone();
    assert_eq!(
        fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        args(&workspace),
        [
            "preview",
            "--stack",
            STACK,
            "--json",
            "--save-plan",
            &plan_path,
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    client.up(&mut keep_going).unwrap();
    assert_eq!(
        args(&workspace),
        [
            "up",
            "--stack",
            STACK,
            "--yes",
            "--skip-preview",
            "--plan",
            &plan_path,
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    assert!(!Path::new(&plan_path).exists());
    client.refresh(&mut keep_going).unwrap();
    assert_eq!(args(&workspace)[0], "refresh");
    client.preview_destroy(&mut keep_going).unwrap();
    assert_eq!(
        args(&workspace),
        [
            "destroy",
            "--stack",
            STACK,
            "--preview-only",
            "--json",
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    client.destroy(&mut keep_going).unwrap();
    assert_eq!(
        args(&workspace),
        [
            "destroy",
            "--stack",
            STACK,
            "--yes",
            "--skip-preview",
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    client.remove_stack(&mut keep_going).unwrap();
    assert_eq!(
        args(&workspace),
        [
            "stack",
            "rm",
            STACK,
            "--yes",
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    assert!(client.up(&mut keep_going).is_err());
    assert_eq!(diagnostics(&workspace).len(), 7);
}

#[test]
fn process_environment_and_home_are_explicit_and_isolated() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    let environment = fs::read_to_string(workspace.work_dir.join("environment.txt")).unwrap();
    for value in [
        "AWS_PROFILE=devnet",
        "AWS_REGION=us-east-1",
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true",
        "AWS_EC2_METADATA_DISABLED=true",
        "PULUMI_BACKEND_URL=s3://zdn-state-test/team/test",
        "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION=true",
        "PULUMI_IGNORE_AMBIENT_PLUGINS=true",
    ] {
        assert!(environment.lines().any(|line| line == value));
    }
    assert!(environment
        .lines()
        .any(|line| line == format!("PULUMI_HOME={}", workspace.pulumi_home().display())));
    for key in [
        "AWS_ACCESS_KEY_ID=",
        "AWS_SECRET_ACCESS_KEY=",
        "AWS_SESSION_TOKEN=",
        "PULUMI_ACCESS_TOKEN=",
        "PULUMI_CONFIG_PASSPHRASE=",
        "PULUMI_CLOUD_SECRET_OVERRIDE=",
        "AWS_ENDPOINT_URL=",
        "AWS_MAX_ATTEMPTS=",
        "AWS_RETRY_MODE=",
    ] {
        assert!(!environment.contains(key));
    }
    assert_eq!(
        fs::canonicalize(workspace.pulumi_home().join("plugins")).unwrap(),
        fs::canonicalize(&workspace.tools.plugins_dir).unwrap()
    );
    assert_eq!(
        fs::read_to_string(workspace.work_dir.join("cwd.txt"))
            .unwrap()
            .trim(),
        fs::canonicalize(&workspace.work_dir)
            .unwrap()
            .to_str()
            .unwrap()
    );
    assert_eq!(
        fs::metadata(workspace.pulumi_home())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&workspace.diagnostics_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn ambient_plugins_are_ignored_while_credential_helpers_remain_on_path() {
    let Some(ambient) = std::env::var_os("ZDN_TEST_PULUMI_AMBIENT_BIN") else {
        // Use a child test process to avoid changing the environment of other
        // concurrently running tests. The inherited values are deliberately bad.
        let root = tempdir().unwrap();
        let ambient = root.path().join("ambient");
        fs::create_dir(&ambient).unwrap();
        executable(
            &ambient.join("pulumi"),
            "#!/bin/sh\nprintf unexpected > ambient-cli-ran\nexit 42\n",
        );
        executable(
            &ambient.join("pulumi-resource-aws"),
            "#!/bin/sh\nprintf unexpected > ambient-provider-ran\nexit 43\n",
        );
        executable(
            &ambient.join("zdn-test-credential-process"),
            "#!/bin/sh\nprintf credential-helper-ran\n",
        );
        let mut paths = vec![ambient.clone()];
        if let Some(path) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&path));
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "ambient_plugins_are_ignored_while_credential_helpers_remain_on_path",
                "--nocapture",
            ])
            .env("ZDN_TEST_PULUMI_AMBIENT_BIN", &ambient)
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("PULUMI_IGNORE_AMBIENT_PLUGINS", "false")
            .env("PULUMI_HOME", root.path().join("foreign-home"))
            .env("AWS_PROFILE", "foreign")
            .env("AWS_REGION", "us-west-2");
        command
            .env("AWS_MAX_ATTEMPTS", "1")
            .env("AWS_RETRY_MODE", "legacy");
        for key in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_ENDPOINT_URL",
            "PULUMI_ACCESS_TOKEN",
            "PULUMI_CONFIG_PASSPHRASE",
        ] {
            command.env(key, SECRET);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };

    assert_eq!(
        std::env::var("PULUMI_IGNORE_AMBIENT_PLUGINS").unwrap(),
        "false"
    );
    let (_root, workspace) = fixture();
    // This helper checks the CLI contract, not the real Pulumi plugin loader.
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\n[ \"$PULUMI_IGNORE_AMBIENT_PLUGINS\" = true ] || exit 44\nzdn-test-credential-process > credential-output.txt\ncommand -v pulumi-resource-aws > ambient-path.txt\n/usr/bin/env > environment.txt\n",
    );
    let command = workspace
        .command("environment", &[], ProcessLimits::default())
        .unwrap();
    assert_eq!(command.program, workspace.tools.executable);
    assert!(runner().run(&command, &mut keep_going).unwrap().success);
    assert_eq!(
        fs::read_to_string(workspace.work_dir.join("credential-output.txt")).unwrap(),
        "credential-helper-ran"
    );
    assert_eq!(
        fs::read_to_string(workspace.work_dir.join("ambient-path.txt"))
            .unwrap()
            .trim(),
        Path::new(&ambient)
            .join("pulumi-resource-aws")
            .to_str()
            .unwrap()
    );
    assert!(!workspace.work_dir.join("ambient-cli-ran").exists());
    assert!(!workspace.work_dir.join("ambient-provider-ran").exists());
    let environment = fs::read_to_string(workspace.work_dir.join("environment.txt")).unwrap();
    assert!(!environment.contains(SECRET));
    assert!(!environment.contains("AWS_PROFILE=foreign"));
    assert!(!environment.contains("AWS_REGION=us-west-2"));
    assert!(!environment.contains("PULUMI_IGNORE_AMBIENT_PLUGINS=false"));
    assert!(!environment.contains("AWS_MAX_ATTEMPTS="));
    assert!(!environment.contains("AWS_RETRY_MODE="));
    assert!(environment
        .lines()
        .any(|line| line == format!("PULUMI_HOME={}", workspace.pulumi_home().display())));
}

#[test]
fn arguments_are_literal_and_never_run_through_a_shell() {
    let (_root, workspace) = fixture();
    let literal = "$(touch should-not-exist) ; printf injected";
    let command = workspace
        .command(
            "literal",
            &["preview", "--message", literal],
            ProcessLimits::default(),
        )
        .unwrap();
    runner().run(&command, &mut keep_going).unwrap();
    assert_eq!(args(&workspace)[2], literal);
    assert!(!workspace.work_dir.join("should-not-exist").exists());
}

#[test]
fn s3_and_kms_validation_refuse_wrong_accounts_and_ambiguous_urls() {
    let (_root, workspace) = fixture();
    for bad in [
        "https://app.pulumi.com",
        "file:///tmp",
        "s3://bucket",
        "s3://bucket/../state",
        "s3://bucket/path?profile=other",
        "s3://bucket/path//next",
        "s3://Bucket/state",
    ] {
        assert!(validate_backend(bad).is_err(), "{bad}");
    }
    for bad in [
        KEY.replace("123456789012", "222222222222"),
        KEY.replace("us-east-1", "us-west-2"),
        KEY.replace("awskms:///", "awskms://"),
        "passphrase".into(),
        format!("{KEY}&profile=other"),
    ] {
        assert!(
            validate_secrets_provider(&bad, &workspace.aws).is_err(),
            "{bad}"
        );
    }
    let mut wrong = workspace.aws.clone();
    wrong.account_id = "123".into();
    assert!(wrong.validate().is_err());
    assert!(validate_backend(&workspace.backend_url).is_ok());
    assert!(validate_backend("s3://zdn-state-test/pulumi/team.v1").is_ok());
    assert!(validate_secrets_provider(KEY, &workspace.aws).is_ok());
}

#[test]
fn project_backend_runtime_and_name_must_match() {
    let (_root, workspace) = fixture();
    for yaml in [
        "name: zdn-foundation\nruntime: yaml\nbackend:\n  url: https://app.pulumi.com\n",
        "name: other\nruntime: yaml\n",
        "name: zdn-foundation\nruntime: nodejs\n",
    ] {
        fs::write(workspace.work_dir.join("Pulumi.yaml"), yaml).unwrap();
        assert!(PulumiClient::new(workspace.clone(), runner()).is_err());
    }
}

#[test]
fn missing_managed_install_never_falls_back_to_global_pulumi() {
    assert!(ManagedTools::resolve(tempdir().unwrap().path()).is_err());
}

#[test]
fn isolated_home_rejects_existing_symlink_or_foreign_plugins() {
    let (root, workspace) = fixture();
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    symlink(&foreign, workspace.pulumi_home()).unwrap();
    assert!(workspace
        .command("preview", &["preview"], ProcessLimits::default())
        .is_err());
    fs::remove_file(workspace.pulumi_home()).unwrap();
    fs::create_dir(workspace.pulumi_home()).unwrap();
    symlink(&foreign, workspace.pulumi_home().join("plugins")).unwrap();
    assert!(workspace
        .command("preview", &["preview"], ProcessLimits::default())
        .is_err());
}

#[test]
fn selection_checks_encrypted_state_provider_and_project() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    let config = workspace.work_dir.join(format!("Pulumi.{STACK}.yaml"));
    assert!(!config.exists());
    client.prepare_stack(false, &mut keep_going).unwrap();
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        format!("secretsprovider: {KEY}\nencryptedkey: ciphertext\n")
    );
    for mutate in [0, 1, 2, 3, 4] {
        let mut value = export_fixture();
        match mutate {
            0 => value["version"] = json!(99),
            1 => value["deployment"]["secrets_providers"]["state"]["url"] = json!("passphrase"),
            2 => {
                value["deployment"]["resources"][0]["urn"] =
                    json!("urn:pulumi:foreign::project::type::name")
            }
            3 => value["features"] = json!(["unknown"]),
            _ => value["deployment"]["snippets"] = json!([{"body":"foreign"}]),
        }
        fs::write(
            workspace.work_dir.join("export.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(client.prepare_stack(false, &mut keep_going).is_err());
        assert!(client.up(&mut keep_going).is_err());
    }
    fs::write(
        workspace.work_dir.join("export.json"),
        serde_json::to_vec(&export_fixture()).unwrap(),
    )
    .unwrap();
    fs::remove_file(&config).unwrap();
    fs::write(
        workspace.work_dir.join("restored-config.yaml"),
        "secretsprovider: passphrase\n",
    )
    .unwrap();
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
    assert!(client.up(&mut keep_going).is_err());
}

#[test]
fn failed_selection_does_not_create_a_stack_or_expose_errors() {
    for code in ["AccessDenied", "UnauthorizedOperation"] {
        let (_root, workspace) = fixture();
        executable(&workspace.tools.executable, &format!("#!/bin/sh\nprintf '%s\\n' \"$1 $2\" >> calls.txt\nprintf '{code} {SECRET}' >&2\nexit 4\n"));
        let mut client = client(workspace.clone());
        let error = client
            .prepare_stack(false, &mut keep_going)
            .unwrap_err()
            .to_string();
        assert!(error.contains("access-denied"));
        assert!(!error.contains(SECRET));
        assert_eq!(
            fs::read_to_string(workspace.work_dir.join("calls.txt")).unwrap(),
            "stack select\n"
        );
        let serialized = serde_json::to_string(&diagnostics(&workspace)).unwrap();
        assert!(!serialized.contains(SECRET));
        assert!(serialized.contains("access-denied"));
    }
}

#[test]
fn lock_classification_matches_known_errors_not_substrings() {
    for (message, category) in [
        (
            "the stack is currently locked by another update",
            "stack-locked",
        ),
        ("stack is locked", "stack-locked"),
        ("another update is currently in progress", "stack-locked"),
        ("ConcurrentUpdateError", "stack-locked"),
        ("request was blocked by a firewall", "command-failed"),
        ("stack was unlocked but deployment failed", "command-failed"),
        (
            "another update will be needed after repair",
            "command-failed",
        ),
    ] {
        let (_root, workspace) = fixture();
        executable(
            &workspace.tools.executable,
            &format!("#!/bin/sh\nprintf '%s' '{message}' >&2\nexit 4\n"),
        );
        let error = client(workspace)
            .prepare_stack(false, &mut keep_going)
            .unwrap_err()
            .to_string();
        assert!(error.contains(category), "{message}: {error}");
    }
}

#[test]
fn initialized_empty_stack_needs_saved_matching_kms_config_to_resume() {
    let (_root, workspace) = fixture();
    fs::write(
        workspace.work_dir.join("export.json"),
        r#"{"version":3,"deployment":{"resources":[]}}"#,
    )
    .unwrap();
    let mut client = client(workspace.clone());
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
    client.prepare_stack(true, &mut keep_going).unwrap();
    client.prepare_stack(false, &mut keep_going).unwrap();
    fs::write(
        workspace.work_dir.join(format!("Pulumi.{STACK}.yaml")),
        "secretsprovider: passphrase\n",
    )
    .unwrap();
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
}

#[test]
fn preview_json_must_be_complete_and_structured() {
    for bad in [
        b"{".as_slice(),
        b"{}",
        b"[]",
        b"{\"changeSummary\":{\"create\":-1}}",
        b"{\"changeSummary\":{\"new-op\":1}}",
        b"{\"changeSummary\":{},\"steps\":null}",
        b"{\"changeSummary\":{},\"maybeCorrupt\":true}",
        b"{\"changeSummary\":{},\"diagnostics\":[{\"severity\":\"error\",\"message\":\"secret\"}]}",
    ] {
        let error = parse_preview(bad).unwrap_err().to_string();
        assert!(!error.contains("secret"));
    }
    let summary = parse_preview(&serde_json::to_vec(&preview_fixture()).unwrap()).unwrap();
    assert_eq!(summary.schema_version, 1);
    assert_eq!(summary.changes["create"], 1);
    assert_eq!(summary.resources.len(), 1);
    assert!(!serde_json::to_string(&summary).unwrap().contains(SECRET));
}

#[test]
fn empty_destroy_preview_does_not_authorize_an_up_plan() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    client.preview(&mut keep_going).unwrap();

    // Pulumi 3.268.0 returned exactly this digest when retrying destroy after
    // every resource had already been deleted. PreviewDigest's empty maps and
    // lists use omitempty: pkg/display/json.go at the v3.268.0 tag.
    for value in [
        json!({"duration":353875}),
        json!({"duration":0}),
        json!({"duration":1,"steps":[],"diagnostics":[],"maybeCorrupt":false}),
    ] {
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(workspace.work_dir.join("preview.json"), &bytes).unwrap();
        let summary = client.preview_destroy(&mut keep_going).unwrap();
        assert!(summary.changes.is_empty());
        assert!(summary.resources.is_empty());
        assert!(client.up(&mut keep_going).is_err());
        assert!(parse_preview(&bytes).is_err());
        assert!(client.preview(&mut keep_going).is_err());
        assert!(client.up(&mut keep_going).is_err());
    }
    client.destroy(&mut keep_going).unwrap();
    assert_eq!(args(&workspace)[0], "destroy");
}

#[test]
fn omitted_destroy_summary_requires_an_unambiguous_empty_digest() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    for value in [
        json!({}),
        json!({"steps":[]}),
        json!({"duration":null}),
        json!({"duration":"353875"}),
        json!({"duration":-1}),
        json!({"duration":1.5}),
        json!({"duration":1,"changeSummary":null}),
        json!({"duration":1,"steps":null}),
        json!({"duration":1,"steps":[{"op":"delete","urn":"urn:pulumi:zdn-test::zdn-foundation::aws:ec2/instance:Instance::host"}]}),
        json!({"duration":1,"maybeCorrupt":true}),
        json!({"duration":1,"maybeCorrupt":null}),
        json!({"duration":1,"diagnostics":null}),
        json!({"duration":1,"diagnostics":[{"severity":"error","message":SECRET}]}),
        json!({"duration":1,"unexpected":SECRET}),
    ] {
        fs::write(
            workspace.work_dir.join("preview.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let error = client.preview_destroy(&mut keep_going).unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert!(client.up(&mut keep_going).is_err());
    }
    fs::write(workspace.work_dir.join("preview.json"), "{\"duration\":").unwrap();
    assert!(client.preview_destroy(&mut keep_going).is_err());
}

#[test]
fn partial_preview_from_helper_is_not_reported_as_success() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    fs::write(
        workspace.work_dir.join("preview.json"),
        "{\"changeSummary\":",
    )
    .unwrap();
    assert!(client.preview(&mut keep_going).is_err());
}

#[test]
fn apply_requires_a_current_preview_and_consumes_its_plan() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    assert!(client.up(&mut keep_going).is_err());
    assert_eq!(args(&workspace)[0], "stack");

    client.preview(&mut keep_going).unwrap();
    let first = args(&workspace)[5].clone();
    client.preview(&mut keep_going).unwrap();
    let second = args(&workspace)[5].clone();
    assert_ne!(first, second);
    assert!(!Path::new(&first).exists());
    client.up(&mut keep_going).unwrap();
    assert_eq!(args(&workspace)[6], second);
    assert!(!Path::new(&second).exists());
    assert!(client.up(&mut keep_going).is_err());

    for invalidate in ["select", "refresh", "destroy-preview", "destroy"] {
        client.preview(&mut keep_going).unwrap();
        let path = args(&workspace)[5].clone();
        match invalidate {
            "select" => client.prepare_stack(false, &mut keep_going).unwrap(),
            "refresh" => client.refresh(&mut keep_going).unwrap(),
            "destroy-preview" => {
                client.preview_destroy(&mut keep_going).unwrap();
            }
            _ => client.destroy(&mut keep_going).unwrap(),
        }
        assert!(client.up(&mut keep_going).is_err(), "{invalidate}");
        assert!(!Path::new(&path).exists());
    }

    client.preview(&mut keep_going).unwrap();
    let path = args(&workspace)[5].clone();
    fs::write(workspace.work_dir.join("preview.json"), "{").unwrap();
    assert!(client.preview(&mut keep_going).is_err());
    assert!(client.up(&mut keep_going).is_err());
    assert!(!Path::new(&path).exists());
}

#[test]
fn preview_blocks_destructive_summary_steps_and_saved_plan_operations() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    for operation in [
        "delete",
        "replace",
        "create-replacement",
        "delete-replaced",
        "read-replacement",
        "discard",
        "discard-replaced",
        "import-replacement",
        "remove-pending-replace",
    ] {
        for location in ["summary", "step", "plan"] {
            let mut preview = preview_fixture();
            let mut plan = plan_fixture();
            match location {
                "summary" => preview["changeSummary"][operation] = json!(1),
                "step" => preview["steps"][0]["op"] = json!(operation),
                _ => {
                    let resource = plan["resourcePlans"]
                        .as_object_mut()
                        .unwrap()
                        .values_mut()
                        .next()
                        .unwrap();
                    resource["steps"] = json!([operation]);
                }
            }
            fs::write(
                workspace.work_dir.join("preview.json"),
                serde_json::to_vec(&preview).unwrap(),
            )
            .unwrap();
            fs::write(
                workspace.work_dir.join("plan.json"),
                serde_json::to_vec(&plan).unwrap(),
            )
            .unwrap();
            let error = client.preview(&mut keep_going).unwrap_err().to_string();
            assert!(!error.contains(SECRET));
            assert!(
                client.up(&mut keep_going).is_err(),
                "{operation} in {location}"
            );
            assert_eq!(args(&workspace)[0], "preview");
            assert!(!Path::new(&args(&workspace)[5]).exists());
        }
    }
    // Teardown still reports deletes: the safety gate is for foundation up.
    client.preview_destroy(&mut keep_going).unwrap();
}

#[test]
fn malformed_missing_foreign_or_modified_plans_never_apply() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    for plan in [
        json!({}),
        json!({"manifest":{},"resourcePlans":null}),
        json!({"manifest":{},"resourcePlans":{"urn:pulumi:foreign::other::type::name":{"steps":["create"]}}}),
        json!({"manifest":{},"resourcePlans":{"urn:pulumi:zdn-test::zdn-foundation::type::name":{"steps":"create"}}}),
        json!({"manifest":{},"resourcePlans":{"urn:pulumi:zdn-test::zdn-foundation::type::name":{"steps":[null]}}}),
        json!({"manifest":{},"resourcePlans":{"urn:pulumi:zdn-test::zdn-foundation::type::name":{"steps":["unknown"]}}}),
    ] {
        fs::write(
            workspace.work_dir.join("plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        assert!(client.preview(&mut keep_going).is_err());
        assert!(client.up(&mut keep_going).is_err());
    }
    // A successful CLI exit without a plan file is insufficient.
    fs::remove_file(workspace.work_dir.join("plan.json")).unwrap();
    assert!(client.preview(&mut keep_going).is_err());
    assert!(client.up(&mut keep_going).is_err());
    fs::write(
        workspace.work_dir.join("plan.json"),
        serde_json::to_vec(&plan_fixture()).unwrap(),
    )
    .unwrap();

    for mutation in ["bytes", "replace-file", "symlink", "project", "selection"] {
        client.preview(&mut keep_going).unwrap();
        let path = args(&workspace)[5].clone();
        match mutation {
            "bytes" => fs::write(&path, b"{}").unwrap(),
            "replace-file" => {
                fs::remove_file(&path).unwrap();
                fs::copy(workspace.work_dir.join("plan.json"), &path).unwrap();
            }
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink(workspace.work_dir.join("plan.json"), &path).unwrap();
            }
            "project" => fs::write(
                workspace.work_dir.join("Pulumi.yaml"),
                "name: zdn-foundation\nruntime: yaml\n# host setup changed\n",
            )
            .unwrap(),
            _ => client.workspace.aws.profile = "different".into(),
        }
        assert!(client.up(&mut keep_going).is_err(), "{mutation}");
        assert_eq!(args(&workspace)[0], "preview");
        fs::write(
            workspace.work_dir.join("Pulumi.yaml"),
            "name: zdn-foundation\nruntime: yaml\n",
        )
        .unwrap();
        client.workspace.aws.profile = "devnet".into();
    }
}

#[test]
fn failed_apply_requires_a_new_plan_and_removes_private_plan_bytes() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    client.preview(&mut keep_going).unwrap();
    let path = args(&workspace)[5].clone();
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\nprintf AccessDenied >&2\nexit 1\n",
    );
    assert!(client
        .up(&mut keep_going)
        .unwrap_err()
        .to_string()
        .contains("access-denied"));
    assert!(!Path::new(&path).exists());
    assert!(client
        .up(&mut keep_going)
        .unwrap_err()
        .to_string()
        .contains("preview"));
    assert!(!serde_json::to_string(&diagnostics(&workspace))
        .unwrap()
        .contains(SECRET));
}

#[test]
fn cancellation_and_progress_errors_allow_cli_checkpoint_before_exit() {
    for fail_progress in [false, true] {
        let (_root, workspace) = fixture();
        executable(
            &workspace.tools.executable,
            r#"#!/bin/sh
trap 'printf interrupted > interrupted; sleep 0.06; test -f provider-finished || exit 2; printf checkpoint > checkpoint; exit 130' INT
(sleep 0.04; touch provider-finished) &
touch started
while :; do sleep 0.01; done
"#,
        );
        let command = workspace
            .command(
                "graceful-stop",
                &[],
                ProcessLimits {
                    shutdown_grace: Duration::from_secs(1),
                    poll_interval: Duration::from_millis(5),
                    ..ProcessLimits::default()
                },
            )
            .unwrap();
        let error = runner()
            .run(&command, &mut || {
                if !workspace.work_dir.join("started").exists() {
                    Ok(RunControl::Continue)
                } else if fail_progress {
                    bail!("lease lost {SECRET}")
                } else {
                    Ok(RunControl::Cancel)
                }
            })
            .unwrap_err()
            .to_string();
        assert!(!error.contains(SECRET));
        assert_eq!(
            fs::read_to_string(workspace.work_dir.join("checkpoint")).unwrap(),
            "checkpoint"
        );
        assert_eq!(
            fs::read_to_string(workspace.work_dir.join("interrupted")).unwrap(),
            "interrupted"
        );
        assert_eq!(
            diagnostics(&workspace)[0]["result"],
            if fail_progress {
                "interrupted"
            } else {
                "cancelled"
            }
        );
    }
}

#[test]
fn output_limits_end_shutdown_grace_for_both_streams_and_all_stop_reasons() {
    for reason in ["cancelled", "timed out", "lease"] {
        for (redirect, count_field) in [("", "stdout_bytes"), (">&2", "stderr_bytes")] {
            let (_root, workspace) = fixture();
            executable(
                &workspace.tools.executable,
                &format!(
                    "#!/bin/sh\n\
                     trap 'touch interrupted; head -c 65536 /dev/zero {redirect}; sleep 1; touch grace-continued; exit 130' INT\n\
                     touch started\n\
                     while :; do sleep 0.01; done\n"
                ),
            );
            let command = workspace
                .command(
                    "shutdown-output",
                    &[],
                    ProcessLimits {
                        timeout: Duration::from_secs(if reason == "timed out" { 2 } else { 10 }),
                        shutdown_grace: Duration::from_secs(5),
                        max_output_bytes: 128,
                        poll_interval: Duration::from_millis(5),
                    },
                )
                .unwrap();
            let error = runner()
                .run(&command, &mut || {
                    if workspace.work_dir.join("started").exists() {
                        match reason {
                            "cancelled" => return Ok(RunControl::Cancel),
                            "lease" => bail!("lease lost {SECRET}"),
                            _ => {}
                        }
                    }
                    Ok(RunControl::Continue)
                })
                .unwrap_err()
                .to_string();
            assert!(error.contains(reason), "{reason}/{count_field}: {error}");
            assert!(workspace.work_dir.join("interrupted").exists());
            assert!(
                !workspace.work_dir.join("grace-continued").exists(),
                "{reason}/{count_field}: output overflow must end the grace period"
            );
            assert!(
                !workspace.work_dir.join(".zdn-pulumi-process.json").exists(),
                "cleanup must be acknowledged before returning"
            );
            let artifact = &diagnostics(&workspace)[0];
            assert_eq!(artifact[count_field], 128);
            assert_eq!(
                artifact["result"],
                match reason {
                    "cancelled" => "cancelled",
                    "timed out" => "timeout",
                    _ => "interrupted",
                }
            );
            assert!(!error.contains(SECRET));
            assert!(artifact.get("stdout").is_none());
            assert!(artifact.get("stderr").is_none());
        }
    }
}

#[test]
fn ignored_interrupt_escalates_after_bounded_grace_and_reaps_descendants() {
    let (_root, workspace) = fixture();
    executable(
        &workspace.tools.executable,
        r#"#!/bin/sh
trap 'touch interrupted' INT
(sleep 0.5; touch escaped) &
touch started
while :; do sleep 0.01; done
"#,
    );
    let command = workspace
        .command(
            "forced-stop",
            &[],
            ProcessLimits {
                shutdown_grace: Duration::from_millis(80),
                poll_interval: Duration::from_millis(5),
                ..ProcessLimits::default()
            },
        )
        .unwrap();
    let mut cancelled = None;
    assert!(runner()
        .run(&command, &mut || {
            if workspace.work_dir.join("started").exists() {
                cancelled.get_or_insert_with(Instant::now);
                Ok(RunControl::Cancel)
            } else {
                Ok(RunControl::Continue)
            }
        })
        .is_err());
    let elapsed = cancelled.unwrap().elapsed();
    assert!(elapsed >= command.limits.shutdown_grace);
    assert!(elapsed < Duration::from_secs(2));
    assert!(workspace.work_dir.join("interrupted").exists());
    std::thread::sleep(Duration::from_millis(550));
    assert!(!workspace.work_dir.join("escaped").exists());
}

#[test]
fn timeout_kills_cli_and_provider_process_group() {
    let (_root, workspace) = fixture();
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\n(sleep 0.5; touch escaped) &\nsleep 10\n",
    );
    let command = workspace
        .command(
            "timeout",
            &[],
            ProcessLimits {
                timeout: Duration::from_millis(40),
                poll_interval: Duration::from_millis(5),
                max_output_bytes: 1024,
                shutdown_grace: Duration::from_millis(80),
            },
        )
        .unwrap();
    let start = Instant::now();
    let error = runner()
        .run(&command, &mut keep_going)
        .unwrap_err()
        .to_string();
    assert!(error.contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(550));
    assert!(!workspace.work_dir.join("escaped").exists());
    assert_eq!(diagnostics(&workspace)[0]["result"], "timeout");
}

#[test]
fn cancellation_kills_descendants_and_heartbeat_failure_stops_execution() {
    let (_root, workspace) = fixture();
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\n(sleep 0.5; touch escaped) &\ntouch started\nsleep 10\n",
    );
    let command = workspace
        .command(
            "cancel",
            &[],
            ProcessLimits {
                poll_interval: Duration::from_millis(5),
                shutdown_grace: Duration::from_millis(80),
                ..ProcessLimits::default()
            },
        )
        .unwrap();
    let error = runner()
        .run(&command, &mut || {
            Ok(if workspace.work_dir.join("started").exists() {
                RunControl::Cancel
            } else {
                RunControl::Continue
            })
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("cancelled"));
    std::thread::sleep(Duration::from_millis(550));
    assert!(!workspace.work_dir.join("escaped").exists());
    let error = runner()
        .run(&command, &mut || bail!("lease failed {SECRET}"))
        .unwrap_err()
        .to_string();
    assert!(!error.contains(SECRET));
    assert!(error.contains("lease"));
}

#[test]
fn normal_cli_exit_cleans_up_leftover_provider_processes() {
    let (_root, workspace) = fixture();
    let scratch = workspace.work_dir.join("temporary");
    fs::create_dir(&scratch).unwrap();
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\nrmdir \"$TMPDIR\" || exit 1\n(sleep 0.5; touch escaped) &\nexit 0\n",
    );
    let mut command = workspace
        .command(
            "leftover",
            &[],
            ProcessLimits {
                poll_interval: Duration::from_millis(5),
                ..ProcessLimits::default()
            },
        )
        .unwrap();
    command
        .env
        .insert("TMPDIR".into(), scratch.into_os_string());
    assert!(runner().run(&command, &mut keep_going).unwrap().success);
    std::thread::sleep(Duration::from_millis(550));
    assert!(!workspace.work_dir.join("escaped").exists());
}

#[test]
fn output_flood_is_bounded_and_diagnostic_excludes_raw_bytes() {
    let (_root, workspace) = fixture();
    executable(
        &workspace.tools.executable,
        "#!/bin/sh\nhead -c 65536 /dev/zero\nsleep 10\n",
    );
    let command = workspace
        .command(
            "flood",
            &[],
            ProcessLimits {
                max_output_bytes: 128,
                poll_interval: Duration::from_millis(5),
                shutdown_grace: Duration::from_millis(80),
                ..ProcessLimits::default()
            },
        )
        .unwrap();
    assert!(runner()
        .run(&command, &mut keep_going)
        .unwrap_err()
        .to_string()
        .contains("output limit"));
    let artifact = &diagnostics(&workspace)[0];
    assert_eq!(artifact["stdout_bytes"], 128);
    assert_eq!(artifact["result"], "output-limit");
    assert!(artifact.get("stdout").is_none());
}

fn foundation_spec() -> FoundationSpec {
    FoundationSpec {
        scope: Scope {
            team_id: "team-test".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        network_id: Uuid::new_v4(),
        aws_profile: "devnet".into(),
        ami_id: "ami-1234567890abcdef0".into(),
        availability_zone: "us-east-1a".into(),
        size: Size::Medium,
        retain_chain_disk: true,
    }
}
fn output_fixture(spec: &FoundationSpec) -> Value {
    json!({"schema_version":1,"scope":spec.scope,"network_id":spec.network_id,"availability_zone":spec.availability_zone,"vpc_id":"vpc-12345678","private_subnet_id":"subnet-12345678","instance_id":"i-1234567890abcdef0","private_ip":"10.90.1.10","chain_volume_id":"vol-12345678","retain_chain_disk":true,"security_group_id":"sg-12345678","nat_gateway_id":"nat-12345678","eip_allocation_id":"eipalloc-12345678"})
}

#[test]
fn output_schema_version_scope_and_completeness_are_checked() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    let spec = foundation_spec();
    fs::write(
        workspace.work_dir.join("outputs.json"),
        serde_json::to_vec(&output_fixture(&spec)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        client.outputs(&spec, &mut keep_going).unwrap().network_id,
        spec.network_id
    );
    assert!(!args(&workspace).contains(&"--show-secrets".into()));
    for field in ["schema_version", "network_id", "instance_id"] {
        let mut output = output_fixture(&spec);
        output[field] = json!(SECRET);
        fs::write(
            workspace.work_dir.join("outputs.json"),
            serde_json::to_vec(&output).unwrap(),
        )
        .unwrap();
        let error = client
            .outputs(&spec, &mut keep_going)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(SECRET));
    }
    let mut wrong_spec = spec.clone();
    wrong_spec.scope.account_id = "222222222222".into();
    fs::remove_file(workspace.work_dir.join("args.bin")).unwrap();
    assert!(client.outputs(&wrong_spec, &mut keep_going).is_err());
    assert!(!workspace.work_dir.join("args.bin").exists());
}

struct UntrustedRunner;
impl PulumiRunner for UntrustedRunner {
    fn run(&self, _: &CommandSpec, _: &mut Progress<'_>) -> Result<ProcessOutput> {
        bail!("error includes {SECRET}");
    }
}
#[test]
fn errors_from_injected_runners_are_also_redacted() {
    let (_root, workspace) = fixture();
    let mut client = PulumiClient::new(workspace, UntrustedRunner).unwrap();
    assert!(!client
        .prepare_stack(false, &mut keep_going)
        .unwrap_err()
        .to_string()
        .contains(SECRET));
}

#[test]
fn malformed_limits_and_precancelled_jobs_do_not_spawn() {
    let (_root, workspace) = fixture();
    let mut command = workspace
        .command("limit", &[], ProcessLimits::default())
        .unwrap();
    command.limits.max_output_bytes = 0;
    assert!(runner().run(&command, &mut keep_going).is_err());
    command.limits.max_output_bytes = 1024;
    assert!(runner()
        .run(&command, &mut || Ok(RunControl::Cancel))
        .is_err());
    assert!(!workspace.work_dir.join("args.bin").exists());
    assert!(command
        .env
        .contains_key(&OsString::from("PULUMI_BACKEND_URL")));
}

#[test]
fn existing_local_config_cannot_override_verified_state_kms() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    client.prepare_stack(true, &mut keep_going).unwrap();
    fs::write(
        workspace.work_dir.join(format!("Pulumi.{STACK}.yaml")),
        "secretsprovider: passphrase\n",
    )
    .unwrap();
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
    assert!(client.up(&mut keep_going).is_err());
}

#[test]
fn stack_discovery_requires_valid_unique_project_scoped_results() {
    let (_root, workspace) = fixture();
    let client = client(workspace.clone());
    for (value, expected) in [
        (json!([]), false),
        (json!([{"name":STACK,"current":false}]), true),
        (
            json!([{"name":"zdn-foundation/zdn-test","current":false}]),
            true,
        ),
        (
            json!([{"name":"organization/zdn-foundation/zdn-test","current":false}]),
            true,
        ),
        (json!([{"name":"other-stack","current":false}]), false),
    ] {
        fs::write(
            workspace.work_dir.join("stacks.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(client.stack_exists(&mut keep_going).unwrap(), expected);
    }
    assert_eq!(
        args(&workspace),
        [
            "stack",
            "ls",
            "--project",
            "zdn-foundation",
            "--output",
            "json",
            "--non-interactive",
            "--color",
            "never"
        ]
    );
    for value in [
        json!({}),
        json!([{}]),
        json!([{"name":STACK}]),
        json!([{"name":"other/zdn-test","current":false}]),
        json!([{"name":"bad name","current":false}]),
        json!([{"name":STACK,"current":false,"project":"foreign"}]),
        json!([{"name":STACK,"current":false},{"name":"zdn-foundation/zdn-test","current":false}]),
    ] {
        fs::write(
            workspace.work_dir.join("stacks.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(client.stack_exists(&mut keep_going).is_err());
    }
    fs::write(workspace.work_dir.join("stacks.json"), "[").unwrap();
    assert!(client.stack_exists(&mut keep_going).is_err());
}

fn provider_fixture() -> Value {
    json!({"urn":"urn:pulumi:zdn-test::zdn-foundation::pulumi:providers:aws::provider","type":"pulumi:providers:aws","id":"provider-id","inputs":{"profile":"devnet","region":"us-east-1","allowedAccountIds":["123456789012"],"version":zdn::infra::AWS_PROVIDER_VERSION}})
}

fn checked_provider_fixture(encoded: bool) -> Value {
    // Defaults and their string encoding follow AWS v7.50.0 CheckConfig:
    // https://github.com/pulumi/pulumi-aws/blob/v7.50.0/provider/resources.go
    // https://github.com/pulumi/pulumi-aws/blob/v7.50.0/provider/configure_test.go
    let mut provider = provider_fixture();
    provider["inputs"]["skipRegionValidation"] = json!(true);
    provider["inputs"]["skipCredentialsValidation"] = json!(false);
    provider["inputs"]["__defaults"] = json!(["skipCredentialsValidation", "skipRegionValidation"]);
    if encoded {
        provider["inputs"]["skipRegionValidation"] = json!("true");
        provider["inputs"]["skipCredentialsValidation"] = json!("false");
        provider["inputs"]["allowedAccountIds"] = json!("[\"123456789012\"]");
    }
    provider
}

fn export_with_provider(provider: Value, pending: bool) -> Value {
    let mut export = export_fixture();
    if pending {
        export["deployment"]["pending_operations"] =
            json!([{"resource":provider,"type":"updating"}]);
    } else {
        export["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
            .push(provider);
    }
    export["deployment"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "urn":"urn:pulumi:zdn-test::zdn-foundation::aws:ec2/instance:Instance::host",
            "type":"aws:ec2/instance:Instance",
            "provider":"urn:pulumi:zdn-test::zdn-foundation::pulumi:providers:aws::provider::provider-id",
        }));
    export
}

fn ownership_defaults() -> Value {
    json!({"tags": {
        "zdn:bootstrap": "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
        "zdn:team-id": "test-team",
        "zdn:managed-by": "zdn"
    }})
}

fn set_project_defaults(workspace: &PulumiWorkspace, defaults: Value) {
    let path = workspace.work_dir.join("Pulumi.yaml");
    let mut project: Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
    project["resources"]["provider"]["type"] = json!("pulumi:providers:aws");
    project["resources"]["provider"]["properties"]["defaultTags"] = defaults;
    fs::write(path, serde_yaml::to_string(&project).unwrap()).unwrap();
}

#[test]
fn selected_stack_accepts_exact_launch_ownership_defaults() {
    let (_root, workspace) = fixture();
    set_project_defaults(&workspace, ownership_defaults());
    let mut client = client(workspace.clone());
    for encoded in [false, true] {
        for pending in [false, true] {
            let mut provider = checked_provider_fixture(encoded);
            provider["inputs"]["defaultTags"] = if encoded {
                json!(ownership_defaults().to_string())
            } else {
                ownership_defaults()
            };
            fs::write(
                workspace.work_dir.join("export.json"),
                serde_json::to_vec(&export_with_provider(provider, pending)).unwrap(),
            )
            .unwrap();
            client.prepare_stack(false, &mut keep_going).unwrap();
            client.preview(&mut keep_going).unwrap();
            client.up(&mut keep_going).unwrap();
            client.prepare_stack(false, &mut keep_going).unwrap();
            client.destroy(&mut keep_going).unwrap();
            assert_eq!(args(&workspace)[0], "destroy");
        }
    }
}

#[test]
fn partial_foundation_without_ownership_defaults_can_retry_and_teardown() {
    let (_root, workspace) = fixture();
    set_project_defaults(&workspace, ownership_defaults());
    let mut client = client(workspace.clone());
    fs::write(
        workspace.work_dir.join("export.json"),
        serde_json::to_vec(&export_with_provider(checked_provider_fixture(true), false)).unwrap(),
    )
    .unwrap();
    client.prepare_stack(false, &mut keep_going).unwrap();
    client.preview(&mut keep_going).unwrap();
    client.up(&mut keep_going).unwrap();
    client.prepare_stack(false, &mut keep_going).unwrap();
    client.destroy(&mut keep_going).unwrap();
}

#[test]
fn selected_stack_rejects_changed_missing_and_extra_ownership_defaults() {
    let (_root, workspace) = fixture();
    set_project_defaults(&workspace, ownership_defaults());
    let mut client = client(workspace.clone());
    let mut invalid = vec![json!(null), json!("not JSON"), json!({"tags": {}})];
    for (key, value) in [
        (
            "zdn:bootstrap",
            json!("a81c4e9b-4612-4e0d-a3fa-c4ab68a04154"),
        ),
        ("zdn:team-id", json!("different-team")),
        ("zdn:managed-by", json!("other-tool")),
        ("Name", json!("would-overwrite-disk-name")),
    ] {
        let mut defaults = ownership_defaults();
        defaults["tags"][key] = value;
        invalid.push(defaults);
    }
    let mut missing = ownership_defaults();
    missing["tags"]
        .as_object_mut()
        .unwrap()
        .remove("zdn:bootstrap");
    invalid.push(missing);
    for defaults in invalid {
        for pending in [false, true] {
            let mut provider = checked_provider_fixture(true);
            provider["inputs"]["defaultTags"] = defaults.clone();
            fs::write(
                workspace.work_dir.join("export.json"),
                serde_json::to_vec(&export_with_provider(provider, pending)).unwrap(),
            )
            .unwrap();
            let error = client
                .prepare_stack(false, &mut keep_going)
                .unwrap_err()
                .to_string();
            assert!(error.contains("defaultTags"), "{error}");
            assert!(client.up(&mut keep_going).is_err());
            assert!(client.destroy(&mut keep_going).is_err());
            assert_eq!(args(&workspace)[1], "export");
        }
    }
}

#[test]
fn generated_provider_defaults_are_limited_to_valid_ownership_tags() {
    let (_root, workspace) = fixture();
    let mut extra = ownership_defaults();
    extra["tags"]["Name"] = json!("would-overwrite-disk-name");
    let mut nil = ownership_defaults();
    nil["tags"]["zdn:bootstrap"] = json!(Uuid::nil().to_string());
    for defaults in [
        extra,
        nil,
        json!({"tags": {"zdn:team-id": "test-team", "zdn:managed-by": "zdn"}}),
        json!({"tags": {"zdn:team-id": "test-team", "zdn:managed-by": "zdn", "zdn:bootstrap": "invalid"}}),
        json!({"tags": {"zdn:team-id": "test-team", "zdn:managed-by": "other", "zdn:bootstrap": "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153"}}),
    ] {
        set_project_defaults(&workspace, defaults);
        assert!(PulumiClient::new(workspace.clone(), runner()).is_err());
    }
}

#[test]
fn checked_provider_defaults_allow_subsequent_apply_and_teardown() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    for encoded in [false, true] {
        for pending in [false, true] {
            for version in [3, 4] {
                let mut export = export_with_provider(checked_provider_fixture(encoded), pending);
                export["version"] = json!(version);
                fs::write(
                    workspace.work_dir.join("export.json"),
                    serde_json::to_vec(&export).unwrap(),
                )
                .unwrap();
                client.prepare_stack(false, &mut keep_going).unwrap();
                client.preview(&mut keep_going).unwrap();
                client.up(&mut keep_going).unwrap();
                assert_eq!(args(&workspace)[0], "up");
                client.prepare_stack(false, &mut keep_going).unwrap();
                client.destroy(&mut keep_going).unwrap();
                assert_eq!(args(&workspace)[0], "destroy");
            }
        }
    }
}

#[test]
fn contrary_or_malformed_provider_defaults_block_apply_and_teardown() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    for (key, expected) in [
        ("skipRegionValidation", true),
        ("skipCredentialsValidation", false),
    ] {
        for value in [
            json!(!expected),
            json!((!expected).to_string()),
            json!(expected.to_string().to_uppercase()),
            json!(format!(" {expected}")),
            json!(format!("\"{expected}\"")),
            json!(null),
            json!(0),
            json!([]),
            json!({"value":expected}),
        ] {
            for pending in [false, true] {
                let mut provider = checked_provider_fixture(true);
                provider["inputs"][key] = value.clone();
                let export = export_with_provider(provider, pending);
                fs::write(
                    workspace.work_dir.join("export.json"),
                    serde_json::to_vec(&export).unwrap(),
                )
                .unwrap();
                let error = client
                    .prepare_stack(false, &mut keep_going)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains(key), "{key}={value}, pending={pending}");
                assert!(client.up(&mut keep_going).is_err());
                assert!(client.destroy(&mut keep_going).is_err());
                assert_eq!(args(&workspace)[1], "export");
            }
        }
    }
}

#[test]
fn checked_defaults_do_not_weaken_provider_scope_and_override_guards() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    for (field, value) in [
        ("profile", json!("other")),
        ("region", json!("us-west-2")),
        ("allowedAccountIds", json!(["222222222222"])),
        ("allowedAccountIds", json!("[\"222222222222\"]")),
        ("allowedAccountIds", json!("not JSON")),
        ("version", json!("99.0.0")),
        ("endpoints", json!([])),
        ("assumeRole", json!({"roleArn":SECRET})),
        ("skipRequestingAccountId", json!("true")),
        ("defaultTags", ownership_defaults()),
    ] {
        for pending in [false, true] {
            let mut provider = checked_provider_fixture(true);
            provider["inputs"][field] = value.clone();
            let export = export_with_provider(provider, pending);
            fs::write(
                workspace.work_dir.join("export.json"),
                serde_json::to_vec(&export).unwrap(),
            )
            .unwrap();
            let error = client
                .prepare_stack(false, &mut keep_going)
                .unwrap_err()
                .to_string();
            assert!(!error.contains(SECRET));
            assert!(client.up(&mut keep_going).is_err());
            assert!(client.destroy(&mut keep_going).is_err());
            assert_eq!(args(&workspace)[1], "export");
        }
    }
}

#[test]
fn selected_stack_checks_saved_provider_account_region_profile_version_and_overrides() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    let mut export = export_fixture();
    export["deployment"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(provider_fixture());
    for string_accounts in [false, true] {
        let mut value = export.clone();
        if string_accounts {
            value["deployment"]["resources"][1]["inputs"]["allowedAccountIds"] =
                json!("[\"123456789012\"]");
        }
        fs::write(
            workspace.work_dir.join("export.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        client.prepare_stack(false, &mut keep_going).unwrap();
    }
    for (field, value) in [
        ("profile", json!("other")),
        ("region", json!("us-west-2")),
        ("allowedAccountIds", json!(["222222222222"])),
        ("version", json!("99.0.0")),
        ("endpoints", json!([])),
        ("assumeRole", json!({"roleArn":SECRET})),
    ] {
        let mut value_export = export.clone();
        value_export["deployment"]["resources"][1]["inputs"][field] = value;
        fs::write(
            workspace.work_dir.join("export.json"),
            serde_json::to_vec(&value_export).unwrap(),
        )
        .unwrap();
        let error = client
            .prepare_stack(false, &mut keep_going)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(SECRET));
        assert!(client.destroy(&mut keep_going).is_err());
    }
}
#[test]
fn pending_resources_and_provider_references_cannot_bypass_selection_guard() {
    let (_root, workspace) = fixture();
    let mut client = client(workspace.clone());
    let mut export = export_fixture();
    export["deployment"]["pending_operations"] =
        json!([{"resource":provider_fixture(),"type":"creating"}]);
    export["deployment"]["pending_operations"][0]["resource"]["inputs"]["profile"] = json!("other");
    fs::write(
        workspace.work_dir.join("export.json"),
        serde_json::to_vec(&export).unwrap(),
    )
    .unwrap();
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
    let mut export = export_fixture();
    export["deployment"]["resources"].as_array_mut().unwrap().push(json!({"urn":"urn:pulumi:zdn-test::zdn-foundation::aws:ec2/instance:Instance::host","type":"aws:ec2/instance:Instance","provider":"urn:pulumi:foreign::project::pulumi:providers:aws::other::id"}));
    fs::write(
        workspace.work_dir.join("export.json"),
        serde_json::to_vec(&export).unwrap(),
    )
    .unwrap();
    assert!(client.prepare_stack(false, &mut keep_going).is_err());
}
