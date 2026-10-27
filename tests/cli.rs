//! Product command boundaries. All effects stay in temporary local directories.

#[cfg(unix)]
#[path = "support/native_exec.rs"]
mod native_exec;

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture {
    temp: tempfile::TempDir,
    source: PathBuf,
    config: PathBuf,
    state: PathBuf,
    snapshot: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("project");
        fs::create_dir(&source).unwrap();
        let fixture = Self {
            config: source.join("devnet.yaml"),
            state: temp.path().join("state"),
            snapshot: temp.path().join("snapshot"),
            source,
            temp,
        };
        fixture.git(&["init", "-q", "--initial-branch=feature"]);
        fs::write(fixture.source.join("README.md"), "tiny source fixture\n").unwrap();
        fixture.git(&["add", "README.md"]);
        fixture.git(&["commit", "-qm", "initial fixture"]);
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .current_dir(self.config.parent().unwrap())
            .stdin(Stdio::null())
            .env("XDG_DATA_HOME", self.temp.path().join("xdg-data"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0");
        command
    }

    fn with_external_config() -> Self {
        let mut fixture = Self::new();
        let directory = fixture.temp.path().join("config");
        fs::create_dir(&directory).unwrap();
        fixture.config = directory.join("devnet.yaml");
        fixture
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "zdn {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "zdn {args:?} did not return JSON: {error}; {:?}",
                output.stdout
            )
        })
    }

    fn fail(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            !output.status.success(),
            "zdn {args:?} unexpectedly succeeded"
        );
        String::from_utf8(output.stderr).unwrap()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(&self.source)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .args([
                "-c",
                "user.name=zdn fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "maintenance.auto=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn local_init(&self) -> Value {
        self.ok(&["init", "--source", ".", "--name", "my-feature"])
    }

    fn bind(&self) -> Value {
        self.ok(&self.binding_args())
    }

    fn binding_args(&self) -> Vec<&str> {
        vec![
            "identity",
            "bind",
            "--state-dir",
            text(&self.state),
            "--team-id",
            "test-team",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
        ]
    }

    fn capture(&self) -> Value {
        self.ok(&["snapshot", "--output", text(&self.snapshot)])
    }

    fn create_receipt(&self) -> Value {
        self.ok(&self.receipt_create_args())
    }

    fn receipt_create_args(&self) -> Vec<&str> {
        vec![
            "receipt",
            "create",
            "--state-dir",
            text(&self.state),
            "--team-id",
            "test-team",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
            "--snapshot",
            text(&self.snapshot),
        ]
    }

    fn resume_args<'a>(&'a self, id: &'a str) -> Vec<&'a str> {
        vec![
            "receipt",
            "resume-plan",
            id,
            "--state-dir",
            text(&self.state),
            "--snapshot",
            text(&self.snapshot),
        ]
    }

    fn edit_config(&self, edit: impl FnOnce(&mut Value)) {
        let mut value: Value = serde_yaml::from_slice(&fs::read(&self.config).unwrap()).unwrap();
        edit(&mut value);
        fs::write(&self.config, serde_yaml::to_string(&value).unwrap()).unwrap();
    }
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn assert_capabilities(output: &Value, supported: bool) {
    let capabilities = &output["capabilities"];
    assert_eq!(capabilities["apiVersion"], "zdn-capabilities/v1alpha1");
    assert_eq!(capabilities["configurationValid"], true);
    assert_eq!(capabilities["requestedServicesSupported"], supported);
    assert_eq!(
        capabilities["deploymentPrerequisites"]["status"],
        "unchecked"
    );
    assert_eq!(capabilities["liveReadinessChecked"], false);
    assert_eq!(capabilities["paymentQualification"], "pending");
    assert_eq!(capabilities["launchReady"], false);
    assert_eq!(
        capabilities["unsupportedServices"]
            .as_array()
            .unwrap()
            .is_empty(),
        supported
    );
}

fn tree(root: &Path) -> BTreeMap<PathBuf, (bool, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, found: &mut BTreeMap<PathBuf, (bool, Vec<u8>)>) {
        for item in fs::read_dir(path).unwrap() {
            let item = item.unwrap();
            let path = item.path();
            let is_dir = item.file_type().unwrap().is_dir();
            found.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                (
                    is_dir,
                    if is_dir {
                        vec![]
                    } else {
                        fs::read(&path).unwrap()
                    },
                ),
            );
            if is_dir {
                visit(root, &path, found);
            }
        }
    }
    let mut found = BTreeMap::new();
    visit(root, root, &mut found);
    found
}

#[test]
fn init_check_and_plan_show_real_defaults_without_claiming_launch_readiness() {
    let fixture = Fixture::new();
    let init = fixture.local_init();
    assert_eq!(init["launchReady"], false);
    let check = fixture.ok(&["check"]);
    let plan = fixture.ok(&["plan"]);
    assert_eq!(check["valid"], true);
    assert_eq!(check["launchReady"], false);
    assert_eq!(check["configSha256"], init["configSha256"]);
    assert_eq!(plan["configSha256"], check["configSha256"]);
    assert_eq!(plan["config"]["node"]["adapter"], "zakura");
    assert_eq!(plan["config"]["node"]["resources"]["preset"], "medium");
    assert_eq!(plan["config"]["network"]["nodes"], 3);
    assert_eq!(plan["config"]["network"]["mining"]["interval"], "25s");
    assert_eq!(plan["config"]["access"]["visibility"], "private");
    assert_eq!(
        plan["config"]["services"],
        serde_json::json!({
            "wallet": false, "lightwallet": false, "faucet": false
        })
    );
    for output in [&init, &check, &plan] {
        assert_capabilities(output, true);
    }
    assert_eq!(plan["lightwalletImplementation"], "lightwalletd");
    assert_eq!(plan["chainRequest"]["paymentPool"], "ironwood");
    assert_eq!(plan["chainRequest"]["kind"], "custom-testnet");
    assert_eq!(plan["chainRequest"]["activationHeights"]["NU6.3"], 1);
    assert_eq!(plan["perNode"]["instance"], "m7a.xlarge");
    assert_eq!(plan["perNode"]["qualified"], false);
    assert_eq!(plan["launchReady"], false);
    assert!(!fixture.state.exists());
}

#[test]
fn init_node_count_is_explicit_bounded_and_keeps_the_three_node_default() {
    for nodes in ["1", "2", "3", "0", "4"] {
        let fixture = Fixture::new();
        let args = ["init", "--release", "fixture", "--nodes", nodes];
        if ["0", "4"].contains(&nodes) {
            fixture.fail(&args);
            assert!(!fixture.config.exists());
        } else {
            fixture.ok(&args);
            assert_eq!(
                fixture.ok(&["plan"])["config"]["network"]["nodes"],
                nodes.parse::<u16>().unwrap()
            );
            assert_eq!(fixture.ok(&["check"])["valid"], true);
        }
    }
}

#[test]
fn plan_and_check_leave_configuration_source_and_state_untouched() {
    let fixture = Fixture::new();
    fixture.local_init();
    let before = tree(fixture.temp.path());
    fixture.ok(&["plan"]);
    fixture.ok(&["check"]);
    assert_eq!(tree(fixture.temp.path()), before);
    assert!(!fixture.temp.path().join("xdg-data").exists());
}

#[test]
fn init_selects_a_source_recipe_without_changing_existing_defaults() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.source.join("node/zakura/docker")).unwrap();
    fs::write(
        fixture.source.join("node/zakura/docker/Dockerfile"),
        "FROM scratch AS runtime\n",
    )
    .unwrap();
    fixture.git(&["add", "."]);
    fixture.git(&["commit", "-qm", "monorepo recipe"]);
    fixture.ok(&[
        "init",
        "--source",
        ".",
        "--dockerfile",
        "node/zakura/docker/Dockerfile",
        "--build-context",
        "node/zakura",
        "--nodes",
        "1",
    ]);
    let plan = fixture.ok(&["plan"]);
    assert_eq!(
        plan["config"]["node"]["build"]["dockerfile"],
        "node/zakura/docker/Dockerfile"
    );
    assert_eq!(plan["config"]["node"]["build"]["context"], "node/zakura");
    let rendered = fixture.ok(&["devnet", "render"]);
    assert_eq!(
        rendered["buildContract"]["recipe"]["dockerfile"],
        "node/zakura/docker/Dockerfile"
    );
    assert_eq!(
        rendered["buildContract"]["recipe"]["context"],
        "node/zakura"
    );

    let default = Fixture::new();
    default.local_init();
    assert_eq!(
        default.ok(&["plan"])["config"]["node"]["build"]["dockerfile"],
        "docker/Dockerfile"
    );
    for args in [
        vec!["init", "--release", "fixture", "--dockerfile", "Dockerfile"],
        vec!["init", "--release", "fixture", "--build-context", "."],
        vec!["init", "--source", ".", "--dockerfile", "../Dockerfile"],
        vec!["init", "--source", ".", "--build-context", "../context"],
    ] {
        let invalid = Fixture::new();
        invalid.fail(&args);
        assert!(!invalid.config.exists());
    }
}

#[test]
fn source_release_and_image_conflicts_fail_before_writing_config() {
    let fixture = Fixture::new();
    for args in [
        vec!["init", "--source", ".", "--release", "v0.1.0"],
        vec![
            "init",
            "--release",
            "v0.1.0",
            "--image",
            "candidate@sha256:invalid",
        ],
        vec!["init", "--revision", "HEAD"],
    ] {
        fixture.fail(&args);
        assert!(!fixture.config.exists());
    }
}

#[test]
fn init_preserves_an_existing_config_byte_for_byte() {
    let fixture = Fixture::new();
    fixture.local_init();
    let before = fs::read(&fixture.config).unwrap();
    for preset in ["node-only", "lightwallet", "planned"] {
        let error = fixture.fail(&[
            "init",
            "--source",
            ".",
            "--name",
            "replacement",
            "--service-preset",
            preset,
        ]);
        assert!(error.contains("never overwritten"));
        assert_eq!(fs::read(&fixture.config).unwrap(), before);
    }
}

#[test]
fn service_presets_report_support_offline_without_home_or_external_tools() {
    for (preset, wallet, lightwallet, faucet) in [
        ("node-only", false, false, false),
        ("lightwallet", false, true, false),
        ("planned", true, true, true),
    ] {
        let fixture = Fixture::new();
        let before = tree(fixture.temp.path());
        let run = |args: &[&str]| {
            let output = fixture
                .command()
                .env_remove("HOME")
                .env_remove("XDG_DATA_HOME")
                .env_remove("AWS_PROFILE")
                .env_remove("AWS_ACCESS_KEY_ID")
                .env_remove("AWS_SECRET_ACCESS_KEY")
                .env("PATH", fixture.temp.path().join("no-tools"))
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice::<Value>(&output.stdout).unwrap()
        };
        let init = run(&["init", "--release", "v0.1.0", "--service-preset", preset]);
        let saved = fs::read(&fixture.config).unwrap();
        let check = run(&["check"]);
        let plan = run(&["plan"]);
        assert_eq!(check["valid"], true);
        assert_eq!(init["configSha256"], check["configSha256"]);
        assert_eq!(check["configSha256"], plan["configSha256"]);
        assert_eq!(
            plan["config"]["services"],
            serde_json::json!({
                "wallet": wallet, "lightwallet": lightwallet, "faucet": faucet
            })
        );
        for output in [&init, &check, &plan] {
            assert_capabilities(output, preset != "planned");
        }
        assert_eq!(fs::read(&fixture.config).unwrap(), saved);
        fs::remove_file(&fixture.config).unwrap();
        assert_eq!(tree(fixture.temp.path()), before);
    }
}

#[test]
fn legacy_omitted_services_remain_valid_and_keep_the_explicit_fingerprint() {
    let fixture = Fixture::new();
    let init = fixture.ok(&["init", "--release", "v0.1.0", "--service-preset", "planned"]);
    for services in [None, Some(serde_json::json!({"wallet": true}))] {
        fixture.edit_config(|config| {
            if let Some(services) = services {
                config["services"] = services;
            } else {
                config.as_object_mut().unwrap().remove("services");
            }
        });
        let check = fixture.ok(&["check"]);
        let plan = fixture.ok(&["plan"]);
        assert_eq!(check["valid"], true);
        assert_eq!(check["configSha256"], init["configSha256"]);
        assert_eq!(plan["configSha256"], init["configSha256"]);
        assert_capabilities(&check, false);
        assert_capabilities(&plan, false);
        assert_eq!(
            plan["config"]["services"],
            serde_json::json!({
                "wallet": true, "lightwallet": true, "faucet": true
            })
        );
    }
}

#[test]
fn init_help_and_invalid_service_preset_are_side_effect_free() {
    let fixture = Fixture::new();
    let before = tree(fixture.temp.path());
    let output = fixture.run(&["init", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for text in [
        "--service-preset",
        "node-only",
        "lightwallet",
        "planned",
        "unsupported",
    ] {
        assert!(help.contains(text), "{help}");
    }
    let error = fixture.fail(&["init", "--release", "v0.1.0", "--service-preset", "unknown"]);
    assert!(error.contains("invalid value"), "{error}");
    assert_eq!(tree(fixture.temp.path()), before);
}

#[test]
fn machine_results_preserve_local_payloads_and_frame_jsonl_events() {
    for format in ["json", "jsonl"] {
        let fixture = Fixture::new();
        let init = fixture.run(&["--format", format, "init", "--release", "v0.1.0"]);
        assert!(init.status.success());
        assert!(init.stderr.is_empty());
        let parse = |output: &Output| -> Vec<Value> {
            if format == "json" {
                vec![serde_json::from_slice(&output.stdout).unwrap()]
            } else {
                String::from_utf8(output.stdout.clone())
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            }
        };
        let initial = parse(&init);
        for command in ["check", "plan"] {
            let legacy = fixture.ok(&[command]);
            let output = fixture.run(&["--format", format, command]);
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            let records = parse(&output);
            assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
            if format == "jsonl" {
                assert_eq!(records[0]["type"], "command-started");
                assert_eq!(records[0]["outcome"], "running");
                assert_eq!(records[0]["command"], command);
            }
            let result = records.last().unwrap();
            assert_eq!(result["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(result["type"], "result");
            assert_eq!(result["outcome"], "succeeded");
            assert_eq!(result["command"], command);
            assert!(result["error"].is_null());
            assert!(result["networkId"].is_null() && result["operationId"].is_null());
            assert_eq!(result["data"], legacy);
            assert_eq!(
                result["data"]["configSha256"],
                initial.last().unwrap()["data"]["configSha256"]
            );
        }
        // Explicit human mode is the compatibility path, not a new envelope.
        assert_eq!(
            fixture.ok(&["--format", "human", "check"]),
            fixture.ok(&["check"])
        );
    }
}

#[test]
fn machine_errors_redact_inputs_and_never_execute_unsupported_commands() {
    let fixture = Fixture::new();
    let secret = "test-only-secret-must-not-be-echoed";
    let before = tree(fixture.temp.path());
    for (arguments, expected_code, exit) in [
        (
            vec!["--format", "json", "init", "--service-preset", secret],
            "invalid-arguments",
            2,
        ),
        (
            vec!["--format=json", "init", "--source", secret],
            "initialization-failed",
            1,
        ),
        (
            vec![
                "--noninteractive",
                "--format=json",
                "check",
                "--config",
                secret,
            ],
            "configuration-check-failed",
            1,
        ),
        (
            vec!["--format", "json", "up", "--yes"],
            "devnet-up-failed",
            1,
        ),
        (
            vec!["--format", "json", "__credentials", "--request", secret],
            "unsupported-format-command",
            1,
        ),
    ] {
        let output = fixture
            .command()
            .env("PATH", fixture.temp.path().join("no-tools"))
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{arguments:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["type"], "result");
        assert_eq!(record["outcome"], "failed");
        assert!(record["data"].is_null());
        assert_eq!(record["error"]["code"], expected_code);
        assert_eq!(record["error"]["retryClassification"], "blocked");
    }
    assert_eq!(tree(fixture.temp.path()), before);
    fixture.local_init();
    fs::write(&fixture.config, format!("unknown-secret-field: {secret}\n")).unwrap();
    let saved = fs::read(&fixture.config).unwrap();
    for (command, expected_code) in [
        ("check", "configuration-check-failed"),
        ("plan", "plan-failed"),
    ] {
        let output = fixture.run(&["--format", "jsonl", command]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains(secret));
        let records: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["type"], "command-started");
        assert_eq!(records[1]["error"]["code"], expected_code);
        assert_eq!(records[1]["outcome"], "failed");
    }
    assert_eq!(fs::read(&fixture.config).unwrap(), saved);
}

#[test]
fn machine_discovery_errors_are_fixed_and_reject_lifecycle_progress_files() {
    for format in ["json", "jsonl"] {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state-SECRET");
        for (args, code) in [
            (
                vec![
                    "devnet",
                    "list",
                    "--profile",
                    "SECRET",
                    "--state-dir",
                    state.to_str().unwrap(),
                ],
                "devnet-list-failed",
            ),
            (
                vec![
                    "devnet",
                    "status",
                    "SECRET",
                    "--state-dir",
                    state.to_str().unwrap(),
                ],
                "devnet-status-failed",
            ),
            (
                vec![
                    "devnet",
                    "health",
                    "SECRET",
                    "--state-dir",
                    state.to_str().unwrap(),
                ],
                "devnet-health-failed",
            ),
            (vec!["doctor"], "doctor-failed"),
            (
                vec![
                    "package",
                    "verify",
                    "--manifest",
                    "SECRET",
                    "--sha256",
                    "SECRET",
                ],
                "package-verification-failed",
            ),
            (
                vec![
                    "package",
                    "export",
                    "--manifest",
                    "SECRET",
                    "--sha256",
                    "SECRET",
                    "--output",
                    "exported",
                ],
                "package-export-failed",
            ),
            (
                vec![
                    "release",
                    "verify",
                    "--catalog",
                    "SECRET",
                    "--signature",
                    "SECRET",
                    "--trusted-key",
                    "SECRET",
                ],
                "release-verification-failed",
            ),
            (
                vec![
                    "release",
                    "resolve",
                    "--catalog",
                    "SECRET",
                    "--signature",
                    "SECRET",
                    "--trusted-key",
                    "SECRET",
                    "--release",
                    "SECRET",
                    "--output",
                    "selected",
                ],
                "release-resolution-failed",
            ),
            (
                vec![
                    "release",
                    "sign",
                    "--catalog",
                    "SECRET",
                    "--key",
                    "SECRET",
                    "--output",
                    "catalog.sig",
                ],
                "release-signing-failed",
            ),
        ] {
            for progress in [false, true] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
                command
                    .env_clear()
                    .env("PATH", "")
                    .current_dir(root.path())
                    .args(["--format", format]);
                let progress_file = root.path().join("progress.jsonl");
                if progress {
                    command.arg("--progress-file").arg(&progress_file);
                }
                let output = command.args(&args).output().unwrap();
                assert_eq!(output.status.code(), Some(1));
                assert!(output.stderr.is_empty());
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(!text.contains("SECRET"));
                let records: Vec<Value> = if format == "json" {
                    vec![serde_json::from_str(&text).unwrap()]
                } else {
                    text.lines()
                        .map(|s| serde_json::from_str(s).unwrap())
                        .collect()
                };
                assert_eq!(
                    records.len(),
                    if !progress && format == "jsonl" { 2 } else { 1 }
                );
                let result = records.last().unwrap();
                assert_eq!(result["type"], "result");
                assert_eq!(result["outcome"], "failed");
                assert_eq!(
                    result["error"]["code"],
                    if progress {
                        "unsupported-progress-command"
                    } else {
                        code
                    }
                );
                assert_eq!(result["error"]["retryClassification"], "blocked");
                assert!(result["data"].is_null());
                assert!(result["networkId"].is_null());
                assert!(result["operationId"].is_null());
                assert!(!progress_file.exists());
                for output in ["exported", "selected", "catalog.sig"] {
                    assert!(!root.path().join(output).exists());
                }
            }
        }
    }
}

#[test]
#[cfg(unix)]
fn lifecycle_progress_rejects_existing_paths_and_unsupported_commands_before_execution() {
    use std::os::unix::fs::symlink;
    for kind in [
        "file",
        "symlink",
        "dangling",
        "directory",
        "missing-parent",
        "local",
        "human",
    ] {
        let f = Fixture::new();
        let target = f.temp.path().join("target");
        fs::write(&target, b"do not replace").unwrap();
        let path = f.temp.path().join("events");
        match kind {
            "file" => fs::write(&path, b"existing report").unwrap(),
            "symlink" => symlink(&target, &path).unwrap(),
            "dangling" => symlink(f.temp.path().join("absent"), &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            _ => (),
        }
        let path = if kind == "missing-parent" {
            path.join("events")
        } else {
            path
        };
        let mut command = f.command();
        if kind != "human" {
            command.args(["--format", "json"]);
        }
        command.arg("--progress-file").arg(&path);
        if kind == "local" {
            command.arg("init");
        } else {
            command.args(["foundation", "up", "--yes"]);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        if kind == "human" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("requires a machine format"));
            assert!(output.stdout.is_empty());
        } else {
            assert!(output.stderr.is_empty());
            let record: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                record["error"]["code"],
                if kind == "local" {
                    "unsupported-progress-command"
                } else {
                    "progress-file-failed"
                }
            );
            assert!(record["networkId"].is_null() && record["operationId"].is_null());
        }
        assert_eq!(fs::read(target).unwrap(), b"do not replace");
        if kind == "file" {
            assert_eq!(fs::read(&path).unwrap(), b"existing report");
        }
        assert!(!f.config.exists());
        assert!(!f.temp.path().join("xdg-data").exists());
        if matches!(kind, "local" | "human") {
            assert!(!path.exists());
        }
    }
}

#[test]
#[cfg(unix)]
fn lifecycle_initial_progress_write_failure_prevents_state_creation() {
    let f = Fixture::new();
    let path = f.temp.path().join("events");
    let output = native_exec::command(f.temp.path(), env!("CARGO_BIN_EXE_zdn"), Some(0))
        .args(["--format", "json", "--progress-file"])
        .arg(&path)
        .args(["foundation", "up", "--yes", "--state-dir"])
        .arg(&f.state)
        .current_dir(&f.source)
        .env_clear()
        .env("PATH", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "progress-write-failed");
    assert!(result["networkId"].is_null() && result["operationId"].is_null());
    assert!(fs::read(path).unwrap().is_empty());
    assert!(!f.state.exists());
}

#[test]
fn machine_help_version_and_parse_errors_have_one_terminal_record() {
    let fixture = Fixture::new();
    for format in ["json", "jsonl"] {
        for (arguments, kind, exit) in [
            (vec!["--help"], "help", 0),
            (vec!["init", "--help"], "help", 0),
            (vec!["--version"], "version", 0),
            (vec!["init", "--release"], "result", 2),
        ] {
            let mut args = vec!["--format", format];
            args.extend(arguments);
            let output = fixture.run(&args);
            assert_eq!(output.status.code(), Some(exit));
            assert!(output.stderr.is_empty());
            let record: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(record["type"], kind);
            if format == "jsonl" {
                assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 1);
            }
        }
        let output = fixture.run(&[
            "--progress-file",
            "must-not-exist",
            "--format",
            format,
            "foundation",
            "up",
            "--not-an-option",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["error"]["code"], "invalid-arguments");
        assert!(!fixture.source.join("must-not-exist").exists());
        for option in ["--noninteractiv", "--test-only-secret=private-value", "-X"] {
            let output = fixture.run(&[option, "--format", format, "check"]);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stderr.is_empty());
            let record: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(record["error"]["code"], "invalid-arguments");
            assert!(!String::from_utf8_lossy(&output.stdout).contains(option));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("private-value"));
            if format == "jsonl" {
                assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 1);
            }
        }
    }
    // Format-looking values after the command are not root format selections.
    for args in [
        vec!["init", "--release", "--format=json"],
        vec!["--noninteractiv", "--", "--format=json", "check"],
        vec!["--noninteractiv", "check", "--format=json"],
    ] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn public_reference_matches_recursive_help_without_state_or_tools() {
    let fixture = Fixture::new();
    // Invalid config and absent tools/credentials must not prevent discovery.
    fs::write(&fixture.config, "not: [valid yaml").unwrap();
    let before = tree(fixture.temp.path());
    let run = |args: &[&str]| {
        fixture
            .command()
            .env_clear()
            .env("PATH", fixture.temp.path().join("no-tools"))
            .env("HOME", fixture.temp.path())
            .env("XDG_DATA_HOME", fixture.temp.path().join("absent-data"))
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .unwrap()
    };
    let output = run(&["reference", "--schema"]);
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(schema["apiVersion"], "zdn-command-reference/v1alpha1");
    assert_eq!(schema["validationComplete"], false);
    let commands: BTreeMap<Vec<String>, &Value> = schema["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| {
            let path = command["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|part| part.as_str().unwrap().to_owned())
                .collect();
            (path, command)
        })
        .collect();
    // Traverse actual advertised help, independently of the reference's command list.
    let mut pending = vec![vec!["zdn".to_owned()]];
    let mut visited = std::collections::BTreeSet::new();
    while let Some(path) = pending.pop() {
        assert!(visited.insert(path.clone()));
        let command = commands[&path];
        let mut args: Vec<_> = path.iter().skip(1).map(String::as_str).collect();
        args.push("--help");
        let output = run(&args);
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "{args:?}: {output:?}"
        );
        let help = String::from_utf8(output.stdout).unwrap();
        assert_eq!(command["longHelp"], help, "{path:?}");
        assert!(!help.contains("__"), "internal protocol leaked: {path:?}");
        if let Some((_, section)) = help.split_once("Commands:\n") {
            for line in section.split("\n\n").next().unwrap().lines() {
                let Some(line) = line
                    .strip_prefix("  ")
                    .filter(|line| !line.starts_with(' '))
                else {
                    continue;
                };
                let name = line.split_whitespace().next().unwrap();
                if name != "help" {
                    let mut child = path.clone();
                    child.push(name.to_owned());
                    pending.push(child);
                }
            }
        }
        for argument in command["arguments"].as_array().unwrap() {
            assert!(
                argument["help"]
                    .as_str()
                    .is_some_and(|help| !help.is_empty()),
                "unexplained argument at {path:?}: {argument}"
            );
        }
        args.pop();
        let mut via_help = vec!["help"];
        via_help.extend(&args);
        let output = run(&via_help);
        assert!(output.status.success() && output.stderr.is_empty());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), help);
        args.push("-h");
        let output = run(&args);
        assert!(output.status.success() && output.stderr.is_empty());
        args.pop();
        args.push("--help");
        for format in ["json", "jsonl"] {
            let mut machine_args = vec!["--format", format];
            machine_args.extend(&args);
            let output = run(&machine_args);
            assert!(output.status.success() && output.stderr.is_empty());
            let record: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(record["type"], "help");
            assert_eq!(record["data"]["text"], help);
            if format == "jsonl" {
                assert_eq!(
                    output
                        .stdout
                        .split(|byte| *byte == b'\n')
                        .filter(|line| !line.is_empty())
                        .count(),
                    1
                );
            }
        }
    }
    assert_eq!(visited, commands.keys().cloned().collect());
    for path in [
        vec!["zdn", "wallet", "backend", "set"],
        vec!["zdn", "devnet", "handoff", "import"],
    ] {
        assert!(visited.contains(&path.into_iter().map(str::to_owned).collect::<Vec<_>>()));
    }
    let reference = run(&["reference"]);
    assert!(reference.status.success() && reference.stderr.is_empty());
    let reference = String::from_utf8(reference.stdout).unwrap();
    for (path, command) in &commands {
        assert!(reference.contains(&format!("=== {} ===", path.join(" "))));
        assert!(reference.contains(command["longHelp"].as_str().unwrap()));
    }
    for format in ["json", "jsonl"] {
        let output = run(&["--format", format, "reference", "--schema"]);
        assert!(output.status.success() && output.stderr.is_empty());
        let records: Vec<Value> = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let terminal = records.last().unwrap();
        assert_eq!(terminal["type"], "result");
        assert_eq!(terminal["data"], schema);
    }
    let output = run(&[
        "--format",
        "json",
        "--progress-file",
        "must-not-exist",
        "reference",
        "--schema",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"]["code"],
        "unsupported-progress-command"
    );
    assert_eq!(tree(fixture.temp.path()), before);
}

#[test]
fn reference_describes_placement_defaults_choices_and_help_exit_boundaries() {
    let fixture = Fixture::new();
    let before = tree(fixture.temp.path());
    let schema = fixture.ok(&["reference", "--schema"]);
    let command = |path: &[&str]| {
        schema["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|command| command["path"] == serde_json::json!(path))
            .unwrap()
    };
    let argument = |path: &[&str], id: &str| {
        command(path)["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|argument| argument["id"] == id)
            .unwrap()
    };
    assert_eq!(
        argument(&["zdn", "init"], "nodes")["defaults"],
        serde_json::json!(["3"])
    );
    assert_eq!(
        argument(&["zdn", "init"], "size")["possibleValues"][0]["name"],
        "small"
    );
    assert!(argument(&["zdn", "init"], "source")["conflictsWith"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("image")));
    let balance = command(&["zdn", "wallet", "balance"]);
    assert_eq!(
        argument(&["zdn", "wallet", "balance"], "wallet_dir")["global"],
        true
    );
    assert!(balance["ancestorOptions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |option| option["path"] == serde_json::json!(["zdn", "wallet"])
                && option["argument"]["long"] == "backend"
        ));
    assert_eq!(
        argument(&["zdn", "wallet", "scan"], "history_json")["position"],
        2
    );
    assert_eq!(argument(&["zdn", "exec"], "command")["last"], true);
    assert!(argument(&["zdn", "image", "verify"], "config")["help"]
        .as_str()
        .unwrap()
        .contains("required unless --inspect"));
    for (args, exit) in [
        (vec!["--noninteractive", "devnet", "update", "--help"], 0),
        (vec!["devnet", "update", "--noninteractive", "--help"], 0),
        (vec!["--format", "json", "wallet", "balance", "--help"], 0),
        (vec!["devnet", "update", "--format", "json", "--help"], 2),
        (
            vec![
                "wallet",
                "--backend",
                "/absent",
                "--backend-sha256",
                "unused",
                "balance",
                "--help",
            ],
            0,
        ),
        (
            vec!["wallet", "balance", "--backend", "/absent", "--help"],
            2,
        ),
        (
            vec!["wallet", "balance", "--wallet-dir", "/absent", "--help"],
            0,
        ),
        (
            vec![
                "init", "--source", "/absent", "--image", "invalid", "--help",
            ],
            0,
        ),
        (vec!["deploy", "--help"], 1),
        (vec!["help", "deploy"], 2),
        (vec!["--format", "json", "deploy", "--help"], 1),
        (vec!["--help-all"], 2),
    ] {
        let output = fixture
            .command()
            .env_clear()
            .env("PATH", "")
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{args:?}: {output:?}");
    }
    assert_eq!(tree(fixture.temp.path()), before);
}

#[cfg(unix)]
#[test]
fn noninteractive_and_machine_modes_never_prompt_on_a_terminal() {
    use rustix::{
        fs::{open, Mode, OFlags},
        pty::{self, OpenptFlags},
    };
    use std::io::IsTerminal;

    let fixture = Fixture::new();
    let master = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let name = pty::ptsname(&master, Vec::new()).unwrap();
    let slave = fs::File::from(
        open(
            name,
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap(),
    );
    assert!(slave.is_terminal());
    for args in [
        vec!["--noninteractive", "init"],
        vec!["init", "--noninteractive"],
        vec!["--format", "json", "init"],
        vec!["--format", "jsonl", "init"],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .current_dir(&fixture.source)
            .args(args)
            .stdin(slave.try_clone().unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("noninteractive CLI prompted or failed to terminate");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains("Choose source") && !stderr.contains("Choose source"));
        assert!(!stderr.contains("Source [1]"));
    }
    assert!(!fixture.config.exists());
}

#[test]
fn unsupported_adapter_is_rejected_by_init_and_config_loading() {
    let fixture = Fixture::new();
    let error = fixture.fail(&["init", "--source", ".", "--adapter", "zebra"]);
    assert!(error.contains("zakura"));
    assert!(!fixture.config.exists());
    fixture.local_init();
    fixture.edit_config(|config| config["node"]["adapter"] = "zebra".into());
    assert!(fixture.fail(&["check"]).contains("zakura"));
    fixture.fail(&["snapshot", "--output", text(&fixture.snapshot)]);
    assert!(!fixture.snapshot.exists());
}

#[test]
fn machine_receipts_report_saved_decisions_without_leaking_diagnostics_or_changing_state() {
    use zdn::state::{Binding, OperationReceipt, PhaseStatus, StateStore};
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    let binding: Binding = serde_json::from_value(fixture.bind()).unwrap();
    let original: OperationReceipt = serde_json::from_value(fixture.create_receipt()).unwrap();
    let store = StateStore::open(&fixture.state).unwrap();
    let diagnostic = "fixture-diagnostic-not-for-export";
    for (status, cancel, expected_status, action, classification) in [
        (None, false, "pending", "run", "safe-to-retry"),
        (None, true, "pending", "stop_cancelled", "cancelled"),
        (
            Some(PhaseStatus::Running {
                external_ref: Some(diagnostic.into()),
            }),
            false,
            "running",
            "reconcile_outcome",
            "reconcile-required",
        ),
        (
            Some(PhaseStatus::Running {
                external_ref: Some(diagnostic.into()),
            }),
            true,
            "running",
            "reconcile_outcome",
            "reconcile-required",
        ),
        (
            Some(PhaseStatus::Failed {
                message: diagnostic.into(),
                retry_safe: true,
            }),
            false,
            "failed",
            "retry",
            "safe-to-retry",
        ),
        (
            Some(PhaseStatus::Failed {
                message: diagnostic.into(),
                retry_safe: true,
            }),
            true,
            "failed",
            "stop_cancelled",
            "cancelled",
        ),
        (
            Some(PhaseStatus::Failed {
                message: diagnostic.into(),
                retry_safe: false,
            }),
            false,
            "failed",
            "reconcile_outcome",
            "reconcile-required",
        ),
        (
            Some(PhaseStatus::Unknown {
                message: diagnostic.into(),
                external_ref: Some(diagnostic.into()),
            }),
            false,
            "unknown",
            "reconcile_outcome",
            "reconcile-required",
        ),
        (
            Some(PhaseStatus::Succeeded {
                result: serde_json::json!({"untrusted": diagnostic}),
            }),
            false,
            "succeeded",
            "reconcile_success",
            "reconcile-required",
        ),
        (
            Some(PhaseStatus::Cancelled),
            false,
            "cancelled",
            "stop_cancelled",
            "cancelled",
        ),
    ] {
        let mut receipt = store
            .begin_operation(
                &binding,
                "deployment",
                original.inputs.clone(),
                &["first", "later"],
            )
            .unwrap();
        let id = receipt.operation_id;
        if let Some(status) = status {
            receipt = store
                .record_phase(
                    id,
                    receipt.revision,
                    "first",
                    PhaseStatus::Running {
                        external_ref: Some(diagnostic.into()),
                    },
                )
                .unwrap();
            if !matches!(status, PhaseStatus::Running { .. }) {
                receipt = store
                    .reconcile_phase(id, receipt.revision, "first", status)
                    .unwrap();
            }
        }
        if cancel {
            receipt = store.request_cancel(id, receipt.revision).unwrap();
        }
        let before = tree(fixture.temp.path());
        for format in ["json", "jsonl"] {
            for (subcommand, verified) in [("inspect", false), ("resume-plan", true)] {
                let id_text = id.to_string();
                let mut args = vec![
                    "--format",
                    format,
                    "receipt",
                    subcommand,
                    &id_text,
                    "--state-dir",
                    text(&fixture.state),
                ];
                if verified {
                    args.extend(["--snapshot", text(&fixture.snapshot)]);
                }
                let output = fixture
                    .command()
                    .env("PATH", fixture.temp.path().join("no-tools"))
                    .args(args)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(output.stderr.is_empty());
                let stdout = String::from_utf8(output.stdout).unwrap();
                assert!(!stdout.contains(diagnostic));
                let records: Vec<Value> = if format == "json" {
                    vec![serde_json::from_str(&stdout).unwrap()]
                } else {
                    stdout
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect()
                };
                let record = records.last().unwrap();
                assert_eq!(record["outcome"], "succeeded");
                assert_eq!(record["operationId"], id_text);
                assert_eq!(record["networkId"], binding.network_id.to_string());
                let data = &record["data"];
                assert_eq!(data["inputsVerified"], verified);
                assert_eq!(data["cancelRequested"], cancel);
                assert_eq!(data["revision"], receipt.revision);
                assert_eq!(data["executionAuthorized"], false);
                assert_eq!(data["liveStateChecked"], false);
                assert_eq!(data["phases"][0]["status"], expected_status);
                assert_eq!(data["phases"][0]["resumeAction"], action);
                assert_eq!(data["phases"][1]["requiresEarlierPhaseVerification"], true);
                assert_eq!(
                    data["retryClassification"],
                    if !verified && classification == "safe-to-retry" {
                        "blocked"
                    } else {
                        classification
                    }
                );
                if format == "jsonl" {
                    assert_eq!(records.len(), 4);
                    assert_eq!(records[0]["type"], "command-started");
                    for index in 0..2 {
                        assert_eq!(records[index + 1]["type"], "saved-phase");
                        assert_eq!(records[index + 1]["outcome"], "observed");
                        assert_eq!(records[index + 1]["operationId"], id_text);
                        assert_eq!(records[index + 1]["data"], data["phases"][index]);
                    }
                }
            }
        }
        assert_eq!(tree(fixture.temp.path()), before);
    }
}

#[test]
fn machine_receipt_retry_classification_accounts_for_later_legacy_attempts() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    let id = receipt["operation_id"].as_str().unwrap();
    let path = fixture.state.join("state.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for earlier in [
        serde_json::json!({"state": "pending"}),
        serde_json::json!({"state": "failed", "message": "legacy safe retry", "retry_safe": true}),
    ] {
        for later in [
            serde_json::json!({"state": "pending"}),
            serde_json::json!({"state": "running", "external_ref": null}),
            serde_json::json!({"state": "succeeded", "result": null}),
            serde_json::json!({"state": "failed", "message": "later safe retry", "retry_safe": true}),
            serde_json::json!({"state": "unknown", "message": "lost outcome", "external_ref": null}),
            serde_json::json!({"state": "cancelled"}),
        ] {
            // Older versions could save this ordering. It must remain readable,
            // but a later attempt prevents an earlier phase from starting again.
            let mut ledger = original.clone();
            ledger["operations"][0]["phases"][0]["status"] = earlier.clone();
            ledger["operations"][0]["phases"][3]["status"] = later.clone();
            fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
            let before = tree(fixture.temp.path());
            for format in ["json", "jsonl"] {
                for (command, verified) in [("inspect", false), ("resume-plan", true)] {
                    let mut args = vec![
                        "--format",
                        format,
                        "receipt",
                        command,
                        id,
                        "--state-dir",
                        text(&fixture.state),
                    ];
                    if verified {
                        args.extend(["--snapshot", text(&fixture.snapshot)]);
                    }
                    let output = fixture.run(&args);
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let records: Vec<Value> = if format == "json" {
                        vec![serde_json::from_slice(&output.stdout).unwrap()]
                    } else {
                        String::from_utf8(output.stdout)
                            .unwrap()
                            .lines()
                            .map(|line| serde_json::from_str(line).unwrap())
                            .collect()
                    };
                    let data = &records.last().unwrap()["data"];
                    let expected = if later["state"] != "pending" {
                        "reconcile-required"
                    } else if verified {
                        "safe-to-retry"
                    } else {
                        "blocked"
                    };
                    assert_eq!(
                        data["phases"][0]["retryClassification"], expected,
                        "{earlier:?}, {later:?}"
                    );
                    assert_eq!(data["retryClassification"], expected);
                    assert_eq!(data["phases"][0]["requiresEarlierPhaseVerification"], false);
                    assert_eq!(
                        data["phases"][0]["resumeAction"],
                        if earlier["state"] == "pending" {
                            "run"
                        } else {
                            "retry"
                        }
                    );
                    if format == "jsonl" {
                        assert_eq!(records[1]["data"]["retryClassification"], expected);
                    }
                }
            }
            assert_eq!(tree(fixture.temp.path()), before);
        }
    }
}

#[test]
fn machine_receipt_recovery_arguments_are_read_only_and_work_outside_the_checkout() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    let id = receipt["operation_id"].as_str().unwrap();
    let mut args = vec!["--format", "json"];
    args.extend(fixture.resume_args(id));
    let report = fixture.ok(&args);
    let other = fixture.temp.path().join("another-working-directory");
    fs::create_dir(&other).unwrap();
    let before = tree(fixture.temp.path());
    assert_eq!(report["data"]["recovery"].as_array().unwrap().len(), 2);
    for step in report["data"]["recovery"].as_array().unwrap() {
        assert_eq!(step["mutates"], false);
        assert_eq!(step["requiresAuthorization"], false);
        let argv: Vec<&str> = step["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(&argv[..4], &["zdn", "--format", "json", "receipt"]);
        let output = fixture
            .command()
            .current_dir(&other)
            .env("PATH", fixture.temp.path().join("no-tools"))
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["operationId"], id);
        assert_eq!(result["data"]["cancelRequested"], false);
    }
    assert_eq!(tree(fixture.temp.path()), before);
    fixture.edit_config(|config| config["network"]["mining"]["interval"] = "29s".into());
    let before = tree(fixture.temp.path());
    let output = fixture.run(&args);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["error"]["code"], "receipt-report-failed");
    assert_eq!(
        error["data"]["immutableInputs"]["changedFields"],
        serde_json::json!([
            {"field":"configSha256","changeKind":"modified"}
        ])
    );
    assert_eq!(
        error["data"]["immutableInputs"]["executionAuthorized"],
        false
    );
    assert_eq!(tree(fixture.temp.path()), before);
}

#[test]
fn machine_receipt_observation_never_initializes_missing_state() {
    let fixture = Fixture::new();
    let before = tree(fixture.temp.path());
    let id = uuid::Uuid::new_v4().to_string();
    let output = fixture.run(&[
        "--format",
        "json",
        "receipt",
        "inspect",
        &id,
        "--state-dir",
        text(&fixture.state),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["error"]["code"], "receipt-report-failed");
    assert_eq!(tree(fixture.temp.path()), before);
}

#[test]
fn noninteractive_init_requires_an_explicit_source_choice() {
    let fixture = Fixture::new();
    let error = fixture.fail(&["init"]);
    assert!(error.contains("input is not interactive"));
    assert!(!fixture.config.exists());
}

#[test]
fn local_snapshot_binding_receipt_and_cancel_form_a_complete_offline_flow() {
    let fixture = Fixture::new();
    fixture.local_init();
    fs::write(fixture.source.join("README.md"), "dirty branch bytes\n").unwrap();
    let snapshot = fixture.capture();
    assert_eq!(snapshot["dirty"], true);
    assert!(fixture.snapshot.join("source.tar").is_file());
    let binding = fixture.bind();
    assert_eq!(binding["reservation"], "unreserved");
    let receipt = fixture.create_receipt();
    assert_eq!(receipt["network_id"], binding["network_id"]);
    assert_eq!(
        receipt["inputs"]["archive_sha256"],
        snapshot["archive_sha256"]
    );
    assert!(receipt["phases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|phase| phase["status"]["state"] == "pending"));
    let id = receipt["operation_id"].as_str().unwrap();
    let resume = fixture.ok(&fixture.resume_args(id));
    assert!(resume["phases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|phase| phase["action"] == "run"));
    let cancelled = fixture.ok(&["receipt", "cancel", id, "--state-dir", text(&fixture.state)]);
    assert_eq!(cancelled["cancel_requested"], true);
    let resume = fixture.ok(&fixture.resume_args(id));
    assert!(resume["phases"]
        .as_array()
        .unwrap()
        .iter()
        .all(|phase| phase["action"] == "stop_cancelled"));
    assert_eq!(fixture.git(&["rev-list", "--count", "HEAD"]), "1");
    assert_eq!(
        fs::read_to_string(fixture.source.join("README.md")).unwrap(),
        "dirty branch bytes\n"
    );
}

#[test]
fn renaming_the_config_label_keeps_the_same_network_id() {
    let fixture = Fixture::new();
    fixture.local_init();
    let first = fixture.bind();
    fixture.edit_config(|config| config["name"] = "renamed-feature".into());
    let renamed = fixture.bind();
    assert_eq!(renamed["network_id"], first["network_id"]);
    assert_eq!(renamed["label"], "renamed-feature");
    let listed = fixture.ok(&[
        "identity",
        "list",
        "--state-dir",
        text(&fixture.state),
        "--team-id",
        "test-team",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
    ]);
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[test]
fn changed_config_is_rejected_by_resume_without_rewriting_the_receipt() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    let saved_state = fs::read(fixture.state.join("state.json")).unwrap();
    fixture.edit_config(|config| config["network"]["nodes"] = 4.into());
    let error = fixture.fail(&fixture.resume_args(receipt["operation_id"].as_str().unwrap()));
    assert!(error.contains("resume inputs differ"));
    let before = tree(fixture.temp.path());
    for format in ["json", "jsonl"] {
        let output = fixture
            .command()
            .args(["--format", format])
            .args(fixture.resume_args(receipt["operation_id"].as_str().unwrap()))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let records: Vec<Value> = if format == "json" {
            vec![serde_json::from_slice(&output.stdout).unwrap()]
        } else {
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
        let terminal = records.last().unwrap();
        assert_eq!(terminal["error"]["code"], "receipt-report-failed");
        assert_eq!(terminal["error"]["retryClassification"], "blocked");
        let report = &terminal["data"]["immutableInputs"];
        assert_eq!(
            report["changedFields"],
            serde_json::json!([
                {"field":"configSha256","changeKind":"modified"}
            ])
        );
        assert_eq!(report["immutable"], true);
        assert_eq!(report["executionAuthorized"], false);
        assert_eq!(report["liveStateChecked"], false);
        assert!(report["guidance"]
            .as_str()
            .unwrap()
            .contains("separate new deployment"));
        assert!(!terminal
            .to_string()
            .contains(fixture.source.to_str().unwrap()));
    }
    assert_eq!(tree(fixture.temp.path()), before);
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        saved_state
    );
}

#[test]
fn damaged_source_archive_is_rejected_before_resume() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    let saved_state = fs::read(fixture.state.join("state.json")).unwrap();
    fs::write(fixture.snapshot.join("source.tar"), "damaged archive").unwrap();
    let error = fixture.fail(&fixture.resume_args(receipt["operation_id"].as_str().unwrap()));
    assert!(error.contains("SHA-256"));
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        saved_state
    );
}

#[test]
fn a_release_candidate_is_explicit_and_still_unqualified() {
    let fixture = Fixture::new();
    fixture.ok(&["init", "--release", "v0.1.0"]);
    let plan = fixture.ok(&["plan"]);
    assert_eq!(plan["config"]["node"]["source"]["release"], "v0.1.0");
    assert!(plan["config"]["node"].get("build").is_none());
    assert_eq!(plan["launchReady"], false);
    assert!(plan["compatibility"]["zakura"].is_null());
    assert!(plan["compatibility"]["wallet"].is_null());
    assert!(plan["compatibility"]["lightwalletd"].is_null());
    assert!(plan["compatibility"]["humanEvidenceSha256"].is_null());
    assert!(plan["compatibility"]["capabilities"]
        .as_object()
        .unwrap()
        .values()
        .all(|value| value == false));
    assert!(fixture
        .fail(&["snapshot", "--output", text(&fixture.snapshot)])
        .contains("local"));
    assert!(!fixture.snapshot.exists());
}

#[test]
fn cloud_commands_fail_before_executing_a_tool_or_creating_files() {
    let fixture = Fixture::new();
    fixture.local_init();
    // An empty PATH makes any accidental AWS/Pulumi/Docker execution fail. The
    // expected stage error must be produced before trying to spawn any of them.
    let before = tree(fixture.temp.path());
    let error = fixture.fail(&["up"]);
    assert!(error.contains("pass --yes"), "{error}");
    for command in ["deploy", "destroy", "status", "logs", "resume"] {
        let output = fixture
            .command()
            .env("PATH", fixture.temp.path().join("no-tools"))
            .args([command, "my-feature"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("not implemented yet"),
            "unexpected {command} failure: {error}"
        );
        assert!(error.contains("No cloud action was started"));
    }
    for command in ["fund", "send", "tx"] {
        let output = fixture
            .command()
            .env("PATH", fixture.temp.path().join("no-tools"))
            .arg(command)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("required arguments"), "{command}: {error}");
        assert!(error.contains("Usage:"), "{command}: {error}");
    }
    assert_eq!(tree(fixture.temp.path()), before);
}

#[test]
fn local_receipt_requires_a_saved_snapshot() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.bind();
    let before = fs::read(fixture.state.join("state.json")).unwrap();
    let error = fixture.fail(&[
        "receipt",
        "create",
        "--state-dir",
        text(&fixture.state),
        "--team-id",
        "test-team",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
    ]);
    assert!(error.contains("requires --snapshot"));
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);
}

#[test]
fn creating_a_receipt_rejects_a_snapshot_from_a_different_requested_commit() {
    let fixture = Fixture::new();
    let first = fixture.git(&["rev-parse", "HEAD"]);
    fixture.ok(&["init", "--source", ".", "--revision", &first]);
    fixture.capture();
    fs::write(fixture.source.join("README.md"), "second commit bytes\n").unwrap();
    fixture.git(&["add", "README.md"]);
    fixture.git(&["commit", "-qm", "second commit"]);
    let second = fixture.git(&["rev-parse", "HEAD"]);
    fixture.edit_config(|config| config["node"]["source"]["revision"] = second.into());
    fixture.bind();
    let error = fixture.fail(&fixture.receipt_create_args());
    assert!(
        error.contains("revision") || error.contains("commit"),
        "unexpected mismatch error: {error}"
    );
}

#[test]
fn creating_a_receipt_rejects_a_snapshot_from_a_different_source_directory() {
    let fixture = Fixture::new();
    fixture.local_init();
    fixture.capture();
    fixture.bind();
    let before = fs::read(fixture.state.join("state.json")).unwrap();
    let path = fixture.snapshot.join("receipt.json");
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["source_root"] = text(&fixture.temp.path().join("other-checkout")).into();
    fs::write(path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let error = fixture.fail(&fixture.receipt_create_args());
    assert!(error.contains("different source directory"), "{error}");
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);
}

#[test]
fn resuming_uses_saved_bytes_after_the_original_head_reference_moves() {
    let fixture = Fixture::new();
    fixture.ok(&["init", "--source", ".", "--revision", "HEAD"]);
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    fs::write(fixture.source.join("README.md"), "later branch work\n").unwrap();
    fixture.git(&["add", "README.md"]);
    fixture.git(&["commit", "-qm", "advance HEAD"]);
    let resumed = fixture.ok(&fixture.resume_args(receipt["operation_id"].as_str().unwrap()));
    assert_eq!(resumed["operation_id"], receipt["operation_id"]);
    assert_eq!(resumed["cancel_requested"], false);
}

#[test]
fn release_and_image_bindings_follow_configuration_branches() {
    let image = format!("example.invalid/zakura@sha256:{}", "a".repeat(64));
    for selection in [["--release", "v0.1.0"], ["--image", image.as_str()]] {
        let fixture = Fixture::new();
        fixture.ok(&["init", selection[0], selection[1]]);
        let first = fixture.bind();
        assert_eq!(first["context"]["branch"], "feature");
        assert_eq!(
            first["context"]["worktree"],
            text(&fs::canonicalize(&fixture.source).unwrap())
        );

        fixture.git(&["switch", "-qc", "other-feature"]);
        let second = fixture.bind();
        assert_eq!(second["context"]["branch"], "other-feature");
        assert_ne!(first["network_id"], second["network_id"]);

        fixture.git(&["switch", "-q", "feature"]);
        assert_eq!(fixture.bind()["network_id"], first["network_id"]);
    }
}

#[test]
fn release_and_image_bindings_find_linked_configuration_worktrees() {
    let image = format!("example.invalid/zakura@sha256:{}", "b".repeat(64));
    for selection in [["--release", "v0.1.0"], ["--image", image.as_str()]] {
        let mut fixture = Fixture::new();
        fixture.ok(&["init", selection[0], selection[1]]);
        let first = fixture.bind();
        let linked = fixture.temp.path().join("linked");
        fixture.git(&[
            "worktree",
            "add",
            "-qb",
            "linked-feature",
            text(&linked),
            "HEAD",
        ]);
        fs::copy(&fixture.config, linked.join("devnet.yaml")).unwrap();
        fixture.config = linked.join("devnet.yaml");
        assert!(linked.join(".git").is_file());
        let second = fixture.bind();
        assert_eq!(second["context"]["branch"], "linked-feature");
        assert_eq!(
            second["context"]["worktree"],
            text(&fs::canonicalize(linked).unwrap())
        );
        assert_ne!(first["network_id"], second["network_id"]);
    }
}

#[test]
fn release_and_image_bindings_allow_configurations_outside_git() {
    let image = format!("example.invalid/zakura@sha256:{}", "c".repeat(64));
    for selection in [["--release", "v0.1.0"], ["--image", image.as_str()]] {
        let fixture = Fixture::with_external_config();
        fixture.ok(&["init", selection[0], selection[1]]);
        let first = fixture.bind();
        assert!(first["context"]["worktree"].is_null());
        assert!(first["context"]["branch"].is_null());
        assert_eq!(fixture.bind()["network_id"], first["network_id"]);
    }
}

#[test]
fn a_broken_configuration_checkout_does_not_fall_back_to_an_unscoped_binding() {
    let fixture = Fixture::new();
    fixture.ok(&["init", "--release", "v0.1.0"]);
    fs::remove_dir_all(fixture.source.join(".git")).unwrap();
    fs::write(
        fixture.source.join(".git"),
        "gitdir: /zdn-nonexistent-fixture-repository\n",
    )
    .unwrap();
    let error = fixture.fail(&fixture.binding_args());
    assert!(error.contains("Git source lookup failed"), "{error}");
    assert!(!fixture.state.exists());
}

#[test]
fn git_lookup_errors_do_not_create_unscoped_bindings() {
    let fixture = Fixture::new();
    fixture.ok(&["init", "--release", "v0.1.0"]);
    let output = fixture
        .command()
        .env("PATH", fixture.temp.path().join("no-tools"))
        .args(fixture.binding_args())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("cannot run git"), "{error}");
    assert!(!fixture.state.exists());
}

#[test]
fn git_environment_cannot_redirect_local_or_configuration_bindings() {
    let foreign = Fixture::new();
    foreign.git(&["switch", "-qc", "foreign-branch"]);
    let image = format!("example.invalid/zakura@sha256:{}", "d".repeat(64));
    for selection in [
        ["--source", "."],
        ["--release", "v0.1.0"],
        ["--image", image.as_str()],
    ] {
        let fixture = Fixture::new();
        fixture.ok(&["init", selection[0], selection[1]]);
        let output = fixture
            .command()
            .env("GIT_DIR", foreign.source.join(".git"))
            .env("GIT_WORK_TREE", &foreign.source)
            .env("GIT_INDEX_FILE", foreign.source.join(".git/index"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.bare")
            .env("GIT_CONFIG_VALUE_0", "true")
            .args(fixture.binding_args())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binding: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(binding["context"]["branch"], "feature");
        assert_eq!(
            binding["context"]["worktree"],
            text(&fs::canonicalize(&fixture.source).unwrap())
        );
        assert_eq!(fixture.bind()["network_id"], binding["network_id"]);
    }
}

#[test]
fn configuration_bindings_support_unborn_and_detached_heads() {
    let fixture = Fixture::new();
    fixture.ok(&["init", "--release", "v0.1.0"]);
    fixture.git(&["switch", "--orphan", "unborn-branch"]);
    let unborn = fixture.bind();
    assert_eq!(unborn["context"]["branch"], "unborn-branch");
    fixture.git(&["switch", "--detach", "feature"]);
    let detached = fixture.bind();
    assert!(detached["context"]["branch"].is_null());
    assert_ne!(unborn["network_id"], detached["network_id"]);
}

#[test]
fn saved_operations_resume_after_source_rename_and_removal() {
    for exact_revision in [false, true] {
        for relative_path in [false, true] {
            let fixture = Fixture::with_external_config();
            let mut init = vec!["init", "--source", text(&fixture.source)];
            if exact_revision {
                init.extend(["--revision", "HEAD"]);
            }
            fixture.ok(&init);
            if relative_path {
                fixture.edit_config(|config| {
                    config["node"]["source"]["path"] = "../project".into();
                });
            }
            fixture.capture();
            fixture.bind();
            let receipt = fixture.create_receipt();
            let id = receipt["operation_id"].as_str().unwrap();
            let before = fs::read(fixture.state.join("state.json")).unwrap();
            assert_eq!(fixture.ok(&fixture.resume_args(id))["operation_id"], id);

            let moved = fixture.temp.path().join("moved-source");
            fs::rename(&fixture.source, &moved).unwrap();
            assert_eq!(fixture.ok(&fixture.resume_args(id))["operation_id"], id);
            fs::remove_dir_all(&moved).unwrap();
            assert_eq!(fixture.ok(&fixture.resume_args(id))["operation_id"], id);
            assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);

            let error = fixture.fail(&fixture.receipt_create_args());
            assert!(error.contains("resolve source"), "{error}");
            assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);
        }
    }
}

#[test]
fn resume_without_a_checkout_still_rejects_changed_snapshot_identity() {
    let fixture = Fixture::with_external_config();
    fixture.ok(&["init", "--source", text(&fixture.source)]);
    fixture.capture();
    fixture.bind();
    let receipt = fixture.create_receipt();
    let id = receipt["operation_id"].as_str().unwrap();
    let before = fs::read(fixture.state.join("state.json")).unwrap();
    fs::remove_dir_all(&fixture.source).unwrap();

    let snapshot_path = fixture.snapshot.join("receipt.json");
    let original = fs::read(&snapshot_path).unwrap();
    let saved: Value = serde_json::from_slice(&original).unwrap();
    for key in ["source_root", "head"] {
        let mut changed = saved.clone();
        changed[key] = if key == "source_root" {
            text(&fixture.temp.path().join("different-source")).into()
        } else {
            "0".repeat(40).into()
        };
        fs::write(&snapshot_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let error = fixture.fail(&fixture.resume_args(id));
        assert!(error.contains("resume inputs differ"), "{error}");
        assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);
    }
    fs::write(&snapshot_path, original).unwrap();
    assert_eq!(fixture.ok(&fixture.resume_args(id))["operation_id"], id);
}

#[cfg(all(feature = "profiling", unix))]
#[test]
fn private_timing_trace_preserves_stdout_and_never_overwrites_existing_files() {
    let fixture = Fixture::new();
    fixture.local_init();
    let config = fixture.temp.path().join("private-argument-sentinel.yaml");
    fs::copy(&fixture.config, &config).unwrap();
    let args = ["--format", "json", "check", "--config", text(&config)];
    let baseline = fixture.run(&args);
    assert!(baseline.status.success());
    let trace = fixture.temp.path().join("timings.jsonl");
    let output = fixture
        .command()
        .args(args)
        .env("ZDN_TRACE_FILE", &trace)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, baseline.stdout);
    assert_eq!(output.stderr, baseline.stderr);
    let bytes = fs::read(&trace).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("private-argument-sentinel"));
    assert!(!text.contains(fixture.temp.path().to_str().unwrap()));
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for name in ["cli.main", "cli.check", "config.load", "config.validate"] {
        let record = records
            .iter()
            .find(|record| record["span"]["name"] == name)
            .unwrap_or_else(|| panic!("missing {name}: {text}"));
        assert_eq!(record["fields"]["message"], "close");
        assert!(record["fields"]["time.busy"].is_string());
        assert!(record["fields"]["time.idle"].is_string());
    }
    assert!(records.iter().any(|record| {
        record["span"]["name"] == "config.load"
            && record["spans"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parent| parent["name"] == "cli.check")
    }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&trace).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let retry = fixture
        .command()
        .args(args)
        .env("ZDN_TRACE_FILE", &trace)
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert_eq!(fs::read(&trace).unwrap(), bytes);
}

#[test]
fn native_runtime_protocol_is_explicit_and_needs_no_external_tools() {
    let root = tempfile::tempdir().unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command.env_clear().env("PATH", "").current_dir(root.path());
        command
    };
    let output = command().arg("__runtime-capabilities").output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["apiVersion"], "zdn-native-runtime/v1alpha1");
    let mut expected = vec!["zdn-build-export/v1alpha2"];
    if cfg!(target_os = "linux") {
        expected.push("zdn-host-capacity/v1alpha1");
        expected.push("zdn-foundation-health/v1alpha1");
        if cfg!(target_arch = "x86_64") {
            expected.push("zdn-host-runtime/v1alpha1");
            expected.push("zdn-host-install-runtime/v1alpha1");
            expected.push("zdn-client-gateway-runtime/v1alpha1");
            expected.push("zdn-lightwallet-runtime/v1alpha1");
            expected.push("zdn-lightwallet-install-runtime/v1alpha1");
            expected.push("zdn-native-image-update-execution/v1alpha1");
        }
    }
    assert_eq!(report["capabilities"], serde_json::json!(expected));
    for (protocol, supported) in [
        ("zdn-build-export/v1alpha2", true),
        ("zdn-build-export/v999", false),
        ("zdn-host-capacity/v1alpha1", cfg!(target_os = "linux")),
        ("zdn-host-capacity/v999", false),
        ("zdn-foundation-health/v1alpha1", cfg!(target_os = "linux")),
        ("zdn-foundation-health/v999", false),
        (
            "zdn-host-runtime/v1alpha1",
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
        ),
        ("zdn-host-runtime/v999", false),
        (
            "zdn-host-install-runtime/v1alpha1",
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
        ),
        ("zdn-host-install-runtime/v999", false),
        (
            "zdn-client-gateway-runtime/v1alpha1",
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
        ),
        ("zdn-client-gateway-runtime/v999", false),
        (
            "zdn-lightwallet-runtime/v1alpha1",
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
        ),
        ("zdn-lightwallet-runtime/v999", false),
        (
            "zdn-lightwallet-install-runtime/v1alpha1",
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
        ),
        ("zdn-lightwallet-install-runtime/v999", false),
    ] {
        let required = command()
            .args(["__runtime-capabilities", "--require", protocol])
            .output()
            .unwrap();
        assert_eq!(required.status.success(), supported);
        if supported {
            assert_eq!(required.stdout, output.stdout);
            assert!(required.stderr.is_empty());
        } else {
            assert!(required.stdout.is_empty());
            assert!(String::from_utf8_lossy(&required.stderr)
                .contains("unsupported runtime capability"));
        }
    }

    // Reject an unknown protocol before opening even the contract input.
    let output = command()
        .args([
            "__build-export",
            "--protocol",
            "zdn-build-export/v999",
            "--contract",
            "missing",
            "--repository",
            "missing",
            "--registry",
            "missing",
            "--config-download",
            "missing",
            "--output",
            "output",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported build-export protocol"));
    assert!(!root.path().join("output").exists());

    let output = command()
        .args([
            "__host-capacity",
            "--protocol",
            "zdn-host-capacity/v999",
            "--root",
            "missing",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported host-capacity protocol"));

    #[cfg(target_os = "linux")]
    for action in ["__host-install", "__client-gateway"] {
        let protocol = if action == "__host-install" {
            "zdn-host-install-runtime/v999"
        } else {
            "zdn-client-gateway-runtime/v999"
        };
        let mut args = vec![action, "--protocol", protocol];
        if action == "__client-gateway" {
            args.extend(["--manifest", "missing", "observe"]);
        }
        let output = command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported"));
    }

    for action in ["__foundation-serve", "__foundation-fetch"] {
        let mut args = vec![action, "--protocol", "zdn-foundation-health/v999"];
        if action == "__foundation-serve" {
            args.extend([
                "--network-id",
                "a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
                "--size",
                "medium",
            ]);
        }
        let output = command().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("unsupported foundation runtime protocol"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_capacity_command_distinguishes_install_and_foundation_limits_without_tools() {
    let root = tempfile::tempdir().unwrap();
    for (name, body) in [
        ("proc/meminfo", "MemTotal: 16777216 kB\n"),
        ("proc/self/cgroup", "0::/system.slice/readiness:service\n"),
        ("proc/self/status", "Cpus_allowed_list:\t2-4,6\n"),
        ("sys/devices/system/cpu/online", "0-7\n"),
        ("sys/fs/cgroup/system.slice/memory.max", "8589934592\n"),
        ("sys/fs/cgroup/system.slice/cpu.max", "150000 100000\n"),
        (
            "sys/fs/cgroup/system.slice/readiness:service/memory.max",
            "3221225472\n",
        ),
        (
            "sys/fs/cgroup/system.slice/readiness:service/cpu.max",
            "128000 100000\n",
        ),
    ] {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }
    for exclude in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("PATH", "")
            .args([
                "__host-capacity",
                "--protocol",
                "zdn-host-capacity/v1alpha1",
                "--root",
            ])
            .arg(root.path());
        if exclude {
            command.arg("--exclude-current-cgroup");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::json!({
                "mem_total_bytes":17179869184_u64,
                "online_cpu_count":8,
                "affinity_cpu_count":4,
                "ancestor_memory_limits_bytes": if exclude {vec![8589934592_u64]} else {vec![3221225472_u64,8589934592]},
                "ancestor_cpu_quota_millis": if exclude {vec![1500]} else {vec![1280,1500]},
            })
        );
    }
}
