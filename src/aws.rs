//! Explicit AWS identity, team-owned state bootstrap, and conditional metadata.

use crate::{
    dependencies::{run_command, run_command_in_memory, run_command_inherited_in_memory},
    state::Scope,
};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tempfile::NamedTempFile;
use uuid::Uuid;

const MAX_RECORD_BYTES: u64 = 64 * 1024;
pub const TEAM_API_VERSION: &str = "zdn-team/v1alpha1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamAws {
    pub account_id: String,
    pub region: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamState {
    pub backend: String,
    pub kms_key_arn: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamDefinition {
    pub api_version: String,
    pub team_id: String,
    pub revision: u64,
    pub bootstrap_id: Uuid,
    pub aws: TeamAws,
    pub state: TeamState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<crate::access::DeploymentAccess>,
}

impl TeamDefinition {
    pub fn scope(&self) -> Scope {
        Scope {
            team_id: self.team_id.clone(),
            account_id: self.aws.account_id.clone(),
            region: self.aws.region.clone(),
        }
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.team_definition.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (self.api_version == TEAM_API_VERSION && self.deployment.is_none())
                || (self.api_version == crate::access::TEAM_ROLE_API_VERSION
                    && self.deployment.is_some()),
            "unsupported team format"
        );
        self.scope().validate()?;
        ensure!(
            self.team_id != "." && self.team_id != "..",
            "invalid team ID"
        );
        ensure!(self.revision > 0, "team revision must be positive");
        ensure!(!self.bootstrap_id.is_nil(), "bootstrap ID must not be nil");
        let (_, prefix) = split_backend(&self.state.backend)?;
        ensure!(
            prefix != "zdn-meta" && !prefix.starts_with("zdn-meta/"),
            "Pulumi state must be separate from zdn metadata"
        );
        validate_key_arn(&self.state.kms_key_arn, &self.aws)?;
        if let Some(access) = &self.deployment {
            ensure!(
                prefix != "zdn-admin" && !prefix.starts_with("zdn-admin/"),
                "deployment state must be separate from administrator state"
            );
            access.validate(self)?;
        }
        Ok(())
    }

    pub fn backend_bucket(&self) -> Result<&str> {
        Ok(split_backend(&self.state.backend)?.0)
    }

    pub fn backend_prefix(&self) -> Result<&str> {
        Ok(split_backend(&self.state.backend)?.1)
    }

    pub fn secrets_provider(&self) -> String {
        format!(
            "awskms:///{}?region={}",
            self.state.kms_key_arn, self.aws.region
        )
    }

    pub fn metadata_prefix(&self) -> String {
        format!("zdn-meta/v1/{}", self.team_id)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_yaml::from_slice(&read_record(path)?)
            .context("read versioned team definition")?;
        value.validate()?;
        Ok(value)
    }

    /// Publish a private team definition without replacing existing content.
    /// Repeating an identical validated definition preserves its original bytes.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.team_definition.save_export")
    )]
    pub fn save_export(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let verify_existing = || -> Result<()> {
            ensure!(
                Self::load(path)? == *self,
                "team export has different settings; choose a new destination"
            );
            Ok(())
        };
        match fs::symlink_metadata(path) {
            Ok(_) => return verify_existing(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = NamedTempFile::new_in(parent)?;
        file.write_all(serde_yaml::to_string(self)?.as_bytes())?;
        file.as_file().sync_all()?;
        match file.persist_noclobber(path) {
            Ok(_) => File::open(parent)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_existing()?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalProfile {
    pub team: TeamDefinition,
    pub aws_profile: String,
}

impl LocalProfile {
    pub fn validate(&self) -> Result<()> {
        self.team.validate()?;
        self.selection().validate()
    }

    pub fn selection(&self) -> AwsSelection {
        AwsSelection {
            profile: self.aws_profile.clone(),
            account_id: self.team.aws.account_id.clone(),
            region: self.team.aws.region.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsSelection {
    pub profile: String,
    pub account_id: String,
    pub region: String,
}

impl AwsSelection {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.aws_selection.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        Scope {
            team_id: "validation".into(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
        }
        .validate()?;
        ensure!(
            !self.profile.is_empty()
                && self.profile.len() <= 128
                && self
                    .profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "AWS profile must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens"
        );
        ensure!(
            !self.region.starts_with("cn-") && !self.region.starts_with("us-gov-"),
            "this foundation supports the commercial AWS partition"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.aws_selection.validate_environment")
    )]
    pub fn validate_environment(&self, env: &BTreeMap<String, String>) -> Result<()> {
        self.validate()?;
        for key in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_ROLE_SESSION_NAME",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        ] {
            ensure!(
                env.get(key).is_none_or(String::is_empty),
                "{key} conflicts with the explicitly selected AWS profile; remove it before continuing"
            );
        }
        for key in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"] {
            ensure!(
                env.get(key)
                    .is_none_or(|v| v.is_empty() || v == &self.profile),
                "{key} conflicts with the selected AWS profile"
            );
        }
        for key in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
            ensure!(
                env.get(key)
                    .is_none_or(|v| v.is_empty() || v == &self.region),
                "{key} conflicts with the selected AWS region"
            );
        }
        ensure!(
            !env.iter()
                .any(|(key, value)| key.starts_with("AWS_ENDPOINT_URL") && !value.is_empty()),
            "AWS endpoint overrides are not supported"
        );
        Ok(())
    }
}

/// One independent API request, including streaming-file or projection arguments.
pub struct AwsCall<'a> {
    pub operation: &'a str,
    pub input: Value,
    pub extra_args: Vec<String>,
}

/// The boundary used by bootstrap and object storage. Implementations must preserve
/// argument boundaries and must not include credentials or raw stderr in errors.
pub trait AwsApi {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra_args: &[String],
    ) -> Result<Value>;

    /// Independent calls with input-ordered, individual outcomes. Preserve known
    /// successes when a peer fails; callers must settle them before retrying.
    /// New dispatch stops after failure, but every started call is joined. The
    /// outer error denotes worker infrastructure failure, not an API outcome.
    /// Existing adapters need not be thread safe and dispatch serially by default.
    fn batch_call(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        let mut failed = false;
        Ok(calls
            .iter()
            .map(|call| {
                if failed {
                    return Err(eyre::eyre!(
                        "AWS batch request not dispatched after peer failure"
                    ));
                }
                let result = self.call(
                    service,
                    call.operation,
                    call.input.clone(),
                    &call.extra_args,
                );
                failed = result.is_err();
                result
            })
            .collect())
    }

    /// Independent calls where expected API errors must not suppress later work.
    /// Outcomes retain input order; every request is dispatched despite API errors.
    fn batch_call_all(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        Ok(calls
            .iter()
            .map(|call| {
                self.call(
                    service,
                    call.operation,
                    call.input.clone(),
                    &call.extra_args,
                )
            })
            .collect())
    }

    /// Adapters with subprocesses should enforce this remaining local budget.
    /// The default preserves compatibility with existing in-process adapters.
    fn call_with_timeout(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra_args: &[String],
        timeout: Duration,
    ) -> Result<Value> {
        ensure!(!timeout.is_zero(), "AWS call budget exhausted");
        self.call(service, operation, input, extra_args)
    }
}

#[derive(Clone, Debug)]
pub struct AwsCli {
    selection: AwsSelection,
    executable: PathBuf,
    environment: BTreeMap<String, String>,
    expected_role: Option<String>,
    in_credential_process: bool,
}

impl AwsCli {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.aws_cli.new")
    )]
    pub fn new(selection: AwsSelection) -> Result<Self> {
        let environment = std::env::vars_os()
            .map(|(key, value)| {
                let key = key.into_string().map_err(|_| {
                    eyre::eyre!("AWS CLI environment contains a non-UTF-8 variable name")
                })?;
                let value = value.into_string().map_err(|_| {
                    eyre::eyre!("AWS CLI environment contains a non-UTF-8 variable value")
                })?;
                Ok((key, value))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let cli = Self::with_environment(selection, "aws", environment)?;
        cli.verify_cli_version()?;
        Ok(cli)
    }

    /// An executable/environment seam for local process-contract tests.
    pub fn with_environment(
        selection: AwsSelection,
        executable: impl Into<PathBuf>,
        environment: BTreeMap<String, String>,
    ) -> Result<Self> {
        selection.validate_environment(&environment)?;
        Ok(Self {
            selection,
            executable: executable.into(),
            environment,
            expected_role: None,
            in_credential_process: false,
        })
    }

    pub(crate) fn within_credential_process(mut self) -> Self {
        self.in_credential_process = true;
        self
    }

    pub fn expect_role(mut self, role: Option<String>) -> Result<Self> {
        if let Some(role) = &role {
            crate::access::iam_resource(role, &self.selection.account_id, "role")?;
        }
        self.expected_role = role;
        Ok(self)
    }

    pub fn selection(&self) -> &AwsSelection {
        &self.selection
    }

    /// Bootstrap uses the current conditional-write and create-with-tags schema.
    pub fn verify_cli_version(&self) -> Result<()> {
        let mut command = Command::new(&self.executable);
        command.arg("--version");
        let output = run_command(&mut command, Duration::from_secs(5))?;
        ensure!(output.success, "cannot read AWS CLI version");
        let text = format!("{} {}", output.stdout, output.stderr);
        validate_cli_version(&text)
    }

    pub fn verify_identity(&self) -> Result<CallerIdentity> {
        verify_identity(self, &self.selection)
    }
}

/// Validate the AWS CLI version without running any process or cloud request.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.validate_cli_version")
)]
pub fn validate_cli_version(text: &str) -> Result<()> {
    let version = text
        .split_whitespace()
        .find_map(|v| v.strip_prefix("aws-cli/"))
        .context("unrecognized AWS CLI version")?;
    let components: Vec<u64> = version
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .context("invalid AWS CLI version")?;
    ensure!(
        components.len() == 3
            && components[0] == 2
            && components.as_slice() >= [2, 37, 4].as_slice(),
        "AWS CLI v2 version 2.37.4 or later is required for conditional writes and atomic bucket tags"
    );
    Ok(())
}

impl AwsCli {
    fn batch_calls(
        &self,
        service: &str,
        calls: &[AwsCall<'_>],
        fail_stop: bool,
    ) -> Result<Vec<Result<Value>>> {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        };
        let next = AtomicUsize::new(0);
        let stopped = AtomicBool::new(false);
        let (sender, receiver) = mpsc::channel();
        let joins = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..calls.len().min(4))
                .map(|_| {
                    let sender = sender.clone();
                    let next = &next;
                    let stopped = &stopped;
                    let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                        while !stopped.load(Ordering::SeqCst) {
                            let index = next.fetch_add(1, Ordering::SeqCst);
                            let Some(call) = calls.get(index) else { break };
                            let result = self.call(
                                service,
                                call.operation,
                                call.input.clone(),
                                &call.extra_args,
                            );
                            if fail_stop && result.is_err() {
                                stopped.store(true, Ordering::SeqCst);
                            }
                            let _ = sender.send((index, result));
                        }
                    });
                    if worker.is_err() {
                        stopped.store(true, Ordering::SeqCst);
                    }
                    worker
                })
                .collect();
            // Join every worker before propagating a spawn/panic error. API
            // failures remain individual outcomes, including successful peers.
            workers
                .into_iter()
                .map(|worker| match worker {
                    Ok(worker) => worker.join().map_err(|_| {
                        stopped.store(true, Ordering::SeqCst);
                        eyre::eyre!("AWS batch worker panicked")
                    }),
                    Err(error) => Err(error.into()),
                })
                .collect::<Vec<Result<()>>>()
        });
        joins.into_iter().collect::<Result<Vec<_>>>()?;
        drop(sender);
        let mut values: Vec<_> = std::iter::repeat_with(|| None).take(calls.len()).collect();
        for (index, result) in receiver {
            values[index] = Some(result);
        }
        Ok(values
            .into_iter()
            .map(|value| {
                value.unwrap_or_else(|| {
                    Err(eyre::eyre!(
                        "AWS batch request not dispatched after peer failure"
                    ))
                })
            })
            .collect())
    }
}

impl AwsApi for AwsCli {
    fn batch_call(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        self.batch_calls(service, calls, true)
    }

    fn batch_call_all(&self, service: &str, calls: &[AwsCall<'_>]) -> Result<Vec<Result<Value>>> {
        self.batch_calls(service, calls, false)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.aws_cli.call")
    )]
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra_args: &[String],
    ) -> Result<Value> {
        self.call_with_timeout(
            service,
            operation,
            input,
            extra_args,
            Duration::from_secs(60),
        )
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.aws_cli.call_with_timeout")
    )]
    fn call_with_timeout(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra_args: &[String],
        timeout: Duration,
    ) -> Result<Value> {
        ensure!(!timeout.is_zero(), "AWS call budget exhausted");
        let mut command = Command::new(&self.executable);
        // Start from the captured environment. No ambient credential or endpoint
        // variable can change the account after the initial validation.
        command.env_clear();
        command.envs(
            self.environment
                .iter()
                .filter(|(key, _)| !key.starts_with("AWS_")),
        );
        for key in [
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CA_BUNDLE",
        ] {
            if let Some(value) = self.environment.get(key) {
                command.env(key, value);
            }
        }
        command
            .env("AWS_PROFILE", &self.selection.profile)
            .env("AWS_REGION", &self.selection.region)
            .env("AWS_DEFAULT_REGION", &self.selection.region)
            .env("AWS_SDK_LOAD_CONFIG", "1")
            .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_MAX_ATTEMPTS", "1")
            .env("AWS_PAGER", "")
            .env("AWS_CLI_AUTO_PROMPT", "off")
            .args([
                "--profile",
                &self.selection.profile,
                "--region",
                &self.selection.region,
                "--output",
                "json",
                // API error classification uses the legacy error-code prefix.
                // Pin stderr separately from stdout and the profile setting.
                "--cli-error-format",
                "legacy",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "10",
                "--cli-read-timeout",
                "30",
                service,
                operation,
            ]);
        if service == "s3api" && operation == "get-object" {
            append_metadata_get_args(&mut command, input, extra_args, &self.selection.account_id)?;
        } else {
            command
                .arg("--cli-input-json")
                .arg(serde_json::to_string(&input)?)
                .args(extra_args);
        }
        // STS responses and credential-process diagnostics can contain tokens.
        // Keep both streams off disk for every AWS API call.
        let run = if self.in_credential_process {
            run_command_inherited_in_memory
        } else {
            run_command_in_memory
        };
        let output = run(&mut command, timeout)
            .map_err(|_| AwsApiError {
                code: "CommandInterrupted".into(),
            })
            .with_context(|| format!("AWS {service} {operation} subprocess did not complete"))?;
        if !output.success {
            let code = aws_error_code(&output.stderr);
            let exit_code = output
                .exit_code
                .map_or_else(|| "none".into(), |code| code.to_string());
            return Err(eyre::Report::from(AwsApiError { code }).wrap_err(format!(
                "AWS {service} {operation} subprocess failed (exit code {exit_code})"
            )));
        }
        if output.stdout.trim().is_empty() {
            return Ok(json!({}));
        }
        let value: Value =
            serde_json::from_str(&output.stdout).context("AWS CLI returned malformed JSON")?;
        if service == "sts" && operation == "get-caller-identity" {
            if let Some(role) = &self.expected_role {
                let identity: CallerIdentity = serde_json::from_value(value.clone())
                    .map_err(|_| eyre::eyre!("AWS CLI returned invalid caller identity"))?;
                crate::credentials::verify_role(&identity, role, &self.selection.account_id)?;
            }
        }
        Ok(value)
    }
}

/// AWS CLI excludes --cli-input-json for operations with streaming output.
/// Keep the metadata read bounded and its owner explicit while mapping only the
/// supported request shape to scalar flags and the required outfile positional.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.append_metadata_get_args")
)]
fn append_metadata_get_args(
    command: &mut Command,
    input: Value,
    extra_args: &[String],
    account_id: &str,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase", deny_unknown_fields)]
    struct GetObjectInput {
        bucket: String,
        key: String,
        expected_bucket_owner: String,
        range: String,
        #[serde(default)]
        version_id: Option<String>,
    }
    let input: GetObjectInput = serde_json::from_value(input)
        .map_err(|_| eyre::eyre!("unsupported metadata get-object request shape"))?;
    ensure!(
        split_backend(&format!("s3://{}/metadata", input.bucket))?.0 == input.bucket,
        "invalid metadata bucket name"
    );
    ensure!(
        !input.key.is_empty()
            && input.key.len() <= 1024
            && !input.key.starts_with('-')
            && !input.key.starts_with("file://")
            && !input.key.starts_with("fileb://")
            && !input.key.chars().any(char::is_control),
        "invalid metadata object key"
    );
    ensure!(
        input.expected_bucket_owner == account_id,
        "metadata bucket owner differs from the selected AWS account"
    );
    ensure!(
        [
            MAX_RECORD_BYTES,
            crate::build_reuse::MAX_BYTES as u64,
            crate::image::MAX_MANIFEST_BYTES as u64,
            crate::image::MAX_CONFIG_BYTES as u64
        ]
        .iter()
        .any(|limit| input.range == format!("bytes=0-{limit}")),
        "get-object must use a supported bounded byte range"
    );
    ensure!(
        extra_args.len() == 1
            && Path::new(&extra_args[0]).is_absolute()
            && !extra_args[0].chars().any(char::is_control),
        "metadata get-object requires one absolute output path"
    );
    for (flag, value) in [
        ("--bucket", input.bucket.as_str()),
        ("--key", input.key.as_str()),
        (
            "--expected-bucket-owner",
            input.expected_bucket_owner.as_str(),
        ),
        ("--range", input.range.as_str()),
    ] {
        command.arg(flag).arg(value);
    }
    if let Some(version) = input.version_id {
        ensure!(
            !version.is_empty() && version.len() <= 1024 && !version.chars().any(char::is_control),
            "invalid object version"
        );
        command.arg("--version-id").arg(version);
    }
    command.arg(&extra_args[0]);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsApiError {
    pub code: String,
}
impl std::fmt::Display for AwsApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AWS request failed ({})", self.code)
    }
}
impl std::error::Error for AwsApiError {}

/// Retry only bounded transport/service failures, never authorization failures.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.transient_error")
)]
pub(crate) fn transient_error(error: &eyre::Report) -> bool {
    error.downcast_ref::<AwsApiError>().is_some_and(|error| {
        matches!(
            error.code.as_str(),
            "TransportError"
                | "CommandInterrupted"
                | "SlowDown"
                | "Throttling"
                | "ThrottlingException"
                | "RequestLimitExceeded"
                | "RequestTimeout"
                | "RequestTimeoutException"
                | "InternalError"
                | "InternalFailure"
                | "ServiceUnavailable"
                | "ServiceUnavailableException"
        )
    })
}

#[derive(Debug)]
pub struct LeaseOwnershipChanged;
impl std::fmt::Display for LeaseOwnershipChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "deployment lease ownership changed; stop mutations and inspect the active operation",
        )
    }
}
impl std::error::Error for LeaseOwnershipChanged {}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.aws_error_code")
)]
fn aws_error_code(stderr: &str) -> String {
    // Client-side credential/configuration failures do not have the API error
    // prefix. Match known CLI diagnostics, but never include their arguments,
    // paths or credential-process output in the returned error.
    // AWS CLI 2.38 also wraps legacy diagnostics with this exact prefix.
    let lines: Vec<_> = stderr
        .lines()
        .map(str::trim)
        .map(|line| line.strip_prefix("aws: [ERROR]: ").unwrap_or(line))
        .collect();
    if lines.iter().any(|line| {
        line.starts_with("Your session has expired.")
            || line.starts_with(
                "Unable to refresh login credentials because of a change in your password.",
            )
            || line.starts_with("The SSO session associated with this profile has expired")
            || line.starts_with("Error loading SSO Token:")
            || line.starts_with("Cannot refresh credentials: MFA token required.")
            || (line.starts_with("Error when retrieving token from ")
                && line.contains("Token has expired and refresh failed"))
    }) {
        return "AuthenticationExpired".into();
    }
    if lines.iter().any(|line| {
        line.starts_with("Unable to locate credentials")
            || line.starts_with("Unable to locate authorization token")
            || line.starts_with("Partial credentials found in ")
            || line.starts_with("Error when retrieving credentials from ")
            || line.starts_with("Error when retrieving token from ")
            || line.starts_with(
                "Unable to create or refresh login credentials due to insufficient permissions.",
            )
            || line.starts_with("An unspecified error happened when resolving AWS credentials")
    }) {
        return "CredentialsUnavailable".into();
    }
    if lines.iter().any(|line| {
        (line.starts_with("The config profile (") && line.ends_with(") could not be found"))
            || line.starts_with("Unable to parse config file:")
            || line.starts_with("Infinite loop in credential configuration detected.")
            || line.starts_with("You must specify a region.")
    }) {
        return "ConfigurationError".into();
    }
    if let Some(code) = stderr
        .split_once("An error occurred (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(code, _)| code)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 80
                && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        })
    {
        return code.to_string();
    }
    if lines.iter().any(|line| {
        line.starts_with("Could not connect to the endpoint URL:")
            || line.starts_with("Connection was closed before we received a valid response")
            || line.starts_with("Read timeout on endpoint URL:")
            || line.starts_with("Connect timeout on endpoint URL:")
            || line.starts_with("Failed to connect to proxy URL:")
    }) {
        return "TransportError".into();
    }
    // Unknown failures may be permanent or authorization related. Do not retry
    // them simply because the CLI omitted a service error code.
    "CommandFailed".into()
}

fn error_is(error: &eyre::Report, codes: &[&str]) -> bool {
    error
        .downcast_ref::<AwsApiError>()
        .is_some_and(|e| codes.contains(&e.code.as_str()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CallerIdentity {
    pub account: String,
    pub arn: String,
    pub user_id: String,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_identity")
)]
pub fn verify_identity(api: &dyn AwsApi, selection: &AwsSelection) -> Result<CallerIdentity> {
    selection.validate()?;
    let raw = api
        .call("sts", "get-caller-identity", json!({}), &[])
        .with_context(|| {
            format!(
                "AWS session unavailable; sign in with aws sso login --profile {}",
                selection.profile
            )
        })?;
    let identity: CallerIdentity =
        serde_json::from_value(raw).context("invalid STS identity response")?;
    ensure!(
        identity.account == selection.account_id,
        "AWS account mismatch: expected {}, received {}",
        selection.account_id,
        identity.account
    );
    let arn: Vec<_> = identity.arn.splitn(6, ':').collect();
    ensure!(
        arn.len() == 6
            && arn[0] == "arn"
            && arn[1] == "aws"
            && matches!(arn[2], "iam" | "sts")
            && arn[4] == selection.account_id
            && !arn[5].is_empty()
            && !identity.user_id.is_empty(),
        "STS identity does not match the selected AWS account"
    );
    ensure!(
        !(arn[2] == "iam" && arn[5] == "root"),
        "root AWS caller is not supported; select a non-root IAM user or assumed-role source profile"
    );
    Ok(identity)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapRequest {
    pub team_id: String,
    pub account_id: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
}

impl BootstrapRequest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.bootstrap_request.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        Scope {
            team_id: self.team_id.clone(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
        }
        .validate()?;
        ensure!(
            self.team_id != "." && self.team_id != "..",
            "invalid team ID"
        );
        split_backend(&format!("s3://{}/{}", self.bucket, self.prefix))?;
        ensure!(
            self.prefix != "zdn-meta" && !self.prefix.starts_with("zdn-meta/"),
            "state prefix overlaps metadata"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapReceipt {
    pub version: u32,
    pub request: BootstrapRequest,
    pub bootstrap_id: Uuid,
    pub key_creation_started: bool,
    pub key_arn: Option<String>,
    pub bucket_creation_started: bool,
    pub bucket_created: bool,
    pub complete: bool,
}

/// Creates a separate backend, never a resource in the network's Pulumi stack.
/// A receipt is flushed before the first mutation. An ambiguous KMS creation
/// requires an explicitly supplied, ownership-tagged recovery ARN.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.bootstrap")
)]
pub fn bootstrap(
    api: &dyn AwsApi,
    selection: &AwsSelection,
    request: &BootstrapRequest,
    receipt_path: &Path,
    recovered_key: Option<&str>,
) -> Result<TeamDefinition> {
    request.validate()?;
    ensure!(
        request.account_id == selection.account_id && request.region == selection.region,
        "bootstrap account/region conflicts with selected AWS identity"
    );
    verify_identity(api, selection)?;
    let _lock = receipt_lock(receipt_path)?;
    ensure!(
        !receipt_path.with_extension("removal.json").try_exists()?,
        "team removal has begun; bootstrap cannot recreate this backend"
    );
    let mut receipt = if receipt_path.exists() {
        let saved: BootstrapReceipt = serde_json::from_slice(&read_record(receipt_path)?)
            .context("invalid bootstrap recovery receipt")?;
        ensure!(
            saved.version == 1 && saved.request == *request && !saved.bootstrap_id.is_nil(),
            "bootstrap request differs from recovery receipt"
        );
        saved
    } else {
        let saved = BootstrapReceipt {
            version: 1,
            request: request.clone(),
            bootstrap_id: Uuid::new_v4(),
            key_creation_started: false,
            key_arn: None,
            bucket_creation_started: false,
            bucket_created: false,
            complete: false,
        };
        save_record(receipt_path, &saved)?;
        saved
    };
    let bucket_input = json!({"Bucket":request.bucket,"ExpectedBucketOwner":request.account_id});
    let existing_bucket = match api.call("s3api", "head-bucket", bucket_input.clone(), &[]) {
        Ok(_) => true,
        Err(e) if error_is(&e, &["404", "NoSuchBucket", "NotFound"]) => false,
        Err(e) => return Err(e).context("cannot establish state bucket ownership"),
    };
    if existing_bucket {
        let tags = api
            .call("s3api", "get-bucket-tagging", bucket_input.clone(), &[])
            .context("existing bucket has no matching bootstrap ownership; do not adopt it")?;
        verify_tags(&tags, "TagSet", &receipt)?;
        ensure!(
            receipt.bucket_creation_started,
            "existing bucket was not created by this recovery receipt"
        );
        // Atomic creation tags recover a successful create whose response was lost.
        receipt.bucket_created = true;
        save_record(receipt_path, &receipt)?;
    } else {
        ensure!(
            !receipt.bucket_creation_started,
            "bucket creation has an uncertain result; inspect the saved receipt before recovery"
        );
        receipt.bucket_creation_started = true;
        save_record(receipt_path, &receipt)?;
        let mut configuration = json!({"Tags":ownership_tags(&receipt, false)});
        if request.region != "us-east-1" {
            configuration["LocationConstraint"] = json!(request.region);
        }
        let input = json!({"Bucket":request.bucket,"ObjectOwnership":"BucketOwnerEnforced",
            "CreateBucketConfiguration":configuration});
        // No blind create retry; a later attempt checks the atomic ownership tags.
        api.call("s3api", "create-bucket", input, &[])
            .context("bucket creation interrupted; preserve the recovery receipt")?;
        verify_tags(
            &api.call("s3api", "get-bucket-tagging", bucket_input.clone(), &[])?,
            "TagSet",
            &receipt,
        )?;
        receipt.bucket_created = true;
        save_record(receipt_path, &receipt)?;
    }
    verify_bucket_region(api, &bucket_input, &request.region)?;
    // Independent idempotent hardening, only after ownership is established.
    // Both must succeed before creating keys or uploading state/metadata.
    let calls = [
        AwsCall {
            operation: "put-public-access-block",
            input: json!({"Bucket":request.bucket,"ExpectedBucketOwner":request.account_id,
                "PublicAccessBlockConfiguration":public_block()}),
            extra_args: Vec::new(),
        },
        AwsCall {
            operation: "put-bucket-ownership-controls",
            input: json!({"Bucket":request.bucket,"ExpectedBucketOwner":request.account_id,
                "OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}}),
            extra_args: Vec::new(),
        },
    ];
    let results = api.batch_call("s3api", &calls)?;
    ensure!(results.len() == calls.len(), "incomplete bucket hardening");
    for result in results {
        result?;
    }
    let policy = tls_policy(&request.bucket);
    match api.call("s3api", "get-bucket-policy", bucket_input.clone(), &[]) {
        Ok(value) => ensure!(
            parse_policy(&value)? == policy,
            "state bucket has an unrelated policy; preserve it and recover manually"
        ),
        Err(e) if error_is(&e, &["NoSuchBucketPolicy"]) => {
            let mut input = bucket_input.clone();
            input["Policy"] = Value::String(serde_json::to_string(&policy)?);
            api.call("s3api", "put-bucket-policy", input, &[])?;
        }
        Err(e) => return Err(e),
    }
    if let Some(key) = recovered_key {
        ensure!(
            receipt.key_creation_started && receipt.key_arn.is_none(),
            "key recovery applies only to an interrupted create-key request"
        );
        verify_key(api, key, &receipt)?;
        receipt.key_arn = Some(key.to_string());
        save_record(receipt_path, &receipt)?;
    }
    if receipt.key_arn.is_none() {
        ensure!(
            !receipt.key_creation_started,
            "KMS creation has an uncertain result; inspect keys tagged with bootstrap {} and supply its ARN for explicit recovery",
            receipt.bootstrap_id
        );
        receipt.key_creation_started = true;
        save_record(receipt_path, &receipt)?;
        let key = api.call("kms", "create-key", json!({
            "Description":format!("zdn {} state and Pulumi secrets",request.team_id),
            "KeyUsage":"ENCRYPT_DECRYPT", "KeySpec":"SYMMETRIC_DEFAULT", "MultiRegion":false,
            "Tags":ownership_tags(&receipt,true)
        }), &[]).context("KMS create result uncertain; preserve receipt and use explicit key recovery")?;
        let arn = string_at(&key, "/KeyMetadata/Arn")?.to_string();
        validate_key_arn(
            &arn,
            &TeamAws {
                account_id: request.account_id.clone(),
                region: request.region.clone(),
            },
        )?;
        receipt.key_arn = Some(arn);
        save_record(receipt_path, &receipt)?;
    }
    let key_arn = receipt
        .key_arn
        .as_deref()
        .context("bootstrap key missing")?;
    verify_key(api, key_arn, &receipt)?;
    api.call("kms", "enable-key-rotation", json!({"KeyId":key_arn}), &[])?;
    let mut input = bucket_input.clone();
    input["VersioningConfiguration"] = json!({"Status":"Enabled"});
    api.call("s3api", "put-bucket-versioning", input, &[])?;
    // A resumed setup must not silently move a previously configured bucket to
    // another KMS key. Fresh S3 buckets use the default AES256 encryption.
    match api.call("s3api", "get-bucket-encryption", bucket_input.clone(), &[]) {
        Ok(current) => {
            let config = current
                .get("ServerSideEncryptionConfiguration")
                .context("missing bucket encryption settings")?;
            let config = normalize_encryption(config).context(
                "unexpected state bucket encryption settings; preserve it and recover manually",
            )?;
            let mut default_aes = config.clone();
            // AWS may report the disabled default explicitly. Bucket keys are
            // meaningful only with KMS; do not accept another field or key.
            if default_aes.pointer("/Rules/0/BucketKeyEnabled") == Some(&json!(false)) {
                default_aes["Rules"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("BucketKeyEnabled");
            }
            ensure!(
                config == encryption(key_arn)
                    || default_aes
                        == json!({"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}),
                "state bucket uses another encryption key; preserve it and recover manually"
            );
        }
        Err(error) if error_is(&error, &["ServerSideEncryptionConfigurationNotFoundError"]) => {}
        Err(error) => return Err(error),
    }
    let mut input = bucket_input;
    input["ServerSideEncryptionConfiguration"] = encryption(key_arn);
    api.call("s3api", "put-bucket-encryption", input, &[])?;
    let team = TeamDefinition {
        api_version: TEAM_API_VERSION.into(),
        team_id: request.team_id.clone(),
        revision: 1,
        bootstrap_id: receipt.bootstrap_id,
        aws: TeamAws {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
        },
        state: TeamState {
            backend: format!("s3://{}/{}", request.bucket, request.prefix),
            kms_key_arn: key_arn.to_string(),
        },
        deployment: None,
    };
    verify_backend(api, selection, &team)?;
    receipt.complete = true;
    save_record(receipt_path, &receipt)?;
    Ok(team)
}

/// Read-only import/preflight. It verifies the original owned backend without
/// changing bucket policies, encryption keys, or permissions.
pub fn verify_backend(
    api: &dyn AwsApi,
    selection: &AwsSelection,
    team: &TeamDefinition,
) -> Result<()> {
    let receipt = verify_backend_ownership(api, selection, team)?;
    let bucket = team.backend_bucket()?;
    let input = json!({"Bucket":bucket,"ExpectedBucketOwner":team.aws.account_id});
    verify_backend_settings(api, &input, team, &receipt)
}

/// Cleanup needs the original backend identity and working state access, not
/// unchanged setup settings. It never repairs or weakens the shared backend.
pub fn verify_backend_for_cleanup(
    api: &dyn AwsApi,
    selection: &AwsSelection,
    team: &TeamDefinition,
) -> Result<()> {
    let receipt = verify_backend_ownership(api, selection, team)?;
    verify_key(api, &team.state.kms_key_arn, &receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_backend_ownership")
)]
fn verify_backend_ownership(
    api: &dyn AwsApi,
    selection: &AwsSelection,
    team: &TeamDefinition,
) -> Result<BootstrapReceipt> {
    team.validate()?;
    ensure!(
        selection.account_id == team.aws.account_id && selection.region == team.aws.region,
        "selected account/region conflicts with team definition"
    );
    verify_identity(api, selection)?;
    let bucket = team.backend_bucket()?;
    let input = json!({"Bucket":bucket,"ExpectedBucketOwner":team.aws.account_id});
    api.call("s3api", "head-bucket", input.clone(), &[])?;
    verify_bucket_region(api, &input, &team.aws.region)?;
    let receipt = BootstrapReceipt {
        version: 1,
        request: BootstrapRequest {
            team_id: team.team_id.clone(),
            account_id: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
            bucket: bucket.to_string(),
            prefix: team.backend_prefix()?.to_string(),
        },
        bootstrap_id: team.bootstrap_id,
        key_creation_started: true,
        key_arn: Some(team.state.kms_key_arn.clone()),
        bucket_creation_started: true,
        bucket_created: true,
        complete: true,
    };
    verify_tags(
        &api.call("s3api", "get-bucket-tagging", input.clone(), &[])?,
        "TagSet",
        &receipt,
    )?;
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_backend_settings")
)]
fn verify_backend_settings(
    api: &dyn AwsApi,
    input: &Value,
    team: &TeamDefinition,
    receipt: &BootstrapReceipt,
) -> Result<()> {
    // Ownership is already established. These read-only settings are independent,
    // but every result must validate before the caller can proceed.
    let calls: Vec<_> = [
        "get-bucket-versioning",
        "get-public-access-block",
        "get-bucket-ownership-controls",
        "get-bucket-encryption",
        "get-bucket-policy",
    ]
    .into_iter()
    .map(|operation| AwsCall {
        operation,
        input: input.clone(),
        extra_args: Vec::new(),
    })
    .collect();
    let responses = api.batch_call("s3api", &calls)?;
    ensure!(
        responses.len() == calls.len(),
        "incomplete backend settings"
    );
    let mut responses = responses.into_iter();
    let versioning = responses.next().unwrap()?;
    ensure!(
        versioning.get("Status") == Some(&json!("Enabled")),
        "state bucket versioning must be enabled"
    );
    let block = responses.next().unwrap()?;
    ensure!(
        block.get("PublicAccessBlockConfiguration") == Some(&public_block()),
        "state bucket must block all public access"
    );
    let owner = responses.next().unwrap()?;
    ensure!(
        owner.pointer("/OwnershipControls/Rules")
            == Some(&json!([{"ObjectOwnership":"BucketOwnerEnforced"}])),
        "state bucket must disable ACLs"
    );
    let enc = responses.next().unwrap()?;
    ensure!(
        enc.get("ServerSideEncryptionConfiguration")
            .and_then(normalize_encryption)
            == Some(encryption(&team.state.kms_key_arn)),
        "state bucket must use the team's KMS encryption key"
    );
    ensure!(
        parse_policy(&responses.next().unwrap()?)? == tls_policy(team.backend_bucket()?),
        "state bucket policy does not match the managed TLS policy"
    );
    verify_key(api, &team.state.kms_key_arn, receipt)?;
    let rotation = api.call(
        "kms",
        "get-key-rotation-status",
        json!({"KeyId":team.state.kms_key_arn}),
        &[],
    )?;
    ensure!(
        rotation.get("KeyRotationEnabled") == Some(&json!(true)),
        "state KMS key rotation must be enabled"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_bucket_region")
)]
fn verify_bucket_region(api: &dyn AwsApi, input: &Value, expected: &str) -> Result<()> {
    let location = api.call("s3api", "get-bucket-location", input.clone(), &[])?;
    ensure!(
        location.get("LocationConstraint").is_some(),
        "missing state bucket location"
    );
    let region = match location.get("LocationConstraint").and_then(Value::as_str) {
        None | Some("") => "us-east-1",
        Some("EU") => "eu-west-1",
        Some(region) => region,
    };
    ensure!(region == expected, "state bucket is in a different region");
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_key")
)]
fn verify_key(api: &dyn AwsApi, arn: &str, receipt: &BootstrapReceipt) -> Result<()> {
    validate_key_arn(
        arn,
        &TeamAws {
            account_id: receipt.request.account_id.clone(),
            region: receipt.request.region.clone(),
        },
    )?;
    let key = api.call("kms", "describe-key", json!({"KeyId":arn}), &[])?;
    ensure!(
        key.pointer("/KeyMetadata/Arn") == Some(&json!(arn))
            && key.pointer("/KeyMetadata/KeyManager") == Some(&json!("CUSTOMER"))
            && key.pointer("/KeyMetadata/KeyUsage") == Some(&json!("ENCRYPT_DECRYPT"))
            && key.pointer("/KeyMetadata/KeySpec") == Some(&json!("SYMMETRIC_DEFAULT"))
            && key.pointer("/KeyMetadata/KeyState") == Some(&json!("Enabled")),
        "KMS key must be the enabled symmetric customer key in the recovery receipt"
    );
    let tags = api.call("kms", "list-resource-tags", json!({"KeyId":arn}), &[])?;
    ensure!(
        tags.get("Truncated").is_none_or(|v| v == &json!(false)),
        "KMS ownership tags response is incomplete"
    );
    verify_tags(&tags, "Tags", receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.ownership_tags")
)]
fn ownership_tags(receipt: &BootstrapReceipt, kms: bool) -> Value {
    let values = [
        ("zdn:project", "zdn".to_string()),
        ("zdn:team", receipt.request.team_id.clone()),
        ("zdn:bootstrap", receipt.bootstrap_id.to_string()),
    ];
    Value::Array(
        values
            .into_iter()
            .map(|(key, value)| {
                if kms {
                    json!({"TagKey":key,"TagValue":value})
                } else {
                    json!({"Key":key,"Value":value})
                }
            })
            .collect(),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.verify_tags")
)]
fn verify_tags(value: &Value, field: &str, receipt: &BootstrapReceipt) -> Result<()> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .context("missing ownership tags")?;
    let expected = ownership_tags(receipt, field == "Tags");
    ensure!(
        expected
            .as_array()
            .unwrap()
            .iter()
            .all(|tag| actual.contains(tag)),
        "resource belongs to a different team or bootstrap; refusing to adopt it"
    );
    Ok(())
}

fn public_block() -> Value {
    json!({"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true})
}

fn encryption(key: &str) -> Value {
    json!({"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":key},"BucketKeyEnabled":true}]})
}

/// S3 can report the independent SSE-C upload setting in addition to the KMS
/// defaults. Either documented singleton preserves our existing contract: this
/// tool requires the KMS defaults, but has never required an SSE-C upload block.
/// Unknown or malformed settings still fail comparison.
/// https://docs.aws.amazon.com/AmazonS3/latest/API/API_BlockedEncryptionTypes.html
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.normalize_encryption")
)]
fn normalize_encryption(config: &Value) -> Option<Value> {
    let mut config = config.clone();
    let rules = config.get_mut("Rules")?.as_array_mut()?;
    if rules.len() != 1 {
        return None;
    }
    let rule = rules[0].as_object_mut()?;
    if let Some(blocked) = rule.remove("BlockedEncryptionTypes") {
        if blocked != json!({"EncryptionType":["SSE-C"]})
            && blocked != json!({"EncryptionType":["NONE"]})
        {
            return None;
        }
    }
    Some(config)
}

pub(crate) fn tls_policy(bucket: &str) -> Value {
    json!({"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny",
        "Principal":"*","Action":"s3:*","Resource":[format!("arn:aws:s3:::{bucket}"),format!("arn:aws:s3:::{bucket}/*")],
        "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]})
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.parse_policy")
)]
fn parse_policy(value: &Value) -> Result<Value> {
    serde_json::from_str(
        value
            .get("Policy")
            .and_then(Value::as_str)
            .context("missing S3 bucket policy")?,
    )
    .context("invalid S3 bucket policy")
}

fn response_etag(value: &Value) -> Result<String> {
    let etag = string_at(value, "/ETag")?;
    ensure!(
        !etag.is_empty() && etag.len() <= 512 && !etag.chars().any(char::is_control),
        "AWS returned an invalid metadata ETag"
    );
    Ok(etag.to_string())
}

fn string_at<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .with_context(|| format!("AWS response is missing {path}"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.split_backend")
)]
fn split_backend(backend: &str) -> Result<(&str, &str)> {
    let (bucket, prefix) = backend
        .strip_prefix("s3://")
        .and_then(|v| v.split_once('/'))
        .context("backend must have the form s3://bucket/prefix without query options")?;
    ensure!(
        bucket.len() >= 3
            && bucket.len() <= 63
            && bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !bucket.starts_with('-')
            && !bucket.ends_with('-'),
        "invalid state bucket name"
    );
    ensure!(
        !prefix.is_empty()
            && prefix.len() <= 256
            && prefix.split('/').all(|part| !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "state prefix must contain plain path components"
    );
    Ok((bucket, prefix))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.validate_key_arn")
)]
fn validate_key_arn(arn: &str, aws: &TeamAws) -> Result<()> {
    let prefix = format!("arn:aws:kms:{}:{}:key/", aws.region, aws.account_id);
    let id = arn
        .strip_prefix(&prefix)
        .context("KMS key ARN must match the team account and region")?;
    ensure!(
        Uuid::parse_str(id).is_ok_and(|v| !v.is_nil()),
        "KMS key ARN must name an immutable key ID"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.regular_file")
)]
fn regular_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_file(),
            "metadata path must be a regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.read_record")
)]
fn read_record(path: &Path) -> Result<Vec<u8>> {
    regular_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "metadata record exceeds size limit"
    );
    Ok(bytes)
}

struct ReceiptLock(File);

impl Drop for ReceiptLock {
    fn drop(&mut self) {
        // A concurrent spawn can briefly inherit this open-file description.
        // Explicitly release ownership instead of waiting for its last close.
        let _ = FileExt::unlock(&self.0);
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.receipt_lock")
)]
fn receipt_lock(path: &Path) -> Result<ReceiptLock> {
    let parent = path.parent().context("receipt needs a parent directory")?;
    ensure!(parent.is_dir(), "receipt directory must already exist");
    regular_file(path)?;
    let lock_path = path.with_extension("lock");
    regular_file(&lock_path)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.try_lock_exclusive()
        .context("another setup owns this recovery receipt")?;
    Ok(ReceiptLock(lock))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.save_record")
)]
fn save_record(path: &Path, record: &impl Serialize) -> Result<()> {
    regular_file(path)?;
    let parent = path.parent().context("receipt needs a parent directory")?;
    let bytes = serde_json::to_vec_pretty(record)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "metadata record exceeds size limit"
    );
    let mut file = NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .context("save recovery receipt atomically")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataObject {
    pub bytes: Vec<u8>,
    pub etag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteCondition {
    Absent,
    Matches(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionalWrite {
    Written(String),
    Conflict,
}

/// Conditional writes are mandatory. There is intentionally no unconditional
/// update or delete method; leases are released through a compare-and-swap tombstone.
pub trait MetadataStore {
    fn get(&self, key: &str) -> Result<Option<MetadataObject>>;
    fn put(&self, key: &str, bytes: &[u8], condition: WriteCondition) -> Result<ConditionalWrite>;
}

pub struct S3Metadata<'a> {
    api: &'a dyn AwsApi,
    team: &'a TeamDefinition,
}
impl<'a> S3Metadata<'a> {
    pub fn new(api: &'a dyn AwsApi, team: &'a TeamDefinition) -> Result<Self> {
        team.validate()?;
        Ok(Self { api, team })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.s3_metadata.input")
    )]
    fn input(&self, key: &str) -> Result<Value> {
        ensure!(
            key.starts_with(&format!("{}/", self.team.metadata_prefix()))
                && !key.split('/').any(|part| part == ".." || part.is_empty()),
            "metadata key is outside the selected team namespace"
        );
        Ok(
            json!({"Bucket":self.team.backend_bucket()?,"Key":key,"ExpectedBucketOwner":self.team.aws.account_id}),
        )
    }
}

impl MetadataStore for S3Metadata<'_> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.s3_metadata.get")
    )]
    fn get(&self, key: &str) -> Result<Option<MetadataObject>> {
        let file = NamedTempFile::new()?;
        let mut input = self.input(key)?;
        input["Range"] = json!(format!("bytes=0-{MAX_RECORD_BYTES}"));
        let reply = match self.api.call(
            "s3api",
            "get-object",
            input,
            &[file.path().to_string_lossy().into_owned()],
        ) {
            Ok(reply) => reply,
            Err(error) if error_is(&error, &["NoSuchKey", "404", "NotFound"]) => return Ok(None),
            Err(error) => return Err(error),
        };
        let bytes = read_record(file.path())?;
        Ok(Some(MetadataObject {
            bytes,
            etag: response_etag(&reply)?,
        }))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "aws.s3_metadata.put")
    )]
    fn put(&self, key: &str, bytes: &[u8], condition: WriteCondition) -> Result<ConditionalWrite> {
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "metadata record exceeds size limit"
        );
        let mut input = self.input(key)?;
        input["ContentType"] = json!("application/json");
        input["ServerSideEncryption"] = json!("aws:kms");
        input["SSEKMSKeyId"] = json!(self.team.state.kms_key_arn);
        match condition {
            WriteCondition::Absent => input["IfNoneMatch"] = json!("*"),
            WriteCondition::Matches(etag) => {
                ensure!(!etag.is_empty(), "missing metadata ETag");
                input["IfMatch"] = json!(etag);
            }
        }
        let mut file = NamedTempFile::new()?;
        file.write_all(bytes)?;
        match self.api.call(
            "s3api",
            "put-object",
            input,
            &["--body".into(), file.path().to_string_lossy().into_owned()],
        ) {
            Ok(reply) => Ok(ConditionalWrite::Written(response_etag(&reply)?)),
            Err(error)
                if error_is(
                    &error,
                    &[
                        "PreconditionFailed",
                        "ConditionalRequestConflict",
                        "412",
                        "409",
                    ],
                ) =>
            {
                Ok(ConditionalWrite::Conflict)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkReservation {
    pub version: u32,
    pub scope: Scope,
    pub network_id: Uuid,
    pub owner_id: Uuid,
}

impl NetworkReservation {
    pub fn new(scope: Scope, network_id: Uuid, owner_id: Uuid) -> Result<Self> {
        let record = Self {
            version: 1,
            scope,
            network_id,
            owner_id,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.version == 1 && !self.network_id.is_nil() && !self.owner_id.is_nil(),
            "invalid network reservation"
        );
        Ok(())
    }

    pub fn key(&self) -> String {
        format!(
            "zdn-meta/v1/{}/networks/{}/reservation.json",
            self.scope.team_id, self.network_id
        )
    }
    pub fn lease_key(&self) -> String {
        format!(
            "zdn-meta/v1/{}/networks/{}/lease.json",
            self.scope.team_id, self.network_id
        )
    }
}

/// Reserve a full UUID. A retry may only reuse the identical immutable owner.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.reserve_network")
)]
pub fn reserve_network(store: &dyn MetadataStore, record: &NetworkReservation) -> Result<()> {
    record.validate()?;
    let bytes = serde_json::to_vec(record)?;
    for _ in 0..3 {
        if let Some(existing) = store.get(&record.key())? {
            let saved: NetworkReservation = serde_json::from_slice(&existing.bytes)?;
            saved.validate()?;
            ensure!(
                saved == *record,
                "network ID is already reserved by another owner or scope"
            );
            return Ok(());
        }
        if let ConditionalWrite::Written(_) =
            store.put(&record.key(), &bytes, WriteCondition::Absent)?
        {
            return Ok(());
        }
    }
    bail!("network reservation changed during conditional writes; retry with the same owner ID")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseOwner {
    pub operation_id: Uuid,
    pub holder_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseRecord {
    pub version: u32,
    pub reservation: NetworkReservation,
    pub owner: LeaseOwner,
    pub expires_at: u64,
    pub generation: u64,
    pub released: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseHandle {
    pub record: LeaseRecord,
    pub etag: String,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.read_lease")
)]
fn read_lease(
    store: &dyn MetadataStore,
    reservation: &NetworkReservation,
) -> Result<Option<LeaseHandle>> {
    let Some(object) = store.get(&reservation.lease_key())? else {
        return Ok(None);
    };
    let record: LeaseRecord =
        serde_json::from_slice(&object.bytes).context("invalid deployment lease")?;
    ensure!(
        record.version == 1
            && record.reservation == *reservation
            && record.generation > 0
            && !record.owner.operation_id.is_nil()
            && !record.owner.holder_id.is_nil()
            && !object.etag.is_empty(),
        "deployment lease has a different scope, owner, or format"
    );
    Ok(Some(LeaseHandle {
        record,
        etag: object.etag,
    }))
}

pub fn inspect_lease(
    store: &dyn MetadataStore,
    reservation: &NetworkReservation,
) -> Result<Option<LeaseHandle>> {
    reservation.validate()?;
    read_lease(store, reservation)
}

fn expiry(now: u64, ttl_seconds: u64) -> Result<u64> {
    ensure!(
        (60..=3600).contains(&ttl_seconds),
        "deployment lease duration must be 60-3600 seconds"
    );
    now.checked_add(ttl_seconds)
        .context("lease expiration overflows")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.acquire_lease")
)]
pub fn acquire_lease(
    store: &dyn MetadataStore,
    reservation: &NetworkReservation,
    owner: LeaseOwner,
    now: u64,
    ttl_seconds: u64,
) -> Result<LeaseHandle> {
    reservation.validate()?;
    ensure!(
        !owner.operation_id.is_nil() && !owner.holder_id.is_nil(),
        "lease owner IDs must not be nil"
    );
    let expires_at = expiry(now, ttl_seconds)?;
    ensure_reservation(store, reservation)?;
    let old = read_lease(store, reservation)?;
    if let Some(previous) = &old {
        if !previous.record.released {
            ensure!(
                previous.record.expires_at > now,
                "deployment lease is stale; inspect it and use explicit recovery with its observed ETag"
            );
            ensure!(
                previous.record.owner == owner,
                "another process holds the deployment lease"
            );
            // Repeated calls with the same holder do not extend the lifetime.
            return Ok(previous.clone());
        }
    }
    let generation = old.as_ref().map_or(Ok(1), |p| {
        p.record
            .generation
            .checked_add(1)
            .context("lease generation overflows")
    })?;
    let record = LeaseRecord {
        version: 1,
        reservation: reservation.clone(),
        owner,
        expires_at,
        generation,
        released: false,
    };
    acquire_lease_record(store, old.as_ref(), record)
}

/// Retry only this conditional request, with an unchanged holder, generation
/// and expiry. A lost write response is recovered only from the exact attempted
/// record. In particular, another owner's release must not retarget the retry.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.acquire_lease_record")
)]
fn acquire_lease_record(
    store: &dyn MetadataStore,
    old: Option<&LeaseHandle>,
    record: LeaseRecord,
) -> Result<LeaseHandle> {
    let condition = old.map_or(WriteCondition::Absent, |p| {
        WriteCondition::Matches(p.etag.clone())
    });
    let bytes = serde_json::to_vec(&record)?;
    for attempt in 0..3 {
        let failure = match store.put(&record.reservation.lease_key(), &bytes, condition.clone()) {
            Ok(ConditionalWrite::Written(etag)) => return Ok(LeaseHandle { record, etag }),
            Ok(ConditionalWrite::Conflict) => LeaseOwnershipChanged.into(),
            Err(error) if transient_error(&error) => error,
            Err(error) => return Err(error),
        };
        let failure = match read_lease(store, &record.reservation) {
            Ok(Some(current)) if current.record == record => return Ok(current),
            Ok(current) if current.as_ref() == old => failure,
            Ok(_) => return Err(LeaseOwnershipChanged.into()),
            Err(error) if transient_error(&error) => error,
            Err(error) => return Err(error),
        };
        if attempt == 2 {
            return Err(failure).context(
                "deployment lease acquisition remains uncertain; inspect its state before retrying",
            );
        }
    }
    unreachable!("bounded lease acquisition always returns")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.ensure_reservation")
)]
fn ensure_reservation(store: &dyn MetadataStore, reservation: &NetworkReservation) -> Result<()> {
    let object = store
        .get(&reservation.key())?
        .context("network ID must be reserved before acquiring a deployment lease")?;
    let saved: NetworkReservation = serde_json::from_slice(&object.bytes)?;
    ensure!(
        saved == *reservation,
        "network reservation belongs to a different owner"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.renew_lease")
)]
pub fn renew_lease(
    store: &dyn MetadataStore,
    handle: &mut LeaseHandle,
    now: u64,
    ttl_seconds: u64,
) -> Result<()> {
    ensure!(
        !handle.record.released && handle.record.expires_at > now,
        "cannot renew an expired or released lease"
    );
    let mut record = handle.record.clone();
    record.expires_at = expiry(now, ttl_seconds)?;
    ensure!(
        record.expires_at > handle.record.expires_at,
        "lease renewal must extend expiration"
    );
    record.generation = record
        .generation
        .checked_add(1)
        .context("lease generation overflows")?;
    let etag = match write_lease(store, &record, &handle.etag) {
        Ok(etag) => etag,
        Err(error) if transient_error(&error) || error.is::<LeaseOwnershipChanged>() => {
            // A successful CAS may lose its response. Only the exact attempted
            // record can recover it; a different holder/generation is not ours.
            match read_lease(store, &record.reservation)? {
                Some(current) if current.record == record => current.etag,
                Some(current) if current == *handle => return Err(error),
                _ => return Err(LeaseOwnershipChanged.into()),
            }
        }
        Err(error) => return Err(error),
    };
    *handle = LeaseHandle { record, etag };
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.release_lease")
)]
pub fn release_lease(store: &dyn MetadataStore, handle: &LeaseHandle, now: u64) -> Result<()> {
    ensure!(!handle.record.released, "lease is already released");
    let mut record = handle.record.clone();
    record.released = true;
    record.expires_at = now;
    record.generation = record
        .generation
        .checked_add(1)
        .context("lease generation overflows")?;
    // Never delete: an old process cannot remove a renewed/recovered owner's lock.
    write_lease(store, &record, &handle.etag)?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.recover_lease")
)]
pub fn recover_lease(
    store: &dyn MetadataStore,
    reservation: &NetworkReservation,
    observed_etag: &str,
    owner: LeaseOwner,
    now: u64,
    ttl_seconds: u64,
) -> Result<LeaseHandle> {
    reservation.validate()?;
    ensure!(
        !owner.operation_id.is_nil() && !owner.holder_id.is_nil(),
        "lease owner IDs must not be nil"
    );
    ensure_reservation(store, reservation)?;
    let old = read_lease(store, reservation)?.context("no deployment lease to recover")?;
    ensure!(
        old.etag == observed_etag && !old.record.released && old.record.expires_at <= now,
        "recovery requires the unchanged observed ETag of an expired lease"
    );
    let record = LeaseRecord {
        version: 1,
        reservation: reservation.clone(),
        owner,
        expires_at: expiry(now, ttl_seconds)?,
        generation: old
            .record
            .generation
            .checked_add(1)
            .context("lease generation overflows")?,
        released: false,
    };
    acquire_lease_record(store, Some(&old), record)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "aws.write_lease")
)]
fn write_lease(store: &dyn MetadataStore, record: &LeaseRecord, etag: &str) -> Result<String> {
    match store.put(
        &record.reservation.lease_key(),
        &serde_json::to_vec(record)?,
        WriteCondition::Matches(etag.to_string()),
    )? {
        ConditionalWrite::Written(etag) => Ok(etag),
        ConditionalWrite::Conflict => Err(LeaseOwnershipChanged.into()),
    }
}

#[cfg(test)]
mod error_classification_tests {
    use super::*;

    #[test]
    fn cli_authentication_and_configuration_errors_fail_without_retry_or_raw_output() {
        for (diagnostic, expected) in [
            ("Your session has expired. Please reauthenticate using 'aws login'.", "AuthenticationExpired"),
            ("The SSO session associated with this profile has expired or is otherwise invalid.", "AuthenticationExpired"),
            ("Error loading SSO Token: Token for fixture-secret does not exist", "AuthenticationExpired"),
            ("Error when retrieving token from sso: Token has expired and refresh failed", "AuthenticationExpired"),
            ("Cannot refresh credentials: MFA token required.", "AuthenticationExpired"),
            ("Unable to refresh login credentials because of a change in your password. Please reauthenticate.", "AuthenticationExpired"),
            ("Unable to locate credentials. You can configure credentials by running aws login.", "CredentialsUnavailable"),
            ("Unable to locate authorization token", "CredentialsUnavailable"),
            ("Partial credentials found in fixture-secret, missing: token", "CredentialsUnavailable"),
            ("Error when retrieving credentials from custom-process: fixture-secret", "CredentialsUnavailable"),
            ("Error when retrieving credentials from custom-process: An error occurred (RequestTimeout): fixture-secret", "CredentialsUnavailable"),
            ("Error when retrieving token from sso: fixture-secret", "CredentialsUnavailable"),
            ("Unable to create or refresh login credentials due to insufficient permissions. fixture-secret", "CredentialsUnavailable"),
            ("An unspecified error happened when resolving AWS credentials or refreshing a login session profile.", "CredentialsUnavailable"),
            ("The config profile (fixture-secret) could not be found", "ConfigurationError"),
            ("Unable to parse config file: fixture-secret", "ConfigurationError"),
            ("Infinite loop in credential configuration detected. fixture-secret", "ConfigurationError"),
            ("You must specify a region. fixture-secret", "ConfigurationError"),
            ("SSL validation failed for fixture-secret", "CommandFailed"),
            ("fixture-secret unrecognized failure", "CommandFailed"),
            ("An error occurred (AccessDenied) when calling a fixture operation: fixture-secret", "AccessDenied"),
            ("An error occurred (AccessDenied): fixture-secret\nRead timeout on endpoint URL: fixture-secret", "AccessDenied"),
        ] {
            let code = aws_error_code(&format!("\n{diagnostic}\n"));
            assert_eq!(code, expected, "{diagnostic}");
            let error = eyre::Report::from(AwsApiError { code });
            assert!(!transient_error(&error), "{diagnostic}");
            assert!(!format!("{error:#}").contains("fixture-secret"));
        }
    }

    #[test]
    fn only_recognized_transport_and_service_failures_are_retryable() {
        for diagnostic in [
            "Could not connect to the endpoint URL: fixture-secret",
            "Connection was closed before we received a valid response from endpoint URL: fixture-secret",
            "Read timeout on endpoint URL: fixture-secret",
            "Connect timeout on endpoint URL: fixture-secret",
            "Failed to connect to proxy URL: fixture-secret",
            "An error occurred (RequestTimeout) when calling the PutObject operation: fixture-secret",
            "An error occurred (ThrottlingException) when calling the fixture operation: fixture-secret",
        ] {
            let error = eyre::Report::from(AwsApiError { code: aws_error_code(diagnostic) });
            assert!(transient_error(&error), "{diagnostic}");
            assert!(!format!("{error:#}").contains("fixture-secret"));
        }
        assert!(transient_error(
            &AwsApiError {
                code: "CommandInterrupted".into()
            }
            .into()
        ));
    }
}

#[cfg(all(test, unix))]
mod receipt_lock_tests {
    use super::*;

    #[test]
    fn receipt_lock_releases_when_an_inherited_descriptor_remains_open() {
        // flock ownership is shared by duplicated descriptors, including a
        // concurrent spawn's fork-before-exec copy. Keep one alive deliberately
        // so this regression does not depend on process scheduling.
        for fail in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("recovery.json");
            let mut inherited = None;
            let result: Result<()> = (|| {
                let owner = receipt_lock(&path)?;
                inherited = Some(owner.0.try_clone()?);
                assert!(receipt_lock(&path).is_err());
                if fail {
                    bail!("simulated bootstrap error");
                }
                Ok(())
            })();
            assert_eq!(result.is_err(), fail);

            let next = receipt_lock(&path).expect("the completed scope must release its lock");
            assert!(receipt_lock(&path).is_err());
            drop(inherited);
            assert!(receipt_lock(&path).is_err());
            drop(next);
            assert!(receipt_lock(&path).is_ok());
        }
    }
}
