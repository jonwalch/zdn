//! Bounded, isolated Pulumi CLI execution for the generated AWS foundation.
//!
//! AWS identity checks and operation leases belong to the caller. This adapter
//! validates the selected account metadata, backend, project and secrets provider.

use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::dependencies::{builtin_manifest, current_platform, verify_installed};
use crate::infra::{parse_outputs, FoundationOutputs, FoundationSpec, AWS_PROVIDER_VERSION};

#[derive(Clone, Debug)]
pub struct ManagedTools {
    pub executable: PathBuf,
    pub bin_dir: PathBuf,
    pub plugins_dir: PathBuf,
}

impl ManagedTools {
    /// Verify every installed tool before returning paths. Never falls back to PATH.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.managed_tools.resolve")
    )]
    pub fn resolve(root: &Path) -> Result<Self> {
        let manifest = builtin_manifest()?;
        let receipt = verify_installed(&manifest, current_platform()?, root)?;
        let installation = fs::canonicalize(root.join(receipt.installation))?;
        Ok(Self {
            executable: installation.join("bin/pulumi"),
            bin_dir: installation.join("bin"),
            plugins_dir: installation.join("pulumi-home/plugins"),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsContext {
    pub profile: String,
    pub account_id: String,
    pub region: String,
    pub credential_files: Option<crate::credentials::CredentialFiles>,
}

impl AwsContext {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.aws_context.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.profile.is_empty()
                && self.profile.len() <= 128
                && self
                    .profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./@".contains(&b)),
            "invalid AWS profile"
        );
        ensure!(
            self.account_id.len() == 12 && self.account_id.bytes().all(|b| b.is_ascii_digit()),
            "invalid AWS account ID"
        );
        ensure!(
            self.region.len() <= 32
                && self.region.split('-').count() >= 3
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid AWS region"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PulumiWorkspace {
    pub tools: ManagedTools,
    pub work_dir: PathBuf,
    pub diagnostics_dir: PathBuf,
    pub backend_url: String,
    pub secrets_provider: String,
    pub aws: AwsContext,
    pub project: String,
    pub stack: String,
}

impl PulumiWorkspace {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.workspace.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        self.aws.validate()?;
        validate_backend(&self.backend_url)?;
        validate_secrets_provider(&self.secrets_provider, &self.aws)?;
        ensure!(
            valid_name(&self.project) && valid_name(&self.stack),
            "invalid Pulumi project or stack name"
        );
        ensure!(
            self.work_dir.is_absolute() && self.diagnostics_dir.is_absolute(),
            "Pulumi workspace paths must be absolute"
        );
        ensure!(
            self.tools.executable.is_absolute()
                && self.tools.bin_dir.is_absolute()
                && self.tools.plugins_dir.is_absolute(),
            "managed tool paths must be absolute"
        );
        ensure!(
            self.tools.executable.is_file(),
            "managed Pulumi executable is missing"
        );
        ensure!(
            self.tools.bin_dir.is_dir() && self.tools.plugins_dir.is_dir(),
            "managed Pulumi plugin directories are missing"
        );
        let project_path = self.work_dir.join("Pulumi.yaml");
        ensure!(
            fs::metadata(&project_path)?.len() <= 4 * 1024 * 1024,
            "Pulumi project exceeds its size limit"
        );
        let project: serde_yaml::Value = serde_yaml::from_slice(&fs::read(project_path)?)
            .map_err(|_| eyre::eyre!("invalid generated Pulumi project"))?;
        ensure!(
            project.get("name").and_then(serde_yaml::Value::as_str) == Some(self.project.as_str()),
            "Pulumi project name does not match workspace"
        );
        ensure!(
            project.get("runtime").and_then(serde_yaml::Value::as_str) == Some("yaml"),
            "Pulumi project must use the managed YAML runtime"
        );
        if let Some(backend) = project.get("backend") {
            ensure!(
                backend.get("url").and_then(serde_yaml::Value::as_str)
                    == Some(self.backend_url.as_str()),
                "Pulumi project backend does not match selected S3 state"
            );
        }
        Ok(())
    }

    pub fn pulumi_home(&self) -> PathBuf {
        self.work_dir.join(".pulumi")
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.workspace.prepare_home")
    )]
    fn prepare_home(&self) -> Result<()> {
        private_directory(&self.pulumi_home())?;
        private_directory(&self.diagnostics_dir)?;
        let plugins = self.pulumi_home().join("plugins");
        let target = fs::canonicalize(&self.tools.plugins_dir)?;
        if fs::symlink_metadata(&plugins).is_ok() {
            ensure!(
                fs::canonicalize(&plugins)? == target,
                "isolated Pulumi home has an unexpected plugin directory"
            );
        } else {
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, plugins)?;
            #[cfg(not(unix))]
            bail!("Pulumi execution requires macOS or Linux");
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.workspace.command")
    )]
    pub fn command(
        &self,
        label: &str,
        args: &[&str],
        limits: ProcessLimits,
    ) -> Result<CommandSpec> {
        self.validate()?;
        self.prepare_home()?;
        let mut env = BTreeMap::new();
        // Deliberately exclude ambient provider credentials, endpoint overrides,
        // Pulumi login/settings, loader injection and interactive configuration.
        for key in [
            "HOME",
            "USER",
            "TMPDIR",
            "TMP",
            "TEMP",
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Some(value) = std::env::var_os(key) {
                env.insert(OsString::from(key), value);
            }
        }
        let mut path = vec![self.tools.bin_dir.clone()];
        // Credential-process profiles may use executables on the user's PATH.
        if let Some(inherited) = std::env::var_os("PATH") {
            path.extend(std::env::split_paths(&inherited));
        }
        env.insert("PATH".into(), std::env::join_paths(path)?);
        for (key, value) in [
            ("AWS_PROFILE", self.aws.profile.as_str()),
            ("AWS_DEFAULT_PROFILE", self.aws.profile.as_str()),
            ("AWS_REGION", self.aws.region.as_str()),
            ("AWS_DEFAULT_REGION", self.aws.region.as_str()),
            ("AWS_SDK_LOAD_CONFIG", "1"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"),
            ("AWS_PAGER", ""),
            ("AWS_CLI_AUTO_PROMPT", "off"),
            ("PULUMI_BACKEND_URL", self.backend_url.as_str()),
            ("PULUMI_SKIP_UPDATE_CHECK", "true"),
            ("PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION", "true"),
            ("PULUMI_IGNORE_AMBIENT_PLUGINS", "true"),
            ("PULUMI_ENABLE_STREAMING_JSON_PREVIEW", "false"),
        ] {
            env.insert(key.into(), value.into());
        }
        if let Some(files) = &self.aws.credential_files {
            ensure!(
                files.config.is_absolute() && files.empty_credentials.is_absolute(),
                "credential paths must be absolute"
            );
            env.insert(
                "AWS_CONFIG_FILE".into(),
                files.config.clone().into_os_string(),
            );
            env.insert(
                "AWS_SHARED_CREDENTIALS_FILE".into(),
                files.empty_credentials.clone().into_os_string(),
            );
        }
        env.insert("PULUMI_HOME".into(), self.pulumi_home().into_os_string());
        let mut command_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        command_args.extend(["--non-interactive".into(), "--color".into(), "never".into()]);
        Ok(CommandSpec {
            label: label.to_owned(),
            program: self.tools.executable.clone(),
            args: command_args,
            env,
            cwd: self.work_dir.clone(),
            diagnostics_dir: self.diagnostics_dir.clone(),
            limits,
        })
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.validate_backend")
)]
pub fn validate_backend(url: &str) -> Result<()> {
    let path = url
        .strip_prefix("s3://")
        .context("Pulumi backend must be an explicit S3 URL")?;
    let (bucket, prefix) = path
        .split_once('/')
        .context("S3 state requires an explicit prefix")?;
    ensure!(
        (3..=63).contains(&bucket.len())
            && bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !bucket.starts_with('-')
            && !bucket.ends_with('-'),
        "invalid S3 state bucket"
    );
    ensure!(
        !prefix.is_empty()
            && prefix.split('/').all(|part| !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "invalid S3 state prefix"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.validate_secrets_provider")
)]
pub fn validate_secrets_provider(url: &str, aws: &AwsContext) -> Result<()> {
    aws.validate()?;
    let prefix = format!(
        "awskms:///arn:aws:kms:{}:{}:key/",
        aws.region, aws.account_id
    );
    let key = url.strip_prefix(&prefix).context(
        "KMS secrets provider must use a key ARN in the selected AWS account and region",
    )?;
    let (id, query) = key
        .split_once('?')
        .context("KMS secrets provider requires an explicit region")?;
    ensure!(
        Uuid::parse_str(id).is_ok()
            || (id.starts_with("mrk-")
                && id.len() == 36
                && id[4..].bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid KMS key ID"
    );
    ensure!(
        query == format!("region={}", aws.region),
        "KMS secrets provider region does not match selection"
    );
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub shutdown_grace: Duration,
    pub max_output_bytes: usize,
    pub poll_interval: Duration,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30 * 60),
            shutdown_grace: Duration::from_secs(30),
            max_output_bytes: 8 * 1024 * 1024,
            poll_interval: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub label: String,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: BTreeMap<OsString, OsString>,
    pub cwd: PathBuf,
    pub diagnostics_dir: PathBuf,
    pub limits: ProcessLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunControl {
    Continue,
    Cancel,
}

/// Called before spawning and at each poll. The caller retries transient failures
/// while it can still prove lease ownership. A returned error starts shutdown.
pub type Progress<'a> = dyn FnMut() -> Result<RunControl> + 'a;

#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub success: bool,
}

pub trait PulumiRunner {
    fn run(&self, command: &CommandSpec, progress: &mut Progress<'_>) -> Result<ProcessOutput>;
}

pub struct SystemPulumiRunner {
    helper: PathBuf,
}

impl SystemPulumiRunner {
    pub fn current_exe() -> Result<Self> {
        Ok(Self::new(std::env::current_exe()?))
    }

    /// Use the zdn binary that implements the private process-supervision protocol.
    pub fn new(helper: PathBuf) -> Self {
        Self { helper }
    }
}

impl PulumiRunner for SystemPulumiRunner {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.system_runner.run")
    )]
    fn run(&self, spec: &CommandSpec, progress: &mut Progress<'_>) -> Result<ProcessOutput> {
        ensure!(valid_name(&spec.label), "invalid Pulumi operation label");
        ensure!(
            !spec.limits.timeout.is_zero()
                && !spec.limits.shutdown_grace.is_zero()
                && spec.limits.shutdown_grace <= Duration::from_secs(60)
                && spec.limits.max_output_bytes > 0
                && spec.limits.max_output_bytes <= 64 * 1024 * 1024
                && !spec.limits.poll_interval.is_zero()
                && spec.limits.poll_interval <= Duration::from_secs(1),
            "invalid Pulumi process limits"
        );
        check_progress(progress)?;
        private_directory(&spec.diagnostics_dir)?;
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        let started = Instant::now();
        let mut child = crate::pulumi_process::Supervisor::spawn(
            &self.helper,
            spec,
            stdout.try_clone()?,
            stderr.try_clone()?,
        )?;
        let outcome = (|| -> Result<crate::pulumi_process::Completion> {
            loop {
                check_progress(progress)?;
                ensure!(
                    started.elapsed() <= spec.limits.timeout,
                    "Pulumi operation timed out"
                );
                ensure!(
                    stdout.metadata()?.len() <= spec.limits.max_output_bytes as u64
                        && stderr.metadata()?.len() <= spec.limits.max_output_bytes as u64,
                    "Pulumi operation exceeded its output limit"
                );
                if let Some(status) = child.poll()? {
                    return Ok(status);
                }
                std::thread::sleep(spec.limits.poll_interval);
            }
        })();
        if let Err(error) = &outcome {
            child.stop(error.to_string().contains("output limit"));
        }
        // A missing cleanup acknowledgement overrides success/cancellation. The
        // durable process receipt then prevents lease release and another run.
        let outcome = child
            .finish(|| {
                [&stdout, &stderr].into_iter().any(|file| {
                    file.metadata().map_or(true, |metadata| {
                        metadata.len() > spec.limits.max_output_bytes as u64
                    })
                })
            })
            .and(outcome);
        let out = read_bounded(&mut stdout, spec.limits.max_output_bytes)?;
        let err = read_bounded(&mut stderr, spec.limits.max_output_bytes)?;
        let classification = match &outcome {
            Ok(status) if status.success => "success",
            Ok(_) => classify_failure(&err, &out),
            Err(error) if error.to_string().contains("cleanup") => "cleanup-unconfirmed",
            Err(error) if error.to_string().contains("cancelled") => "cancelled",
            Err(error) if error.to_string().contains("timed out") => "timeout",
            Err(error) if error.to_string().contains("output limit") => "output-limit",
            Err(_) => "interrupted",
        };
        persist_diagnostic(
            spec,
            classification,
            outcome.as_ref().ok().and_then(|status| status.exit_code),
            started.elapsed(),
            &out,
            &err,
        )?;
        let status = outcome?;
        ensure!(
            stdout.metadata()?.len() <= spec.limits.max_output_bytes as u64
                && stderr.metadata()?.len() <= spec.limits.max_output_bytes as u64,
            "Pulumi operation exceeded its output limit"
        );
        Ok(ProcessOutput {
            stdout: out,
            stderr: err,
            exit_code: status.exit_code,
            success: status.success,
        })
    }
}

fn check_progress(progress: &mut Progress<'_>) -> Result<()> {
    match progress() {
        Ok(RunControl::Continue) => Ok(()),
        Ok(RunControl::Cancel) => bail!("Pulumi operation cancelled"),
        Err(_) => bail!("Pulumi operation stopped because its lease or progress check failed"),
    }
}

fn read_bounded(file: &mut File, limit: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.read_plan")
)]
fn read_plan(file: &tempfile::NamedTempFile, limit: usize) -> Result<Vec<u8>> {
    // reopen checks that the path still identifies the original temporary file.
    let mut input = file.reopen().context("saved Pulumi plan was replaced")?;
    ensure!(
        input.metadata()?.is_file(),
        "saved Pulumi plan must be a regular file"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "saved Pulumi plan exceeds its size limit"
    );
    Ok(bytes)
}

fn safe_up_operation(operation: &str) -> bool {
    matches!(operation, "same" | "create" | "update" | "read")
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    schema_version: u32,
    operation: &'a str,
    result: &'a str,
    exit_code: Option<i32>,
    elapsed_ms: u128,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_sha256: String,
    stderr_sha256: String,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.persist_diagnostic")
)]
fn persist_diagnostic(
    spec: &CommandSpec,
    result: &str,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<()> {
    let diagnostic = Diagnostic {
        schema_version: 1,
        operation: &spec.label,
        result,
        exit_code,
        elapsed_ms: elapsed.as_millis(),
        stdout_bytes: stdout.len(),
        stderr_bytes: stderr.len(),
        stdout_sha256: hex::encode(Sha256::digest(stdout)),
        stderr_sha256: hex::encode(Sha256::digest(stderr)),
    };
    let path = spec
        .diagnostics_dir
        .join(format!("{}-{}.json", spec.label, Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(&diagnostic)?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.private_directory")
)]
fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Pulumi private directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.classify_failure")
)]
fn classify_failure(stderr: &[u8], stdout: &[u8]) -> &'static str {
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(stderr),
        String::from_utf8_lossy(stdout)
    )
    .to_ascii_lowercase();
    if text.contains("expiredtoken")
        || text.contains("expired token")
        || text.contains("sso session")
    {
        "aws-session-expired"
    } else if text.contains("accessdenied")
        || text.contains("access denied")
        || text.contains("unauthorizedoperation")
    {
        "access-denied"
    } else if text.contains("the stack is currently locked")
        || text.contains("stack is locked")
        || text.contains("stack locked by")
        || text.contains("another update is currently in progress")
        || text.contains("concurrentupdate")
    {
        "stack-locked"
    } else {
        "command-failed"
    }
}

/// Keep only bounded, non-secret identifiers needed to recognize the pinned
/// provider's stale NAT address failure. Never expose the provider's raw output.
#[derive(Debug)]
pub(crate) struct PulumiFailure {
    label: String,
    category: &'static str,
    eip_disassociations: Vec<(Option<String>, String)>,
}

impl PulumiFailure {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.failure.from_output")
    )]
    pub(crate) fn from_output(label: &str, output: &ProcessOutput) -> Self {
        let category = classify_failure(&output.stderr, &output.stdout);
        let mut eip_disassociations = Vec::new();
        if label == "destroy" && category == "access-denied" {
            for bytes in [&output.stderr, &output.stdout] {
                for line in String::from_utf8_lossy(bytes).lines() {
                    let line = line.to_ascii_lowercase();
                    if !line.contains("disassociateaddress")
                        || !line.contains("disassociating ec2 eip (")
                        || !(line.contains("unauthorizedoperation")
                            || line.contains("accessdenied"))
                    {
                        continue;
                    }
                    let tokens = line
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                        .collect::<Vec<_>>();
                    let identifier = |prefix: &str| {
                        tokens.iter().copied().find(|token| {
                            token.strip_prefix(prefix).is_some_and(|suffix| {
                                (8..=17).contains(&suffix.len())
                                    && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                            })
                        })
                    };
                    // The pinned provider's disassociateEIP diagnostic names
                    // only the association. The checked checkpoint binds it to
                    // the allocation; reject a contrary allocation if included.
                    if let Some(association) = identifier("eipassoc-") {
                        eip_disassociations.push((
                            identifier("eipalloc-").map(str::to_owned),
                            association.into(),
                        ));
                    }
                }
            }
        }
        Self {
            label: label.into(),
            category,
            eip_disassociations,
        }
    }

    pub(crate) fn is_eip_disassociation(&self, allocation: &str, association: &str) -> bool {
        self.eip_disassociations
            .iter()
            .any(|(saved_allocation, saved_association)| {
                saved_allocation
                    .as_ref()
                    .is_none_or(|saved| saved == allocation)
                    && saved_association == association
            })
    }

    pub(crate) fn has_eip_disassociation(&self) -> bool {
        !self.eip_disassociations.is_empty()
    }
}

impl std::fmt::Display for PulumiFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Pulumi {} failed ({}); inspect the bounded diagnostic receipt",
            self.label, self.category
        )
    }
}
impl std::error::Error for PulumiFailure {}

pub struct PulumiClient<R> {
    pub workspace: PulumiWorkspace,
    runner: R,
    pub limits: ProcessLimits,
    prepared: bool,
    approved_plan: Option<SavedPlan>,
    expected_default_tags: Option<Value>,
}

struct SavedPlan {
    file: tempfile::NamedTempFile,
    sha256: [u8; 32],
    selection: [u8; 32],
}

impl<R: PulumiRunner> PulumiClient<R> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.new")
    )]
    pub fn new(workspace: PulumiWorkspace, runner: R) -> Result<Self> {
        workspace.validate()?;
        crate::pulumi_process::ensure_cleanup(&workspace.work_dir)?;
        let project: Value =
            serde_yaml::from_slice(&fs::read(workspace.work_dir.join("Pulumi.yaml"))?)
                .map_err(|_| eyre::eyre!("invalid generated Pulumi project"))?;
        let expected_default_tags = project
            .pointer("/resources/provider/properties/defaultTags")
            .cloned();
        if let Some(defaults) = &expected_default_tags {
            let tags = defaults
                .get("tags")
                .and_then(Value::as_object)
                .context("invalid generated AWS provider defaultTags")?;
            ensure!(
                defaults.as_object().is_some_and(|object| object.len() == 1)
                    && tags.len() == 3
                    && tags.get("zdn:managed-by").and_then(Value::as_str) == Some("zdn"),
                "generated AWS provider defaultTags must contain only ownership tags"
            );
            let bootstrap = tags
                .get("zdn:bootstrap")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .context("invalid generated AWS provider bootstrap tag")?;
            ensure!(
                !bootstrap.is_nil(),
                "invalid generated AWS provider bootstrap tag"
            );
            crate::state::Scope {
                team_id: tags
                    .get("zdn:team-id")
                    .and_then(Value::as_str)
                    .context("invalid generated AWS provider team tag")?
                    .into(),
                account_id: workspace.aws.account_id.clone(),
                region: workspace.aws.region.clone(),
            }
            .validate()?;
        }
        Ok(Self {
            workspace,
            runner,
            limits: ProcessLimits::default(),
            prepared: false,
            approved_plan: None,
            expected_default_tags,
        })
    }

    /// Discover existence from structured project-scoped results, never error text.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.stack_exists")
    )]
    pub fn stack_exists(&self, progress: &mut Progress<'_>) -> Result<bool> {
        let output = self.invoke(
            "stack-list",
            &[
                "stack",
                "ls",
                "--project",
                &self.workspace.project,
                "--output",
                "json",
            ],
            progress,
        )?;
        let value: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid Pulumi stack list JSON"))?;
        let stacks = value
            .as_array()
            .context("invalid Pulumi stack list shape")?;
        let mut names = BTreeSet::new();
        for stack in stacks {
            let name = stack
                .get("name")
                .and_then(Value::as_str)
                .context("Pulumi stack list entry has no name")?;
            let parts: Vec<_> = name.split('/').collect();
            let local = match parts.as_slice() {
                [name] if valid_name(name) => *name,
                [project, name] if *project == self.workspace.project && valid_name(name) => *name,
                ["organization", project, name]
                    if *project == self.workspace.project && valid_name(name) =>
                {
                    *name
                }
                _ => bail!("Pulumi stack list contains an invalid or foreign project name"),
            };
            ensure!(
                stack
                    .get("project")
                    .is_none_or(|v| v.as_str() == Some(self.workspace.project.as_str())),
                "Pulumi stack list contains a foreign project"
            );
            ensure!(
                stack.get("current").and_then(Value::as_bool).is_some(),
                "invalid Pulumi stack list current field"
            );
            ensure!(
                stack
                    .get("resourceCount")
                    .is_none_or(|v| v.as_u64().is_some()),
                "invalid Pulumi stack resource count"
            );
            ensure!(
                names.insert(local.to_owned()),
                "Pulumi stack list contains duplicate names"
            );
        }
        Ok(names.contains(&self.workspace.stack))
    }

    /// Creation is explicit. A failed select never falls back to creating state.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.prepare_stack")
    )]
    pub fn prepare_stack(&mut self, create: bool, progress: &mut Progress<'_>) -> Result<()> {
        self.approved_plan = None;
        self.prepared = false;
        let stack = self.workspace.stack.clone();
        if create {
            let secrets = self.workspace.secrets_provider.clone();
            self.invoke(
                "stack-init",
                &["stack", "init", &stack, "--secrets-provider", &secrets],
                progress,
            )?;
            self.validate_local_secrets()?;
        } else {
            self.invoke("stack-select", &["stack", "select", &stack], progress)?;
            if self
                .workspace
                .work_dir
                .join(format!("Pulumi.{}.yaml", self.workspace.stack))
                .exists()
            {
                self.validate_local_secrets()?;
            }
            let output = self.invoke(
                "stack-export",
                &["stack", "export", "--stack", &stack],
                progress,
            )?;
            self.validate_export(&output.stdout)?;
            if !self
                .workspace
                .work_dir
                .join(format!("Pulumi.{}.yaml", self.workspace.stack))
                .exists()
            {
                // Handoff regenerates the project, not its local stack config.
                // Restore the backend's wrapped KMS key without changing the
                // secrets provider or accepting an existing conflicting config.
                self.invoke(
                    "config-refresh",
                    &["config", "refresh", "--stack", &stack],
                    progress,
                )?;
                self.validate_local_secrets()?;
            }
        }
        self.prepared = true;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.preview")
    )]
    pub fn preview(&mut self, progress: &mut Progress<'_>) -> Result<PreviewSummary> {
        self.approved_plan = None;
        self.require_prepared()?;
        let file = tempfile::Builder::new()
            .prefix("foundation-plan-")
            .suffix(".json")
            .tempfile_in(self.workspace.pulumi_home())?;
        let path = file.path().to_str().context("invalid Pulumi plan path")?;
        let selection = self.plan_selection()?;
        let output = self.invoke(
            "preview",
            &[
                "preview",
                "--stack",
                &self.workspace.stack,
                "--json",
                "--save-plan",
                path,
            ],
            progress,
        )?;
        let summary = parse_preview(&output.stdout)?;
        ensure!(
            summary.changes.iter().all(|(op, count)| *count == 0 || safe_up_operation(op))
                && summary.resources.iter().all(|step| safe_up_operation(&step.operation)),
            "foundation up refuses resource deletion or replacement; use explicit teardown and a new network for destructive changes"
        );
        let bytes = read_plan(&file, self.limits.max_output_bytes)?;
        self.validate_plan(&bytes)?;
        ensure!(
            selection == self.plan_selection()?,
            "Pulumi project changed during preview"
        );
        self.approved_plan = Some(SavedPlan {
            file,
            sha256: Sha256::digest(bytes).into(),
            selection,
        });
        Ok(summary)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.preview_destroy")
    )]
    pub fn preview_destroy(&mut self, progress: &mut Progress<'_>) -> Result<PreviewSummary> {
        self.approved_plan = None;
        self.require_prepared()?;
        let output = self.invoke(
            "preview-destroy",
            &[
                "destroy",
                "--stack",
                &self.workspace.stack,
                "--preview-only",
                "--json",
            ],
            progress,
        )?;
        parse_preview_response(&output.stdout, true)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.up")
    )]
    pub fn up(&mut self, progress: &mut Progress<'_>) -> Result<()> {
        self.require_prepared()?;
        // A plan is single-use even when apply fails or is cancelled. A retry
        // must observe current state in a fresh preview.
        let plan = self
            .approved_plan
            .take()
            .context("foundation up requires a successful safe preview")?;
        ensure!(
            plan.selection == self.plan_selection()?,
            "Pulumi project or selection changed since preview"
        );
        ensure!(
            <[u8; 32]>::from(Sha256::digest(read_plan(
                &plan.file,
                self.limits.max_output_bytes
            )?)) == plan.sha256,
            "saved Pulumi plan changed since preview"
        );
        let path = plan
            .file
            .path()
            .to_str()
            .context("invalid Pulumi plan path")?;
        self.invoke(
            "up",
            &[
                "up",
                "--stack",
                &self.workspace.stack,
                "--yes",
                "--skip-preview",
                "--plan",
                path,
            ],
            progress,
        )?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.refresh")
    )]
    pub fn refresh(&mut self, progress: &mut Progress<'_>) -> Result<()> {
        self.approved_plan = None;
        self.require_prepared()?;
        self.invoke(
            "refresh",
            &[
                "refresh",
                "--stack",
                &self.workspace.stack,
                "--yes",
                "--skip-preview",
            ],
            progress,
        )?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.outputs")
    )]
    pub fn outputs(
        &self,
        spec: &FoundationSpec,
        progress: &mut Progress<'_>,
    ) -> Result<FoundationOutputs> {
        self.require_prepared()?;
        ensure!(
            spec.scope.account_id == self.workspace.aws.account_id
                && spec.scope.region == self.workspace.aws.region
                && spec.aws_profile == self.workspace.aws.profile,
            "foundation AWS selection does not match Pulumi workspace"
        );
        let output = self.invoke(
            "outputs",
            &[
                "stack",
                "output",
                "--stack",
                &self.workspace.stack,
                "--json",
            ],
            progress,
        )?;
        // Avoid exposing a malformed response or resource input in parse errors.
        parse_outputs(&output.stdout, spec).map_err(|_| {
            eyre::eyre!("Pulumi stack outputs are invalid or do not match the selected foundation")
        })
    }

    pub fn participant_outputs(&self, progress: &mut Progress<'_>) -> Result<Value> {
        ensure!(
            self.workspace.project == "zdn-participant",
            "not a participant stack"
        );
        self.administrator_outputs(progress)
    }

    pub fn access_outputs(&self, progress: &mut Progress<'_>) -> Result<Value> {
        ensure!(
            self.workspace.project == "zdn-access",
            "not an administrator access stack"
        );
        self.administrator_outputs(progress)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.administrator_outputs")
    )]
    fn administrator_outputs(&self, progress: &mut Progress<'_>) -> Result<Value> {
        self.require_prepared()?;
        ensure!(
            matches!(
                self.workspace.project.as_str(),
                "zdn-access" | "zdn-participant"
            ),
            "not an administrator access stack"
        );
        let output = self.invoke(
            "outputs",
            &[
                "stack",
                "output",
                "--stack",
                &self.workspace.stack,
                "--json",
            ],
            progress,
        )?;
        serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid administrator stack outputs"))
    }

    /// Read the selected administrator checkpoint before choosing recovery names.
    /// Apply the same identity/provider checks used when opening an existing stack.
    pub fn participant_export(&self, progress: &mut Progress<'_>) -> Result<Value> {
        ensure!(
            self.workspace.project == "zdn-participant",
            "not a participant stack"
        );
        self.administrator_export(progress)
    }

    pub fn access_export(&self, progress: &mut Progress<'_>) -> Result<Value> {
        ensure!(
            self.workspace.project == "zdn-access",
            "not an administrator access stack"
        );
        self.administrator_export(progress)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.administrator_export")
    )]
    fn administrator_export(&self, progress: &mut Progress<'_>) -> Result<Value> {
        self.require_prepared()?;
        ensure!(
            matches!(
                self.workspace.project.as_str(),
                "zdn-access" | "zdn-participant"
            ),
            "not an administrator access stack"
        );
        let output = self.invoke(
            "stack-export",
            &["stack", "export", "--stack", &self.workspace.stack],
            progress,
        )?;
        self.validate_export(&output.stdout)?;
        serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid administrator stack export"))
    }

    /// Export a selected foundation checkpoint with the normal provider and
    /// account checks before granting first-format permission to a new disk.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.foundation_export")
    )]
    pub fn foundation_export(&self, progress: &mut Progress<'_>) -> Result<Value> {
        self.require_prepared()?;
        ensure!(
            self.workspace.project == "zdn-foundation",
            "not a foundation stack"
        );
        let output = self.invoke(
            "stack-export",
            &["stack", "export", "--stack", &self.workspace.stack],
            progress,
        )?;
        self.validate_export(&output.stdout)?;
        serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid foundation stack export"))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.destroy")
    )]
    pub fn destroy(&mut self, progress: &mut Progress<'_>) -> Result<()> {
        self.approved_plan = None;
        self.require_prepared()?;
        self.invoke(
            "destroy",
            &[
                "destroy",
                "--stack",
                &self.workspace.stack,
                "--yes",
                "--skip-preview",
            ],
            progress,
        )?;
        Ok(())
    }

    /// Only administrator removal may clear protection, after validating every
    /// resource in the checkpoint against its original creation receipt.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.unprotect")
    )]
    pub fn unprotect(&mut self, urns: &[&str], progress: &mut Progress<'_>) -> Result<()> {
        if urns.is_empty() {
            return Ok(());
        }
        self.require_prepared()?;
        ensure!(
            matches!(
                self.workspace.project.as_str(),
                "zdn-access" | "zdn-participant"
            ) && urns.iter().all(|urn| urn.starts_with(&format!(
                "urn:pulumi:{}::{}::aws:",
                self.workspace.stack, self.workspace.project
            ))),
            "unprotect requires an owned administrator resource"
        );
        self.approved_plan = None;
        // Pinned CLI v3.268.0 state/state_unprotect.go accepts variadic URNs
        // and handles them in one state edit. Never broaden this to --all.
        let mut args = vec!["state", "unprotect"];
        args.extend_from_slice(urns);
        args.extend_from_slice(&["--stack", &self.workspace.stack, "--yes"]);
        self.invoke("state-unprotect", &args, progress)?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.remove_stack")
    )]
    pub fn remove_stack(&mut self, progress: &mut Progress<'_>) -> Result<()> {
        self.approved_plan = None;
        self.require_prepared()?;
        self.invoke(
            "stack-remove",
            &["stack", "rm", &self.workspace.stack, "--yes"],
            progress,
        )?;
        self.prepared = false;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.plan_selection")
    )]
    fn plan_selection(&self) -> Result<[u8; 32]> {
        self.workspace.validate()?;
        let project = Sha256::digest(fs::read(self.workspace.work_dir.join("Pulumi.yaml"))?);
        Ok(Sha256::digest(serde_json::to_vec(&(
            &self.workspace.backend_url,
            &self.workspace.secrets_provider,
            &self.workspace.aws.profile,
            &self.workspace.aws.account_id,
            &self.workspace.aws.region,
            &self.workspace.aws.credential_files,
            &self.workspace.project,
            &self.workspace.stack,
            &self.workspace.work_dir,
            hex::encode(project),
        ))?)
        .into())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.validate_plan")
    )]
    fn validate_plan(&self, bytes: &[u8]) -> Result<()> {
        // CLI v3.268.0 writes DeploymentPlanV1 directly (without the versioned
        // deployment wrapper). Inspect operations without retaining properties.
        let plan: Value = serde_json::from_slice(bytes)
            .map_err(|_| eyre::eyre!("invalid saved Pulumi plan JSON"))?;
        ensure!(
            plan.get("manifest").is_some_and(Value::is_object),
            "invalid saved Pulumi plan manifest"
        );
        let resources = plan
            .get("resourcePlans")
            .and_then(Value::as_object)
            .context("saved Pulumi plan is missing resource operations")?;
        let prefix = format!(
            "urn:pulumi:{}::{}::",
            self.workspace.stack, self.workspace.project
        );
        for (urn, resource) in resources {
            ensure!(
                urn.starts_with(&prefix) && urn.len() <= 1024 && !urn.chars().any(char::is_control),
                "saved Pulumi plan contains a foreign resource"
            );
            ensure!(resource.is_object(), "invalid saved Pulumi resource plan");
            if let Some(steps) = resource.get("steps") {
                ensure!(
                    steps.as_array().is_some_and(|steps| steps
                        .iter()
                        .all(|op| op.as_str().is_some_and(safe_up_operation))),
                    "foundation up refuses destructive or unsupported saved plan operations"
                );
            }
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.invoke")
    )]
    fn invoke(
        &self,
        label: &str,
        args: &[&str],
        progress: &mut Progress<'_>,
    ) -> Result<ProcessOutput> {
        let command = self.workspace.command(label, args, self.limits)?;
        let output = self.runner.run(&command, progress).map_err(|error| {
            // The system runner only returns fixed diagnostics, but the runner is
            // also a test/integration boundary. Do not forward arbitrary errors.
            let message = error.to_string();
            let category = if message.contains("cleanup") {
                "has unconfirmed process cleanup; retain the lease and inspect the process receipt"
            } else if message.contains("cancelled") {
                "cancelled"
            } else if message.contains("timed out") {
                "timed out"
            } else if message.contains("output limit") {
                "exceeded output limit"
            } else {
                "could not complete"
            };
            eyre::eyre!("Pulumi {label} {category}; inspect the bounded diagnostic receipt")
        })?;
        ensure!(
            output.stdout.len() <= self.limits.max_output_bytes
                && output.stderr.len() <= self.limits.max_output_bytes,
            "Pulumi response exceeded its output limit"
        );
        if !output.success {
            return Err(PulumiFailure::from_output(label, &output).into());
        }
        Ok(output)
    }

    fn require_prepared(&self) -> Result<()> {
        ensure!(
            self.prepared,
            "prepare and verify the Pulumi stack before running an operation"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.validate_local_secrets")
    )]
    fn validate_local_secrets(&self) -> Result<()> {
        let path = self
            .workspace
            .work_dir
            .join(format!("Pulumi.{}.yaml", self.workspace.stack));
        ensure!(
            fs::metadata(&path)
                .map(|m| m.len() <= 1024 * 1024)
                .unwrap_or(false),
            "Pulumi stack configuration is missing or too large"
        );
        let data = fs::read(path)?;
        let config: serde_yaml::Value = serde_yaml::from_slice(&data)
            .map_err(|_| eyre::eyre!("invalid Pulumi stack configuration"))?;
        ensure!(
            config
                .get("secretsprovider")
                .and_then(serde_yaml::Value::as_str)
                == Some(self.workspace.secrets_provider.as_str()),
            "Pulumi stack secrets provider does not match selected KMS key"
        );
        ensure!(
            config.get("encryptionsalt").is_none(),
            "Pulumi stack unexpectedly uses a passphrase"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.validate_provider")
    )]
    fn validate_provider(&self, value: &Value) -> Result<()> {
        let inputs = value.as_object().context("invalid AWS provider inputs")?;
        ensure!(
            inputs.get("profile").and_then(Value::as_str)
                == Some(self.workspace.aws.profile.as_str())
                && inputs.get("region").and_then(Value::as_str)
                    == Some(self.workspace.aws.region.as_str()),
            "saved AWS provider profile or region does not match selection"
        );
        let accounts = inputs
            .get("allowedAccountIds")
            .context("saved AWS provider has no account restriction")?;
        // Provider configuration may encode complex values as JSON strings.
        let decoded;
        let accounts = if let Some(text) = accounts.as_str() {
            decoded = serde_json::from_str::<Value>(text)
                .map_err(|_| eyre::eyre!("invalid saved AWS provider account restriction"))?;
            &decoded
        } else {
            accounts
        };
        ensure!(
            accounts == &serde_json::json!([self.workspace.aws.account_id]),
            "saved AWS provider account restriction does not match selection"
        );
        ensure!(
            inputs.get("version").and_then(Value::as_str) == Some(AWS_PROVIDER_VERSION),
            "saved AWS provider version does not match managed tools"
        );
        let default_tags = inputs
            .get("defaultTags")
            .map(|value| {
                if let Some(encoded) = value.as_str() {
                    serde_json::from_str::<Value>(encoded)
                        .map_err(|_| eyre::eyre!("invalid saved AWS provider defaultTags"))
                } else {
                    Ok(value.clone())
                }
            })
            .transpose()?;
        // A partial pre-fix foundation has no provider defaults yet. The next
        // checked plan can install the generated defaults, and teardown must
        // remain available. An explicit conflicting value is never accepted.
        ensure!(
            default_tags.is_none() || default_tags == self.expected_default_tags,
            "saved AWS provider defaultTags do not match generated ownership tags"
        );
        // The pinned provider adds these defaults during CheckConfig. Pulumi
        // can persist provider booleans as strings; accept only the exact safe
        // defaults in either representation, never arbitrary configuration.
        for (key, expected) in [
            ("skipRegionValidation", true),
            ("skipCredentialsValidation", false),
        ] {
            if let Some(value) = inputs.get(key) {
                let actual = value.as_bool().or_else(|| match value.as_str() {
                    Some("true") => Some(true),
                    Some("false") => Some(false),
                    _ => None,
                });
                ensure!(
                    actual == Some(expected),
                    "saved AWS provider has an unsupported {key} override"
                );
            }
        }
        ensure!(
            inputs.keys().all(|key| matches!(
                key.as_str(),
                "profile"
                    | "region"
                    | "allowedAccountIds"
                    | "version"
                    | "defaultTags"
                    | "skipRegionValidation"
                    | "skipCredentialsValidation"
                    | "__defaults"
                    | "__internal"
            )),
            "saved AWS provider has unsupported overrides"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi.client.validate_export")
    )]
    fn validate_export(&self, bytes: &[u8]) -> Result<()> {
        let export: Value = serde_json::from_slice(bytes)
            .map_err(|_| eyre::eyre!("invalid Pulumi stack export JSON"))?;
        ensure!(
            matches!(export.get("version").and_then(Value::as_u64), Some(3 | 4)),
            "unsupported Pulumi stack export version"
        );
        ensure!(
            export
                .get("features")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
            "unsupported Pulumi stack export features"
        );
        let deployment = export
            .get("deployment")
            .and_then(Value::as_object)
            .context("Pulumi stack export has no deployment")?;
        ensure!(
            deployment
                .get("snippets")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                && deployment
                    .get("extensions")
                    .is_none_or(|v| v.as_object().is_some_and(serde_json::Map::is_empty)),
            "Pulumi stack contains unsupported extensions"
        );
        if let Some(provider) = deployment.get("secrets_providers") {
            ensure!(
                provider.get("type").and_then(Value::as_str) == Some("cloud")
                    && provider.pointer("/state/url").and_then(Value::as_str)
                        == Some(self.workspace.secrets_provider.as_str()),
                "Pulumi stack secrets provider does not match selected KMS key"
            );
        } else {
            // An initialized but never updated stack has no deployment secrets
            // record. It is resumable only with its saved KMS stack settings.
            ensure!(
                deployment
                    .get("resources")
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
                "Pulumi stack has no KMS secrets metadata"
            );
            self.validate_local_secrets()?;
        }
        let mut resources = Vec::new();
        if let Some(value) = deployment.get("resources") {
            resources.extend(value.as_array().context("invalid Pulumi stack resources")?);
        }
        if let Some(pending) = deployment.get("pending_operations") {
            for operation in pending
                .as_array()
                .context("invalid Pulumi pending operations")?
            {
                resources.push(
                    operation
                        .get("resource")
                        .context("invalid Pulumi pending resource")?,
                );
            }
        }
        let prefix = format!(
            "urn:pulumi:{}::{}::",
            self.workspace.stack, self.workspace.project
        );
        let mut providers = BTreeSet::new();
        for resource in &resources {
            let urn = resource
                .get("urn")
                .and_then(Value::as_str)
                .context("Pulumi resource has no URN")?;
            ensure!(
                urn.starts_with(&prefix),
                "Pulumi stack contains a resource from another project or stack"
            );
            let kind = resource
                .get("type")
                .and_then(Value::as_str)
                .context("Pulumi resource has no type")?;
            ensure!(
                kind == "pulumi:pulumi:Stack"
                    || kind == "pulumi:providers:aws"
                    || kind.starts_with("aws:"),
                "Pulumi foundation contains an unsupported resource provider"
            );
            if kind == "pulumi:providers:aws" {
                self.validate_provider(
                    resource
                        .get("inputs")
                        .context("AWS provider has no saved configuration")?,
                )?;
                let id = resource
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .context("AWS provider has no identity")?;
                providers.insert(format!("{urn}::{id}"));
            }
        }
        for resource in resources {
            if resource
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("aws:"))
            {
                ensure!(
                    resource
                        .get("provider")
                        .and_then(Value::as_str)
                        .is_some_and(|provider| providers.contains(provider)),
                    "Pulumi resource uses an unverified AWS provider"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviewSummary {
    pub schema_version: u32,
    pub changes: BTreeMap<String, u64>,
    pub resources: Vec<PreviewResource>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviewResource {
    pub operation: String,
    pub urn: String,
}

pub fn parse_preview(bytes: &[u8]) -> Result<PreviewSummary> {
    parse_preview_response(bytes, false)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi.parse_preview_response")
)]
fn parse_preview_response(bytes: &[u8], allow_empty_destroy: bool) -> Result<PreviewSummary> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| eyre::eyre!("invalid Pulumi preview JSON"))?;
    ensure!(value.is_object(), "invalid Pulumi preview shape");
    ensure!(
        value
            .get("maybeCorrupt")
            .is_none_or(|v| v.as_bool() == Some(false)),
        "Pulumi preview reports potentially corrupt state"
    );
    let empty_changes = serde_json::Map::new();
    let summary = match value.get("changeSummary") {
        Some(summary) => summary
            .as_object()
            .context("invalid Pulumi preview change summary")?,
        None => {
            // Pulumi 3.268.0 omits empty maps/lists in PreviewDigest. Destroy of
            // an already-empty stack can therefore return only its duration.
            // Accept that narrow shape only for destroy; an up preview must
            // still provide its change summary before approving a saved plan.
            ensure!(
                allow_empty_destroy
                    && value.get("duration").and_then(Value::as_u64).is_some()
                    && value.as_object().unwrap().keys().all(|key| matches!(
                        key.as_str(),
                        "duration" | "maybeCorrupt" | "steps" | "diagnostics"
                    ))
                    && ["steps", "diagnostics"].iter().all(|key| value
                        .get(key)
                        .is_none_or(|items| items.as_array().is_some_and(Vec::is_empty))),
                "Pulumi preview is missing its change summary"
            );
            &empty_changes
        }
    };
    let mut changes = BTreeMap::new();
    for (operation, count) in summary {
        ensure!(
            valid_operation(operation),
            "unsupported Pulumi preview operation"
        );
        changes.insert(
            operation.clone(),
            count
                .as_u64()
                .context("invalid Pulumi preview change count")?,
        );
    }
    let mut resources = Vec::new();
    if let Some(steps) = value.get("steps") {
        for step in steps.as_array().context("invalid Pulumi preview steps")? {
            let operation = step
                .get("op")
                .and_then(Value::as_str)
                .context("Pulumi preview step has no operation")?;
            let urn = step
                .get("urn")
                .and_then(Value::as_str)
                .context("Pulumi preview step has no URN")?;
            ensure!(
                valid_operation(operation)
                    && urn.starts_with("urn:pulumi:")
                    && urn.len() <= 1024
                    && !urn.chars().any(char::is_control),
                "invalid Pulumi preview step"
            );
            resources.push(PreviewResource {
                operation: operation.to_owned(),
                urn: urn.to_owned(),
            });
        }
    }
    if let Some(diagnostics) = value.get("diagnostics") {
        for diagnostic in diagnostics
            .as_array()
            .context("invalid Pulumi preview diagnostics")?
        {
            ensure!(
                diagnostic.get("severity").and_then(Value::as_str) != Some("error"),
                "Pulumi preview contains an error diagnostic"
            );
        }
    }
    Ok(PreviewSummary {
        schema_version: 1,
        changes,
        resources,
    })
}

fn valid_operation(operation: &str) -> bool {
    matches!(
        operation,
        "same"
            | "create"
            | "update"
            | "delete"
            | "replace"
            | "create-replacement"
            | "delete-replaced"
            | "read"
            | "read-replacement"
            | "refresh"
            | "discard"
            | "discard-replaced"
            | "import"
            | "import-replacement"
            | "remove-pending-replace"
    )
}
