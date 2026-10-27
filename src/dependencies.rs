//! Offline prerequisite checks and an explicit, verified managed-tool installer.
//!
//! `doctor` only invokes local version commands. Downloads occur only in `install`.
//! A catalog is trusted input shipped with zdn, never fetched alongside a binary.

use eyre::{bail, ensure, Context, ContextCompat, Result};
use flate2::read::MultiGzDecoder;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CATALOG: &str = include_str!("../data/managed-tools-v1.json");
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_PROCESS_OUTPUT: u64 = 16 * 1024;
// AWS inventories are larger than tool-version output, but remain bounded and
// exclusively in memory because the same runner also captures credentials.
const MAX_MEMORY_PROCESS_OUTPUT: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub schema_version: u32,
    pub catalog: String,
    pub sources: Vec<String>,
    pub platforms: BTreeMap<String, Vec<ToolArtifact>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolArtifact {
    pub name: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub max_download_bytes: u64,
    pub max_unpacked_bytes: u64,
    pub files: Vec<ToolFile>,
    #[serde(default)]
    pub allowed_unused_executables: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolFile {
    pub archive_path: String,
    pub install_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledTool {
    pub name: String,
    pub version: String,
    pub archive_sha256: String,
    pub files: Vec<InstalledFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub schema_version: u32,
    pub catalog_sha256: String,
    pub platform: String,
    /// Relative to the caller's managed directory, never an arbitrary path.
    pub installation: String,
    pub tools: Vec<InstalledTool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PrerequisiteCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    pub ready: bool,
    pub checks: Vec<PrerequisiteCheck>,
    /// Local version checks do not establish IAM permissions or a signed-in identity.
    pub aws_identity_checked: bool,
}

#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub trait ProcessRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<ProcessOutput>;
}

pub struct SystemProcessRunner;

impl ProcessRunner for SystemProcessRunner {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "dependencies.system_process_runner.run")
    )]
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<ProcessOutput> {
        let mut command = Command::new(program);
        command
            .args(args)
            .env("AWS_PAGER", "")
            .env("AWS_CLI_AUTO_PROMPT", "off");
        run_command(&mut command, timeout)
    }
}

/// Run a prepared command with bounded time and output, preserving its arguments,
/// environment, and working directory. Standard input is closed; output is captured.
/// Timeout cleanup applies to the direct child, not arbitrary descendant processes.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.run_command")
)]
pub fn run_command(command: &mut Command, timeout: Duration) -> Result<ProcessOutput> {
    // Files avoid pipe deadlocks if a command produces both stdout and stderr.
    // The loop bounds output as well as elapsed time. No shell is involved.
    let program = command.get_program().to_string_lossy().into_owned();
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .with_context(|| format!("cannot run {program}; install it and add it to PATH"))?;
    let started = Instant::now();
    let status = loop {
        if stdout.metadata()?.len() > MAX_PROCESS_OUTPUT
            || stderr.metadata()?.len() > MAX_PROCESS_OUTPUT
            || started.elapsed() > timeout
        {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} command exceeded its time or output limit");
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = String::new();
    let mut err = String::new();
    stdout
        .take(MAX_PROCESS_OUTPUT + 1)
        .read_to_string(&mut out)?;
    stderr
        .take(MAX_PROCESS_OUTPUT + 1)
        .read_to_string(&mut err)?;
    ensure!(
        out.len() as u64 <= MAX_PROCESS_OUTPUT && err.len() as u64 <= MAX_PROCESS_OUTPUT,
        "{program} command exceeded its output limit"
    );
    Ok(ProcessOutput {
        success: status.success(),
        exit_code: status.code(),
        stdout: out,
        stderr: err,
    })
}

/// Capture potentially secret output in memory, never in temporary files.
/// Drain both pipes without blocking, so a full stderr pipe cannot block a child
/// which is also writing stdout. The deadline includes waiting for EOF after
/// the direct child exits. No reader threads can outlive the operation.
pub fn run_command_in_memory(command: &mut Command, timeout: Duration) -> Result<ProcessOutput> {
    memory_command(command, timeout, true)
}

/// A credential_process runs inside the enclosing AWS CLI or Pulumi group.
/// Its AWS calls must remain in that group so the enclosing runner can stop
/// the whole request. That caller owns descendant cleanup; this runner still
/// kills and reaps its direct child on failure and bounds both output pipes.
pub(crate) fn run_command_inherited_in_memory(
    command: &mut Command,
    timeout: Duration,
) -> Result<ProcessOutput> {
    memory_command(command, timeout, false)
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.memory_command")
)]
fn memory_command(
    command: &mut Command,
    timeout: Duration,
    own_group: bool,
) -> Result<ProcessOutput> {
    use std::os::unix::process::CommandExt;

    let program = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if own_group {
        command.process_group(0);
    }
    let mut child = MemoryProcess {
        child: command
            .spawn()
            .with_context(|| format!("cannot run {program}; install it and add it to PATH"))?,
        cleaned: false,
        own_group,
    };
    let started = Instant::now();
    let mut stdout = child.child.stdout.take().context("missing stdout pipe")?;
    let mut stderr = child.child.stderr.take().context("missing stderr pipe")?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut status = None;
    loop {
        ensure!(
            started.elapsed() <= timeout,
            "{program} command exceeded its time limit"
        );
        let stdout_done = drain_pipe(&mut stdout, &mut out)?;
        let stderr_done = drain_pipe(&mut stderr, &mut err)?;
        if status.is_none() {
            status = child.child.try_wait()?;
            if status.is_some() {
                // Reap owned helpers on success as well as failure. A
                // helper which detached into another group is outside our
                // cleanup scope; its inherited pipes still obey the deadline.
                child.cleanup();
            }
        }
        if let Some(status) = status {
            if stdout_done && stderr_done {
                return Ok(ProcessOutput {
                    success: status.success(),
                    exit_code: status.code(),
                    stdout: String::from_utf8(out).context("command stdout is not UTF-8")?,
                    stderr: String::from_utf8(err).context("command stderr is not UTF-8")?,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(unix))]
fn memory_command(_: &mut Command, _: Duration, _: bool) -> Result<ProcessOutput> {
    bail!("in-memory AWS command execution requires macOS or Linux")
}

#[cfg(unix)]
fn set_nonblocking(pipe: &impl std::os::fd::AsFd) -> Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = OFlag::from_bits_truncate(fcntl(pipe, FcntlArg::F_GETFL)?);
    fcntl(pipe, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

#[cfg(unix)]
fn drain_pipe(pipe: &mut impl Read, output: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0; 4096];
    loop {
        let remaining = (MAX_MEMORY_PROCESS_OUTPUT + 1 - output.len()).min(buffer.len());
        match pipe.read(&mut buffer[..remaining]) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                output.extend_from_slice(&buffer[..count]);
                ensure!(
                    output.len() <= MAX_MEMORY_PROCESS_OUTPUT,
                    "command exceeded its output limit"
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("cannot read command output"),
        }
    }
}

#[cfg(unix)]
struct MemoryProcess {
    child: std::process::Child,
    cleaned: bool,
    own_group: bool,
}

#[cfg(unix)]
impl MemoryProcess {
    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        use nix::{sys::signal::killpg, sys::signal::Signal, unistd::Pid};
        if self.own_group {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.cleaned = true;
    }
}

#[cfg(unix)]
impl Drop for MemoryProcess {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Never calls STS, SSO, a cloud API, or an installation command.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.doctor")
)]
pub fn doctor(runner: &dyn ProcessRunner, managed_root: Option<&Path>) -> DoctorReport {
    let mut checks = Vec::new();
    for (name, prefix) in [
        ("git", "git version "),
        ("aws", "aws-cli/2."),
        ("session-manager-plugin", ""),
    ] {
        let result = runner.run(name, &["--version"], Duration::from_secs(5));
        let (ok, detail) = match result {
            Ok(output) if output.success => {
                let text = format!("{}\n{}", output.stdout, output.stderr);
                let version = text.lines().map(str::trim).find(|line| !line.is_empty());
                let valid = version.is_some_and(|line| {
                    if name == "session-manager-plugin" {
                        line.split('.').count() >= 3
                            && line.split('.').all(|part| {
                                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
                            })
                    } else if name == "aws" {
                        crate::aws::validate_cli_version(line).is_ok()
                    } else {
                        line.starts_with(prefix)
                    }
                });
                if valid {
                    (true, version.unwrap_or_default().to_string())
                } else {
                    (
                        false,
                        format!(
                            "unsupported {name} version output; AWS CLI v2 >= 2.37.4 is required"
                        ),
                    )
                }
            }
            Ok(_) => (false, format!("{name} --version failed")),
            Err(error) => (false, error.to_string()),
        };
        checks.push(PrerequisiteCheck {
            name: name.to_string(),
            ok,
            detail,
        });
    }
    if let Some(root) = managed_root {
        let result = builtin_manifest().and_then(|manifest| {
            let platform = current_platform()?;
            verify_installed(&manifest, platform, root)
        });
        checks.push(match result {
            Ok(receipt) => PrerequisiteCheck {
                name: "managed-tools".into(),
                ok: true,
                detail: format!("verified pinned tools in {}", receipt.installation),
            },
            Err(error) => PrerequisiteCheck {
                name: "managed-tools".into(),
                ok: false,
                detail: format!("{error}; run zdn deps install"),
            },
        });
    }
    DoctorReport {
        ready: checks.iter().all(|check| check.ok),
        checks,
        aws_identity_checked: false,
    }
}

pub fn current_platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "x86_64") => Ok("darwin-amd64"),
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        (os, arch) => bail!("managed tools do not support {os}/{arch}"),
    }
}

pub fn builtin_manifest() -> Result<ToolManifest> {
    let manifest: ToolManifest = serde_json::from_str(CATALOG)?;
    manifest.validate()?;
    Ok(manifest)
}

impl ToolManifest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "dependencies.tool_manifest.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported managed-tool catalog version"
        );
        ensure!(!self.catalog.is_empty(), "managed-tool catalog has no name");
        ensure!(
            !self.platforms.is_empty(),
            "managed-tool catalog has no platforms"
        );
        for (platform, tools) in &self.platforms {
            safe_component(platform)?;
            ensure!(!tools.is_empty(), "managed-tool platform has no tools");
            let mut names = BTreeSet::new();
            let mut destinations = BTreeSet::new();
            for tool in tools {
                safe_component(&tool.name)?;
                safe_component(&tool.version)?;
                ensure!(names.insert(&tool.name), "duplicate tool {}", tool.name);
                ensure!(
                    valid_digest(&tool.sha256),
                    "invalid SHA256 pin for {}",
                    tool.name
                );
                validate_url(&tool.url, true)?;
                ensure!(
                    tool.max_download_bytes > 0 && tool.max_download_bytes <= 1024 * 1024 * 1024,
                    "invalid download limit"
                );
                ensure!(
                    tool.max_unpacked_bytes > 0
                        && tool.max_unpacked_bytes <= 4 * 1024 * 1024 * 1024,
                    "invalid unpacked limit"
                );
                ensure!(!tool.files.is_empty(), "tool has no required files");
                let mut archive_paths = BTreeSet::new();
                for file in &tool.files {
                    safe_path(&file.archive_path)?;
                    safe_path(&file.install_path)?;
                    ensure!(
                        archive_paths.insert(&file.archive_path),
                        "duplicate archive file"
                    );
                    ensure!(
                        destinations.insert(&file.install_path),
                        "duplicate install path"
                    );
                    ensure!(
                        file.install_path.starts_with("bin/")
                            || file.install_path.starts_with("pulumi-home/plugins/"),
                        "tool destination must be in bin or pulumi-home/plugins"
                    );
                }
                for path in &tool.allowed_unused_executables {
                    safe_path(path)?;
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_component(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "unsafe name in managed-tool metadata"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.safe_path")
)]
fn safe_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value.contains(['\\', ':', '\0'])
            && value
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(value)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "unsafe archive or installation path: {value:?}"
    );
    Ok(())
}

/// `allow_loopback` exists for local component tests; ordinary downloads require TLS.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.validate_url")
)]
fn validate_url(url: &str, allow_loopback: bool) -> Result<()> {
    ensure!(
        !url.bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            && !url.contains(['@', '#', '\\']),
        "invalid tool download URL"
    );
    if let Some(rest) = url.strip_prefix("https://") {
        ensure!(
            !rest.is_empty() && !rest.starts_with('/'),
            "invalid HTTPS download URL"
        );
        return Ok(());
    }
    if allow_loopback {
        let port_and_path = url
            .strip_prefix("http://127.0.0.1:")
            .or_else(|| url.strip_prefix("http://[::1]:"));
        if let Some(rest) = port_and_path {
            let port = rest.split('/').next().unwrap_or_default();
            ensure!(
                port.parse::<u16>().is_ok_and(|p| p > 0),
                "invalid loopback download URL"
            );
            return Ok(());
        }
    }
    bail!("tool downloads require HTTPS (explicit loopback test mode permits local HTTP)")
}

pub trait Downloader {
    /// Write at most max_bytes; return an error on truncation, timeout, or cancellation.
    fn download(&self, url: &str, destination: &mut File, max_bytes: u64) -> Result<()>;
}

#[derive(Default)]
pub struct HttpDownloader {
    allow_loopback: bool,
}

impl HttpDownloader {
    /// Enables only numeric loopback HTTP URLs, including redirects.
    pub fn for_loopback_tests() -> Self {
        Self {
            allow_loopback: true,
        }
    }
}

impl Downloader for HttpDownloader {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "dependencies.http_downloader.download")
    )]
    fn download(&self, url: &str, destination: &mut File, max_bytes: u64) -> Result<()> {
        let mut current_url = url.to_string();
        let deadline = Instant::now() + Duration::from_secs(300);
        for _ in 0..=5 {
            validate_url(&current_url, self.allow_loopback)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("tool download deadline expired")?;
            // ureq 2's standard resolver has no deadline. Bound the caller's
            // wait for OS DNS as well as each connection and response body.
            let agent = ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(remaining.min(Duration::from_secs(15)))
                .timeout_read(remaining.min(Duration::from_secs(30)))
                .timeout(remaining)
                .resolver(move |name: &str| {
                    let dns_deadline = deadline.min(Instant::now() + Duration::from_secs(15));
                    resolve_before(name, dns_deadline, |owned| {
                        owned.to_socket_addrs().map(Iterator::collect)
                    })
                })
                .build();
            let response = agent
                .get(&current_url)
                .timeout(
                    deadline
                        .checked_duration_since(Instant::now())
                        .context("tool download deadline expired")?,
                )
                .call()
                .context("tool download failed")?;
            if (300..400).contains(&response.status()) {
                // Official release redirects use absolute HTTPS URLs. Refuse an
                // ambiguous relative location instead of implementing a URL resolver.
                current_url = response
                    .header("Location")
                    .context("redirect has no location")?
                    .into();
                continue;
            }
            ensure!(
                response.status() == 200,
                "tool server did not return a complete file"
            );
            let length = response
                .header("Content-Length")
                .map(str::parse::<u64>)
                .transpose()?;
            if let Some(length) = length {
                ensure!(
                    length <= max_bytes,
                    "tool download exceeds its pinned size limit"
                );
            }
            let copied =
                std::io::copy(&mut response.into_reader().take(max_bytes + 1), destination)?;
            ensure!(copied <= max_bytes, "tool download exceeds its size limit");
            if let Some(length) = length {
                ensure!(copied == length, "tool download was truncated");
            }
            destination.flush()?;
            return Ok(());
        }
        bail!("too many tool download redirects")
    }
}

/// Return by the caller's deadline even if the OS resolver remains blocked.
/// A timed-out worker can finish later, but it owns no archive or installer state.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.resolve_before")
)]
fn resolve_before(
    name: &str,
    deadline: Instant,
    lookup: impl FnOnce(String) -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "tool DNS lookup deadline expired")
        })?;
    let owned = name.to_owned();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("zdn-dns".into())
        .spawn(move || {
            let _ = sender.send(lookup(owned));
        })?;
    receiver
        .recv_timeout(remaining)
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => {
                io::Error::new(io::ErrorKind::TimedOut, "tool DNS lookup deadline expired")
            }
            std::sync::mpsc::RecvTimeoutError::Disconnected => {
                io::Error::other("tool DNS resolver stopped before returning a result")
            }
        })?
}

pub fn install_builtin(root: &Path) -> Result<InstallReceipt> {
    install(
        &builtin_manifest()?,
        current_platform()?,
        root,
        &HttpDownloader::default(),
    )
}

/// Install a trusted catalog. Callers must not accept a catalog from an untrusted URL.
/// The only activation point is the atomic rename of `active.json` after all tools
/// and the immutable receipt have been synced. A failed install cannot replace it.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.install")
)]
pub fn install(
    manifest: &ToolManifest,
    platform: &str,
    root: &Path,
    downloader: &dyn Downloader,
) -> Result<InstallReceipt> {
    manifest.validate()?;
    safe_component(platform)?;
    let artifacts = manifest
        .platforms
        .get(platform)
        .context("platform is absent from managed-tool catalog")?;
    fs::create_dir_all(root)?;
    ensure_directory(root)?;
    let lock_path = root.join(".install.lock");
    ensure_optional_regular(&lock_path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.try_lock_exclusive()
        .context("another managed-tool install is running; retry after it finishes")?;
    let _lock = InstallLock(lock);
    let catalog_sha256 = manifest.digest()?;
    let installation = format!("versions/{catalog_sha256}-{platform}");
    let destination = root.join(&installation);
    let versions = root.join("versions");
    fs::create_dir_all(&versions)?;
    ensure_directory(&versions)?;
    clean_abandoned_staging(root)?;
    if destination.exists() {
        ensure_directory(&destination)?;
        let receipt = read_receipt(&destination.join("receipt.json"))?;
        verify_receipt(manifest, platform, root, &receipt)?;
        activate(root, &receipt)?;
        return Ok(receipt);
    }
    // Named staging directories allow the next invocation to remove leftovers
    // from SIGKILL. The active installation is outside every staging directory.
    let staging = tempfile::Builder::new()
        .prefix(".zdn-install-")
        .tempdir_in(root)?;
    let mut installed = Vec::new();
    for artifact in artifacts {
        let mut archive = tempfile::tempfile_in(staging.path())?;
        downloader
            .download(&artifact.url, &mut archive, artifact.max_download_bytes)
            .with_context(|| format!("cannot download {} {}", artifact.name, artifact.version))?;
        ensure!(
            archive.metadata()?.len() <= artifact.max_download_bytes,
            "download exceeds catalog limit"
        );
        archive.seek(SeekFrom::Start(0))?;
        let actual_sha256 = hash_reader(&mut archive)?;
        ensure!(
            actual_sha256 == artifact.sha256,
            "SHA256 mismatch for {}; installation was not changed",
            artifact.name
        );
        archive.seek(SeekFrom::Start(0))?;
        let files = extract_tool(&mut archive, artifact, staging.path())?;
        installed.push(InstalledTool {
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            archive_sha256: artifact.sha256.clone(),
            files,
        });
    }
    let receipt = InstallReceipt {
        schema_version: 1,
        catalog_sha256,
        platform: platform.to_string(),
        installation,
        tools: installed,
    };
    write_new_json(&staging.path().join("receipt.json"), &receipt)?;
    sync_tree_directories(staging.path())?;
    fs::rename(staging.path(), &destination)?;
    sync_directory(&versions)?;
    // A crash here leaves an intact but inactive version which can be reused.
    activate(root, &receipt)?;
    Ok(receipt)
}

struct InstallLock(File);

impl Drop for InstallLock {
    fn drop(&mut self) {
        // A concurrent spawn can inherit this file description until exec.
        // Closing our descriptor alone can leave that child holding the lock.
        let _ = FileExt::unlock(&self.0);
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.extract_tool")
)]
fn extract_tool(
    archive_file: &mut File,
    artifact: &ToolArtifact,
    root: &Path,
) -> Result<Vec<InstalledFile>> {
    let decoder = MultiGzDecoder::new(archive_file).take(artifact.max_unpacked_bytes + 1);
    let mut archive = tar::Archive::new(decoder);
    let wanted: BTreeMap<_, _> = artifact
        .files
        .iter()
        .map(|file| (file.archive_path.as_str(), file))
        .collect();
    let mut seen = BTreeSet::new();
    let mut found = BTreeMap::new();
    let mut declared_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = std::str::from_utf8(&entry.path_bytes())?.to_string();
        let path = raw_path.strip_prefix("./").unwrap_or(&raw_path);
        let path = if entry.header().entry_type().is_dir() {
            path.trim_end_matches('/')
        } else {
            path
        };
        if path.is_empty() || path == "." {
            ensure!(
                entry.header().entry_type().is_dir(),
                "invalid root archive entry"
            );
            continue;
        }
        safe_path(path)?;
        ensure!(seen.len() < 1024, "too many archive entries");
        ensure!(seen.insert(path.to_string()), "duplicate archive path");
        let mode = entry.header().mode()?;
        ensure!(mode & 0o7000 == 0, "privileged file modes are forbidden");
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "archive links and special files are forbidden"
        );
        declared_bytes = declared_bytes
            .checked_add(entry.size())
            .context("archive size overflow")?;
        ensure!(
            declared_bytes <= artifact.max_unpacked_bytes,
            "archive exceeds unpacked limit"
        );
        if kind.is_dir() {
            continue;
        }
        if let Some(file) = wanted.get(path) {
            ensure!(mode & 0o111 != 0, "required tool is not executable");
            let destination = root.join(&file.install_path);
            let parent = destination
                .parent()
                .context("tool destination has no parent")?;
            fs::create_dir_all(parent)?;
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination)?;
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            let mut buffer = [0; 64 * 1024];
            loop {
                let n = entry.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                output.write_all(&buffer[..n])?;
                hasher.update(&buffer[..n]);
                size += n as u64;
            }
            ensure!(size == entry.size(), "archive file is truncated");
            set_executable(&output)?;
            output.sync_all()?;
            found.insert(
                file.install_path.clone(),
                InstalledFile {
                    path: file.install_path.clone(),
                    sha256: hex::encode(hasher.finalize()),
                    size,
                },
            );
        } else {
            ensure!(
                mode & 0o111 == 0
                    || artifact
                        .allowed_unused_executables
                        .iter()
                        .any(|allowed| allowed == path),
                "unexpected executable in tool archive: {path}"
            );
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
    }
    // Read the gzip trailer as well, so truncated streams or bad CRCs fail even
    // when tar has already seen its end marker. Only zero tar padding may follow.
    let mut decoder = archive.into_inner();
    let mut buffer = [0; 8192];
    loop {
        let n = decoder.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ensure!(
            buffer[..n].iter().all(|byte| *byte == 0),
            "unexpected data after tar end marker"
        );
    }
    ensure!(decoder.limit() > 0, "archive exceeds unpacked limit");
    ensure!(
        found.len() == wanted.len(),
        "archive is missing a required tool"
    );
    Ok(found.into_values().collect())
}

#[cfg(unix)]
fn set_executable(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_file: &File) -> Result<()> {
    bail!("managed tools require macOS or Linux")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.clean_abandoned_staging")
)]
fn clean_abandoned_staging(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".zdn-install-")
        {
            // Do not follow a planted link, and never remove unrelated directories.
            ensure!(
                entry.file_type()?.is_dir(),
                "unexpected managed-tool staging entry"
            );
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.activate")
)]
fn activate(root: &Path, receipt: &InstallReceipt) -> Result<()> {
    ensure_optional_regular(&root.join("active.json"))?;
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(file.as_file_mut(), receipt)?;
    file.as_file_mut().write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(root.join("active.json"))?;
    sync_directory(root)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_receipt(path: &Path) -> Result<InstallReceipt> {
    ensure_optional_regular(path)?;
    let file = File::open(path).context("managed tools are not installed")?;
    ensure!(
        file.metadata()?.len() <= MAX_RECEIPT_BYTES,
        "managed-tool receipt is too large"
    );
    Ok(serde_json::from_reader(file.take(MAX_RECEIPT_BYTES + 1))?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.verify_installed")
)]
pub fn verify_installed(
    manifest: &ToolManifest,
    platform: &str,
    root: &Path,
) -> Result<InstallReceipt> {
    ensure_directory(root)?;
    let receipt = read_receipt(&root.join("active.json"))?;
    verify_receipt(manifest, platform, root, &receipt)?;
    let immutable_receipt = read_receipt(&root.join(&receipt.installation).join("receipt.json"))?;
    ensure!(
        receipt == immutable_receipt,
        "active and installation receipts disagree"
    );
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.verify_receipt")
)]
fn verify_receipt(
    manifest: &ToolManifest,
    platform: &str,
    root: &Path,
    receipt: &InstallReceipt,
) -> Result<()> {
    let digest = manifest.digest()?;
    ensure!(
        receipt.schema_version == 1,
        "unsupported managed-tool receipt version"
    );
    ensure!(
        receipt.catalog_sha256 == digest && receipt.platform == platform,
        "managed tools do not match current catalog/platform"
    );
    let expected_path = format!("versions/{digest}-{platform}");
    ensure!(
        receipt.installation == expected_path,
        "managed-tool installation path does not match catalog"
    );
    ensure_directory(&root.join("versions"))?;
    let install_root = root.join(&expected_path);
    ensure_directory(&install_root)?;
    let artifacts = manifest
        .platforms
        .get(platform)
        .context("unsupported managed-tool platform")?;
    ensure!(
        receipt.tools.len() == artifacts.len(),
        "managed-tool receipt is incomplete"
    );
    for (tool, expected) in receipt.tools.iter().zip(artifacts) {
        ensure!(
            tool.name == expected.name
                && tool.version == expected.version
                && tool.archive_sha256 == expected.sha256,
            "managed-tool pins do not match catalog"
        );
        ensure!(
            tool.files.len() == expected.files.len(),
            "managed-tool file receipt is incomplete"
        );
        let expected_files: BTreeSet<_> = expected
            .files
            .iter()
            .map(|file| file.install_path.as_str())
            .collect();
        let mut seen = BTreeSet::new();
        for file in &tool.files {
            ensure!(
                expected_files.contains(file.path.as_str()) && seen.insert(&file.path),
                "unexpected managed-tool file receipt"
            );
            safe_path(&file.path)?;
            ensure!(valid_digest(&file.sha256), "invalid installed-file hash");
            ensure!(
                file.size <= expected.max_unpacked_bytes,
                "installed-file receipt exceeds the unpacked size limit"
            );
            let mut path = install_root.clone();
            let components: Vec<_> = Path::new(&file.path).components().collect();
            for (index, component) in components.iter().enumerate() {
                path.push(component);
                let metadata = fs::symlink_metadata(&path)?;
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "managed-tool path is a symlink"
                );
                if index + 1 == components.len() {
                    ensure!(metadata.is_file(), "installed tool is not a regular file");
                } else {
                    ensure!(metadata.is_dir(), "managed-tool parent is not a directory");
                }
            }
            let mut installed = File::open(&path)?;
            let metadata = installed.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() == file.size,
                "installed tool has changed"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    metadata.permissions().mode() & 0o7777 == 0o755,
                    "installed tool mode has changed"
                );
            }
            ensure!(
                hash_reader(&mut installed)? == file.sha256,
                "installed tool checksum has changed"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "dependencies.hash_reader")
)]
fn hash_reader(reader: &mut impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn ensure_optional_regular(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "managed-tool metadata is not a regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "managed-tool directory is missing or a symlink: {}",
        path.display()
    );
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_tree_directories(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree_directories(&entry.path())?;
        }
    }
    sync_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returning_releases_install_lock_even_with_an_inherited_descriptor() {
        for fail in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("lock");
            let mut inherited = None;
            let outcome = (|| -> Result<()> {
                let file = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&path)?;
                file.try_lock_exclusive()?;
                let owner = InstallLock(file);
                inherited = Some(owner.0.try_clone()?);
                if fail {
                    bail!("interrupted installation");
                }
                Ok(())
            })();
            assert_eq!(outcome.is_err(), fail);
            let next = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            next.try_lock_exclusive()
                .expect("the completed installer must not retain ownership in a child");
            FileExt::unlock(&next).unwrap();
            drop(inherited);
        }
    }

    #[test]
    fn bounded_resolver_returns_local_results_and_errors_without_network() {
        let expected: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let result = resolve_before(
            "fixture.invalid:443",
            Instant::now() + Duration::from_secs(1),
            move |name| {
                assert_eq!(name, "fixture.invalid:443");
                Ok(vec![expected])
            },
        )
        .unwrap();
        assert_eq!(result, vec![expected]);
        let error = resolve_before(
            "fixture.invalid:443",
            Instant::now() + Duration::from_secs(1),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "fixture lookup failed",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn bounded_resolver_returns_timeout_while_lookup_is_still_blocked() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let error = resolve_before(
            "fixture.invalid:443",
            Instant::now() + Duration::from_millis(20),
            move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                finished_tx.send(()).unwrap();
                Ok(Vec::new())
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
