//! Private SSM port-forwarding sessions for local clients.
//!
//! AWS CLI owns the session-token exchange with the Session Manager plugin. Its
//! output stays in bounded pipes; only strict session IDs, listener notices and
//! byte counts are retained. Endpoints are published together,
//! after both plugin listeners are observed. The existing POSIX supervisor also
//! contains plugin children when the AWS CLI ignores SIGINT or exits before its
//! children.

use eyre::{bail, ensure, Result};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::pulumi::{CommandSpec, ProcessLimits};
use crate::pulumi_process::{Completion, Supervisor};

const POLL: Duration = Duration::from_millis(25);
const MAX_LINE: usize = 4096;
const MAX_DRAIN: usize = 64 * 1024;
const MAX_SESSION_SECONDS: u64 = 24 * 60 * 60;

/// The caller must validate the connection file and its exact document/target
/// relationship. Custom documents fix the remote port; the client never sends
/// a remote host or remote-port parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelTarget {
    pub instance_id: String,
    pub document_name: String,
    pub remote_port: u16,
    pub local_port: Option<u16>,
}

pub struct ConnectOptions {
    pub aws_program: PathBuf,
    pub helper_program: PathBuf,
    pub env: BTreeMap<String, String>,
    pub profile: String,
    pub region: String,
    pub startup_timeout: Duration,
    pub shutdown_grace: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEndpoint {
    pub target_index: usize,
    pub remote_port: u16,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecStatus {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

impl From<Completion> for ExecStatus {
    fn from(completion: Completion) -> Self {
        Self {
            exit_code: completion.exit_code,
            signal: completion.signal,
        }
    }
}

/// A child result never hides cancellation, infrastructure or cleanup failures.
#[derive(Debug)]
pub struct ExecError {
    pub child_status: Option<ExecStatus>,
    pub cancelled: bool,
    pub tunnel_failed: bool,
    pub cleanup_incomplete: bool,
    message: String,
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        if let Some(status) = &self.child_status {
            write!(
                f,
                "; child exit code {:?}, signal {:?}",
                status.exit_code, status.signal
            )?;
        }
        Ok(())
    }
}
impl std::error::Error for ExecError {}

/// Cleanup failure remains distinguishable from the operation's outcome.
#[derive(Debug)]
pub struct CleanupError {
    message: String,
}

impl std::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for CleanupError {}

/// Check the actual local executable before AWS can allocate a session. An
/// incompatible binary can make AWS CLI's StartSession customization silently
/// return success after creating a remote session. Merely finding the file is
/// therefore insufficient. Modern versions also let AWS CLI pass session
/// tokens through an environment variable instead of process arguments.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.verify_plugin")
)]
pub fn verify_plugin(program: &Path, environment: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        program.is_absolute(),
        "Session Manager plugin path must be absolute"
    );
    let mut command = Command::new(program);
    command.arg("--version").env_clear().envs(environment);
    let result = crate::dependencies::run_command_in_memory(&mut command, Duration::from_secs(5))
        .map_err(|_| eyre::eyre!("AWS Session Manager plugin cannot run; install the executable for this operating system and CPU architecture, then check session-manager-plugin --version"))?;
    ensure!(
        result.success,
        "AWS Session Manager plugin --version failed; reinstall the plugin for this operating system and CPU architecture"
    );
    let version = result.stdout.trim();
    let parts = version.split('.').collect::<Vec<_>>();
    ensure!(
        version.len() <= 64
            && parts.len() == 4
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "AWS Session Manager plugin returned an invalid version; install a supported plugin and check session-manager-plugin --version"
    );
    let version: Vec<u64> = parts
        .iter()
        .map(|part| part.parse())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| eyre::eyre!("AWS Session Manager plugin returned an invalid version"))?;
    ensure!(
        version.as_slice() > [1, 2, 497, 0].as_slice(),
        "AWS Session Manager plugin must be newer than 1.2.497.0 to keep session tokens out of process arguments; update the plugin"
    );
    Ok(())
}

/// Start one or two tunnels, publish them once all listeners are ready, and
/// wait until cancellation or a session failure. Cancellation is successful
/// only after local cleanup and termination of every observed remote session.
/// No reconnection is attempted: callers see an error if either tunnel exits.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.run")
)]
pub fn run(
    options: &ConnectOptions,
    targets: &[TunnelTarget],
    cancelled: &AtomicBool,
    ready: impl FnOnce(&[LocalEndpoint]) -> Result<()>,
) -> Result<()> {
    run_scoped(
        options,
        targets,
        cancelled,
        false,
        &mut |_| Ok(()),
        |local| {
            ready(local)?;
            Ok(ReadyAction::Wait)
        },
    )
    .map(|_| ())
}

/// Run a bounded callback after readiness, then close every owned connection.
/// The caller supplies request timeouts; cancellation and tunnel liveness are
/// checked again before accepting its result. Cleanup failure overrides success.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.once")
)]
pub fn once<T>(
    options: &ConnectOptions,
    targets: &[TunnelTarget],
    cancelled: &AtomicBool,
    ready: impl FnOnce(&[LocalEndpoint]) -> Result<T>,
) -> Result<T> {
    let mut result = None;
    run_scoped(
        options,
        targets,
        cancelled,
        false,
        &mut |_| Ok(()),
        |local| {
            result = Some(ready(local)?);
            Ok(ReadyAction::Complete)
        },
    )?;
    ensure!(
        !cancelled.load(Ordering::SeqCst),
        "one-shot connection cancelled"
    );
    result.ok_or_else(|| eyre::eyre!("one-shot connection did not become ready"))
}

/// Start a noninteractive child only after the caller verifies service identity.
/// Its stdout/stderr are inherited, stdin is closed, and the caller supplies an
/// environment independent of the tunnels' credential bridge. The child and its
/// descendants are contained by the existing POSIX supervisor, not a sandbox.
pub fn exec(
    options: &ConnectOptions,
    targets: &[TunnelTarget],
    cancelled: &AtomicBool,
    ready: impl FnOnce(&[LocalEndpoint]) -> Result<CommandSpec>,
) -> Result<ExecStatus> {
    exec_with_progress(options, targets, cancelled, ready, &mut |_| Ok(()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecEvent {
    ConnectionReady,
    ChildStarted,
}

/// Observations must succeed before starting new work. Errors after launch still
/// stop the child and clean up sessions, preserving any confirmed child result.
pub fn exec_with_progress(
    options: &ConnectOptions,
    targets: &[TunnelTarget],
    cancelled: &AtomicBool,
    ready: impl FnOnce(&[LocalEndpoint]) -> Result<CommandSpec>,
    progress: &mut dyn FnMut(ExecEvent) -> Result<()>,
) -> Result<ExecStatus> {
    run_scoped(options, targets, cancelled, true, progress, |local| {
        ready(local).map(ReadyAction::Exec)
    })?
    .map(ExecStatus::from)
    .ok_or_else(|| eyre::eyre!("scoped command did not start"))
}

enum ReadyAction {
    Wait,
    Exec(CommandSpec),
    Complete,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.run_scoped")
)]
fn run_scoped(
    options: &ConnectOptions,
    targets: &[TunnelTarget],
    cancelled: &AtomicBool,
    scoped: bool,
    progress: &mut dyn FnMut(ExecEvent) -> Result<()>,
    ready: impl FnOnce(&[LocalEndpoint]) -> Result<ReadyAction>,
) -> Result<Option<Completion>> {
    validate(options, targets)?;
    if cancelled.load(Ordering::SeqCst) {
        if scoped {
            return Err(ExecError {
                child_status: None,
                cancelled: true,
                tunnel_failed: false,
                cleanup_incomplete: false,
                message: "scoped command cancelled before startup".into(),
            }
            .into());
        }
        return Ok(None);
    }
    // Reserve every requested port before making the first AWS request. The
    // plugin cannot inherit these sockets; matching its listener notice also
    // prevents another process taking the short release/bind gap from being
    // mistaken for a ready tunnel.
    let mut reservations = targets
        .iter()
        .map(|target| Reservation::new(target.local_port))
        .collect::<Result<Vec<_>>>()?;
    let directory = tempfile::Builder::new().prefix("zdn-connect-").tempdir()?;
    let mut sessions = Vec::new();
    let mut child: Option<Supervisor> = None;
    let mut completion = None;
    let mut was_cancelled = false;
    let mut tunnel_failed = false;
    let mut child_started = false;
    let outcome = (|| {
        for (index, target) in targets.iter().enumerate() {
            if cancelled.load(Ordering::SeqCst) {
                was_cancelled = true;
                return Ok(());
            }
            let port = reservations[index].port;
            reservations[index].release();
            sessions.push(
                Session::start(
                    options,
                    target,
                    port,
                    &directory.path().join(index.to_string()),
                )
                .inspect_err(|_| tunnel_failed = true)?,
            );
        }
        let deadline = Instant::now() + options.startup_timeout;
        let mut child_deadline = None;
        let mut ready = Some(ready);
        loop {
            if cancelled.load(Ordering::SeqCst) {
                was_cancelled = true;
                return Ok(());
            }
            for session in &mut sessions {
                session
                    .check_alive()
                    .inspect_err(|_| tunnel_failed = true)?;
            }
            if ready.is_some() {
                let endpoints = sessions
                    .iter()
                    .enumerate()
                    .map(|(index, session)| session.endpoint(index))
                    .collect::<Option<Vec<_>>>();
                if let Some(endpoints) = endpoints {
                    if cancelled.load(Ordering::SeqCst) {
                        was_cancelled = true;
                        return Ok(());
                    }
                    let spec = match ready.take().unwrap()(&endpoints) {
                        Err(error) if !scoped => return Err(error),
                        spec => spec,
                    };
                    if cancelled.load(Ordering::SeqCst) {
                        was_cancelled = true;
                        return Ok(());
                    }
                    let action = spec?;
                    if matches!(action, ReadyAction::Exec(_)) {
                        progress(ExecEvent::ConnectionReady)?;
                        if cancelled.load(Ordering::SeqCst) {
                            was_cancelled = true;
                            return Ok(());
                        }
                    }
                    if !matches!(action, ReadyAction::Wait) {
                        // Identity checks and progress writes may have taken
                        // time. Never start work behind a dead tunnel.
                        for session in &mut sessions {
                            session
                                .check_alive()
                                .inspect_err(|_| tunnel_failed = true)?;
                        }
                    }
                    if matches!(action, ReadyAction::Complete) {
                        return Ok(());
                    }
                    if let ReadyAction::Exec(spec) = action {
                        ensure!(
                            !spec.limits.timeout.is_zero()
                                && spec.limits.timeout <= Duration::from_secs(MAX_SESSION_SECONDS),
                            "invalid scoped command timeout"
                        );
                        let receipts = directory.path().join("exec");
                        fs::create_dir(&receipts)?;
                        child_deadline = Some(Instant::now() + spec.limits.timeout);
                        child = Some(Supervisor::spawn_at(
                            &options.helper_program,
                            &spec,
                            File::from(std::io::stdout().as_fd().try_clone_to_owned()?),
                            File::from(std::io::stderr().as_fd().try_clone_to_owned()?),
                            &receipts,
                        )?);
                    }
                } else {
                    tunnel_failed = Instant::now() >= deadline;
                    ensure!(
                        !tunnel_failed,
                        "SSM tunnel startup timed out before all local listeners were ready; SSM tunnel diagnostics: {}",
                        json!(sessions.iter().map(|session| session.diagnostic("startup-timeout", None)).collect::<Vec<_>>())
                    );
                }
            }
            if let Some(child) = &mut child {
                // Preserve an observed result even if a later event write or
                // receipt read fails and cleanup cannot recover it again.
                completion = child.poll()?;
                if !child_started && child.launched()? {
                    child_started = true;
                    progress(ExecEvent::ChildStarted)?;
                }
                ensure!(
                    child_deadline.is_none_or(|deadline| Instant::now() < deadline),
                    "scoped command exceeded its deadline"
                );
                if let Some(status) = &completion {
                    ensure!(
                        status.exit_code.is_some() || status.signal.is_some(),
                        "scoped command could not start or its exit status is unavailable"
                    );
                    return Ok(());
                }
            }
            std::thread::sleep(POLL);
        }
    })();
    if let Some(child) = &mut child {
        child.stop(false);
    }
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cleanup(options, &mut sessions, directory.path()) {
        cleanup_errors.push(format!("{error:#}"));
    }
    if let Some(child) = &mut child {
        match child.finish_status(|| false) {
            Ok(status) => completion = Some(status),
            Err(_) => cleanup_errors.push("local command process cleanup is unconfirmed".into()),
        }
    }
    let cleanup_incomplete = !cleanup_errors.is_empty();
    if cleanup_incomplete {
        // A supervisor receipt is useful when local process cleanup failed.
        // It contains process identity only, never plugin output or credentials.
        let retained = directory.keep();
        cleanup_errors.push(format!(
            "SSM connection cleanup was incomplete; inspect {}",
            retained.display()
        ));
    }
    if scoped {
        if outcome.is_err() || was_cancelled || cleanup_incomplete {
            let mut messages = Vec::new();
            if let Err(error) = outcome {
                messages.push(format!("{error:#}"));
            }
            if was_cancelled {
                messages.push("scoped command cancelled".into());
            }
            messages.extend(cleanup_errors);
            return Err(ExecError {
                child_status: completion.map(ExecStatus::from),
                cancelled: was_cancelled,
                tunnel_failed,
                cleanup_incomplete,
                message: messages.join("; "),
            }
            .into());
        }
    } else if cleanup_incomplete {
        // Preserve both typed failures: callers still need CleanupError to
        // report incomplete cleanup, but must not lose the operation's cause.
        if let Err(error) = outcome {
            return Err(error.wrap_err(CleanupError {
                message: cleanup_errors.join("; "),
            }));
        }
        return Err(CleanupError {
            message: cleanup_errors.join("; "),
        }
        .into());
    }
    outcome.map(|_| completion)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.validate")
)]
fn validate(options: &ConnectOptions, targets: &[TunnelTarget]) -> Result<()> {
    ensure!(
        (1..=2).contains(&targets.len()),
        "connect requires one or two service targets"
    );
    ensure!(
        options.aws_program.is_absolute() && options.helper_program.is_absolute(),
        "connection executables must use absolute paths"
    );
    ensure!(
        !options.profile.is_empty()
            && options.profile.len() <= 128
            && options
                .profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid AWS connection profile"
    );
    ensure!(
        (5..=32).contains(&options.region.len())
            && options
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "invalid AWS connection region"
    );
    ensure!(
        !options.startup_timeout.is_zero()
            && options.startup_timeout <= Duration::from_secs(300)
            && !options.shutdown_grace.is_zero()
            && options.shutdown_grace <= Duration::from_secs(60),
        "invalid connection startup or shutdown timeout"
    );
    let mut requested = BTreeSet::new();
    let mut documents = BTreeSet::new();
    for target in targets {
        let suffix = target.instance_id.strip_prefix("i-").unwrap_or_default();
        ensure!(
            [8, 17].contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid connection instance ID"
        );
        ensure!(
            target.document_name.starts_with("zdn-")
                && target.document_name.len() <= 128
                && target
                    .document_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && documents.insert(&target.document_name),
            "connection requires distinct, fixed-port zdn session documents"
        );
        ensure!(
            [18234, 9067].contains(&target.remote_port),
            "unsupported connection service port"
        );
        if let Some(port) = target.local_port {
            ensure!(
                port != 0 && requested.insert(port),
                "local connection ports must be distinct and nonzero"
            );
        }
    }
    Ok(())
}

struct Reservation {
    port: u16,
    listeners: Vec<TcpListener>,
}

impl Reservation {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connections.reservation.new")
    )]
    fn new(requested: Option<u16>) -> Result<Self> {
        for _ in 0..16 {
            let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, requested.unwrap_or(0)))
                .map_err(|_| eyre::eyre!("requested local connection port is unavailable"))?;
            let port = ipv4.local_addr()?.port();
            let mut listeners = vec![ipv4];
            match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                Ok(ipv6) => listeners.push(ipv6),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                    ) => {}
                Err(_) if requested.is_none() => continue,
                Err(_) => bail!("requested local connection port is unavailable"),
            }
            return Ok(Self { port, listeners });
        }
        bail!("could not reserve a loopback port for the connection")
    }

    fn release(&mut self) {
        self.listeners.clear();
    }
}

struct Session {
    supervisor: Supervisor,
    stdout: UnixStream,
    stderr: UnixStream,
    output: Notices,
    stdout_bytes: u64,
    stderr_bytes: u64,
    local_port: u16,
    remote_port: u16,
}

impl Session {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connections.session.start")
    )]
    fn start(
        options: &ConnectOptions,
        target: &TunnelTarget,
        port: u16,
        directory: &Path,
    ) -> Result<Self> {
        fs::create_dir(directory)?;
        let (stdout, out_file) = pipe()?;
        let (stderr, err_file) = pipe()?;
        let parameters = json!({"localPortNumber": [port.to_string()]}).to_string();
        let args = [
            "ssm",
            "start-session",
            "--target",
            &target.instance_id,
            "--document-name",
            &target.document_name,
            "--parameters",
            &parameters,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let spec = command(
            options,
            directory,
            args,
            Duration::from_secs(MAX_SESSION_SECONDS),
        );
        let supervisor = Supervisor::spawn(&options.helper_program, &spec, out_file, err_file)
            .map_err(|_| eyre::eyre!("could not start the SSM connection supervisor"))?;
        Ok(Self {
            supervisor,
            stdout,
            stderr,
            output: Notices::default(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            local_port: port,
            remote_port: target.remote_port,
        })
    }

    fn observe(&mut self) -> Result<()> {
        let stdout = drain(&mut self.stdout, |bytes| {
            self.stdout_bytes = self.stdout_bytes.saturating_add(bytes.len() as u64);
            self.output.push(bytes, self.local_port)
        });
        let stderr = drain(&mut self.stderr, |bytes| {
            self.stderr_bytes = self.stderr_bytes.saturating_add(bytes.len() as u64);
            Ok(())
        });
        stdout.and(stderr)
    }

    fn check_alive(&mut self) -> Result<()> {
        self.observe().map_err(|error| {
            eyre::eyre!(
                "{error:#}; SSM tunnel diagnostics: {}",
                self.diagnostic("output-rejected", None)
            )
        })?;
        let status = self.supervisor.poll().map_err(|_| {
            eyre::eyre!(
                "SSM tunnel supervisor status is unconfirmed; SSM tunnel diagnostics: {}",
                self.diagnostic("supervisor-unconfirmed", None)
            )
        })?;
        if let Some(status) = status {
            // Capture any final buffered output before cleanup removes the
            // supervisor receipt. Never mistake cleanup-induced status for the
            // exit that caused this failure. This final drain remains bounded.
            let _ = self.observe();
            bail!("SSM tunnel exited; check the selected AWS identity, target readiness, and Session Manager plugin; SSM tunnel diagnostics: {}", self.diagnostic("process-exited", Some(&status)));
        }
        Ok(())
    }

    fn diagnostic(&self, category: &str, status: Option<&Completion>) -> serde_json::Value {
        json!({
            "category": category,
            "service": if self.remote_port == 18234 { "rpc" } else { "grpc" },
            "listenerState": if self.output.listening { "listener-observed" } else { "before-listener" },
            "sessionNoticeObserved": self.output.session_id.is_some(),
            "exitCode": status.and_then(|status| status.exit_code),
            "signal": status.and_then(|status| status.signal),
            "stdout": { "observedBytes": self.stdout_bytes },
            "stderr": { "observedBytes": self.stderr_bytes },
        })
    }

    fn endpoint(&self, index: usize) -> Option<LocalEndpoint> {
        if !self.output.listening {
            return None;
        }
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.local_port));
        TcpStream::connect_timeout(&address, Duration::from_millis(30))
            .ok()
            .map(|_| LocalEndpoint {
                target_index: index,
                remote_port: self.remote_port,
                address,
            })
    }
}

#[derive(Default)]
struct Notices {
    partial: Vec<u8>,
    session_id: Option<String>,
    listening: bool,
    discarding: bool,
}

impl Notices {
    fn push(&mut self, bytes: &[u8], port: u16) -> Result<()> {
        let mut failure = None;
        for byte in bytes {
            if *byte == b'\n' {
                let line = std::mem::take(&mut self.partial);
                if !self.discarding {
                    if let Err(error) = self.line(&line, port) {
                        failure.get_or_insert(error);
                    }
                }
                self.discarding = false;
            } else if self.discarding {
                continue;
            } else if self.partial.len() == MAX_LINE {
                self.partial.clear();
                self.discarding = true;
                failure
                    .get_or_insert_with(|| eyre::eyre!("SSM plugin output exceeds its line limit"));
            } else {
                self.partial.push(*byte);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn line(&mut self, line: &[u8], port: u16) -> Result<()> {
        let Ok(line) = std::str::from_utf8(line) else {
            return Ok(());
        };
        let line = line.trim_matches(['\r', ' ']);
        if let Some(id) = line.strip_prefix("Starting session with SessionId: ") {
            ensure!(
                valid_session_id(id),
                "SSM plugin returned an invalid session identity"
            );
            ensure!(
                self.session_id.as_deref().is_none_or(|saved| saved == id),
                "SSM plugin changed session identity"
            );
            self.session_id = Some(id.into());
        } else if let Some(notice) = line.strip_prefix("Port ") {
            if let Some((opened, id)) = notice.split_once(" opened for sessionId ") {
                let id = id.strip_suffix('.').unwrap_or(id);
                ensure!(
                    self.session_id.as_deref() == Some(id),
                    "SSM plugin listener belongs to an unobserved session"
                );
                ensure!(
                    opened.parse::<u16>().ok() == Some(port),
                    "SSM plugin opened a different local port"
                );
                self.listening = true;
            }
        } else if line == "Connection to destination port failed, check SSM Agent logs." {
            bail!("SSM cannot reach the private service port; check service readiness");
        }
        Ok(())
    }
}

fn valid_session_id(id: &str) -> bool {
    (1..=96).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@:-".contains(&b))
}

fn pipe() -> Result<(UnixStream, File)> {
    let (reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    Ok((reader, File::from(OwnedFd::from(writer))))
}

fn drain(reader: &mut UnixStream, mut consume: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut bytes = [0; 4096];
    let mut remaining = MAX_DRAIN;
    let mut failure = None;
    while remaining > 0 {
        match reader.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => {
                // Continue the bounded drain after malformed output so a late
                // valid session announcement remains available for cleanup.
                if let Err(error) = consume(&bytes[..count]) {
                    failure.get_or_insert(error);
                }
                remaining -= count;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => bail!("cannot read SSM process output"),
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.command")
)]
fn command(
    options: &ConnectOptions,
    directory: &Path,
    mut args: Vec<OsString>,
    timeout: Duration,
) -> CommandSpec {
    args.extend(
        [
            "--profile",
            &options.profile,
            "--region",
            &options.region,
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "3",
            "--cli-read-timeout",
            "5",
        ]
        .into_iter()
        .map(OsString::from),
    );
    let mut env: BTreeMap<OsString, OsString> = options
        .env
        .iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    env.insert("AWS_MAX_ATTEMPTS".into(), "1".into());
    env.insert("AWS_PAGER".into(), "".into());
    env.insert("AWS_CLI_AUTO_PROMPT".into(), "off".into());
    env.insert("LC_ALL".into(), "C".into());
    CommandSpec {
        label: "ssm-session".into(),
        program: options.aws_program.clone(),
        args,
        env,
        cwd: directory.into(),
        diagnostics_dir: directory.into(),
        limits: ProcessLimits {
            timeout,
            shutdown_grace: options.shutdown_grace,
            max_output_bytes: MAX_DRAIN,
            poll_interval: POLL,
        },
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.cleanup")
)]
fn cleanup(options: &ConnectOptions, sessions: &mut [Session], directory: &Path) -> Result<()> {
    let mut failures = Vec::new();
    let mut terminated = BTreeSet::new();
    // Signal every local session before waiting for any one cleanup. Remote
    // termination also stops plugins whose AWS CLI parent ignores SIGINT.
    for session in sessions.iter_mut() {
        session.supervisor.stop(false);
        let _ = session.observe();
    }
    for round in 0..2 {
        for session in sessions.iter_mut() {
            if let Some(id) = session.output.session_id.as_ref() {
                if terminated.insert(id.clone())
                    && terminate(options, id, directory, terminated.len()).is_err()
                {
                    failures.push(format!(
                        "remote SSM termination is unconfirmed for session {id}"
                    ));
                }
            }
        }
        if round == 0 {
            for session in sessions.iter_mut() {
                if session.supervisor.finish(|| false).is_err() {
                    failures.push("local SSM process cleanup is unconfirmed".into());
                }
                // A session announcement can arrive between cancellation and
                // process exit. Recover it for the second termination pass.
                let _ = session.observe();
            }
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connections.terminate")
)]
fn terminate(options: &ConnectOptions, id: &str, directory: &Path, ordinal: usize) -> Result<()> {
    let directory = directory.join(format!("terminate-{ordinal}"));
    fs::create_dir(&directory)?;
    let (mut stdout, out_file) = pipe()?;
    let (mut stderr, err_file) = pipe()?;
    let args = ["ssm", "terminate-session", "--session-id", id]
        .into_iter()
        .map(OsString::from)
        .collect();
    let mut spec = command(options, &directory, args, Duration::from_secs(12));
    spec.limits.shutdown_grace = Duration::from_secs(1);
    let mut supervisor = Supervisor::spawn(&options.helper_program, &spec, out_file, err_file)?;
    let result = (|| loop {
        drain(&mut stdout, |_| Ok(()))?;
        drain(&mut stderr, |_| Ok(()))?;
        if let Some(completion) = supervisor.poll()? {
            ensure!(completion.success, "SSM termination request failed");
            return Ok(());
        }
        std::thread::sleep(POLL);
    })();
    supervisor.stop(false);
    supervisor.finish(|| false)?;
    result
}
