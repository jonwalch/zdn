//! Native host command boundary, adapted from retired `runner.py::command`.
//! Tools/arguments are trusted caller
//! inputs; stdin and output are not logged or written to files. The receipt
//! directory must be a stable, caller-trusted private path (root-owned on hosts).
//! This owns ordinary descendants in one POSIX session, not programs deliberately
//! escaping with setsid or changing identity. Native host operations use it.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use eyre::{bail, ensure, ContextCompat, Result};

use super::files::{Directory, Lock};
use crate::{
    pulumi::{CommandSpec, ProcessLimits},
    pulumi_process::Supervisor,
};

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);
const CLEANUP_RESERVE: Duration = Duration::from_secs(10);

/// Shared historical policy for finite commands and the final systemd exec.
pub(super) fn environment(region: &str) -> BTreeMap<OsString, OsString> {
    [
        ("PATH", "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/root"),
        ("AWS_REGION", region),
        ("AWS_DEFAULT_REGION", region),
        ("AWS_PAGER", ""),
        ("AWS_RETRY_MODE", "standard"),
        ("AWS_MAX_ATTEMPTS", "5"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

pub struct HostCommand<'a> {
    /// Absolute executable, with literal argv (no shell interpolation).
    pub program: &'a Path,
    pub args: &'a [OsString],
    pub stdin: Option<&'a [u8]>,
    pub timeout: Duration,
    pub allowed: &'a [i32],
}

/// Deliberately not Debug: tools can return credentials on stdout.
pub struct Output {
    pub stdout: Vec<u8>,
    pub exit_code: i32,
}

pub struct Executor {
    helper: PathBuf,
    directory: PathBuf,
    region: String,
    deadline: Instant,
    _lock: Lock,
    lightwallet: bool,
}

impl Executor {
    /// Retain this executor for an entire host action, sharing its one monotonic
    /// deadline. Unconfirmed cleanup leaves its receipt in this directory and
    /// blocks subsequent execution; never delete the directory to bypass it.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.command.new")
    )]
    pub fn new(
        helper: PathBuf,
        directory: PathBuf,
        region: String,
        deadline: Instant,
    ) -> Result<Self> {
        ensure!(
            helper.is_absolute() && directory.is_absolute(),
            "host command paths must be absolute"
        );
        ensure!(
            !region.is_empty()
                && region.len() <= 63
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid host command region"
        );
        // Linux procfs provides the current effective owner, not an owner taken
        // from the unverified target. Ancestors remain the caller's trust input.
        let owner = fs::metadata("/proc/self")?.uid();
        let trusted = Directory::open(&directory, owner)?;
        ensure!(
            fs::symlink_metadata(&directory)?.mode() & 0o777 == 0o700,
            "host command directory must be private"
        );
        let lock = trusted.lock("command.lock")?;
        crate::pulumi_process::ensure_cleanup(&directory)?;
        Ok(Self {
            helper,
            directory,
            region,
            deadline,
            _lock: lock,
            lightwallet: false,
        })
    }

    /// Separate fixed policy; never relax the historical host environment or bound.
    pub(crate) fn lightwallet(helper: PathBuf, directory: PathBuf) -> Result<Self> {
        let mut executor = Self::new(
            helper,
            directory,
            "unused".into(),
            Instant::now() + Duration::from_secs(120),
        )?;
        executor.lightwallet = true;
        Ok(executor)
    }

    /// Share the action's existing cleanup reserve with non-command evidence.
    pub(crate) fn work_deadline(&self) -> Result<Instant> {
        self.deadline
            .checked_sub(CLEANUP_RESERVE)
            .context("host operation exceeded its cumulative deadline")
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.command.execute")
    )]
    pub fn execute(&mut self, request: HostCommand<'_>, cancelled: &AtomicBool) -> Result<Output> {
        ensure!(
            request.program.is_absolute()
                && !request.timeout.is_zero()
                && !request.allowed.is_empty()
                && request.allowed.iter().all(|code| (0..=255).contains(code)),
            "invalid host command request"
        );
        ensure!(!cancelled.load(Ordering::Relaxed), "host command cancelled");
        let started = Instant::now();
        let available = self
            .deadline
            .checked_duration_since(started)
            .and_then(|d| d.checked_sub(CLEANUP_RESERVE))
            .filter(|d| !d.is_zero())
            .context("host operation exceeded its cumulative deadline")?;
        let timeout = request.timeout.min(available);
        let deadline = started
            .checked_add(timeout)
            .context("invalid host command deadline")?;
        let scratch = tempfile::Builder::new()
            .prefix(".stdin-")
            .tempdir_in(&self.directory)?;
        // Lightwallet deployment/node paths can exceed AF_UNIX's pathname
        // limit. Pin the private directory and use its kernel descriptor alias;
        // the parent retains it until transport and owned-session cleanup end.
        // The historical host socket pathname/protocol is unchanged.
        let socket_directory = if self.lightwallet {
            Some(File::open(scratch.path())?)
        } else {
            None
        };
        let socket = match &socket_directory {
            Some(directory) => PathBuf::from(format!(
                "/proc/{}/fd/{}/input",
                std::process::id(),
                directory.as_raw_fd()
            )),
            None => scratch.path().join("input"),
        };
        let listener = UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let (mut stdout, writer) = UnixStream::pair()?;
        stdout.set_nonblocking(true)?;
        let mut env = environment(&self.region);
        let max_output = if self.lightwallet {
            env = [
                ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
                ("HOME", "/nonexistent"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
            1024 * 1024
        } else {
            MAX_OUTPUT
        };
        let spec = CommandSpec {
            label: "host-command".into(),
            program: request.program.into(),
            args: request.args.into(),
            env,
            cwd: self.directory.clone(),
            diagnostics_dir: self.directory.clone(),
            limits: ProcessLimits {
                timeout,
                // Two seconds of TERM grace + five of session cleanup + two
                // of acknowledgement slack fit the ten-second action reserve.
                shutdown_grace: Duration::from_secs(2),
                max_output_bytes: max_output,
                poll_interval: POLL,
            },
        };
        let mut supervisor = Supervisor::spawn_host(
            &self.helper,
            &spec,
            File::from(OwnedFd::from(writer)),
            File::options().write(true).open("/dev/null")?,
            &self.directory,
            &socket,
        )
        .map_err(|_| eyre::eyre!("cannot start host command supervisor"))?;
        let mut input = None;
        let mut input_closed = false;
        let mut pending = request.stdin.unwrap_or_default();
        let mut output = Vec::new();
        let mut eof = false;
        // One span covers the entire duplex loop, including waiting, rather
        // than formatting a trace record for every poll or payload chunk.
        #[cfg(feature = "profiling")]
        let io_span = tracing::info_span!("host.command.io").entered();
        let outcome: Result<i32> = (|| {
            loop {
                ensure!(!cancelled.load(Ordering::Relaxed), "host command cancelled");
                ensure!(
                    Instant::now() < deadline,
                    "host command exceeded its deadline"
                );
                let mut progressed = false;
                if input.is_none() {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_nonblocking(true)
                                .map_err(|_| eyre::eyre!("host command input transport failed"))?;
                            input = Some(stream);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::Interrupted
                            ) => {}
                        Err(_) => bail!("host command input transport failed"),
                    }
                }
                if let Some(stream) = &mut input {
                    if !pending.is_empty() {
                        match stream.write(&pending[..pending.len().min(65536)]) {
                            Ok(0) => pending = &[],
                            Ok(count) => {
                                pending = &pending[count..];
                                progressed = true;
                            }
                            Err(error)
                                if error.kind() == ErrorKind::BrokenPipe
                                    || error.kind() == ErrorKind::ConnectionReset =>
                            {
                                pending = &[]
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    ErrorKind::WouldBlock | ErrorKind::Interrupted
                                ) => {}
                            Err(_) => bail!("host command input transport failed"),
                        }
                    }
                    if pending.is_empty() && !input_closed {
                        // Half-close only: EOF is visible to stdin, while the
                        // supervisor's unrelated control stream remains live.
                        // A tool may close stdin without consuming all input.
                        // Like communicate(), that is not a command failure.
                        match stream.shutdown(Shutdown::Write) {
                            Ok(()) => {}
                            Err(error) if error.kind() == ErrorKind::NotConnected => {}
                            Err(_) => bail!("host command input transport failed"),
                        }
                        input_closed = true;
                    }
                }
                // Bounded work each poll prevents an infinite-output child
                // starving deadline/cancellation or simultaneous stdin writes.
                let mut bytes = [0; 65536];
                match stdout.read(&mut bytes) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        ensure!(
                            output.len() + count <= max_output,
                            "host command output exceeded its bound"
                        );
                        output.extend_from_slice(&bytes[..count]);
                        progressed = true;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => bail!("host command output transport failed"),
                }
                if let Some(completion) = supervisor
                    .poll()
                    .map_err(|_| eyre::eyre!("host command supervisor failed"))?
                {
                    // Poll can complete with buffered output still unread.
                    if eof {
                        ensure!(
                            completion.completed == Some(true) && completion.signal.is_none(),
                            "host command did not complete normally"
                        );
                        let exit_code =
                            completion.exit_code.context("host command did not start")?;
                        ensure!(request.allowed.contains(&exit_code), "host command failed");
                        break Ok(exit_code);
                    }
                }
                // Continue bounded duplex work while bytes are moving. Only
                // idle polls need a delay; each chunk still checks cancellation,
                // the deadline, the output limit and supervisor completion.
                if !progressed {
                    std::thread::sleep(POLL);
                }
            }
        })();
        #[cfg(feature = "profiling")]
        drop(io_span);
        #[cfg(feature = "profiling")]
        let _cleanup_span = tracing::info_span!("host.command.cleanup").entered();
        // Close streams before stopping; never keep capturing an
        // overproducing workload. Preserve an incomplete receipt on failure.
        drop(input);
        drop(stdout);
        if outcome.is_err() {
            supervisor.stop(false);
        }
        supervisor.finish_status(|| false).map_err(|_| eyre::eyre!("host command cleanup is unconfirmed; preserve the process receipt before another operation"))?;
        let exit_code = outcome?;
        Ok(Output {
            stdout: output,
            exit_code,
        })
    }
}
