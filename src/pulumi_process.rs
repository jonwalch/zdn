//! Supervise the pinned Pulumi CLI and plugins in one private POSIX session.
//!
//! Pulumi gives plugins their own process groups (Setpgid). The session survives
//! that change and reparenting. A helper joins each group before killing it:
//! setpgid atomically refuses a group in another session, and the helper's own
//! membership pins the group ID until the signal. Never signal a saved PID.
//! This is containment for the pinned plugins, not a sandbox for programs that
//! deliberately escape with setsid or change their user identity.

use eyre::{bail, ensure, ContextCompat, Result};
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::{getpgid, getsid, setpgid, setsid, Pid};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::foundation::{read_json, write_json};

pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);
const MARKER: &str = ".zdn-pulumi-process.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    token: Uuid,
    session: Option<i32>,
    cli_pid: Option<u32>,
    completion: Option<Completion>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Completion {
    pub success: bool,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    /// Host commands distinguish a normal nonzero exit from supervisor shutdown.
    /// Absent for the unchanged Pulumi protocol and historical receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
}

/// Completion is written only after every live process in the session is gone.
/// Incomplete receipts intentionally survive errors, crashes and lease expiry.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.ensure_cleanup")
)]
pub fn ensure_cleanup(work_dir: &Path) -> Result<()> {
    let path = work_dir.join(MARKER);
    if path.try_exists()? {
        let receipt: Receipt = read_json(&path)?;
        ensure!(receipt.completion.is_some(),
            "Pulumi process cleanup is unconfirmed; retain the lease and inspect {} before another operation", path.display());
    }
    Ok(())
}

pub(crate) struct Supervisor {
    child: Child,
    marker: PathBuf,
    token: Uuid,
    exited: bool,
    grace: Duration,
}

impl Supervisor {
    pub fn spawn(
        helper: &Path,
        spec: &crate::pulumi::CommandSpec,
        stdout: File,
        stderr: File,
    ) -> Result<Self> {
        Self::spawn_at(helper, spec, stdout, stderr, &spec.cwd)
    }

    /// Keep owned process receipts separate from an arbitrary workload's cwd.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi_process.supervisor.spawn_at")
    )]
    pub fn spawn_at(
        helper: &Path,
        spec: &crate::pulumi::CommandSpec,
        stdout: File,
        stderr: File,
        receipt_directory: &Path,
    ) -> Result<Self> {
        Self::spawn_inner(helper, spec, stdout, stderr, receipt_directory, None, false)
    }

    /// Separate opt-in protocol: the workload reads a private socket, while the
    /// supervisor's stdin remains exclusively its cancellation/EOF channel.
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi_process.supervisor.spawn_host")
    )]
    pub fn spawn_host(
        helper: &Path,
        spec: &crate::pulumi::CommandSpec,
        stdout: File,
        stderr: File,
        receipt_directory: &Path,
        input_socket: &Path,
    ) -> Result<Self> {
        Self::spawn_inner(
            helper,
            spec,
            stdout,
            stderr,
            receipt_directory,
            Some(input_socket),
            false,
        )
    }

    /// Opt-in daemon protocol has no workload deadline; EOF still owns cleanup.
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi_process.supervisor.spawn_daemon")
    )]
    pub(crate) fn spawn_daemon(
        helper: &Path,
        spec: &crate::pulumi::CommandSpec,
        receipt_directory: &Path,
    ) -> Result<Self> {
        Self::spawn_inner(
            helper,
            spec,
            File::options().write(true).open("/dev/null")?,
            File::options().write(true).open("/dev/null")?,
            receipt_directory,
            None,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_inner(
        helper: &Path,
        spec: &crate::pulumi::CommandSpec,
        stdout: File,
        stderr: File,
        receipt_directory: &Path,
        input_socket: Option<&Path>,
        daemon: bool,
    ) -> Result<Self> {
        ensure_cleanup(receipt_directory)?;
        let marker = receipt_directory.join(MARKER);
        if marker.try_exists()? {
            fs::remove_file(&marker)?;
        }
        let token = Uuid::new_v4();
        let receipt = Receipt {
            token,
            session: None,
            cli_pid: None,
            completion: None,
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&marker)?;
        file.write_all(&serde_json::to_vec(&receipt)?)?;
        file.sync_all()?;
        File::open(receipt_directory)?.sync_all()?;
        let mut command = Command::new(helper);
        if daemon {
            command.arg("__supervise-lightwallet-client");
        } else if let Some(socket) = input_socket {
            command
                .arg("__supervise-host-command")
                .arg("--input-socket")
                .arg(socket);
        } else {
            command.arg("__supervise-pulumi");
        }
        command
            .arg("--marker")
            .arg(&marker)
            .arg("--token")
            .arg(token.to_string())
            .arg("--grace-ms")
            .arg(spec.limits.shutdown_grace.as_millis().to_string());
        if !daemon {
            command
                .arg("--timeout-ms")
                .arg(spec.limits.timeout.as_millis().to_string());
        }
        let child = command
            .arg("--")
            .arg(&spec.program)
            .args(&spec.args)
            .env_clear()
            .envs(&spec.env)
            .current_dir(&spec.cwd)
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(_) => {
                fs::remove_file(&marker)?;
                bail!("cannot start Pulumi supervisor");
            }
        };
        Ok(Self {
            child,
            marker,
            token,
            exited: false,
            grace: spec.limits.shutdown_grace,
        })
    }

    /// The helper records the workload PID only after a successful spawn.
    pub fn launched(&self) -> Result<bool> {
        let receipt: Receipt = read_json(&self.marker)?;
        ensure!(
            receipt.token == self.token,
            "Pulumi process receipt identity changed"
        );
        Ok(receipt.cli_pid.is_some())
    }

    pub fn poll(&mut self) -> Result<Option<Completion>> {
        if !self.exited {
            self.exited = self.child.try_wait()?.is_some();
        }
        if !self.exited {
            return Ok(None);
        }
        let receipt: Receipt = read_json(&self.marker)?;
        ensure!(
            receipt.token == self.token,
            "Pulumi process receipt identity changed"
        );
        let completion = receipt.completion.context("Pulumi process cleanup is unconfirmed; retain the lease and inspect the process receipt")?;
        Ok(Some(completion))
    }

    pub fn stop(&mut self, force: bool) {
        if let Some(input) = &mut self.child.stdin {
            let _ = input.write_all(if force { b"K" } else { b"I" });
        }
    }

    pub fn finish(&mut self, force_stop: impl FnMut() -> bool) -> Result<()> {
        self.finish_status(force_stop).map(|_| ())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "pulumi_process.supervisor.finish_status")
    )]
    pub fn finish_status(&mut self, mut force_stop: impl FnMut() -> bool) -> Result<Completion> {
        let deadline = Instant::now() + self.grace + CLEANUP_TIMEOUT + Duration::from_secs(2);
        let mut forced = false;
        loop {
            if let Some(completion) = self.poll()? {
                fs::remove_file(&self.marker)?;
                return Ok(completion);
            }
            if !forced && force_stop() {
                self.stop(true);
                // Send once: repeatedly writing while cleanup is blocked could
                // fill the control pipe and prevent the bounded wait from ending.
                forced = true;
            }
            ensure!(Instant::now() < deadline, "Pulumi supervisor did not confirm cleanup; retain the lease and inspect the process receipt");
            std::thread::sleep(POLL);
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // EOF makes the independent supervisor clean up even if this writer dies.
        self.child.stdin.take();
    }
}

/// Internal CLI entry point; enter the session before starting any workload.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.supervise")
)]
pub fn supervise(
    marker: &Path,
    token: Uuid,
    grace: Duration,
    timeout: Duration,
    args: &[OsString],
) -> Result<()> {
    supervise_inner(marker, token, grace, Some(timeout), args, None)
}

/// Internal host protocol. Socket path/argv contain no stdin material. The
/// caller owns its private directory; only the workload inherits this stream.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.supervise_host")
)]
pub fn supervise_host(
    marker: &Path,
    token: Uuid,
    grace: Duration,
    timeout: Duration,
    args: &[OsString],
    input_socket: &Path,
) -> Result<()> {
    supervise_inner(
        marker,
        token,
        grace,
        Some(timeout),
        args,
        Some(input_socket),
    )
}

/// Internal attached-client protocol. No fixed lifetime, no detached workload.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.supervise_lightwallet_client")
)]
pub fn supervise_lightwallet_client(
    marker: &Path,
    token: Uuid,
    grace: Duration,
    args: &[OsString],
) -> Result<()> {
    supervise_inner(marker, token, grace, None, args, None)
}

fn supervise_inner(
    marker: &Path,
    token: Uuid,
    grace: Duration,
    timeout: Option<Duration>,
    args: &[OsString],
    input_socket: Option<&Path>,
) -> Result<()> {
    ensure!(
        !args.is_empty()
            && !grace.is_zero()
            && grace <= Duration::from_secs(60)
            && timeout.is_none_or(|timeout| !timeout.is_zero()),
        "invalid supervisor request"
    );
    let mut receipt: Receipt = read_json(marker)?;
    ensure!(
        receipt.token == token && receipt.session.is_none() && receipt.completion.is_none(),
        "invalid supervisor receipt"
    );
    // Reserve cleanup scratch before starting the workload. After a caller
    // crashes its temporary directory can disappear while shutdown is pending;
    // the open file remains usable even after that directory is removed.
    let mut process_list = tempfile::tempfile()?;
    let session = setsid()?;
    receipt.session = Some(session.as_raw());
    write_json(marker, &receipt)?;
    let input = std::io::stdin();
    fcntl(&input, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    let workload_input = match input_socket {
        Some(socket) => Stdio::from(OwnedFd::from(UnixStream::connect(socket)?)),
        None => Stdio::null(),
    };
    let child = Command::new(&args[0])
        .args(&args[1..])
        .stdin(workload_input)
        .process_group(0)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            receipt.completion = Some(Completion {
                success: false,
                exit_code: None,
                signal: None,
                completed: input_socket.map(|_| false),
            });
            write_json(marker, &receipt)?;
            return Err(error.into());
        }
    };
    receipt.cli_pid = Some(child.id());
    let result = (|| {
        write_json(marker, &receipt)?;
        let started = Instant::now();
        let mut stop_at = None;
        loop {
            // Only this supervisor waits for the CLI. Once reaped, never signal
            // its numeric PID again, even if another process immediately reuses it.
            if let Some(status) = child.try_wait()? {
                // A host tool handling the shutdown signal with exit(0) did
                // not complete its requested operation. Legacy Pulumi receipts
                // retain their original completion semantics and bytes.
                return Ok(if input_socket.is_some() && stop_at.is_some() {
                    None
                } else {
                    Some(status)
                });
            }
            let mut request = [0; 32];
            let mut stop = timeout.is_some_and(|timeout| started.elapsed() >= timeout);
            match input.lock().read(&mut request) {
                Ok(0) => stop = true,
                Ok(n) => {
                    if request[..n].contains(&b'K') {
                        return Ok(None);
                    }
                    stop |= request[..n].contains(&b'I');
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => stop = true,
            }
            if stop && stop_at.is_none() {
                // The direct child has not been reaped, so its PID (also its
                // original process-group ID) cannot be reused by a new leader.
                let pid = Pid::from_raw(i32::try_from(child.id())?);
                let _ = if input_socket.is_some() || timeout.is_none() {
                    killpg(pid, Signal::SIGTERM)
                } else {
                    kill(pid, Signal::SIGINT)
                };
                stop_at = Some(Instant::now() + grace);
            }
            if stop_at.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(None);
            }
            std::thread::sleep(POLL);
        }
    })();
    // Always clean up, including failed receipt writes and normal CLI exits.
    cleanup_session(session, &std::env::current_exe()?, &mut process_list)?;
    let status = child.wait()?;
    receipt.completion = Some(Completion {
        success: result
            .as_ref()
            .is_ok_and(|observed: &Option<ExitStatus>| observed.is_some_and(|s| s.success())),
        exit_code: status.code(),
        signal: status.signal(),
        completed: input_socket.map(|_| result.as_ref().is_ok_and(Option::is_some)),
    });
    write_json(marker, &receipt)?;
    result.map(|_| ())
}

/// Runs inside the supervisor's session. Joining pins the target group and
/// prevents a reused numeric PGID from ever targeting a different session.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.kill_session_group")
)]
pub fn kill_session_group(session: i32, group: i32) -> Result<()> {
    let sid = Pid::from_raw(session);
    ensure!(
        session > 1 && group > 1 && group != session && getsid(None)? == sid,
        "foreign process session"
    );
    setpgid(Pid::from_raw(0), Pid::from_raw(group))?;
    killpg(Pid::from_raw(group), Signal::SIGKILL)?;
    bail!("group killer unexpectedly survived")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "pulumi_process.cleanup_session")
)]
fn cleanup_session(session: Pid, helper: &Path, process_list: &mut File) -> Result<()> {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        ensure!(
            Instant::now() < deadline,
            "Pulumi session cleanup timed out"
        );
        let groups = session_groups(session, deadline, process_list)?;
        if groups.is_empty() {
            return Ok(());
        }
        for group in groups {
            ensure!(
                Instant::now() < deadline,
                "Pulumi session cleanup timed out"
            );
            let mut killer = Command::new(helper)
                .arg("__kill-pulumi-group")
                .arg("--session")
                .arg(session.as_raw().to_string())
                .arg("--group")
                .arg(group.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let status = wait_bounded(&mut killer, deadline)?;
            // Failure to join can mean the group exited meanwhile. Re-enumerate
            // instead of falling back to an unsafe signal of the old group ID.
            if status.signal() != Some(Signal::SIGKILL as i32) {
                std::thread::sleep(POLL);
            }
        }
        std::thread::sleep(POLL);
    }
}

fn wait_bounded(child: &mut Child, deadline: Instant) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("process inspection or cleanup timed out");
        }
        std::thread::sleep(POLL);
    }
}

fn session_groups(session: Pid, deadline: Instant, output: &mut File) -> Result<BTreeSet<i32>> {
    output.set_len(0)?;
    output.seek(SeekFrom::Start(0))?;
    let mut ps = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=", "-o", "stat="])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()?;
    ensure!(
        wait_bounded(
            &mut ps,
            deadline.min(Instant::now() + Duration::from_secs(1))
        )?
        .success(),
        "cannot inspect Pulumi session"
    );
    ensure!(
        output.metadata()?.len() <= 1024 * 1024,
        "process list exceeds limit"
    );
    output.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    output.read_to_string(&mut text)?;
    let mut groups = BTreeSet::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let pid = Pid::from_raw(fields.next().context("missing process ID")?.parse()?);
        let state = fields.next().context("missing process state")?;
        // Zombies cannot mutate resources or create children. Their adopter reaps them.
        if state.starts_with('Z') {
            continue;
        }
        match getsid(Some(pid)) {
            Ok(sid) if sid == session => match getpgid(Some(pid)) {
                Ok(group) if group != session => {
                    groups.insert(group.as_raw());
                }
                Ok(_) | Err(Errno::ESRCH) => {}
                Err(error) => return Err(error.into()),
            },
            Ok(_) | Err(Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(groups)
}
