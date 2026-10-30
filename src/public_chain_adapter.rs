//! Offline public-adapter handshake, not deployment authorization.
//!
//! Only `describe` is supported in this first boundary slice. Compile/render,
//! package selection and lifecycle gates must not consume this as verification.
//! The explicitly trusted executable runs with a scrubbed environment, not an OS
//! sandbox. Ordinary same-group descendants are killed; escaping processes and
//! parent crashes require the existing host supervisor at future host integration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const PROTOCOL: &str = "zdn-public-chain-adapter/v1";
pub const PROTOCOL_ARGUMENT: &str = "--zdn-public-chain-adapter-v1";
const MAX_EXECUTABLE: u64 = 128 * 1024 * 1024;
const MAX_STDOUT: usize = 4 * 1024 * 1024;
const MAX_STDERR: usize = 16 * 1024;
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Core-owned, output-free failures. Never attach executable diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Unavailable,
    Incompatible,
    InvalidPublicInput,
    InvalidOutput,
    Deadline,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self {
            Self::Unavailable => "unavailable",
            Self::Incompatible => "incompatible",
            Self::InvalidPublicInput => "invalid-public-input",
            Self::InvalidOutput => "invalid-output",
            Self::Deadline => "deadline",
        };
        write!(f, "public chain adapter: {category}")
    }
}
impl std::error::Error for Failure {}

type Result<T> = std::result::Result<T, Failure>;

/// Pins supplied by a caller who has explicitly trusted this local executable.
/// This is not a package reader, publisher-authenticity check or trust prompt.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedExecutable {
    pub adapter_id: String,
    pub adapter_version: String,
    pub prepared_input_schema: String,
    pub adapter_selection_sha256: String,
    pub executable_sha256: String,
    pub executable_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Describe,
    Compile,
    Render,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeRequest<'a> {
    protocol: &'static str,
    operation: Operation,
    request_id: Uuid,
    adapter_selection_sha256: &'a str,
    input: DescribeInput<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeInput<'a> {
    adapter_id: &'a str,
    adapter_version: &'a str,
    prepared_input_schema: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeResponse {
    protocol: String,
    operation: Operation,
    request_id: String,
    adapter_selection_sha256: String,
    #[serde(deserialize_with = "object")]
    result: Description,
}

/// Exact v1 handshake; no capability negotiation or adapter-supplied commands.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Description {
    pub adapter_id: String,
    pub adapter_version: String,
    pub prepared_input_schema: String,
    pub runtime_family: String,
    pub operations: Vec<Operation>,
}

/// Verified private snapshot, retained until execution and cleanup finish.
/// A changed source path cannot replace these bytes between check and exec.
pub struct VerifiedExecutable {
    directory: tempfile::TempDir,
    program: PathBuf,
    selection: TrustedExecutable,
}

impl VerifiedExecutable {
    /// Inspect/copy bytes only; never runs the selected program. The source must
    /// be an absolute regular non-symlink file. No PATH lookup or download.
    pub fn verify(path: &Path, selection: TrustedExecutable) -> Result<Self> {
        use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
        if !path.is_absolute()
            || !valid_hash(&selection.adapter_selection_sha256)
            || !valid_hash(&selection.executable_sha256)
            || selection.executable_bytes == 0
            || selection.executable_bytes > MAX_EXECUTABLE
            || [
                &selection.adapter_id,
                &selection.adapter_version,
                &selection.prepared_input_schema,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 128 || !v.is_ascii() || v.bytes().any(|b| b <= 32))
        {
            return Err(Failure::InvalidPublicInput);
        }
        let input = OpenOptions::new()
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
            .open(path)
            .map_err(|_| Failure::Unavailable)?;
        if !input
            .metadata()
            .map_err(|_| Failure::Unavailable)?
            .is_file()
        {
            return Err(Failure::InvalidPublicInput);
        }
        let mut bytes = Vec::new();
        input
            .take(selection.executable_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Unavailable)?;
        if bytes.len() as u64 != selection.executable_bytes
            || hex::encode(Sha256::digest(&bytes)) != selection.executable_sha256
        {
            return Err(Failure::InvalidPublicInput);
        }
        let directory = tempfile::tempdir().map_err(|_| Failure::Unavailable)?;
        let program = directory.path().join("adapter");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&program)
            .map_err(|_| Failure::Unavailable)?;
        output.write_all(&bytes).map_err(|_| Failure::Unavailable)?;
        drop(output);
        Ok(Self {
            directory,
            program,
            selection,
        })
    }

    /// Only the handshake is implemented. Reject later operations before exec;
    /// they need typed public inventory/result/render validation, not opaque JSON.
    /// Consume the snapshot: its trusted child can mutate its own working directory.
    ///
    /// ```compile_fail,E0382
    /// use zdn::public_chain_adapter::{Operation, VerifiedExecutable};
    /// use std::{sync::atomic::AtomicBool, time::Instant};
    /// fn reuse(executable: VerifiedExecutable, deadline: Instant, cancelled: &AtomicBool) {
    ///     let _ = executable.invoke(Operation::Describe, deadline, cancelled);
    ///     let _ = executable.invoke(Operation::Describe, deadline, cancelled);
    /// }
    /// ```
    pub fn invoke(
        self,
        operation: Operation,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Description> {
        if operation != Operation::Describe {
            return Err(Failure::Incompatible);
        }
        if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        let deadline = deadline.min(Instant::now() + DESCRIBE_TIMEOUT);
        let request = DescribeRequest {
            protocol: PROTOCOL,
            operation,
            request_id: Uuid::new_v4(),
            adapter_selection_sha256: &self.selection.adapter_selection_sha256,
            input: DescribeInput {
                adapter_id: &self.selection.adapter_id,
                adapter_version: &self.selection.adapter_version,
                prepared_input_schema: &self.selection.prepared_input_schema,
            },
        };
        let input = serde_json::to_vec(&request).map_err(|_| Failure::InvalidPublicInput)?;
        // The typed handshake is far smaller than the aggregate 4 MiB ceiling.
        let output = self.execute(&input, deadline, cancelled)?;
        // Require objects without collapsing duplicate fields through a Value.
        let mut deserializer = serde_json::Deserializer::from_slice(&output);
        let response: DescribeResponse =
            object(&mut deserializer).map_err(|_| Failure::InvalidOutput)?;
        deserializer.end().map_err(|_| Failure::InvalidOutput)?;
        if response.protocol != PROTOCOL
            || response.operation != operation
            || response.request_id != request.request_id.to_string()
            || response.adapter_selection_sha256 != self.selection.adapter_selection_sha256
        {
            return Err(Failure::InvalidOutput);
        }
        let result = response.result;
        if result.adapter_id != self.selection.adapter_id
            || result.adapter_version != self.selection.adapter_version
            || result.prepared_input_schema != self.selection.prepared_input_schema
            || result.runtime_family != "zakura-custom-testnet"
            || result.operations != [Operation::Describe, Operation::Compile, Operation::Render]
        {
            return Err(Failure::Incompatible);
        }
        if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        Ok(result)
    }

    fn execute(&self, input: &[u8], deadline: Instant, cancelled: &AtomicBool) -> Result<Vec<u8>> {
        use std::{
            io::Write,
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        // Existing dependencies::run_command_in_memory closes stdin and uses
        // one 1 MiB bound. HostCommand requires Linux host receipts/helper CLI.
        // Neither can carry this duplex protocol without broad changes.
        let mut command = Command::new(&self.program);
        command
            .arg(PROTOCOL_ARGUMENT)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("HOME", "/nonexistent")
            .current_dir(self.directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = ChildGuard(loop {
            if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(Failure::Deadline);
            }
            match command.spawn() {
                Ok(child) => break child,
                // A concurrent fork can retain our closed snapshot writer until
                // its exec. ETXTBSY means this adapter has not executed; only
                // that transient launch failure may retry, within the same budget.
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(Failure::Unavailable),
            }
        });
        let stdin = child.0.stdin.take().ok_or(Failure::Unavailable)?;
        let mut stdout = child.0.stdout.take().ok_or(Failure::Unavailable)?;
        let mut stderr = child.0.stderr.take().ok_or(Failure::Unavailable)?;
        for fd in [
            std::os::fd::AsFd::as_fd(&stdin),
            std::os::fd::AsFd::as_fd(&stdout),
            std::os::fd::AsFd::as_fd(&stderr),
        ] {
            use nix::fcntl::{fcntl, FcntlArg, OFlag};
            fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(|_| Failure::Unavailable)?;
        }
        let mut pending = input;
        let mut input_pipe = Some(stdin);
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(Failure::Deadline);
            }
            let before = (pending.len(), output.len(), errors.len());
            if let Some(pipe) = &mut input_pipe {
                match pipe.write(pending) {
                    Ok(0) => return Err(Failure::InvalidOutput),
                    Ok(n) => pending = &pending[n..],
                    Err(e) if transient(&e) => {}
                    Err(_) => return Err(Failure::InvalidOutput),
                }
                if pending.is_empty() {
                    // Dropping the writer sends EOF, not just its borrow.
                    input_pipe = None;
                }
            }
            let out_eof = drain(&mut stdout, &mut output, MAX_STDOUT)?;
            let err_eof = drain(&mut stderr, &mut errors, MAX_STDERR)?;
            // Do not reap until pipes close; the unreaped leader pins its PGID
            // for Drop cleanup even if descendants keep a pipe open.
            if out_eof && err_eof {
                use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
                use nix::unistd::Pid;
                let pid =
                    Pid::from_raw(i32::try_from(child.0.id()).map_err(|_| Failure::Unavailable)?);
                match waitid(
                    Id::Pid(pid),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                )
                .map_err(|_| Failure::Unavailable)?
                {
                    WaitStatus::Exited(_, 0) if input_pipe.is_none() => return Ok(output),
                    WaitStatus::StillAlive => {}
                    _ => return Err(Failure::Unavailable),
                }
            }
            if before == (pending.len(), output.len(), errors.len()) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            map: A,
        ) -> std::result::Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn transient(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut buffer = [0; 8192];
    // One chunk per poll: infinite output cannot starve cancellation/deadlines.
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(n) if bytes.len() + n <= limit => {
            bytes.extend_from_slice(&buffer[..n]);
            Ok(false)
        }
        Ok(_) => Err(Failure::InvalidOutput),
        Err(e) if transient(&e) => Ok(false),
        Err(_) => Err(Failure::InvalidOutput),
    }
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        use nix::{
            sys::signal::{killpg, Signal},
            unistd::Pid,
        };
        if let Ok(pid) = i32::try_from(self.0.id()) {
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
