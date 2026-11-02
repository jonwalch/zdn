//! Offline public-adapter handshake, not deployment authorization.
//!
//! Typed offline describe/compile/render. These are not deployment authorization:
//! package selection and host lifecycle gates must separately authenticate inputs.
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

pub mod contract;
pub mod package;

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
    sandbox: Option<crate::host::adapter_sandbox::Sandbox>,
}

impl VerifiedExecutable {
    pub(crate) fn with_sandbox(mut self, sandbox: crate::host::adapter_sandbox::Sandbox) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Decode a pinned raw bundle in the companion as well as independently
    /// checking its byte inventory here. No input path comes from the protocol.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.compile")
    )]
    pub fn compile(
        self,
        input: &contract::CompileInput,
        bundle: &[u8],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PinnedResult<contract::Compiled>> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        let block_pins = input.validate(bundle)?;
        self.stage_bundle(bundle)?;
        let output = self.exchange(
            Operation::Compile,
            input,
            &input.descriptor,
            &input.seed_bundle,
            None,
            deadline,
            cancelled,
        )?;
        let result = PinnedResult::<contract::Compiled>::read(output)?;
        result.value.validate(input, &block_pins)?;
        Ok(result)
    }

    /// Freshly bound render; security validation precedes use or equality.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.render")
    )]
    pub fn render(
        self,
        input: &contract::RenderInput,
        bundle: &[u8],
        compiled: &PinnedResult<contract::Compiled>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PinnedResult<contract::Rendered>> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(Failure::Deadline);
        }
        let pins = input.public.validate(bundle)?;
        input.options.validate_for_render(input.identity_only)?;
        compiled.value.validate(&input.public, &pins)?;
        if input.compiled_sha256 != compiled.pin.sha256 {
            return Err(Failure::InvalidPublicInput);
        }
        self.stage_bundle(bundle)?;
        let output = self.exchange(
            Operation::Render,
            input,
            &input.public.descriptor,
            &input.public.seed_bundle,
            Some(&input.compiled_sha256),
            deadline,
            cancelled,
        )?;
        let result = PinnedResult::<contract::Rendered>::read(output)?;
        contract::validate_render(&result.value, input)?;
        Ok(result)
    }

    fn stage_bundle(&self, bundle: &[u8]) -> Result<()> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(self.directory.path().join("seed-blocks.bin"))
            .map_err(|_| Failure::Unavailable)?;
        file.write_all(bundle).map_err(|_| Failure::Unavailable)
    }

    #[allow(clippy::too_many_arguments)]
    fn exchange<T: Serialize>(
        &self,
        operation: Operation,
        input: &T,
        descriptor: &contract::Descriptor,
        bundle: &contract::Pin,
        compiled: Option<&str>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>> {
        #[derive(Deserialize, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Context {
            public_descriptor_sha256: String,
            input_sha256: String,
            seed_bundle_sha256: String,
            compiled_result_sha256: Option<String>,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a, T> {
            protocol: &'static str,
            operation: Operation,
            request_id: String,
            adapter_selection_sha256: &'a str,
            context: &'a Context,
            input: &'a T,
        }
        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Response {
            protocol: String,
            operation: Operation,
            request_id: String,
            adapter_selection_sha256: String,
            context: Context,
            result: Box<serde_json::value::RawValue>,
        }
        let context = Context {
            public_descriptor_sha256: contract::Pin::of(
                &serde_json::to_vec(descriptor).map_err(|_| Failure::InvalidPublicInput)?,
            )
            .sha256,
            input_sha256: contract::Pin::of(
                &serde_json::to_vec(input).map_err(|_| Failure::InvalidPublicInput)?,
            )
            .sha256,
            seed_bundle_sha256: bundle.sha256.clone(),
            compiled_result_sha256: compiled.map(str::to_owned),
        };
        let request = Request {
            protocol: PROTOCOL,
            operation,
            request_id: Uuid::new_v4().to_string(),
            adapter_selection_sha256: &self.selection.adapter_selection_sha256,
            context: &context,
            input,
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| Failure::InvalidPublicInput)?;
        if bytes.len() > MAX_STDOUT {
            return Err(Failure::InvalidPublicInput);
        }
        let bytes = self.execute(
            &bytes,
            deadline.min(Instant::now() + Duration::from_secs(30)),
            cancelled,
        )?;
        let response: Response = contract::parse(&bytes).map_err(|_| Failure::InvalidOutput)?;
        if response.protocol != PROTOCOL
            || response.operation != operation
            || response.request_id != request.request_id
            || response.adapter_selection_sha256 != self.selection.adapter_selection_sha256
            || response.context != context
        {
            return Err(Failure::InvalidOutput);
        }
        Ok(response.result.get().as_bytes().to_vec())
    }

    /// Inspect/copy bytes only; never runs the selected program. The source must
    /// be an absolute regular non-symlink file. No PATH lookup or download.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.snapshot")
    )]
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
        let directory = tempfile::tempdir().map_err(|_| Failure::Unavailable)?;
        let program = directory.path().join("adapter");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&program)
            .map_err(|_| Failure::Unavailable)?;
        // Hash exactly the bytes copied into the private snapshot. Never reopen
        // the caller's path after checking it, or retain the whole executable.
        let mut input = input.take(selection.executable_bytes + 1);
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = input.read(&mut buffer).map_err(|_| Failure::Unavailable)?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > selection.executable_bytes {
                return Err(Failure::InvalidPublicInput);
            }
            hash.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(|_| Failure::Unavailable)?;
        }
        if bytes != selection.executable_bytes
            || hex::encode(hash.finalize()) != selection.executable_sha256
        {
            return Err(Failure::InvalidPublicInput);
        }
        drop(output);
        Ok(Self {
            directory,
            program,
            selection,
            sandbox: None,
        })
    }

    /// Handshake entry point. Compile/render require their typed entry points.
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
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.describe")
    )]
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

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.execute")
    )]
    fn execute(&self, input: &[u8], deadline: Instant, cancelled: &AtomicBool) -> Result<Vec<u8>> {
        use std::{
            io::Write,
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        // Existing dependencies::run_command_in_memory closes stdin and uses
        // one 1 MiB bound. HostCommand requires Linux host receipts/helper CLI.
        // Neither can carry this duplex protocol without broad changes.
        let mut command = match &self.sandbox {
            Some(sandbox) => sandbox
                .command(self.directory.path())
                .map_err(|_| Failure::Unavailable)?,
            None => Command::new(&self.program),
        };
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

/// Exact deterministic result bytes, not a hash of an unspecified JSON rewrite.
pub struct PinnedResult<T> {
    value: T,
    bytes: Vec<u8>,
    pin: contract::Pin,
}
impl<T: serde::de::DeserializeOwned + Serialize> PinnedResult<T> {
    pub fn value(&self) -> &T {
        &self.value
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn pin(&self) -> &contract::Pin {
        &self.pin
    }
    fn read(bytes: Vec<u8>) -> Result<Self> {
        let value = contract::parse(&bytes).map_err(|_| Failure::InvalidOutput)?;
        if serde_json::to_vec(&value).map_err(|_| Failure::InvalidOutput)? != bytes {
            return Err(Failure::InvalidOutput);
        }
        let pin = contract::Pin::of(&bytes);
        Ok(Self { value, bytes, pin })
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
