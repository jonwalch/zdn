//! Durable, bounded Run Command requests for idempotent host operations.
//!
//! A dispatch marker reaches disk before SendCommand. Once dispatch is possible,
//! an absent command ID is recovered by the unique comment and exact request;
//! it is never used as permission to submit another command. Only an observed
//! terminal failure, a definitive request rejection, or an explicit repeat of
//! an observed successful command permits a new attempt.
//! Scripts and AWS stderr are not saved. Successful output must be one small,
//! non-secret JSON object; callers own that output schema.

use crate::{
    aws::{self, AwsApi, AwsApiError},
    foundation,
    foundation_live::Runtime,
};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Read,
    path::Path,
    time::Duration,
};
use uuid::Uuid;

mod batch;
pub use batch::{execute_batch, execute_batch_when_online, CommandRequest};

pub const API_VERSION: &str = "zdn-ssm-command/v1alpha1";
const DOCUMENT: &str = "AWS-RunShellScript";
const DOCUMENT_VERSION: &str = "1";
const MAX_SCRIPT_BYTES: usize = 16 * 1024;
const MAX_OUTPUT_BYTES: usize = 20 * 1024;
const MAX_JOURNAL_BYTES: usize = 128 * 1024;
const MAX_ATTEMPTS: usize = 32;
const MAX_PAGES: usize = 20;
const MAX_RECOVERY_SCANS: usize = 6;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Sanitized execution categories, available through `eyre::Report::downcast_ref`.
/// Only `Unavailable` is retryable by an observation caller. Unclassified errors
/// are not transient. These categories do not authorize redispatch: the journal
/// remains the authority for whether a saved command can be resumed or repeated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    InvalidOutput,
    InvalidInvocation,
    RemoteFailed,
    RemoteCancelled,
    RemoteTimedOut,
    Unavailable,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOutput => "SSM result is not one bounded JSON object",
            Self::InvalidInvocation => "SSM invocation identity differs from the saved request",
            Self::RemoteFailed | Self::RemoteCancelled | Self::RemoteTimedOut => {
                "SSM command reached a terminal failure; a later retry will record a new attempt"
            }
            Self::Unavailable => {
                "SSM observation temporarily unavailable; remote completion remains unconfirmed"
            }
        })
    }
}

impl std::error::Error for CommandError {}

/// Sanitized durable attempt state, not host output or permission to redispatch.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandObservation {
    pub attempt_id: Uuid,
    pub attempt_number: usize,
    pub state: &'static str,
    pub command_id_known: bool,
    pub uncertain: bool,
    pub cancellation_requested: bool,
    pub failure: Option<&'static str>,
}

pub type CommandProgress<'a> = dyn FnMut(&CommandObservation) -> Result<()> + 'a;

// Preserve only the structured AWS code, never arbitrary source diagnostics.
fn sanitized_api_error(error: &eyre::Report, message: &'static str) -> eyre::Report {
    match error.downcast_ref::<AwsApiError>() {
        Some(source) => eyre::Report::new(source.clone()).wrap_err(message),
        None => eyre::eyre!(message),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    api_version: String,
    request_sha256: String,
    instance_id: String,
    timeout_secs: u32,
    attempts: Vec<Attempt>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    id: Uuid,
    created_at: u64,
    comment: String,
    command_id: Option<String>,
    state: State,
    /// A local failure, timeout or cancellation is not remote completion.
    uncertain: bool,
    cancellation_requested: bool,
    failure: Option<Failure>,
    output: Option<Value>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum State {
    Prepared,
    Dispatched,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Failure {
    RequestRejected,
    Failed,
    Cancelled,
    TimedOut,
    InvalidOutput,
    ResponseCode,
}

impl Attempt {
    fn new(created_at: u64) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            created_at,
            comment: format!("zdn-command-{id}"),
            command_id: None,
            state: State::Prepared,
            uncertain: false,
            cancellation_requested: false,
            failure: None,
            output: None,
        }
    }
}

/// Run one non-secret, idempotent host operation or resume its saved attempt.
/// A cached success is intentional; use a new journal path for a new observation.
/// `timeout_secs` bounds this local run and the remote script execution (30–7200).
/// The supplied API must bound individual calls. Progress is checked before and
/// after calls and at two-second polling intervals, but this synchronous trait
/// cannot interrupt a call that blocks internally.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.execute")
)]
pub fn execute(
    api: &dyn AwsApi,
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    execute_with_observer(
        api,
        instance_id,
        script,
        journal_path,
        timeout_secs,
        runtime,
        progress,
        &mut |_| Ok(()),
    )
}

/// Observe saved attempt state before effects and after durable transitions.
/// Observer errors stop later effects without undoing saved state; a dispatched
/// intent with no command ID remains uncertain even if reporting prevented send.
/// Cached successes are reported again, not freshly checked against the host.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.execute_with_observer")
)]
pub fn execute_with_observer(
    api: &dyn AwsApi,
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
    observer: &mut CommandProgress<'_>,
) -> Result<Value> {
    let mut budget = ExecutionBudget::new(timeout_secs, runtime, false)?;
    execute_with_budget(
        api,
        instance_id,
        script,
        journal_path,
        &mut budget,
        runtime,
        progress,
        observer,
    )
}

/// One local deadline and optional repeat, shared across activation, its fresh
/// observation, and an explicit restart. Only producer activation enables the
/// repeat: its helper preserves durable production intent after partial effects.
pub(crate) struct ExecutionBudget {
    timeout_secs: u32,
    deadline: Duration,
    repeat_available: bool,
}

impl ExecutionBudget {
    pub(crate) fn new(
        timeout_secs: u32,
        runtime: &impl Runtime,
        repeat_available: bool,
    ) -> Result<Self> {
        Ok(Self {
            timeout_secs,
            deadline: runtime
                .monotonic()
                .checked_add(Duration::from_secs(u64::from(timeout_secs)))
                .context("SSM deadline overflow")?,
            repeat_available,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "ssm.execution_budget.claim_repeat")
    )]
    pub(crate) fn claim_repeat(&mut self, runtime: &impl Runtime) -> Result<()> {
        ensure!(
            runtime.monotonic() < self.deadline,
            "SSM observation deadline reached"
        );
        ensure!(
            self.repeat_available,
            "SSM command repeat budget exhausted; inspect the saved history"
        );
        self.repeat_available = false;
        Ok(())
    }

    /// Observations cannot repeat and must respect both their own timeout and
    /// the enclosing activation deadline, without changing the remote request.
    pub(crate) fn observation(&self, timeout_secs: u32, runtime: &impl Runtime) -> Result<Self> {
        let mut observation = Self::new(timeout_secs, runtime, false)?;
        observation.deadline = observation.deadline.min(self.deadline);
        Ok(observation)
    }
}

/// Execute under a caller-owned budget and journal lock. A fresh retry requires
/// an identity-checked, durably saved `Failed` result; no other error authorizes
/// it. The caller retains its deployment lock and progress guards across calls.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.execute_with_budget")
)]
pub(crate) fn execute_with_budget(
    api: &dyn AwsApi,
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    budget: &mut ExecutionBudget,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
    observer: &mut CommandProgress<'_>,
) -> Result<Value> {
    let timeout_secs = budget.timeout_secs;
    validate_inputs(instance_id, script, timeout_secs)?;
    let _lock = lock_journal(journal_path)?;
    let (request, mut journal) =
        load_or_prepare(instance_id, script, journal_path, timeout_secs, runtime)?;
    if journal.attempts.last().unwrap().state == State::Failed {
        ensure!(
            journal.attempts.len() < MAX_ATTEMPTS,
            "SSM command attempt limit reached; inspect the saved history"
        );
        journal.attempts.push(Attempt::new(runtime.unix_time()?));
    }
    let mut runner = Runner {
        api,
        runtime,
        progress,
        observer,
        reporting_failed: false,
        settlement_only: false,
        journal_path,
        deadline: budget.deadline,
        unavailable: None,
    };
    runner.save(&journal)?;
    let mut result = runner.run(&request, &mut journal);
    let current = journal.attempts.last().unwrap();
    if budget.repeat_available
        && !runner.reporting_failed
        && result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<CommandError>())
            == Some(&CommandError::RemoteFailed)
        && current.state == State::Failed
        && matches!(current.failure, Some(Failure::Failed))
        && current.command_id.is_some()
        && !current.uncertain
        && !current.cancellation_requested
    {
        // Check cancellation, lease ownership and the original deadline before
        // recording or dispatching a new attempt. Never reset the time budget.
        runner.check(&mut journal)?;
        budget.claim_repeat(runtime)?;
        ensure!(
            journal.attempts.len() < MAX_ATTEMPTS,
            "SSM command attempt limit reached; inspect the saved history"
        );
        journal.attempts.push(Attempt::new(runtime.unix_time()?));
        runner.save(&journal)?;
        result = runner.run(&request, &mut journal);
    }
    if result.is_err() {
        let current = journal.attempts.last_mut().unwrap();
        if !matches!(current.state, State::Succeeded | State::Failed) {
            current.uncertain = current.state != State::Prepared;
            runner.save(&journal)?;
        }
    }
    result
}

/// Save a first Prepared attempt for an exact request, without contacting AWS.
/// An existing journal is validated and preserved byte-for-byte, regardless of
/// its last attempt's state. Preparation never retries or replaces an attempt.
/// The caller must retain its operation lock and ownership/cancellation guards.
pub fn prepare(
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
) -> Result<()> {
    validate_inputs(instance_id, script, timeout_secs)?;
    let _lock = lock_journal(journal_path)?;
    load_or_prepare(instance_id, script, journal_path, timeout_secs, runtime)?;
    Ok(())
}

/// Settle an existing submission without sending, retrying, or cancelling any
/// command. Prepared requests are inert. The caller may use a separate copy of
/// the original journal so the historical command receipt remains immutable.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.reconcile_only")
)]
pub fn reconcile_only(
    api: &dyn AwsApi,
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    validate_inputs(instance_id, script, timeout_secs)?;
    let _lock = lock_journal(journal_path)?;
    ensure!(
        read_journal(journal_path)?.is_some(),
        "missing settlement journal"
    );
    let (request, mut journal) =
        load_or_prepare(instance_id, script, journal_path, timeout_secs, runtime)?;
    if matches!(
        journal.attempts.last().unwrap().state,
        State::Prepared | State::Succeeded | State::Failed
    ) {
        return Ok(());
    }
    let mut observer = |_: &CommandObservation| Ok(());
    let mut runner = Runner {
        api,
        runtime,
        progress,
        observer: &mut observer,
        reporting_failed: false,
        settlement_only: true,
        journal_path,
        deadline: ExecutionBudget::new(timeout_secs, runtime, false)?.deadline,
        unavailable: None,
    };
    let result = runner.run(&request, &mut journal);
    if matches!(
        journal.attempts.last().unwrap().state,
        State::Succeeded | State::Failed
    ) && matches!(
        result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<CommandError>()),
        Some(
            CommandError::RemoteFailed
                | CommandError::RemoteCancelled
                | CommandError::RemoteTimedOut
                | CommandError::InvalidOutput
        )
    ) {
        // These terminal-result errors follow a successful save. In-memory
        // terminal state alone does not prove persistence; preserve other errors.
        Ok(())
    } else {
        result.map(|_| ())
    }
}

/// A settlement copy can update only the last unfinished submission; it cannot
/// discard, append, retarget, or replace any part of the prior command history.
/// Completed settlement also permits an unchanged Prepared attempt: it never sent.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.validate_settlement_history")
)]
pub fn validate_settlement_history(
    original: &[u8],
    settled: &[u8],
    require_settled: bool,
) -> Result<()> {
    ensure!(
        original.len() <= MAX_JOURNAL_BYTES && settled.len() <= MAX_JOURNAL_BYTES,
        "settlement history exceeds bound"
    );
    let old: Journal = serde_json::from_slice(original)?;
    let new: Journal = serde_json::from_slice(settled)?;
    validate_journal(
        &old,
        &old.instance_id,
        old.timeout_secs,
        &old.request_sha256,
    )?;
    validate_journal(
        &new,
        &old.instance_id,
        old.timeout_secs,
        &old.request_sha256,
    )?;
    ensure!(
        old.attempts.len() == new.attempts.len(),
        "settlement changed attempt history"
    );
    ensure!(
        !require_settled
            || new.attempts.iter().all(|attempt| {
                matches!(
                    attempt.state,
                    State::Prepared | State::Succeeded | State::Failed
                ) && !attempt.uncertain
            }),
        "settlement still has an unresolved submission"
    );
    for (index, (a, b)) in old.attempts.iter().zip(&new.attempts).enumerate() {
        if index + 1 != old.attempts.len()
            || matches!(a.state, State::Prepared | State::Succeeded | State::Failed)
        {
            ensure!(
                serde_json::to_value(a)? == serde_json::to_value(b)?,
                "settlement changed prior attempt"
            );
        } else {
            ensure!(
                a.id == b.id
                    && a.created_at == b.created_at
                    && a.comment == b.comment
                    && a.cancellation_requested == b.cancellation_requested
                    && a.command_id
                        .as_ref()
                        .is_none_or(|id| b.command_id.as_ref() == Some(id))
                    && b.state != State::Prepared,
                "settlement changed submission identity"
            );
        }
    }
    Ok(())
}

// Both callers validate inputs and hold the journal lock. Only an absent
// journal creates an attempt; retries remain an execution decision.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.load_or_prepare")
)]
fn load_or_prepare(
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
) -> Result<(Value, Journal)> {
    let request = request(instance_id, script, timeout_secs);
    let request_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&request)?));
    let journal = match read_journal(journal_path)? {
        Some(journal) => {
            validate_journal(&journal, instance_id, timeout_secs, &request_sha256)?;
            journal
        }
        None => {
            let journal = Journal {
                api_version: API_VERSION.into(),
                request_sha256,
                instance_id: instance_id.into(),
                timeout_secs,
                attempts: vec![Attempt::new(runtime.unix_time()?)],
            };
            save(journal_path, &journal)?;
            journal
        }
    };
    Ok((request, journal))
}

/// Prepare a new attempt of a successfully completed, idempotent operation.
/// The caller must hold its deployment operation lock and freshly establish
/// that the operation is needed again. This never abandons an uncertain command:
/// recover it through `execute` first. A crash after this write resumes the new
/// prepared attempt through the same journal, preserving all earlier outcomes.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.prepare_repeat_after_success")
)]
pub fn prepare_repeat_after_success(
    instance_id: &str,
    script: &str,
    journal_path: &Path,
    timeout_secs: u32,
    runtime: &impl Runtime,
) -> Result<()> {
    validate_inputs(instance_id, script, timeout_secs)?;
    let _lock = lock_journal(journal_path)?;
    let request_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&request(
        instance_id,
        script,
        timeout_secs,
    ))?));
    let mut journal = read_journal(journal_path)?.context("SSM command has not completed")?;
    validate_journal(&journal, instance_id, timeout_secs, &request_sha256)?;
    ensure!(
        journal.attempts.last().unwrap().state == State::Succeeded,
        "SSM command must reach success before an explicit repeat"
    );
    ensure!(
        journal.attempts.len() < MAX_ATTEMPTS,
        "SSM command attempt limit reached; inspect the saved history"
    );
    journal.attempts.push(Attempt::new(runtime.unix_time()?));
    save(journal_path, &journal)
}

struct Runner<'a, T: Runtime> {
    api: &'a dyn AwsApi,
    runtime: &'a T,
    progress: &'a mut dyn FnMut() -> Result<()>,
    observer: &'a mut CommandProgress<'a>,
    reporting_failed: bool,
    settlement_only: bool,
    journal_path: &'a Path,
    deadline: Duration,
    unavailable: Option<eyre::Report>,
}

impl<T: Runtime> Runner<'_, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "ssm.runner.save")
    )]
    fn save(&mut self, journal: &Journal) -> Result<()> {
        save(self.journal_path, journal)?;
        let attempt = journal.attempts.last().unwrap();
        let result = (self.observer)(&CommandObservation {
            attempt_id: attempt.id,
            attempt_number: journal.attempts.len(),
            state: match attempt.state {
                State::Prepared => "prepared",
                State::Dispatched => "dispatched",
                State::Running => "running",
                State::Succeeded => "succeeded",
                State::Failed => "failed",
            },
            command_id_known: attempt.command_id.is_some(),
            uncertain: attempt.uncertain,
            cancellation_requested: attempt.cancellation_requested,
            failure: attempt.failure.map(|failure| match failure {
                Failure::RequestRejected => "request-rejected",
                Failure::Failed => "failed",
                Failure::Cancelled => "cancelled",
                Failure::TimedOut => "timed-out",
                Failure::InvalidOutput => "invalid-output",
                Failure::ResponseCode => "response-code",
            }),
        });
        self.reporting_failed |= result.is_err();
        result
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "ssm.runner.run")
    )]
    fn run(&mut self, request: &Value, journal: &mut Journal) -> Result<Value> {
        loop {
            if let Some(output) = self.step(request, journal)? {
                return Ok(output);
            }
            self.pause(journal)?;
        }
    }

    // One invocation observation, without sleeping on ordinary pending results.
    // Both single-command and cluster scheduling use the same durable protocol.
    fn step(&mut self, request: &Value, journal: &mut Journal) -> Result<Option<Value>> {
        self.check(journal)?;
        if let Some(output) = &journal.attempts.last().unwrap().output {
            return Ok(Some(output.clone()));
        }
        if journal.attempts.last().unwrap().state == State::Prepared {
            ensure!(!self.settlement_only, "settlement cannot dispatch");
            let current = journal.attempts.last_mut().unwrap();
            current.state = State::Dispatched;
            current.uncertain = true;
            self.save(journal)?;
            // Reporting can block; recheck ownership/cancellation and the
            // original deadline before dispatching after an observer returns.
            self.check(journal)?;
            let mut input = request.clone();
            input["Comment"] = json!(journal.attempts.last().unwrap().comment);
            let response = self.api.call("ssm", "send-command", input, &api_args());
            match response {
                Ok(response) => {
                    if let Some(command) = response.get("Command") {
                        if matches_request(
                            command,
                            request,
                            &journal.attempts.last().unwrap().comment,
                        )? {
                            if let Ok(id) = command_id(command) {
                                let current = journal.attempts.last_mut().unwrap();
                                current.command_id = Some(id);
                                current.state = State::Running;
                                current.uncertain = false;
                                self.save(journal)?;
                            }
                        }
                    }
                }
                Err(error) if definitive_rejection(&error) => {
                    fail(journal, Failure::RequestRejected);
                    self.save(journal)?;
                    self.check(journal)?;
                    return Err(sanitized_api_error(
                        &error,
                        "SSM rejected the command request; inspect permissions and instance readiness",
                    ));
                }
                Err(_) => {}
            }
            self.check(journal)?;
        }
        if journal.attempts.last().unwrap().command_id.is_none() {
            let id = self.recover(request, journal)?;
            let current = journal.attempts.last_mut().unwrap();
            current.command_id = Some(id);
            current.state = State::Running;
            current.uncertain = false;
            self.save(journal)?;
        }
        self.check(journal)?;
        let current = journal.attempts.last().unwrap();
        let id = current.command_id.as_ref().unwrap();
        let response = self.api.call(
            "ssm",
            "get-command-invocation",
            json!({"CommandId":id,"InstanceId":journal.instance_id}),
            &api_args(),
        );
        self.unavailable = response.as_ref().err().filter(|e| retryable(e)).map(|e| {
            sanitized_api_error(
                e,
                "SSM command status is unavailable; the saved command remains uncertain",
            )
        });
        self.check(journal)?;
        let response = match response {
            Ok(response) => response,
            Err(error) if retryable(&error) => return Ok(None),
            Err(error) => {
                return Err(sanitized_api_error(
                    &error,
                    "SSM command status is unavailable; the saved command remains uncertain",
                ));
            }
        };
        validate_invocation(&response, journal)?;
        match response["Status"].as_str().unwrap_or_default() {
            "Pending" | "InProgress" | "Delayed" | "Cancelling" => Ok(None),
            "Success" => {
                if response["ResponseCode"].as_i64() != Some(0) {
                    fail(journal, Failure::ResponseCode);
                    self.save(journal)?;
                    return Err(eyre::Report::new(CommandError::RemoteFailed)
                        .wrap_err("SSM command returned a nonzero or missing response code"));
                }
                let parsed = parse_output(&response);
                match parsed {
                    Ok(output) => {
                        let current = journal.attempts.last_mut().unwrap();
                        current.state = State::Succeeded;
                        current.uncertain = false;
                        current.output = Some(output.clone());
                        self.save(journal)?;
                        Ok(Some(output))
                    }
                    Err(error) => {
                        fail(journal, Failure::InvalidOutput);
                        self.save(journal)?;
                        Err(error.wrap_err(CommandError::InvalidOutput))
                    }
                }
            }
            "Failed" | "Cancelled" | "TimedOut" => {
                let failure = match response["Status"].as_str().unwrap() {
                    "Failed" => Failure::Failed,
                    "Cancelled" => Failure::Cancelled,
                    _ => Failure::TimedOut,
                };
                fail(journal, failure);
                self.save(journal)?;
                Err(eyre::Report::new(match failure {
                    Failure::Cancelled => CommandError::RemoteCancelled,
                    Failure::TimedOut => CommandError::RemoteTimedOut,
                    _ => CommandError::RemoteFailed,
                }))
            }
            _ => Err(eyre::Report::new(CommandError::InvalidInvocation).wrap_err(
                "SSM returned an unsupported command status; the saved command remains uncertain",
            )),
        }
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "ssm.runner.recover")
    )]
    fn recover(&mut self, request: &Value, journal: &mut Journal) -> Result<String> {
        for scan in 0..MAX_RECOVERY_SCANS {
            self.check(journal)?;
            let comment = journal.attempts.last().unwrap().comment.clone();
            let mut input = json!({"InstanceId":journal.instance_id,"MaxResults":50});
            let mut seen_tokens = BTreeSet::new();
            let mut matches = BTreeSet::new();
            let mut complete = false;
            for page in 0..MAX_PAGES {
                self.check(journal)?;
                let response = self
                    .api
                    .call("ssm", "list-commands", input.clone(), &api_args());
                self.unavailable = response.as_ref().err().filter(|e| retryable(e)).map(|e| {
                    sanitized_api_error(
                        e,
                        "SSM command recovery is unavailable; refusing another dispatch",
                    )
                });
                self.check(journal)?;
                let response = match response {
                    Ok(response) => response,
                    Err(error) if retryable(&error) => break,
                    Err(error) => {
                        return Err(sanitized_api_error(
                            &error,
                            "SSM command recovery is unavailable; refusing another dispatch",
                        ));
                    }
                };
                let commands = response["Commands"]
                    .as_array()
                    .context("SSM command recovery returned no command list")?;
                ensure!(
                    commands.len() <= 50,
                    "SSM command recovery page exceeds its bound"
                );
                for command in commands {
                    if command["Comment"] == comment {
                        ensure!(
                            matches_request(command, request, &comment)?,
                            "SSM recovery comment belongs to a different request; refusing another dispatch"
                        );
                        matches.insert(command_id(command)?);
                        ensure!(
                            matches.len() == 1,
                            "multiple SSM commands match the saved request; refusing to choose one"
                        );
                    }
                }
                match response.get("NextToken") {
                    None | Some(Value::Null) => {
                        complete = true;
                        break;
                    }
                    Some(Value::String(token)) if token.is_empty() => {
                        complete = true;
                        break;
                    }
                    Some(Value::String(token)) => {
                        ensure!(
                            token.len() <= 2048
                                && !token.chars().any(char::is_control)
                                && seen_tokens.insert(token.clone()),
                            "invalid or repeated SSM recovery page token"
                        );
                        ensure!(
                            page + 1 < MAX_PAGES,
                            "SSM recovery page limit reached; refusing another dispatch"
                        );
                        input["NextToken"] = json!(token);
                    }
                    _ => bail!("invalid SSM recovery page token"),
                }
            }
            if complete {
                if let Some(id) = matches.into_iter().next() {
                    return Ok(id);
                }
            }
            if scan + 1 < MAX_RECOVERY_SCANS {
                self.pause(journal)?;
            }
        }
        if let Some(error) = self.unavailable.take() {
            return Err(error.wrap_err(CommandError::Unavailable));
        }
        bail!("SSM dispatch remains uncertain after bounded recovery; no command was resent")
    }

    fn check(&mut self, journal: &mut Journal) -> Result<()> {
        let progress = (self.progress)();
        if progress.is_err() || self.runtime.monotonic() >= self.deadline {
            if !self.settlement_only {
                self.cancel(journal)?;
            }
            if progress.is_err() {
                bail!(
                    "SSM operation stopped by progress or cancellation checks; remote completion remains unconfirmed"
                );
            }
            if let Some(error) = self.unavailable.take() {
                return Err(error.wrap_err(CommandError::Unavailable));
            }
            bail!("SSM observation deadline reached; remote completion remains unconfirmed");
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "ssm.runner.cancel")
    )]
    fn cancel(&mut self, journal: &mut Journal) -> Result<()> {
        let current = journal.attempts.last_mut().unwrap();
        if !matches!(
            current.state,
            State::Succeeded | State::Failed | State::Prepared
        ) {
            current.uncertain = true;
            if current.command_id.is_some() {
                current.cancellation_requested = true;
                // The request is recorded before the best-effort call. A reply
                // does not prove cancellation or rollback of host side effects.
                self.save(journal)?;
                let id = journal
                    .attempts
                    .last()
                    .unwrap()
                    .command_id
                    .as_ref()
                    .unwrap();
                let _ = self.api.call_with_timeout(
                    "ssm",
                    "cancel-command",
                    json!({"CommandId":id,"InstanceIds":[journal.instance_id]}),
                    &api_args(),
                    Duration::from_secs(10),
                );
            } else {
                self.save(journal)?;
            }
        }
        Ok(())
    }

    fn pause(&mut self, journal: &mut Journal) -> Result<()> {
        self.check(journal)?;
        let remaining = self.deadline.saturating_sub(self.runtime.monotonic());
        self.runtime.sleep(POLL_INTERVAL.min(remaining));
        self.check(journal)
    }
}

fn request(instance_id: &str, script: &str, timeout_secs: u32) -> Value {
    json!({"DocumentName":DOCUMENT,"DocumentVersion":DOCUMENT_VERSION,"InstanceIds":[instance_id],
        "TimeoutSeconds":timeout_secs.min(120),"MaxConcurrency":"1","MaxErrors":"0",
        "CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[script],"executionTimeout":[timeout_secs.to_string()],"workingDirectory":["/"]}})
}

fn matches_request(command: &Value, request: &Value, comment: &str) -> Result<bool> {
    if command["Comment"] != comment {
        return Ok(false);
    }
    ensure!(command.is_object(), "invalid SSM command record");
    let targets_empty = command
        .get("Targets")
        .is_none_or(|v| v.is_null() || v.as_array().is_some_and(Vec::is_empty));
    Ok(command["InstanceIds"] == request["InstanceIds"]
        && command["DocumentName"] == DOCUMENT
        && command["DocumentVersion"] == DOCUMENT_VERSION
        && command["Parameters"] == request["Parameters"]
        && command["TimeoutSeconds"] == request["TimeoutSeconds"]
        && targets_empty)
}

fn validate_invocation(response: &Value, journal: &Journal) -> Result<()> {
    let attempt = journal.attempts.last().unwrap();
    ensure!(
        response["CommandId"].as_str() == attempt.command_id.as_deref()
            && response["InstanceId"] == journal.instance_id
            && response["Comment"] == attempt.comment
            && response["DocumentName"] == DOCUMENT
            && response["DocumentVersion"] == DOCUMENT_VERSION,
        CommandError::InvalidInvocation
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.parse_output")
)]
fn parse_output(response: &Value) -> Result<Value> {
    let text = response["StandardOutputContent"]
        .as_str()
        .context("SSM returned no JSON result")?;
    ensure!(
        text.len() <= MAX_OUTPUT_BYTES,
        "SSM JSON result exceeds 20 KiB"
    );
    let output: Value =
        serde_json::from_str(text).map_err(|_| eyre::eyre!("SSM result is not one JSON object"))?;
    ensure!(output.is_object(), "SSM result must be one JSON object");
    Ok(output)
}

fn fail(journal: &mut Journal, failure: Failure) {
    let current = journal.attempts.last_mut().unwrap();
    current.state = State::Failed;
    current.uncertain = false;
    current.failure = Some(failure);
    current.output = None;
}

fn command_id(command: &Value) -> Result<String> {
    let id = command["CommandId"]
        .as_str()
        .context("SSM returned no command ID")?;
    validate_command_id(id)?;
    Ok(id.into())
}

fn validate_command_id(id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(id).map_err(|_| eyre::eyre!("invalid SSM command ID"))?;
    ensure!(
        !parsed.is_nil() && parsed.hyphenated().to_string() == id,
        "invalid SSM command ID"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.validate_inputs")
)]
fn validate_inputs(instance: &str, script: &str, timeout: u32) -> Result<()> {
    let suffix = instance
        .strip_prefix("i-")
        .context("SSM requires an EC2 instance ID")?;
    ensure!(
        [8, 17].contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SSM instance ID"
    );
    ensure!(
        !script.is_empty() && script.len() <= MAX_SCRIPT_BYTES && !script.contains('\0'),
        "SSM script must be nonempty, without NULs, and at most 16 KiB"
    );
    ensure!(
        (30..=7200).contains(&timeout),
        "SSM timeout must be between 30 and 7200 seconds"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.retryable")
)]
fn retryable(error: &eyre::Report) -> bool {
    aws::transient_error(error)
        || error.downcast_ref::<AwsApiError>().is_some_and(|e| {
            matches!(
                e.code.as_str(),
                "InvocationDoesNotExist" | "InternalServerError"
            )
        })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.definitive_rejection")
)]
fn definitive_rejection(error: &eyre::Report) -> bool {
    error.downcast_ref::<AwsApiError>().is_some_and(|e| {
        matches!(
            e.code.as_str(),
            "AccessDenied"
                | "AccessDeniedException"
                | "InvalidDocument"
                | "InvalidDocumentVersion"
                | "InvalidParameters"
                | "InvalidInstanceId"
                | "UnsupportedPlatform"
        )
    })
}

fn api_args() -> Vec<String> {
    [
        "--no-paginate",
        "--cli-connect-timeout",
        "2",
        "--cli-read-timeout",
        "3",
    ]
    .map(String::from)
    .into()
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.validate_journal")
)]
fn validate_journal(
    journal: &Journal,
    instance: &str,
    timeout: u32,
    request_sha256: &str,
) -> Result<()> {
    ensure!(
        journal.api_version == API_VERSION
            && journal.instance_id == instance
            && journal.timeout_secs == timeout
            && journal.request_sha256 == request_sha256,
        "SSM journal belongs to a different immutable request"
    );
    ensure!(
        !journal.attempts.is_empty() && journal.attempts.len() <= MAX_ATTEMPTS,
        "invalid SSM attempt history"
    );
    let mut attempts = BTreeSet::new();
    let mut commands = BTreeSet::new();
    for (index, attempt) in journal.attempts.iter().enumerate() {
        ensure!(
            attempt.id.get_version_num() == 4
                && attempts.insert(attempt.id)
                && attempt.comment == format!("zdn-command-{}", attempt.id),
            "invalid SSM attempt identity"
        );
        if let Some(id) = &attempt.command_id {
            validate_command_id(id)?;
            ensure!(commands.insert(id), "duplicate SSM command ID in history");
        }
        ensure!(
            index + 1 == journal.attempts.len()
                || matches!(attempt.state, State::Succeeded | State::Failed),
            "SSM history contains an unfinished earlier attempt"
        );
        ensure!(
            match attempt.state {
                State::Prepared =>
                    attempt.command_id.is_none()
                        && !attempt.uncertain
                        && !attempt.cancellation_requested
                        && attempt.failure.is_none()
                        && attempt.output.is_none(),
                State::Dispatched =>
                    attempt.command_id.is_none()
                        && attempt.uncertain
                        && attempt.failure.is_none()
                        && attempt.output.is_none(),
                State::Running =>
                    attempt.command_id.is_some()
                        && attempt.failure.is_none()
                        && attempt.output.is_none(),
                State::Succeeded =>
                    attempt.command_id.is_some()
                        && !attempt.uncertain
                        && attempt.failure.is_none()
                        && attempt.output.as_ref().is_some_and(Value::is_object),
                State::Failed =>
                    !attempt.uncertain
                        && attempt.failure.is_some()
                        && attempt.output.is_none()
                        && (attempt.command_id.is_some()
                            || matches!(attempt.failure, Some(Failure::RequestRejected))),
            },
            "inconsistent SSM attempt state"
        );
        if let Some(output) = &attempt.output {
            ensure!(
                serde_json::to_vec(output)?.len() <= MAX_OUTPUT_BYTES,
                "SSM cached result exceeds its bound"
            );
        }
    }
    Ok(())
}

/// Validate portable terminal evidence without submitting or recovering commands.
/// Cancellation flags and all terminal attempts remain part of the original bytes.
pub fn validate_handoff(
    bytes: &[u8],
    expected_instance: &str,
    script: &str,
    timeout_secs: u32,
) -> Result<()> {
    validate_handoff_request(bytes, expected_instance, script, timeout_secs, true)
}

/// Unconfirmed current updates and inert historical observations can retain their
/// last unfinished attempt. Earlier attempts and the immutable request still
/// validate; this grants no execution authority or permission to resend.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.validate_handoff_request")
)]
pub(crate) fn validate_handoff_request(
    bytes: &[u8],
    expected_instance: &str,
    script: &str,
    timeout_secs: u32,
    require_terminal: bool,
) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_JOURNAL_BYTES,
        "SSM journal exceeds its size bound"
    );
    let journal: Journal =
        serde_json::from_slice(bytes).map_err(|_| eyre::eyre!("invalid SSM command journal"))?;
    validate_inputs(expected_instance, script, timeout_secs)?;
    let request_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&request(
        expected_instance,
        script,
        timeout_secs,
    ))?));
    validate_journal(&journal, expected_instance, timeout_secs, &request_sha256)?;
    ensure!(
        !require_terminal
            || journal.attempts.iter().all(|attempt| {
                matches!(attempt.state, State::Succeeded | State::Failed) && !attempt.uncertain
            }),
        "SSM handoff requires terminal, certain attempts; reconcile on the source controller"
    );
    Ok(())
}

fn save(path: &Path, journal: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec(journal)?;
    ensure!(
        bytes.len() <= MAX_JOURNAL_BYTES,
        "SSM journal exceeds its size bound"
    );
    foundation::write_private(path, &bytes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.read_journal")
)]
fn read_journal(path: &Path) -> Result<Option<Journal>> {
    let file = match private_open(path, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_JOURNAL_BYTES,
        "SSM journal exceeds its size bound"
    );
    Ok(Some(
        serde_json::from_slice(&bytes).map_err(|_| eyre::eyre!("invalid SSM command journal"))?,
    ))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.private_open")
)]
fn private_open(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "SSM journal and lock must be regular files"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "SSM journal and lock must have private permissions"
        );
    }
    Ok(file)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.lock_journal")
)]
fn lock_journal(path: &Path) -> Result<File> {
    let parent = path
        .parent()
        .context("SSM journal needs a parent directory")?;
    ensure!(
        fs::symlink_metadata(parent)?.file_type().is_dir(),
        "SSM journal parent must be a real directory"
    );
    let mut name = path
        .file_name()
        .context("SSM journal needs a file name")?
        .to_os_string();
    name.push(".lock");
    let file = private_open(&parent.join(name), true)?;
    FileExt::try_lock_exclusive(&file).context("another process holds the SSM journal lock")?;
    Ok(file)
}
