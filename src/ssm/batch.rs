//! Overlap remote commands without worker threads or concurrent lease writers.
use super::*;
use std::path::PathBuf;

// Bound remote work independently of topology size. Queued requests start when
// a slot becomes free; adding nodes does not add controller threads or leases.
const MAX_IN_FLIGHT: usize = 4;

pub struct CommandRequest {
    pub instance_id: String,
    pub script: String,
    pub journal_path: PathBuf,
    pub timeout_secs: u32,
}

struct Pending {
    _lock: File,
    request: Value,
    journal: Journal,
    deadline: Option<Duration>,
    online: bool,
    output: Option<Value>,
    unavailable: Option<eyre::Report>,
}

/// Execute independent requests on distinct hosts with at most four outstanding
/// remote commands. Results retain input order. All journals are validated and
/// locked before dispatch. Existing submissions recover their exact attempts;
/// cached successes are not dispatched again. Queueing does not consume a fresh
/// command's execution budget. Progress and observation callbacks stay on the
/// controller thread, including lease renewal and cancellation checks.
///
/// On failure, stop dispatching and durably mark every unfinished submission
/// uncertain, requesting bounded best-effort cancellation for known IDs. This
/// is not proof of remote termination: recovery must settle the saved journals.
pub fn execute_batch(
    api: &dyn AwsApi,
    commands: &[CommandRequest],
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
    observer: &mut CommandProgress<'_>,
) -> Result<Vec<Value>> {
    execute_batch_inner(api, commands, None, runtime, progress, observer)
}

/// Admit fresh commands as their hosts become online, without waiting for the
/// slowest host. Availability has one separate budget; offline hosts consume
/// neither execution slots nor command budgets. Recover existing submissions
/// immediately, even if their hosts are currently offline.
pub fn execute_batch_when_online(
    api: &dyn AwsApi,
    commands: &[CommandRequest],
    availability_timeout: Duration,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
    observer: &mut CommandProgress<'_>,
) -> Result<Vec<Value>> {
    execute_batch_inner(
        api,
        commands,
        Some(availability_timeout),
        runtime,
        progress,
        observer,
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "ssm.execute_batch")
)]
fn execute_batch_inner(
    api: &dyn AwsApi,
    commands: &[CommandRequest],
    availability_timeout: Option<Duration>,
    runtime: &impl Runtime,
    progress: &mut dyn FnMut() -> Result<()>,
    observer: &mut CommandProgress<'_>,
) -> Result<Vec<Value>> {
    let mut instances = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for command in commands {
        validate_inputs(&command.instance_id, &command.script, command.timeout_secs)?;
        ensure!(
            instances.insert(&command.instance_id) && paths.insert(&command.journal_path),
            "SSM batch requires distinct hosts and journals"
        );
    }
    let mut pending = Vec::with_capacity(commands.len());
    for command in commands {
        progress()?;
        let lock = lock_journal(&command.journal_path)?;
        let (request, mut journal) = load_or_prepare(
            &command.instance_id,
            &command.script,
            &command.journal_path,
            command.timeout_secs,
            runtime,
        )?;
        if journal.attempts.last().unwrap().state == State::Failed {
            ensure!(
                journal.attempts.len() < MAX_ATTEMPTS,
                "SSM command attempt limit reached; inspect the saved history"
            );
            journal.attempts.push(Attempt::new(runtime.unix_time()?));
        }
        let current = journal.attempts.last().unwrap();
        let output = current.output.clone();
        let deadline = if matches!(current.state, State::Dispatched | State::Running) {
            Some(ExecutionBudget::new(command.timeout_secs, runtime, false)?.deadline)
        } else {
            None
        };
        let mut runner = Runner {
            api,
            runtime,
            progress,
            observer,
            reporting_failed: false,
            settlement_only: false,
            journal_path: &command.journal_path,
            deadline: Duration::MAX,
            unavailable: None,
        };
        runner.save(&journal)?;
        pending.push(Pending {
            _lock: lock,
            request,
            journal,
            deadline,
            online: availability_timeout.is_none(),
            output,
            unavailable: None,
        });
    }

    let availability_deadline = availability_timeout
        .map(|timeout| {
            runtime
                .monotonic()
                .checked_add(timeout)
                .context("SSM availability budget overflow")
        })
        .transpose()?;
    let result: Result<()> = (|| loop {
        progress()?;
        let waiting: Vec<_> = commands
            .iter()
            .zip(&pending)
            .filter(|(_, p)| p.output.is_none() && p.deadline.is_none() && !p.online)
            .map(|(command, _)| command.instance_id.as_str())
            .collect();
        for chunk in waiting.chunks(50) {
            progress()?;
            let remaining = availability_deadline
                .unwrap()
                .saturating_sub(runtime.monotonic());
            ensure!(
                !remaining.is_zero(),
                "SSM node availability deadline exceeded"
            );
            let response = api.call_with_timeout(
                "ssm",
                "describe-instance-information",
                json!({"Filters":[{"Key":"InstanceIds","Values":chunk}],"MaxResults":50}),
                &api_args(),
                remaining.min(Duration::from_secs(10)),
            )?;
            ensure!(
                response
                    .get("NextToken")
                    .is_none_or(|v| v.is_null() || v == ""),
                "SSM availability response is paginated"
            );
            for instance in response["InstanceInformationList"]
                .as_array()
                .context("missing SSM instance information")?
            {
                let id = instance["InstanceId"]
                    .as_str()
                    .context("missing SSM instance identity")?;
                ensure!(chunk.contains(&id), "unexpected SSM instance identity");
                if instance["PingStatus"] == "Online" {
                    let index = commands.iter().position(|c| c.instance_id == id).unwrap();
                    pending[index].online = true;
                }
            }
        }
        let mut active = pending
            .iter()
            .filter(|p| p.deadline.is_some() && p.output.is_none())
            .count();
        // Settle active work before admission, so a newly online earlier host
        // can use a slot released by a later host in this same iteration.
        for started in [true, false] {
            for (command, pending) in commands.iter().zip(&mut pending) {
                if pending.output.is_some() || pending.deadline.is_some() != started {
                    continue;
                }
                if pending.deadline.is_none() {
                    if !pending.online || active >= MAX_IN_FLIGHT {
                        continue;
                    }
                    pending.deadline =
                        Some(ExecutionBudget::new(command.timeout_secs, runtime, false)?.deadline);
                    active += 1;
                }
                let mut runner = Runner {
                    api,
                    runtime,
                    progress,
                    observer,
                    reporting_failed: false,
                    settlement_only: false,
                    journal_path: &command.journal_path,
                    deadline: pending.deadline.unwrap(),
                    unavailable: pending.unavailable.take(),
                };
                pending.output = runner.step(&pending.request, &mut pending.journal)?;
                pending.unavailable = runner.unavailable;
                if pending.output.is_some() {
                    active -= 1;
                }
            }
        }
        if pending.iter().all(|p| p.output.is_some()) {
            return Ok(());
        }
        let deadline = pending
            .iter()
            .filter(|p| p.output.is_none())
            .filter_map(|p| p.deadline)
            .chain(
                (!waiting.is_empty())
                    .then_some(availability_deadline)
                    .flatten(),
            )
            .min()
            .context("SSM batch has no active commands")?;
        runtime.sleep(POLL_INTERVAL.min(deadline.saturating_sub(runtime.monotonic())));
    })();
    if let Err(error) = result {
        let mut save_failed = false;
        // A failing progress observer must not prevent other nodes' cancellation
        // journals from being saved. No new command is dispatched in this path.
        for (command, pending) in commands.iter().zip(&mut pending) {
            let mut runner = Runner {
                api,
                runtime,
                progress,
                observer: &mut |_| Ok(()),
                reporting_failed: false,
                settlement_only: false,
                journal_path: &command.journal_path,
                deadline: Duration::ZERO,
                unavailable: None,
            };
            save_failed |= runner.cancel(&mut pending.journal).is_err();
        }
        return if save_failed {
            Err(error.wrap_err("SSM batch stopped; cancellation journal persistence failed"))
        } else {
            Err(error)
        };
    }
    Ok(pending.into_iter().map(|p| p.output.unwrap()).collect())
}
