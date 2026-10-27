//! No AWS process or network is used: command persistence and eventual
//! consistency are modeled through the public API and a fake clock.

use eyre::{bail, Result};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::Path,
    time::Duration,
};
use uuid::Uuid;
use zdn::{
    aws::{AwsApi, AwsApiError},
    foundation_live::Runtime,
    ssm::{
        execute, execute_batch, execute_batch_when_online, prepare, prepare_repeat_after_success,
        CommandError, CommandRequest,
    },
};

const INSTANCE: &str = "i-0123456789abcdef0";
const SCRIPT: &str = "printf '%s\\n' '{\"ready\":true}'";

#[test]
fn settlement_never_sends_retries_or_cancels_even_after_lost_reply() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original-command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    prepare(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
    zdn::ssm::reconcile_only(&aws, INSTANCE, SCRIPT, &path, 30, &clock, &mut || Ok(())).unwrap();
    assert!(aws.calls.borrow().is_empty());
    aws.sends.borrow_mut().push_back(Send::Crash);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&aws, &clock, &path)))
            .is_err()
    );
    let original = fs::read(&path).unwrap();
    let settlement = root.path().join("settlement.json");
    zdn::foundation::write_private(&settlement, &original).unwrap();
    aws.polls.borrow_mut().push_back(Poll::Status("Failed"));
    zdn::ssm::reconcile_only(&aws, INSTANCE, SCRIPT, &settlement, 30, &clock, &mut || {
        Ok(())
    })
    .unwrap();
    zdn::ssm::reconcile_only(&aws, INSTANCE, SCRIPT, &settlement, 30, &clock, &mut || {
        Ok(())
    })
    .unwrap();
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(aws.call_count("cancel-command"), 0);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(zdn::ssm::reconcile_only(
        &aws,
        INSTANCE,
        "wrong",
        &settlement,
        30,
        &clock,
        &mut || Ok(())
    )
    .is_err());
}

#[test]
fn settlement_blocks_absent_duplicate_unavailable_and_cancelled_observations() {
    for mode in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        aws.sends.borrow_mut().push_back(Send::Crash);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&aws, &clock, &path)))
                .is_err()
        );
        match mode {
            0 => aws.commands.borrow_mut().clear(),
            1 => {
                let mut duplicate = aws.commands.borrow()[0].clone();
                duplicate["CommandId"] = json!(Uuid::new_v4());
                aws.commands.borrow_mut().push(duplicate);
            }
            2 => aws
                .pages
                .borrow_mut()
                .push_back(Page::Error("AccessDeniedException")),
            _ => {}
        }
        assert!(
            zdn::ssm::reconcile_only(&aws, INSTANCE, SCRIPT, &path, 30, &clock, &mut || {
                if mode == 3 {
                    bail!("cancelled")
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(aws.call_count("cancel-command"), 0);
    }
}

#[test]
fn settlement_requires_durable_terminal_observation() {
    struct BlockJournalWrite<'a> {
        aws: &'a Aws,
        directory: &'a Path,
        saved: &'a Path,
    }
    impl AwsApi for BlockJournalWrite<'_> {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            let response = self.aws.call(service, operation, input, extra)?;
            if operation == "get-command-invocation" {
                // Preserve the durable receipt, but make its original parent
                // a file so atomic publication fails even when run as root.
                fs::rename(self.directory, self.saved)?;
                fs::write(self.directory, b"blocked")?;
            }
            Ok(response)
        }
    }

    for blocked in [false, true] {
        for poll in [
            Poll::Status("Success"),
            Poll::Status("Failed"),
            Poll::Status("Cancelled"),
            Poll::Status("TimedOut"),
            Poll::Code(1),
            Poll::Text("invalid output".into()),
        ] {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join("journal");
            fs::create_dir(&directory).unwrap();
            let path = directory.join("command.json");
            let saved = root.path().join("saved");
            let aws = Aws::default();
            let clock = Clock::default();
            aws.sends.borrow_mut().push_back(Send::Crash);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&aws, &clock, &path)))
                    .is_err()
            );
            aws.polls.borrow_mut().push_back(poll);
            let blocking = BlockJournalWrite {
                aws: &aws,
                directory: &directory,
                saved: &saved,
            };
            let api: &dyn AwsApi = if blocked { &blocking } else { &aws };
            let result =
                zdn::ssm::reconcile_only(api, INSTANCE, SCRIPT, &path, 30, &clock, &mut || Ok(()));
            if blocked {
                let error = result.expect_err("unpersisted terminal observation must not settle");
                assert!(
                    error.downcast_ref::<std::io::Error>().is_some(),
                    "{error:#}"
                );
                assert_eq!(
                    journal(&saved.join("command.json"))["attempts"][0]["state"],
                    "running"
                );
            } else {
                result.unwrap();
                let state = journal(&path)["attempts"][0]["state"].clone();
                assert!(state == "succeeded" || state == "failed", "{state}");
            }
        }
    }
}

#[derive(Default)]
struct Clock(Cell<u64>);
impl Runtime for Clock {
    fn unix_time(&self) -> Result<u64> {
        Ok(1_800_000_000 + self.0.get())
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.0.get())
    }
    fn sleep(&self, duration: Duration) {
        self.0.set(self.0.get() + duration.as_secs());
    }
}

enum Send {
    Success,
    LostReply,
    NotAccepted,
    Crash,
    Malformed,
    Rejected,
}
enum Poll {
    Status(&'static str),
    Error(&'static str),
    UnknownError,
    Text(String),
    WrongInstance,
    Code(i64),
}
enum Page {
    Value(Value),
    Error(&'static str),
}

#[derive(Default)]
struct Aws {
    calls: RefCell<Vec<(String, Value)>>,
    commands: RefCell<Vec<Value>>,
    sends: RefCell<VecDeque<Send>>,
    polls: RefCell<VecDeque<Poll>>,
    pages: RefCell<VecDeque<Page>>,
    always_pending: Cell<bool>,
    cancel_fails: Cell<bool>,
}

impl Aws {
    fn call_count(&self, operation: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|(name, _)| name == operation)
            .count()
    }

    fn response(&self, input: &Value) -> Value {
        let commands = self.commands.borrow();
        let command = commands
            .iter()
            .find(|command| command["CommandId"] == input["CommandId"])
            .unwrap();
        json!({"CommandId":command["CommandId"],"InstanceId":command["InstanceIds"][0],
            "DocumentName":command["DocumentName"],"DocumentVersion":command["DocumentVersion"],
            "Comment":command["Comment"],"Status":"Success","ResponseCode":0,
            "StandardOutputContent":"{\"ready\":true}\n","StandardErrorContent":"private stderr must never be saved"})
    }
}

fn error(code: &str) -> eyre::Report {
    AwsApiError { code: code.into() }.into()
}

impl AwsApi for Aws {
    fn call(
        &self,
        service: &str,
        operation: &str,
        mut input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert_eq!(service, "ssm");
        assert_eq!(
            extra,
            [
                "--no-paginate",
                "--cli-connect-timeout",
                "2",
                "--cli-read-timeout",
                "3"
            ]
        );
        self.calls
            .borrow_mut()
            .push((operation.into(), input.clone()));
        match operation {
            "send-command" => {
                let mode = self.sends.borrow_mut().pop_front().unwrap_or(Send::Success);
                if matches!(mode, Send::NotAccepted) {
                    return Err(error("RequestTimeout"));
                }
                if matches!(mode, Send::Rejected) {
                    return Err(error("AccessDeniedException"));
                }
                input["CommandId"] = json!(Uuid::new_v4());
                self.commands.borrow_mut().push(input.clone());
                match mode {
                    Send::LostReply => Err(error("CommandInterrupted")),
                    Send::Crash => panic!("simulated process stop after remote acceptance"),
                    Send::Malformed => Ok(json!({"Command":{"CommandId":"not a command ID"}})),
                    _ => Ok(json!({"Command":input})),
                }
            }
            "list-commands" => {
                assert_eq!(input["MaxResults"], 50);
                match self.pages.borrow_mut().pop_front() {
                    Some(Page::Value(value)) => Ok(value),
                    Some(Page::Error(code)) => Err(error(code)),
                    None => Ok(
                        json!({"Commands":self.commands.borrow().iter().filter(|c| c["InstanceIds"][0] == input["InstanceId"]).collect::<Vec<_>>()}),
                    ),
                }
            }
            "get-command-invocation" => {
                let mut response = self.response(&input);
                assert_eq!(input["InstanceId"], response["InstanceId"]);
                let next = self.polls.borrow_mut().pop_front();
                match next {
                    Some(Poll::Status(status)) => response["Status"] = json!(status),
                    Some(Poll::Error(code)) => return Err(error(code)),
                    Some(Poll::UnknownError) => bail!("private unknown diagnostic"),
                    Some(Poll::Text(text)) => response["StandardOutputContent"] = json!(text),
                    Some(Poll::WrongInstance) => {
                        response["InstanceId"] = json!("i-fffffffffffffffff")
                    }
                    Some(Poll::Code(code)) => response["ResponseCode"] = json!(code),
                    None if self.always_pending.get() => response["Status"] = json!("InProgress"),
                    None => {}
                }
                Ok(response)
            }
            "cancel-command" => {
                assert!(self
                    .commands
                    .borrow()
                    .iter()
                    .any(|c| c["CommandId"] == input["CommandId"]
                        && c["InstanceIds"] == input["InstanceIds"]));
                if self.cancel_fails.get() {
                    bail!("private cancellation diagnostic must not escape");
                }
                Ok(json!({}))
            }
            _ => panic!("unexpected operation {operation}"),
        }
    }
}

fn journal(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn run(aws: &Aws, clock: &Clock, path: &Path) -> Result<Value> {
    execute(aws, INSTANCE, SCRIPT, path, 30, clock, &mut || Ok(()))
}

// A remote command completes after its own fake-clock delay, not after the
// controller polls it a particular number of times. No real timing/AWS involved.
struct BatchAws<'a> {
    aws: Aws,
    clock: &'a Clock,
    durations: Vec<u64>,
    online_after: Vec<u64>,
    availability_reply: RefCell<Option<Value>>,
    started: RefCell<BTreeMap<String, u64>>,
    finished: RefCell<BTreeSet<String>>,
    max_active: Cell<usize>,
    failure: Cell<Option<usize>>,
}

impl<'a> BatchAws<'a> {
    fn new(clock: &'a Clock, durations: Vec<u64>) -> Self {
        Self {
            aws: Aws::default(),
            clock,
            online_after: vec![0; durations.len()],
            availability_reply: RefCell::default(),
            durations,
            started: RefCell::default(),
            finished: RefCell::default(),
            max_active: Cell::new(0),
            failure: Cell::new(None),
        }
    }
}

impl AwsApi for BatchAws<'_> {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        if operation == "describe-instance-information" {
            assert_eq!(service, "ssm");
            self.aws
                .calls
                .borrow_mut()
                .push((operation.into(), input.clone()));
            if let Some(reply) = &*self.availability_reply.borrow() {
                return Ok(reply.clone());
            }
            let ids = input["Filters"][0]["Values"].as_array().unwrap();
            assert!(ids.len() <= 50);
            assert_eq!(input["MaxResults"], 50);
            return Ok(
                json!({"InstanceInformationList":ids.iter().filter_map(|id| {
                let index = usize::from_str_radix(id.as_str().unwrap().trim_start_matches("i-"), 16).unwrap();
                (self.clock.0.get() >= self.online_after[index])
                    .then(|| json!({"InstanceId":id,"PingStatus":"Online"}))
            }).collect::<Vec<_>>()}),
            );
        }
        if operation == "send-command" {
            let instance = input["InstanceIds"][0].as_str().unwrap().to_owned();
            self.started
                .borrow_mut()
                .insert(instance.clone(), self.clock.0.get());
            self.finished.borrow_mut().remove(&instance);
            self.max_active.set(
                self.max_active
                    .get()
                    .max(self.started.borrow().len() - self.finished.borrow().len()),
            );
        }
        let mut response = self.aws.call(service, operation, input, extra)?;
        if operation == "get-command-invocation" {
            let instance = response["InstanceId"].as_str().unwrap().to_owned();
            let index = usize::from_str_radix(instance.trim_start_matches("i-"), 16).unwrap();
            if self.clock.0.get() - self.started.borrow()[&instance] < self.durations[index] {
                response["Status"] = json!("InProgress");
            } else {
                if self.failure.get() == Some(index) {
                    response["Status"] = json!("Failed");
                }
                response["StandardOutputContent"] = json!(json!({"instance":instance}).to_string());
                self.finished.borrow_mut().insert(instance);
            }
        }
        Ok(response)
    }
}

fn batch_commands(root: &Path, count: usize) -> Vec<CommandRequest> {
    (0..count)
        .map(|index| CommandRequest {
            instance_id: format!("i-{index:017x}"),
            script: SCRIPT.into(),
            journal_path: root.join(format!("node-{index}.json")),
            timeout_secs: 30,
        })
        .collect()
}

#[test]
fn batch_overlaps_arbitrary_node_counts_refills_slots_and_preserves_result_order() {
    for count in [0, 1, 3, 7] {
        let root = tempfile::tempdir().unwrap();
        let clock = Clock::default();
        // The slow first node must not block refilling another node's slot.
        // Seven commands finish at fake time 8; fixed waves would take 10.
        let aws = BatchAws::new(&clock, vec![8, 2, 6, 4, 2, 2, 2]);
        let commands = batch_commands(root.path(), count);
        let expected: Vec<_> = commands
            .iter()
            .map(|c| json!({"instance":c.instance_id}))
            .collect();
        let result =
            execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).unwrap();
        assert_eq!(result, expected);
        assert_eq!(clock.0.get(), if count == 0 { 0 } else { 8 });
        assert_eq!(aws.max_active.get(), count.min(4));
        if count == 7 {
            assert_eq!(aws.started.borrow()[&commands[4].instance_id], 2);
        }
        // Cached install results must not cause another dispatch on resume.
        assert_eq!(
            execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).unwrap(),
            expected
        );
        assert_eq!(aws.aws.call_count("send-command"), count);
    }
}

#[test]
fn batch_queued_nodes_receive_their_own_execution_budget() {
    let root = tempfile::tempdir().unwrap();
    let clock = Clock::default();
    let aws = BatchAws::new(&clock, vec![20; 9]);
    let commands = batch_commands(root.path(), 9);
    let outputs = execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).unwrap();
    assert_eq!(outputs.len(), 9);
    // Three waves fit their individual 30-second budgets, not one shared budget.
    assert_eq!(clock.0.get(), 60);
    assert_eq!(aws.max_active.get(), 4);
    for command in commands {
        assert_eq!(
            journal(&command.journal_path)["attempts"][0]["state"],
            "succeeded"
        );
    }
}

#[test]
fn online_batch_admits_available_hosts_without_offline_head_of_line_or_queue_timeouts() {
    for count in [0, 1, 7, 53] {
        let root = tempfile::tempdir().unwrap();
        let clock = Clock::default();
        let mut aws = BatchAws::new(&clock, vec![2; count]);
        if count > 0 {
            aws.online_after[0] = 8;
        }
        let commands = batch_commands(root.path(), count);
        let expected: Vec<_> = commands
            .iter()
            .map(|c| json!({"instance":c.instance_id}))
            .collect();
        assert_eq!(
            execute_batch_when_online(
                &aws,
                &commands,
                Duration::from_secs(10),
                &clock,
                &mut || Ok(()),
                &mut |_| Ok(())
            )
            .unwrap(),
            expected
        );
        if count > 0 {
            assert_eq!(aws.started.borrow()[&commands[0].instance_id], 8);
        }
        if count > 1 {
            assert_eq!(aws.started.borrow()[&commands[1].instance_id], 0);
        }
        assert!(aws.max_active.get() <= 4);
        let queries = aws.aws.call_count("describe-instance-information");
        // Success recovery needs neither availability nor another submission.
        *aws.availability_reply.borrow_mut() = Some(Value::Null);
        assert_eq!(
            execute_batch_when_online(
                &aws,
                &commands,
                Duration::ZERO,
                &clock,
                &mut || Ok(()),
                &mut |_| Ok(())
            )
            .unwrap(),
            expected
        );
        assert_eq!(aws.aws.call_count("describe-instance-information"), queries);
        assert_eq!(aws.aws.call_count("send-command"), count);
    }
}

#[test]
fn online_batch_deadline_or_cancellation_preserves_started_and_unstarted_requests() {
    for cancelled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let clock = Clock::default();
        let mut aws = BatchAws::new(&clock, vec![2, 8, 0]);
        aws.online_after[0] = u64::MAX;
        let commands = batch_commands(root.path(), 3);
        let error = execute_batch_when_online(
            &aws,
            &commands,
            Duration::from_secs(6),
            &clock,
            &mut || {
                if cancelled && clock.0.get() >= 4 {
                    bail!("cancelled");
                }
                Ok(())
            },
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains(if cancelled {
            "cancelled"
        } else {
            "availability deadline"
        }));
        assert_eq!(clock.0.get(), if cancelled { 4 } else { 6 });
        let saved: Vec<_> = commands.iter().map(|c| journal(&c.journal_path)).collect();
        assert_eq!(saved[0]["attempts"][0]["state"], "prepared");
        assert_eq!(saved[1]["attempts"][0]["uncertain"], true);
        assert_eq!(saved[1]["attempts"][0]["cancellationRequested"], true);
        assert_eq!(saved[2]["attempts"][0]["state"], "succeeded");
        assert_eq!(aws.aws.call_count("send-command"), 2);
        assert_eq!(aws.aws.call_count("cancel-command"), 1);
    }
}

#[test]
fn online_batch_recovers_an_uncertain_submission_without_waiting_for_availability() {
    let root = tempfile::tempdir().unwrap();
    let clock = Clock::default();
    let aws = BatchAws::new(&clock, vec![2]);
    let commands = batch_commands(root.path(), 1);
    aws.aws.sends.borrow_mut().push_back(Send::Crash);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(()))
    }))
    .is_err());
    *aws.availability_reply.borrow_mut() = Some(Value::Null);
    let output = execute_batch_when_online(
        &aws,
        &commands,
        Duration::ZERO,
        &clock,
        &mut || Ok(()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(output, [json!({"instance":commands[0].instance_id})]);
    assert_eq!(aws.aws.call_count("describe-instance-information"), 0);
    assert_eq!(aws.aws.call_count("send-command"), 1);
    assert_eq!(
        journal(&commands[0].journal_path)["attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn online_batch_refuses_malformed_paginated_or_foreign_availability_before_dispatch() {
    for reply in [
        Value::Null,
        json!({"InstanceInformationList":[],"NextToken":"more"}),
        json!({"InstanceInformationList":[{"PingStatus":"Online"}]}),
        json!({"InstanceInformationList":[{"InstanceId":INSTANCE,"PingStatus":"Online"}]}),
    ] {
        let root = tempfile::tempdir().unwrap();
        let clock = Clock::default();
        let aws = BatchAws::new(&clock, vec![2]);
        *aws.availability_reply.borrow_mut() = Some(reply);
        let commands = batch_commands(root.path(), 1);
        assert!(execute_batch_when_online(
            &aws,
            &commands,
            Duration::from_secs(10),
            &clock,
            &mut || Ok(()),
            &mut |_| Ok(())
        )
        .is_err());
        assert_eq!(aws.aws.call_count("send-command"), 0);
        assert_eq!(
            journal(&commands[0].journal_path)["attempts"][0]["state"],
            "prepared"
        );
    }
}

#[test]
fn batch_failure_cancellation_and_observer_errors_preserve_all_unfinished_work() {
    for mode in ["remote", "cancel", "observer", "timeout"] {
        let root = tempfile::tempdir().unwrap();
        let clock = Clock::default();
        let aws = BatchAws::new(&clock, vec![if mode == "timeout" { 40 } else { 8 }; 7]);
        let commands = batch_commands(root.path(), 7);
        aws.failure.set((mode == "remote").then_some(1));
        let result = execute_batch(
            &aws,
            &commands,
            &clock,
            &mut || {
                if mode == "cancel" && clock.0.get() >= 2 {
                    bail!("cancelled");
                }
                Ok(())
            },
            &mut |observation| {
                if mode == "observer"
                    && observation.state == "running"
                    && aws.started.borrow().len() == 3
                {
                    bail!("observer failed");
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "{mode}");
        let sends = aws.aws.call_count("send-command");
        assert_eq!(sends, if mode == "observer" { 3 } else { 4 }, "{mode}");
        let saved: Vec<_> = commands.iter().map(|c| journal(&c.journal_path)).collect();
        for (index, record) in saved.iter().enumerate() {
            let attempt = &record["attempts"][0];
            if index >= sends {
                assert_eq!(attempt["state"], "prepared", "{mode}");
            } else if mode == "remote" && index == 1 {
                assert_eq!(attempt["state"], "failed");
            } else if attempt["state"] != "succeeded" {
                assert_eq!(attempt["uncertain"], true, "{mode}");
                assert_eq!(attempt["cancellationRequested"], true, "{mode}");
            }
        }
        if mode == "remote" {
            aws.failure.set(None);
            execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).unwrap();
            for (index, command) in commands.iter().enumerate() {
                let record = journal(&command.journal_path);
                let attempts = record["attempts"].as_array().unwrap();
                assert_eq!(attempts.len(), if index == 1 { 2 } else { 1 });
                if index < sends && index != 1 {
                    assert_eq!(
                        attempts[0]["commandId"],
                        saved[index]["attempts"][0]["commandId"]
                    );
                }
                assert_eq!(attempts.last().unwrap()["state"], "succeeded");
            }
            assert_eq!(aws.aws.call_count("send-command"), 8);
        }
    }
}

#[test]
fn batch_recovers_lost_replies_and_rejects_invalid_requests_before_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let clock = Clock::default();
    let aws = BatchAws::new(&clock, vec![2; 3]);
    aws.aws.sends.borrow_mut().push_back(Send::LostReply);
    let mut commands = batch_commands(root.path(), 3);
    execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).unwrap();
    assert_eq!(aws.aws.call_count("send-command"), 3);
    assert_eq!(
        journal(&commands[0].journal_path)["attempts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let calls = aws.aws.calls.borrow().len();
    commands[2].instance_id = commands[0].instance_id.clone();
    assert!(execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).is_err());
    assert_eq!(aws.aws.calls.borrow().len(), calls);

    // A changed final journal must prevent even valid earlier requests from
    // dispatching; validation cannot be interleaved with eager submission.
    let fresh = tempfile::tempdir().unwrap();
    let aws = BatchAws::new(&clock, vec![2; 3]);
    let mut commands = batch_commands(fresh.path(), 3);
    let last = &commands[2];
    prepare(
        &last.instance_id,
        &last.script,
        &last.journal_path,
        last.timeout_secs,
        &clock,
    )
    .unwrap();
    commands[2].script.push_str("\n# changed request");
    assert!(execute_batch(&aws, &commands, &clock, &mut || Ok(()), &mut |_| Ok(())).is_err());
    assert!(aws.aws.calls.borrow().is_empty());
}

#[test]
fn execution_errors_preserve_permanent_categories_and_aws_codes() {
    for (poll, expected) in [
        (
            Poll::Text("private malformed output".into()),
            CommandError::InvalidOutput,
        ),
        (Poll::WrongInstance, CommandError::InvalidInvocation),
        (Poll::Status("Failed"), CommandError::RemoteFailed),
        (Poll::Status("Cancelled"), CommandError::RemoteCancelled),
        (Poll::Status("TimedOut"), CommandError::RemoteTimedOut),
        (Poll::Code(1), CommandError::RemoteFailed),
    ] {
        let root = tempfile::tempdir().unwrap();
        let aws = Aws::default();
        aws.polls.borrow_mut().push_back(poll);
        let error = run(&aws, &Clock::default(), &root.path().join("command.json")).unwrap_err();
        assert_eq!(error.downcast_ref::<CommandError>(), Some(&expected));
        assert!(!format!("{error:#?}").contains("private"));
    }
    for stage in ["send", "poll", "recovery"] {
        let root = tempfile::tempdir().unwrap();
        let aws = Aws::default();
        match stage {
            "send" => aws.sends.borrow_mut().push_back(Send::Rejected),
            "poll" => aws
                .polls
                .borrow_mut()
                .push_back(Poll::Error("AccessDeniedException")),
            _ => {
                aws.sends.borrow_mut().push_back(Send::LostReply);
                aws.pages
                    .borrow_mut()
                    .push_back(Page::Error("AccessDeniedException"));
            }
        }
        let error = run(&aws, &Clock::default(), &root.path().join("command.json")).unwrap_err();
        assert_eq!(
            error.downcast_ref::<AwsApiError>().unwrap().code,
            "AccessDeniedException",
            "{stage}"
        );
        assert_ne!(
            error.downcast_ref::<CommandError>(),
            Some(&CommandError::Unavailable)
        );
    }
}

#[test]
fn exhausted_transient_observations_are_typed_and_resume_without_redispatch() {
    for recovery in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        if recovery {
            aws.sends.borrow_mut().push_back(Send::LostReply);
            aws.pages
                .borrow_mut()
                .extend((0..6).map(|_| Page::Error("ThrottlingException")));
        } else {
            aws.polls
                .borrow_mut()
                .extend((0..15).map(|_| Poll::Error("ThrottlingException")));
        }
        let error = run(&aws, &clock, &path).unwrap_err();
        assert_eq!(
            error.downcast_ref::<CommandError>(),
            Some(&CommandError::Unavailable)
        );
        assert_eq!(
            error.downcast_ref::<AwsApiError>().unwrap().code,
            "ThrottlingException"
        );
        assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
        run(&aws, &clock, &path).unwrap();
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(journal(&path)["attempts"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn unknown_aws_and_absent_dispatch_failures_are_not_transient() {
    for scenario in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let aws = Aws::default();
        if scenario == 0 {
            aws.sends.borrow_mut().push_back(Send::NotAccepted);
        } else if scenario == 1 {
            aws.polls.borrow_mut().push_back(Poll::UnknownError);
        } else {
            aws.polls
                .borrow_mut()
                .push_back(Poll::Error("UnknownFailure"));
        }
        let error = run(&aws, &Clock::default(), &root.path().join("command.json")).unwrap_err();
        assert!(!format!("{error:#?}").contains("private"));
        assert_ne!(
            error.downcast_ref::<CommandError>(),
            Some(&CommandError::Unavailable)
        );
    }
}

fn interrupt_after_dispatch(aws: &Aws, clock: &Clock, path: &Path) {
    aws.sends.borrow_mut().push_back(Send::Crash);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(aws, clock, path)));
    assert!(result.is_err());
    assert_eq!(journal(path)["attempts"][0]["state"], "dispatched");
    assert!(journal(path)["attempts"][0]["commandId"].is_null());
}

#[test]
fn attempt_observations_are_durable_sanitized_and_reporting_never_replays_work() {
    for stop in ["prepared", "dispatched", "running", "succeeded", "failed"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        if stop == "failed" {
            aws.polls.borrow_mut().push_back(Poll::Status("Failed"));
        }
        let mut stopped_at = None;
        let error = zdn::ssm::execute_with_observer(
            &aws,
            INSTANCE,
            SCRIPT,
            &path,
            30,
            &clock,
            &mut || Ok(()),
            &mut |observation| {
                let saved = journal(&path);
                let attempt = &saved["attempts"][0];
                assert_eq!(observation.attempt_number, 1);
                assert_eq!(attempt["id"], observation.attempt_id.to_string());
                assert_eq!(attempt["state"], observation.state);
                assert_eq!(attempt["uncertain"], observation.uncertain);
                assert_eq!(
                    serde_json::to_value(observation)?,
                    json!({"attemptId": attempt["id"], "attemptNumber": 1,
                        "state": attempt["state"],
                        "commandIdKnown": !attempt["commandId"].is_null(),
                        "uncertain": attempt["uncertain"],
                        "cancellationRequested": false, "failure": attempt["failure"]}),
                );
                if observation.state == stop {
                    stopped_at = Some(aws.calls.borrow().len());
                    bail!("reporting interrupted");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "reporting interrupted");
        assert_eq!(Some(aws.calls.borrow().len()), stopped_at);
        assert_eq!(journal(&path)["attempts"][0]["state"], stop);
        assert_eq!(
            aws.call_count("send-command"),
            usize::from(!matches!(stop, "prepared" | "dispatched"))
        );
        let result = run(&aws, &clock, &path);
        if stop == "dispatched" {
            // The durable intent is ambiguous, even though this fixture knows
            // reporting stopped the actual send. Recovery must not invent one.
            assert!(result.is_err());
            assert_eq!(aws.call_count("send-command"), 0);
            assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
        } else {
            assert_eq!(result.unwrap(), json!({"ready": true}));
            assert_eq!(
                aws.call_count("send-command"),
                if stop == "failed" { 2 } else { 1 }
            );
            assert_eq!(
                journal(&path)["attempts"].as_array().unwrap().len(),
                if stop == "failed" { 2 } else { 1 }
            );
        }
    }
}

#[test]
fn delayed_attempt_reporting_cannot_bypass_deadline_or_ownership_guards() {
    for deadline in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        let stopped = Cell::new(false);
        let result = zdn::ssm::execute_with_observer(
            &aws,
            INSTANCE,
            SCRIPT,
            &path,
            30,
            &clock,
            &mut || {
                if !deadline && stopped.get() {
                    bail!("ownership lost");
                }
                Ok(())
            },
            &mut |observation| {
                if observation.state == "dispatched" {
                    stopped.set(true);
                    if deadline {
                        clock.0.set(30);
                    }
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(aws.calls.borrow().is_empty());
        assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
    }
}

#[test]
fn attempt_observer_reports_recovered_identity_cached_results_and_cancellation() {
    for cancel in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        aws.sends.borrow_mut().push_back(Send::LostReply);
        let mut observations = Vec::new();
        let result = zdn::ssm::execute_with_observer(
            &aws,
            INSTANCE,
            SCRIPT,
            &path,
            30,
            &clock,
            &mut || {
                if cancel && aws.call_count("get-command-invocation") > 0 {
                    bail!("cancelled");
                }
                Ok(())
            },
            &mut |observation| {
                observations.push(serde_json::to_value(observation)?);
                Ok(())
            },
        );
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(result.is_err(), cancel);
        let last = observations.last().unwrap();
        assert_eq!(last["commandIdKnown"], true);
        assert_eq!(last["uncertain"], cancel);
        assert_eq!(last["cancellationRequested"], cancel);
        assert_eq!(last["state"], if cancel { "running" } else { "succeeded" });
        assert_eq!(aws.call_count("cancel-command"), usize::from(cancel));
        assert!(observations
            .iter()
            .all(|o| o["attemptId"] == last["attemptId"]));
        if !cancel {
            let calls = aws.calls.borrow().len();
            let mut resumed = Vec::new();
            zdn::ssm::execute_with_observer(
                &aws,
                INSTANCE,
                SCRIPT,
                &path,
                30,
                &clock,
                &mut || Ok(()),
                &mut |o| {
                    resumed.push(serde_json::to_value(o)?);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(resumed, vec![last.clone()]);
            assert_eq!(aws.calls.borrow().len(), calls);
        }
    }
}

#[test]
fn saves_identity_before_dispatch_and_returns_a_cached_success_without_new_aws_calls() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    let result = run(&aws, &clock, &path).unwrap();
    assert_eq!(result, json!({"ready":true}));
    let saved = journal(&path);
    assert_eq!(saved["instanceId"], INSTANCE);
    assert_eq!(saved["attempts"][0]["state"], "succeeded");
    assert_eq!(saved["attempts"][0]["uncertain"], false);
    assert_eq!(saved["attempts"][0]["output"], result);
    assert_eq!(
        saved["attempts"][0]["comment"],
        aws.commands.borrow()[0]["Comment"]
    );
    assert_eq!(saved["requestSha256"].as_str().unwrap().len(), 64);
    assert!(!fs::read_to_string(&path).unwrap().contains(SCRIPT));
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains("private stderr"));
    let calls = aws.calls.borrow().len();
    assert_eq!(run(&aws, &clock, &path).unwrap(), result);
    assert_eq!(aws.calls.borrow().len(), calls);
    assert_eq!(aws.call_count("send-command"), 1);
}

#[test]
fn preparation_is_local_and_preserves_every_existing_attempt_without_retrying() {
    for state in ["prepared", "dispatched", "running", "succeeded", "failed"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        prepare(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
        let first = journal(&path);
        assert_eq!(first["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(first["attempts"][0]["state"], "prepared");
        assert_eq!(first["attempts"][0]["uncertain"], false);
        assert!(first["attempts"][0]["commandId"].is_null());
        assert!(aws.calls.borrow().is_empty());
        if state != "prepared" {
            if state == "failed" {
                aws.polls.borrow_mut().push_back(Poll::Status("Failed"));
            }
            let _ = zdn::ssm::execute_with_observer(
                &aws,
                INSTANCE,
                SCRIPT,
                &path,
                30,
                &clock,
                &mut || Ok(()),
                &mut |observation| {
                    if observation.state == state {
                        bail!("interrupted");
                    }
                    Ok(())
                },
            );
        }
        assert_eq!(journal(&path)["attempts"][0]["state"], state);
        // Even noncanonical JSON bytes must not be rewritten by preparation.
        let bytes = serde_json::to_vec_pretty(&journal(&path)).unwrap();
        fs::write(&path, &bytes).unwrap();
        let calls = aws.calls.borrow().len();
        clock.0.set(10);
        prepare(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes, "{state}");
        assert_eq!(aws.calls.borrow().len(), calls);
        for (instance, script, timeout) in [
            ("i-fffffffffffffffff", SCRIPT, 30),
            (INSTANCE, "another operation", 30),
            (INSTANCE, SCRIPT, 60),
        ] {
            assert!(prepare(instance, script, &path, timeout, &clock).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        if state == "prepared" {
            run(&aws, &clock, &path).unwrap();
            assert_eq!(
                journal(&path)["attempts"][0]["id"],
                first["attempts"][0]["id"]
            );
            assert_eq!(aws.call_count("send-command"), 1);
        }
    }
}

#[test]
fn preparation_rejects_invalid_requests_and_corrupt_journals_without_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let clock = Clock::default();
    for (instance, script, timeout) in [
        ("not-an-instance", SCRIPT, 30),
        (INSTANCE, "", 30),
        (INSTANCE, SCRIPT, 29),
    ] {
        assert!(prepare(instance, script, &path, timeout, &clock).is_err());
        assert!(!path.exists());
    }
    prepare(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
    let mut invalid = journal(&path);
    invalid["attempts"][0]["uncertain"] = json!(true);
    for bytes in [
        serde_json::to_vec(&invalid).unwrap(),
        b"broken journal".to_vec(),
    ] {
        fs::write(&path, &bytes).unwrap();
        assert!(prepare(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn explicit_repeat_preserves_success_and_resumes_its_prepared_or_unknown_attempt() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    run(&aws, &clock, &path).unwrap();
    let first = journal(&path)["attempts"][0].clone();
    prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
    assert_eq!(aws.call_count("send-command"), 1);
    let prepared = journal(&path);
    assert_eq!(prepared["attempts"][0], first);
    assert_eq!(prepared["attempts"][1]["state"], "prepared");
    assert!(prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    // Restart after preparation, then crash after AWS accepts that same attempt.
    aws.sends.borrow_mut().push_back(Send::Crash);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&aws, &clock, &path)))
            .is_err()
    );
    assert!(prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("send-command"), 2);
    let saved = journal(&path);
    assert_eq!(saved["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(saved["attempts"][0], first);
    assert_eq!(saved["attempts"][1]["id"], prepared["attempts"][1]["id"]);
    assert_eq!(saved["attempts"][1]["state"], "succeeded");
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("send-command"), 2);
}

#[test]
fn explicit_repeat_rejects_missing_changed_or_uncertain_commands_without_rewriting() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let clock = Clock::default();
    assert!(prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    assert!(!path.exists());
    let aws = Aws::default();
    run(&aws, &clock, &path).unwrap();
    let before = fs::read(&path).unwrap();
    for (instance, script, timeout) in [
        ("i-fffffffffffffffff", SCRIPT, 30),
        (INSTANCE, "another operation", 30),
        (INSTANCE, SCRIPT, 60),
    ] {
        assert!(prepare_repeat_after_success(instance, script, &path, timeout, &clock).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let mut saved = journal(&path);
    saved["attempts"][0]["state"] = json!("running");
    saved["attempts"][0]["uncertain"] = json!(true);
    saved["attempts"][0]["output"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(aws.call_count("send-command"), 1);
}

#[test]
fn explicit_repeat_keeps_the_attempt_history_bounded() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    run(&aws, &clock, &path).unwrap();
    for _ in 1..32 {
        prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock).unwrap();
        run(&aws, &clock, &path).unwrap();
    }
    let before = fs::read(&path).unwrap();
    assert!(
        prepare_repeat_after_success(INSTANCE, SCRIPT, &path, 30, &clock)
            .unwrap_err()
            .to_string()
            .contains("attempt limit")
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(aws.call_count("send-command"), 32);
}

#[test]
fn lost_or_malformed_send_response_recovers_the_original_command() {
    for mode in [Send::LostReply, Send::Malformed] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        aws.sends.borrow_mut().push_back(mode);
        assert_eq!(
            run(&aws, &Clock::default(), &path).unwrap(),
            json!({"ready":true})
        );
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(aws.call_count("list-commands"), 1);
        assert_eq!(
            journal(&path)["attempts"][0]["commandId"],
            aws.commands.borrow()[0]["CommandId"]
        );
    }
}

#[test]
fn process_restart_recovers_persisted_dispatch_without_sending_again() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    interrupt_after_dispatch(&aws, &clock, &path);
    let id = journal(&path)["attempts"][0]["id"].clone();
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(journal(&path)["attempts"][0]["id"], id);
}

#[test]
fn recovery_checks_all_pages_before_accepting_a_unique_match() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    interrupt_after_dispatch(&aws, &clock, &path);
    let command = aws.commands.borrow()[0].clone();
    aws.pages.borrow_mut().extend([
        Page::Value(json!({"Commands":[command],"NextToken":"second-page"})),
        Page::Value(json!({"Commands":[]})),
    ]);
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("list-commands"), 2);
    let calls = aws.calls.borrow();
    assert_eq!(
        calls
            .iter()
            .filter(|(name, _)| name == "list-commands")
            .nth(1)
            .unwrap()
            .1["NextToken"],
        "second-page"
    );
}

#[test]
fn duplicate_matching_commands_are_not_guessed_or_resent() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    interrupt_after_dispatch(&aws, &clock, &path);
    let original = aws.commands.borrow()[0].clone();
    let mut duplicate = original.clone();
    duplicate["CommandId"] = json!(Uuid::new_v4());
    aws.pages.borrow_mut().extend([
        Page::Value(json!({"Commands":[original],"NextToken":"second"})),
        Page::Value(json!({"Commands":[duplicate]})),
    ]);
    assert!(run(&aws, &clock, &path)
        .unwrap_err()
        .to_string()
        .contains("multiple SSM commands"));
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(aws.call_count("get-command-invocation"), 0);
    assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
}

#[test]
fn same_comment_with_wrong_instance_document_version_or_commands_fails_closed() {
    for (key, value) in [
        ("InstanceIds", json!(["i-fffffffffffffffff"])),
        ("InstanceIds", json!([INSTANCE, "i-fffffffffffffffff"])),
        ("DocumentName", json!("AWS-OtherDocument")),
        ("DocumentVersion", json!("2")),
        ("Parameters", json!({"commands":["echo changed"]})),
        ("Targets", json!([{"Key":"tag:Name","Values":["foreign"]}])),
        ("TimeoutSeconds", json!(31)),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        interrupt_after_dispatch(&aws, &clock, &path);
        aws.commands.borrow_mut()[0][key] = value;
        assert!(run(&aws, &clock, &path).is_err(), "{key}");
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(aws.call_count("get-command-invocation"), 0);
    }
}

#[test]
fn absent_command_stays_uncertain_across_retries_without_blind_resend() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    aws.sends.borrow_mut().push_back(Send::NotAccepted);
    for iteration in 1..=2 {
        let error = run(&aws, &clock, &path).unwrap_err().to_string();
        assert!(error.contains("no command was resent"));
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(aws.call_count("list-commands"), iteration * 6);
        assert_eq!(journal(&path)["attempts"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn transient_recovery_and_invocation_visibility_failures_are_bounded_and_retried() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    aws.sends.borrow_mut().push_back(Send::LostReply);
    aws.pages
        .borrow_mut()
        .push_back(Page::Error("InternalServerError"));
    aws.polls.borrow_mut().extend([
        Poll::Error("InvocationDoesNotExist"),
        Poll::Error("ThrottlingException"),
        Poll::Status("Pending"),
        Poll::Status("Delayed"),
        Poll::Status("InProgress"),
    ]);
    let mut checks = Vec::new();
    execute(&aws, INSTANCE, SCRIPT, &path, 30, &clock, &mut || {
        checks.push(clock.0.get());
        Ok(())
    })
    .unwrap();
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(aws.call_count("list-commands"), 2);
    assert_eq!(aws.call_count("get-command-invocation"), 6);
    assert!(checks.windows(2).all(|times| times[1] - times[0] <= 2));
    assert_eq!(clock.0.get(), 12);
}

#[test]
fn polling_permission_error_preserves_known_command_for_later_resume() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    aws.polls
        .borrow_mut()
        .push_back(Poll::Error("AccessDeniedException"));
    assert!(run(&aws, &clock, &path).is_err());
    assert_eq!(journal(&path)["attempts"][0]["state"], "running");
    assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(aws.call_count("list-commands"), 0);
}

#[test]
fn terminal_failures_preserve_history_before_a_new_explicit_attempt() {
    for status in ["Failed", "Cancelled", "TimedOut"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        aws.polls.borrow_mut().push_back(Poll::Status(status));
        assert!(run(&aws, &clock, &path).is_err());
        let first = journal(&path)["attempts"][0].clone();
        assert_eq!(first["state"], "failed");
        run(&aws, &clock, &path).unwrap();
        let saved = journal(&path);
        assert_eq!(saved["attempts"][0], first);
        assert_eq!(saved["attempts"].as_array().unwrap().len(), 2);
        assert_ne!(
            saved["attempts"][0]["comment"],
            saved["attempts"][1]["comment"]
        );
        assert_eq!(aws.call_count("send-command"), 2);
    }
}

#[test]
fn definitive_send_rejection_can_be_retried_without_marking_it_as_success() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    aws.sends.borrow_mut().push_back(Send::Rejected);
    assert!(run(&aws, &clock, &path).is_err());
    assert_eq!(journal(&path)["attempts"][0]["failure"], "request-rejected");
    assert_eq!(aws.call_count("list-commands"), 0);
    run(&aws, &clock, &path).unwrap();
    assert_eq!(aws.call_count("send-command"), 2);
}

#[test]
fn progress_cancellation_cancels_known_id_and_keeps_uncertain_receipt() {
    for cancel_fails in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        aws.cancel_fails.set(cancel_fails);
        let error = execute(
            &aws,
            INSTANCE,
            SCRIPT,
            &path,
            30,
            &Clock::default(),
            &mut || {
                if aws.call_count("send-command") > 0 {
                    bail!("private cancellation diagnostic");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert_eq!(aws.call_count("cancel-command"), 1);
        assert_eq!(aws.call_count("get-command-invocation"), 0);
        let attempt = &journal(&path)["attempts"][0];
        assert_eq!(attempt["uncertain"], true);
        assert_eq!(attempt["cancellationRequested"], true);
        assert_eq!(attempt["state"], "running");
        assert!(attempt["output"].is_null());
    }
}

#[test]
fn deadline_cancels_remote_work_and_does_not_report_completion() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    aws.always_pending.set(true);
    assert!(run(&aws, &clock, &path)
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert_eq!(clock.0.get(), 30);
    assert_eq!(aws.call_count("send-command"), 1);
    assert_eq!(aws.call_count("cancel-command"), 1);
    assert_eq!(journal(&path)["attempts"][0]["uncertain"], true);
}

#[test]
fn prepared_but_unsent_request_can_resume_safely() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    assert!(
        execute(&aws, INSTANCE, SCRIPT, &path, 30, &clock, &mut || bail!(
            "cancel"
        ))
        .is_err()
    );
    assert!(aws.calls.borrow().is_empty());
    let first = journal(&path)["attempts"][0].clone();
    assert_eq!(first["state"], "prepared");
    run(&aws, &clock, &path).unwrap();
    assert_eq!(journal(&path)["attempts"][0]["id"], first["id"]);
}

#[test]
fn install_execution_timeout_is_preserved_with_bounded_delivery_and_input_limits() {
    let root = tempfile::tempdir().unwrap();
    let aws = Aws::default();
    let clock = Clock::default();
    execute(
        &aws,
        INSTANCE,
        SCRIPT,
        &root.path().join("install.json"),
        5400,
        &clock,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        aws.commands.borrow()[0]["Parameters"]["executionTimeout"],
        json!(["5400"])
    );
    assert_eq!(aws.commands.borrow()[0]["TimeoutSeconds"], 120);
    let calls = aws.calls.borrow().len();
    for (instance, script, timeout) in [
        ("i-$(id)", SCRIPT, 30),
        (INSTANCE, "", 30),
        (INSTANCE, SCRIPT, 29),
        (INSTANCE, SCRIPT, 7201),
    ] {
        assert!(execute(
            &aws,
            instance,
            script,
            &root.path().join("bad.json"),
            timeout,
            &clock,
            &mut || Ok(())
        )
        .is_err());
    }
    assert_eq!(aws.calls.borrow().len(), calls);
}

#[test]
fn mismatched_inputs_and_invalid_invocation_identity_never_produce_success() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    run(&aws, &clock, &path).unwrap();
    let calls = aws.calls.borrow().len();
    for (instance, script, timeout) in [
        ("i-fffffffffffffffff", SCRIPT, 30),
        (INSTANCE, "echo different", 30),
        (INSTANCE, SCRIPT, 31),
    ] {
        assert!(
            execute(&aws, instance, script, &path, timeout, &clock, &mut || Ok(
                ()
            ))
            .is_err()
        );
    }
    assert_eq!(aws.calls.borrow().len(), calls);
    let other = root.path().join("wrong-invocation.json");
    aws.polls.borrow_mut().push_back(Poll::WrongInstance);
    assert!(run(&aws, &clock, &other).is_err());
    assert!(journal(&other)["attempts"][0]["output"].is_null());
}

#[test]
fn malformed_large_or_non_object_output_and_bad_response_code_fail_without_raw_logs() {
    for text in [
        "private output must not escape".into(),
        "[]".into(),
        "{} {}".into(),
        format!("{{\"data\":\"{}\"}}", "x".repeat(20 * 1024)),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        aws.polls.borrow_mut().push_back(Poll::Text(text));
        let error = run(&aws, &Clock::default(), &path).unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert!(!fs::read_to_string(&path).unwrap().contains("private"));
        assert_eq!(journal(&path)["attempts"][0]["failure"], "invalid-output");
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    aws.polls.borrow_mut().push_back(Poll::Code(1));
    assert!(run(&aws, &Clock::default(), &path).is_err());
    assert_eq!(journal(&path)["attempts"][0]["failure"], "response-code");
}

#[test]
fn repeated_or_excess_recovery_pages_stop_without_dispatch() {
    for excessive in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("command.json");
        let aws = Aws::default();
        let clock = Clock::default();
        interrupt_after_dispatch(&aws, &clock, &path);
        for index in 0..20 {
            let token = if excessive {
                format!("page-{index}")
            } else {
                "same-page".into()
            };
            aws.pages
                .borrow_mut()
                .push_back(Page::Value(json!({"Commands":[],"NextToken":token})));
        }
        assert!(run(&aws, &clock, &path).is_err());
        assert_eq!(aws.call_count("send-command"), 1);
        assert_eq!(
            aws.call_count("list-commands"),
            if excessive { 20 } else { 2 }
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinks_insecure_receipts_and_concurrent_journal_users_are_refused() {
    use fs2::FileExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("command.json");
    let aws = Aws::default();
    let clock = Clock::default();
    run(&aws, &clock, &path).unwrap();
    let calls = aws.calls.borrow().len();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(run(&aws, &clock, &path).is_err());
    assert!(prepare(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.path().join("alias.json");
    symlink(&path, &alias).unwrap();
    assert!(run(&aws, &clock, &alias).is_err());
    assert!(prepare(INSTANCE, SCRIPT, &alias, 30, &clock).is_err());
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join("command.json.lock"))
        .unwrap();
    FileExt::try_lock_exclusive(&lock).unwrap();
    assert!(run(&aws, &clock, &path).is_err());
    assert!(prepare(INSTANCE, SCRIPT, &path, 30, &clock).is_err());
    assert_eq!(aws.calls.borrow().len(), calls);
}
