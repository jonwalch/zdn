//! Opt-in local-command protocol. Never wrap credentials or infer cloud retry safety.

use clap::ValueEnum;
use eyre::Result;
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Write},
    path::Path,
};
use zdn::state::{OperationInput, OperationReceipt, PhaseStatus, ResumeAction};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Preserve the existing command-specific output.
    #[default]
    Human,
    /// One versioned terminal record on stdout.
    Json,
    /// Versioned progress and terminal records, one per line.
    Jsonl,
}

impl Format {
    pub fn machine(self) -> bool {
        self != Self::Human
    }
}

/// Recover only the root format option for clap failures. Stop at the command
/// boundary so a flag-looking command argument or child argument cannot opt in.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli_output.requested_format")
)]
pub fn requested_format(arguments: &[OsString]) -> Format {
    let mut arguments = arguments.iter().skip(1);
    while let Some(argument) = arguments.next() {
        let Some(argument) = argument.to_str() else {
            break;
        };
        if argument == "--progress-file" {
            arguments.next();
            continue;
        }
        let value = if argument == "--format" {
            arguments.next().and_then(|value| value.to_str())
        } else if let Some(value) = argument.strip_prefix("--format=") {
            Some(value)
        } else if argument.starts_with('-') && argument != "--" && argument != "-" {
            // An invalid root option must not hide a later format selection.
            continue;
        } else {
            break;
        };
        return match value {
            Some("json") => Format::Json,
            Some("jsonl") => Format::Jsonl,
            _ => Format::Human,
        };
    }
    Format::Human
}

pub fn event(command: Option<&str>, kind: &str, outcome: &str, data: Value) -> Value {
    json!({
        "apiVersion": "zdn-cli/v1alpha1",
        "type": kind,
        "command": command,
        "outcome": outcome,
        "networkId": null,
        "operationId": null,
        "data": data,
        "error": null
    })
}

pub fn failure(command: Option<&str>, code: &str, message: &str) -> Value {
    let mut record = event(command, "result", "failed", Value::Null);
    record["error"] = json!({
        "code": code,
        "message": message,
        "retryClassification": "blocked"
    });
    record
}

/// Live execution output owns only protocol state, never mutation authorization.
pub struct OperationOutput {
    pub format: Format,
    pub network_id: Option<uuid::Uuid>,
    command: &'static str,
    saved: Option<OperationReceipt>,
    build: Option<zdn::build_job::BuildObservation>,
    update: Option<Value>,
    ssm: Option<zdn::ssm::CommandObservation>,
    progress_file: Option<File>,
}

impl OperationOutput {
    pub fn new(format: Format, command: &'static str) -> Self {
        Self {
            format,
            network_id: None,
            command,
            saved: None,
            build: None,
            update: None,
            ssm: None,
            progress_file: None,
        }
    }

    pub fn set_progress_file(&mut self, path: &Path) -> Result<()> {
        self.progress_file = Some(create_event_file(path)?);
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.write_file")
    )]
    pub fn write_file(&mut self, record: &Value) -> Result<()> {
        if let Some(file) = &mut self.progress_file {
            serde_json::to_writer(&mut *file, record)?;
            writeln!(file)?;
            file.flush()?;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.progress")
    )]
    pub fn progress(&mut self, record: &Value) -> Result<()> {
        if self.format == Format::Jsonl {
            write(self.format, record)?;
        }
        self.write_file(record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.observe")
    )]
    pub fn observe(&mut self, saved: &OperationReceipt, name: Option<&str>) -> Result<()> {
        // Retain identity even if the output stream breaks after a durable write.
        self.network_id = Some(saved.network_id);
        self.saved = Some(saved.clone());
        if self.format != Format::Jsonl && self.progress_file.is_none() {
            return Ok(());
        }
        let report = receipt(saved, None)?;
        let (kind, outcome, data) = if let Some(name) = name {
            let phase = report["phases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|phase| phase["name"] == name)
                .unwrap();
            let status = phase["status"].as_str().unwrap();
            (
                if status == "running" {
                    "phase-started"
                } else {
                    "phase-result"
                },
                status,
                json!({"phase": phase, "revision": saved.revision,
                    "stateRevision": saved.state_revision, "cancelRequested": saved.cancel_requested}),
            )
        } else {
            ("operation-started", "running", report.clone())
        };
        let mut record = event(Some(self.command), kind, outcome, data);
        record["networkId"] = json!(saved.network_id);
        record["operationId"] = json!(saved.operation_id);
        self.progress(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.observe_build")
    )]
    pub fn observe_build(&mut self, build: &zdn::build_job::BuildObservation) -> Result<()> {
        // Retain the durable attempt even when reporting itself fails.
        self.build = Some(build.clone());
        let mut record = event(
            Some(self.command),
            "build-observed",
            "observed",
            json!(build),
        );
        record["networkId"] = json!(self.network_id);
        record["operationId"] = json!(self.saved.as_ref().map(|saved| saved.operation_id));
        self.progress(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.observe_update")
    )]
    pub fn observe_update(&mut self, id: uuid::Uuid) -> Result<()> {
        self.update = Some(json!({"updateId": id}));
        let mut record = event(
            Some(self.command),
            "update-prepared",
            "observed",
            json!({"updateId": id}),
        );
        record["networkId"] = json!(self.network_id);
        self.progress(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.observe_update_progress")
    )]
    pub fn observe_update_progress(
        &mut self,
        intent: &zdn::update::UpdateIntent,
        node: Option<&str>,
    ) -> Result<()> {
        let data = json!({"updateId": intent.id, "node": node,
            "completedNodes": intent.completed, "finished": intent.finished});
        self.update = Some(data.clone());
        let mut record = event(Some(self.command), "update-observed", "observed", data);
        record["networkId"] = json!(self.network_id);
        record["operationId"] = json!(self.saved.as_ref().map(|saved| saved.operation_id));
        self.progress(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.observe_command")
    )]
    pub fn observe_command(&mut self, command: &zdn::ssm::CommandObservation) -> Result<()> {
        self.ssm = Some(command.clone());
        let mut record = event(
            Some(self.command),
            "ssm-observed",
            "observed",
            json!(command),
        );
        record["networkId"] = json!(self.network_id);
        record["operationId"] = json!(self.saved.as_ref().map(|saved| saved.operation_id));
        self.progress(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cli_output.finish")
    )]
    pub fn finish(&self, mut record: Value) -> Result<Value> {
        record["networkId"] = json!(self.network_id);
        if let Some(saved) = &self.saved {
            record["operationId"] = json!(saved.operation_id);
            if !record["error"].is_null() {
                let report = receipt(saved, None)?;
                record["error"]["retryClassification"] = report["retryClassification"].clone();
                if record["data"].is_null() {
                    record["data"] = json!({});
                }
                record["data"]["savedReceipt"] = report;
            }
        }
        if let Some(build) = &self.build {
            if record["data"].is_null() {
                record["data"] = json!({});
            }
            record["data"]["build"] = json!(build);
            if !record["error"].is_null()
                && self.saved.is_none()
                && build.submission_recorded
                && matches!(build.job_outcome, None | Some("unknown"))
            {
                record["error"]["retryClassification"] = json!("reconcile-required");
            }
        }
        if let Some(update) = &self.update {
            if record["data"].is_null() {
                record["data"] = json!({});
            }
            record["data"]["updateId"] = update["updateId"].clone();
            record["data"]["update"] = update.clone();
        }
        if let Some(ssm) = &self.ssm {
            if record["data"].is_null() {
                record["data"] = json!({});
            }
            record["data"]["ssm"] = json!(ssm);
        }
        Ok(record)
    }
}

/// Publish only a new private file, never truncate or follow an existing final symlink.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli_output.create_event_file")
)]
pub fn create_event_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        eyre::bail!("private event files currently require macOS or Linux")
    }
}

/// Report a single durable snapshot, excluding arbitrary diagnostics and results.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli_output.receipt")
)]
pub fn receipt(
    receipt: &OperationReceipt,
    expected_inputs: Option<&OperationInput>,
) -> Result<Value> {
    let plan = receipt.resume_plan(expected_inputs.unwrap_or(&receipt.inputs))?;
    let inputs_verified = expected_inputs.is_some();
    let classifications: Vec<_> = plan
        .phases
        .iter()
        .enumerate()
        .map(|(index, phase)| match phase.action {
            ResumeAction::ReconcileSuccess | ResumeAction::ReconcileOutcome => "reconcile-required",
            ResumeAction::StopCancelled => "cancelled",
            ResumeAction::Run | ResumeAction::Retry
                if receipt.phases[index + 1..]
                    .iter()
                    .any(|later| !matches!(later.status, PhaseStatus::Pending)) =>
            {
                "reconcile-required"
            }
            ResumeAction::Run | ResumeAction::Retry if inputs_verified => "safe-to-retry",
            _ => "blocked",
        })
        .collect();
    // Outstanding effects take precedence over cancellation intent and later retries.
    let classification = ["reconcile-required", "cancelled", "blocked"]
        .into_iter()
        .find(|value| classifications.contains(value))
        .unwrap_or("safe-to-retry");
    let phases: Vec<_> = receipt.phases.iter().zip(&plan.phases)
        .zip(&classifications).enumerate()
        .map(|(index, ((phase, decision), classification))| {
            let status = match phase.status {
                PhaseStatus::Pending => "pending",
                PhaseStatus::Running { .. } => "running",
                PhaseStatus::Succeeded { .. } => "succeeded",
                PhaseStatus::Failed { .. } => "failed",
                PhaseStatus::Unknown { .. } => "unknown",
                PhaseStatus::Cancelled => "cancelled",
            };
            json!({"name": phase.name, "status": status, "resumeAction": decision.action,
                "retryClassification": classification, "requiresEarlierPhaseVerification": index > 0})
        }).collect();
    Ok(json!({
        "operationId": receipt.operation_id, "networkId": receipt.network_id,
        "scope": receipt.scope, "kind": receipt.kind,
        "revision": receipt.revision, "stateRevision": receipt.state_revision,
        "cancelRequested": receipt.cancel_requested, "inputsVerified": inputs_verified,
        "retryClassification": classification, "phases": phases,
        "liveStateChecked": false, "executionAuthorized": false
    }))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli_output.write")
)]
pub fn write(format: Format, value: &Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    if format == Format::Jsonl {
        serde_json::to_writer(&mut stdout, value)?;
    } else {
        serde_json::to_writer_pretty(&mut stdout, value)?;
    }
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zdn::state::{OperationInput, PhaseRecord, Scope};

    #[test]
    fn operation_results_keep_identity_and_classify_durable_failures_without_raw_diagnostics() {
        let diagnostic = "fixture-diagnostic-not-for-export";
        for (status, classification) in [
            (
                PhaseStatus::Failed {
                    message: diagnostic.into(),
                    retry_safe: true,
                },
                "blocked",
            ),
            (
                PhaseStatus::Running {
                    external_ref: Some(diagnostic.into()),
                },
                "reconcile-required",
            ),
            (
                PhaseStatus::Unknown {
                    message: diagnostic.into(),
                    external_ref: Some(diagnostic.into()),
                },
                "reconcile-required",
            ),
            (
                PhaseStatus::Succeeded {
                    result: json!({"untrusted": diagnostic}),
                },
                "reconcile-required",
            ),
            (PhaseStatus::Cancelled, "cancelled"),
        ] {
            let saved = OperationReceipt {
                version: 1,
                operation_id: uuid::Uuid::new_v4(),
                network_id: uuid::Uuid::new_v4(),
                scope: Scope {
                    team_id: "fixture".into(),
                    account_id: "123456789012".into(),
                    region: "us-east-1".into(),
                },
                kind: "foundation-up".into(),
                inputs: OperationInput {
                    config_sha256: "a".repeat(64),
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                revision: 1,
                state_revision: 1,
                cancel_requested: false,
                phases: vec![PhaseRecord {
                    name: "apply".into(),
                    status,
                }],
            };
            saved.validate().unwrap();
            let mut output = OperationOutput::new(Format::Json, "foundation up");
            #[cfg(unix)]
            let progress = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            output
                .set_progress_file(&progress.path().join("events.jsonl"))
                .unwrap();
            let build = zdn::build_job::BuildObservation {
                attempt_id: uuid::Uuid::new_v4(),
                contract_sha256: "b".repeat(64),
                exporter_helper: None,
                source_uploaded: true,
                submission_recorded: true,
                build_id_known: true,
                reused_from: None,
                job_outcome: None,
                image_verified: false,
            };
            output.observe_build(&build).unwrap();
            output.observe(&saved, Some("apply")).unwrap();
            output.observe_build(&build).unwrap();
            let mut command = zdn::ssm::CommandObservation {
                attempt_id: uuid::Uuid::new_v4(),
                attempt_number: 2,
                state: "running",
                command_id_known: true,
                uncertain: true,
                cancellation_requested: false,
                failure: None,
            };
            output.observe_command(&command).unwrap();
            #[cfg(unix)]
            {
                let records: Vec<Value> =
                    std::fs::read_to_string(progress.path().join("events.jsonl"))
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect();
                assert!(records[0]["operationId"].is_null());
                assert_eq!(records[2]["type"], "build-observed");
                assert_eq!(records[2]["operationId"], saved.operation_id.to_string());
                assert_eq!(
                    records.last().unwrap()["operationId"],
                    saved.operation_id.to_string()
                );
                assert_eq!(records.last().unwrap()["type"], "ssm-observed");
                assert_eq!(
                    records.last().unwrap()["networkId"],
                    saved.network_id.to_string()
                );
                assert_eq!(records.last().unwrap()["data"], json!(command));
                output.progress_file =
                    Some(File::open(progress.path().join("events.jsonl")).unwrap());
            }
            // Keep the newest durable state even when writing it fails.
            command.cancellation_requested = true;
            #[cfg(unix)]
            assert!(output.observe_command(&command).is_err());
            #[cfg(not(unix))]
            output.observe_command(&command).unwrap();
            let mut failure = failure(
                Some("foundation up"),
                "foundation-up-failed",
                "Apply failed.",
            );
            let mismatch = json!(zdn::immutable_inputs::ImmutableInputReport::config_fingerprint());
            failure["data"] = json!({"immutableInputs":mismatch});
            let failed = output.finish(failure).unwrap();
            assert_eq!(failed["networkId"], saved.network_id.to_string());
            assert_eq!(failed["operationId"], saved.operation_id.to_string());
            assert_eq!(failed["error"]["retryClassification"], classification);
            assert_eq!(failed["data"]["savedReceipt"]["revision"], 1);
            assert_eq!(failed["data"]["immutableInputs"], mismatch);
            assert_eq!(failed["data"]["ssm"], json!(command));
            assert_eq!(
                failed["data"]["build"]["attemptId"],
                build.attempt_id.to_string()
            );
            assert!(!failed.to_string().contains(diagnostic));
            let success = output
                .finish(event(
                    Some("foundation up"),
                    "result",
                    "succeeded",
                    json!({"ready": true}),
                ))
                .unwrap();
            assert_eq!(
                success["data"],
                json!({"ready": true, "build": build, "ssm": command})
            );
            assert_eq!(success["operationId"], saved.operation_id.to_string());
        }
    }
}
