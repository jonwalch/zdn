use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use uuid::Uuid;
use zdn::state::{
    Binding, BindingContext, OperationInput, PhaseStatus, ResumeAction, Scope, StateStore,
};

fn inputs() -> OperationInput {
    OperationInput {
        config_sha256: "a".repeat(64),
        source_manifest_sha256: Some("b".repeat(64)),
        archive_sha256: Some("c".repeat(64)),
    }
}

fn fixture() -> (TempDir, StateStore, Binding) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    let config = source.join("devnet.yaml");
    fs::write(&config, "name: feature\n").unwrap();
    let context = BindingContext::new(
        &config,
        None,
        None,
        Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
    )
    .unwrap();
    let store = StateStore::open(temp.path().join("state")).unwrap();
    let binding = store.bind(&context, "feature").unwrap();
    (temp, store, binding)
}

fn running() -> PhaseStatus {
    PhaseStatus::Running { external_ref: None }
}

fn succeeded() -> PhaseStatus {
    PhaseStatus::Succeeded {
        result: serde_json::json!({"local_result": "fixture-only"}),
    }
}

#[test]
fn effect_outcome_merges_only_cancellation_and_never_starts_work() {
    let (_temp, store, binding) = fixture();
    let initial = store
        .begin_operation(&binding, "apply", inputs(), &["apply", "ready"])
        .unwrap();
    let id = initial.operation_id;
    let started = store
        .record_phase(id, initial.revision, "apply", running())
        .unwrap();
    let cancelled = store.request_cancel(id, started.revision).unwrap();
    // Repeated requests are harmless, but both cancellation revisions must survive.
    let cancelled = store.request_cancel(id, cancelled.revision).unwrap();
    assert!(store
        .record_phase_outcome(&started, "apply", running())
        .is_err());
    let finished = store
        .record_phase_outcome(&started, "apply", succeeded())
        .unwrap();
    assert!(finished.cancel_requested);
    assert_eq!(finished.revision, cancelled.revision + 1);
    assert_eq!(finished.phases[0].status, succeeded());
    assert!(store
        .record_phase(id, finished.revision, "ready", running())
        .is_err());
    assert!(store
        .record_phase_outcome(
            &started,
            "apply",
            PhaseStatus::Unknown {
                message: "stale result".into(),
                external_ref: None,
            }
        )
        .is_err());
    assert_eq!(store.operation(id).unwrap(), finished);

    let initial = store
        .begin_operation(&binding, "apply", inputs(), &["apply"])
        .unwrap();
    let id = initial.operation_id;
    let started = store
        .record_phase(id, initial.revision, "apply", running())
        .unwrap();
    let reconciled = store
        .reconcile_phase(
            id,
            started.revision,
            "apply",
            PhaseStatus::Unknown {
                message: "another observer recorded uncertainty".into(),
                external_ref: None,
            },
        )
        .unwrap();
    let cancelled = store.request_cancel(id, reconciled.revision).unwrap();
    assert!(store
        .record_phase_outcome(&started, "apply", succeeded())
        .is_err());
    assert_eq!(store.operation(id).unwrap(), cancelled);
}

#[test]
fn restarted_effect_rejects_the_original_attempt_even_after_cancellation() {
    for cancel in [false, true] {
        let (_temp, store, binding) = fixture();
        let initial = store
            .begin_operation(&binding, "apply", inputs(), &["apply"])
            .unwrap();
        let original = store
            .record_phase(initial.operation_id, initial.revision, "apply", running())
            .unwrap();
        let checked = store
            .reconcile_phase(
                original.operation_id,
                original.revision,
                "apply",
                PhaseStatus::Failed {
                    message: "checked; safe to retry".into(),
                    retry_safe: true,
                },
            )
            .unwrap();
        let restarted = store
            .record_phase(checked.operation_id, checked.revision, "apply", running())
            .unwrap();
        let current = if cancel {
            store
                .request_cancel(restarted.operation_id, restarted.revision)
                .unwrap()
        } else {
            restarted.clone()
        };
        assert!(store
            .record_phase_outcome(&original, "apply", succeeded())
            .is_err());
        assert_eq!(store.operation(original.operation_id).unwrap(), current);
        let finished = store
            .record_phase_outcome(&restarted, "apply", succeeded())
            .unwrap();
        assert_eq!(finished.cancel_requested, cancel);
    }
}

#[test]
fn legacy_receipts_gain_state_revision_before_a_restart() {
    let (temp, store, binding) = fixture();
    let initial = store
        .begin_operation(&binding, "apply", inputs(), &["apply"])
        .unwrap();
    let original = store
        .record_phase(initial.operation_id, initial.revision, "apply", running())
        .unwrap();
    let path = temp.path().join("state/state.json");
    let mut ledger: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    ledger["operations"][0]
        .as_object_mut()
        .unwrap()
        .remove("state_revision");
    fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let legacy = store.operation(original.operation_id).unwrap();
    assert_eq!(legacy.state_revision, 0);
    let checked = store
        .reconcile_phase(
            legacy.operation_id,
            legacy.revision,
            "apply",
            PhaseStatus::Failed {
                message: "checked".into(),
                retry_safe: true,
            },
        )
        .unwrap();
    let restarted = store
        .record_phase(checked.operation_id, checked.revision, "apply", running())
        .unwrap();
    assert_eq!(restarted.state_revision, 2);
    assert!(store
        .record_phase_outcome(&legacy, "apply", succeeded())
        .is_err());
    assert_eq!(store.operation(legacy.operation_id).unwrap(), restarted);
}

#[test]
fn saved_inputs_are_immutable_and_resume_requires_all_original_hashes() {
    let (_temp, store, binding) = fixture();
    let receipt = store
        .begin_operation(&binding, "prepare", inputs(), &["capture", "inspect"])
        .unwrap();
    assert_eq!(receipt.inputs, inputs());
    assert_eq!(
        store
            .resume(receipt.operation_id, &inputs())
            .unwrap()
            .phases[0]
            .action,
        ResumeAction::Run
    );
    for (field, reported) in [
        ("config", "configSha256"),
        ("manifest", "sourceManifestSha256"),
        ("archive", "archiveSha256"),
    ] {
        let mut changed = inputs();
        match field {
            "config" => changed.config_sha256 = "d".repeat(64),
            "manifest" => changed.source_manifest_sha256 = Some("d".repeat(64)),
            "archive" => changed.archive_sha256 = Some("d".repeat(64)),
            _ => unreachable!(),
        }
        let error = store
            .resume(receipt.operation_id, &changed)
            .unwrap_err()
            .wrap_err("outer reporting boundary");
        assert!(format!("{error:#}").contains("original inputs"));
        let mismatch = error
            .downcast_ref::<zdn::immutable_inputs::ImmutableInputError>()
            .unwrap();
        let report = serde_json::to_value(&mismatch.report).unwrap();
        assert_eq!(
            report["changedFields"],
            serde_json::json!([
                {"field": reported, "changeKind": "modified"}
            ])
        );
        assert_eq!(report["immutable"], true);
        assert_eq!(report["executionAuthorized"], false);
        assert_eq!(report["liveStateChecked"], false);
        assert!(report["guidance"]
            .as_str()
            .unwrap()
            .contains("Restore the original inputs"));
        assert!(report["guidance"]
            .as_str()
            .unwrap()
            .contains("separate new deployment"));
        assert!(!format!("{mismatch:?}").contains(&"d".repeat(64)));
    }
    // Paired optional hashes can disappear or reappear without changing validation.
    let image_only = OperationInput {
        config_sha256: inputs().config_sha256,
        source_manifest_sha256: None,
        archive_sha256: None,
    };
    for (saved, candidate, kind) in [
        (inputs(), image_only.clone(), "removed"),
        (image_only, inputs(), "added"),
    ] {
        let mut snapshot = receipt.clone();
        snapshot.inputs = saved;
        let error = snapshot.resume_plan(&candidate).unwrap_err();
        let mismatch = error
            .downcast_ref::<zdn::immutable_inputs::ImmutableInputError>()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&mismatch.report).unwrap()["changedFields"],
            serde_json::json!([
                {"field": "archiveSha256", "changeKind": kind},
                {"field": "sourceManifestSha256", "changeKind": kind}
            ])
        );
    }
    assert_eq!(
        store.operation(receipt.operation_id).unwrap().inputs,
        inputs()
    );
    let mut incomplete = inputs();
    incomplete.archive_sha256 = None;
    assert!(store
        .begin_operation(&binding, "prepare", incomplete, &["capture"])
        .is_err());
    assert!(store
        .begin_operation(&binding, "prepare", inputs(), &["capture", "capture"])
        .is_err());
}

#[test]
fn uncertain_outcomes_and_saved_success_require_reconciliation_before_retry_or_skip() {
    let (_temp, store, binding) = fixture();
    let receipt = store
        .begin_operation(&binding, "prepare", inputs(), &["capture", "inspect"])
        .unwrap();
    let id = receipt.operation_id;
    assert!(store.record_phase(id, 0, "inspect", running()).is_err());
    let running_receipt = store.record_phase(id, 0, "capture", running()).unwrap();
    assert_eq!(
        store.resume(id, &inputs()).unwrap().phases[0].action,
        ResumeAction::ReconcileOutcome
    );
    let unknown = store
        .record_phase(
            id,
            running_receipt.revision,
            "capture",
            PhaseStatus::Unknown {
                message: "process ended before the response was saved".into(),
                external_ref: Some("fixture-job".into()),
            },
        )
        .unwrap();
    assert!(store
        .record_phase(id, unknown.revision, "capture", running())
        .is_err());
    assert!(store
        .record_phase(id, unknown.revision, "capture", succeeded())
        .is_err());
    assert_eq!(
        store.resume(id, &inputs()).unwrap().phases[0].action,
        ResumeAction::ReconcileOutcome
    );
    let checked = store
        .reconcile_phase(id, unknown.revision, "capture", succeeded())
        .unwrap();
    assert_eq!(
        store.resume(id, &inputs()).unwrap().phases[0].action,
        ResumeAction::ReconcileSuccess
    );
    assert!(store
        .record_phase(id, checked.revision, "capture", running())
        .is_err());
    store
        .record_phase(id, checked.revision, "inspect", running())
        .unwrap();
}

#[test]
fn reconciliation_cannot_grant_an_earlier_retry_after_a_later_phase_started() {
    let (_temp, store, binding) = fixture();
    for later_status in [
        running(),
        succeeded(),
        PhaseStatus::Failed {
            message: "known failure".into(),
            retry_safe: true,
        },
        PhaseStatus::Failed {
            message: "uncertain failure".into(),
            retry_safe: false,
        },
        PhaseStatus::Unknown {
            message: "lost response".into(),
            external_ref: Some("fixture-job".into()),
        },
        PhaseStatus::Cancelled,
    ] {
        let mut receipt = store
            .begin_operation(
                &binding,
                "prepare",
                inputs(),
                &["capture", "inspect", "publish"],
            )
            .unwrap();
        for status in [running(), succeeded()] {
            receipt = store
                .record_phase(receipt.operation_id, receipt.revision, "capture", status)
                .unwrap();
        }
        receipt = store
            .record_phase(receipt.operation_id, receipt.revision, "inspect", running())
            .unwrap();
        if later_status != running() {
            receipt = store
                .reconcile_phase(
                    receipt.operation_id,
                    receipt.revision,
                    "inspect",
                    later_status.clone(),
                )
                .unwrap();
        }
        let before = fs::read(store.root().join("state.json")).unwrap();
        let error = store
            .reconcile_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                PhaseStatus::Failed {
                    message: "prerequisite disappeared".into(),
                    retry_safe: true,
                },
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("later phase has already started or finished"),
            "{later_status:?}: {error}"
        );
        assert_eq!(fs::read(store.root().join("state.json")).unwrap(), before);
        assert_eq!(store.operation(receipt.operation_id).unwrap(), receipt);

        // Rechecking success remains valid during a downstream effect, as does
        // recording uncertainty without authorizing a concurrent prerequisite retry.
        receipt = store
            .reconcile_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                succeeded(),
            )
            .unwrap();
        receipt = store
            .reconcile_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                PhaseStatus::Unknown {
                    message: "prerequisite no longer observed".into(),
                    external_ref: None,
                },
            )
            .unwrap();
        assert!(store
            .reconcile_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                PhaseStatus::Failed {
                    message: "retry requested".into(),
                    retry_safe: true,
                }
            )
            .is_err());
        store
            .request_cancel(receipt.operation_id, receipt.revision)
            .unwrap();
    }
}

#[test]
fn starting_a_phase_rechecks_later_attempts_in_existing_receipts() {
    let (_temp, store, binding) = fixture();
    let receipt = store
        .begin_operation(
            &binding,
            "prepare",
            inputs(),
            &["capture", "inspect", "publish"],
        )
        .unwrap();
    let path = store.root().join("state.json");
    let original = fs::read(&path).unwrap();
    // An old version could save this ordering. Keep the receipt inspectable and
    // cancellable, but never start the retry described by those old bytes.
    for earlier in [
        PhaseStatus::Pending,
        PhaseStatus::Failed {
            message: "old retry-safe decision".into(),
            retry_safe: true,
        },
    ] {
        let mut ledger: serde_json::Value = serde_json::from_slice(&original).unwrap();
        ledger["operations"][0]["phases"][0]["status"] = serde_json::to_value(earlier).unwrap();
        ledger["operations"][0]["phases"][2]["status"] = serde_json::to_value(running()).unwrap();
        let before = serde_json::to_vec(&ledger).unwrap();
        fs::write(&path, &before).unwrap();
        store.operation(receipt.operation_id).unwrap();
        assert!(store
            .record_phase(receipt.operation_id, receipt.revision, "capture", running())
            .unwrap_err()
            .to_string()
            .contains("later phase"));
        assert_eq!(fs::read(&path).unwrap(), before);
        store
            .request_cancel(receipt.operation_id, receipt.revision)
            .unwrap();
    }
}

#[test]
fn an_earlier_phase_can_retry_while_all_later_phases_are_pending() {
    let (_temp, store, binding) = fixture();
    for checked_before_retry in [
        succeeded(),
        PhaseStatus::Unknown {
            message: "lost response".into(),
            external_ref: None,
        },
    ] {
        let mut receipt = store
            .begin_operation(&binding, "prepare", inputs(), &["capture", "inspect"])
            .unwrap();
        receipt = store
            .record_phase(receipt.operation_id, receipt.revision, "capture", running())
            .unwrap();
        receipt = store
            .record_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                checked_before_retry,
            )
            .unwrap();
        receipt = store
            .reconcile_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                PhaseStatus::Failed {
                    message: "checked absent".into(),
                    retry_safe: true,
                },
            )
            .unwrap();
        receipt = store
            .record_phase(receipt.operation_id, receipt.revision, "capture", running())
            .unwrap();
        receipt = store
            .record_phase(
                receipt.operation_id,
                receipt.revision,
                "capture",
                succeeded(),
            )
            .unwrap();
        store
            .record_phase(receipt.operation_id, receipt.revision, "inspect", running())
            .unwrap();
    }
}

#[test]
fn retry_safety_is_explicit_and_cancellation_does_not_claim_remote_work_stopped() {
    let (_temp, store, binding) = fixture();
    for retry_safe in [false, true] {
        let receipt = store
            .begin_operation(&binding, "prepare", inputs(), &["capture", "inspect"])
            .unwrap();
        let started = store
            .record_phase(receipt.operation_id, 0, "capture", running())
            .unwrap();
        let failed = store
            .record_phase(
                receipt.operation_id,
                started.revision,
                "capture",
                PhaseStatus::Failed {
                    message: "fixture failure".into(),
                    retry_safe,
                },
            )
            .unwrap();
        let action = store
            .resume(receipt.operation_id, &inputs())
            .unwrap()
            .phases[0]
            .action
            .clone();
        assert_eq!(
            action,
            if retry_safe {
                ResumeAction::Retry
            } else {
                ResumeAction::ReconcileOutcome
            }
        );
        let cancelled = store
            .request_cancel(receipt.operation_id, failed.revision)
            .unwrap();
        let plan = store.resume(receipt.operation_id, &inputs()).unwrap();
        assert!(plan.cancel_requested);
        assert_eq!(
            plan.phases[0].action,
            if retry_safe {
                ResumeAction::StopCancelled
            } else {
                ResumeAction::ReconcileOutcome
            }
        );
        assert_eq!(plan.phases[1].action, ResumeAction::StopCancelled);
        assert!(store
            .record_phase(
                receipt.operation_id,
                cancelled.revision,
                "capture",
                running()
            )
            .is_err());
    }
    let receipt = store
        .begin_operation(&binding, "prepare", inputs(), &["capture"])
        .unwrap();
    let started = store
        .record_phase(receipt.operation_id, 0, "capture", running())
        .unwrap();
    store
        .request_cancel(receipt.operation_id, started.revision)
        .unwrap();
    assert_eq!(
        store
            .resume(receipt.operation_id, &inputs())
            .unwrap()
            .phases[0]
            .action,
        ResumeAction::ReconcileOutcome
    );
}

#[test]
fn stale_writers_and_invalid_transitions_cannot_replace_a_durable_receipt() {
    let (_temp, store, binding) = fixture();
    let receipt = store
        .begin_operation(&binding, "prepare", inputs(), &["capture"])
        .unwrap();
    let started = store
        .record_phase(receipt.operation_id, receipt.revision, "capture", running())
        .unwrap();
    let durable_bytes = fs::read(store.root().join("state.json")).unwrap();
    assert!(store
        .record_phase(
            receipt.operation_id,
            receipt.revision,
            "capture",
            succeeded()
        )
        .unwrap_err()
        .to_string()
        .contains("stale"));
    assert!(store
        .record_phase(
            receipt.operation_id,
            started.revision,
            "capture",
            PhaseStatus::Pending
        )
        .is_err());
    assert_eq!(
        fs::read(store.root().join("state.json")).unwrap(),
        durable_bytes
    );
    assert_eq!(store.operation(receipt.operation_id).unwrap(), started);
}

#[test]
fn incompatible_receipt_versions_and_forged_input_hashes_fail_closed() {
    let (_temp, store, binding) = fixture();
    let receipt = store
        .begin_operation(&binding, "prepare", inputs(), &["capture"])
        .unwrap();
    let path = store.root().join("state.json");
    let original = fs::read(&path).unwrap();
    for field in ["version", "hash"] {
        let mut state: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match field {
            "version" => state["operations"][0]["version"] = serde_json::json!(2),
            "hash" => {
                state["operations"][0]["inputs"]["config_sha256"] = serde_json::json!("not-a-hash")
            }
            _ => unreachable!(),
        }
        let corrupted = serde_json::to_vec(&state).unwrap();
        fs::write(&path, &corrupted).unwrap();
        assert!(store.operation(receipt.operation_id).is_err());
        assert!(store.request_cancel(receipt.operation_id, 0).is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupted);
    }
}

#[test]
fn killed_process_before_or_after_durable_write_leaves_a_complete_known_receipt() {
    let (_temp, store, binding) = fixture();
    for moment in ["before", "after"] {
        let receipt = store
            .begin_operation(&binding, "prepare", inputs(), &["capture"])
            .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "receipt_process_worker", "--nocapture"])
            .env("ZDN_RECEIPT_WORKER_STATE", store.root())
            .env(
                "ZDN_RECEIPT_WORKER_OPERATION",
                receipt.operation_id.to_string(),
            )
            .env("ZDN_RECEIPT_WORKER_MOMENT", moment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "worker exited before ready"
            );
            if line.contains("RECEIPT_READY") {
                break;
            }
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let reopened = StateStore::open(store.root()).unwrap();
        let recovered = reopened.operation(receipt.operation_id).unwrap();
        assert_eq!(recovered.inputs, inputs());
        assert_eq!(
            recovered.phases[0].status,
            if moment == "before" {
                PhaseStatus::Pending
            } else {
                running()
            }
        );
        let action = reopened
            .resume(receipt.operation_id, &inputs())
            .unwrap()
            .phases[0]
            .action
            .clone();
        assert_eq!(
            action,
            if moment == "before" {
                ResumeAction::Run
            } else {
                ResumeAction::ReconcileOutcome
            }
        );
        // A killed process must not leave the cross-process lock held.
        reopened
            .request_cancel(receipt.operation_id, recovered.revision)
            .unwrap();
    }
}

#[test]
fn receipt_process_worker() {
    let Ok(state) = std::env::var("ZDN_RECEIPT_WORKER_STATE") else {
        return;
    };
    let operation: Uuid = std::env::var("ZDN_RECEIPT_WORKER_OPERATION")
        .unwrap()
        .parse()
        .unwrap();
    let moment = std::env::var("ZDN_RECEIPT_WORKER_MOMENT").unwrap();
    let store = StateStore::open(state).unwrap();
    if moment == "after" {
        store
            .record_phase(operation, 0, "capture", running())
            .unwrap();
    }
    println!("RECEIPT_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    if moment == "before" {
        store
            .record_phase(operation, 0, "capture", running())
            .unwrap();
    }
}
