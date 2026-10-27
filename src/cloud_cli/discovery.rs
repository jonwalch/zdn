//! Saved local observations only: no authority, lease, or artifact checks.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use zdn::state::PhaseStatus;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.discovery.list")
)]
pub(super) fn list(args: StoreArgs, profile_name: String) -> Result<serde_json::Value> {
    // Deliberately discard underlying diagnostics: malformed local files can
    // contain credential-bearing strings, including in serde error messages.
    let store = open_store(args).map_err(|_| eyre::eyre!("cannot open local state"))?;
    let profile = load_profile(&store, &profile_name)
        .map_err(|_| eyre::eyre!("cannot read selected local profile"))?;
    let scope = profile.team.scope();
    let (bindings, operations) = store
        .snapshot(&scope)
        .map_err(|_| eyre::eyre!("cannot read local bindings"))?;
    let operations: BTreeMap<_, _> = operations
        .into_iter()
        .map(|operation| (operation.operation_id, operation))
        .collect();
    let mut networks = BTreeMap::<_, BTreeSet<String>>::new();
    for binding in bindings {
        networks
            .entry(binding.network_id)
            .or_default()
            .insert(binding.label);
    }
    let mut entries = Vec::new();
    for (id, labels) in networks {
        let mut row = json!({
            "networkId": id, "labels": labels, "receiptState": "missing",
            "requestKind": null, "destroyed": null, "lastOperationId": null,
            "lastOperation": null, "unresolvedOperationId": null,
            "pendingUpdateId": null, "recoveryState": "blocked", "blockers": [],
            "cleanup": null
        });
        let mut blockers = BTreeSet::new();
        let deployment = DeploymentFile::read_snapshot(store.root(), id);
        match deployment {
            Ok(deployment)
                if deployment.spec.scope == scope
                    && deployment.team == profile.team
                    && deployment.spec.network_id == id =>
            {
                row["receiptState"] = json!("valid");
                // Presence is not verified preparation or permission to resume.
                // Partial/legacy build inputs also rule out foundation cleanup.
                let source_build = deployment.cluster.is_none()
                    && [
                        "source-preparation.json",
                        "source-build-inputs.json",
                        "source-preparation",
                        "source-snapshot",
                        "build",
                    ]
                    .iter()
                    .any(|name| {
                        fs::symlink_metadata(
                            store
                                .root()
                                .join("foundation")
                                .join(id.to_string())
                                .join(name),
                        )
                        .is_ok()
                    });
                row["requestKind"] = json!(if deployment.cluster.is_some() {
                    "nodes"
                } else if source_build {
                    "source-build"
                } else {
                    "foundation"
                });
                row["destroyed"] = json!(deployment.destroyed);
                row["lastOperationId"] = json!(deployment.last_operation);
                row["unresolvedOperationId"] = json!(deployment.unresolved_operation);
                if source_build {
                    blockers.insert("source_build_preflight_required");
                } else if deployment.cluster.is_none() {
                    blockers.insert("missing_node_request");
                }
                if deployment.spec.aws_profile != profile.aws_profile {
                    blockers.insert("aws_profile_mismatch");
                }
                if deployment.destroyed {
                    blockers.insert("destroyed");
                }
                if deployment.unresolved_operation.is_some() {
                    blockers.insert("reconcile_required");
                }
                if let Some(id) = deployment
                    .unresolved_operation
                    .filter(|id| Some(*id) != deployment.last_operation)
                {
                    if !operations.get(&id).is_some_and(|op| {
                        op.network_id == deployment.spec.network_id && op.scope == scope
                    }) {
                        blockers.insert("inaccessible_operation_receipt");
                    }
                }
                if let Some(runtime) = &deployment.runtime {
                    if let Some(update) = runtime.update.as_ref().filter(|_| runtime.pending()) {
                        row["pendingUpdateId"] = json!(update.id);
                        blockers.insert("pending_update");
                    }
                }
                if deployment
                    .cluster
                    .as_ref()
                    .and_then(|c| c.artifact_set.as_ref())
                    .is_some_and(|set| {
                        set.compatibility.helper_version != env!("CARGO_PKG_VERSION")
                    })
                {
                    blockers.insert("incompatible_package_helper");
                }
                if let Some(operation_id) = deployment.last_operation {
                    match operations.get(&operation_id) {
                        Some(operation)
                            if operation.network_id == id && operation.scope == scope =>
                        {
                            let phases: Vec<_> = operation
                                .phases
                                .iter()
                                .enumerate()
                                .map(|(index, phase)| {
                                    let status = match phase.status {
                                        PhaseStatus::Pending => "pending",
                                        PhaseStatus::Running { .. } => "running",
                                        PhaseStatus::Succeeded { .. } => "succeeded",
                                        PhaseStatus::Failed { .. } => "failed",
                                        PhaseStatus::Unknown { .. } => "unknown",
                                        PhaseStatus::Cancelled => "cancelled",
                                    };
                                    let name = match phase.name.as_str() {
                                        "verify" | "reserve" | "lease" | "prepare" | "preview"
                                        | "apply" | "install" | "readiness" | "destroy"
                                        | "cleanup" | "remove-stack" | "update" => {
                                            Some(phase.name.as_str())
                                        }
                                        _ => None,
                                    };
                                    json!({"index": index, "name": name, "status": status})
                                })
                                .collect();
                            let succeeded = operation
                                .phases
                                .iter()
                                .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. }));
                            let uncertain = operation.phases.iter().any(|p| {
                                matches!(
                                    p.status,
                                    PhaseStatus::Running { .. }
                                        | PhaseStatus::Unknown { .. }
                                        | PhaseStatus::Failed {
                                            retry_safe: false,
                                            ..
                                        }
                                )
                            });
                            if uncertain {
                                blockers.insert("reconcile_required");
                            } else if !succeeded || operation.cancel_requested {
                                blockers.insert("operation_incomplete");
                            }
                            row["lastOperation"] = json!({"receiptState":"valid", "status": if uncertain {"uncertain"} else if succeeded {"succeeded"} else {"incomplete"}, "cancelRequested":operation.cancel_requested,"phases":phases});
                        }
                        _ => {
                            row["lastOperation"] = json!({"receiptState":"inaccessible"});
                            blockers.insert("inaccessible_operation_receipt");
                        }
                    }
                }
                row["cleanup"] = cleanup_report(
                    &deployment,
                    &profile_name,
                    store.root(),
                    blockers
                        .iter()
                        .any(|blocker| !matches!(*blocker, "destroyed" | "missing_node_request")),
                )?;
            }
            result => {
                let path = store
                    .root()
                    .join("foundation")
                    .join(id.to_string())
                    .join("deployment.json");
                let missing = result.is_err()
                    && fs::symlink_metadata(path)
                        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
                row["receiptState"] = json!(if missing { "missing" } else { "invalid" });
                blockers.insert(if missing {
                    "missing_request"
                } else {
                    "invalid_receipt"
                });
            }
        }
        if blockers.is_empty() {
            row["recoveryState"] = json!("ready-for-preflight");
        }
        row["blockers"] = json!(blockers);
        entries.push(row);
    }
    Ok(json!({
        "apiVersion":"zdn-deployment-list/v1alpha1", "scope":"local",
        "profile":profile_name, "teamId":scope.team_id, "accountId":scope.account_id,
        "region":scope.region, "awsChecked":false, "liveReadinessChecked":false,
        "artifactIntegrityChecked":false, "entries":entries
    }))
}

/// Saved evidence and conditional command proposals, never live deletion authority.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.discovery.cleanup_report")
)]
fn cleanup_report(
    deployment: &Deployment,
    profile: &str,
    state: &Path,
    blocked: bool,
) -> Result<serde_json::Value> {
    let state = state
        .to_str()
        .context("cleanup command arguments require a UTF-8 local state path")?;
    let expected_prefix = format!(
        "s3://{}/{}",
        deployment.team.backend_bucket()?,
        zdn::devnet::artifact_prefix(&deployment.team, &deployment.spec)
    );
    let saved = deployment.cleanup.as_ref();
    let valid = saved.is_none_or(|report| {
        report
            .retained_volumes
            .iter()
            .all(|id| zdn::infra::validate_aws_id(id, "vol-").is_ok())
            && report
                .retained_artifact_prefixes
                .iter()
                .all(|prefix| deployment.cluster.is_some() && prefix == &expected_prefix)
    });
    let kind = if deployment.cluster.is_some() {
        "devnet"
    } else {
        "foundation"
    };
    let mut arguments = vec![
        "zdn".to_owned(),
        kind.to_owned(),
        "status".to_owned(),
        deployment.spec.network_id.to_string(),
        "--profile".into(),
        profile.into(),
        "--state-dir".into(),
        state.into(),
    ];
    let mut steps = vec![json!({"purpose":"inspect-inventory", "arguments":arguments,
        "mutates":false, "requiresAuthorization":false})];
    let mut operations = BTreeSet::new();
    for id in [deployment.last_operation, deployment.unresolved_operation]
        .into_iter()
        .flatten()
    {
        if operations.insert(id) {
            steps.push(json!({"purpose":"inspect-receipt", "arguments":["zdn", "receipt", "inspect", id.to_string(), "--state-dir", state],
                "mutates":false, "requiresAuthorization":false}));
        }
    }
    if !blocked
        && valid
        && saved.is_none_or(|report| {
            report.remaining_resources.is_empty() && report.shared_backend_preserved
        })
    {
        arguments[2] = "destroy".into();
        arguments.push("--yes".into());
        for delete_data in [false, true] {
            if delete_data {
                arguments.push("--delete-data".into());
            }
            steps.push(
                json!({"purpose":if delete_data { "delete-data" } else { "retain-data" },
                "arguments":arguments, "mutates":true, "requiresAuthorization":true,
                "requiresFreshInventory":true, "requiresOwnershipAndLeaseChecks":true}),
            );
        }
    }
    let saved = saved.filter(|_| valid);
    Ok(json!({
        "source":"saved-cleanup-receipt", "receiptState": if !valid { "invalid" } else if saved.is_some() { "valid" } else { "missing" },
        "retainedVolumeIds":saved.map(|report| &report.retained_volumes),
        "retainedArtifactPrefixes":saved.map(|report| &report.retained_artifact_prefixes),
        "remainingResourceCount":saved.map(|report| report.remaining_resources.len()),
        "sharedBackendPreserved":saved.map(|report| report.shared_backend_preserved),
        "liveStateChecked":false, "executionAuthorized":false, "retentionDefault":true,
        "retainedDiskRestoreSupported":false,
        "cost":{"estimateStatus":"not-estimated", "monthlyUsd":null, "billingChecked":false,
            "ongoingChargesPossible":true, "assumptions":[
                "retained volumes and artifact versions may incur storage charges",
                "the shared state backend, KMS key and registry are preserved",
                "resource existence, volume sizes, regional rates and actual billing are unchecked"]},
        "steps":steps
    }))
}
