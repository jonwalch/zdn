//! Fresh diagnostics only: no lifecycle backend, lease, tools or service repair.
use super::{cluster::lightwallet, new_volume, Runtime};
use crate::{
    aws::AwsApi,
    devnet,
    foundation::Deployment,
    health::{Check, Options, Report, Status, API_VERSION},
};
use eyre::{ensure, ContextCompat, Result};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use uuid::Uuid;

/// Credential-free local preflight, also usable before CLI credential setup.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.health.validate")
)]
pub(crate) fn validate(deployment: &Deployment, directory: &Path, options: Options) -> Result<()> {
    options.validate()?;
    deployment.validate()?;
    deployment.require_native_execution()?;
    ensure!(!deployment.destroyed, "health requires a live deployment");
    ensure!(
        deployment.stack_initialized && deployment.outputs.is_some(),
        "health requires provisioned outputs"
    );
    ensure!(
        deployment.unresolved_operation.is_none(),
        "health refuses an unresolved operation"
    );
    ensure!(
        !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
        "health refuses a pending update"
    );
    let request = deployment
        .cluster
        .as_ref()
        .context("health requires a node deployment")?;
    request.verify_local(directory)?;
    let mut updates = BTreeMap::new();
    let root = directory.join("updates");
    if root.try_exists()? {
        ensure!(
            std::fs::symlink_metadata(&root)?.is_dir(),
            "invalid updates directory"
        );
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_dir(),
                "invalid update proof directory"
            );
            let id = Uuid::parse_str(
                entry
                    .file_name()
                    .to_str()
                    .context("invalid update directory")?,
            )?;
            let path = entry.path().join("completed.json");
            let intent: crate::update::UpdateIntent = if path.try_exists()? {
                serde_json::from_slice(&devnet::read_bounded(
                    &path,
                    crate::handoff::MAX_MANIFEST_BYTES,
                )?)?
            } else {
                deployment
                    .runtime
                    .as_ref()
                    .and_then(|r| r.update.as_ref())
                    .filter(|u| u.id == id && u.finished)
                    .cloned()
                    .context("missing completed update proof")?
            };
            ensure!(
                intent.id == id && intent.finished,
                "invalid completed update proof"
            );
            updates.insert(id, intent);
        }
    }
    super::validate_health_proofs(deployment, directory, &updates)
}

struct Budget<'a, T> {
    api: &'a dyn AwsApi,
    runtime: &'a T,
    cancel: &'a AtomicBool,
    deadline: Duration,
}
impl<T: Runtime> Budget<'_, T> {
    fn remaining(&self) -> Result<Duration> {
        ensure!(!self.cancel.load(Ordering::SeqCst), "health cancelled");
        let remaining = self.deadline.saturating_sub(self.runtime.monotonic());
        ensure!(!remaining.is_zero(), "health deadline reached");
        Ok(remaining)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.health.budget.observe")
    )]
    fn observe(
        &self,
        directory: &Path,
        key: &str,
        instance: &str,
        script: &str,
        timeout: u32,
    ) -> Result<Value> {
        self.remaining()?;
        let journal = directory.join(format!("{key}-{}.json", Uuid::new_v4()));
        // Do not recover any previous observation, even after an ambiguous dispatch.
        // A read-only remote command can outlive this local budget/cancellation.
        let value =
            crate::ssm::execute(self, instance, script, &journal, timeout, self, &mut || {
                self.remaining().map(|_| ())
            })?;
        self.remaining()?;
        Ok(value)
    }
}
impl<T: Runtime> Runtime for Budget<'_, T> {
    fn unix_time(&self) -> Result<u64> {
        self.runtime.unix_time()
    }
    fn monotonic(&self) -> Duration {
        self.runtime.monotonic()
    }
    fn sleep(&self, duration: Duration) {
        if let Ok(remaining) = self.remaining() {
            self.runtime.sleep(duration.min(remaining));
        }
    }
}
impl<T: Runtime> AwsApi for Budget<'_, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.health.budget.call")
    )]
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra_args: &[String],
    ) -> Result<Value> {
        let remaining = self.remaining()?;
        let result = self.api.call_with_timeout(
            service,
            operation,
            input,
            extra_args,
            remaining.min(Duration::from_secs(60)),
        );
        self.remaining()?;
        result
    }
}

fn checked(status: Status, time: u64) -> Check {
    Check {
        status,
        observed_at: (status != Status::Unavailable).then_some(time),
        fresh: status != Status::Unavailable,
        code: match status {
            Status::Ready => None,
            Status::NotReady => Some("not-ready".into()),
            Status::Invalid => Some("invalid-observation".into()),
            _ => Some("observation-unavailable".into()),
        },
    }
}

/// Never infer a recoverable readiness condition from an arbitrary remote error.
/// In particular, the installed node observer reports failed identity checks as
/// terminal SSM failures, not as a successful stopped-node observation.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.health.failed")
)]
fn failed(error: &eyre::Report) -> (Check, bool) {
    use crate::ssm::CommandError;
    let transient = crate::aws::transient_error(error)
        || error.downcast_ref::<CommandError>() == Some(&CommandError::Unavailable);
    let (status, code) = match error.downcast_ref::<CommandError>() {
        Some(CommandError::InvalidInvocation) => (Status::Invalid, "invalid-invocation"),
        Some(CommandError::InvalidOutput) => (Status::Invalid, "invalid-output"),
        Some(CommandError::RemoteFailed) => (Status::Unavailable, "remote-observation-failed"),
        Some(CommandError::RemoteCancelled) => {
            (Status::Unavailable, "remote-observation-cancelled")
        }
        Some(CommandError::RemoteTimedOut) => (Status::Unavailable, "remote-observation-timed-out"),
        _ if transient => (Status::Unavailable, "observation-unavailable"),
        _ => match error.downcast_ref::<crate::aws::AwsApiError>() {
            Some(error)
                if matches!(
                    error.code.as_str(),
                    "AccessDenied"
                        | "AccessDeniedException"
                        | "UnauthorizedOperation"
                        | "UnrecognizedClientException"
                        | "ExpiredToken"
                        | "ExpiredTokenException"
                ) =>
            {
                (Status::Unavailable, "authorization-denied")
            }
            Some(_) => (Status::Unavailable, "request-rejected"),
            None => (Status::Unavailable, "observation-failed"),
        },
    };
    (
        Check {
            status,
            observed_at: None,
            fresh: false,
            code: Some(code.into()),
        },
        transient,
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.health.check")
)]
pub(crate) fn check(
    api: &dyn AwsApi,
    deployment: &Deployment,
    directory: &Path,
    options: Options,
    runtime: &impl Runtime,
    cancel: &AtomicBool,
) -> Result<Report> {
    validate(deployment, directory, options)?;
    let started_at = runtime.unix_time()?;
    let budget = Budget {
        api,
        runtime,
        cancel,
        deadline: runtime.monotonic() + Duration::from_secs(u64::from(options.timeout_secs)),
    };
    let request = deployment.cluster.as_ref().context("missing cluster")?;
    let outputs = deployment.outputs.as_ref().context("missing outputs")?;
    let mut hosts = BTreeMap::new();
    for node in outputs.nodes.values() {
        let mut host = lightwallet::host_spec(deployment, directory, node)?;
        host.new_volume = new_volume::saved_authorization(
            deployment,
            directory,
            new_volume::AuthorizationTarget::Node(node),
        )?;
        let hash = host.install_sha256()?;
        let command = super::cluster::native::node_command(
            request.native_runtime_protocol.as_deref(),
            &host,
            "observe",
        )?;
        host.image = crate::update::active_image(deployment, &node.node_id)?
            .image
            .clone();
        hosts.insert(node.node_id.clone(), (host, hash, command));
    }
    let mut checks = BTreeMap::new();
    for key in hosts
        .keys()
        .cloned()
        .chain(request.block_interval_seconds.map(|_| "producer".into()))
        .chain(request.lightwallet.as_ref().map(|_| "lightwallet".into()))
        .chain(request.client_access.then(|| "clientGateway".into()))
    {
        checks.insert(
            key,
            Check {
                status: Status::Unchecked,
                observed_at: None,
                fresh: false,
                code: None,
            },
        );
    }
    let diagnostics = directory.join("diagnostics/health");
    let mut attempts = 0;
    while budget.remaining().is_ok() {
        crate::foundation::private_directory(&directory.join("diagnostics"))?;
        crate::foundation::private_directory(&diagnostics)?;
        attempts += 1;
        let mut retry_allowed = true;
        for check in checks.values_mut() {
            *check = Check {
                status: Status::Unchecked,
                observed_at: None,
                fresh: false,
                code: None,
            };
        }
        for (id, (host, hash, script)) in &hosts {
            if budget.remaining().is_err() {
                break;
            }
            let node = &outputs.nodes[id];
            let result = budget.observe(
                &diagnostics,
                id,
                &node.instance_id,
                script,
                super::cluster::NODE_OBSERVATION_TIMEOUT,
            );
            let mut status = Status::Unavailable;
            if let Ok(value) = &result {
                let expected_update = deployment
                    .runtime
                    .as_ref()
                    .and_then(|r| r.nodes.get(id))
                    .map(|r| r.update_id.to_string());
                status = if value["updateId"] != serde_json::to_value(expected_update)? {
                    Status::Invalid
                } else if devnet::validate_observation(value, host, hash).is_ok() {
                    Status::Ready
                } else {
                    Status::Invalid
                };
            }
            let check = match &result {
                Ok(_) => checked(status, runtime.unix_time()?),
                Err(error) => {
                    let (check, retryable) = failed(error);
                    retry_allowed &= retryable;
                    check
                }
            };
            checks.insert(id.clone(), check.clone());
            if host.role == "producer" && request.block_interval_seconds.is_some() {
                let producer = match &result {
                    Ok(value) if status == Status::Ready => {
                        match devnet::validate_producer_observation(value, host, true) {
                            Ok(_) => Status::Ready,
                            Err(_)
                                if value["scheduledProducer"] == false
                                    && value["producer"].is_null() =>
                            {
                                Status::NotReady
                            }
                            Err(_) => Status::Invalid,
                        }
                    }
                    _ => status,
                };
                checks.insert(
                    "producer".into(),
                    if result.is_ok() {
                        checked(producer, runtime.unix_time()?)
                    } else {
                        check
                    },
                );
            }
        }
        if request.lightwallet.is_some() && budget.remaining().is_ok() {
            let spec = lightwallet::install_spec(deployment, directory)?;
            let node = outputs
                .nodes
                .get(&spec.host.node_id)
                .context("missing lightwallet node")?;
            let script = super::cluster::native::lightwallet_command(
                request.native_runtime_protocol.as_deref(),
                &spec,
                "observe",
            )?;
            let result = budget.observe(
                &diagnostics,
                "lightwallet",
                &node.instance_id,
                &script,
                lightwallet::OBSERVATION_TIMEOUT,
            );
            let check = match result {
                Ok(value) => {
                    let status =
                        match crate::lightwallet_service::validate_observation(&value, &spec) {
                            Ok(observation) if observation.status == "ready" => Status::Ready,
                            Ok(_) => Status::NotReady,
                            Err(_) => Status::Invalid,
                        };
                    checked(status, runtime.unix_time()?)
                }
                Err(error) => {
                    let (check, retryable) = failed(&error);
                    retry_allowed &= retryable;
                    check
                }
            };
            checks.insert("lightwallet".into(), check);
        }
        if request.client_access && budget.remaining().is_ok() {
            // Gateway identity is based on the original installation, even after image updates.
            let node = &outputs.nodes["node-1"];
            let mut host = lightwallet::host_spec(deployment, directory, node)?;
            host.new_volume = new_volume::saved_authorization(
                deployment,
                directory,
                new_volume::AuthorizationTarget::Node(node),
            )?;
            let script = super::cluster::selected_gateway(
                directory,
                &host,
                request.native_runtime_protocol.as_deref(),
            )?
            .observe_script;
            let result = budget.observe(
                &diagnostics,
                "client-gateway",
                &node.instance_id,
                &script,
                super::cluster::CLIENT_OBSERVE_TIMEOUT,
            );
            let check = match result {
                Ok(value) => {
                    let status = match super::cluster::native::validate_gateway_observation(
                        request.native_runtime_protocol.as_deref(),
                        &host,
                        &value,
                    ) {
                        Ok(observation) if observation.status == "ready" => Status::Ready,
                        Ok(_) => Status::NotReady,
                        Err(_) => Status::Invalid,
                    };
                    checked(status, runtime.unix_time()?)
                }
                Err(error) => {
                    let (check, retryable) = failed(&error);
                    retry_allowed &= retryable;
                    check
                }
            };
            checks.insert("clientGateway".into(), check);
        }
        if checks.values().all(|c| c.status == Status::Ready)
            || !options.wait
            || !retry_allowed
            || checks.values().any(|c| c.status == Status::Invalid)
            || budget.remaining().is_err()
        {
            break;
        }
        budget.sleep(Duration::from_secs(2));
    }
    let cancelled = cancel.load(Ordering::SeqCst);
    let timed_out = runtime.monotonic() >= budget.deadline;
    Ok(Report {
        api_version: API_VERSION.into(),
        network_id: deployment.spec.network_id,
        started_at,
        checked_at: runtime.unix_time()?,
        attempts,
        ready: !cancelled && !timed_out && checks.values().all(|c| c.status == Status::Ready),
        timed_out,
        cancelled,
        live_readiness_checked: checks.values().any(|c| c.fresh),
        payment_qualification: "pending".into(),
        launch_ready: false,
        checks,
    })
}
