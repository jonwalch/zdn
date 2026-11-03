//! Fresh observation only. No Pulumi, managed tools, reservation, lease,
//! companion discovery, install, bootstrap or producer activation on controller.
use super::*;
use crate::health::{
    Check, Options, ProducerHealth, ProducerState, ProductionWindow, Report, Status, API_VERSION,
};
use crate::state::{Binding, StateStore};

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.health.validate")
)]
pub fn validate(deployment: &Deployment, root: &Path, options: Options) -> Result<()> {
    options.validate()?;
    ensure!(
        deployment.unresolved_operation.is_none(),
        "external health requires a settled operation"
    );
    validate_runtime(deployment, root)
}

pub(super) fn validate_runtime(deployment: &Deployment, root: &Path) -> Result<()> {
    validate_saved(deployment, root)?;
    deployment.require_native_execution()?;
    ensure!(
        !deployment.destroyed && deployment.stack_initialized && deployment.outputs.is_some(),
        "external health requires a settled provisioned deployment"
    );
    update::require_settled(deployment, root)?;
    let (store, evidence) = load_inventory(deployment, root)?;
    ensure!(
        evidence.pending_identity.is_none()
            && store.read_pinned(&evidence.inventory)?.is_complete()
            && evidence.manifests.len()
                == usize::from(
                    deployment
                        .external
                        .as_ref()
                        .context("external deployment required")?
                        .node_count
                ),
        "external runtime cohort incomplete"
    );
    super::super::new_volume::validate_handoff(deployment, root)?;
    Ok(())
}

struct Budget<'a, T> {
    api: &'a dyn AwsApi,
    runtime: &'a T,
    cancel: &'a AtomicBool,
    deadline: Duration,
}
impl<T: Runtime> Budget<'_, T> {
    fn remaining(&self) -> Result<Duration> {
        ensure!(
            !self.cancel.load(Ordering::SeqCst),
            "external health cancelled"
        );
        let remaining = self.deadline.saturating_sub(self.runtime.monotonic());
        ensure!(!remaining.is_zero(), "external health deadline reached");
        Ok(remaining)
    }
}
impl<T: Runtime> AwsApi for Budget<'_, T> {
    fn call(&self, service: &str, operation: &str, input: Value, args: &[String]) -> Result<Value> {
        let result = self.api.call_with_timeout(
            service,
            operation,
            input,
            args,
            self.remaining()?.min(Duration::from_secs(60)),
        );
        self.remaining()?;
        result
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

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.health.check")
)]
#[allow(clippy::too_many_arguments)]
pub fn check(
    api: &dyn AwsApi,
    store: &StateStore,
    binding: &Binding,
    deployment: &Deployment,
    root: &Path,
    options: Options,
    runtime: &impl Runtime,
    cancel: &AtomicBool,
) -> Result<Report> {
    validate(deployment, root, options)?;
    // Local saved evidence only; health never sends or records a control.
    let stop = super::qualification::producer_stop(store, binding, deployment, root)?;
    let budget = Budget {
        api,
        runtime,
        cancel,
        deadline: runtime.monotonic() + Duration::from_secs(u64::from(options.timeout_secs)),
    };
    let (_, evidence) = load_inventory(deployment, root)?;
    let started_at = runtime.unix_time()?;
    let mut report = Report {
        api_version: API_VERSION.into(),
        network_id: deployment.spec.network_id,
        started_at,
        checked_at: started_at,
        attempts: 0,
        ready: false,
        timed_out: false,
        cancelled: false,
        live_readiness_checked: false,
        payment_qualification: "pending".into(),
        launch_ready: false,
        checks: BTreeMap::new(),
        producer: None,
    };
    let journal = root.join("health");
    foundation::private_directory(&journal)?;
    loop {
        report.attempts += 1;
        for node in deployment
            .outputs
            .as_ref()
            .context("external outputs missing")?
            .nodes
            .values()
        {
            let original = RuntimeRequest::from_slice(&devnet::read_bounded(
                &root.join(format!("{}-external-runtime.json", node.node_id)),
                16 * 1024 * 1024,
            )?)?;
            let effective = update::effective(root, &node.node_id, &evidence, &original)?;
            let mut actions = vec!["observe"];
            if node.node_id == "node-1" {
                actions.push("gateway-observe");
            }
            for action in actions {
                let key = format!("{}-{action}", node.node_id);
                let observed = (|| -> Result<Value> {
                    let remaining = budget.remaining()?;
                    crate::ssm::execute(
                        &budget,
                        &node.instance_id,
                        &runtime_script(&original, action)?,
                        &journal.join(format!("{key}-{}.json", Uuid::new_v4())),
                        remaining.as_secs().clamp(1, 300) as u32,
                        &budget,
                        &mut || budget.remaining().map(|_| ()),
                    )
                })();
                let scheduled = action == "observe" && effective.block_interval_seconds.is_some();
                let status = match observed {
                    Ok(value) => {
                        report.live_readiness_checked = true;
                        if scheduled {
                            let producer =
                                observe_producer(&effective, &value, stop, runtime.unix_time()?)
                                    .unwrap_or_else(|_| failed(&effective, ProducerState::Invalid));
                            let status = match producer.state {
                                ProducerState::Active
                                | ProducerState::Stopped
                                | ProducerState::Expired => Status::Ready,
                                ProducerState::NotRunning => Status::NotReady,
                                _ => Status::Invalid,
                            };
                            report.producer = Some(producer);
                            status
                        } else if if action == "observe" {
                            validate_observation(&effective, &value, false)
                        } else {
                            validate_gateway(&effective, &value)
                        }
                        .is_ok()
                        {
                            Status::Ready
                        } else {
                            Status::Invalid
                        }
                    }
                    Err(_) => {
                        if scheduled {
                            report.producer = Some(failed(&effective, ProducerState::Unavailable));
                        }
                        Status::Unavailable
                    }
                };
                let time = runtime.unix_time()?;
                report.checks.insert(
                    key,
                    Check {
                        status,
                        observed_at: (status != Status::Unavailable).then_some(time),
                        fresh: status != Status::Unavailable,
                        code: (status != Status::Ready).then(|| {
                            match status {
                                Status::Invalid => "invalid-observation",
                                Status::NotReady => "producer-not-running",
                                _ => "observation-unavailable",
                            }
                            .into()
                        }),
                    },
                );
            }
        }
        report.checked_at = runtime.unix_time()?;
        report.ready = !report.checks.is_empty()
            && report
                .checks
                .values()
                .all(|check| check.status == Status::Ready);
        report.cancelled = cancel.load(Ordering::SeqCst);
        report.timed_out = runtime.monotonic() >= budget.deadline;
        if report.ready
            || !options.wait
            || report.cancelled
            || report.timed_out
            || report
                .checks
                .values()
                .any(|check| check.status == Status::Invalid)
        {
            return Ok(report);
        }
        budget.sleep(Duration::from_secs(2));
    }
}

fn failed(runtime: &RuntimeRequest, state: ProducerState) -> ProducerHealth {
    ProducerHealth {
        node_id: runtime.provisioning.node_id.clone(),
        state,
        stop_control_id: None,
        production: None,
    }
}

/// Node readiness is always required. A running producer must be actively
/// owned; a stopped one is acceptable only with an authenticated exhausted
/// lifetime or saved deliberate-stop evidence. The host cannot distinguish a
/// crash from a stop, so any other stopped producer is not running.
fn observe_producer(
    runtime: &RuntimeRequest,
    value: &Value,
    stop: Option<Uuid>,
    now: u64,
) -> Result<ProducerHealth> {
    validate_observation(runtime, value, false)?;
    let window = |activation: &Value, expired: bool| -> Result<ProductionWindow> {
        let (activated, deadline) = runtime.validate_production(activation)?;
        Ok(ProductionWindow {
            activated_unix_seconds: activated,
            deadline_unix_seconds: deadline,
            expired: expired || now >= deadline,
        })
    };
    let (state, production) = if !value["productionExpired"].is_null() {
        validate_update_observation(runtime, value)?;
        (
            ProducerState::Expired,
            Some(window(&value["productionExpired"], true)?),
        )
    } else {
        // Older host helpers do not report the activation; omit the window.
        let production = match value.get("productionActivation") {
            None | Some(Value::Null) => None,
            Some(activation) => Some(window(activation, false)?),
        };
        let state = if !value["producer"].is_null() {
            validate_observation(runtime, value, true)?;
            ProducerState::Active
        } else if stop.is_some() {
            ProducerState::Stopped
        } else {
            ProducerState::NotRunning
        };
        (state, production)
    };
    Ok(ProducerHealth {
        node_id: runtime.provisioning.node_id.clone(),
        state,
        stop_control_id: stop.filter(|_| state == ProducerState::Stopped),
        production,
    })
}
