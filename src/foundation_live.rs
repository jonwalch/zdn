//! AWS/SSM and Pulumi adapters for the one-host foundation.

use crate::{
    aws::{
        self, AwsApi, AwsCli, AwsSelection, LeaseHandle, LeaseOwner, NetworkReservation,
        S3Metadata, TeamDefinition,
    },
    foundation::{self, CleanupReport, Deployment, FoundationBackend},
    infra::{FoundationOutputs, FoundationSpec, FIXTURE_MEMORY_BYTES, GIB},
    pulumi::{
        AwsContext, ManagedTools, PulumiClient, PulumiRunner, PulumiWorkspace, RunControl,
        SystemPulumiRunner,
    },
};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

mod cluster;
mod destroy;
pub(crate) mod health;
mod new_volume;

pub use cluster::selected_fetch_installer;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationHistory {
    Validate,
    Preserve,
}

/// Validate authoritative local installation proofs, not historical read-only
/// observations. No journal is modified and no external service is contacted.
pub fn validate_health_proofs(
    deployment: &Deployment,
    directory: &Path,
    updates: &std::collections::BTreeMap<Uuid, crate::update::UpdateIntent>,
) -> Result<()> {
    crate::update::validate_completed_history(deployment, updates)?;
    new_volume::validate_handoff(deployment, directory)?;
    cluster::validate_handoff(deployment, directory, updates, ObservationHistory::Preserve)
}

/// Validate portable local runtime proofs without credentials, tools or AWS.
pub(crate) fn validate_handoff(
    deployment: &Deployment,
    directory: &Path,
    updates: &std::collections::BTreeMap<Uuid, crate::update::UpdateIntent>,
) -> Result<()> {
    new_volume::validate_handoff(deployment, directory)?;
    cluster::validate_handoff(deployment, directory, updates, ObservationHistory::Validate)
}

const LEASE_SECONDS: u64 = 900;
// Two bounded AWS CLI calls (60s each) plus Pulumi's 30s SIGINT grace,
// plus up to 5s for session cleanup, leaving 25s before the proven lease expires.
const LEASE_STOP_MARGIN: u64 = 180;

/// Clock and wait boundary for bounded, offline lifecycle tests.
pub trait Runtime {
    fn unix_time(&self) -> Result<u64>;
    fn monotonic(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

pub struct SystemRuntime(Instant);
impl Default for SystemRuntime {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Runtime for SystemRuntime {
    fn unix_time(&self) -> Result<u64> {
        unix_time()
    }
    fn monotonic(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Default)]
struct Heartbeat {
    deadline: Duration,
    next_renewal: Duration,
    attempted_wall: Option<u64>,
    attempted_monotonic: Option<Duration>,
    retry_count: u32,
    state_busy_since: Option<Duration>,
}
impl Heartbeat {
    fn acquired(&mut self, handle: &LeaseHandle, wall: u64, monotonic: Duration) {
        *self = Self {
            deadline: monotonic
                + Duration::from_secs(handle.record.expires_at.saturating_sub(wall)),
            next_renewal: monotonic + Duration::from_secs(30),
            ..Self::default()
        };
    }
    fn check_budget(&self, handle: &LeaseHandle, runtime: &impl Runtime) -> Result<()> {
        ensure!(
            !handle.record.released
                && handle
                    .record
                    .expires_at
                    .saturating_sub(runtime.unix_time()?)
                    > LEASE_STOP_MARGIN
                && self.deadline.saturating_sub(runtime.monotonic())
                    > Duration::from_secs(LEASE_STOP_MARGIN),
            "deployment lease renewal deadline reached; stopping before lease expiry"
        );
        Ok(())
    }
}

pub fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub struct LiveBackend<'a, A = AwsCli, R = SystemPulumiRunner, T = SystemRuntime> {
    pub aws: A,
    client: PulumiClient<R>,
    selection: AwsSelection,
    runtime: T,
    team: TeamDefinition,
    reservation: NetworkReservation,
    lease: Option<LeaseHandle>,
    cancel: Arc<AtomicBool>,
    heartbeat: Heartbeat,
    recovery_etag: Option<String>,
    destroying: bool,
    destroy_context: Option<Deployment>,
    stack_missing: bool,
    state_root: PathBuf,
    deployment_directory: PathBuf,
    command_progress: Option<Box<crate::ssm::CommandProgress<'a>>>,
}

impl LiveBackend<'_> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.new")
    )]
    pub fn new(
        deployment: &Deployment,
        directory: &Path,
        managed: &Path,
        cancel: Arc<AtomicBool>,
        recovery_etag: Option<String>,
    ) -> Result<Self> {
        deployment.validate()?;
        let (api, credential_files) = crate::credentials::client(
            &deployment.team,
            aws::AwsSelection {
                profile: deployment.spec.aws_profile.clone(),
                account_id: deployment.spec.scope.account_id.clone(),
                region: deployment.spec.scope.region.clone(),
            },
            &directory.join("credentials"),
        )?;
        let program = deployment.render()?;
        let project = directory.join("project");
        foundation::private_directory(&project)?;
        foundation::write_private(&project.join("Pulumi.yaml"), program.to_yaml()?.as_bytes())?;
        let workspace = PulumiWorkspace {
            tools: ManagedTools::resolve(managed)?,
            work_dir: project,
            diagnostics_dir: directory.join("diagnostics"),
            backend_url: deployment.team.state.backend.clone(),
            secrets_provider: deployment.team.secrets_provider(),
            aws: AwsContext {
                profile: deployment.spec.aws_profile.clone(),
                account_id: deployment.spec.scope.account_id.clone(),
                region: deployment.spec.scope.region.clone(),
                credential_files,
            },
            project: program.name,
            stack: format!("zdn-{}", deployment.spec.network_id.simple()),
        };
        Ok(Self {
            command_progress: None,
            deployment_directory: directory.to_owned(),
            selection: api.selection().clone(),
            runtime: SystemRuntime::default(),
            aws: api,
            client: PulumiClient::new(workspace, SystemPulumiRunner::current_exe()?)?,
            team: deployment.team.clone(),
            reservation: NetworkReservation::new(
                deployment.spec.scope.clone(),
                deployment.spec.network_id,
                deployment.owner_id,
            )?,
            lease: None,
            cancel,
            heartbeat: Heartbeat::default(),
            recovery_etag,
            destroying: false,
            destroy_context: None,
            stack_missing: false,
            state_root: directory
                .parent()
                .and_then(Path::parent)
                .context("foundation directory must be inside local state")?
                .to_owned(),
        })
    }
}

impl<'a, A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'a, A, R, T> {
    pub fn observe_commands(
        &mut self,
        observer: impl FnMut(&crate::ssm::CommandObservation) -> Result<()> + 'a,
    ) {
        self.command_progress = Some(Box::new(observer));
    }

    /// Acquire the existing deployment's mutation lease without preparing a stack.
    pub fn acquire_update(&mut self, deployment: &Deployment, id: Uuid) -> Result<()> {
        deployment.require_native_execution()?;
        aws::verify_identity(&self.aws, &self.selection)?;
        FoundationBackend::reserve(self, deployment)?;
        FoundationBackend::acquire(self, deployment, id)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.release_update")
    )]
    pub fn release_update(&mut self) -> Result<()> {
        if let Some(handle) = self.lease.as_ref() {
            aws::release_lease(
                &S3Metadata::new(&self.aws, &self.team)?,
                handle,
                self.runtime.unix_time()?,
            )?;
            self.lease = None;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.build_update")
    )]
    pub fn build_update(
        &mut self,
        contract: &crate::build::BuildContract,
        archive: &Path,
        directory: &Path,
        progress: &mut crate::build_job::BuildProgress<'_>,
    ) -> Result<()> {
        // This entrypoint has no deployment argument: use the durable binding,
        // never infer execution selection from a build contract or helper pin.
        let deployment: Deployment =
            foundation::read_json(&self.deployment_directory.join("deployment.json"))?;
        deployment.validate()?;
        deployment.require_native_execution()?;
        crate::build_job::run_with_progress(
            &self.aws,
            &self.team,
            contract,
            archive,
            directory,
            &self.runtime,
            || {
                ensure!(
                    pulse(
                        &self.aws,
                        &self.team,
                        &mut self.lease,
                        &self.cancel,
                        &mut self.heartbeat,
                        &self.state_root,
                        &self.runtime
                    )? == RunControl::Continue,
                    "update build cancelled"
                );
                Ok(())
            },
            progress,
        )?;
        Ok(())
    }

    fn poll(&mut self) -> Result<()> {
        let control = pulse(
            &self.aws,
            &self.team,
            &mut self.lease,
            &self.cancel,
            &mut self.heartbeat,
            &self.state_root,
            &self.runtime,
        )?;
        ensure!(
            control == RunControl::Continue,
            "foundation operation cancelled"
        );
        Ok(())
    }

    fn pause(&mut self, deadline: Duration) -> Result<()> {
        ensure!(
            self.runtime.monotonic() < deadline,
            "AWS readiness or cleanup deadline exceeded"
        );
        for _ in 0..10 {
            self.poll()?;
            self.runtime.sleep(Duration::from_millis(500));
        }
        Ok(())
    }
}

fn pulse(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    lease: &mut Option<LeaseHandle>,
    cancel: &AtomicBool,
    heartbeat: &mut Heartbeat,
    state_root: &Path,
    runtime: &impl Runtime,
) -> Result<RunControl> {
    if cancel.load(Ordering::SeqCst) {
        return Ok(RunControl::Cancel);
    }
    let Some(handle) = lease else {
        return Ok(RunControl::Continue);
    };
    heartbeat.check_budget(handle, runtime)?;
    let store = crate::state::StateStore::open(state_root)?.with_lock_timeout(Duration::ZERO);
    match store.operation(handle.record.owner.operation_id) {
        Ok(operation) => {
            heartbeat.state_busy_since = None;
            if operation.cancel_requested {
                return Ok(RunControl::Cancel);
            }
        }
        Err(error) if error.is::<crate::state::StateLockBusy>() => {
            let since = heartbeat
                .state_busy_since
                .get_or_insert(runtime.monotonic());
            ensure!(
                runtime.monotonic().saturating_sub(*since) < Duration::from_secs(30),
                "local cancellation state stayed busy for 30 seconds; stopping safely"
            );
        }
        Err(error) => return Err(error),
    }
    if runtime.monotonic() >= heartbeat.next_renewal {
        heartbeat
            .attempted_monotonic
            .get_or_insert(runtime.monotonic());
        let attempted_wall = *heartbeat.attempted_wall.get_or_insert(runtime.unix_time()?);
        match aws::renew_lease(
            &S3Metadata::new(api, team)?,
            handle,
            attempted_wall,
            LEASE_SECONDS,
        ) {
            Ok(()) => {
                // Keep the original attempt time when recovering a lost reply.
                // Neither retries nor a backward clock adjustment extend our
                // locally proven lifetime beyond the record committed to S3.
                heartbeat.deadline = heartbeat.attempted_monotonic.unwrap_or(runtime.monotonic())
                    + Duration::from_secs(LEASE_SECONDS);
                heartbeat.next_renewal = runtime.monotonic() + Duration::from_secs(30);
                heartbeat.attempted_wall = None;
                heartbeat.attempted_monotonic = None;
                heartbeat.retry_count = 0;
            }
            Err(error) if aws::transient_error(&error) => {
                heartbeat.retry_count = heartbeat.retry_count.saturating_add(1);
                heartbeat.next_renewal = runtime.monotonic()
                    + Duration::from_secs((1u64 << heartbeat.retry_count.min(5)).min(30));
            }
            Err(error) => return Err(error),
        }
    }
    heartbeat.check_budget(handle, runtime)?;
    Ok(RunControl::Continue)
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> FoundationBackend for LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.verify")
    )]
    fn verify(&mut self, deployment: &Deployment, destroying: bool) -> Result<()> {
        if !destroying {
            deployment.require_native_execution()?;
        }
        self.destroying = destroying;
        self.destroy_context = destroying.then(|| deployment.clone());
        self.poll()?;
        aws::verify_identity(&self.aws, &self.selection)?;
        if destroying {
            aws::verify_backend_for_cleanup(&self.aws, &self.selection, &deployment.team)?;
        } else {
            aws::verify_backend(&self.aws, &self.selection, &deployment.team)?;
            validate_host_request(&self.aws, &deployment.spec)?;
            if deployment.cluster.is_some() {
                self.verify_cluster(deployment)?;
            } else if let Some(runtime) = &deployment.foundation_runtime {
                runtime.verify_local(&self.deployment_directory)?;
                self.verify_runtime_access(deployment)?;
            }
        }
        Ok(())
    }
    fn reserve(&mut self, _: &Deployment) -> Result<()> {
        self.poll()?;
        aws::reserve_network(&S3Metadata::new(&self.aws, &self.team)?, &self.reservation)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.acquire")
    )]
    fn acquire(&mut self, _: &Deployment, operation_id: Uuid) -> Result<()> {
        self.poll()?;
        let store = S3Metadata::new(&self.aws, &self.team)?;
        let owner = LeaseOwner {
            operation_id,
            holder_id: Uuid::new_v4(),
        };
        let acquired_wall = self.runtime.unix_time()?;
        let acquired_monotonic = self.runtime.monotonic();
        self.lease = Some(if let Some(etag) = &self.recovery_etag {
            aws::recover_lease(
                &store,
                &self.reservation,
                etag,
                owner,
                acquired_wall,
                LEASE_SECONDS,
            )?
        } else {
            aws::acquire_lease(
                &store,
                &self.reservation,
                owner,
                acquired_wall,
                LEASE_SECONDS,
            )?
        });
        self.heartbeat.acquired(
            self.lease.as_ref().expect("acquired lease"),
            acquired_wall,
            acquired_monotonic,
        );
        Ok(())
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.prepare")
    )]
    fn prepare(&mut self, deployment: &Deployment, reconcile: bool) -> Result<()> {
        if !self.destroying {
            self.stage_cluster_artifacts(deployment)?;
        }
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        let exists = self.client.stack_exists(&mut progress)?;
        if !exists && self.destroying {
            self.stack_missing = true;
            return Ok(());
        }
        ensure!(
            exists || !deployment.stack_initialized,
            "the saved Pulumi stack disappeared; inspect state recovery before provisioning"
        );
        self.client.prepare_stack(!exists, &mut progress)?;
        if reconcile && exists {
            self.client.refresh(&mut progress)?;
        }
        if self.destroying && deployment.outputs.is_none() {
            let checkpoint = self.client.foundation_export(&mut progress)?;
            destroy::save_volume_identities(&self.deployment_directory, deployment, &checkpoint)?;
        }
        if !self.destroying && deployment.cluster.is_some() {
            let checkpoint = self.client.foundation_export(&mut progress)?;
            self.record_volume_creation(deployment, &checkpoint)?;
        }
        Ok(())
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.preview")
    )]
    fn preview(&mut self, destroying: bool) -> Result<Value> {
        if self.stack_missing {
            return Ok(json!({"stackAbsent":true,"resourceChanges":0}));
        }
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        let summary = if destroying {
            self.client.preview_destroy(&mut progress)?
        } else {
            self.client.preview(&mut progress)?
        };
        Ok(serde_json::to_value(summary)?)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.apply")
    )]
    fn apply(&mut self, deployment: &Deployment) -> Result<FoundationOutputs> {
        deployment.require_native_execution()?;
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        self.client.up(&mut progress)?;
        self.client.outputs(&deployment.spec, &mut progress)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.deploy_runtime")
    )]
    fn deploy_runtime(&mut self, deployment: &Deployment) -> Result<Value> {
        deployment.require_native_execution()?;
        if deployment
            .runtime
            .as_ref()
            .is_some_and(|r| !r.nodes.is_empty())
        {
            // Preserve installed image revisions, but still reconcile services.
            self.complete_cluster_install(deployment)
        } else {
            self.install_cluster(deployment)
        }
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.ready")
    )]
    fn ready(&mut self, deployment: &Deployment) -> Result<Value> {
        deployment.require_native_execution()?;
        if deployment.cluster.is_some() {
            return self.observe_cluster(deployment);
        }
        let outputs = deployment
            .outputs
            .as_ref()
            .context("foundation outputs are missing")?;
        let deadline = self.runtime.monotonic() + Duration::from_secs(900);
        loop {
            self.poll()?;
            let response = self.aws.call(
                "ssm",
                "describe-instance-information",
                json!({
                "Filters":[{"Key":"InstanceIds","Values":[outputs.instance_id]}]}),
                &[],
            )?;
            if array(&response, "InstanceInformationList")?
                .iter()
                .any(|item| {
                    item["InstanceId"] == outputs.instance_id && item["PingStatus"] == "Online"
                })
            {
                break;
            }
            self.pause(deadline)?;
        }
        // The SSM agent starts before cloud-init installs the native helper.
        // Bound installation wait and health fetching together, and do not
        // turn failed initialization into a successful health observation.
        let health_script = r#"timeout --signal=TERM --kill-after=5s 600s /bin/sh <<'ZDN_FOUNDATION_HEALTH'
cloud-init status --wait >/dev/null 2>&1 || { echo 'foundation initialization failed' >&2; exit 1; }
exec /opt/zdn/foundation-zdn __foundation-fetch --protocol zdn-foundation-health/v1alpha1
ZDN_FOUNDATION_HEALTH"#;
        let sent = self.aws.call("ssm", "send-command", json!({
            "DocumentName":"AWS-RunShellScript", "InstanceIds":[outputs.instance_id], "TimeoutSeconds":120,
            "Comment":"zdn foundation health check", "Parameters": {
                "commands":[health_script],
                "executionTimeout":["620"] }}), &[])?;
        let command_id = sent
            .pointer("/Command/CommandId")
            .and_then(Value::as_str)
            .context("SSM returned no command ID")?;
        Uuid::parse_str(command_id).context("invalid SSM command ID")?;
        loop {
            self.poll()?;
            let response = self.aws.call(
                "ssm",
                "get-command-invocation",
                json!({"CommandId":command_id,"InstanceId":outputs.instance_id}),
                &[],
            );
            let response = match response {
                Ok(value) => value,
                Err(error) if aws_error(&error, "InvocationDoesNotExist") => {
                    self.pause(deadline)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match response["Status"]
                .as_str()
                .context("SSM returned no command status")?
            {
                "Pending" | "InProgress" | "Delayed" => self.pause(deadline)?,
                "Success" => {
                    ensure!(
                        response["ResponseCode"].as_i64() == Some(0),
                        "SSM health command returned a failure code"
                    );
                    let body = response["StandardOutputContent"]
                        .as_str()
                        .context("SSM returned no health response")?;
                    return Ok(serde_json::to_value(validate_health(
                        body,
                        &deployment.spec,
                    )?)?);
                }
                _ => {
                    bail!("foundation host health command failed; inspect SSM command {command_id}")
                }
            }
        }
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.destroy")
    )]
    fn destroy(&mut self) -> Result<()> {
        if self.stack_missing {
            return Ok(());
        }
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        let result = self.client.destroy(&mut progress);
        let Err(error) = result else {
            return Ok(());
        };
        // This is deliberately one retry of one proven provider failure, not
        // generic permission-error recovery. Keep the same lease throughout.
        let Some(failure) = error.downcast_ref::<crate::pulumi::PulumiFailure>() else {
            return Err(error);
        };
        if !failure.has_eip_disassociation() {
            return Err(error);
        }
        let Some(deployment) = self.destroy_context.as_ref() else {
            return Err(error);
        };
        let checkpoint = self.client.foundation_export(&mut progress)?;
        if !destroy::stale_nat_address(&self.aws, deployment, &checkpoint, failure, &mut progress)?
        {
            return Err(error);
        }
        self.client.refresh(&mut progress)?;
        let refreshed = self.client.foundation_export(&mut progress)?;
        destroy::confirm_address_refreshed(deployment, &checkpoint, &refreshed)?;
        destroy::record_address_recovery(
            &self.deployment_directory,
            deployment,
            &checkpoint,
            &refreshed,
            false,
        )?;
        self.client.destroy(&mut progress)?;
        destroy::record_address_recovery(
            &self.deployment_directory,
            deployment,
            &checkpoint,
            &refreshed,
            true,
        )
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.cleanup")
    )]
    fn cleanup(&mut self, deployment: &Deployment, delete_data: bool) -> Result<CleanupReport> {
        let saved_volumes =
            destroy::load_volume_identities(&self.deployment_directory, deployment)?;
        let deadline = self.runtime.monotonic() + Duration::from_secs(600);
        loop {
            self.poll()?;
            let mut report =
                inventory_with_volume_identities(&self.aws, deployment, &saved_volumes)?;
            if delete_data {
                // Require saved identity as well as current ownership and attributes.
                for id in &report.retained_volumes {
                    let data =
                        self.aws
                            .call("ec2", "describe-volumes", json!({"VolumeIds":[id]}), &[])?;
                    let volumes = array(&data, "Volumes")?;
                    ensure!(
                        volumes.len() == 1
                            && volumes[0]["VolumeId"] == *id
                            && (owned_chain_volume(&volumes[0], deployment)?
                                || destroy::owned_recorded_volume(
                                    &volumes[0],
                                    deployment,
                                    &saved_volumes
                                )?),
                        "data volume ownership changed"
                    );
                    if volumes[0]["State"] == "available"
                        && array(&volumes[0], "Attachments")?.is_empty()
                    {
                        self.poll()?;
                        self.aws
                            .call("ec2", "delete-volume", json!({"VolumeId":id}), &[])?;
                    }
                }
                report = inventory_with_volume_identities(&self.aws, deployment, &saved_volumes)?;
            }
            if report.remaining_resources.is_empty()
                && (!delete_data || report.retained_volumes.is_empty())
            {
                aws::verify_backend_for_cleanup(&self.aws, &self.selection, &self.team)?;
                report.retained_artifact_prefixes =
                    self.cleanup_cluster_artifacts(deployment, delete_data)?;
                report.shared_backend_preserved = true;
                return Ok(report);
            }
            if self.runtime.monotonic() >= deadline {
                return Ok(report);
            }
            self.pause(deadline)?;
        }
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.remove_stack")
    )]
    fn remove_stack(&mut self) -> Result<()> {
        if self.stack_missing {
            return Ok(());
        }
        let mut progress = || {
            pulse(
                &self.aws,
                &self.team,
                &mut self.lease,
                &self.cancel,
                &mut self.heartbeat,
                &self.state_root,
                &self.runtime,
            )
        };
        self.client.remove_stack(&mut progress)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.live_backend.release")
    )]
    fn release(&mut self) -> Result<()> {
        crate::pulumi_process::ensure_cleanup(&self.client.workspace.work_dir)?;
        if let Some(handle) = self.lease.as_ref() {
            aws::release_lease(
                &S3Metadata::new(&self.aws, &self.team)?,
                handle,
                self.runtime.unix_time()?,
            )?;
            self.lease = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

fn aws_error(error: &eyre::Report, code: &str) -> bool {
    error
        .downcast_ref::<aws::AwsApiError>()
        .is_some_and(|error| error.code == code)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.validate_host_request")
)]
pub fn validate_host_request(api: &dyn AwsApi, spec: &FoundationSpec) -> Result<()> {
    spec.validate()?;
    let response = api.call(
        "ec2",
        "describe-images",
        json!({"ImageIds":[spec.ami_id],"Owners":["amazon"]}),
        &[],
    )?;
    let images = array(&response, "Images")?;
    ensure!(
        images.len() == 1,
        "select one available Amazon Linux 2023 AMI"
    );
    let image = &images[0];
    ensure!(
        image["ImageId"] == spec.ami_id
            && image["Architecture"] == "x86_64"
            && image["State"] == "available"
            && image["RootDeviceType"] == "ebs"
            && image["VirtualizationType"] == "hvm"
            && image["Name"]
                .as_str()
                .is_some_and(|name| name.starts_with("al2023-ami-")),
        "foundation requires an available Amazon-owned AL2023 x86-64 HVM/EBS AMI"
    );
    let response = api.call(
        "ec2",
        "describe-availability-zones",
        json!({"ZoneNames":[spec.availability_zone]}),
        &[],
    )?;
    let zones = array(&response, "AvailabilityZones")?;
    ensure!(
        zones.len() == 1
            && zones[0]["ZoneName"] == spec.availability_zone
            && zones[0]["RegionName"] == spec.scope.region
            && zones[0]["State"] == "available",
        "selected availability zone is unavailable or in another region"
    );
    let response = api.call("ec2", "describe-instance-type-offerings", json!({"LocationType":"availability-zone",
        "Filters":[{"Name":"location","Values":[spec.availability_zone]}, {"Name":"instance-type","Values":[spec.size.allocation().instance]}]}), &[])?;
    ensure!(
        array(&response, "InstanceTypeOfferings")?
            .iter()
            .any(
                |offer| offer["InstanceType"] == spec.size.allocation().instance
                    && offer["Location"] == spec.availability_zone
            ),
        "selected size is not offered in this availability zone"
    );
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHealth {
    pub schema_version: u32,
    pub network_id: Uuid,
    pub status: String,
    pub chain_mounted: bool,
    pub docker_active: bool,
    pub ssm_active: bool,
    pub effective_memory_bytes: u64,
    pub application_memory_bytes: u64,
    pub visible_cpus: u32,
    pub visible_cpu_millis: u32,
    pub application_cpu_millis: u32,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.validate_health")
)]
pub fn validate_health(body: &str, spec: &FoundationSpec) -> Result<HostHealth> {
    ensure!(
        body.len() <= 16 * 1024,
        "health response exceeds size limit"
    );
    let health: HostHealth =
        serde_json::from_str(body).context("invalid foundation health response")?;
    let allocation = spec.size.allocation();
    ensure!(
        health.schema_version == 1
            && health.network_id == spec.network_id
            && health.status == "ready"
            && health.chain_mounted
            && health.docker_active
            && health.ssm_active,
        "foundation host is not ready for this network"
    );
    let available = health
        .effective_memory_bytes
        .checked_sub(u64::from(allocation.host_reserve_gib) * GIB)
        .context("host has insufficient effective memory")?;
    let available = available
        .min(u64::from(allocation.max_node_gib) * GIB)
        .checked_sub(FIXTURE_MEMORY_BYTES)
        .context("host has insufficient memory for the health service")?;
    ensure!(
        health.application_memory_bytes > 0 && health.application_memory_bytes <= available,
        "host application memory exceeds effective capacity or preset"
    );
    ensure!(
        health.visible_cpus > 0
            && health.visible_cpu_millis > 500
            && health.application_cpu_millis > 0
            && health.application_cpu_millis <= health.visible_cpu_millis - 500
            && health.visible_cpu_millis <= allocation.vcpus * 1000
            && u64::from(health.visible_cpu_millis) <= u64::from(health.visible_cpus) * 1000,
        "invalid host CPU budget"
    );
    Ok(health)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("AWS response is missing {key}"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.owned_chain_volume")
)]
fn owned_chain_volume(volume: &Value, deployment: &Deployment) -> Result<bool> {
    if volume.get("Tags").is_none() {
        return Ok(false);
    }
    let tags = array(volume, "Tags")?;
    if let Some(cluster) = &deployment.cluster {
        // A cluster can have several identically scoped disks. Tags alone must
        // never turn an unrecorded disk into a delete-data candidate.
        let Some(outputs) = &deployment.outputs else {
            return Ok(false);
        };
        let topology = cluster.topology()?;
        crate::cluster_infra::validate_node_outputs(&outputs.nodes, &topology)?;
        if outputs
            .lightwallet
            .as_ref()
            .is_some_and(|cache| volume["VolumeId"] == cache.cache_volume_id)
        {
            return owned_lightwallet_cache(volume, deployment);
        }
        let Some(saved) = outputs
            .nodes
            .values()
            .find(|node| volume["VolumeId"] == node.volume_id)
        else {
            return Ok(false);
        };
        let node = topology
            .nodes()
            .into_iter()
            .find(|node| node.node_id == saved.node_id)
            .context("saved volume has an unknown topology node")?;
        let mut expected = vec![
            ("zdn:network-id", deployment.spec.network_id.to_string()),
            ("zdn:team-id", deployment.spec.scope.team_id.clone()),
            ("zdn:managed-by", "zdn".into()),
            ("Name", deployment.spec.resource_name(&node.volume_key)),
            ("zdn:node-id", node.node_id),
        ];
        if deployment.team.deployment.is_some() {
            expected.push(("zdn:bootstrap", deployment.team.bootstrap_id.to_string()));
        }
        let owned = expected.iter().all(|(key, value)| {
            tags.iter()
                .any(|tag| tag["Key"] == *key && tag["Value"] == *value)
        });
        if owned {
            ensure!(
                volume["AvailabilityZone"] == deployment.spec.availability_zone
                    && volume["Encrypted"] == true,
                "chain volume attributes differ from deployment"
            );
        }
        return Ok(owned);
    }
    let expected = [
        ("zdn:network-id", deployment.spec.network_id.to_string()),
        ("zdn:team-id", deployment.spec.scope.team_id.clone()),
        ("zdn:managed-by", "zdn".into()),
        ("Name", deployment.spec.resource_name("chain-disk")),
    ];
    let Some(outputs) = &deployment.outputs else {
        return Ok(false);
    };
    let owned = expected.iter().all(|(key, value)| {
        tags.iter()
            .any(|tag| tag["Key"] == *key && tag["Value"] == *value)
    });
    if owned {
        ensure!(
            volume["AvailabilityZone"] == deployment.spec.availability_zone
                && volume["Encrypted"] == true,
            "chain volume attributes differ from deployment"
        );
        ensure!(
            volume["VolumeId"] == outputs.chain_volume_id,
            "unexpected second chain volume; inspect retained disks before cleanup"
        );
    }
    Ok(owned)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.validate_cache_outputs")
)]
fn validate_cache_outputs(deployment: &Deployment) -> Result<()> {
    let Some(outputs) = &deployment.outputs else {
        return Ok(());
    };
    let request = deployment
        .cluster
        .as_ref()
        .and_then(|cluster| cluster.lightwallet.as_ref());
    match (request, &outputs.lightwallet) {
        (None, None) => Ok(()),
        (Some(request), Some(cache)) => {
            request.allocation.validate_for(deployment.spec.size)?;
            crate::cluster_infra::validate_lightwallet_outputs(
                cache,
                &deployment.cluster.as_ref().unwrap().topology()?,
                &outputs.nodes,
            )?;
            ensure!(
                cache.cache_size_gib == request.allocation.cache_gib,
                "saved lightwallet cache size differs from the deployment request"
            );
            Ok(())
        }
        _ => bail!("saved lightwallet cache outputs differ from the deployment request"),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.owned_lightwallet_cache")
)]
fn owned_lightwallet_cache(volume: &Value, deployment: &Deployment) -> Result<bool> {
    validate_cache_outputs(deployment)?;
    let Some(cache) = deployment
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.lightwallet.as_ref())
    else {
        return Ok(false);
    };
    if volume["VolumeId"] != cache.cache_volume_id {
        return Ok(false);
    }
    let tags = array(volume, "Tags")?;
    let expected = [
        ("zdn:network-id", deployment.spec.network_id.to_string()),
        ("zdn:team-id", deployment.spec.scope.team_id.clone()),
        ("zdn:managed-by", "zdn".into()),
        ("zdn:bootstrap", deployment.team.bootstrap_id.to_string()),
        ("zdn:node-id", cache.node_id.clone()),
        ("zdn:service", "lightwalletd".into()),
        (
            "Name",
            deployment
                .spec
                .resource_name(crate::cluster_infra::LIGHTWALLET_CACHE_DISK),
        ),
    ];
    let owned = expected.iter().all(|(key, value)| {
        tags.iter().filter(|tag| tag["Key"] == *key).count() == 1
            && tags
                .iter()
                .any(|tag| tag["Key"] == *key && tag["Value"] == *value)
    });
    if owned {
        ensure!(
            volume["AvailabilityZone"] == deployment.spec.availability_zone
                && volume["Encrypted"] == true
                && volume["Size"] == cache.cache_size_gib
                && volume["VolumeType"] == "gp3",
            "lightwallet cache attributes differ from deployment"
        );
    }
    Ok(owned)
}

struct SavedResource<'a> {
    request_key: &'static str,
    id: &'a str,
    absent_error: &'static str,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.inventory_items")
)]
fn inventory_items(response: &Value, list: &str) -> Result<Vec<Value>> {
    let items = array(response, list)?;
    if list == "Reservations" {
        let mut instances = Vec::new();
        for reservation in items {
            instances.extend(array(reservation, "Instances")?.iter().cloned());
        }
        Ok(instances)
    } else {
        Ok(items.clone())
    }
}

fn resource_id<'a>(resource: &'a Value, key: &str) -> Result<&'a str> {
    resource
        .get(key)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .with_context(|| format!("AWS response is missing {key}"))
}

fn inventory_args(operation: &str) -> Vec<String> {
    // Full instance metadata for three nodes exceeds the bounded AWS output
    // capture. Inventory needs only IDs and states, including for saved IDs.
    if operation == "describe-instances" {
        vec![
            "--query".into(),
            "{Reservations: Reservations[].{Instances: Instances[].{InstanceId: InstanceId, State: {Name: State.Name}}}}".into(),
        ]
    } else {
        Vec::new()
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.inventory_resources")
)]
fn inventory_resources<'a>(
    api: &dyn AwsApi,
    operation: &str,
    list: &str,
    id_key: &str,
    tagged: &Value,
    saved: impl IntoIterator<Item = SavedResource<'a>>,
) -> Result<Vec<Value>> {
    let mut resources = inventory_items(tagged, list)?;
    for resource in &resources {
        resource_id(resource, id_key)?;
    }
    // Ownership tags can change or disappear. Saved IDs remain evidence of
    // leftovers; looking them up never grants permission to delete them.
    for saved in saved {
        match api.call(
            "ec2",
            operation,
            json!({saved.request_key:[saved.id]}),
            &inventory_args(operation),
        ) {
            Ok(response) => {
                let known = inventory_items(&response, list)?;
                // EC2 can forget terminated IDs with a successful empty result.
                // Preserve any contradictory tagged evidence, as for NotFound.
                if operation == "describe-instances" && known.is_empty() {
                    continue;
                }
                ensure!(
                    known.len() == 1,
                    "AWS must return one resource for the saved {id_key}"
                );
                ensure!(
                    resource_id(&known[0], id_key)? == saved.id,
                    "AWS returned a different resource than the saved {id_key}"
                );
                resources.retain(|resource| resource[id_key] != saved.id);
                resources.extend(known);
            }
            // Keep any tagged result until a later inventory also shows it
            // absent. Contradictory eventual-consistency reads are not cleanup.
            Err(error) if aws_error(&error, saved.absent_error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(resources)
}

pub fn inventory(api: &dyn AwsApi, deployment: &Deployment) -> Result<CleanupReport> {
    inventory_with_volume_identities(api, deployment, &Default::default())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.inventory_with_volume_identities")
)]
fn inventory_with_volume_identities(
    api: &dyn AwsApi,
    deployment: &Deployment,
    saved_volumes: &std::collections::BTreeMap<String, String>,
) -> Result<CleanupReport> {
    let filters = json!([
        {"Name":"tag:zdn:network-id","Values":[deployment.spec.network_id.to_string()]},
        {"Name":"tag:zdn:team-id","Values":[deployment.spec.scope.team_id]},
        {"Name":"tag:zdn:managed-by","Values":["zdn"]}]);
    let outputs = deployment.outputs.as_ref();
    validate_cache_outputs(deployment)?;
    if let (Some(cluster), Some(outputs)) = (&deployment.cluster, outputs) {
        crate::cluster_infra::validate_node_outputs(&outputs.nodes, &cluster.topology()?)?;
        let first = &outputs.nodes[crate::cluster_infra::PRODUCER_NODE_ID];
        ensure!(
            first.instance_id == outputs.instance_id
                && first.volume_id == outputs.chain_volume_id
                && first.private_ip == outputs.private_ip,
            "first-node outputs differ from foundation compatibility fields"
        );
    }
    // Read each tagged family once, regardless of node count. Exact saved-ID
    // reconciliation below stays authoritative and handles NotFound individually.
    let calls: Vec<_> = [
        "describe-instances", "describe-vpcs", "describe-addresses",
        "describe-subnets", "describe-security-groups", "describe-internet-gateways",
        "describe-route-tables", "describe-nat-gateways", "describe-volumes",
    ].into_iter().map(|operation| crate::aws::AwsCall {
        operation,
        input: json!({if operation == "describe-nat-gateways" { "Filter" } else { "Filters" }:filters}),
        extra_args: inventory_args(operation),
    }).collect();
    let responses = api.batch_call("ec2", &calls)?;
    ensure!(
        responses.len() == calls.len(),
        "incomplete network inventory"
    );
    let tagged: std::collections::BTreeMap<_, _> = calls
        .iter()
        .zip(responses)
        .map(|(call, response)| Ok((call.operation, response?)))
        .collect::<Result<_>>()?;
    let mut report = CleanupReport::default();
    let mut saved_instances: Vec<_> = outputs
        .map(|outputs| SavedResource {
            request_key: "InstanceIds",
            id: &outputs.instance_id,
            absent_error: "InvalidInstanceID.NotFound",
        })
        .into_iter()
        .collect();
    if let Some(outputs) = outputs.filter(|_| deployment.cluster.is_some()) {
        for node in outputs.nodes.values() {
            if node.instance_id == outputs.instance_id {
                continue;
            }
            saved_instances.push(SavedResource {
                request_key: "InstanceIds",
                id: &node.instance_id,
                absent_error: "InvalidInstanceID.NotFound",
            });
        }
    }
    let instances = inventory_resources(
        api,
        "describe-instances",
        "Reservations",
        "InstanceId",
        &tagged["describe-instances"],
        saved_instances,
    )?;
    for instance in instances {
        let state = instance
            .pointer("/State/Name")
            .and_then(Value::as_str)
            .context("AWS response is missing instance state")?;
        ensure!(
            matches!(
                state,
                "pending" | "running" | "shutting-down" | "terminated" | "stopping" | "stopped"
            ),
            "AWS returned an invalid instance state"
        );
        if state != "terminated" {
            report.remaining_resources.push(format!(
                "instance:{}",
                resource_id(&instance, "InstanceId")?
            ));
        }
    }
    for (operation, list, id, saved) in [
        (
            "describe-vpcs",
            "Vpcs",
            "VpcId",
            outputs.map(|outputs| SavedResource {
                request_key: "VpcIds",
                id: &outputs.vpc_id,
                absent_error: "InvalidVpcID.NotFound",
            }),
        ),
        (
            "describe-addresses",
            "Addresses",
            "AllocationId",
            outputs.map(|outputs| SavedResource {
                request_key: "AllocationIds",
                id: &outputs.eip_allocation_id,
                absent_error: "InvalidAllocationID.NotFound",
            }),
        ),
        (
            "describe-subnets",
            "Subnets",
            "SubnetId",
            outputs.map(|outputs| SavedResource {
                request_key: "SubnetIds",
                id: &outputs.private_subnet_id,
                absent_error: "InvalidSubnetID.NotFound",
            }),
        ),
        (
            "describe-security-groups",
            "SecurityGroups",
            "GroupId",
            outputs.map(|outputs| SavedResource {
                request_key: "GroupIds",
                id: &outputs.security_group_id,
                absent_error: "InvalidGroup.NotFound",
            }),
        ),
        (
            "describe-internet-gateways",
            "InternetGateways",
            "InternetGatewayId",
            None,
        ),
        ("describe-route-tables", "RouteTables", "RouteTableId", None),
    ] {
        for value in inventory_resources(api, operation, list, id, &tagged[operation], saved)? {
            report
                .remaining_resources
                .push(format!("{id}:{}", resource_id(&value, id)?));
        }
    }
    let nats = inventory_resources(
        api,
        "describe-nat-gateways",
        "NatGateways",
        "NatGatewayId",
        &tagged["describe-nat-gateways"],
        outputs.map(|outputs| SavedResource {
            request_key: "NatGatewayIds",
            id: &outputs.nat_gateway_id,
            absent_error: "NatGatewayNotFound",
        }),
    )?;
    for nat in nats {
        let state = nat["State"]
            .as_str()
            .context("AWS response is missing NAT state")?;
        ensure!(
            matches!(
                state,
                "pending" | "failed" | "available" | "deleting" | "deleted"
            ),
            "AWS returned an invalid NAT state"
        );
        if state != "deleted" {
            report
                .remaining_resources
                .push(format!("nat:{}", resource_id(&nat, "NatGatewayId")?));
        }
    }
    let mut saved_disks: Vec<_> = outputs
        .map(|outputs| SavedResource {
            request_key: "VolumeIds",
            id: &outputs.chain_volume_id,
            absent_error: "InvalidVolume.NotFound",
        })
        .into_iter()
        .collect();
    if let Some(outputs) = outputs.filter(|_| deployment.cluster.is_some()) {
        for node in outputs.nodes.values() {
            if node.volume_id == outputs.chain_volume_id {
                continue;
            }
            saved_disks.push(SavedResource {
                request_key: "VolumeIds",
                id: &node.volume_id,
                absent_error: "InvalidVolume.NotFound",
            });
        }
        if let Some(cache) = &outputs.lightwallet {
            saved_disks.push(SavedResource {
                request_key: "VolumeIds",
                id: &cache.cache_volume_id,
                absent_error: "InvalidVolume.NotFound",
            });
        }
    }
    if deployment.outputs.is_none() {
        for id in saved_volumes.values() {
            saved_disks.push(SavedResource {
                request_key: "VolumeIds",
                id,
                absent_error: "InvalidVolume.NotFound",
            });
        }
    }
    let volumes = inventory_resources(
        api,
        "describe-volumes",
        "Volumes",
        "VolumeId",
        &tagged["describe-volumes"],
        saved_disks,
    )?;
    for volume in &volumes {
        let id = resource_id(volume, "VolumeId")?;
        let state = volume["State"]
            .as_str()
            .context("AWS response is missing volume state")?;
        ensure!(
            matches!(
                state,
                "creating" | "available" | "in-use" | "deleting" | "deleted" | "error"
            ),
            "AWS returned an invalid volume state"
        );
        if state == "deleted" {
            continue;
        }
        if (owned_chain_volume(volume, deployment)?
            || destroy::owned_recorded_volume(volume, deployment, saved_volumes)?)
            && state == "available"
            && array(volume, "Attachments")?.is_empty()
        {
            report.retained_volumes.push(id.into());
        } else {
            report.remaining_resources.push(format!("volume:{id}"));
        }
    }
    for (operation, key, purpose) in [
        ("get-role", "RoleName", "host-role"),
        (
            "get-instance-profile",
            "InstanceProfileName",
            "host-profile",
        ),
    ] {
        let name = deployment.spec.resource_name(purpose);
        match api.call("iam", operation, json!({key:name}), &[]) {
            Ok(_) => report.remaining_resources.push(format!("{key}:{name}")),
            Err(error) if aws_error(&error, "NoSuchEntity") => {}
            Err(error) => return Err(error),
        }
    }
    report.remaining_resources.sort();
    report.remaining_resources.dedup();
    report.retained_volumes.sort();
    report.retained_volumes.dedup();
    Ok(report)
}
