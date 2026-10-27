//! Native producer ownership observations and control used by host operations.
//! Callers authenticate the spec/artifacts and mount identity first, and retain
//! root-owned stable directory ancestors and the state path for the whole action.
//! These point-in-time observations are not a lock or launch authorization.

use std::{
    collections::BTreeMap, io::ErrorKind, path::Path, sync::atomic::AtomicBool, time::Duration,
};

use eyre::{ensure, ContextCompat, Result};
use serde::Serialize;
use serde_json::json;

use super::{
    command::{Executor, HostCommand},
    files::Directory,
    HostInstallSpec,
};
use crate::chain::producer::{read_status, ProducerIdentity, ProducerPhase, ProducerStatus};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub scheduled_producer: bool,
    pub producer: Option<ProducerStatus>,
}

fn unscheduled() -> Observation {
    Observation {
        scheduled_producer: false,
        producer: None,
    }
}

/// Exact Python sorted compact JSON plus LF, including the nested volume identity.
pub fn authorization(spec: &HostInstallSpec) -> Result<Vec<u8>> {
    let value = json!({
        "apiVersion": "zdn-producer-authorization/v1alpha1",
        "identity": {
            "apiVersion": "zdn-host-volume/v1alpha1",
            "deploymentId": spec.deployment_id,
            "nodeId": spec.node_id,
            "volumeId": spec.volume_id,
            "consensusFingerprint": spec.consensus_fingerprint,
            "installSha256": spec.install_sha256()?,
        },
        "intervalSeconds": spec.block_interval_seconds,
    });
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn missing(error: &eyre::Report) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == ErrorKind::NotFound)
        || error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
}

/// Absence is false; unsafe, malformed or foreign saved bytes are errors.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.producer.authorized")
)]
pub fn authorized(spec: &HostInstallSpec, node: &Directory) -> Result<bool> {
    let bytes = match node.read("producer-authorized.json", 8192) {
        Ok(bytes) => bytes,
        Err(error) if missing(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    ensure!(
        spec.block_interval_seconds.is_some()
            && spec.role == "producer"
            && spec.node_id == "node-1",
        "this host cannot own the block controller"
    );
    ensure!(
        bytes == authorization(spec)?,
        "producer authorization differs from installation"
    );
    Ok(true)
}

struct Service {
    active: String,
    sub: String,
    pid: u32,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.producer.service")
)]
fn service(systemctl: &Path, executor: &mut Executor, cancelled: &AtomicBool) -> Result<Service> {
    // Native bounded adaptation: four short ASCII properties fit in 4 KiB;
    // MainPID must fit the journal's u32 rather than Python's unbounded integer.
    let args = [
        "show",
        "zdn-producer.service",
        "--property=LoadState,ActiveState,SubState,MainPID",
    ]
    .map(Into::into);
    let output = executor.execute(
        HostCommand {
            program: systemctl,
            args: &args,
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0, 1],
        },
        cancelled,
    )?;
    ensure!(
        output.stdout.len() <= 4096 && output.stdout.is_ascii(),
        "invalid producer service observation"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let mut values = BTreeMap::new();
    let lines: Vec<_> = text.lines().collect();
    ensure!(lines.len() == 4, "invalid producer service observation");
    for line in lines {
        let (key, value) = line
            .split_once('=')
            .context("invalid producer service observation")?;
        ensure!(
            ["LoadState", "ActiveState", "SubState", "MainPID"].contains(&key)
                && values.insert(key, value).is_none(),
            "invalid producer service observation"
        );
    }
    let pid = values["MainPID"];
    ensure!(
        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "invalid producer service observation"
    );
    ensure!(
        (output.exit_code == 0 && values["LoadState"] == "loaded")
            || (values["LoadState"] == "not-found"
                && values["ActiveState"] == "inactive"
                && values["SubState"] == "dead"
                && pid == "0"),
        "producer service could not be inspected"
    );
    Ok(Service {
        active: values["ActiveState"].into(),
        sub: values["SubState"].into(),
        pid: pid.parse()?,
    })
}

/// Called only after durable authorization and fresh readiness. Clear the
/// systemd failure counter only for a stopped controller, never its journal.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.producer.start")
)]
pub(super) fn start(
    systemctl: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    let run = |executor: &mut Executor, action: &str, seconds| {
        executor.execute(
            HostCommand {
                program: systemctl,
                args: &[action.into(), "zdn-producer.service".into()],
                stdin: None,
                timeout: Duration::from_secs(seconds),
                allowed: &[0],
            },
            cancelled,
        )
    };
    run(executor, "enable", 60)?;
    let service = service(systemctl, executor, cancelled)?;
    if matches!(service.active.as_str(), "inactive" | "failed") && service.pid == 0 {
        run(executor, "reset-failed", 60)?;
    }
    run(executor, "start", 150)?;
    Ok(())
}

/// Trusted state path must name this node's producer directory, not caller data.
/// Starting tolerates only unavailable files or transient ownership/phase, never
/// malformed journals or identity errors. Unlike the Python helper's broad exit
/// code 1, direct read_status preserves all non-NotFound validation failures.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.producer.observe")
)]
pub fn observe(
    spec: &HostInstallSpec,
    node: &Directory,
    state: &Path,
    systemctl: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    starting: bool,
) -> Result<Observation> {
    if spec.block_interval_seconds.is_none() {
        return Ok(unscheduled());
    }
    ensure!(state.is_absolute(), "producer state path must be absolute");
    let service = service(systemctl, executor, cancelled)?;
    let running = service.active == "active" && service.sub == "running" && service.pid > 0;
    if spec.role != "producer" {
        ensure!(
            !running && !matches!(service.active.as_str(), "activating" | "reloading"),
            "follower has an unexpected block controller"
        );
        ensure!(
            !authorized(spec, node)?,
            "follower has producer authorization"
        );
        return Ok(unscheduled());
    }
    if !running {
        return Ok(unscheduled());
    }
    ensure!(
        authorized(spec, node)?,
        "active producer has no saved authorization"
    );
    let identity = ProducerIdentity {
        deployment_id: spec.deployment_id,
        node_id: spec.node_id.clone(),
        consensus_fingerprint: spec.consensus_fingerprint.clone(),
    };
    let report = match read_status(state, &identity) {
        Ok(report) => report,
        Err(error) if starting && missing(&error) => return Ok(unscheduled()),
        Err(error) => return Err(error),
    };
    // read_status validates version/identity and supplies the fixed pending,
    // launchReady=false qualification; there is no subprocess schema to trust.
    // Cadence incompatibility is never a startup grace condition.
    ensure!(
        Some(report.journal.interval_secs) == spec.block_interval_seconds,
        "controller interval differs from running service"
    );
    let owned = report.controller_locked && report.journal.owner_pid == service.pid;
    if starting && !owned {
        return Ok(unscheduled());
    }
    ensure!(owned, "controller owner differs from running service");
    if starting && report.journal.phase == ProducerPhase::Starting {
        return Ok(unscheduled());
    }
    ensure!(
        matches!(
            report.journal.phase,
            ProducerPhase::Waiting | ProducerPhase::Generating
        ),
        "controller is not healthy"
    );
    Ok(Observation {
        scheduled_producer: true,
        producer: Some(report),
    })
}

/// Legacy installs neither inspect nor acquire scheduling by upgrading.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.producer.require_stopped")
)]
pub fn require_stopped(
    spec: &HostInstallSpec,
    systemctl: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    if spec.block_interval_seconds.is_some() {
        let service = service(systemctl, executor, cancelled)?;
        ensure!(
            matches!(service.active.as_str(), "inactive" | "failed") && service.pid == 0,
            "block controller must stop before node bootstrap"
        );
    }
    Ok(())
}
