//! Native node launch/observation/cleanup from `runner.py` lines 479–607.
//! Snapshots and launch arguments are not readiness or mount authority. Callers
//! supply authenticated specs, fresh current-and-ancestor capacity observations,
//! an absolute trusted Docker executable and an action-owned command executor.
//! No host runtime selects these operations yet. Cleanup mutates only a freshly
//! inspected exact container ID, never an unverified name or foreign container.

use std::{collections::BTreeSet, path::Path, sync::atomic::AtomicBool, time::Duration};

use eyre::{ensure, ContextCompat, Result};
use serde::Serialize;
use serde_json::{json, Value};

use super::{
    command::{Executor, HostCommand},
    HostInstallSpec,
};
use crate::{image, infra::HostObservation};

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveLimits {
    pub effective_memory_bytes: u64,
    pub visible_cpu_millis: u32,
    pub host_reserve_bytes: u64,
    pub host_reserve_cpu_millis: u32,
    pub node_memory_bytes: u64,
    pub node_cpu_millis: u32,
}

/// Node-specific reserves, not foundation/test-service allocation rules.
pub fn effective_limits(
    spec: &HostInstallSpec,
    observation: &HostObservation,
) -> Result<EffectiveLimits> {
    spec.validate()?;
    let memory = observation
        .ancestor_memory_limits_bytes
        .iter()
        .copied()
        .fold(observation.mem_total_bytes, u64::min);
    // The historical node uses process affinity, not the online CPU count.
    let cpu = observation
        .affinity_cpu_count
        .checked_mul(1000)
        .context("CPU count overflow")?;
    let cpu = observation
        .ancestor_cpu_quota_millis
        .iter()
        .copied()
        .fold(cpu, u32::min);
    let node_memory = memory
        .checked_sub(spec.host_reserve_bytes)
        .context("effective memory cannot fit host reserve")?
        .min(spec.memory_bytes);
    let node_cpu = cpu
        .checked_sub(250)
        .context("effective CPU cannot fit host reserve")?
        .min(spec.cpu_millis);
    ensure!(
        node_memory >= 1024 * 1024 * 1024 && node_cpu >= 250,
        "effective host resources do not fit node and reserved host budget"
    );
    Ok(EffectiveLimits {
        effective_memory_bytes: memory,
        visible_cpu_millis: cpu,
        host_reserve_bytes: spec.host_reserve_bytes,
        host_reserve_cpu_millis: 250,
        node_memory_bytes: node_memory,
        node_cpu_millis: node_cpu,
    })
}

fn name(spec: &HostInstallSpec) -> String {
    format!("zdn-{}-{}", spec.deployment_id, spec.node_id)
}

fn node_command(spec: &HostInstallSpec) -> Vec<String> {
    vec![
        "-i".into(),
        format!("PATH={}", image::LAUNCH_PATH),
        format!("HOME={}", image::LAUNCH_HOME),
        image::NODE_BINARY.into(),
        "--config".into(),
        format!("{}/zakura.toml", spec.node_root()),
        "start".into(),
    ]
}

/// Literal argv for an attached Docker client. The caller must verify artifacts,
/// mounts and metadata firewall before execution and retain session ownership.
/// `image` is separately authenticated revision data; never substitute it into
/// `spec`, whose digest remains the original container ownership label.
pub fn arguments(
    spec: &HostInstallSpec,
    image: &str,
    observation: &HostObservation,
) -> Result<Vec<String>> {
    spec.validate_image(image)?;
    let limits = effective_limits(spec, observation)?;
    let root = spec.node_root();
    let mut args = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name(spec),
        "--platform".into(),
        "linux/amd64".into(),
        "--network".into(),
        "host".into(),
        "--user".into(),
        format!("{}:{}", image::RUNTIME_UID, image::RUNTIME_GID),
        "--workdir".into(),
        "/".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--no-healthcheck".into(),
        "--stop-signal".into(),
        "SIGINT".into(),
        "--stop-timeout".into(),
        "60".into(),
        "--pids-limit".into(),
        "1024".into(),
        "--memory".into(),
        limits.node_memory_bytes.to_string(),
        "--memory-swap".into(),
        limits.node_memory_bytes.to_string(),
        "--cpus".into(),
        format!(
            "{}.{:03}",
            limits.node_cpu_millis / 1000,
            limits.node_cpu_millis % 1000
        ),
        "--log-driver".into(),
        "journald".into(),
        "--label".into(),
        format!("zdn.install={}", spec.install_sha256()?),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777".into(),
        "--mount".into(),
        format!("type=bind,src={root},dst={root},readonly"),
    ];
    for child in ["state", "identity", "rpc"] {
        args.extend([
            "--mount".into(),
            format!("type=bind,src={root}/{child},dst={root}/{child}"),
        ]);
    }
    args.extend([
        "--entrypoint".into(),
        image::ENV_ENTRYPOINT.into(),
        image.into(),
    ]);
    args.extend(node_command(spec));
    Ok(args)
}

fn record(spec: &HostInstallSpec, image: &str, raw: &[u8]) -> Result<Value> {
    let records: Vec<Value> =
        serde_json::from_slice(raw).map_err(|_| eyre::eyre!("invalid container inspection"))?;
    ensure!(records.len() == 1, "expected exactly one node container");
    let record = records.into_iter().next().unwrap();
    ensure!(
        record["Name"] == format!("/{}", name(spec))
            && record["Config"]["Image"] == image
            && record["Config"]["Labels"]["zdn.install"] == spec.install_sha256()?,
        "container belongs to a different installation"
    );
    Ok(record)
}

/// Inspect actual node isolation, exact budgets and every durable bind mount.
/// This is a fresh Docker observation only, not authenticated chain readiness.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.container.running_limits")
)]
pub fn running_limits(
    spec: &HostInstallSpec,
    image: &str,
    observation: &HostObservation,
    docker: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<EffectiveLimits> {
    spec.validate_image(image)?;
    let limits = effective_limits(spec, observation)?;
    let args = ["container".into(), "inspect".into(), name(spec).into()];
    let output = executor.execute(
        HostCommand {
            program: docker,
            args: &args,
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    )?;
    let container = record(spec, image, &output.stdout)?;
    let config = &container["Config"];
    let host = &container["HostConfig"];
    ensure!(
        container["State"]["Running"] == true,
        "node container is not running"
    );
    ensure!(
        config["User"] == format!("{}:{}", image::RUNTIME_UID, image::RUNTIME_GID)
            && config["WorkingDir"] == "/"
            && config["Entrypoint"] == json!([image::ENV_ENTRYPOINT])
            && config["Cmd"] == json!(node_command(spec))
            && config["StopSignal"] == "SIGINT"
            && config["Healthcheck"]["Test"] == json!(["NONE"])
            && host["NetworkMode"] == "host"
            && host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host
                .get("CapAdd")
                .is_none_or(|v| v.is_null() || v.as_array().is_some_and(Vec::is_empty))
            && host["CapDrop"] == json!(["ALL"])
            && host["PidsLimit"] == 1024
            && host["PidMode"] == ""
            && host["LogConfig"]["Type"] == "journald"
            && [
                json!(["no-new-privileges"]),
                json!(["no-new-privileges:true"])
            ]
            .contains(&host["SecurityOpt"]),
        "running container has unsafe launch settings"
    );
    ensure!(
        host["Memory"].as_u64() == Some(limits.node_memory_bytes)
            && host["MemorySwap"] == host["Memory"]
            && host["NanoCpus"].as_u64() == Some(u64::from(limits.node_cpu_millis) * 1_000_000),
        "running container resource limits differ from effective host budget"
    );
    let mounts = container["Mounts"]
        .as_array()
        .context("invalid container mounts")?;
    let root = spec.node_root();
    let expected: BTreeSet<_> = [
        root.clone(),
        format!("{root}/state"),
        format!("{root}/identity"),
        format!("{root}/rpc"),
    ]
    .into_iter()
    .collect();
    let mut observed = BTreeSet::new();
    for mount in mounts {
        if mount["Type"] == "tmpfs" && mount["Destination"] == "/tmp" {
            continue;
        }
        let target = mount["Destination"]
            .as_str()
            .context("invalid container mount target")?;
        ensure!(
            mount["Type"] == "bind"
                && expected.contains(target)
                && mount["Source"] == target
                && mount["RW"] == (target != root)
                && observed.insert(target.to_owned()),
            "running container durable mounts differ from installation"
        );
    }
    ensure!(
        observed == expected,
        "running container durable mounts differ from installation"
    );
    Ok(limits)
}

/// Stop/remove only the exact freshly verified container ID, then require a
/// new absence observation. An unsuccessful stop never authorizes force-remove.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.container.cleanup")
)]
pub fn cleanup(
    spec: &HostInstallSpec,
    image: &str,
    docker: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    spec.validate()?;
    spec.validate_image(image)?;
    let mut command = |args: &[&str], timeout, allowed: &[i32]| {
        let args: Vec<_> = args.iter().map(|s| (*s).into()).collect();
        executor.execute(
            HostCommand {
                program: docker,
                args: &args,
                stdin: None,
                timeout: Duration::from_secs(timeout),
                allowed,
            },
            cancelled,
        )
    };
    let filter = format!("name=^/{}$", name(spec));
    let listing = [
        "container",
        "ls",
        "--all",
        "--filter",
        &filter,
        "--format",
        "{{.ID}}",
    ];
    let output = {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.container.cleanup.list").entered();
        command(&listing, 60, &[0])?
    };
    ensure!(output.stdout.is_ascii(), "invalid node container ID");
    let id = std::str::from_utf8(&output.stdout)?.trim();
    if id.is_empty() {
        return Ok(());
    }
    ensure!(
        (12..=64).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "ambiguous old node container"
    );
    let inspected = {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.container.cleanup.inspect").entered();
        command(&["container", "inspect", id], 60, &[0])?
    };
    let old = record(spec, image, &inspected.stdout)?;
    let running = old["State"]["Running"]
        .as_bool()
        .context("invalid container state")?;
    if running {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.container.cleanup.stop").entered();
        command(&["stop", "--time", "60", id], 75, &[0])?;
    }
    {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.container.cleanup.remove").entered();
        command(&["container", "rm", "--force", id], 60, &[0, 1])?;
    }
    #[cfg(feature = "profiling")]
    let _span = tracing::info_span!("host.container.cleanup.absence").entered();
    let remaining = command(&listing, 60, &[0])?;
    ensure!(
        remaining.stdout.trim_ascii().is_empty(),
        "old node container was not removed"
    );
    Ok(())
}
