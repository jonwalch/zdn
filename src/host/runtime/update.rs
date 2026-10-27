//! Forward-only updates of an already native installation. No legacy adoption,
//! unit replacement, database rollback or new producer authorization is allowed.
//! Tools, stable root-controlled ancestors and a consistent kernel/daemon view
//! remain trusted. Offline alternate roots are fixture inputs, not namespaces.

use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use eyre::{ensure, ContextCompat, Result};
use serde_json::Value;

use super::{
    control::{self, Config},
    install,
    revision::{self, Journal, Phase, Request, Snapshot},
    revision_delivery,
};
use crate::host::{
    command::{Executor, HostCommand},
    container, firewall, inputs, producer, readiness,
    volume::{self, Installation},
};

pub const PROTOCOL: &str = revision::EXECUTION_PROTOCOL;

/// The CLI authenticates the fixed original manifest and actual running inode;
/// a request cannot select another helper or grant a legacy conversion.
pub fn execute(path: &Path, bytes: &[u8], cancelled: &AtomicBool) -> Result<Value> {
    (|| {
        let (original, config) = control::authenticated(path)?;
        let request = Request::from_slice(bytes)?;
        ensure!(
            request.original.bytes()? == original.bytes()?,
            "native update manifest differs"
        );
        dispatch(&request, config, cancelled)
    })()
    .map_err(|_: eyre::Report| eyre::eyre!("native image update failed"))
}

/// Retains separate update serialization while releasing install.lock for node
/// stop/start children. Every external command shares one action deadline;
/// sixty seconds of that deadline are reserved for failure-side producer stop.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.update.dispatch")
)]
pub fn dispatch(request: &Request, config: Config<'_>, cancelled: &AtomicBool) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(4800);
    request.bytes()?;
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "native update cancelled"
    );
    let original = &request.original;
    let spec = &original.spec;
    ensure!(
        spec.block_interval_seconds.is_some(),
        "native update requires durable scheduled bootstrap completion"
    );
    let executable = config.executable(original)?;
    let metadata = config.open("/etc/zdn")?;
    ensure!(
        metadata.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
            == original.bytes()?,
        "native update intent differs"
    );
    ensure!(
        metadata.read("identity.json", 8192)? == volume::identity(spec)?,
        "native update identity differs"
    );
    let _update_lock = metadata.lock("native-update.lock")?;
    let mut installation = Some(Installation::acquire(&metadata, spec)?);
    let commands = metadata.ensure_directory("commands", 0o700)?;
    commands.ensure_directory("image-update", 0o700)?;
    commands.ensure_directory("image-update-cleanup", 0o700)?;
    let mut executor = Executor::new(
        executable.clone(),
        config.path("/etc/zdn/commands/image-update"),
        spec.helper.region.clone(),
        deadline - Duration::from_secs(60),
    )?;
    let systemctl = config.tool("systemctl")?;
    let docker = config.tool("docker")?;
    verify_units(&config, original, &systemctl, &mut executor, cancelled)?;
    config.mounted(
        original,
        installation.as_ref().unwrap().identity(),
        &mut executor,
        cancelled,
        false,
    )?;
    let node = config.open(&spec.node_root())?;
    ensure!(
        node.read("bootstrap-complete.json", 8192)? == installation.as_ref().unwrap().identity(),
        "native update requires original bootstrap completion"
    );
    ensure!(
        node.read("zakura.toml", 8 * 1024 * 1024)? == spec.config_toml.as_bytes(),
        "native update node configuration differs"
    );
    inputs::verify(spec, &config.open("/etc/zdn/artifacts")?)?;
    let updates = metadata.ensure_directory(revision::NAMESPACE, 0o700)?;
    let mut state =
        Journal::open(&updates, original, installation.as_mut().unwrap())?.begin(request)?;
    let target = updates.ensure_directory(&request.update_id.to_string(), 0o700)?;
    let result = (|| {
        let mut phase = state.transaction.as_ref().unwrap().phase;
        if phase == Phase::Done {
            // A completed retry is observation only, not another stop/start.
            revision_delivery::verify(request, &target, Some(&docker), &mut executor, cancelled)?;
            ensure!(
                service(&systemctl, "zdn-node.service", &mut executor, cancelled)?,
                "native node is stopped"
            );
            return observe(
                request,
                &config,
                installation.as_ref().unwrap(),
                &mut executor,
                cancelled,
            );
        }
        if phase == Phase::Staging {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.runtime.update.stage").entered();
            let scratch = config.path("/etc/zdn/commands/image-update");
            revision_delivery::stage(
                request,
                &target,
                &scratch,
                &revision_delivery::Tools {
                    aws: config.tool("aws")?,
                    docker: docker.clone(),
                },
                &mut executor,
                cancelled,
            )?;
            state = Journal::open(&updates, original, installation.as_mut().unwrap())?
                .advance(request.update_id, Phase::Stopping)?;
            phase = Phase::Stopping;
        }
        if phase == Phase::Stopping {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.runtime.update.stop").entered();
            drop(installation.take());
            stop_producer(&systemctl, &mut executor, cancelled, spec)?;
            call(
                &systemctl,
                &["stop", "zdn-node.service"],
                150,
                &mut executor,
                cancelled,
            )?;
            installation = Some(Installation::acquire(&metadata, spec)?);
            verify_units(&config, original, &systemctl, &mut executor, cancelled)?;
            ensure!(
                !service(&systemctl, "zdn-node.service", &mut executor, cancelled)?,
                "native node did not stop"
            );
            config.mounted(
                original,
                installation.as_ref().unwrap().identity(),
                &mut executor,
                cancelled,
                false,
            )?;
            let old_image = state
                .active
                .as_ref()
                .map(|r| r.image.image.as_str())
                .unwrap_or(&spec.image);
            container::cleanup(spec, old_image, &docker, &mut executor, cancelled)?;
            Journal::open(&updates, original, installation.as_mut().unwrap())?
                .advance(request.update_id, Phase::Activating)?;
            phase = Phase::Activating;
        }
        revision_delivery::verify(request, &target, Some(&docker), &mut executor, cancelled)?;
        {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.runtime.update.activate").entered();
            if phase == Phase::Activating {
                Journal::open(&updates, original, installation.as_mut().unwrap())?
                    .publish_active(request.update_id)?;
            } else {
                // Recover a ready/released prefix before any further maintenance.
                Journal::open(&updates, original, installation.as_mut().unwrap())?
                    .hold_maintenance(request.update_id)?;
            }
            drop(installation.take());
            call(
                &systemctl,
                &["reset-failed", "zdn-node.service"],
                60,
                &mut executor,
                cancelled,
            )?;
            call(
                &systemctl,
                &["start", "zdn-node.service"],
                650,
                &mut executor,
                cancelled,
            )?;
            // The unchanged node unit Wants the producer. Maintenance forbids its
            // start, but explicitly settle systemd before strict readiness checks.
            stop_producer(&systemctl, &mut executor, cancelled, spec)?;
            installation = Some(Installation::acquire(&metadata, spec)?);
            verify_units(&config, original, &systemctl, &mut executor, cancelled)?;
            ensure!(
                service(&systemctl, "zdn-node.service", &mut executor, cancelled)?,
                "native node did not start"
            );
        }
        {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.runtime.update.readiness").entered();
            observe(
                request,
                &config,
                installation.as_ref().unwrap(),
                &mut executor,
                cancelled,
            )?;
            if phase == Phase::Activating {
                Journal::open(&updates, original, installation.as_mut().unwrap())?
                    .advance(request.update_id, Phase::Ready)?;
            }
        }
        // A systemd prepare child may have remounted storage. Never authorize
        // from a descriptor retained across that child, even after fresh probes.
        let node = config.open(&spec.node_root())?;
        let authorized = producer::authorized(spec, &node)?;
        Journal::open(&updates, original, installation.as_mut().unwrap())?
            .release_maintenance(request.update_id)?;
        if spec.role == "producer" && spec.block_interval_seconds.is_some() && authorized {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.runtime.update.producer_restart").entered();
            producer::start(&systemctl, &mut executor, cancelled)?;
            let until = (Instant::now() + Duration::from_secs(150)).min(executor.work_deadline()?);
            while !producer::observe(
                spec,
                &node,
                &config.path(&format!("{}/producer", spec.node_root())),
                &systemctl,
                &mut executor,
                cancelled,
                true,
            )?
            .scheduled_producer
            {
                ensure!(
                    !cancelled.load(Ordering::Relaxed) && Instant::now() < until,
                    "native producer restart exceeded deadline"
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
        let report = observe(
            request,
            &config,
            installation.as_ref().unwrap(),
            &mut executor,
            cancelled,
        )?;
        Journal::open(&updates, original, installation.as_mut().unwrap())?
            .advance(request.update_id, Phase::Done)?;
        Ok(report)
    })();
    if result.is_err() {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.runtime.update.failure_maintenance").entered();
        // Never undo an active image or erase an uncertain request. If producer
        // release began, re-hold durably before attempting bounded cleanup.
        let current = Snapshot::load(&updates, original)?;
        if let Some(tx) = &current.transaction {
            if tx.phase == Phase::Ready {
                if installation.is_none() {
                    installation = Some(Installation::acquire(&metadata, spec)?);
                }
                Journal::open(&updates, original, installation.as_mut().unwrap())?
                    .hold_maintenance(request.update_id)?;
            }
            if tx.phase != Phase::Done && (current.producer_hold || tx.phase == Phase::Ready) {
                let mut cleanup = Executor::new(
                    executable,
                    config.path("/etc/zdn/commands/image-update-cleanup"),
                    spec.helper.region.clone(),
                    deadline,
                )?;
                stop_producer(&systemctl, &mut cleanup, &AtomicBool::new(false), spec)?;
            }
        }
    }
    result
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.update.observe")
)]
fn observe(
    request: &Request,
    config: &Config<'_>,
    installation: &Installation<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let spec = &request.original.spec;
    config.mounted(
        &request.original,
        installation.identity(),
        executor,
        cancelled,
        false,
    )?;
    let node = config.open(&spec.node_root())?;
    ensure!(
        node.read("bootstrap-complete.json", 8192)? == installation.identity(),
        "native original bootstrap completion differs"
    );
    inputs::verify(spec, &config.open("/etc/zdn/artifacts")?)?;
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        false,
        executor,
        cancelled,
    )?;
    let mut report = readiness::readiness(
        &readiness::Config {
            spec,
            image: &request.image.image,
            installation,
            node: &node,
            helper: &config.path("/etc/zdn/artifacts/zdn"),
            manifest: &config.path("/etc/zdn/artifacts/manifest.json"),
            bundle: &config.path("/etc/zdn/artifacts/chain.tar"),
            cookie: &config.path(&format!("{}/rpc/.cookie", spec.node_root())),
            producer_state: &config.path(&format!("{}/producer", spec.node_root())),
            systemctl: &config.tool("systemctl")?,
            docker: &config.tool("docker")?,
            kernel_root: config.root,
        },
        executor,
        cancelled,
        false,
    )?;
    report["updateId"] = Value::String(request.update_id.to_string());
    ensure!(
        !cancelled.load(Ordering::Relaxed) && Instant::now() < executor.work_deadline()?,
        "native update interrupted"
    );
    Ok(report)
}

fn call(
    systemctl: &Path,
    args: &[&str],
    seconds: u64,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    Ok(executor
        .execute(
            HostCommand {
                program: systemctl,
                args: &args.iter().map(Into::into).collect::<Vec<_>>(),
                stdin: None,
                timeout: Duration::from_secs(seconds),
                allowed: &[0],
            },
            cancelled,
        )?
        .stdout)
}

fn stop_producer(
    systemctl: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    spec: &crate::host::HostInstallSpec,
) -> Result<()> {
    if spec.role == "producer" && spec.block_interval_seconds.is_some() {
        call(
            systemctl,
            &["stop", "zdn-producer.service"],
            35,
            executor,
            cancelled,
        )?;
        producer::require_stopped(spec, systemctl, executor, cancelled)?;
    }
    Ok(())
}

fn verify_units(
    config: &Config<'_>,
    original: &super::Manifest,
    systemctl: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    let (node, producer) = install::units_for(original)?;
    let units = config.open("/etc/systemd/system")?;
    for (name, expected) in [
        ("zdn-node.service", Some(node)),
        ("zdn-producer.service", producer),
    ] {
        if let Some(expected) = expected {
            ensure!(
                units.read(name, 65536)? == expected.as_bytes()
                    && units.regular(name, 65536)?.metadata()?.mode() & 0o7777 == 0o644,
                "native update unit differs"
            );
            service(systemctl, name, executor, cancelled)?;
        } else {
            units.require_absent(name)?;
        }
    }
    Ok(())
}

/// Authenticate the effective unit as well as its current finite state.
fn service(
    systemctl: &Path,
    name: &str,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<bool> {
    let names = [
        "FragmentPath",
        "DropInPaths",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
    ];
    let raw = call(
        systemctl,
        &["show", name, &format!("--property={}", names.join(","))],
        60,
        executor,
        cancelled,
    )?;
    ensure!(
        raw.len() <= 4096 && raw.is_ascii(),
        "native update properties exceed bound"
    );
    let mut properties = BTreeMap::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("invalid native update property")?;
        ensure!(
            names.contains(&key) && properties.insert(key, value).is_none(),
            "unexpected native update property"
        );
    }
    ensure!(
        properties.len() == names.len(),
        "missing native update property"
    );
    ensure!(
        properties["FragmentPath"] == format!("/etc/systemd/system/{name}")
            && properties["DropInPaths"].is_empty()
            && properties["LoadState"] == "loaded",
        "native update effective unit differs"
    );
    let pid = properties["MainPID"];
    ensure!(
        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "invalid native update service PID"
    );
    let pid: u32 = pid.parse()?;
    if properties["ActiveState"] == "active" && properties["SubState"] == "running" && pid > 0 {
        return Ok(true);
    }
    ensure!(
        matches!(properties["ActiveState"], "inactive" | "failed") && pid == 0,
        "native update service is transitioning"
    );
    Ok(false)
}
