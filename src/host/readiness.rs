//! Native bootstrap/readiness gate, adapted from retired runner.py.
//!
//! Prerequisites (not established here): caller-authenticated spec, freshly
//! verified mounted identity, pinned helper/artifacts, and stable root-owned
//! ancestors for all supplied paths/directories. Retain the installation guard
//! and one action-owned Executor throughout. This does not install or activate.

use std::{
    ffi::OsString,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use eyre::{ensure, Result};
use nix::errno::Errno;
use serde_json::{json, Value};

use super::{
    capacity::{self, CgroupScope},
    command::{Executor, HostCommand},
    container,
    files::Directory,
    producer,
    volume::Installation,
    HostInstallSpec,
};

/// Explicit trusted inputs; none of these pathnames are discovered from output.
/// `kernel_root` is the trusted live kernel tree (`/`) or an explicit fixture,
/// never a previously collected capacity snapshot. `node` must be reopened
/// after verified mounting. Path ancestors must remain stable for the action.
pub struct Config<'a> {
    /// Original immutable installation; image revisions never alter its hash.
    pub spec: &'a HostInstallSpec,
    /// Caller-authenticated selected image, separately pinned from installation.
    pub image: &'a str,
    pub installation: &'a Installation<'a>,
    pub node: &'a Directory,
    pub helper: &'a Path,
    pub manifest: &'a Path,
    pub bundle: &'a Path,
    pub cookie: &'a Path,
    pub producer_state: &'a Path,
    pub systemctl: &'a Path,
    pub docker: &'a Path,
    pub kernel_root: &'a Path,
}

impl Config<'_> {
    fn validate(&self) -> Result<String> {
        ensure!(
            [
                self.helper,
                self.manifest,
                self.bundle,
                self.cookie,
                self.producer_state,
                self.systemctl,
                self.docker,
                self.kernel_root
            ]
            .iter()
            .all(|path| path.is_absolute()),
            "host readiness paths must be absolute"
        );
        self.spec.validate_image(self.image)?;
        self.installation.verify_spec(self.spec)
    }
}

/// Missing is false; malformed, unsafe or foreign markers fail closed. Legacy
/// installs deliberately ignore markers and never gain scheduling on upgrade.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.readiness.bootstrap_completed")
)]
pub fn bootstrap_completed(config: &Config<'_>) -> Result<bool> {
    config.validate()?;
    if config.spec.block_interval_seconds.is_none() {
        return Ok(false);
    }
    match config.node.read("bootstrap-complete.json", 8192) {
        Ok(bytes) => {
            ensure!(
                bytes == config.installation.identity(),
                "bootstrap completion belongs to another installation"
            );
            Ok(true)
        }
        Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Observe-only (`bootstrap=false`) never submits seeds or publishes completion.
/// A retained completion skips seeds only, never authenticated fresh RPC/rules.
/// Helper diagnostics are intentionally discarded, including JSON parser details.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.readiness.readiness")
)]
pub fn readiness(
    config: &Config<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    bootstrap: bool,
) -> Result<Value> {
    let digest = config.validate()?;
    let bootstrap = bootstrap && !bootstrap_completed(config)?;
    if bootstrap {
        producer::require_stopped(config.spec, config.systemctl, executor, cancelled)?;
    }
    let endpoint = config.spec.runtime_options()?.rpc_listen_addr;
    let mut common: Vec<OsString> = vec![
        "--manifest".into(),
        config.manifest.into(),
        "--rpc-endpoint".into(),
        endpoint.into(),
        "--cookie-file".into(),
        config.cookie.into(),
        "--request-timeout-secs".into(),
        "10".into(),
    ];
    let mut run = |action: &str, common: &[OsString], extra: &[OsString], budget| {
        let mut args = vec!["chain".into(), action.into()];
        args.extend_from_slice(common);
        args.extend_from_slice(extra);
        executor.execute(
            HostCommand {
                program: config.helper,
                args: &args,
                stdin: None,
                timeout: Duration::from_secs(budget),
                allowed: &[0],
            },
            cancelled,
        )
    };
    {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.readiness.wait_rpc").entered();
        run(
            "wait-rpc",
            &common,
            &["--deadline-secs".into(), "60".into()],
            70,
        )?;
    }
    common.extend(["--deadline-secs".into(), "180".into()]);
    if bootstrap {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.readiness.bootstrap").entered();
        run(
            "bootstrap",
            &common,
            &[
                "--bundle".into(),
                config.bundle.into(),
                "--producer-stopped".into(),
            ],
            200,
        )?;
    }
    let output = {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.readiness.verify").entered();
        run(
            "readiness",
            &common,
            &["--role".into(), config.spec.role.clone().into()],
            200,
        )?
    };
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| eyre::eyre!("unexpected readiness schema"))?;
    ensure!(
        report.get("launchReady") == Some(&Value::Bool(false)),
        "unexpected readiness schema"
    );
    ensure!(!cancelled.load(Ordering::Relaxed), "host command cancelled");
    if bootstrap && config.spec.block_interval_seconds.is_some() {
        config.node.publish(
            "bootstrap-complete.json",
            config.installation.identity(),
            0o600,
        )?;
    }
    let resources = capacity::observe(config.kernel_root, CgroupScope::CurrentAndAncestors)?;
    let limits = container::running_limits(
        config.spec,
        config.image,
        &resources,
        config.docker,
        executor,
        cancelled,
    )?;
    let producer = producer::observe(
        config.spec,
        config.node,
        config.producer_state,
        config.systemctl,
        executor,
        cancelled,
        false,
    )?;
    ensure!(!cancelled.load(Ordering::Relaxed), "host command cancelled");
    Ok(json!({
        "apiVersion": "zdn-host-observation/v1alpha1", "nodeId": config.spec.node_id,
        "installSha256": digest, "status": "ready", "deploymentId": config.spec.deployment_id,
        "consensusFingerprint": config.spec.consensus_fingerprint,
        "configSha256": config.spec.config_sha256, "image": config.image,
        "effectiveLimits": limits, "readiness": report, "paymentQualification": "pending",
        "launchReady": false, "scheduledProducer": producer.scheduled_producer,
        "producer": producer.producer,
    }))
}
