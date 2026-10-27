//! Privileged native gateway wiring from client_gateway/install.py. An exact
//! native host installation is required; legacy Python hosts are not adopted.
//! The root-only CLI fixes the manifest and endpoint. Explicit fixture roots,
//! owners and loopback ports below are trusted caller inputs, not namespaces.
//! Daemon startup only reads trusted files: it neither takes the installer lock
//! held by its activating parent nor writes through its read-only /etc sandbox.

use std::{
    collections::BTreeMap,
    fs::File,
    net::{SocketAddr, TcpListener},
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
    Manifest,
};
use crate::{
    client_gateway::{native, runtime, ENDPOINT, UNIT_NAME},
    host::{
        capacity::{self, CgroupScope},
        command::{Executor, HostCommand},
        container, firewall, inputs, readiness,
        volume::{self, Installation},
    },
};

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum Operation {
    Install,
    Observe,
    Serve,
}

pub fn execute(path: &Path, operation: Operation, stop: &AtomicBool) -> Result<Option<Value>> {
    (|| {
        let (manifest, config) = control::authenticated(path)?;
        dispatch(&manifest, config, operation, ENDPOINT.parse()?, stop)
    })()
    .map_err(|_: eyre::Report| eyre::eyre!("native gateway operation failed"))
}

/// The listener is preopened for offline loopback fixtures; production binds
/// only the fixed participant endpoint after root/manifest/inode authentication.
pub fn serve(
    manifest: &Manifest,
    config: Config<'_>,
    listener: TcpListener,
    stop: &AtomicBool,
) -> Result<()> {
    config.executable(manifest)?;
    let metadata = config.open("/etc/zdn")?;
    ensure!(
        metadata.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
            == manifest.bytes()?,
        "native host intent differs"
    );
    let anchor = File::from(nix::fcntl::open(
        config.root,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_DIRECTORY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?);
    runtime::serve(
        listener,
        runtime::Config {
            anchor,
            identity_paths: [
                "etc/zdn/identity.json".into(),
                "var/lib/zdn/.zdn-volume.json".into(),
            ],
            cookie_path: format!(
                "{}/rpc/.cookie",
                manifest.spec.node_root().trim_start_matches('/')
            )
            .into(),
            root_uid: config.owner,
            node_uid: config.node_owner,
            identity: serde_json::from_slice(&volume::identity(&manifest.spec)?)?,
            service_sha256: native::service_sha256(manifest)?,
            upstream: native::upstream(manifest)?,
        },
        stop,
    )
}

/// Install or observe only an already installed native node. All finite work
/// shares one 340s deadline and the original installation lock. Holding that
/// lock across gateway activation is safe: its daemon is read-only and does
/// not need it. Health never bootstraps a node or authorizes block production.
pub fn dispatch(
    manifest: &Manifest,
    config: Config<'_>,
    operation: Operation,
    endpoint: SocketAddr,
    stop: &AtomicBool,
) -> Result<Option<Value>> {
    #[cfg(feature = "profiling")]
    let dispatch = match operation {
        Operation::Install => tracing::info_span!("host.runtime.gateway.install"),
        Operation::Observe => tracing::info_span!("host.runtime.gateway.observe"),
        Operation::Serve => tracing::info_span!("host.runtime.gateway.serve_preflight"),
    }
    .entered();
    let deadline = Instant::now() + Duration::from_secs(340);
    ensure!(!stop.load(Ordering::Relaxed), "gateway operation cancelled");
    ensure!(
        endpoint.ip() == std::net::Ipv4Addr::LOCALHOST && endpoint.port() != 0,
        "invalid gateway endpoint"
    );
    if operation == Operation::Serve {
        #[cfg(feature = "profiling")]
        drop(dispatch);
        serve(manifest, config, TcpListener::bind(endpoint)?, stop)?;
        return Ok(None);
    }
    let executable = config.executable(manifest)?;
    let metadata = config.open("/etc/zdn")?;
    ensure!(
        metadata.read("identity.json", 8192)? == volume::identity(&manifest.spec)?,
        "native host identity differs"
    );
    ensure!(
        metadata.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
            == manifest.bytes()?,
        "native host intent differs"
    );
    let installation = Installation::acquire(&metadata, &manifest.spec)?;
    let snapshot = super::revision::Snapshot::from_installation(&metadata, manifest)?;
    let selected = snapshot.as_ref().and_then(|state| state.active.as_ref());
    let image = selected
        .map(|request| request.image.image.as_str())
        .unwrap_or(&manifest.spec.image);
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("gateway", 0o700)?;
    let mut executor = Executor::new(
        executable,
        config.path("/etc/zdn/commands/gateway"),
        manifest.spec.helper.region.clone(),
        deadline,
    )?;
    config.mounted(
        manifest,
        installation.identity(),
        &mut executor,
        stop,
        false,
    )?;
    let artifacts = config.open("/etc/zdn/artifacts")?;
    inputs::verify(&manifest.spec, &artifacts)?;
    if let Some(request) = selected {
        let selected = config.open(&format!(
            "/etc/zdn/{}/{}",
            super::revision::NAMESPACE,
            request.update_id
        ))?;
        super::revision_delivery::verify(request, &selected, None, &mut executor, stop)?;
    }
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        false,
        &mut executor,
        stop,
    )?;
    let docker = config.tool("docker")?;
    let resources = capacity::observe(config.root, CgroupScope::CurrentAndAncestors)?;
    container::running_limits(
        &manifest.spec,
        image,
        &resources,
        &docker,
        &mut executor,
        stop,
    )?;
    // Never replace a historical gateway, even after its unit was removed.
    match config.open("/usr/local/libexec") {
        Ok(directory) => {
            directory.require_absent("zdn-client-rpc.py")?;
            directory.require_absent("zdn-client-rpc-install.py")?;
        }
        Err(error)
            if error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(error),
    }
    let units = config.open("/etc/systemd/system")?;
    let unit = native::unit(manifest)?;
    let systemctl = config.tool("systemctl")?;
    if operation == Operation::Install {
        units.publish(UNIT_NAME, unit.as_bytes(), 0o644)?;
        call(&systemctl, &["daemon-reload"], &mut executor, stop)?;
    } else {
        ensure!(
            units.read(UNIT_NAME, 16384)? == unit.as_bytes(),
            "native gateway unit differs"
        );
    }
    ensure!(
        units.regular(UNIT_NAME, 16384)?.metadata()?.mode() & 0o7777 == 0o644,
        "native gateway unit permissions differ"
    );
    let properties = properties(
        &systemctl,
        &["FragmentPath", "DropInPaths", "LoadState"],
        &mut executor,
        stop,
    )?;
    ensure!(
        properties["FragmentPath"] == "/etc/systemd/system/zdn-client-rpc.service"
            && properties["DropInPaths"].is_empty()
            && properties["LoadState"] == "loaded",
        "gateway unit load path differs"
    );
    if operation == Operation::Install {
        let node = config.open(&manifest.spec.node_root())?;
        readiness::readiness(
            &readiness::Config {
                spec: &manifest.spec,
                image,
                installation: &installation,
                node: &node,
                helper: &config.path("/etc/zdn/artifacts/zdn"),
                manifest: &config.path("/etc/zdn/artifacts/manifest.json"),
                bundle: &config.path("/etc/zdn/artifacts/chain.tar"),
                cookie: &config.path(&format!("{}/rpc/.cookie", manifest.spec.node_root())),
                producer_state: &config.path(&format!("{}/producer", manifest.spec.node_root())),
                systemctl: &systemctl,
                docker: &docker,
                kernel_root: config.root,
            },
            &mut executor,
            stop,
            false,
        )?;
        call(&systemctl, &["enable", UNIT_NAME], &mut executor, stop)?;
    }
    #[cfg(feature = "profiling")]
    let _health = tracing::info_span!("host.runtime.gateway.health_gate").entered();
    let was_active = active(&systemctl, &mut executor, stop)?;
    if !was_active && operation == Operation::Observe {
        return Ok(Some(native::observation(manifest, "stopped")?));
    }
    let until = if was_active {
        executor.work_deadline()?
    } else {
        call(
            &systemctl,
            &["reset-failed", UNIT_NAME],
            &mut executor,
            stop,
        )?;
        call(&systemctl, &["start", UNIT_NAME], &mut executor, stop)?;
        (Instant::now() + Duration::from_secs(20)).min(executor.work_deadline()?)
    };
    loop {
        let report = (|| {
            ensure!(
                active(&systemctl, &mut executor, stop)?,
                "gateway service is not active"
            );
            let report = runtime::health(endpoint, until, stop)?;
            let parsed = native::validate_observation(&report, manifest)?;
            ensure!(parsed.status == "ready", "gateway is not ready");
            Ok(report)
        })();
        if was_active {
            return report.map(Some);
        }
        if let Ok(report) = report {
            return Ok(Some(report));
        }
        ensure!(
            !stop.load(Ordering::Relaxed) && Instant::now() < until,
            "gateway startup health unavailable"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn call(
    systemctl: &Path,
    args: &[&str],
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<Vec<u8>> {
    let output = executor.execute(
        HostCommand {
            program: systemctl,
            args: &args.iter().map(Into::into).collect::<Vec<_>>(),
            stdin: None,
            timeout: Duration::from_secs(30),
            allowed: &[0],
        },
        stop,
    )?;
    Ok(output.stdout)
}

fn properties(
    systemctl: &Path,
    names: &[&str],
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<BTreeMap<String, String>> {
    let raw = call(
        systemctl,
        &[
            "show",
            UNIT_NAME,
            &format!("--property={}", names.join(",")),
        ],
        executor,
        stop,
    )?;
    ensure!(raw.len() <= 4096, "gateway properties exceed bound");
    let text = std::str::from_utf8(&raw).map_err(|_| eyre::eyre!("invalid gateway properties"))?;
    let mut properties = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line.split_once('=').context("invalid gateway property")?;
        ensure!(
            names.contains(&name)
                && properties
                    .insert(name.to_string(), value.to_string())
                    .is_none(),
            "unexpected gateway property"
        );
    }
    ensure!(properties.len() == names.len(), "missing gateway property");
    Ok(properties)
}

fn active(systemctl: &Path, executor: &mut Executor, stop: &AtomicBool) -> Result<bool> {
    let properties = properties(
        systemctl,
        &["ActiveState", "SubState", "MainPID"],
        executor,
        stop,
    )?;
    let pid = &properties["MainPID"];
    ensure!(
        !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "invalid gateway PID"
    );
    let pid: u32 = pid
        .parse()
        .map_err(|_| eyre::eyre!("invalid gateway PID"))?;
    if matches!(properties["ActiveState"].as_str(), "inactive" | "failed") && pid == 0 {
        return Ok(false);
    }
    ensure!(
        properties["ActiveState"] == "active" && properties["SubState"] == "running" && pid > 0,
        "gateway service state differs"
    );
    Ok(true)
}
