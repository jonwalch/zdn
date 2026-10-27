//! Opt-in privileged port of lightwallet_service/install.py. No deployment
//! selects this recipe. Alternate anchors are trusted offline fixtures, not a
//! namespace or permission to relax the real BlockDevice boundary.
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use eyre::{ensure, ContextCompat, Result};
use serde_json::{json, Value};

use super::control::Config;
use crate::{
    host::{
        capacity::{self, CgroupScope},
        command::{Executor, HostCommand},
        container,
        files::Directory,
        firewall, inputs, volume,
    },
    lightwallet_service::{
        cache::{self, prepare},
        image_delivery::{self, Artifact},
        native::{self, Manifest, UNIT_NAME},
        render_service, runtime,
    },
};

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum Operation {
    Install,
    Prepare,
    Observe,
    Start,
    Stop,
    Serve,
}

impl Operation {
    fn budget(self) -> u64 {
        match self {
            Self::Install => 2400,
            Self::Prepare | Self::Stop | Self::Serve => 180,
            Self::Observe => 300,
            Self::Start => 500,
        }
    }
}

fn production() -> Result<Config<'static>> {
    ensure!(nix::unistd::Uid::effective().is_root(), "root required");
    ensure!(std::env::consts::ARCH == "x86_64", "x86-64 required");
    Ok(Config {
        root: Path::new("/"),
        owner: 0,
        node_owner: crate::image::RUNTIME_UID,
    })
}

fn running(config: &Config<'_>, manifest: &Manifest, file: &File) -> Result<()> {
    let executable = config.executable(&manifest.node)?;
    let expected = fs::symlink_metadata(executable)?;
    let actual = file.metadata()?;
    ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "running runtime differs"
    );
    Ok(())
}

/// Fixed root/path/owner/tool boundary, with no user endpoint overrides.
pub fn execute(path: &Path, operation: Operation, stop: &AtomicBool) -> Result<Option<Value>> {
    (|| {
        ensure!(
            operation != Operation::Install,
            "install requires canonical stdin"
        );
        let config = production()?;
        ensure!(
            path.parent() == Some(Path::new(native::MANIFEST_DIRECTORY)),
            "invalid role manifest path"
        );
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid manifest name")?;
        let manifest = Manifest::load(&config.open(native::MANIFEST_DIRECTORY)?, name)?;
        running(&config, &manifest, &File::open("/proc/self/exe")?)?;
        dispatch(&manifest, config, operation, stop)
    })()
    .map_err(|_: eyre::Report| eyre::eyre!("native lightwallet operation failed"))
}

pub fn execute_install(stop: &AtomicBool) -> Result<Value> {
    (|| {
        let config = production()?;
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(native::MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let manifest = Manifest::from_slice(&bytes)?;
        install(&manifest, config, File::open("/proc/self/exe")?, stop)
    })()
    .map_err(|_: eyre::Report| eyre::eyre!("native lightwallet installation failed"))
}

/// Offline fixture entry; production supplies /proc/self/exe. This does not
/// deliver a helper: the native node must already pin and own this exact inode.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.lightwallet.install")
)]
pub fn install(
    manifest: &Manifest,
    config: Config<'_>,
    executable: File,
    stop: &AtomicBool,
) -> Result<Value> {
    manifest.validate()?;
    running(&config, manifest, &executable)?;
    dispatch(manifest, config, Operation::Install, stop)?.context("missing install report")
}

fn prerequisites(config: &Config<'_>, manifest: &Manifest, stop: &AtomicBool) -> Result<()> {
    manifest.validate()?;
    ensure!(
        !stop.load(Ordering::Relaxed),
        "lightwallet operation cancelled"
    );
    let executable = config.executable(&manifest.node)?;
    ensure!(
        fs::symlink_metadata(executable)?.mode() & 0o7777 == 0o555,
        "native executable mode differs"
    );
    let etc = config.open("/etc")?;
    ensure!(
        etc.regular("zdn-prerequisites-ready", 33)?
            .metadata()?
            .mode()
            & 0o7777
            == 0o600
            && etc.read("zdn-prerequisites-ready", 33)? == b"zdn-host-prerequisites/v1alpha1\n",
        "invalid prerequisites"
    );
    let node = config.open("/etc/zdn")?;
    ensure!(
        node.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
            == manifest.node.bytes()?
            && node.read("identity.json", 8192)? == volume::identity(&manifest.node.spec)?,
        "native node intent differs"
    );
    match config.open("/usr/local/libexec") {
        Ok(dir) => {
            for name in [
                "zdn-host.py",
                "zdn-lightwalletd.py",
                "zdn-lightwalletd-install.py",
            ] {
                dir.require_absent(name)?;
            }
        }
        Err(e) if missing(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

fn missing(e: &eyre::Report) -> bool {
    e.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
}

fn runtime_config(config: &Config<'_>, manifest: &Manifest) -> Result<runtime::RuntimeConfig> {
    Ok(runtime::RuntimeConfig {
        host: manifest.spec.host.clone(),
        service: manifest.spec.service.clone(),
        filesystem_root: config.root.into(),
        kernel_root: config.root.into(),
        root_uid: config.owner,
        node_uid: config.node_owner,
        node_gid: config.node_owner,
        tools: runtime::Tools {
            docker: config.tool("docker")?,
            lsblk: config.tool("lsblk")?,
            findmnt: config.tool("findmnt")?,
            iptables: config.tool("iptables")?,
            ip6tables: config.tool("ip6tables")?,
            supervisor: config.executable(&manifest.node)?,
        },
        poll_interval: Duration::from_millis(100),
    })
}

/// Finite operations share one cumulative deadline. Both installer locks are
/// released before systemd starts its prepare/serve children, then reacquired
/// for fresh final authentication. Observe/stop never recreate lost identity.
pub fn dispatch(
    manifest: &Manifest,
    config: Config<'_>,
    operation: Operation,
    stop: &AtomicBool,
) -> Result<Option<Value>> {
    #[cfg(feature = "profiling")]
    let operation_span = match operation {
        Operation::Install => tracing::info_span!("host.runtime.lightwallet.dispatch_install"),
        Operation::Prepare => tracing::info_span!("host.runtime.lightwallet.prepare"),
        Operation::Observe => tracing::info_span!("host.runtime.lightwallet.observe"),
        Operation::Start => tracing::info_span!("host.runtime.lightwallet.start"),
        Operation::Stop => tracing::info_span!("host.runtime.lightwallet.stop"),
        Operation::Serve => tracing::info_span!("host.runtime.lightwallet.serve_preflight"),
    }
    .entered();
    let deadline = Instant::now() + Duration::from_secs(operation.budget());
    prerequisites(&config, manifest, stop)?;
    let executable = config.executable(&manifest.node)?;
    let systemctl = config.tool("systemctl")?;
    let runtime = runtime_config(&config, manifest)?;
    let tools = prepare::Tools {
        lsblk: config.tool("lsblk")?,
        findmnt: config.tool("findmnt")?,
        blkid: config.tool("blkid")?,
        wipefs: config.tool("wipefs")?,
        blockdev: config.tool("blockdev")?,
        mkfs_ext4: config.tool("mkfs.ext4")?,
        mount: config.tool("mount")?,
    };
    let aws = config.tool("aws")?;
    let units = config.open("/etc/systemd/system")?;
    units.require_absent("zdn-lightwalletd.service.d")?;
    let unit = native::unit(manifest)?;
    match units.read(UNIT_NAME, 16384) {
        Ok(bytes) => ensure!(
            bytes == unit.as_bytes()
                && units.regular(UNIT_NAME, 16384)?.metadata()?.mode() & 0o7777 == 0o644,
            "native unit differs"
        ),
        Err(e) if missing(&e) && operation == Operation::Install => {}
        Err(e) => return Err(e),
    }
    let node = config.open("/etc/zdn")?;
    let node_install = volume::Installation::acquire(&node, &manifest.node.spec)?;
    let metadata = if operation == Operation::Install {
        config
            .open("/etc")?
            .ensure_directory("zdn-lightwalletd", 0o700)?
    } else {
        config.open("/etc/zdn-lightwalletd")?
    };
    if operation == Operation::Install {
        // A native journal is not migration authorization. Check legacy and
        // interrupted intent before even invoking observational tools; repeat
        // under the cache lock at acquire_native below.
        match metadata.regular("identity.json", 16384) {
            Ok(_) => ensure!(
                metadata.read("native-install-intent.json", native::MAX_MANIFEST_BYTES)?
                    == manifest.bytes()?,
                "legacy lightwallet identity is not native intent"
            ),
            Err(e) if missing(&e) => {}
            Err(e) => return Err(e),
        }
        match metadata.read("native-install-intent.json", native::MAX_MANIFEST_BYTES) {
            Ok(bytes) => ensure!(
                bytes == manifest.bytes()?,
                "native lightwallet intent differs"
            ),
            Err(e) if missing(&e) => {}
            Err(e) => return Err(e),
        }
    }
    if operation != Operation::Install {
        metadata.regular("identity.json", 16384)?;
        ensure!(
            metadata.read("native-install-intent.json", native::MAX_MANIFEST_BYTES)?
                == manifest.bytes()?,
            "native lightwallet intent differs"
        );
        Manifest::load(
            &config.open(native::MANIFEST_DIRECTORY)?,
            &manifest.file_name()?,
        )?;
        ensure!(
            config
                .open(native::MANIFEST_DIRECTORY)?
                .regular(&manifest.file_name()?, native::MAX_MANIFEST_BYTES)?
                .metadata()?
                .mode()
                & 0o7777
                == 0o600,
            "role manifest permissions differ"
        );
    }
    let action = match operation {
        Operation::Install => "install",
        Operation::Prepare => "prepare",
        Operation::Observe => "observe",
        Operation::Start => "start",
        Operation::Stop => "stop",
        Operation::Serve => "serve",
    };
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory(action, 0o700)?;
    let mut executor = Executor::new(
        executable,
        config.path(&format!("/etc/zdn-lightwalletd/commands/{action}")),
        manifest.spec.host.helper.region.clone(),
        deadline,
    )?;
    unit_loaded(
        &systemctl,
        &mut executor,
        stop,
        operation == Operation::Install,
    )?;
    if operation != Operation::Stop {
        verify_node(&config, manifest, &node_install, &mut executor, stop)?;
    }
    // Tools, ancestors, node evidence and effective unit selection precede intent.
    let mut installation = cache::Installation::acquire_native(&metadata, manifest)?;
    if operation == Operation::Serve {
        drop(executor);
        drop(installation);
        drop(node_install);
        #[cfg(feature = "profiling")]
        drop(operation_span);
        runtime::supervise(runtime, stop)?;
        return Ok(None);
    }
    if operation == Operation::Stop {
        call(&systemctl, &["stop", UNIT_NAME], 135, &mut executor, stop)?;
        ensure!(
            !active(&systemctl, &mut executor, stop)?,
            "lightwallet did not stop"
        );
        runtime::cleanup_container(runtime, &mut executor, stop)?;
        return Ok(Some(stop_report(manifest)?));
    }
    let artifacts = if operation == Operation::Install {
        metadata.ensure_directory("artifacts", 0o700)?
    } else {
        metadata.open_directory("artifacts")?
    };
    if operation == Operation::Install {
        for artifact in [
            Artifact::ImageRecord,
            Artifact::ImageManifest,
            Artifact::ImageConfig,
        ] {
            image_delivery::fetch_artifact(
                &manifest.spec,
                artifact,
                &artifacts,
                &aws,
                &mut executor,
                stop,
            )?;
        }
        metadata.ensure_directory("scratch", 0o700)?;
        image_delivery::pull_image(
            &manifest.spec,
            &artifacts,
            &config.path("/etc/zdn-lightwalletd/scratch"),
            &image_delivery::Tools {
                aws,
                docker: config.tool("docker")?,
            },
            &mut executor,
            stop,
        )?;
    }
    if matches!(
        operation,
        Operation::Install | Operation::Start | Operation::Prepare
    ) {
        prepare::prepare(
            &manifest.spec,
            prepare::Root {
                path: config.root,
                owner: config.owner,
                node_owner: config.node_owner,
            },
            &tools,
            &mut installation,
            &mut executor,
            stop,
            operation == Operation::Install,
        )?;
    }
    image_delivery::verify_image(
        &manifest.spec,
        &artifacts,
        Some(&config.tool("docker")?),
        &mut executor,
        stop,
    )?;
    if operation == Operation::Prepare {
        return Ok(None);
    }
    if operation == Operation::Install {
        metadata
            .ensure_directory("runtime", 0o700)?
            .ensure_directory("manifests", 0o700)?
            .publish(&manifest.file_name()?, &manifest.bytes()?, 0o600)?;
        units.publish(UNIT_NAME, unit.as_bytes(), 0o644)?;
        call(&systemctl, &["daemon-reload"], 60, &mut executor, stop)?;
        unit_loaded(&systemctl, &mut executor, stop, false)?;
        call(&systemctl, &["enable", UNIT_NAME], 60, &mut executor, stop)?;
    }
    if matches!(operation, Operation::Install | Operation::Start) {
        #[cfg(feature = "profiling")]
        let _startup = tracing::info_span!("host.runtime.lightwallet.startup").entered();
        drop(installation);
        drop(node_install);
        if !active(&systemctl, &mut executor, stop)? {
            call(
                &systemctl,
                &["reset-failed", UNIT_NAME],
                60,
                &mut executor,
                stop,
            )?;
        }
        call(&systemctl, &["start", UNIT_NAME], 180, &mut executor, stop)?;
        let until = (Instant::now() + Duration::from_secs(90)).min(executor.work_deadline()?);
        loop {
            ensure!(
                active(&systemctl, &mut executor, stop)?,
                "service stopped during startup"
            );
            if runtime::observe_container(
                runtime_config(&config, manifest)?,
                &mut executor,
                stop,
                true,
            )? == Some(true)
            {
                break;
            }
            ensure!(
                !stop.load(Ordering::Relaxed) && Instant::now() < until,
                "container startup timed out"
            );
            thread::sleep(Duration::from_millis(100));
        }
        let node_install = volume::Installation::acquire(&node, &manifest.node.spec)?;
        let installation = cache::Installation::acquire_native(&metadata, manifest)?;
        verify_node(&config, manifest, &node_install, &mut executor, stop)?;
        let report = observation(
            &config,
            manifest,
            &installation,
            &tools,
            &artifacts,
            &systemctl,
            &mut executor,
            stop,
        )?;
        ensure!(report["status"] == "ready", "lightwallet did not start");
        verify_node(&config, manifest, &node_install, &mut executor, stop)?;
        return Ok(Some(report));
    }
    let report = observation(
        &config,
        manifest,
        &installation,
        &tools,
        &artifacts,
        &systemctl,
        &mut executor,
        stop,
    )?;
    verify_node(&config, manifest, &node_install, &mut executor, stop)?;
    Ok(Some(report))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.lightwallet.verify_node")
)]
fn verify_node(
    config: &Config<'_>,
    manifest: &Manifest,
    installation: &volume::Installation<'_>,
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<()> {
    let node = config.open("/etc/zdn")?;
    ensure!(
        node.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
            == manifest.node.bytes()?
            && node.read("volume-claimed.json", 8192)? == installation.identity(),
        "node claim differs"
    );
    config.mounted(
        &manifest.node,
        installation.identity(),
        executor,
        stop,
        false,
    )?;
    inputs::verify(&manifest.spec.host, &config.open("/etc/zdn/artifacts")?)?;
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        false,
        executor,
        stop,
    )?;
    // ExecStartPre inherits this service's small supervisor leaf. Exclude only
    // that explicitly named leaf, never arbitrary controller limits.
    let membership = fs::read_to_string(config.path("/proc/self/cgroup"))?;
    let groups: Vec<_> = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect();
    let scope = if groups.len() == 1
        && Path::new(groups[0])
            .file_name()
            .is_some_and(|name| name == UNIT_NAME)
    {
        CgroupScope::AncestorsOnly
    } else {
        CgroupScope::CurrentAndAncestors
    };
    let resources = capacity::observe(config.root, scope)?;
    let mut service = manifest.spec.service.clone();
    service.host_observation = resources.clone();
    service.validate(&manifest.spec.host)?;
    container::running_limits(
        &manifest.spec.host,
        &manifest.spec.host.image,
        &resources,
        &config.tool("docker")?,
        executor,
        stop,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.lightwallet.observation")
)]
fn observation(
    config: &Config<'_>,
    manifest: &Manifest,
    installation: &cache::Installation<'_>,
    tools: &prepare::Tools,
    artifacts: &Directory,
    systemctl: &Path,
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<Value> {
    unit_loaded(systemctl, executor, stop, false)?;
    image_delivery::verify_image(
        &manifest.spec,
        artifacts,
        Some(&config.tool("docker")?),
        executor,
        stop,
    )?;
    let ready = active(systemctl, executor, stop)?;
    let report = if ready {
        verify_cache(config, manifest, installation, tools, executor, stop)?;
        ensure!(
            runtime::observe_container(runtime_config(config, manifest)?, executor, stop, false)?
                == Some(true),
            "container not running"
        );
        let helper = config.path("/etc/zdn/artifacts/zdn");
        let args = vec![
            "lightwallet".into(),
            "readiness".into(),
            "--manifest".into(),
            config
                .path("/etc/zdn/artifacts/manifest.json")
                .into_os_string(),
            "--rpc-endpoint".into(),
            native::rpc_endpoint(manifest)?.to_string().into(),
            "--cookie-file".into(),
            config
                .path(&format!("{}/rpc/.cookie", manifest.spec.host.node_root()))
                .into_os_string(),
            "--grpc-endpoint".into(),
            "127.0.0.1:9067".into(),
            "--max-lag-blocks".into(),
            "2".into(),
            "--request-timeout-secs".into(),
            "10".into(),
            "--deadline-secs".into(),
            "180".into(),
        ];
        let output = executor.execute(
            HostCommand {
                program: &helper,
                args: &args,
                stdin: None,
                timeout: Duration::from_secs(200),
                allowed: &[0],
            },
            stop,
        )?;
        let report: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid readiness report"))?;
        ensure!(
            report["apiVersion"] == "zdn-lightwallet-readiness/v1alpha1"
                && report["consensusFingerprint"] == manifest.spec.host.consensus_fingerprint
                && report["protocolVersion"] == "v0.5.0"
                && report["launchReady"] == false
                && report["paymentQualification"] == "pending"
                && report["ironwoodTreeVerified"] == true
                && report["compactDataVerified"] == true
                && report["lagBlocks"].as_u64().is_some_and(|n| n <= 2)
                && report["checkedCompactBlocks"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "readiness differs"
        );
        ensure!(
            active(systemctl, executor, stop)?
                && runtime::observe_container(
                    runtime_config(config, manifest)?,
                    executor,
                    stop,
                    false
                )? == Some(true),
            "service stopped during readiness"
        );
        verify_cache(config, manifest, installation, tools, executor, stop)?;
        unit_loaded(systemctl, executor, stop, false)?;
        image_delivery::verify_image(
            &manifest.spec,
            artifacts,
            Some(&config.tool("docker")?),
            executor,
            stop,
        )?;
        report
    } else {
        Value::Null
    };
    let rendered = render_service(&manifest.spec.host, &manifest.spec.service)?;
    Ok(
        json!({"apiVersion":"zdn-lightwallet-host-observation/v1alpha1", "deploymentId":manifest.spec.host.deployment_id,
        "nodeId":manifest.spec.host.node_id, "installSha256":manifest.install_sha256, "serviceSha256":rendered.service_sha256,
        "cacheVolumeId":manifest.spec.service.cache_volume_id, "image":manifest.spec.service.image,
        "status":if ready {"ready"} else {"stopped"}, "readiness":report, "paymentQualification":"pending", "launchReady":false}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.lightwallet.verify_cache")
)]
fn verify_cache(
    config: &Config<'_>,
    manifest: &Manifest,
    installation: &cache::Installation<'_>,
    tools: &prepare::Tools,
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<()> {
    ensure!(
        prepare::observe(
            &manifest.spec,
            &prepare::Root {
                path: config.root,
                owner: config.owner,
                node_owner: config.node_owner
            },
            tools,
            executor,
            stop
        )?
        .mounted,
        "cache is not mounted"
    );
    let cache =
        config.open(&render_service(&manifest.spec.host, &manifest.spec.service)?.cache_root)?;
    ensure!(
        cache.read(".zdn-lightwalletd-volume.json", 16384)? == installation.cache_identity()
            && config
                .open("/etc/zdn-lightwalletd")?
                .read("volume-claimed.json", 16384)?
                == installation.cache_identity(),
        "cache claim differs"
    );
    let data = config.path(&format!(
        "{}/data",
        render_service(&manifest.spec.host, &manifest.spec.service)?.cache_root
    ));
    Directory::open(&data, config.node_owner)?;
    ensure!(
        fs::symlink_metadata(data)?.mode() & 0o7777 == 0o700,
        "cache data permissions differ"
    );
    Ok(())
}

fn stop_report(manifest: &Manifest) -> Result<Value> {
    Ok(
        json!({"apiVersion":"zdn-lightwallet-stop/v1alpha1", "installSha256":manifest.install_sha256,
        "serviceSha256":render_service(&manifest.spec.host, &manifest.spec.service)?.service_sha256,
        "cacheVolumeId":manifest.spec.service.cache_volume_id, "status":"stopped"}),
    )
}

fn call(
    tool: &Path,
    args: &[&str],
    seconds: u64,
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<Vec<u8>> {
    Ok(executor
        .execute(
            HostCommand {
                program: tool,
                args: &args.iter().map(Into::into).collect::<Vec<_>>(),
                stdin: None,
                timeout: Duration::from_secs(seconds),
                allowed: &[0],
            },
            stop,
        )?
        .stdout)
}

fn properties(
    systemctl: &Path,
    names: &[&str],
    executor: &mut Executor,
    stop: &AtomicBool,
) -> Result<BTreeMap<String, String>> {
    let bytes = call(
        systemctl,
        &[
            "show",
            UNIT_NAME,
            &format!("--property={}", names.join(",")),
        ],
        60,
        executor,
        stop,
    )?;
    ensure!(bytes.len() <= 4096, "service properties exceed bound");
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (name, value) = line.split_once('=').context("invalid service property")?;
        ensure!(
            names.contains(&name) && result.insert(name.into(), value.into()).is_none(),
            "unexpected service property"
        );
    }
    ensure!(result.len() == names.len(), "missing service property");
    Ok(result)
}

fn unit_loaded(
    systemctl: &Path,
    executor: &mut Executor,
    stop: &AtomicBool,
    allow_absent: bool,
) -> Result<()> {
    let p = properties(
        systemctl,
        &["FragmentPath", "DropInPaths", "LoadState"],
        executor,
        stop,
    )?;
    ensure!(
        p["DropInPaths"].is_empty()
            && ((p["FragmentPath"] == "/etc/systemd/system/zdn-lightwalletd.service"
                && p["LoadState"] == "loaded")
                || (allow_absent && p["FragmentPath"].is_empty() && p["LoadState"] == "not-found")),
        "foreign service fragment or drop-ins"
    );
    Ok(())
}

fn active(systemctl: &Path, executor: &mut Executor, stop: &AtomicBool) -> Result<bool> {
    let p = properties(
        systemctl,
        &["LoadState", "ActiveState", "SubState", "MainPID"],
        executor,
        stop,
    )?;
    let pid = &p["MainPID"];
    ensure!(
        p["LoadState"] == "loaded" && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
        "invalid service state"
    );
    let pid: u32 = pid.parse()?;
    if p["ActiveState"] == "active" && p["SubState"] == "running" && pid > 0 {
        return Ok(true);
    }
    ensure!(
        matches!(p["ActiveState"].as_str(), "inactive" | "failed") && pid == 0,
        "service transitioning"
    );
    Ok(false)
}
