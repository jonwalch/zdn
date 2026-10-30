//! Root-only fixed external host actions. The controller authenticates stdin
//! installation requests; subsequent systemd actions authenticate immutable
//! root-owned manifests and the actual running helper inode/hash. Stop does not
//! open or execute a companion. No action adopts a lost identity or key.
use super::{Manifest, ProductionAdmission, MAX_BYTES};
use crate::{
    chain::{
        bootstrap::BootstrapOptions, producer::ProducerOptions, readiness::ReadinessOptions,
        rpc::SystemClock, runtime_config::NodeRole,
    },
    host::{
        artifact_delivery::{self, Delivery},
        capacity::{self, CgroupScope},
        command::{self, Executor, HostCommand},
        container,
        files::{self, Directory},
        firewall, image_delivery, node_paths, producer,
        runtime::control::Config,
        volume::{prepare, probe, VolumeSpec},
    },
    native_peers::NativeIdentity,
};
use eyre::{ensure, ContextCompat, Result};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Seek},
    net::TcpListener,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Operation {
    Prepare,
    Run,
    Ready,
    Observe,
    StartProducer,
    Produce,
    Stop,
    GatewayInstall,
    GatewayObserve,
    GatewayServe,
}

impl Operation {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Run => "run",
            Self::Ready => "ready",
            Self::Observe => "observe",
            Self::StartProducer => "start-producer",
            Self::Produce => "produce",
            Self::Stop => "stop",
            Self::GatewayInstall => "gateway-install",
            Self::GatewayObserve => "gateway-observe",
            Self::GatewayServe => "gateway-serve",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "external-prepare",
            Self::Run => "external-run",
            Self::Ready => "external-ready",
            Self::Observe => "external-observe",
            Self::StartProducer => "external-start-producer",
            Self::Produce => "external-produce",
            Self::Stop => "external-stop",
            Self::GatewayInstall => "external-gateway-install",
            Self::GatewayObserve => "external-gateway-observe",
            Self::GatewayServe => "external-gateway-serve",
        }
    }
}

fn root() -> Result<Config<'static>> {
    ensure!(
        nix::unistd::Uid::effective().is_root() && std::env::consts::ARCH == "x86_64",
        "unsupported external host"
    );
    Ok(Config {
        root: Path::new("/"),
        owner: 0,
        node_owner: crate::image::RUNTIME_UID,
    })
}

pub(super) fn authenticate_running(
    manifest: &Manifest,
    running: &mut File,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    let pin = &manifest.chain.objects.host_helper;
    let info = running.metadata()?;
    ensure!(
        info.is_file() && info.uid() == 0 && info.mode() & 0o022 == 0 && info.mode() & 0o100 != 0,
        "unsafe external runtime executable"
    );
    running.rewind()?;
    let digest = files::digest_file(running, pin.bytes, &mut || {
        ensure!(
            Instant::now() < deadline && !cancelled.load(Ordering::Relaxed),
            "external operation interrupted"
        );
        Ok(())
    })?;
    ensure!(
        digest.bytes == pin.bytes && digest.sha256 == pin.sha256,
        "external runtime executable differs"
    );
    crate::devnet::validate_helper(&digest.prefix)
}

/// Bounded canonical final manifest on stdin. Requires completed phase-one
/// identity provisioning: this installer cannot format or generate native keys.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.runtime.control.install_stdin")
)]
pub fn install_stdin(cancelled: &AtomicBool) -> Result<Value> {
    (|| {
        let config = root()?;
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let manifest = Manifest::from_slice(&bytes)?;
        install(&manifest, config, File::open("/proc/self/exe")?, cancelled)
    })()
    .map_err(|_: eyre::Report| {
        eyre::eyre!("external host installation failed; retain immutable inputs and host evidence")
    })
}

pub fn execute(path: &Path, operation: Operation, cancelled: &AtomicBool) -> Result<Option<Value>> {
    (|| {
        // Dispatch may exec or supervise a daemon; close authentication first.
        #[cfg(feature = "profiling")]
        let preflight = tracing::info_span!("host.external.runtime.control.execute").entered();
        let (manifest, config) = authenticate(path, cancelled)?;
        #[cfg(feature = "profiling")]
        drop(preflight);
        dispatch(&manifest, config, operation, cancelled)
    })()
    .map_err(|_: eyre::Report| {
        eyre::eyre!("external host operation failed; inspect retained evidence")
    })
}

pub(super) fn authenticate(
    path: &Path,
    cancelled: &AtomicBool,
) -> Result<(Manifest, Config<'static>)> {
    let config = root()?;
    ensure!(
        path.parent() == Some(Path::new("/etc/zdn/external-runtime")),
        "invalid external manifest path"
    );
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid external manifest filename")?;
    let manifest = Manifest::from_slice(
        &config
            .open("/etc/zdn/external-runtime")?
            .read(name, MAX_BYTES)?,
    )?;
    ensure!(
        name == manifest.file_name()?,
        "external manifest filename differs"
    );
    let expected = std::fs::symlink_metadata(manifest.executable())?;
    let mut running = File::open("/proc/self/exe")?;
    let actual = running.metadata()?;
    ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "external runtime inode differs"
    );
    authenticate_running(
        &manifest,
        &mut running,
        Instant::now() + Duration::from_secs(30),
        cancelled,
    )?;
    Ok((manifest, config))
}

pub(super) fn require_identity(
    manifest: &Manifest,
    config: &Config<'_>,
    metadata: &Directory,
) -> Result<()> {
    require_metadata(manifest, metadata)?;
    let node = config.open(&manifest.node_root())?;
    let saved = NativeIdentity::from_json(&node.read("native-public-identity.json", 1024)?)?;
    ensure!(
        saved.node_id == manifest.chain.options.expected_node_id
            && saved.chain_fingerprint.as_deref()
                == Some(&manifest.provisioning.native_fingerprint),
        "retained native public identity differs"
    );
    Ok(())
}

pub(super) fn require_metadata(manifest: &Manifest, metadata: &Directory) -> Result<()> {
    ensure!(
        metadata.read("identity.json", 8192)? == manifest.volume_identity()?,
        "external disk identity differs"
    );
    ensure!(
        metadata.read("external-install-intent.json", 8192)? == manifest.provisioning.bytes()?,
        "external provisioning intent differs"
    );
    Ok(())
}

pub(super) fn mounted(
    manifest: &Manifest,
    config: &Config<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    producer: bool,
) -> Result<()> {
    let observed = probe::observe_at(
        &manifest.provisioning,
        config.root,
        &config.probe_tools()?,
        executor,
        cancelled,
        producer,
    )?;
    ensure!(
        observed.filesystem == probe::Filesystem::MountedExt4,
        "external volume is not mounted"
    );
    ensure!(
        config
            .open(crate::host::DATA_ROOT)?
            .read(".zdn-volume.json", 8192)?
            == manifest.volume_identity()?,
        "external mounted identity differs"
    );
    Ok(())
}

pub(super) fn systemctl(
    config: &Config<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    args: &[&str],
    seconds: u64,
) -> Result<()> {
    executor.execute(
        HostCommand {
            program: &config.tool("systemctl")?,
            args: &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            stdin: None,
            timeout: Duration::from_secs(seconds),
            allowed: &[0],
        },
        cancelled,
    )?;
    Ok(())
}

fn absent(error: &eyre::Report) -> bool {
    error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
}

fn preflight_unit(directory: &Directory, name: &str, expected: Option<&str>) -> Result<()> {
    match directory.read(name, 64 * 1024) {
        Ok(bytes) => ensure!(
            Some(bytes.as_slice()) == expected.map(str::as_bytes),
            "conflicting external service unit"
        ),
        Err(error) if absent(&error) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Same effective-unit admission as the ordinary image updater; no drop-in or
/// foreign fragment may substitute another startup/producer/gateway command.
pub(super) fn verify_units(
    manifest: &Manifest,
    config: &Config<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    let (node, producer, gateway) = manifest.units()?;
    let units = config.open("/etc/systemd/system")?;
    for (name, expected) in [
        ("zdn-node.service", Some(node)),
        ("zdn-producer.service", producer),
        (crate::client_gateway::UNIT_NAME, gateway),
    ] {
        if let Some(expected) = expected {
            ensure!(
                units.read(name, 65536)? == expected.as_bytes()
                    && units.regular(name, 65536)?.metadata()?.mode() & 0o7777 == 0o644,
                "external unit differs"
            );
            crate::host::runtime::update::service(
                &config.tool("systemctl")?,
                name,
                executor,
                cancelled,
            )?;
        } else {
            units.require_absent(name)?;
        }
    }
    Ok(())
}

/// Existing volume claim and immutable source publication, followed by the
/// common node/producer/gateway supervisor policies. The installation lock is
/// released before systemctl waits for children which acquire that same lock.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.runtime.control.install")
)]
pub fn install(
    manifest: &Manifest,
    config: Config<'_>,
    mut running: File,
    cancelled: &AtomicBool,
) -> Result<Value> {
    manifest.validate()?;
    super::super::require_isolated_execution()?;
    let deadline = Instant::now() + Duration::from_secs(4800);
    authenticate_running(manifest, &mut running, deadline, cancelled)?;
    ensure!(
        config.open("/etc")?.read("zdn-prerequisites-ready", 33)?
            == b"zdn-host-prerequisites/v1alpha1\n",
        "prerequisites not ready"
    );
    let metadata = config.open("/etc/zdn")?;
    let _control = metadata.lock("external-update.lock")?;
    metadata.require_absent("native-install-intent.json")?;
    // Presence is required before acquire: installation is not identity repair.
    ensure!(
        metadata.read("external-install-intent.json", 8192)? == manifest.provisioning.bytes()?,
        "provision external identity first"
    );
    let mut installation = manifest.provisioning.acquire(&metadata)?;
    let (node_unit, producer_unit, gateway_unit) = manifest.units()?;
    let units = config.open("/etc/systemd/system")?;
    for (name, expected) in [
        ("zdn-node.service", Some(node_unit.as_str())),
        ("zdn-producer.service", producer_unit.as_deref()),
        (crate::client_gateway::UNIT_NAME, gateway_unit.as_deref()),
    ] {
        preflight_unit(&units, name, expected)?;
    }
    // Bind final selection before downloads. Conflicting retries do not mutate
    // disks/services and cannot silently turn an install into an update.
    metadata.publish("external-runtime-intent.json", &manifest.bytes()?, 0o600)?;
    let artifacts = metadata.ensure_directory("external-artifacts", 0o700)?;
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("external-install", 0o700)?;
    metadata.ensure_directory("scratch", 0o700)?;
    let pin = &manifest.chain.objects.host_helper;
    let mut executor = Executor::new(
        Path::new("/proc/self/exe").into(),
        config.path("/etc/zdn/commands/external-install"),
        pin.region.clone(),
        deadline,
    )?;
    let aws = config.tool("aws")?;
    let docker = config.tool("docker")?;
    manifest
        .chain
        .deliver(&artifacts, &aws, &mut executor, cancelled)?;
    let prepared = manifest.chain.prepare(&artifacts, deadline, cancelled)?;
    ensure!(
        serde_json::to_vec(prepared.image())? == serde_json::to_vec(&manifest.image)?,
        "external rendered image differs"
    );
    image_delivery::pull_image(
        &prepared.image().image,
        &pin.region,
        &config.path("/etc/zdn/scratch"),
        &image_delivery::Tools {
            aws: aws.clone(),
            docker: docker.clone(),
        },
        &mut executor,
        cancelled,
        || {},
    )?;
    let actual = executor.execute(
        HostCommand {
            program: &docker,
            args: &[
                "image".into(),
                "inspect".into(),
                prepared.image().image.clone().into(),
            ],
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    )?;
    prepared.verify_pulled_image(&actual.stdout)?;
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        true,
        &mut executor,
        cancelled,
    )?;
    prepare::prepare(
        &manifest.provisioning,
        prepare::Root {
            path: config.root,
            owner: config.owner,
        },
        &prepare::Tools {
            probe: config.probe_tools()?,
            mkfs_ext4: config.tool("mkfs.ext4")?,
            mount: config.tool("mount")?,
        },
        &mut installation,
        &mut executor,
        cancelled,
        false,
    )?;
    require_identity(manifest, &config, &metadata)?;
    let node = node_paths::create_external(
        &manifest.provisioning,
        &config.open(crate::host::DATA_ROOT)?,
        &installation,
        config.node_owner,
    )?;
    node.publish("zakura.toml", manifest.chain.config_toml.as_bytes(), 0o444)?;
    let runtime = metadata
        .ensure_directory("runtime", 0o700)?
        .ensure_directory(&pin.sha256, 0o700)?;
    artifact_delivery::fetch_object(
        Delivery {
            pin,
            name: "zdn",
            mode: 0o555,
            timeout: Duration::from_secs(600),
        },
        &runtime,
        &aws,
        &mut executor,
        cancelled,
        crate::devnet::validate_helper,
    )?;
    metadata
        .ensure_directory("external-runtime", 0o700)?
        .publish(&manifest.file_name()?, &manifest.bytes()?, 0o600)?;
    units.publish("zdn-node.service", node_unit.as_bytes(), 0o644)?;
    if let Some(unit) = producer_unit {
        units.publish("zdn-producer.service", unit.as_bytes(), 0o644)?;
    }
    if let Some(unit) = gateway_unit {
        units.publish(crate::client_gateway::UNIT_NAME, unit.as_bytes(), 0o644)?;
    }
    drop(installation);
    for (args, seconds) in [
        (&["daemon-reload"][..], 60),
        (&["enable", "zdn-node.service"][..], 60),
        (&["start", "zdn-node.service"][..], 650),
    ] {
        systemctl(&config, &mut executor, cancelled, args, seconds)?;
    }
    // A fresh host invocation recompiles and checks all readiness, never just
    // trusts systemd's status or the successful start receipt.
    dispatch(manifest, config, Operation::Observe, cancelled)?
        .context("missing external readiness observation")
}

pub fn dispatch(
    manifest: &Manifest,
    config: Config<'_>,
    operation: Operation,
    cancelled: &AtomicBool,
) -> Result<Option<Value>> {
    // Exec does not run Rust drops. Daemon supervision must not extend this
    // finite preflight either; close it explicitly before all three paths.
    #[cfg(feature = "profiling")]
    let preflight = tracing::info_span!("host.external.runtime.control.dispatch").entered();
    manifest.validate()?;
    let seconds = match operation {
        Operation::Prepare | Operation::Run => 180,
        Operation::Ready => 420,
        Operation::Observe => 250,
        Operation::StartProducer => 650,
        Operation::Produce | Operation::GatewayServe => 600,
        Operation::Stop => 125,
        Operation::GatewayInstall | Operation::GatewayObserve => 340,
    };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let metadata = config.open("/etc/zdn")?;
    require_metadata(manifest, &metadata)?;
    ensure!(
        metadata.read("external-runtime-intent.json", MAX_BYTES)? == manifest.bytes()?,
        "external active runtime differs"
    );
    let installation = if matches!(operation, Operation::Produce | Operation::GatewayServe) {
        None
    } else {
        Some(manifest.provisioning.acquire(&metadata)?)
    };
    let snapshot = super::update::Snapshot::from_installation(&metadata, manifest)?;
    if let Some(state) = &snapshot {
        if matches!(operation, Operation::Produce | Operation::StartProducer) {
            ensure!(
                !state.producer_hold,
                "external producer maintenance is active"
            );
        }
        if matches!(
            operation,
            Operation::Prepare | Operation::Run | Operation::Ready
        ) {
            if let Some(tx) = &state.transaction {
                use crate::host::runtime::revision::Phase;
                ensure!(
                    tx.phase != Phase::Stopping,
                    "external startup blocked while stopping for update"
                );
                if tx.phase == Phase::Activating {
                    ensure!(
                        state.active.as_ref().map(|r| r.bytes()).transpose()?
                            == Some(tx.request.bytes()?),
                        "external target activation incomplete"
                    );
                }
            }
        }
    }
    let selected = snapshot.as_ref().and_then(|s| s.active.as_ref());
    let manifest = selected.map(|r| &r.target).unwrap_or(manifest);
    let artifact_path = selected
        .map(|r| {
            format!(
                "/etc/zdn/{}/{}/artifacts",
                super::update::NAMESPACE,
                r.update_id
            )
        })
        .unwrap_or_else(|| "/etc/zdn/external-artifacts".into());
    if operation == Operation::GatewayServe {
        // Read-only daemon startup deliberately does not acquire the install
        // lock, write receipts, invoke Docker/firewall, or contact AWS.
        ensure!(
            manifest.provisioning.node_id == "node-1",
            "external gateway requires node-1"
        );
        ensure!(
            config
                .open(crate::host::DATA_ROOT)?
                .read(".zdn-volume.json", 8192)?
                == manifest.volume_identity()?,
            "external mounted identity differs"
        );
        require_identity(manifest, &config, &metadata)?;
        ensure!(
            config
                .open(&manifest.node_root())?
                .read("zakura.toml", contract_limit())?
                == manifest.chain.config_toml.as_bytes(),
            "external config differs"
        );
        let prepared =
            manifest
                .chain
                .prepare(&config.open(&artifact_path)?, deadline, cancelled)?;
        let anchor = File::from(nix::fcntl::open(
            config.root,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?);
        #[cfg(feature = "profiling")]
        drop(preflight);
        prepared.serve_gateway(
            &manifest.chain,
            &manifest.provisioning,
            anchor,
            TcpListener::bind(crate::client_gateway::ENDPOINT)?,
            cancelled,
        )?;
        return Ok(None);
    }
    let command_path = if operation == Operation::Produce {
        config
            .open("/run/zdn-producer")?
            .ensure_directory("commands", 0o700)?;
        config.path("/run/zdn-producer/commands")
    } else {
        metadata
            .ensure_directory("commands", 0o700)?
            .ensure_directory(operation.name(), 0o700)?;
        if operation == Operation::StartProducer {
            metadata
                .ensure_directory("commands", 0o700)?
                .ensure_directory("external-start-producer-cleanup", 0o700)?;
        }
        config.path(&format!("/etc/zdn/commands/{}", operation.name()))
    };
    let mut executor = Executor::new(
        config.path(&manifest.executable()),
        command_path,
        manifest.chain.objects.host_helper.region.clone(),
        if operation == Operation::StartProducer {
            deadline - Duration::from_secs(60)
        } else {
            deadline
        },
    )?;
    let docker = config.tool("docker")?;
    if operation == Operation::Stop {
        if manifest.block_interval_seconds.is_some() {
            systemctl(
                &config,
                &mut executor,
                cancelled,
                &["stop", "zdn-producer.service"],
                35,
            )?;
            producer::require_service_stopped(
                &config.tool("systemctl")?,
                &mut executor,
                cancelled,
            )?;
        }
        container::cleanup(
            manifest,
            &manifest.image.image,
            &docker,
            &mut executor,
            cancelled,
        )?;
        return Ok(Some(manifest.observation("stopped")?));
    }
    super::super::require_isolated_execution()?;
    let artifacts = config.open(&artifact_path)?;
    let prepared = manifest.chain.prepare(&artifacts, deadline, cancelled)?;
    ensure!(
        serde_json::to_vec(prepared.image())? == serde_json::to_vec(&manifest.image)?,
        "external rendered image differs"
    );
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        operation == Operation::Prepare,
        &mut executor,
        cancelled,
    )?;
    if operation == Operation::Prepare {
        let mut installation = installation.context("missing installation lock")?;
        prepare::prepare(
            &manifest.provisioning,
            prepare::Root {
                path: config.root,
                owner: config.owner,
            },
            &prepare::Tools {
                probe: config.probe_tools()?,
                mkfs_ext4: config.tool("mkfs.ext4")?,
                mount: config.tool("mount")?,
            },
            &mut installation,
            &mut executor,
            cancelled,
            false,
        )?;
        require_identity(manifest, &config, &metadata)?;
        let node = config.open(&manifest.node_root())?;
        ensure!(
            node.read("zakura.toml", contract_limit())? == manifest.chain.config_toml.as_bytes(),
            "external config differs"
        );
        let actual = executor.execute(
            HostCommand {
                program: &docker,
                args: &[
                    "image".into(),
                    "inspect".into(),
                    prepared.image().image.clone().into(),
                ],
                stdin: None,
                timeout: Duration::from_secs(60),
                allowed: &[0],
            },
            cancelled,
        )?;
        prepared.verify_pulled_image(&actual.stdout)?;
        container::cleanup(
            manifest,
            &prepared.image().image,
            &docker,
            &mut executor,
            cancelled,
        )?;
        return Ok(None);
    }
    mounted(
        manifest,
        &config,
        &mut executor,
        cancelled,
        operation == Operation::Produce,
    )?;
    require_identity(manifest, &config, &metadata)?;
    let node = config.open(&manifest.node_root())?;
    ensure!(
        node.read("zakura.toml", contract_limit())? == manifest.chain.config_toml.as_bytes(),
        "external config differs"
    );
    if operation == Operation::Run {
        let args = container::arguments(
            manifest,
            &prepared.image().image,
            &capacity::observe(config.root, CgroupScope::CurrentAndAncestors)?,
        )?;
        ensure!(
            !cancelled.load(Ordering::Relaxed) && Instant::now() < deadline,
            "external startup interrupted"
        );
        drop(executor);
        drop(installation);
        drop(prepared);
        #[cfg(feature = "profiling")]
        drop(preflight);
        crate::host::runtime::control::notify_starting()?;
        return Err(Command::new(docker)
            .args(args)
            .env_clear()
            .envs(command::environment(
                &manifest.chain.objects.host_helper.region,
            ))
            .exec()
            .into());
    }
    let clock = SystemClock::default();
    let rpc = prepared.chain().wait_for_rpc(
        &manifest.chain.options.rpc_listen,
        &config.path(&format!("{}/.cookie", manifest.chain.options.cookie_dir)),
        &clock,
        Duration::from_secs(10),
        Duration::from_secs(120),
    )?;
    if operation == Operation::Produce {
        ensure!(
            node.read("producer-authorized.json", 8192)? == manifest.producer_authorization()?,
            "external producer is not authorized"
        );
        ensure!(
            node.read("bootstrap-complete.json", 8192)? == manifest.volume_identity()?,
            "external bootstrap is incomplete"
        );
        let mut options = ProducerOptions::new(
            config.path(&format!("{}/producer", manifest.node_root())),
            manifest.producer_identity(),
        );
        options.interval = Duration::from_secs(
            manifest
                .block_interval_seconds
                .context("unscheduled producer")?,
        );
        let admission = ProductionAdmission::load(manifest, &node)?;
        admission.constrain(&mut options);
        let rpc = admission.guard(&rpc);
        // Existing exclusive producer lock, intent-before-generate and pending
        // reconciliation are the sole generation journal. No external variant.
        drop(executor);
        drop(installation);
        #[cfg(feature = "profiling")]
        drop(preflight);
        return Ok(Some(serde_json::to_value(
            prepared
                .chain()
                .produce(&rpc, &clock, &options, cancelled)?,
        )?));
    }
    if operation == Operation::Ready {
        match node.read("bootstrap-complete.json", 8192) {
            Ok(bytes) => ensure!(
                bytes == manifest.volume_identity()?,
                "external bootstrap identity differs"
            ),
            Err(error) if absent(&error) => {
                producer::require_service_stopped(
                    &config.tool("systemctl")?,
                    &mut executor,
                    cancelled,
                )?;
                prepared.chain().bootstrap(
                    &rpc,
                    &clock,
                    &BootstrapOptions {
                        producer_stopped: true,
                        ..Default::default()
                    },
                )?;
                node.publish(
                    "bootstrap-complete.json",
                    &manifest.volume_identity()?,
                    0o600,
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    let role = if manifest.chain.options.role == "producer" {
        NodeRole::Producer
    } else {
        NodeRole::Follower
    };
    let readiness = prepared.chain().readiness(
        &rpc,
        &clock,
        &ReadinessOptions {
            role,
            ..Default::default()
        },
    )?;
    // Ready executes as ExecStartPost while its own unit is still activating.
    // Other observation/activation actions require settled effective units.
    if operation != Operation::Ready {
        let original = super::Manifest::from_slice(
            &metadata.read("external-runtime-intent.json", MAX_BYTES)?,
        )?;
        verify_units(&original, &config, &mut executor, cancelled)?;
    }
    container::running_limits(
        manifest,
        &prepared.image().image,
        &capacity::observe(config.root, CgroupScope::CurrentAndAncestors)?,
        &docker,
        &mut executor,
        cancelled,
    )?;
    if operation == Operation::StartProducer {
        ensure!(
            node.read("bootstrap-complete.json", 8192)? == manifest.volume_identity()?,
            "external bootstrap incomplete"
        );
        manifest.activate_production(&node)?;
        node.publish(
            "producer-authorized.json",
            &manifest.producer_authorization()?,
            0o600,
        )?;
        let result = (|| {
            producer::start(&config.tool("systemctl")?, &mut executor, cancelled)?;
            loop {
                let status = producer::observe_external(
                    manifest,
                    &node,
                    &config.path(&format!("{}/producer", manifest.node_root())),
                    &config.tool("systemctl")?,
                    &mut executor,
                    cancelled,
                    true,
                )?;
                if status.scheduled_producer {
                    let status = status
                        .producer
                        .context("missing owned producer observation")?;
                    return Ok(Some(
                        serde_json::json!({"observation":manifest.observation("ready")?,"readiness":readiness,"producer":status}),
                    ));
                }
                ensure!(
                    !cancelled.load(Ordering::Relaxed)
                        && Instant::now() < executor.work_deadline()?,
                    "external producer startup unavailable"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        })();
        if result.is_err() {
            let mut cleanup = Executor::new(
                config.path(&manifest.executable()),
                config.path("/etc/zdn/commands/external-start-producer-cleanup"),
                manifest.chain.objects.host_helper.region.clone(),
                deadline,
            )?;
            systemctl(
                &config,
                &mut cleanup,
                &AtomicBool::new(false),
                &["stop", "zdn-producer.service"],
                35,
            )?;
        }
        return result;
    }
    if matches!(
        operation,
        Operation::GatewayInstall | Operation::GatewayObserve
    ) {
        ensure!(
            manifest.provisioning.node_id == "node-1",
            "external gateway requires node-1"
        );
        if operation == Operation::GatewayInstall {
            systemctl(&config, &mut executor, cancelled, &["daemon-reload"], 60)?;
            systemctl(
                &config,
                &mut executor,
                cancelled,
                &["enable", crate::client_gateway::UNIT_NAME],
                60,
            )?;
            systemctl(
                &config,
                &mut executor,
                cancelled,
                &["start", crate::client_gateway::UNIT_NAME],
                150,
            )?;
        }
        // Authenticated health is checked by participants too; do not replace
        // it with is-active or the gateway unit's service name.
        systemctl(
            &config,
            &mut executor,
            cancelled,
            &["is-active", "--quiet", crate::client_gateway::UNIT_NAME],
            30,
        )?;
        let expected = serde_json::json!({"apiVersion":crate::client_gateway::OBSERVATION_API_VERSION,
            "deploymentId":manifest.provisioning.deployment_id,"nodeId":manifest.provisioning.node_id,
            "consensusFingerprint":manifest.provisioning.native_fingerprint,"serviceSha256":manifest.chain.gateway_service_sha256()?,
            "endpoint":crate::client_gateway::ENDPOINT,"status":"ready"});
        let until = (Instant::now() + Duration::from_secs(90)).min(executor.work_deadline()?);
        let actual = loop {
            match crate::client_gateway::runtime::health(
                crate::client_gateway::ENDPOINT.parse()?,
                until,
                cancelled,
            ) {
                Ok(actual) => break actual,
                Err(error) if operation == Operation::GatewayObserve => return Err(error),
                Err(_) => {
                    ensure!(
                        !cancelled.load(Ordering::Relaxed) && Instant::now() < until,
                        "external gateway startup health unavailable"
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        };
        ensure!(
            actual == expected,
            "external gateway authenticated service differs"
        );
        return Ok(Some(actual));
    }
    let producer = producer::observe_external(
        manifest,
        &node,
        &config.path(&format!("{}/producer", manifest.node_root())),
        &config.tool("systemctl")?,
        &mut executor,
        cancelled,
        false,
    )?
    .producer;
    Ok(Some(
        serde_json::json!({"observation":manifest.observation("ready")?,"readiness":readiness,"producer":producer}),
    ))
}

fn contract_limit() -> u64 {
    crate::public_chain_adapter::contract::MAX_METADATA as u64
}
