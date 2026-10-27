//! Native node control from runner.py::main/start_producer/produce.
//!
//! This API does not install units, fetch its runtime or authorize migration.
//! Production callers authenticate a root-owned immutable manifest and invoke
//! the pinned executable as root. `Config` permits explicit offline fixture
//! roots/owners, not namespaces: tools must observe that same tree. Stable
//! trusted administrators, Linux procfs and an outer supervisor for blocking
//! kernel/filesystem operations remain prerequisites.

use std::{
    collections::VecDeque,
    fs,
    os::linux::net::SocketAddrExt,
    os::unix::fs::MetadataExt,
    os::unix::net::{SocketAddr, UnixDatagram},
    os::unix::process::CommandExt,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use eyre::{ensure, ContextCompat, Result};
use serde_json::Value;

use super::{revision, Manifest};
use crate::host::{
    capacity::{self, CgroupScope},
    command::{self, Executor, HostCommand},
    container,
    files::Directory,
    firewall, image_delivery, inputs, node_paths, producer, readiness,
    volume::{self, prepare, probe, Installation},
};

/// No first-install operation: control can neither adopt nor format a volume.
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum Operation {
    Prepare,
    Run,
    Ready,
    Observe,
    StartProducer,
    Produce,
    Stop,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Run => "run",
            Self::Ready => "ready",
            Self::Observe => "observe",
            Self::StartProducer => "start-producer",
            Self::Produce => "produce",
            Self::Stop => "stop",
        }
    }

    fn budget(self) -> Duration {
        Duration::from_secs(match self {
            Self::Prepare | Self::Run | Self::Produce => 180,
            Self::Ready => 420,
            Self::Observe => 250,
            Self::StartProducer => 650,
            Self::Stop => 125,
        })
    }
}

pub struct Config<'a> {
    /// `/`, owner 0 in production. Ancestors of an alternate anchor are trusted
    /// by the fixture caller, never inferred from unverified filesystem metadata.
    pub root: &'a Path,
    pub owner: u32,
    pub node_owner: u32,
}

impl Config<'_> {
    pub(super) fn path(&self, logical: &str) -> PathBuf {
        self.root.join(logical.trim_start_matches('/'))
    }

    pub(super) fn open(&self, logical: &str) -> Result<Directory> {
        let mut directory = Directory::open(self.root, self.owner)?;
        for component in Path::new(logical).components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    directory =
                        directory.open_directory(name.to_str().context("invalid host path")?)?;
                }
                _ => eyre::bail!("invalid host path"),
            }
        }
        Ok(directory)
    }

    /// Fixed historical search order, never inherited PATH. Resolve normal
    /// distro tool symlinks, then authenticate aliases and target ancestors.
    /// Keep the invoked name: multicall binaries dispatch on their alias.
    /// An unsafe earlier candidate fails closed instead of selecting a fallback.
    pub(super) fn tool(&self, name: &str) -> Result<PathBuf> {
        for parent in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
            let candidate = self.path(parent).join(name);
            let resolved = match fs::canonicalize(&candidate) {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => eyre::bail!("host tool could not be resolved"),
            };
            let anchor = fs::canonicalize(self.root)?;
            let relative = resolved
                .strip_prefix(&anchor)
                .ok()
                .context("host tool escaped its root")?;
            let parent = relative.parent().context("invalid host tool")?;
            let name = relative
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid host tool")?;
            self.open(parent.to_str().context("invalid host tool")?)?
                .executable(name)?;
            // Returning a verified target alone loses argv[0]. Returning an
            // unchecked alias would allow an untrusted link/ancestor to change
            // the executable after this check. Authenticate the entire route;
            // as with other tools, the trusted owner must keep it stable.
            let mut pending: VecDeque<_> = candidate
                .strip_prefix(self.root)?
                .components()
                .map(|part| part.as_os_str().to_owned())
                .collect();
            let mut cursor = anchor.clone();
            let mut links = 0;
            while let Some(part) = pending.pop_front() {
                if part == "." {
                    continue;
                }
                if part == ".." {
                    ensure!(cursor != anchor, "host tool escaped its root");
                    cursor.pop();
                    continue;
                }
                cursor.push(part);
                let metadata = fs::symlink_metadata(&cursor)?;
                ensure!(metadata.uid() == self.owner, "untrusted host tool route");
                if metadata.file_type().is_symlink() {
                    links += 1;
                    ensure!(links <= 40, "host tool has too many symlinks");
                    let target = fs::read_link(&cursor)?;
                    cursor.pop();
                    let target = if target.is_absolute() {
                        cursor = anchor.clone();
                        target.strip_prefix(&anchor)?
                    } else {
                        target.as_path()
                    };
                    for part in target.components().rev() {
                        pending.push_front(part.as_os_str().to_owned());
                    }
                } else {
                    ensure!(metadata.mode() & 0o022 == 0, "writable host tool route");
                    ensure!(
                        pending.is_empty() || metadata.is_dir(),
                        "invalid host tool route"
                    );
                }
            }
            ensure!(cursor == resolved, "host tool changed during resolution");
            return Ok(candidate);
        }
        eyre::bail!("required host tool is unavailable")
    }

    pub(super) fn probe_tools(&self) -> Result<probe::Tools> {
        Ok(probe::Tools {
            lsblk: self.tool("lsblk")?,
            findmnt: self.tool("findmnt")?,
            blkid: self.tool("blkid")?,
            wipefs: self.tool("wipefs")?,
            blockdev: self.tool("blockdev")?,
        })
    }

    pub(super) fn executable(&self, manifest: &Manifest) -> Result<PathBuf> {
        manifest.validate()?;
        ensure!(self.root.is_absolute(), "host root must be absolute");
        let logical = format!("/etc/zdn/runtime/{}", manifest.runtime.helper.sha256);
        let directory = self.open(&logical)?;
        directory.executable("zdn")?;
        let digest = directory.digest("zdn", manifest.runtime.helper.bytes)?;
        ensure!(
            digest.bytes == manifest.runtime.helper.bytes
                && digest.sha256 == manifest.runtime.helper.sha256,
            "native runtime executable differs"
        );
        crate::devnet::validate_helper(&digest.prefix)?;
        Ok(self.path(&logical).join("zdn"))
    }

    pub(super) fn mounted(
        &self,
        manifest: &Manifest,
        identity: &[u8],
        executor: &mut Executor,
        cancelled: &AtomicBool,
        producer_namespace: bool,
    ) -> Result<Directory> {
        let observation = probe::observe_at(
            &manifest.spec,
            self.root,
            &self.probe_tools()?,
            executor,
            cancelled,
            producer_namespace,
        )?;
        ensure!(
            observation.filesystem == probe::Filesystem::MountedExt4,
            "expected chain volume is not mounted"
        );
        let volume = self.open("/var/lib/zdn")?;
        ensure!(
            volume.read(".zdn-volume.json", 8192)? == identity,
            "chain volume identity differs"
        );
        Ok(volume)
    }
}

/// Privileged CLI boundary. No alternate root, owner or executable override is
/// exposed. The manifest name and running inode both bind the chosen runtime.
pub fn execute(path: &Path, operation: Operation, cancelled: &AtomicBool) -> Result<Option<Value>> {
    (|| {
        let (manifest, config) = authenticated(path)?;
        dispatch(&manifest, config, operation, cancelled)
    })()
    .map_err(|_: eyre::Report| eyre::eyre!("native host operation failed"))
}

/// Shared root-only manifest and running-inode boundary for native host roles.
/// Each role also hashes the selected executable before its own effects.
pub(super) fn authenticated(path: &Path) -> Result<(Manifest, Config<'static>)> {
    ensure!(
        nix::unistd::Uid::effective().is_root(),
        "host control requires root"
    );
    ensure!(
        std::env::consts::ARCH == "x86_64",
        "host control requires x86-64"
    );
    ensure!(
        path.parent() == Some(Path::new("/etc/zdn/runtime/manifests")),
        "invalid host runtime manifest path"
    );
    let config = Config {
        root: Path::new("/"),
        owner: 0,
        node_owner: crate::image::RUNTIME_UID,
    };
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid host runtime manifest path")?;
    let manifest = Manifest::load(&config.open("/etc/zdn/runtime/manifests")?, name)?;
    let expected = fs::symlink_metadata(format!(
        "/etc/zdn/runtime/{}/zdn",
        manifest.runtime.helper.sha256
    ))?;
    let running = fs::metadata("/proc/self/exe")?;
    ensure!(
        expected.dev() == running.dev() && expected.ino() == running.ino(),
        "running native runtime differs"
    );
    Ok((manifest, config))
}

/// Seven control operations. Finite actions share one deadline/cleanup reserve
/// and the original installation lock. Produce only reads existing identity:
/// its activating parent holds that lock while systemd waits for it to start.
/// Each operation owns separate command receipts. Run/produce finally exec,
/// preserving systemd MainPID; no workload deadline follows that handoff.
/// Runtime selection never establishes first-install or producer authority.
pub fn dispatch(
    manifest: &Manifest,
    config: Config<'_>,
    operation: Operation,
    cancelled: &AtomicBool,
) -> Result<Option<Value>> {
    // This guard must close before exec replaces the process (no Rust drops).
    #[cfg(feature = "profiling")]
    let preflight = tracing::info_span!("host.runtime.control.dispatch").entered();
    let deadline = Instant::now() + operation.budget();
    manifest.validate()?;
    ensure!(config.root.is_absolute(), "host root must be absolute");
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "host operation cancelled"
    );
    let spec = &manifest.spec;
    let executable = config.executable(manifest)?;
    let metadata = config.open("/etc/zdn")?;
    // Control is not install: never recreate lost original identity as a side
    // effect of observing/stopping a service. acquire checks its exact bytes.
    let identity = volume::identity(spec)?;
    ensure!(
        metadata.read("identity.json", 8192)? == identity,
        "native runtime original identity differs"
    );
    let mut installation = if operation == Operation::Produce {
        None
    } else {
        Some(Installation::acquire(&metadata, spec)?)
    };
    let snapshot = revision::Snapshot::from_installation(&metadata, manifest)?;
    if let Some(snapshot) = &snapshot {
        if snapshot.transaction.is_some() {
            ensure!(
                metadata.read("native-install-intent.json", super::MAX_MANIFEST_BYTES)?
                    == manifest.bytes()?,
                "native image revision original intent differs"
            );
        }
        if matches!(operation, Operation::Produce | Operation::StartProducer) {
            ensure!(!snapshot.producer_hold, "producer maintenance is active");
        }
        if matches!(
            operation,
            Operation::Prepare | Operation::Run | Operation::Ready
        ) {
            if let Some(transaction) = &snapshot.transaction {
                ensure!(
                    transaction.phase != revision::Phase::Stopping,
                    "node startup is blocked during update stop"
                );
                if transaction.phase == revision::Phase::Activating {
                    ensure!(
                        snapshot
                            .active
                            .as_ref()
                            .map(|request| request.bytes())
                            .transpose()?
                            == Some(transaction.request.bytes()?),
                        "native target activation is incomplete"
                    );
                }
            }
        }
    }
    let active = snapshot.as_ref().and_then(|state| state.active.as_ref());
    let image = active
        .map(|request| request.image.image.as_str())
        .unwrap_or(&spec.image);
    let command_path = if operation == Operation::Produce {
        // The hardened producer unit supplies RuntimeDirectory=zdn-producer.
        // /etc is read-only there; receipts must not widen its durable writes.
        config
            .open("/run/zdn-producer")?
            .ensure_directory("commands", 0o700)?;
        config.path("/run/zdn-producer/commands")
    } else {
        metadata
            .ensure_directory("commands", 0o700)?
            .ensure_directory(operation.name(), 0o700)?;
        config.path(&format!("/etc/zdn/commands/{}", operation.name()))
    };
    let mut executor = Executor::new(
        executable,
        command_path,
        spec.helper.region.clone(),
        deadline,
    )?;
    let docker = config.tool("docker")?;
    if operation == Operation::Stop {
        if spec.block_interval_seconds.is_some() && spec.role == "producer" {
            let systemctl = config.tool("systemctl")?;
            executor.execute(
                HostCommand {
                    program: &systemctl,
                    args: &["stop".into(), "zdn-producer.service".into()],
                    stdin: None,
                    timeout: Duration::from_secs(35),
                    allowed: &[0],
                },
                cancelled,
            )?;
            producer::require_stopped(spec, &systemctl, &mut executor, cancelled)?;
        }
        container::cleanup(spec, image, &docker, &mut executor, cancelled)?;
        return Ok(None);
    }
    let artifacts = config.open("/etc/zdn/artifacts")?;
    let helper = config.path("/etc/zdn/artifacts/zdn");
    if operation == Operation::Produce {
        ensure!(
            spec.role == "producer"
                && spec.node_id == "node-1"
                && spec.block_interval_seconds.is_some(),
            "this host cannot own the block controller"
        );
        config.mounted(manifest, &identity, &mut executor, cancelled, true)?;
        let node = config.open(&spec.node_root())?;
        ensure!(
            producer::authorized(spec, &node)?,
            "block production has not been authorized"
        );
        // Avoid charging the entire chain bundle to the small producer cgroup.
        for (name, pin) in [("manifest.json", &spec.manifest), ("zdn", &spec.helper)] {
            let observed = artifacts.digest(name, pin.bytes)?;
            ensure!(
                observed.bytes == pin.bytes && observed.sha256 == pin.sha256,
                "producer artifact differs"
            );
            if name == "zdn" {
                crate::devnet::validate_helper(&observed.prefix)?;
            }
        }
        artifacts.executable("zdn")?;
        node.open_directory("producer")?;
        let args = vec![
            "chain".into(),
            "produce".into(),
            "--manifest".into(),
            config
                .path("/etc/zdn/artifacts/manifest.json")
                .into_os_string(),
            "--rpc-endpoint".into(),
            spec.runtime_options()?.rpc_listen_addr.into(),
            "--cookie-file".into(),
            config
                .path(&format!("{}/rpc/.cookie", spec.node_root()))
                .into_os_string(),
            "--state-dir".into(),
            config
                .path(&format!("{}/producer", spec.node_root()))
                .into_os_string(),
            "--deployment-id".into(),
            spec.deployment_id.to_string().into(),
            "--node-id".into(),
            spec.node_id.clone().into(),
            "--interval-secs".into(),
            spec.block_interval_seconds.unwrap().to_string().into(),
            "--request-timeout-secs".into(),
            "10".into(),
            "--deadline-secs".into(),
            "120".into(),
        ];
        ensure!(
            Instant::now() < executor.work_deadline()? && !cancelled.load(Ordering::Relaxed),
            "host operation interrupted"
        );
        drop(executor);
        drop(installation);
        #[cfg(feature = "profiling")]
        drop(preflight);
        return Err(Command::new(helper)
            .args(args)
            .env_clear()
            .envs(command::environment(&spec.helper.region))
            .exec()
            .into());
    }
    let mut installation = installation.take().expect("finite host operation guard");
    inputs::verify(spec, &artifacts)?;
    if let Some(request) = active {
        ensure!(
            config
                .open(&spec.node_root())?
                .read("bootstrap-complete.json", 8192)?
                == installation.identity(),
            "image revision requires original bootstrap completion"
        );
        let selected = config.open(&format!(
            "/etc/zdn/{}/{}",
            revision::NAMESPACE,
            request.update_id
        ))?;
        super::revision_delivery::verify(
            request,
            &selected,
            (operation == Operation::Prepare).then_some(docker.as_path()),
            &mut executor,
            cancelled,
        )?;
    }
    artifacts.executable("zdn")?;
    firewall::ensure_rules(
        &config.tool("iptables")?,
        &config.tool("ip6tables")?,
        operation == Operation::Prepare,
        &mut executor,
        cancelled,
    )?;
    if operation == Operation::Prepare {
        let tools = prepare::Tools {
            probe: config.probe_tools()?,
            mkfs_ext4: config.tool("mkfs.ext4")?,
            mount: config.tool("mount")?,
        };
        prepare::prepare(
            spec,
            prepare::Root {
                path: config.root,
                owner: config.owner,
            },
            &tools,
            &mut installation,
            &mut executor,
            cancelled,
            false,
        )?;
        let volume = config.open("/var/lib/zdn")?;
        node_paths::create(spec, &volume, &installation, config.node_owner)?;
        if active.is_none() {
            image_delivery::inspect(spec, &artifacts, &docker, &mut executor, cancelled)?;
        }
        container::cleanup(spec, image, &docker, &mut executor, cancelled)?;
        return Ok(None);
    }
    config.mounted(manifest, &identity, &mut executor, cancelled, false)?;
    let node = config.open(&spec.node_root())?;
    ensure!(
        node.read("zakura.toml", 8 * 1024 * 1024)? == spec.config_toml.as_bytes(),
        "node configuration differs"
    );
    if operation == Operation::Run {
        let resources = capacity::observe(config.root, CgroupScope::CurrentAndAncestors)?;
        let args = container::arguments(spec, image, &resources)?;
        ensure!(
            Instant::now() < executor.work_deadline()? && !cancelled.load(Ordering::Relaxed),
            "host operation interrupted"
        );
        drop(executor);
        drop(installation);
        #[cfg(feature = "profiling")]
        drop(preflight);
        // systemd must not start Ready while Run still owns install.lock.
        // This releases ExecStartPost, which retains actual chain readiness;
        // an exec failure still fails the service through its main process.
        if let Some(socket) = std::env::var_os("NOTIFY_SOCKET") {
            let address = if let Some(name) = socket.as_encoded_bytes().strip_prefix(b"@") {
                SocketAddr::from_abstract_name(name)?
            } else {
                SocketAddr::from_pathname(Path::new(&socket))?
            };
            let notify = UnixDatagram::unbound()?;
            notify.set_write_timeout(Some(Duration::from_secs(1)))?;
            ensure!(
                notify.send_to_addr(b"READY=1", &address)? == 7,
                "host startup notification failed"
            );
        }
        return Err(Command::new(docker)
            .args(args)
            .env_clear()
            .envs(command::environment(&spec.helper.region))
            .exec()
            .into());
    }
    let systemctl = config.tool("systemctl")?;
    let chain_manifest = config.path("/etc/zdn/artifacts/manifest.json");
    let bundle = config.path("/etc/zdn/artifacts/chain.tar");
    let cookie = config.path(&format!("{}/rpc/.cookie", spec.node_root()));
    let state = config.path(&format!("{}/producer", spec.node_root()));
    let readiness = readiness::Config {
        spec,
        image,
        installation: &installation,
        node: &node,
        helper: &helper,
        manifest: &chain_manifest,
        bundle: &bundle,
        cookie: &cookie,
        producer_state: &state,
        systemctl: &systemctl,
        docker: &docker,
        kernel_root: config.root,
    };
    if operation == Operation::StartProducer {
        #[cfg(feature = "profiling")]
        let _startup = tracing::info_span!("host.runtime.control.start_producer").entered();
        ensure!(
            spec.role == "producer"
                && spec.node_id == "node-1"
                && spec.block_interval_seconds.is_some(),
            "this host cannot own the block controller"
        );
        ensure!(
            readiness::bootstrap_completed(&readiness)?,
            "block production requires completed first bootstrap"
        );
        readiness::readiness(&readiness, &mut executor, cancelled, false)?;
        node.publish(
            "producer-authorized.json",
            &producer::authorization(spec)?,
            0o600,
        )?;
        producer::start(&systemctl, &mut executor, cancelled)?;
        let until = (Instant::now() + Duration::from_secs(150)).min(executor.work_deadline()?);
        while !producer::observe(
            spec,
            &node,
            &state,
            &systemctl,
            &mut executor,
            cancelled,
            true,
        )?
        .scheduled_producer
        {
            ensure!(
                !cancelled.load(Ordering::Relaxed) && Instant::now() < until,
                "controller did not become ready before its deadline"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
    let mut report = readiness::readiness(
        &readiness,
        &mut executor,
        cancelled,
        operation == Operation::Ready && active.is_none(),
    )?;
    if let Some(request) = active {
        report["updateId"] = Value::String(request.update_id.to_string());
    }
    ensure!(
        Instant::now() < executor.work_deadline()? && !cancelled.load(Ordering::Relaxed),
        "host operation interrupted"
    );
    Ok(Some(report))
}
