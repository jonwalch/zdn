//! Native lightwallet container supervisor. The privileged runtime entry point
//! authenticates typed specs, tools, filesystem/kernel anchors and owners and
//! enforces root invocation. Alternate anchors are for offline fixtures.
//!
//! Files are opened descriptor-relatively without links. Trusted owners must
//! not concurrently replace ancestors/mounts; this is not a hostile-root
//! sandbox. Attached clients use the existing session supervisor and durable
//! cleanup receipts, independently of Docker-daemon container ownership.
//!
//! Source mapping: `secure_read`/`root_directory` -> descriptor directory/read
//! operations; `read_cookie`/`write_credentials` -> cookie/atomic credentials;
//! `verify_cache`, `verify_node_and_image`, `cleanup_container`, `supervise`
//! retain their checks and lifecycle here. `effective_capacity` reuses native
//! host capacity observation, excluding only the validated systemd leaf, and
//! the existing service-budget validator (including its online-CPU ceiling).
//! `command` reuses the host executor with a separate fixed PATH/HOME-only,
//! 1 MiB policy. `stop_child` reuses full-session cleanup (including changed
//! process groups), not merely the original process group. The opt-in client
//! protocol omits a deadline entirely; existing finite protocols are unchanged.
//!
//! Deliberate hardening: full inspected Docker IDs bind all mutations; fresh
//! absence is required even after failed kill/rm; foreign credential entries
//! are not replaced/unlinked; directory creation and replacement use pinned
//! descriptors and directory fsync. Unconfirmed session receipts block launch
//! but not prior daemon reconciliation. Recipe identities and deployment gates
//! are enforced by the native installer/runtime. This API neither
//! installs nor qualifies any service, and cannot contain hostile setsid/UID
//! escapes (the same trusted-tool boundary as the existing supervisor).

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use eyre::{ensure, ContextCompat, Result};
use nix::{
    errno::Errno,
    fcntl::{open, openat, renameat, OFlag},
    sys::stat::{fchmod, mkdirat, Mode},
    unistd::{fchown, unlinkat, Gid, Uid, UnlinkatFlags},
};
use serde_json::{json, Value};

use super::{
    hash, render_service, rpc_endpoint, LightwalletServiceSpec, RenderedLightwalletService,
};
use crate::{
    host::{
        capacity::{observe, CgroupScope},
        command::{Executor, HostCommand},
        files::Directory,
        HostInstallSpec,
    },
    pulumi::{CommandSpec, ProcessLimits},
    pulumi_process::Supervisor,
};

/// Explicit trusted executables. No ambient PATH lookup selects a tool.
pub struct Tools {
    pub docker: PathBuf,
    pub lsblk: PathBuf,
    pub findmnt: PathBuf,
    pub iptables: PathBuf,
    pub ip6tables: PathBuf,
    /// This build's zdn executable, providing the internal session protocol.
    pub supervisor: PathBuf,
}

/// Caller-authenticated inputs, deliberately not Debug (host config is private).
pub struct RuntimeConfig {
    pub host: HostInstallSpec,
    pub service: LightwalletServiceSpec,
    /// `/` in production; ancestor trust is the caller's responsibility.
    pub filesystem_root: PathBuf,
    /// Trusted proc/ and sys/ tree, normally `/`.
    pub kernel_root: PathBuf,
    pub root_uid: u32,
    pub node_uid: u32,
    pub node_gid: u32,
    pub tools: Tools,
    /// Cookie checks and cancellation latency; must be in (0, 1 second].
    pub poll_interval: Duration,
}

/// Blocks for the daemon lifetime. Cancellation is cooperative; cleanup ignores
/// the cancellation flag so Docker stop and session reaping still complete.
/// Errors deliberately disclose no tool output, cookie or configuration bytes.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_runtime.supervise")
)]
pub fn supervise(config: RuntimeConfig, cancelled: &AtomicBool) -> Result<()> {
    (|| run(validated_runtime(config)?, cancelled))()
        .map_err(|_: eyre::Report| eyre::eyre!("zdn lightwalletd supervisor failed"))
}

/// Finite observation, without launch, credential publication or supervisor lock.
/// `None` means freshly absent; `Some(false)` means an allowed created container;
/// `Some(true)` means running. All present containers must satisfy install policy.
/// Host/cache/image authentication remains the controller's responsibility.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_runtime.observe_container")
)]
pub fn observe_container(
    config: RuntimeConfig,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    allow_starting: bool,
) -> Result<Option<bool>> {
    (|| {
        let rt = validated_runtime(config)?;
        let record = rt.inspect_owned(&mut |args, timeout, allowed| {
            finite_docker(&rt, executor, cancelled, args, timeout, allowed)
        })?;
        record
            .map(|record| rt.verify_container_policy(&record, allow_starting))
            .transpose()
    })()
    .map_err(|_| eyre::eyre!("zdn lightwalletd observation failed"))
}

/// Finite full-ID cleanup with fresh absence confirmation and descriptor-safe
/// removal of known credentials. Uses the caller's cumulative command budget
/// and cancellation, unlike the daemon's deliberately uncancellable cleanup.
/// Does not launch, create runtime directories, or acquire the supervisor lock.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_runtime.cleanup_container_finite")
)]
pub fn cleanup_container(
    config: RuntimeConfig,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    (|| {
        let rt = validated_runtime(config)?;
        let docker = rt.reap_container(&mut |args, timeout, allowed| {
            finite_docker(&rt, executor, cancelled, args, timeout, allowed)
        });
        let credentials = rt.remove_credentials();
        docker?;
        credentials
    })()
    .map_err(|_| eyre::eyre!("zdn lightwalletd cleanup failed"))
}

type DockerCommand<'a> = dyn FnMut(&[&str], u64, &[i32]) -> Result<Vec<u8>> + 'a;

fn finite_docker(
    rt: &Runtime,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    args: &[&str],
    timeout: u64,
    allowed: &[i32],
) -> Result<Vec<u8>> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    Ok(executor
        .execute(
            HostCommand {
                program: &rt.config.tools.docker,
                args: &args,
                stdin: None,
                timeout: Duration::from_secs(timeout),
                allowed,
            },
            cancelled,
        )?
        .stdout)
}

struct Runtime {
    config: RuntimeConfig,
    rendered: RenderedLightwalletService,
    root: File,
    runtime: PathBuf,
    commands: PathBuf,
    client_receipts: PathBuf,
    name: String,
}

// Read-only construction: finite controllers neither create directories nor lock
// the supervisor's lifetime domain, and do not require its cgroup membership.
fn validated_runtime(config: RuntimeConfig) -> Result<Runtime> {
    ensure!(
        config.filesystem_root.is_absolute()
            && config.kernel_root.is_absolute()
            && !config.poll_interval.is_zero()
            && config.poll_interval <= Duration::from_secs(1),
        "invalid runtime anchors or interval"
    );
    for tool in [
        &config.tools.docker,
        &config.tools.lsblk,
        &config.tools.findmnt,
        &config.tools.iptables,
        &config.tools.ip6tables,
        &config.tools.supervisor,
    ] {
        ensure!(tool.is_absolute(), "tool path must be absolute");
    }
    let rendered = render_service(&config.host, &config.service)?;
    let runtime = Path::new(&rendered.credential_path)
        .parent()
        .and_then(Path::parent)
        .context("invalid credential path")?
        .to_path_buf();
    let root = File::from(open(
        &config.filesystem_root,
        directory_flags(),
        Mode::empty(),
    )?);
    trusted_directory(&root, config.root_uid, None)?;
    let rt = Runtime {
        name: format!(
            "zdn-lightwalletd-{}-{}",
            config.host.deployment_id, config.host.node_id
        ),
        commands: runtime.join("commands"),
        client_receipts: runtime.join("client"),
        config,
        rendered,
        root,
        runtime,
    };
    Ok(rt)
}

fn run(rt: Runtime, cancelled: &AtomicBool) -> Result<()> {
    rt.directory(&rt.runtime, true, rt.config.root_uid, Some(0o700))?;
    let lock_directory = Directory::open(&rt.physical(&rt.runtime)?, rt.config.root_uid)?;
    let _lock = lock_directory.lock("supervisor.lock")?;
    rt.directory(&rt.commands, true, rt.config.root_uid, Some(0o700))?;
    rt.directory(&rt.client_receipts, true, rt.config.root_uid, Some(0o700))?;
    let mut child: Option<Supervisor> = None;
    let mut cache_verified = false;
    let outcome = (|| {
        rt.verify_cache()?;
        cache_verified = true;
        rt.verify_node()?;
        // Recovery precedes cookie read, including a missing/malformed cookie.
        rt.cleanup_container()?;
        crate::pulumi_process::ensure_cleanup(&rt.physical(&rt.client_receipts)?)?;
        let mut cookie = rt.cookie()?;
        rt.write_credentials(&cookie)?;
        ensure!(!cancelled.load(Ordering::Relaxed), "service cancelled");
        child = Some(rt.start()?);
        // One lifetime span, never a span per poll or ordinary cookie check.
        #[cfg(feature = "profiling")]
        let _supervision = tracing::info_span!("lightwallet_runtime.supervision_loop").entered();
        loop {
            if cancelled.load(Ordering::Relaxed) {
                return Ok(());
            }
            ensure!(
                child.as_mut().context("missing client")?.poll()?.is_none(),
                "client exited"
            );
            std::thread::sleep(rt.config.poll_interval);
            if cancelled.load(Ordering::Relaxed) {
                return Ok(());
            }
            let updated = rt.cookie()?;
            if updated != cookie {
                #[cfg(feature = "profiling")]
                let _rotation = tracing::info_span!("lightwallet_runtime.rotate_restart").entered();
                // Both cleanup domains run even when daemon stop fails.
                let docker = rt.cleanup_container();
                let attached = stop_client(&mut child);
                docker?;
                attached?;
                rt.verify_cache()?;
                rt.verify_node()?;
                rt.write_credentials(&updated)?;
                cookie = updated;
                ensure!(!cancelled.load(Ordering::Relaxed), "service cancelled");
                child = Some(rt.start()?);
            }
        }
    })();
    // On all exits after successful cache validation reconcile the daemon,
    // even if launch failed before returning an attached-client handle.
    #[cfg(feature = "profiling")]
    let _cleanup = tracing::info_span!("lightwallet_runtime.cleanup").entered();
    let docker = if cache_verified {
        rt.cleanup_container()
    } else {
        Ok(())
    };
    let attached = stop_client(&mut child);
    let credentials = rt.remove_credentials();
    docker?;
    attached?;
    credentials?;
    outcome
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_runtime.stop_client")
)]
fn stop_client(child: &mut Option<Supervisor>) -> Result<()> {
    if let Some(mut supervisor) = child.take() {
        supervisor.stop(false);
        supervisor.finish_status(|| false)?;
    }
    Ok(())
}

impl Runtime {
    fn verify_container_policy(&self, record: &Value, allow_starting: bool) -> Result<bool> {
        let config = &record["Config"];
        let host = &record["HostConfig"];
        let args = &self.rendered.docker_arguments;
        let option = |key: &str| -> Result<&str> {
            let index = args
                .iter()
                .position(|v| v == key)
                .context("missing rendered option")?;
            args.get(index + 1)
                .map(String::as_str)
                .context("missing rendered value")
        };
        let image = args
            .iter()
            .position(|v| v == &self.config.service.image)
            .context("missing rendered image")?;
        let running = record["State"]["Running"]
            .as_bool()
            .context("missing container state")?;
        ensure!(
            running || (allow_starting && record["State"]["Status"] == "created"),
            "container not running"
        );
        ensure!(
            config["User"] == option("--user")?
                && config["WorkingDir"] == option("--workdir")?
                && config["Entrypoint"] == json!([option("--entrypoint")?])
                && config["Cmd"] == json!(&args[image + 1..])
                && config["StopSignal"] == option("--stop-signal")?
                && config["Healthcheck"]["Test"] == json!(["NONE"])
                && host["NetworkMode"] == option("--network")?
                && host["ReadonlyRootfs"] == true
                && host["Privileged"] == false
                && (host["CapAdd"].is_null() || host["CapAdd"] == json!([]))
                && host["CapDrop"] == json!([option("--cap-drop")?])
                && host["PidsLimit"] == option("--pids-limit")?.parse::<u64>()?
                && host["PidMode"] == ""
                && host["LogConfig"]["Type"] == option("--log-driver")?
                && (host["SecurityOpt"] == json!(["no-new-privileges"])
                    || host["SecurityOpt"] == json!([option("--security-opt")?]))
                && host["Memory"] == self.config.service.memory_bytes
                && host["MemorySwap"] == self.config.service.memory_bytes
                && host["NanoCpus"] == u64::from(self.config.service.cpu_millis) * 1_000_000,
            "unsafe container policy"
        );
        let mounts = record["Mounts"].as_array().context("missing mounts")?;
        let mut expected = BTreeMap::new();
        for pair in args.windows(2).filter(|p| p[0] == "--mount") {
            let (source, tail) = pair[1]
                .strip_prefix("type=bind,src=")
                .context("invalid bind")?
                .split_once(",dst=")
                .context("invalid bind")?;
            let (destination, rw) = tail
                .strip_suffix(",readonly")
                .map_or((tail, true), |s| (s, false));
            expected.insert(self.physical(Path::new(source))?, (destination, rw));
        }
        for mount in mounts {
            if mount["Type"] == "bind" {
                let source = Path::new(mount["Source"].as_str().context("missing source")?);
                let (destination, rw) = expected.remove(source).context("unexpected bind")?;
                ensure!(
                    mount["Destination"] == destination && mount["RW"] == rw,
                    "bind differs"
                );
            } else {
                ensure!(
                    mount["Type"] == "tmpfs" && mount["Destination"] == "/tmp",
                    "unexpected mount"
                );
            }
        }
        ensure!(expected.is_empty(), "missing binds");
        Ok(running)
    }

    fn physical(&self, path: &Path) -> Result<PathBuf> {
        ensure!(path.is_absolute(), "absolute logical path required");
        ensure!(
            path.components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "invalid logical path"
        );
        Ok(self.config.filesystem_root.join(path.strip_prefix("/")?))
    }

    fn directory(&self, path: &Path, create: bool, owner: u32, exact: Option<u32>) -> Result<File> {
        self.physical(path)?;
        let parts: Vec<_> = path.strip_prefix("/")?.components().collect();
        let mut current = self.root.try_clone()?;
        for (index, part) in parts.iter().enumerate() {
            let name = part.as_os_str();
            let last = index + 1 == parts.len();
            if create {
                match mkdirat(
                    &current,
                    name,
                    Mode::from_bits_truncate(if last { exact.unwrap_or(0o700) } else { 0o700 }),
                ) {
                    Ok(()) => {
                        let new =
                            File::from(openat(&current, name, directory_flags(), Mode::empty())?);
                        fchmod(
                            &new,
                            Mode::from_bits_truncate(if last {
                                exact.unwrap_or(0o700)
                            } else {
                                0o700
                            }),
                        )?;
                    }
                    Err(Errno::EEXIST) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            current = File::from(openat(&current, name, directory_flags(), Mode::empty())?);
            trusted_directory(
                &current,
                if last { owner } else { self.config.root_uid },
                if last { exact } else { None },
            )?;
        }
        Ok(current)
    }

    fn read(&self, path: &Path, owner: u32, limit: u64, rpc: bool) -> Result<Vec<u8>> {
        let parent = self.directory(
            path.parent().context("missing parent")?,
            false,
            if rpc {
                self.config.node_uid
            } else {
                self.config.root_uid
            },
            if rpc { Some(0o700) } else { None },
        )?;
        private_read(
            &parent,
            path.file_name().context("missing filename")?,
            owner,
            limit,
        )
    }

    fn command(
        &self,
        tool: &Path,
        args: &[&str],
        timeout: u64,
        allowed: &[i32],
    ) -> Result<Vec<u8>> {
        let mut executor = Executor::lightwallet(
            self.config.tools.supervisor.clone(),
            self.physical(&self.commands)?,
        )?;
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        Ok(executor
            .execute(
                HostCommand {
                    program: tool,
                    args: &args,
                    stdin: None,
                    timeout: Duration::from_secs(timeout),
                    allowed,
                },
                &AtomicBool::new(false),
            )?
            .stdout)
    }

    fn docker(&self, args: &[&str], timeout: u64, allowed: &[i32]) -> Result<Vec<u8>> {
        self.command(&self.config.tools.docker, args, timeout, allowed)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.verify_cache")
    )]
    fn verify_cache(&self) -> Result<()> {
        let cache = Path::new(&self.rendered.cache_root);
        self.directory(cache, false, self.config.root_uid, None)?;
        let identity: Value = serde_json::from_slice(&self.read(
            &cache.join(".zdn-lightwalletd-volume.json"),
            self.config.root_uid,
            8192,
            false,
        )?)?;
        ensure!(
            identity == serde_json::from_str::<Value>(&self.rendered.cache_identity_json)?,
            "cache identity differs"
        );
        let volumes: Value = serde_json::from_slice(&self.command(
            &self.config.tools.lsblk,
            &[
                "--json",
                "--bytes",
                "--output",
                "PATH,TYPE,SERIAL,SIZE,MAJ:MIN,MOUNTPOINTS",
            ],
            10,
            &[0],
        )?)?;
        let matches: Vec<_> = volumes["blockdevices"]
            .as_array()
            .context("missing volumes")?
            .iter()
            .filter(|v| {
                v["serial"].as_str().unwrap_or("").replace('-', "")
                    == self.config.service.cache_volume_id.replace('-', "")
            })
            .collect();
        ensure!(matches.len() == 1, "cache volume missing or ambiguous");
        let volume = matches[0];
        let cache_path = self.physical(cache)?;
        let cache_path = cache_path.to_str().context("cache path is not UTF-8")?;
        ensure!(
            volume["type"] == "disk"
                && no_children(volume)
                && integer(&volume["size"]) == Some(self.config.service.cache_bytes)
                && volume["mountpoints"] == json!([cache_path]),
            "cache disk differs"
        );
        let mounts: Value = serde_json::from_slice(&self.command(
            &self.config.tools.findmnt,
            &[
                "--json",
                "--mountpoint",
                cache_path,
                "--output",
                "SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN,FSROOT",
            ],
            10,
            &[0],
        )?)?;
        let mounts = mounts["filesystems"].as_array().context("missing mounts")?;
        ensure!(mounts.len() == 1, "ambiguous cache mount");
        let mount = &mounts[0];
        let options: Vec<_> = mount["options"]
            .as_str()
            .context("missing options")?
            .split(',')
            .collect();
        ensure!(
            mount["target"] == cache_path
                && mount["source"].as_str().is_some()
                && volume["path"].as_str().is_some()
                && mount["source"] == volume["path"]
                && mount["maj:min"].as_str().is_some()
                && mount["maj:min"] == volume["maj:min"]
                && mount["fsroot"] == "/"
                && mount["fstype"] == "ext4"
                && no_children(mount)
                && ["rw", "nodev", "nosuid", "noexec"]
                    .iter()
                    .all(|o| options.contains(o))
                && !options.contains(&"ro"),
            "cache mount differs"
        );
        self.directory(
            &cache.join("data"),
            false,
            self.config.node_uid,
            Some(0o700),
        )?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.verify_node")
    )]
    fn verify_node(&self) -> Result<()> {
        let host = &self.config.host;
        let install_hash = hash(&serde_json::to_vec(host)?);
        let identity: Value = serde_json::from_slice(&self.read(
            Path::new("/etc/zdn/volume-claimed.json"),
            self.config.root_uid,
            8192,
            false,
        )?)?;
        ensure!(
            identity
                == json!({"apiVersion":"zdn-host-volume/v1alpha1", "deploymentId":host.deployment_id,
            "nodeId":host.node_id, "volumeId":host.volume_id, "consensusFingerprint":host.consensus_fingerprint,
            "installSha256":install_hash}),
            "node identity differs"
        );
        let mut membership = String::new();
        File::open(self.config.kernel_root.join("proc/self/cgroup"))?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut membership)?;
        ensure!(
            membership.len() <= 1024 * 1024,
            "cgroup membership exceeds bound"
        );
        let unified: Vec<_> = membership
            .lines()
            .filter_map(|l| l.strip_prefix("0::"))
            .collect();
        ensure!(
            unified.len() == 1
                && Path::new(unified[0]).file_name() == Some("zdn-lightwalletd.service".as_ref()),
            "unexpected supervisor cgroup"
        );
        let mut service = self.config.service.clone();
        service.host_observation = observe(&self.config.kernel_root, CgroupScope::AncestorsOnly)?;
        service.validate(host)?;
        let name = format!("zdn-{}-{}", host.deployment_id, host.node_id);
        let nodes: Value =
            serde_json::from_slice(&self.docker(&["container", "inspect", &name], 10, &[0])?)?;
        let node = single(&nodes)?;
        let memory = node["HostConfig"]["Memory"]
            .as_u64()
            .context("node memory missing")?;
        let cpu = node["HostConfig"]["NanoCpus"]
            .as_u64()
            .context("node CPU missing")?;
        ensure!(
            node["State"]["Running"] == true
                && node["Config"]["Image"] == host.image
                && node["Config"]["Labels"]["zdn.install"] == install_hash
                && memory > 0
                && memory <= host.memory_bytes
                && node["HostConfig"]["MemorySwap"] == memory
                && cpu > 0
                && cpu <= u64::from(host.cpu_millis) * 1_000_000,
            "node budget or identity differs"
        );
        let images: Value = serde_json::from_slice(&self.docker(
            &["image", "inspect", &self.config.service.image],
            10,
            &[0],
        )?)?;
        let image = single(&images)?;
        ensure!(
            image["Os"] == "linux"
                && image["Architecture"] == "amd64"
                && image["RepoDigests"]
                    .as_array()
                    .context("image digests missing")?
                    .contains(&json!(self.config.service.image)),
            "image differs"
        );
        let uid = self.config.node_uid.to_string();
        for (tool, address) in [
            (&self.config.tools.iptables, "169.254.169.254/32"),
            (&self.config.tools.ip6tables, "fd00:ec2::254/128"),
        ] {
            self.command(
                tool,
                &[
                    "--wait",
                    "5",
                    "--check",
                    "OUTPUT",
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid,
                    "-d",
                    address,
                    "-j",
                    "REJECT",
                ],
                10,
                &[0],
            )?;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.cleanup_container")
    )]
    fn cleanup_container(&self) -> Result<()> {
        self.reap_container(&mut |args, timeout, allowed| self.docker(args, timeout, allowed))
    }

    fn inspect_owned(&self, command: &mut DockerCommand<'_>) -> Result<Option<Value>> {
        let filter = format!("name=^/{}$", self.name);
        let list = |command: &mut DockerCommand<'_>| {
            command(
                &[
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    &filter,
                    "--format",
                    "{{.ID}}",
                ],
                10,
                &[0],
            )
        };
        let raw = list(command)?;
        let id = std::str::from_utf8(&raw)?.trim();
        if id.is_empty() {
            return Ok(None);
        }
        ensure!(
            (12..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "ambiguous container ID"
        );
        let inspected = match command(&["container", "inspect", id], 10, &[0]) {
            Ok(inspected) => inspected,
            Err(error) => {
                // --rm can race the inspection after a natural client exit.
                // No mutation is safe without identity, but fresh absence is.
                if list(command)?.iter().all(u8::is_ascii_whitespace) {
                    return Ok(None);
                }
                return Err(error);
            }
        };
        let records: Value = serde_json::from_slice(&inspected)?;
        let record = single(&records)?;
        // Bind the inspected full ID too; subsequent operations never use a name.
        let full = record["Id"].as_str().context("container ID missing")?;
        ensure!(
            full.len() == 64
                && full.starts_with(id)
                && full
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && record["Name"] == format!("/{}", self.name)
                && record["Config"]["Image"] == self.config.service.image
                && record["Config"]["Labels"]["zdn.lightwalletd"] == self.rendered.service_sha256,
            "foreign surviving container"
        );
        Ok(Some(record.clone()))
    }

    fn reap_container(&self, command: &mut DockerCommand<'_>) -> Result<()> {
        let Some(record) = self.inspect_owned(command)? else {
            return Ok(());
        };
        let full = record["Id"].as_str().context("container ID missing")?;
        let running = record["State"]["Running"]
            .as_bool()
            .context("missing container state")?;
        if running && command(&["stop", "--time", "30", full], 40, &[0]).is_err() {
            let _ = command(&["kill", "--signal", "KILL", full], 10, &[0, 1]);
        }
        let _ = command(&["container", "rm", full], 10, &[0, 1]);
        let filter = format!("name=^/{}$", self.name);
        ensure!(
            command(
                &[
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    &filter,
                    "--format",
                    "{{.ID}}"
                ],
                10,
                &[0]
            )?
            .iter()
            .all(u8::is_ascii_whitespace),
            "container cleanup incomplete"
        );
        Ok(())
    }

    fn cookie(&self) -> Result<Vec<u8>> {
        let raw = self.read(
            &Path::new(&self.config.host.node_root()).join("rpc/.cookie"),
            self.config.node_uid,
            1024,
            true,
        )?;
        let cookie = raw
            .strip_suffix(b"\r\n")
            .or_else(|| raw.strip_suffix(b"\n"))
            .unwrap_or(&raw);
        ensure!(
            cookie.len() == 55
                && cookie.starts_with(b"__cookie__:")
                && cookie[54] == b'='
                && cookie[11..54]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b)),
            "invalid authentication cookie"
        );
        Ok(cookie.to_vec())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.write_credentials")
    )]
    fn write_credentials(&self, cookie: &[u8]) -> Result<()> {
        let parent = self.directory(
            &self.runtime.join("credentials"),
            true,
            self.config.root_uid,
            Some(0o755),
        )?;
        self.check_credentials(&parent)?;
        let endpoint = rpc_endpoint(&self.config.host)?;
        let mut bytes = format!(
            "rpcbind={}\nrpcport={}\nrpcuser=__cookie__\nrpcpassword=",
            endpoint.ip(),
            endpoint.port()
        )
        .into_bytes();
        bytes.extend_from_slice(&cookie[11..]);
        bytes.push(b'\n');
        let name = format!(".pending-{}", uuid::Uuid::new_v4());
        let result = (|| {
            let mut file = File::from(openat(
                &parent,
                name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR,
            )?);
            fchown(
                &file,
                Some(Uid::from_raw(self.config.node_uid)),
                Some(Gid::from_raw(self.config.node_gid)),
            )?;
            fchmod(&file, Mode::S_IRUSR)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            renameat(&parent, name.as_str(), &parent, "zcash.conf")?;
            parent.sync_all()?;
            Ok(())
        })();
        let _ = unlinkat(&parent, name.as_str(), UnlinkatFlags::NoRemoveDir);
        result
    }

    fn check_credentials(&self, parent: &File) -> Result<bool> {
        match private_file(parent, "zcash.conf".as_ref(), self.config.node_uid, 8192) {
            Ok(file) => {
                let metadata = file.metadata()?;
                ensure!(
                    metadata.mode() & 0o7777 == 0o400 && metadata.gid() == self.config.node_gid,
                    "foreign credential entry"
                );
                Ok(true)
            }
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.remove_credentials")
    )]
    fn remove_credentials(&self) -> Result<()> {
        let parent = match self.directory(
            &self.runtime.join("credentials"),
            false,
            self.config.root_uid,
            Some(0o755),
        ) {
            Ok(parent) => parent,
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        };
        if self.check_credentials(&parent)? {
            unlinkat(&parent, "zcash.conf", UnlinkatFlags::NoRemoveDir)?;
            parent.sync_all()?;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_runtime.start_client")
    )]
    fn start(&self) -> Result<Supervisor> {
        let mut args = self.rendered.docker_arguments.clone();
        // Logical host paths map only through the caller's trusted anchor.
        for argument in &mut args {
            if let Some(rest) = argument.strip_prefix("type=bind,src=") {
                let (source, tail) = rest.split_once(",dst=").context("invalid bind argument")?;
                *argument = format!(
                    "type=bind,src={},dst={tail}",
                    self.physical(Path::new(source))?.display()
                );
            }
        }
        let spec = CommandSpec {
            label: "lightwallet-client".into(),
            program: self.config.tools.docker.clone(),
            args: args.into_iter().map(OsString::from).collect(),
            env: environment(),
            cwd: self.physical(&self.runtime)?,
            diagnostics_dir: self.physical(&self.client_receipts)?,
            limits: ProcessLimits {
                timeout: Duration::from_secs(1),
                shutdown_grace: Duration::from_secs(5),
                max_output_bytes: 1024 * 1024,
                poll_interval: self.config.poll_interval,
            },
        };
        Supervisor::spawn_daemon(
            &self.config.tools.supervisor,
            &spec,
            &self.physical(&self.client_receipts)?,
        )
    }
}

fn environment() -> BTreeMap<OsString, OsString> {
    [
        ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/nonexistent"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn trusted_directory(file: &File, owner: u32, exact: Option<u32>) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == owner
            && metadata.mode() & 0o022 == 0
            && exact.is_none_or(|mode| metadata.mode() & 0o7777 == mode),
        "untrusted directory"
    );
    Ok(())
}

fn private_file(parent: &File, name: &std::ffi::OsStr, owner: u32, limit: u64) -> Result<File> {
    let file = File::from(openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == owner
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() <= 1
            && metadata.len() <= limit,
        "untrusted private input"
    );
    Ok(file)
}

fn private_read(parent: &File, name: &std::ffi::OsStr, owner: u32, limit: u64) -> Result<Vec<u8>> {
    let file = private_file(parent, name, owner, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "private input exceeds bound");
    Ok(bytes)
}

fn single(value: &Value) -> Result<&Value> {
    let values = value.as_array().context("missing records")?;
    ensure!(values.len() == 1, "expected one record");
    Ok(&values[0])
}

fn integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
fn no_children(value: &Value) -> bool {
    value["children"].is_null() || value["children"].as_array().is_some_and(Vec::is_empty)
}
