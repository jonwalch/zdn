//! Native cache preparation, adapted from retired install.py cache operations.
//!
//! Caller authenticates native selection separately. Root/owner, executable
//! paths, ancestors, /dev and the kernel/tool view must be trusted and stable.
//! Alternate roots are fixture anchors, not sandboxes; tools must report the
//! same physical tree. Observations alone never authorize mutation. No cache
//! zero-scan fallback exists. BlockDevice retains its real-block-device check
//! and real /sys counters (not a caller-injected counter implementation).
//! Point-in-time checks cannot exclude hostile-root/hotplug races or interrupt
//! a blocked kernel read; an enclosing supervisor is required for that bound.
//!
//! Cache-specific parsing is intentional: node evidence/probe APIs bind the
//! chain serial and /var/lib/zdn, omit cache size/major:minor/options checks,
//! and allow different mounts. Reuse their device/counter implementation, not
//! fabricated HostInstallSpec cache fields. All tools share Executor's action
//! deadline and cleanup reserve. Native lightwallet installation uses this API.

use super::Installation;
use crate::{
    host::{
        command::{Executor, HostCommand, Output},
        files::Directory,
        volume::device::BlockDevice,
    },
    lightwallet_service::{render_service, LightwalletInstallSpec},
};
use eyre::{ensure, ContextCompat, Result};
use serde_json::Value;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub struct Root<'a> {
    pub path: &'a Path,
    pub owner: u32,
    /// Production UID/GID 10001; never inferred from existing files.
    pub node_owner: u32,
}

pub struct Tools {
    pub lsblk: PathBuf,
    pub findmnt: PathBuf,
    pub blkid: PathBuf,
    pub wipefs: PathBuf,
    pub blockdev: PathBuf,
    pub mkfs_ext4: PathBuf,
    pub mount: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub device: PathBuf,
    pub major_minor: String,
    pub mounted: bool,
    inventory: Value,
}

fn check(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(Ordering::SeqCst),
        "cache preparation cancelled"
    );
    ensure!(Instant::now() < deadline, "cache preparation timed out");
    Ok(())
}

fn command(
    executor: &mut Executor,
    tool: &Path,
    args: &[OsString],
    allowed: &[i32],
    timeout: u64,
    cancelled: &AtomicBool,
) -> Result<Output> {
    let deadline = executor.work_deadline()?;
    check(deadline, cancelled)?;
    ensure!(tool.is_absolute(), "cache tool must be absolute");
    executor.execute(
        HostCommand {
            program: tool,
            args,
            stdin: None,
            timeout: Duration::from_secs(timeout).min(
                deadline
                    .checked_duration_since(Instant::now())
                    .context("cache preparation timed out")?,
            ),
            allowed,
        },
        cancelled,
    )
}

fn parse(raw: &[u8]) -> Result<Value> {
    ensure!(raw.len() <= 16 * 1024 * 1024, "cache observation too large");
    serde_json::from_slice(raw).map_err(|_| eyre::eyre!("invalid cache observation"))
}
fn empty_children(v: &Value) -> bool {
    v["children"].is_null() || v["children"].as_array().is_some_and(Vec::is_empty)
}
fn number(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}
fn walk<'a>(devices: &'a [Value], serial: &str, found: &mut Vec<&'a Value>) -> Result<()> {
    for device in devices {
        if device["serial"]
            .as_str()
            .is_some_and(|s| s.replace('-', "") == serial)
        {
            found.push(device);
        }
        if !device["children"].is_null() {
            walk(
                device["children"]
                    .as_array()
                    .context("invalid cache children")?,
                serial,
                found,
            )?;
        }
    }
    Ok(())
}

/// Read-only observation, explicitly NOT a claim or formatting authorization.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.cache.observe")
)]
pub fn observe(
    spec: &LightwalletInstallSpec,
    root: &Root<'_>,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<Observation> {
    spec.validate()?;
    ensure!(root.path.is_absolute(), "cache root must be absolute");
    let cache = cache_path(spec, root.path)?;
    let raw = command(
        executor,
        &tools.lsblk,
        &[
            "--json".into(),
            "--bytes".into(),
            "--paths".into(),
            "--output".into(),
            "PATH,TYPE,SERIAL,SIZE,MAJ:MIN,MOUNTPOINTS".into(),
        ],
        &[0],
        10,
        cancelled,
    )?;
    let inventory = parse(&raw.stdout)?;
    let mut matches = Vec::new();
    walk(
        inventory["blockdevices"]
            .as_array()
            .context("missing cache devices")?,
        &spec.service.cache_volume_id.replace('-', ""),
        &mut matches,
    )?;
    ensure!(matches.len() == 1, "cache serial missing or ambiguous");
    let disk = matches[0];
    let path = disk["path"].as_str().context("missing cache device path")?;
    let parts = path
        .strip_prefix("/dev/nvme")
        .and_then(|p| p.split_once('n'))
        .context("invalid cache device path")?;
    ensure!(
        [parts.0, parts.1]
            .into_iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
        "invalid cache device path"
    );
    ensure!(
        disk["type"] == "disk"
            && empty_children(disk)
            && number(&disk["size"]) == Some(spec.service.cache_bytes),
        "cache disk differs"
    );
    let mounts = disk["mountpoints"]
        .as_array()
        .context("missing cache mountpoints")?;
    ensure!(
        mounts
            .iter()
            .all(|m| m.is_null() || m == "" || m.as_str() == cache.to_str()),
        "cache mounted elsewhere"
    );
    let major_minor = disk["maj:min"]
        .as_str()
        .context("missing cache device number")?;
    ensure!(
        major_minor.split_once(':').is_some_and(|(a, b)| [a, b]
            .into_iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))),
        "invalid cache device number"
    );
    let raw = command(
        executor,
        &tools.findmnt,
        &[
            "--json".into(),
            "--mountpoint".into(),
            cache.as_os_str().into(),
            "--output".into(),
            "SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN,FSROOT".into(),
        ],
        &[0, 1],
        10,
        cancelled,
    )?;
    let mounted = raw.exit_code == 0;
    if mounted {
        let inventory = parse(&raw.stdout)?;
        let mounts = inventory["filesystems"]
            .as_array()
            .context("missing cache mounts")?;
        ensure!(mounts.len() == 1, "ambiguous cache mount");
        let m = &mounts[0];
        let options: Vec<_> = m["options"]
            .as_str()
            .context("missing cache mount options")?
            .split(',')
            .collect();
        ensure!(
            m["source"] == path
                && m["target"].as_str() == cache.to_str()
                && m["fstype"] == "ext4"
                && m["fsroot"] == "/"
                && m["maj:min"] == major_minor
                && empty_children(m)
                && ["rw", "nodev", "nosuid", "noexec"]
                    .iter()
                    .all(|o| options.contains(o))
                && !options.contains(&"ro"),
            "cache mount differs"
        );
        ensure!(
            disk["mountpoints"] == serde_json::json!([cache]),
            "cache disk mountpoints differ"
        );
    } else {
        ensure!(
            mounts.iter().all(|m| m.is_null() || m == ""),
            "cache mount observations disagree"
        );
    }
    Ok(Observation {
        device: root
            .path
            .join(path.strip_prefix('/').context("invalid cache path")?),
        major_minor: major_minor.into(),
        mounted,
        inventory: disk.clone(),
    })
}

fn cache_path(spec: &LightwalletInstallSpec, root: &Path) -> Result<PathBuf> {
    Ok(root.join(
        render_service(&spec.host, &spec.service)?
            .cache_root
            .strip_prefix('/')
            .context("invalid cache root")?,
    ))
}

/// Retain the metadata lock through fresh verification, claiming and data leaf
/// creation. Errors intentionally expose no tool output or authenticated bytes.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.cache.prepare")
)]
pub fn prepare(
    spec: &LightwalletInstallSpec,
    root: Root<'_>,
    tools: &Tools,
    installation: &mut Installation<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    allow_create: bool,
) -> Result<()> {
    prepare_inner(
        spec,
        root,
        tools,
        installation,
        executor,
        cancelled,
        allow_create,
    )
    .map_err(|_| eyre::eyre!("lightwallet cache preparation failed"))
}

fn prepare_inner(
    spec: &LightwalletInstallSpec,
    root: Root<'_>,
    tools: &Tools,
    installation: &mut Installation<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    allow_create: bool,
) -> Result<()> {
    installation.verify_spec(spec)?;
    ensure!(root.path.is_absolute(), "cache root must be absolute");
    ensure!(
        [
            &tools.lsblk,
            &tools.findmnt,
            &tools.blkid,
            &tools.wipefs,
            &tools.blockdev,
            &tools.mkfs_ext4,
            &tools.mount
        ]
        .into_iter()
        .all(|p| p.is_absolute()),
        "cache tools must be absolute"
    );
    let deadline = executor.work_deadline()?;
    check(deadline, cancelled)?;
    let cache = cache_path(spec, root.path)?;
    let logical = render_service(&spec.host, &spec.service)?.cache_root;
    let mut parent = Directory::open(root.path, root.owner)?;
    let components: Vec<_> = logical.trim_start_matches('/').split('/').collect();
    for name in &components[..components.len() - 1] {
        parent = match parent.open_directory(name) {
            Ok(d) => d,
            Err(e) if e.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) => {
                parent.ensure_directory(name, 0o700)?
            }
            Err(e) => return Err(e),
        };
    }
    let leaf = components.last().context("missing cache leaf")?;
    let mounted = match parent.open_directory(leaf) {
        Ok(d) => d,
        Err(e) if e.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) => {
            parent.ensure_directory(leaf, 0o700)?
        }
        Err(e) => return Err(e),
    };
    let observed = observe(spec, &root, tools, executor, cancelled)?;
    if !observed.mounted {
        ensure!(
            mounted.entries()?.next().transpose()?.is_none(),
            "unmounted cache is not empty"
        );
        let fs = command(
            executor,
            &tools.blkid,
            &[
                "-p".into(),
                "-o".into(),
                "export".into(),
                observed.device.as_os_str().into(),
            ],
            &[0, 2],
            60,
            cancelled,
        )?;
        if fs.exit_code == 2 {
            ensure!(allow_create, "cache formatting requires creation authority");
            let authorization = spec
                .new_volume
                .as_ref()
                .context("cache requires saved creation authorization")?;
            ensure!(
                authorization.size_bytes == spec.service.cache_bytes
                    && authorization.volume_id == spec.service.cache_volume_id,
                "cache creation authorization differs"
            );
            installation
                .directory
                .require_absent("volume-claimed.json")?;
            installation
                .directory
                .require_absent("format-intent.json")?;
            let signatures = command(
                executor,
                &tools.wipefs,
                &[
                    "--no-act".into(),
                    "--json".into(),
                    observed.device.as_os_str().into(),
                ],
                &[0],
                60,
                cancelled,
            )?;
            ensure!(
                parse(&signatures.stdout)?["signatures"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
                "cache has unknown signatures"
            );
            let size = command(
                executor,
                &tools.blockdev,
                &["--getsize64".into(), observed.device.as_os_str().into()],
                &[0],
                60,
                cancelled,
            )?;
            let size = std::str::from_utf8(&size.stdout)?.trim();
            ensure!(
                !size.is_empty()
                    && size.bytes().all(|b| b.is_ascii_digit())
                    && size.parse::<u64>()? == spec.service.cache_bytes,
                "cache block size differs"
            );
            let device = BlockDevice::open(&observed.device)?;
            device.require_unused()?;
            ensure!(
                observe(spec, &root, tools, executor, cancelled)? == observed,
                "cache attachment changed"
            );
            device.recheck_path()?;
            check(deadline, cancelled)?;
            installation.begin_format()?;
            device.require_unused()?;
            ensure!(
                observe(spec, &root, tools, executor, cancelled)? == observed,
                "cache attachment changed"
            );
            device.recheck_path()?;
            #[cfg(feature = "profiling")]
            let _format = tracing::info_span!("lightwallet.cache.prepare.mkfs").entered();
            command(
                executor,
                &tools.mkfs_ext4,
                &[
                    "-q".into(),
                    "-m".into(),
                    "0".into(),
                    observed.device.as_os_str().into(),
                ],
                &[0],
                300,
                cancelled,
            )?;
        } else {
            ensure!(fs.stdout.is_ascii(), "invalid cache filesystem");
            let mut types = Vec::new();
            for line in std::str::from_utf8(&fs.stdout)?.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    ensure!(key != "PTTYPE", "partitioned cache");
                    if key == "TYPE" {
                        types.push(value);
                    }
                }
            }
            ensure!(types == ["ext4"], "unknown cache filesystem");
            match installation.directory.read(
                "volume-claimed.json",
                installation.cache_identity.len() as u64,
            ) {
                Ok(bytes) => ensure!(
                    bytes == installation.cache_identity,
                    "foreign saved cache claim"
                ),
                Err(e)
                    if e.downcast_ref::<nix::errno::Errno>()
                        == Some(&nix::errno::Errno::ENOENT) =>
                {
                    ensure!(allow_create, "cache recovery requires creation authority");
                    installation.verify_format_intent()?;
                }
                Err(e) => return Err(e),
            }
            ensure!(
                observe(spec, &root, tools, executor, cancelled)? == observed,
                "cache attachment changed"
            );
        }
        drop(mounted);
        #[cfg(feature = "profiling")]
        let _mount = tracing::info_span!("lightwallet.cache.prepare.mount").entered();
        command(
            executor,
            &tools.mount,
            &[
                "-t".into(),
                "ext4".into(),
                "-o".into(),
                "nodev,nosuid,noexec".into(),
                observed.device.as_os_str().into(),
                cache.into_os_string(),
            ],
            &[0],
            60,
            cancelled,
        )?;
    } else {
        drop(mounted);
    }
    let fresh = observe(spec, &root, tools, executor, cancelled)?;
    ensure!(
        fresh.mounted
            && fresh.device == observed.device
            && fresh.major_minor == observed.major_minor,
        "cache did not mount as expected"
    );
    let mounted = parent.open_directory(leaf)?;
    check(deadline, cancelled)?;
    installation.claim_mounted(&mounted, allow_create)?;
    mounted.ensure_owned_directory("data", 0o700, root.node_owner)?;
    check(deadline, cancelled)
}
