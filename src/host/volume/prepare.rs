//! Native volume preparation, adapted from retired `runner.py::prepare_volume`.
//!
//! `Root` is an explicit caller-authenticated filesystem anchor, NOT a sandbox
//! or kernel namespace. Production uses `/`, owner 0. Its ancestors, tool paths,
//! `/dev`, `/sys` and kernel observations must be trusted and stable throughout.
//! Alternate roots allow unprivileged record fixtures; probe logical paths stay
//! `/var/lib/zdn`, and this API does not authenticate fabricated tool output.
//! Selected device and mount-directory paths are rooted beneath this anchor;
//! read-only tools must observe that same tree while reporting logical paths
//! (and resolvable physical mount sources). An alternate tree with ordinary
//! host tools is NOT a valid view of its devices. In particular a fixture file
//! is never accepted by `BlockDevice`, regardless of the reported signatures.
//! Native host installation uses this API; offline tests do not qualify live EBS.
//!
//! The install lock is retained through acknowledgement. Trusted-owner/root
//! interference and hotplug between checks and kernel operations cannot be
//! excluded by point-in-time observations. A blocked device read/counter read
//! cannot be interrupted by a deadline; use an enclosing supervised process.
//! The caller retains this host's action-owned installation guard. Evidence
//! shares Executor's cumulative deadline and cleanup reserve; zero scans also
//! retain the historical 1800-second limit, without a fresh action budget.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use eyre::{ensure, ContextCompat, Result};

use super::{device::BlockDevice, probe, Installation};
use crate::host::{
    command::{Executor, HostCommand},
    files::Directory,
    HostInstallSpec,
};

/// Caller-trusted root and expected owner; never infer ownership from the tree.
pub struct Root<'a> {
    pub path: &'a Path,
    pub owner: u32,
}

/// Explicit trusted absolute executable paths; no inherited PATH lookup.
pub struct Tools {
    pub probe: probe::Tools,
    pub mkfs_ext4: PathBuf,
    pub mount: PathBuf,
}

/// Prepare and claim the volume, retaining the installation guard throughout.
/// `allow_create` is first-install authority, not evidence of blankness.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.prepare")
)]
pub fn prepare(
    spec: &HostInstallSpec,
    root: Root<'_>,
    tools: &Tools,
    installation: &mut Installation<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    allow_create: bool,
) -> Result<()> {
    installation.verify_spec(spec)?;
    ensure!(root.path.is_absolute(), "filesystem root must be absolute");
    for tool in [
        &tools.probe.lsblk,
        &tools.probe.findmnt,
        &tools.probe.blkid,
        &tools.probe.wipefs,
        &tools.probe.blockdev,
        &tools.mkfs_ext4,
        &tools.mount,
    ] {
        ensure!(tool.is_absolute(), "volume tools must be absolute");
    }
    let deadline = executor.work_deadline()?;
    check(deadline, cancelled)?;
    let anchor = Directory::open(root.path, root.owner)?;
    let parent = anchor.open_directory("var")?.open_directory("lib")?;
    let mounted = match parent.open_directory("zdn") {
        Ok(directory) => directory,
        Err(error)
            if error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) =>
        {
            parent.ensure_directory("zdn", 0o700)?
        }
        Err(error) => return Err(error),
    };
    let observe = |executor: &mut Executor| {
        probe::observe_at(spec, root.path, &tools.probe, executor, cancelled, false)
    };
    let observed = observe(executor)?;
    if observed.filesystem != probe::Filesystem::MountedExt4 {
        ensure!(
            mounted.entries()?.next().transpose()?.is_none(),
            "unmounted chain mount point is not empty"
        );
        if let probe::Filesystem::NoRecognizedFilesystem { size_bytes } = observed.filesystem {
            ensure!(allow_create, "chain volume is blank during a restart");
            // Reject uncertain history before expensive evidence collection.
            installation
                .directory
                .require_absent("volume-claimed.json")?;
            installation
                .directory
                .require_absent("format-intent.json")?;
            let mut device = BlockDevice::open(&observed.device)?;
            if let Some(authorization) = &spec.new_volume {
                ensure!(
                    authorization.size_bytes == size_bytes,
                    "new-volume size differs"
                );
                device.require_unused()?;
            } else {
                let scan_deadline = deadline.min(Instant::now() + Duration::from_secs(1800));
                device.require_zero(size_bytes, scan_deadline, cancelled)?;
            }
            let fresh = observe(executor)?;
            ensure!(fresh == observed, "volume attachment or filesystem changed");
            device.recheck_path()?;
            check(deadline, cancelled)?;
            installation.begin_format()?;
            if spec.new_volume.is_some() {
                device.require_unused()?;
            }
            device.recheck_path()?;
            {
                #[cfg(feature = "profiling")]
                let _format = tracing::info_span!("host.volume.prepare.mkfs").entered();
                run(
                    executor,
                    &tools.mkfs_ext4,
                    &[
                        "-q".into(),
                        "-m".into(),
                        "0".into(),
                        observed.device.as_os_str().into(),
                    ],
                    Duration::from_secs(300),
                    deadline,
                    cancelled,
                )?;
            }
        } else {
            let fresh = observe(executor)?;
            ensure!(fresh == observed, "volume attachment or filesystem changed");
        }
        // Never carry a pre-mount directory descriptor into claiming.
        drop(mounted);
        #[cfg(feature = "profiling")]
        let mount = tracing::info_span!("host.volume.prepare.mount").entered();
        run(
            executor,
            &tools.mount,
            &[
                "-t".into(),
                "ext4".into(),
                "-o".into(),
                "nodev,nosuid,noexec".into(),
                observed.device.as_os_str().into(),
                root.path.join("var/lib/zdn").into_os_string(),
            ],
            Duration::from_secs(60),
            deadline,
            cancelled,
        )?;
        #[cfg(feature = "profiling")]
        drop(mount);
    } else {
        drop(mounted);
    }
    let fresh = observe(executor)?;
    ensure!(
        fresh.device == observed.device && fresh.filesystem == probe::Filesystem::MountedExt4,
        "chain volume did not mount as expected"
    );
    let mounted = parent.open_directory("zdn")?;
    check(deadline, cancelled)?;
    {
        #[cfg(feature = "profiling")]
        let _claim = tracing::info_span!("host.volume.prepare.claim").entered();
        installation.claim_mounted(&mounted, allow_create)?;
    }
    check(deadline, cancelled)
}

fn check(deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(Ordering::SeqCst),
        "volume preparation cancelled"
    );
    ensure!(Instant::now() < deadline, "volume preparation timed out");
    Ok(())
}

fn run(
    executor: &mut Executor,
    program: &Path,
    args: &[OsString],
    timeout: Duration,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    check(deadline, cancelled)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("volume preparation timed out")?;
    executor.execute(
        HostCommand {
            program,
            args,
            stdin: None,
            timeout: timeout.min(remaining),
            allowed: &[0],
        },
        cancelled,
    )?;
    Ok(())
}
