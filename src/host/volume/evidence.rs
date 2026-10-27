//! Read-only parsers from `runner.py`'s volume_device/unused_device checks.
//!
//! These consume bounded command/kernel observations, not live device authority.
//! Selection does not open a device or prove blankness/mount identity. Counters
//! are additional evidence only, never a substitute for pinned creation
//! provenance. Native observation/format/mount orchestration is still separate.

use std::{
    collections::BTreeSet,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use eyre::{ensure, Context, ContextCompat, Result};
use serde::Deserialize;

use crate::host::{HostInstallSpec, DATA_ROOT};

const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct Inventory {
    blockdevices: Vec<Device>,
}

#[derive(Deserialize)]
struct Device {
    path: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    serial: Option<String>,
    #[serde(default)]
    mountpoints: Vec<Option<String>>,
    #[serde(default)]
    children: Vec<Device>,
}

/// Require one matching EBS serial anywhere in the lsblk tree, a whole Nitro
/// disk, and only the permitted mounts. Producer namespaces additionally allow
/// their exact state-directory bind mount; this does NOT verify its source/root.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.evidence.attached_device")
)]
pub fn attached_device(
    spec: &HostInstallSpec,
    lsblk: &[u8],
    producer_namespace: bool,
) -> Result<PathBuf> {
    spec.validate()?;
    ensure!(
        lsblk.len() <= MAX_METADATA_BYTES,
        "block inventory exceeds its bound"
    );
    let inventory: Inventory =
        serde_json::from_slice(lsblk).map_err(|_| eyre::eyre!("invalid block inventory"))?;
    let mut selected = None;
    select(
        &inventory.blockdevices,
        &spec.volume_id.replace('-', ""),
        &mut selected,
    )?;
    let selected = selected.context("expected exactly one attached EBS serial")?;
    ensure!(
        selected.kind.as_deref() == Some("disk") && selected.children.is_empty(),
        "expected EBS volume has partitions or is not a whole disk"
    );
    let path = selected
        .path
        .as_deref()
        .context("expected Nitro EBS device")?;
    let (controller, namespace) = path
        .strip_prefix("/dev/nvme")
        .and_then(|suffix| suffix.split_once('n'))
        .context("expected Nitro EBS device")?;
    ensure!(
        [controller, namespace]
            .into_iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        "expected Nitro EBS device"
    );
    let producer = format!("{}/producer", spec.node_root());
    ensure!(
        selected
            .mountpoints
            .iter()
            .all(|mount| match mount.as_deref() {
                None | Some("") | Some(DATA_ROOT) => true,
                Some(mount) => producer_namespace && mount == producer,
            }),
        "expected EBS device is mounted elsewhere"
    );
    Ok(path.into())
}

fn select<'a>(
    devices: &'a [Device],
    serial: &str,
    selected: &mut Option<&'a Device>,
) -> Result<()> {
    for device in devices {
        if device
            .serial
            .as_deref()
            .is_some_and(|value| value.trim().replace('-', "") == serial)
        {
            ensure!(
                selected.is_none(),
                "expected exactly one attached EBS serial"
            );
            *selected = Some(device);
        }
        select(&device.children, serial, selected)?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct MountInventory {
    filesystems: Vec<Mount>,
}

#[derive(Deserialize)]
struct Mount {
    source: Option<String>,
    target: Option<String>,
    fstype: Option<String>,
    fsroot: Option<String>,
    options: Option<String>,
}

/// Interpret a successful findmnt observation for DATA_ROOT. A parent mount is
/// not the chain mount. Resolve source aliases in the host filesystem, matching
/// the old realpath comparison; a missing source now fails closed. The caller
/// must separately verify device type/attachment and the mounted ownership
/// record. Neither this snapshot nor path resolution prevents hostile-root races.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.evidence.chain_mounted")
)]
pub fn chain_mounted(findmnt: &[u8], expected_device: &Path) -> Result<bool> {
    let mount = single_mount(findmnt)?;
    let target = mount
        .target
        .as_deref()
        .context("chain mount has no target")?;
    if target != DATA_ROOT {
        return Ok(false);
    }
    ensure!(
        mount.fstype.as_deref() == Some("ext4"),
        "chain mount uses the wrong filesystem"
    );
    let source = mount.source.context("chain mount has no source")?;
    let resolved = std::fs::canonicalize(source)
        .map_err(|_| eyre::eyre!("chain mount source cannot be resolved"))?;
    ensure!(
        resolved == expected_device,
        "chain mount uses the wrong source"
    );
    Ok(true)
}

/// The producer's systemd namespace may expose exactly its state bind mount.
/// Preserve the exact source+filesystem-root contract rather than accepting any
/// ext4 directory on the same disk. This does not prove the root-volume claim.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.evidence.verify_producer_mount")
)]
pub fn verify_producer_mount(
    spec: &HostInstallSpec,
    findmnt: &[u8],
    expected_device: &Path,
) -> Result<()> {
    spec.validate()?;
    let mount = single_mount(findmnt)?;
    let target = format!("{}/producer", spec.node_root());
    // node_root() always starts at DATA_ROOT; retain the leading slash.
    let fsroot = &target[DATA_ROOT.len()..];
    let device = expected_device.to_str().context("invalid device path")?;
    let source = format!("{device}[{fsroot}]");
    ensure!(
        mount.target.as_deref() == Some(target.as_str())
            && mount.source.as_deref() == Some(source.as_str())
            && mount.fsroot.as_deref() == Some(fsroot)
            && mount.fstype.as_deref() == Some("ext4"),
        "producer state mount uses the wrong source or filesystem root"
    );
    let options: BTreeSet<_> = mount
        .options
        .as_deref()
        .context("producer state mount has no options")?
        .split(',')
        .collect();
    ensure!(
        ["rw", "nodev", "nosuid", "noexec"]
            .into_iter()
            .all(|option| options.contains(option))
            && !options.contains("ro"),
        "producer state mount has unsafe options"
    );
    Ok(())
}

fn single_mount(raw: &[u8]) -> Result<Mount> {
    ensure!(
        raw.len() <= MAX_METADATA_BYTES,
        "mount inventory exceeds its bound"
    );
    let mut inventory: MountInventory =
        serde_json::from_slice(raw).map_err(|_| eyre::eyre!("invalid mount inventory"))?;
    ensure!(inventory.filesystems.len() == 1, "ambiguous chain mount");
    Ok(inventory.filesystems.remove(0))
}

/// Parse `/sys/dev/block/MAJOR:MINOR/stat` supplied by a separately verified
/// block-device observation. Reads and unrelated diagnostic counters are legal;
/// guest writes, discarded sectors and in-flight I/O must all be zero.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.evidence.require_unused_counters")
)]
pub fn require_unused_counters(raw: &[u8]) -> Result<()> {
    ensure!(
        raw.len() <= 4096 && raw.is_ascii(),
        "invalid block I/O counters"
    );
    let values = std::str::from_utf8(raw)?
        .split_ascii_whitespace()
        .map(|field| {
            ensure!(
                field.bytes().all(|b| b.is_ascii_digit()),
                "invalid block I/O counters"
            );
            field.parse::<u64>().context("invalid block I/O counters")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(values.len() >= 15, "invalid block I/O counters");
    ensure!(
        [4, 5, 6, 8, 11, 12, 13]
            .into_iter()
            .all(|index| values[index] == 0),
        "new volume has guest writes, discards or in-flight I/O; preserve it for inspection"
    );
    Ok(())
}

/// Check exactly `expected_size` zero bytes followed by EOF, in bounded memory.
/// This checks stream contents only: the caller must separately establish an
/// opened block device, expected size and attachment/mount identity. It is NOT
/// format authority. Cancellation/deadlines are checked around each read; this
/// cannot interrupt a kernel read that has not returned (as in the old runner).
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.evidence.require_zero_contents")
)]
pub fn require_zero_contents(
    reader: &mut impl Read,
    expected_size: u64,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut remaining = expected_size;
    let mut buffer = vec![0; 8 * 1024 * 1024];
    loop {
        ensure!(
            !cancelled.load(Ordering::SeqCst),
            "blank volume scan cancelled"
        );
        ensure!(Instant::now() < deadline, "blank volume scan timed out");
        // The final one-byte read detects a device larger than the observed
        // size without adding to expected_size (which might be u64::MAX).
        let wanted = remaining.min(buffer.len() as u64).max(1) as usize;
        let count = match reader.read(&mut buffer[..wanted]) {
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => eyre::bail!("blank volume scan read failed"),
        };
        ensure!(
            !cancelled.load(Ordering::SeqCst),
            "blank volume scan cancelled"
        );
        ensure!(Instant::now() < deadline, "blank volume scan timed out");
        if remaining == 0 {
            ensure!(
                count == 0,
                "expected volume size changed during blankness check"
            );
            return Ok(());
        }
        ensure!(
            count > 0 && buffer[..count].iter().all(|byte| *byte == 0),
            "expected volume contains unknown raw data or changed size"
        );
        remaining -= count as u64;
    }
}
