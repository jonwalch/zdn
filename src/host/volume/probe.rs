//! Read-only tool observations from `runner.py::volume_device`, `is_mounted`
//! and the blkid/wipefs/blockdev portion of `prepare_volume`.
//!
//! A snapshot is NOT format/mount/claim authority. No recognized signature does
//! not imply zero contents. Before a mutation the installer must separately
//! check opened block-device identity, blankness or pinned creation provenance
//! plus unused counters, durable intent, and fresh attachment/mount observations.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

use eyre::{ensure, Result};
use serde::Deserialize;

use super::evidence;
use crate::host::{
    command::{Executor, HostCommand, Output},
    HostInstallSpec, DATA_ROOT,
};

/// Caller-selected absolute executable paths. Activation must resolve these in
/// the trusted host tool path, never in a user-controlled/inherited PATH.
pub struct Tools {
    pub lsblk: PathBuf,
    pub findmnt: PathBuf,
    pub blkid: PathBuf,
    pub wipefs: PathBuf,
    pub blockdev: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Filesystem {
    MountedExt4,
    UnmountedExt4,
    /// Only tool metadata: unknown raw data can still occupy this device.
    NoRecognizedFilesystem {
        size_bytes: u64,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Observation {
    pub device: PathBuf,
    pub filesystem: Filesystem,
}

/// Collect a bounded snapshot using read-only tool operations, without disk
/// writes, mount changes, record publication or uncertain-format retry authority.
/// Producer-namespace observations additionally verify the exact state bind
/// when the chain mount is present; they do not claim producer authorization.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.volume.probe.observe")
)]
pub fn observe(
    spec: &HostInstallSpec,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    producer_namespace: bool,
) -> Result<Observation> {
    observe_at(
        spec,
        Path::new("/"),
        tools,
        executor,
        cancelled,
        producer_namespace,
    )
}

/// Explicit trusted filesystem view for preparation fixtures. Tools still
/// report logical mount targets and must observe this same caller-owned tree.
/// Production callers use `/`; this is not a namespace or fabricated authority.
pub(in crate::host) fn observe_at(
    spec: &HostInstallSpec,
    root: &Path,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    producer_namespace: bool,
) -> Result<Observation> {
    spec.validate()?;
    ensure!(root.is_absolute(), "filesystem root must be absolute");
    let inventory = {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.volume.probe.inventory").entered();
        command(
            executor,
            &tools.lsblk,
            &[
                "--json".into(),
                "--paths".into(),
                "--output".into(),
                "PATH,TYPE,SERIAL,FSTYPE,MOUNTPOINTS".into(),
            ],
            &[0],
            cancelled,
        )?
    };
    let logical = evidence::attached_device(spec, &inventory.stdout, producer_namespace)?;
    let device = root.join(logical.strip_prefix("/")?);
    let mount = {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.volume.probe.chain_mount").entered();
        command(
            executor,
            &tools.findmnt,
            &[
                "--json".into(),
                "--target".into(),
                DATA_ROOT.into(),
                "--output".into(),
                "SOURCE,TARGET,FSTYPE".into(),
            ],
            &[0, 1],
            cancelled,
        )?
    };
    let filesystem = if mount.exit_code == 0 && evidence::chain_mounted(&mount.stdout, &device)? {
        if producer_namespace {
            let mount = {
                #[cfg(feature = "profiling")]
                let _span = tracing::info_span!("host.volume.probe.producer_mount").entered();
                command(
                    executor,
                    &tools.findmnt,
                    &[
                        "--json".into(),
                        "--target".into(),
                        format!("{}/producer", spec.node_root()).into(),
                        "--output".into(),
                        "SOURCE,TARGET,FSTYPE,FSROOT,OPTIONS".into(),
                    ],
                    &[0],
                    cancelled,
                )?
            };
            evidence::verify_producer_mount(spec, &mount.stdout, &device)?;
        }
        Filesystem::MountedExt4
    } else {
        let filesystem = {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.volume.probe.filesystem").entered();
            command(
                executor,
                &tools.blkid,
                &[
                    "-p".into(),
                    "-o".into(),
                    "export".into(),
                    device.as_os_str().into(),
                ],
                &[0, 2],
                cancelled,
            )?
        };
        if filesystem.exit_code == 0 {
            require_ext4(&filesystem.stdout)?;
            Filesystem::UnmountedExt4
        } else {
            let signatures = {
                #[cfg(feature = "profiling")]
                let _span = tracing::info_span!("host.volume.probe.signatures").entered();
                command(
                    executor,
                    &tools.wipefs,
                    &[
                        "--no-act".into(),
                        "--json".into(),
                        device.as_os_str().into(),
                    ],
                    &[0],
                    cancelled,
                )?
            };
            #[derive(Deserialize)]
            struct Signatures {
                signatures: Option<Vec<serde_json::Value>>,
            }
            let signatures: Signatures = serde_json::from_slice(&signatures.stdout)
                .map_err(|_| eyre::eyre!("invalid volume signature observation"))?;
            ensure!(
                signatures.signatures.is_none_or(|s| s.is_empty()),
                "expected volume has unknown signatures"
            );
            let size = {
                #[cfg(feature = "profiling")]
                let _span = tracing::info_span!("host.volume.probe.size").entered();
                command(
                    executor,
                    &tools.blockdev,
                    &["--getsize64".into(), device.as_os_str().into()],
                    &[0],
                    cancelled,
                )?
            };
            let size_bytes = parse_size(&size.stdout)?;
            if let Some(authorization) = &spec.new_volume {
                ensure!(
                    authorization.size_bytes == size_bytes,
                    "new-volume authorization does not match the observed disk size"
                );
            }
            Filesystem::NoRecognizedFilesystem { size_bytes }
        }
    };
    Ok(Observation { device, filesystem })
}

fn command(
    executor: &mut Executor,
    program: &Path,
    args: &[OsString],
    allowed: &[i32],
    cancelled: &AtomicBool,
) -> Result<Output> {
    executor.execute(
        HostCommand {
            program,
            args,
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed,
        },
        cancelled,
    )
}

fn require_ext4(raw: &[u8]) -> Result<()> {
    ensure!(raw.is_ascii(), "invalid filesystem observation");
    let mut filesystem = None;
    for line in std::str::from_utf8(raw)?.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "TYPE" => {
                    ensure!(filesystem.is_none(), "ambiguous filesystem observation");
                    filesystem = Some(value);
                }
                "PTTYPE" => eyre::bail!("expected whole-disk ext4 filesystem"),
                _ => {}
            }
        }
    }
    ensure!(
        filesystem == Some("ext4"),
        "expected whole-disk ext4 filesystem"
    );
    Ok(())
}

fn parse_size(raw: &[u8]) -> Result<u64> {
    let raw = raw.trim_ascii();
    ensure!(
        !raw.is_empty() && raw.iter().all(u8::is_ascii_digit),
        "invalid data volume size"
    );
    let size = std::str::from_utf8(raw)?
        .parse::<u64>()
        .map_err(|_| eyre::eyre!("invalid data volume size"))?;
    ensure!(
        (1024 * 1024 * 1024..=2 * 1024u64.pow(4)).contains(&size),
        "unexpected data volume size"
    );
    Ok(size)
}
