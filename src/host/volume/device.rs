//! Opened-device evidence from `runner.py::zero_device` and `unused_device`.
//!
//! The absolute device path must come from a fresh validated attachment probe
//! through trusted ancestors (normally `/dev`). Descriptor/path agreement does
//! not establish EBS serial, mount identity, creation provenance or permission
//! to format. Callers still need the install lock, durable intent and fresh
//! attachment/mount checks immediately before any mutation. Nothing here writes.

use std::{
    fs::{self, File},
    io::{Read, Seek},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Instant,
};

use eyre::{ensure, Result};
use nix::{
    fcntl::{open, OFlag},
    sys::stat::{major, minor, Mode},
};

use super::evidence;

pub struct BlockDevice {
    file: File,
    path: PathBuf,
}

impl BlockDevice {
    /// Open read-only/no-follow/nonblocking and require an actual block device,
    /// never a regular file, FIFO or character device. Intermediate ancestors
    /// remain the caller's trust input, not a hostile-root race boundary.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.device.open")
    )]
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "expected an absolute block-device path");
        let file = File::from(open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        ensure!(
            file.metadata()?.file_type().is_block_device(),
            "expected a real block device"
        );
        let device = Self {
            file,
            path: path.into(),
        };
        device.recheck_path()?;
        Ok(device)
    }

    /// Require the original path to still name this opened block-device inode.
    /// This is a point-in-time check, not an attachment/mount reservation.
    pub fn recheck_path(&self) -> Result<()> {
        let opened = self.file.metadata()?;
        let current = fs::symlink_metadata(&self.path)?;
        ensure!(
            current.file_type().is_block_device()
                && current.dev() == opened.dev()
                && current.ino() == opened.ino()
                && current.rdev() == opened.rdev(),
            "block-device path changed"
        );
        Ok(())
    }

    /// Scan from byte zero with bounded memory, requiring exact observed size
    /// and EOF. Deadline/cancellation checks cannot interrupt a blocked kernel
    /// read; an enclosing supervised process remains necessary for that bound.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.device.require_zero")
    )]
    pub fn require_zero(
        &mut self,
        expected_size: u64,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        self.recheck_path()?;
        self.file
            .rewind()
            .map_err(|_| eyre::eyre!("cannot rewind block device"))?;
        evidence::require_zero_contents(&mut self.file, expected_size, deadline, cancelled)?;
        self.recheck_path()
    }

    /// Kernel counters are additional evidence ONLY. Pinned EBS creation
    /// provenance is still required before using this instead of a zero scan.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.volume.device.require_unused")
    )]
    pub fn require_unused(&self) -> Result<()> {
        self.recheck_path()?;
        let number = self.file.metadata()?.rdev();
        let path = format!("/sys/dev/block/{}:{}/stat", major(number), minor(number));
        let file = File::from(open(
            Path::new(&path),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let mut raw = Vec::new();
        file.take(4097).read_to_end(&mut raw)?;
        evidence::require_unused_counters(&raw)?;
        self.recheck_path()
    }
}
