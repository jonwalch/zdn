//! Trusted native-host files, ported from `runner.py`'s private_components,
//! directory, regular_bytes, publish and artifact_digest operations.
//!
//! Start at `/` with owner 0 on a host, then descend one component at a time.
//! An alternate anchor is useful for isolated filesystem tests; its ancestors
//! must already be trusted by the caller. Open descriptors pin each directory;
//! no later operation traverses its pathname again. This is not protection from
//! a hostile root/expected owner modifying the filesystem concurrently.
//! Reopen and verify mounted identity after intentional mount transitions:
//! descriptors opened before mounting still refer to the underlying directory.

use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use eyre::{ensure, Context, Result};
use fs2::FileExt;
use nix::{
    errno::Errno,
    fcntl::{open, openat, AtFlags, OFlag},
    sys::stat::{fchmod, mkdirat, Mode},
    unistd::{fchown, linkat, unlinkat, Gid, Uid, UnlinkatFlags},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const FILE_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC);

/// A directory controlled by the expected owner, with no group/other writes.
pub struct Directory {
    file: File,
    owner: u32,
}

/// Exclusive, nonblocking host-operation lock. Keep it for the whole operation;
/// do not unlink its pathname when releasing it (waiters use the same inode).
#[must_use = "retain the guard for the entire host operation"]
pub struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        // A concurrent spawn can inherit the open-file description until exec.
        // Closing only our descriptor would let that child retain the lock.
        let _ = FileExt::unlock(&self.0);
    }
}

/// Streaming artifact identity; the prefix is at most 64 bytes (for ELF checks).
#[derive(Debug, Eq, PartialEq)]
pub struct ArtifactDigest {
    pub bytes: u64,
    pub sha256: String,
    pub prefix: Vec<u8>,
}

/// Private download staging under a pinned directory. The parent descriptor
/// is retained until this is closed. The procfs path is usable by child tools
/// without inheriting our CLOEXEC descriptor.
pub(super) struct Download<'a> {
    temporary: tempfile::TempDir,
    directory: Directory,
    _parent: &'a Directory,
}

impl Download<'_> {
    pub(super) fn path(&self) -> PathBuf {
        self.temporary.path().join("artifact")
    }

    pub(super) fn close(self) -> Result<()> {
        self.temporary
            .close()
            .context("remove host download staging")
    }
}

impl Directory {
    /// Open a trusted anchor without following a final symlink. Production
    /// callers must use `/`, owner 0, then `open_directory`/`ensure_directory`.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.open")
    )]
    pub fn open(anchor: &Path, owner: u32) -> Result<Self> {
        let file = File::from(open(anchor, DIRECTORY_FLAGS, Mode::empty())?);
        trusted(&file.metadata()?, owner, true)?;
        Ok(Self { file, owner })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.open_directory")
    )]
    pub fn open_directory(&self, name: &str) -> Result<Self> {
        component(name)?;
        let file = File::from(openat(&self.file, name, DIRECTORY_FLAGS, Mode::empty())?);
        trusted(&file.metadata()?, self.owner, true)?;
        Ok(Self {
            file,
            owner: self.owner,
        })
    }

    /// Create a directory or require an existing directory's exact mode.
    /// This does not repair permissions or change ownership on retries.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.ensure_directory")
    )]
    pub fn ensure_directory(&self, name: &str, mode: u32) -> Result<Self> {
        self.ensure_owned_directory(name, mode, self.owner)
    }

    /// Create a leaf for an explicitly selected owner beneath this trusted
    /// parent. Only a newly created directory is chowned/chmodded; retries
    /// reject foreign ownership or mode, never repair them. Production node
    /// leaves use UID/GID 10001 while their ancestors remain root-owned.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.ensure_owned_directory")
    )]
    pub fn ensure_owned_directory(&self, name: &str, mode: u32, owner: u32) -> Result<Self> {
        component(name)?;
        safe_mode(mode)?;
        let created = match mkdirat(&self.file, name, Mode::S_IRWXU) {
            Ok(()) => true,
            Err(Errno::EEXIST) => false,
            Err(error) => return Err(error).context("create host directory"),
        };
        let file = File::from(openat(&self.file, name, DIRECTORY_FLAGS, Mode::empty())?);
        if created {
            trusted(&file.metadata()?, self.owner, true)?;
            if owner != self.owner {
                fchown(
                    &file,
                    Some(Uid::from_raw(owner)),
                    Some(Gid::from_raw(owner)),
                )?;
            }
            // mkdir respects umask; only a directory we just created is changed.
            fchmod(&file, Mode::from_bits_truncate(mode))?;
            file.sync_all()?;
        }
        trusted(&file.metadata()?, owner, true)?;
        ensure!(
            file.metadata()?.mode() & 0o7777 == mode,
            "existing host directory has different permissions"
        );
        // Also sync exact retries: a prior publication may have succeeded but
        // failed before the parent-directory durability acknowledgement.
        self.file.sync_all()?;
        Ok(Self { file, owner })
    }

    /// Use the existing lock inode, with exact private permissions. Opening a
    /// FIFO/device must not block; no unsafe file is repaired or truncated.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.lock")
    )]
    pub fn lock(&self, name: &str) -> Result<Lock> {
        component(name)?;
        let file = File::from(openat(
            &self.file,
            name,
            OFlag::O_RDWR
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?);
        let metadata = file.metadata()?;
        trusted(&metadata, self.owner, false)?;
        ensure!(
            metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1,
            "unsafe host operation lock"
        );
        file.try_lock_exclusive()
            .context("another host operation is running")?;
        Ok(Lock(file))
    }

    /// Require no directory entry at all, including a dangling symlink. This
    /// is an observation under the caller's operation lock, not a reservation
    /// against concurrent modifications by the trusted directory owner.
    pub fn require_absent(&self, name: &str) -> Result<()> {
        component(name)?;
        match nix::sys::stat::fstatat(&self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(Errno::ENOENT) => Ok(()),
            Err(error) => Err(error).context("inspect host record"),
            Ok(_) => eyre::bail!("host record already exists"),
        }
    }

    /// Enumerate the pinned directory, not its potentially renamed pathname.
    /// Linux procfs is trusted kernel state, as in the host command executor.
    /// Consumers must open children through this Directory, not entry paths.
    pub(crate) fn entries(&self) -> Result<std::fs::ReadDir> {
        Ok(std::fs::read_dir(format!(
            "/proc/self/fd/{}",
            self.file.as_raw_fd()
        ))?)
    }

    /// Read a bounded trusted regular file without following a symlink or
    /// blocking on a FIFO. Ownership and mode come from the opened descriptor.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.read")
    )]
    pub fn read(&self, name: &str, limit: u64) -> Result<Vec<u8>> {
        let mut file = self.regular(name, limit)?;
        let mut contents = Vec::new();
        read_chunks(&mut file, limit, &mut || Ok(()), |chunk| {
            contents.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(contents)
    }

    /// Read bounded metadata with exact digest, private mode and cancellation
    /// checks on every chunk. Unlike a download, absence is an error.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.read_verified")
    )]
    pub(crate) fn read_verified(
        &self,
        name: &str,
        bytes: u64,
        sha256: &str,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut file = self.regular(name, bytes)?;
        ensure!(
            file.metadata()?.mode() & 0o7777 == 0o600,
            "existing host artifact mode differs"
        );
        let mut contents = Vec::new();
        read_chunks(&mut file, bytes, check, |chunk| {
            contents.extend_from_slice(chunk);
            Ok(())
        })?;
        ensure!(
            contents.len() as u64 == bytes && hex::encode(Sha256::digest(&contents)) == sha256,
            "existing host artifact differs"
        );
        Ok(contents)
    }

    /// Hash in bounded chunks rather than retaining a potentially large bundle.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.digest")
    )]
    pub fn digest(&self, name: &str, limit: u64) -> Result<ArtifactDigest> {
        let mut file = self.regular(name, limit)?;
        digest_file(&mut file, limit, &mut || Ok(()))
    }

    /// Authenticate a regular executable reached through trusted traversal.
    /// Execution still assumes that the trusted owner keeps the path stable.
    pub(super) fn executable(&self, name: &str) -> Result<()> {
        let file = self.regular(name, u64::MAX)?;
        ensure!(
            file.metadata()?.mode() & 0o100 != 0,
            "host tool is not executable"
        );
        Ok(())
    }

    /// Exact streaming retry, including permissions and durability. Absence is
    /// distinct from an unsafe entry; symlinks and foreign files never trigger
    /// a download or repair.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.artifact_matches")
    )]
    pub(super) fn artifact_matches(
        &self,
        name: &str,
        expected: &ArtifactDigest,
        mode: u32,
        check: &mut impl FnMut() -> Result<()>,
        validate: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<bool> {
        let mut file = match self.regular(name, expected.bytes) {
            Ok(file) => file,
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {
                return Ok(false)
            }
            Err(error) => return Err(error),
        };
        ensure!(
            file.metadata()?.mode() & 0o7777 == mode,
            "existing host artifact mode differs"
        );
        let actual = digest_file(&mut file, expected.bytes, check)?;
        ensure!(
            actual.bytes == expected.bytes && actual.sha256 == expected.sha256,
            "existing host artifact differs"
        );
        if !expected.prefix.is_empty() {
            ensure!(
                actual.prefix == expected.prefix,
                "existing host artifact prefix differs"
            );
        }
        validate(&actual.prefix)?;
        file.sync_all()?;
        self.file.sync_all()?;
        Ok(true)
    }

    pub(super) fn download(&self) -> Result<Download<'_>> {
        use std::os::unix::fs::PermissionsExt;
        let parent = format!("/proc/{}/fd/{}", std::process::id(), self.file.as_raw_fd());
        let temporary = tempfile::Builder::new()
            .prefix(".download-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        let directory = Self::open(temporary.path(), self.owner)?;
        fchmod(&directory.file, Mode::S_IRWXU)?;
        Ok(Download {
            temporary,
            directory,
            _parent: self,
        })
    }

    /// Verify downloaded bytes through the same trusted-file boundary, then
    /// publish create-only. The expected owner/tool must not mutate staging
    /// concurrently; this is not hostile-root containment.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.publish_download")
    )]
    pub(super) fn publish_download(
        &self,
        name: &str,
        download: &Download<'_>,
        expected: &ArtifactDigest,
        mode: u32,
        check: &mut impl FnMut() -> Result<()>,
        validate: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<()> {
        component(name)?;
        safe_mode(mode)?;
        ensure!(
            download.directory.owner == self.owner,
            "download owner differs"
        );
        let mut file = download.directory.regular("artifact", expected.bytes)?;
        let actual = digest_file(&mut file, expected.bytes, check)?;
        ensure!(
            actual.bytes == expected.bytes && actual.sha256 == expected.sha256,
            "downloaded host artifact differs"
        );
        validate(&actual.prefix)?;
        check()?;
        fchmod(&file, Mode::from_bits_truncate(mode))?;
        file.sync_all()?;
        match linkat(
            &download.directory.file,
            "artifact",
            &self.file,
            name,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                ensure!(
                    self.artifact_matches(name, &actual, mode, check, |_| Ok(()))?,
                    "artifact disappeared during publication"
                );
            }
            Err(error) => return Err(error).context("publish host artifact"),
        }
        self.file.sync_all()?;
        ensure!(
            self.artifact_matches(name, &actual, mode, check, |_| Ok(()))?,
            "published artifact disappeared"
        );
        Ok(())
    }

    /// Durable, atomic create-only publication. Only identical bytes AND mode
    /// allow a retry, including a concurrent publisher's winning destination.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.publish")
    )]
    pub fn publish(&self, name: &str, contents: &[u8], mode: u32) -> Result<()> {
        component(name)?;
        safe_mode(mode)?;
        match self.regular(name, contents.len() as u64) {
            Ok(file) => return self.exact(file, contents, mode),
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {}
            Err(error) => return Err(error),
        }
        let temporary_name = format!(".pending-{}", Uuid::new_v4());
        let mut file = File::from(openat(
            &self.file,
            temporary_name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?);
        let pending = Pending {
            parent: &self.file,
            name: &temporary_name,
        };
        trusted(&file.metadata()?, self.owner, false)?;
        file.write_all(contents)?;
        fchmod(&file, Mode::from_bits_truncate(mode))?;
        file.sync_all()?;
        match linkat(
            &self.file,
            temporary_name.as_str(),
            &self.file,
            name,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                self.exact(self.regular(name, contents.len() as u64)?, contents, mode)?;
            }
            Err(error) => return Err(error).context("publish host file"),
        }
        // Remove the staging link before syncing the containing directory.
        unlinkat(
            &self.file,
            temporary_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )?;
        drop(pending);
        self.file.sync_all()?;
        Ok(())
    }

    /// Checked descriptor-relative replacement under the caller's operation
    /// lock. Absence is allowed; existing entries must be private, singly
    /// linked regular files. Never repairs an unsafe destination.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.files.replace")
    )]
    pub fn replace(&self, name: &str, contents: &[u8], limit: u64) -> Result<()> {
        component(name)?;
        ensure!(contents.len() as u64 <= limit, "replacement exceeds bound");
        match self.regular(name, limit) {
            Ok(file) => {
                let metadata = file.metadata()?;
                ensure!(
                    metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1,
                    "unsafe replacement destination"
                );
            }
            Err(error) if error.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {}
            Err(error) => return Err(error),
        }
        let temporary_name = format!(".pending-{}", Uuid::new_v4());
        let mut file = File::from(openat(
            &self.file,
            temporary_name.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?);
        let pending = Pending {
            parent: &self.file,
            name: &temporary_name,
        };
        trusted(&file.metadata()?, self.owner, false)?;
        fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR)?;
        file.write_all(contents)?;
        file.sync_all()?;
        nix::fcntl::renameat(&self.file, temporary_name.as_str(), &self.file, name)?;
        drop(pending);
        self.file.sync_all()?;
        Ok(())
    }

    pub(super) fn regular(&self, name: &str, limit: u64) -> Result<File> {
        component(name)?;
        let file = File::from(openat(&self.file, name, FILE_FLAGS, Mode::empty())?);
        let metadata = file.metadata()?;
        trusted(&metadata, self.owner, false)?;
        ensure!(metadata.len() <= limit, "host file exceeded its bound");
        Ok(file)
    }

    fn exact(&self, mut file: File, contents: &[u8], mode: u32) -> Result<()> {
        ensure!(
            file.metadata()?.mode() & 0o7777 == mode,
            "existing host file has different permissions"
        );
        let mut offset = 0;
        let mut equal = true;
        read_chunks(&mut file, contents.len() as u64, &mut || Ok(()), |chunk| {
            equal &= contents.get(offset..offset + chunk.len()) == Some(chunk);
            offset += chunk.len();
            Ok(())
        })?;
        ensure!(
            equal && offset == contents.len(),
            "existing host file differs"
        );
        file.sync_all()?;
        self.file.sync_all()?;
        Ok(())
    }
}

struct Pending<'a> {
    parent: &'a File,
    name: &'a str,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        let _ = unlinkat(self.parent, self.name, UnlinkatFlags::NoRemoveDir);
    }
}

fn component(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0']),
        "host file name must be one path component"
    );
    Ok(())
}

fn safe_mode(mode: u32) -> Result<()> {
    ensure!(
        mode & !0o777 == 0 && mode & 0o022 == 0,
        "host permissions allow unsupported bits or untrusted writes"
    );
    Ok(())
}

fn trusted(metadata: &Metadata, owner: u32, directory: bool) -> Result<()> {
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "host input has an untrusted file type"
    );
    ensure!(
        metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "host input has untrusted ownership or permissions"
    );
    Ok(())
}

pub(super) fn read_chunks(
    file: &mut File,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let mut total = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        check()?;
        // One byte beyond the bound detects growth after the initial fstat,
        // without overflow even for u64::MAX.
        let wanted = (limit - total).saturating_add(1).min(buffer.len() as u64) as usize;
        let bytes = file.read(&mut buffer[..wanted])?;
        if bytes == 0 {
            return Ok(total);
        }
        ensure!(
            bytes as u64 <= limit - total,
            "host file exceeded its bound"
        );
        total += bytes as u64;
        consume(&buffer[..bytes])?;
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.files.digest_file")
)]
pub(super) fn digest_file(
    file: &mut File,
    limit: u64,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<ArtifactDigest> {
    let mut hash = Sha256::new();
    let mut prefix = Vec::new();
    let bytes = read_chunks(file, limit, check, |chunk| {
        hash.update(chunk);
        prefix.extend_from_slice(&chunk[..chunk.len().min(64 - prefix.len())]);
        Ok(())
    })?;
    Ok(ArtifactDigest {
        bytes,
        sha256: hex::encode(hash.finalize()),
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_operation_releases_lock_even_with_an_inherited_description() {
        let root = tempfile::tempdir().unwrap();
        let directory =
            Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
        let guard = directory.lock("install.lock").unwrap();
        // Safely simulate the shared description a concurrent fork inherits
        // before exec closes CLOEXEC descriptors. No child/fork is needed.
        let inherited = guard.0.try_clone().unwrap();
        drop(guard);
        let next = directory.lock("install.lock").unwrap();
        assert!(directory.lock("install.lock").is_err());
        drop(inherited);
        assert!(directory.lock("install.lock").is_err());
        drop(next);
        drop(directory.lock("install.lock").unwrap());
    }
}
