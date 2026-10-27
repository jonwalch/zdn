//! Digest-pinned, data-only deployment packages resolved into disposable storage.
use crate::{
    artifact_set::{self, ArtifactSet},
    dependencies::{Downloader, HttpDownloader},
    devnet::{read_bounded, Artifact},
};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

pub const API_VERSION: &str = "zdn-deployment-package/v1alpha1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub api_version: String,
    pub artifact_set: ArtifactSet,
    pub sources: BTreeMap<String, Location>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Location {
    File { path: PathBuf },
    Https { url: String },
}

#[derive(Debug)]
pub struct ResolvedPackage {
    directory: tempfile::TempDir,
    pub artifact_set: ArtifactSet,
}

impl ResolvedPackage {
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
}

pub fn resolve(
    manifest: &Path,
    sha256: &str,
    overrides: &BTreeMap<String, PathBuf>,
) -> Result<ResolvedPackage> {
    resolve_inner(
        manifest,
        sha256,
        overrides,
        &HttpDownloader::default(),
        false,
    )
}

/// The injected downloader owns transport policy. Numeric loopback HTTP is
/// accepted here for scripted tests; HttpDownloader still requires its explicit
/// for_loopback_tests constructor to fetch it. Ordinary resolve requires HTTPS.
pub fn resolve_with_downloader(
    manifest: &Path,
    sha256: &str,
    overrides: &BTreeMap<String, PathBuf>,
    downloader: &impl Downloader,
) -> Result<ResolvedPackage> {
    resolve_inner(manifest, sha256, overrides, downloader, true)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.resolve_inner")
)]
fn resolve_inner(
    manifest: &Path,
    sha256: &str,
    overrides: &BTreeMap<String, PathBuf>,
    downloader: &impl Downloader,
    allow_loopback: bool,
) -> Result<ResolvedPackage> {
    crate::devnet::validate_hash(sha256).context("invalid package SHA-256 pin")?;
    let bytes = read_bounded(manifest, artifact_set::MAX_MANIFEST_BYTES)?;
    let base = manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    resolve_bytes(&bytes, sha256, base, overrides, downloader, allow_loopback)
}

/// Resolve a catalog location with exactly the package transport and hash policy.
/// File locations are relative to base; HTTPS packages should use HTTPS artifact
/// sources (or explicit overrides), not files beside a remote manifest.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.resolve_location")
)]
pub(crate) fn resolve_location(
    location: &Location,
    sha256: &str,
    base: &Path,
    overrides: &BTreeMap<String, PathBuf>,
    downloader: &impl Downloader,
) -> Result<ResolvedPackage> {
    crate::devnet::validate_hash(sha256).context("invalid package SHA-256 pin")?;
    location.validate(false)?;
    match location {
        Location::File { path } => {
            let mut bytes = Vec::new();
            open_relative(base, path)?
                .take(artifact_set::MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= artifact_set::MAX_MANIFEST_BYTES,
                "package exceeds its size limit"
            );
            let package_base = base.join(path.parent().unwrap_or(Path::new("")));
            resolve_bytes(&bytes, sha256, &package_base, overrides, downloader, false)
        }
        Location::Https { url } => {
            let directory = tempfile::tempdir()?;
            let manifest = directory.path().join("package.json");
            let mut file = File::create(&manifest)?;
            downloader.download(url, &mut file, artifact_set::MAX_MANIFEST_BYTES)?;
            // Recheck the bound and raw hash even for injected downloaders.
            resolve_inner(&manifest, sha256, overrides, downloader, false)
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.resolve_bytes")
)]
fn resolve_bytes(
    bytes: &[u8],
    sha256: &str,
    base: &Path,
    overrides: &BTreeMap<String, PathBuf>,
    downloader: &impl Downloader,
    allow_loopback: bool,
) -> Result<ResolvedPackage> {
    ensure!(
        hex::encode(Sha256::digest(bytes)) == sha256,
        "package SHA-256 mismatch"
    );
    // Nothing is decoded or fetched until the raw manifest pin has matched.
    let package: Package = serde_json::from_slice(bytes).context("decode deployment package")?;
    ensure!(
        package.api_version == API_VERSION,
        "unsupported deployment package API version"
    );
    package.artifact_set.require_compatible()?;
    ensure!(
        package
            .sources
            .keys()
            .eq(package.artifact_set.artifacts.keys()),
        "package sources must exactly match artifact inventory"
    );
    ensure!(
        overrides
            .keys()
            .all(|name| package.sources.contains_key(name)),
        "unknown package artifact override"
    );
    // Validate all locations even when an override substitutes their bytes.
    for location in package.sources.values() {
        location.validate(allow_loopback)?;
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix("zdn-package-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir()?;
    let limits = artifact_set::artifact_limits(package.artifact_set.lightwallet_image.is_some());
    for (name, artifact) in &package.artifact_set.artifacts {
        let limit = *limits.get(name).context("unknown artifact name")?;
        ensure!(artifact.bytes <= limit, "artifact exceeds size limit");
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(directory.path().join(name))?;
        if let Some(path) = overrides.get(name) {
            copy_checked(open_regular(path)?, &mut output, artifact)?;
        } else {
            match &package.sources[name] {
                Location::File { path } => {
                    copy_checked(open_relative(base, path)?, &mut output, artifact)?;
                }
                Location::Https { url } => {
                    downloader.download(url, &mut output, artifact.bytes)?;
                    output.seek(SeekFrom::Start(0))?;
                    // Independently check injected downloaders too.
                    check_stream(&mut output, &mut std::io::sink(), artifact)?;
                }
            }
        }
    }
    package.artifact_set.verify(directory.path())?;
    Ok(ResolvedPackage {
        directory,
        artifact_set: package.artifact_set,
    })
}

impl Location {
    pub(crate) fn validate(&self, allow_loopback: bool) -> Result<()> {
        match self {
            Self::File { path } => validate_path(path),
            Self::Https { url } => validate_url(url, allow_loopback),
        }
    }
}

/// A self-contained export has a new package pin, but exactly the supplied
/// artifact set, including its original immutable provenance.
#[derive(Clone, Debug)]
pub struct ExportedPackage {
    pub manifest: PathBuf,
    pub sha256: String,
}

/// Prepare a data-only directory containing package.json and the fixed artifacts.
/// The destination must not exist, even as an empty directory or symlink.
/// Linux renameat2(RENAME_NOREPLACE) and macOS renameatx_np(RENAME_EXCL) publish
/// the entire verified directory atomically; unsupported filesystems fail without
/// replacing the destination. No file is made executable. The caller owns the
/// existing destination parent directory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.export")
)]
pub fn export(
    directory: &Path,
    artifact_set: &ArtifactSet,
    destination: &Path,
) -> Result<ExportedPackage> {
    #[cfg(target_os = "linux")]
    use nix::fcntl::{renameat2, RenameFlags};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    artifact_set.verify(directory)?;
    let name = destination
        .file_name()
        .context("export destination needs a name")?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_fd = File::open(parent)?;
    let pending = tempfile::Builder::new()
        .prefix(".zdn-package-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let mut sources = BTreeMap::new();
    for (name, artifact) in &artifact_set.artifacts {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(pending.path().join(name))?;
        copy_checked(
            open_relative(directory, Path::new(name))?,
            &mut output,
            artifact,
        )?;
        output.sync_all()?;
        sources.insert(name.clone(), Location::File { path: name.into() });
    }
    // Verify the copied snapshot too: source mutation cannot export unchecked data.
    artifact_set.verify(pending.path())?;
    let bytes = serde_json::to_vec_pretty(&Package {
        api_version: API_VERSION.into(),
        artifact_set: artifact_set.clone(),
        sources,
    })?;
    ensure!(
        bytes.len() as u64 <= artifact_set::MAX_MANIFEST_BYTES,
        "exported package exceeds its size limit"
    );
    let mut manifest = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(pending.path().join("package.json"))?;
    manifest.write_all(&bytes)?;
    manifest.sync_all()?;
    File::open(pending.path())?.sync_all()?;
    #[cfg(target_os = "linux")]
    renameat2(
        &parent_fd,
        Path::new(pending.path().file_name().unwrap()),
        &parent_fd,
        Path::new(name),
        RenameFlags::RENAME_NOREPLACE,
    )
    .context("publish package export without overwrite")?;
    #[cfg(target_os = "macos")]
    rustix::fs::renameat_with(
        &parent_fd,
        pending.path().file_name().unwrap(),
        &parent_fd,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("publish package export without overwrite")?;
    // Do not leave TempDir owning a path that is no longer ours.
    let _ = pending.keep();
    parent_fd.sync_all()?;
    Ok(ExportedPackage {
        manifest: destination.join("package.json"),
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.validate_path")
)]
fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("package path is not UTF-8")?;
    ensure!(
        !text.is_empty()
            && !text.contains(['\\', ':', '\0'])
            && text
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "package file path must contain only relative normal components"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.validate_url")
)]
fn validate_url(url: &str, allow_loopback: bool) -> Result<()> {
    ensure!(
        url.len() <= 8192
            && !url
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            && !url.contains(['@', '#', '\\']),
        "invalid package download URL"
    );
    let request = ureq::get(url);
    let parsed = request
        .request_url()
        .context("invalid package download URL")?;
    let parsed = parsed.as_url();
    let https = parsed.scheme() == "https" && url.starts_with("https://");
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?']).next().unwrap_or_default());
    let loopback = allow_loopback
        && parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]"))
        && parsed.port().is_some_and(|p| p > 0);
    ensure!(
        (https || loopback)
            && authority.is_some_and(|host| !host.is_empty())
            && parsed.host_str().is_some_and(|h| !h.is_empty())
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "package downloads require HTTPS"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.open_regular")
)]
fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "package source must be a regular file"
    );
    Ok(file)
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.open_relative")
)]
fn open_relative(base: &Path, path: &Path) -> Result<File> {
    use nix::{
        fcntl::{openat, OFlag},
        sys::stat::Mode,
    };
    let mut directory = File::open(base)?;
    let mut parts = path.components().peekable();
    while let Some(Component::Normal(part)) = parts.next() {
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let flags = if parts.peek().is_some() {
            flags | OFlag::O_DIRECTORY
        } else {
            flags
        };
        let file = File::from(openat(&directory, Path::new(part), flags, Mode::empty())?);
        if parts.peek().is_none() {
            ensure!(
                file.metadata()?.is_file(),
                "package source must be a regular file"
            );
            return Ok(file);
        }
        directory = file;
    }
    eyre::bail!("empty package file path")
}

#[cfg(not(unix))]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.open_relative")
)]
fn open_relative(base: &Path, path: &Path) -> Result<File> {
    let mut full = base.to_path_buf();
    for part in path.components() {
        full.push(part);
        ensure!(
            !std::fs::symlink_metadata(&full)?.file_type().is_symlink(),
            "package source contains symlink"
        );
    }
    open_regular(&full)
}

fn copy_checked(mut input: File, output: &mut File, artifact: &Artifact) -> Result<()> {
    check_stream(&mut input, output, artifact)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "package.check_stream")
)]
fn check_stream(input: &mut impl Read, output: &mut impl Write, artifact: &Artifact) -> Result<()> {
    let mut bounded = input.take(artifact.bytes + 1);
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = bounded.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(
            count <= artifact.bytes,
            "package artifact exceeds pinned size"
        );
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    ensure!(count == artifact.bytes, "package artifact size mismatch");
    ensure!(
        hex::encode(hash.finalize()) == artifact.sha256,
        "package artifact SHA-256 mismatch"
    );
    Ok(())
}
