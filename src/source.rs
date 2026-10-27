//! Immutable, local-only source capture. No command in this module fetches or builds.

use eyre::{bail, ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::ops::Bound::{Included, Unbounded};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::SystemTime;

const RECEIPT_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct CaptureOptions {
    pub source: PathBuf,
    /// A new directory, outside the checkout, for source.tar and receipt.json.
    pub output: PathBuf,
    /// None captures current working files; Some captures the resolved commit.
    pub revision: Option<String>,
    /// Exact, checkout-relative files to include in addition to tracked files.
    pub include: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    Worktree,
    Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotFileKind {
    File,
    Symlink,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SnapshotFile {
    pub path: String,
    /// Unix permission bits (0644 or 0755 for files, 0777 for symlinks).
    pub mode: u32,
    pub kind: SnapshotFileKind,
    /// For symlinks, the hash and size describe the link target text.
    pub sha256: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SnapshotReceipt {
    pub schema_version: u32,
    pub source_root: PathBuf,
    pub mode: SnapshotMode,
    pub head: String,
    pub branch: Option<String>,
    pub dirty: bool,
    pub files: Vec<SnapshotFile>,
    pub deleted_paths: Vec<String>,
    pub omitted_untracked: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub archive_sha256: String,
    pub archive_bytes: u64,
}

/// Boundaries for deterministic mutation tests and local progress reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureCheckpoint {
    Selected,
    Copied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GitEntry {
    mode: u32,
    object: String,
}

#[derive(Debug, PartialEq, Eq)]
struct WorktreeState {
    head: String,
    branch: Option<String>,
    index: Vec<u8>,
    flags: Vec<u8>,
    untracked: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: SystemTime,
    symlink: bool,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64, u32),
}

impl FileStamp {
    fn new(metadata: &Metadata) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            symlink: metadata.file_type().is_symlink(),
            #[cfg(unix)]
            identity: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.mode(),
            ),
        })
    }
}

pub fn capture(options: &CaptureOptions) -> Result<SnapshotReceipt> {
    capture_with_hook(options, |_| Ok(()))
}

struct CaptureLock(File);

impl Drop for CaptureLock {
    fn drop(&mut self) {
        // A concurrent spawn can briefly inherit this open-file description.
        // Explicitly unlock before returning, even if that child has not exec'd.
        let _ = FileExt::unlock(&self.0);
    }
}

/// Capture with a caller-supplied barrier. A hook error aborts publication.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.capture")
)]
pub fn capture_with_hook(
    options: &CaptureOptions,
    mut hook: impl FnMut(CaptureCheckpoint) -> Result<()>,
) -> Result<SnapshotReceipt> {
    let source = options
        .source
        .canonicalize()
        .context("source directory does not exist")?;
    let root_text = git_text(&source, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root_text.strip_suffix('\n').unwrap_or(&root_text)).canonicalize()?;
    ensure!(
        source == root,
        "source must be the Git worktree root; select {}",
        root.display()
    );
    let (output, parent) = output_location(&options.output, &root)?;
    let lock_path = parent.join(".zdn-source-capture.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "source capture lock must be a regular file: {}",
            lock_path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect source capture lock"),
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    ensure!(
        lock_metadata.is_file() && !lock_metadata.file_type().is_symlink(),
        "source capture lock must be a regular file: {}",
        lock_path.display()
    );
    lock.try_lock_exclusive().context(
        "another source capture is in progress in this output parent; retry after it completes",
    )?;
    let _lock = CaptureLock(lock);
    ensure!(
        !output.try_exists()? && fs::symlink_metadata(&output).is_err(),
        "snapshot output already exists: {}; choose a new directory",
        output.display()
    );
    let temporary = tempfile::Builder::new()
        .prefix(".zdn-capture-")
        .tempdir_in(&parent)?;
    let data = temporary.path().join("data");
    fs::create_dir(&data)?;
    let published = temporary.path().join("published");
    fs::create_dir(&published)?;

    let mut receipt = if let Some(revision) = &options.revision {
        ensure!(
            options.include.is_empty(),
            "--include applies only to worktree capture, not an exact revision"
        );
        capture_revision(&root, revision, &data, &mut hook)?
    } else {
        capture_worktree(&root, &options.include, &data, &mut hook)?
    };
    validate_links(&receipt.files)?;
    validate_dependencies(
        &receipt.files,
        &data,
        (receipt.mode == SnapshotMode::Worktree).then_some(root.as_path()),
    )?;
    let archive = published.join("source.tar");
    let (sha256, size) = write_archive(&archive, &data, &receipt.files)?;
    receipt.archive_sha256 = sha256;
    receipt.archive_bytes = size;
    let mut manifest =
        BufWriter::with_capacity(64 * 1024, File::create(published.join("receipt.json"))?);
    serde_json::to_writer_pretty(&mut manifest, &receipt)?;
    manifest.write_all(b"\n")?;
    // The receipt must reach the file before fsync and atomic publication.
    manifest.flush()?;
    manifest.get_ref().sync_all()?;
    File::open(&published)?.sync_all()?;
    // All zdn writers share the parent lock. Publication moves one completed
    // directory; an interrupted copy can never be mistaken for a valid snapshot.
    ensure!(
        fs::symlink_metadata(&output).is_err(),
        "snapshot output appeared during capture: {}",
        output.display()
    );
    fs::rename(&published, &output).context("publish completed source snapshot")?;
    File::open(&parent)?.sync_all()?;
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.output_location")
)]
fn output_location(output: &Path, root: &Path) -> Result<(PathBuf, PathBuf)> {
    let absolute = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    let name = absolute
        .file_name()
        .context("snapshot output must name a new directory")?;
    let parent = absolute
        .parent()
        .context("snapshot output must have a parent directory")?
        .canonicalize()
        .context("create the snapshot output's parent directory first")?;
    ensure!(
        !parent.starts_with(root),
        "snapshot output must be outside the source checkout"
    );
    Ok((parent.join(name), parent))
}

fn empty_receipt(root: &Path, mode: SnapshotMode, head: String) -> SnapshotReceipt {
    SnapshotReceipt {
        schema_version: RECEIPT_VERSION,
        source_root: root.to_owned(),
        mode,
        head,
        branch: None,
        dirty: false,
        files: Vec::new(),
        deleted_paths: Vec::new(),
        omitted_untracked: Vec::new(),
        excluded_paths: Vec::new(),
        archive_sha256: String::new(),
        archive_bytes: 0,
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.capture_worktree")
)]
fn capture_worktree(
    root: &Path,
    includes: &[PathBuf],
    data: &Path,
    hook: &mut impl FnMut(CaptureCheckpoint) -> Result<()>,
) -> Result<SnapshotReceipt> {
    let before = worktree_state(root)?;
    let mut selected = parse_index(&before.index)?;
    let skipped = skip_worktree_paths(&before.flags)?;
    reject_submodules(&selected)?;
    let baseline = tree_entries(root, &before.head)?;
    let mut receipt = empty_receipt(root, SnapshotMode::Worktree, before.head.clone());
    receipt.branch.clone_from(&before.branch);
    // Never run `git status`: checking worktree contents can invoke arbitrary
    // clean/process filter commands configured by the repository. Compare the
    // index and the raw captured bytes with HEAD instead.
    receipt.dirty = selected != baseline || !before.untracked.is_empty();
    let mut explicit = BTreeSet::new();
    for include in includes {
        let path = relative_path(include)?;
        ensure!(
            !excluded(&path),
            "included path is excluded from source capture: {path}"
        );
        explicit.insert(path.clone());
        selected.entry(path).or_insert(GitEntry {
            mode: 0o100644,
            object: String::new(),
        });
    }
    receipt.omitted_untracked = before
        .untracked
        .iter()
        .filter(|path| !explicit.contains(*path) && !excluded(path))
        .cloned()
        .collect();
    let mut stamps = BTreeMap::new();
    for path in selected.keys() {
        if excluded(path) {
            receipt.excluded_paths.push(path.clone());
            continue;
        }
        ensure_safe_parents(root, path)?;
        match fs::symlink_metadata(root.join(path)) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() || metadata.file_type().is_symlink(),
                    "source path is not a regular file or symlink: {path}"
                );
                stamps.insert(path.clone(), FileStamp::new(&metadata)?);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ensure!(
                    !skipped.contains(path),
                    "source file is omitted by sparse checkout or skip-worktree: {path}; restore the full checkout before capture"
                );
                ensure!(
                    !explicit.contains(path),
                    "included file does not exist: {path}"
                );
                receipt.deleted_paths.push(path.clone());
            }
            Err(error) => return Err(error).with_context(|| format!("inspect source {path}")),
        }
    }
    for path in baseline.keys() {
        if !selected.contains_key(path) && !excluded(path) {
            receipt.deleted_paths.push(path.clone());
        }
    }
    for path in &before.untracked {
        if excluded(path) {
            receipt.excluded_paths.push(path.clone());
        }
    }
    receipt.deleted_paths.sort();
    receipt.deleted_paths.dedup();
    receipt.dirty |= !receipt.deleted_paths.is_empty();
    receipt.excluded_paths.sort();
    receipt.excluded_paths.dedup();
    reject_worktree_lfs(root, stamps.keys())?;
    hook(CaptureCheckpoint::Selected)?;
    for (path, stamp) in &stamps {
        ensure_stamp(root, path, stamp)?;
        let metadata = fs::symlink_metadata(root.join(path))?;
        let file = if metadata.file_type().is_symlink() {
            let target = fs::read_link(root.join(path))?;
            let target = target
                .to_str()
                .context("source symlink target is not UTF-8")?
                .to_owned();
            // Verify the working link too, not just its path in the archive.
            let resolved = root
                .join(path)
                .canonicalize()
                .with_context(|| format!("dangling source symlink: {path}"))?;
            ensure!(
                resolved.starts_with(root),
                "source symlink escapes the checkout: {path}"
            );
            symlink_entry(path, target)
        } else {
            let saved = staged_path(data, path);
            let mut source = File::open(root.join(path))?;
            let mut destination = File::create_new(&saved)?;
            let (sha256, size) = copy_hash(&mut source, &mut destination)?;
            reject_lfs_pointer(&saved, path)?;
            SnapshotFile {
                path: path.clone(),
                mode: regular_mode(&metadata, selected[path].mode),
                kind: SnapshotFileKind::File,
                sha256,
                size,
                link_target: None,
            }
        };
        ensure_stamp(root, path, stamp)?;
        receipt.files.push(file);
    }
    if !receipt.dirty {
        // This also catches assume-unchanged/skip-worktree edits and ignored
        // files supplied through --include, without invoking Git filters.
        let mut objects = GitObjects::start(root)?;
        for file in &receipt.files {
            let Some(original) = baseline.get(&file.path) else {
                receipt.dirty = true;
                break;
            };
            let expected_mode = if original.mode == 0o120000 {
                0o777
            } else {
                original.mode & 0o777
            };
            let original_kind = if original.mode == 0o120000 {
                SnapshotFileKind::Symlink
            } else {
                SnapshotFileKind::File
            };
            if file.mode != expected_mode
                || file.kind != original_kind
                || objects.copy_blob(&original.object, &mut io::sink())?
                    != (file.sha256.clone(), file.size)
            {
                receipt.dirty = true;
                break;
            }
        }
        objects.finish()?;
    }
    hook(CaptureCheckpoint::Copied)?;
    ensure!(
        before == worktree_state(root)?,
        "source Git state changed during capture; retry with a new snapshot"
    );
    for file in &receipt.files {
        ensure_stamp(root, &file.path, &stamps[&file.path])?;
        let actual = if file.kind == SnapshotFileKind::Symlink {
            let target = fs::read_link(root.join(&file.path))?;
            hash_reader(
                target
                    .to_str()
                    .context("symlink target is not UTF-8")?
                    .as_bytes(),
            )?
        } else {
            hash_reader(File::open(root.join(&file.path))?)?
        };
        ensure!(
            actual == (file.sha256.clone(), file.size),
            "source bytes changed during capture: {}; retry with a new snapshot",
            file.path
        );
        ensure_stamp(root, &file.path, &stamps[&file.path])?;
    }
    // A tracked deletion recreated during capture also changes the snapshot.
    for path in &receipt.deleted_paths {
        if selected.contains_key(path) {
            ensure!(
                fs::symlink_metadata(root.join(path)).is_err(),
                "deleted source file reappeared during capture: {path}"
            );
        }
    }
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.copy_revision")
)]
fn capture_revision(
    root: &Path,
    revision: &str,
    data: &Path,
    hook: &mut impl FnMut(CaptureCheckpoint) -> Result<()>,
) -> Result<SnapshotReceipt> {
    ensure!(!revision.is_empty(), "source revision cannot be empty");
    let expression = format!("{revision}^{{commit}}");
    let head = git_text(
        root,
        &["rev-parse", "--verify", "--end-of-options", &expression],
    )?
    .trim()
    .to_owned();
    let entries = tree_entries(root, &head)?;
    reject_submodules(&entries)?;
    let mut receipt = empty_receipt(root, SnapshotMode::Revision, head);
    let mut objects = GitObjects::start(root)?;
    hook(CaptureCheckpoint::Selected)?;
    for (path, entry) in entries {
        if excluded(&path) {
            receipt.excluded_paths.push(path);
            continue;
        }
        if entry.mode == 0o120000 {
            let mut bytes = Vec::new();
            objects.copy_blob(&entry.object, &mut bytes)?;
            let target = String::from_utf8(bytes).context("source symlink target is not UTF-8")?;
            receipt.files.push(symlink_entry(&path, target));
        } else {
            ensure!(
                matches!(entry.mode, 0o100644 | 0o100755),
                "unsupported Git mode for {path}"
            );
            let saved = staged_path(data, &path);
            let mut file = File::create_new(&saved)?;
            let (sha256, size) = objects.copy_blob(&entry.object, &mut file)?;
            reject_lfs_pointer(&saved, &path)?;
            receipt.files.push(SnapshotFile {
                path,
                mode: entry.mode & 0o777,
                kind: SnapshotFileKind::File,
                sha256,
                size,
                link_target: None,
            });
        }
    }
    objects.finish()?;
    hook(CaptureCheckpoint::Copied)?;
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.git_command")
)]
fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    // Replacement refs can substitute different commit, tree, or blob bytes
    // without changing the object ID recorded in the source receipt.
    command.env("GIT_NO_REPLACE_OBJECTS", "1");
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command.env("GIT_NO_LAZY_FETCH", "1");
    command.env("GIT_TERMINAL_PROMPT", "0");
    command
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.git_bytes")
)]
fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_command(root)
        .args(args)
        .output()
        .context("run Git; install Git first")?;
    ensure!(
        output.status.success(),
        "Git {} failed: {}",
        args.first().copied().unwrap_or("command"),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    String::from_utf8(git_bytes(root, args)?).context("Git returned non-UTF-8 source metadata")
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.worktree_state")
)]
fn worktree_state(root: &Path) -> Result<WorktreeState> {
    let head = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])
        .context("source capture requires an existing Git commit")?
        .trim()
        .to_owned();
    let branch = git_command(root)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()?;
    let branch = if branch.status.success() {
        Some(
            String::from_utf8(branch.stdout)?
                .trim_end_matches('\n')
                .to_owned(),
        )
    } else if branch.status.code() == Some(1) {
        None
    } else {
        bail!("cannot read source branch");
    };
    Ok(WorktreeState {
        head,
        branch,
        index: git_bytes(root, &["ls-files", "--stage", "-z"])?,
        flags: git_bytes(root, &["ls-files", "-v", "-z"])?,
        untracked: nul_paths(&git_bytes(
            root,
            &["ls-files", "--others", "--exclude-standard", "-z"],
        )?)?,
    })
}

fn nul_paths(bytes: &[u8]) -> Result<Vec<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| relative_path(Path::new(std::str::from_utf8(part)?)))
        .collect()
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.parse_index")
)]
fn parse_index(bytes: &[u8]) -> Result<BTreeMap<String, GitEntry>> {
    let mut entries = BTreeMap::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let record = std::str::from_utf8(record).context("source paths must use UTF-8")?;
        let (metadata, path) = record
            .split_once('\t')
            .context("invalid Git index record")?;
        let parts: Vec<_> = metadata.split_whitespace().collect();
        ensure!(parts.len() == 3, "invalid Git index metadata");
        ensure!(
            parts[2] == "0",
            "resolve Git merge conflicts before source capture: {path}"
        );
        entries.insert(
            relative_path(Path::new(path))?,
            GitEntry {
                mode: u32::from_str_radix(parts[0], 8)?,
                object: parts[1].to_owned(),
            },
        );
    }
    Ok(entries)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.skip_worktree_paths")
)]
fn skip_worktree_paths(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        ensure!(
            record.len() >= 3 && record[1] == b' ',
            "invalid Git index flags"
        );
        if matches!(record[0], b'S' | b's') {
            paths.insert(relative_path(Path::new(std::str::from_utf8(
                &record[2..],
            )?))?);
        }
    }
    Ok(paths)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.tree_entries")
)]
fn tree_entries(root: &Path, revision: &str) -> Result<BTreeMap<String, GitEntry>> {
    let bytes = git_bytes(root, &["ls-tree", "-r", "--full-tree", "-z", revision])?;
    let mut entries = BTreeMap::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let record = std::str::from_utf8(record).context("source paths must use UTF-8")?;
        let (metadata, path) = record.split_once('\t').context("invalid Git tree record")?;
        let parts: Vec<_> = metadata.split_whitespace().collect();
        ensure!(parts.len() == 3, "invalid Git tree metadata");
        entries.insert(
            relative_path(Path::new(path))?,
            GitEntry {
                mode: u32::from_str_radix(parts[0], 8)?,
                object: parts[2].to_owned(),
            },
        );
    }
    Ok(entries)
}

fn reject_submodules(entries: &BTreeMap<String, GitEntry>) -> Result<()> {
    for (path, entry) in entries {
        ensure!(entry.mode != 0o160000,
            "Git submodules are not supported by source capture yet: {path}; vendor the required source or choose a supported release");
    }
    Ok(())
}

fn relative_path(path: &Path) -> Result<String> {
    ensure!(!path.as_os_str().is_empty(), "source path cannot be empty");
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            _ => bail!(
                "source path must be checkout-relative without '..': {}",
                path.display()
            ),
        }
    }
    ensure!(
        !normalized.as_os_str().is_empty(),
        "include an exact file, not the checkout directory"
    );
    Ok(normalized
        .to_str()
        .context("source paths must use UTF-8")?
        .to_owned())
}

fn excluded(path: &str) -> bool {
    let path = Path::new(path);
    if path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some(
                ".git"
                    | ".context"
                    | ".aws"
                    | ".ssh"
                    | ".gnupg"
                    | ".zdn"
                    | ".pulumi"
                    | ".zcash"
                    | ".zakura"
                    | ".zebra"
                    | ".lightwalletd"
                    | "target"
                    | "node_modules"
                    | "__pycache__"
                    | ".venv"
                    | "venv"
            )
        )
    }) {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "credentials"
            | "credentials.json"
            | "credentials.toml"
            | "credentials.yaml"
            | "wallet.dat"
            | "wallet.db"
            | "wallet.sqlite"
            | "wallet.sqlite3"
            | "wallet.keys"
            | "wallet.seed"
            | "mnemonic"
            | "id_rsa"
            | "id_ed25519"
    ) || lower == ".env"
        || (lower.starts_with(".env.")
            && !matches!(
                lower.as_str(),
                ".env.example" | ".env.sample" | ".env.template"
            ))
        || (name.starts_with("Pulumi.")
            && (name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".json")))
        || matches!(
            Path::new(&lower).extension().and_then(|ext| ext.to_str()),
            Some("pem" | "p12" | "pfx" | "key")
        )
}

fn ensure_safe_parents(root: &Path, path: &str) -> Result<()> {
    let mut current = root.to_owned();
    let parts: Vec<_> = Path::new(path).components().collect();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "source path has a non-directory or symlink parent: {path}"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_stamp(root: &Path, path: &str, expected: &FileStamp) -> Result<()> {
    ensure_safe_parents(root, path)?;
    let actual = fs::symlink_metadata(root.join(path))
        .with_context(|| format!("source changed during capture: {path}"))?;
    ensure!(
        FileStamp::new(&actual)? == *expected,
        "source changed during capture: {path}; retry with a new snapshot"
    );
    Ok(())
}

fn regular_mode(metadata: &Metadata, index_mode: u32) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = index_mode;
        if metadata.permissions().mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        index_mode & 0o777
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.reject_worktree_lfs")
)]
fn reject_worktree_lfs<'a>(root: &Path, paths: impl Iterator<Item = &'a String>) -> Result<()> {
    let mut paths_file = tempfile::tempfile()?;
    for path in paths {
        paths_file.write_all(path.as_bytes())?;
        paths_file.write_all(&[0])?;
    }
    use std::io::Seek;
    paths_file.rewind()?;
    let output = git_command(root)
        .args(["check-attr", "-z", "--stdin", "filter"])
        .stdin(paths_file)
        .output()?;
    ensure!(
        output.status.success(),
        "cannot check source Git LFS attributes"
    );
    let fields: Vec<_> = output.stdout.split(|byte| *byte == 0).collect();
    for fields in fields.chunks_exact(3) {
        ensure!(fields[2] != b"lfs", "Git LFS source is not supported yet: {}; vendor the required bytes without LFS or choose a supported release",
            String::from_utf8_lossy(fields[0]));
    }
    Ok(())
}

fn reject_lfs_pointer(file: &Path, path: &str) -> Result<()> {
    let mut prefix = [0; 44];
    let count = File::open(file)?.read(&mut prefix)?;
    ensure!(
        !prefix[..count].starts_with(b"version https://git-lfs.github.com/spec/v1"),
        "unresolved Git LFS pointer is not supported: {path}"
    );
    Ok(())
}

fn symlink_entry(path: &str, target: String) -> SnapshotFile {
    SnapshotFile {
        path: path.to_owned(),
        mode: 0o777,
        kind: SnapshotFileKind::Symlink,
        sha256: hex::encode(Sha256::digest(target.as_bytes())),
        size: target.len() as u64,
        link_target: Some(target),
    }
}

fn resolve_archive_path(path: &Path, files: &BTreeMap<&str, &SnapshotFile>) -> Result<PathBuf> {
    let mut pending = archive_path_steps(path)?;
    let mut resolved = PathBuf::new();
    let mut expansions = 0;
    while let Some(component) = pending.pop_front() {
        if component == Path::new("..") {
            ensure!(
                resolved.pop(),
                "path escapes the source checkout: {}",
                path.display()
            );
            continue;
        }
        let candidate = resolved.join(&component);
        let name = candidate.to_str().context("source path is not UTF-8")?;
        if let Some(file) = files.get(name) {
            if let Some(target) = &file.link_target {
                expansions += 1;
                ensure!(
                    expansions <= 64,
                    "source symlink cycle or excessive link depth: {}",
                    path.display()
                );
                // POSIX expands each link before processing subsequent '..'
                // components. Lexically normalizing the whole target first
                // could hide an escape through an intermediate directory link.
                let mut target = archive_path_steps(Path::new(target))?;
                target.append(&mut pending);
                pending = target;
                continue;
            }
            ensure!(
                pending.is_empty(),
                "source path traverses a file: {}",
                path.display()
            );
        } else if !pending.is_empty() {
            ensure!(
                archive_has_descendants(name, files),
                "source path traverses a directory not included in the snapshot: {}",
                path.display()
            );
        }
        resolved = candidate;
    }
    Ok(resolved)
}

fn archive_path_steps(path: &Path) -> Result<VecDeque<PathBuf>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(_) | Component::ParentDir => {
                Some(Ok(PathBuf::from(component.as_os_str())))
            }
            Component::CurDir => None,
            _ => Some(Err(eyre::eyre!(
                "absolute paths are not portable source dependencies: {}",
                path.display()
            ))),
        })
        .collect()
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.validate_links")
)]
fn validate_links(files: &[SnapshotFile]) -> Result<()> {
    let entries: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    for file in files
        .iter()
        .filter(|file| file.kind == SnapshotFileKind::Symlink)
    {
        let resolved = resolve_archive_path(Path::new(&file.path), &entries)
            .with_context(|| format!("invalid source symlink {}", file.path))?;
        let target = resolved.to_str().context("source path is not UTF-8")?;
        ensure!(
            !target.is_empty(),
            "symlink to source root is not supported: {}",
            file.path
        );
        ensure!(
            entries.contains_key(target) || archive_has_descendants(target, &entries),
            "source symlink target is not included in the snapshot: {} -> {target}",
            file.path
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.validate_dependencies")
)]
fn validate_dependencies(
    files: &[SnapshotFile],
    data: &Path,
    worktree: Option<&Path>,
) -> Result<()> {
    let entries: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    for file in files {
        let path = Path::new(&file.path);
        let is_manifest = path.file_name().is_some_and(|name| name == "Cargo.toml");
        let is_config = path
            .file_name()
            .is_some_and(|name| name == "config" || name == "config.toml")
            && path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == ".cargo");
        if !is_manifest && !is_config {
            continue;
        }
        let document = read_cargo_document(path, &entries, data)?;
        let base = if is_manifest {
            path.parent().unwrap_or(Path::new(""))
        } else {
            path.parent()
                .and_then(Path::parent)
                .unwrap_or(Path::new(""))
        };
        check_dependency_tables(&document, base, &entries, &file.path)?;
        if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
            for target in targets.values() {
                check_dependency_tables(target, base, &entries, &file.path)?;
            }
        }
        if let Some(workspace) = document.get("workspace") {
            check_dependency_tables(workspace, base, &entries, &file.path)?;
            check_workspace_members(workspace, base, &entries, &file.path)?;
        }
        if let Some(workspace) = document
            .get("package")
            .and_then(|package| package.get("workspace"))
            .and_then(toml::Value::as_str)
        {
            check_cargo_path(workspace, base, &entries, &file.path)?;
        }
        if is_config {
            if let Some(paths) = document.get("paths").and_then(toml::Value::as_array) {
                for dependency in paths.iter().filter_map(toml::Value::as_str) {
                    check_cargo_path(dependency, base, &entries, &file.path)?;
                }
            }
            if let Some(sources) = document.get("source").and_then(toml::Value::as_table) {
                for (name, source) in sources {
                    if let Some(directory) = source.get("directory") {
                        let directory = directory.as_str().with_context(|| {
                            format!(
                                "Cargo source.{name}.directory must be a path in {}",
                                file.path
                            )
                        })?;
                        ensure!(
                            archive_directory(&base.join(directory), &entries).with_context(|| {
                                format!("external Cargo source directory in {}: {directory}", file.path)
                            })?,
                            "Cargo source directory in {} is absent from the snapshot: {directory}; track or explicitly include its required files",
                            file.path
                        );
                    }
                }
            }
        } else {
            let legacy = cargo_legacy_edition(&document, base, &entries, data)?;
            check_cargo_entrypoints(&document, base, &entries, &file.path, worktree, legacy)?;
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.read_cargo_document")
)]
fn read_cargo_document(
    path: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    data: &Path,
) -> Result<toml::Value> {
    let resolved = resolve_archive_path(path, entries)?;
    let bytes = fs::read_to_string(staged_path(
        data,
        resolved
            .to_str()
            .context("source Cargo path is not UTF-8")?,
    ))
    .with_context(|| format!("read source Cargo file {}", path.display()))?;
    toml::from_str(&bytes).with_context(|| format!("parse source Cargo file {}", path.display()))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.cargo_legacy_edition")
)]
fn cargo_legacy_edition(
    document: &toml::Value,
    base: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    data: &Path,
) -> Result<bool> {
    let package = document.get("package");
    let edition = package.and_then(|package| package.get("edition"));
    if edition
        .and_then(|edition| edition.get("workspace"))
        .and_then(toml::Value::as_bool)
        != Some(true)
    {
        return Ok(edition.is_none() || edition.and_then(toml::Value::as_str) == Some("2015"));
    }
    let explicit = package
        .and_then(|package| package.get("workspace"))
        .and_then(toml::Value::as_str)
        .map(|path| base.join(path));
    let candidates: Vec<_> = match explicit {
        Some(root) => vec![root],
        None => base.ancestors().map(Path::to_owned).collect(),
    };
    for root in candidates {
        let manifest = root.join("Cargo.toml");
        let Ok(resolved) = resolve_archive_path(&manifest, entries) else {
            continue;
        };
        if !resolved
            .to_str()
            .is_some_and(|path| entries.contains_key(path))
        {
            continue;
        }
        let document = read_cargo_document(&manifest, entries, data)?;
        if let Some(workspace) = document.get("workspace") {
            let edition = workspace
                .get("package")
                .and_then(|package| package.get("edition"))
                .and_then(toml::Value::as_str)
                .with_context(|| {
                    format!(
                        "Cargo workspace.package.edition is absent from {}",
                        manifest.display()
                    )
                })?;
            return Ok(edition == "2015");
        }
    }
    bail!(
        "Cargo workspace edition for {} is absent from the snapshot; capture its workspace root",
        base.display()
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.check_cargo_entrypoints")
)]
fn check_cargo_entrypoints(
    document: &toml::Value,
    base: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    manifest: &str,
    worktree: Option<&Path>,
    legacy: bool,
) -> Result<()> {
    let Some(package) = document.get("package") else {
        return Ok(());
    };
    let paths = CargoSourcePaths {
        base,
        entries,
        manifest,
        worktree,
    };
    match package.get("build") {
        Some(toml::Value::Boolean(false)) => {}
        Some(toml::Value::Boolean(true)) => paths.required("build.rs", "package.build")?,
        Some(toml::Value::String(path)) => paths.required(path, "package.build")?,
        None => paths.optional("build.rs", "implicit build script")?,
        Some(_) => bail!("Cargo package.build must be a path or boolean in {manifest}"),
    }
    if let Some(library) = document.get("lib") {
        let default_name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .replace('-', "_");
        let legacy_path = format!(
            "src/{}.rs",
            library
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or(&default_name)
        );
        let path = match library.get("path") {
            Some(value) => value
                .as_str()
                .with_context(|| format!("Cargo lib.path must be a path in {manifest}"))?,
            None if legacy && !paths.present("src/lib.rs")? && paths.present(&legacy_path)? => {
                &legacy_path
            }
            None => "src/lib.rs",
        };
        paths.required(path, "lib.path")?;
    } else if package.get("autolib").and_then(toml::Value::as_bool) != Some(false) {
        paths.optional("src/lib.rs", "implicit library")?;
    }
    let binaries = document.get("bin").and_then(toml::Value::as_array);
    let mut explicit_names = BTreeSet::new();
    for binary in binaries.into_iter().flatten() {
        if let Some(name) = binary.get("name").and_then(toml::Value::as_str) {
            explicit_names.insert(name);
        }
        if let Some(path) = binary.get("path") {
            paths.required(
                path.as_str()
                    .with_context(|| format!("Cargo bin.path must be a path in {manifest}"))?,
                "bin.path",
            )?;
            continue;
        }
        let name = binary
            .get("name")
            .and_then(toml::Value::as_str)
            .with_context(|| {
                format!("Cargo binary without a path must have a name in {manifest}")
            })?;
        ensure!(
            !name.is_empty()
                && Path::new(name).file_name().and_then(|name| name.to_str()) == Some(name),
            "invalid Cargo binary name in {manifest}: {name}"
        );
        let mut candidates = vec![
            format!("src/bin/{name}.rs"),
            format!("src/bin/{name}/main.rs"),
        ];
        if package.get("name").and_then(toml::Value::as_str) == Some(name) {
            candidates.push("src/main.rs".to_owned());
        }
        let mut matched = false;
        for candidate in &candidates {
            if paths.present(candidate)? {
                paths.required(candidate, "implicit bin.path")?;
                matched = true;
            }
        }
        // Cargo still accepts the historical renamed src/main.rs binary for
        // Edition 2015 when no path with the declared name can be inferred.
        if !matched && legacy && paths.present("src/main.rs")? {
            paths.required("src/main.rs", "implicit bin.path")?;
            matched = true;
        }
        ensure!(
            matched,
            "Cargo binary {name} in {manifest} has no source file in the snapshot; set bin.path or track its inferred source file"
        );
    }
    let discover_bins = package
        .get("autobins")
        .and_then(toml::Value::as_bool)
        .unwrap_or(!legacy || binaries.is_none());
    if discover_bins {
        if !package
            .get("name")
            .and_then(toml::Value::as_str)
            .is_some_and(|name| explicit_names.contains(name))
        {
            paths.optional("src/main.rs", "implicit binary")?;
        }
        for child in paths.bin_children()? {
            let name = child.file_name().context("Cargo binary path has no name")?;
            let name = name.to_str().context("Cargo binary path is not UTF-8")?;
            let (target_name, candidate) = if let Some(name) = name.strip_suffix(".rs") {
                (name, format!("src/bin/{name}.rs"))
            } else {
                (name, format!("src/bin/{name}/main.rs"))
            };
            if !explicit_names.contains(target_name) {
                paths.optional(&candidate, "implicit binary")?;
            }
        }
    }
    Ok(())
}

struct CargoSourcePaths<'a> {
    base: &'a Path,
    entries: &'a BTreeMap<&'a str, &'a SnapshotFile>,
    manifest: &'a str,
    worktree: Option<&'a Path>,
}

impl CargoSourcePaths<'_> {
    fn required(&self, source: &str, field: &str) -> Result<()> {
        ensure!(
            !source.is_empty(),
            "Cargo {field} path is empty in {}",
            self.manifest
        );
        let resolved =
            resolve_archive_path(&self.base.join(source), self.entries).with_context(|| {
                format!(
                    "invalid Cargo {field} in {}: {source}; capture a self-contained checkout",
                    self.manifest
                )
            })?;
        ensure!(
            self.entries.contains_key(resolved.to_str().context("Cargo source path is not UTF-8")?),
            "Cargo {field} in {} is absent from the snapshot: {source}; track or explicitly include its required file",
            self.manifest
        );
        Ok(())
    }

    fn present(&self, source: &str) -> Result<bool> {
        let path = self.base.join(source);
        if resolve_archive_path(&path, self.entries)
            .ok()
            .and_then(|resolved| {
                resolved
                    .to_str()
                    .map(|path| self.entries.contains_key(path))
            })
            == Some(true)
        {
            return Ok(true);
        }
        // An omitted (including ignored) default source must not silently
        // disappear from a branch build. Revision captures consult only the
        // selected tree and never inspect the current worktree for defaults.
        if let Some(root) = self.worktree {
            match fs::symlink_metadata(root.join(path)) {
                Ok(_) => return Ok(true),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) => {}
                Err(error) => return Err(error).context("inspect implicit Cargo source"),
            }
        }
        Ok(false)
    }

    fn optional(&self, source: &str, field: &str) -> Result<()> {
        if self.present(source)? {
            self.required(source, field)?;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "source.cargo_source_paths.bin_children")
    )]
    fn bin_children(&self) -> Result<BTreeSet<PathBuf>> {
        let path = self.base.join("src/bin");
        let mut children = if archive_directory(&path, self.entries).unwrap_or(false) {
            archive_children(&path, self.entries)?
        } else {
            BTreeSet::new()
        };
        if let Some(root) = self.worktree {
            match fs::symlink_metadata(root.join(&path)) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        ensure!(
                            archive_directory(&path, self.entries)?,
                            "implicit Cargo binary directory is absent from the snapshot: {}",
                            path.display()
                        );
                    }
                    if metadata.is_dir() || metadata.file_type().is_symlink() {
                        ensure!(
                            root.join(&path).canonicalize()?.starts_with(root),
                            "implicit Cargo binary directory escapes the source checkout: {}",
                            path.display()
                        );
                        for child in fs::read_dir(root.join(&path))? {
                            children.insert(path.join(child?.file_name()));
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) => {}
                Err(error) => return Err(error).context("inspect implicit Cargo binary directory"),
            }
        }
        Ok(children)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.check_workspace_members")
)]
fn check_workspace_members(
    workspace: &toml::Value,
    base: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    manifest: &str,
) -> Result<()> {
    let strings = |key| -> Result<Vec<&str>> {
        let Some(value) = workspace.get(key) else {
            return Ok(Vec::new());
        };
        value
            .as_array()
            .with_context(|| format!("Cargo workspace {key} must be an array in {manifest}"))?
            .iter()
            .map(|value| {
                value.as_str().with_context(|| {
                    format!("Cargo workspace {key} must contain strings in {manifest}")
                })
            })
            .collect()
    };
    // Cargo joins these paths to an absolute root, where a leading './' is
    // already an interior component. Drop CurDir here to obtain the same
    // comparisons for archive-relative paths; preserve '..' for link handling.
    let relative_paths = |values: Vec<&str>| -> Vec<PathBuf> {
        values
            .into_iter()
            .map(|value| {
                base.join(value)
                    .components()
                    .filter(|component| !matches!(component, Component::CurDir))
                    .collect()
            })
            .collect()
    };
    let members = relative_paths(strings("members")?);
    let excludes = relative_paths(strings("exclude")?);
    for pattern in &members {
        let mut expanded = expand_workspace_member(pattern, entries).with_context(|| {
            format!("external Cargo workspace member or invalid pattern in {manifest}")
        })?;
        // Cargo falls back to the original path when a glob matches nothing,
        // so a missing required member must not turn into an empty workspace.
        let unmatched = expanded.is_empty();
        if unmatched {
            expanded.push(pattern.clone());
        }
        for path in expanded {
            // Cargo ignores existing non-directory matches (for example,
            // crates/README). A pattern with no matches still needs to fail.
            if !unmatched && !archive_directory(&path, entries)? {
                continue;
            }
            let member_manifest = path.join("Cargo.toml");
            // Cargo's excludes are literal path prefixes. An explicitly named
            // member takes precedence; a match through a glob does not.
            let explicitly_named = members
                .iter()
                .any(|member| member_manifest.starts_with(member));
            let excluded = excludes
                .iter()
                .any(|excluded| member_manifest.starts_with(excluded));
            if excluded && !explicitly_named {
                continue;
            }
            let resolved = resolve_archive_path(&member_manifest, entries)
                .with_context(|| format!("invalid Cargo workspace member in {manifest}"))?;
            ensure!(
                resolved
                    .to_str()
                    .is_some_and(|path| entries.contains_key(path)),
                "Cargo workspace member manifest {} is absent from the snapshot ({manifest}); stage or explicitly include the required files",
                member_manifest.display()
            );
        }
    }
    Ok(())
}

/// Expand Cargo member patterns over captured entries only. Unlike a filesystem
/// glob, this never reads omitted working files or traverses real symlinks.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.expand_workspace_member")
)]
fn expand_workspace_member(
    pattern: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
) -> Result<Vec<PathBuf>> {
    let pattern_text = pattern
        .to_str()
        .context("Cargo member pattern is not UTF-8")?;
    glob::Pattern::new(pattern_text).context("invalid Cargo workspace member glob")?;
    let parts: Vec<_> = archive_path_steps(pattern)?.into_iter().collect();
    let mut matches = BTreeSet::new();
    match_workspace_parts(
        Path::new(""),
        &parts,
        entries,
        &mut BTreeSet::new(),
        &mut matches,
        &mut 100_000,
        256,
    )?;
    Ok(matches.into_iter().collect())
}

fn match_workspace_parts(
    prefix: &Path,
    parts: &[PathBuf],
    entries: &BTreeMap<&str, &SnapshotFile>,
    recursive_ancestors: &mut BTreeSet<PathBuf>,
    matches: &mut BTreeSet<PathBuf>,
    steps_left: &mut usize,
    depth_left: usize,
) -> Result<()> {
    ensure!(
        depth_left > 0,
        "Cargo workspace glob exceeds the nested matching limit"
    );
    ensure!(
        *steps_left > 0,
        "Cargo workspace glob exceeds the capture expansion limit"
    );
    *steps_left -= 1;
    let Some((part, rest)) = parts.split_first() else {
        matches.insert(prefix.to_owned());
        return Ok(());
    };
    if part == Path::new("..") {
        let path = prefix.join(part);
        // Resolve links before '..'; lexical normalization can hide an escape.
        resolve_archive_path(&path, entries)?;
        return match_workspace_parts(
            &path,
            rest,
            entries,
            recursive_ancestors,
            matches,
            steps_left,
            depth_left - 1,
        );
    }
    if part == Path::new("**") {
        let resolved = resolve_archive_path(prefix, entries)?;
        ensure!(
            recursive_ancestors.len() < 64,
            "Cargo workspace glob exceeds 64 recursive directories"
        );
        ensure!(
            recursive_ancestors.insert(resolved.clone()),
            "recursive Cargo workspace glob follows a directory symlink cycle: {}",
            prefix.display()
        );
        // A recursive wildcard consumes zero or more complete directories.
        match_workspace_parts(
            prefix,
            rest,
            entries,
            &mut BTreeSet::new(),
            matches,
            steps_left,
            depth_left - 1,
        )?;
        for child in archive_children(prefix, entries)? {
            if archive_directory(&child, entries)? {
                match_workspace_parts(
                    &child,
                    parts,
                    entries,
                    recursive_ancestors,
                    matches,
                    steps_left,
                    depth_left - 1,
                )?;
            }
        }
        recursive_ancestors.remove(&resolved);
        return Ok(());
    }
    let matcher = glob::Pattern::new(part.to_str().context("Cargo member path is not UTF-8")?)?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    for child in archive_children(prefix, entries)? {
        if matcher.matches_path_with(Path::new(child.file_name().unwrap()), options) {
            match_workspace_parts(
                &child,
                rest,
                entries,
                &mut BTreeSet::new(),
                matches,
                steps_left,
                depth_left - 1,
            )?;
        }
    }
    Ok(())
}

fn archive_directory(path: &Path, entries: &BTreeMap<&str, &SnapshotFile>) -> Result<bool> {
    let resolved = resolve_archive_path(path, entries)?;
    let name = resolved.to_str().context("source path is not UTF-8")?;
    Ok(!entries.contains_key(name) && archive_has_descendants(name, entries))
}

fn archive_has_descendants(name: &str, entries: &BTreeMap<&str, &SnapshotFile>) -> bool {
    let prefix = archive_directory_prefix(name);
    entries
        .range::<str, _>((Included(prefix.as_str()), Unbounded))
        .next()
        .is_some_and(|(path, _)| path.starts_with(&prefix))
}

fn archive_directory_prefix(name: &str) -> String {
    if name.is_empty() {
        String::new()
    } else {
        format!("{name}/")
    }
}

fn archive_children(
    path: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
) -> Result<BTreeSet<PathBuf>> {
    let resolved = resolve_archive_path(path, entries)?;
    let name = resolved.to_str().context("source path is not UTF-8")?;
    let prefix = archive_directory_prefix(name);
    let mut lower = prefix.clone();
    let mut children = BTreeSet::new();
    while let Some((&entry, _)) = entries
        .range::<str, _>((Included(lower.as_str()), Unbounded))
        .next()
    {
        let Some(relative) = entry.strip_prefix(&prefix) else {
            break;
        };
        let (child, directory) = relative
            .split_once('/')
            .map_or((relative, false), |(child, _)| (child, true));
        children.insert(path.join(child));
        lower.clear();
        if directory {
            // '/' immediately precedes '0' in byte order. Seek past this
            // child's entire subtree, without skipping siblings such as a0
            // or allocating a PathBuf for every descendant before deduplication.
            lower.push_str(&prefix);
            lower.push_str(child);
            lower.push('0');
        } else {
            // Archive paths cannot contain NUL; this excludes just this file.
            lower.push_str(entry);
            lower.push('\0');
        }
    }
    Ok(children)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.check_dependency_tables")
)]
fn check_dependency_tables(
    document: &toml::Value,
    base: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    manifest: &str,
) -> Result<()> {
    for key in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "replace",
    ] {
        if let Some(table) = document.get(key).and_then(toml::Value::as_table) {
            for dependency in table.values() {
                if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
                    check_cargo_path(path, base, entries, manifest)?;
                }
            }
        }
    }
    if let Some(registries) = document.get("patch").and_then(toml::Value::as_table) {
        for registry in registries.values().filter_map(toml::Value::as_table) {
            for dependency in registry.values() {
                if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
                    check_cargo_path(path, base, entries, manifest)?;
                }
            }
        }
    }
    Ok(())
}

fn check_cargo_path(
    dependency: &str,
    base: &Path,
    entries: &BTreeMap<&str, &SnapshotFile>,
    manifest: &str,
) -> Result<()> {
    let resolved = resolve_archive_path(&base.join(dependency).join("Cargo.toml"), entries)
        .with_context(|| format!("external Cargo path dependency or path absent from the snapshot in {manifest}: {dependency}; capture a self-contained checkout"))?;
    ensure!(entries.contains_key(resolved.to_str().context("Cargo dependency path is not UTF-8")?),
        "Cargo path dependency in {manifest} is absent from the snapshot: {dependency}; track or explicitly include its required files");
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.copy_hash")
)]
fn copy_hash(reader: &mut impl Read, writer: &mut impl Write) -> Result<(String, u64)> {
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((hex::encode(hash.finalize()), size))
}

fn hash_reader(mut reader: impl Read) -> Result<(String, u64)> {
    copy_hash(&mut reader, &mut io::sink())
}

fn staged_path(data: &Path, path: &str) -> PathBuf {
    // Source names are archive metadata, not local filenames. In particular,
    // README/readme and directory case variants must remain separate on APFS.
    // Create-new writes also fail safely if two identities ever collide.
    data.join(hex::encode(Sha256::digest(path.as_bytes())))
}

struct HashedFile {
    file: File,
    hash: Sha256,
    size: u64,
}

impl Read for HashedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(buffer)?;
        self.hash.update(&buffer[..count]);
        self.size += count as u64;
        Ok(count)
    }
}

impl Write for HashedFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = self.file.write(buffer)?;
        self.hash.update(&buffer[..count]);
        self.size += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "source.write_archive")
)]
fn write_archive(path: &Path, data: &Path, files: &[SnapshotFile]) -> Result<(String, u64)> {
    let destination = HashedFile {
        file: File::create(path)?,
        hash: Sha256::new(),
        size: 0,
    };
    let mut archive = tar::Builder::new(BufWriter::with_capacity(64 * 1024, destination));
    for file in files {
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(file.mode);
        if let Some(target) = &file.link_target {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            archive.append_link(&mut header, &file.path, target)?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(file.size);
            let mut source = HashedFile {
                file: File::open(staged_path(data, &file.path))?,
                hash: Sha256::new(),
                size: 0,
            };
            archive.append_data(&mut header, &file.path, &mut source)?;
            // tar writes all supplied bytes without enforcing the header size.
            // Never publish an archive that differs from the selected receipt.
            ensure!(
                source.size == file.size && hex::encode(source.hash.finalize()) == file.sha256,
                "staged source bytes changed before archiving: {}",
                file.path
            );
        }
    }
    archive.finish()?;
    // Finish includes the TAR terminators. Flush before both the digest and
    // fsync so buffered bytes cannot be omitted from the receipt or publication.
    let destination = archive
        .into_inner()?
        .into_inner()
        .map_err(|e| e.into_error())?;
    destination.file.sync_all()?;
    Ok((hex::encode(destination.hash.finalize()), destination.size))
}

struct GitObjects {
    child: Child,
    input: Option<BufWriter<ChildStdin>>,
    output: BufReader<ChildStdout>,
}

impl GitObjects {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "source.git_objects.start")
    )]
    fn start(root: &Path) -> Result<Self> {
        let mut child = git_command(root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().context("Git object input is missing")?;
        let output = child
            .stdout
            .take()
            .context("Git object output is missing")?;
        Ok(Self {
            child,
            // Coalesce the object ID and newline into one request write; each
            // request is still flushed before reading its framed response.
            input: Some(BufWriter::new(input)),
            output: BufReader::new(output),
        })
    }

    fn copy_blob(&mut self, object: &str, writer: &mut impl Write) -> Result<(String, u64)> {
        ensure!(
            object.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid Git object ID"
        );
        let input = self.input.as_mut().context("Git object reader is closed")?;
        writeln!(input, "{object}")?;
        input.flush()?;
        let mut header = String::new();
        self.output.read_line(&mut header)?;
        let parts: Vec<_> = header.split_whitespace().collect();
        ensure!(
            parts.len() == 3 && parts[0] == object && parts[1] == "blob",
            "Git source object is missing or is not a blob: {object}"
        );
        let size: u64 = parts[2].parse()?;
        let result = copy_hash(&mut self.output.by_ref().take(size), writer)?;
        ensure!(
            result.1 == size,
            "Git source object was truncated: {object}"
        );
        let mut end = [0];
        self.output.read_exact(&mut end)?;
        ensure!(end == *b"\n", "invalid Git object delimiter");
        Ok(result)
    }

    fn finish(mut self) -> Result<()> {
        self.input.take();
        ensure!(
            self.child.wait()?.success(),
            "Git source object reader failed"
        );
        Ok(())
    }
}

impl Drop for GitObjects {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_capture_keeps_lexically_adjacent_children_and_component_boundaries() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("checkout");
        fs::create_dir(&root).unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "Source Test"],
            vec!["config", "user.email", "source@example.invalid"],
        ] {
            git_text(&root, &args).unwrap();
        }
        let names = ["a!", "a.", "a", "a0", "a00", "é"];
        for name in names {
            let directory = root.join(format!("members/{name}/core/src"));
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("lib.rs"), b"").unwrap();
            fs::write(
                directory.parent().unwrap().join("Cargo.toml"),
                b"[package]\nname = 'fixture'\nversion = '0.1.0'\n",
            )
            .unwrap();
        }
        fs::write(root.join("members/a.txt"), b"not a directory").unwrap();
        fs::create_dir_all(root.join("members-other/bad/core")).unwrap();
        fs::write(root.join("members-other/bad/core/README"), b"decoy").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            b"[workspace]\nmembers = ['members/*/core']\n",
        )
        .unwrap();
        git_text(&root, &["add", "."]).unwrap();
        git_text(
            &root,
            &["-c", "commit.gpgSign=false", "commit", "-qm", "fixture"],
        )
        .unwrap();
        let options = |name: &str, revision| CaptureOptions {
            source: root.clone(),
            output: temporary.path().join(name),
            revision,
            include: Vec::new(),
        };
        let worktree = options("worktree", None);
        capture(&worktree).unwrap();
        let revision = options("revision", Some("HEAD".to_owned()));
        capture(&revision).unwrap();
        assert_eq!(
            fs::read(worktree.output.join("source.tar")).unwrap(),
            fs::read(revision.output.join("source.tar")).unwrap()
        );
        // Each child must actually be visited, not merely preserved in the tar.
        // Deleting only its manifest leaves a captured directory that must fail.
        for (index, name) in names.into_iter().enumerate() {
            let manifest = root.join(format!("members/{name}/core/Cargo.toml"));
            let bytes = fs::read(&manifest).unwrap();
            fs::remove_file(&manifest).unwrap();
            let options = options(&format!("missing-{index}"), None);
            let error = format!("{:#}", capture(&options).unwrap_err());
            assert!(error.contains("workspace member manifest"), "{error}");
            assert!(
                error.contains(&format!("members/{name}/core/Cargo.toml")),
                "{error}"
            );
            assert!(!options.output.exists());
            fs::write(manifest, bytes).unwrap();
        }
    }

    #[test]
    fn capture_lock_releases_on_success_and_error_with_an_inherited_descriptor() {
        for fail in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("lock");
            let mut inherited = None;
            let result = (|| -> Result<()> {
                let file = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&path)?;
                file.try_lock_exclusive()?;
                let owner = CaptureLock(file);
                // A duplicate has the same ownership as a descriptor inherited
                // by a child between fork and exec in another thread.
                inherited = Some(owner.0.try_clone()?);
                if fail {
                    bail!("simulated capture interruption");
                }
                Ok(())
            })();
            assert_eq!(result.is_err(), fail);
            let next = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            next.try_lock_exclusive()
                .expect("capture must release ownership before its caller can retry");
            FileExt::unlock(&next).unwrap();
            drop(inherited);
        }
    }
}
