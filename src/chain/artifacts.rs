//! Bounded, offline byte-integrity checks for declared chain artifacts.
//!
//! A bundle is one canonical TAR file. It contains normalized manifest metadata,
//! followed by the declared raw genesis and seed blocks. Only the named source
//! files are read; unrelated files in the source directory are ignored. Block
//! decoding, block hashes, ancestry, checkpoints, and consensus are not verified.

use super::manifest::{BlockIdentity, ConsensusManifest};
use eyre::{ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

pub const BUNDLE_API_VERSION: &str = "zdn-chain-bundle/v1alpha1";
pub const REPORT_API_VERSION: &str = "zdn-chain-artifact-check/v1alpha1";
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOCK_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BLOCK_COUNT: usize = 4096;
const TAR_BLOCK: usize = 512;
const ZERO_BLOCK: [u8; TAR_BLOCK] = [0; TAR_BLOCK];

/// A result of this invocation, never a trusted input or launch qualification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReport {
    pub api_version: String,
    pub consensus_fingerprint: String,
    pub bundle_sha256: String,
    pub bundle_bytes: u64,
    pub block_count: usize,
    pub block_bytes: u64,
    pub byte_integrity_verified: bool,
    pub block_decoding_verified: bool,
    pub consensus_verified: bool,
    pub qualification: String,
    pub launch_ready: bool,
}

/// Verified bytes captured from the same stream that produced the integrity
/// report. A later change to the source file cannot change this snapshot.
/// Identity fields remain declarations until the node decodes the block.
#[derive(Debug)]
pub struct VerifiedBlock {
    pub identity: BlockIdentity,
    pub bytes: Vec<u8>,
}

/// A bounded in-memory snapshot: at most 4096 blocks and 128 MiB of raw bytes.
#[derive(Debug)]
pub struct VerifiedBundle {
    pub report: ArtifactReport,
    pub blocks: Vec<VerifiedBlock>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleMetadata<'a> {
    api_version: &'static str,
    consensus_fingerprint: &'a str,
    manifest: &'a ConsensusManifest,
}

struct Prepared {
    manifest: ConsensusManifest,
    fingerprint: String,
    metadata: Vec<u8>,
    block_count: usize,
    block_bytes: u64,
    bundle_bytes: u64,
}

impl Prepared {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.artifacts.prepare")
    )]
    fn new(manifest: &ConsensusManifest) -> Result<Self> {
        // Bound both the supplied representation and its resolved defaults before
        // creating any output. This also bounds metadata allocation below.
        check_manifest_size(manifest)?;
        ensure!(
            manifest.seed_blocks.len() < MAX_BLOCK_COUNT,
            "chain artifact block count exceeds {MAX_BLOCK_COUNT}"
        );
        let manifest = manifest.normalized()?;
        check_manifest_size(&manifest)?;
        let fingerprint = manifest.fingerprint()?;
        let metadata = serde_json::to_vec(&BundleMetadata {
            api_version: BUNDLE_API_VERSION,
            consensus_fingerprint: &fingerprint,
            manifest: &manifest,
        })?;
        let mut prepared = Self {
            block_count: 1 + manifest.seed_blocks.len(),
            block_bytes: 0,
            bundle_bytes: entry_bytes(metadata.len() as u64) + 2 * TAR_BLOCK as u64,
            manifest,
            fingerprint,
            metadata,
        };
        // Normalization bounds every block to 2 MiB and the count above is
        // bounded, so these sums cannot overflow u64.
        prepared.block_bytes = prepared.blocks().map(|block| block.bytes_length).sum();
        ensure!(
            prepared.block_bytes <= MAX_BLOCK_BYTES,
            "chain artifact raw block bytes exceed 128 MiB"
        );
        prepared.bundle_bytes += prepared
            .blocks()
            .map(|block| entry_bytes(block.bytes_length))
            .sum::<u64>();
        ensure!(
            prepared.bundle_bytes <= MAX_BUNDLE_BYTES,
            "chain artifact bundle exceeds 256 MiB"
        );
        Ok(prepared)
    }

    fn blocks(&self) -> impl Iterator<Item = &BlockIdentity> {
        std::iter::once(&self.manifest.genesis).chain(self.manifest.seed_blocks.iter())
    }
}

/// The direct source filename for a declared block height. Files contain raw
/// bytes, not hexadecimal text. The canonical TAR adds the `blocks/` prefix.
pub fn block_file_name(height: u32) -> String {
    format!("{height:010}.bin")
}

/// Copy and verify all declared bytes, then atomically publish a new bundle.
/// The destination is never overwritten, including when it is a dangling link.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.artifacts.import_bundle")
)]
pub fn import_bundle(
    manifest: &ConsensusManifest,
    blocks_dir: &Path,
    output: &Path,
) -> Result<ArtifactReport> {
    let prepared = Prepared::new(manifest)?;
    let directory = BlockDirectory::open(blocks_dir)?;
    // The atomic no-clobber operation below also protects against a destination
    // created after this early, inexpensive check.
    match fs::symlink_metadata(output) {
        Ok(_) => eyre::bail!("chain artifact bundle destination already exists"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect chain artifact destination"),
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).context("create pending chain artifact bundle")?;
    write_header(&mut staged, "bundle.json", prepared.metadata.len() as u64)?;
    staged.write_all(&prepared.metadata)?;
    write_padding(&mut staged, prepared.metadata.len() as u64)?;
    for block in prepared.blocks() {
        let name = block_file_name(block.height);
        let mut source = directory.open_block(&name)?;
        let before = file_state(&source)?;
        ensure!(
            before.length == block.bytes_length,
            "raw block {name} has a different size than its manifest"
        );
        write_header(&mut staged, &format!("blocks/{name}"), block.bytes_length)?;
        copy_block(&mut source, &mut staged, block)
            .with_context(|| format!("verify raw block {name}"))?;
        ensure!(
            before == file_state(&source)?,
            "raw block {name} changed during import"
        );
        write_padding(&mut staged, block.bytes_length)?;
    }
    staged.write_all(&ZERO_BLOCK)?;
    staged.write_all(&ZERO_BLOCK)?;
    staged.as_file_mut().seek(SeekFrom::Start(0))?;
    // Re-read what will be published. A successful source read alone cannot
    // attest the archive that the caller will subsequently use.
    let report = verify_file(&prepared, staged.as_file_mut(), None)?;
    staged.as_file().sync_all()?;
    let published = staged
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .context("publish chain artifact bundle without replacing a destination")?;
    published.sync_all()?;
    File::open(parent)?
        .sync_all()
        .context("bundle was published but its parent directory could not be synced")?;
    Ok(report)
}

/// Re-read a bundle against the caller's expected manifest. Metadata and every
/// canonical TAR byte are checked; saved reports or qualification flags are not
/// accepted as evidence. This does not decode or validate any Zcash block.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.artifacts.verify_bundle")
)]
pub fn verify_bundle(manifest: &ConsensusManifest, bundle: &Path) -> Result<ArtifactReport> {
    let prepared = Prepared::new(manifest)?;
    let mut file = open_regular(bundle).context("open chain artifact bundle")?;
    verify_file(&prepared, &mut file, None)
}

/// Verify the complete canonical bundle and retain its exact verified payloads.
/// This is one file open and one read pass, not verify-then-reopen. No blocks are
/// returned if metadata, payloads, padding, file identity, or size checks fail.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.artifacts.snapshot_bundle")
)]
pub fn snapshot_bundle(manifest: &ConsensusManifest, bundle: &Path) -> Result<VerifiedBundle> {
    let prepared = Prepared::new(manifest)?;
    let mut file = open_regular(bundle).context("open chain artifact bundle")?;
    let mut blocks = Vec::with_capacity(prepared.block_count);
    let report = verify_file(&prepared, &mut file, Some(&mut blocks))?;
    Ok(VerifiedBundle { report, blocks })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.artifacts.verify_file")
)]
fn verify_file(
    prepared: &Prepared,
    file: &mut File,
    mut captured: Option<&mut Vec<VerifiedBlock>>,
) -> Result<ArtifactReport> {
    let before = file_state(file)?;
    ensure!(
        before.length <= MAX_BUNDLE_BYTES && before.length == prepared.bundle_bytes,
        "chain artifact bundle has an unexpected size"
    );
    let mut reader = HashReader {
        inner: file,
        hash: Sha256::new(),
        bytes: 0,
    };
    read_header(&mut reader, "bundle.json", prepared.metadata.len() as u64)?;
    let mut metadata = vec![0; prepared.metadata.len()];
    reader.read_exact(&mut metadata)?;
    ensure!(
        metadata == prepared.metadata,
        "chain artifact bundle metadata differs from the expected normalized manifest"
    );
    read_padding(&mut reader, metadata.len() as u64)?;
    for block in prepared.blocks() {
        let name = format!("blocks/{}", block_file_name(block.height));
        read_header(&mut reader, &name, block.bytes_length)?;
        // The archive has other entries after this block, so limit the reader
        // precisely to this payload. The declared digest binds its exact bytes.
        let mut payload = (&mut reader).take(block.bytes_length);
        if let Some(blocks) = captured.as_mut() {
            let mut bytes = Vec::with_capacity(block.bytes_length as usize);
            copy_block(&mut payload, &mut bytes, block)
                .with_context(|| format!("verify bundled block {name}"))?;
            blocks.push(VerifiedBlock {
                identity: block.clone(),
                bytes,
            });
        } else {
            copy_block(&mut payload, &mut io::sink(), block)
                .with_context(|| format!("verify bundled block {name}"))?;
        }
        read_padding(&mut reader, block.bytes_length)?;
    }
    let mut end = [0; 2 * TAR_BLOCK];
    reader.read_exact(&mut end)?;
    ensure!(
        end == [0; 2 * TAR_BLOCK],
        "invalid chain artifact TAR end marker"
    );
    let mut trailing = [0];
    ensure!(
        reader.read(&mut trailing)? == 0,
        "unexpected trailing chain artifact bundle bytes"
    );
    ensure!(
        reader.bytes == prepared.bundle_bytes,
        "chain artifact bundle length changed during verification"
    );
    ensure!(
        before == file_state(reader.inner)?,
        "chain artifact bundle changed during verification"
    );
    Ok(ArtifactReport {
        api_version: REPORT_API_VERSION.into(),
        consensus_fingerprint: prepared.fingerprint.clone(),
        bundle_sha256: hex::encode(reader.hash.finalize()),
        bundle_bytes: reader.bytes,
        block_count: prepared.block_count,
        block_bytes: prepared.block_bytes,
        byte_integrity_verified: true,
        block_decoding_verified: false,
        consensus_verified: false,
        qualification: "pending".into(),
        launch_ready: false,
    })
}

fn header(path: &str, bytes: u64) -> Result<tar::Header> {
    let mut header = tar::Header::new_ustar();
    header.set_path(path)?;
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(bytes);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    Ok(header)
}

fn write_header(writer: &mut impl Write, path: &str, bytes: u64) -> Result<()> {
    writer.write_all(header(path, bytes)?.as_bytes())?;
    Ok(())
}

fn read_header(reader: &mut impl Read, path: &str, bytes: u64) -> Result<()> {
    let mut actual = [0; TAR_BLOCK];
    reader.read_exact(&mut actual)?;
    ensure!(
        &actual == header(path, bytes)?.as_bytes(),
        "unexpected or noncanonical chain artifact TAR header for {path}"
    );
    Ok(())
}

fn padding(bytes: u64) -> usize {
    ((TAR_BLOCK as u64 - bytes % TAR_BLOCK as u64) % TAR_BLOCK as u64) as usize
}

fn entry_bytes(bytes: u64) -> u64 {
    TAR_BLOCK as u64 + bytes + padding(bytes) as u64
}

fn write_padding(writer: &mut impl Write, bytes: u64) -> Result<()> {
    writer.write_all(&ZERO_BLOCK[..padding(bytes)])?;
    Ok(())
}

fn read_padding(reader: &mut impl Read, bytes: u64) -> Result<()> {
    let mut actual = [0; TAR_BLOCK];
    let count = padding(bytes);
    reader.read_exact(&mut actual[..count])?;
    ensure!(actual == ZERO_BLOCK, "nonzero chain artifact TAR padding");
    Ok(())
}

fn copy_block(
    reader: &mut impl Read,
    writer: &mut impl Write,
    block: &BlockIdentity,
) -> Result<()> {
    let mut limited = reader.take(block.bytes_length + 1);
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(
            bytes <= block.bytes_length,
            "raw block exceeds its declared size"
        );
        hash.update(&buffer[..count]);
        writer.write_all(&buffer[..count])?;
    }
    ensure!(
        bytes == block.bytes_length,
        "raw block is shorter than its declared size"
    );
    ensure!(
        hex::encode(hash.finalize()) == block.bytes_sha256,
        "raw block SHA-256 differs from its manifest"
    );
    Ok(())
}

struct HashReader<R> {
    inner: R,
    hash: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.hash.update(&buffer[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}

fn check_manifest_size(manifest: &ConsensusManifest) -> Result<()> {
    struct SizeLimit(u64);
    impl Write for SizeLimit {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 += bytes.len() as u64;
            if self.0 > MAX_MANIFEST_BYTES {
                return Err(io::Error::other("chain manifest exceeds 2 MiB"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(SizeLimit(0), manifest).context("bound chain artifact manifest")?;
    Ok(())
}

/// Open before checking metadata, without ever waiting for a FIFO writer. The
/// no-follow flag closes the leaf-symlink race between inspection and opening.
fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "expected a regular artifact file"
    );
    let file = options.open(path)?;
    file_state(&file)?;
    Ok(file)
}

struct BlockDirectory {
    #[cfg(unix)]
    directory: File,
    #[cfg(not(unix))]
    path: std::path::PathBuf,
}

impl BlockDirectory {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.artifacts.open_directory")
    )]
    fn open(path: &Path) -> Result<Self> {
        // A trailing slash or `/.` must not turn a leaf symlink into an ancestor
        // that O_NOFOLLOW would permit. Components retain `..` and therefore do
        // not change the meaning of paths through real directory ancestors.
        let path: std::path::PathBuf = path.components().collect();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(
                    nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_DIRECTORY,
                )
                .open(&path)
                .context("open raw block directory")?;
            ensure!(
                directory.metadata()?.is_dir(),
                "expected a raw block directory"
            );
            Ok(Self { directory })
        }
        #[cfg(not(unix))]
        {
            ensure!(
                fs::symlink_metadata(&path)?.file_type().is_dir(),
                "expected a real raw block directory"
            );
            Ok(Self { path })
        }
    }

    fn open_block(&self, name: &str) -> Result<File> {
        #[cfg(unix)]
        {
            use nix::fcntl::{openat, OFlag};
            use nix::sys::stat::Mode;
            let opened = openat(
                &self.directory,
                name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("open raw block {name}"))?;
            let file = File::from(opened);
            file_state(&file)?;
            Ok(file)
        }
        #[cfg(not(unix))]
        open_regular(&self.path.join(name))
    }
}

#[derive(PartialEq, Eq)]
struct FileState {
    length: u64,
    modified: SystemTime,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, i64, i64),
}

fn file_state(file: &File) -> Result<FileState> {
    let metadata: Metadata = file.metadata()?;
    ensure!(metadata.is_file(), "expected a regular chain artifact file");
    Ok(FileState {
        length: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        unix: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    })
}
