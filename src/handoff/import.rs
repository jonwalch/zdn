//! Strict offline decoding and atomic local publication of deployment handoffs.
use super::{Manifest, MANIFEST_NAME, MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES};
use crate::{
    aws, devnet, foundation,
    state::{Binding, BindingContext, StateStore},
};
use eyre::{ensure, Context, ContextCompat, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};
use uuid::Uuid;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.import")
)]
pub fn import(
    store: &StateStore,
    context: &BindingContext,
    expected_network_id: Uuid,
    profile: &aws::LocalProfile,
    archive_path: &Path,
    sha256: &str,
) -> Result<Binding> {
    devnet::validate_hash(sha256)?;
    profile.validate()?;
    ensure!(
        profile.team.scope() == context.scope,
        "receiving profile scope differs from context"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    }
    let mut file = options.open(archive_path).context("open handoff archive")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_ARCHIVE_BYTES,
        "handoff archive must be a bounded regular file"
    );
    // Hash the bytes we privately snapshot, not a caller-owned file that could
    // be modified in place between hashing and parsing the same descriptor.
    let mut snapshot = tempfile::NamedTempFile::new_in(store.root())?;
    let mut hasher = Sha256::new();
    let mut source = (&mut file).take(MAX_ARCHIVE_BYTES + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        count += size as u64;
        ensure!(
            count <= MAX_ARCHIVE_BYTES,
            "handoff archive exceeds size limit"
        );
        hasher.update(&buffer[..size]);
        snapshot.write_all(&buffer[..size])?;
    }
    ensure!(
        count <= MAX_ARCHIVE_BYTES && hex::encode(hasher.finalize()) == sha256,
        "handoff archive SHA-256 mismatch"
    );
    snapshot.seek(SeekFrom::Start(0))?;
    let staging = tempfile::Builder::new()
        .prefix(".handoff-")
        .tempdir_in(store.root())?;
    let directory = staging
        .path()
        .join("foundation")
        .join(expected_network_id.to_string());
    foundation::private_directory(&staging.path().join("foundation"))?;
    foundation::private_directory(&directory)?;
    let mut archive = tar::Archive::new(snapshot.take(MAX_ARCHIVE_BYTES + 1));
    archive.set_ignore_zeros(true);
    // raw entries expose (and thus reject) GNU/PAX extensions instead of letting
    // the tar reader silently rewrite names or entry metadata for us.
    let mut entries = archive.entries()?.raw(true);
    let mut first = entries.next().context("handoff archive is empty")??;
    ensure!(
        first.header().entry_type() == tar::EntryType::Regular
            && first.path_bytes().as_ref() == MANIFEST_NAME.as_bytes(),
        "handoff manifest must be the first regular file"
    );
    ensure!(
        first.size() <= MAX_MANIFEST_BYTES,
        "handoff manifest exceeds size limit"
    );
    let mut bytes = Vec::new();
    first.read_to_end(&mut bytes)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).context("decode handoff manifest")?;
    manifest.validate()?;
    ensure!(
        manifest.binding.network_id == expected_network_id,
        "handoff network ID differs from explicitly selected ID"
    );
    ensure!(
        manifest.binding.scope == context.scope && manifest.deployment.team == profile.team,
        "handoff team definition or scope differs from receiving profile"
    );
    ensure!(manifest.deployment.spec.aws_profile == profile.aws_profile,
        "receiving AWS profile name must match the saved deployment; immutable recovery proofs cannot be rewritten");
    let mut seen = BTreeSet::new();
    for entry in entries {
        let mut entry = entry?;
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "handoff permits only regular files"
        );
        let raw = entry.path_bytes();
        let name = std::str::from_utf8(&raw)?.to_owned();
        let path = Path::new(&name);
        ensure!(
            !name.is_empty()
                && !name.contains('\\')
                && path.components().all(|c| matches!(c, Component::Normal(_)))
                && path
                    .components()
                    .map(|c| c.as_os_str().to_str().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("/")
                    == name,
            "noncanonical handoff payload path"
        );
        ensure!(seen.insert(name.clone()), "duplicate handoff payload");
        let artifact = manifest
            .files
            .get(&name)
            .context("undeclared handoff payload")?;
        ensure!(
            entry.size() == artifact.bytes && entry.size() <= manifest.file_limit(&name)?,
            "handoff payload size mismatch"
        );
        let target = directory.join(path);
        if let Some(parent) = target.parent() {
            let mut current = directory.clone();
            for component in parent.strip_prefix(&directory)?.components() {
                current.push(component);
                foundation::private_directory(&current)?;
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&target)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = entry.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            ensure!(
                size <= artifact.bytes,
                "handoff payload exceeds declared size"
            );
            hash.update(&buffer[..n]);
            output.write_all(&buffer[..n])?;
        }
        ensure!(
            size == artifact.bytes && hex::encode(hash.finalize()) == artifact.sha256,
            "handoff payload integrity mismatch"
        );
        output.sync_all()?;
    }
    ensure!(
        seen.len() == manifest.files.len(),
        "handoff archive is missing declared payloads"
    );
    manifest.verify_directory(&directory)?;
    // Preserve the spec and its proof hashes, including local profile selection.
    foundation::write_json(&directory.join("deployment.json"), &manifest.deployment)?;
    super::sync_directories(&directory)?;
    store.import_handoff(
        context,
        expected_network_id,
        &manifest.binding,
        &manifest.operations,
        staging.path(),
    )
}
