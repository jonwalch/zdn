//! Private, offline deployment snapshots. Publication never replaces a path.
use super::{Manifest, API_VERSION, MANIFEST_NAME, MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES};
use crate::{
    devnet::{self, Artifact},
    foundation::{self, DeploymentFile},
    state::{Binding, StateStore},
};
use eyre::{ensure, Context, ContextCompat, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.export")
)]
pub fn export(store: &StateStore, binding: &Binding, output: &Path) -> Result<String> {
    // Inspect before opening the writer: open would create a missing directory.
    DeploymentFile::read_snapshot(store.root(), binding.network_id)?;
    let deployment_file = DeploymentFile::open(store.root(), binding.network_id)?;
    let deployment = deployment_file.load()?;
    let mut manifest = Manifest {
        api_version: API_VERSION.into(),
        binding: binding.to_export(),
        deployment,
        operations: store.handoff_operations(binding)?,
        updates: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    ensure!(
        manifest.deployment.spec.network_id == binding.network_id
            && manifest.deployment.spec.scope == binding.context.scope,
        "handoff deployment identity differs from its binding"
    );
    // Keep an existing build attempt locked until the handoff is published.
    let _build_lock = if let Some(request) = &manifest.deployment.cluster {
        crate::build_job::validate_handoff(
            &deployment_file.directory().join("build"),
            &manifest.deployment.team,
            request,
        )?
    } else {
        let preparation =
            crate::build::preparation::Preparation::read(deployment_file.directory())?;
        preparation.verify(deployment_file.directory(), &manifest.deployment)?;
        Some(crate::build_job::lock_preparation(
            &deployment_file.directory().join("build"),
            &manifest.deployment.team,
            &preparation.contract,
        )?)
    };
    let updates_directory = deployment_file.directory().join("updates");
    let mut update_build_locks = Vec::new();
    if updates_directory.try_exists()? {
        ensure!(
            fs::symlink_metadata(&updates_directory)?.is_dir(),
            "updates must be a real directory"
        );
        for entry in fs::read_dir(&updates_directory)? {
            let entry = entry?;
            ensure!(
                fs::symlink_metadata(entry.path())?.is_dir(),
                "update must be a real directory"
            );
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| eyre::eyre!("invalid update path"))?;
            let id = uuid::Uuid::parse_str(&name)?;
            ensure!(id.to_string() == name, "noncanonical update UUID");
            let completed = entry.path().join("completed.json");
            let latest = manifest
                .deployment
                .runtime
                .as_ref()
                .and_then(|r| r.update.as_ref())
                .filter(|u| u.id == id);
            let intent = if let Some(pending) = latest.filter(|u| !u.finished) {
                pending.clone()
            } else if completed.try_exists()? {
                serde_json::from_slice(&devnet::read_bounded(&completed, MAX_MANIFEST_BYTES)?)?
            } else {
                latest
                    .cloned()
                    .context("missing historical completed or current update metadata")?
            };
            let revision = intent
                .revision
                .as_ref()
                .context("missing update candidate revision")?;
            let mut request = manifest
                .deployment
                .cluster
                .as_ref()
                .context("missing node request")?
                .clone();
            request.image = revision.image.clone();
            request.build = revision.build.clone();
            request.artifacts = revision.artifacts.clone();
            update_build_locks.push(crate::build_job::validate_handoff(
                &entry.path().join("build"),
                &manifest.deployment.team,
                &request,
            )?);
            ensure!(intent.id == id, "update directory identity mismatch");
            manifest.updates.insert(id, intent);
        }
    }
    if let Some(latest) = manifest
        .deployment
        .runtime
        .as_ref()
        .and_then(|r| r.update.as_ref())
    {
        ensure!(
            manifest.updates.contains_key(&latest.id),
            "latest update directory missing"
        );
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        !fs::canonicalize(parent)?.starts_with(fs::canonicalize(deployment_file.directory())?),
        "handoff output must be outside the deployment directory"
    );
    ensure!(
        fs::symlink_metadata(output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "handoff output already exists or cannot be inspected"
    );
    let staging = tempfile::tempdir()?;
    let mut total = 0u64;
    inventory(
        &mut manifest,
        deployment_file.directory(),
        staging.path(),
        "",
        &mut total,
    )?;
    for (id, intent) in manifest
        .updates
        .iter()
        .filter(|(_, intent)| intent.finished)
    {
        let path = format!("updates/{id}/completed.json");
        if !manifest.files.contains_key(&path) {
            let bytes = serde_json::to_vec(intent)?;
            ensure!(
                bytes.len() as u64 <= MAX_MANIFEST_BYTES,
                "completed update metadata exceeds bound"
            );
            total = total
                .checked_add(bytes.len() as u64)
                .context("handoff size overflow")?;
            ensure!(
                total <= MAX_ARCHIVE_BYTES && manifest.files.len() < 1024,
                "handoff inventory exceeds its bound"
            );
            foundation::write_private(&staging.path().join(&path), &bytes)?;
            manifest.files.insert(
                path,
                Artifact {
                    sha256: devnet::sha256(&bytes),
                    bytes: bytes.len() as u64,
                },
            );
        }
    }
    super::sync_directories(staging.path())?;
    // This checks both the copied bytes and their semantic recovery contracts,
    // including the staged artifact hashes saved in the deployment request.
    manifest.verify_directory(staging.path())?;
    let metadata = serde_json::to_vec(&manifest)?;
    ensure!(
        metadata.len() as u64 <= MAX_MANIFEST_BYTES,
        "handoff manifest exceeds its bound"
    );
    let archive_size = manifest
        .files
        .values()
        .map(|file| 512 + file.bytes.div_ceil(512) * 512)
        .sum::<u64>()
        + 512
        + (metadata.len() as u64).div_ceil(512) * 512
        + 1024;
    ensure!(
        archive_size <= MAX_ARCHIVE_BYTES,
        "handoff archive exceeds its bound"
    );
    let mut archive = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut tar = tar::Builder::new(archive.as_file_mut());
        append(
            &mut tar,
            MANIFEST_NAME,
            metadata.len() as u64,
            &metadata[..],
        )?;
        for (path, artifact) in &manifest.files {
            append(
                &mut tar,
                path,
                artifact.bytes,
                File::open(staging.path().join(path))?,
            )?;
        }
        tar.finish()?;
    }
    ensure!(
        archive.as_file().metadata()?.len() <= MAX_ARCHIVE_BYTES,
        "handoff archive exceeds its bound"
    );
    archive.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = archive.as_file_mut().read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        archive
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    archive.as_file().sync_all()?;
    archive
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    // deployment_file (and its writer lock) lives through publication and fsync.
    Ok(hex::encode(hash.finalize()))
}

fn append<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    size: u64,
    reader: impl Read,
) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, path, reader)?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.export.inventory")
)]
fn inventory(
    manifest: &mut Manifest,
    source: &Path,
    staging: &Path,
    prefix: &str,
    total: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(source.join(prefix))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eyre::eyre!("non-UTF8 handoff path"))?;
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = fs::symlink_metadata(entry.path())?.file_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "handoff refuses symlinks and special files: {path}"
        );
        let initial = manifest.deployment.cluster.is_none();
        if initial
            && prefix.is_empty()
            && matches!(
                name.as_str(),
                "build" | "source-snapshot" | "source-preparation"
            )
        {
            ensure!(
                kind.is_dir(),
                "source preparation workspace must be a directory"
            );
            foundation::private_directory(&staging.join(&path))?;
            inventory(manifest, source, staging, &path, total)?;
            continue;
        }
        // Only the durable attempt and its pinned exporter are portable.
        // Downloads, unverified outputs and abandoned tempfile bytes must never
        // become recovery authority; verification binds the exporter to the receipt.
        if initial && prefix == "build" && !matches!(name.as_str(), "attempt.json" | "exporter") {
            ensure!(
                kind.is_file(),
                "excluded build metadata must be a regular file"
            );
            continue;
        }
        if prefix.is_empty() {
            if matches!(
                name.as_str(),
                "credentials"
                    | "project"
                    | "diagnostics"
                    | "build"
                    | "source-snapshot"
                    | "source-preparation"
            ) {
                ensure!(kind.is_dir(), "excluded workspace must be a directory");
                continue;
            }
            if name == "updates" {
                ensure!(kind.is_dir(), "updates must be a directory");
                foundation::private_directory(&staging.join(&path))?;
                inventory(manifest, source, staging, &path, total)?;
                continue;
            }
            if (!initial
                && matches!(
                    name.as_str(),
                    "source-build-inputs.json" | "source-preparation.json"
                ))
                || matches!(
                    name.as_str(),
                    "deployment.json"
                        | ".zdn-pulumi-process.json"
                        | "operation.lock"
                        | ".zdn-source-capture.lock"
                )
                || name.ends_with(".json.lock")
            {
                ensure!(kind.is_file(), "excluded metadata must be a regular file");
                continue;
            }
            if name == "artifacts" {
                ensure!(kind.is_dir(), "artifacts must be a directory");
                foundation::private_directory(&staging.join("artifacts"))?;
                inventory(manifest, source, staging, "artifacts", total)?;
                continue;
            }
        }
        if prefix == "updates" {
            let id = uuid::Uuid::parse_str(&name)?;
            ensure!(
                id.to_string() == name && manifest.updates.contains_key(&id) && kind.is_dir(),
                "unknown update directory"
            );
            foundation::private_directory(&staging.join(&path))?;
            inventory(manifest, source, staging, &path, total)?;
            continue;
        }
        if prefix.starts_with("updates/") && prefix.split('/').count() == 2 {
            if matches!(name.as_str(), "build" | "source-snapshot") {
                ensure!(
                    kind.is_dir(),
                    "excluded update workspace must be a directory"
                );
                let id = uuid::Uuid::parse_str(prefix.strip_prefix("updates/").unwrap())?;
                if name == "build" && manifest.updates[&id].build_exporter_protocol.is_some() {
                    foundation::private_directory(&staging.join(&path))?;
                    inventory(manifest, source, staging, &path, total)?;
                }
                continue;
            }
            if matches!(name.as_str(), "source-config.json" | "build-contract.json")
                || name.ends_with("-command.json.lock")
            {
                ensure!(kind.is_file(), "excluded update metadata must be a file");
                continue;
            }
            if name == "artifacts" {
                ensure!(kind.is_dir(), "update artifacts must be a directory");
                foundation::private_directory(&staging.join(&path))?;
                inventory(manifest, source, staging, &path, total)?;
                continue;
            }
        }
        if prefix.starts_with("updates/")
            && prefix.ends_with("/build")
            && !matches!(
                name.as_str(),
                "attempt.json"
                    | "result.json"
                    | "image.json"
                    | "image-manifest.json"
                    | "image-config.json"
            )
        {
            ensure!(
                kind.is_file(),
                "excluded update build metadata must be a file"
            );
            continue;
        }
        ensure!(kind.is_file(), "unsupported handoff directory: {path}");
        let limit = manifest.file_limit(&path)?;
        let artifact = devnet::snapshot_file(&entry.path(), &staging.join(&path), limit)
            .with_context(|| format!("read handoff file {path}"))?;
        *total = total
            .checked_add(artifact.bytes)
            .context("handoff size overflow")?;
        ensure!(
            *total <= MAX_ARCHIVE_BYTES && manifest.files.len() < 1024,
            "handoff inventory exceeds its bound"
        );
        manifest.files.insert(path, artifact);
    }
    Ok(())
}
