//! Read-only native equivalent of `runner.py`'s verify_inputs/verify_artifact.
//!
//! This binds trusted local artifact bytes to a validated install spec and
//! re-renders its exact runtime configuration in process. It neither fetches
//! artifacts nor executes the helper, inspects Docker, touches a volume or
//! establishes readiness. Bundle pins are checked here; canonical TAR/block
//! verification still belongs to the chain bootstrap, as in the old runtime.

use eyre::{ensure, Result};

use super::{files::Directory, HostInstallSpec, S3Object};
use crate::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RenderedRuntimeConfig},
    },
    image::{self, ImageRecord},
};

/// `artifacts` must be reached through trusted directory traversal (root-owned
/// on a host). The result is configuration data, not saved launch authority.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.inputs.verify")
)]
pub fn verify(spec: &HostInstallSpec, artifacts: &Directory) -> Result<RenderedRuntimeConfig> {
    spec.validate()?;
    let manifest: ConsensusManifest = serde_json::from_slice(&read_pinned(
        artifacts,
        "manifest.json",
        &spec.manifest,
        2 * 1024 * 1024,
    )?)?;
    for (name, object) in [("chain.tar", &spec.bundle), ("zdn", &spec.helper)] {
        let observed = artifacts.digest(name, object.bytes)?;
        ensure!(
            observed.bytes == object.bytes && observed.sha256 == object.sha256,
            "host artifact size or digest mismatch"
        );
        if name == "zdn" {
            crate::devnet::validate_helper(&observed.prefix)?;
        }
    }
    verified_image(spec, artifacts)?;
    let runtime = render_runtime_config(&manifest, &spec.runtime_options()?)?;
    ensure!(
        runtime.config_sha256 == spec.config_sha256
            && runtime.config_toml == spec.config_toml
            && runtime.consensus_fingerprint == spec.consensus_fingerprint,
        "fetched manifest does not produce the pinned runtime configuration"
    );
    Ok(runtime)
}

/// Shared byte-bound image metadata for input preflight and Docker delivery.
/// Callers validate the complete installation spec before using these pins.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.inputs.verified_image")
)]
pub(super) fn verified_image(
    spec: &HostInstallSpec,
    artifacts: &Directory,
) -> Result<(ImageRecord, image::VerifiedManifest)> {
    let image = ImageRecord::from_json(&read_pinned(
        artifacts,
        "image.json",
        &spec.image_record,
        image::MAX_RECORD_BYTES as u64,
    )?)?;
    ensure!(
        image.image == spec.image,
        "host image and image record differ"
    );
    let manifest = image::validate_manifest_bytes(
        &image,
        &read_pinned(
            artifacts,
            "image-manifest.json",
            &spec.image_manifest,
            image::MAX_MANIFEST_BYTES as u64,
        )?,
    )?;
    Ok((image, manifest))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.inputs.read_pinned")
)]
fn read_pinned(
    directory: &Directory,
    name: &str,
    expected: &S3Object,
    limit: u64,
) -> Result<Vec<u8>> {
    ensure!(
        expected.bytes <= limit,
        "host metadata exceeds its size bound"
    );
    let contents = directory.read(name, expected.bytes)?;
    ensure!(
        contents.len() as u64 == expected.bytes && super::hash(&contents) == expected.sha256,
        "host artifact size or digest mismatch"
    );
    Ok(contents)
}
