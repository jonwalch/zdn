//! Native lightwallet image delivery, adapted from retired install.py operations.
//! Callers retain the installation lock and
//! authenticate directory ancestors, owners and stable absolute tool paths.
//! Trusted procfs is required for descriptor-pinned downloads. This API neither
//! activates a service nor qualifies lightwalletd or Ironwood compatibility.

use super::LightwalletInstallSpec;
pub use crate::host::image_delivery::Tools;
use crate::{
    host::{
        artifact_delivery::{fetch_object, Delivery},
        command::{Executor, HostCommand},
        files::Directory,
        S3Object,
    },
    lightwallet_image::{self as image, ImageRecord, ImageValidationReport},
};
use eyre::{ensure, Result};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Artifact {
    ImageRecord,
    ImageManifest,
    ImageConfig,
}

impl Artifact {
    fn pin(self, spec: &LightwalletInstallSpec) -> (&S3Object, &'static str, u64) {
        match self {
            Self::ImageRecord => (
                &spec.image_record,
                "image.json",
                image::MAX_RECORD_BYTES as u64,
            ),
            Self::ImageManifest => (
                &spec.image_manifest,
                "image-manifest.json",
                image::MAX_MANIFEST_BYTES as u64,
            ),
            Self::ImageConfig => (
                &spec.image_config,
                "image-config.json",
                image::MAX_CONFIG_BYTES as u64,
            ),
        }
    }
}

fn validate(spec: &LightwalletInstallSpec) -> Result<()> {
    spec.validate()?;
    for kind in [
        Artifact::ImageRecord,
        Artifact::ImageManifest,
        Artifact::ImageConfig,
    ] {
        let (pin, _, limit) = kind.pin(spec);
        ensure!(
            pin.bytes <= limit,
            "lightwallet image metadata exceeds parser bound"
        );
    }
    Ok(())
}

/// Immutable retry or private, streaming S3 delivery, with the historical
/// 180-second bound under the Executor's cumulative deadline/cleanup reserve.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.image_delivery.fetch_artifact")
)]
pub fn fetch_artifact(
    spec: &LightwalletInstallSpec,
    artifact: Artifact,
    artifacts: &Directory,
    aws: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    validate(spec)?;
    let (pin, name, _) = artifact.pin(spec);
    fetch_object(
        Delivery {
            pin,
            name,
            mode: 0o600,
            timeout: Duration::from_secs(180),
        },
        artifacts,
        aws,
        executor,
        cancelled,
        |_| Ok(()),
    )
}

/// Read exact pinned bytes without contacting AWS. Safe traversal and immutable
/// file permissions are enforced by the same file mechanism as node delivery.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.image_delivery.check_artifact")
)]
pub fn check_artifact(
    spec: &LightwalletInstallSpec,
    artifact: Artifact,
    artifacts: &Directory,
    executor: &Executor,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    validate(spec)?;
    let deadline = executor.work_deadline()?;
    let mut check = || {
        ensure!(
            !cancelled.load(Ordering::Relaxed),
            "lightwallet image delivery cancelled"
        );
        ensure!(
            Instant::now() < deadline,
            "host operation exceeded its cumulative deadline"
        );
        Ok(())
    };
    check()?;
    let (pin, name, _) = artifact.pin(spec);
    let contents = artifacts.read_verified(name, pin.bytes, &pin.sha256, &mut check)?;
    check()?;
    Ok(contents)
}

/// Native replacement for helper verification. Inspection, when requested,
/// uses daemon metadata rather than the saved publisher configuration.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.image_delivery.verify_image")
)]
pub fn verify_image(
    spec: &LightwalletInstallSpec,
    artifacts: &Directory,
    docker: Option<&Path>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<ImageValidationReport> {
    let record = check_artifact(spec, Artifact::ImageRecord, artifacts, executor, cancelled)?;
    let manifest = check_artifact(
        spec,
        Artifact::ImageManifest,
        artifacts,
        executor,
        cancelled,
    )?;
    let config = check_artifact(spec, Artifact::ImageConfig, artifacts, executor, cancelled)?;
    let record = ImageRecord::from_json(&record)?;
    ensure!(
        record.image == spec.service.image,
        "lightwallet record selects a different image"
    );
    image::validate_artifacts(&record, &manifest, &config, None)?;
    let inspection = docker
        .map(|docker| {
            executor.execute(
                HostCommand {
                    program: docker,
                    args: &[
                        "image".into(),
                        "inspect".into(),
                        spec.service.image.clone().into(),
                    ],
                    stdin: None,
                    timeout: Duration::from_secs(60),
                    allowed: &[0],
                },
                cancelled,
            )
        })
        .transpose()?;
    let report = image::validate_artifacts(
        &record,
        &manifest,
        &config,
        inspection.as_ref().map(|output| output.stdout.as_slice()),
    )?;
    ensure!(
        report.image == spec.service.image
            && !report.launch_ready
            && report.qualification == "pending"
            && !report.source_provenance_verified
            && report.docker_metadata_verified == docker.is_some(),
        "unexpected lightwallet image verification report"
    );
    Ok(report)
}

/// Credentials are explicitly removed even on failure/cancellation, before
/// reopening pinned artifacts and validating post-pull daemon metadata.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.image_delivery.pull_image")
)]
pub fn pull_image(
    spec: &LightwalletInstallSpec,
    artifacts: &Directory,
    scratch: &Path,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<ImageValidationReport> {
    verify_image(spec, artifacts, None, executor, cancelled)?;
    crate::host::image_delivery::pull_image(
        &spec.service.image,
        &spec.host.helper.region,
        scratch,
        tools,
        executor,
        cancelled,
        || {},
    )?;
    verify_image(spec, artifacts, Some(&tools.docker), executor, cancelled)
}
