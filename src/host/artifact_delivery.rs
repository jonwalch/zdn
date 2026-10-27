//! Native artifact delivery, adapted from retired `runner.py::fetch_artifact`.
//!
//! Callers retain the installation lock, authenticate tools and the directory's
//! expected owner/ancestors (root on hosts), and reopen it after mount changes.
//! Linux procfs must be trusted and visible to tools. Directory descriptors pin
//! staging paths even if ancestors are renamed; no hostile-root containment or
//! live AWS/node qualification is implied. Native installation uses this API.

use super::{
    command::{Executor, HostCommand},
    files::{ArtifactDigest, Directory},
    HostInstallSpec, S3Object,
};
use eyre::{ensure, Result};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Artifact {
    Manifest,
    Bundle,
    Helper,
    ImageRecord,
    ImageManifest,
}

#[derive(serde::Deserialize)]
struct ObjectMetadata {
    #[serde(rename = "ContentLength")]
    content_length: u64,
}

impl Artifact {
    fn pin(self, spec: &HostInstallSpec) -> (&S3Object, &'static str, u64) {
        match self {
            Self::Manifest => (&spec.manifest, "manifest.json", 2 * 1024 * 1024),
            Self::Bundle => (&spec.bundle, "chain.tar", super::MAX_ARTIFACT_BYTES),
            Self::Helper => (&spec.helper, "zdn", super::MAX_ARTIFACT_BYTES),
            Self::ImageRecord => (
                &spec.image_record,
                "image.json",
                crate::image::MAX_RECORD_BYTES as u64,
            ),
            Self::ImageManifest => (
                &spec.image_manifest,
                "image-manifest.json",
                crate::image::MAX_MANIFEST_BYTES as u64,
            ),
        }
    }

    fn validate(self, prefix: &[u8]) -> Result<()> {
        if matches!(self, Self::Helper) {
            crate::devnet::validate_helper(prefix)?;
        }
        Ok(())
    }
}

/// Fetch exactly one pinned object, or verify an immutable local retry without
/// contacting AWS. Metadata is validated before subprocess effects; downloaded
/// bytes are streamed, never collected in memory. All commands and chunk checks
/// share the existing executor deadline, with a 600-second download bound.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.artifact_delivery.fetch")
)]
pub fn fetch(
    spec: &HostInstallSpec,
    artifact: Artifact,
    artifacts: &Directory,
    aws: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    spec.validate()?;
    ensure!(aws.is_absolute(), "host artifact tool must be absolute");
    // Validate every metadata pin before any subprocess, not only the selected
    // one. The bundle/helper remain streaming objects up to the shared bound.
    for kind in [
        Artifact::Manifest,
        Artifact::ImageRecord,
        Artifact::ImageManifest,
    ] {
        let (pin, _, limit) = kind.pin(spec);
        ensure!(pin.bytes <= limit, "host metadata exceeds its size bound");
    }
    let (pin, name, _) = artifact.pin(spec);
    let mode = if matches!(artifact, Artifact::Helper) {
        0o555
    } else {
        0o600
    };
    fetch_object(
        Delivery {
            pin,
            name,
            mode,
            timeout: Duration::from_secs(600),
        },
        artifacts,
        aws,
        executor,
        cancelled,
        |prefix| artifact.validate(prefix),
    )
}

/// Validated consumer policy; callers validate the complete installation first.
pub(crate) struct Delivery<'a> {
    pub pin: &'a S3Object,
    pub name: &'a str,
    pub mode: u32,
    pub timeout: Duration,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.artifact_delivery.fetch_object")
)]
pub(crate) fn fetch_object(
    delivery: Delivery<'_>,
    artifacts: &Directory,
    aws: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    validate: impl Fn(&[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(aws.is_absolute(), "host artifact tool must be absolute");
    let Delivery {
        pin,
        name,
        mode,
        timeout,
    } = delivery;
    let expected = ArtifactDigest {
        bytes: pin.bytes,
        sha256: pin.sha256.clone(),
        prefix: Vec::new(),
    };
    let deadline = executor.work_deadline()?;
    let mut check = || {
        ensure!(
            !cancelled.load(Ordering::Relaxed),
            "host artifact fetch cancelled"
        );
        ensure!(
            Instant::now() < deadline,
            "host operation exceeded its cumulative deadline"
        );
        Ok(())
    };
    check()?;
    if artifacts.artifact_matches(name, &expected, mode, &mut check, |prefix| validate(prefix))? {
        return check();
    }
    let pending = artifacts.download()?;
    let result = (|| {
        #[cfg(feature = "profiling")]
        let download = tracing::info_span!("host.artifact_delivery.download").entered();
        let output = executor.execute(
            HostCommand {
                program: aws,
                args: &[
                    "s3api".into(),
                    "get-object".into(),
                    "--bucket".into(),
                    pin.bucket.clone().into(),
                    "--key".into(),
                    pin.key.clone().into(),
                    "--expected-bucket-owner".into(),
                    pin.owner_account.clone().into(),
                    "--region".into(),
                    pin.region.clone().into(),
                    "--output".into(),
                    "json".into(),
                    pending.path().into_os_string(),
                ],
                stdin: None,
                timeout,
                allowed: &[0],
            },
            cancelled,
        )?;
        #[cfg(feature = "profiling")]
        drop(download);
        ensure!(
            output.stdout.len() <= 64 * 1024,
            "S3 artifact metadata exceeds bound"
        );
        let metadata: ObjectMetadata = serde_json::from_slice(&output.stdout)
            .map_err(|_| eyre::eyre!("invalid S3 artifact metadata"))?;
        ensure!(
            metadata.content_length == pin.bytes,
            "S3 artifact size mismatch"
        );
        artifacts.publish_download(name, &pending, &expected, mode, &mut check, |prefix| {
            validate(prefix)
        })
    })();
    // Explicit close also reports cleanup failures after command cancellation
    // or invalid downloads. Drop is only a fallback for unwinding.
    {
        #[cfg(feature = "profiling")]
        let _cleanup = tracing::info_span!("host.artifact_delivery.cleanup").entered();
        pending.close()?;
    }
    result?;
    check()
}
