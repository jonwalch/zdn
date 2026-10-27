//! Native revision delivery used by host updates, not journal authority.
//!
//! The caller authenticates original-native-install intent, retains the original
//! installation lock, verifies live mount identity and trusted directory owners
//! and ancestors, and supplies a dedicated immutable staging Directory for this
//! request's UUID. Reopen descriptors after mount changes. Tools and scratch must
//! be trusted stable absolute paths; scratch is private. Trusted Linux procfs is
//! required by streamed delivery. The caller's Executor supplies one cumulative
//! deadline including cleanup reserve. The native runtime selects this API;
//! successful staging/inspection is not live node or payment qualification.

use super::revision::Request;
pub use crate::host::image_delivery::Tools;
use crate::{
    host::{
        artifact_delivery::{fetch_object, Delivery},
        command::{Executor, HostCommand},
        files::Directory,
        S3Object,
    },
    image::{self, ImageInspectionReport, ImageRecord},
};
use eyre::{ensure, Result};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

fn pins(request: &Request) -> [(&S3Object, &str); 3] {
    [
        (&request.image_record, "image.json"),
        (&request.image_manifest, "image-manifest.json"),
        (&request.image_config, "image-config.json"),
    ]
}

fn check(executor: &Executor, cancelled: &AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(Ordering::Relaxed),
        "revision delivery cancelled"
    );
    ensure!(
        Instant::now() < executor.work_deadline()?,
        "revision delivery deadline exceeded"
    );
    Ok(())
}

fn read(
    directory: &Directory,
    pin: &S3Object,
    name: &str,
    executor: &Executor,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    check(executor, cancelled)?;
    directory.read_verified(name, pin.bytes, &pin.sha256, &mut || {
        check(executor, cancelled)
    })
}

// Check every retained entry before any network effect, including partial retries.
fn retained(
    request: &Request,
    directory: &Directory,
    executor: &Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut bytes = Vec::new();
    for (pin, name) in pins(request) {
        bytes.push(match read(directory, pin, name, executor, cancelled) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) => {
                None
            }
            Err(e) => return Err(e),
        });
    }
    if let Some(record) = &bytes[0] {
        ensure!(
            ImageRecord::from_json(record)? == request.image,
            "revision record differs from request"
        );
    }
    if let Some(manifest) = &bytes[1] {
        let verified = image::validate_manifest_bytes(&request.image, manifest)?;
        if let Some(config) = &bytes[2] {
            image::validate_config_bytes(&request.image, &verified, config)?;
        }
    }
    Ok(())
}

/// Verify all exact raw pins and native metadata offline; optionally inspect the
/// daemon freshly. None means no daemon observation, not a readiness receipt.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.revision_delivery.verify")
)]
pub fn verify(
    request: &Request,
    artifacts: &Directory,
    docker: Option<&Path>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<Option<ImageInspectionReport>> {
    request.bytes()?;
    ensure!(
        docker.is_none_or(Path::is_absolute),
        "revision Docker tool must be absolute"
    );
    let [record, manifest, config] =
        pins(request).map(|(pin, name)| read(artifacts, pin, name, executor, cancelled));
    let record = ImageRecord::from_json(&record?)?;
    ensure!(
        record == request.image,
        "revision record differs from request"
    );
    let manifest = image::validate_manifest_bytes(&record, &manifest?)?;
    image::validate_config_bytes(&record, &manifest, &config?)?;
    check(executor, cancelled)?;
    docker
        .map(|docker| {
            let output = executor.execute(
                HostCommand {
                    program: docker,
                    args: &[
                        "image".into(),
                        "inspect".into(),
                        record.image.clone().into(),
                    ],
                    stdin: None,
                    timeout: Duration::from_secs(60),
                    allowed: &[0],
                },
                cancelled,
            )?;
            image::validate_docker_inspect(&record, &manifest, &output.stdout)
        })
        .transpose()
}

/// Fetch original request pins create-only (600s per download), verify all three
/// before ECR login/pull (1200s), then inspect only after credential cleanup.
/// Never rewrites original installation identity, selection, or journal state.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.revision_delivery.stage")
)]
pub fn stage(
    request: &Request,
    artifacts: &Directory,
    scratch: &Path,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<ImageInspectionReport> {
    request.bytes()?;
    ensure!(
        tools.aws.is_absolute() && tools.docker.is_absolute() && scratch.is_absolute(),
        "revision delivery paths must be absolute"
    );
    check(executor, cancelled)?;
    retained(request, artifacts, executor, cancelled)?;
    for (pin, name) in pins(request) {
        fetch_object(
            Delivery {
                pin,
                name,
                mode: 0o600,
                timeout: Duration::from_secs(600),
            },
            artifacts,
            &tools.aws,
            executor,
            cancelled,
            |_| Ok(()),
        )?;
    }
    verify(request, artifacts, None, executor, cancelled)?;
    crate::host::image_delivery::pull_image(
        &request.image.image,
        &request.original.spec.helper.region,
        scratch,
        tools,
        executor,
        cancelled,
        || {},
    )?;
    verify(request, artifacts, Some(&tools.docker), executor, cancelled)?
        .ok_or_else(|| eyre::eyre!("missing revision inspection"))
}
