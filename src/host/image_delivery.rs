//! Native image delivery, adapted from retired `runner.py` image operations.
//!
//! The caller retains the installation lock and authenticates stable root-owned
//! artifact/scratch ancestors and tool paths. Docker credentials exist only in a
//! private temporary directory, never argv or the environment. Native installation
//! and observations use this API. Image inspection is not node readiness.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

use eyre::{ensure, Result};

use super::{
    command::{Executor, HostCommand},
    files::Directory,
    inputs, HostInstallSpec,
};
use crate::image::{self, ImageInspectionReport};

/// Resolve both tools from the trusted host path, not an inherited PATH.
pub struct Tools {
    pub aws: PathBuf,
    pub docker: PathBuf,
}

/// Validate exact pinned metadata before invoking Docker. The daemon, not the
/// saved publisher record, supplies the actual pulled image configuration.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.image_delivery.inspect")
)]
pub fn inspect(
    spec: &HostInstallSpec,
    artifacts: &Directory,
    docker: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<ImageInspectionReport> {
    spec.validate()?;
    let (record, manifest) = inputs::verified_image(spec, artifacts)?;
    let output = executor.execute(
        HostCommand {
            program: docker,
            args: &["image".into(), "inspect".into(), spec.image.clone().into()],
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    )?;
    image::validate_docker_inspect(&record, &manifest, &output.stdout)
        .map_err(|_| eyre::eyre!("pulled host image failed inspection"))
}

/// Fresh delivery only: login/password and pull use the action's shared deadline.
/// Credentials are removed before inspection, including after failed/cancelled
/// commands. Cleanup errors are returned, never treated as confirmed removal.
/// This neither launches a container nor changes runtime/installer selection.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.image_delivery.pull")
)]
pub fn pull(
    spec: &HostInstallSpec,
    artifacts: &Directory,
    scratch: &Path,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<ImageInspectionReport> {
    #[cfg(feature = "profiling")]
    let preflight = tracing::info_span!("host.image_delivery.preflight").entered();
    spec.validate()?;
    ensure!(
        tools.aws.is_absolute() && tools.docker.is_absolute(),
        "host image tools must be absolute"
    );
    // Reject mismatched records before any network-facing action. Inspection
    // reopens the exact pins after delivery rather than trusting old metadata.
    inputs::verified_image(spec, artifacts)?;
    pull_image(
        &spec.image,
        &spec.helper.region,
        scratch,
        tools,
        executor,
        cancelled,
        || {
            #[cfg(feature = "profiling")]
            drop(preflight);
        },
    )?;
    inspect(spec, artifacts, &tools.docker, executor, cancelled)
}

/// Shared regional ECR credential lifecycle. Consumer metadata must already be
/// validated. Always removes credentials before returning to daemon inspection.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.image_delivery.pull_image")
)]
pub(crate) fn pull_image(
    image: &str,
    region: &str,
    scratch: &Path,
    tools: &Tools,
    executor: &mut Executor,
    cancelled: &AtomicBool,
    preflight_done: impl FnOnce(),
) -> Result<()> {
    ensure!(
        tools.aws.is_absolute() && tools.docker.is_absolute(),
        "host image tools must be absolute"
    );
    ensure!(scratch.is_absolute(), "host image scratch must be absolute");
    let owner = fs::metadata("/proc/self")?.uid();
    let _trusted = Directory::open(scratch, owner)?;
    ensure!(
        fs::symlink_metadata(scratch)?.mode() & 0o7777 == 0o700,
        "host image scratch must be private"
    );
    let credentials = tempfile::Builder::new()
        .prefix(".docker-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(scratch)?;
    preflight_done();
    let result = (|| -> Result<()> {
        #[cfg(feature = "profiling")]
        let password_phase = tracing::info_span!("host.image_delivery.password").entered();
        let mut password = executor
            .execute(
                HostCommand {
                    program: &tools.aws,
                    args: &[
                        "ecr".into(),
                        "get-login-password".into(),
                        "--region".into(),
                        region.into(),
                    ],
                    stdin: None,
                    timeout: Duration::from_secs(60),
                    allowed: &[0],
                },
                cancelled,
            )?
            .stdout;
        ensure!(
            !password.is_empty() && password.len() < 8192,
            "invalid ECR login response"
        );
        #[cfg(feature = "profiling")]
        drop(password_phase);
        let registry = image.split('/').next().expect("validated image");
        #[cfg(feature = "profiling")]
        let login_phase = tracing::info_span!("host.image_delivery.login").entered();
        let login = executor.execute(
            HostCommand {
                program: &tools.docker,
                args: &[
                    "--config".into(),
                    credentials.path().as_os_str().into(),
                    "login".into(),
                    "--username".into(),
                    "AWS".into(),
                    "--password-stdin".into(),
                    registry.into(),
                ],
                stdin: Some(&password),
                timeout: Duration::from_secs(60),
                allowed: &[0],
            },
            cancelled,
        );
        password.fill(0);
        login?;
        #[cfg(feature = "profiling")]
        drop(login_phase);
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.image_delivery.pull_command").entered();
        executor.execute(
            HostCommand {
                program: &tools.docker,
                args: &[
                    "--config".into(),
                    credentials.path().as_os_str().into(),
                    "pull".into(),
                    "--platform".into(),
                    "linux/amd64".into(),
                    image.into(),
                ],
                stdin: None,
                timeout: Duration::from_secs(1200),
                allowed: &[0],
            },
            cancelled,
        )?;
        Ok(())
    })();
    {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("host.image_delivery.credential_cleanup").entered();
        credentials
            .close()
            .map_err(|_| eyre::eyre!("host image credential cleanup failed"))?;
    }
    result
}
