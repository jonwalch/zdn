//! Durable, bounded CodeBuild submission and exact-identity recovery.

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, io::Read, path::Path, time::Duration};
use uuid::Uuid;

use crate::{
    aws::{AwsApi, AwsCall, TeamDefinition},
    build::BuildContract,
    build_infra::BuildInfrastructure,
    foundation_live::Runtime,
    image::{self, ImageRecord},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildResult {
    pub contract_sha256: String,
    pub image: ImageRecord,
}

/// Execution machinery is not image identity. Old attempts without an exporter
/// remain readable for inspection/cleanup, but cannot execute or be converted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExporter {
    pub protocol: String,
    pub helper: crate::devnet::Artifact,
    pub version: Option<String>,
}

impl NativeExporter {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == crate::build_export::PROTOCOL,
            "unsupported native exporter protocol"
        );
        crate::devnet::validate_hash(&self.helper.sha256)?;
        ensure!(
            (64..=crate::devnet::MAX_HELPER_BYTES).contains(&self.helper.bytes),
            "invalid native exporter size"
        );
        if let Some(version) = &self.version {
            validate_version(version)?;
        }
        Ok(())
    }

    pub(crate) fn key(&self, attempt: Uuid) -> String {
        format!("sources/runtime/{attempt}/{}", self.helper.sha256)
    }
}

/// Sanitized durable attempt state, not provider logs or authorization to retry.
/// A successful job or reuse pointer does not establish a verified image.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildObservation {
    pub attempt_id: Uuid,
    pub contract_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exporter_helper: Option<crate::devnet::Artifact>,
    pub source_uploaded: bool,
    pub submission_recorded: bool,
    pub build_id_known: bool,
    pub reused_from: Option<Uuid>,
    pub job_outcome: Option<&'static str>,
    pub image_verified: bool,
}

pub type BuildProgress<'a> = dyn FnMut(&BuildObservation) -> Result<()> + 'a;

pub(crate) struct AttemptLock(fs::File);

impl Drop for AttemptLock {
    fn drop(&mut self) {
        // Closing alone leaves flock held by descriptors inherited during a
        // concurrent fork. Ownership ends with this guard, not the last close.
        let _ = FileExt::unlock(&self.0);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    schema_version: u32,
    team: TeamDefinition,
    project: String,
    repository: String,
    attempt_id: Uuid,
    contract: BuildContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exporter: Option<NativeExporter>,
    source_version: Option<String>,
    dispatched: bool,
    reused: Option<Uuid>,
    build_id: Option<String>,
    terminal: Option<String>,
}

impl Attempt {
    fn observation(&self, image_verified: bool) -> Result<BuildObservation> {
        Ok(BuildObservation {
            attempt_id: self.attempt_id,
            contract_sha256: self.contract.fingerprint()?,
            exporter_helper: self.exporter.as_ref().map(|e| e.helper.clone()),
            source_uploaded: self.source_version.is_some(),
            submission_recorded: self.dispatched,
            build_id_known: self.build_id.is_some(),
            reused_from: self.reused,
            job_outcome: self.terminal.as_deref().map(|outcome| match outcome {
                "SUCCEEDED" => "succeeded",
                "FAILED" => "failed",
                "FAULT" => "fault",
                "STOPPED" => "stopped",
                "TIMED_OUT" => "timed-out",
                _ => "unknown",
            }),
            image_verified,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_job.attempt.read")
    )]
    fn read(directory: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        private_open(&directory.join("attempt.json"), false)?
            .take(65537)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "build receipt exceeds size bound");
        serde_json::from_slice(&bytes).context("invalid build receipt")
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_job.attempt.validate")
    )]
    fn validate(
        &self,
        team: &TeamDefinition,
        contract: &BuildContract,
        infra: &BuildInfrastructure,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.team == *team
                && self.project == infra.project_name
                && self.repository == infra.repository_uri
                && self.contract == *contract,
            "build receipt identity mismatch"
        );
        ensure!(
            self.attempt_id.get_version_num() == 4
                && self.attempt_id.get_variant() == uuid::Variant::RFC4122
                && self
                    .reused
                    .is_none_or(|id| id.get_version_num() == 4
                        && id.get_variant() == uuid::Variant::RFC4122)
                && (!self.dispatched || self.source_version.is_some())
                && (self.build_id.is_none() || self.dispatched)
                && (self.terminal.is_none() || self.build_id.is_some())
                && !(self.reused.is_some() && self.dispatched),
            "invalid build receipt state"
        );
        if let Some(version) = &self.source_version {
            validate_version(version)?;
        }
        if let Some(exporter) = &self.exporter {
            exporter.validate()?;
            ensure!(
                !self.dispatched || exporter.version.is_some(),
                "dispatched native build has no pinned exporter version"
            );
        }
        if let Some(id) = &self.build_id {
            validate_build_id(id, infra)?;
        }
        Ok(())
    }
}

/// Offline identity validation, deliberately preserving every dispatch field.
/// Returns saved observations, never image verification or execution permission.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.validate_preparation")
)]
pub fn validate_preparation(
    directory: &Path,
    team: &TeamDefinition,
    contract: &BuildContract,
) -> Result<BuildObservation> {
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "build directory must be real"
    );
    let receipt = Attempt::read(directory)?;
    receipt.validate(team, contract, &BuildInfrastructure::for_team(team)?)?;
    ensure!(
        receipt.terminal.is_none() || receipt.terminal.as_deref() == Some("SUCCEEDED"),
        "failed terminal build cannot be handed off or resumed"
    );
    if let Some(exporter) = receipt.exporter.as_ref().filter(|e| e.version.is_none()) {
        if receipt.reused.is_none() {
            ensure!(
                crate::devnet::hash_file(
                    &directory.join("exporter"),
                    crate::devnet::MAX_HELPER_BYTES
                )? == exporter.helper,
                "saved native exporter changed"
            );
        }
    }
    receipt.observation(false)
}

/// Re-observe only an already known job for cleanup, verifying successful output
/// through bounded S3/ECR reads when missing locally. This cannot submit, stop,
/// resume, or publish a reuse index. Unknown submissions and nonterminal jobs
/// remain blocked rather than entering the build lifecycle.
pub fn reconcile_for_removal(
    api: &dyn AwsApi,
    directory: &Path,
    team: &TeamDefinition,
) -> Result<()> {
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "build directory must be real"
    );
    let lock = private_open(&directory.join("attempt.lock"), true)?;
    FileExt::try_lock_exclusive(&lock).context("another process holds the build receipt lock")?;
    let _lock = AttemptLock(lock);
    let mut receipt = Attempt::read(directory)?;
    receipt.contract.validate()?;
    let infra = BuildInfrastructure::for_team(team)?;
    receipt.validate(team, &receipt.contract, &infra)?;
    if !receipt.dispatched {
        return Ok(());
    }
    if receipt.terminal.is_none() {
        let id = receipt
            .build_id
            .as_ref()
            .context("unknown build submission; cleanup cannot discover or resubmit a job")?;
        let spec = crate::build_script::native_buildspec(
            &receipt.contract,
            &infra,
            receipt.attempt_id,
            receipt
                .source_version
                .as_deref()
                .context("missing source version")?,
            receipt
                .exporter
                .as_ref()
                .context("missing native exporter")?,
        )?;
        let response = api.call("codebuild", "batch-get-builds", json!({"ids":[id]}), &[])?;
        validate_jobs(&response, &infra, std::slice::from_ref(id))?;
        let job = &response["builds"][0];
        ensure!(
            job["source"]["buildspec"] == spec,
            "build source identity mismatch"
        );
        let status = job["buildStatus"]
            .as_str()
            .context("missing build status")?;
        ensure!(
            ["SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"].contains(&status)
                && (job["endTime"].is_number()
                    || job["endTime"].as_str().is_some_and(|s| !s.is_empty())),
            "active/unknown build job; cleanup requires an observed terminal job"
        );
        receipt.terminal = Some(status.to_owned());
    }
    if receipt.terminal.as_deref() == Some("SUCCEEDED")
        && !directory.join("result.json").try_exists()?
    {
        validate_result(
            api,
            &infra,
            &receipt.contract,
            receipt.attempt_id,
            directory,
        )?;
    }
    save(directory, &receipt, &mut |_| Ok(()))
}

/// Exact cleanup authority from the original attempt, not from a bucket prefix.
/// Unknown submissions must be reconciled through the build lifecycle first.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.removal_evidence")
)]
pub fn removal_evidence(directory: &Path, team: &TeamDefinition) -> Result<serde_json::Value> {
    let receipt = Attempt::read(directory)?;
    receipt.contract.validate()?;
    receipt.validate(
        team,
        &receipt.contract,
        &BuildInfrastructure::for_team(team)?,
    )?;
    ensure!(
        !receipt.dispatched
            || (receipt.build_id.is_some()
                && receipt.terminal.as_deref().is_some_and(|s| [
                    "SUCCEEDED",
                    "FAILED",
                    "FAULT",
                    "STOPPED",
                    "TIMED_OUT"
                ]
                .contains(&s))),
        "build submission is active or uncertain; reconcile it before team removal"
    );
    let mut keys = vec![
        format!("sources/{}.tar", receipt.contract.source_sha256),
        format!("images/{}.json", receipt.contract.fingerprint()?),
    ];
    if let Some(exporter) = &receipt.exporter {
        // Record intent even when PutObject's reply was lost. Cleanup owns all
        // versions at this exact attempt/hash key, never the runtime prefix.
        keys.push(exporter.key(receipt.attempt_id));
    }
    for attempt in std::iter::once(receipt.attempt_id).chain(receipt.reused) {
        for name in ["result.json", "image-manifest.json", "image-config.json"] {
            keys.push(format!("results/{attempt}/{name}"));
        }
    }
    let digest = if directory.join("result.json").try_exists()? {
        let result: BuildResult = crate::foundation::read_json(&directory.join("result.json"))?;
        ensure!(
            result.contract_sha256 == receipt.contract.fingerprint()?,
            "build result contract changed"
        );
        receipt.contract.validate_image(&result.image)?;
        ensure!(
            result.image.image.split_once('@').map(|v| v.0) == Some(receipt.repository.as_str()),
            "build result repository changed"
        );
        Some(result.image.manifest_digest()?.to_owned())
    } else {
        None
    };
    Ok(
        json!({"attempt":serde_json::to_value(&receipt)?,"buildId":receipt.build_id,"keys":keys,"imageDigest":digest}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.lock_preparation")
)]
pub(crate) fn lock_preparation(
    directory: &Path,
    team: &TeamDefinition,
    contract: &BuildContract,
) -> Result<AttemptLock> {
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "build directory must be real"
    );
    let lock = private_open(&directory.join("attempt.lock"), true)?;
    FileExt::try_lock_exclusive(&lock).context("another process holds the build receipt lock")?;
    let lock = AttemptLock(lock);
    validate_preparation(directory, team, contract)?;
    Ok(lock)
}

/// A staged cluster does not prove that a later source-build attempt finished.
/// Only matching, locally verified successful build/reuse evidence may be omitted.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.validate_handoff")
)]
pub(crate) fn validate_handoff(
    directory: &Path,
    team: &TeamDefinition,
    request: &crate::devnet::ClusterRequest,
) -> Result<Option<AttemptLock>> {
    if !directory.try_exists()? {
        return Ok(None);
    }
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "build receipt directory must be real"
    );
    let lock = private_open(&directory.join("attempt.lock"), true)?;
    FileExt::try_lock_exclusive(&lock).context("another process holds the build receipt lock")?;
    let lock = AttemptLock(lock);
    let receipt = Attempt::read(directory)?;
    let contract = request
        .build
        .as_ref()
        .context("build receipt is unrelated to staged deployment")?;
    let infra = BuildInfrastructure::for_team(team)?;
    receipt.validate(team, contract, &infra)?;
    ensure!(
        receipt.terminal.as_deref() == Some("SUCCEEDED") || receipt.reused.is_some(),
        "finish or reconcile incomplete build before handoff"
    );
    let result: BuildResult = crate::foundation::read_json(&directory.join("result.json"))?;
    ensure!(
        result.contract_sha256 == contract.fingerprint()? && result.image == request.image,
        "build result differs from staged deployment"
    );
    contract.validate_image(&result.image)?;
    for name in ["image.json", "image-manifest.json", "image-config.json"] {
        let artifact = request
            .artifacts
            .get(name)
            .context("missing staged build artifact")?;
        let bytes = crate::devnet::read_bounded(&directory.join(name), artifact.bytes)?;
        ensure!(
            bytes.len() as u64 == artifact.bytes
                && crate::devnet::sha256(&bytes) == artifact.sha256,
            "build outputs differ from staged deployment"
        );
    }
    Ok(Some(lock))
}

/// A receipt directory may be resumed only with the identical contract and team.
/// Uncertain submissions are recovered, never resubmitted. The caller supplies a cancellation check
/// and clock so every failure path is testable without sleeping or AWS.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.run")
)]
pub fn run(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    contract: &BuildContract,
    archive: &Path,
    directory: &Path,
    runtime: &impl Runtime,
    check_cancel: impl FnMut() -> Result<()>,
) -> Result<BuildResult> {
    run_with_progress(
        api,
        team,
        contract,
        archive,
        directory,
        runtime,
        check_cancel,
        &mut |_| Ok(()),
    )
}

/// Prepare native export with a private, exact Linux helper copy.
/// Existing legacy attempts cannot be converted or executed.
pub fn prepare_native(
    directory: &Path,
    team: &TeamDefinition,
    contract: &BuildContract,
    helper: &Path,
) -> Result<()> {
    contract.validate()?;
    let (_lock, receipt) = open_attempt(
        directory,
        team,
        contract,
        &BuildInfrastructure::for_team(team)?,
        Some(helper),
    )?;
    save(directory, &receipt, &mut |_| Ok(()))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.open_attempt")
)]
fn open_attempt(
    directory: &Path,
    team: &TeamDefinition,
    contract: &BuildContract,
    infra: &BuildInfrastructure,
    helper: Option<&Path>,
) -> Result<(AttemptLock, Attempt)> {
    let new_directory = !directory.try_exists()?;
    if new_directory {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory)?;
        fs::File::open(
            directory
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
    }
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(metadata.is_dir(), "receipt directory must not be a symlink");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "receipt directory must be private"
        );
    }
    let lock = private_open(&directory.join("attempt.lock"), true)?;
    FileExt::try_lock_exclusive(&lock).context("another process holds the build receipt lock")?;
    let lock = AttemptLock(lock);
    let mut receipt: Attempt = match Attempt::read(directory) {
        Ok(receipt) => receipt,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            ensure!(
                new_directory,
                "build receipt missing from existing directory; inspect the job before retrying"
            );
            Attempt {
                schema_version: 1,
                team: team.clone(),
                project: infra.project_name.clone(),
                repository: infra.repository_uri.clone(),
                attempt_id: Uuid::new_v4(),
                contract: contract.clone(),
                exporter: None,
                source_version: None,
                dispatched: false,
                reused: None,
                build_id: None,
                terminal: None,
            }
        }
        Err(error) => return Err(error),
    };
    if let Some(helper) = helper {
        if new_directory {
            let target = directory.join("exporter");
            let artifact =
                crate::devnet::snapshot_file(helper, &target, crate::devnet::MAX_HELPER_BYTES)?;
            crate::devnet::validate_helper_file(&target)?;
            receipt.exporter = Some(NativeExporter {
                protocol: crate::build_export::PROTOCOL.into(),
                helper: artifact,
                version: None,
            });
        } else {
            let saved = receipt
                .exporter
                .as_ref()
                .context("cannot change a legacy attempt's exporter")?;
            ensure!(
                crate::devnet::hash_file(helper, crate::devnet::MAX_HELPER_BYTES)? == saved.helper,
                "saved native exporter changed"
            );
        }
    }
    receipt.validate(team, contract, infra)?;
    Ok((lock, receipt))
}

/// Observe saved transitions before later effects. Observer errors stop this run;
/// they never erase submission intent, resubmit, or imply a remote job stopped.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.run_with_progress")
)]
pub fn run_with_progress(
    api: &dyn AwsApi,
    team: &TeamDefinition,
    contract: &BuildContract,
    archive: &Path,
    directory: &Path,
    runtime: &impl Runtime,
    mut check_cancel: impl FnMut() -> Result<()>,
    progress: &mut BuildProgress<'_>,
) -> Result<BuildResult> {
    let infra = BuildInfrastructure::for_team(team)?;
    contract.verify_archive(archive)?;
    let (_lock, mut receipt) = open_attempt(directory, team, contract, &infra, None)?;
    ensure!(
        receipt.exporter.is_some(),
        "legacy build execution is retired; prepare a fresh native build attempt"
    );
    if receipt
        .terminal
        .as_deref()
        .is_some_and(|status| status != "SUCCEEDED")
    {
        progress(&receipt.observation(false)?)?;
    }
    ensure!(
        receipt.terminal.is_none() || receipt.terminal.as_deref() == Some("SUCCEEDED"),
        "build attempt is terminal: {:?}",
        receipt.terminal
    );
    save(directory, &receipt, progress)?;
    if !receipt.dispatched {
        check_cancel()?;
    }
    // Verify fixed infrastructure before uploading source or starting billed work.
    let project = api.call(
        "codebuild",
        "batch-get-projects",
        json!({"names":[infra.project_name]}),
        &[],
    )?;
    validate_project(&project, &infra)?;
    if !receipt.dispatched && receipt.reused.is_none() {
        receipt.reused = crate::build_reuse::lookup(api, &infra, contract, directory)?;
        save(directory, &receipt, progress)?;
    }
    if let Some(attempt) = receipt.reused {
        let result = validate_result(api, &infra, contract, attempt, directory)?;
        check_cancel()?;
        progress(&receipt.observation(true)?)?;
        return Ok(result);
    }
    let attempt = receipt.attempt_id;
    // Prepare and validate every private copy before starting either upload.
    // Keep the files alive until the batch has joined all of its workers.
    let mut uploads = Vec::new();
    if let Some(exporter) = receipt.exporter.as_ref().filter(|e| e.version.is_none()) {
        let mut helper = tempfile::NamedTempFile::new_in(directory)?;
        ensure!(
            crate::devnet::copy_file(
                &directory.join("exporter"),
                crate::devnet::MAX_HELPER_BYTES,
                helper.as_file_mut()
            )? == exporter.helper,
            "saved native exporter changed"
        );
        crate::devnet::validate_helper_file(helper.path())?;
        let checksum = STANDARD.encode(hex::decode(&exporter.helper.sha256)?);
        uploads.push((true, helper, json!({"Bucket":infra.source_bucket,"Key":exporter.key(attempt),"ExpectedBucketOwner":infra.account_id,"ServerSideEncryption":"AES256","ChecksumSHA256":checksum})));
    }
    if receipt.source_version.is_none() {
        // Upload a private copy, not a mutable path in the user's snapshot directory.
        let source = tempfile::NamedTempFile::new_in(directory)?;
        fs::copy(archive, source.path())?;
        contract.verify_archive(source.path())?;
        let checksum = STANDARD.encode(hex::decode(&contract.source_sha256)?);
        uploads.push((false, source, json!({"Bucket":infra.source_bucket,"Key":format!("sources/{}.tar",contract.source_sha256),"ExpectedBucketOwner":infra.account_id,"ServerSideEncryption":"AES256","ChecksumSHA256":checksum})));
    }
    if !uploads.is_empty() {
        let calls = uploads
            .iter()
            .map(|(_, file, input)| {
                Ok(AwsCall {
                    operation: "put-object",
                    input: input.clone(),
                    extra_args: vec![
                        "--body".into(),
                        file.path()
                            .to_str()
                            .context("non-UTF-8 upload path")?
                            .into(),
                    ],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        check_cancel()?;
        let results = api.batch_call("s3api", &calls)?;
        ensure!(results.len() == uploads.len(), "incomplete upload batch");
        let mut failure = None;
        for ((helper, _, input), uploaded) in uploads.iter().zip(results) {
            let saved = (|| -> Result<()> {
                let uploaded = uploaded?;
                ensure!(
                    uploaded["ChecksumSHA256"] == input["ChecksumSHA256"]
                        && uploaded["ServerSideEncryption"] == "AES256",
                    "S3 did not confirm upload checksum/encryption"
                );
                let version = uploaded["VersionId"]
                    .as_str()
                    .context("source bucket must have versioning enabled")?;
                validate_version(version)?;
                if *helper {
                    receipt.exporter.as_mut().unwrap().version = Some(version.into());
                } else {
                    receipt.source_version = Some(version.into());
                }
                save(directory, &receipt, progress)
            })();
            // A failed peer or observer must not discard another successful
            // upload. Persist all successes on this controller thread first.
            if let Err(error) = saved {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
    }
    if !receipt.dispatched {
        check_cancel()?;
    }
    let source_version = receipt
        .source_version
        .as_deref()
        .context("missing source version")?;
    let buildspec = crate::build_script::native_buildspec(
        contract,
        &infra,
        attempt,
        source_version,
        receipt
            .exporter
            .as_ref()
            .context("missing native exporter")?,
    )?;
    if receipt.dispatched && receipt.build_id.is_none() {
        receipt.build_id = Some(recover(
            api,
            &infra,
            &buildspec,
            runtime,
            &mut check_cancel,
        )?);
        save(directory, &receipt, progress)?;
    }
    if !receipt.dispatched {
        receipt.dispatched = true;
        save(directory, &receipt, progress)?;
        let started = api.call("codebuild", "start-build", json!({"projectName":infra.project_name,"idempotencyToken":attempt.to_string(),"buildspecOverride":buildspec}), &[])
        .context("StartBuild outcome may be unknown; do not resubmit this attempt automatically")?;
        let id = started["build"]["id"]
            .as_str()
            .context("StartBuild omitted build ID; inspect CodeBuild before retrying")?;
        validate_build(&started["build"], &infra, id)?;
        ensure!(
            started["build"]["source"]["buildspec"] == buildspec,
            "build source identity mismatch"
        );
        receipt.build_id = Some(id.to_owned());
        save(directory, &receipt, progress)?;
    }
    let id = receipt.build_id.as_deref().context("missing build ID")?;
    let deadline = runtime.monotonic() + Duration::from_secs(3 * 60 * 60 + 300);
    while receipt.terminal.as_deref() != Some("SUCCEEDED") {
        if let Err(error) = check_cancel().and_then(|_| {
            ensure!(
                runtime.monotonic() < deadline,
                "CodeBuild polling deadline exceeded"
            );
            Ok(())
        }) {
            let owned = api.call("codebuild", "batch-get-builds", json!({"ids":[id]}), &[])?;
            validate_jobs(&owned, &infra, &[id.to_owned()])?;
            ensure!(
                owned["builds"][0]["source"]["buildspec"] == buildspec,
                "build source identity mismatch"
            );
            if owned["builds"][0]["buildStatus"] != "IN_PROGRESS" {
                return Err(error);
            }
            api.call("codebuild", "stop-build", json!({"id":id}), &[])
                .with_context(|| format!("could not stop {id}; inspect it manually"))?;
            return Err(error).with_context(|| {
                format!("stop requested for {id}; termination is not yet confirmed")
            });
        }
        let response = api.call("codebuild", "batch-get-builds", json!({"ids":[id]}), &[])?;
        ensure!(
            response["buildsNotFound"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "CodeBuild job not found"
        );
        let builds = response["builds"]
            .as_array()
            .context("CodeBuild jobs missing")?;
        ensure!(builds.len() == 1, "CodeBuild returned unexpected jobs");
        validate_build(&builds[0], &infra, id)?;
        ensure!(
            builds[0]["source"]["buildspec"] == buildspec,
            "build source identity mismatch"
        );
        match builds[0]["buildStatus"].as_str() {
            Some("IN_PROGRESS") => runtime.sleep(Duration::from_secs(5)),
            Some("SUCCEEDED") => {
                receipt.terminal = Some("SUCCEEDED".into());
                save(directory, &receipt, progress)?;
                break;
            }
            Some("FAILED" | "FAULT" | "STOPPED" | "TIMED_OUT") => {
                receipt.terminal = builds[0]["buildStatus"].as_str().map(str::to_owned);
                save(directory, &receipt, progress)?;
                eyre::bail!(
                    "CodeBuild {id} ended with {}; no nodes allocated",
                    builds[0]["buildStatus"]
                )
            }
            _ => eyre::bail!("unknown CodeBuild status"),
        }
    }
    check_cancel()?;
    let result = validate_result(api, &infra, contract, attempt, directory)?;
    check_cancel()?;
    crate::build_reuse::publish(api, &infra, contract, attempt, directory)?;
    check_cancel()?;
    progress(&receipt.observation(true)?)?;
    Ok(result)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.validate_result")
)]
fn validate_result(
    api: &dyn AwsApi,
    infra: &BuildInfrastructure,
    contract: &BuildContract,
    attempt: Uuid,
    directory: &Path,
) -> Result<BuildResult> {
    let result_bytes = download(
        api,
        infra,
        attempt,
        "result.json",
        image::MAX_RECORD_BYTES,
        directory,
    )?;
    let result: BuildResult =
        serde_json::from_slice(&result_bytes).context("decode build result")?;
    ensure!(
        result.contract_sha256 == contract.fingerprint()?,
        "build result contract mismatch"
    );
    contract.validate_image(&result.image)?;
    ensure!(
        result.image.image.split_once('@').map(|v| v.0) == Some(infra.repository_uri.as_str()),
        "build result repository differs from team build repository"
    );
    let downloads = [
        prepare_download(
            infra,
            attempt,
            "image-manifest.json",
            image::MAX_MANIFEST_BYTES,
            directory,
        )?,
        prepare_download(
            infra,
            attempt,
            "image-config.json",
            image::MAX_CONFIG_BYTES,
            directory,
        )?,
    ];
    let calls = downloads
        .iter()
        .map(|(_, call)| AwsCall {
            operation: call.operation,
            input: call.input.clone(),
            extra_args: call.extra_args.clone(),
        })
        .collect::<Vec<_>>();
    let responses = api.batch_call("s3api", &calls)?;
    ensure!(
        responses.len() == downloads.len(),
        "incomplete result batch"
    );
    let mut responses = responses.into_iter();
    let manifest = read_download(
        &downloads[0].0,
        responses.next().unwrap()?,
        image::MAX_MANIFEST_BYTES,
    )?;
    let config = read_download(
        &downloads[1].0,
        responses.next().unwrap()?,
        image::MAX_CONFIG_BYTES,
    )?;
    let verified = image::validate_manifest_bytes(&result.image, &manifest)?;
    image::validate_config_bytes(&result.image, &verified, &config)?;
    // Observe the immutable digest independently in ECR, not just in job output.
    let observed = api.call("ecr", "batch-get-image", json!({"registryId":infra.account_id,"repositoryName":infra.repository,"imageIds":[{"imageDigest":result.image.manifest_digest()?}],"acceptedMediaTypes":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"]}), &[])?;
    ensure!(
        observed["failures"].as_array().is_some_and(Vec::is_empty)
            && observed["images"]
                .as_array()
                .is_some_and(|images| images.len() == 1
                    && images[0]["imageId"]["imageDigest"]
                        == result.image.manifest_digest().unwrap_or_default()
                    && images[0]["imageManifest"]
                        .as_str()
                        .is_some_and(|s| s.as_bytes() == manifest)),
        "ECR differs from verified build result"
    );
    for (name, bytes) in [
        ("image.json", serde_json::to_vec_pretty(&result.image)?),
        ("image-manifest.json", manifest),
        ("image-config.json", config),
        ("result.json", result_bytes),
    ] {
        crate::foundation::write_private(&directory.join(name), &bytes)?;
    }
    Ok(result)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.validate_project")
)]
fn validate_project(response: &Value, infra: &BuildInfrastructure) -> Result<()> {
    let projects = response["projects"]
        .as_array()
        .context("CodeBuild project missing; repeat administrator setup")?;
    ensure!(
        response["projectsNotFound"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && projects.len() == 1,
        "CodeBuild project missing; repeat administrator setup"
    );
    let p = &projects[0];
    ensure!(
        p["name"] == infra.project_name
            && p["arn"]
                == format!(
                    "arn:aws:codebuild:{}:{}:project/{}",
                    infra.region, infra.account_id, infra.project_name
                ),
        "wrong CodeBuild project"
    );
    ensure!(
        p["environment"]["type"] == "LINUX_CONTAINER"
            && p["environment"]["image"] == "aws/codebuild/standard:7.0"
            && p["environment"]["computeType"] == "BUILD_GENERAL1_MEDIUM"
            && p["environment"]["privilegedMode"] == true
            && p["source"]["type"] == "NO_SOURCE"
            && p["artifacts"]["type"] == "NO_ARTIFACTS",
        "CodeBuild project must use the fixed native Docker executor"
    );
    crate::build_script::validate_project_cache(p, infra)?;
    Ok(())
}

fn validate_build(build: &Value, infra: &BuildInfrastructure, id: &str) -> Result<()> {
    validate_build_id(id, infra)?;
    ensure!(
        build["id"] == id
            && build["projectName"] == infra.project_name
            && build["arn"]
                == format!(
                    "arn:aws:codebuild:{}:{}:build/{id}",
                    infra.region, infra.account_id
                ),
        "CodeBuild returned a different job"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.download")
)]
fn download(
    api: &dyn AwsApi,
    infra: &BuildInfrastructure,
    attempt: Uuid,
    name: &str,
    limit: usize,
    directory: &Path,
) -> Result<Vec<u8>> {
    let (file, call) = prepare_download(infra, attempt, name, limit, directory)?;
    let response = api.call("s3api", call.operation, call.input, &call.extra_args)?;
    read_download(&file, response, limit)
}

fn prepare_download(
    infra: &BuildInfrastructure,
    attempt: Uuid,
    name: &str,
    limit: usize,
    directory: &Path,
) -> Result<(tempfile::NamedTempFile, AwsCall<'static>)> {
    let file = tempfile::NamedTempFile::new_in(directory)?;
    let call = AwsCall {
        operation: "get-object",
        input: json!({"Bucket":infra.source_bucket,"Key":format!("results/{attempt}/{name}"),"ExpectedBucketOwner":infra.account_id,"Range":format!("bytes=0-{limit}")}),
        extra_args: vec![file
            .path()
            .to_str()
            .context("non-UTF-8 result path")?
            .into()],
    };
    Ok((file, call))
}

fn read_download(file: &tempfile::NamedTempFile, response: Value, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response["ServerSideEncryption"] == "AES256",
        "build result encryption mismatch"
    );
    let mut bytes = Vec::new();
    fs::File::open(file.path())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "invalid build result size"
    );
    Ok(bytes)
}

pub use crate::build_script::native_buildspec;

fn save(directory: &Path, receipt: &Attempt, progress: &mut BuildProgress<'_>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(receipt)?;
    ensure!(bytes.len() <= 65536, "build receipt exceeds size bound");
    crate::foundation::write_private(&directory.join("attempt.json"), &bytes)?;
    progress(&receipt.observation(false)?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.private_open")
)]
fn private_open(path: &Path, create: bool) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "receipt and lock must be regular files");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.permissions().mode() & 0o077 == 0
                && metadata.uid()
                    == fs::metadata(path.parent().context("receipt needs parent")?)?.uid()
                && metadata.nlink() == 1,
            "receipt and lock must be private owned files"
        );
    }
    Ok(file)
}

fn validate_version(version: &str) -> Result<()> {
    ensure!(
        !version.is_empty()
            && version != "null"
            && version.len() <= 1024
            && !version.chars().any(char::is_control),
        "invalid source object version"
    );
    Ok(())
}

fn validate_build_id(id: &str, infra: &BuildInfrastructure) -> Result<()> {
    let suffix = id
        .strip_prefix(&format!("{}:", infra.project_name))
        .context("build ID belongs to a different project")?;
    let uuid = Uuid::parse_str(suffix).context("invalid build ID")?;
    ensure!(
        uuid.to_string() == suffix
            && uuid.get_version_num() == 4
            && uuid.get_variant() == uuid::Variant::RFC4122,
        "invalid build ID"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.validate_jobs")
)]
fn validate_jobs(response: &Value, infra: &BuildInfrastructure, ids: &[String]) -> Result<()> {
    ensure!(
        response["buildsNotFound"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "incomplete CodeBuild recovery results"
    );
    let jobs = response["builds"]
        .as_array()
        .context("missing CodeBuild jobs")?;
    ensure!(
        jobs.len() == ids.len(),
        "incomplete CodeBuild recovery results"
    );
    let mut seen = std::collections::HashSet::new();
    for job in jobs {
        let id = job["id"].as_str().context("missing job ID")?;
        ensure!(
            ids.iter().any(|v| v == id) && seen.insert(id),
            "unexpected or duplicate CodeBuild job"
        );
        validate_build(job, infra, id)?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_job.recover")
)]
fn recover(
    api: &dyn AwsApi,
    infra: &BuildInfrastructure,
    spec: &str,
    runtime: &impl Runtime,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<String> {
    let deadline = runtime.monotonic() + Duration::from_secs(300);
    let mut token: Option<String> = None;
    let mut tokens = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    let mut matches = Vec::new();
    for _ in 0..100 {
        check()?;
        ensure!(
            runtime.monotonic() < deadline,
            "CodeBuild recovery deadline exceeded"
        );
        // Explicit sortOrder is rejected by AWS for projects with >100 builds.
        let mut input = json!({"projectName":infra.project_name});
        if let Some(t) = &token {
            input["nextToken"] = json!(t);
        }
        let page = api.call(
            "codebuild",
            "list-builds-for-project",
            input,
            &["--no-paginate".into()],
        )?;
        let ids = page["ids"]
            .as_array()
            .context("missing recovery build IDs")?;
        ensure!(ids.len() <= 100, "recovery page exceeds bound");
        let ids: Vec<String> = ids
            .iter()
            .map(|v| v.as_str().map(str::to_owned).context("invalid recovery ID"))
            .collect::<Result<_>>()?;
        for id in &ids {
            validate_build_id(id, infra)?;
            ensure!(seen.insert(id.clone()), "duplicate recovery ID");
        }
        if !ids.is_empty() {
            check()?;
            ensure!(
                runtime.monotonic() < deadline,
                "CodeBuild recovery deadline exceeded"
            );
            let response = api.call("codebuild", "batch-get-builds", json!({"ids":ids}), &[])?;
            validate_jobs(&response, infra, &ids)?;
            for job in response["builds"].as_array().context("missing jobs")? {
                if job["source"]["buildspec"] == spec {
                    matches.push(job["id"].as_str().context("missing ID")?.to_owned());
                }
            }
        }
        check()?;
        ensure!(
            runtime.monotonic() < deadline,
            "CodeBuild recovery deadline exceeded"
        );
        match page.get("nextToken") {
            None | Some(Value::Null) => {
                ensure!(
                    matches.len() == 1,
                    "uncertain CodeBuild submission has {} exact matches; refusing redispatch",
                    matches.len()
                );
                return Ok(matches.remove(0));
            }
            Some(value) => {
                let next = value.as_str().context("invalid recovery token")?;
                ensure!(
                    !next.is_empty() && next.len() <= 4096 && tokens.insert(next.to_owned()),
                    "invalid or repeated recovery token"
                );
                token = Some(next.to_owned());
            }
        }
    }
    eyre::bail!("CodeBuild recovery scan incomplete; refusing redispatch")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_recovery_is_not_blocked_by_an_inherited_lock_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("build");
        let team: TeamDefinition = serde_json::from_value(json!({
            "apiVersion":"zdn-team/v1alpha1","teamId":"test-team","revision":1,
            "bootstrapId":"a81c4e9b-4612-4e0d-a3fa-c4ab68a04153",
            "aws":{"accountId":"123456789012","region":"us-east-1"},
            "state":{"backend":"s3://zdn-test-state/pulumi/zdn","kmsKeyArn":"arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"}
        })).unwrap();
        let contract = BuildContract {
            api_version: crate::build::API_VERSION.into(),
            source_sha256: "ab".repeat(32),
            source_bytes: 1,
            revision: "12".repeat(20),
            recipe: crate::build::BuildRecipe {
                dockerfile: "docker/Dockerfile".into(),
                context: ".".into(),
                target: "runtime".into(),
            },
            platform: "linux/amd64".into(),
            required_capabilities: Default::default(),
        };
        let helper = root.path().join("helper");
        let mut bytes = [0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        fs::write(&helper, bytes).unwrap();
        let prepare = || prepare_native(&directory, &team, &contract, &helper);
        prepare().unwrap();
        let owner = lock_preparation(&directory, &team, &contract).unwrap();
        // Model the shared open-file description held between fork and exec.
        let inherited = owner.0.try_clone().unwrap();
        assert!(prepare().is_err());
        drop(owner);
        prepare().unwrap();
        let next = lock_preparation(&directory, &team, &contract).unwrap();
        drop(inherited);
        assert!(prepare().is_err());
        drop(next);
        prepare().unwrap();
    }
}
