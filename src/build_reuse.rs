//! Team-scoped exact-contract index, never proof that an image is usable.
//!
//! The caller must download `results/{attempt}/result.json`, manifest and config,
//! then perform all contract, image and independent ECR validation before reuse.
//! Neither tags nor local image records are consulted here.

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

use crate::{
    aws::{AwsApi, AwsApiError},
    build::BuildContract,
    build_infra::BuildInfrastructure,
};

pub(crate) const MAX_BYTES: usize = 4096;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pointer {
    version: u32,
    contract_sha256: String,
    attempt: Uuid,
    source_bucket: String,
    project_name: String,
    repository: String,
    repository_uri: String,
    account_id: String,
    region: String,
}

impl Pointer {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build_reuse.pointer.new")
    )]
    fn new(infra: &BuildInfrastructure, contract: &BuildContract, attempt: Uuid) -> Result<Self> {
        ensure!(
            attempt.get_version_num() == 4 && attempt.get_variant() == uuid::Variant::RFC4122,
            "reuse attempt must be a v4 UUID"
        );
        Ok(Self {
            version: 1,
            contract_sha256: contract.fingerprint()?,
            attempt,
            source_bucket: infra.source_bucket.clone(),
            project_name: infra.project_name.clone(),
            repository: infra.repository.clone(),
            repository_uri: infra.repository_uri.clone(),
            account_id: infra.account_id.clone(),
            region: infra.region.clone(),
        })
    }
}

/// Return only a bound attempt pointer; no build outputs are downloaded or validated.
/// Only a typed S3 NoSuchKey is a miss. Every other failure is actionable.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_reuse.lookup")
)]
pub fn lookup(
    api: &dyn AwsApi,
    infra: &BuildInfrastructure,
    contract: &BuildContract,
    directory: &Path,
) -> Result<Option<Uuid>> {
    let key = format!("images/{}.json", contract.fingerprint()?);
    let file = tempfile::NamedTempFile::new_in(directory)?;
    let response = match api.call("s3api", "get-object", json!({"Bucket":infra.source_bucket,"Key":key,"ExpectedBucketOwner":infra.account_id,"Range":format!("bytes=0-{MAX_BYTES}")}), &[file.path().to_str().context("non-UTF-8 reuse path")?.into()]) {
        Ok(response) => response,
        Err(error) if error.downcast_ref::<AwsApiError>().is_some_and(|e| e.code == "NoSuchKey") => return Ok(None),
        Err(error) => return Err(error),
    };
    ensure!(
        response["ServerSideEncryption"] == "AES256",
        "reuse index encryption mismatch"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(file.path())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BYTES,
        "invalid reuse index size"
    );
    let pointer: Pointer = serde_json::from_slice(&bytes).context("invalid reuse index")?;
    ensure!(
        pointer == Pointer::new(infra, contract, pointer.attempt)?,
        "reuse index contract or team infrastructure mismatch"
    );
    Ok(Some(pointer.attempt))
}

/// Publish only after the caller has fully verified the attempt's outputs.
/// First writer wins: an existing valid bound pointer is preserved, including
/// one naming a different attempt. A conflict without a visible pointer fails;
/// an unknown write outcome fails and can be recovered by rerunning publication.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_reuse.publish")
)]
pub fn publish(
    api: &dyn AwsApi,
    infra: &BuildInfrastructure,
    contract: &BuildContract,
    attempt: Uuid,
    directory: &Path,
) -> Result<()> {
    let pointer = Pointer::new(infra, contract, attempt)?;
    let bytes = serde_json::to_vec(&pointer)?;
    ensure!(bytes.len() <= MAX_BYTES, "reuse index exceeds size limit");
    let checksum = STANDARD.encode(Sha256::digest(&bytes));
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(&bytes)?;
    let response = api.call("s3api", "put-object", json!({"Bucket":infra.source_bucket,"Key":format!("images/{}.json",pointer.contract_sha256),"ExpectedBucketOwner":infra.account_id,"IfNoneMatch":"*","ServerSideEncryption":"AES256","ContentType":"application/json","ChecksumSHA256":checksum}), &["--body".into(), file.path().to_str().context("non-UTF-8 reuse path")?.into()]);
    match response {
        Ok(response) => {
            ensure!(
                response["ChecksumSHA256"] == checksum
                    && response["ServerSideEncryption"] == "AES256",
                "S3 did not confirm reuse index checksum/encryption; publication outcome unknown"
            );
            Ok(())
        }
        Err(error)
            if error.downcast_ref::<AwsApiError>().is_some_and(|e| {
                matches!(
                    e.code.as_str(),
                    "PreconditionFailed" | "ConditionalRequestConflict"
                )
            }) =>
        {
            if lookup(api, infra, contract, directory)?.is_some() {
                Ok(())
            } else {
                bail!("reuse index conditional conflict without an existing pointer; retry publication")
            }
        }
        Err(error) => Err(error)
            .context("reuse index publication failed; outcome may be unknown, rerun to recover"),
    }
}
