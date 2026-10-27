//! Native build-result exporter. This checks metadata, not layer contents or
//! runtime behavior.

use eyre::{ensure, Context, ContextCompat, Result};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::Path,
};

use crate::{
    build::BuildContract,
    build_job::BuildResult,
    image::{self, ImageProvenance, ImageRecord},
};

pub const PROTOCOL: &str = "zdn-build-export/v1alpha2";

// JSON escaping can expand each manifest byte to six bytes in the ECR envelope.
const MAX_REGISTRY_BYTES: usize = 6 * image::MAX_MANIFEST_BYTES + 64 * 1024;

/// Export registry metadata using only the configuration blob, never image layers.
/// Validate all inputs before creating a new output directory. Existing output
/// paths (including symlinks) are never reused. I/O failures during publication
/// can leave an incomplete new directory; callers must not treat it as success.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "build_export.export_downloaded_config")
)]
pub fn export_downloaded_config(
    contract: &BuildContract,
    repository: &str,
    registry: &Path,
    download_response: &Path,
    output: &Path,
    downloader: &dyn crate::dependencies::Downloader,
) -> Result<()> {
    contract.validate()?;
    let response: Value =
        serde_json::from_slice(&bounded(File::open(registry)?, MAX_REGISTRY_BYTES)?)
            .context("decode ECR response")?;
    ensure!(
        response
            .get("failures")
            .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty)),
        "ECR response must contain no failures"
    );
    let images = response["images"]
        .as_array()
        .context("missing ECR images")?;
    ensure!(images.len() == 1, "ECR must return exactly one image");
    let manifest = images[0]["imageManifest"]
        .as_str()
        .context("missing ECR image manifest")?
        .as_bytes();
    ensure!(
        !manifest.is_empty() && manifest.len() <= image::MAX_MANIFEST_BYTES,
        "invalid image manifest size"
    );
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest)));
    ensure!(
        images[0]["imageId"]["imageDigest"] == digest,
        "ECR image digest mismatch"
    );
    let parsed: Value = serde_json::from_slice(manifest)?;
    let record = ImageRecord {
        api_version: image::API_VERSION.into(),
        image: format!("{repository}@{digest}"),
        config_digest: parsed["config"]["digest"]
            .as_str()
            .context("missing configuration digest")?
            .into(),
        platform: contract.platform.clone(),
        provenance: ImageProvenance::Source {
            revision: contract.revision.clone(),
            snapshot_sha256: contract.source_sha256.clone(),
        },
        capabilities: contract.required_capabilities.clone(),
        binary_path: image::NODE_BINARY.into(),
        environment_launcher: image::ENV_ENTRYPOINT.into(),
    };
    contract.validate_image(&record)?;
    ensure!(
        record.image.split_once('@').map(|v| v.0) == Some(repository),
        "repository must be an untagged supported image repository"
    );
    let verified = image::validate_manifest_bytes(&record, manifest)?;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DownloadResponse {
        download_url: String,
        layer_digest: String,
    }
    // Never include response values (in particular presigned URLs) in errors.
    let response: DownloadResponse =
        serde_json::from_slice(&bounded(File::open(download_response)?, 64 * 1024)?)
            .map_err(|_| eyre::eyre!("invalid ECR configuration download response"))?;
    ensure!(
        response.layer_digest == record.config_digest,
        "ECR configuration download digest mismatch"
    );
    ensure!(
        !response.download_url.is_empty(),
        "missing ECR configuration download URL"
    );
    let mut file = tempfile::tempfile()?;
    downloader
        .download(
            &response.download_url,
            &mut file,
            image::MAX_CONFIG_BYTES as u64,
        )
        .map_err(|_| eyre::eyre!("configuration download failed"))?;
    file.rewind()?;
    let config = bounded(file, image::MAX_CONFIG_BYTES)?;
    image::validate_config_bytes(&record, &verified, &config)?;
    let result = serde_json::to_vec(&BuildResult {
        contract_sha256: contract.fingerprint()?,
        image: record,
    })?;
    ensure!(
        result.len() <= image::MAX_RECORD_BYTES,
        "build result too large"
    );

    fs::create_dir(output).context("create new export directory")?;
    for (name, bytes) in [
        ("result.json", result.as_slice()),
        ("image-manifest.json", manifest),
        ("image-config.json", config.as_slice()),
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))?
            .write_all(bytes)?;
    }
    Ok(())
}

fn bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "invalid metadata size"
    );
    Ok(bytes)
}
