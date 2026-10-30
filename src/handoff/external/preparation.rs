//! Source preparation is a separate explicit external state, never ordinary
//! Preparation selected just because the cluster field is absent.
use super::*;
use crate::foundation::external::source::{SourcePreparation, FILE, ROOT};

fn saved(manifest: &Manifest) -> Result<&SourcePreparation> {
    manifest
        .deployment
        .external_source
        .as_ref()
        .context("missing external source preparation")
}

pub(super) fn file_limit(manifest: &Manifest, path: &str) -> Result<u64> {
    let source = saved(manifest)?;
    if path == FILE {
        return Ok(MAX_MANIFEST_BYTES);
    }
    let name = path
        .strip_prefix(&format!("{ROOT}/"))
        .context("unknown external preparation file")?;
    if name == FILE {
        return Ok(MAX_MANIFEST_BYTES);
    }
    if let Some(name) = name.strip_prefix("public/") {
        return source
            .artifacts
            .get(name)
            .map(|a| a.bytes)
            .context("unknown external preparation public slot");
    }
    if let Some(name) = name.strip_prefix("build/") {
        return super::build_limit(name);
    }
    match name {
        "source-snapshot/source.tar" => Ok(source.contract.source_bytes),
        "source-snapshot/receipt.json" => Ok(MAX_MANIFEST_BYTES),
        _ => eyre::bail!("unknown external preparation slot"),
    }
}

pub(super) fn validate(manifest: &Manifest) -> Result<()> {
    let source = saved(manifest)?;
    source.validate(&manifest.deployment)?;
    manifest.require(&format!("{ROOT}/{FILE}"))?;
    for (name, artifact) in &source.artifacts {
        ensure!(
            manifest.files.get(&format!("{ROOT}/public/{name}")) == Some(artifact),
            "external source public inventory differs"
        );
    }
    for name in [
        "source-snapshot/source.tar",
        "source-snapshot/receipt.json",
        "build/attempt.json",
    ] {
        manifest.require(&format!("{ROOT}/{name}"))?;
    }
    if manifest.deployment.external.is_none() {
        let deployment = &manifest.deployment;
        ensure!(
            deployment.cluster.is_none()
                && deployment.runtime.is_none()
                && deployment.last_operation.is_none()
                && deployment.unresolved_operation.is_none()
                && !deployment.stack_initialized
                && deployment.outputs.is_none()
                && manifest.operations.is_empty()
                && manifest.updates.is_empty(),
            "external source preparation contains operation effects"
        );
        ensure!(
            manifest.files.len() <= 32,
            "external source preparation inventory exceeds bound"
        );
        for (path, artifact) in &manifest.files {
            devnet::validate_hash(&artifact.sha256)?;
            ensure!(
                artifact.bytes <= file_limit(manifest, path)?,
                "external source preparation file exceeds bound"
            );
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.external.preparation.verify")
)]
pub(super) fn verify(manifest: &Manifest, root: &Path) -> Result<()> {
    let source = saved(manifest)?;
    source.verify_local(&manifest.deployment, root)?;
    let trust: crate::public_chain_adapter::package::CoreTrust =
        serde_json::from_value(source.trust.clone())?;
    let public = root.join(ROOT).join("public");
    let inspected = PublicPackage::inspect(
        &read(manifest, root, &format!("{ROOT}/public/package.json"))?,
        &trust.package,
        &public,
    )?;
    ensure!(
        inspected.compiled_result == source.compiled_json.as_bytes()
            && inspected.manifest.host_adapter.adapter_selection_sha256
                == trust.adapter_selection_sha256
            && inspected.manifest.host_adapter.executable_sha256 == trust.executable.sha256
            && inspected.manifest.host_adapter.executable_bytes == trust.executable.bytes,
        "external preparation package selection differs"
    );
    devnet::validate_helper_file(&public.join("zdn"))?;
    let prefix = format!("{ROOT}/build");
    let observation = crate::build_job::validate_preparation(
        &root.join(&prefix),
        &manifest.deployment.team,
        &source.contract,
    )?;
    if let Some(helper) = observation.exporter_helper {
        ensure!(
            manifest.files.get(&format!("{prefix}/exporter")) == Some(&helper),
            "external source exporter differs"
        );
    }
    let outputs = [
        "result.json",
        "image.json",
        "image-manifest.json",
        "image-config.json",
    ];
    if outputs
        .iter()
        .any(|name| manifest.files.contains_key(&format!("{prefix}/{name}")))
    {
        ensure!(
            observation.job_outcome == Some("succeeded") || observation.reused_from.is_some(),
            "external source output is not backed by a successful build"
        );
        for name in outputs {
            manifest.require(&format!("{prefix}/{name}"))?;
        }
        crate::build_job::removal_evidence(&root.join(&prefix), &manifest.deployment.team)?;
        let result: crate::build_job::BuildResult =
            serde_json::from_slice(&read(manifest, root, &format!("{prefix}/result.json"))?)?;
        ensure!(
            result.contract_sha256 == source.contract.fingerprint()?,
            "external source result contract differs"
        );
        source.contract.validate_image(&result.image)?;
        let compiled: crate::public_chain_adapter::contract::Compiled =
            serde_json::from_str(&source.compiled_json)?;
        let requirements = compiled.image_requirements()?;
        let image = crate::image::ImageRecord::from_json_for_requirements(
            &read(manifest, root, &format!("{prefix}/image.json"))?,
            &requirements,
        )?;
        ensure!(
            image == result.image,
            "external source result image differs"
        );
        let proof = crate::image::validate_manifest_bytes_for_requirements(
            &image,
            &requirements,
            &read(manifest, root, &format!("{prefix}/image-manifest.json"))?,
        )?;
        crate::image::validate_config_bytes_for_requirements(
            &image,
            &requirements,
            &proof,
            &read(manifest, root, &format!("{prefix}/image-config.json"))?,
        )?;
        if let Some(external) = &manifest.deployment.external {
            ensure!(
                image == external.typed_request()?.image,
                "external source build and staged image differ"
            );
        }
    } else {
        ensure!(
            manifest.deployment.external.is_none(),
            "completed external source image proof missing"
        );
    }
    Ok(())
}
