//! Offline external evidence admission. No prepare/render/companion execution.
//! Uses the existing archive publisher and state transaction; these are not
//! replacement lifecycle records. The private wire records mirror the controller.
use super::{Manifest, MAX_MANIFEST_BYTES};
use crate::{
    devnet::{self, external::ExternalRequest, Artifact},
    foundation::{self, Deployment},
    host::external::{identity, runtime, Provisioning},
    native_peers::{NativeCohort, NativeInventoryStore},
    public_chain_adapter::{contract::Pin, package::PublicPackage},
    state::PhaseStatus,
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

mod controls;
mod preparation;
mod volumes;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveImage {
    update_id: Uuid,
    image: String,
    runtime: Pin,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Evidence {
    schema: String,
    request: Pin,
    cohort: Pin,
    inventory: Pin,
    inventory_json: String,
    pending_identity: Option<String>,
    manifests: BTreeMap<String, Pin>,
    pending_update: Option<Uuid>,
    active_images: BTreeMap<String, ActiveImage>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema: String,
    id: Uuid,
    deployment_id: Uuid,
    request: Pin,
    image: crate::image::ImageRecord,
    artifacts: BTreeMap<String, Artifact>,
    nodes: BTreeMap<String, Pin>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    schema: String,
    id: Uuid,
    deployment_id: Uuid,
    request: Pin,
    nodes: Vec<String>,
    original_config: crate::config::Config,
    candidate_config: crate::config::Config,
    contract: crate::build::BuildContract,
}

fn request(manifest: &Manifest) -> Result<ExternalRequest> {
    manifest
        .deployment
        .external
        .as_ref()
        .context("missing external ownership")?
        .typed_request()
}

fn uuid(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value)?;
    ensure!(
        id.to_string() == value
            && id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122,
        "noncanonical external recovery UUID"
    );
    Ok(id)
}

fn nodes(manifest: &Manifest) -> Result<BTreeSet<String>> {
    Ok(manifest
        .deployment
        .node_topology()?
        .nodes()
        .into_iter()
        .map(|n| n.node_id)
        .collect())
}

/// Walk only the named evidence containers, never arbitrary controller/host
/// directories. Unknown children fail closed; known private workspaces are not
/// entered at all. The shared tar importer independently enforces exact paths.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.external.inventory")
)]
pub(super) fn inventory(
    manifest: &mut Manifest,
    source: &Path,
    staging: &Path,
    prefix: &str,
    total: &mut u64,
) -> Result<()> {
    for entry in std::fs::read_dir(source.join(prefix))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eyre::eyre!("invalid external evidence filename"))?;
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = std::fs::symlink_metadata(entry.path())?.file_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "external handoff refuses links and special files"
        );
        if prefix.is_empty() {
            if matches!(
                name.as_str(),
                "credentials" | "project" | "diagnostics" | "health" | "source-preparation"
            ) {
                ensure!(kind.is_dir(), "excluded workspace must be a real directory");
                continue;
            }
            if matches!(
                name.as_str(),
                "deployment.json"
                    | ".zdn-pulumi-process.json"
                    | "operation.lock"
                    | ".zdn-source-capture.lock"
                    | "source-build-inputs.json"
                    | "source-preparation.json"
            ) || name.ends_with(".json.lock")
            {
                ensure!(kind.is_file(), "excluded metadata must be a regular file");
                continue;
            }
        }
        if prefix == "native-inventory" && name == "inventory.lock" {
            ensure!(kind.is_file(), "native inventory lock must be regular");
            continue;
        }
        let build = prefix == "build"
            || prefix == "external-source/build"
            || (prefix.starts_with("external-updates/")
                && prefix.split('/').count() == 3
                && prefix.ends_with("/build"));
        if build
            && matches!(
                name.as_str(),
                "attempt.lock" | "image.json.lock" | "result.json.lock"
            )
        {
            ensure!(kind.is_file(), "build lock must be regular");
            continue;
        }
        if prefix.starts_with("external-updates/")
            && prefix.split('/').count() == 2
            && name.ends_with("-command.json.lock")
        {
            ensure!(kind.is_file(), "command lock must be regular");
            continue;
        }
        if prefix.starts_with("external-controls/")
            && prefix.split('/').count() == 2
            && name == "command.json.lock"
        {
            ensure!(kind.is_file(), "command lock must be regular");
            continue;
        }
        if kind.is_dir() {
            let allowed = if prefix.is_empty() {
                matches!(
                    name.as_str(),
                    "artifacts"
                        | "native-inventory"
                        | "external-updates"
                        | "external-controls"
                        | "build"
                        | "source-snapshot"
                        | "external-source"
                )
            } else if prefix == "external-updates" || prefix == "external-controls" {
                uuid(&name)?;
                true
            } else if prefix == "external-source" {
                matches!(name.as_str(), "public" | "build" | "source-snapshot")
            } else {
                prefix.starts_with("external-updates/")
                    && prefix.split('/').count() == 2
                    && matches!(name.as_str(), "build" | "source-snapshot")
            };
            ensure!(allowed, "unsupported external evidence directory: {path}");
            foundation::private_directory(&staging.join(&path))?;
            inventory(manifest, source, staging, &path, total)?;
            continue;
        }
        let limit = manifest.file_limit(&path)?;
        let artifact = devnet::snapshot_file(&entry.path(), &staging.join(&path), limit)?;
        *total = total
            .checked_add(artifact.bytes)
            .context("external handoff size overflow")?;
        ensure!(
            *total <= super::MAX_ARCHIVE_BYTES && manifest.files.len() < 1024,
            "external handoff exceeds bound"
        );
        manifest.files.insert(path, artifact);
    }
    Ok(())
}

pub(super) fn validate(manifest: &Manifest) -> Result<()> {
    let deployment = &manifest.deployment;
    ensure!(
        deployment.cluster.is_none() && deployment.runtime.is_none() && manifest.updates.is_empty(),
        "external handoff cannot contain ordinary request/update state"
    );
    if deployment.external.is_none() {
        return preparation::validate(manifest);
    }
    if deployment.external_source.is_some() {
        preparation::validate(manifest)?;
    }
    let request = request(manifest)?;
    ensure!(
        manifest.files.len() <= 1024,
        "external inventory exceeds bound"
    );
    for (path, artifact) in &manifest.files {
        devnet::validate_hash(&artifact.sha256)?;
        ensure!(
            artifact.bytes <= file_limit(manifest, path)?,
            "external recovery file exceeds bound"
        );
    }
    manifest.require("artifacts/external-request.json")?;
    for (name, artifact) in &request.artifacts {
        ensure!(
            manifest.files.get(&format!("artifacts/{name}")) == Some(artifact),
            "external public artifact inventory differs from request"
        );
    }
    let mut ids = BTreeSet::new();
    for operation in &manifest.operations {
        operation.validate()?;
        ensure!(
            operation.network_id == manifest.binding.network_id
                && operation.scope == manifest.binding.scope
                && ids.insert(operation.operation_id),
            "foreign or duplicate external operation"
        );
    }
    if let Some(last) = deployment.last_operation {
        let operation = manifest
            .operations
            .iter()
            .find(|op| op.operation_id == last)
            .context("missing external last operation")?;
        ensure!(
            matches!(
                operation.kind.as_str(),
                "external-up" | "external-update" | "external-control"
            ) && !operation.cancel_requested,
            "external handoff requires up/update/control evidence"
        );
        let phases: &[&str] = if operation.kind == "external-up" {
            &[
                "verify",
                "reserve",
                "lease",
                "prepare",
                "preview",
                "apply",
                "install",
                "readiness",
            ]
        } else if operation.kind == "external-control" {
            controls::PHASES
        } else {
            &[
                "verify",
                "reserve",
                "lease",
                "preflight",
                "build",
                "update",
                "readiness",
            ]
        };
        ensure!(
            operation
                .phases
                .iter()
                .map(|p| p.name.as_str())
                .eq(phases.iter().copied()),
            "external operation phase contract differs"
        );
        if operation.kind == "external-up" {
            ensure!(
                operation.inputs.config_sha256
                    == devnet::sha256(&serde_json::to_vec(&(
                        &deployment.spec,
                        &deployment.team,
                        deployment.owner_id,
                        Option::<bool>::None,
                        deployment
                            .external
                            .as_ref()
                            .context("missing external deployment")?,
                    ))?)
                    && operation.inputs.source_manifest_sha256.is_none()
                    && operation.inputs.archive_sha256.is_none(),
                "external up operation identity differs"
            );
        }
        ensure!(
            deployment.stack_initialized && deployment.outputs.is_some(),
            "external outputs missing"
        );
        // Unknown update/control outcomes stay unresolved. Their saved intent
        // and command histories are authenticated below, without cloud calls.
        ensure!(
            deployment.unresolved_operation.is_none_or(|id| id == last
                && matches!(
                    operation.kind.as_str(),
                    "external-update" | "external-control"
                )),
            "foreign unresolved external operation"
        );
        ensure!(
            deployment.unresolved_operation.is_some()
                || operation
                    .phases
                    .iter()
                    .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. })),
            "external operation must be completed or an identified unresolved mutation"
        );
        manifest.require("external-evidence.json")?;
        manifest.require("native-inventory/cohort.json")?;
        for node in nodes(manifest)? {
            for suffix in [
                "external-provisioning.json",
                "external-identity.json",
                "external-identity-install.sh",
                "external-identity-command.json",
                "external-runtime.json",
                "external-runtime-install.sh",
                "external-install-command.json",
            ] {
                manifest.require(&format!("{node}-{suffix}"))?;
            }
            manifest.require(&format!("native-inventory/{node}.json"))?;
            let receipt = manifest
                .files
                .contains_key(&format!("{node}-new-volume.json"));
            ensure!(
                receipt
                    == manifest
                        .files
                        .contains_key(&format!("{node}-new-volume-checkpoint.json"))
                    && (!receipt || manifest.files.contains_key("new-volume-creation.json"))
                    && (!manifest.files.contains_key("new-volume-creation.json") || receipt),
                "incomplete external new-volume proof chain"
            );
        }
        for name in [
            "node-1-external-start-producer-command.json",
            "node-1-external-gateway-install-command.json",
            "client-endpoints.json",
        ] {
            manifest.require(name)?;
        }
    } else {
        ensure!(
            deployment.unresolved_operation.is_none()
                && !deployment.stack_initialized
                && deployment.outputs.is_none()
                && manifest.operations.is_empty()
                && manifest.files.keys().all(|p| p.starts_with("artifacts/")
                    || p.starts_with("build/")
                    || p.starts_with("source-snapshot/")
                    || p.starts_with("external-source/")
                    || p == crate::foundation::external::source::FILE),
            "staged external deployment contains unexplained effects"
        );
    }
    controls::validate(manifest)?;
    Ok(())
}

fn build_limit(path: &str) -> Result<u64> {
    Ok(match path {
        "attempt.json" => 65536,
        "exporter" => devnet::MAX_HELPER_BYTES,
        "result.json" | "image.json" => crate::image::MAX_RECORD_BYTES as u64,
        "image-manifest.json" => crate::image::MAX_MANIFEST_BYTES as u64,
        "image-config.json" => crate::image::MAX_CONFIG_BYTES as u64,
        _ => eyre::bail!("unknown external build payload"),
    })
}

pub(super) fn file_limit(manifest: &Manifest, path: &str) -> Result<u64> {
    if path == crate::foundation::external::source::FILE || path.starts_with("external-source/") {
        return preparation::file_limit(manifest, path);
    }
    let request = request(manifest)?;
    if let Some(name) = path.strip_prefix("artifacts/") {
        if name == "external-request.json" {
            return Ok(4 * 1024 * 1024);
        }
        return request
            .artifacts
            .get(name)
            .map(|a| a.bytes)
            .context("unknown external public artifact");
    }
    if let Some(name) = path.strip_prefix("build/") {
        ensure!(request.build.is_some(), "unrelated initial external build");
        return build_limit(name);
    }
    if let Some(name) = path.strip_prefix("source-snapshot/") {
        let build = request
            .build
            .as_ref()
            .context("unrelated external source archive")?;
        return match name {
            "source.tar" => Ok(build.source_bytes),
            "receipt.json" => Ok(MAX_MANIFEST_BYTES),
            _ => eyre::bail!("unknown external source slot"),
        };
    }
    let members = nodes(manifest)?;
    if let Some(name) = path.strip_prefix("native-inventory/") {
        ensure!(
            name == "cohort.json" || members.iter().any(|n| name == format!("{n}.json")),
            "foreign native inventory slot"
        );
        return Ok(16 * 1024);
    }
    if let Some(rest) = path.strip_prefix("external-updates/") {
        let (id, name) = rest
            .split_once('/')
            .context("missing external update path")?;
        uuid(id)?;
        if let Some(build) = name.strip_prefix("build/") {
            return build_limit(build);
        }
        return Ok(match name {
            "intent.json"
            | "source.json"
            | "client-endpoints.json"
            | "source-snapshot/receipt.json" => MAX_MANIFEST_BYTES,
            "source-snapshot/source.tar" => crate::build::MAX_SOURCE_BYTES,
            "image.json" => crate::image::MAX_RECORD_BYTES as u64,
            "image-manifest.json" => crate::image::MAX_MANIFEST_BYTES as u64,
            "image-config.json" => crate::image::MAX_CONFIG_BYTES as u64,
            _ if members.iter().any(|n| name == format!("{n}-request.json")) => {
                crate::host::runtime::revision::MAX_REQUEST_BYTES
            }
            _ if members.iter().any(|n| name == format!("{n}-command.json")) => 128 * 1024,
            _ => eyre::bail!("unknown external update payload"),
        });
    }
    if let Some(rest) = path.strip_prefix("external-controls/") {
        let (id, name) = rest
            .split_once('/')
            .context("missing external control path")?;
        uuid(id)?;
        return match name {
            "intent.json" => Ok(32 * 1024),
            "control.sh" => Ok(16 * 1024),
            "command.json" => Ok(128 * 1024),
            _ => eyre::bail!("unknown external control payload"),
        };
    }
    if matches!(
        path,
        "external-evidence.json"
            | "client-endpoints.json"
            | "new-volume-creation.json"
            | "cleanup-volume-identities.json"
            | "stale-address-recovery.json"
    ) {
        return Ok(MAX_MANIFEST_BYTES);
    }
    for node in members {
        for suffix in [
            "external-provisioning.json",
            "external-identity.json",
            "external-runtime.json",
            "new-volume.json",
            "new-volume-checkpoint.json",
        ] {
            if path == format!("{node}-{suffix}") {
                return Ok(MAX_MANIFEST_BYTES);
            }
        }
        if path == format!("{node}-external-identity-install.sh")
            || path == format!("{node}-external-runtime-install.sh")
        {
            return Ok(32 * 1024 * 1024);
        }
        for suffix in [
            "external-identity-command.json",
            "external-install-command.json",
        ] {
            if path == format!("{node}-{suffix}") {
                return Ok(128 * 1024);
            }
        }
        if node == "node-1"
            && matches!(
                path,
                "node-1-external-start-producer-command.json"
                    | "node-1-external-gateway-install-command.json"
            )
        {
            return Ok(128 * 1024);
        }
        for stem in [
            format!("{node}-external-observe-"),
            format!("{node}-external-gateway-observe-"),
        ] {
            if let Some(id) = path
                .strip_prefix(&stem)
                .and_then(|p| p.strip_suffix(".json"))
            {
                ensure!(
                    node == "node-1" || !stem.contains("gateway"),
                    "foreign external gateway"
                );
                uuid(id)?;
                return Ok(128 * 1024);
            }
        }
        if let Some(id) = path
            .strip_prefix(&format!("{node}-external-update-"))
            .and_then(|p| p.strip_suffix("-install.sh"))
        {
            uuid(id)?;
            return Ok(32 * 1024 * 1024);
        }
    }
    eyre::bail!("unsupported external handoff file: {path}")
}

fn read(manifest: &Manifest, root: &Path, name: &str) -> Result<Vec<u8>> {
    manifest.require(name)?;
    devnet::read_bounded(&root.join(name), manifest.file_limit(name)?)
}

fn image(
    request: &ExternalRequest,
    root: &Path,
    expected: &crate::image::ImageRecord,
) -> Result<()> {
    let requirements = request.validate()?;
    let saved = crate::image::ImageRecord::from_json_for_requirements(
        &devnet::read_bounded(
            &root.join("image.json"),
            crate::image::MAX_RECORD_BYTES as u64,
        )?,
        &requirements,
    )?;
    ensure!(saved == *expected, "external image record differs");
    let proof = crate::image::validate_manifest_bytes_for_requirements(
        expected,
        &requirements,
        &devnet::read_bounded(
            &root.join("image-manifest.json"),
            crate::image::MAX_MANIFEST_BYTES as u64,
        )?,
    )?;
    crate::image::validate_config_bytes_for_requirements(
        expected,
        &requirements,
        &proof,
        &devnet::read_bounded(
            &root.join("image-config.json"),
            crate::image::MAX_CONFIG_BYTES as u64,
        )?,
    )?;
    Ok(())
}

fn command(
    manifest: &Manifest,
    root: &Path,
    path: &str,
    instance: &str,
    script: &str,
    timeout: u32,
    terminal: bool,
) -> Result<()> {
    crate::ssm::validate_handoff_request(
        &read(manifest, root, path)?,
        instance,
        script,
        timeout,
        terminal,
    )
}

/// Only read after the journal's immutable request and complete attempt history
/// have passed the shared SSM validator. Never recover or resend a command here.
fn successful_output(manifest: &Manifest, root: &Path, path: &str) -> Result<serde_json::Value> {
    let journal: serde_json::Value = serde_json::from_slice(&read(manifest, root, path)?)?;
    let last = journal["attempts"]
        .as_array()
        .and_then(|a| a.last())
        .context("missing external command attempt")?;
    ensure!(
        last["state"] == "succeeded" && last["uncertain"] == false,
        "external revision has no confirmed command result"
    );
    Ok(last["output"].clone())
}

fn installer(
    manifest: &Manifest,
    root: &Path,
    stem: &str,
    journal: &str,
    instance: &str,
    script: &str,
    terminal: bool,
) -> Result<()> {
    let path = format!("{stem}-install.sh");
    ensure!(
        read(manifest, root, &path)? == script.as_bytes(),
        "external installer changed"
    );
    let deployment = &manifest.deployment;
    let object = crate::host::S3Object {
        bucket: deployment.team.backend_bucket()?.into(),
        key: format!(
            "{}{}/{path}",
            devnet::artifact_prefix(&deployment.team, &deployment.spec),
            devnet::sha256(script.as_bytes())
        ),
        sha256: devnet::sha256(script.as_bytes()),
        bytes: script.len() as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    };
    command(
        manifest,
        root,
        journal,
        instance,
        &crate::foundation_live::selected_fetch_installer(deployment, &object, 7200)?,
        7200,
        terminal,
    )
}

/// Held through archive publication, like ordinary source preparation locks.
pub(super) fn locks(
    manifest: &Manifest,
    root: &Path,
) -> Result<Vec<crate::build_job::AttemptLock>> {
    let mut locks = Vec::new();
    if let Some(source) = &manifest.deployment.external_source {
        locks.push(crate::build_job::lock_preparation(
            &root.join("external-source/build"),
            &manifest.deployment.team,
            &source.contract,
        )?);
    }
    if manifest.deployment.external.is_none() {
        return Ok(locks);
    }
    let request = request(manifest)?;
    if root.join("build").try_exists()? {
        locks.push(crate::build_job::lock_preparation(
            &root.join("build"),
            &manifest.deployment.team,
            request.build.as_ref().context("unrelated external build")?,
        )?);
    }
    let updates = root.join("external-updates");
    if updates.try_exists()? {
        ensure!(
            std::fs::symlink_metadata(&updates)?.is_dir(),
            "unsafe external updates directory"
        );
        for entry in std::fs::read_dir(updates)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_dir(),
                "unsafe external update directory"
            );
            uuid(
                entry
                    .file_name()
                    .to_str()
                    .context("invalid external update name")?,
            )?;
            if entry.path().join("source.json").try_exists()? {
                let source: Source = foundation::read_json(&entry.path().join("source.json"))?;
                locks.push(crate::build_job::lock_preparation(
                    &entry.path().join("build"),
                    &manifest.deployment.team,
                    &source.contract,
                )?);
            }
        }
    }
    Ok(locks)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.external.verify")
)]
pub(super) fn verify(manifest: &Manifest, root: &Path) -> Result<()> {
    let deployment = &manifest.deployment;
    if deployment.external_source.is_some() {
        preparation::verify(manifest, root)?;
    }
    if deployment.external.is_none() {
        return Ok(());
    }
    let request = request(manifest)?;
    ensure!(
        read(manifest, root, "artifacts/external-request.json")? == request.bytes()?,
        "external request bytes changed"
    );
    let inspected = PublicPackage::inspect(
        &read(manifest, root, "artifacts/package.json")?,
        &request.trust.package,
        &root.join("artifacts"),
    )?;
    ensure!(
        inspected.compiled_result == serde_json::to_vec(&request.compiled)?
            && inspected.manifest.host_adapter.adapter_selection_sha256
                == request.trust.adapter_selection_sha256
            && inspected.manifest.host_adapter.executable_sha256 == request.trust.executable.sha256
            && inspected.manifest.host_adapter.executable_bytes == request.trust.executable.bytes,
        "external package/trust/compiled selection differs"
    );
    image(&request, &root.join("artifacts"), &request.image)?;
    devnet::validate_helper_file(&root.join("artifacts/zdn"))?;
    if let Some(contract) = &request.build {
        if manifest.files.keys().any(|p| p.starts_with("build/")) {
            verify_build(manifest, root, "build", contract, Some(&request.image))?;
        }
        if manifest.files.contains_key("source-snapshot/source.tar") {
            contract.verify_archive(&root.join("source-snapshot/source.tar"))?;
            manifest.require("source-snapshot/receipt.json")?;
        }
    }
    if deployment.last_operation.is_none() {
        return Ok(());
    }
    crate::foundation_live::external::validate_saved(deployment, root)?;
    let evidence: Evidence =
        serde_json::from_slice(&read(manifest, root, "external-evidence.json")?)?;
    let external = deployment
        .external
        .as_ref()
        .context("missing external ownership")?;
    let outputs = deployment
        .outputs
        .as_ref()
        .context("external outputs missing")?;
    let cohort = NativeCohort::new(
        deployment.spec.network_id,
        request.artifacts["descriptor.json"].sha256.clone(),
        request.compiled.native_fingerprint.clone(),
        &external.topology()?,
        &outputs.nodes,
        external.listener()?,
    )?;
    let store =
        NativeInventoryStore::open_existing(&root.join("native-inventory"), cohort.clone())?;
    let inventory = store.read_pinned(&evidence.inventory)?;
    ensure!(
        evidence.schema == runtime::SCHEMA
            && evidence.request == Pin::of(&request.bytes()?)
            && evidence.cohort == cohort.pin()?
            && evidence.pending_identity.is_none()
            && inventory.is_complete()
            && evidence.inventory_json == serde_json::to_string(&inventory)?
            && evidence.manifests.keys().cloned().collect::<BTreeSet<_>>() == nodes(manifest)?,
        "external lifecycle/cohort identity differs"
    );
    evidence
        .inventory
        .check(evidence.inventory_json.as_bytes())?;
    let mut runtimes = BTreeMap::new();
    for (node, output) in &outputs.nodes {
        let provisioning = Provisioning::from_slice(&read(
            manifest,
            root,
            &format!("{node}-external-provisioning.json"),
        )?)?;
        volumes::verify(
            deployment,
            manifest,
            root,
            output,
            provisioning.new_volume.as_ref(),
        )?;
        let identity = identity::Manifest::from_slice(&read(
            manifest,
            root,
            &format!("{node}-external-identity.json"),
        )?)?;
        ensure!(
            identity.request.bytes()? == request.bytes()?
                && identity.provisioning.bytes()? == provisioning.bytes()?
                && serde_json::to_value(&identity.sources)?
                    == serde_json::to_value(request.objects(&deployment.team, &deployment.spec)?)?,
            "external identity manifest differs"
        );
        let public = crate::public_chain_adapter::contract::RenderInput {
            public: inspected.input.clone(),
            compiled_sha256: request.artifacts["compiled.json"].sha256.clone(),
            options: identity.options.clone(),
            identity_only: true,
        };
        crate::public_chain_adapter::contract::validate_render(
            &crate::public_chain_adapter::contract::Rendered {
                config_toml: identity.config_toml.clone(),
            },
            &public,
        )?;
        installer(
            manifest,
            root,
            &format!("{node}-external-identity"),
            &format!("{node}-external-identity-command.json"),
            &output.instance_id,
            &crate::host::runtime::bootstrap::render_external_identity(&identity)?,
            true,
        )?;
        let identity_output = successful_output(
            manifest,
            root,
            &format!("{node}-external-identity-command.json"),
        )?;
        let identity_output =
            crate::native_peers::NativeIdentity::from_json(&serde_json::to_vec(&identity_output)?)?;
        ensure!(
            identity_output.node_id == inventory.expected_node_id(node)?
                && identity_output.chain_fingerprint.as_deref()
                    == Some(&request.compiled.native_fingerprint),
            "external identity result differs from native inventory"
        );
        let bytes = read(manifest, root, &format!("{node}-external-runtime.json"))?;
        evidence.manifests[node].check(&bytes)?;
        let runtime = runtime::Manifest::from_slice(&bytes)?;
        ensure!(
            runtime.production_limits == request.production_limits,
            "external runtime production limits differ from request"
        );
        let mut expected_identity_options = runtime.chain.options.clone();
        expected_identity_options.role = "follower".into();
        expected_identity_options.expected_node_id.clear();
        expected_identity_options.peers.clear();
        expected_identity_options.reward_address = None;
        ensure!(
            serde_json::to_value(&identity.options)?
                == serde_json::to_value(expected_identity_options)?,
            "external provisioning options differ from saved runtime"
        );
        let public = crate::public_chain_adapter::contract::RenderInput {
            public: inspected.input.clone(),
            compiled_sha256: request.artifacts["compiled.json"].sha256.clone(),
            options: runtime.chain.options.clone(),
            identity_only: false,
        };
        crate::public_chain_adapter::contract::validate_render(
            &crate::public_chain_adapter::contract::Rendered {
                config_toml: runtime.chain.config_toml.clone(),
            },
            &public,
        )?;
        installer(
            manifest,
            root,
            &format!("{node}-external-runtime"),
            &format!("{node}-external-install-command.json"),
            &output.instance_id,
            &crate::foundation_live::external::runtime_script(&runtime, "install")?,
            true,
        )?;
        crate::foundation_live::external::validate_observation(
            &runtime,
            &successful_output(
                manifest,
                root,
                &format!("{node}-external-install-command.json"),
            )?,
            false,
        )?;
        if node == "node-1" {
            for (name, action, timeout) in [
                (
                    "node-1-external-start-producer-command.json",
                    "start-producer",
                    7200,
                ),
                (
                    "node-1-external-gateway-install-command.json",
                    "gateway-install",
                    600,
                ),
            ] {
                command(
                    manifest,
                    root,
                    name,
                    &output.instance_id,
                    &crate::foundation_live::external::runtime_script(&runtime, action)?,
                    timeout,
                    true,
                )?;
                let value = successful_output(manifest, root, name)?;
                if action == "start-producer" {
                    crate::foundation_live::external::validate_observation(&runtime, &value, true)?;
                } else {
                    ensure!(
                        value
                            == serde_json::json!({"apiVersion":crate::client_gateway::OBSERVATION_API_VERSION,
                        "deploymentId":runtime.provisioning.deployment_id,"nodeId":runtime.provisioning.node_id,
                        "consensusFingerprint":runtime.provisioning.native_fingerprint,
                        "serviceSha256":runtime.chain.gateway_service_sha256()?,"endpoint":crate::client_gateway::ENDPOINT,"status":"ready"}),
                        "external gateway result differs"
                    );
                }
            }
        }
        for path in manifest.files.keys() {
            let action = if path.starts_with(&format!("{node}-external-observe-")) {
                Some("observe")
            } else if path.starts_with(&format!("{node}-external-gateway-observe-")) {
                Some("gateway-observe")
            } else {
                None
            };
            if let Some(action) = action {
                command(
                    manifest,
                    root,
                    path,
                    &output.instance_id,
                    &crate::foundation_live::external::runtime_script(&runtime, action)?,
                    300,
                    false,
                )?;
            }
        }
        runtimes.insert(node.clone(), runtime);
    }
    verify_updates(manifest, root, &request, &evidence, &runtimes)?;
    let expected = crate::foundation_live::external::endpoint_file(deployment, root)?;
    let saved: crate::endpoints::EndpointFile =
        serde_json::from_slice(&read(manifest, root, "client-endpoints.json")?)?;
    // Pending updates can have a newer host revision than the last published
    // endpoint file. It remains inert evidence; do not rewrite it on import.
    if evidence.pending_update.is_none() {
        ensure!(
            serde_json::to_value(saved)? == serde_json::to_value(expected)?,
            "external endpoint revision differs"
        );
    }
    deployment.render()?;
    Ok(())
}

fn verify_build(
    manifest: &Manifest,
    root: &Path,
    prefix: &str,
    contract: &crate::build::BuildContract,
    expected: Option<&crate::image::ImageRecord>,
) -> Result<()> {
    manifest.require(&format!("{prefix}/attempt.json"))?;
    let observation = crate::build_job::validate_preparation(
        &root.join(prefix),
        &manifest.deployment.team,
        contract,
    )?;
    if let Some(helper) = observation.exporter_helper {
        ensure!(
            manifest.files.get(&format!("{prefix}/exporter")) == Some(&helper),
            "external exporter pin differs"
        );
    }
    if let Some(expected) = expected {
        ensure!(
            observation.job_outcome == Some("succeeded") || observation.reused_from.is_some(),
            "external staged build has not finished successfully"
        );
        crate::build_job::removal_evidence(&root.join(prefix), &manifest.deployment.team)?;
        let result: crate::build_job::BuildResult =
            serde_json::from_slice(&read(manifest, root, &format!("{prefix}/result.json"))?)?;
        ensure!(
            result.contract_sha256 == contract.fingerprint()? && result.image == *expected,
            "external build result differs"
        );
        contract.validate_image(expected)?;
        image(&request(manifest)?, &root.join(prefix), expected)?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "handoff.external.verify_updates")
)]
fn verify_updates(
    manifest: &Manifest,
    root: &Path,
    request: &ExternalRequest,
    evidence: &Evidence,
    runtimes: &BTreeMap<String, runtime::Manifest>,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    for path in manifest
        .files
        .keys()
        .filter_map(|p| p.strip_prefix("external-updates/"))
    {
        ids.insert(uuid(
            path.split('/').next().context("missing external UUID")?,
        )?);
    }
    ensure!(
        evidence.pending_update.is_none_or(|id| ids.contains(&id)),
        "missing pending external update"
    );
    let mut updates = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    let mut targets = BTreeMap::new();
    for id in &ids {
        let prefix = format!("external-updates/{id}");
        let pending = evidence.pending_update == Some(*id);
        let source = if manifest
            .files
            .contains_key(&format!("{prefix}/source.json"))
        {
            let source: Source =
                serde_json::from_slice(&read(manifest, root, &format!("{prefix}/source.json"))?)?;
            ensure!(
                source.schema == "zdn-external-source-update/v1"
                    && source.id == *id
                    && source.deployment_id == manifest.deployment.spec.network_id
                    && source.request == evidence.request,
                "foreign external source update"
            );
            request.require_config(&source.original_config)?;
            crate::foundation::update_controller::validate_source_config(
                &source.original_config,
                &source.candidate_config,
            )?;
            let receipt: crate::source::SnapshotReceipt = serde_json::from_slice(&read(
                manifest,
                root,
                &format!("{prefix}/source-snapshot/receipt.json"),
            )?)?;
            let mut contract = crate::build::BuildContract::new(
                &receipt,
                source
                    .candidate_config
                    .node
                    .build
                    .as_ref()
                    .context("missing source recipe")?,
            )?;
            contract.require_external(&request.validate()?)?;
            ensure!(
                contract == source.contract,
                "external source contract differs"
            );
            manifest.require(&format!("{prefix}/source-snapshot/source.tar"))?;
            contract.verify_archive(&root.join(&prefix).join("source-snapshot/source.tar"))?;
            let selected: BTreeSet<_> = source.nodes.iter().cloned().collect();
            ensure!(
                !selected.is_empty()
                    && selected.len() == source.nodes.len()
                    && selected.is_subset(&nodes(manifest)?),
                "external source targets differ"
            );
            verify_build(manifest, root, &format!("{prefix}/build"), &contract, None)?;
            Some(source)
        } else {
            None
        };
        // The controller hashes canonical typed inputs, not the formatting of
        // the saved JSON. Source updates bind the source even after an image
        // intent has been materialized by the build.
        let source_inputs = source
            .as_ref()
            .map(|source| {
                crate::foundation_live::external::update::operation_inputs(
                    &manifest.deployment,
                    &serde_json::to_vec(source)?,
                    Some(&source.contract.source_sha256),
                )
            })
            .transpose()?;
        if !manifest
            .files
            .contains_key(&format!("{prefix}/intent.json"))
        {
            ensure!(
                pending && source.is_some(),
                "orphan external source/build evidence"
            );
            inputs.insert(*id, source_inputs.context("missing source inputs")?);
            continue;
        }
        let intent: Intent =
            serde_json::from_slice(&read(manifest, root, &format!("{prefix}/intent.json"))?)?;
        ensure!(
            intent.schema == runtime::update::SCHEMA
                && intent.id == *id
                && intent.deployment_id == manifest.deployment.spec.network_id
                && intent.request == evidence.request
                && !intent.nodes.is_empty()
                && intent.nodes.keys().all(|n| runtimes.contains_key(n)),
            "foreign external image intent"
        );
        inputs.insert(
            *id,
            match source_inputs {
                Some(inputs) => inputs,
                None => crate::foundation_live::external::update::operation_inputs(
                    &manifest.deployment,
                    &serde_json::to_vec(&intent)?,
                    None,
                )?,
            },
        );
        targets.insert(*id, intent.nodes.keys().cloned().collect::<Vec<_>>());
        ensure!(
            intent.artifacts.len() == 3
                && ["image.json", "image-manifest.json", "image-config.json"]
                    .iter()
                    .all(|name| intent
                        .artifacts
                        .get(*name)
                        .is_some_and(
                            |a| manifest.files.get(&format!("{prefix}/{name}")) == Some(a)
                        )),
            "external image proof inventory differs"
        );
        image(request, &root.join(&prefix), &intent.image)?;
        let registry = format!(
            "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
            manifest.deployment.team.aws.account_id,
            manifest.deployment.team.aws.region,
            manifest.deployment.team.team_id
        );
        ensure!(
            intent.image.image.starts_with(&registry),
            "external update image is outside team registry"
        );
        if let Some(source) = source {
            ensure!(
                intent.nodes.keys().collect::<BTreeSet<_>>() == source.nodes.iter().collect(),
                "external source and image target sets differ"
            );
            verify_build(
                manifest,
                root,
                &format!("{prefix}/build"),
                &source.contract,
                Some(&intent.image),
            )?;
        }
        for (node, pin) in &intent.nodes {
            let bytes = read(manifest, root, &format!("{prefix}/{node}-request.json"))?;
            pin.check(&bytes)?;
            let update = runtime::update::Request::from_slice(&bytes)?;
            ensure!(
                update.update_id == *id
                    && update.original.bytes()? == runtimes[node].bytes()?
                    && update.target.image == intent.image,
                "external runtime update identity differs"
            );
            for (name, object) in [
                ("image.json", &update.target.chain.objects.image_record),
                (
                    "image-manifest.json",
                    &update.target.chain.objects.image_manifest,
                ),
                (
                    "image-config.json",
                    &update.target.chain.objects.image_config,
                ),
            ] {
                let artifact = &intent.artifacts[name];
                let expected = crate::host::S3Object {
                    bucket: manifest.deployment.team.backend_bucket()?.into(),
                    key: format!(
                        "{}{}/{name}",
                        devnet::artifact_prefix(
                            &manifest.deployment.team,
                            &manifest.deployment.spec
                        ),
                        artifact.sha256
                    ),
                    sha256: artifact.sha256.clone(),
                    bytes: artifact.bytes,
                    owner_account: manifest.deployment.team.aws.account_id.clone(),
                    region: manifest.deployment.team.aws.region.clone(),
                };
                ensure!(
                    serde_json::to_value(object)? == serde_json::to_value(expected)?,
                    "external update source authority differs"
                );
            }
            let journal = format!("{prefix}/{node}-command.json");
            let script_path = format!("{node}-external-update-{id}-install.sh");
            let active = evidence
                .active_images
                .get(node)
                .is_some_and(|active| active.update_id == *id);
            if manifest.files.contains_key(&journal)
                || manifest.files.contains_key(&script_path)
                || !pending
                || active
            {
                installer(
                    manifest,
                    root,
                    &format!("{node}-external-update-{id}"),
                    &journal,
                    &manifest
                        .deployment
                        .outputs
                        .as_ref()
                        .context("missing external outputs")?
                        .nodes[node]
                        .instance_id,
                    &update.render()?,
                    !pending || active,
                )?;
                if !pending || active {
                    ensure!(
                        successful_output(manifest, root, &journal)?
                            == serde_json::json!({"schema":runtime::update::SCHEMA,
                        "updateId":id,"phase":"done","runtime":Pin::of(&update.target.bytes()?)}),
                        "external update completion result differs"
                    );
                }
            }
            updates.insert((*id, node.clone()), update);
        }
        if !pending {
            manifest.require(&format!("{prefix}/client-endpoints.json"))?;
        }
    }
    // Authenticate every predecessor edge, not just the current target image.
    for ((id, node), update) in &updates {
        let mut seen = BTreeSet::from([*id]);
        let mut current = update;
        loop {
            if let Some(previous) = current.expected_update_id {
                ensure!(seen.insert(previous), "cyclic external revision history");
                let predecessor = updates
                    .get(&(previous, node.clone()))
                    .context("missing external predecessor revision")?;
                ensure!(
                    current.expected_image == predecessor.target.image.image,
                    "external predecessor image differs"
                );
                current = predecessor;
            } else {
                ensure!(
                    current.expected_image == request.image.image,
                    "external initial revision differs"
                );
                break;
            }
        }
    }
    for (node, active) in &evidence.active_images {
        let update = updates
            .get(&(active.update_id, node.clone()))
            .context("missing active external revision")?;
        ensure!(
            active.image == update.target.image.image
                && active.runtime == Pin::of(&update.target.bytes()?),
            "external active revision pin differs"
        );
    }
    for node in runtimes.keys() {
        let confirmed: BTreeSet<_> = updates
            .keys()
            .filter(|(id, n)| {
                n == node
                    && (evidence.pending_update != Some(*id)
                        || evidence
                            .active_images
                            .get(node)
                            .is_some_and(|a| a.update_id == *id))
            })
            .map(|(id, _)| *id)
            .collect();
        let mut successors = BTreeMap::new();
        for ((id, n), update) in &updates {
            if n == node {
                if let Some(previous) = update.expected_update_id {
                    ensure!(
                        successors.insert(previous, *id).is_none(),
                        "forked external revision history"
                    );
                }
                if evidence.pending_update == Some(*id) && !confirmed.contains(id) {
                    ensure!(
                        update.expected_update_id
                            == evidence.active_images.get(node).map(|a| a.update_id),
                        "pending external update does not extend the active revision"
                    );
                }
            }
        }
        let frontier: Vec<_> = confirmed
            .iter()
            .filter(|id| {
                successors
                    .get(*id)
                    .is_none_or(|next| !confirmed.contains(next))
            })
            .collect();
        ensure!(
            frontier.len() <= 1
                && evidence.active_images.get(node).map(|a| a.update_id)
                    == frontier.first().map(|id| **id),
            "external active revision is not the confirmed history frontier"
        );
    }
    let deployment = &manifest.deployment;
    let output = &deployment
        .outputs
        .as_ref()
        .context("missing external outputs")?
        .nodes["node-1"];
    let mut endpoints = Vec::new();
    for chain in std::iter::once(&runtimes["node-1"].chain).chain(
        updates
            .iter()
            .filter(|((_, node), _)| node == "node-1")
            .map(|(_, update)| &update.target.chain),
    ) {
        endpoints.push(crate::endpoints::EndpointFile::from_external(
            deployment.spec.scope.clone(),
            deployment.team.bootstrap_id,
            request.node_count,
            output.instance_id.clone(),
            chain,
        )?);
    }
    for path in manifest
        .files
        .keys()
        .filter(|p| p.as_str() == "client-endpoints.json" || p.ends_with("/client-endpoints.json"))
    {
        let saved: crate::endpoints::EndpointFile =
            serde_json::from_slice(&read(manifest, root, path)?)?;
        saved.validate()?;
        ensure!(
            endpoints.contains(&saved),
            "external endpoints belong to a foreign runtime revision"
        );
    }
    // No admitted script or build file may escape the intent/source inventory.
    for path in manifest.files.keys() {
        if let Some(rest) = path.strip_prefix("external-updates/") {
            let (id, name) = rest
                .split_once('/')
                .context("invalid external update file")?;
            let id = uuid(id)?;
            if name.ends_with("-request.json") || name.ends_with("-command.json") {
                let node = name
                    .strip_suffix("-request.json")
                    .or_else(|| name.strip_suffix("-command.json"))
                    .context("invalid node file")?;
                ensure!(
                    updates.contains_key(&(id, node.to_owned())),
                    "unaccounted external node update evidence"
                );
            }
            if name.starts_with("build/") || name.starts_with("source-snapshot/") {
                manifest.require(&format!("external-updates/{id}/source.json"))?;
            }
        }
        if let Some(rest) = path.strip_suffix("-install.sh") {
            if let Some((node, id)) = rest.split_once("-external-update-") {
                ensure!(
                    updates.contains_key(&(uuid(id)?, node.to_owned())),
                    "orphan external update installer"
                );
            }
        }
    }
    // Retained successful receipts are recovery evidence too, including those
    // preceding last_operation. Neither removing an entire revision nor
    // rewriting its intent may turn a completed update back into the original
    // deployment. A succeeded update phase remains binding if readiness later
    // failed or its outcome is still unknown.
    for operation in manifest
        .operations
        .iter()
        .filter(|operation| operation.kind == "external-update")
    {
        let result = operation.phases.iter().find_map(|phase| {
            if phase.name == "update" {
                if let PhaseStatus::Succeeded { result } = &phase.status {
                    return Some(result);
                }
            }
            None
        });
        if result.is_none()
            && !operation
                .phases
                .iter()
                .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. }))
        {
            continue;
        }
        ensure!(
            operation
                .phases
                .iter()
                .map(|phase| phase.name.as_str())
                .eq([
                    "verify",
                    "reserve",
                    "lease",
                    "preflight",
                    "build",
                    "update",
                    "readiness"
                ]),
            "external update receipt phase contract differs"
        );
        let result = result.context("missing successful external update result")?;
        let id = uuid(
            result
                .get("updateId")
                .and_then(serde_json::Value::as_str)
                .context("missing successful external update UUID")?,
        )?;
        let nodes = targets
            .get(&id)
            .context("missing successful external update intent")?;
        ensure!(
            inputs.get(&id) == Some(&operation.inputs)
                && *result == serde_json::json!({"updateId":id,"nodes":nodes}),
            "successful external operation revision differs"
        );
    }
    controls::verify(manifest, root, evidence, runtimes, &updates)?;
    if let Some(unresolved) = manifest.deployment.unresolved_operation {
        let operation = manifest
            .operations
            .iter()
            .find(|o| o.operation_id == unresolved)
            .context("missing unresolved operation")?;
        if operation.kind == "external-control" {
            return Ok(());
        }
        ensure!(
            evidence.pending_update.is_some(),
            "unresolved external update has no durable selection"
        );
        let id = evidence.pending_update.context("missing pending update")?;
        ensure!(
            inputs.get(&id) == Some(&operation.inputs),
            "unresolved external operation intent differs"
        );
    }
    Ok(())
}
