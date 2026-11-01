//! Image-only external revisions: explicit node selection, frozen image proofs,
//! existing foundation leases and SSM journals, resume-forward host maintenance.
use super::*;
use crate::{
    foundation::{DeploymentFile, OperationProgress},
    host::external::runtime::update as host_update,
    state::{Binding, OperationInput, OperationReceipt, PhaseStatus, StateStore},
};

mod source;
pub use source::prepare as prepare_source;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema: String,
    id: Uuid,
    deployment_id: Uuid,
    request: Pin,
    image: crate::image::ImageRecord,
    artifacts: BTreeMap<String, devnet::Artifact>,
    nodes: BTreeMap<String, Pin>,
}

fn directory(root: &Path, id: Uuid) -> PathBuf {
    root.join("external-updates").join(id.to_string())
}

fn image_object(
    deployment: &Deployment,
    name: &str,
    a: &devnet::Artifact,
) -> Result<crate::host::S3Object> {
    Ok(crate::host::S3Object {
        bucket: deployment.team.backend_bucket()?.into(),
        key: format!(
            "{}{}/{name}",
            devnet::artifact_prefix(&deployment.team, &deployment.spec),
            a.sha256
        ),
        sha256: a.sha256.clone(),
        bytes: a.bytes,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    })
}

pub(super) fn image_inputs(
    deployment: &Deployment,
    root: &Path,
    id: Uuid,
) -> Result<(crate::image::ImageRecord, PathBuf)> {
    let (intent, _) = load(deployment, root, id)?;
    Ok((
        intent.image,
        directory(root, id).join("image-manifest.json"),
    ))
}

pub fn require_settled(deployment: &Deployment, root: &Path) -> Result<()> {
    if deployment.external.is_some() && root.join(EVIDENCE).try_exists()? {
        let evidence: Evidence = foundation::read_json(&root.join(EVIDENCE))?;
        ensure!(
            evidence.pending_update.is_none(),
            "resume the pending external update before up or destroy"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn prepare(
    deployment: &Deployment,
    root: &Path,
    nodes: &[String],
    record: &Path,
    manifest: &Path,
    config: &Path,
    cancelled: &AtomicBool,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    prepare_image(
        deployment, root, nodes, record, manifest, config, cancelled, id, false,
    )?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.update.prepare_image")
)]
fn prepare_image(
    deployment: &Deployment,
    root: &Path,
    nodes: &[String],
    record: &Path,
    manifest: &Path,
    config: &Path,
    cancelled: &AtomicBool,
    id: Uuid,
    from_source: bool,
) -> Result<()> {
    validate_saved(deployment, root)?;
    let external = deployment
        .external
        .as_ref()
        .context("external deployment required")?;
    let request = external.typed_request()?;
    let requirements = request.validate()?;
    let (inventory_store, mut evidence) = load_inventory(deployment, root)?;
    ensure!(
        (evidence.pending_update.is_none() || (from_source && evidence.pending_update == Some(id)))
            && evidence.pending_identity.is_none(),
        "external operation remains pending"
    );
    let inventory = inventory_store.read_pinned(&evidence.inventory)?;
    ensure!(
        inventory.is_complete() && !nodes.is_empty(),
        "external update requires complete cohort and explicit nodes"
    );
    let image_bytes = devnet::read_bounded(record, crate::image::MAX_RECORD_BYTES as u64)?;
    let image = crate::image::ImageRecord::from_json_for_requirements(&image_bytes, &requirements)?;
    let manifest_bytes = devnet::read_bounded(manifest, crate::image::MAX_MANIFEST_BYTES as u64)?;
    let config_bytes = devnet::read_bounded(config, crate::image::MAX_CONFIG_BYTES as u64)?;
    let proof = crate::image::validate_manifest_bytes_for_requirements(
        &image,
        &requirements,
        &manifest_bytes,
    )?;
    crate::image::validate_config_bytes_for_requirements(
        &image,
        &requirements,
        &proof,
        &config_bytes,
    )?;
    let prefix = format!(
        "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
        deployment.team.aws.account_id, deployment.team.aws.region, deployment.team.team_id
    );
    ensure!(
        image.image.starts_with(&prefix),
        "external update image is outside the team registry"
    );
    let prepared = request.prepare(
        &root.join("artifacts"),
        Instant::now() + Duration::from_secs(120),
        cancelled,
    )?;
    let target_dir = directory(root, id);
    foundation::private_directory(&target_dir)?;
    let mut artifacts = BTreeMap::new();
    for (name, bytes) in [
        ("image.json", image_bytes),
        ("image-manifest.json", manifest_bytes),
        ("image-config.json", config_bytes),
    ] {
        saved_bytes(&target_dir.join(name), &bytes)?;
        artifacts.insert(
            name.into(),
            devnet::Artifact {
                bytes: bytes.len() as u64,
                sha256: devnet::sha256(&bytes),
            },
        );
    }
    let object = |name: &str| -> Result<crate::host::S3Object> {
        let a = &artifacts[name];
        Ok(crate::host::S3Object {
            bucket: deployment.team.backend_bucket()?.into(),
            key: format!(
                "{}{}/{name}",
                devnet::artifact_prefix(&deployment.team, &deployment.spec),
                a.sha256
            ),
            sha256: a.sha256.clone(),
            bytes: a.bytes,
            owner_account: deployment.team.aws.account_id.clone(),
            region: deployment.team.aws.region.clone(),
        })
    };
    let mut selected = BTreeMap::new();
    for node in nodes {
        ensure!(
            !selected.contains_key(node) && evidence.manifests.contains_key(node),
            "external update node is duplicated or unknown"
        );
        let original = RuntimeRequest::from_slice(&devnet::read_bounded(
            &root.join(format!("{node}-external-runtime.json")),
            16 * 1024 * 1024,
        )?)?;
        let mut target = original.clone();
        target.image = image.clone();
        target.chain.options.image_digest = image.manifest_digest()?.into();
        target.chain.objects.image_record = object("image.json")?;
        target.chain.objects.image_manifest = object("image-manifest.json")?;
        target.chain.objects.image_config = object("image-config.json")?;
        let rendered = prepared.render_with_inventory(
            target.chain.options.clone(),
            &inventory,
            &evidence.inventory,
            Instant::now() + Duration::from_secs(120),
            cancelled,
        )?;
        ensure!(
            rendered.value().config_toml == original.chain.config_toml,
            "image update would change native configuration"
        );
        let active = evidence.active_images.get(node);
        let update = host_update::Request {
            schema: host_update::SCHEMA.into(),
            original,
            update_id: id,
            expected_image: active.map_or_else(
                || request.image.image.clone(),
                |active| active.image.clone(),
            ),
            expected_update_id: active.map(|active| active.update_id),
            target,
        };
        let bytes = update.bytes()?;
        saved_bytes(&target_dir.join(format!("{node}-request.json")), &bytes)?;
        selected.insert(node.clone(), Pin::of(&bytes));
    }
    let intent = Intent {
        schema: host_update::SCHEMA.into(),
        id,
        deployment_id: deployment.spec.network_id,
        request: Pin::of(&request.bytes()?),
        image,
        artifacts,
        nodes: selected,
    };
    saved_bytes(
        &target_dir.join("intent.json"),
        &serde_json::to_vec(&intent)?,
    )?;
    evidence.pending_update = Some(id);
    foundation::write_json(&root.join(EVIDENCE), &evidence)?;
    Ok(())
}

pub(super) fn validate_pending_source(
    deployment: &Deployment,
    root: &Path,
    id: Uuid,
) -> Result<()> {
    source::load(deployment, root, id)?.context("external update image intent is missing")?;
    Ok(())
}

fn load(
    deployment: &Deployment,
    root: &Path,
    id: Uuid,
) -> Result<(Intent, BTreeMap<String, host_update::Request>)> {
    let intent: Intent = foundation::read_json(&directory(root, id).join("intent.json"))?;
    let request = deployment
        .external
        .as_ref()
        .context("external deployment required")?
        .typed_request()?;
    ensure!(
        intent.schema == host_update::SCHEMA
            && intent.id == id
            && intent.deployment_id == deployment.spec.network_id
            && intent.request == Pin::of(&request.bytes()?),
        "external update intent differs"
    );
    let requirements = request.validate()?;
    requirements.validate_image(&intent.image)?;
    let prefix = format!(
        "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
        deployment.team.aws.account_id, deployment.team.aws.region, deployment.team.team_id
    );
    ensure!(
        intent.image.image.starts_with(&prefix),
        "external update image is outside the team registry"
    );
    let limits = [
        ("image.json", crate::image::MAX_RECORD_BYTES as u64),
        (
            "image-manifest.json",
            crate::image::MAX_MANIFEST_BYTES as u64,
        ),
        ("image-config.json", crate::image::MAX_CONFIG_BYTES as u64),
    ];
    ensure!(
        intent.artifacts.len() == limits.len(),
        "external update requires exactly three image proofs"
    );
    let mut proofs = BTreeMap::new();
    for (name, limit) in limits {
        let artifact = intent
            .artifacts
            .get(name)
            .context("external image proof missing")?;
        let bytes = devnet::read_bounded(&directory(root, id).join(name), limit)?;
        Pin {
            bytes: artifact.bytes,
            sha256: artifact.sha256.clone(),
        }
        .check(&bytes)?;
        proofs.insert(name, bytes);
    }
    let image = crate::image::ImageRecord::from_json_for_requirements(
        &proofs["image.json"],
        &requirements,
    )?;
    ensure!(
        serde_json::to_value(&image)? == serde_json::to_value(&intent.image)?,
        "external update record differs"
    );
    let proof = crate::image::validate_manifest_bytes_for_requirements(
        &image,
        &requirements,
        &proofs["image-manifest.json"],
    )?;
    crate::image::validate_config_bytes_for_requirements(
        &image,
        &requirements,
        &proof,
        &proofs["image-config.json"],
    )?;
    if let Some(source) = source::load(deployment, root, id)? {
        source.contract.validate_image(&image)?;
        ensure!(
            intent
                .nodes
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
                == source
                    .nodes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>(),
            "external source and runtime target sets differ"
        );
    }
    ensure!(!intent.nodes.is_empty(), "external update has no nodes");
    let mut updates = BTreeMap::new();
    for (node, pin) in &intent.nodes {
        ensure!(
            deployment
                .node_topology()?
                .nodes()
                .iter()
                .any(|member| member.node_id == *node),
            "external update node is outside the saved cohort"
        );
        let bytes = devnet::read_bounded(
            &directory(root, id).join(format!("{node}-request.json")),
            crate::host::runtime::revision::MAX_REQUEST_BYTES,
        )?;
        pin.check(&bytes)?;
        let update = host_update::Request::from_slice(&bytes)?;
        ensure!(
            update.update_id == id && update.original.provisioning.node_id == *node,
            "external node update binding differs"
        );
        ensure!(
            evidence_original(root, node, &update.original)?,
            "external update original manifest differs"
        );
        ensure!(
            serde_json::to_value(&update.target.image)? == serde_json::to_value(&intent.image)?,
            "external target image differs"
        );
        for (name, actual) in [
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
            ensure!(
                serde_json::to_value(actual)?
                    == serde_json::to_value(image_object(
                        deployment,
                        name,
                        &intent.artifacts[name]
                    )?)?,
                "external image source differs from immutable update evidence"
            );
        }
        updates.insert(node.clone(), update);
    }
    Ok((intent, updates))
}

fn evidence_original(root: &Path, node: &str, original: &RuntimeRequest) -> Result<bool> {
    Ok(devnet::read_bounded(
        &root.join(format!("{node}-external-runtime.json")),
        16 * 1024 * 1024,
    )? == original.bytes()?)
}

/// Bind already admitted immutable update bytes to the existing operation
/// receipt. Image-only updates have no source/archive pair; source updates pin
/// both together. This pure boundary never authorizes execution by itself.
pub fn operation_inputs(
    deployment: &Deployment,
    input: &[u8],
    source_archive_sha256: Option<&str>,
) -> Result<OperationInput> {
    let inputs = OperationInput {
        config_sha256: devnet::sha256(&serde_json::to_vec(&(&deployment.spec, input))?),
        source_manifest_sha256: source_archive_sha256.map(|_| devnet::sha256(input)),
        archive_sha256: source_archive_sha256.map(str::to_owned),
    };
    inputs.validate()?;
    Ok(inputs)
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.update.apply")
)]
pub fn apply<A: AwsApi, R: PulumiRunner, T: Runtime>(
    store: &StateStore,
    file: &DeploymentFile,
    binding: &Binding,
    deployment: &mut Deployment,
    backend: &mut LiveBackend<'_, A, R, T>,
    id: Uuid,
    reconcile: bool,
    progress: &mut OperationProgress<'_>,
) -> Result<OperationReceipt> {
    let root = file.directory();
    let source = source::load(deployment, root, id)?;
    let image = if directory(root, id).join("intent.json").try_exists()? {
        Some(load(deployment, root, id)?)
    } else {
        None
    };
    ensure!(
        source.is_some() || image.is_some(),
        "external update inputs missing"
    );
    let (_, mut evidence) = load_inventory(deployment, root)?;
    ensure!(
        evidence.pending_update == Some(id)
            || (reconcile
                && evidence.pending_update.is_none()
                && image
                    .as_ref()
                    .is_some_and(|(_, updates)| updates.keys().all(|node| evidence
                        .active_images
                        .get(node)
                        .is_some_and(|active| active.update_id == id)))),
        "external update is not the saved pending selection"
    );
    if let Some(previous) = deployment.last_operation {
        let receipt = store.operation(previous)?;
        ensure!(
            reconcile
                || receipt
                    .phases
                    .iter()
                    .all(|p| matches!(p.status, PhaseStatus::Succeeded { .. })),
            "previous operation requires --reconcile"
        );
    }
    let input = if let Some(source) = &source {
        serde_json::to_vec(source)?
    } else {
        serde_json::to_vec(&image.as_ref().context("external image intent missing")?.0)?
    };
    let mut receipt = store.begin_operation(
        binding,
        "external-update",
        operation_inputs(
            deployment,
            &input,
            source
                .as_ref()
                .map(|source| source.contract.source_sha256.as_str()),
        )?,
        &[
            "verify",
            "reserve",
            "lease",
            "preflight",
            "build",
            "update",
            "readiness",
        ],
    )?;
    deployment.last_operation = Some(receipt.operation_id);
    deployment.unresolved_operation = Some(receipt.operation_id);
    file.save(deployment)?;
    let result = (|| {
        progress(&receipt, None)?;
        foundation::phase(store, &mut receipt, "verify", false, progress, || {
            backend.verify(deployment, false)
        })?;
        foundation::phase(store, &mut receipt, "reserve", true, progress, || {
            backend.reserve(deployment)
        })?;
        let operation_id = receipt.operation_id;
        foundation::phase(store, &mut receipt, "lease", true, progress, || {
            backend.acquire(deployment, operation_id)
        })?;
        foundation::phase(store, &mut receipt, "preflight", false, progress, || {
            let nodes = source
                .as_ref()
                .map(|source| source.nodes.clone())
                .unwrap_or_else(|| {
                    image
                        .as_ref()
                        .map(|(_, updates)| updates.keys().cloned().collect())
                        .unwrap_or_default()
                });
            preflight(backend, deployment, &nodes)?;
            if !reconcile {
                backend.observe_external(deployment, true)?;
            }
            Ok(json!({"ownershipChecked":true,"freshReadinessChecked":!reconcile}))
        })?;
        foundation::phase(store, &mut receipt, "build", true, progress, || {
            if let Some(source) = &source {
                let build = directory(root, id).join("build");
                backend.build_update(
                    &source.contract,
                    &directory(root, id).join("source-snapshot/source.tar"),
                    &build,
                    &mut |_| Ok(()),
                )?;
                if !directory(root, id).join("intent.json").try_exists()? {
                    prepare_image(
                        deployment,
                        root,
                        &source.nodes,
                        &build.join("image.json"),
                        &build.join("image-manifest.json"),
                        &build.join("image-config.json"),
                        &backend.cancel,
                        id,
                        true,
                    )?;
                }
            }
            Ok(json!({"sourceBuild":source.is_some()}))
        })?;
        let (intent, updates) = load(deployment, root, id)?;
        backend.verify_external_image(
            deployment,
            &intent.image,
            &deployment
                .external
                .as_ref()
                .context("external deployment required")?
                .typed_request()?
                .validate()?,
            &directory(root, id).join("image-manifest.json"),
        )?;
        foundation::phase(store, &mut receipt, "update", true, progress, || {
            preflight(
                backend,
                deployment,
                &updates.keys().cloned().collect::<Vec<_>>(),
            )?;
            let files = intent
                .artifacts
                .iter()
                .map(|(name, a)| {
                    Ok((
                        crate::host::S3Object {
                            bucket: deployment.team.backend_bucket()?.into(),
                            key: format!(
                                "{}{}/{name}",
                                devnet::artifact_prefix(&deployment.team, &deployment.spec),
                                a.sha256
                            ),
                            sha256: a.sha256.clone(),
                            bytes: a.bytes,
                            owner_account: deployment.team.aws.account_id.clone(),
                            region: deployment.team.aws.region.clone(),
                        },
                        directory(root, id).join(name),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            backend.poll()?;
            devnet::upload_files(&backend.aws, &deployment.team, &files)?;
            for (node, request) in &updates {
                let output = deployment
                    .outputs
                    .as_ref()
                    .context("external outputs missing")?
                    .nodes
                    .get(node)
                    .context("external update node missing")?;
                let script = backend.external_script(
                    deployment,
                    &format!("{node}-external-update-{id}"),
                    &request.render()?,
                )?;
                let journal = directory(root, id).join(format!("{node}-command.json"));
                let value = backend.remote(&output.instance_id, &script, &journal, TIMEOUT)?;
                ensure!(
                    value
                        == json!({"schema":host_update::SCHEMA,"updateId":id,"phase":"done","runtime":Pin::of(&request.target.bytes()?)}),
                    "external update did not prove target completion"
                );
                evidence.active_images.insert(
                    node.clone(),
                    ActiveImage {
                        update_id: id,
                        image: intent.image.image.clone(),
                        runtime: Pin::of(&request.target.bytes()?),
                    },
                );
                foundation::write_json(&root.join(EVIDENCE), &evidence)?;
            }
            Ok(json!({"updateId":id,"nodes":intent.nodes.keys().collect::<Vec<_>>()}))
        })?;
        foundation::phase(store, &mut receipt, "readiness", false, progress, || {
            backend.observe_external(deployment, true)
        })?;
        let endpoints = endpoint_file(deployment, root)?;
        saved_bytes(
            &directory(root, id).join("client-endpoints.json"),
            &serde_json::to_vec_pretty(&endpoints)?,
        )?;
        foundation::write_json(&root.join("client-endpoints.json"), &endpoints)?;
        deployment.unresolved_operation = None;
        file.save(deployment)?;
        // Publish completion last: a crash at either preceding write remains
        // resumable using this UUID and its already confirmed command receipts.
        evidence.pending_update = None;
        foundation::write_json(&root.join(EVIDENCE), &evidence)?;
        Ok::<_, eyre::Report>(())
    })();
    let released = backend.release();
    result?;
    released?;
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.update.preflight")
)]
pub(super) fn preflight<A: AwsApi, R: PulumiRunner, T: Runtime>(
    backend: &mut LiveBackend<'_, A, R, T>,
    deployment: &Deployment,
    nodes: &[String],
) -> Result<()> {
    let outputs = deployment
        .outputs
        .as_ref()
        .context("external outputs missing")?;
    ensure!(!nodes.is_empty(), "external update node selection missing");
    for node in nodes {
        let target = outputs
            .nodes
            .get(node)
            .context("external update node missing")?;
        backend.poll()?;
        // These independent reads still precede every effect. Validate both
        // responses below, including the exact saved host/volume attachment.
        let responses = backend.aws.batch_call(
            "ec2",
            &[
                aws::AwsCall {
                    operation: "describe-instances",
                    input: json!({"InstanceIds":[target.instance_id]}),
                    extra_args: vec![],
                },
                aws::AwsCall {
                    operation: "describe-volumes",
                    input: json!({"VolumeIds":[target.volume_id]}),
                    extra_args: vec![],
                },
            ],
        )?;
        let [instance_response, volume_response]: [_; 2] = responses
            .try_into()
            .map_err(|_| eyre::eyre!("incomplete external host preflight batch"))?;
        let response = instance_response?;
        let reservations = array(&response, "Reservations")?;
        ensure!(
            response.get("NextToken").is_none() && reservations.len() == 1,
            "incomplete external host inventory"
        );
        let instances = array(&reservations[0], "Instances")?;
        ensure!(
            instances.len() == 1,
            "external update requires exactly one saved host"
        );
        let instance = &instances[0];
        ensure!(
            instance["InstanceId"] == target.instance_id
                && instance["State"]["Name"] == "running"
                && instance["VpcId"] == outputs.vpc_id
                && instance["SubnetId"] == outputs.private_subnet_id
                && instance["PrivateIpAddress"] == target.private_ip.to_string(),
            "external update host differs"
        );
        let tags = array(instance, "Tags")?;
        for (key, value) in [
            ("zdn:network-id", deployment.spec.network_id.to_string()),
            ("zdn:team-id", deployment.team.team_id.clone()),
            ("zdn:managed-by", "zdn".into()),
            ("zdn:bootstrap", deployment.team.bootstrap_id.to_string()),
            ("zdn:node-id", node.clone()),
        ] {
            ensure!(
                tags.iter().filter(|tag| tag["Key"] == key).count() == 1
                    && tags
                        .iter()
                        .any(|tag| tag["Key"] == key && tag["Value"] == value),
                "external update host ownership differs"
            );
        }
        backend.poll()?;
        let response = volume_response?;
        let volumes = array(&response, "Volumes")?;
        ensure!(
            response.get("NextToken").is_none()
                && volumes.len() == 1
                && volumes[0]["VolumeId"] == target.volume_id
                && owned_chain_volume(&volumes[0], deployment)?,
            "external update volume ownership differs"
        );
        let attachments = array(&volumes[0], "Attachments")?;
        ensure!(
            volumes[0]["State"] == "in-use"
                && attachments.len() == 1
                && attachments[0]["InstanceId"] == target.instance_id
                && attachments[0]["State"] == "attached",
            "external update volume attachment differs"
        );
    }
    Ok(())
}

pub(super) fn effective(
    root: &Path,
    node: &str,
    evidence: &Evidence,
    original: &RuntimeRequest,
) -> Result<RuntimeRequest> {
    if let Some(active) = evidence.active_images.get(node) {
        let bytes = devnet::read_bounded(
            &directory(root, active.update_id).join(format!("{node}-request.json")),
            crate::host::runtime::revision::MAX_REQUEST_BYTES,
        )?;
        let request = host_update::Request::from_slice(&bytes)?;
        active.runtime.check(&request.target.bytes()?)?;
        ensure!(
            request.original.bytes()? == original.bytes()?
                && request.update_id == active.update_id
                && request.target.image.image == active.image,
            "external active image lost original authority"
        );
        Ok(request.target)
    } else {
        Ok(original.clone())
    }
}
