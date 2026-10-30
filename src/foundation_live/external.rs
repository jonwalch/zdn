//! External controller dispatch through the existing foundation reservation,
//! lease, Pulumi, immutable upload and durable SSM command machinery.
use super::*;
use crate::{
    devnet,
    host::external::{identity, Provisioning},
    native_peers::{NativeCohort, NativeInventoryStore},
    public_chain_adapter::contract::{Pin, RenderOptions},
};
use std::collections::BTreeMap;

pub const RUNTIME_PROTOCOL: &str = "zdn-external-runtime/v1";
const EVIDENCE: &str = "external-evidence.json";
const TIMEOUT: u32 = 7200;

pub type RuntimeRequest = crate::host::external::runtime::Manifest;
pub mod health;
pub mod qualification;
pub mod update;

/// Existing native build cleanup admission, not adapter compatibility. Never
/// destroy around an active/unknown billed build or submit work to settle it.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.verify_cleanup_builds")
)]
pub(super) fn verify_cleanup_builds(
    api: &dyn AwsApi,
    deployment: &Deployment,
    root: &Path,
) -> Result<()> {
    let updates = root.join("external-updates");
    if !updates.try_exists()? {
        return Ok(());
    }
    ensure!(
        std::fs::symlink_metadata(&updates)?.is_dir(),
        "invalid external update directory"
    );
    for entry in std::fs::read_dir(updates)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_dir(),
            "invalid external update proof directory"
        );
        Uuid::parse_str(
            entry
                .file_name()
                .to_str()
                .context("invalid external update UUID")?,
        )?;
        let build = entry.path().join("build");
        if build.try_exists()? {
            crate::build_job::reconcile_for_removal(api, &build, &deployment.team)?;
        }
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveImage {
    update_id: Uuid,
    image: String,
    runtime: Pin,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Evidence {
    schema: String,
    request: Pin,
    cohort: Pin,
    inventory: Pin,
    inventory_json: String,
    /// A pending identity result bridges the create-only inventory publication
    /// and the atomic evidence write. Recovery may complete only this exact edge.
    pending_identity: Option<String>,
    manifests: BTreeMap<String, Pin>,
    pending_update: Option<Uuid>,
    active_images: BTreeMap<String, ActiveImage>,
}

fn saved_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            devnet::read_bounded(path, 32 * 1024 * 1024)? == bytes,
            "saved external execution input changed"
        );
        Ok(())
    } else {
        foundation::write_private(path, bytes)
    }
}

fn cohort(deployment: &Deployment) -> Result<NativeCohort> {
    let external = deployment
        .external
        .as_ref()
        .context("missing external deployment")?;
    let request = external.typed_request()?;
    NativeCohort::new(
        deployment.spec.network_id,
        request.artifacts["descriptor.json"].sha256.clone(),
        request.compiled.native_fingerprint,
        &external.topology()?,
        &deployment
            .outputs
            .as_ref()
            .context("missing external outputs")?
            .nodes,
        external.listener()?,
    )
}

fn options(
    deployment: &Deployment,
    node: &str,
    provisioning: &Provisioning,
    identity_only: bool,
) -> Result<RenderOptions> {
    let external = deployment
        .external
        .as_ref()
        .context("missing external request")?;
    let request = external.typed_request()?;
    let root = provisioning.node_root();
    Ok(RenderOptions {
        deployment_id: deployment.spec.network_id.to_string(),
        node_id: node.into(),
        role: if !identity_only && node == "node-1" {
            "producer"
        } else {
            "follower"
        }
        .into(),
        image_digest: request.image.manifest_digest()?.into(),
        state_dir: format!("{root}/state"),
        identity_dir: format!("{root}/identity"),
        cookie_dir: format!("{root}/rpc"),
        rpc_listen: "127.0.0.1:18232".into(),
        native_listen: format!("0.0.0.0:{}", external.native_port),
        expected_node_id: String::new(),
        peers: Vec::new(),
        reward_address: (!identity_only && node == "node-1")
            .then(|| external.reward_address.clone()),
    })
}

/// Read the pinned cohort without a companion invocation. Used by recovery and
/// observation admission; no missing inventory is silently reinitialized.
fn load_inventory(
    deployment: &Deployment,
    directory: &Path,
) -> Result<(NativeInventoryStore, Evidence)> {
    let expected = cohort(deployment)?;
    let store =
        NativeInventoryStore::open_existing(&directory.join("native-inventory"), expected.clone())?;
    let evidence: Evidence = foundation::read_json(&directory.join(EVIDENCE))?;
    let request = deployment
        .external
        .as_ref()
        .context("missing external request")?
        .typed_request()?;
    ensure!(
        evidence.schema == RUNTIME_PROTOCOL
            && evidence.request == Pin::of(&request.bytes()?)
            && evidence.cohort == expected.pin()?,
        "external lifecycle evidence differs"
    );
    evidence
        .inventory
        .check(evidence.inventory_json.as_bytes())?;
    if evidence.pending_identity.is_none() {
        store.read_pinned(&evidence.inventory)?;
    } else {
        let before: Value = serde_json::from_str(&evidence.inventory_json)?;
        let mut current = serde_json::to_value(store.read()?)?;
        if current != before {
            current["entries"]
                .as_object_mut()
                .context("invalid external inventory entries")?
                .remove(
                    evidence
                        .pending_identity
                        .as_ref()
                        .context("pending identity missing")?,
                );
            ensure!(
                current == before,
                "uncommitted native inventory changed outside the pending member"
            );
        }
    }
    Ok((store, evidence))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.external.validate_saved")
)]
pub fn validate_saved(deployment: &Deployment, directory: &Path) -> Result<()> {
    deployment.validate()?;
    let Some(external) = &deployment.external else {
        return Ok(());
    };
    let request = external.typed_request()?;
    ensure!(
        devnet::read_bounded(
            &directory.join("artifacts/external-request.json"),
            4 * 1024 * 1024
        )? == request.bytes()?,
        "saved external request bytes differ"
    );
    if directory.join(EVIDENCE).try_exists()? {
        let (store, evidence) = load_inventory(deployment, directory)?;
        if evidence.pending_identity.is_none() {
            let inventory = store.read_pinned(&evidence.inventory)?;
            for (node, pin) in &evidence.manifests {
                ensure!(
                    inventory.is_complete(),
                    "runtime manifest precedes complete native cohort"
                );
                let bytes = devnet::read_bounded(
                    &directory.join(format!("{node}-external-runtime.json")),
                    16 * 1024 * 1024,
                )?;
                pin.check(&bytes)?;
                let runtime = RuntimeRequest::from_slice(&bytes)?;
                let output = deployment
                    .outputs
                    .as_ref()
                    .context("external outputs missing")?
                    .nodes
                    .get(node)
                    .context("external manifest names a foreign node")?;
                let provisioning = Provisioning::from_slice(&devnet::read_bounded(
                    &directory.join(format!("{node}-external-provisioning.json")),
                    8192,
                )?)?;
                let mut expected_options = options(deployment, node, &provisioning, false)?;
                inventory.bind_render_options(&mut expected_options)?;
                let allocation = deployment.spec.size.allocation();
                ensure!(
                    runtime.chain.native_inventory == evidence.inventory
                        && provisioning.deployment_id == deployment.spec.network_id
                        && provisioning.node_id == *node
                        && provisioning.volume_id == output.volume_id
                        && provisioning.request == evidence.request
                        && provisioning.descriptor_sha256
                            == request.artifacts["descriptor.json"].sha256
                        && provisioning.native_fingerprint == request.compiled.native_fingerprint
                        && runtime.provisioning.bytes()? == provisioning.bytes()?
                        && runtime.chain.request == evidence.request
                        && runtime.chain.compiled_json.as_bytes()
                            == serde_json::to_vec(&request.compiled)?
                        && serde_json::to_value(&runtime.chain.trust)?
                            == serde_json::to_value(&request.trust)?
                        && serde_json::to_value(&runtime.chain.objects)?
                            == serde_json::to_value(
                                request.objects(&deployment.team, &deployment.spec)?
                            )?
                        && serde_json::to_value(&runtime.chain.options)?
                            == serde_json::to_value(expected_options)?
                        && serde_json::to_value(&runtime.image)?
                            == serde_json::to_value(&request.image)?
                        && runtime.memory_bytes == u64::from(allocation.max_node_gib) * GIB
                        && runtime.cpu_millis
                            == allocation.vcpus * 1000 - crate::infra::HOST_CPU_RESERVE_MILLIS
                        && runtime.host_reserve_bytes
                            == u64::from(allocation.host_reserve_gib) * GIB
                        && runtime.production_limits == request.production_limits
                        && runtime.block_interval_seconds
                            == (node == "node-1").then_some(request.block_interval_seconds),
                    "external runtime pin differs"
                );
            }
        }
    }
    Ok(())
}

/// Portable public connection binding for the currently confirmed host revision.
/// This reads pinned local evidence only; it never discovers or runs an adapter.
pub fn endpoint_file(
    deployment: &Deployment,
    directory: &Path,
) -> Result<crate::endpoints::EndpointFile> {
    validate_saved(deployment, directory)?;
    let (_, evidence) = load_inventory(deployment, directory)?;
    let original = RuntimeRequest::from_slice(&devnet::read_bounded(
        &directory.join("node-1-external-runtime.json"),
        16 * 1024 * 1024,
    )?)?;
    let runtime = update::effective(directory, "node-1", &evidence, &original)?;
    crate::endpoints::EndpointFile::from_external(
        deployment.spec.scope.clone(),
        deployment.team.bootstrap_id,
        deployment
            .external
            .as_ref()
            .context("missing external request")?
            .node_count,
        deployment
            .outputs
            .as_ref()
            .context("missing external outputs")?
            .nodes["node-1"]
            .instance_id
            .clone(),
        &runtime.chain,
    )
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.external.verify_external")
    )]
    pub(super) fn verify_external(&mut self, deployment: &Deployment) -> Result<()> {
        validate_saved(deployment, &self.deployment_directory)?;
        let request = deployment
            .external
            .as_ref()
            .context("missing external request")?
            .typed_request()?;
        let requirements = request.validate()?;
        request.prepare(
            &self.deployment_directory.join("artifacts"),
            Instant::now() + Duration::from_secs(120),
            &self.cancel,
        )?;
        self.verify_runtime_access(deployment)?;
        self.verify_external_image(
            deployment,
            &request.image,
            &requirements,
            &self
                .deployment_directory
                .join("artifacts/image-manifest.json"),
        )?;
        // A retained host revision is not permission to reuse a missing or
        // requirement-incompatible image merely because the initial image exists.
        if self.deployment_directory.join(EVIDENCE).try_exists()? {
            let (_, evidence) = load_inventory(deployment, &self.deployment_directory)?;
            let ids: std::collections::BTreeSet<_> = evidence
                .active_images
                .values()
                .map(|active| active.update_id)
                .chain(evidence.pending_update)
                .collect();
            for id in ids {
                if evidence.pending_update == Some(id)
                    && !self
                        .deployment_directory
                        .join("external-updates")
                        .join(id.to_string())
                        .join("intent.json")
                        .try_exists()?
                {
                    update::validate_pending_source(deployment, &self.deployment_directory, id)?;
                    continue;
                }
                let (image, manifest) =
                    update::image_inputs(deployment, &self.deployment_directory, id)?;
                self.verify_external_image(deployment, &image, &requirements, &manifest)?;
            }
        }
        Ok(())
    }

    fn verify_external_image(
        &mut self,
        deployment: &Deployment,
        image: &crate::image::ImageRecord,
        requirements: &crate::image::ImageBuildRequirements,
        manifest: &Path,
    ) -> Result<()> {
        requirements.validate_image(image)?;
        self.poll()?;
        let prefix = format!(
            "{}.dkr.ecr.{}.amazonaws.com/zdn/{}/",
            deployment.team.aws.account_id, deployment.team.aws.region, deployment.team.team_id
        );
        let tail = image
            .image
            .strip_prefix(&prefix)
            .context("external image must use same-team regional ECR")?;
        let repository = tail
            .split_once('@')
            .context("external image digest missing")?
            .0;
        ensure!(!repository.is_empty(), "external image repository missing");
        let response = self.aws.call("ecr", "batch-get-image", json!({"registryId":deployment.team.aws.account_id,"repositoryName":format!("zdn/{}/{repository}",deployment.team.team_id),"imageIds":[{"imageDigest":image.manifest_digest()?}],"acceptedMediaTypes":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"]}), &[])?;
        ensure!(
            response["failures"].as_array().is_some_and(Vec::is_empty),
            "external ECR image unavailable"
        );
        let images = array(&response, "images")?;
        ensure!(
            images.len() == 1 && images[0]["imageId"]["imageDigest"] == image.manifest_digest()?,
            "external ECR image differs"
        );
        let bytes = images[0]["imageManifest"]
            .as_str()
            .context("external ECR manifest missing")?
            .as_bytes();
        ensure!(
            bytes == devnet::read_bounded(manifest, crate::image::MAX_MANIFEST_BYTES as u64)?,
            "external ECR manifest bytes differ"
        );
        crate::image::validate_manifest_bytes_for_requirements(image, requirements, bytes)?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.external.stage_external_artifacts")
    )]
    pub(super) fn stage_external_artifacts(&mut self, deployment: &Deployment) -> Result<()> {
        let request = deployment
            .external
            .as_ref()
            .context("missing external request")?
            .typed_request()?;
        request.prepare(
            &self.deployment_directory.join("artifacts"),
            Instant::now() + Duration::from_secs(120),
            &self.cancel,
        )?;
        let objects = request.objects(&deployment.team, &deployment.spec)?;
        let files: Vec<_> = objects
            .slots()
            .into_iter()
            .map(|(name, object, _)| {
                (
                    object.clone(),
                    self.deployment_directory.join("artifacts").join(name),
                )
            })
            .collect();
        for chunk in files.chunks(4) {
            self.poll()?;
            devnet::upload_files(&self.aws, &deployment.team, chunk)?;
        }
        self.poll()
    }

    fn external_script(
        &mut self,
        deployment: &Deployment,
        stem: &str,
        script: &str,
    ) -> Result<String> {
        let path = self.deployment_directory.join(format!("{stem}-install.sh"));
        saved_bytes(&path, script.as_bytes())?;
        let pin = Pin::of(script.as_bytes());
        let object = cluster::installer_object(deployment, stem, &pin.sha256, script.len())?;
        self.poll()?;
        devnet::upload_file(&self.aws, &deployment.team, &object, &path)?;
        cluster::selected_fetch_installer(deployment, &object, TIMEOUT)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.external.install_external")
    )]
    pub(super) fn install_external(&mut self, deployment: &Deployment) -> Result<Value> {
        let external = deployment
            .external
            .as_ref()
            .context("missing external request")?;
        let request = external.typed_request()?;
        let objects = request.objects(&deployment.team, &deployment.spec)?;
        let outputs = deployment
            .outputs
            .as_ref()
            .context("missing external outputs")?;
        self.authorize_new_volumes(deployment)?;
        let expected = cohort(deployment)?;
        let evidence_path = self.deployment_directory.join(EVIDENCE);
        let (store, mut evidence) = if evidence_path.try_exists()? {
            load_inventory(deployment, &self.deployment_directory)?
        } else {
            // An unpinned existing inventory is not permission to adopt IDs.
            let path = self.deployment_directory.join("native-inventory");
            let store = if path.try_exists()? {
                NativeInventoryStore::open_existing(&path, expected.clone())?
            } else {
                NativeInventoryStore::open(&path, expected.clone())?
            };
            let inventory = store.read()?;
            ensure!(
                inventory.completed_count() == 0,
                "unbound external inventory requires evidence recovery"
            );
            let evidence = Evidence {
                schema: RUNTIME_PROTOCOL.into(),
                request: Pin::of(&request.bytes()?),
                cohort: expected.pin()?,
                inventory: inventory.pin()?,
                inventory_json: serde_json::to_string(&inventory)?,
                pending_identity: None,
                manifests: BTreeMap::new(),
                pending_update: None,
                active_images: BTreeMap::new(),
            };
            foundation::write_json(&evidence_path, &evidence)?;
            (store, evidence)
        };
        ensure!(
            evidence.pending_update.is_none(),
            "resume the pending external image update before up"
        );
        if !evidence.active_images.is_empty() {
            // Installed revisions keep their original manifest/volume authority.
            // Up never republishes or reinstalls the old first-launch image.
            return self.observe_external(deployment, true);
        }
        for node in outputs.nodes.values() {
            if evidence.pending_identity.as_deref() != Some(node.node_id.as_str())
                && store.read()?.expected_node_id(&node.node_id).is_ok()
            {
                continue;
            }
            let provisioning = Provisioning {
                schema: "zdn-external-provisioning/v1".into(),
                deployment_id: deployment.spec.network_id,
                node_id: node.node_id.clone(),
                volume_id: node.volume_id.clone(),
                descriptor_sha256: request.artifacts["descriptor.json"].sha256.clone(),
                native_fingerprint: request.compiled.native_fingerprint.clone(),
                request: Pin::of(&request.bytes()?),
                new_volume: self.saved_volume_authorization(deployment, node)?,
            };
            saved_bytes(
                &self
                    .deployment_directory
                    .join(format!("{}-external-provisioning.json", node.node_id)),
                &provisioning.bytes()?,
            )?;
            let identity = identity::Manifest::new(
                request.clone(),
                provisioning,
                objects.clone(),
                options(
                    deployment,
                    &node.node_id,
                    &Provisioning::from_slice(&devnet::read_bounded(
                        &self
                            .deployment_directory
                            .join(format!("{}-external-provisioning.json", node.node_id)),
                        8192,
                    )?)?,
                    true,
                )?,
                &self.deployment_directory.join("artifacts"),
                Instant::now() + Duration::from_secs(120),
                &self.cancel,
            )?;
            let stem = format!("{}-external-identity", node.node_id);
            saved_bytes(
                &self.deployment_directory.join(format!("{stem}.json")),
                &identity.bytes()?,
            )?;
            let script = self.external_script(
                deployment,
                &stem,
                &crate::host::runtime::bootstrap::render_external_identity(&identity)?,
            )?;
            let journal = self
                .deployment_directory
                .join(format!("{stem}-command.json"));
            if let Some(pending) = &evidence.pending_identity {
                ensure!(
                    pending == &node.node_id,
                    "finish pending identity evidence before another cohort member"
                );
            } else {
                store.read_pinned(&evidence.inventory)?;
                evidence.pending_identity = Some(node.node_id.clone());
                foundation::write_json(&evidence_path, &evidence)?;
            }
            let value = self
                .remote_batch(&[crate::ssm::CommandRequest {
                    instance_id: node.instance_id.clone(),
                    script,
                    journal_path: journal,
                    timeout_secs: TIMEOUT,
                }])?
                .remove(0);
            let inventory = store.record(&node.node_id, &serde_json::to_vec(&value)?)?;
            evidence.inventory = inventory.pin()?;
            evidence.inventory_json = serde_json::to_string(&inventory)?;
            evidence.pending_identity = None;
            foundation::write_json(&evidence_path, &evidence)?;
        }
        let inventory = store.read_pinned(&evidence.inventory)?;
        ensure!(inventory.is_complete(), "external native cohort incomplete");
        // No final runtime render or service activation can precede every ID.
        let mut runtimes = Vec::new();
        for node in outputs.nodes.values() {
            let provisioning = Provisioning::from_slice(&devnet::read_bounded(
                &self
                    .deployment_directory
                    .join(format!("{}-external-provisioning.json", node.node_id)),
                8192,
            )?)?;
            let manifest = request.host_manifest(
                &self.deployment_directory.join("artifacts"),
                objects.clone(),
                options(deployment, &node.node_id, &provisioning, false)?,
                &inventory,
                &evidence.inventory,
                Instant::now() + Duration::from_secs(120),
                &self.cancel,
            )?;
            let allocation = deployment.spec.size.allocation();
            let runtime = RuntimeRequest {
                schema: RUNTIME_PROTOCOL.into(),
                provisioning,
                chain: manifest,
                image: request.image.clone(),
                memory_bytes: u64::from(allocation.max_node_gib) * GIB,
                cpu_millis: allocation.vcpus * 1000 - crate::infra::HOST_CPU_RESERVE_MILLIS,
                host_reserve_bytes: u64::from(allocation.host_reserve_gib) * GIB,
                production_limits: request.production_limits.clone(),
                block_interval_seconds: (node.node_id == "node-1")
                    .then_some(request.block_interval_seconds),
            };
            let bytes = runtime.bytes()?;
            saved_bytes(
                &self
                    .deployment_directory
                    .join(format!("{}-external-runtime.json", node.node_id)),
                &bytes,
            )?;
            evidence
                .manifests
                .insert(node.node_id.clone(), Pin::of(&bytes));
            runtimes.push((node, runtime));
        }
        foundation::write_json(&evidence_path, &evidence)?;
        for (node, runtime) in &runtimes {
            let script = self.external_script(
                deployment,
                &format!("{}-external-runtime", node.node_id),
                &runtime_script(runtime, "install")?,
            )?;
            let journal = self
                .deployment_directory
                .join(format!("{}-external-install-command.json", node.node_id));
            let value = self
                .remote_batch(&[crate::ssm::CommandRequest {
                    instance_id: node.instance_id.clone(),
                    script,
                    journal_path: journal,
                    timeout_secs: TIMEOUT,
                }])?
                .remove(0);
            validate_observation(runtime, &value, false)?;
        }
        // A fresh cohort observation, not the cached install replies, gates the
        // sole producer action. Its own SSM record remains durable on recovery.
        self.observe_external(deployment, false)?;
        let (node, runtime) = runtimes
            .iter()
            .find(|(node, _)| node.node_id == "node-1")
            .context("external producer missing")?;
        let journal = self
            .deployment_directory
            .join("node-1-external-start-producer-command.json");
        let value = self.remote(
            &node.instance_id,
            &runtime_script(runtime, "start-producer")?,
            &journal,
            TIMEOUT,
        )?;
        validate_observation(runtime, &value, true)?;
        let gateway_journal = self
            .deployment_directory
            .join("node-1-external-gateway-install-command.json");
        let gateway = self.remote(
            &node.instance_id,
            &runtime_script(runtime, "gateway-install")?,
            &gateway_journal,
            600,
        )?;
        validate_gateway(runtime, &gateway)?;
        let endpoints = crate::endpoints::EndpointFile::from_external(
            deployment.spec.scope.clone(),
            deployment.team.bootstrap_id,
            external.node_count,
            node.instance_id.clone(),
            &runtime.chain,
        )?;
        saved_bytes(
            &self.deployment_directory.join("client-endpoints.json"),
            &serde_json::to_vec_pretty(&endpoints)?,
        )?;
        Ok(json!({"installed":true,"nativeInventory":evidence.inventory,"scheduledProducer":true}))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.external.observe_external")
    )]
    pub(super) fn observe_external(
        &mut self,
        deployment: &Deployment,
        producer: bool,
    ) -> Result<Value> {
        validate_saved(deployment, &self.deployment_directory)?;
        let (_, evidence) = load_inventory(deployment, &self.deployment_directory)?;
        ensure!(
            evidence.pending_identity.is_none()
                && evidence.manifests.len()
                    == usize::from(
                        deployment
                            .external
                            .as_ref()
                            .context("missing external request")?
                            .node_count
                    ),
            "external runtime cohort incomplete"
        );
        let mut observations = BTreeMap::new();
        for node in deployment
            .outputs
            .as_ref()
            .context("missing external outputs")?
            .nodes
            .values()
        {
            let runtime = RuntimeRequest::from_slice(&devnet::read_bounded(
                &self
                    .deployment_directory
                    .join(format!("{}-external-runtime.json", node.node_id)),
                16 * 1024 * 1024,
            )?)?;
            let journal = self.deployment_directory.join(format!(
                "{}-external-observe-{}.json",
                node.node_id,
                Uuid::new_v4()
            ));
            let value = self.remote(
                &node.instance_id,
                &runtime_script(&runtime, "observe")?,
                &journal,
                300,
            )?;
            let effective = update::effective(
                &self.deployment_directory,
                &node.node_id,
                &evidence,
                &runtime,
            )?;
            validate_observation(&effective, &value, producer && node.node_id == "node-1")?;
            if producer && node.node_id == "node-1" {
                let gateway_journal = self.deployment_directory.join(format!(
                    "node-1-external-gateway-observe-{}.json",
                    Uuid::new_v4()
                ));
                let gateway = self.remote(
                    &node.instance_id,
                    &runtime_script(&runtime, "gateway-observe")?,
                    &gateway_journal,
                    300,
                )?;
                validate_gateway(&effective, &gateway)?;
            }
            observations.insert(node.node_id.clone(), value);
        }
        Ok(
            json!({"nodes":observations,"scheduledProducer":producer,"nativeInventory":evidence.inventory}),
        )
    }
}

/// Strict binding of authenticated SSM stdout. A host reply cannot replace
/// request/manifest/inventory identity or merely assert generic health.
pub fn validate_observation(runtime: &RuntimeRequest, value: &Value, producer: bool) -> Result<()> {
    runtime.validate_ready_observation(value)?;
    if producer {
        ensure!(
            value["producer"]["controllerLocked"] == true
                && value["producer"]["identity"]
                    == serde_json::to_value(runtime.producer_identity())?
                && value["producer"]["intervalSecs"].as_u64() == runtime.block_interval_seconds
                && matches!(
                    value["producer"]["phase"].as_str(),
                    Some("waiting" | "generating")
                ),
            "external producer is not actively owned"
        );
    }
    Ok(())
}

fn validate_gateway(runtime: &RuntimeRequest, value: &Value) -> Result<()> {
    ensure!(
        *value
            == json!({"apiVersion":crate::client_gateway::OBSERVATION_API_VERSION,
        "deploymentId":runtime.provisioning.deployment_id,"nodeId":runtime.provisioning.node_id,
        "consensusFingerprint":runtime.provisioning.native_fingerprint,
        "serviceSha256":runtime.chain.gateway_service_sha256()?,"endpoint":crate::client_gateway::ENDPOINT,"status":"ready"}),
        "external gateway service binding differs"
    );
    Ok(())
}

/// Hash-checked helper delivery selects one fixed hidden host action. The outer
/// installer transport supplies cloud-init waiting and process supervision.
pub fn runtime_script(runtime: &RuntimeRequest, action: &str) -> Result<String> {
    ensure!(
        [
            "install",
            "observe",
            "start-producer",
            "stop",
            "gateway-install",
            "gateway-observe"
        ]
        .contains(&action),
        "invalid external runtime action"
    );
    if action != "install" {
        use crate::host::external::runtime::control::Operation;
        let operation = match action {
            "observe" => Operation::Observe,
            "start-producer" => Operation::StartProducer,
            "stop" => Operation::Stop,
            "gateway-install" => Operation::GatewayInstall,
            "gateway-observe" => Operation::GatewayObserve,
            _ => unreachable!("validated external runtime action"),
        };
        return runtime.render_operation(operation);
    }
    crate::host::runtime::bootstrap::render_external(runtime)
}
