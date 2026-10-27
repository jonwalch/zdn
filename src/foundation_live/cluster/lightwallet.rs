//! Durable lightwallet installation and current health observations.
#[cfg(test)]
mod tests;
use super::*;
use crate::{
    cluster_infra::{ClusterNodeOutputs, LightwalletLimits},
    host::HostInstallSpec,
    infra::HostObservation,
    lightwallet_service::{self as service, LightwalletInstallSpec, LightwalletServiceSpec},
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapacityReceipt {
    api_version: String,
    deployment_id: Uuid,
    instance_id: String,
    request_sha256: String,
    observation: HostObservation,
    limits: LightwalletLimits,
}

const CAPACITY_TIMEOUT: u32 = 1200;
pub(in crate::foundation_live) const OBSERVATION_TIMEOUT: u32 = 360;
pub(super) const START_TIMEOUT: u32 = 600;

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.lightwallet.live_backend.prepare_lightwallet_capacity"
        )
    )]
    pub(super) fn prepare_lightwallet_capacity(&mut self, deployment: &Deployment) -> Result<()> {
        let request = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?;
        let Some(service) = &request.lightwallet else {
            return Ok(());
        };
        deployment.validate_outputs(
            deployment
                .outputs
                .as_ref()
                .context("missing cluster outputs")?,
        )?;
        let script = capacity_script(deployment)?;
        let node = lightwallet_node(deployment)?;
        let path = self.deployment_directory.join("lightwallet-capacity.json");
        if path.exists() {
            self.lightwallet_capacity(deployment)?;
            return Ok(());
        }
        ensure!(
            !self
                .deployment_directory
                .join(format!("{}-install.sh", node.node_id))
                .exists()
                && !self
                    .deployment_directory
                    .join("lightwallet-install.sh")
                    .exists(),
            "saved lightwallet capacity is missing after installer publication; cannot recapture limits"
        );
        self.wait_for_node(&node.instance_id)?;
        let journal = self
            .deployment_directory
            .join("lightwallet-capacity-command.json");
        let observation: HostObservation = serde_json::from_value(self.remote(
            &node.instance_id,
            &script,
            &journal,
            CAPACITY_TIMEOUT,
        )?)
        .context("decode selected host capacity")?;
        let limits = service
            .allocation
            .effective_limits(deployment.spec.size, &observation)?;
        let receipt = CapacityReceipt {
            api_version: "zdn-lightwallet-capacity/v1alpha1".into(),
            deployment_id: deployment.spec.network_id,
            instance_id: node.instance_id.clone(),
            request_sha256: devnet::sha256(&serde_json::to_vec(request)?),
            observation,
            limits,
        };
        foundation::write_private(&path, &serde_json::to_vec_pretty(&receipt)?)?;
        self.lightwallet_capacity(deployment)?;
        Ok(())
    }

    fn lightwallet_capacity(&self, deployment: &Deployment) -> Result<CapacityReceipt> {
        read_capacity(deployment, &self.deployment_directory)
    }

    pub(super) fn cluster_host_spec(
        &self,
        deployment: &Deployment,
        node: &ClusterNodeOutputs,
    ) -> Result<HostInstallSpec> {
        host_spec(deployment, &self.deployment_directory, node)
    }

    fn lightwallet_spec(&self, deployment: &Deployment) -> Result<LightwalletInstallSpec> {
        install_spec(deployment, &self.deployment_directory)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.lightwallet.live_backend.install_lightwallet"
        )
    )]
    pub(super) fn install_lightwallet(&mut self, deployment: &Deployment) -> Result<Value> {
        if deployment
            .cluster
            .as_ref()
            .is_none_or(|r| r.lightwallet.is_none())
        {
            return Ok(Value::Null);
        }
        let cache = deployment
            .outputs
            .as_ref()
            .and_then(|o| o.lightwallet.as_ref())
            .context("missing lightwallet outputs")?;
        self.authorize_new_lightwallet_volume(deployment, cache)?;
        let spec = self.lightwallet_spec(deployment)?;
        let rendered = selected_lightwallet(
            &self.deployment_directory,
            &spec,
            deployment
                .cluster
                .as_ref()
                .unwrap()
                .native_runtime_protocol
                .as_deref(),
        )?;
        let path = self.deployment_directory.join("lightwallet-install.sh");
        if path.exists() {
            ensure!(
                devnet::read_bounded(&path, 32 * 1024 * 1024)? == rendered.script.as_bytes(),
                "saved lightwallet installer differs; preserve the deployment for recovery"
            );
        } else {
            foundation::write_private(&path, rendered.script.as_bytes())?;
        }
        let object = installer_object(
            deployment,
            "lightwallet",
            &rendered.script_sha256,
            rendered.script.len(),
        )?;
        self.poll()?;
        devnet::upload_file(&self.aws, &deployment.team, &object, &path)?;
        let script = selected_fetch_installer(deployment, &object, INSTALL_TIMEOUT)?;
        let journal = self
            .deployment_directory
            .join("lightwallet-install-command.json");
        let report = self.remote(&cache.instance_id, &script, &journal, INSTALL_TIMEOUT)?;
        ensure!(
            service::validate_observation(&report, &spec)?.status == "ready",
            "lightwallet installation did not establish readiness"
        );
        self.ensure_lightwallet_running(deployment, &spec)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.lightwallet.live_backend.observe_lightwallet"
        )
    )]
    fn observe_lightwallet(
        &mut self,
        deployment: &Deployment,
        spec: &LightwalletInstallSpec,
    ) -> Result<Value> {
        let node = lightwallet_node(deployment)?;
        self.wait_for_node(&node.instance_id)?;
        let journal = self
            .deployment_directory
            .join(format!("lightwallet-observe-{}.json", Uuid::new_v4()));
        let script = native::lightwallet_command(
            deployment
                .cluster
                .as_ref()
                .context("missing cluster request")?
                .native_runtime_protocol
                .as_deref(),
            spec,
            "observe",
        )?;
        let report = self.remote(&node.instance_id, &script, &journal, OBSERVATION_TIMEOUT)?;
        service::validate_observation(&report, spec)?;
        Ok(report)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.lightwallet.live_backend.ensure_lightwallet_running"
        )
    )]
    fn ensure_lightwallet_running(
        &mut self,
        deployment: &Deployment,
        spec: &LightwalletInstallSpec,
    ) -> Result<Value> {
        let node = lightwallet_node(deployment)?;
        let script = native::lightwallet_command(
            deployment
                .cluster
                .as_ref()
                .context("missing cluster request")?
                .native_runtime_protocol
                .as_deref(),
            spec,
            "start",
        )?;
        let timeout = START_TIMEOUT;
        let journal = self
            .deployment_directory
            .join("lightwallet-start-command.json");
        // Start and observe share a nonblocking host lock. Settle a saved start
        // before observing; an in-flight start may still hold that lock.
        if !journal.try_exists()? {
            let report = self.observe_lightwallet(deployment, spec)?;
            if report["status"] == "ready" {
                return Ok(report);
            }
        }
        let report = self.remote(&node.instance_id, &script, &journal, timeout)?;
        ensure!(
            service::validate_observation(&report, spec)?.status == "ready",
            "lightwallet start did not establish readiness"
        );
        let report = self.observe_lightwallet(deployment, spec)?;
        if report["status"] != "ready" {
            crate::ssm::prepare_repeat_after_success(
                &node.instance_id,
                &script,
                &journal,
                timeout,
                &self.runtime,
            )?;
            let report = self.remote(&node.instance_id, &script, &journal, timeout)?;
            ensure!(
                service::validate_observation(&report, spec)?.status == "ready",
                "lightwallet restart did not establish readiness"
            );
        }
        let report = self.observe_lightwallet(deployment, spec)?;
        ensure!(
            report["status"] == "ready",
            "lightwallet service is stopped"
        );
        Ok(report)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.lightwallet.live_backend.observe_lightwallet_ready"
        )
    )]
    pub(super) fn observe_lightwallet_ready(&mut self, deployment: &Deployment) -> Result<Value> {
        let spec = self.lightwallet_spec(deployment)?;
        let report = self.observe_lightwallet(deployment, &spec)?;
        ensure!(
            report["status"] == "ready",
            "lightwallet service is stopped"
        );
        Ok(report)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.lightwallet.host_spec")
)]
pub(in crate::foundation_live) fn host_spec(
    deployment: &Deployment,
    directory: &Path,
    node: &ClusterNodeOutputs,
) -> Result<HostInstallSpec> {
    let request = deployment
        .cluster
        .as_ref()
        .context("missing cluster request")?;
    let mut host = request.host_spec(&deployment.spec, &deployment.team, node)?;
    if request.lightwallet.is_some()
        && node.node_id == request.topology()?.lightwallet_node().node_id
    {
        let receipt = read_capacity(deployment, directory)?;
        host.memory_bytes = receipt.limits.node_memory_bytes;
        host.cpu_millis = receipt.limits.node_cpu_millis;
    }
    Ok(host)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.lightwallet.install_spec")
)]
pub(in crate::foundation_live) fn install_spec(
    deployment: &Deployment,
    directory: &Path,
) -> Result<LightwalletInstallSpec> {
    use super::super::new_volume::{saved_authorization, AuthorizationTarget};
    let request = deployment
        .cluster
        .as_ref()
        .context("missing cluster request")?;
    let requested = request
        .lightwallet
        .as_ref()
        .context("missing lightwallet request")?;
    let outputs = deployment
        .outputs
        .as_ref()
        .context("missing cluster outputs")?;
    deployment.validate_outputs(outputs)?;
    let cache = outputs
        .lightwallet
        .as_ref()
        .context("missing lightwallet cache")?;
    let node = lightwallet_node(deployment)?;
    let mut host = host_spec(deployment, directory, node)?;
    host.new_volume = saved_authorization(deployment, directory, AuthorizationTarget::Node(node))?;
    let capacity = read_capacity(deployment, directory)?;
    Ok(LightwalletInstallSpec {
        api_version: service::INSTALL_API_VERSION.into(),
        host,
        service: LightwalletServiceSpec {
            api_version: service::API_VERSION.into(),
            image: requested.image.image.clone(),
            source_revision: requested.image.source_revision.clone(),
            cache_volume_id: cache.cache_volume_id.clone(),
            cache_bytes: u64::from(cache.cache_size_gib) * GIB,
            memory_bytes: requested.allocation.service_memory_bytes,
            cpu_millis: requested.allocation.service_cpu_millis,
            host_observation: capacity.observation,
        },
        new_volume: saved_authorization(
            deployment,
            directory,
            AuthorizationTarget::Lightwallet(cache),
        )?,
        image_record: request.s3_object(
            &deployment.team,
            &deployment.spec,
            "lightwallet-image.json",
        )?,
        image_manifest: request.s3_object(
            &deployment.team,
            &deployment.spec,
            "lightwallet-image-manifest.json",
        )?,
        image_config: request.s3_object(
            &deployment.team,
            &deployment.spec,
            "lightwallet-image-config.json",
        )?,
    })
}

fn capacity_script(deployment: &Deployment) -> Result<String> {
    let request = deployment
        .cluster
        .as_ref()
        .context("missing cluster request")?;
    let service = request
        .lightwallet
        .as_ref()
        .context("missing lightwallet request")?;
    match service.capacity_protocol.as_deref() {
        None => eyre::bail!("lightwallet capacity requires native selection"),
        Some(crate::host::CAPACITY_PROTOCOL) => crate::host::capacity_bootstrap::render(
            &request.s3_object(&deployment.team, &deployment.spec, "zdn")?,
        ),
        Some(_) => eyre::bail!("unsupported lightwallet capacity protocol"),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.lightwallet.read_capacity")
)]
fn read_capacity(deployment: &Deployment, directory: &Path) -> Result<CapacityReceipt> {
    let request = deployment
        .cluster
        .as_ref()
        .context("missing cluster request")?;
    let service = request
        .lightwallet
        .as_ref()
        .context("missing lightwallet request")?;
    let node = lightwallet_node(deployment)?;
    let receipt: CapacityReceipt =
        foundation::read_json(&directory.join("lightwallet-capacity.json"))?;
    ensure!(
        receipt.api_version == "zdn-lightwallet-capacity/v1alpha1"
            && receipt.deployment_id == deployment.spec.network_id
            && receipt.instance_id == node.instance_id
            && receipt.request_sha256 == devnet::sha256(&serde_json::to_vec(request)?),
        "saved capacity belongs to another deployment, instance, or request"
    );
    ensure!(
        receipt.limits
            == service
                .allocation
                .effective_limits(deployment.spec.size, &receipt.observation)?,
        "saved capacity limits differ from measured allocation"
    );
    Ok(receipt)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(
        skip_all,
        name = "foundation_live.cluster.lightwallet.validate_handoff"
    )
)]
pub(crate) fn validate_handoff(
    deployment: &Deployment,
    directory: &Path,
    observations: ObservationHistory,
) -> Result<()> {
    if deployment.outputs.is_some()
        && deployment
            .cluster
            .as_ref()
            .is_some_and(|r| r.lightwallet.is_some())
    {
        let spec = install_spec(deployment, directory)?;
        let protocol = deployment
            .cluster
            .as_ref()
            .unwrap()
            .native_runtime_protocol
            .as_deref();
        let rendered = selected_lightwallet(directory, &spec, protocol)?;
        let instance = &lightwallet_node(deployment)?.instance_id;
        validate_installer(
            deployment,
            directory,
            "lightwallet",
            instance,
            &rendered.script,
            INSTALL_TIMEOUT,
        )?;
        validate_command(
            directory,
            "lightwallet-capacity-command.json",
            instance,
            &capacity_script(deployment)?,
            CAPACITY_TIMEOUT,
        )?;
        if directory
            .join("lightwallet-start-command.json")
            .try_exists()?
        {
            validate_command(
                directory,
                "lightwallet-start-command.json",
                instance,
                &native::lightwallet_command(protocol, &spec, "start")?,
                START_TIMEOUT,
            )?;
        }
        if observations == ObservationHistory::Validate {
            validate_observations(
                directory,
                "lightwallet",
                instance,
                &native::lightwallet_command(protocol, &spec, "observe")?,
                OBSERVATION_TIMEOUT,
            )?;
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(
        skip_all,
        name = "foundation_live.cluster.lightwallet.lightwallet_node"
    )
)]
fn lightwallet_node(deployment: &Deployment) -> Result<&ClusterNodeOutputs> {
    let request = deployment
        .cluster
        .as_ref()
        .context("missing cluster request")?;
    let node_id = request.topology()?.lightwallet_node().node_id;
    deployment
        .outputs
        .as_ref()
        .context("missing cluster outputs")?
        .nodes
        .get(&node_id)
        .context("missing lightwallet host")
}
