//! Independently journalled client-service installation preserves saved node installers.
use super::*;
use crate::{endpoints::EndpointFile, host::HostInstallSpec};

#[cfg(test)]
mod tests;

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.client_access.live_backend.client_host"
        )
    )]
    fn client_host(&self, deployment: &Deployment) -> Result<(HostInstallSpec, String)> {
        let node = deployment
            .outputs
            .as_ref()
            .context("missing cluster outputs")?
            .nodes
            .get("node-1")
            .context("missing client RPC host")?;
        let mut host = self.cluster_host_spec(deployment, node)?;
        host.new_volume = self.saved_volume_authorization(deployment, node)?;
        Ok((host, node.instance_id.clone()))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.client_access.live_backend.install_client_access"
        )
    )]
    pub(super) fn install_client_access(&mut self, deployment: &Deployment) -> Result<Value> {
        if !deployment.cluster.as_ref().is_some_and(|r| r.client_access) {
            return Ok(Value::Null);
        }
        let (host, instance) = self.client_host(deployment)?;
        let protocol = deployment
            .cluster
            .as_ref()
            .unwrap()
            .native_runtime_protocol
            .as_deref();
        let rendered = selected_gateway(&self.deployment_directory, &host, protocol)?;
        let path = self.deployment_directory.join("client-rpc-install.sh");
        if path.exists() {
            ensure!(
                devnet::read_bounded(&path, 32 * 1024 * 1024)? == rendered.script.as_bytes(),
                "saved client RPC installer differs; preserve the deployment for recovery"
            );
        } else {
            foundation::write_private(&path, rendered.script.as_bytes())?;
        }
        let object = installer_object(
            deployment,
            "client-rpc",
            &rendered.script_sha256,
            rendered.script.len(),
        )?;
        self.poll()?;
        devnet::upload_file(&self.aws, &deployment.team, &object, &path)?;
        let script = selected_fetch_installer(deployment, &object, CLIENT_INSTALL_TIMEOUT)?;
        let journal = self
            .deployment_directory
            .join("client-rpc-install-command.json");
        // Always settle a saved in-flight installation before probing the same host lock.
        let report = self.remote(&instance, &script, &journal, CLIENT_INSTALL_TIMEOUT)?;
        ensure!(
            native::validate_gateway_observation(protocol, &host, &report)?.status == "ready",
            "client RPC installation did not establish readiness"
        );
        let mut report = self.observe_client_access(deployment)?;
        if report["status"] == "stopped" {
            crate::ssm::prepare_repeat_after_success(
                &instance,
                &script,
                &journal,
                CLIENT_INSTALL_TIMEOUT,
                &self.runtime,
            )?;
            let restarted = self.remote(&instance, &script, &journal, CLIENT_INSTALL_TIMEOUT)?;
            ensure!(
                native::validate_gateway_observation(protocol, &host, &restarted)?.status
                    == "ready",
                "client RPC restart did not establish readiness"
            );
            report = self.observe_client_access(deployment)?;
        }
        ensure!(
            report["status"] == "ready",
            "private client RPC service is not ready"
        );
        // Save only non-secret target identities after all services have passed installation.
        // The active operation is ours; the public export path still refuses uncertain operations.
        let mut observed = deployment.clone();
        observed.unresolved_operation = None;
        let endpoints = EndpointFile::from_deployment(&observed)?;
        endpoints.validate_live_documents(&self.aws)?;
        foundation::write_json(
            &self.deployment_directory.join("client-endpoints.json"),
            &endpoints,
        )?;
        Ok(report)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.client_access.live_backend.observe_client_access"
        )
    )]
    fn observe_client_access(&mut self, deployment: &Deployment) -> Result<Value> {
        let (host, instance) = self.client_host(deployment)?;
        let protocol = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?
            .native_runtime_protocol
            .as_deref();
        let script = selected_gateway(&self.deployment_directory, &host, protocol)?.observe_script;
        let journal = self
            .deployment_directory
            .join(format!("client-rpc-observe-{}.json", Uuid::new_v4()));
        let report = self.remote(&instance, &script, &journal, CLIENT_OBSERVE_TIMEOUT)?;
        native::validate_gateway_observation(protocol, &host, &report)?;
        Ok(report)
    }

    pub(super) fn observe_client_access_ready(&mut self, deployment: &Deployment) -> Result<Value> {
        let report = self.observe_client_access(deployment)?;
        ensure!(
            report["status"] == "ready",
            "private client RPC service is not ready"
        );
        Ok(report)
    }
}
