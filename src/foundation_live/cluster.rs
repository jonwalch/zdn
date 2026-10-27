//! Private node operations share the foundation's reservation and renewal loop.
use super::*;
use crate::{devnet, host::S3Object};

mod client_access;
pub(super) mod lightwallet;
pub(super) mod native;
mod update;

#[cfg(test)]
mod compatibility_tests;
#[cfg(test)]
pub(super) mod producer_tests;
#[cfg(test)]
mod tests;

const INSTALL_TIMEOUT: u32 = 7200;
const CLIENT_INSTALL_TIMEOUT: u32 = 600;
pub(super) const NODE_OBSERVATION_TIMEOUT: u32 = 300;
const PRODUCER_START_TIMEOUT: u32 = 720;
pub(super) const CLIENT_OBSERVE_TIMEOUT: u32 = 360;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.validate_handoff")
)]
pub(super) fn validate_handoff(
    deployment: &Deployment,
    directory: &Path,
    updates: &std::collections::BTreeMap<Uuid, crate::update::UpdateIntent>,
    observations: ObservationHistory,
) -> Result<()> {
    use super::new_volume::{saved_authorization, AuthorizationTarget};
    update::validate_handoff(deployment, directory, updates)?;
    let Some(outputs) = &deployment.outputs else {
        return Ok(());
    };
    let request = deployment
        .cluster
        .as_ref()
        .context("missing node request")?;
    for node in outputs.nodes.values() {
        let mut host = lightwallet::host_spec(deployment, directory, node)?;
        host.new_volume =
            saved_authorization(deployment, directory, AuthorizationTarget::Node(node))?;
        let protocol = request.native_runtime_protocol.as_deref();
        let rendered = selected_node(directory, &host, protocol)?;
        validate_installer(
            deployment,
            directory,
            &node.node_id,
            &node.instance_id,
            &rendered.script,
            INSTALL_TIMEOUT,
        )?;
        if observations == ObservationHistory::Validate {
            validate_observations(
                directory,
                &node.node_id,
                &node.instance_id,
                &native::node_command(protocol, &host, "observe")?,
                NODE_OBSERVATION_TIMEOUT,
            )?;
        }
        if node.node_id == "node-1" {
            if request.block_interval_seconds.is_some() {
                validate_command(
                    directory,
                    "node-1-start-producer-command.json",
                    &node.instance_id,
                    &native::node_command(protocol, &host, "start-producer")?,
                    PRODUCER_START_TIMEOUT,
                )?;
            }
            if request.client_access {
                let rendered = selected_gateway(directory, &host, protocol)?;
                validate_installer(
                    deployment,
                    directory,
                    "client-rpc",
                    &node.instance_id,
                    &rendered.script,
                    CLIENT_INSTALL_TIMEOUT,
                )?;
                if observations == ObservationHistory::Validate {
                    validate_observations(
                        directory,
                        "client-rpc",
                        &node.instance_id,
                        &rendered.observe_script,
                        CLIENT_OBSERVE_TIMEOUT,
                    )?;
                }
            }
        }
    }
    lightwallet::validate_handoff(deployment, directory, observations)
}

fn saved_installer(directory: &Path, stem: &str) -> Result<Option<Vec<u8>>> {
    let path = directory.join(format!("{stem}-install.sh"));
    if path.try_exists()? {
        Ok(Some(devnet::read_bounded(&path, 32 * 1024 * 1024)?))
    } else {
        Ok(None)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.selected_node")
)]
fn selected_node(
    directory: &Path,
    host: &crate::host::HostInstallSpec,
    protocol: Option<&str>,
) -> Result<crate::host::RenderedHostInstall> {
    let saved = saved_installer(directory, &host.node_id)?;
    let manifest = native::node_manifest(protocol, host)?;
    let script = crate::host::runtime::bootstrap::render(&manifest)?;
    ensure!(
        saved.is_none_or(|bytes| bytes == script.as_bytes()),
        "saved native node installer differs from the immutable deployment"
    );
    Ok(crate::host::RenderedHostInstall {
        api_version: crate::host::API_VERSION.into(),
        install_sha256: manifest.install_sha256,
        script_sha256: devnet::sha256(script.as_bytes()),
        script,
        node_root: host.node_root(),
        rpc_endpoint: host.runtime_arguments()?.1,
        qualification: "pending".into(),
        launch_ready: false,
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.selected_gateway")
)]
pub(super) fn selected_gateway(
    directory: &Path,
    host: &crate::host::HostInstallSpec,
    protocol: Option<&str>,
) -> Result<crate::client_gateway::RenderedClientGatewayInstall> {
    // Authenticate the dependent node recipe even when no gateway has yet been saved.
    selected_node(directory, host, protocol)?;
    let manifest = native::node_manifest(protocol, host)?;
    let script = native::gateway_command(&manifest, "install")?;
    let rendered = crate::client_gateway::RenderedClientGatewayInstall {
        install_sha256: manifest.install_sha256.clone(),
        service_sha256: crate::client_gateway::native::service_sha256(&manifest)?,
        script_sha256: devnet::sha256(script.as_bytes()),
        script,
        observe_script: native::gateway_command(&manifest, "observe")?,
    };
    if let Some(saved) = saved_installer(directory, "client-rpc")? {
        ensure!(
            saved == rendered.script.as_bytes(),
            "saved client RPC installer differs from the immutable deployment"
        );
    }
    Ok(rendered)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.selected_lightwallet")
)]
fn selected_lightwallet(
    directory: &Path,
    spec: &crate::lightwallet_service::LightwalletInstallSpec,
    protocol: Option<&str>,
) -> Result<crate::lightwallet_service::RenderedLightwalletInstall> {
    selected_node(directory, &spec.host, protocol)?;
    let manifest = native::lightwallet_manifest(protocol, spec)?;
    let script = crate::lightwallet_service::native::bootstrap(&manifest)?;
    ensure!(
        saved_installer(directory, "lightwallet")?.is_none_or(|bytes| bytes == script.as_bytes()),
        "saved native lightwallet installer differs from the immutable deployment"
    );
    Ok(crate::lightwallet_service::RenderedLightwalletInstall {
        api_version: crate::lightwallet_service::INSTALL_API_VERSION.into(),
        install_sha256: manifest.install_sha256,
        service_sha256: crate::lightwallet_service::render_service(&spec.host, &spec.service)?
            .service_sha256,
        script_sha256: devnet::sha256(script.as_bytes()),
        script,
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.validate_installer")
)]
fn validate_installer(
    deployment: &Deployment,
    directory: &Path,
    stem: &str,
    instance: &str,
    script: &str,
    timeout: u32,
) -> Result<()> {
    ensure!(
        devnet::read_bounded(
            &directory.join(format!("{stem}-install.sh")),
            32 * 1024 * 1024
        )? == script.as_bytes(),
        "saved {stem} installer differs from the immutable deployment"
    );
    let object = installer_object(
        deployment,
        stem,
        &devnet::sha256(script.as_bytes()),
        script.len(),
    )?;
    validate_command(
        directory,
        &format!("{stem}-install-command.json"),
        instance,
        &selected_fetch_installer(deployment, &object, timeout)?,
        timeout,
    )
}

fn validate_command(
    directory: &Path,
    name: &str,
    instance: &str,
    script: &str,
    timeout: u32,
) -> Result<()> {
    let bytes = devnet::read_bounded(&directory.join(name), 128 * 1024)?;
    crate::ssm::validate_handoff(&bytes, instance, script, timeout)
        .with_context(|| format!("validate saved command {name}"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.validate_observations")
)]
fn validate_observations(
    directory: &Path,
    stem: &str,
    instance: &str,
    script: &str,
    timeout: u32,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let name = entry?.file_name();
        let name = name.to_str().context("non-UTF8 recovery file")?;
        if name.starts_with(&format!("{stem}-observe-")) && name.ends_with(".json") {
            let bytes = devnet::read_bounded(&directory.join(name), 128 * 1024)?;
            crate::ssm::validate_handoff_request(&bytes, instance, script, timeout, false)?;
        }
    }
    Ok(())
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.verify_cluster"
        )
    )]
    pub(super) fn verify_cluster(&mut self, deployment: &Deployment) -> Result<()> {
        deployment.require_native_execution()?;
        let request = deployment
            .cluster
            .as_ref()
            .context("missing node request")?;
        request.verify_local(&self.deployment_directory)?;
        devnet::verify_ecr(
            &self.aws,
            request,
            &deployment.team,
            &self.deployment_directory,
        )?;
        self.verify_runtime_access(deployment)
    }

    pub(super) fn verify_runtime_access(&mut self, deployment: &Deployment) -> Result<()> {
        let access = deployment
            .team
            .deployment
            .as_ref()
            .context("runtime access setup is required")?;
        for (arn, expected) in [
            (
                access.runtime_boundary_arn.clone(),
                crate::access::runtime_boundary_for_team(&deployment.team)?,
            ),
            (
                crate::access::runtime_data_policy_arn(&deployment.team),
                crate::access::runtime_data_policy(&deployment.team)?,
            ),
        ] {
            let policy=self.aws.call("iam","get-policy",json!({"PolicyArn":arn}),&[])
                .context("node runtime permissions are missing; repeat zdn setup bootstrap with the administrator profile")?;
            let version = policy
                .pointer("/Policy/DefaultVersionId")
                .and_then(Value::as_str)
                .context("runtime policy version missing")?;
            let document = self.aws.call(
                "iam",
                "get-policy-version",
                json!({"PolicyArn":arn,"VersionId":version}),
                &[],
            )?;
            let document = document
                .pointer("/PolicyVersion/Document")
                .context("runtime policy document missing")?;
            let parsed = if let Some(text) = document.as_str() {
                serde_json::from_str(text)?
            } else {
                document.clone()
            };
            ensure!(
                parsed == expected,
                "node runtime permission policy is outdated or differs; repeat zdn setup bootstrap with the administrator profile"
            );
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.stage_cluster_artifacts"
        )
    )]
    pub(super) fn stage_cluster_artifacts(&mut self, deployment: &Deployment) -> Result<()> {
        deployment.require_native_execution()?;
        if let Some(runtime) = &deployment.foundation_runtime {
            runtime.verify_local(&self.deployment_directory)?;
            self.poll()?;
            devnet::upload_file(
                &self.aws,
                &deployment.team,
                &runtime.object(&deployment.team, &deployment.spec)?,
                &self
                    .deployment_directory
                    .join(crate::foundation_runtime::HELPER),
            )?;
            return self.poll();
        }
        let Some(request) = &deployment.cluster else {
            return Ok(());
        };
        request.verify_local(&self.deployment_directory)?;
        let files = request
            .artifacts
            .keys()
            .map(|name| {
                Ok((
                    request.s3_object(&deployment.team, &deployment.spec, name)?,
                    devnet::artifact_path(&self.deployment_directory, name),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        for chunk in files.chunks(4) {
            self.poll()?;
            devnet::upload_files(&self.aws, &deployment.team, chunk)?;
        }
        self.poll()
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.install_cluster"
        )
    )]
    pub(super) fn install_cluster(&mut self, deployment: &Deployment) -> Result<Value> {
        deployment.require_native_execution()?;
        let request = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?;
        let outputs = deployment
            .outputs
            .as_ref()
            .context("missing cluster outputs")?;
        crate::cluster_infra::validate_node_outputs(&outputs.nodes, &request.topology()?)?;
        self.authorize_new_volumes(deployment)?;
        self.prepare_lightwallet_capacity(deployment)?;
        let mut commands = Vec::new();
        let mut hosts = Vec::new();
        let mut installers = Vec::new();
        for node in outputs.nodes.values() {
            let mut host = self.cluster_host_spec(deployment, node)?;
            host.new_volume = self.authorize_new_volume(deployment, node)?;
            let rendered = selected_node(
                &self.deployment_directory,
                &host,
                request.native_runtime_protocol.as_deref(),
            )?;
            let path = self
                .deployment_directory
                .join(format!("{}-install.sh", node.node_id));
            if path.exists() {
                ensure!(
                    devnet::read_bounded(&path, 32 * 1024 * 1024)? == rendered.script.as_bytes(),
                    "saved host installer differs; do not change an existing runtime during recovery"
                );
            } else {
                foundation::write_private(&path, rendered.script.as_bytes())?;
            }
            let object = installer_object(
                deployment,
                &node.node_id,
                &rendered.script_sha256,
                rendered.script.len(),
            )?;
            self.poll()?;
            let script = selected_fetch_installer(deployment, &object, INSTALL_TIMEOUT)?;
            installers.push((object, path));
            let journal = self
                .deployment_directory
                .join(format!("{}-install-command.json", node.node_id));
            commands.push(crate::ssm::CommandRequest {
                instance_id: node.instance_id.clone(),
                script,
                journal_path: journal,
                timeout_secs: INSTALL_TIMEOUT,
            });
            hosts.push((host, rendered.install_sha256));
        }
        for chunk in installers.chunks(4) {
            self.poll()?;
            devnet::upload_files(&self.aws, &deployment.team, chunk)?;
        }
        let reports = self.remote_batch(&commands)?;
        for ((host, install_sha256), report) in hosts.iter().zip(reports) {
            crate::devnet::validate_observation(&report, host, install_sha256)?;
        }
        self.complete_cluster_install(deployment)
    }

    // This belongs to the install phase: activation has durable remote effects,
    // so an interrupted start must leave an uncertain operation to reconcile.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.complete_cluster_install"
        )
    )]
    pub(super) fn complete_cluster_install(&mut self, deployment: &Deployment) -> Result<Value> {
        deployment.require_native_execution()?;
        let observations = self.observe_cluster_runtime(deployment, false)?;
        let request = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?;
        if request.block_interval_seconds.is_some() {
            let node = deployment
                .outputs
                .as_ref()
                .context("missing cluster outputs")?
                .nodes
                .get("node-1")
                .context("producer node output missing")?;
            let mut host = self.cluster_host_spec(deployment, node)?;
            host.new_volume = self.saved_volume_authorization(deployment, node)?;
            let expected_hash = host.install_sha256()?;
            let image = crate::update::active_image(deployment, &node.node_id)?
                .image
                .clone();
            // Keep one journal across retries. A lost SendCommand response
            // must be recovered before a later attempt can start anything.
            let journal = self
                .deployment_directory
                .join("node-1-start-producer-command.json");
            let script = native::node_command(
                request.native_runtime_protocol.as_deref(),
                &host,
                "start-producer",
            )?;
            let timeout = PRODUCER_START_TIMEOUT;
            let mut budget = crate::ssm::ExecutionBudget::new(timeout, &self.runtime, true)?;
            self.remote_with_budget(&node.instance_id, &script, &journal, &mut budget)?;
            // Cached activation may describe an earlier image. Settle it first,
            // then validate current health against the active image and original
            // installation identity, without rewriting historical command results.
            let report = self.observe_effective_node(
                &host,
                &image,
                &node.instance_id,
                Some(&budget),
                request.native_runtime_protocol.as_deref(),
            )?;
            host.image = image;
            if !devnet::validate_producer_observation(&report, &host, false)? {
                self.poll()?;
                // Explicit restart and failure recovery share one allowance.
                // Neither can replenish it or reset the activation deadline.
                budget.claim_repeat(&self.runtime)?;
                crate::ssm::prepare_repeat_after_success(
                    &node.instance_id,
                    &script,
                    &journal,
                    timeout,
                    &self.runtime,
                )?;
                let report =
                    self.remote_with_budget(&node.instance_id, &script, &journal, &mut budget)?;
                devnet::validate_observation(&report, &host, &expected_hash)?;
                devnet::validate_producer_observation(&report, &host, true)?;
            }
        }
        let lightwallet = self.install_lightwallet(deployment)?;
        let client_access = self.install_client_access(deployment)?;
        Ok(
            json!({"prerequisites":observations,"producerActivationRequested":request.block_interval_seconds.is_some(),"lightwallet":lightwallet,"clientAccess":client_access,"launchReady":false}),
        )
    }

    pub(super) fn observe_cluster(&mut self, deployment: &Deployment) -> Result<Value> {
        deployment.require_native_execution()?;
        self.observe_cluster_runtime(deployment, true)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.observe_cluster_runtime"
        )
    )]
    fn observe_cluster_runtime(
        &mut self,
        deployment: &Deployment,
        require_producer: bool,
    ) -> Result<Value> {
        let request = deployment
            .cluster
            .as_ref()
            .context("missing cluster request")?;
        let outputs = deployment
            .outputs
            .as_ref()
            .context("missing cluster outputs")?;
        crate::cluster_infra::validate_node_outputs(&outputs.nodes, &request.topology()?)?;
        let mut commands = Vec::new();
        let mut hosts = Vec::new();
        for node in outputs.nodes.values() {
            let mut host = self.cluster_host_spec(deployment, node)?;
            host.new_volume = self.saved_volume_authorization(deployment, node)?;
            let script =
                native::node_command(request.native_runtime_protocol.as_deref(), &host, "observe")?;
            commands.push(crate::ssm::CommandRequest {
                instance_id: node.instance_id.clone(),
                script,
                journal_path: self.deployment_directory.join(format!(
                    "{}-observe-{}.json",
                    node.node_id,
                    Uuid::new_v4(),
                )),
                timeout_secs: NODE_OBSERVATION_TIMEOUT,
            });
            hosts.push(host);
        }
        let observations = self.remote_batch(&commands)?;
        let mut reports = serde_json::Map::new();
        let mut scheduled_producer = false;
        for ((node, mut host), report) in outputs.nodes.values().zip(hosts).zip(observations) {
            let baseline_hash = host.install_sha256()?;
            let image = crate::update::active_image(deployment, &node.node_id)?
                .image
                .clone();
            host.image = image;
            devnet::validate_observation(&report, &host, &baseline_hash)?;
            let expected_update = deployment
                .runtime
                .as_ref()
                .and_then(|r| r.nodes.get(&node.node_id))
                .map(|r| r.update_id.to_string());
            ensure!(
                report["updateId"].as_str() == expected_update.as_deref(),
                "host active update identity differs"
            );
            scheduled_producer |=
                devnet::validate_producer_observation(&report, &host, require_producer)?;
            reports.insert(node.node_id.clone(), report);
        }
        let mut result = json!({"nodeReady":true,"nodes":reports,"scheduledProducer":scheduled_producer,"paymentQualification":"pending","launchReady":false});
        if require_producer && request.lightwallet.is_some() {
            result["lightwallet"] = self.observe_lightwallet_ready(deployment)?;
            result["lightwalletReady"] = json!(true);
        }
        if require_producer && request.client_access {
            result["clientAccess"] = self.observe_client_access_ready(deployment)?;
        }
        Ok(result)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.observe_effective_node"
        )
    )]
    fn observe_effective_node(
        &mut self,
        host: &crate::host::HostInstallSpec,
        image: &str,
        instance: &str,
        activation_budget: Option<&crate::ssm::ExecutionBudget>,
        protocol: Option<&str>,
    ) -> Result<Value> {
        let journal = self.deployment_directory.join(format!(
            "{}-observe-{}.json",
            host.node_id,
            Uuid::new_v4()
        ));
        let mut budget = match activation_budget {
            Some(budget) => budget.observation(NODE_OBSERVATION_TIMEOUT, &self.runtime)?,
            None => {
                crate::ssm::ExecutionBudget::new(NODE_OBSERVATION_TIMEOUT, &self.runtime, false)?
            }
        };
        let script = native::node_command(protocol, host, "observe")?;
        let report = self.remote_with_budget(instance, &script, &journal, &mut budget)?;
        let baseline_hash = host.install_sha256()?;
        let mut effective = host.clone();
        effective.image = image.into();
        devnet::validate_observation(&report, &effective, &baseline_hash)?;
        Ok(report)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.cluster.live_backend.wait_for_node")
    )]
    fn wait_for_node(&mut self, instance: &str) -> Result<()> {
        self.wait_for_nodes(&[instance])
    }

    fn wait_for_nodes(&mut self, instances: &[&str]) -> Result<()> {
        let mut pending: std::collections::BTreeSet<_> = instances.iter().copied().collect();
        let deadline = self.runtime.monotonic() + Duration::from_secs(900);
        while !pending.is_empty() {
            let selected: Vec<_> = pending.iter().copied().collect();
            for chunk in selected.chunks(50) {
                self.poll()?;
                ensure!(
                    self.runtime.monotonic() < deadline,
                    "SSM node availability deadline exceeded"
                );
                let response = self.aws.call(
                    "ssm",
                    "describe-instance-information",
                    json!({"Filters":[{"Key":"InstanceIds","Values":chunk}],"MaxResults":50}),
                    &[],
                )?;
                for instance in array(&response, "InstanceInformationList")? {
                    if instance["PingStatus"] == "Online" {
                        if let Some(id) = instance["InstanceId"].as_str() {
                            pending.remove(id);
                        }
                    }
                }
            }
            if !pending.is_empty() {
                self.pause(deadline)?;
            }
        }
        Ok(())
    }

    fn remote(
        &mut self,
        instance: &str,
        script: &str,
        journal: &Path,
        seconds: u32,
    ) -> Result<Value> {
        let mut budget = crate::ssm::ExecutionBudget::new(seconds, &self.runtime, false)?;
        self.remote_with_budget(instance, script, journal, &mut budget)
    }

    fn remote_batch(&mut self, commands: &[crate::ssm::CommandRequest]) -> Result<Vec<Value>> {
        let mut progress = || {
            ensure!(
                pulse(
                    &self.aws,
                    &self.team,
                    &mut self.lease,
                    &self.cancel,
                    &mut self.heartbeat,
                    &self.state_root,
                    &self.runtime,
                )? == RunControl::Continue,
                "node operation cancelled"
            );
            Ok(())
        };
        crate::ssm::execute_batch_when_online(
            &self.aws,
            commands,
            Duration::from_secs(900),
            &self.runtime,
            &mut progress,
            &mut |observation| match &mut self.command_progress {
                Some(observer) => observer(observation),
                None => Ok(()),
            },
        )
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.remote_with_budget"
        )
    )]
    fn remote_with_budget(
        &mut self,
        instance: &str,
        script: &str,
        journal: &Path,
        budget: &mut crate::ssm::ExecutionBudget,
    ) -> Result<Value> {
        let mut progress = || {
            ensure!(
                pulse(
                    &self.aws,
                    &self.team,
                    &mut self.lease,
                    &self.cancel,
                    &mut self.heartbeat,
                    &self.state_root,
                    &self.runtime
                )? == RunControl::Continue,
                "node operation cancelled"
            );
            Ok(())
        };
        crate::ssm::execute_with_budget(
            &self.aws,
            instance,
            script,
            journal,
            budget,
            &self.runtime,
            &mut progress,
            &mut |observation| match &mut self.command_progress {
                Some(observer) => observer(observation),
                None => Ok(()),
            },
        )
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.live_backend.cleanup_cluster_artifacts"
        )
    )]
    pub(super) fn cleanup_cluster_artifacts(
        &mut self,
        deployment: &Deployment,
        delete_data: bool,
    ) -> Result<Vec<String>> {
        if deployment.cluster.is_none() && deployment.foundation_runtime.is_none() {
            return Ok(Vec::new());
        }
        let prefix = devnet::artifact_prefix(&deployment.team, &deployment.spec);
        if !delete_data {
            return Ok(vec![format!(
                "s3://{}/{prefix}",
                deployment.team.backend_bucket()?
            )]);
        }
        // The namespace includes the full deployment UUID. Never list or remove
        // shared Pulumi state, network reservations, leases, or another devnet.
        for _ in 0..100 {
            self.poll()?;
            // Version metadata grows beyond bounded AWS capture after ordinary
            // image updates. Project only deletion identities and keep pages
            // bounded even for maximum-length keys/version IDs (1 MiB capture).
            let page=self.aws.call("s3api","list-object-versions",json!({"Bucket":deployment.team.backend_bucket()?,"Prefix":prefix,"ExpectedBucketOwner":deployment.team.aws.account_id,"MaxKeys":50}),&["--no-paginate".into(), "--query".into(), "{IsTruncated:IsTruncated,Versions:Versions[].{Key:Key,VersionId:VersionId} || `[]`,DeleteMarkers:DeleteMarkers[].{Key:Key,VersionId:VersionId} || `[]`}".into()])?;
            let mut objects = Vec::new();
            for field in ["Versions", "DeleteMarkers"] {
                if let Some(items) = page.get(field) {
                    for item in items.as_array().context("invalid artifact versions")? {
                        let key = item["Key"].as_str().context("artifact key missing")?;
                        ensure!(
                            key.starts_with(&prefix),
                            "S3 returned artifact outside deployment prefix"
                        );
                        let version = item["VersionId"]
                            .as_str()
                            .context("artifact version missing")?;
                        objects.push(json!({"Key":key,"VersionId":version}));
                    }
                }
            }
            if objects.is_empty() {
                ensure!(page["IsTruncated"] == false, "incomplete artifact listing");
                return Ok(Vec::new());
            }
            // Leave room below the OS per-argument limit for --cli-input-json.
            // Normal short identities still fit in a single deletion request.
            let mut max_identity_bytes = 1;
            for object in &objects {
                max_identity_bytes = max_identity_bytes.max(serde_json::to_vec(object)?.len() + 1);
            }
            for chunk in objects.chunks((64 * 1024 / max_identity_bytes).max(1)) {
                self.poll()?;
                let deleted=self.aws.call("s3api","delete-objects",json!({"Bucket":deployment.team.backend_bucket()?,"ExpectedBucketOwner":deployment.team.aws.account_id,"Delete":{"Objects":chunk,"Quiet":true}}),&[])?;
                ensure!(
                    deleted
                        .get("Errors")
                        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
                    "deployment artifact deletion is incomplete"
                );
            }
        }
        bail!("deployment artifact cleanup exceeded its page bound")
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.installer_object")
)]
fn installer_object(
    deployment: &Deployment,
    stem: &str,
    sha256: &str,
    bytes: usize,
) -> Result<S3Object> {
    Ok(S3Object {
        bucket: deployment.team.backend_bucket()?.into(),
        key: format!(
            "{}{sha256}/{stem}-install.sh",
            devnet::artifact_prefix(&deployment.team, &deployment.spec)
        ),
        sha256: sha256.into(),
        bytes: bytes as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    })
}

/// The immutable request selects transport bytes independently of the installer.
/// Missing selection is unsupported, including for handoff.
pub fn selected_fetch_installer(
    deployment: &Deployment,
    object: &S3Object,
    timeout: u32,
) -> Result<String> {
    let protocol = deployment
        .cluster
        .as_ref()
        .context("installer transport requires a cluster request")?
        .installer_fetch_protocol
        .as_deref();
    match protocol {
        None => bail!("installer transport requires native selection"),
        Some(protocol) => {
            crate::host::installer_bootstrap::render_selected(protocol, object, timeout)
        }
    }
}
