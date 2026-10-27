//! Update adapter: no Pulumi, allocation, formatting or initial installation calls.
use super::*;
use crate::{foundation::update_controller::Backend, update::ImageRevision};

fn original_host(
    deployment: &Deployment,
    directory: &Path,
    node: &str,
) -> Result<crate::host::HostInstallSpec> {
    let output = deployment
        .outputs
        .as_ref()
        .and_then(|o| o.nodes.get(node))
        .context("missing node")?;
    let request = deployment.cluster.as_ref().context("missing cluster")?;
    ensure!(
        request.lightwallet.is_none() || request.topology()?.lightwallet_node().node_id != node,
        "updating the lightwallet host is not supported"
    );
    let mut host = lightwallet::host_spec(deployment, directory, output)?;
    host.new_volume = super::super::new_volume::saved_authorization(
        deployment,
        directory,
        super::super::new_volume::AuthorizationTarget::Node(output),
    )?;
    Ok(host)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.render_update_script")
)]
fn render_update_script(
    deployment: &Deployment,
    directory: &Path,
    intent: &crate::update::UpdateIntent,
    node: &str,
) -> Result<String> {
    use crate::host::runtime::revision::{Request, API_VERSION, EXECUTION_PROTOCOL};
    let protocol = deployment
        .cluster
        .as_ref()
        .context("missing cluster")?
        .native_runtime_protocol
        .as_deref();
    ensure!(
        intent.host_runtime_protocol.as_deref() == Some(EXECUTION_PROTOCOL),
        "unsupported native update dispatcher"
    );
    let host = original_host(deployment, directory, node)?;
    let original = native::node_manifest(protocol, &host)?;
    ensure!(
        directory.join(format!("{node}-install.sh")).try_exists()?,
        "missing original native installer"
    );
    selected_node(directory, &host, protocol)?;
    let revision = intent.revision.as_ref().context("missing candidate")?;
    let target = intent.targets.get(node).context("missing target")?;
    Request {
        api_version: API_VERSION.into(),
        original,
        update_id: intent.id,
        expected_image: target.expected_image.clone(),
        expected_update_id: target.expected_update_id,
        image: revision.image.clone(),
        image_record: update_object(deployment, revision, "image.json")?,
        image_manifest: update_object(deployment, revision, "image-manifest.json")?,
        image_config: update_object(deployment, revision, "image-config.json")?,
    }
    .render()
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.update_script_object")
)]
fn update_script_object(
    deployment: &Deployment,
    id: Uuid,
    node: &str,
    script: &str,
) -> Result<S3Object> {
    let sha256 = devnet::sha256(script.as_bytes());
    Ok(S3Object {
        bucket: deployment.team.backend_bucket()?.into(),
        key: format!(
            "{}updates/{id}/{node}-{sha256}.sh",
            devnet::artifact_prefix(&deployment.team, &deployment.spec)
        ),
        sha256,
        bytes: script.len() as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.save_update_script")
)]
fn save_update_script(
    deployment: &Deployment,
    directory: &Path,
    intent: &crate::update::UpdateIntent,
    node: &str,
) -> Result<(PathBuf, S3Object)> {
    let script = render_update_script(deployment, directory, intent, node)?;
    let path = directory
        .join("updates")
        .join(intent.id.to_string())
        .join(format!("{node}-update.sh"));
    if path.exists() {
        ensure!(
            devnet::read_bounded(&path, 32 * 1024 * 1024)? == script.as_bytes(),
            "saved update script changed"
        );
    } else {
        foundation::write_private(&path, script.as_bytes())?;
    }
    let object = update_script_object(deployment, intent.id, node, &script)?;
    Ok((path, object))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.command_path")
)]
fn command_path(directory: &Path, node: &str) -> PathBuf {
    directory.join(format!("{node}-command.json"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.validate_handoff")
)]
pub(super) fn validate_handoff(
    deployment: &Deployment,
    directory: &Path,
    updates: &std::collections::BTreeMap<Uuid, crate::update::UpdateIntent>,
) -> Result<()> {
    for (id, intent) in updates {
        ensure!(*id == intent.id, "invalid update identity");
        let revision = intent
            .revision
            .as_ref()
            .context("missing completed revision")?;
        let update_directory = directory.join("updates").join(id.to_string());
        let saved = ImageRevision::read(*id, revision.build.clone(), &update_directory)?;
        ensure!(
            serde_json::to_value(saved)? == serde_json::to_value(revision)?,
            "saved update artifact changed"
        );
        for (node, target) in &intent.targets {
            let script = render_update_script(deployment, directory, intent, node)?;
            ensure!(
                devnet::read_bounded(
                    &update_directory.join(format!("{node}-update.sh")),
                    32 * 1024 * 1024
                )? == script.as_bytes(),
                "saved update script changed"
            );
            let object = update_script_object(deployment, *id, node, &script)?;
            let bytes = devnet::read_bounded(
                &update_directory.join(format!("{node}-command.json")),
                128 * 1024,
            )?;
            crate::ssm::validate_handoff_request(
                &bytes,
                &target.instance_id,
                &selected_fetch_installer(deployment, &object, 7200)?,
                7200,
                intent.finished || intent.completed.contains(node),
            )?;
        }
    }
    Ok(())
}

impl<A: AwsApi, R: PulumiRunner, T: Runtime> LiveBackend<'_, A, R, T> {
    /// Check exact existing hosts/disks before a build or remote mutation. A
    /// resumed command may already have switched images, so only a new update
    /// can require the old cluster-wide runtime observation here.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.update.live_backend.preflight_update"
        )
    )]
    pub fn preflight_update(&mut self, deployment: &Deployment, fresh: bool) -> Result<()> {
        deployment.require_native_execution()?;
        let intent = deployment
            .runtime
            .as_ref()
            .and_then(|r| r.update.as_ref())
            .context("missing update")?;
        let outputs = deployment
            .outputs
            .as_ref()
            .context("missing node outputs")?;
        for (node, target) in &intent.targets {
            self.poll()?;
            let installer = self.deployment_directory.join(format!("{node}-install.sh"));
            ensure!(installer.try_exists()?, "missing original native installer");
            let host = original_host(deployment, &self.deployment_directory, node)?;
            selected_node(
                &self.deployment_directory,
                &host,
                deployment
                    .cluster
                    .as_ref()
                    .context("missing cluster")?
                    .native_runtime_protocol
                    .as_deref(),
            )?;
            let response = self.aws.call(
                "ec2",
                "describe-instances",
                json!({"InstanceIds":[target.instance_id]}),
                &[],
            )?;
            let reservations = array(&response, "Reservations")?;
            ensure!(
                response.get("NextToken").is_none() && reservations.len() == 1,
                "incomplete update host inventory"
            );
            let instances = array(&reservations[0], "Instances")?;
            ensure!(
                instances.len() == 1,
                "update requires exactly one saved host"
            );
            let instance = &instances[0];
            ensure!(
                instance["InstanceId"] == target.instance_id
                    && instance["State"]["Name"] == "running"
                    && instance["VpcId"] == outputs.vpc_id
                    && instance["SubnetId"] == outputs.private_subnet_id
                    && instance["PrivateIpAddress"] == outputs.nodes[node].private_ip.to_string(),
                "update host identity or state differs"
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
                    tags.iter().filter(|t| t["Key"] == key).count() == 1
                        && tags.iter().any(|t| t["Key"] == key && t["Value"] == value),
                    "update host ownership differs"
                );
            }
            self.poll()?;
            let response = self.aws.call(
                "ec2",
                "describe-volumes",
                json!({"VolumeIds":[target.volume_id]}),
                &[],
            )?;
            let volumes = array(&response, "Volumes")?;
            ensure!(
                response.get("NextToken").is_none()
                    && volumes.len() == 1
                    && volumes[0]["VolumeId"] == target.volume_id
                    && owned_chain_volume(&volumes[0], deployment)?,
                "update chain volume identity differs"
            );
            let attachments = array(&volumes[0], "Attachments")?;
            ensure!(
                volumes[0]["State"] == "in-use"
                    && attachments.len() == 1
                    && attachments[0]["InstanceId"] == target.instance_id
                    && attachments[0]["State"] == "attached",
                "update chain volume attachment differs"
            );
        }
        if fresh {
            self.observe_cluster(deployment)?;
        }
        Ok(())
    }

    fn update_directory(&self, id: Uuid) -> PathBuf {
        self.deployment_directory
            .join("updates")
            .join(id.to_string())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_live.cluster.update.update_object")
)]
fn update_object(
    deployment: &Deployment,
    revision: &ImageRevision,
    name: &str,
) -> Result<S3Object> {
    let artifact = revision
        .artifacts
        .get(name)
        .context("missing update artifact")?;
    Ok(S3Object {
        bucket: deployment.team.backend_bucket()?.into(),
        key: format!(
            "{}updates/{}/artifacts/{name}",
            devnet::artifact_prefix(&deployment.team, &deployment.spec),
            revision.update_id
        ),
        sha256: artifact.sha256.clone(),
        bytes: artifact.bytes,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    })
}
impl<A: AwsApi, R: PulumiRunner, T: Runtime> Backend for LiveBackend<'_, A, R, T> {
    fn pulse(&mut self) -> Result<()> {
        self.poll()
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "foundation_live.cluster.update.live_backend.stage")
    )]
    fn stage(&mut self, deployment: &Deployment, revision: &ImageRevision) -> Result<()> {
        deployment.require_native_execution()?;
        revision.validate()?;
        let directory = self.update_directory(revision.update_id);
        self.poll()?;
        let saved = ImageRevision::read(revision.update_id, revision.build.clone(), &directory)?;
        ensure!(
            serde_json::to_value(saved)? == serde_json::to_value(revision)?,
            "saved update artifact changed"
        );
        let mut request = deployment.cluster.clone().context("missing cluster")?;
        request.image = revision.image.clone();
        request.lightwallet = None;
        devnet::verify_ecr(&self.aws, &request, &deployment.team, &directory)?;
        for name in revision.artifacts.keys() {
            self.poll()?;
            devnet::upload_file(
                &self.aws,
                &deployment.team,
                &update_object(deployment, revision, name)?,
                &devnet::artifact_path(&directory, name),
            )?;
        }
        let intent = deployment
            .runtime
            .as_ref()
            .and_then(|r| r.update.as_ref())
            .context("missing update")?;
        ensure!(intent.id == revision.update_id, "update identity differs");
        for (node, target) in &intent.targets {
            self.poll()?;
            let (_, object) =
                save_update_script(deployment, &self.deployment_directory, intent, node)?;
            self.poll()?;
            crate::ssm::prepare(
                &target.instance_id,
                &selected_fetch_installer(deployment, &object, 7200)?,
                &command_path(&directory, node),
                7200,
                &self.runtime,
            )?;
        }
        self.poll()?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.update.live_backend.dispatch"
        )
    )]
    fn dispatch(&mut self, deployment: &Deployment, node: &str) -> Result<()> {
        deployment.require_native_execution()?;
        let intent = deployment
            .runtime
            .as_ref()
            .and_then(|r| r.update.as_ref())
            .context("missing update")?;
        let output = deployment
            .outputs
            .as_ref()
            .and_then(|o| o.nodes.get(node))
            .context("missing node")?;
        let (path, object) =
            save_update_script(deployment, &self.deployment_directory, intent, node)?;
        let directory = self.update_directory(intent.id);
        self.poll()?;
        devnet::upload_file(&self.aws, &deployment.team, &object, &path)?;
        self.remote(
            &output.instance_id,
            &selected_fetch_installer(deployment, &object, 7200)?,
            &command_path(&directory, node),
            7200,
        )?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "foundation_live.cluster.update.live_backend.observe"
        )
    )]
    fn observe(
        &mut self,
        deployment: &Deployment,
        node: &str,
        revision: &ImageRevision,
    ) -> Result<()> {
        deployment.require_native_execution()?;
        let output = deployment
            .outputs
            .as_ref()
            .and_then(|o| o.nodes.get(node))
            .context("missing node")?;
        let mut host = self.cluster_host_spec(deployment, output)?;
        host.new_volume = self.saved_volume_authorization(deployment, output)?;
        let report = self.observe_effective_node(
            &host,
            &revision.image.image,
            &output.instance_id,
            None,
            deployment
                .cluster
                .as_ref()
                .context("missing cluster request")?
                .native_runtime_protocol
                .as_deref(),
        )?;
        ensure!(
            report["updateId"] == revision.update_id.to_string(),
            "host update identity differs"
        );
        Ok(())
    }

    fn ready(&mut self, deployment: &Deployment) -> Result<()> {
        deployment.require_native_execution()?;
        self.observe_cluster(deployment)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "update_live_tests.rs"]
mod live_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{update_controller as controller, DeploymentFile};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Fake {
        events: Vec<String>,
        fail_node: Option<String>,
        cancelled: bool,
    }
    impl Backend for Fake {
        fn pulse(&mut self) -> Result<()> {
            ensure!(!self.cancelled, "cancelled");
            Ok(())
        }
        fn stage(&mut self, _: &Deployment, _: &ImageRevision) -> Result<()> {
            self.events.push("stage".into());
            Ok(())
        }
        fn dispatch(&mut self, _: &Deployment, node: &str) -> Result<()> {
            self.events.push(format!("dispatch:{node}"));
            Ok(())
        }
        fn observe(&mut self, _: &Deployment, node: &str, _: &ImageRevision) -> Result<()> {
            self.events.push(format!("observe:{node}"));
            ensure!(self.fail_node.as_deref() != Some(node), "not freshly ready");
            Ok(())
        }
        fn ready(&mut self, _: &Deployment) -> Result<()> {
            self.events.push("cluster+services".into());
            Ok(())
        }
    }

    fn fixture() -> (tempfile::TempDir, DeploymentFile, Deployment) {
        let temp = tempfile::tempdir().unwrap();
        let deployment = super::super::producer_tests::fixture_deployment();
        let file = DeploymentFile::open(temp.path(), deployment.spec.network_id).unwrap();
        file.save(&deployment).unwrap();
        (temp, file, deployment)
    }

    fn candidate(deployment: &Deployment, id: Uuid) -> ImageRevision {
        let mut image = deployment.cluster.as_ref().unwrap().image.clone();
        let (repository, _) = image.image.split_once('@').unwrap();
        image.image = format!("{repository}@sha256:{}", "e".repeat(64));
        image.config_digest = format!("sha256:{}", "f".repeat(64));
        ImageRevision {
            update_id: id,
            image,
            build: None,
            artifacts: ["image.json", "image-manifest.json", "image-config.json"]
                .into_iter()
                .map(|n| {
                    (
                        n.into(),
                        crate::devnet::Artifact {
                            sha256: "a".repeat(64),
                            bytes: 1,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn explicit_selection_pending_authorization_and_resume_identity() {
        let (_temp, file, mut deployment) = fixture();
        for nodes in [
            vec![],
            vec!["node-2".into(), "node-2".into()],
            vec!["node-99".into()],
        ] {
            assert!(controller::prepare(&mut deployment, &nodes, true).is_err());
        }
        assert!(controller::prepare(&mut deployment, &["node-2".into()], false).is_err());
        let id = controller::prepare(&mut deployment, &["node-2".into()], true).unwrap();
        assert!(file.load().unwrap().runtime.is_none());
        file.save(&deployment).unwrap();
        assert!(file.load().unwrap().runtime.unwrap().pending());
        assert!(controller::prepare(&mut deployment, &["node-1".into()], true).is_err());
        assert!(controller::resume(&deployment, Uuid::new_v4(), true).is_err());
        assert!(controller::resume(&deployment, id, false).is_err());
        controller::resume(&deployment, id, true).unwrap();
    }

    #[test]
    fn mixed_state_is_atomic_and_completed_nodes_require_fresh_observations() {
        let (_temp, file, mut deployment) = fixture();
        let original = deployment.render().unwrap().to_yaml().unwrap();
        let id = controller::prepare(&mut deployment, &["node-1".into(), "node-2".into()], true)
            .unwrap();
        let revision = candidate(&deployment, id);
        controller::set_revision(&file, &mut deployment, revision).unwrap();
        let mut fake = Fake {
            fail_node: Some("node-1".into()),
            ..Default::default()
        };
        assert!(controller::run(&file, &mut deployment, &mut fake).is_err());
        assert_eq!(
            fake.events,
            [
                "stage",
                "dispatch:node-2",
                "observe:node-2",
                "dispatch:node-1",
                "observe:node-1"
            ]
        );
        let saved = file.load().unwrap();
        let runtime = saved.runtime.as_ref().unwrap();
        assert_eq!(runtime.nodes.keys().collect::<Vec<_>>(), vec!["node-2"]);
        assert_eq!(
            runtime
                .update
                .as_ref()
                .unwrap()
                .completed
                .iter()
                .collect::<Vec<_>>(),
            vec!["node-2"]
        );
        assert!(!runtime.update.as_ref().unwrap().finished);
        assert_ne!(
            crate::update::active_image(&saved, "node-2").unwrap().image,
            saved.cluster.as_ref().unwrap().image.image
        );
        for unchanged in ["node-1", "node-3"] {
            assert_eq!(
                crate::update::active_image(&saved, unchanged).unwrap(),
                &saved.cluster.as_ref().unwrap().image
            );
        }
        let mut stale = Fake {
            fail_node: Some("node-2".into()),
            ..Default::default()
        };
        assert!(controller::run(&file, &mut deployment, &mut stale).is_err());
        assert_eq!(stale.events, ["stage", "observe:node-2"]);
        let mut recovered = Fake::default();
        controller::run(&file, &mut deployment, &mut recovered).unwrap();
        assert_eq!(
            recovered.events,
            [
                "stage",
                "observe:node-2",
                "dispatch:node-1",
                "observe:node-1",
                "cluster+services"
            ]
        );
        assert!(
            file.load()
                .unwrap()
                .runtime
                .unwrap()
                .update
                .unwrap()
                .finished
        );
        assert_eq!(deployment.render().unwrap().to_yaml().unwrap(), original);
        let completed_path = file
            .directory()
            .join(format!("updates/{id}/completed.json"));
        let completed_bytes = std::fs::read(&completed_path).unwrap();
        let completed: crate::update::UpdateIntent =
            serde_json::from_slice(&completed_bytes).unwrap();
        assert!(completed.finished);
        assert_eq!(completed.completed.len(), 2);
        controller::run(&file, &mut deployment, &mut Fake::default()).unwrap();
        assert_eq!(std::fs::read(&completed_path).unwrap(), completed_bytes);
        std::fs::write(&completed_path, b"conflicting metadata").unwrap();
        assert!(controller::run(&file, &mut deployment, &mut Fake::default()).is_err());
        assert_eq!(
            std::fs::read(&completed_path).unwrap(),
            b"conflicting metadata"
        );
        let mut cancelled = Fake {
            cancelled: true,
            ..Default::default()
        };
        assert!(controller::run(&file, &mut deployment, &mut cancelled).is_err());
        assert!(cancelled.events.is_empty());
    }

    #[test]
    fn completed_history_failure_does_not_publish_finished_state() {
        let (_temp, file, mut deployment) = fixture();
        let id = controller::prepare(&mut deployment, &["node-2".into()], true).unwrap();
        let revision = candidate(&deployment, id);
        controller::set_revision(&file, &mut deployment, revision).unwrap();
        std::fs::write(file.directory().join("updates"), b"not a directory").unwrap();
        assert!(controller::run(&file, &mut deployment, &mut Fake::default()).is_err());
        assert!(
            !deployment
                .runtime
                .as_ref()
                .unwrap()
                .update
                .as_ref()
                .unwrap()
                .finished
        );
        assert!(
            !file
                .load()
                .unwrap()
                .runtime
                .unwrap()
                .update
                .unwrap()
                .finished
        );
    }

    #[test]
    fn update_receipts_reject_identity_drift_and_incomplete_success() {
        let (_temp, file, mut deployment) = fixture();
        let id = controller::prepare(&mut deployment, &["node-2".into()], true).unwrap();
        let revision = candidate(&deployment, id);
        controller::set_revision(&file, &mut deployment, revision).unwrap();
        let mut other_profile = deployment.clone();
        other_profile.spec.aws_profile = "another-developer".into();
        other_profile.validate().unwrap();
        for mode in 0..6 {
            let mut changed = deployment.clone();
            let runtime = changed.runtime.as_mut().unwrap();
            let update = runtime.update.as_mut().unwrap();
            match mode {
                0 => update.finished = true,
                1 => {
                    update.completed.insert("node-2".into());
                }
                2 => {
                    update.targets.get_mut("node-2").unwrap().volume_id =
                        "vol-00000000000000099".into()
                }
                3 => {
                    update.targets.get_mut("node-2").unwrap().expected_image =
                        update.revision.as_ref().unwrap().image.image.clone()
                }
                4 => update.build_contract_sha256 = Some("a".repeat(64)),
                _ => update.storage_compatibility_acknowledged = false,
            }
            assert!(changed.validate().is_err(), "{mode}");
        }
    }
}
