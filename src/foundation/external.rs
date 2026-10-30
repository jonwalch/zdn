//! Saved external ownership is portable data. Execution is Linux-only and uses
//! the external typed contracts, never an invented ordinary consensus manifest.
use crate::{
    aws::TeamDefinition,
    cluster_infra::{ClusterTopology, NativeListener},
    infra::{FoundationSpec, PulumiProgram},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SCHEMA: &str = "zdn-external-deployment/v1";
pub mod source;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalDeployment {
    pub schema: String,
    /// Public immutable request only. Value keeps cleanup readable on platforms
    /// which do not compile the Linux companion executor.
    pub request: Value,
    pub request_sha256: String,
    pub node_count: u8,
    pub native_port: u16,
    pub reward_address: String,
}

impl ExternalDeployment {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported external deployment schema"
        );
        self.topology()?;
        crate::devnet::validate_hash(&self.request_sha256)?;
        ensure!(
            self.native_port != 0,
            "external native port must be nonzero"
        );
        ensure!(
            !self.reward_address.is_empty()
                && self.reward_address.len() <= 512
                && self
                    .reward_address
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()),
            "invalid external reward address"
        );
        ensure!(
            self.request["schema"] == crate_schema()
                && self.request["nodeCount"] == self.node_count,
            "external ownership and request differ"
        );
        #[cfg(target_os = "linux")]
        {
            let request = self.typed_request()?;
            request.validate()?;
            ensure!(
                request.block_interval_seconds <= 3600,
                "external host runtime cadence exceeds one hour"
            );
            ensure!(
                crate::devnet::sha256(&request.bytes()?) == self.request_sha256,
                "external request pin differs"
            );
        }
        Ok(())
    }

    pub fn topology(&self) -> Result<ClusterTopology> {
        ClusterTopology::new(self.node_count)
    }

    pub fn listener(&self) -> Result<NativeListener> {
        NativeListener::new(
            format!("0.0.0.0:{}", self.native_port).parse()?,
            &self.topology()?,
        )
    }

    pub fn render(
        &self,
        base: PulumiProgram,
        spec: &FoundationSpec,
        team: &TeamDefinition,
    ) -> Result<PulumiProgram> {
        self.validate()?;
        let topology = self.topology()?;
        let scripts = topology
            .nodes()
            .into_iter()
            .map(|node| (node.node_id, format!("{}dnf install -y bubblewrap\ntest -x /usr/bin/bwrap\ntest -x /usr/bin/setpriv\n", crate::host::base_user_data())))
            .collect();
        let program = topology.render_native(base, spec, &scripts, self.listener()?)?;
        let mut value = serde_json::to_value(program)?;
        for (key, resource) in crate::endpoints::session_document_resources(
            &spec.scope,
            team.bootstrap_id,
            spec.network_id,
            false,
        )? {
            value["resources"][key] = resource;
        }
        value["resources"]["hostArtifactsPolicy"] = json!({"name":spec.resource_name("host-artifacts-policy"),"type":"aws:iam:RolePolicyAttachment","properties":{"role":"${hostRole.name}","policyArn":crate::access::runtime_data_policy_arn(team)},"options":{"provider":"${provider}"}});
        for node in topology.nodes() {
            value["resources"][&node.host_key]["options"]["dependsOn"]
                .as_array_mut()
                .context("host dependency list missing")?
                .push(json!("${hostArtifactsPolicy}"));
        }
        let program: PulumiProgram = serde_json::from_value(value)?;
        program.validate_references()?;
        Ok(program)
    }

    #[cfg(target_os = "linux")]
    pub fn new(
        request: crate::devnet::external::ExternalRequest,
        native_port: u16,
        reward_address: String,
    ) -> Result<Self> {
        let value = Self {
            schema: SCHEMA.into(),
            request_sha256: crate::devnet::sha256(&request.bytes()?),
            node_count: request.node_count,
            request: serde_json::to_value(request)?,
            native_port,
            reward_address,
        };
        value.validate()?;
        Ok(value)
    }

    #[cfg(target_os = "linux")]
    pub fn typed_request(&self) -> Result<crate::devnet::external::ExternalRequest> {
        let request: crate::devnet::external::ExternalRequest =
            serde_json::from_value(self.request.clone())?;
        request.validate()?;
        Ok(request)
    }
}

fn crate_schema() -> &'static str {
    "zdn-external-artifact-set/v1"
}
