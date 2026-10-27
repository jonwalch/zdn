//! Credential-free private-service identities and least-privilege session access.
//!
//! Endpoint files select fixed services, never arbitrary SSM documents, remote
//! hosts, ports, AWS profiles, or deployment state. Their contents are portable
//! routing information, not an authorization grant or proof of live readiness.

use crate::{
    access::iam_resource,
    aws::{AwsApi, AwsSelection},
    cluster_infra::{ClusterTopology, PRODUCER_NODE_ID},
    foundation::Deployment,
    infra::AWS_PROVIDER_VERSION,
    state::Scope,
};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use uuid::Uuid;

pub const API_VERSION: &str = "zdn-endpoints/v1alpha1";
pub const MAX_FILE_BYTES: usize = 16 * 1024;
/// This is the restricted client gateway, not Zakura's administrative RPC.
pub const NODE_RPC_PORT: u16 = 18234;
pub const LIGHTWALLET_GRPC_PORT: u16 = 9067;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Service {
    NodeRpc,
    LightwalletGrpc,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Self::NodeRpc => "node-rpc",
            Self::LightwalletGrpc => "lightwallet-grpc",
        }
    }

    pub fn remote_port(self) -> u16 {
        match self {
            Self::NodeRpc => NODE_RPC_PORT,
            Self::LightwalletGrpc => LIGHTWALLET_GRPC_PORT,
        }
    }

    pub fn document_name(self, bootstrap_id: Uuid, network_id: Uuid) -> String {
        // The administrator grants document creation inside this bootstrap's
        // namespace. A deployment role cannot create or retag another team's
        // document merely by reusing its network UUID.
        format!("zdn-{bootstrap_id}-{network_id}-{}-v1", self.name())
    }

    pub fn document_key(self) -> &'static str {
        match self {
            Self::NodeRpc => "nodeRpcSessionDocument",
            Self::LightwalletGrpc => "lightwalletSessionDocument",
        }
    }

    /// Session document schema:
    /// https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-schema.html
    /// The sole caller parameter is local. Omitting host forces the SSM agent
    /// to connect to its own loopback interface, and portNumber is a literal.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.service.session_document")
    )]
    pub fn session_document(self) -> Value {
        json!({
            "schemaVersion":"1.0",
            "description":format!("zdn private {} service", self.name()),
            "sessionType":"Port",
            "parameters":{
                "localPortNumber":{
                    "type":"String",
                    "description":"Local loopback listener port",
                    "allowedPattern":"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
                }
            },
            "properties":{
                "type":"LocalPortForwarding",
                "portNumber":self.remote_port().to_string(),
                "localPortNumber":"{{ localPortNumber }}"
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTarget {
    pub service: Service,
    pub node_id: String,
    pub instance_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFile {
    pub api_version: String,
    pub network_id: Uuid,
    pub scope: Scope,
    pub bootstrap_id: Uuid,
    pub consensus_fingerprint: String,
    pub node_count: u8,
    pub targets: Vec<EndpointTarget>,
}

impl EndpointFile {
    /// Validate saved identities. The caller separately verifies that its
    /// runtime receipt includes the installed client gateway and ready services.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.from_deployment")
    )]
    pub fn from_deployment(deployment: &Deployment) -> Result<Self> {
        deployment.validate()?;
        ensure!(!deployment.destroyed, "devnet has been destroyed");
        ensure!(
            deployment.unresolved_operation.is_none(),
            "devnet has an unresolved deployment operation"
        );
        ensure!(
            !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
            "devnet has an unresolved image update"
        );
        let cluster = deployment
            .cluster
            .as_ref()
            .context("foundation hosts have no private node endpoints")?;
        ensure!(
            cluster.client_access,
            "legacy devnet has no installed private client gateway; create a devnet with client access enabled"
        );
        let outputs = deployment
            .outputs
            .as_ref()
            .context("devnet has no saved outputs")?;
        let node = &outputs.nodes[PRODUCER_NODE_ID];
        let mut targets = vec![EndpointTarget {
            service: Service::NodeRpc,
            node_id: node.node_id.clone(),
            instance_id: node.instance_id.clone(),
        }];
        if let Some(lightwallet) = &outputs.lightwallet {
            targets.push(EndpointTarget {
                service: Service::LightwalletGrpc,
                node_id: lightwallet.node_id.clone(),
                instance_id: lightwallet.instance_id.clone(),
            });
        }
        let file = Self {
            api_version: API_VERSION.into(),
            network_id: deployment.spec.network_id,
            scope: deployment.spec.scope.clone(),
            bootstrap_id: deployment.team.bootstrap_id,
            consensus_fingerprint: cluster.manifest.fingerprint()?,
            node_count: cluster.node_count,
            targets,
        };
        file.validate()?;
        Ok(file)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported endpoint file version"
        );
        validate_scope(&self.scope, self.bootstrap_id, self.network_id)?;
        ensure!(
            self.consensus_fingerprint.len() == 64
                && self
                    .consensus_fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "endpoint consensus fingerprint must be canonical SHA-256"
        );
        let topology = ClusterTopology::new(self.node_count)?;
        ensure!(
            (1..=2).contains(&self.targets.len()),
            "endpoint file must contain one or two services"
        );
        ensure!(
            self.targets[0].service == Service::NodeRpc,
            "node RPC must be the first endpoint"
        );
        let mut services = BTreeSet::new();
        for target in &self.targets {
            ensure!(
                services.insert(target.service),
                "duplicate endpoint service"
            );
            crate::infra::validate_aws_id(&target.instance_id, "i-")?;
            let node = match target.service {
                Service::NodeRpc => PRODUCER_NODE_ID.to_owned(),
                Service::LightwalletGrpc => topology.lightwallet_node().node_id,
            };
            ensure!(
                target.node_id == node,
                "service target differs from the selected node"
            );
        }
        if self.targets.len() == 2 {
            ensure!(
                (self.targets[0].instance_id == self.targets[1].instance_id)
                    == (self.node_count == 1),
                "service instance identities disagree with topology"
            );
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.validate_identity")
    )]
    pub fn validate_identity(
        &self,
        scope: &Scope,
        bootstrap_id: Uuid,
        network_id: Uuid,
        consensus_fingerprint: &str,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.scope == *scope
                && self.bootstrap_id == bootstrap_id
                && self.network_id == network_id
                && self.consensus_fingerprint == consensus_fingerprint,
            "endpoint file belongs to a different network, team, account, region, bootstrap, or chain"
        );
        Ok(())
    }

    pub fn validate_for(&self, deployment: &Deployment) -> Result<()> {
        self.validate()?;
        ensure!(
            *self == Self::from_deployment(deployment)?,
            "endpoint file differs from the saved deployment"
        );
        Ok(())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_FILE_BYTES, "endpoint file is too large");
        let file: Self = serde_json::from_slice(bytes).context("invalid endpoint file")?;
        file.validate()?;
        Ok(file)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.load")
    )]
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).context("read endpoint file metadata")?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_FILE_BYTES as u64,
            "endpoint file must be a bounded regular file"
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = options.open(path).context("open endpoint file")?;
        ensure!(
            file.metadata()?.is_file(),
            "endpoint file must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Self::from_json(&bytes)
    }

    /// Publish a complete file, refusing to replace an existing destination.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.save_new")
    )]
    pub fn save_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(bytes.len() < MAX_FILE_BYTES, "endpoint file is too large");
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temporary = NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(path)
            .context("endpoint output already exists or could not be published")?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn target(&self, service: Service) -> Option<&EndpointTarget> {
        self.targets.iter().find(|target| target.service == service)
    }

    pub fn document_arn(&self, service: Service) -> String {
        format!(
            "arn:aws:ssm:{}:{}:document/{}",
            self.scope.region,
            self.scope.account_id,
            self.document_name(service)
        )
    }

    pub fn document_name(&self, service: Service) -> String {
        service.document_name(self.bootstrap_id, self.network_id)
    }

    pub fn instance_arn(&self, target: &EndpointTarget) -> String {
        format!(
            "arn:aws:ec2:{}:{}:instance/{}",
            self.scope.region, self.scope.account_id, target.instance_id
        )
    }

    pub fn participant_role_name(&self) -> String {
        format!("zdn-{}-participant", self.network_id.simple())
    }

    pub fn participant_role_path(&self) -> String {
        format!("/zdn-participants/{}/", self.bootstrap_id)
    }

    pub fn participant_role_arn(&self) -> String {
        format!(
            "arn:aws:iam::{}:role{}{}",
            self.scope.account_id,
            self.participant_role_path(),
            self.participant_role_name()
        )
    }

    /// No state/deployment grants and no arbitrary document, command, or host
    /// choice. This policy grants access; it is not a deny boundary for an
    /// existing principal with unrelated policies. Setup creates a separate role.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.participant_policy")
    )]
    pub fn participant_policy(&self) -> Result<Value> {
        self.validate()?;
        let instances: BTreeSet<_> = self
            .targets
            .iter()
            .map(|target| self.instance_arn(target))
            .collect();
        let instance_ids: BTreeSet<_> = self
            .targets
            .iter()
            .map(|target| target.instance_id.clone())
            .collect();
        let documents: Vec<_> = self
            .targets
            .iter()
            .map(|target| self.document_arn(target.service))
            .collect();
        let session_prefix = format!(
            "arn:aws:ssm:{}:{}:session/",
            self.scope.region, self.scope.account_id
        );
        // AWS's Session Manager examples use BoolIfExists: the document check
        // can be absent while IAM evaluates the EC2 target. An explicit false
        // still fails. Exact document grants and all instance tags remain required.
        // https://d1.awsstatic.com/events/Summits/reinvent2023/NET202_Secure-remote-connectivity-to-AWS.pdf (slide 40)
        Ok(json!({"Version":"2012-10-17","Statement":[
            {"Sid":"StartOnlyNetworkInstances","Effect":"Allow","Action":"ssm:StartSession","Resource":instances,
                "Condition":{
                    "BoolIfExists":{"ssm:SessionDocumentAccessCheck":"true"},
                    "StringEquals":{
                        "ssm:resourceTag/zdn:managed-by":"zdn",
                        "ssm:resourceTag/zdn:team-id":self.scope.team_id,
                        "ssm:resourceTag/zdn:bootstrap":self.bootstrap_id.to_string(),
                        "ssm:resourceTag/zdn:network-id":self.network_id.to_string()
                    }
                }
            },
            {"Sid":"StartOnlyFixedServiceDocuments","Effect":"Allow","Action":["ssm:StartSession","ssm:GetDocument"],"Resource":documents},
            {"Sid":"OpenOwnSessionChannel","Effect":"Allow","Action":"ssmmessages:OpenDataChannel","Resource":format!("{session_prefix}${{aws:userid}}-*")},
            {"Sid":"EndOwnNetworkSessions","Effect":"Allow","Action":"ssm:TerminateSession","Resource":format!("{session_prefix}*"),
                "Condition":{"StringEquals":{
                    "ssm:resourceTag/aws:ssmmessages:target-id":instance_ids,
                    "ssm:resourceTag/aws:ssmmessages:session-id":"${aws:userid}"
                }}
            }
        ]}))
    }

    /// One session identity per trusted IAM principal. A shared source role is
    /// itself one participant; its callers must already share a trust boundary.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.participant_session_names")
    )]
    pub fn participant_session_names(
        &self,
        trusted_principals: &[String],
    ) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        ensure!(
            (1..=20).contains(&trusted_principals.len()),
            "select 1-20 explicit trusted IAM principals"
        );
        let mut principals = BTreeSet::new();
        for principal in trusted_principals {
            ensure!(principals.insert(principal), "duplicate trusted principal");
            let kind = if principal.contains(":user/") {
                "user"
            } else {
                "role"
            };
            iam_resource(principal, &self.scope.account_id, kind)?;
            ensure!(
                *principal != self.participant_role_arn(),
                "participant role cannot trust itself"
            );
            ensure!(
                !principal.contains(":role/zdn/")
                    && !principal.contains(":role/zdn-admin/")
                    && !principal.contains(":role/zdn-participants/"),
                "trust a caller identity, not a zdn runtime, deployment, or participant role"
            );
        }
        let mut names = BTreeSet::new();
        principals
            .into_iter()
            .map(|principal| {
                let name = format!(
                    "zdn-{}",
                    hex::encode(&Sha256::digest(principal.as_bytes())[..16])
                );
                ensure!(
                    names.insert(name.clone()),
                    "participant session name collision"
                );
                Ok((principal.clone(), name))
            })
            .collect()
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.participant_trust_policy")
    )]
    pub fn participant_trust_policy(&self, trusted_principals: &[String]) -> Result<Value> {
        let statements: Vec<_> = self
            .participant_session_names(trusted_principals)?
            .into_iter()
            .map(|(principal, name)| {
                json!({
                    "Effect":"Allow", "Action":"sts:AssumeRole", "Principal":{"AWS":principal},
                    "Condition":{"StringEquals":{"sts:RoleSessionName":name}}
                })
            })
            .collect();
        let policy = json!({"Version":"2012-10-17","Statement":statements});
        // Fail before creating resources if the default IAM trust-policy quota
        // cannot hold the per-principal conditions.
        ensure!(
            policy.to_string().len() <= 2048,
            "participant trust policy exceeds the default 2048-character IAM limit; select fewer principals"
        );
        Ok(policy)
    }

    /// Confirm the default content immediately before creating sessions. This
    /// does not need EC2 inventory or any deployment-state permission. The
    /// administrator remains trusted to preserve documents between this check
    /// and StartSession; IAM fixes the allowed document ARN, not its contents.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.validate_live_documents")
    )]
    pub fn validate_live_documents(&self, api: &dyn AwsApi) -> Result<()> {
        self.validate()?;
        for target in &self.targets {
            let document_arn = self.document_arn(target.service);
            let document_name = self.document_name(target.service);
            let response = api.call(
                "ssm",
                "get-document",
                json!({
                    "Name":document_arn,
                    "DocumentVersion":"$DEFAULT", "DocumentFormat":"JSON"
                }),
                &[],
            )?;
            let returned_name = response.get("Name").and_then(Value::as_str);
            ensure!(
                (returned_name == Some(document_arn.as_str())
                    || returned_name == Some(document_name.as_str()))
                    && response.get("DocumentType").and_then(Value::as_str) == Some("Session")
                    && response.get("Status").and_then(Value::as_str) == Some("Active")
                    && response.get("DocumentFormat").and_then(Value::as_str) == Some("JSON"),
                "private session document has an unexpected identity, type, status, or format"
            );
            let content = response
                .get("Content")
                .and_then(Value::as_str)
                .context("private session document has no JSON content")?;
            ensure!(
                content.len() <= MAX_FILE_BYTES,
                "private session document is too large"
            );
            let actual: Value = serde_json::from_str(content)
                .context("invalid private session document content")?;
            ensure!(
                actual == target.service.session_document(),
                "private session document content differs from the fixed service contract"
            );
        }
        Ok(())
    }

    /// Administrator-owned separate stack. The network stack owns documents;
    /// this stack owns only the protected role and its attached inline policy.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "endpoints.endpoint_file.render_participant")
    )]
    pub fn render_participant(
        &self,
        administrator: &AwsSelection,
        trusted_principals: &[String],
    ) -> Result<Value> {
        self.validate()?;
        administrator.validate()?;
        ensure!(
            administrator.account_id == self.scope.account_id
                && administrator.region == self.scope.region,
            "administrator selection differs from endpoint account or region"
        );
        let trust = self.participant_trust_policy(trusted_principals)?;
        // Pulumi YAML interpolation uses the same delimiter as IAM variables.
        // Escape them in the program while keeping the policy helper raw JSON.
        let permissions = self.participant_policy()?.to_string().replace("${", "$${");
        Ok(json!({
            "name":"zdn-participant", "runtime":"yaml",
            "resources":{
                "provider":{"type":"pulumi:providers:aws","properties":{
                    "region":self.scope.region,"profile":administrator.profile,"allowedAccountIds":[self.scope.account_id]
                },"options":{"version":AWS_PROVIDER_VERSION}},
                "participantRole":{"type":"aws:iam:Role","properties":{
                    "name":self.participant_role_name(),"path":self.participant_role_path(),
                    "assumeRolePolicy":trust.to_string(),"maxSessionDuration":3600,
                    "tags":ownership_tags(&self.scope, self.bootstrap_id, self.network_id)
                },"options":{"provider":"${provider}","protect":true}},
                "participantPolicy":{"type":"aws:iam:RolePolicy","properties":{
                    "name":"zdn-private-services","role":"${participantRole.name}","policy":permissions
                },"options":{"provider":"${provider}","protect":true}}
            },
            "outputs":{"roleArn":"${participantRole.arn}"}
        }))
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "endpoints.validate_scope")
)]
fn validate_scope(scope: &Scope, bootstrap_id: Uuid, network_id: Uuid) -> Result<()> {
    scope.validate()?;
    ensure!(
        scope.team_id != "." && scope.team_id != "..",
        "invalid team ID"
    );
    ensure!(
        !scope.region.starts_with("cn-") && !scope.region.starts_with("us-gov-"),
        "endpoint files support the standard AWS partition only"
    );
    ensure!(!bootstrap_id.is_nil(), "bootstrap ID must not be nil");
    ensure!(
        network_id.get_version_num() == 4,
        "network ID must be a UUIDv4"
    );
    Ok(())
}

pub fn ownership_tags(scope: &Scope, bootstrap_id: Uuid, network_id: Uuid) -> Value {
    json!({
        "zdn:managed-by":"zdn", "zdn:team-id":scope.team_id,
        "zdn:bootstrap":bootstrap_id.to_string(), "zdn:network-id":network_id.to_string()
    })
}

/// Render cluster-owned, fixed-port document resources before AWS assigns host
/// IDs. No parameter can select a command, a different host, or a remote port.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "endpoints.session_document_resources")
)]
pub fn session_document_resources(
    scope: &Scope,
    bootstrap_id: Uuid,
    network_id: Uuid,
    lightwallet: bool,
) -> Result<BTreeMap<String, Value>> {
    validate_scope(scope, bootstrap_id, network_id)?;
    let services = [Service::NodeRpc, Service::LightwalletGrpc];
    Ok(services
        .into_iter()
        .filter(|service| *service == Service::NodeRpc || lightwallet)
        .map(|service| {
            let name = service.document_name(bootstrap_id, network_id);
            (
                service.document_key().into(),
                json!({
                    "name":name,
                    "type":"aws:ssm:Document",
                    "properties":{
                        "name":name,"documentType":"Session","documentFormat":"JSON",
                        "content":service.session_document().to_string(),
                        "tags":ownership_tags(scope, bootstrap_id, network_id)
                    },
                    "options":{"provider":"${provider}"}
                }),
            )
        })
        .collect())
}
