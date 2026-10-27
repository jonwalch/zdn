//! Deterministic, typed Pulumi program for one private foundation test host.
//!
//! Rendering does not contact AWS. A successful render is not a provider or host
//! qualification; the caller must validate the pinned AMI and observed outputs.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{config::Size, state::Scope};

pub const FOUNDATION_SCHEMA_VERSION: u32 = 1;
pub const AWS_PROVIDER_VERSION: &str = "7.50.0";
pub const READINESS_PORT: u16 = 18080;
pub const GIB: u64 = 1024 * 1024 * 1024;
pub const FIXTURE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const FIXTURE_CPU_MILLIS: u32 = 250;
pub const HOST_CPU_RESERVE_MILLIS: u32 = 250;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundationSpec {
    pub scope: Scope,
    pub network_id: Uuid,
    pub aws_profile: String,
    pub ami_id: String,
    pub availability_zone: String,
    pub size: Size,
    pub retain_chain_disk: bool,
}

impl FoundationSpec {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.foundation_spec.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.network_id.get_version_num() == 4,
            "network ID must be a UUIDv4"
        );
        ensure!(
            !self.scope.region.starts_with("cn-") && !self.scope.region.starts_with("us-gov-"),
            "the foundation currently supports the standard AWS partition only"
        );
        ensure!(
            !self.aws_profile.is_empty()
                && self.aws_profile.len() <= 128
                && self
                    .aws_profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./@".contains(&b)),
            "invalid AWS profile"
        );
        validate_aws_id(&self.ami_id, "ami-")?;
        let suffix = self
            .availability_zone
            .strip_prefix(&self.scope.region)
            .context("availability zone must be in the selected region")?;
        ensure!(
            suffix.len() == 1 && suffix.bytes().all(|b| b.is_ascii_lowercase()),
            "select one standard availability zone in the deployment region"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.foundation_spec.render")
    )]
    pub fn render(&self) -> Result<PulumiProgram> {
        self.validate()?;
        let mut resources = BTreeMap::new();
        let tags = |purpose: &str| -> BTreeMap<String, String> {
            [
                ("Name".into(), self.resource_name(purpose)),
                ("zdn:network-id".into(), self.network_id.to_string()),
                ("zdn:team-id".into(), self.scope.team_id.clone()),
                ("zdn:managed-by".into(), "zdn".into()),
                ("zdn:purpose".into(), "foundation".into()),
            ]
            .into()
        };
        resources.insert(
            "provider".into(),
            Resource {
                name: self.resource_name("provider"),
                definition: Definition::Provider(Provider {
                    region: self.scope.region.clone(),
                    profile: self.aws_profile.clone(),
                    allowed_account_ids: vec![self.scope.account_id.clone()],
                    default_tags: None,
                }),
                options: ResourceOptions {
                    version: Some(AWS_PROVIDER_VERSION.into()),
                    ..Default::default()
                },
            },
        );
        let mut add = |key: &str, definition: Definition, dependencies: &[&str], retain: bool| {
            resources.insert(
                key.into(),
                Resource {
                    name: self.resource_name(key),
                    definition,
                    options: ResourceOptions {
                        provider: Some(reference("provider")),
                        depends_on: dependencies.iter().map(|name| reference(name)).collect(),
                        ignore_changes: Vec::new(),
                        retain_on_delete: retain,
                        ..Default::default()
                    },
                },
            );
        };
        add(
            "vpc",
            Definition::Vpc(Vpc {
                cidr_block: "10.90.0.0/16".into(),
                enable_dns_support: true,
                enable_dns_hostnames: true,
                tags: tags("vpc"),
            }),
            &[],
            false,
        );
        add(
            "defaultSecurityGroup",
            Definition::DefaultSecurityGroup(DefaultSecurityGroup {
                vpc_id: reference("vpc.id"),
                ingress: vec![],
                egress: vec![],
                tags: tags("default-sg"),
            }),
            &[],
            false,
        );
        for (key, cidr) in [
            ("publicSubnet", "10.90.0.0/24"),
            ("privateSubnet", "10.90.1.0/24"),
        ] {
            add(
                key,
                Definition::Subnet(Subnet {
                    vpc_id: reference("vpc.id"),
                    cidr_block: cidr.into(),
                    availability_zone: self.availability_zone.clone(),
                    map_public_ip_on_launch: false,
                    tags: tags(key),
                }),
                &[],
                false,
            );
        }
        add(
            "internetGateway",
            Definition::InternetGateway(InternetGateway {
                vpc_id: reference("vpc.id"),
                tags: tags("internet-gateway"),
            }),
            &[],
            false,
        );
        add(
            "publicRoutes",
            Definition::RouteTable(RouteTable {
                vpc_id: reference("vpc.id"),
                tags: tags("public-routes"),
                routes: vec![Route {
                    cidr_block: "0.0.0.0/0".into(),
                    gateway_id: Some(reference("internetGateway.id")),
                    nat_gateway_id: None,
                }],
            }),
            &[],
            false,
        );
        add(
            "publicRouteAssociation",
            Definition::RouteTableAssociation(RouteTableAssociation {
                subnet_id: reference("publicSubnet.id"),
                route_table_id: reference("publicRoutes.id"),
            }),
            &[],
            false,
        );
        add(
            "natAddress",
            Definition::Eip(Eip {
                domain: "vpc".into(),
                tags: tags("nat-address"),
            }),
            &["internetGateway"],
            false,
        );
        add(
            "natGateway",
            Definition::NatGateway(NatGateway {
                allocation_id: reference("natAddress.id"),
                subnet_id: reference("publicSubnet.id"),
                connectivity_type: "public".into(),
                tags: tags("nat"),
            }),
            &["internetGateway", "publicRouteAssociation"],
            false,
        );
        add(
            "privateRoutes",
            Definition::RouteTable(RouteTable {
                vpc_id: reference("vpc.id"),
                tags: tags("private-routes"),
                routes: vec![Route {
                    cidr_block: "0.0.0.0/0".into(),
                    gateway_id: None,
                    nat_gateway_id: Some(reference("natGateway.id")),
                }],
            }),
            &[],
            false,
        );
        add(
            "privateRouteAssociation",
            Definition::RouteTableAssociation(RouteTableAssociation {
                subnet_id: reference("privateSubnet.id"),
                route_table_id: reference("privateRoutes.id"),
            }),
            &[],
            false,
        );
        add(
            "hostSecurityGroup",
            Definition::SecurityGroup(SecurityGroup {
                name: self.resource_name("host-sg"),
                description: "Private foundation host; SSM outbound only".into(),
                vpc_id: reference("vpc.id"),
                ingress: vec![],
                egress: vec![SecurityRule {
                    protocol: "tcp".into(),
                    from_port: 443,
                    to_port: 443,
                    cidr_blocks: vec!["0.0.0.0/0".into()],
                    description: "HTTPS for SSM and distribution packages".into(),
                }],
                tags: tags("host-sg"),
            }),
            &[],
            false,
        );
        add(
            "hostRole",
            Definition::Role(Role {
                name: self.resource_name("host-role"),
                path: None,
                permissions_boundary: None,
                assume_role_policy: serde_json::to_string(
                    &json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}),
                )?,
                tags: tags("host-role"),
            }),
            &[],
            false,
        );
        add(
            "hostSsmPolicy",
            Definition::RolePolicyAttachment(RolePolicyAttachment {
                role: reference("hostRole.name"),
                policy_arn: "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore".into(),
            }),
            &[],
            false,
        );
        add(
            "hostProfile",
            Definition::InstanceProfile(InstanceProfile {
                name: self.resource_name("host-profile"),
                path: None,
                role: reference("hostRole.name"),
                tags: tags("host-profile"),
            }),
            &[],
            false,
        );
        let allocation = self.size.allocation();
        add(
            "chainDisk",
            Definition::Volume(Volume {
                availability_zone: self.availability_zone.clone(),
                encrypted: true,
                size: allocation.chain_disk_gib,
                volume_type: "gp3".into(),
                iops: 3000,
                throughput: 125,
                tags: tags("chain-disk"),
            }),
            &[],
            self.retain_chain_disk,
        );
        add(
            "host",
            Definition::Instance(Instance {
                ami: self.ami_id.clone(),
                availability_zone: self.availability_zone.clone(),
                instance_type: allocation.instance.into(),
                subnet_id: reference("privateSubnet.id"),
                private_ip: None,
                associate_public_ip_address: false,
                vpc_security_group_ids: vec![reference("hostSecurityGroup.id")],
                iam_instance_profile: reference("hostProfile.name"),
                metadata_options: MetadataOptions {
                    http_endpoint: "enabled".into(),
                    http_tokens: "required".into(),
                    http_put_response_hop_limit: 1,
                    instance_metadata_tags: "disabled".into(),
                },
                root_block_device: RootBlockDevice {
                    encrypted: true,
                    delete_on_termination: true,
                    volume_size: allocation.root_disk_gib,
                    volume_type: "gp3".into(),
                    tags: tags("root-disk"),
                },
                user_data: self.cloud_init()?,
                user_data_replace_on_change: true,
                tags: tags("host"),
            }),
            &["hostSsmPolicy", "privateRouteAssociation"],
            false,
        );
        add(
            "chainAttachment",
            Definition::VolumeAttachment(VolumeAttachment {
                device_name: "/dev/sdf".into(),
                instance_id: reference("host.id"),
                volume_id: reference("chainDisk.id"),
                force_detach: false,
                stop_instance_before_detaching: true,
            }),
            &[],
            false,
        );
        let outputs = json!({
            "schema_version": FOUNDATION_SCHEMA_VERSION,
            "scope": self.scope,
            "network_id": self.network_id,
            "availability_zone": self.availability_zone,
            "vpc_id": reference("vpc.id"),
            "private_subnet_id": reference("privateSubnet.id"),
            "instance_id": reference("host.id"),
            "private_ip": reference("host.privateIp"),
            "chain_volume_id": reference("chainDisk.id"),
            "retain_chain_disk": self.retain_chain_disk,
            "security_group_id": reference("hostSecurityGroup.id"),
            "nat_gateway_id": reference("natGateway.id"),
            "eip_allocation_id": reference("natAddress.id")
        });
        let program = PulumiProgram {
            name: "zdn-foundation".into(),
            runtime: "yaml".into(),
            resources,
            outputs: serde_json::from_value(outputs)?,
        };
        program.validate_references()?;
        Ok(program)
    }

    pub fn resource_name(&self, purpose: &str) -> String {
        format!("zdn-{}-{purpose}", self.network_id)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.foundation_spec.cloud_init")
    )]
    pub fn cloud_init(&self) -> Result<String> {
        self.validate()?;
        // Preparation only: the selected native runtime installs and starts
        // the readiness service after verifying its pinned helper.
        let script = HOST_SETUP.to_owned();
        // There are no user-controlled shell strings. The only Pulumi expression
        // in this script is the generated volume resource reference.
        ensure!(script.len() <= 16 * 1024, "EC2 user data exceeds 16 KiB");
        Ok(script)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PulumiProgram {
    pub name: String,
    pub runtime: String,
    pub resources: BTreeMap<String, Resource>,
    pub outputs: BTreeMap<String, Value>,
}

impl PulumiProgram {
    pub fn to_yaml(&self) -> Result<String> {
        self.validate_references()?;
        Ok(serde_yaml::to_string(self)?)
    }

    /// Reject dangling resource/property references and dependency cycles before
    /// starting Pulumi. Provider-schema compatibility remains a separate gate.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.pulumi_program.validate_references")
    )]
    pub fn validate_references(&self) -> Result<()> {
        let mut graph = BTreeMap::new();
        for (name, resource) in &self.resources {
            let mut refs = BTreeSet::new();
            collect_references(&serde_json::to_value(resource)?, &mut refs)?;
            self.check_references(&refs)?;
            graph.insert(
                name.as_str(),
                refs.into_iter()
                    .map(|r| r.split('.').next().unwrap().to_owned())
                    .collect::<BTreeSet<_>>(),
            );
        }
        let mut output_refs = BTreeSet::new();
        collect_references(&serde_json::to_value(&self.outputs)?, &mut output_refs)?;
        self.check_references(&output_refs)?;
        let mut complete = BTreeSet::new();
        for name in self.resources.keys() {
            visit(name, &graph, &mut complete, &mut BTreeSet::new())?;
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.pulumi_program.check_references")
    )]
    fn check_references(&self, refs: &BTreeSet<String>) -> Result<()> {
        for target in refs {
            let (name, property) = target
                .split_once('.')
                .map_or((target.as_str(), None), |(a, b)| (a, Some(b)));
            let resource = self
                .resources
                .get(name)
                .with_context(|| format!("unresolved Pulumi reference {target}"))?;
            if let Some(property) = property {
                ensure!(
                    resource.definition.output_properties().contains(&property),
                    "unknown Pulumi output reference {target}"
                );
            }
        }
        Ok(())
    }
}

fn visit<'a>(
    name: &'a str,
    graph: &'a BTreeMap<&str, BTreeSet<String>>,
    complete: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
) -> Result<()> {
    if complete.contains(name) {
        return Ok(());
    }
    ensure!(
        active.insert(name.into()),
        "Pulumi dependency cycle at {name}"
    );
    for dependency in &graph[name] {
        visit(dependency, graph, complete, active)?;
    }
    active.remove(name);
    complete.insert(name.into());
    Ok(())
}

fn collect_references(value: &Value, refs: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::String(value) => {
            let mut rest = value.as_str();
            while let Some(start) = rest.find("${") {
                rest = &rest[start + 2..];
                let end = rest.find('}').context("unclosed Pulumi reference")?;
                refs.insert(rest[..end].into());
                rest = &rest[end + 1..];
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_references(item, refs)?;
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                collect_references(item, refs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reference(target: &str) -> String {
    format!("${{{target}}}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    pub name: String,
    #[serde(flatten)]
    pub definition: Definition,
    pub options: ResourceOptions,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_changes: Vec<String>,
    #[serde(default)]
    pub retain_on_delete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "properties")]
pub enum Definition {
    #[serde(rename = "pulumi:providers:aws")]
    Provider(Provider),
    #[serde(rename = "aws:ec2:Vpc")]
    Vpc(Vpc),
    #[serde(rename = "aws:ec2:Subnet")]
    Subnet(Subnet),
    #[serde(rename = "aws:ec2:InternetGateway")]
    InternetGateway(InternetGateway),
    #[serde(rename = "aws:ec2:RouteTable")]
    RouteTable(RouteTable),
    #[serde(rename = "aws:ec2:RouteTableAssociation")]
    RouteTableAssociation(RouteTableAssociation),
    #[serde(rename = "aws:ec2:Eip")]
    Eip(Eip),
    #[serde(rename = "aws:ec2:NatGateway")]
    NatGateway(NatGateway),
    #[serde(rename = "aws:ec2:DefaultSecurityGroup")]
    DefaultSecurityGroup(DefaultSecurityGroup),
    #[serde(rename = "aws:ec2:SecurityGroup")]
    SecurityGroup(SecurityGroup),
    #[serde(rename = "aws:iam:Role")]
    Role(Role),
    #[serde(rename = "aws:iam:RolePolicyAttachment")]
    RolePolicyAttachment(RolePolicyAttachment),
    #[serde(rename = "aws:iam:InstanceProfile")]
    InstanceProfile(InstanceProfile),
    #[serde(rename = "aws:ebs:Volume")]
    Volume(Volume),
    #[serde(rename = "aws:ec2:Instance")]
    Instance(Instance),
    #[serde(rename = "aws:ec2:VolumeAttachment")]
    VolumeAttachment(VolumeAttachment),
    #[serde(rename = "aws:ssm:Document")]
    SessionDocument(SessionDocument),
}
impl Definition {
    fn output_properties(&self) -> &[&str] {
        match self {
            Self::Instance(_) => &["id", "privateIp"],
            Self::Role(_) | Self::InstanceProfile(_) => &["id", "name", "arn"],
            _ => &["id"],
        }
    }
}

macro_rules! properties {
    ($name:ident { $($(#[$meta:meta])* $field:ident : $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name { $($(#[$meta])* pub $field: $kind),* }
    };
}
type Tags = BTreeMap<String, String>;
properties!(SessionDocument {
    name: String,
    document_type: String,
    document_format: String,
    content: String,
    tags: Tags
});
properties!(Provider {
    region: String,
    profile: String,
    allowed_account_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_tags: Option<DefaultTags>
});
properties!(DefaultTags { tags: Tags });
properties!(Vpc {
    cidr_block: String,
    enable_dns_support: bool,
    enable_dns_hostnames: bool,
    tags: Tags
});
properties!(Subnet {
    vpc_id: String,
    cidr_block: String,
    availability_zone: String,
    map_public_ip_on_launch: bool,
    tags: Tags
});
properties!(InternetGateway {
    vpc_id: String,
    tags: Tags
});
properties!(RouteTable { vpc_id: String, routes: Vec<Route>, tags: Tags });
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub cidr_block: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat_gateway_id: Option<String>,
}
properties!(RouteTableAssociation {
    subnet_id: String,
    route_table_id: String
});
properties!(Eip {
    domain: String,
    tags: Tags
});
properties!(NatGateway {
    allocation_id: String,
    subnet_id: String,
    connectivity_type: String,
    tags: Tags
});
properties!(DefaultSecurityGroup { vpc_id: String, ingress: Vec<SecurityRule>, egress: Vec<SecurityRule>, tags: Tags });
properties!(SecurityGroup { name: String, description: String, vpc_id: String, ingress: Vec<SecurityRule>, egress: Vec<SecurityRule>, tags: Tags });
properties!(SecurityRule { protocol: String, from_port: u16, to_port: u16, cidr_blocks: Vec<String>, description: String });
properties!(Role {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions_boundary: Option<String>,
    assume_role_policy: String,
    tags: Tags
});
properties!(RolePolicyAttachment {
    role: String,
    policy_arn: String
});
properties!(InstanceProfile {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    role: String,
    tags: Tags
});
properties!(Volume {
    availability_zone: String,
    encrypted: bool,
    size: u32,
    #[serde(rename = "type")]
    volume_type: String,
    iops: u32,
    throughput: u32,
    tags: Tags
});
properties!(Instance { ami: String, availability_zone: String, instance_type: String, subnet_id: String, #[serde(default, skip_serializing_if = "Option::is_none")] private_ip: Option<Ipv4Addr>, associate_public_ip_address: bool, vpc_security_group_ids: Vec<String>, iam_instance_profile: String, metadata_options: MetadataOptions, root_block_device: RootBlockDevice, user_data: String, user_data_replace_on_change: bool, tags: Tags });
properties!(MetadataOptions {
    http_endpoint: String,
    http_tokens: String,
    http_put_response_hop_limit: u8,
    instance_metadata_tags: String
});
properties!(RootBlockDevice {
    encrypted: bool,
    delete_on_termination: bool,
    volume_size: u32,
    volume_type: String,
    tags: Tags
});
properties!(VolumeAttachment {
    device_name: String,
    instance_id: String,
    volume_id: String,
    force_detach: bool,
    stop_instance_before_detaching: bool
});

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FoundationOutputs {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nodes: BTreeMap<String, crate::cluster_infra::ClusterNodeOutputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightwallet: Option<crate::cluster_infra::ClusterLightwalletOutputs>,
    pub schema_version: u32,
    pub scope: Scope,
    pub network_id: Uuid,
    pub availability_zone: String,
    pub vpc_id: String,
    pub private_subnet_id: String,
    pub instance_id: String,
    pub private_ip: Ipv4Addr,
    pub chain_volume_id: String,
    pub retain_chain_disk: bool,
    pub security_group_id: String,
    pub nat_gateway_id: String,
    pub eip_allocation_id: String,
}
impl FoundationOutputs {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "infra.foundation_outputs.validate_for")
    )]
    pub fn validate_for(&self, spec: &FoundationSpec) -> Result<()> {
        spec.validate()?;
        ensure!(
            self.schema_version == FOUNDATION_SCHEMA_VERSION,
            "unsupported foundation output schema"
        );
        ensure!(
            self.scope == spec.scope && self.network_id == spec.network_id,
            "foundation outputs belong to another deployment scope"
        );
        ensure!(
            self.availability_zone == spec.availability_zone,
            "foundation output availability zone changed"
        );
        ensure!(
            self.retain_chain_disk == spec.retain_chain_disk,
            "foundation output retention differs from request"
        );
        for (value, prefix) in [
            (&self.vpc_id, "vpc-"),
            (&self.private_subnet_id, "subnet-"),
            (&self.instance_id, "i-"),
            (&self.chain_volume_id, "vol-"),
            (&self.security_group_id, "sg-"),
            (&self.nat_gateway_id, "nat-"),
            (&self.eip_allocation_id, "eipalloc-"),
        ] {
            validate_aws_id(value, prefix)?;
        }
        let ip = self.private_ip.octets();
        ensure!(
            ip[..3] == [10, 90, 1] && (4..255).contains(&ip[3]),
            "foundation host IP is outside the private subnet"
        );
        if !self.nodes.is_empty() {
            let topology =
                crate::cluster_infra::ClusterTopology::new(self.nodes.len().try_into()?)?;
            crate::cluster_infra::validate_node_outputs(&self.nodes, &topology)?;
            let first = &self.nodes["node-1"];
            ensure!(
                first.instance_id == self.instance_id
                    && first.private_ip == self.private_ip
                    && first.volume_id == self.chain_volume_id,
                "first node outputs differ from primary host outputs"
            );
            if let Some(lightwallet) = &self.lightwallet {
                crate::cluster_infra::validate_lightwallet_outputs(
                    lightwallet,
                    &topology,
                    &self.nodes,
                )?;
            }
        } else {
            ensure!(
                self.lightwallet.is_none(),
                "lightwallet outputs require a private node topology"
            );
        }
        Ok(())
    }
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "infra.parse_outputs")
)]
pub fn parse_outputs(bytes: &[u8], spec: &FoundationSpec) -> Result<FoundationOutputs> {
    ensure!(
        bytes.len() <= 1024 * 1024,
        "foundation outputs exceed 1 MiB"
    );
    let outputs: FoundationOutputs =
        serde_json::from_slice(bytes).context("invalid or incomplete foundation outputs")?;
    outputs.validate_for(spec)?;
    Ok(outputs)
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "infra.validate_aws_id")
)]
pub fn validate_aws_id(value: &str, prefix: &str) -> Result<()> {
    let suffix = value
        .strip_prefix(prefix)
        .with_context(|| format!("expected {prefix} AWS identifier"))?;
    ensure!(
        [8, 17].contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid {prefix} AWS identifier"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub mem_total_bytes: u64,
    /// Finite limits from every cgroup ancestor; omit unlimited values.
    pub ancestor_memory_limits_bytes: Vec<u64>,
    pub online_cpu_count: u32,
    pub affinity_cpu_count: u32,
    /// Finite CPU quota/period ratios from every cgroup ancestor, in milli-CPUs.
    pub ancestor_cpu_quota_millis: Vec<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveLimits {
    pub effective_memory_bytes: u64,
    pub host_reserve_bytes: u64,
    pub fixture_memory_bytes: u64,
    pub application_memory_bytes: u64,
    pub visible_cpu_millis: u32,
    pub application_cpu_millis: u32,
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "infra.effective_limits")
)]
pub fn effective_limits(size: Size, host: &HostObservation) -> Result<EffectiveLimits> {
    let allocation = size.allocation();
    let memory = host
        .ancestor_memory_limits_bytes
        .iter()
        .copied()
        .fold(host.mem_total_bytes, u64::min);
    let reserve = u64::from(allocation.host_reserve_gib) * GIB;
    let application = memory
        .checked_sub(reserve)
        .and_then(|n| n.checked_sub(FIXTURE_MEMORY_BYTES))
        .context("effective host memory cannot fit the host reserve and test service")?
        .min(u64::from(allocation.max_node_gib) * GIB - FIXTURE_MEMORY_BYTES);
    ensure!(
        application > 0,
        "no application memory remains after reservations"
    );
    let cpus = host
        .online_cpu_count
        .min(host.affinity_cpu_count)
        .min(allocation.vcpus)
        .checked_mul(1000)
        .context("CPU count overflow")?;
    let visible = host
        .ancestor_cpu_quota_millis
        .iter()
        .copied()
        .fold(cpus, u32::min);
    let application_cpu = visible
        .checked_sub(HOST_CPU_RESERVE_MILLIS + FIXTURE_CPU_MILLIS)
        .context("effective CPU cannot fit the host reserve and test service")?;
    ensure!(
        application_cpu > 0,
        "no application CPU remains after reservations"
    );
    Ok(EffectiveLimits {
        effective_memory_bytes: memory,
        host_reserve_bytes: reserve,
        fixture_memory_bytes: FIXTURE_MEMORY_BYTES,
        application_memory_bytes: application,
        visible_cpu_millis: visible,
        application_cpu_millis: application_cpu,
    })
}

const HOST_SETUP: &str = r#"#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/zdn-foundation-setup.log) 2>&1
# Only a pinned Amazon Linux 2023 x86-64 AMI is supported.
test "$(uname -m)" = x86_64
. /etc/os-release
test "$ID" = amzn
test "$VERSION_ID" = 2023
dnf install -y docker awscli-2 amazon-ssm-agent e2fsprogs util-linux
systemctl enable --now docker amazon-ssm-agent
install -d -m 0755 /opt/zdn /var/lib/zdn /var/lib/zdn-chain
cat >/opt/zdn/prepare-chain.sh <<'SH'
#!/bin/bash
set -euo pipefail
volume='${chainDisk.id}'
serial=$(printf '%s' "$volume" | tr -d '-')
device="/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$serial"
for attempt in $(seq 1 180); do
  test -b "$device" && break
  sleep 2
done
test -b "$device"
# Format only a blank owned volume. Unknown existing filesystems are an error.
if ! blkid "$device"; then
  test -z "$(wipefs --noheadings --output TYPE "$device")"
  mkfs.ext4 "$device"
fi
test "$(blkid -s TYPE -o value "$device")" = ext4
uuid=$(blkid -s UUID -o value "$device")
if ! grep -q "UUID=$uuid " /etc/fstab; then
  printf 'UUID=%s /var/lib/zdn-chain ext4 defaults,nofail 0 2\n' "$uuid" >>/etc/fstab
fi
mountpoint -q /var/lib/zdn-chain || mount /var/lib/zdn-chain
SH
chmod 0755 /opt/zdn/prepare-chain.sh
cat >/etc/systemd/system/zdn-chain.service <<'UNIT'
[Unit]
Description=Attach the zdn foundation data filesystem
After=local-fs.target
Before=zdn-foundation.service
[Service]
Type=oneshot
ExecStart=/opt/zdn/prepare-chain.sh
RemainAfterExit=yes
TimeoutStartSec=420
[Install]
WantedBy=multi-user.target
UNIT
"#;
