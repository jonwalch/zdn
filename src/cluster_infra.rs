//! Private one-to-three-node topology derived from the constrained foundation.
//!
//! This only renders resources. The deployment lifecycle must reject conversion
//! of an existing foundation host and must gate apply with an approved preview.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    config::Size,
    infra::{Definition, FoundationSpec, HostObservation, PulumiProgram, SecurityRule, GIB},
};

pub const P2P_PORT: u16 = 18233;
pub const MAX_NODES: u8 = 3;
pub const PRODUCER_NODE_ID: &str = "node-1";
pub const LIGHTWALLET_CACHE_DISK: &str = "lightwalletCacheDisk";
pub const LIGHTWALLET_CACHE_ATTACHMENT: &str = "lightwalletCacheAttachment";
pub const LIGHTWALLET_CACHE_DEVICE: &str = "/dev/sdg";

/// Initial bounded service allocations, not qualified capacity recommendations.
/// Save this value in the immutable deployment request before creating hosts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletAllocation {
    pub cache_gib: u32,
    pub service_memory_bytes: u64,
    pub service_cpu_millis: u32,
    pub node_memory_bytes: u64,
    pub node_cpu_millis: u32,
    pub host_reserve_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletLimits {
    pub effective_memory_bytes: u64,
    pub visible_cpu_millis: u32,
    pub node_memory_bytes: u64,
    pub node_cpu_millis: u32,
}

impl LightwalletAllocation {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cluster_infra.lightwallet_allocation.for_size")
    )]
    pub fn for_size(size: Size) -> Self {
        let allocation = size.allocation();
        let (cache_gib, service_memory_bytes, service_cpu_millis) = match size {
            Size::Small => (20, GIB / 2, 250),
            Size::Medium => (40, GIB, 500),
            Size::Large => (80, 2 * GIB, 1000),
        };
        Self {
            cache_gib,
            service_memory_bytes,
            service_cpu_millis,
            node_memory_bytes: u64::from(allocation.max_node_gib) * GIB - service_memory_bytes,
            node_cpu_millis: allocation.vcpus * 1000
                - crate::infra::HOST_CPU_RESERVE_MILLIS
                - service_cpu_millis,
            host_reserve_bytes: u64::from(allocation.host_reserve_gib) * GIB,
        }
    }

    pub fn validate_for(&self, size: Size) -> Result<()> {
        ensure!(
            *self == Self::for_size(size),
            "lightwallet allocation differs from the selected preset"
        );
        Ok(())
    }

    /// Derive limits from the smallest observed ancestor constraints. The caller
    /// must pin these limits before rendering the host install specification.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(
            skip_all,
            name = "cluster_infra.lightwallet_allocation.effective_limits"
        )
    )]
    pub fn effective_limits(
        &self,
        size: Size,
        host: &HostObservation,
    ) -> Result<LightwalletLimits> {
        self.validate_for(size)?;
        let allocation = size.allocation();
        let effective_memory_bytes = host
            .ancestor_memory_limits_bytes
            .iter()
            .copied()
            .fold(host.mem_total_bytes, u64::min)
            .min(u64::from(allocation.host_gib) * GIB);
        let node_memory_bytes = effective_memory_bytes
            .checked_sub(self.host_reserve_bytes)
            .and_then(|n| n.checked_sub(self.service_memory_bytes))
            .context("effective memory cannot fit host and lightwallet reserves")?
            .min(self.node_memory_bytes);
        ensure!(
            node_memory_bytes >= GIB,
            "effective memory cannot fit the minimum node allocation"
        );
        let visible_cpu_millis = host
            .online_cpu_count
            .min(host.affinity_cpu_count)
            .min(allocation.vcpus)
            .checked_mul(1000)
            .context("host CPU observation overflow")?;
        let visible_cpu_millis = host
            .ancestor_cpu_quota_millis
            .iter()
            .copied()
            .fold(visible_cpu_millis, u32::min);
        let node_cpu_millis = visible_cpu_millis
            .checked_sub(crate::infra::HOST_CPU_RESERVE_MILLIS)
            .and_then(|n| n.checked_sub(self.service_cpu_millis))
            .context("effective CPU cannot fit host and lightwallet reserves")?
            .min(self.node_cpu_millis);
        ensure!(
            node_cpu_millis >= 250,
            "effective CPU cannot fit the minimum node allocation"
        );
        Ok(LightwalletLimits {
            effective_memory_bytes,
            visible_cpu_millis,
            node_memory_bytes,
            node_cpu_millis,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterTopology {
    node_count: u8,
}

/// Stable identities are independent of provider-assigned instance IDs.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterNode {
    pub node_id: String,
    pub private_ip: Ipv4Addr,
    pub host_key: String,
    pub volume_key: String,
    pub attachment_key: String,
    pub producer: bool,
}

impl ClusterTopology {
    pub fn new(node_count: u8) -> Result<Self> {
        ensure!(
            (1..=MAX_NODES).contains(&node_count),
            "the private topology requires between 1 and {MAX_NODES} nodes"
        );
        Ok(Self { node_count })
    }

    pub fn node_count(&self) -> u8 {
        self.node_count
    }

    /// Keep indexing away from the producer when another host is available.
    pub fn lightwallet_node(&self) -> ClusterNode {
        self.nodes().remove(usize::from(self.node_count > 1))
    }

    /// Add a separate retained cache disk without changing chain disk identities
    /// or opening an inbound service port. Initialization happens through SSM.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cluster_infra.topology.render_with_lightwallet")
    )]
    pub fn render_with_lightwallet(
        &self,
        base: PulumiProgram,
        spec: &FoundationSpec,
        user_data: &BTreeMap<String, String>,
        cache_gib: u32,
    ) -> Result<PulumiProgram> {
        ensure!(
            (1..=2048).contains(&cache_gib),
            "lightwallet cache must be 1 to 2048 GiB"
        );
        let mut program = self.render(base, spec, user_data)?;
        ensure!(
            !program.resources.contains_key(LIGHTWALLET_CACHE_DISK)
                && !program.resources.contains_key(LIGHTWALLET_CACHE_ATTACHMENT)
                && !program.outputs.contains_key("lightwallet"),
            "lightwallet resources are already present"
        );
        let node = self.lightwallet_node();
        let mut disk = program.resources[&node.volume_key].clone();
        disk.name = spec.resource_name(LIGHTWALLET_CACHE_DISK);
        let Definition::Volume(volume) = &mut disk.definition else {
            unreachable!("validated chain volume")
        };
        volume.size = cache_gib;
        volume.tags.insert("Name".into(), disk.name.clone());
        volume
            .tags
            .insert("zdn:service".into(), "lightwalletd".into());
        let mut attachment = program.resources[&node.attachment_key].clone();
        attachment.name = spec.resource_name(LIGHTWALLET_CACHE_ATTACHMENT);
        let Definition::VolumeAttachment(properties) = &mut attachment.definition else {
            unreachable!("validated chain attachment")
        };
        properties.device_name = LIGHTWALLET_CACHE_DEVICE.into();
        properties.volume_id = reference(&format!("{LIGHTWALLET_CACHE_DISK}.id"));
        program
            .resources
            .insert(LIGHTWALLET_CACHE_DISK.into(), disk);
        program
            .resources
            .insert(LIGHTWALLET_CACHE_ATTACHMENT.into(), attachment);
        program.outputs.insert(
            "lightwallet".into(),
            json!({
                "node_id": node.node_id,
                "instance_id": reference(&format!("{}.id", node.host_key)),
                "cache_volume_id": reference(&format!("{LIGHTWALLET_CACHE_DISK}.id")),
                "cache_size_gib": cache_gib,
            }),
        );
        program.validate_references()?;
        Ok(program)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cluster_infra.topology.nodes")
    )]
    pub fn nodes(&self) -> Vec<ClusterNode> {
        (1..=self.node_count)
            .map(|index| {
                let suffix = if index == 1 {
                    String::new()
                } else {
                    index.to_string()
                };
                ClusterNode {
                    node_id: format!("node-{index}"),
                    private_ip: Ipv4Addr::new(10, 90, 1, 9 + index),
                    host_key: format!("host{suffix}"),
                    volume_key: format!("chainDisk{suffix}"),
                    attachment_key: format!("chainAttachment{suffix}"),
                    producer: index == 1,
                }
            })
            .collect()
    }

    /// Each node connects only to the other members of this private topology.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cluster_infra.topology.peers")
    )]
    pub fn peers(&self, node_id: &str) -> Result<Vec<String>> {
        let nodes = self.nodes();
        ensure!(
            nodes.iter().any(|node| node.node_id == node_id),
            "unknown topology node {node_id}"
        );
        Ok(nodes
            .into_iter()
            .filter(|node| node.node_id != node_id)
            .map(|node| format!("{}:{P2P_PORT}", node.private_ip))
            .collect())
    }

    /// `base` must be the team-constrained `Deployment::render()` result.
    /// User data installs host prerequisites; node installation follows through
    /// SSM after volume attachment. The renderer never creates credentials.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cluster_infra.topology.render")
    )]
    pub fn render(
        &self,
        mut base: PulumiProgram,
        spec: &FoundationSpec,
        user_data: &BTreeMap<String, String>,
    ) -> Result<PulumiProgram> {
        validate_base(&base, spec)?;
        let nodes = self.nodes();
        ensure!(
            user_data.keys().eq(nodes.iter().map(|node| &node.node_id)),
            "host setup scripts must name exactly the topology's nodes"
        );
        for script in user_data.values() {
            ensure!(
                script.starts_with("#!/bin/bash\n")
                    && !script.contains('\0')
                    && script.len() <= 16 * 1024,
                "host setup must be a Bash script of at most 16 KiB"
            );
        }

        // Clone the constrained host and disk: bootstrap ownership, IAM path,
        // provider/default tags, boundary and protected-tag options stay intact.
        let host_template = base.resources["host"].clone();
        let disk_template = base.resources["chainDisk"].clone();
        let attachment_template = base.resources["chainAttachment"].clone();
        let mut outputs = BTreeMap::new();
        for node in &nodes {
            if !node.producer {
                for key in [&node.host_key, &node.volume_key, &node.attachment_key] {
                    ensure!(
                        !base.resources.contains_key(key),
                        "private topology would overwrite resource {key}"
                    );
                }
            }
            let mut host = host_template.clone();
            host.name = spec.resource_name(&node.host_key);
            let Definition::Instance(instance) = &mut host.definition else {
                unreachable!("validated host")
            };
            instance.private_ip = Some(node.private_ip);
            instance.user_data.clone_from(&user_data[&node.node_id]);
            tag_node(&mut instance.tags, &host.name, &node.node_id);
            tag_node(
                &mut instance.root_block_device.tags,
                &spec.resource_name(&format!("{}-root-disk", node.node_id)),
                &node.node_id,
            );

            let mut disk = disk_template.clone();
            disk.name = spec.resource_name(&node.volume_key);
            disk.options.retain_on_delete = true;
            let Definition::Volume(volume) = &mut disk.definition else {
                unreachable!("validated chain disk")
            };
            tag_node(&mut volume.tags, &disk.name, &node.node_id);

            let mut attachment = attachment_template.clone();
            attachment.name = spec.resource_name(&node.attachment_key);
            let Definition::VolumeAttachment(properties) = &mut attachment.definition else {
                unreachable!("validated attachment")
            };
            properties.instance_id = reference(&format!("{}.id", node.host_key));
            properties.volume_id = reference(&format!("{}.id", node.volume_key));

            base.resources.insert(node.host_key.clone(), host);
            base.resources.insert(node.volume_key.clone(), disk);
            base.resources
                .insert(node.attachment_key.clone(), attachment);
            outputs.insert(
                node.node_id.clone(),
                json!({
                    "node_id": node.node_id,
                    "instance_id": reference(&format!("{}.id", node.host_key)),
                    "private_ip": reference(&format!("{}.privateIp", node.host_key)),
                    "volume_id": reference(&format!("{}.id", node.volume_key)),
                }),
            );
        }

        let group = base.resources.get_mut("hostSecurityGroup").unwrap();
        let Definition::SecurityGroup(group) = &mut group.definition else {
            unreachable!("validated host security group")
        };
        let private_peers = SecurityRule {
            protocol: "tcp".into(),
            from_port: P2P_PORT,
            to_port: P2P_PORT,
            cidr_blocks: nodes
                .iter()
                .map(|node| format!("{}/32", node.private_ip))
                .collect(),
            description: "Zakura P2P between the private devnet nodes".into(),
        };
        group.description = "Private Zakura hosts; internal P2P and outbound HTTPS".into();
        group.ingress = vec![private_peers.clone()];
        group.egress = vec![
            SecurityRule {
                protocol: "tcp".into(),
                from_port: 443,
                to_port: 443,
                cidr_blocks: vec!["0.0.0.0/0".into()],
                description: "HTTPS for SSM, AWS APIs and distribution packages".into(),
            },
            private_peers,
        ];
        base.outputs
            .insert("nodes".into(), serde_json::to_value(outputs)?);
        base.validate_references()?;
        Ok(base)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cluster_infra.validate_base")
)]
fn validate_base(base: &PulumiProgram, spec: &FoundationSpec) -> Result<()> {
    spec.validate()?;
    base.validate_references()?;
    ensure!(
        spec.retain_chain_disk,
        "private node data disks must be retained"
    );
    ensure!(
        base.outputs.get("scope") == Some(&serde_json::to_value(&spec.scope)?)
            && base.outputs.get("network_id") == Some(&json!(spec.network_id)),
        "foundation program belongs to another deployment"
    );
    ensure!(
        !base.outputs.contains_key("nodes"),
        "private topology must be rendered from the unexpanded foundation"
    );
    for (kind, count) in [
        (
            "host",
            base.resources
                .values()
                .filter(|r| matches!(r.definition, Definition::Instance(_)))
                .count(),
        ),
        (
            "chain disk",
            base.resources
                .values()
                .filter(|r| matches!(r.definition, Definition::Volume(_)))
                .count(),
        ),
        (
            "disk attachment",
            base.resources
                .values()
                .filter(|r| matches!(r.definition, Definition::VolumeAttachment(_)))
                .count(),
        ),
    ] {
        ensure!(count == 1, "foundation must contain exactly one {kind}");
    }
    let Definition::Subnet(subnet) = &base
        .resources
        .get("privateSubnet")
        .context("missing private subnet")?
        .definition
    else {
        eyre::bail!("invalid private subnet resource")
    };
    ensure!(
        subnet.cidr_block == "10.90.1.0/24"
            && subnet.availability_zone == spec.availability_zone
            && !subnet.map_public_ip_on_launch,
        "private subnet differs from the supported topology"
    );
    let Definition::Instance(host) = &base
        .resources
        .get("host")
        .context("missing foundation host")?
        .definition
    else {
        eyre::bail!("invalid foundation host resource")
    };
    let allocation = spec.size.allocation();
    ensure!(
        host.ami == spec.ami_id
            && host.availability_zone == spec.availability_zone
            && host.instance_type == allocation.instance
            && host.root_block_device.volume_size == allocation.root_disk_gib
            && host.root_block_device.encrypted
            && host.root_block_device.delete_on_termination
            && host.subnet_id == reference("privateSubnet.id")
            && host.vpc_security_group_ids == [reference("hostSecurityGroup.id")]
            && host.iam_instance_profile == reference("hostProfile.name")
            && !host.associate_public_ip_address
            && host.private_ip.is_none()
            && host.metadata_options.http_tokens == "required"
            && host.metadata_options.http_put_response_hop_limit == 1,
        "foundation host differs from the supported private allocation"
    );
    let disk = base
        .resources
        .get("chainDisk")
        .context("missing chain disk")?;
    let Definition::Volume(volume) = &disk.definition else {
        eyre::bail!("invalid chain disk resource")
    };
    ensure!(
        disk.options.retain_on_delete
            && volume.encrypted
            && volume.volume_type == "gp3"
            && volume.size == allocation.chain_disk_gib
            && volume.availability_zone == spec.availability_zone,
        "foundation disk differs from the supported retained allocation"
    );
    let Definition::VolumeAttachment(attachment) = &base
        .resources
        .get("chainAttachment")
        .context("missing chain attachment")?
        .definition
    else {
        eyre::bail!("invalid chain attachment resource")
    };
    ensure!(
        attachment.instance_id == reference("host.id")
            && attachment.volume_id == reference("chainDisk.id")
            && attachment.device_name == "/dev/sdf"
            && !attachment.force_detach
            && attachment.stop_instance_before_detaching,
        "foundation attachment differs from the supported topology"
    );
    ensure!(
        matches!(
            base.resources
                .get("hostSecurityGroup")
                .map(|r| &r.definition),
            Some(Definition::SecurityGroup(_))
        ),
        "missing host security group"
    );
    Ok(())
}

fn reference(target: &str) -> String {
    format!("${{{target}}}")
}

fn tag_node(tags: &mut BTreeMap<String, String>, name: &str, node_id: &str) {
    tags.insert("Name".into(), name.into());
    tags.insert("zdn:node-id".into(), node_id.into());
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterNodeOutputs {
    pub node_id: String,
    pub instance_id: String,
    pub private_ip: Ipv4Addr,
    pub volume_id: String,
}

/// A dedicated cache disk follows data retention: destroy retains it, and the
/// controller may delete it only through the explicit owned-data cleanup path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterLightwalletOutputs {
    pub node_id: String,
    pub instance_id: String,
    pub cache_volume_id: String,
    pub cache_size_gib: u32,
}

pub fn parse_lightwallet_outputs(
    value: &Value,
    topology: &ClusterTopology,
    nodes: &BTreeMap<String, ClusterNodeOutputs>,
) -> Result<ClusterLightwalletOutputs> {
    let outputs =
        serde_json::from_value(value.clone()).context("invalid lightwallet cache outputs")?;
    validate_lightwallet_outputs(&outputs, topology, nodes)?;
    Ok(outputs)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cluster_infra.validate_lightwallet_outputs")
)]
pub fn validate_lightwallet_outputs(
    outputs: &ClusterLightwalletOutputs,
    topology: &ClusterTopology,
    nodes: &BTreeMap<String, ClusterNodeOutputs>,
) -> Result<()> {
    validate_node_outputs(nodes, topology)?;
    let selected = topology.lightwallet_node();
    ensure!(
        outputs.node_id == selected.node_id
            && outputs.instance_id == nodes[&selected.node_id].instance_id,
        "lightwallet outputs differ from the selected host"
    );
    validate_aws_id(&outputs.cache_volume_id, "vol-")?;
    ensure!(
        nodes
            .values()
            .all(|node| node.volume_id != outputs.cache_volume_id),
        "lightwallet cache must not reuse a node chain volume"
    );
    ensure!(
        (1..=2048).contains(&outputs.cache_size_gib),
        "lightwallet cache output size is out of bounds"
    );
    Ok(())
}

/// Validate the `nodes` field of observed stack outputs. This proves shape and
/// consistency only; AWS ownership and current instance state need live checks.
pub fn parse_node_outputs(
    value: &Value,
    topology: &ClusterTopology,
) -> Result<BTreeMap<String, ClusterNodeOutputs>> {
    let nodes: BTreeMap<String, ClusterNodeOutputs> =
        serde_json::from_value(value.clone()).context("invalid private node outputs")?;
    validate_node_outputs(&nodes, topology)?;
    Ok(nodes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cluster_infra.validate_node_outputs")
)]
pub fn validate_node_outputs(
    outputs: &BTreeMap<String, ClusterNodeOutputs>,
    topology: &ClusterTopology,
) -> Result<()> {
    let expected = topology.nodes();
    ensure!(
        outputs.keys().eq(expected.iter().map(|node| &node.node_id)),
        "private node outputs do not match the requested node set"
    );
    let mut instances = BTreeSet::new();
    let mut volumes = BTreeSet::new();
    for node in expected {
        let actual = &outputs[&node.node_id];
        ensure!(
            actual.node_id == node.node_id && actual.private_ip == node.private_ip,
            "private node output identity changed for {}",
            node.node_id
        );
        validate_aws_id(&actual.instance_id, "i-")?;
        validate_aws_id(&actual.volume_id, "vol-")?;
        ensure!(
            instances.insert(&actual.instance_id) && volumes.insert(&actual.volume_id),
            "private node outputs reuse an instance or volume"
        );
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cluster_infra.validate_aws_id")
)]
fn validate_aws_id(value: &str, prefix: &str) -> Result<()> {
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
