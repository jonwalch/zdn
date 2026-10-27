use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    access::{DeploymentAccess, TEAM_ROLE_API_VERSION},
    aws::{TeamAws, TeamDefinition, TeamState},
    cluster_infra::{parse_node_outputs, ClusterTopology, P2P_PORT},
    config::Size,
    foundation::Deployment,
    infra::{Definition, FoundationSpec, PulumiProgram},
    state::Scope,
};

fn deployment() -> Deployment {
    let scope = Scope {
        team_id: "private-team".into(),
        account_id: "123456789012".into(),
        region: "us-east-1".into(),
    };
    let mut team = TeamDefinition {
        api_version: TEAM_ROLE_API_VERSION.into(),
        team_id: scope.team_id.clone(),
        revision: 1,
        bootstrap_id: Uuid::parse_str("965f7c13-e186-4d52-b7e3-ef92db98a0ec").unwrap(),
        aws: TeamAws {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
        },
        state: TeamState {
            backend: "s3://zdn-private-team/pulumi/private-team".into(),
            kms_key_arn:
                "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001".into(),
        },
        deployment: None,
    };
    team.deployment = Some(DeploymentAccess::managed(&team));
    Deployment::new(
        FoundationSpec {
            scope,
            network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        },
        team,
    )
    .unwrap()
}

fn scripts(topology: &ClusterTopology) -> BTreeMap<String, String> {
    topology
        .nodes()
        .into_iter()
        .map(|node| {
            let script = format!("#!/bin/bash\nset -euo pipefail\n# {}\n", node.node_id);
            (node.node_id, script)
        })
        .collect()
}

fn render(deployment: &Deployment, count: u8) -> PulumiProgram {
    let topology = ClusterTopology::new(count).unwrap();
    topology
        .render(
            deployment.render().unwrap(),
            &deployment.spec,
            &scripts(&topology),
        )
        .unwrap()
}

#[test]
fn topology_bounds_and_peer_membership_are_explicit() {
    assert!(ClusterTopology::new(0).is_err());
    assert!(ClusterTopology::new(4).is_err());
    assert!(ClusterTopology::new(u8::MAX).is_err());
    let topology = ClusterTopology::new(3).unwrap();
    assert_eq!(topology.node_count(), 3);
    let nodes = topology.nodes();
    assert_eq!(nodes[0].node_id, "node-1");
    assert_eq!(nodes[0].private_ip.to_string(), "10.90.1.10");
    assert_eq!(nodes[0].host_key, "host");
    assert_eq!(nodes[0].volume_key, "chainDisk");
    assert_eq!(nodes[0].attachment_key, "chainAttachment");
    assert!(nodes[0].producer);
    assert_eq!(nodes[2].host_key, "host3");
    assert_eq!(nodes[2].private_ip.to_string(), "10.90.1.12");
    assert!(!nodes[1].producer);
    assert!(!nodes[2].producer);
    assert_eq!(
        topology.peers("node-2").unwrap(),
        ["10.90.1.10:18233", "10.90.1.12:18233"]
    );
    assert!(topology.peers("node-4").is_err());
    assert!(ClusterTopology::new(1)
        .unwrap()
        .peers("node-1")
        .unwrap()
        .is_empty());
}

#[test]
fn three_hosts_have_independent_retained_disks_and_a_shared_network() {
    let deployment = deployment();
    let value = serde_json::to_value(render(&deployment, 3)).unwrap();
    let resources = value["resources"].as_object().unwrap();
    for (kind, expected) in [
        ("aws:ec2:Instance", 3),
        ("aws:ebs:Volume", 3),
        ("aws:ec2:VolumeAttachment", 3),
        ("aws:ec2:Vpc", 1),
        ("aws:ec2:Subnet", 2),
        ("aws:ec2:NatGateway", 1),
        ("aws:iam:Role", 1),
    ] {
        assert_eq!(
            resources.values().filter(|r| r["type"] == kind).count(),
            expected
        );
    }
    for node in ClusterTopology::new(3).unwrap().nodes() {
        let host = &resources[&node.host_key]["properties"];
        assert_eq!(host["privateIp"], node.private_ip.to_string());
        assert_eq!(host["associatePublicIpAddress"], false);
        assert_eq!(host["subnetId"], "${privateSubnet.id}");
        assert_eq!(
            host["vpcSecurityGroupIds"],
            json!(["${hostSecurityGroup.id}"])
        );
        assert!(host.get("keyName").is_none());
        assert_eq!(host["metadataOptions"]["httpTokens"], "required");
        assert_eq!(host["metadataOptions"]["httpPutResponseHopLimit"], 1);
        assert_eq!(host["rootBlockDevice"]["encrypted"], true);
        assert_eq!(host["rootBlockDevice"]["deleteOnTermination"], true);
        let disk = &resources[&node.volume_key];
        assert_eq!(disk["properties"]["encrypted"], true);
        assert_eq!(disk["options"]["retainOnDelete"], true);
        assert_eq!(disk["properties"]["tags"]["zdn:node-id"], node.node_id);
        assert_eq!(disk["properties"]["tags"]["Name"], disk["name"]);
        let attachment = &resources[&node.attachment_key]["properties"];
        assert_eq!(
            attachment["instanceId"],
            format!("${{{}.id}}", node.host_key)
        );
        assert_eq!(
            attachment["volumeId"],
            format!("${{{}.id}}", node.volume_key)
        );
        assert_eq!(attachment["forceDetach"], false);
        assert_eq!(attachment["stopInstanceBeforeDetaching"], true);
        assert_eq!(
            value["outputs"]["nodes"][&node.node_id]["instance_id"],
            attachment["instanceId"]
        );
    }
    // Foundation status/teardown still have the first node's original keys.
    assert_eq!(value["outputs"]["instance_id"], "${host.id}");
    assert_eq!(value["outputs"]["chain_volume_id"], "${chainDisk.id}");
    assert_eq!(value["outputs"]["private_ip"], "${host.privateIp}");
}

#[test]
fn firewall_allows_only_membership_p2p_and_outbound_https() {
    for count in 1..=3 {
        let value = serde_json::to_value(render(&deployment(), count)).unwrap();
        let rules = &value["resources"]["hostSecurityGroup"]["properties"];
        let ingress = rules["ingress"].as_array().unwrap();
        let egress = rules["egress"].as_array().unwrap();
        let members: Vec<_> = (0..count)
            .map(|n| format!("10.90.1.{}/32", 10 + n))
            .collect();
        assert_eq!(ingress.len(), 1);
        assert_eq!(ingress[0]["protocol"], "tcp");
        assert_eq!(ingress[0]["fromPort"], P2P_PORT);
        assert_eq!(ingress[0]["toPort"], P2P_PORT);
        assert_eq!(ingress[0]["cidrBlocks"], json!(members));
        assert_eq!(egress.len(), 2);
        assert_eq!(egress[0]["protocol"], "tcp");
        assert_eq!(egress[0]["fromPort"], 443);
        assert_eq!(egress[0]["toPort"], 443);
        assert_eq!(egress[0]["cidrBlocks"], json!(["0.0.0.0/0"]));
        assert_eq!(egress[1], ingress[0]);
        assert_eq!(
            value["resources"]["privateSubnet"]["properties"]["mapPublicIpOnLaunch"],
            false
        );
    }
}

#[test]
fn constrained_iam_and_protected_root_volume_tags_survive_expansion() {
    let deployment = deployment();
    let base = serde_json::to_value(deployment.render().unwrap()).unwrap();
    let cluster = serde_json::to_value(render(&deployment, 3)).unwrap();
    for key in ["provider", "hostRole", "hostProfile", "hostSsmPolicy"] {
        assert_eq!(cluster["resources"][key], base["resources"][key]);
    }
    for key in ["host", "host2", "host3"] {
        assert_eq!(
            cluster["resources"][key]["options"],
            base["resources"]["host"]["options"]
        );
        let host = &cluster["resources"][key]["properties"];
        for tag in ["zdn:bootstrap", "zdn:team-id", "zdn:managed-by"] {
            assert_eq!(
                host["tags"][tag],
                base["resources"]["host"]["properties"]["tags"][tag]
            );
            assert!(host["rootBlockDevice"]["tags"].get(tag).is_none());
        }
    }
    assert!(cluster["resources"].get("defaultSecurityGroup").is_none());
}

#[test]
fn every_node_uses_the_requested_instance_and_disk_budget() {
    for size in [Size::Small, Size::Medium, Size::Large] {
        let mut deployment = deployment();
        deployment.spec.size = size;
        let allocation = size.allocation();
        let value = serde_json::to_value(render(&deployment, 3)).unwrap();
        for node in ClusterTopology::new(3).unwrap().nodes() {
            let host = &value["resources"][node.host_key]["properties"];
            let disk = &value["resources"][node.volume_key]["properties"];
            assert_eq!(host["instanceType"], allocation.instance);
            assert_eq!(
                host["rootBlockDevice"]["volumeSize"],
                allocation.root_disk_gib
            );
            assert_eq!(disk["size"], allocation.chain_disk_gib);
            assert_eq!(disk["iops"], 3000);
            assert_eq!(disk["throughput"], 125);
        }
    }
}

#[test]
fn each_host_uses_only_its_explicit_setup_script() {
    let topology = ClusterTopology::new(3).unwrap();
    let data = scripts(&topology);
    let value = serde_json::to_value(render(&deployment(), 3)).unwrap();
    for node in topology.nodes() {
        let host = &value["resources"][node.host_key]["properties"];
        assert_eq!(host["userData"], data[&node.node_id]);
        assert!(!host["userData"]
            .as_str()
            .unwrap()
            .contains("zdn-foundation"));
        assert_eq!(host["userDataReplaceOnChange"], true);
    }
}

#[test]
fn scripts_require_exact_node_set_and_ec2_size_bounds() {
    let deployment = deployment();
    let topology = ClusterTopology::new(3).unwrap();
    let try_scripts = |scripts: &BTreeMap<String, String>| {
        topology.render(deployment.render().unwrap(), &deployment.spec, scripts)
    };
    let mut data = scripts(&topology);
    data.remove("node-3");
    assert!(try_scripts(&data).is_err());
    data = scripts(&topology);
    data.insert("node-4".into(), "#!/bin/bash\n".into());
    assert!(try_scripts(&data).is_err());
    for invalid in [
        "#!/bin/sh\n".to_owned(),
        "#!/bin/bash\n\0".to_owned(),
        format!("#!/bin/bash\n{}", "x".repeat(16 * 1024)),
    ] {
        data = scripts(&topology);
        data.insert("node-2".into(), invalid);
        assert!(try_scripts(&data).is_err());
    }
}

#[test]
fn renderer_rejects_foreign_scope_and_unsafe_or_expanded_foundations() {
    let deployment = deployment();
    let topology = ClusterTopology::new(3).unwrap();
    let original = serde_json::to_value(deployment.render().unwrap()).unwrap();
    for (pointer, value) in [
        ("/outputs/network_id", json!(Uuid::new_v4())),
        ("/outputs/scope/team_id", json!("someone-else")),
        (
            "/resources/privateSubnet/properties/cidrBlock",
            json!("10.90.2.0/24"),
        ),
        (
            "/resources/host/properties/associatePublicIpAddress",
            json!(true),
        ),
        (
            "/resources/host/properties/instanceType",
            json!("m7a.large"),
        ),
        ("/resources/chainDisk/options/retainOnDelete", json!(false)),
        ("/resources/chainDisk/properties/encrypted", json!(false)),
        (
            "/resources/chainAttachment/properties/forceDetach",
            json!(true),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let base = serde_json::from_value(changed).unwrap();
        assert!(
            topology
                .render(base, &deployment.spec, &scripts(&topology))
                .is_err(),
            "{pointer}"
        );
    }
    let expanded = render(&deployment, 3);
    assert!(topology
        .render(expanded, &deployment.spec, &scripts(&topology))
        .is_err());
    let mut duplicate = deployment.render().unwrap();
    duplicate
        .resources
        .insert("host2".into(), duplicate.resources["host"].clone());
    assert!(topology
        .render(duplicate, &deployment.spec, &scripts(&topology))
        .is_err());
    let mut renamed_spec = deployment.spec.clone();
    renamed_spec.retain_chain_disk = false;
    assert!(topology
        .render(
            deployment.render().unwrap(),
            &renamed_spec,
            &scripts(&topology)
        )
        .is_err());
}

#[test]
fn generated_program_is_deterministic_roundtrips_and_has_no_reference_cycles() {
    let deployment = deployment();
    let rendered = render(&deployment, 3);
    rendered.validate_references().unwrap();
    let first = rendered.to_yaml().unwrap();
    assert_eq!(first, render(&deployment, 3).to_yaml().unwrap());
    let restored: PulumiProgram = serde_yaml::from_str(&first).unwrap();
    assert_eq!(first, restored.to_yaml().unwrap());
    let names: BTreeSet<_> = rendered.resources.values().map(|r| &r.name).collect();
    assert_eq!(names.len(), rendered.resources.len());
    let mut other = deployment.clone();
    other.spec.network_id = Uuid::new_v4();
    for resource in render(&other, 3).resources.values() {
        assert!(!names.contains(&resource.name));
    }
}

fn observed() -> Value {
    json!({
        "node-1":{"node_id":"node-1","instance_id":"i-00000000000000001","private_ip":"10.90.1.10","volume_id":"vol-00000000000000001"},
        "node-2":{"node_id":"node-2","instance_id":"i-00000000000000002","private_ip":"10.90.1.11","volume_id":"vol-00000000000000002"},
        "node-3":{"node_id":"node-3","instance_id":"i-00000000000000003","private_ip":"10.90.1.12","volume_id":"vol-00000000000000003"},
    })
}

#[test]
fn observed_outputs_require_exact_membership_and_expected_addresses() {
    let topology = ClusterTopology::new(3).unwrap();
    let valid = observed();
    assert_eq!(parse_node_outputs(&valid, &topology).unwrap().len(), 3);
    for (pointer, value) in [
        ("/node-2/node_id", json!("node-1")),
        ("/node-2/private_ip", json!("10.90.1.10")),
        ("/node-2/private_ip", json!("10.90.1.99")),
        ("/node-2/instance_id", json!("i-00000000000000001")),
        ("/node-2/volume_id", json!("vol-00000000000000001")),
        ("/node-2/instance_id", json!("i-0$malicious")),
        ("/node-2/volume_id", json!("vol-ABABABAB")),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            parse_node_outputs(&changed, &topology).is_err(),
            "{pointer}"
        );
    }
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("node-3");
    assert!(parse_node_outputs(&missing, &topology).is_err());
    let mut extra = valid.clone();
    extra["node-4"] = valid["node-3"].clone();
    assert!(parse_node_outputs(&extra, &topology).is_err());
    let mut unexpected_field = valid;
    unexpected_field["node-1"]["public_ip"] = json!("192.0.2.1");
    assert!(parse_node_outputs(&unexpected_field, &topology).is_err());
}

#[test]
fn generated_resources_keep_owned_disk_mount_reference_dependencies_valid() {
    let deployment = deployment();
    let topology = ClusterTopology::new(3).unwrap();
    let mut data = scripts(&topology);
    for node in topology.nodes() {
        data.get_mut(&node.node_id)
            .unwrap()
            .push_str(&format!("volume='${{{}.id}}'\n", node.volume_key));
    }
    topology
        .render(deployment.render().unwrap(), &deployment.spec, &data)
        .unwrap();
    data.get_mut("node-2")
        .unwrap()
        .push_str("bad='${unknown.id}'\n");
    assert!(topology
        .render(deployment.render().unwrap(), &deployment.spec, &data)
        .is_err());
    // Referencing the own instance in user data would form an apply-time cycle.
    let mut data = scripts(&topology);
    data.get_mut("node-2")
        .unwrap()
        .push_str("bad='${host2.id}'\n");
    assert!(topology
        .render(deployment.render().unwrap(), &deployment.spec, &data)
        .is_err());
    assert!(matches!(
        render(&deployment, 3).resources["host3"].definition,
        Definition::Instance(_)
    ));
}

#[test]
fn lightwallet_cache_is_separate_retained_and_uses_an_existing_follower() {
    use zdn::cluster_infra::{LIGHTWALLET_CACHE_ATTACHMENT, LIGHTWALLET_CACHE_DISK};
    let deployment = deployment();
    for count in 1..=3 {
        let topology = ClusterTopology::new(count).unwrap();
        let rendered = topology
            .render_with_lightwallet(
                deployment.render().unwrap(),
                &deployment.spec,
                &scripts(&topology),
                40,
            )
            .unwrap();
        let value = serde_json::to_value(&rendered).unwrap();
        let plain = serde_json::to_value(render(&deployment, count)).unwrap();
        for (key, resource) in plain["resources"].as_object().unwrap() {
            assert_eq!(value["resources"][key], *resource, "changed {key}");
        }
        for (key, output) in plain["outputs"].as_object().unwrap() {
            assert_eq!(value["outputs"][key], *output, "changed output {key}");
        }
        let selected = topology.lightwallet_node();
        assert_eq!(
            selected.node_id,
            if count == 1 { "node-1" } else { "node-2" }
        );
        let disk = &value["resources"][LIGHTWALLET_CACHE_DISK];
        let node_disk = &plain["resources"][&selected.volume_key];
        assert_eq!(disk["options"], node_disk["options"]);
        assert_eq!(disk["options"]["retainOnDelete"], true);
        for key in [
            "encrypted",
            "type",
            "availabilityZone",
            "iops",
            "throughput",
        ] {
            assert_eq!(disk["properties"][key], node_disk["properties"][key]);
        }
        for tag in [
            "zdn:bootstrap",
            "zdn:team-id",
            "zdn:managed-by",
            "zdn:network-id",
            "zdn:node-id",
        ] {
            assert_eq!(
                disk["properties"]["tags"][tag],
                node_disk["properties"]["tags"][tag]
            );
        }
        assert_eq!(disk["properties"]["tags"]["zdn:service"], "lightwalletd");
        assert_eq!(disk["properties"]["tags"]["Name"], disk["name"]);
        assert_eq!(disk["properties"]["size"], 40);
        let attachment = &value["resources"][LIGHTWALLET_CACHE_ATTACHMENT]["properties"];
        assert_eq!(attachment["deviceName"], "/dev/sdg");
        assert_eq!(
            attachment["instanceId"],
            format!("${{{}.id}}", selected.host_key)
        );
        assert_eq!(attachment["volumeId"], "${lightwalletCacheDisk.id}");
        assert_eq!(attachment["forceDetach"], false);
        assert_eq!(attachment["stopInstanceBeforeDetaching"], true);
        assert_eq!(
            value["outputs"]["lightwallet"],
            json!({"node_id":selected.node_id,"instance_id":attachment["instanceId"],"cache_volume_id":attachment["volumeId"],"cache_size_gib":40})
        );
        let yaml = rendered.to_yaml().unwrap();
        let restored: PulumiProgram = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(yaml, restored.to_yaml().unwrap());
        rendered.validate_references().unwrap();
    }
}

#[test]
fn lightwallet_cache_renderer_refuses_invalid_sizes_and_conflicting_resources() {
    let deployment = deployment();
    let topology = ClusterTopology::new(2).unwrap();
    for size in [0, 2049, u32::MAX] {
        assert!(topology
            .render_with_lightwallet(
                deployment.render().unwrap(),
                &deployment.spec,
                &scripts(&topology),
                size
            )
            .is_err());
    }
    let mut base = deployment.render().unwrap();
    base.outputs.insert("lightwallet".into(), json!({}));
    assert!(topology
        .render_with_lightwallet(base, &deployment.spec, &scripts(&topology), 40)
        .is_err());
    let mut base = deployment.render().unwrap();
    base.resources.insert(
        "lightwalletCacheAttachment".into(),
        base.resources["hostSsmPolicy"].clone(),
    );
    assert!(topology
        .render_with_lightwallet(base, &deployment.spec, &scripts(&topology), 40)
        .is_err());
}

#[test]
fn lightwallet_outputs_pin_selected_host_and_cannot_reuse_any_chain_disk() {
    use zdn::cluster_infra::parse_lightwallet_outputs;
    let topology = ClusterTopology::new(3).unwrap();
    let nodes = parse_node_outputs(&observed(), &topology).unwrap();
    let value = json!({"node_id":"node-2","instance_id":"i-00000000000000002","cache_volume_id":"vol-00000000000000004","cache_size_gib":40});
    let parsed = parse_lightwallet_outputs(&value, &topology, &nodes).unwrap();
    assert_eq!(parsed.cache_volume_id, "vol-00000000000000004");
    for (key, changed) in [
        ("node_id", json!("node-1")),
        ("instance_id", json!("i-00000000000000001")),
        ("cache_volume_id", json!("vol-00000000000000001")),
        ("cache_volume_id", json!("vol-00000000000000002")),
        ("cache_volume_id", json!("vol-00000000000000003")),
        ("cache_volume_id", json!("vol-ABABABAB")),
        ("cache_size_gib", json!(0)),
        ("cache_size_gib", json!(2049)),
        ("unknown", json!(true)),
    ] {
        let mut bad = value.clone();
        bad[key] = changed;
        assert!(
            parse_lightwallet_outputs(&bad, &topology, &nodes).is_err(),
            "{key}"
        );
    }
    assert!(parse_lightwallet_outputs(&value, &ClusterTopology::new(2).unwrap(), &nodes).is_err());
}

#[test]
fn lightwallet_presets_share_the_existing_host_budget_without_oversubscription() {
    use zdn::{
        cluster_infra::LightwalletAllocation,
        infra::{HostObservation, GIB, HOST_CPU_RESERVE_MILLIS},
    };
    for (size, cache_gib, memory, cpu) in [
        (Size::Small, 20, GIB / 2, 250),
        (Size::Medium, 40, GIB, 500),
        (Size::Large, 80, 2 * GIB, 1000),
    ] {
        let host = size.allocation();
        let allocation = LightwalletAllocation::for_size(size);
        allocation.validate_for(size).unwrap();
        assert_eq!(allocation.cache_gib, cache_gib);
        assert_eq!(allocation.service_memory_bytes, memory);
        assert_eq!(allocation.service_cpu_millis, cpu);
        assert_eq!(
            allocation.node_memory_bytes + memory + allocation.host_reserve_bytes,
            u64::from(host.host_gib) * GIB
        );
        assert_eq!(
            allocation.node_cpu_millis + cpu + HOST_CPU_RESERVE_MILLIS,
            host.vcpus * 1000
        );
        let observation = HostObservation {
            mem_total_bytes: u64::from(host.host_gib) * GIB,
            ancestor_memory_limits_bytes: vec![],
            online_cpu_count: host.vcpus,
            affinity_cpu_count: host.vcpus,
            ancestor_cpu_quota_millis: vec![],
        };
        let effective = allocation.effective_limits(size, &observation).unwrap();
        assert_eq!(effective.node_memory_bytes, allocation.node_memory_bytes);
        assert_eq!(effective.node_cpu_millis, allocation.node_cpu_millis);
        let encoded = serde_json::to_vec(&allocation).unwrap();
        assert_eq!(
            serde_json::from_slice::<LightwalletAllocation>(&encoded).unwrap(),
            allocation
        );
        let mut altered = allocation.clone();
        altered.node_memory_bytes += 1;
        assert!(altered.validate_for(size).is_err());
        assert!(altered.effective_limits(size, &observation).is_err());
    }
}

#[test]
fn lightwallet_effective_budgets_honor_memtotal_affinity_and_every_cgroup_ancestor() {
    use zdn::{
        cluster_infra::LightwalletAllocation,
        infra::{HostObservation, GIB},
    };
    let allocation = LightwalletAllocation::for_size(Size::Medium);
    let mut host = HostObservation {
        mem_total_bytes: 16 * GIB - GIB / 4,
        ancestor_memory_limits_bytes: vec![14 * GIB, 12 * GIB, 15 * GIB],
        online_cpu_count: 4,
        affinity_cpu_count: 3,
        ancestor_cpu_quota_millis: vec![2800, 2200, 2500],
    };
    let limits = allocation.effective_limits(Size::Medium, &host).unwrap();
    assert_eq!(limits.effective_memory_bytes, 12 * GIB);
    assert_eq!(limits.node_memory_bytes, 9 * GIB);
    assert_eq!(limits.visible_cpu_millis, 2200);
    assert_eq!(limits.node_cpu_millis, 1450);
    host.ancestor_memory_limits_bytes.clear();
    host.ancestor_cpu_quota_millis.clear();
    let limits = allocation.effective_limits(Size::Medium, &host).unwrap();
    assert_eq!(limits.node_memory_bytes, 13 * GIB - GIB / 4);
    assert_eq!(limits.node_cpu_millis, 2250);
    host.mem_total_bytes = u64::MAX;
    host.online_cpu_count = u32::MAX;
    host.affinity_cpu_count = u32::MAX;
    let limits = allocation.effective_limits(Size::Medium, &host).unwrap();
    assert_eq!(limits.node_memory_bytes, allocation.node_memory_bytes);
    assert_eq!(limits.node_cpu_millis, allocation.node_cpu_millis);
    for memory in [0, 3 * GIB, 4 * GIB - 1] {
        host.mem_total_bytes = memory;
        assert!(allocation.effective_limits(Size::Medium, &host).is_err());
    }
    host.mem_total_bytes = 16 * GIB;
    for quota in [0, 749, 750, 999] {
        host.ancestor_cpu_quota_millis = vec![quota];
        assert!(allocation.effective_limits(Size::Medium, &host).is_err());
    }
    host.ancestor_cpu_quota_millis = vec![1000];
    assert_eq!(
        allocation
            .effective_limits(Size::Medium, &host)
            .unwrap()
            .node_cpu_millis,
        250
    );
}
