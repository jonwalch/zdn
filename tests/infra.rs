use std::{collections::BTreeSet, process::Command};

use serde_json::{json, Value};
use uuid::Uuid;
use zdn::{
    config::Size,
    infra::{
        effective_limits, parse_outputs, Definition, FoundationSpec, HostObservation,
        PulumiProgram, AWS_PROVIDER_VERSION, FIXTURE_MEMORY_BYTES, GIB,
    },
    state::Scope,
};

fn spec() -> FoundationSpec {
    FoundationSpec {
        scope: Scope {
            team_id: "test-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        },
        network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
        aws_profile: "developer".into(),
        ami_id: "ami-0123456789abcdef0".into(),
        availability_zone: "us-east-1a".into(),
        size: Size::Medium,
        retain_chain_disk: true,
    }
}

fn document(spec: &FoundationSpec) -> Value {
    serde_yaml::from_str(&spec.render().unwrap().to_yaml().unwrap()).unwrap()
}

fn output(spec: &FoundationSpec) -> Value {
    json!({
        "schema_version":1, "scope":spec.scope, "network_id":spec.network_id,
        "availability_zone":spec.availability_zone,
        "vpc_id":"vpc-0123456789abcdef0", "private_subnet_id":"subnet-0123456789abcdef0",
        "instance_id":"i-0123456789abcdef0", "private_ip":"10.90.1.12",
        "chain_volume_id":"vol-0123456789abcdef0", "retain_chain_disk":spec.retain_chain_disk,
        "security_group_id":"sg-0123456789abcdef0", "nat_gateway_id":"nat-0123456789abcdef0",
        "eip_allocation_id":"eipalloc-0123456789abcdef0"
    })
}

#[test]
fn deterministic_program_round_trips_with_full_id_names() {
    let spec = spec();
    let first = spec.render().unwrap().to_yaml().unwrap();
    assert_eq!(first, spec.render().unwrap().to_yaml().unwrap());
    let saved: PulumiProgram = serde_yaml::from_str(&first).unwrap();
    assert_eq!(first, saved.to_yaml().unwrap());
    let value = document(&spec);
    let mut names = BTreeSet::new();
    for resource in value["resources"].as_object().unwrap().values() {
        let name = resource["name"].as_str().unwrap();
        assert!(name.contains(&spec.network_id.to_string()));
        assert!(names.insert(name));
    }
    // Different network IDs cannot reuse any physical/logical name, even when
    // their visible labels and team configuration are otherwise identical.
    let mut other = spec.clone();
    other.network_id = Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04154").unwrap();
    for resource in document(&other)["resources"].as_object().unwrap().values() {
        assert!(!names.contains(resource["name"].as_str().unwrap()));
    }
}

#[test]
fn every_cloud_resource_uses_the_guarded_pinned_provider() {
    let value = document(&spec());
    let resources = value["resources"].as_object().unwrap();
    let provider = &resources["provider"];
    assert_eq!(provider["type"], "pulumi:providers:aws");
    assert_eq!(provider["properties"]["region"], "us-east-1");
    assert_eq!(provider["properties"]["profile"], "developer");
    assert_eq!(
        provider["properties"]["allowedAccountIds"],
        json!(["123456789012"])
    );
    assert_eq!(provider["options"]["version"], AWS_PROVIDER_VERSION);
    let catalog: Value =
        serde_json::from_str(include_str!("../data/managed-tools-v1.json")).unwrap();
    for tools in catalog["platforms"].as_object().unwrap().values() {
        let aws = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "pulumi-resource-aws")
            .unwrap();
        assert_eq!(aws["version"], AWS_PROVIDER_VERSION);
    }

    for (name, resource) in resources {
        if name != "provider" {
            assert_eq!(resource["options"]["provider"], "${provider}");
        }
    }
}

#[test]
fn private_host_has_only_outbound_https_and_no_ssh_credentials() {
    let value = document(&spec());
    let resources = &value["resources"];
    let host = &resources["host"]["properties"];
    assert_eq!(host["associatePublicIpAddress"], false);
    assert_eq!(host["subnetId"], "${privateSubnet.id}");
    assert_eq!(
        host["vpcSecurityGroupIds"],
        json!(["${hostSecurityGroup.id}"])
    );
    assert!(host.get("keyName").is_none());
    assert!(host.get("ipv6Addresses").is_none());
    assert_eq!(host["metadataOptions"]["httpTokens"], "required");
    assert_eq!(host["metadataOptions"]["httpPutResponseHopLimit"], 1);
    assert_eq!(
        resources["privateSubnet"]["properties"]["mapPublicIpOnLaunch"],
        false
    );
    assert_eq!(
        resources["hostSecurityGroup"]["properties"]["ingress"],
        json!([])
    );
    let egress = resources["hostSecurityGroup"]["properties"]["egress"]
        .as_array()
        .unwrap();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["protocol"], "tcp");
    assert_eq!(egress[0]["fromPort"], 443);
    assert_eq!(egress[0]["toPort"], 443);
    assert_eq!(
        resources["defaultSecurityGroup"]["properties"]["ingress"],
        json!([])
    );
    assert_eq!(
        resources["defaultSecurityGroup"]["properties"]["egress"],
        json!([])
    );
}

#[test]
fn egress_has_a_complete_one_az_nat_route_without_public_host_addresses() {
    let value = document(&spec());
    let resources = &value["resources"];
    assert_eq!(
        resources["privateRoutes"]["properties"]["routes"][0]["natGatewayId"],
        "${natGateway.id}"
    );
    assert!(resources["privateRoutes"]["properties"]["routes"][0]
        .get("gatewayId")
        .is_none());
    assert_eq!(
        resources["natGateway"]["properties"]["subnetId"],
        "${publicSubnet.id}"
    );
    assert_eq!(
        resources["natGateway"]["properties"]["allocationId"],
        "${natAddress.id}"
    );
    assert_eq!(
        resources["publicRoutes"]["properties"]["routes"][0]["gatewayId"],
        "${internetGateway.id}"
    );
    assert_eq!(
        resources["publicRouteAssociation"]["properties"]["routeTableId"],
        "${publicRoutes.id}"
    );
    assert_eq!(
        resources["privateRouteAssociation"]["properties"]["routeTableId"],
        "${privateRoutes.id}"
    );
    let deps = resources["host"]["options"]["dependsOn"]
        .as_array()
        .unwrap();
    assert!(deps.contains(&json!("${privateRouteAssociation}")));
    assert!(deps.contains(&json!("${hostSsmPolicy}")));
    for subnet in ["privateSubnet", "publicSubnet"] {
        assert_eq!(
            resources[subnet]["properties"]["availabilityZone"],
            "us-east-1a"
        );
    }
}

#[test]
fn runtime_role_has_ssm_access_and_no_state_or_build_permissions() {
    let value = document(&spec());
    let resources = value["resources"].as_object().unwrap();
    let attachments = resources
        .values()
        .filter(|r| r["type"] == "aws:iam:RolePolicyAttachment")
        .collect::<Vec<_>>();
    assert_eq!(attachments.len(), 1);
    assert_eq!(
        attachments[0]["properties"]["policyArn"],
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    );
    assert!(!resources
        .values()
        .any(|r| r["type"] == "aws:iam:RolePolicy"));
    let policy: Value = serde_json::from_str(
        resources["hostRole"]["properties"]["assumeRolePolicy"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        policy["Statement"][0]["Principal"],
        json!({"Service":"ec2.amazonaws.com"})
    );
    let text = serde_json::to_string(&resources).unwrap();
    for forbidden in ["s3:", "kms:", "codebuild:", "ecr:", "secretsmanager:"] {
        assert!(
            !text.contains(forbidden),
            "unexpected runtime permission {forbidden}"
        );
    }
}

#[test]
fn retained_chain_disk_is_independent_encrypted_and_safely_detached() {
    let spec = spec();
    let value = document(&spec);
    let resources = &value["resources"];
    assert_eq!(resources["chainDisk"]["properties"]["encrypted"], true);
    assert_eq!(resources["chainDisk"]["properties"]["type"], "gp3");
    assert_eq!(resources["chainDisk"]["properties"]["size"], 80);
    assert_eq!(resources["chainDisk"]["options"]["retainOnDelete"], true);
    assert_eq!(
        resources["host"]["properties"]["rootBlockDevice"]["encrypted"],
        true
    );
    assert_eq!(
        resources["host"]["properties"]["rootBlockDevice"]["deleteOnTermination"],
        true
    );
    assert!(resources["host"]["properties"]
        .get("ebsBlockDevices")
        .is_none());
    assert_eq!(
        resources["chainAttachment"]["properties"]["stopInstanceBeforeDetaching"],
        true
    );
    assert_eq!(
        resources["chainAttachment"]["properties"]["forceDetach"],
        false
    );
    let mut deletion = spec.clone();
    deletion.retain_chain_disk = false;
    let delete_value = document(&deletion);
    // Retention changes cannot rename/resize/replace the data or host resource.
    for name in ["host", "chainDisk", "chainAttachment"] {
        assert_eq!(
            value["resources"][name]["name"],
            delete_value["resources"][name]["name"]
        );
        assert_eq!(
            value["resources"][name]["properties"],
            delete_value["resources"][name]["properties"]
        );
    }
    assert_eq!(
        delete_value["resources"]["chainDisk"]["options"]["retainOnDelete"],
        false
    );
}

#[test]
fn dangling_properties_resources_and_dependency_cycles_fail_before_pulumi() {
    let spec = spec();
    let mut missing = spec.render().unwrap();
    missing.resources.remove("chainDisk");
    assert!(missing
        .to_yaml()
        .unwrap_err()
        .to_string()
        .contains("unresolved"));
    let mut misspelled = spec.render().unwrap();
    misspelled
        .outputs
        .insert("private_ip".into(), json!("${host.privateIpTypo}"));
    assert!(misspelled
        .to_yaml()
        .unwrap_err()
        .to_string()
        .contains("unknown Pulumi output"));
    let mut cyclic = spec.render().unwrap();
    cyclic
        .resources
        .get_mut("vpc")
        .unwrap()
        .options
        .depends_on
        .push("${host}".into());
    assert!(cyclic.to_yaml().unwrap_err().to_string().contains("cycle"));
}

#[test]
fn foundation_inputs_reject_unpinned_or_cross_region_values() {
    let base = spec();
    for ami in [
        "latest",
        "resolve:ssm:/ami",
        "ami-X1234567",
        "ami-1234",
        "${other.id}",
    ] {
        let mut changed = base.clone();
        changed.ami_id = ami.into();
        assert!(changed.render().is_err(), "accepted {ami}");
    }
    for zone in [
        "us-west-2a",
        "us-east-1",
        "us-east-1a;id",
        "us-east-1-atl-1a",
    ] {
        let mut changed = base.clone();
        changed.availability_zone = zone.into();
        assert!(changed.render().is_err(), "accepted {zone}");
    }
    let mut changed = base.clone();
    changed.network_id = Uuid::nil();
    assert!(changed.render().is_err());
    changed = base.clone();
    changed.aws_profile = "${other.id}".into();
    assert!(changed.render().is_err());
    changed = base;
    changed.scope.account_id = "someone-else".into();
    assert!(changed.render().is_err());
}

#[test]
fn strict_output_contract_rejects_missing_wrong_scope_and_public_addresses() {
    let spec = spec();
    let good = output(&spec);
    assert!(parse_outputs(&serde_json::to_vec(&good).unwrap(), &spec).is_ok());
    for key in good.as_object().unwrap().keys() {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            parse_outputs(&serde_json::to_vec(&missing).unwrap(), &spec).is_err(),
            "accepted missing {key}"
        );
    }
    for (key, bad) in [
        ("schema_version", json!(2)),
        ("network_id", json!(Uuid::new_v4())),
        ("private_ip", json!("8.8.8.8")),
        ("private_ip", json!("10.90.0.8")),
        ("private_ip", json!("10.90.1.0")),
        ("instance_id", json!("${host.id}")),
        ("retain_chain_disk", json!(false)),
        ("availability_zone", json!("us-east-1b")),
    ] {
        let mut changed = good.clone();
        changed[key] = bad;
        assert!(
            parse_outputs(&serde_json::to_vec(&changed).unwrap(), &spec).is_err(),
            "accepted wrong {key}"
        );
    }
    let mut wrong_team = good;
    wrong_team["scope"]["team_id"] = json!("another-org");
    assert!(parse_outputs(&serde_json::to_vec(&wrong_team).unwrap(), &spec).is_err());
}

#[test]
fn optional_lightwallet_outputs_preserve_legacy_encoding_and_require_selected_node() {
    let spec = spec();
    let mut value = output(&spec);
    let legacy = parse_outputs(&serde_json::to_vec(&value).unwrap(), &spec).unwrap();
    assert!(legacy.lightwallet.is_none());
    assert_eq!(serde_json::to_value(&legacy).unwrap(), value);
    value["lightwallet"] = json!({"node_id":"node-1","instance_id":value["instance_id"],"cache_volume_id":"vol-0123456789abcdef1","cache_size_gib":40});
    assert!(parse_outputs(&serde_json::to_vec(&value).unwrap(), &spec).is_err());
    value["private_ip"] = json!("10.90.1.10");
    value["nodes"] = json!({"node-1":{"node_id":"node-1","instance_id":value["instance_id"],"private_ip":value["private_ip"],"volume_id":value["chain_volume_id"]}});
    let outputs = parse_outputs(&serde_json::to_vec(&value).unwrap(), &spec).unwrap();
    assert_eq!(outputs.lightwallet.unwrap().cache_size_gib, 40);
    value["lightwallet"]["cache_volume_id"] = value["chain_volume_id"].clone();
    assert!(parse_outputs(&serde_json::to_vec(&value).unwrap(), &spec).is_err());
}

fn host() -> HostObservation {
    HostObservation {
        mem_total_bytes: 16 * GIB - 512 * 1024 * 1024,
        ancestor_memory_limits_bytes: vec![],
        online_cpu_count: 4,
        affinity_cpu_count: 4,
        ancestor_cpu_quota_millis: vec![],
    }
}

#[test]
fn effective_memory_uses_measured_and_all_ancestor_limits_before_reserves() {
    let measured = host();
    let limits = effective_limits(Size::Medium, &measured).unwrap();
    assert_eq!(limits.effective_memory_bytes, measured.mem_total_bytes);
    assert_eq!(
        limits.application_memory_bytes,
        measured.mem_total_bytes - 2 * GIB - FIXTURE_MEMORY_BYTES
    );
    let mut cgroup = measured.clone();
    cgroup.ancestor_memory_limits_bytes = vec![15 * GIB, 10 * GIB, 12 * GIB];
    cgroup.ancestor_cpu_quota_millis = vec![3500, 2000];
    cgroup.affinity_cpu_count = 3;
    let limits = effective_limits(Size::Medium, &cgroup).unwrap();
    assert_eq!(
        limits.application_memory_bytes,
        8 * GIB - FIXTURE_MEMORY_BYTES
    );
    assert_eq!(limits.visible_cpu_millis, 2000);
    assert_eq!(limits.application_cpu_millis, 1500);
}

#[test]
fn allocations_never_oversubscribe_and_fixture_is_charged_once() {
    for size in [Size::Small, Size::Medium, Size::Large] {
        let alloc = size.allocation();
        let measured = HostObservation {
            mem_total_bytes: 128 * GIB,
            online_cpu_count: 64,
            affinity_cpu_count: 64,
            ..host()
        };
        let limits = effective_limits(size, &measured).unwrap();
        assert_eq!(
            limits.application_memory_bytes + limits.fixture_memory_bytes,
            u64::from(alloc.max_node_gib) * GIB
        );
        assert_eq!(limits.visible_cpu_millis, alloc.vcpus * 1000);
        assert_eq!(
            limits.application_cpu_millis + 500,
            limits.visible_cpu_millis
        );
        assert_eq!(limits.fixture_memory_bytes, FIXTURE_MEMORY_BYTES);
        let mut too_small = measured.clone();
        too_small.ancestor_memory_limits_bytes =
            vec![limits.host_reserve_bytes + FIXTURE_MEMORY_BYTES];
        assert!(effective_limits(size, &too_small).is_err());
        too_small = measured;
        too_small.ancestor_cpu_quota_millis = vec![500];
        assert!(effective_limits(size, &too_small).is_err());
    }
}

#[test]
fn host_preparation_is_python_free_bounded_shell_with_safe_chain_setup() {
    let spec = spec();
    let script = spec.cloud_init().unwrap();
    assert!(script.len() <= 16 * 1024);
    assert!(script.contains("dnf install -y docker awscli-2 amazon-ssm-agent e2fsprogs util-linux"));
    assert!(script.contains("nvme-Amazon_Elastic_Block_Store_$serial"));
    assert!(script.contains("test -z \"$(wipefs --noheadings --output TYPE \"$device\")\""));
    assert!(script.contains("test \"$(blkid -s TYPE -o value \"$device\")\" = ext4"));
    assert!(script.contains("mountpoint -q /var/lib/zdn-chain || mount /var/lib/zdn-chain"));
    assert!(script.contains("Before=zdn-foundation.service"));
    assert!(script.contains("TimeoutStartSec=420"));
    assert!(!script.contains("zakurad"));
    for absent in [
        "python",
        "foundation.py",
        "cat >/etc/systemd/system/zdn-foundation.service",
        "systemctl daemon-reload",
        "systemctl enable --now zdn-chain.service",
        "docker build",
        "docker pull",
        "generate(",
        "cargo ",
        "0.0.0.0', 18080",
    ] {
        assert!(!script.contains(absent));
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("setup.sh");
    std::fs::write(&file, &script).unwrap();
    assert!(Command::new("bash")
        .arg("-n")
        .arg(&file)
        .status()
        .unwrap()
        .success());
    // Ensure service setup has no volume-attachment dependency cycle and the
    // only expression expanded by Pulumi is the owned data volume ID.
    assert_eq!(script.matches("${").count(), 1);
    assert!(script.contains("${chainDisk.id}"));
    let rendered = spec.render().unwrap();
    assert!(matches!(
        rendered.resources["host"].definition,
        Definition::Instance(_)
    ));
}
