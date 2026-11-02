#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use zdn::public_chain_adapter::{contract::*, Failure};

fn fixture() -> (RenderInput, Value) {
    let descriptor = Descriptor {
        schema: SCHEMA.into(),
        native_name: "Fixture".into(),
        native_fingerprint: "ab".repeat(32),
    };
    let descriptor_hash = Pin::of(&serde_json::to_vec(&descriptor).unwrap()).sha256;
    let root=format!("/var/lib/zdn/deployments/00000000-0000-4000-8000-000000000000/nodes/node-1/chains/{descriptor_hash}");
    let rules = json!({"network_name":"Fixture","network_magic":[1,2,3,4],"genesis_hash":"ab".repeat(32),"target_difficulty_limit":"ff".repeat(32),"disable_pow":true,"slow_start_interval":0,"max_block_time_start_height":1,"should_allow_unshielded_coinbase_spends":true,"activation_heights":{"NU7":102},"pre_blossom_halving_interval":144,"funding_streams":[],"lockbox_disbursements":[{"address":"fixture","amount":0}],"checkpoints":[[0,vec![0xab;32]],[1,vec![0xcd;32]]],"experimental_slh_dsa_b128s_activation_height":103,"experimental_slh_dsa_b128s_max_checks_per_transaction":16,"experimental_slh_dsa_b128s_max_checks_per_block":64});
    let o = RenderOptions {
        deployment_id: "00000000-0000-4000-8000-000000000000".into(),
        node_id: "node-1".into(),
        role: "follower".into(),
        image_digest: format!("sha256:{}", "12".repeat(32)),
        state_dir: format!("{root}/state"),
        identity_dir: format!("{root}/identity"),
        cookie_dir: format!("{root}/rpc"),
        rpc_listen: "127.0.0.1:18232".into(),
        native_listen: "0.0.0.0:18233".into(),
        expected_node_id: "ef".repeat(32),
        peers: vec![],
        reward_address: None,
    };
    let config = json!({
        "network":{"network":rules,"p2p_stack":"zakura","listen_addr":"0.0.0.0:18233","identity_dir":format!("{root}/identity"),"initial_mainnet_peers":[],"initial_testnet_peers":[],"cache_dir":false,"zakura":{"listen_addr":"0.0.0.0:18233","bootstrap_peers":[],"nat_traversal":false,"expected_node_id":"ef".repeat(32)}},
        "state":{"cache_dir":format!("{root}/state"),"ephemeral":false,"should_backup_non_finalized_state":true,"delete_old_database":false,"storage_mode":"archive"},
        "consensus":{"checkpoint_sync":true,"vct_fast_sync":false},"mempool":{"debug_enable_at_height":0},
        "rpc":{"listen_addr":"127.0.0.1:18232","cookie_dir":format!("{root}/rpc"),"cookie_file_name":".cookie","enable_cookie_auth":true,"debug_force_finished_sync":false},
        "mining":{"internal_miner":false,"optimistic_block_inventory":false},"tracing":{"use_color":false,"force_use_color":false,"use_journald":false},"zcashd_compat":{"enabled":false}
    });
    (
        RenderInput {
            public: CompileInput {
                descriptor,
                native_rules_json: serde_json::to_string(&rules).unwrap(),
                wallet_profile_json: "{}".into(),
                seed_bundle: Pin::of(&[]),
            },
            compiled_sha256: "ab".repeat(32),
            options: o,
            identity_only: false,
        },
        config,
    )
}
fn rendered(v: &Value) -> Rendered {
    Rendered {
        config_toml: toml::to_string_pretty(v).unwrap(),
    }
}

#[test]
fn security_checks_reject_identical_but_unsafe_adapter_renders() {
    let (input, config) = fixture();
    validate_render(&rendered(&config), &input).unwrap();
    for (pointer, value) in [
        ("/state/delete_old_database", json!(true)),
        ("/state/ephemeral", json!(true)),
        ("/state/cache_dir", json!("/etc")),
        ("/rpc/listen_addr", json!("0.0.0.0:18232")),
        ("/rpc/enable_cookie_auth", json!(false)),
        ("/rpc/cookie_dir", json!("/tmp")),
        ("/rpc/cookie_file_name", json!("../cookie")),
        ("/mining/internal_miner", json!(true)),
        ("/network/identity_dir", json!("/tmp")),
        ("/network/zakura/nat_traversal", json!(true)),
        ("/network/zakura/expected_node_id", json!("00".repeat(32))),
        ("/network/zakura/listen_addr", json!("0.0.0.0:9999")),
    ] {
        let mut bad = config.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        let same_on_both_hosts = rendered(&bad);
        assert_eq!(
            validate_render(&same_on_both_hosts, &input),
            Err(Failure::InvalidOutput),
            "{pointer}"
        );
    }
    for table in [
        "rpc",
        "network",
        "state",
        "mining",
        "tracing",
        "consensus",
        "mempool",
        "zcashd_compat",
    ] {
        let mut bad = config.clone();
        bad[table]["unknown_setting"] = true.into();
        assert!(validate_render(&rendered(&bad), &input).is_err(), "{table}");
    }
    let mut bad = config.clone();
    bad["network"]["zakura"]["zakura_node_secret_key"] = "secret".into();
    assert!(validate_render(&rendered(&bad), &input).is_err());
    let mut changed_input = input;
    changed_input.options.state_dir = "/etc".into();
    assert!(validate_render(&rendered(&config), &changed_input).is_err());
}

#[test]
fn identity_only_config_is_not_a_runtime_permission() {
    let (mut input, mut config) = fixture();
    assert!(!serde_json::to_value(&input)
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("identityOnly"));
    input.identity_only = true;
    assert!(validate_render(&rendered(&config), &input).is_err());
    input.options.expected_node_id.clear();
    config["network"]["zakura"]
        .as_object_mut()
        .unwrap()
        .remove("expected_node_id");
    validate_render(&rendered(&config), &input).unwrap();
    assert!(input.options.validate().is_err());
    let bytes = serde_json::to_vec(&input).unwrap();
    assert!(parse::<RenderInput>(&bytes).unwrap().identity_only);
    input.identity_only = false;
    assert!(validate_render(&rendered(&config), &input).is_err());
    input.identity_only = true;
    input.options.role = "producer".into();
    input.options.reward_address = Some("not-permitted".into());
    assert!(validate_render(&rendered(&config), &input).is_err());
}

#[test]
fn external_provisioning_has_distinct_immutable_volume_ownership() {
    use std::os::unix::fs::PermissionsExt;
    use zdn::host::{external::Provisioning, files::Directory};
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(root.path(), nix::unistd::Uid::effective().as_raw()).unwrap();
    let mut spec = Provisioning {
        schema: "zdn-external-provisioning/v1".into(),
        deployment_id: "00000000-0000-4000-8000-000000000000".parse().unwrap(),
        node_id: "node-1".into(),
        volume_id: "vol-00000000000000001".into(),
        descriptor_sha256: "ab".repeat(32),
        native_fingerprint: "cd".repeat(32),
        request: Pin::of(b"{}"),
        new_volume: None,
    };
    let bytes = spec.bytes().unwrap();
    Provisioning::from_slice(&bytes).unwrap();
    let guard = spec.acquire(&directory).unwrap();
    let identity = guard.identity().to_vec();
    let value: Value = serde_json::from_slice(&identity).unwrap();
    assert_eq!(value["apiVersion"], "zdn-external-volume/v1");
    assert_eq!(value["nativeFingerprint"], "cd".repeat(32));
    assert!(value.get("consensusFingerprint").is_none());
    assert_eq!(
        directory
            .read("external-install-intent.json", 8192)
            .unwrap(),
        bytes
    );
    drop(guard);
    assert_eq!(spec.acquire(&directory).unwrap().identity(), identity);
    spec.native_fingerprint = "ef".repeat(32);
    assert!(spec.acquire(&directory).is_err());
    assert_eq!(directory.read("identity.json", 8192).unwrap(), identity);
    assert_eq!(
        directory
            .read("external-install-intent.json", 8192)
            .unwrap(),
        bytes
    );
}

#[test]
fn strict_typed_objects_reject_duplicates_unknown_fields_arrays_and_floats() {
    for raw in [
        r#"{"bytes":1,"bytes":2,"sha256":"x"}"#,
        r#"[1,"x"]"#,
        r#"{"bytes":1,"sha256":"x","privateKey":"secret"}"#,
        r#"{"bytes":1.0,"sha256":"x"}"#,
    ] {
        assert!(parse::<Pin>(raw.as_bytes()).is_err(), "{raw}");
    }
    let (input, _) = fixture();
    let mut v = serde_json::to_value(input).unwrap();
    v["public"]["seedBundle"] = json!([0, "ab".repeat(32)]);
    assert!(parse::<RenderInput>(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(strict_value(br#"{"a":{"b":1,"b":2}}"#).is_err());
}

#[test]
fn checkpoint_envelope_uses_native_bounded_byte_arrays_not_hex_strings() {
    let (input, config) = fixture();
    validate_render(&rendered(&config), &input).unwrap();
    for hash in [
        json!("ab".repeat(32)),
        json!(vec![0xab; 31]),
        json!(vec![0xab; 33]),
        json!(vec![256; 32]),
        json!(vec![-1; 32]),
        json!(vec![1.0; 32]),
        json!({"hash":vec![0xab;32]}),
    ] {
        let mut changed_input = input.clone();
        let mut rules: Value = serde_json::from_str(&input.public.native_rules_json).unwrap();
        rules["checkpoints"][0][1] = hash;
        changed_input.public.native_rules_json = serde_json::to_string(&rules).unwrap();
        // Use identical unsafe bytes on both sides. Independent envelope
        // validation must reject them before whole-render equality can help.
        let mut changed_config = config.clone();
        changed_config["network"]["network"] = rules;
        assert!(validate_render(&rendered(&changed_config), &changed_input).is_err());
    }
}

#[test]
fn raw_bundle_integrity_and_private_peer_inventory_are_bounded() {
    let bytes = [1, 0, 0, 0, 0xaa, 1, 0, 0, 0, 0xbb];
    let blocks = bundle_blocks(&bytes).unwrap();
    assert_eq!(blocks, vec![&[0xaa][..], &[0xbb][..]]);
    for raw in [
        &bytes[..9],
        &bytes[..5],
        &[0, 0, 0, 0][..],
        &[0xff, 0xff, 0xff, 0xff][..],
    ] {
        assert!(bundle_blocks(raw).is_err());
    }
    let pin = Pin::of(&bytes);
    assert!(pin.check(&bytes[..9]).is_err());
    let (mut input, _) = fixture();
    input.options.peers = vec![Peer {
        node_id: "ab".repeat(32),
        endpoint: "10.0.0.2:18233".into(),
    }];
    input.options.validate().unwrap();
    input.options.peers.push(input.options.peers[0].clone());
    assert!(input.options.validate().is_err());
    input.options.peers.pop();
    input.options.peers[0].endpoint = "8.8.8.8:18233".into();
    assert!(input.options.validate().is_err());
}

#[test]
fn explicit_external_selection_never_falls_back_to_ordinary_execution() {
    let mut config = zdn::config::Config::draft(
        "fixture".into(),
        "developer".into(),
        zdn::config::Source {
            image: Some(format!("example@sha256:{}", "ab".repeat(32))),
            ..Default::default()
        },
        zdn::config::Size::Medium,
    )
    .unwrap();
    assert!(serde_json::to_value(&config)
        .unwrap()
        .get("chain")
        .is_none());
    config.chain = Some(zdn::config::ChainSelection::Ordinary);
    config.validate().unwrap();
    config.chain = Some(zdn::config::ChainSelection::External {
        package_sha256: "ab".repeat(32),
        adapter_selection_sha256: "cd".repeat(32),
        production_limits: None,
    });
    config.validate().unwrap();
    assert!(config
        .require_ordinary_chain()
        .unwrap_err()
        .to_string()
        .contains("ordinary chain execution is forbidden"));
    assert!(zdn::chain::ChainRequest::from_config(&config).is_err());
    config.chain = Some(zdn::config::ChainSelection::External {
        package_sha256: "not-a-pin".into(),
        adapter_selection_sha256: "cd".repeat(32),
        production_limits: None,
    });
    assert!(config.validate().is_err());
}

#[test]
fn full_rpc_upgrade_schedule_collapses_only_for_diagnostic_comparison() {
    let (directory, input, _, _) = public_package();
    let mut compiled: Compiled =
        serde_json::from_slice(&std::fs::read(directory.path().join("compiled.json")).unwrap())
            .unwrap();
    compiled.upgrades.extend([
        Upgrade {
            name: "Overwinter".into(),
            branch_id: "5ba81b19".into(),
            activation_height: 102,
        },
        Upgrade {
            name: "NU7".into(),
            branch_id: "77190ad9".into(),
            activation_height: 102,
        },
    ]);
    compiled.expected_rules["rules"]["activationHeights"] = json!([
        {"height":0,"upgrade":"Genesis"}, {"height":102,"upgrade":"NU7"}
    ]);
    let pins: Vec<_> = compiled.seed_blocks.iter().map(|b| b.pin.clone()).collect();
    compiled.validate(&input.public, &pins).unwrap();
    let mut reversed = compiled.clone();
    reversed.upgrades.swap(1, 2);
    assert!(reversed.validate(&input.public, &pins).is_err());
    let mut wrong_height = compiled.clone();
    wrong_height.upgrades[1].activation_height = 103;
    assert!(wrong_height.validate(&input.public, &pins).is_err());
    for duplicate_name in [false, true] {
        let mut duplicate = compiled.clone();
        if duplicate_name {
            duplicate.upgrades[1].name = duplicate.upgrades[2].name.clone();
        } else {
            duplicate.upgrades[1].branch_id = duplicate.upgrades[2].branch_id.clone();
        }
        assert!(duplicate.validate(&input.public, &pins).is_err());
    }
    compiled.expected_rules["rules"]["activationHeights"][1]["upgrade"] = json!("Overwinter");
    assert!(compiled.validate(&input.public, &pins).is_err());
}

fn public_package() -> (
    tempfile::TempDir,
    RenderInput,
    Vec<u8>,
    zdn::public_chain_adapter::package::CoreTrust,
) {
    use std::fs;
    use zdn::public_chain_adapter::{
        package::{CoreTrust, PublicPackage},
        TrustedExecutable,
    };
    let directory = tempfile::tempdir().unwrap();
    let (mut input, _) = fixture();
    let bundle = [1, 0, 0, 0, 0xaa, 1, 0, 0, 0, 0xbb];
    input.public.seed_bundle = Pin::of(&bundle);
    let seed_blocks = vec![
        SeedBlock {
            height: 0,
            hash: "ab".repeat(32),
            pin: Pin::of(&[0xaa]),
        },
        SeedBlock {
            height: 1,
            hash: "cd".repeat(32),
            pin: Pin::of(&[0xbb]),
        },
    ];
    let compiled = Compiled {
        schema: SCHEMA.into(),
        native_name: input.public.descriptor.native_name.clone(),
        native_fingerprint: input.public.descriptor.native_fingerprint.clone(),
        expected_rules: json!({"rules":{"genesisHash":"ab".repeat(32),
            "checkpoints":[{"height":0,"hash":"ab".repeat(32)},{"height":1,"hash":"cd".repeat(32)}],
            "activationHeights":[{"height":0,"upgrade":"Genesis"}],"difficulty":{"proofOfWork":"disabled"}}}),
        upgrades: vec![Upgrade {
            name: "Genesis".into(),
            branch_id: "00000000".into(),
            activation_height: 0,
        }],
        seed_blocks,
        cargo_features: vec![
            "default-release-binaries".into(),
            "experimental-slh-dsa-b128s".into(),
        ],
        required_capabilities: vec![
            "native-managed-identity-v1".into(),
            "slh-dsa-b128s-v2".into(),
        ],
        transport_class: "large-hex-v1".into(),
    };
    let mut unsupported = compiled.clone();
    unsupported
        .required_capabilities
        .push("arbitrary-network-hook".into());
    assert!(unsupported.image_requirements().is_err());
    unsupported = compiled.clone();
    unsupported.cargo_features = vec!["a".repeat(65)];
    assert!(unsupported.image_requirements().is_err());
    let compiled = serde_json::to_vec(&compiled).unwrap();
    let script = format!(
        r#"#!/usr/bin/python3
import json,sys
r=json.load(sys.stdin)
assert open('seed-blocks.bin','rb').read()==bytes([1,0,0,0,170,1,0,0,0,187])
out={{k:r[k] for k in ('protocol','operation','requestId','adapterSelectionSha256','context')}}
out['result']=json.loads({:?})
print(json.dumps(out,separators=(',',':')))
"#,
        String::from_utf8(compiled.clone()).unwrap()
    );
    let script = script.as_bytes();
    let descriptor = serde_json::to_vec(&input.public.descriptor).unwrap();
    let manifest = PublicPackage {
        schema: "zdn-external-package/v1".into(),
        source_url: "https://example.invalid/native".into(),
        source_revision: "01".repeat(20),
        license: "MIT".into(),
        host_platform: "linux/amd64".into(),
        host_adapter: TrustedExecutable {
            adapter_id: "fixture".into(),
            adapter_version: "1".into(),
            prepared_input_schema: SCHEMA.into(),
            adapter_selection_sha256: "01".repeat(32),
            executable_sha256: Pin::of(script).sha256,
            executable_bytes: script.len() as u64,
        },
        prepared_chain_source: Pin::of(b"source"),
        prepared_profile_source: Pin::of(b"{}"),
        descriptor: Pin::of(&descriptor),
        native_rules: Pin::of(input.public.native_rules_json.as_bytes()),
        wallet_profile: Pin::of(input.public.wallet_profile_json.as_bytes()),
        seed_bundle: Pin::of(&bundle),
        compiled_result: Pin::of(&compiled),
    };
    let metadata = serde_json::to_vec(&manifest).unwrap();
    for (name, bytes) in [
        ("descriptor.json", descriptor.as_slice()),
        (
            "native-rules.json",
            input.public.native_rules_json.as_bytes(),
        ),
        (
            "wallet-profile.json",
            input.public.wallet_profile_json.as_bytes(),
        ),
        ("seed-blocks.bin", bundle.as_slice()),
        ("host-adapter", script),
        ("compiled.json", compiled.as_slice()),
    ] {
        fs::write(directory.path().join(name), bytes).unwrap();
    }
    let trust = CoreTrust {
        package: Pin::of(&metadata),
        adapter_selection_sha256: "01".repeat(32),
        executable: Pin::of(script),
    };
    (directory, input, metadata, trust)
}

#[test]
fn package_execution_requires_independent_trust_and_exact_recompilation() {
    use std::{
        fs,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::public_chain_adapter::package::{CoreTrust, PreparedExternalChain, PublicPackage};
    let (directory, input, metadata, trust) = public_package();
    let cancel = AtomicBool::new(false);
    let prepare = |trust: &CoreTrust| {
        PreparedExternalChain::prepare(
            &metadata,
            directory.path(),
            trust,
            Instant::now() + Duration::from_secs(5),
            &cancel,
        )
    };
    let prepared = prepare(&trust).unwrap();
    assert_eq!(prepared.compiled().seed_blocks.len(), 2);
    assert_eq!(prepared.requirements().unwrap().cargo_features.len(), 2);
    fs::write(directory.path().join("package.json"), &metadata).unwrap();
    let trust_path = directory.path().join("private-trust-sentinel.json");
    fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();
    let command = || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
        command.env_clear().env("PATH", "").args([
            "--format",
            "json",
            "external",
            "compile",
            "--public-directory",
            directory.path().to_str().unwrap(),
            "--trust",
            trust_path.to_str().unwrap(),
        ]);
        command
    };
    let baseline = command().output().unwrap();
    assert!(baseline.status.success(), "{baseline:?}");
    let trace = directory.path().join("trace.jsonl");
    let traced = command()
        .env("ZDN_TRACE_FILE", &trace)
        .env("AWS_SECRET_ACCESS_KEY", "private-environment-sentinel")
        .output()
        .unwrap();
    assert!(traced.status.success(), "{traced:?}");
    assert_eq!(traced.stdout, baseline.stdout);
    assert_eq!(traced.stderr, baseline.stderr);
    if cfg!(feature = "profiling") {
        let text = fs::read_to_string(&trace).unwrap();
        for private in [
            "private-trust-sentinel",
            "private-environment-sentinel",
            directory.path().to_str().unwrap(),
            &input.public.descriptor.native_fingerprint,
        ] {
            assert!(!text.contains(private), "private input in trace");
        }
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for name in [
            "external_cli.run",
            "adapter.package.prepare",
            "adapter.package.inspect",
            "adapter.snapshot",
            "adapter.compile",
            "adapter.execute",
        ] {
            assert!(
                records.iter().any(|record| {
                    record["span"]["name"] == name
                        && record["fields"]["message"] == "close"
                        && record["fields"]["time.busy"].is_string()
                        && record["fields"]["time.idle"].is_string()
                }),
                "missing closed span {name}"
            );
        }
        assert!(records.iter().any(|record| {
            record["span"]["name"] == "adapter.execute"
                && record["spans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|parent| parent["name"] == "adapter.compile")
        }));
    } else {
        assert!(!trace.exists());
    }
    let mut wrong = trust.clone();
    wrong.executable.sha256 = "00".repeat(32);
    assert!(prepare(&wrong).is_err());
    wrong = trust.clone();
    wrong.adapter_selection_sha256 = "00".repeat(32);
    assert!(prepare(&wrong).is_err());
    fs::write(directory.path().join("seed-blocks.bin"), [0u8; 10]).unwrap();
    assert!(prepare(&trust).is_err());
    // Structural metadata inspection needs neither the binary nor its slots.
    fs::remove_file(directory.path().join("host-adapter")).unwrap();
    PublicPackage::from_json(&metadata, &trust.package).unwrap();
}

#[test]
fn staged_requests_bind_semantic_config_across_yaml_and_json_formats() {
    use std::{fs, process::Command};
    use zdn::{
        config::{ChainSelection, Config, ServicePreset, Size, Source},
        devnet::external::ExternalRequest,
        image::{self, ImageCapabilities, ImageProvenance, ImageRecord},
    };
    let (directory, _, metadata, trust) = public_package();
    let root = directory.path();
    fs::write(root.join("package.json"), &metadata).unwrap();
    fs::write(root.join("trust.json"), serde_json::to_vec(&trust).unwrap()).unwrap();
    let compiled: Compiled =
        serde_json::from_slice(&fs::read(root.join("compiled.json")).unwrap()).unwrap();
    let requirements = compiled.image_requirements().unwrap();
    let image_config = serde_json::to_vec(&json!({
        "architecture":"amd64", "os":"linux",
        "config":{"Env":[format!("FEATURES={}", requirements.cargo_features.join(","))]},
        "rootfs":{"type":"layers", "diff_ids":[format!("sha256:{}", "ab".repeat(32))]}
    }))
    .unwrap();
    let image_manifest = serde_json::to_vec(&json!({
        "schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json", "digest":format!("sha256:{}",Pin::of(&image_config).sha256), "size":image_config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip", "digest":format!("sha256:{}", "cd".repeat(32)), "size":1}]
    })).unwrap();
    let image = ImageRecord {
        api_version: image::FEATURE_API_VERSION.into(),
        image: format!(
            "registry.example/fixture@sha256:{}",
            Pin::of(&image_manifest).sha256
        ),
        config_digest: format!("sha256:{}", Pin::of(&image_config).sha256),
        platform: "linux/amd64".into(),
        provenance: ImageProvenance::Release {
            revision: "ab".repeat(20),
            version: "v1.0.0".into(),
        },
        capabilities: ImageCapabilities::for_requirements(requirements).unwrap(),
        binary_path: image::NODE_BINARY.into(),
        environment_launcher: image::ENV_ENTRYPOINT.into(),
    };
    fs::write(root.join("image.json"), serde_json::to_vec(&image).unwrap()).unwrap();
    fs::write(root.join("image-config.json"), image_config).unwrap();
    fs::write(root.join("image-manifest.json"), image_manifest).unwrap();
    // Data-only ELF header; stage checks it but never executes it or an image.
    let mut helper = [0; 64];
    helper[..4].copy_from_slice(b"\x7fELF");
    helper[4] = 2;
    helper[5] = 1;
    helper[16..18].copy_from_slice(&2u16.to_le_bytes());
    helper[18..20].copy_from_slice(&62u16.to_le_bytes());
    fs::write(root.join("zdn"), helper).unwrap();
    let mut config = Config::draft(
        "external-fixture".into(),
        "developer".into(),
        Source {
            image: Some(image.image),
            ..Default::default()
        },
        Size::Medium,
    )
    .unwrap();
    config.services = ServicePreset::NodeOnly.services();
    config.chain = Some(ChainSelection::External {
        package_sha256: trust.package.sha256,
        adapter_selection_sha256: trust.adapter_selection_sha256,
        production_limits: None,
    });
    let yaml = serde_yaml::to_string(&config).unwrap();
    fs::write(root.join("external.yaml"), &yaml).unwrap();
    let output = root.join("staged");
    let result = Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .args(["external", "stage", "--public-directory"])
        .arg(root)
        .arg("--trust")
        .arg(root.join("trust.json"))
        .arg("--config")
        .arg(root.join("external.yaml"))
        .arg("--image-record")
        .arg(root.join("image.json"))
        .arg("--image-manifest")
        .arg(root.join("image-manifest.json"))
        .arg("--image-config")
        .arg(root.join("image-config.json"))
        .arg("--host-helper")
        .arg(root.join("zdn"))
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let request =
        ExternalRequest::from_slice(&fs::read(output.join("external-request.json")).unwrap())
            .unwrap();
    assert_ne!(request.config_sha256, Pin::of(yaml.as_bytes()).sha256);
    for text in [
        yaml.clone(),
        format!("# Formatting does not change identity\n{yaml}"),
        serde_json::to_string_pretty(&config).unwrap(),
    ] {
        let parsed: Config = serde_yaml::from_str(&text).unwrap();
        request.require_config(&parsed).unwrap();
    }
    config.name = "different-config".into();
    assert!(request.require_config(&config).is_err());
}

#[test]
fn external_startup_returns_the_client_authenticated_after_cookie_creation_or_rotation() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        cell::Cell,
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use zdn::{chain::rpc::Clock, public_chain_adapter::package::PreparedExternalChain};

    struct StartupClock {
        elapsed: Cell<Duration>,
        cookie: std::path::PathBuf,
    }
    impl Clock for StartupClock {
        fn elapsed(&self) -> Duration {
            self.elapsed.get()
        }
        fn sleep(&self, duration: Duration) {
            self.elapsed.set(self.elapsed.get() + duration);
            fs::write(&self.cookie, "__cookie__:current").unwrap();
            fs::set_permissions(&self.cookie, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    let (directory, _, metadata, trust) = public_package();
    let prepared = PreparedExternalChain::prepare(
        &metadata,
        directory.path(),
        &trust,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
    )
    .unwrap();
    for stale_cookie in [false, true] {
        let cookie = directory.path().join("cookie");
        if stale_cookie {
            fs::write(&cookie, "__cookie__:old").unwrap();
            fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let expected_rules = prepared.compiled().expected_rules.clone();
        let server = std::thread::spawn(move || {
            // One rejected stale credential, then startup and the operational
            // rule check. Missing-cookie startup never connects before retry.
            for attempt in 0..if stale_cookie { 3 } else { 2 } {
                let deadline = Instant::now() + Duration::from_secs(3);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(accepted) => break accepted,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing expected RPC request");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("RPC fixture accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    headers.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["method"], "getchainrules");
                let unauthorized = stale_cookie && attempt == 0;
                let expected = if unauthorized {
                    "__cookie__:old"
                } else {
                    "__cookie__:current"
                };
                assert!(headers.contains(&format!("Basic {}", STANDARD.encode(expected))));
                let response = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0", "id":request["id"], "result":expected_rules}),
                )
                .unwrap();
                write!(
                    stream,
                    "HTTP/1.1 {} Reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if unauthorized { 401 } else { 200 },
                    response.len()
                )
                .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let clock = StartupClock {
            elapsed: Cell::new(Duration::ZERO),
            cookie: cookie.clone(),
        };
        let rpc = prepared
            .wait_for_rpc(
                &endpoint,
                &cookie,
                &clock,
                Duration::from_secs(1),
                Duration::from_secs(3),
            )
            .unwrap();
        prepared.verify_rules(&rpc, Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        assert_eq!(clock.elapsed(), Duration::from_secs(1));
        fs::remove_file(cookie).unwrap();
    }

    let cookie = directory.path().join("unsafe-cookie");
    fs::write(&cookie, "__cookie__:current").unwrap();
    fs::set_permissions(&cookie, fs::Permissions::from_mode(0o644)).unwrap();
    let clock = StartupClock {
        elapsed: Cell::new(Duration::ZERO),
        cookie: cookie.clone(),
    };
    assert!(prepared
        .wait_for_rpc(
            "127.0.0.1:1",
            &cookie,
            &clock,
            Duration::from_secs(1),
            Duration::from_secs(3)
        )
        .is_err());
    assert_eq!(clock.elapsed(), Duration::ZERO);
}
