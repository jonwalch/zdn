#![cfg(target_os = "linux")]
//! Extends handoff_{export,import}: explicit external dispatch, with inert public
//! files only. The companion is deliberately not executable (nor is the ELF
//! header fixture a program). No node, Docker, cloud, downloads or builds.
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Read, path::Path};
use uuid::Uuid;
use zdn::{
    access::DeploymentAccess,
    aws::{LocalProfile, TeamAws, TeamDefinition, TeamState},
    config::Size,
    devnet::{external::ExternalRequest, Artifact},
    foundation::{external::ExternalDeployment, Deployment, DeploymentFile},
    handoff::{self, Manifest, EXTERNAL_API_VERSION},
    image::{self, ImageCapabilities, ImageProvenance, ImageRecord},
    infra::FoundationSpec,
    public_chain_adapter::{
        contract::*,
        package::{CoreTrust, PublicPackage},
        TrustedExecutable,
    },
    state::{Binding, BindingContext, OperationInput, PhaseStatus, Scope, StateStore},
};

fn artifact(bytes: &[u8]) -> Artifact {
    Artifact {
        sha256: zdn::devnet::sha256(bytes),
        bytes: bytes.len() as u64,
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", zdn::devnet::sha256(bytes))
}

fn public_files() -> (ExternalRequest, BTreeMap<String, Vec<u8>>) {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let descriptor = Descriptor {
        schema: SCHEMA.into(),
        native_name: "Fixture".into(),
        native_fingerprint: "ab".repeat(32),
    };
    files.insert(
        "descriptor.json".into(),
        serde_json::to_vec(&descriptor).unwrap(),
    );
    files.insert(
        "native-rules.json".into(),
        serde_json::to_vec(&rules()).unwrap(),
    );
    files.insert("wallet-profile.json".into(), b"{}".to_vec());
    let bundle = [
        1_u32.to_le_bytes().as_slice(),
        b"a",
        1_u32.to_le_bytes().as_slice(),
        b"b",
    ]
    .concat();
    files.insert("seed-blocks.bin".into(), bundle.clone());
    files.insert(
        "host-adapter".into(),
        b"not an executable; handoff must never run this".to_vec(),
    );
    let compiled = Compiled {
        schema: SCHEMA.into(),
        native_name: descriptor.native_name,
        native_fingerprint: descriptor.native_fingerprint,
        expected_rules: json!({"rules":{"checkpoints":[{"height":0,"hash":"ab".repeat(32)},{"height":1,"hash":"cd".repeat(32)}],"activationHeights":[{"height":0,"upgrade":"BeforeOverwinter"}],"genesisHash":"ab".repeat(32)}}),
        upgrades: vec![Upgrade {
            name: "BeforeOverwinter".into(),
            branch_id: "00000000".into(),
            activation_height: 0,
        }],
        seed_blocks: vec![
            SeedBlock {
                height: 0,
                hash: "ab".repeat(32),
                pin: Pin::of(b"a"),
            },
            SeedBlock {
                height: 1,
                hash: "cd".repeat(32),
                pin: Pin::of(b"b"),
            },
        ],
        cargo_features: vec!["experimental-slh-dsa-b128s".into()],
        required_capabilities: vec![
            "native-managed-identity-v1".into(),
            "slh-dsa-b128s-v2".into(),
        ],
        transport_class: "large-hex-v1".into(),
    };
    files.insert(
        "compiled.json".into(),
        serde_json::to_vec(&compiled).unwrap(),
    );
    let selection = TrustedExecutable {
        adapter_id: "fixture".into(),
        adapter_version: "1".into(),
        prepared_input_schema: "fixture/v1".into(),
        adapter_selection_sha256: "12".repeat(32),
        executable_sha256: zdn::devnet::sha256(&files["host-adapter"]),
        executable_bytes: files["host-adapter"].len() as u64,
    };
    let package = PublicPackage {
        schema: "zdn-external-package/v1".into(),
        source_url: "https://example.invalid/fixture".into(),
        source_revision: "ab".repeat(20),
        license: "MIT".into(),
        host_platform: "linux/amd64".into(),
        host_adapter: selection,
        prepared_chain_source: Pin::of(b"public source"),
        prepared_profile_source: Pin::of(b"public profile"),
        descriptor: Pin::of(&files["descriptor.json"]),
        native_rules: Pin::of(&files["native-rules.json"]),
        seed_bundle: Pin::of(&bundle),
        wallet_profile: Pin::of(&files["wallet-profile.json"]),
        compiled_result: Pin::of(&files["compiled.json"]),
    };
    files.insert("package.json".into(), serde_json::to_vec(&package).unwrap());
    let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux",
        "config":{"Env":["FEATURES=experimental-slh-dsa-b128s"],"Volumes":null,"OnBuild":null},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","ab".repeat(32))]}}))
    .unwrap();
    let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","cd".repeat(32)),"size":123}]})).unwrap();
    let image = ImageRecord {
        api_version: image::FEATURE_API_VERSION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/team/node@{}",
            digest(&manifest)
        ),
        config_digest: digest(&config),
        platform: "linux/amd64".into(),
        provenance: ImageProvenance::Release {
            revision: "ab".repeat(20),
            version: "v1.0.0".into(),
        },
        capabilities: ImageCapabilities::for_requirements(compiled.image_requirements().unwrap())
            .unwrap(),
        binary_path: image::NODE_BINARY.into(),
        environment_launcher: image::ENV_ENTRYPOINT.into(),
    };
    files.insert("image.json".into(), serde_json::to_vec(&image).unwrap());
    files.insert("image-manifest.json".into(), manifest);
    files.insert("image-config.json".into(), config);
    let mut elf = vec![0; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[16] = 2;
    elf[18] = 62;
    files.insert("zdn".into(), elf);
    let request = ExternalRequest {
        schema: zdn::devnet::external::SCHEMA.into(),
        config_sha256: "ab".repeat(32),
        trust: CoreTrust {
            package: Pin::of(&files["package.json"]),
            adapter_selection_sha256: "12".repeat(32),
            executable: Pin::of(&files["host-adapter"]),
        },
        compiled,
        image,
        build: None,
        node_count: 1,
        block_interval_seconds: 25,
        production_limits: None,
        artifacts: files
            .iter()
            .map(|(n, b)| (n.clone(), artifact(b)))
            .collect(),
    };
    request.validate().unwrap();
    (request, files)
}

struct Fixture {
    root: tempfile::TempDir,
    store: StateStore,
    binding: Binding,
    context: BindingContext,
    profile: LocalProfile,
    directory: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let scope = Scope {
            team_id: "team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let mut team = TeamDefinition {
            api_version: zdn::access::TEAM_ROLE_API_VERSION.into(),
            team_id: scope.team_id.clone(),
            revision: 1,
            bootstrap_id: Uuid::new_v4(),
            aws: TeamAws {
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
            },
            state: TeamState {
                backend: "s3://zdn-handoff-fixture/pulumi/team".into(),
                kms_key_arn:
                    "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"
                        .into(),
            },
            deployment: None,
        };
        team.deployment = Some(DeploymentAccess::managed(&team));
        fs::create_dir(root.path().join("source")).unwrap();
        let config = root.path().join("source/network.yaml");
        fs::write(&config, "name: fixture\n").unwrap();
        let context = BindingContext::new(config, None, None, scope.clone()).unwrap();
        let store = StateStore::open(root.path().join("sender")).unwrap();
        let binding = store.bind(&context, "fixture").unwrap();
        let mut deployment = Deployment::new(
            FoundationSpec {
                scope,
                network_id: binding.network_id,
                aws_profile: "fixture".into(),
                ami_id: "ami-0123456789abcdef0".into(),
                availability_zone: "us-east-1a".into(),
                size: Size::Medium,
                retain_chain_disk: true,
            },
            team.clone(),
        )
        .unwrap();
        let (request, files) = public_files();
        deployment.external =
            Some(ExternalDeployment::new(request.clone(), 18233, "tFixture".into()).unwrap());
        let file = DeploymentFile::open(store.root(), binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        let directory = file.directory().to_owned();
        fs::create_dir(directory.join("artifacts")).unwrap();
        for (name, bytes) in files {
            fs::write(directory.join("artifacts").join(name), bytes).unwrap();
        }
        fs::write(
            directory.join("artifacts/external-request.json"),
            request.bytes().unwrap(),
        )
        .unwrap();
        Self {
            root,
            store,
            binding,
            context,
            profile: LocalProfile {
                aws_profile: "fixture".into(),
                team,
            },
            directory,
        }
    }

    fn export(&self, name: &str) -> (std::path::PathBuf, String) {
        let output = self.root.path().join(name);
        let hash = handoff::export::export(&self.store, &self.binding, &output).unwrap();
        (output, hash)
    }

    fn manifest(&self) -> Manifest {
        let (path, _) = self.export("manifest.tar");
        let mut archive = tar::Archive::new(fs::File::open(path).unwrap());
        let mut bytes = Vec::new();
        archive
            .entries()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[test]
fn external_staging_roundtrips_without_executable_companion_or_original_paths() {
    let fixture = Fixture::new();
    let (path, hash) = fixture.export("external.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    let imported = handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash,
    )
    .unwrap();
    assert_eq!(imported.network_id, fixture.binding.network_id);
    let original =
        DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).unwrap();
    let saved = DeploymentFile::read_snapshot(receiver.root(), fixture.binding.network_id).unwrap();
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        serde_json::to_value(saved).unwrap()
    );
    assert!(handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash
    )
    .is_err());
    // Import is inert; a second export remains byte-identical despite relocation.
    let second = fixture.root.path().join("relocated.tar");
    assert_eq!(
        hash,
        handoff::export::export(&receiver, &imported, &second).unwrap()
    );
}

#[test]
fn external_version_and_closed_inventory_do_not_fall_into_ordinary_preparation() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest();
    assert_eq!(manifest.api_version, EXTERNAL_API_VERSION);
    manifest.validate().unwrap();
    let mut wrong_version = manifest.clone();
    wrong_version.api_version = handoff::API_VERSION.into();
    assert!(wrong_version.validate().is_err());
    for path in [
        "artifacts/.cookie",
        "artifacts/wallet.dat",
        "artifacts/../package.json",
        "artifacts/private/key",
        "native-inventory/node-2.json",
        "node-2-external-runtime.json",
        "updates/a/completed.json",
        "external-updates/../intent.json",
        "external-updates/00000000-0000-4000-8000-000000000000/private.json",
        "external-controls/../intent.json",
        "external-controls/00000000-0000-4000-8000-000000000000/private.json",
        "external-controls/00000000-0000-4000-8000-000000000000/command.json.lock",
        "external-controls/00000000-0000-4000-8000-00000000000A/intent.json",
        "external-source/public/private",
        "node-1-external-observe-../x.json",
    ] {
        assert!(manifest.file_limit(path).is_err(), "accepted {path}");
    }
    let mut missing = manifest.clone();
    missing.files.remove("artifacts/compiled.json");
    assert!(missing.validate().is_err());
    let mut changed = manifest.clone();
    changed
        .files
        .get_mut("artifacts/host-adapter")
        .unwrap()
        .sha256 = "ff".repeat(32);
    assert!(changed.validate().is_err());
}

#[test]
fn changed_public_bytes_and_uninventoried_directories_refuse_publication() {
    for (name, directory) in [
        ("artifacts/private", true),
        ("state", true),
        ("artifacts/.cookie", false),
    ] {
        let fixture = Fixture::new();
        let path = fixture.directory.join(name);
        if directory {
            fs::create_dir(&path).unwrap();
            fs::write(path.join("secret"), "never portable").unwrap();
        } else {
            fs::write(path, "never portable").unwrap();
        }
        let output = fixture.root.path().join("refused.tar");
        assert!(handoff::export::export(&fixture.store, &fixture.binding, &output).is_err());
        assert!(!output.exists());
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.directory.join("artifacts/seed-blocks.bin"),
        b"changed",
    )
    .unwrap();
    let output = fixture.root.path().join("refused.tar");
    assert!(handoff::export::export(&fixture.store, &fixture.binding, &output).is_err());
    assert!(!output.exists());
}

#[test]
fn private_controller_workspaces_are_not_exported_and_links_are_refused() {
    let fixture = Fixture::new();
    for name in ["credentials", "project", "diagnostics", "health"] {
        fs::create_dir(fixture.directory.join(name)).unwrap();
        fs::write(fixture.directory.join(name).join("secret"), "not portable").unwrap();
    }
    fs::create_dir(fixture.directory.join("health/private")).unwrap();
    fs::write(fixture.directory.join("health/private/.cookie"), "secret").unwrap();
    std::os::unix::fs::symlink(
        "/must-not-be-traversed",
        fixture.directory.join("health/observations"),
    )
    .unwrap();
    let manifest = fixture.manifest();
    assert_eq!(manifest.files.len(), 12);
    assert!(!manifest
        .files
        .keys()
        .any(|path| path.starts_with("health/")));
    assert!(manifest.file_limit("health/observation.json").is_err());
    fs::remove_dir_all(fixture.directory.join("health")).unwrap();
    std::os::unix::fs::symlink(
        fixture.directory.join("diagnostics"),
        fixture.directory.join("health"),
    )
    .unwrap();
    assert!(handoff::export::export(
        &fixture.store,
        &fixture.binding,
        &fixture.root.path().join("health-link.tar")
    )
    .is_err());
    fs::remove_file(fixture.directory.join("health")).unwrap();
    fs::write(fixture.directory.join("health"), "not a directory").unwrap();
    assert!(handoff::export::export(
        &fixture.store,
        &fixture.binding,
        &fixture.root.path().join("health-file.tar")
    )
    .is_err());
    fs::remove_file(fixture.directory.join("health")).unwrap();
    fs::remove_file(fixture.directory.join("artifacts/host-adapter")).unwrap();
    std::os::unix::fs::symlink(
        "/bin/false",
        fixture.directory.join("artifacts/host-adapter"),
    )
    .unwrap();
    assert!(handoff::export::export(
        &fixture.store,
        &fixture.binding,
        &fixture.root.path().join("refused.tar")
    )
    .is_err());
}

fn archive(manifest: &Manifest, directory: &Path, output: &Path) -> String {
    let mut builder = tar::Builder::new(fs::File::create(output).unwrap());
    let bytes = serde_json::to_vec(manifest).unwrap();
    let mut header = tar::Header::new_ustar();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, handoff::MANIFEST_NAME, &bytes[..])
        .unwrap();
    for path in manifest.files.keys() {
        builder
            .append_path_with_name(directory.join(path), path)
            .unwrap();
    }
    builder.finish().unwrap();
    drop(builder);
    zdn::devnet::sha256(&fs::read(output).unwrap())
}

#[test]
fn independently_repinned_but_foreign_request_refuses_before_state_attachment() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest();
    let path = fixture.directory.join("artifacts/external-request.json");
    let mut request: ExternalRequest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    request.config_sha256 = "ff".repeat(32);
    let bytes = request.bytes().unwrap();
    fs::write(&path, &bytes).unwrap();
    manifest
        .files
        .insert("artifacts/external-request.json".into(), artifact(&bytes));
    let output = fixture.root.path().join("tampered.tar");
    let hash = archive(&manifest, &fixture.directory, &output);
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    assert!(handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &output,
        &hash
    )
    .is_err());
    assert!(!receiver
        .root()
        .join("foundation")
        .join(fixture.binding.network_id.to_string())
        .exists());
}

#[test]
fn external_up_receipt_is_not_an_ordinary_up_or_an_incomplete_launch() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest();
    let phases = [
        "verify",
        "reserve",
        "lease",
        "prepare",
        "preview",
        "apply",
        "install",
        "readiness",
    ];
    let operation = fixture
        .store
        .begin_operation(
            &fixture.binding,
            "external-up",
            OperationInput {
                config_sha256: "ab".repeat(32),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &phases,
        )
        .unwrap();
    manifest.deployment.last_operation = Some(operation.operation_id);
    manifest.operations = vec![operation.clone()];
    assert!(manifest.validate().is_err()); // no cloud effects/outputs/evidence may be inferred
    for name in ["external-up", "devnet-up", "foundation-up"] {
        manifest.operations[0].kind = name.into();
        assert!(manifest.validate().is_err());
    }
    manifest.operations[0].phases[0].status = PhaseStatus::Unknown {
        message: "preserve unknown outcome".into(),
        external_ref: None,
    };
    manifest.deployment.unresolved_operation = Some(operation.operation_id);
    assert!(manifest.validate().is_err());
}

fn rules() -> Value {
    json!({"network_name":"Fixture","network_magic":[1,2,3,4],"genesis_hash":"ab".repeat(32),"target_difficulty_limit":"ff".repeat(32),"disable_pow":true,"slow_start_interval":0,"max_block_time_start_height":1,"should_allow_unshielded_coinbase_spends":true,"activation_heights":{"NU7":102},"pre_blossom_halving_interval":144,"funding_streams":[],"lockbox_disbursements":[{"address":"fixture","amount":0}],"checkpoints":[[0,vec![0xab;32]],[1,vec![0xcd;32]]],"experimental_slh_dsa_b128s_activation_height":103,"experimental_slh_dsa_b128s_max_checks_per_transaction":16,"experimental_slh_dsa_b128s_max_checks_per_block":64})
}

fn rendered(options: &RenderOptions, identity: bool) -> String {
    let o = options;
    let peers: Vec<_> = o
        .peers
        .iter()
        .map(|p| format!("{}@{}", p.node_id, p.endpoint))
        .collect();
    let mut config = json!({
        "network":{"network":rules(),"p2p_stack":"zakura","listen_addr":o.native_listen,"identity_dir":o.identity_dir,"initial_mainnet_peers":[],"initial_testnet_peers":[],"cache_dir":false,"zakura":{"listen_addr":o.native_listen,"bootstrap_peers":peers,"nat_traversal":false,"expected_node_id":o.expected_node_id}},
        "state":{"cache_dir":o.state_dir,"ephemeral":false,"should_backup_non_finalized_state":true,"delete_old_database":false,"storage_mode":"archive"},
        "consensus":{"checkpoint_sync":true,"vct_fast_sync":false},"mempool":{"debug_enable_at_height":0},
        "rpc":{"listen_addr":o.rpc_listen,"cookie_dir":o.cookie_dir,"cookie_file_name":".cookie","enable_cookie_auth":true,"debug_force_finished_sync":false},
        "mining":{"internal_miner":false,"optimistic_block_inventory":false},"tracing":{"use_color":false,"force_use_color":false,"use_journald":false},"zcashd_compat":{"enabled":false}});
    if identity {
        config["network"]["zakura"]
            .as_object_mut()
            .unwrap()
            .remove("expected_node_id");
    }
    if let Some(reward) = &o.reward_address {
        config["mining"]["miner_address"] = json!(reward);
    }
    toml::to_string_pretty(&config).unwrap()
}

fn save_json(root: &Path, name: &str, value: &impl serde::Serialize) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn save_journal(root: &Path, name: &str, script: &str, timeout: u32, output: Value) {
    let id = Uuid::new_v4();
    let instance = "i-00000000000000001";
    let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],"TimeoutSeconds":timeout.min(120),"MaxConcurrency":"1","MaxErrors":"0","CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},"Parameters":{"commands":[script],"executionTimeout":[timeout.to_string()],"workingDirectory":["/"]}});
    save_json(
        root,
        name,
        &json!({"apiVersion":"zdn-ssm-command/v1alpha1","instanceId":instance,"timeoutSecs":timeout,"requestSha256":zdn::devnet::sha256(&serde_json::to_vec(&request).unwrap()),"attempts":[{"id":id,"createdAt":1800000000_u64,"comment":format!("zdn-command-{id}"),"commandId":Uuid::new_v4(),"state":"succeeded","uncertain":false,"cancellationRequested":false,"failure":null,"output":output}]}),
    );
}

fn save_installer(
    fixture: &Fixture,
    deployment: &Deployment,
    stem: &str,
    journal: &str,
    script: &str,
    output: Value,
) {
    fs::write(fixture.directory.join(format!("{stem}-install.sh")), script).unwrap();
    let object = zdn::host::S3Object {
        bucket: deployment.team.backend_bucket().unwrap().into(),
        key: format!(
            "{}{}/{stem}-install.sh",
            zdn::devnet::artifact_prefix(&deployment.team, &deployment.spec),
            zdn::devnet::sha256(script.as_bytes())
        ),
        sha256: zdn::devnet::sha256(script.as_bytes()),
        bytes: script.len() as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    };
    let fetch = zdn::foundation_live::selected_fetch_installer(deployment, &object, 7200).unwrap();
    save_journal(&fixture.directory, journal, &fetch, 7200, output);
}

impl Fixture {
    fn completed(&self) -> zdn::host::external::runtime::Manifest {
        use zdn::{
            host::external::{identity, runtime, Provisioning},
            native_peers::{NativeCohort, NativeInventoryStore},
        };
        let file = DeploymentFile::open(self.store.root(), self.binding.network_id).unwrap();
        let mut deployment = file.load().unwrap();
        let external = deployment.external.as_ref().unwrap();
        let request = external.typed_request().unwrap();
        let node = deployment.node_topology().unwrap().nodes().remove(0);
        let node = zdn::cluster_infra::ClusterNodeOutputs {
            node_id: node.node_id,
            instance_id: "i-00000000000000001".into(),
            private_ip: node.private_ip,
            volume_id: "vol-00000000000000001".into(),
        };
        let outputs = zdn::infra::FoundationOutputs {
            schema_version: 1,
            scope: deployment.spec.scope.clone(),
            network_id: deployment.spec.network_id,
            availability_zone: deployment.spec.availability_zone.clone(),
            vpc_id: "vpc-12345678".into(),
            private_subnet_id: "subnet-12345678".into(),
            instance_id: node.instance_id.clone(),
            private_ip: node.private_ip,
            chain_volume_id: node.volume_id.clone(),
            retain_chain_disk: true,
            security_group_id: "sg-12345678".into(),
            nat_gateway_id: "nat-12345678".into(),
            eip_allocation_id: "eipalloc-12345678".into(),
            nodes: BTreeMap::from([("node-1".into(), node.clone())]),
            lightwallet: None,
        };
        let cohort = NativeCohort::new(
            deployment.spec.network_id,
            request.artifacts["descriptor.json"].sha256.clone(),
            request.compiled.native_fingerprint.clone(),
            &external.topology().unwrap(),
            &outputs.nodes,
            external.listener().unwrap(),
        )
        .unwrap();
        let store =
            NativeInventoryStore::open(&self.directory.join("native-inventory"), cohort.clone())
                .unwrap();
        let public_id = json!({"schema":zdn::native_peers::IDENTITY_SCHEMA,"nodeId":"ef".repeat(32),"chainFingerprint":request.compiled.native_fingerprint});
        let inventory = store
            .record("node-1", &serde_json::to_vec(&public_id).unwrap())
            .unwrap();
        let provisioning = Provisioning {
            schema: "zdn-external-provisioning/v1".into(),
            deployment_id: deployment.spec.network_id,
            node_id: node.node_id.clone(),
            volume_id: node.volume_id,
            descriptor_sha256: request.artifacts["descriptor.json"].sha256.clone(),
            native_fingerprint: request.compiled.native_fingerprint.clone(),
            request: Pin::of(&request.bytes().unwrap()),
            new_volume: None,
        };
        save_json(
            &self.directory,
            "node-1-external-provisioning.json",
            &provisioning,
        );
        let root = provisioning.node_root();
        let mut options = RenderOptions {
            deployment_id: deployment.spec.network_id.to_string(),
            node_id: "node-1".into(),
            role: "follower".into(),
            image_digest: request.image.manifest_digest().unwrap().into(),
            state_dir: format!("{root}/state"),
            identity_dir: format!("{root}/identity"),
            cookie_dir: format!("{root}/rpc"),
            rpc_listen: "127.0.0.1:18232".into(),
            native_listen: "0.0.0.0:18233".into(),
            expected_node_id: String::new(),
            peers: vec![],
            reward_address: None,
        };
        let config_toml = rendered(&options, true);
        let identity = identity::Manifest {
            schema: identity::SCHEMA.into(),
            provisioning: provisioning.clone(),
            request: request.clone(),
            sources: request.objects(&deployment.team, &deployment.spec).unwrap(),
            options: options.clone(),
            config: Pin::of(config_toml.as_bytes()),
            config_toml,
        };
        save_json(&self.directory, "node-1-external-identity.json", &identity);
        save_installer(
            self,
            &deployment,
            "node-1-external-identity",
            "node-1-external-identity-command.json",
            &zdn::host::runtime::bootstrap::render_external_identity(&identity).unwrap(),
            public_id,
        );
        inventory.bind_render_options(&mut options).unwrap();
        options.role = "producer".into();
        options.reward_address = Some("tFixture".into());
        let config_toml = rendered(&options, false);
        let allocation = deployment.spec.size.allocation();
        let runtime = runtime::Manifest {
            schema: runtime::SCHEMA.into(),
            provisioning,
            chain: zdn::host::external::Manifest {
                schema: zdn::host::external::SCHEMA.into(),
                request: Pin::of(&request.bytes().unwrap()),
                trust: request.trust.clone(),
                objects: request.objects(&deployment.team, &deployment.spec).unwrap(),
                compiled_json: String::from_utf8(serde_json::to_vec(&request.compiled).unwrap())
                    .unwrap(),
                native_inventory: inventory.pin().unwrap(),
                options,
                config: Pin::of(config_toml.as_bytes()),
                config_toml,
            },
            image: request.image.clone(),
            memory_bytes: u64::from(allocation.max_node_gib) * zdn::infra::GIB,
            cpu_millis: allocation.vcpus * 1000 - zdn::infra::HOST_CPU_RESERVE_MILLIS,
            host_reserve_bytes: u64::from(allocation.host_reserve_gib) * zdn::infra::GIB,
            block_interval_seconds: Some(25),
            production_limits: request.production_limits.clone(),
        };
        save_json(&self.directory, "node-1-external-runtime.json", &runtime);
        let observation = json!({"observation":runtime.observation("ready").unwrap(),"readiness":{"apiVersion":zdn::chain::readiness::API_VERSION,"consensusFingerprint":request.compiled.native_fingerprint,"role":"producer","effectiveRulesVerified":true,"historyPresent":true,"miningReady":true,"launchReady":false},"producer":{"controllerLocked":true,"identity":runtime.producer_identity(),"intervalSecs":25,"phase":"waiting"}});
        save_installer(
            self,
            &deployment,
            "node-1-external-runtime",
            "node-1-external-install-command.json",
            &zdn::foundation_live::external::runtime_script(&runtime, "install").unwrap(),
            observation.clone(),
        );
        save_journal(
            &self.directory,
            "node-1-external-start-producer-command.json",
            &zdn::foundation_live::external::runtime_script(&runtime, "start-producer").unwrap(),
            7200,
            observation,
        );
        let gateway = json!({"apiVersion":zdn::client_gateway::OBSERVATION_API_VERSION,"deploymentId":runtime.provisioning.deployment_id,"nodeId":"node-1","consensusFingerprint":request.compiled.native_fingerprint,"serviceSha256":runtime.chain.gateway_service_sha256().unwrap(),"endpoint":zdn::client_gateway::ENDPOINT,"status":"ready"});
        save_journal(
            &self.directory,
            "node-1-external-gateway-install-command.json",
            &zdn::foundation_live::external::runtime_script(&runtime, "gateway-install").unwrap(),
            600,
            gateway,
        );
        save_json(
            &self.directory,
            "external-evidence.json",
            &json!({"schema":runtime::SCHEMA,"request":Pin::of(&request.bytes().unwrap()),"cohort":cohort.pin().unwrap(),"inventory":inventory.pin().unwrap(),"inventoryJson":serde_json::to_string(&inventory).unwrap(),"pendingIdentity":null,"manifests":{"node-1":Pin::of(&runtime.bytes().unwrap())},"pendingUpdate":null,"activeImages":{}}),
        );
        deployment.outputs = Some(outputs);
        deployment.stack_initialized = true;
        let phases = [
            "verify",
            "reserve",
            "lease",
            "prepare",
            "preview",
            "apply",
            "install",
            "readiness",
        ];
        let config_sha256 = zdn::devnet::sha256(
            &serde_json::to_vec(&(
                &deployment.spec,
                &deployment.team,
                deployment.owner_id,
                Option::<bool>::None,
                deployment.external.as_ref().unwrap(),
            ))
            .unwrap(),
        );
        let mut operation = self
            .store
            .begin_operation(
                &self.binding,
                "external-up",
                OperationInput {
                    config_sha256,
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                &phases,
            )
            .unwrap();
        for name in phases {
            operation = self
                .store
                .record_phase(
                    operation.operation_id,
                    operation.revision,
                    name,
                    PhaseStatus::Running { external_ref: None },
                )
                .unwrap();
            operation = self
                .store
                .record_phase(
                    operation.operation_id,
                    operation.revision,
                    name,
                    PhaseStatus::Succeeded { result: json!({}) },
                )
                .unwrap();
        }
        deployment.last_operation = Some(operation.operation_id);
        file.save(&deployment).unwrap();
        let endpoints =
            zdn::foundation_live::external::endpoint_file(&deployment, &self.directory).unwrap();
        save_json(&self.directory, "client-endpoints.json", &endpoints);
        runtime
    }
}

#[test]
fn completed_external_up_exports_exact_native_cohort_and_rejects_changed_ssm_authority() {
    let fixture = Fixture::new();
    fixture.completed();
    let manifest = fixture.manifest();
    manifest.verify_directory(&fixture.directory).unwrap();
    assert_eq!(manifest.operations.last().unwrap().kind, "external-up");
    for name in [
        "native-inventory/cohort.json",
        "native-inventory/node-1.json",
        "node-1-external-runtime.json",
        "node-1-external-identity-command.json",
    ] {
        assert!(manifest.files.contains_key(name));
    }
    let path = fixture
        .directory
        .join("node-1-external-install-command.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["instanceId"] = json!("i-00000000000000002");
    save_json(
        &fixture.directory,
        "node-1-external-install-command.json",
        &value,
    );
    let mut changed = manifest.clone();
    changed.files.insert(
        "node-1-external-install-command.json".into(),
        artifact(&fs::read(path).unwrap()),
    );
    assert!(changed.verify_directory(&fixture.directory).is_err());
}

// Match the controller's typed serialization order: operation_inputs deliberately
// binds canonical structs rather than JSON object key order or whitespace.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIntent {
    schema: String,
    id: Uuid,
    deployment_id: Uuid,
    request: Pin,
    image: ImageRecord,
    artifacts: BTreeMap<String, Artifact>,
    nodes: BTreeMap<String, Pin>,
}

fn stage_update(
    fixture: &Fixture,
    runtime: &zdn::host::external::runtime::Manifest,
    predecessor: Option<Uuid>,
) -> (zdn::host::external::runtime::update::Request, Vec<u8>) {
    let id = Uuid::new_v4();
    let prefix = format!("external-updates/{id}");
    let request = zdn::host::external::runtime::update::Request {
        schema: zdn::host::external::runtime::update::SCHEMA.into(),
        original: runtime.clone(),
        update_id: id,
        expected_image: runtime.image.image.clone(),
        expected_update_id: predecessor,
        target: runtime.clone(),
    };
    let mut artifacts = BTreeMap::new();
    let mut target = request.target.clone();
    target.image =
        serde_json::from_slice(&fs::read(fixture.directory.join("artifacts/image.json")).unwrap())
            .unwrap();
    for (name, object) in [
        ("image.json", &mut target.chain.objects.image_record),
        (
            "image-manifest.json",
            &mut target.chain.objects.image_manifest,
        ),
        ("image-config.json", &mut target.chain.objects.image_config),
    ] {
        let bytes = fs::read(fixture.directory.join("artifacts").join(name)).unwrap();
        save_bytes(&fixture.directory, &format!("{prefix}/{name}"), &bytes);
        artifacts.insert(name.to_owned(), artifact(&bytes));
        let deployment =
            DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id)
                .unwrap();
        object.sha256 = zdn::devnet::sha256(&bytes);
        object.bytes = bytes.len() as u64;
        object.key = format!(
            "{}{}/{name}",
            zdn::devnet::artifact_prefix(&deployment.team, &deployment.spec),
            object.sha256
        );
    }
    let request = zdn::host::external::runtime::update::Request { target, ..request };
    let bytes = request.bytes().unwrap();
    save_bytes(
        &fixture.directory,
        &format!("{prefix}/node-1-request.json"),
        &bytes,
    );
    let intent = UpdateIntent {
        schema: zdn::host::external::runtime::update::SCHEMA.into(),
        id,
        deployment_id: fixture.binding.network_id,
        request: runtime.chain.request.clone(),
        image: request.target.image.clone(),
        artifacts,
        nodes: BTreeMap::from([("node-1".into(), Pin::of(&bytes))]),
    };
    // Pretty-printing is accepted; the receipt below uses canonical bytes.
    save_bytes(
        &fixture.directory,
        &format!("{prefix}/intent.json"),
        &serde_json::to_vec_pretty(&intent).unwrap(),
    );
    let mut evidence: Value = serde_json::from_slice(
        &fs::read(fixture.directory.join("external-evidence.json")).unwrap(),
    )
    .unwrap();
    evidence["pendingUpdate"] = json!(id);
    save_json(&fixture.directory, "external-evidence.json", &evidence);
    (request, serde_json::to_vec(&intent).unwrap())
}

fn complete_update(
    fixture: &Fixture,
    runtime: &zdn::host::external::runtime::Manifest,
    predecessor: Option<Uuid>,
) -> Uuid {
    let (update, input) = stage_update(fixture, runtime, predecessor);
    let id = update.update_id;
    let prefix = format!("external-updates/{id}");
    let file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    let mut deployment = file.load().unwrap();
    save_installer(
        fixture,
        &deployment,
        &format!("node-1-external-update-{id}"),
        &format!("{prefix}/node-1-command.json"),
        &update.render().unwrap(),
        json!({"schema":zdn::host::external::runtime::update::SCHEMA,"updateId":id,"phase":"done","runtime":Pin::of(&update.target.bytes().unwrap())}),
    );
    let mut evidence: Value = serde_json::from_slice(
        &fs::read(fixture.directory.join("external-evidence.json")).unwrap(),
    )
    .unwrap();
    evidence["pendingUpdate"] = Value::Null;
    evidence["activeImages"]["node-1"] = json!({"updateId":id,"image":update.target.image.image,"runtime":Pin::of(&update.target.bytes().unwrap())});
    save_json(&fixture.directory, "external-evidence.json", &evidence);
    let endpoints = zdn::endpoints::EndpointFile::from_external(
        deployment.spec.scope.clone(),
        deployment.team.bootstrap_id,
        1,
        deployment.outputs.as_ref().unwrap().nodes["node-1"]
            .instance_id
            .clone(),
        &update.target.chain,
    )
    .unwrap();
    save_json(
        &fixture.directory,
        &format!("{prefix}/client-endpoints.json"),
        &endpoints,
    );
    save_json(&fixture.directory, "client-endpoints.json", &endpoints);
    let phases = [
        "verify",
        "reserve",
        "lease",
        "preflight",
        "build",
        "update",
        "readiness",
    ];
    let mut operation = fixture
        .store
        .begin_operation(
            &fixture.binding,
            "external-update",
            zdn::foundation_live::external::update::operation_inputs(&deployment, &input, None)
                .unwrap(),
            &phases,
        )
        .unwrap();
    for name in phases {
        operation = fixture
            .store
            .record_phase(
                operation.operation_id,
                operation.revision,
                name,
                PhaseStatus::Running { external_ref: None },
            )
            .unwrap();
        operation = fixture
            .store
            .record_phase(
                operation.operation_id,
                operation.revision,
                name,
                PhaseStatus::Succeeded {
                    result: if name == "update" {
                        json!({"updateId":id,"nodes":["node-1"]})
                    } else {
                        json!({})
                    },
                },
            )
            .unwrap();
    }
    deployment.last_operation = Some(operation.operation_id);
    file.save(&deployment).unwrap();
    id
}

#[test]
fn completed_external_updates_bind_all_retained_receipts_and_refuse_repinned_omission() {
    let fixture = Fixture::new();
    let runtime = fixture.completed();
    let original_endpoints = fs::read(fixture.directory.join("client-endpoints.json")).unwrap();
    let first = complete_update(&fixture, &runtime, None);
    complete_update(&fixture, &runtime, Some(first));
    let manifest = fixture.manifest();
    manifest.verify_directory(&fixture.directory).unwrap();
    let (path, hash) = fixture.export("completed-updates.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    let imported = handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash,
    )
    .unwrap();
    let reexport = fixture.root.path().join("completed-relocated.tar");
    assert_eq!(
        hash,
        handoff::export::export(&receiver, &imported, &reexport).unwrap()
    );
    let historical = manifest
        .operations
        .iter()
        .position(|operation| operation.kind == "external-update")
        .unwrap();
    assert_ne!(
        Some(manifest.operations[historical].operation_id),
        manifest.deployment.last_operation
    );
    let mut changed = manifest.clone();
    changed.operations[historical].inputs.config_sha256 = "ff".repeat(32);
    assert!(changed.verify_directory(&fixture.directory).is_err());
    for result in [
        json!({"updateId":Uuid::new_v4(),"nodes":["node-1"]}),
        json!({"updateId":first,"nodes":["node-2"]}),
    ] {
        let mut changed = manifest.clone();
        changed.operations[historical]
            .phases
            .iter_mut()
            .find(|phase| phase.name == "update")
            .unwrap()
            .status = PhaseStatus::Succeeded { result };
        assert!(changed.verify_directory(&fixture.directory).is_err());
    }
    // Remove both whole revision directories and their top-level scripts,
    // roll back public endpoints/active pins, then independently repin the tar.
    let mut stripped = manifest.clone();
    stripped.files.retain(|path, _| {
        !path.starts_with("external-updates/") && !path.contains("-external-update-")
    });
    let mut evidence: Value = serde_json::from_slice(
        &fs::read(fixture.directory.join("external-evidence.json")).unwrap(),
    )
    .unwrap();
    evidence["activeImages"] = json!({});
    save_json(&fixture.directory, "external-evidence.json", &evidence);
    save_bytes(
        &fixture.directory,
        "client-endpoints.json",
        &original_endpoints,
    );
    for path in ["external-evidence.json", "client-endpoints.json"] {
        stripped.files.insert(
            path.into(),
            artifact(&fs::read(fixture.directory.join(path)).unwrap()),
        );
    }
    // Repeat with last_operation pointing to the original up receipt: retained
    // successful history, not just the latest receipt, must prevent rollback.
    let up = manifest
        .operations
        .iter()
        .find(|operation| operation.kind == "external-up")
        .unwrap()
        .operation_id;
    for (name, last) in [
        ("stripped-latest", manifest.deployment.last_operation),
        ("stripped-history", Some(up)),
    ] {
        stripped.deployment.last_operation = last;
        let output = fixture.root.path().join(format!("{name}.tar"));
        let hash = archive(&stripped, &fixture.directory, &output);
        let receiver = StateStore::open(fixture.root.path().join(name)).unwrap();
        assert!(handoff::import::import(
            &receiver,
            &fixture.context,
            fixture.binding.network_id,
            &fixture.profile,
            &output,
            &hash,
        )
        .is_err());
        assert!(!receiver
            .root()
            .join("foundation")
            .join(fixture.binding.network_id.to_string())
            .exists());
    }
}

#[test]
fn staged_external_update_is_portable_but_pending_selection_is_not_cleared() {
    let fixture = Fixture::new();
    let runtime = fixture.completed();
    let (update, _) = stage_update(&fixture, &runtime, None);
    let id = update.update_id;
    let (path, hash) = fixture.export("pending.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash,
    )
    .unwrap();
    let imported: Value = serde_json::from_slice(
        &fs::read(
            receiver
                .root()
                .join("foundation")
                .join(fixture.binding.network_id.to_string())
                .join("external-evidence.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(imported["pendingUpdate"], json!(id));
}

fn save_bytes(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

impl Fixture {
    fn source_preparation(&self) {
        use zdn::{
            config::{ChainSelection, Config, Source},
            foundation::external::source::{self, SourcePreparation},
            source::{SnapshotMode, SnapshotReceipt},
        };
        let file = DeploymentFile::open(self.store.root(), self.binding.network_id).unwrap();
        let mut deployment = file.load().unwrap();
        let request = deployment.external.take().unwrap().typed_request().unwrap();
        let mut config = Config::draft(
            "fixture".into(),
            "fixture".into(),
            Source {
                path: Some("/does-not-exist/never-opened".into()),
                ..Default::default()
            },
            Size::Medium,
        )
        .unwrap();
        config.chain = Some(ChainSelection::External {
            package_sha256: request.trust.package.sha256.clone(),
            adapter_selection_sha256: request.trust.adapter_selection_sha256.clone(),
            production_limits: request.production_limits.clone(),
        });
        config.services = zdn::config::ServicePreset::NodeOnly.services();
        let mut builder = tar::Builder::new(Vec::new());
        let bytes = b"FROM scratch\n";
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "docker/Dockerfile", &bytes[..])
            .unwrap();
        let archive = builder.into_inner().unwrap();
        let receipt = SnapshotReceipt {
            schema_version: 1,
            source_root: "/does-not-exist/never-opened".into(),
            mode: SnapshotMode::Revision,
            head: "ab".repeat(20),
            branch: None,
            dirty: false,
            files: vec![],
            deleted_paths: vec![],
            omitted_untracked: vec![],
            excluded_paths: vec![],
            archive_sha256: zdn::devnet::sha256(&archive),
            archive_bytes: archive.len() as u64,
        };
        let mut contract =
            zdn::build::BuildContract::new(&receipt, config.node.build.as_ref().unwrap()).unwrap();
        contract
            .require_external(&request.validate().unwrap())
            .unwrap();
        let artifacts = source::limits()
            .into_keys()
            .map(|n| (n.clone(), request.artifacts[&n].clone()))
            .collect();
        let preparation = SourcePreparation {
            schema: source::SCHEMA.into(),
            deployment_sha256: zdn::devnet::sha256(
                &serde_json::to_vec(&(&deployment.spec, &deployment.team, deployment.owner_id))
                    .unwrap(),
            ),
            config,
            trust: serde_json::to_value(&request.trust).unwrap(),
            compiled_json: serde_json::to_string(&request.compiled).unwrap(),
            contract: contract.clone(),
            artifacts,
            native_port: 18233,
            reward_address: "tFixture".into(),
        };
        let root = self.directory.join(source::ROOT);
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("public")).unwrap();
        for name in source::limits().into_keys() {
            fs::copy(
                self.directory.join("artifacts").join(&name),
                root.join("public").join(name),
            )
            .unwrap();
        }
        save_bytes(&root, "source-snapshot/source.tar", &archive);
        save_json(&root, "source-snapshot/receipt.json", &receipt);
        // Local attempt creation only: no exporter/companion is executed and no
        // CodeBuild submission is made (both "executables" are inert files).
        zdn::build_job::prepare_native(
            &root.join("build"),
            &deployment.team,
            &contract,
            &root.join("public/zdn"),
        )
        .unwrap();
        save_json(&root, source::FILE, &preparation);
        save_json(&self.directory, source::FILE, &preparation);
        deployment.external_source = Some(preparation);
        file.save(&deployment).unwrap();
        fs::remove_dir_all(self.directory.join("artifacts")).unwrap();
    }
}

#[test]
fn external_source_unknown_submission_roundtrips_exact_journal_and_archive_without_checkout() {
    let fixture = Fixture::new();
    fixture.source_preparation();
    let path = fixture.directory.join("external-source/build/attempt.json");
    let mut attempt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    attempt["dispatched"] = json!(true);
    attempt["sourceVersion"] = json!("source-version");
    attempt["exporter"]["version"] = json!("exporter-version");
    save_json(
        &fixture.directory,
        "external-source/build/attempt.json",
        &attempt,
    );
    let original = fs::read(&path).unwrap();
    let (archive, hash) = fixture.export("source.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &archive,
        &hash,
    )
    .unwrap();
    let directory = receiver
        .root()
        .join("foundation")
        .join(fixture.binding.network_id.to_string());
    assert_eq!(
        original,
        fs::read(directory.join("external-source/build/attempt.json")).unwrap()
    );
    let deployment =
        DeploymentFile::read_snapshot(receiver.root(), fixture.binding.network_id).unwrap();
    assert!(deployment.external.is_none());
    assert!(deployment.external_source.is_some());
    assert!(deployment.require_native_execution().is_err());
    assert!(zdn::build_job::removal_evidence(
        &directory.join("external-source/build"),
        &deployment.team
    )
    .is_err());
}

#[test]
fn external_source_atomic_publication_crash_is_portable_and_changed_archive_refuses() {
    let fixture = Fixture::new();
    fixture.source_preparation();
    let file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    let mut deployment = file.load().unwrap();
    deployment.external_source = None;
    file.save(&deployment).unwrap();
    drop(file);
    fs::remove_file(fixture.directory.join("external-source-preparation.json")).unwrap();
    let manifest = fixture.manifest();
    assert!(manifest.deployment.external_source.is_some());
    manifest.verify_directory(&fixture.directory).unwrap();
    let profiles = fixture.store.root().join("profiles");
    zdn::foundation::private_directory(&profiles).unwrap();
    zdn::foundation::write_json(&profiles.join("fixture.json"), &fixture.profile).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .args(["devnet", "handoff", "export"])
        .arg(fixture.binding.network_id.to_string())
        .args(["--profile", "fixture", "--state-dir"])
        .arg(fixture.store.root())
        .arg("--output")
        .arg(fixture.root.path().join("cli-handoff.tar"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["apiVersion"], EXTERNAL_API_VERSION);
    assert_eq!(result["cloudAccessChecked"], false);
    assert!(!fixture
        .directory
        .join("external-source-preparation.json")
        .exists());
    let path = fixture
        .directory
        .join("external-source/source-snapshot/source.tar");
    fs::write(&path, b"foreign archive").unwrap();
    let mut changed = manifest;
    changed.files.insert(
        "external-source/source-snapshot/source.tar".into(),
        artifact(b"foreign archive"),
    );
    assert!(changed.verify_directory(&fixture.directory).is_err());
}

fn save_control(
    fixture: &Fixture,
    original: &zdn::host::external::runtime::Manifest,
    active: &zdn::host::external::runtime::Manifest,
    action: zdn::host::external::runtime::qualification::Action,
    complete: bool,
) -> Uuid {
    use zdn::{
        foundation_live::external::qualification::{read_only, Intent},
        host::external::runtime::qualification::{Request, SCHEMA},
    };
    let file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    let mut deployment = file.load().unwrap();
    let mutating = !read_only(&action);
    let id = Uuid::new_v4();
    let intent = Intent {
        schema: SCHEMA.into(),
        owner: Pin::of(
            &serde_json::to_vec(&(
                &deployment.spec,
                &deployment.team,
                deployment.owner_id,
                &deployment.external,
                &deployment.outputs,
            ))
            .unwrap(),
        ),
        node_id: "node-1".into(),
        instance_id: deployment.outputs.as_ref().unwrap().nodes["node-1"]
            .instance_id
            .clone(),
        original: Pin::of(&original.bytes().unwrap()),
        request: Request {
            schema: SCHEMA.into(),
            id,
            runtime: Pin::of(&active.bytes().unwrap()),
            action,
        },
    };
    let prefix = format!("external-controls/{id}");
    save_json(
        &fixture.directory,
        &format!("{prefix}/intent.json"),
        &intent,
    );
    let script = intent.request.render(original).unwrap();
    save_bytes(
        &fixture.directory,
        &format!("{prefix}/control.sh"),
        script.as_bytes(),
    );
    let response = json!({"schema":SCHEMA,"request":Pin::of(&intent.request.bytes().unwrap()),
        "runtime":intent.request.runtime,"deploymentId":active.provisioning.deployment_id,
        "nodeId":"node-1","nativeInventory":active.chain.native_inventory,
        "result":{"fixture":true}});
    let journal = format!("{prefix}/command.json");
    save_journal(
        &fixture.directory,
        &journal,
        &script,
        1200,
        response.clone(),
    );
    save_bytes(&fixture.directory, &format!("{journal}.lock"), b"");
    if !complete {
        let mut value: Value =
            serde_json::from_slice(&fs::read(fixture.directory.join(&journal)).unwrap()).unwrap();
        value["attempts"][0]["state"] = json!("running");
        value["attempts"][0]["uncertain"] = json!(true);
        value["attempts"][0]["output"] = Value::Null;
        save_json(&fixture.directory, &journal, &value);
    }
    let phases = ["verify", "reserve", "lease", "control", "release"];
    let mut operation = fixture
        .store
        .begin_operation_with_id(
            &fixture.binding,
            "external-control",
            OperationInput {
                config_sha256: zdn::devnet::sha256(&serde_json::to_vec(&intent).unwrap()),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &phases,
            id,
        )
        .unwrap();
    for phase in phases {
        operation = fixture
            .store
            .record_phase(
                id,
                operation.revision,
                phase,
                PhaseStatus::Running { external_ref: None },
            )
            .unwrap();
        let status = if phase == "control" && !complete {
            PhaseStatus::Unknown {
                message: "preserve uncertain control".into(),
                external_ref: None,
            }
        } else {
            PhaseStatus::Succeeded {
                result: if phase == "control" {
                    response.clone()
                } else {
                    json!({})
                },
            }
        };
        operation = fixture
            .store
            .record_phase(id, operation.revision, phase, status)
            .unwrap();
        if phase == "control" && !complete {
            break;
        }
    }
    if mutating {
        deployment.last_operation = Some(id);
        deployment.unresolved_operation = (!complete).then_some(id);
        file.save(&deployment).unwrap();
    }
    id
}

#[test]
fn external_controls_roundtrip_original_and_historical_updated_runtime_queries() {
    use zdn::host::external::runtime::qualification::{Action, Query};
    let fixture = Fixture::new();
    let original = fixture.completed();
    let first_control = save_control(
        &fixture,
        &original,
        &original,
        Action::Read { query: Query::Tip },
        true,
    );
    let first_update = complete_distinct_control_update(&fixture, &original, None, "v1.0.1");
    let update: zdn::host::external::runtime::update::Request = serde_json::from_slice(
        &fs::read(fixture.directory.join(format!(
            "external-updates/{first_update}/node-1-request.json"
        )))
        .unwrap(),
    )
    .unwrap();
    let historical = save_control(
        &fixture,
        &original,
        &update.target,
        Action::Read {
            query: Query::BlockHash { height: 7 },
        },
        true,
    );
    complete_distinct_control_update(&fixture, &original, Some(first_update), "v1.0.2");
    let manifest = fixture.manifest();
    manifest.verify_directory(&fixture.directory).unwrap();
    assert!(!manifest.files.keys().any(|p| p.ends_with(".lock")));
    assert_ne!(manifest.deployment.last_operation, Some(historical));
    assert!(manifest.deployment.unresolved_operation.is_none());
    let file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    assert!(zdn::foundation_live::external::qualification::load(
        &file.load().unwrap(),
        &fixture.directory,
        first_control
    )
    .is_err());
    drop(file);
    let (path, hash) = fixture.export("historical-controls.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    let imported = handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash,
    )
    .unwrap();
    let relocated = fixture.root.path().join("historical-relocated.tar");
    assert_eq!(
        hash,
        handoff::export::export(&receiver, &imported, &relocated).unwrap()
    );
    for id in [first_control, historical] {
        let mut stripped = manifest.clone();
        stripped
            .files
            .retain(|p, _| !p.starts_with(&format!("external-controls/{id}/")));
        assert!(stripped.verify_directory(&fixture.directory).is_err());
    }
}

#[test]
fn external_control_rejects_repinned_scripts_results_and_foreign_intents() {
    use zdn::{
        foundation_live::external::qualification::Intent,
        host::external::runtime::qualification::Action,
    };
    let fixture = Fixture::new();
    let runtime = fixture.completed();
    let id = save_control(&fixture, &runtime, &runtime, Action::StopProducer, true);
    let manifest = fixture.manifest();
    assert_eq!(manifest.deployment.last_operation, Some(id));
    manifest.verify_directory(&fixture.directory).unwrap();
    let prefix = format!("external-controls/{id}");
    for name in ["control.sh", "command.json", "intent.json"] {
        let path = format!("{prefix}/{name}");
        let original = fs::read(fixture.directory.join(&path)).unwrap();
        let bytes = if name == "control.sh" {
            b"#!/bin/bash\nexit 0\n".to_vec()
        } else if name == "command.json" {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            value["attempts"][0]["output"]["request"]["sha256"] = json!("ff".repeat(32));
            serde_json::to_vec(&value).unwrap()
        } else {
            let mut intent: Intent = serde_json::from_slice(&original).unwrap();
            intent.owner.sha256 = "ff".repeat(32);
            serde_json::to_vec(&intent).unwrap()
        };
        save_bytes(&fixture.directory, &path, &bytes);
        let mut changed = manifest.clone();
        changed.files.insert(path.clone(), artifact(&bytes));
        if name == "intent.json" {
            changed
                .operations
                .iter_mut()
                .find(|o| o.operation_id == id)
                .unwrap()
                .inputs
                .config_sha256 = zdn::devnet::sha256(&bytes);
        }
        assert!(
            changed.verify_directory(&fixture.directory).is_err(),
            "{name}"
        );
        save_bytes(&fixture.directory, &path, &original);
    }
    for alteration in 0..4 {
        let mut changed = manifest.clone();
        let operation = changed
            .operations
            .iter_mut()
            .find(|o| o.operation_id == id)
            .unwrap();
        match alteration {
            0 => operation.inputs.archive_sha256 = Some("ff".repeat(32)),
            1 => operation.phases[3].name = "update".into(),
            2 => {
                if let PhaseStatus::Succeeded { result } = &mut operation.phases[3].status {
                    result["result"] = json!({"foreign":true});
                }
            }
            _ => {
                changed.operations.retain(|o| o.operation_id != id);
                changed.deployment.last_operation = manifest
                    .operations
                    .iter()
                    .find(|o| o.kind == "external-up")
                    .map(|o| o.operation_id);
            }
        }
        assert!(changed.verify_directory(&fixture.directory).is_err());
    }
    for name in ["intent.json", "control.sh", "command.json"] {
        let mut changed = manifest.clone();
        changed.files.remove(&format!("{prefix}/{name}"));
        assert!(changed.verify_directory(&fixture.directory).is_err());
    }
}

#[test]
fn unresolved_external_control_preserves_unknown_journal_and_active_binding() {
    use zdn::host::external::runtime::qualification::{Action, Query};
    let fixture = Fixture::new();
    let runtime = fixture.completed();
    let id = save_control(&fixture, &runtime, &runtime, Action::RestartNode, false);
    // Fresh reads must not displace an unresolved mutation's pointers.
    save_control(
        &fixture,
        &runtime,
        &runtime,
        Action::Read { query: Query::Tip },
        true,
    );
    let manifest = fixture.manifest();
    assert_eq!(manifest.deployment.last_operation, Some(id));
    assert_eq!(manifest.deployment.unresolved_operation, Some(id));
    manifest.verify_directory(&fixture.directory).unwrap();
    let mut detached = manifest.clone();
    detached.deployment.unresolved_operation = None;
    detached.deployment.last_operation = detached
        .operations
        .iter()
        .find(|o| o.kind == "external-up")
        .map(|o| o.operation_id);
    assert!(detached.verify_directory(&fixture.directory).is_err());
    let mut rebound = manifest.clone();
    rebound
        .operations
        .iter_mut()
        .find(|o| o.operation_id == id)
        .unwrap()
        .inputs
        .config_sha256 = "ff".repeat(32);
    assert!(rebound.verify_directory(&fixture.directory).is_err());
    let journal = format!("external-controls/{id}/command.json");
    let original = fs::read(fixture.directory.join(&journal)).unwrap();
    let (path, hash) = fixture.export("unknown-control.tar");
    let receiver = StateStore::open(fixture.root.path().join("receiver")).unwrap();
    handoff::import::import(
        &receiver,
        &fixture.context,
        fixture.binding.network_id,
        &fixture.profile,
        &path,
        &hash,
    )
    .unwrap();
    let file = DeploymentFile::open(receiver.root(), fixture.binding.network_id).unwrap();
    assert_eq!(file.load().unwrap().unresolved_operation, Some(id));
    assert_eq!(fs::read(file.directory().join(&journal)).unwrap(), original);
    // An unresolved control may not be laundered into historical-runtime
    // evidence after a newer confirmed update becomes active.
    complete_distinct_control_update(&fixture, &runtime, None, "v1.0.1");
    let file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    let mut deployment = file.load().unwrap();
    deployment.last_operation = Some(id);
    deployment.unresolved_operation = Some(id);
    file.save(&deployment).unwrap();
    assert!(handoff::export::export(
        &fixture.store,
        &fixture.binding,
        &fixture.root.path().join("stale-unknown.tar")
    )
    .is_err());
}

// Different authenticated image-record metadata yields distinct runtime pins
// while retaining the tiny fixed OCI config/layer fixtures (no image builds).
fn complete_distinct_control_update(
    fixture: &Fixture,
    original: &zdn::host::external::runtime::Manifest,
    predecessor: Option<Uuid>,
    version: &str,
) -> Uuid {
    let path = fixture.directory.join("artifacts/image.json");
    let bytes = fs::read(&path).unwrap();
    let mut image: ImageRecord = serde_json::from_slice(&bytes).unwrap();
    image.provenance = ImageProvenance::Release {
        revision: "ab".repeat(20),
        version: version.into(),
    };
    fs::write(&path, serde_json::to_vec(&image).unwrap()).unwrap();
    let id = complete_update(fixture, original, predecessor);
    fs::write(path, bytes).unwrap();
    id
}

#[test]
fn external_handoff_binds_request_production_limits_and_updates_preserve_them() {
    let fixture = Fixture::new();
    let original = fixture.completed();
    let mut manifest = fixture.manifest();
    let mut changed = original.clone();
    changed.production_limits = Some(zdn::config::ExternalProductionLimits {
        max_height: 100,
        lifetime_seconds: 60,
    });
    // A bounded replacement is valid in isolation, not authority to change the
    // deployment's saved request, even after repinning its local evidence.
    let bytes = changed.bytes().unwrap();
    let path = "node-1-external-runtime.json";
    save_bytes(&fixture.directory, path, &bytes);
    manifest.files.insert(path.into(), artifact(&bytes));
    let path = "external-evidence.json";
    let mut evidence: Value =
        serde_json::from_slice(&fs::read(fixture.directory.join(path)).unwrap()).unwrap();
    evidence["manifests"]["node-1"] = json!(Pin::of(&bytes));
    let bytes = serde_json::to_vec(&evidence).unwrap();
    save_bytes(&fixture.directory, path, &bytes);
    manifest.files.insert(path.into(), artifact(&bytes));
    assert!(manifest.verify_directory(&fixture.directory).is_err());
    let update = zdn::host::external::runtime::update::Request {
        schema: zdn::host::external::runtime::update::SCHEMA.into(),
        update_id: Uuid::new_v4(),
        expected_image: original.image.image.clone(),
        expected_update_id: None,
        original,
        target: changed,
    };
    assert!(update.bytes().is_err());
}
