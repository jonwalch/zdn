//! Data-only staging fixtures follow the independent patterns in image.rs and
//! chain_artifacts.rs. The tiny block and ELF bytes are never executed and do
//! not qualify a node, image, or chain.

use std::{cell::RefCell, collections::BTreeMap, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;
use zdn::{
    access::{DeploymentAccess, TEAM_ROLE_API_VERSION},
    aws::{AwsApi, AwsApiError, TeamAws, TeamDefinition, TeamState},
    chain::{artifacts::import_bundle, manifest::ConsensusManifest, runtime_config::NodeRole},
    config::{Config, Size, Source},
    devnet::{self, ClusterRequest, InputPaths},
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
    infra::FoundationSpec,
    state::Scope,
};

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

#[cfg(unix)]
#[path = "support/machine_failure.rs"]
mod machine_failure;

#[cfg(unix)]
#[path = "support/native_tool.rs"]
mod native_tool;
#[cfg(unix)]
#[path = "support/source_build_aws.rs"]
mod source_build_aws;

#[cfg(unix)]
#[path = "support/native_exec.rs"]
mod native_exec;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn native_manifest(host: &zdn::host::HostInstallSpec) -> zdn::host::runtime::Manifest {
    zdn::host::runtime::Manifest::new(
        host.clone(),
        zdn::host::runtime::Selection {
            protocol: zdn::host::runtime::PROTOCOL.into(),
            helper: host.helper.clone(),
        },
    )
    .unwrap()
}

fn native_command(host: &zdn::host::HostInstallSpec, gateway: bool, operation: &str) -> String {
    let manifest = native_manifest(host);
    let (entrypoint, protocol) = if gateway {
        ("__client-gateway", zdn::client_gateway::native::PROTOCOL)
    } else {
        ("__host-runtime", zdn::host::runtime::PROTOCOL)
    };
    format!(
        "/etc/zdn/runtime/{}/zdn {entrypoint} --protocol {protocol} --manifest /etc/zdn/runtime/manifests/{} {operation}",
        host.helper.sha256, manifest.file_name().unwrap()
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

#[test]
fn update_source_config_allows_only_source_and_build_fields() {
    let fixture = Fixture::new();
    let original = &fixture.config;
    let mut candidate = original.clone();
    candidate.node.source.revision = Some("candidate-revision".into());
    zdn::foundation::update_controller::validate_source_config(original, &candidate).unwrap();
    for change in ["name", "resources", "services", "access"] {
        let mut changed = candidate.clone();
        match change {
            "name" => changed.name.push_str("-other"),
            "resources" => changed.node.resources.preset = Size::Large,
            "services" => changed.services.lightwallet = !changed.services.lightwallet,
            "access" => changed.access.visibility = zdn::config::Visibility::Public,
            _ => unreachable!(),
        }
        assert!(
            zdn::foundation::update_controller::validate_source_config(original, &changed).is_err(),
            "{change}"
        );
    }
}

fn helper_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes
}

#[test]
fn staged_helper_binds_all_bytes_across_stream_chunks_and_immutable_retries() {
    let fixture = Fixture::new();
    let mut helper = helper_bytes();
    helper.extend((0..150_001).map(|n| (n % 251) as u8));
    fs::write(&fixture.helper, &helper).unwrap();
    let request = fixture.stage().unwrap();
    assert_eq!(request.artifacts["zdn"].bytes, helper.len() as u64);
    assert_eq!(request.artifacts["zdn"].sha256, sha256(&helper));
    assert_eq!(
        fs::read(fixture.output.join("artifacts/zdn")).unwrap(),
        helper
    );
    let retry = fixture.stage().unwrap();
    assert_eq!(retry.artifacts, request.artifacts);

    // Caller mutations cannot replace the private saved snapshot on a retry.
    *helper.last_mut().unwrap() ^= 1;
    fs::write(&fixture.helper, &helper).unwrap();
    assert!(fixture.stage().is_err());
    request.verify_local(&fixture.output).unwrap();

    // A valid ELF prefix must not hide corruption beyond the first hash chunk.
    fs::write(fixture.output.join("artifacts/zdn"), &helper).unwrap();
    assert!(request.verify_local(&fixture.output).is_err());
    fs::write(fixture.output.join("artifacts/zdn"), &helper[..64]).unwrap();
    assert!(request.verify_local(&fixture.output).is_err());
}

struct Fixture {
    root: TempDir,
    output: PathBuf,
    manifest: PathBuf,
    bundle: PathBuf,
    image_record: PathBuf,
    image_manifest: PathBuf,
    image_config: PathBuf,
    helper: PathBuf,
    config: Config,
    team: TeamDefinition,
    spec: FoundationSpec,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blocks = root.path().join("blocks");
        fs::create_dir(&blocks).unwrap();
        let bytes = b"synthetic genesis, not an encoded block";
        fs::write(blocks.join("0000000000.bin"), bytes).unwrap();
        let mut chain: Value =
            serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
        chain["genesis"] = json!({"height":0,"hash":format!("{:064x}",1),"bytesSha256":sha256(bytes),"bytesLength":bytes.len()});
        chain["seedBlocks"] = json!([]);
        chain["checkpoints"] = json!([{"height":0,"hash":format!("{:064x}",1)}]);
        let manifest = root.path().join("manifest.json");
        fs::write(&manifest, serde_json::to_vec(&chain).unwrap()).unwrap();
        let bundle = root.path().join("chain.tar");
        let chain: ConsensusManifest = serde_json::from_value(chain).unwrap();
        import_bundle(&chain, &blocks, &bundle).unwrap();

        let config_bytes = serde_json::to_vec(&json!({
            "architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["zakurad"],"Cmd":[],"Volumes":null,"OnBuild":null},
            "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}
        })).unwrap();
        let manifest_bytes = serde_json::to_vec(&json!({
            "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config_bytes),"size":config_bytes.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":123}]
        })).unwrap();
        let image = ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/zakura@{}",
                digest(&manifest_bytes)
            ),
            config_digest: digest(&config_bytes),
            platform: "linux/amd64".into(),
            provenance: ImageProvenance::Release {
                revision: "c".repeat(40),
                version: "v0.0.1".into(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
        };
        let image_record = root.path().join("image.json");
        let image_manifest = root.path().join("image-manifest.json");
        let image_config = root.path().join("image-config.json");
        let helper = root.path().join("zdn");
        fs::write(&image_record, serde_json::to_vec(&image).unwrap()).unwrap();
        fs::write(&image_manifest, manifest_bytes).unwrap();
        fs::write(&image_config, config_bytes).unwrap();
        fs::write(&helper, helper_bytes()).unwrap();
        let mut config = Config::draft(
            "private-feature".into(),
            "private-team".into(),
            Source {
                image: Some(image.image),
                ..Default::default()
            },
            Size::Medium,
        )
        .unwrap();
        config.services = zdn::config::Services {
            wallet: false,
            lightwallet: false,
            faucet: false,
        };
        let scope = Scope {
            team_id: "private-team".into(),
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
        };
        let spec = FoundationSpec {
            scope: scope.clone(),
            network_id: Uuid::parse_str("a81c4e9b-4612-4e0d-a3fa-c4ab68a04153").unwrap(),
            aws_profile: "developer".into(),
            ami_id: "ami-0123456789abcdef0".into(),
            availability_zone: "us-east-1a".into(),
            size: Size::Medium,
            retain_chain_disk: true,
        };
        let mut team = TeamDefinition {
            api_version: TEAM_ROLE_API_VERSION.into(),
            team_id: scope.team_id.clone(),
            revision: 1,
            bootstrap_id: Uuid::parse_str("965f7c13-e186-4d52-b7e3-ef92db98a0ec").unwrap(),
            aws: TeamAws {
                account_id: scope.account_id,
                region: scope.region,
            },
            state: TeamState {
                backend: "s3://zdn-private-team/pulumi/private-team".into(),
                kms_key_arn:
                    "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"
                        .into(),
            },
            deployment: None,
        };
        team.deployment = Some(DeploymentAccess::managed(&team));
        let output = root.path().join("deployment");
        zdn::foundation::private_directory(&output).unwrap();
        Self {
            root,
            output,
            manifest,
            bundle,
            image_record,
            image_manifest,
            image_config,
            helper,
            config,
            team,
            spec,
        }
    }

    fn paths(&self) -> InputPaths<'_> {
        InputPaths {
            build_contract: None,
            manifest: &self.manifest,
            bundle: &self.bundle,
            image_record: &self.image_record,
            image_manifest: &self.image_manifest,
            image_config: &self.image_config,
            helper: &self.helper,
        }
    }

    fn stage(&self) -> Result<ClusterRequest> {
        devnet::stage(
            &self.config,
            &self.spec,
            &self.team,
            &self.paths(),
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
            &self.output,
        )
    }

    fn replace_image_config(&mut self, config: &Value) {
        let bytes = serde_json::to_vec(config).unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&self.image_manifest).unwrap()).unwrap();
        manifest["config"]["digest"] = json!(digest(&bytes));
        manifest["config"]["size"] = json!(bytes.len());
        fs::write(&self.image_config, &bytes).unwrap();
        let mut record: ImageRecord =
            serde_json::from_slice(&fs::read(&self.image_record).unwrap()).unwrap();
        record.config_digest = digest(&bytes);
        self.replace_manifest(record, &manifest);
    }

    fn replace_manifest(&mut self, mut record: ImageRecord, manifest: &Value) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        record.image = format!(
            "{}@{}",
            record.image.split_once('@').unwrap().0,
            digest(&bytes)
        );
        self.config.node.source.image = Some(record.image.clone());
        fs::write(&self.image_record, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::write(&self.image_manifest, bytes).unwrap();
    }
}

struct LightwalletFixture {
    record: PathBuf,
    manifest: PathBuf,
    config: PathBuf,
    inspect: PathBuf,
}

impl LightwalletFixture {
    fn new(fixture: &mut Fixture) -> Self {
        use zdn::lightwallet_image as image;
        fixture.config.services.lightwallet = true;
        let config = json!({"architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["lightwalletd"],"Cmd":["--help"],"WorkingDir":"/srv/lightwalletd"},
            "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}});
        let config_bytes = serde_json::to_vec(&config).unwrap();
        let manifest_bytes = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config_bytes),"size":config_bytes.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":123}]})).unwrap();
        let record = image::ImageRecord {
            api_version: image::API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/lightwalletd@{}",
                digest(&manifest_bytes)
            ),
            config_digest: digest(&config_bytes),
            platform: "linux/amd64".into(),
            source_revision: image::SOURCE_REVISION.into(),
            source_version: image::SOURCE_VERSION.into(),
            protocol_revision: image::PROTOCOL_REVISION.into(),
            protocol_version: image::PROTOCOL_VERSION.into(),
            binary_path: image::BINARY_PATH.into(),
            environment_launcher: image::ENVIRONMENT_LAUNCHER.into(),
        };
        let inspect = json!([{"Id":record.config_digest,"RepoDigests":[record.image],
            "Os":"linux","Architecture":"amd64","Config":config["config"]}]);
        let paths = Self {
            record: fixture.root.path().join("lightwallet-image.json"),
            manifest: fixture.root.path().join("lightwallet-image-manifest.json"),
            config: fixture.root.path().join("lightwallet-image-config.json"),
            inspect: fixture.root.path().join("lightwallet-inspect.json"),
        };
        fs::write(&paths.record, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::write(&paths.manifest, manifest_bytes).unwrap();
        fs::write(&paths.config, config_bytes).unwrap();
        fs::write(&paths.inspect, serde_json::to_vec(&inspect).unwrap()).unwrap();
        paths
    }

    fn paths(&self) -> devnet::LightwalletInputPaths<'_> {
        devnet::LightwalletInputPaths {
            image_record: &self.record,
            image_manifest: &self.manifest,
            image_config: &self.config,
        }
    }

    fn stage(&self, fixture: &Fixture) -> Result<ClusterRequest> {
        devnet::stage_with_lightwallet(
            &fixture.config,
            &fixture.spec,
            &fixture.team,
            &fixture.paths(),
            Some(&self.paths()),
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
            &fixture.output,
        )
    }

    fn cli_inputs(&self) -> Vec<&str> {
        vec![
            "--lightwallet-image-record",
            self.record.to_str().unwrap(),
            "--lightwallet-image-manifest",
            self.manifest.to_str().unwrap(),
            "--lightwallet-image-config",
            self.config.to_str().unwrap(),
        ]
    }
}

#[test]
fn staging_freezes_six_artifacts_and_renders_private_peer_roles() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    assert_eq!(request.artifacts.len(), 6);
    request.verify_local(&fixture.output).unwrap();
    assert_eq!(request.config_sha256, fixture.config.fingerprint().unwrap());
    assert_eq!(
        request.ecr_repository(&fixture.team).unwrap(),
        "zdn/private-team/zakura"
    );
    for node in request.topology().unwrap().nodes() {
        let runtime = request.runtime(&fixture.spec, &node.node_id).unwrap();
        assert_eq!(
            runtime.role,
            if node.producer {
                NodeRole::Producer
            } else {
                NodeRole::Follower
            }
        );
        let config: toml::Value = toml::from_str(&runtime.config_toml).unwrap();
        assert_eq!(
            config["network"]["listen_addr"].as_str(),
            Some(format!("{}:18233", node.private_ip).as_str())
        );
        let peers = config["network"]["initial_testnet_peers"]
            .as_array()
            .unwrap();
        assert_eq!(peers.len(), 2);
        for peer in request.topology().unwrap().peers(&node.node_id).unwrap() {
            assert!(peers.iter().any(|p| p.as_str() == Some(&peer)));
        }
        assert_eq!(
            config["rpc"]["listen_addr"].as_str(),
            Some("127.0.0.1:18232")
        );
    }
    for (name, artifact) in &request.artifacts {
        let bytes = fs::read(devnet::artifact_path(&fixture.output, name)).unwrap();
        assert_eq!(artifact.sha256, sha256(&bytes));
        assert_eq!(artifact.bytes, bytes.len() as u64);
        let object = request
            .s3_object(&fixture.team, &fixture.spec, name)
            .unwrap();
        object.validate().unwrap();
        assert!(object
            .key
            .ends_with(&format!("/{}/{name}", artifact.sha256)));
        assert!(object.key.contains(&fixture.spec.network_id.to_string()));
    }
    // Idempotent preparation preserves existing exact copies.
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        serde_json::to_value(fixture.stage().unwrap()).unwrap()
    );
}

#[test]
fn lightwallet_staging_freezes_nine_artifacts_and_separate_private_cache() {
    let mut fixture = Fixture::new();
    let lightwallet = LightwalletFixture::new(&mut fixture);
    let request = lightwallet.stage(&fixture).unwrap();
    request.verify_local(&fixture.output).unwrap();
    assert_eq!(request.artifacts.len(), 9);
    let service = request.lightwallet.as_ref().unwrap();
    assert_eq!(
        service.image.ecr_repository(&fixture.team).unwrap(),
        "zdn/private-team/lightwalletd"
    );
    assert_eq!(
        service.allocation,
        zdn::cluster_infra::LightwalletAllocation::for_size(Size::Medium)
    );
    for name in [
        "lightwallet-image.json",
        "lightwallet-image-manifest.json",
        "lightwallet-image-config.json",
    ] {
        let bytes = fs::read(devnet::artifact_path(&fixture.output, name)).unwrap();
        let object = request
            .s3_object(&fixture.team, &fixture.spec, name)
            .unwrap();
        assert_eq!(object.sha256, sha256(&bytes));
        assert_eq!(object.bytes, bytes.len() as u64);
        assert!(object.key.contains(&fixture.spec.network_id.to_string()));
    }
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::to_value(lightwallet.stage(&fixture).unwrap()).unwrap()
    );
    let program = request
        .render(fixture.spec.render().unwrap(), &fixture.spec, &fixture.team)
        .unwrap();
    let program = serde_json::to_value(program).unwrap();
    assert_eq!(
        program["resources"]["lightwalletCacheDisk"]["properties"]["size"],
        40
    );
    assert_eq!(
        program["resources"]["lightwalletCacheDisk"]["properties"]["encrypted"],
        true
    );
    assert_eq!(
        program["resources"]["lightwalletCacheDisk"]["options"]["retainOnDelete"],
        true
    );
    assert_eq!(
        program["resources"]["lightwalletCacheAttachment"]["properties"]["instanceId"],
        "${host2.id}"
    );
    assert_eq!(
        program["resources"]["lightwalletCacheAttachment"]["properties"]["deviceName"],
        "/dev/sdg"
    );
    assert_eq!(program["outputs"]["lightwallet"]["node_id"], "node-2");
    assert_eq!(
        program["resources"]
            .as_object()
            .unwrap()
            .values()
            .filter(|r| r["type"] == "aws:ec2:Instance")
            .count(),
        3
    );
    // Existing private group has no lightwallet ingress rule.
    let rules = &program["resources"]["hostSecurityGroup"]["properties"]["ingress"];
    assert!(rules.is_array());
    assert!(!serde_json::to_string(rules).unwrap().contains("9067"));
}

#[test]
fn lightwallet_input_requirements_fail_before_any_artifact_reads_or_publication() {
    for include_paths in [false, true] {
        let mut fixture = Fixture::new();
        let lightwallet = LightwalletFixture::new(&mut fixture);
        fixture.config.services.lightwallet = !include_paths;
        fs::remove_file(&fixture.manifest).unwrap();
        let error = devnet::stage_with_lightwallet(
            &fixture.config,
            &fixture.spec,
            &fixture.team,
            &fixture.paths(),
            include_paths.then(|| lightwallet.paths()).as_ref(),
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
            &fixture.output,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("services.lightwallet requires all three lightwallet image inputs"),
            "{error}"
        );
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }
}

#[test]
fn lightwallet_stage_rejects_foreign_namespace_and_corrupt_metadata_without_writes() {
    for mode in 0..3 {
        let mut fixture = Fixture::new();
        let lightwallet = LightwalletFixture::new(&mut fixture);
        match mode {
            0 => {
                let mut record: Value =
                    serde_json::from_slice(&fs::read(&lightwallet.record).unwrap()).unwrap();
                record["image"] = json!(record["image"]
                    .as_str()
                    .unwrap()
                    .replace("/private-team/", "/another-team/"));
                fs::write(&lightwallet.record, serde_json::to_vec(&record).unwrap()).unwrap();
            }
            1 => fs::write(&lightwallet.manifest, b"{}").unwrap(),
            2 => fs::write(&lightwallet.config, b"{}").unwrap(),
            _ => unreachable!(),
        }
        assert!(lightwallet.stage(&fixture).is_err());
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }
}

#[test]
fn lightwallet_staged_mutations_are_rejected_before_any_upload() {
    for name in [
        "lightwallet-image.json",
        "lightwallet-image-manifest.json",
        "lightwallet-image-config.json",
    ] {
        let mut fixture = Fixture::new();
        let lightwallet = LightwalletFixture::new(&mut fixture);
        let request = lightwallet.stage(&fixture).unwrap();
        let path = devnet::artifact_path(&fixture.output, name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(request.verify_local(&fixture.output).is_err());
        let aws = FakeS3::new(&fixture.team);
        assert!(devnet::upload(
            &aws,
            &request,
            &fixture.spec,
            &fixture.team,
            &fixture.output
        )
        .is_err());
        assert!(aws.calls.borrow().is_empty());
    }
}

#[test]
fn lightwallet_upload_covers_all_immutable_metadata_and_is_retry_safe() {
    let mut fixture = Fixture::new();
    let lightwallet = LightwalletFixture::new(&mut fixture);
    let request = lightwallet.stage(&fixture).unwrap();
    let mut aws = FakeS3::new(&fixture.team);
    aws.lost_put_reply = true;
    assert!(devnet::upload(
        &aws,
        &request,
        &fixture.spec,
        &fixture.team,
        &fixture.output,
    )
    .is_err());
    aws.lost_put_reply = false;
    devnet::upload(
        &aws,
        &request,
        &fixture.spec,
        &fixture.team,
        &fixture.output,
    )
    .unwrap();
    assert_eq!(aws.objects.borrow().len(), 9);
    aws.calls.borrow_mut().clear();
    devnet::upload(
        &aws,
        &request,
        &fixture.spec,
        &fixture.team,
        &fixture.output,
    )
    .unwrap();
    assert_eq!(aws.calls.borrow().as_slice(), ["head-object"; 9]);
}

#[test]
fn lightwallet_ecr_observation_binds_both_repositories_and_child_bytes() {
    struct Images {
        node: Value,
        lightwallet: Value,
        calls: RefCell<Vec<String>>,
    }
    impl AwsApi for Images {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            assert_eq!((service, operation), ("ecr", "batch-get-image"));
            assert!(extra.is_empty());
            assert_eq!(input["registryId"], "123456789012");
            let repository = input["repositoryName"].as_str().unwrap();
            self.calls.borrow_mut().push(repository.into());
            let response = match repository {
                "zdn/private-team/zakura" => &self.node,
                "zdn/private-team/lightwalletd" => &self.lightwallet,
                other => panic!("unexpected repository {other}"),
            };
            if response["failures"] == json!([]) {
                assert_eq!(
                    input["imageIds"][0]["imageDigest"],
                    response["images"][0]["imageId"]["imageDigest"]
                );
            }
            Ok(response.clone())
        }
    }
    let mut fixture = Fixture::new();
    let lightwallet = LightwalletFixture::new(&mut fixture);
    let request = lightwallet.stage(&fixture).unwrap();
    let node_response = json!({"failures":[],"images":[{"imageId":{"imageDigest":request.image.manifest_digest().unwrap()},"imageManifest":fs::read_to_string(&fixture.image_manifest).unwrap()}]});
    let service = request.lightwallet.as_ref().unwrap();
    let lightwallet_response = json!({"failures":[],"images":[{"imageId":{"imageDigest":service.image.manifest_digest().unwrap()},"imageManifest":fs::read_to_string(&lightwallet.manifest).unwrap()}]});
    for mode in 0..3 {
        let mut response = lightwallet_response.clone();
        match mode {
            0 => {}
            1 => response["failures"] = json!([{"failureCode":"ImageNotFound"}]),
            2 => {
                response["images"][0]["imageManifest"] = json!(format!(
                    "{}\n",
                    response["images"][0]["imageManifest"].as_str().unwrap()
                ))
            }
            _ => unreachable!(),
        }
        let aws = Images {
            node: node_response.clone(),
            lightwallet: response,
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            devnet::verify_ecr(&aws, &request, &fixture.team, &fixture.output).is_ok(),
            mode == 0
        );
        assert_eq!(
            aws.calls.borrow().as_slice(),
            ["zdn/private-team/zakura", "zdn/private-team/lightwalletd"]
        );
    }
}

#[test]
fn unsupported_image_platform_index_and_helper_fail_before_artifact_publication() {
    for mode in 0..4 {
        let mut fixture = Fixture::new();
        match mode {
            0 => {
                fixture.config.node.source.image =
                    Some(format!("ghcr.io/other/node@sha256:{}", "d".repeat(64)))
            }
            1 => {
                let mut config: Value =
                    serde_json::from_slice(&fs::read(&fixture.image_config).unwrap()).unwrap();
                config["architecture"] = json!("arm64");
                fixture.replace_image_config(&config);
            }
            2 => {
                let record =
                    serde_json::from_slice(&fs::read(&fixture.image_record).unwrap()).unwrap();
                fixture.replace_manifest(record,&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}));
            }
            3 => fs::write(&fixture.helper, [0xcf, 0xfa, 0xed, 0xfe]).unwrap(),
            _ => unreachable!(),
        }
        assert!(fixture.stage().is_err(), "mode{mode}");
        assert!(!fixture.output.join("artifacts").exists(), "mode{mode}");
    }
}

#[test]
fn staging_rejects_foreign_ecr_namespace_scope_and_unsupported_checkpoints() {
    for mode in 0..4 {
        let mut fixture = Fixture::new();
        match mode {
            0 => {
                let mut record: ImageRecord =
                    serde_json::from_slice(&fs::read(&fixture.image_record).unwrap()).unwrap();
                record.image = record.image.replace("/private-team/", "/other-team/");
                fixture.config.node.source.image = Some(record.image.clone());
                fs::write(&fixture.image_record, serde_json::to_vec(&record).unwrap()).unwrap();
            }
            1 => fixture.spec.scope.team_id = "other-team".into(),
            2 => {
                let mut manifest: ConsensusManifest =
                    serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
                manifest.checkpoints.push(zdn::chain::manifest::Checkpoint {
                    height: 1,
                    hash: format!("{:064x}", 2),
                });
                fs::write(&fixture.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();
                fs::remove_file(&fixture.bundle).unwrap();
                import_bundle(
                    &manifest,
                    &fixture.root.path().join("blocks"),
                    &fixture.bundle,
                )
                .unwrap();
            }
            3 => fixture.config.network.nodes = 4,
            _ => unreachable!(),
        }
        assert!(fixture.stage().is_err(), "mode{mode}");
        assert!(!fixture.output.join("artifacts").exists(), "mode{mode}");
    }
}

#[test]
fn mutation_of_any_saved_input_is_rejected_before_upload() {
    for name in [
        "manifest.json",
        "chain.tar",
        "image.json",
        "image-manifest.json",
        "image-config.json",
        "zdn",
    ] {
        let fixture = Fixture::new();
        let request = fixture.stage().unwrap();
        let path = devnet::artifact_path(&fixture.output, name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(request.verify_local(&fixture.output).is_err(), "{name}");
        let aws = FakeS3::new(&fixture.team);
        assert!(devnet::upload(
            &aws,
            &request,
            &fixture.spec,
            &fixture.team,
            &fixture.output
        )
        .is_err());
        assert!(aws.calls.borrow().is_empty());
    }
}

#[test]
fn helper_header_and_file_size_checks_reject_wrong_machine_and_nonregular_inputs() {
    let valid = helper_bytes();
    devnet::validate_helper(&valid).unwrap();
    for index in [0, 4, 5, 16, 18] {
        let mut changed = valid.clone();
        changed[index] = 0;
        assert!(devnet::validate_helper(&changed).is_err(), "byte{index}");
    }
    assert!(devnet::validate_helper(&valid[..63]).is_err());
    let fixture = Fixture::new();
    assert!(devnet::read_bounded(&fixture.helper, 63).is_err());
    assert!(devnet::read_bounded(fixture.root.path(), 64).is_err());
    #[cfg(unix)]
    {
        let link = fixture.root.path().join("helper-link");
        std::os::unix::fs::symlink(&fixture.helper, &link).unwrap();
        assert!(devnet::read_bounded(&link, 64).is_err());
    }
}

#[derive(Default)]
struct FakeS3 {
    bucket: String,
    owner: String,
    kms: String,
    prefix: String,
    objects: RefCell<BTreeMap<String, Value>>,
    calls: RefCell<Vec<String>>,
    lost_put_reply: bool,
    fail_put: bool,
    fail_key: Option<String>,
    head_error: Option<String>,
}
impl FakeS3 {
    fn new(team: &TeamDefinition) -> Self {
        Self {
            bucket: team.backend_bucket().unwrap().into(),
            owner: team.aws.account_id.clone(),
            kms: team.state.kms_key_arn.clone(),
            prefix: format!("{}/artifacts/", team.metadata_prefix()),
            ..Default::default()
        }
    }
}
impl AwsApi for FakeS3 {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert_eq!(service, "s3api");
        assert!(matches!(operation, "head-object" | "put-object"));
        assert_eq!(input["Bucket"], self.bucket);
        assert_eq!(input["ExpectedBucketOwner"], self.owner);
        let key = input["Key"].as_str().unwrap();
        assert!(key.starts_with(&self.prefix));
        self.calls.borrow_mut().push(operation.into());
        if operation == "head-object" {
            assert!(extra.is_empty());
            assert_eq!(input["ChecksumMode"], "ENABLED");
            if let Some(code) = &self.head_error {
                return Err(AwsApiError { code: code.clone() }.into());
            }
            return self
                .objects
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| AwsApiError { code: "404".into() }.into());
        }
        assert_eq!(extra.len(), 2);
        assert_eq!(extra[0], "--body");
        assert_eq!(input["IfNoneMatch"], "*");
        assert_eq!(input["ServerSideEncryption"], "aws:kms");
        assert_eq!(input["SSEKMSKeyId"], self.kms);
        let bytes = fs::read(&extra[1]).unwrap();
        let checksum = STANDARD.encode(Sha256::digest(&bytes));
        assert_eq!(input["ChecksumSHA256"], checksum);
        assert_eq!(input["Metadata"]["sha256"], sha256(&bytes));
        assert!(
            !self.objects.borrow().contains_key(key),
            "must not overwrite objects"
        );
        let fail_put = self.fail_put || self.fail_key.as_deref() == Some(key);
        if !fail_put {
            self.objects.borrow_mut().insert(key.into(),json!({"ContentLength":bytes.len(),"ChecksumSHA256":checksum,"ServerSideEncryption":"aws:kms","SSEKMSKeyId":self.kms}));
        }
        if self.lost_put_reply || fail_put {
            Err(AwsApiError {
                code: "RequestTimeout".into(),
            }
            .into())
        } else {
            Ok(json!({}))
        }
    }
}

#[test]
fn immutable_upload_uses_owner_kms_and_server_checksum_and_recovers_lost_replies() {
    for lost_put_reply in [false, true] {
        let fixture = Fixture::new();
        let request = fixture.stage().unwrap();
        let mut aws = FakeS3::new(&fixture.team);
        aws.lost_put_reply = lost_put_reply;
        let first = devnet::upload(
            &aws,
            &request,
            &fixture.spec,
            &fixture.team,
            &fixture.output,
        );
        if lost_put_reply {
            assert!(first.is_err());
            assert_eq!(aws.objects.borrow().len(), 1);
            // A lost success is reconciled, while undispatched peers resume.
            assert_eq!(
                aws.calls
                    .borrow()
                    .iter()
                    .filter(|s| *s == "head-object")
                    .count(),
                12
            );
            aws.lost_put_reply = false;
            devnet::upload(
                &aws,
                &request,
                &fixture.spec,
                &fixture.team,
                &fixture.output,
            )
            .unwrap();
        } else {
            first.unwrap();
        }
        assert_eq!(aws.objects.borrow().len(), 6);
        assert_eq!(
            aws.calls
                .borrow()
                .iter()
                .filter(|s| s.as_str() == "put-object")
                .count(),
            6
        );
        aws.calls.borrow_mut().clear();
        devnet::upload(
            &aws,
            &request,
            &fixture.spec,
            &fixture.team,
            &fixture.output,
        )
        .unwrap();
        assert_eq!(aws.calls.borrow().as_slice(), ["head-object"; 6]);
    }
}

#[test]
fn immutable_upload_refuses_remote_corruption_denial_and_failed_puts() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    let object = request
        .s3_object(&fixture.team, &fixture.spec, "zdn")
        .unwrap();
    let path = devnet::artifact_path(&fixture.output, "zdn");
    for (field, value) in [
        ("ContentLength", json!(999)),
        ("ChecksumSHA256", json!("wrong")),
        ("ServerSideEncryption", json!("AES256")),
        ("SSEKMSKeyId", json!("foreign-key")),
    ] {
        let aws = FakeS3::new(&fixture.team);
        devnet::upload_file(&aws, &fixture.team, &object, &path).unwrap();
        aws.calls.borrow_mut().clear();
        aws.objects.borrow_mut().get_mut(&object.key).unwrap()[field] = value;
        assert!(
            devnet::upload_file(&aws, &fixture.team, &object, &path).is_err(),
            "{field}"
        );
        assert_eq!(aws.calls.borrow().as_slice(), ["head-object"]);
    }
    let mut denied = FakeS3::new(&fixture.team);
    denied.head_error = Some("AccessDenied".into());
    assert!(devnet::upload_file(&denied, &fixture.team, &object, &path).is_err());
    assert_eq!(denied.calls.borrow().as_slice(), ["head-object"]);
    let mut failed = FakeS3::new(&fixture.team);
    failed.fail_put = true;
    assert!(devnet::upload_file(&failed, &fixture.team, &object, &path).is_err());
    assert!(failed.objects.borrow().is_empty());
}

#[test]
fn upload_files_validates_the_entire_group_before_remote_calls() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    let mut files: Vec<_> = request
        .artifacts
        .keys()
        .map(|name| {
            (
                request
                    .s3_object(&fixture.team, &fixture.spec, name)
                    .unwrap(),
                devnet::artifact_path(&fixture.output, name),
            )
        })
        .collect();
    let aws = FakeS3::new(&fixture.team);
    files.last_mut().unwrap().0.bytes += 1;
    assert!(devnet::upload_files(&aws, &fixture.team, &files).is_err());
    assert!(aws.calls.borrow().is_empty());
    files.last_mut().unwrap().0.bytes -= 1;
    devnet::upload_files(&aws, &fixture.team, &files).unwrap();
    assert_eq!(aws.objects.borrow().len(), 6);
    assert_eq!(&aws.calls.borrow()[..6], ["head-object"; 6]);

    struct Malformed {
        s3: FakeS3,
        mode: &'static str,
        heads: std::cell::Cell<usize>,
    }
    impl AwsApi for Malformed {
        fn call(
            &self,
            service: &str,
            operation: &str,
            input: Value,
            extra: &[String],
        ) -> Result<Value> {
            self.s3.call(service, operation, input, extra)
        }
        fn batch_call(
            &self,
            service: &str,
            calls: &[zdn::aws::AwsCall<'_>],
        ) -> Result<Vec<Result<Value>>> {
            let mut outcomes = self.s3.batch_call(service, calls)?;
            match self.mode {
                "put-short" => {
                    outcomes.pop();
                }
                "put-extra" => outcomes.push(Ok(json!({}))),
                "put-outer" => eyre::bail!("fixture worker failure after writes"),
                _ => {}
            }
            Ok(outcomes)
        }
        fn batch_call_all(
            &self,
            service: &str,
            calls: &[zdn::aws::AwsCall<'_>],
        ) -> Result<Vec<Result<Value>>> {
            let mut outcomes = self.s3.batch_call_all(service, calls)?;
            let round = self.heads.get();
            self.heads.set(round + 1);
            match (round, self.mode) {
                (0, "head-short") | (1, "reconcile-short") => {
                    outcomes.pop();
                }
                (0, "head-extra") | (1, "reconcile-extra") => outcomes.push(Ok(json!({}))),
                _ => {}
            }
            Ok(outcomes)
        }
    }
    for mode in [
        "head-short",
        "head-extra",
        "put-short",
        "put-extra",
        "put-outer",
        "reconcile-short",
        "reconcile-extra",
    ] {
        let api = Malformed {
            s3: FakeS3::new(&fixture.team),
            mode,
            heads: std::cell::Cell::new(0),
        };
        assert!(
            devnet::upload_files(&api, &fixture.team, &files).is_err(),
            "{mode}"
        );
        if mode.starts_with("head-") {
            assert!(api.s3.objects.borrow().is_empty());
        } else {
            assert_eq!(api.s3.objects.borrow().len(), 6);
            assert_eq!(
                &api.s3.calls.borrow()[12..],
                ["head-object"; 6],
                "all writes reconciled: {mode}"
            );
        }
        devnet::upload_files(&api.s3, &fixture.team, &files).unwrap();
        assert_eq!(api.s3.objects.borrow().len(), 6);
    }
}

#[test]
fn upload_files_settles_successful_peers_after_failure_and_resumes_without_overwrite() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    let files: Vec<_> = request
        .artifacts
        .keys()
        .map(|name| {
            (
                request
                    .s3_object(&fixture.team, &fixture.spec, name)
                    .unwrap(),
                devnet::artifact_path(&fixture.output, name),
            )
        })
        .collect();
    let mut aws = FakeS3::new(&fixture.team);
    aws.fail_key = Some(files[1].0.key.clone());
    assert!(devnet::upload_files(&aws, &fixture.team, &files).is_err());
    assert_eq!(aws.objects.borrow().len(), 1);
    assert_eq!(&aws.calls.borrow()[8..], ["head-object"; 6]);
    aws.fail_key = None;
    devnet::upload_files(&aws, &fixture.team, &files).unwrap();
    assert_eq!(aws.objects.borrow().len(), 6);
    assert_eq!(
        aws.calls
            .borrow()
            .iter()
            .filter(|s| *s == "put-object")
            .count(),
        7
    );

    let mut aws = FakeS3::new(&fixture.team);
    aws.lost_put_reply = true;
    devnet::upload_file(&aws, &fixture.team, &files[0].0, &files[0].1).unwrap();
    assert_eq!(
        aws.calls.borrow().as_slice(),
        ["head-object", "put-object", "head-object"]
    );
}

struct FakeEcr {
    response: Value,
    calls: RefCell<usize>,
}
impl AwsApi for FakeEcr {
    fn call(
        &self,
        service: &str,
        operation: &str,
        input: Value,
        extra: &[String],
    ) -> Result<Value> {
        assert_eq!((service, operation), ("ecr", "batch-get-image"));
        assert!(extra.is_empty());
        assert_eq!(input["registryId"], "123456789012");
        assert_eq!(input["repositoryName"], "zdn/private-team/zakura");
        *self.calls.borrow_mut() += 1;
        Ok(self.response.clone())
    }
}

#[test]
fn registry_observation_must_return_the_exact_saved_child_manifest() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    let good = json!({"failures":[],"images":[{"imageId":{"imageDigest":request.image.manifest_digest().unwrap()},"imageManifest":fs::read_to_string(&fixture.image_manifest).unwrap()}]});
    let aws = FakeEcr {
        response: good.clone(),
        calls: RefCell::new(0),
    };
    devnet::verify_ecr(&aws, &request, &fixture.team, &fixture.output).unwrap();
    assert_eq!(*aws.calls.borrow(), 1);
    for mutation in 0..3 {
        let mut response = good.clone();
        match mutation {
            0 => response["failures"] = json!([{"failureCode":"ImageNotFound"}]),
            1 => {
                response["images"][0]["imageId"]["imageDigest"] =
                    json!(format!("sha256:{}", "e".repeat(64)))
            }
            2 => {
                response["images"][0]["imageManifest"] = json!(format!(
                    "{}\n",
                    response["images"][0]["imageManifest"].as_str().unwrap()
                ))
            }
            _ => unreachable!(),
        }
        let aws = FakeEcr {
            response,
            calls: RefCell::new(0),
        };
        assert!(devnet::verify_ecr(&aws, &request, &fixture.team, &fixture.output).is_err());
    }
}

#[test]
fn host_specs_preserve_resource_reserves_and_observations_require_exact_identity() {
    let fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    for node in request.topology().unwrap().nodes() {
        let outputs = zdn::cluster_infra::ClusterNodeOutputs {
            node_id: node.node_id.clone(),
            instance_id: "i-00000000000000001".into(),
            private_ip: node.private_ip,
            volume_id: "vol-00000000000000001".into(),
        };
        let host = request
            .host_spec(&fixture.spec, &fixture.team, &outputs)
            .unwrap();
        host.validate().unwrap();
        assert_eq!(host.memory_bytes, 14 * zdn::infra::GIB);
        assert_eq!(host.host_reserve_bytes, 2 * zdn::infra::GIB);
        assert_eq!(host.cpu_millis, 3750);
        let install_sha256 = host.install_sha256().unwrap();
        let good = json!({
            "apiVersion":"zdn-host-observation/v1alpha1", "nodeId":host.node_id,
            "deploymentId":host.deployment_id,"consensusFingerprint":host.consensus_fingerprint,
            "configSha256":host.config_sha256,"image":host.image,"installSha256":install_sha256,
            "status":"ready","launchReady":false,"paymentQualification":"pending",
            "scheduledProducer":false,"producer":null,
            "effectiveLimits":{"effectiveMemoryBytes":16*zdn::infra::GIB,"visibleCpuMillis":4000,
                "hostReserveBytes":host.host_reserve_bytes,"hostReserveCpuMillis":250,
                "nodeMemoryBytes":host.memory_bytes,"nodeCpuMillis":host.cpu_millis},
            "readiness":{
                "apiVersion":zdn::chain::readiness::API_VERSION,"consensusFingerprint":host.consensus_fingerprint,
                "role":host.role,"effectiveRulesVerified":true,"historyPresent":true,
                "miningReady":node.producer,"launchReady":false,"paymentQualification":"pending",
                "tip":{"height":0,"hash":format!("{:064x}",1)}
            }
        });
        devnet::validate_observation(&good, &host, &install_sha256).unwrap();
        assert_eq!(host.block_interval_seconds, Some(25));
        assert_eq!(
            devnet::validate_producer_observation(&good, &host, true).is_ok(),
            !node.producer
        );
        let mut scheduled = good.clone();
        scheduled["scheduledProducer"] = json!(true);
        scheduled["producer"] = json!({
            "apiVersion":zdn::chain::producer::API_VERSION,
            "identity":{"deploymentId":host.deployment_id,"nodeId":host.node_id,"consensusFingerprint":host.consensus_fingerprint},
            "intervalSecs":25,"controllerLocked":true,"ownerPid":1234,"ownerSession":Uuid::new_v4(),
            "phase":"waiting","paymentQualification":"pending","launchReady":false
        });
        assert_eq!(
            devnet::validate_producer_observation(&scheduled, &host, true).is_ok(),
            node.producer
        );
        if node.producer {
            for (pointer, bad) in [
                ("/producer/identity/nodeId", json!("node-2")),
                ("/producer/identity/deploymentId", json!(Uuid::new_v4())),
                (
                    "/producer/identity/consensusFingerprint",
                    json!("f".repeat(64)),
                ),
                ("/producer/apiVersion", json!("unrecognized")),
                ("/producer/intervalSecs", json!(75)),
                ("/producer/controllerLocked", json!(false)),
                ("/producer/ownerPid", json!(0)),
                ("/producer/ownerSession", json!("invalid")),
                ("/producer/phase", json!("stalled")),
                ("/producer/paymentQualification", json!("passed")),
                ("/producer/launchReady", json!(true)),
                ("/scheduledProducer", json!(false)),
            ] {
                let mut changed = scheduled.clone();
                *changed.pointer_mut(pointer).unwrap() = bad;
                assert!(
                    devnet::validate_producer_observation(&changed, &host, true).is_err(),
                    "{pointer}"
                );
            }
        }
        for (pointer, bad) in [
            ("/nodeId", json!("foreign-node")),
            ("/deploymentId", json!(Uuid::new_v4())),
            ("/consensusFingerprint", json!("f".repeat(64))),
            ("/configSha256", json!("f".repeat(64))),
            ("/image", json!("different-image")),
            ("/installSha256", json!("f".repeat(64))),
            ("/status", json!("starting")),
            ("/launchReady", json!(true)),
            ("/paymentQualification", json!("passed")),
            ("/readiness/role", json!("unrecognized")),
            ("/readiness/effectiveRulesVerified", json!(false)),
            ("/readiness/historyPresent", json!(false)),
            ("/readiness/miningReady", json!(!node.producer)),
            ("/readiness/launchReady", json!(true)),
            ("/readiness/paymentQualification", json!("passed")),
            ("/readiness/tip/hash", json!("abc")),
            ("/readiness/tip/height", json!(u64::from(u32::MAX) + 1)),
            (
                "/effectiveLimits/nodeMemoryBytes",
                json!(15 * zdn::infra::GIB),
            ),
            (
                "/effectiveLimits/effectiveMemoryBytes",
                json!(15 * zdn::infra::GIB),
            ),
            ("/effectiveLimits/nodeCpuMillis", json!(4000)),
            ("/effectiveLimits/hostReserveBytes", json!(0)),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                devnet::validate_observation(&changed, &host, &install_sha256).is_err(),
                "{pointer}"
            );
        }
    }
}

#[test]
fn producer_cadence_is_pinned_and_legacy_requests_stay_disabled() {
    let mut fixture = Fixture::new();
    let request = fixture.stage().unwrap();
    assert_eq!(request.block_interval_seconds, Some(25));
    fixture.config.network.mining.interval = "75s".into();
    let changed = fixture.stage().unwrap();
    assert_eq!(changed.block_interval_seconds, Some(75));
    assert_ne!(changed.config_sha256, request.config_sha256);
    let mut legacy = serde_json::to_value(&request).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("blockIntervalSeconds");
    let parsed: ClusterRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(parsed.block_interval_seconds, None);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), legacy);
    parsed.validate(&fixture.spec, &fixture.team).unwrap();
    for interval in [0, 86_401] {
        let mut invalid = request.clone();
        invalid.block_interval_seconds = Some(interval);
        assert!(invalid.validate(&fixture.spec, &fixture.team).is_err());
    }
}

fn cli_fixture(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let source = fixture.root.path().join("source");
    let state = fixture.root.path().join("cli-state");
    fs::create_dir(&source).unwrap();
    zdn::state::StateStore::open(&state).unwrap();
    zdn::foundation::private_directory(&state.join("profiles")).unwrap();
    zdn::foundation::write_private(
        &state.join("profiles/private-team.json"),
        &serde_json::to_vec(&json!({"team":fixture.team,"awsProfile":"developer"})).unwrap(),
    )
    .unwrap();
    fs::write(
        source.join("devnet.yaml"),
        serde_yaml::to_string(&fixture.config).unwrap(),
    )
    .unwrap();
    (source, state)
}
fn cli(
    source: &std::path::Path,
    state: &std::path::Path,
    action: &str,
    extra: &[&str],
) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .current_dir(source)
        .env("PATH", "")
        .args([
            "devnet",
            action,
            "--state-dir",
            state.to_str().unwrap(),
            "--ami-id",
            "ami-0123456789abcdef0",
            "--availability-zone",
            "us-east-1a",
        ])
        .args(extra)
        .output()
        .unwrap()
}
fn cli_inputs(f: &Fixture) -> Vec<&str> {
    vec![
        "--manifest",
        f.manifest.to_str().unwrap(),
        "--bundle",
        f.bundle.to_str().unwrap(),
        "--image-record",
        f.image_record.to_str().unwrap(),
        "--image-manifest",
        f.image_manifest.to_str().unwrap(),
        "--image-config",
        f.image_config.to_str().unwrap(),
        "--host-helper",
        f.helper.to_str().unwrap(),
        "--reward-address",
        "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
    ]
}

#[test]
fn foundation_cli_freezes_explicit_runtime_and_reuses_saved_helper() {
    for native in [false, true] {
        let fixture = Fixture::new();
        let (source, state) = cli_fixture(&fixture);
        let render = |helper: bool| {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
            command.current_dir(&source).env("PATH", "").args([
                "foundation",
                "render",
                "--state-dir",
                state.to_str().unwrap(),
                "--ami-id",
                "ami-0123456789abcdef0",
                "--availability-zone",
                "us-east-1a",
            ]);
            if helper {
                command.arg("--host-helper").arg(&fixture.helper);
            }
            command.output().unwrap()
        };
        // Fresh foundation requests cannot fall back to Python without a helper.
        assert!(!render(false).status.success());
        let first = render(true);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let first: Value = serde_json::from_slice(&first.stdout).unwrap();
        let id = Uuid::parse_str(first["networkId"].as_str().unwrap()).unwrap();
        let file = zdn::foundation::DeploymentFile::open(&state, id).unwrap();
        let mut saved = file.load().unwrap();
        assert!(saved.foundation_runtime.is_some());
        if !native {
            // Decode the absent selection of a historical saved request.
            saved.foundation_runtime = None;
            file.save(&saved).unwrap();
        }
        let before = fs::read(file.directory().join("deployment.json")).unwrap();
        drop(file);
        if !native {
            for helper in [false, true] {
                let legacy = render(helper);
                assert!(!legacy.status.success());
                assert!(
                    String::from_utf8_lossy(&legacy.stderr).contains("legacy execution is retired")
                );
            }
            let file = zdn::foundation::DeploymentFile::open(&state, id).unwrap();
            assert_eq!(
                fs::read(file.directory().join("deployment.json")).unwrap(),
                before
            );
            continue;
        }
        // An unchanged explicit retry and a saved-input retry both preserve
        // the original private executable, including deleted caller inputs.
        assert!(render(true).status.success());
        fs::write(&fixture.helper, b"not the pinned helper").unwrap();
        assert!(!render(true).status.success());
        fs::remove_file(&fixture.helper).unwrap();
        let again = render(false);
        assert!(
            again.status.success(),
            "{}",
            String::from_utf8_lossy(&again.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&again.stdout).unwrap(),
            first
        );
        let file = zdn::foundation::DeploymentFile::open(&state, id).unwrap();
        assert_eq!(
            fs::read(file.directory().join("deployment.json")).unwrap(),
            before
        );
        if native {
            fs::remove_file(file.directory().join(zdn::foundation_runtime::HELPER)).unwrap();
            drop(file);
            assert!(!render(false).status.success());
        }
    }
}

fn deployment_package(
    f: &Fixture,
    lightwallet: Option<&LightwalletFixture>,
) -> zdn::package::Package {
    use zdn::artifact_set::{ArtifactSet, Compatibility, Provenance};
    let request = match lightwallet {
        Some(lw) => lw.stage(f).unwrap(),
        None => f.stage().unwrap(),
    };
    let mut provenance = BTreeMap::new();
    for component in ["chain", "node", "helper"] {
        provenance.insert(
            component.into(),
            Provenance {
                source_url: "https://example.invalid/source.git".into(),
                revision: "c".repeat(40),
                license: "MIT".into(),
            },
        );
    }
    let lightwallet_image = request.lightwallet.map(|lw| lw.image);
    if let Some(lw) = &lightwallet_image {
        provenance.insert(
            "lightwallet".into(),
            Provenance {
                source_url: "https://example.invalid/lightwallet.git".into(),
                revision: lw.source_revision.clone(),
                license: "MIT".into(),
            },
        );
    }
    let sources = request
        .artifacts
        .keys()
        .map(|name| {
            (
                name.clone(),
                zdn::package::Location::File {
                    path: PathBuf::from(name),
                },
            )
        })
        .collect();
    zdn::package::Package {
        api_version: zdn::package::API_VERSION.into(),
        artifact_set: ArtifactSet {
            api_version: zdn::artifact_set::API_VERSION.into(),
            platform: "linux/amd64".into(),
            consensus_fingerprint: request.manifest.fingerprint().unwrap(),
            node_image: request.image,
            build: None,
            lightwallet_image,
            compatibility: Compatibility::current(lightwallet.is_some()),
            provenance,
            artifacts: request.artifacts,
        },
        sources,
    }
}

fn save_package(f: &Fixture, package: &zdn::package::Package) -> (PathBuf, String) {
    let bytes = serde_json::to_vec(package).unwrap();
    let path = f.root.path().join("package.json");
    fs::write(&path, &bytes).unwrap();
    (path, sha256(&bytes))
}

#[test]
fn cli_package_verifies_stages_and_recovers_without_originals() {
    for (lightwallet, source_build) in [(false, false), (true, false), (false, true)] {
        let mut f = Fixture::new();
        let lw = lightwallet.then(|| LightwalletFixture::new(&mut f));
        let mut package = deployment_package(&f, lw.as_ref());
        if source_build {
            package.artifact_set.node_image.provenance = ImageProvenance::Source {
                revision: "c".repeat(40),
                snapshot_sha256: "a".repeat(64),
            };
            package.artifact_set.build = Some(zdn::build::BuildContract {
                api_version: zdn::build::API_VERSION.into(),
                source_sha256: "a".repeat(64),
                source_bytes: 1,
                revision: "c".repeat(40),
                platform: "linux/amd64".into(),
                required_capabilities: ImageCapabilities::default(),
                recipe: zdn::build::BuildRecipe {
                    dockerfile: "Dockerfile".into(),
                    context: ".".into(),
                    target: "runtime".into(),
                },
            });
            let bytes = serde_json::to_vec(&package.artifact_set.node_image).unwrap();
            fs::write(&f.image_record, &bytes).unwrap();
            package.artifact_set.artifacts.insert(
                "image.json".into(),
                devnet::Artifact {
                    sha256: sha256(&bytes),
                    bytes: bytes.len() as u64,
                },
            );
        }
        let (path, pin) = save_package(&f, &package);
        let verify = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env("PATH", "")
            .args([
                "package",
                "verify",
                "--manifest",
                path.to_str().unwrap(),
                "--sha256",
                &pin,
            ])
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stderr)
        );
        let report: Value = serde_json::from_slice(&verify.stdout).unwrap();
        assert_eq!(report["byteIntegrityVerified"], true);
        assert_eq!(report["publisherAuthenticated"], false);
        assert_eq!(report["artifactExecutionVerified"], false);
        assert_eq!(report["launchReady"], false);
        let (source, state) = cli_fixture(&f);
        let args = [
            "--package",
            path.to_str().unwrap(),
            "--package-sha256",
            &pin,
            "--reward-address",
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
        ];
        let render = cli(&source, &state, "render", &args);
        assert!(
            render.status.success(),
            "{}",
            String::from_utf8_lossy(&render.stderr)
        );
        let first: Value = serde_json::from_slice(&render.stdout).unwrap();
        assert_eq!(
            first["artifactSetSha256"],
            package.artifact_set.fingerprint().unwrap()
        );
        let store = zdn::state::StateStore::open(&state).unwrap();
        let id = Uuid::parse_str(first["networkId"].as_str().unwrap()).unwrap();
        let saved = zdn::foundation::DeploymentFile::read_snapshot(store.root(), id).unwrap();
        let cluster = saved.cluster.unwrap();
        assert_eq!(cluster.build, package.artifact_set.build);
        assert_eq!(
            cluster.artifact_set.unwrap().fingerprint().unwrap(),
            first["artifactSetSha256"]
        );
        assert_eq!(cluster.artifacts.len(), if lightwallet { 9 } else { 6 });

        // Metadata changes are immutable even if every artifact byte is identical.
        let mut changed = package.clone();
        changed
            .artifact_set
            .provenance
            .get_mut("helper")
            .unwrap()
            .license = "Apache-2.0".into();
        let (_, changed_pin) = save_package(&f, &changed);
        let rejected = cli(
            &source,
            &state,
            "render",
            &[
                "--package",
                path.to_str().unwrap(),
                "--package-sha256",
                &changed_pin,
                "--reward-address",
                "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
            ],
        );
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("cannot change existing cluster inputs"));
        fs::remove_file(path).unwrap();
        for name in package.sources.keys() {
            fs::remove_file(f.root.path().join(name)).unwrap();
        }
        let recovered = cli(&source, &state, "render", &[]);
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&recovered.stdout).unwrap(),
            first
        );
    }
}

#[test]
fn cli_invalid_package_fails_before_binding_tools_or_cloud_access() {
    for failure in ["pin", "override", "compatibility", "config"] {
        let mut f = Fixture::new();
        let mut package = deployment_package(&f, None);
        if failure == "compatibility" {
            package.artifact_set.compatibility.helper_version = "wrong".into();
        }
        if failure == "config" {
            f.config.node.source.image = Some(format!(
                "{}@sha256:{}",
                f.config
                    .node
                    .source
                    .image
                    .as_ref()
                    .unwrap()
                    .split_once('@')
                    .unwrap()
                    .0,
                "e".repeat(64)
            ));
        }
        let (path, mut pin) = save_package(&f, &package);
        if failure == "pin" {
            pin = "0".repeat(64);
        }
        let (source, state) = cli_fixture(&f);
        let bad_helper = f.root.path().join("bad-helper");
        fs::write(&bad_helper, b"corrupt override").unwrap();
        for action in ["render", "up"] {
            let mut args = vec![
                "--package",
                path.to_str().unwrap(),
                "--package-sha256",
                &pin,
                "--reward-address",
                "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
            ];
            if action == "up" {
                args.push("--yes");
            }
            if failure == "override" {
                args.extend(["--host-helper", bad_helper.to_str().unwrap()]);
            }
            let result = cli(&source, &state, action, &args);
            assert!(!result.status.success(), "{failure}/{action}");
            let error = String::from_utf8_lossy(&result.stderr);
            let expected = match failure {
                "pin" => "package SHA-256 mismatch",
                "override" => "size",
                "compatibility" => "compatibility",
                _ => "package image differs",
            };
            assert!(error.contains(expected), "{failure}/{action}: {error}");
            assert!(!source.join(".zdn").exists());
            assert!(zdn::state::StateStore::open(&state)
                .unwrap()
                .list(&f.spec.scope)
                .unwrap()
                .is_empty());
        }
    }
}

#[cfg(unix)]
#[test]
fn source_up_verifies_build_before_entering_node_provisioning() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    for (mode, format) in ["human", "json", "jsonl"].into_iter().flat_map(|format| {
        [
            "failed",
            "corrupt",
            "valid",
            "uncertain",
            "interrupted",
            "uncertain-publication",
        ]
        .into_iter()
        .filter(move |mode| *mode != "uncertain-publication" || format == "json")
        .map(move |mode| (mode, format))
    }) {
        let mut f = Fixture::new();
        f.config.node.source = Source {
            path: Some(".".into()),
            ..Default::default()
        };
        f.config.node.build = Some(Default::default());
        let (source, state) = cli_fixture(&f);
        let git = |args: &[&str]| {
            assert!(Command::new("git")
                .current_dir(&source)
                .args([
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=/dev/null"
                ])
                .args(args)
                .status()
                .unwrap()
                .success());
        };
        git(&["init", "-q"]);
        fs::create_dir(source.join("docker")).unwrap();
        fs::write(
            source.join("docker/Dockerfile"),
            "FROM scratch AS runtime\n",
        )
        .unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "tiny source"]);
        let bin = f.root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let infra = zdn::build_infra::BuildInfrastructure::for_team(&f.team).unwrap();
        let fixture = json!({"root":bin,"project":infra.project_name,"bucket":infra.source_bucket,"uri":infra.repository_uri,"roleName":f.team.deployment.as_ref().unwrap().role_arn.rsplit('/').next().unwrap(),"manifest":fs::read_to_string(&f.image_manifest).unwrap(),"config":fs::read_to_string(&f.image_config).unwrap()});
        native_tool::install(&bin.join("aws"), "source_build_aws::worker", &fixture);
        let progress_sequence = std::cell::Cell::new(0);
        let invoke = |command: &[&str]| {
            let mut process = Command::new(env!("CARGO_BIN_EXE_zdn"));
            process
                .current_dir(if source.exists() {
                    &source
                } else {
                    f.root.path()
                })
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("HOME", f.root.path())
                .env("ZDN_MODE", mode)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null");
            if command.first() == Some(&"up") {
                process.args(["--format", format]);
                if format != "human" {
                    progress_sequence.set(progress_sequence.get() + 1);
                    process.arg("--progress-file").arg(
                        f.root
                            .path()
                            .join(format!("events-{}.jsonl", progress_sequence.get())),
                    );
                }
            }
            process.args(command).output().unwrap()
        };
        let check_failure = |output: &std::process::Output, legacy_message: &str| -> Value {
            assert_eq!(output.status.code(), Some(1));
            if format == "human" {
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains(legacy_message),
                    "{mode}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Value::Null;
            }
            assert!(output.stderr.is_empty());
            let stdout = String::from_utf8_lossy(&output.stdout);
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&stdout).unwrap()]
            } else {
                stdout
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            let terminal = records.last().unwrap();
            assert_eq!(terminal["type"], "result");
            assert_eq!(terminal["error"]["code"], "devnet-up-failed");
            let progress_path = f
                .root
                .path()
                .join(format!("events-{}.jsonl", progress_sequence.get()));
            assert_eq!(
                fs::metadata(&progress_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let progress = fs::read_to_string(progress_path).unwrap();
            let events: Vec<Value> = progress
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(events[0]["type"], "command-started");
            assert_eq!(events.last().unwrap(), terminal);
            if format == "jsonl" {
                assert_eq!(events, records);
            }
            if !terminal["data"]["build"].is_null() {
                let build_event = events
                    .iter()
                    .rev()
                    .find(|event| event["type"] == "build-observed")
                    .unwrap();
                assert_eq!(build_event["data"], terminal["data"]["build"]);
            }
            for event in &events {
                assert_eq!(event["command"], "up");
                assert!(event["operationId"].is_null());
                assert!(matches!(
                    event["type"].as_str().unwrap(),
                    "command-started" | "build-observed" | "result"
                ));
                if event["type"] == "build-observed" {
                    assert_eq!(event["networkId"], terminal["networkId"]);
                    assert_eq!(event["outcome"], "observed");
                }
            }
            assert!(!stdout.contains("fixture-version"));
            assert!(!stdout.contains("buildspecOverride"));
            assert!(!stdout.contains(&format!("{}:00000000", infra.project_name)));
            assert!(!progress.contains("fixture-version"));
            assert!(!progress.contains("buildspecOverride"));
            terminal.clone()
        };
        let render = invoke(&["devnet", "render"]);
        assert!(
            render.status.success(),
            "{}",
            String::from_utf8_lossy(&render.stderr)
        );
        let rendered: Value = serde_json::from_slice(&render.stdout).unwrap();
        assert_eq!(rendered["cloudActionStarted"], false);
        assert_eq!(rendered["buildContract"]["platform"], "linux/amd64");
        assert!(!bin.join("calls").exists());
        let tools = f.root.path().join("no-tools");
        let command = [
            "up",
            "--yes",
            "--state-dir",
            state.to_str().unwrap(),
            "--managed-dir",
            tools.to_str().unwrap(),
            "--ami-id",
            "ami-0123456789abcdef0",
            "--availability-zone",
            "us-east-1a",
            "--manifest",
            f.manifest.to_str().unwrap(),
            "--bundle",
            f.bundle.to_str().unwrap(),
            "--host-helper",
            f.helper.to_str().unwrap(),
            "--reward-address",
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
        ];
        let result = invoke(&command);
        let error = String::from_utf8_lossy(&result.stderr);
        let expected = match mode {
            "failed" => "ended with",
            "corrupt" => "configuration size",
            "uncertain" | "uncertain-publication" => "outcome may be unknown",
            "interrupted" => "ServiceUnavailableException",
            _ => "No such file or directory",
        };
        let report = check_failure(&result, expected);
        let store = zdn::state::StateStore::open(&state).unwrap();
        let binding = &store.list(&f.team.scope()).unwrap()[0];
        let deployment =
            zdn::foundation::DeploymentFile::read_snapshot(&state, binding.network_id).unwrap();
        assert!(deployment.outputs.is_none() && deployment.last_operation.is_none());
        if format != "human" {
            assert_eq!(report["networkId"], binding.network_id.to_string());
            assert_eq!(report["data"]["build"]["submissionRecorded"], true);
            assert_eq!(
                report["data"]["build"]["buildIdKnown"],
                !matches!(mode, "uncertain" | "uncertain-publication")
            );
            assert_eq!(report["data"]["build"]["imageVerified"], mode == "valid");
            assert_eq!(
                report["data"]["build"]["jobOutcome"],
                match mode {
                    "failed" => json!("failed"),
                    "valid" | "corrupt" => json!("succeeded"),
                    _ => Value::Null,
                }
            );
            assert_eq!(
                report["error"]["retryClassification"],
                if matches!(mode, "uncertain" | "uncertain-publication" | "interrupted") {
                    "reconcile-required"
                } else {
                    "blocked"
                }
            );
            let attempt: Value = serde_json::from_slice(
                &fs::read(
                    state
                        .join("foundation")
                        .join(binding.network_id.to_string())
                        .join("build/attempt.json"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(report["data"]["build"]["attemptId"], attempt["attemptId"]);
            assert_eq!(
                report["data"]["build"]["exporterHelper"],
                attempt["exporter"]["helper"]
            );
            assert_eq!(attempt["exporter"]["protocol"], zdn::build_export::PROTOCOL);
            assert_eq!(
                attempt["exporter"]["helper"]["sha256"],
                sha256(&fs::read(&f.helper).unwrap())
            );
        }
        if mode == "valid" {
            if format == "human" {
                assert!(error.contains("deploy private nodes"));
            }
            let request = deployment.cluster.unwrap();
            assert!(request.build.is_some());
            assert_eq!(request.config_sha256, f.config.fingerprint().unwrap());
            request
                .build
                .unwrap()
                .validate_image(&request.image)
                .unwrap();
        } else {
            assert!(deployment.cluster.is_none());
        }
        let calls = fs::read_to_string(bin.join("calls")).unwrap();
        assert!(!calls.contains("ec2.") && !calls.contains("ssm."));
        assert_eq!(calls.matches("codebuild.start-build").count(), 1);
        let started: Value = zdn::foundation::read_json(&bin.join("started.json")).unwrap();
        let spec = started["buildspecOverride"].as_str().unwrap();
        assert!(!spec.contains("python3"));
        assert!(spec.contains(&format!(
            "__runtime-capabilities --require {}",
            zdn::build_export::PROTOCOL
        )));

        let directory = state
            .join("foundation")
            .join(binding.network_id.to_string());
        if format == "json"
            && matches!(
                mode,
                "uncertain" | "uncertain-publication" | "interrupted" | "corrupt"
            )
        {
            let receipt = fs::read(directory.join("build/attempt.json")).unwrap();
            let archive = f.root.path().join("initial-build.tar");
            let pin = zdn::handoff::export::export(&store, binding, &archive).unwrap();
            let receiver = zdn::state::StateStore::open(f.root.path().join("receiver")).unwrap();
            let receiving_workspace = f.root.path().join("receiving-workspace");
            fs::create_dir(&receiving_workspace).unwrap();
            let receiving_config = receiving_workspace.join("devnet.yaml");
            fs::copy(source.join("devnet.yaml"), &receiving_config).unwrap();
            let context = zdn::state::BindingContext::new(
                receiving_config.clone(),
                None,
                None,
                f.team.scope(),
            )
            .unwrap();
            let profile: zdn::aws::LocalProfile =
                zdn::foundation::read_json(&state.join("profiles/private-team.json")).unwrap();
            zdn::handoff::import::import(
                &receiver,
                &context,
                binding.network_id,
                &profile,
                &archive,
                &pin,
            )
            .unwrap();
            let target = receiver
                .root()
                .join("foundation")
                .join(binding.network_id.to_string());
            assert_eq!(
                fs::read(target.join("build/attempt.json")).unwrap(),
                receipt
            );
            assert_eq!(
                fs::read_to_string(bin.join("calls")).unwrap(),
                calls,
                "transfer contacted AWS"
            );
            zdn::foundation::private_directory(&receiver.root().join("profiles")).unwrap();
            zdn::foundation::write_json(
                &receiver.root().join("profiles/private-team.json"),
                &profile,
            )
            .unwrap();
            fs::remove_dir_all(&source).unwrap();
            fs::remove_file(receiving_config).unwrap();
            for path in [
                &f.manifest,
                &f.bundle,
                &f.helper,
                &f.image_record,
                &f.image_manifest,
                &f.image_config,
            ] {
                fs::remove_file(path).unwrap();
            }
            let network = binding.network_id.to_string();
            let saved = [
                "up",
                "--yes",
                "--saved",
                &network,
                "--profile",
                "private-team",
                "--state-dir",
                receiver.root().to_str().unwrap(),
                "--managed-dir",
                tools.to_str().unwrap(),
            ];
            let denied = invoke(&saved);
            let denied_report = check_failure(&denied, "pass --reconcile");
            assert_eq!(
                denied_report["data"]["build"]["attemptId"],
                report["data"]["build"]["attemptId"]
            );
            assert_eq!(denied_report["data"]["build"]["imageVerified"], false);
            assert_eq!(
                denied_report["error"]["retryClassification"],
                if matches!(mode, "uncertain" | "uncertain-publication" | "interrupted") {
                    "reconcile-required"
                } else {
                    "blocked"
                }
            );
            assert_eq!(fs::read_to_string(bin.join("calls")).unwrap(), calls);
            fs::write(bin.join("retry"), "").unwrap();
            let mut saved = saved.to_vec();
            saved.push("--reconcile");
            if mode == "uncertain-publication" {
                // A controlled provider authentication failure must preserve
                // unknown work until the same login is available again. This
                // is not evidence of real AWS session expiration/enforcement.
                fs::write(bin.join("login-denied"), "").unwrap();
                let denied = invoke(&saved);
                check_failure(&denied, "AuthenticationExpired");
                assert!(!String::from_utf8_lossy(&denied.stdout)
                    .contains("fixture-secret-do-not-disclose"));
                assert!(!String::from_utf8_lossy(&denied.stderr)
                    .contains("fixture-secret-do-not-disclose"));
                assert_eq!(
                    fs::read(target.join("build/attempt.json")).unwrap(),
                    receipt
                );
                assert!(!bin.join("index.json").exists());
                fs::remove_file(bin.join("login-denied")).unwrap();
                // First recover the accepted job, then lose the accepted index
                // write's reply. Restart the real CLI again with the same saved
                // request: neither boundary may become a new build or network.
                check_failure(&invoke(&saved), "reuse index publication failed");
                let pointer: Value = zdn::foundation::read_json(&bin.join("index.json")).unwrap();
                let attempt: Value =
                    zdn::foundation::read_json(&target.join("build/attempt.json")).unwrap();
                assert_eq!(pointer["attempt"], report["data"]["build"]["attemptId"]);
                assert_eq!(attempt["attemptId"], pointer["attempt"]);
                assert_eq!(attempt["terminal"], "SUCCEEDED");
                assert_eq!(
                    attempt["contract"],
                    serde_json::from_slice::<Value>(&receipt).unwrap()["contract"]
                );
                let pending = zdn::foundation::DeploymentFile::read_snapshot(
                    receiver.root(),
                    binding.network_id,
                )
                .unwrap();
                assert!(pending.outputs.is_none() && pending.last_operation.is_none());
                let calls = fs::read_to_string(bin.join("calls")).unwrap();
                assert_eq!(calls.matches("codebuild.start-build").count(), 1);
                assert!(!calls.contains("ec2.") && !calls.contains("ssm."));
            }
            let resumed = invoke(&saved);
            let resumed_report = check_failure(&resumed, "deploy private nodes");
            assert_eq!(resumed_report["data"]["build"]["imageVerified"], true);
            let after: Value =
                serde_json::from_slice(&fs::read(target.join("build/attempt.json")).unwrap())
                    .unwrap();
            let before: Value = serde_json::from_slice(&receipt).unwrap();
            for field in [
                "attemptId",
                "sourceVersion",
                "contract",
                "project",
                "repository",
                "team",
                "dispatched",
                "reused",
            ] {
                assert_eq!(after[field], before[field], "{mode}/{field}");
            }
            let deployment =
                zdn::foundation::DeploymentFile::read_snapshot(receiver.root(), binding.network_id)
                    .unwrap();
            deployment.cluster.unwrap().verify_local(&target).unwrap();
            assert!(
                !deployment.stack_initialized
                    && deployment.outputs.is_none()
                    && deployment.last_operation.is_none()
            );
            let calls = fs::read_to_string(bin.join("calls")).unwrap();
            assert_eq!(calls.matches("codebuild.start-build").count(), 1);
            assert_eq!(
                calls.matches("ecr.batch-get-image").count(),
                if mode == "uncertain-publication" {
                    2
                } else {
                    1
                }
            );
            assert!(!calls.contains("ec2.") && !calls.contains("ssm."));
            continue;
        }
        if mode == "interrupted" && format == "human" {
            for (lost, expected) in [
                ("source-snapshot", "refusing recapture"),
                ("source-build-inputs.json", "input receipt missing"),
            ] {
                let hidden_build = f.root.path().join("lost-build");
                let hidden_input = f.root.path().join("lost-input");
                fs::rename(directory.join("build"), &hidden_build).unwrap();
                fs::rename(directory.join(lost), &hidden_input).unwrap();
                check_failure(&invoke(&command), expected);
                assert!(!directory.join("build").exists() && !directory.join(lost).exists());
                assert_eq!(fs::read_to_string(bin.join("calls")).unwrap(), calls);
                fs::rename(hidden_build, directory.join("build")).unwrap();
                fs::rename(hidden_input, directory.join(lost)).unwrap();
            }
        }
        let snapshot = directory.join("source-snapshot/source.tar");
        let original_archive = fs::read(&snapshot).unwrap();
        // Changed working files must not replace the archive of an interrupted build.
        fs::write(
            source.join("docker/Dockerfile"),
            "changed after submission\n",
        )
        .unwrap();
        fs::write(bin.join("retry"), "").unwrap();
        let resumed = invoke(&command);
        let resumed_report = check_failure(
            &resumed,
            if mode == "failed" {
                "terminal"
            } else {
                "deploy private nodes"
            },
        );
        if format != "human" {
            assert_eq!(
                resumed_report["data"]["build"]["attemptId"],
                report["data"]["build"]["attemptId"]
            );
            assert_eq!(
                resumed_report["data"]["build"]["imageVerified"],
                mode != "failed"
            );
        }
        assert_eq!(fs::read(&snapshot).unwrap(), original_archive);
        let calls = fs::read_to_string(bin.join("calls")).unwrap();
        assert_eq!(calls.matches("codebuild.start-build").count(), 1);
        assert!(!calls.contains("ec2.") && !calls.contains("ssm."));
        if mode == "uncertain" {
            assert_eq!(
                calls.matches("codebuild.list-builds-for-project").count(),
                1
            );
        }
        if mode == "valid" {
            // A changed config must fail before even reading AWS, not become a new build.
            let config_path = source.join("devnet.yaml");
            let original_config = fs::read(&config_path).unwrap();
            let mut changed = f.config.clone();
            changed.node.build.as_mut().unwrap().dockerfile = "docker/Otherfile".into();
            fs::write(&config_path, serde_yaml::to_string(&changed).unwrap()).unwrap();
            let rejected = invoke(&command);
            check_failure(&rejected, "source build inputs changed");
            assert_eq!(fs::read_to_string(bin.join("calls")).unwrap(), calls);
            fs::write(&config_path, original_config).unwrap();
            fs::write(
                source.join("docker/Dockerfile"),
                "FROM scratch AS runtime\n",
            )
            .unwrap();

            // Same source/config in a fresh local deployment reuses the verified image.
            let second_state = f.root.path().join("second-state");
            zdn::state::StateStore::open(&second_state).unwrap();
            zdn::foundation::private_directory(&second_state.join("profiles")).unwrap();
            fs::copy(
                state.join("profiles/private-team.json"),
                second_state.join("profiles/private-team.json"),
            )
            .unwrap();
            let mut second_command = command;
            second_command[3] = second_state.to_str().unwrap();
            let reused = invoke(&second_command);
            let reused_report = check_failure(&reused, "deploy private nodes");
            if format != "human" {
                assert_eq!(reused_report["data"]["build"]["imageVerified"], true);
                assert_eq!(reused_report["data"]["build"]["submissionRecorded"], false);
                assert_eq!(
                    reused_report["data"]["build"]["reusedFrom"],
                    report["data"]["build"]["attemptId"]
                );
                assert_ne!(
                    reused_report["data"]["build"]["attemptId"],
                    report["data"]["build"]["attemptId"]
                );
            }
            let calls = fs::read_to_string(bin.join("calls")).unwrap();
            assert_eq!(calls.matches("codebuild.start-build").count(), 1);
            assert_eq!(calls.matches("ecr.batch-get-image").count(), 3);
            assert!(!calls.contains("ec2.") && !calls.contains("ssm."));
        }
    }
}

#[test]
fn capabilities_report_supported_services_without_checking_missing_source_or_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let config = Config::draft(
        "capabilities".into(),
        "devnet".into(),
        Source {
            path: Some(root.path().join("missing-source")),
            ..Default::default()
        },
        Size::Medium,
    )
    .unwrap();
    for lightwallet in [false, true] {
        let mut config = config.clone();
        config.services = zdn::config::Services {
            wallet: false,
            lightwallet,
            faucet: false,
        };
        let mut inputs = vec![
            "--manifest",
            "--bundle",
            "--host-helper",
            "--reward-address",
        ];
        if lightwallet {
            inputs.extend([
                "--lightwallet-image-record",
                "--lightwallet-image-manifest",
                "--lightwallet-image-config",
            ]);
        }
        assert_eq!(
            devnet::capabilities(&config).unwrap(),
            json!({
                "apiVersion": "zdn-capabilities/v1alpha1",
                "configurationValid": true,
                "requestedServicesSupported": true,
                "unsupportedServices": [],
                "requestedServices": {"wallet": false, "lightwallet": lightwallet, "faucet": false},
                "deploymentPrerequisites": {
                    "status": "unchecked",
                    "explicitInputHints": inputs,
                    "unchecked": ["artifacts", "tools", "aws-identity", "aws-permissions"]
                },
                "liveReadinessChecked": false,
                "paymentQualification": "pending",
                "launchReady": false
            })
        );
        devnet::require_supported_services(&config).unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn capabilities_report_unsupported_services_and_reject_invalid_configuration() {
    let mut fixture = Fixture::new();
    for services in unsupported_services() {
        fixture.config.services = services;
        let report = devnet::capabilities(&fixture.config).unwrap();
        let mut expected = vec!["wallet"];
        if fixture.config.services.faucet {
            expected.push("faucet");
        }
        assert_eq!(report["unsupportedServices"], json!(expected));
        assert_eq!(report["requestedServicesSupported"], false);
        assert_eq!(report["launchReady"], false);
        assert_eq!(report["requestedServices"], json!(fixture.config.services));
        assert!(devnet::require_supported_services(&fixture.config).is_err());
    }
    // Faucet alone is invalid under the schema, but the deployment guard must
    // still reject it independently rather than relying on wallet selection.
    fixture.config.services.wallet = false;
    fixture.config.services.faucet = true;
    assert!(devnet::require_supported_services(&fixture.config).is_err());
    assert!(devnet::capabilities(&fixture.config).is_err());
    fixture.config.services.faucet = false;
    fixture.config.name.clear();
    assert!(devnet::capabilities(&fixture.config).is_err());
}

fn unsupported_services() -> [zdn::config::Services; 3] {
    [
        zdn::config::Services {
            wallet: true,
            lightwallet: false,
            faucet: false,
        },
        // The schema requires a wallet when a faucet is requested.
        zdn::config::Services {
            wallet: true,
            lightwallet: false,
            faucet: true,
        },
        zdn::config::Services::default(),
    ]
}

#[test]
fn staging_rejects_unimplemented_services_before_reading_or_writing_artifacts() {
    for services in unsupported_services() {
        let mut fixture = Fixture::new();
        fixture.config.services = services;
        fs::remove_file(&fixture.manifest).unwrap();
        let error = fixture.stage().unwrap_err().to_string();
        assert!(error.contains("services are not implemented"), "{error}");
        assert!(error.contains("services.wallet"), "{error}");
        assert!(error.contains("services.faucet"), "{error}");
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }
}

#[test]
fn cli_rejects_unimplemented_services_before_state_tools_or_aws_access() {
    for services in unsupported_services() {
        let mut fixture = Fixture::new();
        fixture.config.services = services;
        let source = fixture.root.path().join("source");
        let state = fixture.root.path().join("missing-state");
        let managed = fixture.root.path().join("missing-managed-tools");
        fs::create_dir(&source).unwrap();
        let config = serde_yaml::to_string(&fixture.config).unwrap();
        fs::write(source.join("devnet.yaml"), &config).unwrap();
        for action in ["render", "up"] {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
            command
                .env_clear()
                .env("PATH", "")
                .env("AWS_PROFILE", "invalid-no-aws-access")
                .env("AWS_CONFIG_FILE", source.join("missing-aws-config"))
                .env(
                    "AWS_SHARED_CREDENTIALS_FILE",
                    source.join("missing-aws-credentials"),
                )
                .current_dir(&source)
                .args(["devnet", action, "--state-dir"])
                .arg(&state)
                .args(["--manifest", "missing-manifest.json"]);
            if action == "up" {
                command.args(["--yes", "--managed-dir"]).arg(&managed);
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains("services are not implemented"), "{error}");
            assert!(error.contains("services.wallet"), "{error}");
            assert!(error.contains("services.faucet to false"), "{error}");
            assert!(!state.exists());
            assert!(!managed.exists());
            assert_eq!(fs::read_dir(&source).unwrap().count(), 1);
            assert_eq!(
                fs::read_to_string(source.join("devnet.yaml")).unwrap(),
                config
            );
        }
    }
}

#[test]
fn cli_render_is_offline_reuses_saved_inputs_and_keeps_launch_unqualified() {
    let f = Fixture::new();
    let (source, state) = cli_fixture(&f);
    let result = cli(&source, &state, "render", &cli_inputs(&f));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let first: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(first["nodeCount"], 3);
    assert_eq!(first["launchReady"], false);
    assert_eq!(first["nodeRuntimeQualified"], false);
    let program: Value = serde_yaml::from_str(first["pulumiYaml"].as_str().unwrap()).unwrap();
    assert_eq!(
        program["resources"]
            .as_object()
            .unwrap()
            .values()
            .filter(|r| r["type"] == "aws:ec2:Instance")
            .count(),
        3
    );
    fs::remove_file(&f.helper).unwrap();
    let result = cli(&source, &state, "render", &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let second: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(first, second);
    let store = zdn::state::StateStore::open(state).unwrap();
    let id = Uuid::parse_str(first["networkId"].as_str().unwrap()).unwrap();
    let receipt = zdn::foundation::DeploymentFile::read_snapshot(store.root(), id).unwrap();
    assert!(receipt.cluster.is_some());
    assert!(receipt.outputs.is_none());
    assert!(receipt.last_operation.is_none());
}

#[test]
fn cli_runtime_is_native_by_default_and_legacy_replay_never_converts() {
    for native in [false, true] {
        let f = Fixture::new();
        let (source, state) = cli_fixture(&f);
        let mut inputs = cli_inputs(&f);
        if native {
            inputs.push("--native-runtime");
        }
        let first = cli(&source, &state, "render", &inputs);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let output: Value = serde_json::from_slice(&first.stdout).unwrap();
        let id = Uuid::parse_str(output["networkId"].as_str().unwrap()).unwrap();
        let saved = zdn::foundation::DeploymentFile::read_snapshot(&state, id).unwrap();
        let request = saved.cluster.unwrap();
        assert_eq!(
            request.native_runtime_protocol.as_deref(),
            Some(zdn::host::runtime::PROTOCOL)
        );
        let replay = cli(&source, &state, "render", &cli_inputs(&f));
        assert!(
            replay.status.success(),
            "{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        let replay = cli(&source, &state, "render", &[]);
        assert!(replay.status.success());
        let again = zdn::foundation::DeploymentFile::read_snapshot(&state, id)
            .unwrap()
            .cluster
            .unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::to_value(&again).unwrap()
        );
        assert!(cli(&source, &state, "render", &["--native-runtime"])
            .status
            .success());
        let mut invalid = request.clone();
        invalid.installer_fetch_protocol = None;
        assert!(invalid
            .validate(&f.spec, &f.team)
            .unwrap_err()
            .to_string()
            .contains("native installer transport"));
        let mut invalid = request;
        invalid.native_runtime_protocol = Some("unsupported".into());
        assert!(invalid.validate(&f.spec, &f.team).is_err());

        let file = zdn::foundation::DeploymentFile::open(&state, id).unwrap();
        let mut legacy = file.load().unwrap();
        legacy.cluster.as_mut().unwrap().native_runtime_protocol = None;
        file.save(&legacy).unwrap();
        drop(file);
        for flags in [vec![], vec!["--native-runtime"]] {
            let rejected = cli(&source, &state, "render", &flags);
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stderr).contains("cannot convert saved legacy")
            );
            let unchanged = zdn::foundation::DeploymentFile::read_snapshot(&state, id).unwrap();
            assert_eq!(
                serde_json::to_value(&unchanged).unwrap(),
                serde_json::to_value(&legacy).unwrap()
            );
        }
    }
    let conflict = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .args(["devnet", "up", "--saved", "unused", "--native-runtime"])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cannot be used with"));
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("must-not-exist");
    let retired = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .args(["devnet", "update", "unused", "--resume"])
        .arg(Uuid::new_v4().to_string())
        .args([
            "--reconcile",
            "--migrate-update-dispatcher",
            "--yes",
            "--acknowledge-storage-compatibility",
            "--state-dir",
        ])
        .arg(&state)
        .output()
        .unwrap();
    assert!(!retired.status.success());
    assert!(String::from_utf8_lossy(&retired.stderr)
        .contains("unexpected argument '--migrate-update-dispatcher'"));
    assert!(!state.exists());
}

#[cfg(unix)]
#[test]
fn machine_source_up_requires_consent_before_binding_or_build_preparation() {
    let mut f = Fixture::new();
    f.config.node.source = Source {
        path: Some(".".into()),
        ..Default::default()
    };
    f.config.node.build = Some(Default::default());
    let (source, _) = cli_fixture(&f);
    let state = f.root.path().join("must-not-exist");
    for format in ["json", "jsonl"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .current_dir(&source)
            .args(["--format", format, "devnet", "up", "--state-dir"])
            .arg(&state)
            .arg("--manifest")
            .arg(&f.manifest)
            .arg("--bundle")
            .arg(&f.bundle)
            .arg("--host-helper")
            .arg(&f.helper)
            .args(["--reward-address", "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let result: Value = serde_json::from_str(if format == "json" {
            &stdout
        } else {
            stdout.lines().last().unwrap()
        })
        .unwrap();
        assert_eq!(result["error"]["code"], "devnet-up-failed");
        assert!(result["networkId"].is_null());
        assert!(result["operationId"].is_null());
        assert!(!state.exists());
        assert!(!source.join(".zdn").exists());
    }
}

#[cfg(unix)]
#[test]
fn machine_fresh_up_keeps_binding_identity_when_staging_fails() {
    for format in ["json", "jsonl"] {
        let f = Fixture::new();
        let (source, state) = cli_fixture(&f);
        fs::write(&f.image_manifest, b"corrupt-image-manifest").unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("PATH", "")
            .current_dir(&source)
            .args(["--format", format, "devnet", "up", "--yes", "--state-dir"])
            .arg(&state)
            .args([
                "--ami-id",
                "ami-0123456789abcdef0",
                "--availability-zone",
                "us-east-1a",
            ])
            .args(cli_inputs(&f))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let records: Vec<Value> = if format == "json" {
            vec![serde_json::from_str(&stdout).unwrap()]
        } else {
            stdout
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        assert_eq!(records.len(), if format == "json" { 1 } else { 2 });
        let result = records.last().unwrap();
        let bindings = zdn::state::StateStore::open(&state)
            .unwrap()
            .list(&f.spec.scope)
            .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(result["networkId"], bindings[0].network_id.to_string());
        assert!(result["operationId"].is_null());
        assert_eq!(result["error"]["code"], "devnet-up-failed");
        assert_eq!(result["error"]["retryClassification"], "blocked");
        let saved =
            zdn::foundation::DeploymentFile::read_snapshot(&state, bindings[0].network_id).unwrap();
        assert!(saved.last_operation.is_none());
        assert!(saved.cluster.is_none());
        assert!(!stdout.contains("corrupt-image-manifest"));
    }
}

#[cfg(unix)]
#[test]
fn machine_lifecycle_reports_saved_and_fresh_pinned_requests_without_builds() {
    use std::{
        io::{BufRead, BufReader, Read},
        process::{Command, Stdio},
    };
    use zdn::{
        foundation::DeploymentFile,
        state::{PhaseStatus, StateStore},
    };

    for (action, format, delete_data) in [
        ("destroy", "json", false),
        ("destroy", "jsonl", false),
        ("destroy", "json", true),
        ("destroy", "jsonl", true),
        ("up", "json", false),
        ("up", "jsonl", false),
        ("up-alias", "json", false),
        ("up-alias", "jsonl", false),
        ("fresh-up", "json", false),
        ("fresh-up", "jsonl", false),
        ("package-up", "json", false),
        ("package-up", "jsonl", false),
    ] {
        let f = Fixture::new();
        let (source, state) = cli_fixture(&f);
        let fresh = matches!(action, "fresh-up" | "package-up");
        let network = if fresh {
            None
        } else {
            let rendered = cli(&source, &state, "render", &cli_inputs(&f));
            assert!(
                rendered.status.success(),
                "{}",
                String::from_utf8_lossy(&rendered.stderr)
            );
            let report: Value = serde_json::from_slice(&rendered.stdout).unwrap();
            Some(Uuid::parse_str(report["networkId"].as_str().unwrap()).unwrap())
        };
        let package =
            (action == "package-up").then(|| save_package(&f, &deployment_package(&f, None)));
        if !fresh {
            fs::remove_dir_all(&source).unwrap();
            for path in [
                &f.manifest,
                &f.bundle,
                &f.image_record,
                &f.image_manifest,
                &f.image_config,
                &f.helper,
            ] {
                fs::remove_file(path).unwrap();
            }
        }
        machine_failure::install(f.root.path());
        let release = f.root.path().join("release");
        let waiting = f.root.path().join("waiting");
        let stderr = f.root.path().join("stderr");
        if format == "json" {
            fs::write(&release, b"ready").unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("HOME", f.root.path())
            .env("PATH", f.root.path().join("bin"))
            .env("ZDN_FIXTURE_WAITING", &waiting)
            .env("ZDN_FIXTURE_RELEASE", &release)
            .current_dir(if fresh { &source } else { f.root.path() })
            .args(["--format", format]);
        if action == "up-alias" {
            command.arg("up");
        } else {
            command.args(["devnet", if fresh { "up" } else { action }]);
        }
        if action != "destroy" && !fresh {
            command.arg("--saved");
        }
        if let Some(network) = network {
            command
                .arg(network.to_string())
                .args(["--profile", "private-team"]);
        }
        if fresh {
            command.args([
                "--ami-id",
                "ami-0123456789abcdef0",
                "--availability-zone",
                "us-east-1a",
            ]);
            if let Some((path, pin)) = &package {
                command.arg("--package").arg(path).args([
                    "--package-sha256",
                    pin,
                    "--reward-address",
                    "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
                ]);
            } else {
                command.args(cli_inputs(&f));
            }
        }
        command
            .args(["--yes", "--state-dir"])
            .arg(&state)
            .arg("--managed-dir")
            .arg(f.root.path().join("tools"))
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap());
        if delete_data {
            command.arg("--delete-data");
        }
        let mut child = command.spawn().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut records = Vec::<Value>::new();
        if format == "jsonl" {
            for expected in ["command-started", "operation-started", "phase-started"] {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let event: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(event["type"], expected, "{event}");
                records.push(event);
            }
            assert!(child.try_wait().unwrap().is_none());
            let operation = Uuid::parse_str(records[1]["operationId"].as_str().unwrap()).unwrap();
            assert!(matches!(
                StateStore::open(&state)
                    .unwrap()
                    .operation(operation)
                    .unwrap()
                    .phases[0]
                    .status,
                PhaseStatus::Running { .. }
            ));
            fs::write(&release, b"ready").unwrap();
        }
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        assert!(fs::read(&stderr).unwrap().is_empty());
        assert!(waiting.exists());
        assert!(!rest.contains("fixture-diagnostic-not-for-export"));
        if format == "jsonl" {
            records.extend(
                rest.lines()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap()),
            );
            assert_eq!(records.len(), 5);
            assert_eq!(records[3]["type"], "phase-result");
            assert_eq!(records[3]["outcome"], "failed");
        } else {
            records.push(serde_json::from_str(&rest).unwrap());
        }
        let result = records.last().unwrap();
        assert_eq!(
            result["error"]["code"],
            if action == "destroy" {
                "devnet-destroy-failed"
            } else {
                "devnet-up-failed"
            }
        );
        let id = Uuid::parse_str(result["operationId"].as_str().unwrap()).unwrap();
        let store = StateStore::open(&state).unwrap();
        let saved = store.operation(id).unwrap();
        let bindings = store.list(&f.spec.scope).unwrap();
        assert_eq!(bindings.len(), 1);
        let expected = bindings[0].network_id;
        if let Some(network) = network {
            assert_eq!(network, expected);
        }
        let network = expected;
        assert_eq!(saved.network_id, network);
        assert_eq!(
            saved.kind,
            if action != "destroy" {
                "devnet-up"
            } else if delete_data {
                "foundation-destroy-data"
            } else {
                "foundation-destroy-retain"
            }
        );
        assert_eq!(
            result["data"]["savedReceipt"]["phases"][0]["status"],
            "failed"
        );
        assert!(
            !DeploymentFile::read_snapshot(&state, network)
                .unwrap()
                .destroyed
        );
        assert!(saved.phases[1..]
            .iter()
            .all(|p| matches!(p.status, PhaseStatus::Pending)));
        for record in records.iter().skip(usize::from(format == "jsonl")) {
            assert_eq!(
                record["command"],
                if action == "up-alias" {
                    "up".into()
                } else if fresh {
                    "devnet up".into()
                } else {
                    format!("devnet {action}")
                }
            );
            assert_eq!(record["networkId"], network.to_string());
            assert_eq!(record["operationId"], id.to_string());
        }
    }
}

// No HOME or PATH: a valid recovery reaches credential prerequisites, but can
// never execute AWS, install tools, or dispatch a build in these tests.
fn saved_up(cwd: &std::path::Path, state: &std::path::Path, extra: &[&str]) -> String {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .current_dir(cwd)
        .args([
            "devnet",
            "up",
            "--state-dir",
            state.to_str().unwrap(),
            "--managed-dir",
            state.join("tools").to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .unwrap();
    assert!(!result.status.success());
    String::from_utf8(result.stderr).unwrap()
}

#[test]
fn cli_saved_up_conflicts_are_rejected_before_state_io() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("must-not-exist");
    for flag in [
        "--config",
        "--ami-id",
        "--availability-zone",
        "--package",
        "--package-sha256",
        "--manifest",
        "--bundle",
        "--image-record",
        "--image-manifest",
        "--image-config",
        "--lightwallet-image-record",
        "--lightwallet-image-manifest",
        "--lightwallet-image-config",
        "--host-helper",
        "--reward-address",
    ] {
        let error = saved_up(
            root.path(),
            &state,
            &["--saved", "network", "--yes", flag, "absent"],
        );
        assert!(error.contains("cannot be used with"), "{flag}: {error}");
        assert!(!state.exists(), "{flag}");
    }
    let error = saved_up(root.path(), &state, &["--profile", "devnet", "--yes"]);
    assert!(error.contains("--saved"), "{error}");
    assert!(!state.exists());
    let error = saved_up(root.path(), &state, &["--saved", "network"]);
    assert!(error.contains("pass --yes"), "{error}");
    assert!(!state.exists());
    for format in ["json", "jsonl"] {
        for consent in [false, true] {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
            command
                .env_clear()
                .env("PATH", "")
                .current_dir(root.path())
                .args(["--format", format, "devnet", "up", "--state-dir"])
                .arg(&state);
            if consent {
                command.arg("--yes");
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stderr.is_empty());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let result: Value = if format == "json" {
                serde_json::from_str(&stdout).unwrap()
            } else {
                serde_json::from_str(stdout.lines().last().unwrap()).unwrap()
            };
            assert_eq!(result["error"]["code"], "devnet-up-failed");
            assert!(result["networkId"].is_null());
            assert!(result["operationId"].is_null());
            assert!(!state.exists());
        }
    }
}

#[test]
fn cli_saved_up_recovers_without_original_inputs_and_preserves_saved_identity() {
    let f = Fixture::new();
    let (source, state) = cli_fixture(&f);
    let (package, pin) = save_package(&f, &deployment_package(&f, None));
    let rendered = cli(
        &source,
        &state,
        "render",
        &[
            "--package",
            package.to_str().unwrap(),
            "--package-sha256",
            &pin,
            "--reward-address",
            "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
        ],
    );
    assert!(
        rendered.status.success(),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let report: Value = serde_json::from_slice(&rendered.stdout).unwrap();
    let id = report["networkId"].as_str().unwrap();
    let directory = PathBuf::from(report["receiptDirectory"].as_str().unwrap());
    let before = fs::read(directory.join("deployment.json")).unwrap();
    let artifacts: BTreeMap<_, _> = fs::read_dir(directory.join("artifacts"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), fs::read(path).unwrap())
        })
        .collect();
    fs::copy(
        state.join("profiles/private-team.json"),
        state.join("profiles/devnet.json"),
    )
    .unwrap();
    for path in [
        &f.manifest,
        &f.bundle,
        &f.image_record,
        &f.image_manifest,
        &f.image_config,
        &f.helper,
        &package,
    ] {
        fs::remove_file(path).unwrap();
    }
    fs::remove_dir_all(&source).unwrap();
    for selector in [id, &id[..8], "private-feature"] {
        let error = saved_up(f.root.path(), &state, &["--saved", selector, "--yes"]);
        assert!(error.contains("HOME is required"), "{selector}: {error}");
        assert_eq!(fs::read(directory.join("deployment.json")).unwrap(), before);
        for (path, bytes) in &artifacts {
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
    }
    let error = saved_up(f.root.path(), &state, &["--saved", "absent", "--yes"]);
    assert!(error.contains("no network matches"), "{error}");
    let error = saved_up(
        f.root.path(),
        &state,
        &["--saved", id, "--profile", "missing", "--yes"],
    );
    assert!(error.contains("profile"), "{error}");
    let store = zdn::state::StateStore::open(&state).unwrap();
    let other_source = f.root.path().join("other-source");
    fs::create_dir(&other_source).unwrap();
    let other_config = other_source.join("devnet.yaml");
    fs::write(&other_config, "binding-only fixture").unwrap();
    let context =
        zdn::state::BindingContext::new(other_config, None, None, f.spec.scope.clone()).unwrap();
    store.bind(&context, "private-feature").unwrap();
    let error = saved_up(
        f.root.path(),
        &state,
        &["--saved", "private-feature", "--yes"],
    );
    assert!(error.contains("ambiguous network selection"), "{error}");
    let mut profile: Value =
        serde_json::from_slice(&fs::read(state.join("profiles/devnet.json")).unwrap()).unwrap();
    profile["awsProfile"] = json!("other-developer");
    zdn::foundation::write_json(&state.join("profiles/devnet.json"), &profile).unwrap();
    let error = saved_up(f.root.path(), &state, &["--saved", id, "--yes"]);
    assert!(error.contains("saved team or AWS profile"), "{error}");
    assert_eq!(fs::read(directory.join("deployment.json")).unwrap(), before);
    profile["awsProfile"] = json!("developer");
    profile["team"]["revision"] = json!(2);
    zdn::foundation::write_json(&state.join("profiles/devnet.json"), &profile).unwrap();
    let error = saved_up(f.root.path(), &state, &["--saved", id, "--yes"]);
    assert!(error.contains("saved team or AWS profile"), "{error}");
    profile["team"]["aws"]["region"] = json!("us-west-2");
    profile["team"]["state"]["kmsKeyArn"] =
        json!("arn:aws:kms:us-west-2:123456789012:key/00000000-0000-4000-8000-000000000001");
    zdn::foundation::write_json(&state.join("profiles/devnet.json"), &profile).unwrap();
    let error = saved_up(f.root.path(), &state, &["--saved", id, "--yes"]);
    assert!(
        error.contains("no local binding in this team, account, and region"),
        "{error}"
    );
    assert_eq!(fs::read(directory.join("deployment.json")).unwrap(), before);
}

#[test]
fn cli_saved_up_requires_reconcile_before_backend_setup() {
    use zdn::state::{OperationInput, PhaseStatus, StateStore};
    let f = Fixture::new();
    let (source, state) = cli_fixture(&f);
    let rendered = cli(&source, &state, "render", &cli_inputs(&f));
    assert!(rendered.status.success());
    let report: Value = serde_json::from_slice(&rendered.stdout).unwrap();
    let id = report["networkId"].as_str().unwrap();
    let store = StateStore::open(&state).unwrap();
    let binding = store.resolve(&f.spec.scope, id, None).unwrap();
    let file = zdn::foundation::DeploymentFile::open(&state, binding.network_id).unwrap();
    let mut deployment = file.load().unwrap();
    drop(file);
    for status in [
        PhaseStatus::Running { external_ref: None },
        PhaseStatus::Unknown {
            message: "lost result".into(),
            external_ref: None,
        },
        PhaseStatus::Failed {
            message: "effect not settled".into(),
            retry_safe: false,
        },
    ] {
        let operation = store
            .begin_operation(
                &binding,
                "devnet-up",
                OperationInput {
                    config_sha256: "a".repeat(64),
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                &["apply"],
            )
            .unwrap();
        let running = store
            .record_phase(
                operation.operation_id,
                operation.revision,
                "apply",
                PhaseStatus::Running { external_ref: None },
            )
            .unwrap();
        if !matches!(status, PhaseStatus::Running { .. }) {
            store
                .record_phase_outcome(&running, "apply", status)
                .unwrap();
        }
        deployment.last_operation = Some(operation.operation_id);
        let file = zdn::foundation::DeploymentFile::open(&state, binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        drop(file);
        let before = fs::read(
            PathBuf::from(report["receiptDirectory"].as_str().unwrap()).join("deployment.json"),
        )
        .unwrap();
        for reconcile in [false, true] {
            let mut args = vec!["--saved", id, "--profile", "private-team", "--yes"];
            if reconcile {
                args.push("--reconcile");
            }
            let error = saved_up(f.root.path(), &state, &args);
            let expected = if reconcile {
                "HOME is required"
            } else {
                "uncertain outcome"
            };
            assert!(error.contains(expected), "{error}");
        }
        for format in ["json", "jsonl"] {
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
                .env_clear()
                .env("PATH", "")
                .current_dir(f.root.path())
                .args([
                    "--format",
                    format,
                    "devnet",
                    "up",
                    "--saved",
                    id,
                    "--profile",
                    "private-team",
                    "--yes",
                    "--state-dir",
                ])
                .arg(&state)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stderr.is_empty());
            let stdout = String::from_utf8(output.stdout).unwrap();
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&stdout).unwrap()]
            } else {
                stdout
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            assert_eq!(records.len(), if format == "json" { 1 } else { 2 });
            let result = records.last().unwrap();
            assert_eq!(result["error"]["code"], "devnet-up-failed");
            assert_eq!(result["error"]["retryClassification"], "reconcile-required");
            assert_eq!(result["networkId"], id);
            assert!(result["operationId"].is_null());
            assert_eq!(
                result["data"]["blockingReceipt"]["operationId"],
                operation.operation_id.to_string()
            );
        }
        let reopened = zdn::foundation::DeploymentFile::open(&state, binding.network_id).unwrap();
        assert_eq!(
            fs::read(reopened.directory().join("deployment.json")).unwrap(),
            before
        );
    }
    let mut foreign_context = binding.context.clone();
    foreign_context.config_path = source.join("foreign.yaml");
    let other = store.bind(&foreign_context, "foreign").unwrap();
    let foreign = store
        .begin_operation(
            &other,
            "devnet-up",
            OperationInput {
                config_sha256: "a".repeat(64),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &["apply"],
        )
        .unwrap();
    for (last, expected) in [
        (foreign.operation_id, "does not belong"),
        (Uuid::new_v4(), "operation receipt was not found"),
    ] {
        deployment.last_operation = Some(last);
        let file = zdn::foundation::DeploymentFile::open(&state, binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        drop(file);
        let error = saved_up(
            f.root.path(),
            &state,
            &[
                "--saved",
                id,
                "--profile",
                "private-team",
                "--yes",
                "--reconcile",
            ],
        );
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn cli_saved_up_blocks_invalid_saved_requests_before_backend_setup() {
    for case in [
        "foundation",
        "destroyed",
        "legacy",
        "missing",
        "corrupt",
        "helper",
    ] {
        let f = Fixture::new();
        let (source, state) = cli_fixture(&f);
        let rendered = cli(&source, &state, "render", &cli_inputs(&f));
        assert!(rendered.status.success());
        let report: Value = serde_json::from_slice(&rendered.stdout).unwrap();
        let directory = PathBuf::from(report["receiptDirectory"].as_str().unwrap());
        let path = directory.join("deployment.json");
        let mut deployment: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let expected = match case {
            "foundation" => {
                deployment["cluster"] = Value::Null;
                "no node ClusterRequest"
            }
            "destroyed" => {
                deployment["destroyed"] = json!(true);
                "was destroyed"
            }
            "legacy" => {
                deployment["cluster"]
                    .as_object_mut()
                    .unwrap()
                    .remove("nativeRuntimeProtocol");
                "legacy execution is retired"
            }
            "missing" => {
                fs::remove_file(directory.join("artifacts/zdn")).unwrap();
                "No such file"
            }
            "corrupt" => {
                fs::write(directory.join("artifacts/zdn"), b"corrupt").unwrap();
                "staged artifact changed: zdn"
            }
            "helper" => {
                deployment["cluster"]["artifactSet"] =
                    serde_json::to_value(deployment_package(&f, None).artifact_set).unwrap();
                deployment["cluster"]["artifactSet"]["compatibility"]["helperVersion"] =
                    json!("999.0.0");
                "helper version differs"
            }
            _ => unreachable!(),
        };
        zdn::foundation::write_json(&path, &deployment).unwrap();
        let before = fs::read(&path).unwrap();
        let error = saved_up(
            f.root.path(),
            &state,
            &[
                "--saved",
                report["networkId"].as_str().unwrap(),
                "--profile",
                "private-team",
                "--yes",
            ],
        );
        assert!(!error.contains("HOME is required"), "{case}: {error}");
        assert!(error.contains(expected), "{case}: {error}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn cli_lightwallet_render_reuses_saved_metadata_and_keeps_qualification_pending() {
    for legacy in [false, true] {
        let mut fixture = Fixture::new();
        let lightwallet = LightwalletFixture::new(&mut fixture);
        let (source, state) = cli_fixture(&fixture);
        let mut args = cli_inputs(&fixture);
        args.extend(lightwallet.cli_inputs());
        let result = cli(&source, &state, "render", &args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let first: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(first["launchReady"], false);
        assert_eq!(first["nodeRuntimeQualified"], false);
        let program: Value = serde_yaml::from_str(first["pulumiYaml"].as_str().unwrap()).unwrap();
        assert_eq!(
            program["resources"]["lightwalletCacheDisk"]["type"],
            "aws:ebs:Volume"
        );
        let network_id = Uuid::parse_str(first["networkId"].as_str().unwrap()).unwrap();
        let mut saved = zdn::foundation::DeploymentFile::read_snapshot(&state, network_id).unwrap();
        assert_eq!(
            saved
                .cluster
                .as_ref()
                .unwrap()
                .installer_fetch_protocol
                .as_deref(),
            Some("zdn-installer-fetch/v1alpha2")
        );
        assert_eq!(
            saved
                .cluster
                .as_ref()
                .unwrap()
                .lightwallet
                .as_ref()
                .unwrap()
                .capacity_protocol
                .as_deref(),
            Some("zdn-host-capacity/v1alpha1")
        );
        assert!(saved.outputs.is_none() && saved.last_operation.is_none());
        if legacy {
            saved.cluster.as_mut().unwrap().native_runtime_protocol = None;
            saved.cluster.as_mut().unwrap().installer_fetch_protocol = None;
            saved
                .cluster
                .as_mut()
                .unwrap()
                .lightwallet
                .as_mut()
                .unwrap()
                .capacity_protocol = None;
            zdn::foundation::DeploymentFile::open(&state, network_id)
                .unwrap()
                .save(&saved)
                .unwrap();
        }
        // Legacy metadata remains readable, but identical inputs cannot convert
        // it to the native default or grant new execution authority.
        let repeated = cli(&source, &state, "render", &args);
        if legacy {
            assert!(!repeated.status.success());
            assert!(
                String::from_utf8_lossy(&repeated.stderr).contains("cannot convert saved legacy")
            );
            assert_eq!(
                serde_json::to_value(
                    zdn::foundation::DeploymentFile::read_snapshot(&state, network_id).unwrap()
                )
                .unwrap(),
                serde_json::to_value(&saved).unwrap()
            );
            continue;
        }
        assert!(
            repeated.status.success(),
            "{}",
            String::from_utf8_lossy(&repeated.stderr)
        );
        let first: Value = serde_json::from_slice(&repeated.stdout).unwrap();
        let before = serde_json::to_value(&saved).unwrap();
        for path in [
            &fixture.helper,
            &lightwallet.record,
            &lightwallet.manifest,
            &lightwallet.config,
        ] {
            fs::remove_file(path).unwrap();
        }
        let result = cli(&source, &state, "render", &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let second: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_value(
                zdn::foundation::DeploymentFile::read_snapshot(&state, network_id).unwrap()
            )
            .unwrap(),
            before
        );
    }
}

#[test]
fn cli_lightwallet_partial_or_mismatched_inputs_fail_before_state_and_tools() {
    for mode in 0..3 {
        let mut fixture = Fixture::new();
        let lightwallet = LightwalletFixture::new(&mut fixture);
        fixture.config.services.lightwallet = mode != 2;
        let source = fixture.root.path().join("isolated-cli-source");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("devnet.yaml"),
            serde_yaml::to_string(&fixture.config).unwrap(),
        )
        .unwrap();
        let state = fixture.root.path().join("missing-cli-state");
        let mut args = cli_inputs(&fixture);
        match mode {
            0 => {}
            1 => args.extend([
                "--lightwallet-image-record",
                lightwallet.record.to_str().unwrap(),
            ]),
            2 => args.extend(lightwallet.cli_inputs()),
            _ => unreachable!(),
        }
        for action in ["render", "up"] {
            let mut args = args.clone();
            if action == "up" {
                args.push("--yes");
            }
            let result = cli(&source, &state, action, &args);
            assert!(!result.status.success());
            let error = String::from_utf8_lossy(&result.stderr);
            let expected = match mode {
                0 => "requires all three lightwallet image inputs",
                1 => "lightwallet-image-config together",
                2 => "image inputs require services.lightwallet: true",
                _ => unreachable!(),
            };
            assert!(error.contains(expected), "{action} mode {mode}: {error}");
            assert!(!state.exists());
            assert_eq!(fs::read_dir(&source).unwrap().count(), 1);
        }
    }
}

#[test]
fn cli_image_verification_is_offline_and_cannot_qualify_payments_or_provenance() {
    let mut fixture = Fixture::new();
    let lightwallet = LightwalletFixture::new(&mut fixture);
    for inspect in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("PATH", "")
            .args(["lightwallet", "verify-image", "--record"])
            .arg(&lightwallet.record)
            .arg("--manifest")
            .arg(&lightwallet.manifest)
            .arg("--config")
            .arg(&lightwallet.config);
        if inspect {
            command.arg("--docker-inspect").arg(&lightwallet.inspect);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["manifestBytesVerified"], true);
        assert_eq!(report["configBytesVerified"], true);
        assert_eq!(report["dockerMetadataVerified"], inspect);
        assert_eq!(report["sourceProvenanceVerified"], false);
        assert_eq!(report["binaryContentsVerified"], false);
        assert_eq!(report["launchReady"], false);
        assert_eq!(report["qualification"], "pending");
    }
    fs::write(&lightwallet.config, b"corrupt metadata").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .args(["lightwallet", "verify-image", "--record"])
        .arg(&lightwallet.record)
        .arg("--manifest")
        .arg(&lightwallet.manifest)
        .arg("--config")
        .arg(&lightwallet.config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn legacy_service_flags_do_not_block_saved_status_or_teardown_selection() {
    let fixture = Fixture::new();
    let (source, state) = cli_fixture(&fixture);
    let rendered = cli(&source, &state, "render", &cli_inputs(&fixture));
    assert!(
        rendered.status.success(),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let report: Value = serde_json::from_slice(&rendered.stdout).unwrap();
    let network = Uuid::parse_str(report["networkId"].as_str().unwrap()).unwrap();
    let file = zdn::foundation::DeploymentFile::open(&state, network).unwrap();
    let mut saved = file.load().unwrap();
    // Older builds silently staged node-only deployments with these flags.
    // Model that receipt without relaxing the new launch/staging checks.
    let mut legacy = fixture.config.clone();
    legacy.services = zdn::config::Services::default();
    saved.cluster.as_mut().unwrap().config_sha256 = legacy.fingerprint().unwrap();
    file.save(&saved).unwrap();
    let directory = file.directory().to_owned();
    drop(file);
    fs::remove_file(source.join("devnet.yaml")).unwrap();
    let expected = serde_json::to_value(&saved).unwrap();
    for action in ["status", "destroy"] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"));
        command
            .env_clear()
            .env("PATH", "")
            // A known local validation boundary proves saved selection works,
            // while ensuring this regression cannot invoke a cloud request.
            .env("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
            .current_dir(&source)
            .args(["devnet", action, &network.to_string(), "--state-dir"])
            .arg(&state)
            .args(["--profile", "private-team"]);
        if action == "destroy" {
            command.args(["--yes", "--reconcile", "--managed-dir"]);
            command.arg(fixture.root.path().join("missing-managed-tools"));
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("AWS endpoint overrides are not supported"),
            "{action}: {error}"
        );
        let observed = zdn::foundation::DeploymentFile::read_snapshot(&state, network).unwrap();
        assert_eq!(serde_json::to_value(observed).unwrap(), expected);
        assert!(!directory.join("credentials").exists());
    }
}

#[test]
fn cli_rejects_partial_inputs_config_changes_and_missing_apply_consent_offline() {
    let f = Fixture::new();
    let (source, state) = cli_fixture(&f);
    let result = cli(
        &source,
        &state,
        "render",
        &["--manifest", f.manifest.to_str().unwrap()],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("together"));
    let result = cli(&source, &state, "up", &cli_inputs(&f));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--yes"));
    let result = cli(&source, &state, "render", &cli_inputs(&f));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut config = f.config.clone();
    config.network.nodes = 2;
    fs::write(
        source.join("devnet.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
    let result = cli(&source, &state, "render", &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("immutable saved node request"));
    config.access.visibility = zdn::config::Visibility::Public;
    fs::write(
        source.join("devnet.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
    let result = cli(&source, &state, "render", &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("public access"));
}
#[test]
fn manifest_cannot_override_requested_upgrade_heights_or_proof_of_work() {
    let mut f = Fixture::new();
    f.config
        .network
        .activation_heights
        .insert("NU6.3".into(), 75);
    assert!(f
        .stage()
        .unwrap_err()
        .to_string()
        .contains("configured upgrade"));
    assert!(!f.output.join("artifacts").exists());
    let f = Fixture::new();
    let mut manifest: Value = serde_json::from_slice(&fs::read(&f.manifest).unwrap()).unwrap();
    manifest["difficulty"]["proofOfWork"] = json!("equihash");
    fs::write(&f.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(f
        .stage()
        .unwrap_err()
        .to_string()
        .contains("proof of work differs"));
}

struct Lifecycle {
    store: zdn::state::StateStore,
    binding: zdn::state::Binding,
    file: zdn::foundation::DeploymentFile,
    deployment: zdn::foundation::Deployment,
    _inputs: Fixture,
}

impl Lifecycle {
    fn native() -> Self {
        let mut fixture = Self::new();
        let request = fixture.deployment.cluster.as_mut().unwrap();
        request.native_runtime_protocol = Some(zdn::host::runtime::PROTOCOL.into());
        request.installer_fetch_protocol = Some(zdn::host::installer_bootstrap::PROTOCOL.into());
        fixture.file.save(&fixture.deployment).unwrap();
        fixture
    }

    fn new() -> Self {
        use zdn::{
            foundation::{Deployment, DeploymentFile},
            state::{BindingContext, StateStore},
        };
        let mut inputs = Fixture::new();
        let source = inputs.root.path().join("lifecycle-source");
        fs::create_dir(&source).unwrap();
        let config_path = source.join("devnet.yaml");
        fs::write(&config_path, serde_yaml::to_string(&inputs.config).unwrap()).unwrap();
        let store = StateStore::open(inputs.root.path().join("lifecycle-state")).unwrap();
        let context =
            BindingContext::new(config_path, None, None, inputs.spec.scope.clone()).unwrap();
        let binding = store.bind(&context, "lifecycle").unwrap();
        inputs.spec.network_id = binding.network_id;
        let request = inputs.stage().unwrap();
        let mut deployment = Deployment::new(inputs.spec.clone(), inputs.team.clone()).unwrap();
        deployment.cluster = Some(request);
        let file = DeploymentFile::open(store.root(), binding.network_id).unwrap();
        file.save(&deployment).unwrap();
        Self {
            store,
            binding,
            file,
            deployment,
            _inputs: inputs,
        }
    }

    fn backend(&self) -> LifecycleBackend {
        let request = self.deployment.cluster.as_ref().unwrap();
        let nodes: BTreeMap<_, _> = request
            .topology()
            .unwrap()
            .nodes()
            .into_iter()
            .enumerate()
            .map(|(index, node)| {
                (
                    node.node_id.clone(),
                    zdn::cluster_infra::ClusterNodeOutputs {
                        node_id: node.node_id,
                        private_ip: node.private_ip,
                        instance_id: format!("i-{:017x}", index + 1),
                        volume_id: format!("vol-{:017x}", index + 1),
                    },
                )
            })
            .collect();
        let first = &nodes["node-1"];
        LifecycleBackend {
            state: self.store.root().to_owned(),
            file: self.file.directory().join("deployment.json"),
            calls: Vec::new(),
            fail: None,
            cancel_install: false,
            reconciles: Vec::new(),
            output: zdn::infra::FoundationOutputs {
                schema_version: 1,
                scope: self.deployment.spec.scope.clone(),
                network_id: self.binding.network_id,
                availability_zone: self.deployment.spec.availability_zone.clone(),
                vpc_id: "vpc-12345678".into(),
                private_subnet_id: "subnet-12345678".into(),
                instance_id: first.instance_id.clone(),
                private_ip: first.private_ip,
                chain_volume_id: first.volume_id.clone(),
                retain_chain_disk: true,
                security_group_id: "sg-12345678".into(),
                nat_gateway_id: "nat-12345678".into(),
                eip_allocation_id: "eipalloc-12345678".into(),
                nodes,
                lightwallet: None,
            },
        }
    }

    fn apply(
        &mut self,
        backend: &mut LifecycleBackend,
        reconcile: bool,
    ) -> Result<zdn::state::OperationReceipt> {
        zdn::foundation::apply(
            &self.store,
            &self.file,
            &self.binding,
            &mut self.deployment,
            backend,
            reconcile,
        )
    }

    fn last(&self) -> zdn::state::OperationReceipt {
        self.store
            .operation(self.deployment.last_operation.unwrap())
            .unwrap()
    }
}

struct LifecycleBackend {
    state: PathBuf,
    file: PathBuf,
    output: zdn::infra::FoundationOutputs,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    cancel_install: bool,
    reconciles: Vec<bool>,
}

impl LifecycleBackend {
    fn step(&mut self, phase: &'static str) -> Result<()> {
        use zdn::state::{PhaseStatus, StateStore};
        self.calls.push(phase);
        let saved: zdn::foundation::Deployment = zdn::foundation::read_json(&self.file)?;
        let store = StateStore::open(&self.state)?;
        let receipt = store.operation(saved.last_operation.unwrap())?;
        assert!(
            matches!(
                lifecycle_phase(&receipt, phase),
                PhaseStatus::Running { .. }
            ),
            "{phase} must be durable before effects"
        );
        if matches!(phase, "install" | "readiness") {
            assert_eq!(
                saved.outputs.as_ref().unwrap().nodes.len(),
                3,
                "all output identities must be saved before install"
            );
        }
        if phase == "readiness" {
            assert!(matches!(
                lifecycle_phase(&receipt, "install"),
                PhaseStatus::Succeeded { .. }
            ));
        }
        if phase == "install" && self.cancel_install {
            store.request_cancel(receipt.operation_id, receipt.revision)?;
        }
        if self.fail == Some(phase) {
            eyre::bail!("fixture private remote details");
        }
        Ok(())
    }
}

impl zdn::foundation::FoundationBackend for LifecycleBackend {
    fn verify(&mut self, _: &zdn::foundation::Deployment, _: bool) -> Result<()> {
        self.step("verify")
    }
    fn reserve(&mut self, _: &zdn::foundation::Deployment) -> Result<()> {
        self.step("reserve")
    }
    fn acquire(&mut self, _: &zdn::foundation::Deployment, _: Uuid) -> Result<()> {
        self.step("lease")
    }
    fn prepare(&mut self, _: &zdn::foundation::Deployment, reconcile: bool) -> Result<()> {
        self.reconciles.push(reconcile);
        self.step("prepare")
    }
    fn preview(&mut self, _: bool) -> Result<Value> {
        self.step("preview")?;
        Ok(json!({"create":3}))
    }
    fn apply(&mut self, _: &zdn::foundation::Deployment) -> Result<zdn::infra::FoundationOutputs> {
        self.step("apply")?;
        Ok(self.output.clone())
    }
    fn deploy_runtime(&mut self, _: &zdn::foundation::Deployment) -> Result<Value> {
        self.step("install")?;
        Ok(json!({"nodesInstalled":3,"launchReady":false}))
    }
    fn ready(&mut self, _: &zdn::foundation::Deployment) -> Result<Value> {
        self.step("readiness")?;
        Ok(json!({"nodeReady":true,"launchReady":false}))
    }
    fn destroy(&mut self) -> Result<()> {
        self.step("destroy")
    }
    fn cleanup(
        &mut self,
        _: &zdn::foundation::Deployment,
        _: bool,
    ) -> Result<zdn::foundation::CleanupReport> {
        self.step("cleanup")?;
        Ok(zdn::foundation::CleanupReport {
            shared_backend_preserved: true,
            ..Default::default()
        })
    }
    fn remove_stack(&mut self) -> Result<()> {
        self.step("remove-stack")
    }
    fn release(&mut self) -> Result<()> {
        self.calls.push("release");
        Ok(())
    }
}

fn health_cli(
    cwd: &std::path::Path,
    state: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    // Missing HOME and an empty PATH make credential/tool setup an observable
    // failure, never a route to real AWS calls.
    std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .current_dir(cwd)
        .args(["devnet", "health"])
        .args(args)
        .args(["--state-dir", state.to_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
fn cli_health_help_and_timeout_bounds_require_no_state_or_credentials() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("must-not-be-created");
    let help = health_cli(root.path(), &state, &["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    for expected in ["<SELECTOR>", "--wait", "--timeout-seconds", "120"] {
        assert!(help.contains(expected), "missing {expected}: {help}");
    }
    for timeout in ["0", "7201", "4294967296", "not-a-number"] {
        let output = health_cli(
            root.path(),
            &state,
            &["absent", "--wait", "--timeout-seconds", timeout],
        );
        assert_eq!(output.status.code(), Some(2), "timeout {timeout}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("--timeout-seconds"), "{error}");
        assert!(!error.contains("HOME is required"), "{error}");
        assert!(!state.exists(), "argument parsing created saved state");
    }
    let missing = health_cli(root.path(), &state, &[]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("<SELECTOR>"));
    assert!(!state.exists());
}

#[test]
fn cli_health_rejects_local_lifecycle_states_before_credentials_without_mutation() {
    fn snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(
            root: &std::path::Path,
            directory: &std::path::Path,
            entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
        ) {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                let is_dir = path.is_dir();
                entries.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    if is_dir {
                        None
                    } else {
                        Some(fs::read(&path).unwrap())
                    },
                );
                if is_dir {
                    visit(root, &path, entries);
                }
            }
        }
        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    for (case, expected) in [
        ("unprovisioned", "health requires provisioned outputs"),
        ("destroyed", "health requires a live deployment"),
        ("unresolved", "health refuses an unresolved operation"),
        ("pending-update", "health refuses a pending update"),
        ("foundation-only", "legacy execution is retired"),
        (
            "interrupted-ledger",
            "health refuses an incomplete or foreign operation",
        ),
    ] {
        let mut f = Lifecycle::native();
        if case != "unprovisioned" {
            let mut backend = f.backend();
            f.apply(&mut backend, false).unwrap();
            match case {
                "destroyed" => {
                    zdn::foundation::destroy(
                        &f.store,
                        &f.file,
                        &f.binding,
                        &mut f.deployment,
                        &mut backend,
                        false,
                        false,
                    )
                    .unwrap();
                }
                "unresolved" => f.deployment.unresolved_operation = Some(Uuid::new_v4()),
                "interrupted-ledger" => {
                    let receipt = f
                        .store
                        .begin_operation(
                            &f.binding,
                            "devnet-up",
                            zdn::state::OperationInput {
                                config_sha256: "a".repeat(64),
                                source_manifest_sha256: None,
                                archive_sha256: None,
                            },
                            &["readiness"],
                        )
                        .unwrap();
                    f.store
                        .record_phase(
                            receipt.operation_id,
                            receipt.revision,
                            "readiness",
                            zdn::state::PhaseStatus::Running { external_ref: None },
                        )
                        .unwrap();
                    // A crash can leave Running before unresolved_operation is persisted.
                    f.deployment.last_operation = Some(receipt.operation_id);
                }
                "pending-update" => {
                    zdn::foundation::update_controller::prepare(
                        &mut f.deployment,
                        &["node-2".into()],
                        true,
                    )
                    .unwrap();
                }
                "foundation-only" => {
                    f.deployment.cluster = None;
                    f.deployment.runtime = None;
                    f.deployment.outputs.as_mut().unwrap().nodes.clear();
                }
                _ => unreachable!(),
            }
            f.file.save(&f.deployment).unwrap();
        }
        zdn::foundation::private_directory(&f.store.root().join("profiles")).unwrap();
        zdn::foundation::write_json(
            &f.store.root().join("profiles/devnet.json"),
            &json!({"team":f.deployment.team,"awsProfile":"developer"}),
        )
        .unwrap();
        let id = f.binding.network_id.to_string();
        drop(f.file);
        let before = snapshot(f.store.root());
        // Default and explicit valid bounds must reach local preflight. Exercise
        // all selector forms, not just an implementation's UUID-only happy path.
        for args in [
            vec!["lifecycle"],
            vec![id.as_str(), "--wait", "--timeout-seconds", "1"],
            vec![&id[..8], "--timeout-seconds", "7200"],
        ] {
            let output = health_cli(f._inputs.root.path(), f.store.root(), &args);
            assert!(!output.status.success(), "accepted {case}");
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains(expected), "{case}: {error}");
            assert!(!error.contains("HOME is required"), "{case}: {error}");
            assert!(output.stdout.is_empty(), "reported success for {case}");
            assert_eq!(snapshot(f.store.root()), before, "mutated {case}");
        }
    }
}

fn lifecycle_phase<'a>(
    receipt: &'a zdn::state::OperationReceipt,
    name: &str,
) -> &'a zdn::state::PhaseStatus {
    &receipt
        .phases
        .iter()
        .find(|phase| phase.name == name)
        .unwrap()
        .status
}

#[test]
fn saved_package_with_older_helper_allows_inspection_and_destroy_but_not_execution() {
    use zdn::foundation::{self, DeploymentFile};
    let mut fixture = Lifecycle::native();
    let mut backend = fixture.backend();
    fixture.apply(&mut backend, false).unwrap();
    let mut package = deployment_package(&fixture._inputs, None);
    package.artifact_set.compatibility.helper_version = "0.0.0".into();
    fixture.deployment.cluster.as_mut().unwrap().artifact_set = Some(package.artifact_set.clone());
    fixture.file.save(&fixture.deployment).unwrap();
    fixture.deployment = fixture.file.load().unwrap();
    let snapshot =
        DeploymentFile::read_snapshot(fixture.store.root(), fixture.binding.network_id).unwrap();
    assert_eq!(
        snapshot
            .cluster
            .unwrap()
            .artifact_set
            .unwrap()
            .compatibility
            .helper_version,
        "0.0.0"
    );
    let fingerprint = package.artifact_set.fingerprint().unwrap();
    assert_eq!(
        fixture
            .deployment
            .cluster
            .as_ref()
            .unwrap()
            .artifact_set
            .as_ref()
            .unwrap()
            .fingerprint()
            .unwrap(),
        fingerprint
    );

    let error = fixture
        .deployment
        .cluster
        .as_ref()
        .unwrap()
        .verify_local(&fixture._inputs.output)
        .unwrap_err();
    assert!(error.to_string().contains("compatibility"));
    let (manifest, pin) = save_package(&fixture._inputs, &package);
    assert!(zdn::package::resolve(&manifest, &pin, &BTreeMap::new())
        .unwrap_err()
        .to_string()
        .contains("compatibility"));

    // The public up boundary must reject before invoking any backend operation.
    backend.calls.clear();
    assert!(fixture
        .apply(&mut backend, false)
        .unwrap_err()
        .to_string()
        .contains("compatibility"));
    assert!(backend.calls.is_empty());

    // Update must fail before publishing intent, looking up tools or calling AWS.
    foundation::private_directory(&fixture.store.root().join("profiles")).unwrap();
    foundation::write_json(
        &fixture.store.root().join("profiles/private-team.json"),
        &json!({"team":fixture.deployment.team,"awsProfile":"developer"}),
    )
    .unwrap();
    let before = serde_json::to_value(&fixture.deployment).unwrap();
    drop(fixture.file);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env("PATH", "")
        .args([
            "devnet",
            "update",
            "lifecycle",
            "--profile",
            "private-team",
            "--state-dir",
            fixture.store.root().to_str().unwrap(),
            "--node",
            "node-2",
            "--image-record",
            fixture._inputs.image_record.to_str().unwrap(),
            "--image-manifest",
            fixture._inputs.image_manifest.to_str().unwrap(),
            "--image-config",
            fixture._inputs.image_config.to_str().unwrap(),
            "--acknowledge-storage-compatibility",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("compatibility"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fixture.file = DeploymentFile::open(fixture.store.root(), fixture.binding.network_id).unwrap();
    assert_eq!(
        serde_json::to_value(fixture.file.load().unwrap()).unwrap(),
        before
    );

    foundation::destroy(
        &fixture.store,
        &fixture.file,
        &fixture.binding,
        &mut fixture.deployment,
        &mut backend,
        false,
        false,
    )
    .unwrap();
    assert!(fixture.file.load().unwrap().destroyed);
    assert!(backend.calls.contains(&"destroy") && backend.calls.contains(&"cleanup"));
}

#[test]
fn update_reporting_failures_preserve_confirmed_nodes_and_do_not_repeat_replacement() {
    use zdn::{foundation::update_controller as controller, update::ImageRevision};
    #[derive(Default)]
    struct Remote {
        replacements: BTreeMap<String, usize>,
        observations: BTreeMap<String, usize>,
        cluster_checks: usize,
    }
    impl controller::Backend for Remote {
        fn pulse(&mut self) -> Result<()> {
            Ok(())
        }
        fn stage(&mut self, _: &zdn::foundation::Deployment, _: &ImageRevision) -> Result<()> {
            Ok(())
        }
        fn dispatch(&mut self, deployment: &zdn::foundation::Deployment, node: &str) -> Result<()> {
            if node == "node-1" {
                assert!(deployment
                    .runtime
                    .as_ref()
                    .unwrap()
                    .update
                    .as_ref()
                    .unwrap()
                    .completed
                    .contains("node-3"));
            }
            *self.replacements.entry(node.into()).or_default() += 1;
            Ok(())
        }
        fn observe(
            &mut self,
            _: &zdn::foundation::Deployment,
            node: &str,
            _: &ImageRevision,
        ) -> Result<()> {
            assert_eq!(self.replacements.get(node), Some(&1));
            *self.observations.entry(node.into()).or_default() += 1;
            Ok(())
        }
        fn ready(&mut self, _: &zdn::foundation::Deployment) -> Result<()> {
            self.cluster_checks += 1;
            Ok(())
        }
    }
    for stop_after_finish in [false, true] {
        let mut f = Lifecycle::new();
        let mut backend = f.backend();
        f.apply(&mut backend, false).unwrap();
        let id = controller::prepare(&mut f.deployment, &["node-1".into(), "node-3".into()], true)
            .unwrap();
        let directory = f.file.directory().join("updates").join(id.to_string());
        fs::create_dir_all(directory.join("artifacts")).unwrap();
        let mut image_config: Value =
            serde_json::from_slice(&fs::read(&f._inputs.image_config).unwrap()).unwrap();
        image_config["config"]["Labels"] = json!({"fixture.revision": "new-image"});
        f._inputs.replace_image_config(&image_config);
        for (name, path) in [
            ("image.json", &f._inputs.image_record),
            ("image-manifest.json", &f._inputs.image_manifest),
            ("image-config.json", &f._inputs.image_config),
        ] {
            fs::copy(path, directory.join("artifacts").join(name)).unwrap();
        }
        let revision = ImageRevision::read(id, None, &directory).unwrap();
        controller::set_revision(&f.file, &mut f.deployment, revision).unwrap();
        let mut remote = Remote::default();
        let error = controller::run_with_progress(
            &f.file,
            &mut f.deployment,
            &mut remote,
            &mut |intent, node| {
                let saved = f.file.load()?;
                let runtime = saved.runtime.as_ref().unwrap();
                assert_eq!(runtime.update.as_ref().unwrap().completed, intent.completed);
                assert_eq!(runtime.update.as_ref().unwrap().finished, intent.finished);
                if let Some(node) = node {
                    assert!(intent.completed.contains(node));
                    assert_eq!(runtime.nodes[node].update_id, id);
                    assert_ne!(
                        runtime.nodes[node].image.image,
                        saved.cluster.as_ref().unwrap().image.image
                    );
                } else {
                    assert!(intent.finished);
                    assert!(directory.join("completed.json").exists());
                }
                if !stop_after_finish || intent.finished {
                    eyre::bail!("reporting interrupted");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "reporting interrupted");
        let saved = f.file.load().unwrap();
        let runtime = saved.runtime.as_ref().unwrap();
        assert_eq!(runtime.nodes.len(), if stop_after_finish { 2 } else { 1 });
        assert_eq!(runtime.update.as_ref().unwrap().finished, stop_after_finish);
        assert!(!runtime.nodes.contains_key("node-2"));
        assert_eq!(remote.cluster_checks, usize::from(stop_after_finish));
        // The saved assignment survives a process reload, while observation stays fresh.
        f.deployment = saved;
        controller::run(&f.file, &mut f.deployment, &mut remote).unwrap();
        assert_eq!(
            remote.replacements,
            BTreeMap::from([("node-1".into(), 1), ("node-3".into(), 1)])
        );
        assert_eq!(remote.observations["node-3"], 2);
        assert!(
            f.deployment
                .runtime
                .as_ref()
                .unwrap()
                .update
                .as_ref()
                .unwrap()
                .finished
        );
    }
}

#[test]
#[cfg(unix)]
fn machine_update_flushes_saved_identity_before_aws_and_preserves_uncertainty() {
    use std::{
        io::{BufRead, BufReader, Read},
        process::{Command, Stdio},
    };
    for format in ["json", "jsonl"] {
        let mut fixture = Lifecycle::native();
        let mut backend = fixture.backend();
        fixture.apply(&mut backend, false).unwrap();
        let root = fixture._inputs.root.path();
        machine_failure::install(root);
        let state = fixture.store.root();
        zdn::foundation::private_directory(&state.join("profiles")).unwrap();
        zdn::foundation::write_json(
            &state.join("profiles/private-team.json"),
            &json!({"team":fixture.deployment.team,"awsProfile":"developer"}),
        )
        .unwrap();
        let directory = fixture.file.directory().to_owned();
        drop(fixture.file);
        let events = root.join("events.jsonl");
        let release = root.join("release");
        if format == "json" {
            fs::write(&release, b"ready").unwrap();
        }
        let stderr = root.join("stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env_clear()
            .env("HOME", root)
            .env("PATH", root.join("bin"))
            .env("ZDN_FIXTURE_WAITING", root.join("waiting"))
            .env("ZDN_FIXTURE_RELEASE", &release)
            .args(["--format", format, "--progress-file"])
            .arg(&events)
            .args([
                "devnet",
                "update",
                "lifecycle",
                "--profile",
                "private-team",
                "--state-dir",
            ])
            .arg(state)
            .arg("--managed-dir")
            .arg(root.join("tools"))
            .args([
                "--yes",
                "--acknowledge-storage-compatibility",
                "--node",
                "node-2",
                "--image-record",
            ])
            .arg(&fixture._inputs.image_record)
            .arg("--image-manifest")
            .arg(&fixture._inputs.image_manifest)
            .arg("--image-config")
            .arg(&fixture._inputs.image_config)
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut records = Vec::<Value>::new();
        if format == "jsonl" {
            for kind in [
                "command-started",
                "update-prepared",
                "operation-started",
                "phase-started",
            ] {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let record: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(record["type"], kind, "{record}");
                records.push(record);
            }
            assert!(child.try_wait().unwrap().is_none());
            let saved =
                zdn::foundation::DeploymentFile::read_snapshot(state, fixture.binding.network_id)
                    .unwrap();
            assert_eq!(
                records[1]["data"]["updateId"],
                saved.runtime.unwrap().update.unwrap().id.to_string()
            );
            let operation = fixture
                .store
                .operation(saved.last_operation.unwrap())
                .unwrap();
            assert!(matches!(
                operation.phases[0].status,
                zdn::state::PhaseStatus::Running { .. }
            ));
            fs::write(&release, b"ready").unwrap();
        }
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        assert!(fs::read(stderr).unwrap().is_empty());
        let result: Value = if format == "json" {
            serde_json::from_str(&rest).unwrap()
        } else {
            records.extend(
                rest.lines()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap()),
            );
            records.last().unwrap().clone()
        };
        let file_records: Vec<Value> = fs::read_to_string(events)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(file_records.len(), 6);
        assert_eq!(file_records.last().unwrap(), &result);
        if format == "jsonl" {
            assert_eq!(file_records, records);
        }
        assert_eq!(file_records[4]["type"], "phase-result");
        assert_eq!(file_records[4]["outcome"], "unknown");
        assert_eq!(result["error"]["code"], "devnet-update-failed");
        assert_eq!(result["error"]["retryClassification"], "reconcile-required");
        let saved =
            zdn::foundation::DeploymentFile::read_snapshot(state, fixture.binding.network_id)
                .unwrap();
        assert_eq!(
            result["operationId"],
            saved.last_operation.unwrap().to_string()
        );
        assert_eq!(result["networkId"], fixture.binding.network_id.to_string());
        let intent = saved.runtime.unwrap().update.unwrap();
        assert_eq!(result["data"]["updateId"], intent.id.to_string());
        assert!(!intent.finished && intent.completed.is_empty());
        assert!(directory
            .join("updates")
            .join(intent.id.to_string())
            .join("artifacts/image.json")
            .exists());
        assert!(!result
            .to_string()
            .contains("fixture-diagnostic-not-for-export"));
    }
}

#[test]
fn cli_update_freezes_inputs_and_resumes_without_original_files() {
    for (from_source, format) in ["human", "json", "jsonl"].into_iter().flat_map(|format| {
        [false, true]
            .into_iter()
            .map(move |source| (source, format))
    }) {
        let mut fixture = Lifecycle::native();
        let mut backend = fixture.backend();
        fixture.apply(&mut backend, false).unwrap();
        zdn::foundation::private_directory(&fixture.store.root().join("profiles")).unwrap();
        zdn::foundation::write_json(
            &fixture.store.root().join("profiles/private-team.json"),
            &json!({"team":fixture.deployment.team,"awsProfile":"developer"}),
        )
        .unwrap();
        let directory = fixture.file.directory().to_owned();
        drop(fixture.file); // The subprocess must acquire the real deployment lock.
        let source = fixture._inputs.root.path().join("candidate");
        let config_path = fixture._inputs.root.path().join("candidate.yaml");
        let inputs = if from_source {
            fs::create_dir_all(source.join("docker")).unwrap();
            fs::write(
                source.join("docker/Dockerfile"),
                "FROM scratch AS runtime\n",
            )
            .unwrap();
            for args in [
                vec!["init", "--quiet"],
                vec!["add", "."],
                vec![
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
            ] {
                assert!(std::process::Command::new("git")
                    .current_dir(&source)
                    .args(args)
                    .status()
                    .unwrap()
                    .success());
            }
            let mut config = fixture._inputs.config.clone();
            config.node.source = Source {
                path: Some(source.clone()),
                ..Default::default()
            };
            config.node.build = Some(Default::default());
            fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
            vec![
                "--source-config",
                config_path.to_str().unwrap(),
                "--build-helper",
                fixture._inputs.helper.to_str().unwrap(),
            ]
        } else {
            // A valid, oversized fixture lets a subprocess file-size limit
            // fail artifact publication after the first two files succeed.
            let mut config: Value =
                serde_json::from_slice(&fs::read(&fixture._inputs.image_config).unwrap()).unwrap();
            config["fixturePadding"] = json!("x".repeat(128 * 1024));
            let config = serde_json::to_vec(&config).unwrap();
            fs::write(&fixture._inputs.image_config, &config).unwrap();
            let mut manifest: Value =
                serde_json::from_slice(&fs::read(&fixture._inputs.image_manifest).unwrap())
                    .unwrap();
            manifest["config"]["digest"] = json!(digest(&config));
            manifest["config"]["size"] = json!(config.len());
            let manifest = serde_json::to_vec(&manifest).unwrap();
            fs::write(&fixture._inputs.image_manifest, &manifest).unwrap();
            let mut image: ImageRecord =
                serde_json::from_slice(&fs::read(&fixture._inputs.image_record).unwrap()).unwrap();
            image.config_digest = digest(&config);
            image.image = format!(
                "{}@{}",
                image.image.split_once('@').unwrap().0,
                digest(&manifest)
            );
            fs::write(
                &fixture._inputs.image_record,
                serde_json::to_vec(&image).unwrap(),
            )
            .unwrap();
            vec![
                "--image-record",
                fixture._inputs.image_record.to_str().unwrap(),
                "--image-manifest",
                fixture._inputs.image_manifest.to_str().unwrap(),
                "--image-config",
                fixture._inputs.image_config.to_str().unwrap(),
            ]
        };
        let invoke = |extra: &[&str], limited: bool| {
            native_exec::command(
                &directory,
                env!("CARGO_BIN_EXE_zdn"),
                limited.then_some(65536),
            )
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            // No HOME: credential preparation stops before executing AWS.
            .args(["--format", format])
            .args([
                "devnet",
                "update",
                "lifecycle",
                "--profile",
                "private-team",
                "--state-dir",
                fixture.store.root().to_str().unwrap(),
                "--managed-dir",
                directory.to_str().unwrap(),
                "--acknowledge-storage-compatibility",
                "--yes",
            ])
            .args(extra)
            .output()
            .unwrap()
        };
        let check_failure = |output: &std::process::Output, legacy: &str| -> Value {
            assert_eq!(output.status.code(), Some(1));
            if format == "human" {
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains(legacy),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Value::Null;
            }
            assert!(output.stderr.is_empty());
            let stdout = String::from_utf8_lossy(&output.stdout);
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&stdout).unwrap()]
            } else {
                stdout
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            let result = records.last().unwrap();
            assert_eq!(result["error"]["code"], "devnet-update-failed");
            assert_eq!(result["error"]["retryClassification"], "blocked");
            for event in &records {
                assert_eq!(event["command"], "devnet update");
            }
            result.clone()
        };
        let mut start = vec!["--node", "node-2"];
        start.extend(inputs);
        if from_source {
            let before = fs::read(directory.join("deployment.json")).unwrap();
            let helper = fs::read(&fixture._inputs.helper).unwrap();
            fs::write(&fixture._inputs.helper, [0; 64]).unwrap();
            check_failure(&invoke(&start, false), "Linux x86-64 ELF");
            assert_eq!(fs::read(directory.join("deployment.json")).unwrap(), before);
            fs::write(&fixture._inputs.helper, helper).unwrap();
        } else {
            let before = fs::read(directory.join("deployment.json")).unwrap();
            assert!(before.len() < 65536);
            let failed = invoke(&start, true);
            assert!(!failed.status.success());
            assert!(!String::from_utf8_lossy(&failed.stderr).contains("HOME is required"));
            assert_eq!(fs::read(directory.join("deployment.json")).unwrap(), before);
            let orphan = fs::read_dir(directory.join("updates"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert!(orphan.join("artifacts/image-manifest.json").exists());
            assert!(!orphan.join("artifacts/image-config.json").exists());
        }
        let prepared = invoke(&start, false);
        let report = check_failure(&prepared, "HOME is required");
        let saved: zdn::foundation::Deployment =
            zdn::foundation::read_json(&directory.join("deployment.json")).unwrap();
        let intent = saved.runtime.as_ref().unwrap().update.as_ref().unwrap();
        let id = intent.id.to_string();
        if format != "human" {
            assert_eq!(report["networkId"], fixture.binding.network_id.to_string());
            assert_eq!(
                report["operationId"],
                saved.last_operation.unwrap().to_string()
            );
            assert_eq!(report["data"]["updateId"], id);
            assert_eq!(
                report["data"]["savedReceipt"]["phases"][0]["status"],
                "pending"
            );
        }
        let update_directory = directory.join("updates").join(&id);
        let frozen = if from_source {
            assert!(intent.build_contract_sha256.is_some());
            assert_eq!(
                intent.build_exporter_protocol.as_deref(),
                Some(zdn::build_export::PROTOCOL)
            );
            assert_eq!(
                fs::read(update_directory.join("build/exporter")).unwrap(),
                fs::read(&fixture._inputs.helper).unwrap()
            );
            fs::remove_dir_all(&source).unwrap();
            fs::remove_file(&config_path).unwrap();
            fs::remove_file(&fixture._inputs.helper).unwrap();
            update_directory.join("source-snapshot/source.tar")
        } else {
            assert!(intent.revision.is_some());
            fs::remove_file(&fixture._inputs.image_record).unwrap();
            fs::remove_file(&fixture._inputs.image_manifest).unwrap();
            fs::remove_file(&fixture._inputs.image_config).unwrap();
            update_directory.join("artifacts/image.json")
        };
        let bytes = fs::read(&frozen).unwrap();
        let resumed = invoke(&["--resume", &id, "--reconcile"], false);
        let resumed_report = check_failure(&resumed, "HOME is required");
        if format != "human" {
            assert_eq!(resumed_report["data"]["updateId"], id);
            assert_ne!(resumed_report["operationId"], report["operationId"]);
        }
        assert_eq!(fs::read(&frozen).unwrap(), bytes);
        if from_source {
            let attempt = update_directory.join("build/attempt.json");
            let original = fs::read(&attempt).unwrap();
            let mut downgraded: Value = serde_json::from_slice(&original).unwrap();
            downgraded.as_object_mut().unwrap().remove("exporter");
            zdn::foundation::write_json(&attempt, &downgraded).unwrap();
            check_failure(
                &invoke(&["--resume", &id, "--reconcile"], false),
                "native update exporter selection missing",
            );
            zdn::foundation::write_private(&attempt, &original).unwrap();
            let exporter = update_directory.join("build/exporter");
            let helper = fs::read(&exporter).unwrap();
            fs::write(&exporter, [helper.as_slice(), b"changed"].concat()).unwrap();
            check_failure(
                &invoke(&["--resume", &id, "--reconcile"], false),
                "saved native exporter changed",
            );
            zdn::foundation::write_private(&exporter, &helper).unwrap();
            let path = update_directory.join("build-contract.json");
            let mut contract: zdn::build::BuildContract =
                zdn::foundation::read_json(&path).unwrap();
            contract.revision = "e".repeat(40);
            zdn::foundation::write_json(&path, &contract).unwrap();
            let changed = invoke(&["--resume", &id, "--reconcile"], false);
            let changed_report = check_failure(&changed, "saved update build contract changed");
            if format != "human" {
                assert_eq!(changed_report["data"]["updateId"], id);
                assert!(changed_report["operationId"].is_null());
            }
        }
    }
}

#[test]
fn unresolved_image_update_blocks_up_and_destroy_before_backend_calls() {
    let mut fixture = Lifecycle::new();
    let mut backend = fixture.backend();
    fixture.apply(&mut backend, false).unwrap();
    zdn::foundation::update_controller::prepare(&mut fixture.deployment, &["node-2".into()], true)
        .unwrap();
    fixture.file.save(&fixture.deployment).unwrap();
    backend.calls.clear();
    for reconcile in [false, true] {
        assert!(fixture
            .apply(&mut backend, reconcile)
            .unwrap_err()
            .to_string()
            .contains("update"));
        assert!(zdn::foundation::destroy(
            &fixture.store,
            &fixture.file,
            &fixture.binding,
            &mut fixture.deployment,
            &mut backend,
            false,
            reconcile
        )
        .unwrap_err()
        .to_string()
        .contains("update"));
    }
    assert!(backend.calls.is_empty());
    zdn::foundation::private_directory(&fixture.store.root().join("profiles")).unwrap();
    zdn::foundation::write_json(
        &fixture.store.root().join("profiles/devnet.json"),
        &json!({"team":fixture.deployment.team,"awsProfile":"developer"}),
    )
    .unwrap();
    let path = fixture.file.directory().join("deployment.json");
    let before = fs::read(&path).unwrap();
    drop(fixture.file);
    for extra in [
        vec!["--saved", "lifecycle", "--yes"],
        vec!["--saved", "lifecycle", "--yes", "--reconcile"],
    ] {
        let error = saved_up(fixture._inputs.root.path(), fixture.store.root(), &extra);
        assert!(error.contains("an image update is unresolved"), "{error}");
        assert!(!error.contains("HOME is required"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn settled_runtime_up_reconciles_services_without_changing_assignments() {
    let mut fixture = Lifecycle::new();
    let mut backend = fixture.backend();
    fixture.apply(&mut backend, false).unwrap();
    let id = zdn::foundation::update_controller::prepare(
        &mut fixture.deployment,
        &["node-2".into()],
        true,
    )
    .unwrap();
    let cluster = fixture.deployment.cluster.as_ref().unwrap();
    let revision = zdn::update::ImageRevision {
        update_id: id,
        image: cluster.image.clone(),
        build: None,
        artifacts: cluster
            .artifacts
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "image.json" | "image-manifest.json" | "image-config.json"
                )
            })
            .map(|(name, artifact)| (name.clone(), artifact.clone()))
            .collect(),
    };
    let runtime = fixture.deployment.runtime.as_mut().unwrap();
    runtime.nodes.insert("node-2".into(), revision.clone());
    let intent = runtime.update.as_mut().unwrap();
    intent.revision = Some(revision);
    intent.completed.insert("node-2".into());
    intent.finished = true;
    fixture.file.save(&fixture.deployment).unwrap();
    let before = serde_json::to_value(&fixture.deployment.runtime).unwrap();
    backend.fail = Some("install");
    assert!(fixture.apply(&mut backend, false).is_err());
    assert!(matches!(
        lifecycle_phase(&fixture.last(), "install"),
        zdn::state::PhaseStatus::Unknown { .. }
    ));
    backend.fail = None;
    fixture.apply(&mut backend, true).unwrap();
    assert_eq!(
        serde_json::to_value(fixture.file.load().unwrap().runtime).unwrap(),
        before
    );
}

#[test]
fn cluster_install_is_durable_and_an_unknown_result_requires_reconcile() {
    use zdn::state::PhaseStatus;
    let mut fixture = Lifecycle::new();
    let mut backend = fixture.backend();
    backend.fail = Some("install");
    assert!(fixture.apply(&mut backend, false).is_err());
    let failed = fixture.last();
    assert_eq!(failed.kind, "devnet-up");
    assert!(matches!(
        lifecycle_phase(&failed, "install"),
        PhaseStatus::Unknown { .. }
    ));
    assert!(matches!(
        lifecycle_phase(&failed, "readiness"),
        PhaseStatus::Pending
    ));
    assert!(!serde_json::to_string(&failed)
        .unwrap()
        .contains("private remote"));
    assert_eq!(backend.calls.last(), Some(&"release"));
    assert_eq!(fixture.file.load().unwrap().outputs.unwrap().nodes.len(), 3);
    let calls = backend.calls.len();
    backend.fail = None;
    assert!(fixture
        .apply(&mut backend, false)
        .unwrap_err()
        .to_string()
        .contains("reconcile"));
    assert_eq!(backend.calls.len(), calls);
    let recovered = fixture.apply(&mut backend, true).unwrap();
    assert_ne!(failed.operation_id, recovered.operation_id);
    assert!(recovered
        .phases
        .iter()
        .all(|phase| matches!(phase.status, PhaseStatus::Succeeded { .. })));
    assert_eq!(backend.reconciles, [false, true]);
    assert!(fixture.file.load().unwrap().unresolved_operation.is_none());
}

#[test]
fn unchanged_cluster_install_still_needs_fresh_readiness_before_success() {
    use zdn::state::PhaseStatus;
    let mut fixture = Lifecycle::new();
    let mut backend = fixture.backend();
    let first = fixture.apply(&mut backend, false).unwrap();
    backend.fail = Some("readiness");
    assert!(fixture.apply(&mut backend, false).is_err());
    let second = fixture.last();
    assert_ne!(first.operation_id, second.operation_id);
    assert!(matches!(
        lifecycle_phase(&second, "install"),
        PhaseStatus::Succeeded { .. }
    ));
    assert!(matches!(
        lifecycle_phase(&second, "readiness"),
        PhaseStatus::Failed {
            retry_safe: true,
            ..
        }
    ));
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|&&name| name == "install")
            .count(),
        2
    );
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|&&name| name == "readiness")
            .count(),
        2
    );
    assert_eq!(backend.calls.last(), Some(&"release"));
    backend.fail = None;
    fixture.apply(&mut backend, false).unwrap();
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|&&name| name == "readiness")
            .count(),
        3
    );
}

#[test]
fn cancellation_after_install_preserves_outputs_and_does_not_start_readiness() {
    use zdn::state::PhaseStatus;
    let mut fixture = Lifecycle::new();
    let mut backend = fixture.backend();
    backend.cancel_install = true;
    assert!(fixture.apply(&mut backend, false).is_err());
    let receipt = fixture.last();
    assert!(receipt.cancel_requested);
    assert!(matches!(
        lifecycle_phase(&receipt, "install"),
        PhaseStatus::Succeeded { .. }
    ));
    assert!(matches!(
        lifecycle_phase(&receipt, "readiness"),
        PhaseStatus::Pending
    ));
    assert!(!backend.calls.contains(&"readiness"));
    assert_eq!(backend.calls.last(), Some(&"release"));
    assert_eq!(fixture.file.load().unwrap().outputs.unwrap().nodes.len(), 3);
}

#[test]
fn incomplete_cluster_apply_outputs_are_uncertain_before_any_host_install() {
    use zdn::state::PhaseStatus;
    for count in [0, 1] {
        let mut fixture = Lifecycle::new();
        let mut backend = fixture.backend();
        backend
            .output
            .nodes
            .retain(|node, _| count == 1 && node == "node-1");
        assert!(fixture.apply(&mut backend, false).is_err());
        assert!(matches!(
            lifecycle_phase(&fixture.last(), "apply"),
            PhaseStatus::Unknown { .. }
        ));
        assert!(!backend.calls.contains(&"install"));
        assert_eq!(backend.calls.last(), Some(&"release"));
        assert!(fixture.file.load().unwrap().outputs.is_none());
    }
}

#[test]
fn endpoint_export_requires_completed_client_install_and_is_read_only_during_writer_lock() {
    let mut f = Lifecycle::new();
    f.deployment.outputs = Some(f.backend().output);
    f.file.save(&f.deployment).unwrap();
    zdn::foundation::private_directory(&f.store.root().join("profiles")).unwrap();
    zdn::foundation::write_json(
        &f.store.root().join("profiles/private-team.json"),
        &json!({"team":f.deployment.team,"awsProfile":"developer"}),
    )
    .unwrap();
    let output_path = f._inputs.root.path().join("participant-endpoints.json");
    let invoke = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
            .env("PATH", "")
            .args([
                "endpoints",
                "lifecycle",
                "--profile",
                "private-team",
                "--state-dir",
                f.store.root().to_str().unwrap(),
                "--output",
                output_path.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let missing = invoke();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("installation has not completed"));
    assert!(!output_path.exists());
    let endpoints = zdn::endpoints::EndpointFile::from_deployment(&f.deployment).unwrap();
    zdn::foundation::write_json(
        &f.file.directory().join("client-endpoints.json"),
        &endpoints,
    )
    .unwrap();
    let deployment_before = fs::read(f.file.directory().join("deployment.json")).unwrap();
    let export = invoke();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(
        zdn::endpoints::EndpointFile::load(&output_path).unwrap(),
        endpoints
    );
    assert_eq!(
        fs::read(f.file.directory().join("deployment.json")).unwrap(),
        deployment_before
    );
    let bytes = fs::read(&output_path).unwrap();
    assert!(!invoke().status.success());
    assert_eq!(fs::read(&output_path).unwrap(), bytes);
}

fn handoff_cli(
    cwd: &std::path::Path,
    state: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
        .env_clear()
        .env("PATH", "")
        .current_dir(cwd)
        .args(["devnet", "handoff"])
        .args(args)
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "--profile",
            "private-team",
        ])
        .output()
        .unwrap()
}

#[test]
fn cli_handoff_roundtrip_rebinds_workspace_and_resumes_without_original_inputs() {
    for lightwallet in [false, true] {
        let mut f = Fixture::new();
        let lw = lightwallet.then(|| LightwalletFixture::new(&mut f));
        let (source, state) = cli_fixture(&f);
        let mut args = cli_inputs(&f);
        if let Some(lw) = &lw {
            args.extend(lw.cli_inputs());
        }
        let rendered = cli(&source, &state, "render", &args);
        assert!(
            rendered.status.success(),
            "{}",
            String::from_utf8_lossy(&rendered.stderr)
        );
        let rendered: Value = serde_json::from_slice(&rendered.stdout).unwrap();
        let id = rendered["networkId"].as_str().unwrap();
        let original = state.join("foundation").join(id);
        for excluded in ["credentials", "project", "diagnostics", "source-snapshot"] {
            zdn::foundation::private_directory(&original.join(excluded)).unwrap();
            fs::write(
                original.join(excluded).join("secret"),
                "must-not-be-transferred",
            )
            .unwrap();
        }
        let archive = f.root.path().join("handoff.tar");
        let exported = handoff_cli(
            &source,
            &state,
            &["export", id, "--output", archive.to_str().unwrap()],
        );
        assert!(
            exported.status.success(),
            "{}",
            String::from_utf8_lossy(&exported.stderr)
        );
        let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
        let pin = exported["sha256"].as_str().unwrap();
        let raw = fs::read(&archive).unwrap();
        assert_eq!(sha256(&raw), pin);
        assert!(!raw
            .windows(b"must-not-be-transferred".len())
            .any(|b| b == b"must-not-be-transferred"));
        assert!(!handoff_cli(
            &source,
            &state,
            &["export", id, "--output", archive.to_str().unwrap()]
        )
        .status
        .success());
        assert_eq!(fs::read(&archive).unwrap(), raw);

        let receiving_source = f.root.path().join("receiving-workspace");
        let receiving_state = f.root.path().join("receiving-state");
        fs::create_dir(&receiving_source).unwrap();
        fs::copy(
            source.join("devnet.yaml"),
            receiving_source.join("devnet.yaml"),
        )
        .unwrap();
        zdn::state::StateStore::open(&receiving_state).unwrap();
        zdn::foundation::private_directory(&receiving_state.join("profiles")).unwrap();
        fs::copy(
            state.join("profiles/private-team.json"),
            receiving_state.join("profiles/private-team.json"),
        )
        .unwrap();
        let import_args = [
            "import",
            "--from",
            archive.to_str().unwrap(),
            "--sha256",
            pin,
            "--network-id",
            id,
            "--team-id",
            "private-team",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
        ];
        let imported = handoff_cli(&receiving_source, &receiving_state, &import_args);
        assert!(
            imported.status.success(),
            "{}",
            String::from_utf8_lossy(&imported.stderr)
        );
        let imported: Value = serde_json::from_slice(&imported.stdout).unwrap();
        assert_eq!(imported["networkId"], id);
        assert_eq!(imported["deploymentStarted"], false);
        assert_eq!(imported["cloudAccessChecked"], false);
        assert_eq!(
            imported["binding"]["context"]["config_path"],
            receiving_source.join("devnet.yaml").to_str().unwrap()
        );
        let target = receiving_state.join("foundation").join(id);
        let deployment: zdn::foundation::Deployment =
            zdn::foundation::read_json(&target.join("deployment.json")).unwrap();
        deployment
            .cluster
            .as_ref()
            .unwrap()
            .verify_local(&target)
            .unwrap();
        for excluded in [
            "credentials",
            "project",
            "diagnostics",
            "build",
            "source-snapshot",
        ] {
            assert!(!target.join(excluded).exists());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(target.join("artifacts/chain.tar"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let before = fs::read(target.join("deployment.json")).unwrap();
        assert!(
            !handoff_cli(&receiving_source, &receiving_state, &import_args)
                .status
                .success()
        );
        assert_eq!(fs::read(target.join("deployment.json")).unwrap(), before);
        fs::remove_dir_all(&source).unwrap();
        fs::remove_dir_all(&state).unwrap();
        for input in [
            &f.manifest,
            &f.bundle,
            &f.image_record,
            &f.image_manifest,
            &f.image_config,
            &f.helper,
        ] {
            fs::remove_file(input).unwrap();
        }
        fs::remove_file(receiving_source.join("devnet.yaml")).unwrap();
        let error = saved_up(
            &receiving_source,
            &receiving_state,
            &["--saved", id, "--profile", "private-team", "--yes"],
        );
        assert!(error.contains("HOME is required"), "{error}");
        assert_eq!(fs::read(target.join("deployment.json")).unwrap(), before);
    }
}

#[test]
fn handoff_rejects_malformed_archives_and_identity_changes_before_publication() {
    use std::io::Read;
    let f = Lifecycle::new();
    for name in f.deployment.cluster.as_ref().unwrap().artifacts.keys() {
        zdn::foundation::private_directory(&f.file.directory().join("artifacts")).unwrap();
        fs::copy(
            f._inputs.output.join("artifacts").join(name),
            f.file.directory().join("artifacts").join(name),
        )
        .unwrap();
    }
    let id = f.binding.network_id;
    let context = f.binding.context.clone();
    let profile = zdn::aws::LocalProfile {
        team: f.deployment.team.clone(),
        aws_profile: "developer".into(),
    };
    drop(f.file);
    let archive = f._inputs.root.path().join("valid.tar");
    let pin = zdn::handoff::export::export(&f.store, &f.binding, &archive).unwrap();
    let mut original = Vec::new();
    for entry in tar::Archive::new(fs::File::open(&archive).unwrap())
        .entries()
        .unwrap()
    {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        original.push((name, bytes));
    }
    for case in [
        "control",
        "wrong-id",
        "wrong-team",
        "wrong-profile",
        "missing",
        "duplicate",
        "undeclared",
        "traversal",
        "absolute",
        "symlink",
        "corrupt",
        "bad-version",
        "incomplete-build",
    ] {
        let receiver =
            zdn::state::StateStore::open(f._inputs.root.path().join(format!("receiver-{case}")))
                .unwrap();
        let mut entries = original.clone();
        let mut profile = profile.clone();
        let mut selected_id = id;
        match case {
            "wrong-id" => selected_id = Uuid::new_v4(),
            "wrong-team" => profile.team.bootstrap_id = Uuid::new_v4(),
            "wrong-profile" => profile.aws_profile = "another-name".into(),
            "missing" => {
                entries.pop();
            }
            "duplicate" => entries.push(entries.last().unwrap().clone()),
            "undeclared" | "traversal" | "absolute" | "symlink" => entries.push((
                match case {
                    "traversal" => "../escaped",
                    "absolute" => "/escaped",
                    _ => "undeclared",
                }
                .into(),
                b"invalid".to_vec(),
            )),
            "corrupt" => entries.last_mut().unwrap().1[0] ^= 1,
            "bad-version" | "incomplete-build" => {
                let mut value: Value = serde_json::from_slice(&entries[0].1).unwrap();
                if case == "bad-version" {
                    value["apiVersion"] = json!("future");
                } else {
                    value["deployment"]["cluster"] = Value::Null;
                }
                entries[0].1 = serde_json::to_vec(&value).unwrap();
            }
            _ => {}
        }
        let candidate = f._inputs.root.path().join(format!("{case}.tar"));
        let mut tar = tar::Builder::new(fs::File::create(&candidate).unwrap());
        for (index, (name, bytes)) in entries.iter().enumerate() {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(if case == "symlink" && index == entries.len() - 1 {
                tar::EntryType::Symlink
            } else {
                tar::EntryType::Regular
            });
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            tar.append(&header, &bytes[..]).unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        let candidate_pin = sha256(&fs::read(&candidate).unwrap());
        let result = zdn::handoff::import::import(
            &receiver,
            &context,
            selected_id,
            &profile,
            &candidate,
            &candidate_pin,
        );
        if case == "control" {
            result.unwrap();
            assert_eq!(pin, candidate_pin);
        } else {
            assert!(result.is_err(), "accepted {case}");
            assert!(
                receiver.list(&context.scope).unwrap().is_empty(),
                "published {case}"
            );
            assert!(
                !receiver.root().join("foundation").exists(),
                "installed {case}"
            );
        }
    }
}

#[test]
fn completed_handoff_preserves_terminal_journals_and_prior_cancellation_evidence() {
    completed_handoff(0, false, false, None, false);
}

#[test]
fn completed_update_handoff_roundtrips_selected_nodes_and_resumes_without_install() {
    completed_handoff(1, false, false, None, false);
}

#[test]
fn repeated_update_handoff_retains_old_history_and_completed_update_operation() {
    completed_handoff(2, true, false, None, false);
}

#[test]
fn source_built_handoff_preserves_receipts_and_native_resume_contract() {
    completed_handoff(1, true, true, None, false);
    completed_handoff(2, true, true, None, true);
}

#[test]
fn handoff_rejects_cross_node_update_dependency_cycles() {
    completed_handoff(3, true, false, None, false);
}

#[test]
fn interrupted_update_handoff_preserves_settled_commands_and_prior_revisions() {
    completed_handoff(2, true, false, Some("succeeded"), false);
    completed_handoff(1, true, true, Some("succeeded"), false);
}

#[test]
fn interrupted_update_handoff_recovers_existing_commands_without_redispatch() {
    completed_handoff(2, true, false, Some("running"), false);
    completed_handoff(1, true, true, Some("dispatched"), false);
    completed_handoff(1, true, true, Some("dispatched"), true);
}

#[test]
fn interrupted_update_handoff_preserves_prepared_attempt_until_explicit_resume() {
    completed_handoff(1, true, false, Some("prepared"), false);
}

#[test]
fn interrupted_update_handoff_preserves_completion_publication_without_finishing() {
    completed_handoff(2, true, false, Some("publication"), false);
    completed_handoff(1, true, true, Some("publication"), false);
    completed_handoff(1, true, true, Some("publication"), true);
}

fn completed_handoff(
    rounds: usize,
    update_operation: bool,
    from_source: bool,
    command_state: Option<&str>,
    native_exporter: bool,
) {
    let interrupted = command_state.is_some();
    let publication = command_state == Some("publication");
    let mut f = Lifecycle::native();
    let history = f
        .store
        .begin_operation(
            &f.binding,
            "cancelled-history",
            zdn::state::OperationInput {
                config_sha256: "a".repeat(64),
                source_manifest_sha256: None,
                archive_sha256: None,
            },
            &["prepare"],
        )
        .unwrap();
    let history = f
        .store
        .request_cancel(history.operation_id, history.revision)
        .unwrap();
    f.store
        .record_phase(
            history.operation_id,
            history.revision,
            "prepare",
            zdn::state::PhaseStatus::Cancelled,
        )
        .unwrap();
    let mut backend = f.backend();
    f.apply(&mut backend, false).unwrap();
    let directory = f.file.directory().to_owned();
    zdn::foundation::private_directory(&directory.join("artifacts")).unwrap();
    for name in f.deployment.cluster.as_ref().unwrap().artifacts.keys() {
        fs::copy(
            f._inputs.output.join("artifacts").join(name),
            directory.join("artifacts").join(name),
        )
        .unwrap();
    }
    // Real rendered installers, synthetic terminal evidence; never execute hosts or AWS.
    let request = f.deployment.cluster.as_ref().unwrap();
    for node in f.deployment.outputs.as_ref().unwrap().nodes.values() {
        let host = request
            .host_spec(&f.deployment.spec, &f.deployment.team, node)
            .unwrap();
        let script = zdn::host::runtime::bootstrap::render(&native_manifest(&host)).unwrap();
        handoff_installer_evidence(
            &f.deployment,
            &directory,
            &node.node_id,
            &node.instance_id,
            &script,
            7200,
        );
        if node.node_id == "node-1" {
            let script = native_command(&host, true, "install");
            handoff_installer_evidence(
                &f.deployment,
                &directory,
                "client-rpc",
                &node.instance_id,
                &script,
                600,
            );
            let mut observation = handoff_command_evidence(
                &node.instance_id,
                &native_command(&host, true, "observe"),
                360,
            );
            observation["attempts"][0]["state"] = json!("dispatched");
            observation["attempts"][0]["commandId"] = Value::Null;
            observation["attempts"][0]["uncertain"] = json!(true);
            observation["attempts"][0]["output"] = Value::Null;
            zdn::foundation::write_json(
                &directory.join(format!("client-rpc-observe-{}.json", Uuid::new_v4())),
                &observation,
            )
            .unwrap();
        }
    }
    let producer = handoff_command_evidence(
        &f.deployment.outputs.as_ref().unwrap().nodes["node-1"].instance_id,
        &native_command(
            &request
                .host_spec(
                    &f.deployment.spec,
                    &f.deployment.team,
                    &f.deployment.outputs.as_ref().unwrap().nodes["node-1"],
                )
                .unwrap(),
            false,
            "start-producer",
        ),
        720,
    );
    zdn::foundation::write_json(
        &directory.join("node-1-start-producer-command.json"),
        &producer,
    )
    .unwrap();
    let observation_name = format!("node-2-observe-{}.json", Uuid::new_v4());
    let mut observation = handoff_command_evidence(
        &f.deployment.outputs.as_ref().unwrap().nodes["node-2"].instance_id,
        &native_command(
            &request
                .host_spec(
                    &f.deployment.spec,
                    &f.deployment.team,
                    &f.deployment.outputs.as_ref().unwrap().nodes["node-2"],
                )
                .unwrap(),
            false,
            "observe",
        ),
        300,
    );
    observation["attempts"][0]["state"] = json!("running");
    observation["attempts"][0]["uncertain"] = json!(true);
    observation["attempts"][0]["output"] = Value::Null;
    zdn::foundation::write_json(&directory.join(&observation_name), &observation).unwrap();
    let mut update_paths = Vec::new();
    for round in 0..rounds {
        use zdn::foundation::update_controller as controller;
        let targets = if round == 0 || rounds == 3 {
            vec!["node-1".into(), "node-2".into()]
        } else {
            vec!["node-1".into()]
        };
        let id = controller::prepare(&mut f.deployment, &targets, true).unwrap();
        let id = if rounds == 3 {
            // Make ancestry run opposite to map/UUID ordering, with both node
            // targets sharing each predecessor. Handoff must accept this before
            // the later mutation introduces a per-node-valid cross-node cycle.
            let reverse_id = Uuid::parse_str(&format!(
                "{:08x}-0000-4000-8000-000000000000",
                rounds - round
            ))
            .unwrap();
            f.deployment
                .runtime
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap()
                .id = reverse_id;
            reverse_id
        } else {
            id
        };
        let update_directory = directory.join("updates").join(id.to_string());
        zdn::foundation::private_directory(&directory.join("updates")).unwrap();
        zdn::foundation::private_directory(&update_directory).unwrap();
        zdn::foundation::private_directory(&update_directory.join("artifacts")).unwrap();
        let mut config: Value =
            serde_json::from_slice(&fs::read(&f._inputs.image_config).unwrap()).unwrap();
        config["config"]["Labels"] = json!({"fixture.revision":round.to_string()});
        f._inputs.replace_image_config(&config);
        let build = from_source.then(|| {
            let contract = zdn::build::BuildContract {
                api_version: zdn::build::API_VERSION.into(),
                source_sha256: "a".repeat(64),
                source_bytes: 1,
                revision: "c".repeat(40),
                platform: "linux/amd64".into(),
                required_capabilities: ImageCapabilities::default(),
                recipe: zdn::build::BuildRecipe {
                    dockerfile: "Dockerfile".into(),
                    context: ".".into(),
                    target: "runtime".into(),
                },
            };
            let mut image: ImageRecord =
                zdn::foundation::read_json(&f._inputs.image_record).unwrap();
            image.provenance = ImageProvenance::Source {
                revision: contract.revision.clone(),
                snapshot_sha256: contract.source_sha256.clone(),
            };
            if native_exporter {
                let infra =
                    zdn::build_infra::BuildInfrastructure::for_team(&f.deployment.team).unwrap();
                image.image = format!(
                    "{}@{}",
                    infra.repository_uri,
                    image.manifest_digest().unwrap()
                );
            }
            zdn::foundation::write_json(&f._inputs.image_record, &image).unwrap();
            zdn::foundation::write_json(&update_directory.join("build-contract.json"), &contract)
                .unwrap();
            f.deployment
                .runtime
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap()
                .build_contract_sha256 = Some(contract.fingerprint().unwrap());
            contract
        });
        for (name, source) in [
            ("image.json", &f._inputs.image_record),
            ("image-manifest.json", &f._inputs.image_manifest),
            ("image-config.json", &f._inputs.image_config),
        ] {
            fs::copy(source, update_directory.join("artifacts").join(name)).unwrap();
        }
        let revision = zdn::update::ImageRevision::read(id, build, &update_directory).unwrap();
        if native_exporter {
            let contract = revision.build.as_ref().unwrap();
            let build = update_directory.join("build");
            zdn::build_job::prepare_native(&build, &f.deployment.team, contract, &f._inputs.helper)
                .unwrap();
            let mut receipt: Value =
                zdn::foundation::read_json(&build.join("attempt.json")).unwrap();
            if round == 0 {
                receipt["sourceVersion"] = json!("source-version");
                receipt["exporter"]["version"] = json!("runtime-version");
                receipt["dispatched"] = json!(true);
                receipt["buildId"] = json!(format!(
                    "{}:{}",
                    receipt["project"].as_str().unwrap(),
                    Uuid::new_v4()
                ));
                receipt["terminal"] = json!("SUCCEEDED");
            } else {
                receipt["reused"] = json!(Uuid::new_v4());
            }
            zdn::foundation::write_json(&build.join("attempt.json"), &receipt).unwrap();
            zdn::foundation::write_json(
                &build.join("result.json"),
                &zdn::build_job::BuildResult {
                    contract_sha256: contract.fingerprint().unwrap(),
                    image: revision.image.clone(),
                },
            )
            .unwrap();
            for name in revision.artifacts.keys() {
                fs::copy(
                    update_directory.join("artifacts").join(name),
                    build.join(name),
                )
                .unwrap();
            }
            f.deployment
                .runtime
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap()
                .build_exporter_protocol = Some(zdn::build_export::PROTOCOL.into());
        }
        assert_ne!(
            revision.image.image,
            f.deployment.cluster.as_ref().unwrap().image.image
        );
        controller::set_revision(&f.file, &mut f.deployment, revision).unwrap();
        controller::run(
            &f.file,
            &mut f.deployment,
            &mut HandoffUpdateBackend(directory.clone()),
        )
        .unwrap();
        assert!(update_directory.join("completed.json").exists());
        update_paths.push(format!("updates/{id}/node-1-update.sh"));
        update_paths.push(format!("updates/{id}/node-1-command.json"));
        update_paths.push(format!("updates/{id}/artifacts/image-config.json"));
    }
    // Old controllers saved only the latest finished intent in deployment.json.
    // The exporter may synthesize that metadata, but never earlier history.
    if rounds == 1 && !publication {
        let id = f
            .deployment
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap()
            .id;
        fs::remove_file(directory.join(format!("updates/{id}/completed.json"))).unwrap();
    }
    if rounds > 0 {
        assert_eq!(
            zdn::update::active_image(&f.deployment, "node-3")
                .unwrap()
                .image,
            f.deployment.cluster.as_ref().unwrap().image.image
        );
        assert_ne!(
            zdn::update::active_image(&f.deployment, "node-1")
                .unwrap()
                .image,
            f.deployment.cluster.as_ref().unwrap().image.image
        );
    }
    if interrupted {
        let runtime = f.deployment.runtime.as_mut().unwrap();
        let intent = runtime.update.as_mut().unwrap();
        intent.finished = false;
        if !publication {
            intent.completed.remove("node-1");
            let previous = intent.targets["node-1"].expected_update_id;
            if let Some(id) = previous {
                let prior: zdn::update::UpdateIntent = zdn::foundation::read_json(
                    &directory.join(format!("updates/{id}/completed.json")),
                )
                .unwrap();
                runtime
                    .nodes
                    .insert("node-1".into(), prior.revision.unwrap());
            } else {
                runtime.nodes.remove("node-1");
            }
        }
        let completed = directory.join(format!("updates/{}/completed.json", intent.id));
        if completed.exists() && !publication {
            fs::remove_file(completed).unwrap();
        }
        if matches!(command_state, Some("prepared" | "running" | "dispatched")) {
            let command = directory.join(format!("updates/{}/node-1-command.json", intent.id));
            let mut journal: Value = zdn::foundation::read_json(&command).unwrap();
            let attempt = &mut journal["attempts"][0];
            attempt["state"] = json!(command_state.unwrap());
            attempt["uncertain"] = json!(command_state != Some("prepared"));
            attempt["cancellationRequested"] = json!(command_state != Some("prepared"));
            attempt["output"] = Value::Null;
            if matches!(command_state, Some("prepared" | "dispatched")) {
                attempt["commandId"] = Value::Null;
            }
            zdn::foundation::write_json(&command, &journal).unwrap();
        }
        f.file.save(&f.deployment).unwrap();
    }
    if update_operation {
        use zdn::state::PhaseStatus;
        let receipt = f
            .store
            .begin_operation(
                &f.binding,
                "devnet-update",
                zdn::state::OperationInput {
                    config_sha256: "a".repeat(64),
                    source_manifest_sha256: None,
                    archive_sha256: None,
                },
                &["update"],
            )
            .unwrap();
        let receipt = f
            .store
            .record_phase(
                receipt.operation_id,
                receipt.revision,
                "update",
                PhaseStatus::Running {
                    external_ref: interrupted.then(|| {
                        f.deployment
                            .runtime
                            .as_ref()
                            .unwrap()
                            .update
                            .as_ref()
                            .unwrap()
                            .id
                            .to_string()
                    }),
                },
            )
            .unwrap();
        f.store
            .record_phase(
                receipt.operation_id,
                receipt.revision,
                "update",
                if interrupted {
                    PhaseStatus::Unknown {
                        message: "controller stopped after command completion".into(),
                        external_ref: Some(
                            f.deployment
                                .runtime
                                .as_ref()
                                .unwrap()
                                .update
                                .as_ref()
                                .unwrap()
                                .id
                                .to_string(),
                        ),
                    }
                } else {
                    PhaseStatus::Succeeded {
                        result: json!({"updated":true}),
                    }
                },
            )
            .unwrap();
        f.deployment.last_operation = Some(receipt.operation_id);
        f.file.save(&f.deployment).unwrap();
    }
    let before = f.store.handoff_operations(&f.binding).unwrap();
    drop(f.file);
    if rounds > 0 {
        let update_id = update_paths[0].split('/').nth(1).unwrap();
        let build = directory.join(format!("updates/{update_id}/build"));
        zdn::foundation::private_directory(&build).unwrap();
        let saved_build = native_exporter.then(|| fs::read(build.join("attempt.json")).unwrap());
        zdn::foundation::write_private(&build.join("attempt.json"), b"{\"dispatched\":true}")
            .unwrap();
        let blocked = f._inputs.root.path().join("uncertain-update-build.tar");
        assert!(zdn::handoff::export::export(&f.store, &f.binding, &blocked).is_err());
        assert!(!blocked.exists());
        if let Some(saved) = saved_build {
            zdn::foundation::write_private(&build.join("attempt.json"), &saved).unwrap();
        } else {
            fs::remove_dir_all(&build).unwrap();
        }
        let mut missing = vec![update_paths[2].clone()];
        if native_exporter {
            for name in [
                "attempt.json",
                "result.json",
                "image.json",
                "image-manifest.json",
                "image-config.json",
            ] {
                missing.push(format!("updates/{update_id}/build/{name}"));
            }
        }
        if rounds > 1 {
            let old_id = update_paths[0].split('/').nth(1).unwrap();
            missing.push(format!("updates/{old_id}/completed.json"));
        }
        for name in missing {
            let path = directory.join(&name);
            let saved = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            let blocked = f._inputs.root.path().join("missing-update.tar");
            assert!(
                zdn::handoff::export::export(&f.store, &f.binding, &blocked).is_err(),
                "export accepted missing {name}"
            );
            assert!(!blocked.exists());
            zdn::foundation::write_private(&path, &saved).unwrap();
        }
        for entry in fs::read_dir(&directory).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if name.starts_with("client-rpc-observe-") && name.ends_with(".json") {
                update_paths.push(name);
            }
        }
    }
    let archive = f._inputs.root.path().join("completed.tar");
    zdn::foundation::private_directory(&directory.join("diagnostics")).unwrap();
    zdn::foundation::private_directory(&directory.join("diagnostics/health")).unwrap();
    fs::write(
        directory.join("diagnostics/health/uncertain.json"),
        b"not recovery evidence",
    )
    .unwrap();
    let pin = zdn::handoff::export::export(&f.store, &f.binding, &archive).unwrap();
    let receiver =
        zdn::state::StateStore::open(f._inputs.root.path().join("completed-receiver")).unwrap();
    let profile = zdn::aws::LocalProfile {
        team: f.deployment.team.clone(),
        aws_profile: "developer".into(),
    };
    let binding = zdn::handoff::import::import(
        &receiver,
        &f.binding.context,
        f.binding.network_id,
        &profile,
        &archive,
        &pin,
    )
    .unwrap();
    assert_eq!(receiver.handoff_operations(&binding).unwrap(), before);
    assert!(
        receiver
            .operation(history.operation_id)
            .unwrap()
            .cancel_requested
    );
    let target = receiver
        .root()
        .join("foundation")
        .join(binding.network_id.to_string());
    if native_exporter {
        for update in fs::read_dir(directory.join("updates")).unwrap() {
            let source = update.unwrap().path();
            let copied = target
                .join("updates")
                .join(source.file_name().unwrap())
                .join("build");
            assert!(!copied.join("exporter").exists());
            assert_eq!(
                zdn::build_job::removal_evidence(&copied, &f.deployment.team).unwrap(),
                zdn::build_job::removal_evidence(&source.join("build"), &f.deployment.team)
                    .unwrap()
            );
            let mut reader = tar::Archive::new(fs::File::open(&archive).unwrap());
            let mut manifest: zdn::handoff::Manifest =
                serde_json::from_reader(reader.entries().unwrap().next().unwrap().unwrap())
                    .unwrap();
            let receipt = copied.join("attempt.json");
            let saved = fs::read(&receipt).unwrap();
            let mut legacy: Value = serde_json::from_slice(&saved).unwrap();
            legacy.as_object_mut().unwrap().remove("exporter");
            let bytes = serde_json::to_vec(&legacy).unwrap();
            zdn::foundation::write_private(&receipt, &bytes).unwrap();
            manifest.files.insert(
                format!(
                    "updates/{}/build/attempt.json",
                    source.file_name().unwrap().to_str().unwrap()
                ),
                devnet::Artifact {
                    sha256: sha256(&bytes),
                    bytes: bytes.len() as u64,
                },
            );
            assert!(
                manifest.verify_directory(&target).is_err(),
                "accepted a repinned legacy receipt for a native update"
            );
            zdn::foundation::write_private(&receipt, &saved).unwrap();
        }
    }
    assert!(!target.join("diagnostics").exists());
    assert_eq!(
        fs::read(target.join("node-2-install-command.json")).unwrap(),
        fs::read(directory.join("node-2-install-command.json")).unwrap()
    );
    let imported_file =
        zdn::foundation::DeploymentFile::open(receiver.root(), binding.network_id).unwrap();
    let mut imported = imported_file.load().unwrap();
    assert_eq!(
        serde_json::to_value(&imported).unwrap(),
        serde_json::to_value(&f.deployment).unwrap()
    );
    if interrupted {
        use zdn::foundation::update_controller as controller;
        let intent = imported.runtime.as_ref().unwrap().update.as_ref().unwrap();
        let id = intent.id;
        assert!(!intent.finished);
        assert_eq!(intent.completed.contains("node-1"), publication);
        let command = target.join(format!("updates/{id}/node-1-command.json"));
        let before = fs::read(&command).unwrap();
        assert_eq!(
            before,
            fs::read(directory.join(format!("updates/{id}/node-1-command.json"))).unwrap()
        );
        let completed_path = target.join(format!("updates/{id}/completed.json"));
        assert_eq!(completed_path.exists(), publication);
        let completion_bytes = publication.then(|| fs::read(&completed_path).unwrap());
        let mut archive_reader = tar::Archive::new(fs::File::open(&archive).unwrap());
        let manifest: zdn::handoff::Manifest =
            serde_json::from_reader(archive_reader.entries().unwrap().next().unwrap().unwrap())
                .unwrap();
        assert!(zdn::update::validate_completed_history(&imported, &manifest.updates).is_err());
        if let Some(saved) = &completion_bytes {
            assert_eq!(
                fs::read(directory.join(format!("updates/{id}/completed.json"))).unwrap(),
                *saved
            );
            for field in ["finished", "completed", "baselineSha256"] {
                let mut changed: Value = serde_json::from_slice(saved).unwrap();
                changed[field] = match field {
                    "finished" => json!(false),
                    "completed" => json!([]),
                    _ => json!("0".repeat(64)),
                };
                let bytes = serde_json::to_vec(&changed).unwrap();
                zdn::foundation::write_private(&completed_path, &bytes).unwrap();
                let mut invalid = manifest.clone();
                invalid.files.insert(
                    format!("updates/{id}/completed.json"),
                    devnet::Artifact {
                        sha256: sha256(&bytes),
                        bytes: bytes.len() as u64,
                    },
                );
                assert!(
                    invalid.verify_directory(&target).is_err(),
                    "accepted {field}"
                );
                zdn::foundation::write_private(&completed_path, saved).unwrap();
            }
        }
        if let Some(older) = manifest.updates.keys().copied().find(|older| *older != id) {
            let mut invalid = manifest.clone();
            invalid.updates.get_mut(&older).unwrap().finished = false;
            invalid
                .files
                .remove(&format!("updates/{older}/completed.json"));
            assert!(
                invalid.validate().is_err(),
                "accepted an unfinished historical update"
            );
        }
        for case in [
            "cancelled",
            "wrong-update",
            "wrong-operation",
            "completed-operation",
            "missing-command",
        ] {
            let mut invalid = manifest.clone();
            let operation = invalid
                .operations
                .iter_mut()
                .find(|o| Some(o.operation_id) == imported.last_operation)
                .unwrap();
            match case {
                "cancelled" => operation.cancel_requested = true,
                "wrong-update" => {
                    operation.phases[0].status = zdn::state::PhaseStatus::Unknown {
                        message: "interrupted".into(),
                        external_ref: Some(Uuid::new_v4().to_string()),
                    }
                }
                "wrong-operation" => operation.kind = "devnet-up".into(),
                "completed-operation" => {
                    operation.phases[0].status = zdn::state::PhaseStatus::Succeeded {
                        result: json!({"updated":true}),
                    }
                }
                _ => {
                    invalid
                        .files
                        .remove(&format!("updates/{id}/node-1-command.json"));
                }
            }
            assert!(
                invalid.verify_directory(&target).is_err(),
                "accepted {case}"
            );
        }
        // Only the unconfirmed current target can carry an unfinished attempt.
        // An earlier revision or a confirmed target must still be certain.
        let (confirmed_id, confirmed_node) = manifest
            .updates
            .iter()
            .find_map(|(id, intent)| intent.completed.iter().next().map(|node| (id, node)))
            .unwrap();
        let confirmed_name = format!("updates/{confirmed_id}/{confirmed_node}-command.json");
        let confirmed_path = target.join(&confirmed_name);
        let confirmed_bytes = fs::read(&confirmed_path).unwrap();
        for name in [format!("updates/{id}/node-1-command.json"), confirmed_name] {
            let path = target.join(&name);
            let saved = fs::read(&path).unwrap();
            for case in ["running", "wrong-request", "unfinished-history"] {
                let mut changed: Value = serde_json::from_slice(&saved).unwrap();
                let attempt = &mut changed["attempts"][0];
                attempt["state"] = json!("running");
                attempt["commandId"] = json!(Uuid::new_v4());
                attempt["output"] = Value::Null;
                attempt["uncertain"] = json!(true);
                if case == "wrong-request" {
                    changed["requestSha256"] = json!("0".repeat(64));
                } else if case == "unfinished-history" {
                    let mut next = changed["attempts"][0].clone();
                    let uuid = Uuid::new_v4();
                    next["id"] = json!(uuid);
                    next["comment"] = json!(format!("zdn-command-{uuid}"));
                    next["commandId"] = json!(Uuid::new_v4());
                    changed["attempts"].as_array_mut().unwrap().push(next);
                }
                let bytes = serde_json::to_vec(&changed).unwrap();
                zdn::foundation::write_private(&path, &bytes).unwrap();
                let mut altered = manifest.clone();
                altered.files.insert(
                    name.clone(),
                    devnet::Artifact {
                        sha256: sha256(&bytes),
                        bytes: bytes.len() as u64,
                    },
                );
                assert_eq!(
                    altered.verify_directory(&target).is_ok(),
                    !publication && path == command && case == "running",
                    "{name}: {case}"
                );
                zdn::foundation::write_private(&path, &saved).unwrap();
            }
        }
        assert!(controller::resume(&imported, id, false).is_err());
        controller::resume(&imported, id, true).unwrap();
        controller::run(
            &imported_file,
            &mut imported,
            &mut HandoffUpdateBackend(target.clone()),
        )
        .unwrap();
        if command_state == Some("succeeded") || publication {
            assert_eq!(fs::read(&command).unwrap(), before);
        } else {
            let before: Value = serde_json::from_slice(&before).unwrap();
            let after: Value = zdn::foundation::read_json(&command).unwrap();
            assert_eq!(after["attempts"].as_array().unwrap().len(), 1);
            assert_eq!(after["attempts"][0]["id"], before["attempts"][0]["id"]);
            assert_eq!(after["attempts"][0]["state"], "succeeded");
            assert_eq!(after["attempts"][0]["uncertain"], false);
            assert_eq!(
                after["attempts"][0]["cancellationRequested"],
                command_state != Some("prepared")
            );
            if command_state == Some("running") {
                assert_eq!(
                    after["attempts"][0]["commandId"],
                    before["attempts"][0]["commandId"]
                );
            }
        }
        assert_eq!(fs::read(confirmed_path).unwrap(), confirmed_bytes);
        assert!(
            imported
                .runtime
                .as_ref()
                .unwrap()
                .update
                .as_ref()
                .unwrap()
                .finished
        );
        assert!(target.join(format!("updates/{id}/completed.json")).exists());
        if let Some(saved) = completion_bytes {
            assert_eq!(fs::read(&completed_path).unwrap(), saved);
        }
        assert_eq!(
            imported.render().unwrap().to_yaml().unwrap(),
            f.deployment.render().unwrap().to_yaml().unwrap()
        );
        return;
    }
    let runtime_before = serde_json::to_value(&imported.runtime).unwrap();
    let mut completed_updates = std::collections::BTreeMap::new();
    if target.join("updates").exists() {
        for entry in fs::read_dir(target.join("updates")).unwrap() {
            let intent: zdn::update::UpdateIntent =
                zdn::foundation::read_json(&entry.unwrap().path().join("completed.json")).unwrap();
            completed_updates.insert(intent.id, intent);
        }
    }
    // Exercise the pure public contract as well as the handoff roundtrip above.
    // In the three-round fixture, every edge points toward a larger UUID.
    zdn::update::validate_completed_history(&imported, &completed_updates).unwrap();
    if rounds == 3 {
        for (id, intent) in &completed_updates {
            for target in intent.targets.values() {
                if let Some(previous) = target.expected_update_id {
                    assert!(previous > *id);
                }
            }
        }
    }
    zdn::foundation_live::validate_health_proofs(&imported, &target, &completed_updates).unwrap();
    zdn::health::validate(&imported, &target, zdn::health::Options::default()).unwrap();
    // Completed metadata is authority, not just a pointer to matching image bytes.
    // Mutate an older intent when possible to exercise the full ancestry, not
    // merely equality with the latest saved intent.
    if rounds > 0 {
        let first = update_paths[0].split('/').nth(1).unwrap();
        let path = target.join(format!("updates/{first}/completed.json"));
        let saved = fs::read(&path).unwrap();
        let intent: Value = serde_json::from_slice(&saved).unwrap();
        for case in ["targets", "completed", "baseline", "predecessor", "cycle"] {
            let mut corrupt = intent.clone();
            match case {
                "targets" => corrupt["targets"] = json!({}),
                "completed" => corrupt["completed"] = json!([]),
                "baseline" => corrupt["baselineSha256"] = json!("0".repeat(64)),
                "predecessor" => {
                    corrupt["targets"]["node-1"]["expectedUpdateId"] = json!(Uuid::new_v4())
                }
                "cycle" => corrupt["targets"]["node-1"]["expectedUpdateId"] = json!(first),
                _ => unreachable!(),
            }
            zdn::foundation::write_json(&path, &corrupt).unwrap();
            let corrupt: zdn::update::UpdateIntent = serde_json::from_value(corrupt).unwrap();
            let mut history = completed_updates.clone();
            history.insert(corrupt.id, corrupt);
            assert!(zdn::update::validate_completed_history(&imported, &history).is_err());
            assert!(
                zdn::foundation_live::validate_health_proofs(&imported, &target, &history).is_err(),
                "historical proof validation accepted corrupted {case} metadata"
            );
        }
        zdn::foundation::write_private(&path, &saved).unwrap();
        zdn::foundation_live::validate_health_proofs(&imported, &target, &completed_updates)
            .unwrap();
        let mut fork = intent.clone();
        let fork_id = Uuid::new_v4();
        fork["id"] = json!(fork_id);
        fork["revision"]["updateId"] = json!(fork_id);
        let fork_directory = target.join("updates").join(fork_id.to_string());
        zdn::foundation::private_directory(&fork_directory).unwrap();
        zdn::foundation::write_json(&fork_directory.join("completed.json"), &fork).unwrap();
        let mut fork_history = completed_updates.clone();
        fork_history.insert(fork_id, serde_json::from_value(fork).unwrap());
        assert!(
            zdn::foundation_live::validate_health_proofs(&imported, &target, &fork_history)
                .is_err()
        );
        fs::remove_file(fork_directory.join("completed.json")).unwrap();
        fs::remove_dir(fork_directory).unwrap();
        if rounds > 1 {
            fs::remove_file(&path).unwrap();
            let mut missing_history = completed_updates.clone();
            missing_history.remove(&Uuid::parse_str(first).unwrap());
            assert!(zdn::foundation_live::validate_health_proofs(
                &imported,
                &target,
                &missing_history
            )
            .is_err());
            zdn::foundation::write_private(&path, &saved).unwrap();
        }
    }
    let mut resumed_backend = backend;
    resumed_backend.calls.clear();
    resumed_backend.state = receiver.root().to_owned();
    resumed_backend.file = target.join("deployment.json");
    zdn::foundation::apply(
        &receiver,
        &imported_file,
        &binding,
        &mut imported,
        &mut resumed_backend,
        true,
    )
    .unwrap();
    assert_eq!(
        fs::read(target.join(&observation_name)).unwrap(),
        fs::read(directory.join(&observation_name)).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&imported.runtime).unwrap(),
        runtime_before
    );
    drop(imported_file);
    if from_source {
        let intent = imported.runtime.as_ref().unwrap().update.as_ref().unwrap();
        let id = intent.id.to_string();
        let update_directory = target.join("updates").join(&id);
        assert!(!update_directory.join("build-contract.json").exists());
        assert!(!update_directory.join("source-snapshot").exists());
        zdn::foundation::private_directory(&receiver.root().join("profiles")).unwrap();
        zdn::foundation::write_json(
            &receiver.root().join("profiles/private-team.json"),
            &profile,
        )
        .unwrap();
        let invoke = || {
            std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
                .env_clear()
                .env("PATH", "")
                .args([
                    "devnet",
                    "update",
                    &binding.network_id.to_string(),
                    "--resume",
                    &id,
                    "--reconcile",
                    "--state-dir",
                    receiver.root().to_str().unwrap(),
                    "--profile",
                    "private-team",
                    "--managed-dir",
                    target.to_str().unwrap(),
                    "--acknowledge-storage-compatibility",
                    "--yes",
                ])
                .output()
                .unwrap()
        };
        let resumed = invoke();
        assert!(!resumed.status.success());
        // Local recovery succeeds before credential preparation; no AWS runs.
        let error = String::from_utf8_lossy(&resumed.stderr);
        assert!(error.contains("HOME is required"), "{error}");
        assert_eq!(update_directory.join("build").exists(), native_exporter);
        let mut conflicting = intent.revision.as_ref().unwrap().build.clone().unwrap();
        conflicting.revision = "e".repeat(40);
        zdn::foundation::write_json(&update_directory.join("build-contract.json"), &conflicting)
            .unwrap();
        let rejected = invoke();
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("saved update build contract changed"));
        fs::remove_file(update_directory.join("build-contract.json")).unwrap();
        let file =
            zdn::foundation::DeploymentFile::open(receiver.root(), binding.network_id).unwrap();
        let mut pending = file.load().unwrap();
        let runtime = pending.runtime.as_mut().unwrap();
        let intent = runtime.update.as_mut().unwrap();
        intent.finished = false;
        // One confirmed follower and one untouched producer model a partial
        // update, not merely a crash after all nodes completed.
        intent.completed.remove("node-1");
        if let Some(previous) = intent.targets["node-1"].expected_update_id {
            runtime.nodes.insert(
                "node-1".into(),
                completed_updates[&previous].revision.clone().unwrap(),
            );
        } else {
            runtime.nodes.remove("node-1");
        }
        file.save(&pending).unwrap();
        drop(file);
        let resumed = invoke();
        let error = String::from_utf8_lossy(&resumed.stderr);
        assert!(error.contains("HOME is required"), "{error}");
        assert_eq!(update_directory.join("build").exists(), native_exporter);
        zdn::foundation::write_json(&update_directory.join("build-contract.json"), &conflicting)
            .unwrap();
        let rejected = invoke();
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("saved update build contract changed"));
        fs::remove_file(update_directory.join("build-contract.json")).unwrap();
        let file =
            zdn::foundation::DeploymentFile::open(receiver.root(), binding.network_id).unwrap();
        let mut building = file.load().unwrap();
        let runtime = building.runtime.as_mut().unwrap();
        let intent = runtime.update.as_mut().unwrap();
        intent.revision = None;
        intent.completed.clear();
        for (node, target) in &intent.targets {
            if let Some(previous) = target.expected_update_id {
                runtime.nodes.insert(
                    node.clone(),
                    completed_updates[&previous].revision.clone().unwrap(),
                );
            } else {
                runtime.nodes.remove(node);
            }
        }
        file.save(&building).unwrap();
        drop(file);
        let rejected = invoke();
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("saved update build contract changed"));
    }
    // Re-pin the inventory and archive after mutation: semantic validation must
    // reject these even when every transported hash is internally consistent.
    use std::io::Read;
    let original: Vec<_> = tar::Archive::new(fs::File::open(&archive).unwrap())
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (name, bytes)
        })
        .collect();
    for (name, bytes) in original.iter().skip(1) {
        assert_eq!(&fs::read(target.join(name)).unwrap(), bytes, "lost {name}");
    }
    // A recovered deployment must not recover, delete or reinterpret old
    // read-only command attempts merely to allow a fresh health preflight.
    // Handoff must still reject observations bound to the wrong instance/script.
    if !from_source {
        let mut preserved = Vec::new();
        for stem in ["node-2", "client-rpc", "lightwallet"] {
            let name = format!("{stem}-observe-{}.json", Uuid::new_v4());
            let mut journal = handoff_command_evidence(
                &imported.outputs.as_ref().unwrap().nodes["node-2"].instance_id,
                "foreign-observer-command",
                300,
            );
            journal["attempts"][0]["state"] = json!("running");
            journal["attempts"][0]["uncertain"] = json!(true);
            journal["attempts"][0]["output"] = Value::Null;
            let path = target.join(name);
            zdn::foundation::write_json(&path, &journal).unwrap();
            preserved.push((path.clone(), fs::read(&path).unwrap()));
        }
        zdn::foundation_live::validate_health_proofs(&imported, &target, &completed_updates)
            .unwrap();
        let blocked = f._inputs.root.path().join("uncertain-observations.tar");
        assert!(zdn::handoff::export::export(&receiver, &binding, &blocked).is_err());
        assert!(!blocked.exists());
        for (path, bytes) in preserved {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
    if rounds > 0 {
        for case in [
            "missing-revision",
            "pending",
            "uncertain-update",
            "wrong-history",
            "missing-history",
            "cross-node-cycle",
        ] {
            if case == "missing-history" && rounds < 2 {
                continue;
            }
            if case == "cross-node-cycle" && rounds != 3 {
                continue;
            }
            let mut entries = original.clone();
            let mut manifest: Value = serde_json::from_slice(&entries[0].1).unwrap();
            let id = f
                .deployment
                .runtime
                .as_ref()
                .unwrap()
                .update
                .as_ref()
                .unwrap()
                .id
                .to_string();
            match case {
                "missing-revision" => {
                    let name = format!("updates/{id}/artifacts/image-manifest.json");
                    entries.retain(|(entry, _)| entry != &name);
                    manifest["files"].as_object_mut().unwrap().remove(&name);
                }
                "pending" => manifest["deployment"]["runtime"]["update"]["finished"] = json!(false),
                "cross-node-cycle" => {
                    let a = update_paths[0].split('/').nth(1).unwrap();
                    let b = update_paths[3].split('/').nth(1).unwrap();
                    let c = update_paths[6].split('/').nth(1).unwrap();
                    let baseline = json!(f.deployment.cluster.as_ref().unwrap().image.image);
                    let a_image = manifest["updates"][a]["revision"]["image"]["image"].clone();
                    let b_image = manifest["updates"][b]["revision"]["image"]["image"].clone();
                    // Node-1 says B preceded A; node-2 still says A preceded B.
                    // Both end at C and individually reach the original image.
                    manifest["updates"][a]["targets"]["node-1"]["expectedUpdateId"] = json!(b);
                    manifest["updates"][a]["targets"]["node-1"]["expectedImage"] = b_image;
                    manifest["updates"][b]["targets"]["node-1"]["expectedUpdateId"] = Value::Null;
                    manifest["updates"][b]["targets"]["node-1"]["expectedImage"] = baseline;
                    manifest["updates"][c]["targets"]["node-1"]["expectedUpdateId"] = json!(a);
                    manifest["updates"][c]["targets"]["node-1"]["expectedImage"] = a_image;
                    manifest["deployment"]["runtime"]["update"] = manifest["updates"][c].clone();
                    let crossed: zdn::handoff::Manifest =
                        serde_json::from_value(manifest.clone()).unwrap();
                    let error = zdn::update::validate_completed_history(
                        &crossed.deployment,
                        &crossed.updates,
                    )
                    .expect_err("accepted cross-node dependency cycle");
                    assert!(
                        error.to_string().contains("cyclic update dependency"),
                        "{error:#}"
                    );
                    let error = crossed
                        .validate()
                        .expect_err("accepted cross-node dependency cycle");
                    assert!(
                        error.to_string().contains("cyclic update dependency"),
                        "{error:#}"
                    );
                    let mut saved = Vec::new();
                    for (update_id, intent) in &crossed.updates {
                        let path = target.join(format!("updates/{update_id}/completed.json"));
                        saved.push((path.clone(), fs::read(&path).unwrap()));
                        zdn::foundation::write_json(&path, intent).unwrap();
                    }
                    let error = zdn::foundation_live::validate_health_proofs(
                        &crossed.deployment,
                        &target,
                        &crossed.updates,
                    )
                    .expect_err("health accepted cross-node dependency cycle");
                    assert!(
                        error.to_string().contains("cyclic update dependency"),
                        "{error:#}"
                    );
                    for (path, bytes) in saved {
                        zdn::foundation::write_private(&path, &bytes).unwrap();
                    }
                    for update_id in [a, b, c] {
                        let name = format!("updates/{update_id}/completed.json");
                        entries
                            .iter_mut()
                            .find(|(entry, _)| entry == &name)
                            .unwrap()
                            .1 = serde_json::to_vec(&manifest["updates"][update_id]).unwrap();
                    }
                }
                "wrong-history" => {
                    manifest["updates"][&id]["targets"]["node-1"]["expectedImage"] = json!(
                        f.deployment.runtime.as_ref().unwrap().nodes["node-1"]
                            .image
                            .image
                    );
                    manifest["deployment"]["runtime"]["update"] = manifest["updates"][&id].clone();
                    let name = format!("updates/{id}/completed.json");
                    entries
                        .iter_mut()
                        .find(|(entry, _)| entry == &name)
                        .unwrap()
                        .1 = serde_json::to_vec(&manifest["updates"][&id]).unwrap();
                }
                "missing-history" => {
                    let old_id = update_paths[0].split('/').nth(1).unwrap();
                    manifest["updates"].as_object_mut().unwrap().remove(old_id);
                    let prefix = format!("updates/{old_id}/");
                    entries.retain(|(entry, _)| !entry.starts_with(&prefix));
                    manifest["files"]
                        .as_object_mut()
                        .unwrap()
                        .retain(|name, _| !name.starts_with(&prefix));
                }
                "uncertain-update" => {
                    let name = format!("updates/{id}/node-1-command.json");
                    let bytes = &mut entries
                        .iter_mut()
                        .find(|(entry, _)| entry == &name)
                        .unwrap()
                        .1;
                    let mut command: Value = serde_json::from_slice(bytes).unwrap();
                    command["attempts"][0]["uncertain"] = json!(true);
                    *bytes = serde_json::to_vec(&command).unwrap();
                }
                _ => unreachable!(),
            }
            for (name, bytes) in entries.iter().skip(1) {
                manifest["files"][name] = json!({"sha256":sha256(bytes),"bytes":bytes.len()});
            }
            entries[0].1 = serde_json::to_vec(&manifest).unwrap();
            let candidate = f._inputs.root.path().join(format!("semantic-{case}.tar"));
            let mut tar = tar::Builder::new(fs::File::create(&candidate).unwrap());
            for (name, bytes) in entries {
                let mut header = tar::Header::new_ustar();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o600);
                header.set_cksum();
                tar.append_data(&mut header, name, &bytes[..]).unwrap();
            }
            tar.finish().unwrap();
            drop(tar);
            let receiver = zdn::state::StateStore::open(
                f._inputs.root.path().join(format!("semantic-{case}")),
            )
            .unwrap();
            assert!(
                zdn::handoff::import::import(
                    &receiver,
                    &f.binding.context,
                    f.binding.network_id,
                    &profile,
                    &candidate,
                    &sha256(&fs::read(&candidate).unwrap())
                )
                .is_err(),
                "accepted {case}"
            );
            assert!(receiver.list(&f.binding.context.scope).unwrap().is_empty());
            assert!(!receiver.root().join("foundation").exists());
        }
    }
    for (index, name) in [
        "node-2-install.sh",
        "client-rpc-install.sh",
        "node-2-install-command.json",
        "client-rpc-install-command.json",
        "node-1-start-producer-command.json",
        &observation_name,
        "node-2-install-command.json",
        "node-2-install-command.json",
    ]
    .iter()
    .copied()
    .chain(update_paths.iter().map(String::as_str))
    .enumerate()
    {
        let path = directory.join(name);
        let saved = fs::read(&path).unwrap();
        let replacement = if name.ends_with(".sh") || name.ends_with("image-config.json") {
            [saved.as_slice(), b"\n# different installer\n"].concat()
        } else {
            let mut value: Value = serde_json::from_slice(&saved).unwrap();
            if index == 6 {
                value["timeoutSecs"] = json!(600);
            } else if index == 7 {
                value["attempts"][0]["state"] = json!("running");
                value["attempts"][0]["output"] = Value::Null;
            } else {
                // Valid evidence for a different command on the SAME host.
                value = handoff_command_evidence(
                    value["instanceId"].as_str().unwrap(),
                    "printf wrong-command",
                    value["timeoutSecs"].as_u64().unwrap() as u32,
                );
            }
            serde_json::to_vec(&value).unwrap()
        };
        zdn::foundation::write_private(&path, &replacement).unwrap();
        let blocked = f._inputs.root.path().join(format!("blocked-{index}.tar"));
        assert!(
            zdn::handoff::export::export(&f.store, &f.binding, &blocked).is_err(),
            "export accepted {index}:{name}"
        );
        assert!(!blocked.exists());
        zdn::foundation::write_private(&path, &saved).unwrap();
        let mut entries = original.clone();
        let mut manifest: Value = serde_json::from_slice(&entries[0].1).unwrap();
        manifest["files"][name] = json!({"sha256":sha256(&replacement),"bytes":replacement.len()});
        entries[0].1 = serde_json::to_vec(&manifest).unwrap();
        entries
            .iter_mut()
            .find(|(entry, _)| entry == name)
            .unwrap()
            .1 = replacement;
        let mut tar = tar::Builder::new(fs::File::create(&blocked).unwrap());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, name, &bytes[..]).unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        let receiver =
            zdn::state::StateStore::open(f._inputs.root.path().join(format!("invalid-{index}")))
                .unwrap();
        assert!(
            zdn::handoff::import::import(
                &receiver,
                &f.binding.context,
                f.binding.network_id,
                &profile,
                &blocked,
                &sha256(&fs::read(&blocked).unwrap())
            )
            .is_err(),
            "import accepted {index}:{name}"
        );
        assert!(receiver.list(&f.binding.context.scope).unwrap().is_empty());
        assert!(!receiver.root().join("foundation").exists());
    }
}

// No remote effects: render payloads, save evidence and recover through fake SSM.
struct HandoffUpdateBackend(PathBuf);

impl zdn::foundation::update_controller::Backend for HandoffUpdateBackend {
    fn pulse(&mut self) -> Result<()> {
        Ok(())
    }
    fn stage(
        &mut self,
        _: &zdn::foundation::Deployment,
        _: &zdn::update::ImageRevision,
    ) -> Result<()> {
        Ok(())
    }
    fn dispatch(&mut self, deployment: &zdn::foundation::Deployment, node: &str) -> Result<()> {
        let intent = deployment
            .runtime
            .as_ref()
            .unwrap()
            .update
            .as_ref()
            .unwrap();
        let revision = intent.revision.as_ref().unwrap();
        let target = &intent.targets[node];
        let output = &deployment.outputs.as_ref().unwrap().nodes[node];
        let host = deployment.cluster.as_ref().unwrap().host_spec(
            &deployment.spec,
            &deployment.team,
            output,
        )?;
        let object = |name: &str| {
            let artifact = &revision.artifacts[name];
            zdn::host::S3Object {
                bucket: deployment.team.backend_bucket().unwrap().into(),
                key: format!(
                    "{}updates/{}/artifacts/{name}",
                    devnet::artifact_prefix(&deployment.team, &deployment.spec),
                    intent.id
                ),
                sha256: artifact.sha256.clone(),
                bytes: artifact.bytes,
                owner_account: deployment.team.aws.account_id.clone(),
                region: deployment.team.aws.region.clone(),
            }
        };
        let script = zdn::host::runtime::revision::Request {
            api_version: zdn::host::runtime::revision::API_VERSION.into(),
            update_id: intent.id,
            original: native_manifest(&host),
            expected_image: target.expected_image.clone(),
            expected_update_id: target.expected_update_id,
            image: revision.image.clone(),
            image_record: object("image.json"),
            image_manifest: object("image-manifest.json"),
            image_config: object("image-config.json"),
        }
        .render()?;
        let directory = self.0.join("updates").join(intent.id.to_string());
        zdn::foundation::write_private(
            &directory.join(format!("{node}-update.sh")),
            script.as_bytes(),
        )?;
        let object = zdn::host::S3Object {
            bucket: deployment.team.backend_bucket()?.into(),
            key: format!(
                "{}updates/{}/{node}-{}.sh",
                devnet::artifact_prefix(&deployment.team, &deployment.spec),
                intent.id,
                sha256(script.as_bytes())
            ),
            sha256: sha256(script.as_bytes()),
            bytes: script.len() as u64,
            owner_account: deployment.team.aws.account_id.clone(),
            region: deployment.team.aws.region.clone(),
        };
        let command = directory.join(format!("{node}-command.json"));
        if command.exists() {
            let bytes = fs::read(&command)?;
            let journal: Value = serde_json::from_slice(&bytes)?;
            let attempt = journal["attempts"].as_array().unwrap().last().unwrap();
            if attempt["state"] == "succeeded" {
                zdn::ssm::validate_handoff(
                    &bytes,
                    &output.instance_id,
                    &zdn::foundation_live::selected_fetch_installer(deployment, &object, 7200)?,
                    7200,
                )?;
                return Ok(());
            }
            let remote = json!({"CommandId":attempt["commandId"].as_str().map(str::to_owned).unwrap_or_else(|| Uuid::new_v4().to_string()),
                "Comment":attempt["comment"],"DocumentName":"AWS-RunShellScript","DocumentVersion":"1",
                "InstanceIds":[output.instance_id],"TimeoutSeconds":120,
                "Parameters":{"commands":[zdn::foundation_live::selected_fetch_installer(deployment, &object, 7200)?],"executionTimeout":["7200"],"workingDirectory":["/"]}});
            zdn::ssm::execute(
                &HandoffSsm(remote, attempt["state"] == "prepared"),
                &output.instance_id,
                &zdn::foundation_live::selected_fetch_installer(deployment, &object, 7200)?,
                &command,
                7200,
                &zdn::foundation_live::SystemRuntime::default(),
                &mut || Ok(()),
            )?;
            return Ok(());
        }
        zdn::foundation::write_json(
            &command,
            &handoff_command_evidence(
                &output.instance_id,
                &zdn::foundation_live::selected_fetch_installer(deployment, &object, 7200)?,
                7200,
            ),
        )
    }
    fn observe(
        &mut self,
        _: &zdn::foundation::Deployment,
        _: &str,
        _: &zdn::update::ImageRevision,
    ) -> Result<()> {
        Ok(())
    }
    fn ready(&mut self, deployment: &zdn::foundation::Deployment) -> Result<()> {
        let output = &deployment.outputs.as_ref().unwrap().nodes["node-1"];
        let host = deployment.cluster.as_ref().unwrap().host_spec(
            &deployment.spec,
            &deployment.team,
            output,
        )?;
        let script = native_command(&host, true, "observe");
        zdn::foundation::write_json(
            &self
                .0
                .join(format!("client-rpc-observe-{}.json", Uuid::new_v4())),
            &handoff_command_evidence(&output.instance_id, &script, 360),
        )
    }
}

struct HandoffSsm(Value, bool);

impl AwsApi for HandoffSsm {
    fn call(&self, service: &str, operation: &str, input: Value, _: &[String]) -> Result<Value> {
        assert_eq!(service, "ssm");
        if operation == "send-command" {
            // Only a never-dispatched Prepared attempt can take this path.
            // The existing uncertain-command cases still fail if redispatched.
            assert!(self.1, "uncertain command must never be redispatched");
            assert_eq!(input["InstanceIds"], self.0["InstanceIds"]);
            for field in [
                "DocumentName",
                "DocumentVersion",
                "Comment",
                "TimeoutSeconds",
                "Parameters",
            ] {
                assert_eq!(input[field], self.0[field]);
            }
            return Ok(json!({"Command":self.0}));
        }
        assert_eq!(input["InstanceId"], self.0["InstanceIds"][0]);
        match operation {
            "list-commands" => Ok(json!({"Commands":[self.0]})),
            "get-command-invocation" => {
                assert_eq!(input["CommandId"], self.0["CommandId"]);
                Ok(
                    json!({"CommandId":self.0["CommandId"],"InstanceId":self.0["InstanceIds"][0],
                    "DocumentName":"AWS-RunShellScript","DocumentVersion":"1","Comment":self.0["Comment"],
                    "Status":"Success","ResponseCode":0,"StandardOutputContent":"{\"ready\":true}"}),
                )
            }
            _ => panic!("handoff must not redispatch or cancel an existing command: {operation}"),
        }
    }
}

fn handoff_command_evidence(instance: &str, script: &str, timeout: u32) -> Value {
    let request = json!({"DocumentName":"AWS-RunShellScript","DocumentVersion":"1","InstanceIds":[instance],
        "TimeoutSeconds":timeout.min(120),"MaxConcurrency":"1","MaxErrors":"0",
        "CloudWatchOutputConfig":{"CloudWatchOutputEnabled":false},
        "Parameters":{"commands":[script],"executionTimeout":[timeout.to_string()],"workingDirectory":["/"]}});
    let attempt = Uuid::new_v4();
    json!({"apiVersion":zdn::ssm::API_VERSION,"requestSha256":sha256(&serde_json::to_vec(&request).unwrap()),
        "instanceId":instance,"timeoutSecs":timeout,"attempts":[{"id":attempt,"createdAt":1_800_000_000_u64,
        "comment":format!("zdn-command-{attempt}"),"commandId":Uuid::new_v4(),"state":"succeeded",
        "uncertain":false,"cancellationRequested":true,"failure":null,"output":{"ready":true}}]})
}

fn handoff_installer_evidence(
    deployment: &zdn::foundation::Deployment,
    directory: &std::path::Path,
    stem: &str,
    instance: &str,
    script: &str,
    timeout: u32,
) {
    zdn::foundation::write_private(
        &directory.join(format!("{stem}-install.sh")),
        script.as_bytes(),
    )
    .unwrap();
    let hash = sha256(script.as_bytes());
    let object = zdn::host::S3Object {
        bucket: deployment.team.backend_bucket().unwrap().into(),
        key: format!(
            "{}{hash}/{stem}-install.sh",
            devnet::artifact_prefix(&deployment.team, &deployment.spec)
        ),
        sha256: hash,
        bytes: script.len() as u64,
        owner_account: deployment.team.aws.account_id.clone(),
        region: deployment.team.aws.region.clone(),
    };
    let fetch =
        zdn::foundation_live::selected_fetch_installer(deployment, &object, timeout).unwrap();
    zdn::foundation::write_json(
        &directory.join(format!("{stem}-install-command.json")),
        &handoff_command_evidence(instance, &fetch, timeout),
    )
    .unwrap();
}

#[test]
fn handoff_excludes_only_complete_matching_build_workspaces() {
    let mut f = Lifecycle::new();
    let directory = f.file.directory().to_owned();
    let infra = zdn::build_infra::BuildInfrastructure::for_team(&f.deployment.team).unwrap();
    let contract = zdn::build::BuildContract {
        api_version: zdn::build::API_VERSION.into(),
        source_sha256: "a".repeat(64),
        source_bytes: 1,
        revision: "c".repeat(40),
        platform: "linux/amd64".into(),
        required_capabilities: ImageCapabilities::default(),
        recipe: zdn::build::BuildRecipe {
            dockerfile: "Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
        },
    };
    let request = f.deployment.cluster.as_mut().unwrap();
    request.image.provenance = ImageProvenance::Source {
        revision: contract.revision.clone(),
        snapshot_sha256: contract.source_sha256.clone(),
    };
    request.image.image = format!(
        "{}@{}",
        infra.repository_uri,
        request.image.manifest_digest().unwrap()
    );
    request.build = Some(contract.clone());
    zdn::foundation::private_directory(&directory.join("artifacts")).unwrap();
    for name in request.artifacts.keys() {
        fs::copy(
            f._inputs.output.join("artifacts").join(name),
            directory.join("artifacts").join(name),
        )
        .unwrap();
    }
    let image = serde_json::to_vec_pretty(&request.image).unwrap();
    zdn::foundation::write_private(&directory.join("artifacts/image.json"), &image).unwrap();
    request.artifacts.insert(
        "image.json".into(),
        devnet::Artifact {
            sha256: sha256(&image),
            bytes: image.len() as u64,
        },
    );
    f.file.save(&f.deployment).unwrap();
    drop(f.file);
    let build = directory.join("build");
    let result = zdn::build_job::BuildResult {
        contract_sha256: contract.fingerprint().unwrap(),
        image: f.deployment.cluster.as_ref().unwrap().image.clone(),
    };
    let completed = json!({"schemaVersion":1,"team":f.deployment.team,"project":infra.project_name,"repository":infra.repository_uri,
        "attemptId":Uuid::new_v4(),"contract":contract,"sourceVersion":"version-1","dispatched":true,"reused":null,
        "buildId":format!("{}:{}",infra.project_name,Uuid::new_v4()),"terminal":"SUCCEEDED"});
    for case in [
        "absent",
        "success",
        "reused",
        "not-uploaded",
        "uncertain-start",
        "running",
        "failed",
        "unrelated",
        "malformed",
        "missing-result",
        "partial-reuse",
        "changed-output",
    ] {
        let accepted = matches!(case, "absent" | "success" | "reused");
        if case != "absent" {
            zdn::foundation::private_directory(&build).unwrap();
            let mut receipt = completed.clone();
            match case {
                "not-uploaded" => {
                    receipt["sourceVersion"] = Value::Null;
                    receipt["dispatched"] = json!(false);
                    receipt["buildId"] = Value::Null;
                    receipt["terminal"] = Value::Null;
                }
                "uncertain-start" => {
                    receipt["buildId"] = Value::Null;
                    receipt["terminal"] = Value::Null;
                }
                "running" => receipt["terminal"] = Value::Null,
                "failed" => receipt["terminal"] = json!("FAILED"),
                "unrelated" => receipt["contract"]["sourceSha256"] = json!("d".repeat(64)),
                "reused" | "partial-reuse" => {
                    receipt["sourceVersion"] = Value::Null;
                    receipt["dispatched"] = json!(false);
                    receipt["buildId"] = Value::Null;
                    receipt["terminal"] = Value::Null;
                    receipt["reused"] = json!(Uuid::new_v4());
                }
                _ => {}
            }
            zdn::foundation::write_json(&build.join("attempt.json"), &receipt).unwrap();
            zdn::foundation::write_json(&build.join("result.json"), &result).unwrap();
            for name in ["image.json", "image-manifest.json", "image-config.json"] {
                zdn::foundation::write_private(
                    &build.join(name),
                    &fs::read(directory.join("artifacts").join(name)).unwrap(),
                )
                .unwrap();
            }
            match case {
                "malformed" => {
                    zdn::foundation::write_private(&build.join("attempt.json"), b"{").unwrap()
                }
                "missing-result" => fs::remove_file(build.join("result.json")).unwrap(),
                "partial-reuse" => fs::remove_file(build.join("image-config.json")).unwrap(),
                "changed-output" => {
                    zdn::foundation::write_private(&build.join("image-config.json"), b"{}").unwrap()
                }
                _ => {}
            }
        }
        let archive = f._inputs.root.path().join(format!("build-{case}.tar"));
        let exported = zdn::handoff::export::export(&f.store, &f.binding, &archive);
        assert_eq!(exported.is_ok(), accepted, "{case}: {exported:?}");
        assert_eq!(archive.exists(), accepted);
        if accepted {
            let mut tar = tar::Archive::new(fs::File::open(archive).unwrap());
            assert!(tar.entries().unwrap().all(|entry| !entry
                .unwrap()
                .path()
                .unwrap()
                .starts_with("build")));
        }
    }
}

fn initial_build_fixture(lightwallet: bool) -> Lifecycle {
    initial_build_fixture_with_runtime(lightwallet, false)
}

fn initial_build_fixture_with_runtime(lightwallet: bool, native_runtime: bool) -> Lifecycle {
    use std::process::Command;
    let mut f = Lifecycle::new();
    f.deployment.cluster = None;
    f.file.save(&f.deployment).unwrap();
    let source = f._inputs.root.path().join("initial-source");
    fs::create_dir(&source).unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.name", "fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
    ] {
        assert!(Command::new("git")
            .current_dir(&source)
            .args(args)
            .status()
            .unwrap()
            .success());
    }
    fs::create_dir(source.join("docker")).unwrap();
    fs::write(
        source.join("docker/Dockerfile"),
        b"FROM scratch AS runtime\n",
    )
    .unwrap();
    assert!(Command::new("git")
        .current_dir(&source)
        .args(["add", "."])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .current_dir(&source)
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "tiny local fixture"
        ])
        .status()
        .unwrap()
        .success());
    f._inputs.config.node.source = Source {
        path: Some(source.clone()),
        ..Default::default()
    };
    f._inputs.config.node.build = Some(Default::default());
    let lw = lightwallet.then(|| LightwalletFixture::new(&mut f._inputs));
    let receipt = zdn::source::capture(&zdn::source::CaptureOptions {
        source: source.clone(),
        output: f.file.directory().join("source-snapshot"),
        revision: None,
        include: vec![],
    })
    .unwrap();
    let contract =
        zdn::build::BuildContract::new(&receipt, f._inputs.config.node.build.as_ref().unwrap())
            .unwrap();
    let inputs = zdn::state::OperationInput {
        config_sha256: f._inputs.config.fingerprint().unwrap(),
        source_manifest_sha256: Some(sha256(
            &fs::read(f.file.directory().join("source-snapshot/receipt.json")).unwrap(),
        )),
        archive_sha256: Some(receipt.archive_sha256),
    };
    zdn::foundation::write_json(
        &f.file.directory().join("source-build-inputs.json"),
        &inputs,
    )
    .unwrap();
    let mut paths = BTreeMap::from([
        (
            "source-preparation/manifest.json".into(),
            f._inputs.manifest.clone(),
        ),
        (
            "source-preparation/chain.tar".into(),
            f._inputs.bundle.clone(),
        ),
        ("source-preparation/zdn".into(), f._inputs.helper.clone()),
    ]);
    if let Some(lw) = lw {
        paths.extend([
            (
                "source-preparation/lightwallet-image.json".into(),
                lw.record,
            ),
            (
                "source-preparation/lightwallet-image-manifest.json".into(),
                lw.manifest,
            ),
            (
                "source-preparation/lightwallet-image-config.json".into(),
                lw.config,
            ),
        ]);
    }
    zdn::build::preparation::Preparation::save(
        &f._inputs.config,
        &f.deployment,
        &contract,
        "t28CMna95MpGxD5VWbAh3RRdZR4F3pEHuhB",
        native_runtime,
        &paths,
        f.file.directory(),
    )
    .unwrap();
    // Preparation must survive loss of every caller-owned input, not use them
    // opportunistically while an original checkout still happens to exist.
    fs::remove_dir_all(source).unwrap();
    for path in paths.values() {
        fs::remove_file(path).unwrap();
    }
    f
}

#[test]
fn source_preparation_rejects_invalid_snapshot_before_publishing_payloads() {
    use zdn::build::preparation::{Preparation, RECORD};
    let f = initial_build_fixture(false);
    let saved = Preparation::read(f.file.directory()).unwrap();
    let mut sources: BTreeMap<_, _> = saved
        .files
        .keys()
        .map(|path| (path.clone(), f.file.directory().join(path)))
        .collect();
    let invalid = f._inputs.root.path().join("invalid-helper");
    fs::write(&invalid, b"not an ELF executable").unwrap();
    sources.insert("source-preparation/zdn".into(), invalid);
    let target = f._inputs.root.path().join("unpublished-preparation");
    zdn::foundation::private_directory(&target).unwrap();
    assert!(Preparation::save(
        &saved.config,
        &f.deployment,
        &saved.contract,
        &saved.reward_address,
        false,
        &sources,
        &target,
    )
    .is_err());
    for path in [RECORD, "source-preparation", "build"] {
        assert!(!target.join(path).exists(), "published invalid {path}");
    }
}

#[test]
fn source_preparation_freezes_transport_and_capacity_through_retry_and_promotion() {
    use zdn::build::preparation::{Preparation, RECORD};
    for protocol in [
        None,
        Some("zdn-installer-fetch/v1alpha1"),
        Some("zdn-installer-fetch/v1alpha2"),
    ] {
        let f = initial_build_fixture_with_runtime(true, protocol.is_some());
        let directory = f.file.directory();
        let saved = Preparation::read(directory).unwrap();
        assert_eq!(
            saved.capacity_protocol.as_deref(),
            Some("zdn-host-capacity/v1alpha1")
        );
        assert_eq!(
            saved.installer_fetch_protocol.as_deref(),
            Some("zdn-installer-fetch/v1alpha2")
        );
        let mut record = serde_json::to_value(&saved).unwrap();
        if protocol.is_none() {
            record.as_object_mut().unwrap().remove("capacityProtocol");
            record
                .as_object_mut()
                .unwrap()
                .remove("nativeRuntimeProtocol");
            record
                .as_object_mut()
                .unwrap()
                .remove("installerFetchProtocol");
        } else {
            record["installerFetchProtocol"] = json!(protocol);
        }
        zdn::foundation::write_json(&directory.join(RECORD), &record).unwrap();
        let saved = Preparation::read(directory).unwrap();
        let before = fs::read(directory.join(RECORD)).unwrap();
        let attempt = fs::read(directory.join("build/attempt.json")).unwrap();
        let again = Preparation::save(
            &saved.config,
            &f.deployment,
            &saved.contract,
            &saved.reward_address,
            false,
            &BTreeMap::new(),
            directory,
        );
        if protocol.is_none() {
            assert!(again.is_err());
            assert!(saved.stage(directory, &f.deployment).is_err());
            assert!(Preparation::save(
                &saved.config,
                &f.deployment,
                &saved.contract,
                &saved.reward_address,
                true,
                &BTreeMap::new(),
                directory,
            )
            .is_err());
            assert_eq!(fs::read(directory.join(RECORD)).unwrap(), before);
            assert_eq!(
                fs::read(directory.join("build/attempt.json")).unwrap(),
                attempt
            );
            continue;
        }
        let again = again.unwrap();
        assert_eq!(again.native_runtime_protocol, saved.native_runtime_protocol);
        assert_eq!(again.capacity_protocol, saved.capacity_protocol);
        assert_eq!(
            again.installer_fetch_protocol,
            saved.installer_fetch_protocol
        );
        assert_eq!(fs::read(directory.join(RECORD)).unwrap(), before);
        assert_eq!(
            fs::read(directory.join("build/attempt.json")).unwrap(),
            attempt
        );
        let mut image =
            ImageRecord::from_json(&fs::read(&f._inputs.image_record).unwrap()).unwrap();
        image.provenance = ImageProvenance::Source {
            revision: saved.contract.revision.clone(),
            snapshot_sha256: saved.contract.source_sha256.clone(),
        };
        zdn::foundation::write_json(&directory.join("build/image.json"), &image).unwrap();
        fs::copy(
            &f._inputs.image_manifest,
            directory.join("build/image-manifest.json"),
        )
        .unwrap();
        fs::copy(
            &f._inputs.image_config,
            directory.join("build/image-config.json"),
        )
        .unwrap();
        let staged = again.stage(directory, &f.deployment).unwrap();
        assert_eq!(
            staged.native_runtime_protocol,
            saved.native_runtime_protocol
        );
        assert_eq!(
            staged.artifacts["zdn"],
            saved.files["source-preparation/zdn"]
        );
        assert_eq!(staged.installer_fetch_protocol.as_deref(), protocol);
        assert_eq!(
            staged
                .lightwallet
                .as_ref()
                .unwrap()
                .capacity_protocol
                .as_deref(),
            Some("zdn-host-capacity/v1alpha1")
        );
        let mut invalid = again;
        invalid.installer_fetch_protocol = Some("unsupported".into());
        assert!(invalid.stage(directory, &f.deployment).is_err());
        invalid.installer_fetch_protocol = saved.installer_fetch_protocol;
        invalid.native_runtime_protocol = Some(zdn::host::runtime::PROTOCOL.into());
        invalid.capacity_protocol = None;
        assert!(invalid.stage(directory, &f.deployment).is_err());
        invalid.capacity_protocol = Some("unsupported".into());
        assert!(invalid.stage(directory, &f.deployment).is_err());
    }
}

#[test]
fn initial_build_handoff_preserves_every_attempt_field_and_exact_portable_inputs() {
    for (lightwallet, native) in [(false, false), (true, false), (false, true), (true, true)] {
        for state in [
            "not-uploaded",
            "runtime-uploaded",
            "uploaded",
            "uncertain",
            "running",
            "succeeded",
            "reused",
        ] {
            let f = initial_build_fixture_with_runtime(lightwallet, native);
            let directory = f.file.directory().to_owned();
            let path = directory.join("build/attempt.json");
            let mut attempt: Value = zdn::foundation::read_json(&path).unwrap();
            if native {
                assert_eq!(attempt["exporter"]["protocol"], zdn::build_export::PROTOCOL);
                if !matches!(state, "not-uploaded" | "reused") {
                    attempt["exporter"]["version"] = json!("runtime'exact-version");
                }
            } else {
                // Model the published legacy receipt vocabulary, not a newly
                // inferred renderer choice on the receiving controller.
                attempt.as_object_mut().unwrap().remove("exporter");
                fs::remove_file(directory.join("build/exporter")).unwrap();
            }
            if !matches!(state, "not-uploaded" | "runtime-uploaded" | "reused") {
                attempt["sourceVersion"] = json!("exact-uploaded-version");
            }
            if !matches!(
                state,
                "not-uploaded" | "runtime-uploaded" | "uploaded" | "reused"
            ) {
                attempt["dispatched"] = json!(true);
            }
            if state == "reused" {
                attempt["reused"] = json!(Uuid::new_v4());
            }
            if matches!(state, "running" | "succeeded") {
                attempt["buildId"] = json!(format!(
                    "{}:{}",
                    attempt["project"].as_str().unwrap(),
                    Uuid::new_v4()
                ));
            }
            if state == "succeeded" {
                attempt["terminal"] = json!("SUCCEEDED");
            }
            zdn::foundation::write_json(&path, &attempt).unwrap();
            let exact = fs::read(&path).unwrap();
            for name in ["credentials", "project", "diagnostics"] {
                zdn::foundation::private_directory(&directory.join(name)).unwrap();
                fs::write(
                    directory.join(name).join("secret"),
                    "excluded-controller-private-data",
                )
                .unwrap();
            }
            // Even a terminal success has not verified these bytes. They must
            // not be trusted or carried as a staged image in an initial handoff.
            for name in [
                "result.json",
                "image.json",
                "image-manifest.json",
                "image-config.json",
                ".tmp-abandoned-download",
            ] {
                fs::write(
                    directory.join("build").join(name),
                    "excluded-unverified-output",
                )
                .unwrap();
            }
            drop(f.file);
            let archive = f._inputs.root.path().join("partial.tar");
            let pin = zdn::handoff::export::export(&f.store, &f.binding, &archive).unwrap();
            if native {
                fs::remove_file(directory.join("build/exporter")).unwrap();
            }
            let raw = fs::read(&archive).unwrap();
            for excluded in [
                "excluded-controller-private-data",
                "excluded-unverified-output",
                "attempt.lock",
                "operation.lock",
            ] {
                assert!(!raw
                    .windows(excluded.len())
                    .any(|w| w == excluded.as_bytes()));
            }
            let receiver =
                zdn::state::StateStore::open(f._inputs.root.path().join("receiver")).unwrap();
            let profile = zdn::aws::LocalProfile {
                aws_profile: f.deployment.spec.aws_profile.clone(),
                team: f.deployment.team.clone(),
            };
            let context = f.binding.context.clone();
            zdn::handoff::import::import(
                &receiver,
                &context,
                f.binding.network_id,
                &profile,
                &archive,
                &pin,
            )
            .unwrap();
            let target = receiver
                .root()
                .join("foundation")
                .join(f.binding.network_id.to_string());
            assert_eq!(
                fs::read(target.join("build/attempt.json")).unwrap(),
                exact,
                "{state}"
            );
            let prep = zdn::build::preparation::Preparation::read(&target).unwrap();
            assert_eq!(
                prep.native_runtime_protocol.as_deref(),
                Some(zdn::host::runtime::PROTOCOL)
            );
            let deployment = zdn::foundation::DeploymentFile::read_snapshot(
                receiver.root(),
                f.binding.network_id,
            )
            .unwrap();
            prep.verify(&target, &deployment).unwrap();
            assert_eq!(
                prep.installer_fetch_protocol.as_deref(),
                Some("zdn-installer-fetch/v1alpha2")
            );
            assert_eq!(
                prep.capacity_protocol.as_deref(),
                if lightwallet {
                    Some("zdn-host-capacity/v1alpha1")
                } else {
                    None
                }
            );
            assert!(deployment.cluster.is_none() && deployment.runtime.is_none());
            assert_eq!(target.join("build/exporter").is_file(), native);
            if native {
                let bytes = fs::read(target.join("build/exporter")).unwrap();
                let expected = &prep.files["source-preparation/zdn"];
                assert_eq!(sha256(&bytes), expected.sha256);
                assert_eq!(bytes.len() as u64, expected.bytes);
            }
            assert_eq!(
                zdn::build_job::validate_preparation(
                    &target.join("build"),
                    &deployment.team,
                    &prep.contract
                )
                .unwrap()
                .submission_recorded,
                !matches!(
                    state,
                    "not-uploaded" | "runtime-uploaded" | "uploaded" | "reused"
                )
            );
        }
    }
}

#[test]
fn initial_build_handoff_rejects_incomplete_or_unbound_inputs_and_effects() {
    use fs2::FileExt;
    for case in [
        "missing-preparation",
        "missing-attempt",
        "missing-snapshot-receipt",
        "missing-inputs",
        "missing-helper",
        "missing-exporter",
        "exporter",
        "archive",
        "contract",
        "config",
        "input-binding",
        "attempt-contract",
        "build-lock",
        "forbidden-payload",
        "update",
        "stack",
        "operation",
    ] {
        let mut f = initial_build_fixture(false);
        let directory = f.file.directory().to_owned();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join("build/attempt.lock"))
            .unwrap();
        match case {
            "missing-preparation" => {
                fs::remove_file(directory.join("source-preparation.json")).unwrap()
            }
            "missing-attempt" => fs::remove_file(directory.join("build/attempt.json")).unwrap(),
            "missing-snapshot-receipt" => {
                fs::remove_file(directory.join("source-snapshot/receipt.json")).unwrap()
            }
            "missing-inputs" => {
                fs::remove_file(directory.join("source-build-inputs.json")).unwrap()
            }
            "missing-helper" => fs::remove_file(directory.join("source-preparation/zdn")).unwrap(),
            "missing-exporter" => fs::remove_file(directory.join("build/exporter")).unwrap(),
            "exporter" => fs::write(directory.join("build/exporter"), b"changed").unwrap(),
            "archive" => {
                fs::write(directory.join("source-snapshot/source.tar"), b"changed").unwrap()
            }
            "contract" | "config" => {
                let mut prep = zdn::build::preparation::Preparation::read(&directory).unwrap();
                if case == "contract" {
                    prep.contract.revision = "f".repeat(40);
                } else {
                    prep.config.name.push_str("-changed");
                }
                zdn::foundation::write_json(&directory.join("source-preparation.json"), &prep)
                    .unwrap();
            }
            "input-binding" | "attempt-contract" => {
                let path = directory.join(if case == "input-binding" {
                    "source-build-inputs.json"
                } else {
                    "build/attempt.json"
                });
                let mut value: Value = zdn::foundation::read_json(&path).unwrap();
                if case == "input-binding" {
                    value["config_sha256"] = json!("d".repeat(64));
                } else {
                    value["contract"]["sourceSha256"] = json!("d".repeat(64));
                }
                zdn::foundation::write_json(&path, &value).unwrap();
            }
            "build-lock" => lock.try_lock_exclusive().unwrap(),
            "forbidden-payload" => fs::write(
                directory.join("source-preparation/credentials.json"),
                b"secret",
            )
            .unwrap(),
            "update" => {
                zdn::foundation::private_directory(&directory.join("updates")).unwrap();
                zdn::foundation::private_directory(
                    &directory.join("updates").join(Uuid::new_v4().to_string()),
                )
                .unwrap();
            }
            "stack" => {
                f.deployment.stack_initialized = true;
                f.file.save(&f.deployment).unwrap();
            }
            "operation" => {
                f.deployment.last_operation = Some(Uuid::new_v4());
                f.file.save(&f.deployment).unwrap();
            }
            _ => unreachable!(),
        }
        drop(f.file);
        let archive = f._inputs.root.path().join("rejected.tar");
        let result = zdn::handoff::export::export(&f.store, &f.binding, &archive);
        assert!(result.is_err(), "{case}");
        assert!(!archive.exists(), "{case} published an invalid handoff");
    }
}

#[test]
fn initial_build_import_checks_semantic_bindings_even_with_a_new_valid_archive_pin() {
    use std::io::Read;
    let f = initial_build_fixture(false);
    drop(f.file);
    let archive = f._inputs.root.path().join("initial.tar");
    zdn::handoff::export::export(&f.store, &f.binding, &archive).unwrap();
    let mut payloads = BTreeMap::new();
    for entry in tar::Archive::new(fs::File::open(&archive).unwrap())
        .entries()
        .unwrap()
    {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        payloads.insert(name, bytes);
    }
    let original: zdn::handoff::Manifest =
        serde_json::from_slice(&payloads.remove("handoff.json").unwrap()).unwrap();
    for case in [
        "control",
        "missing-preparation",
        "missing-receipt",
        "missing-attempt",
        "missing-exporter",
        "repinned-exporter",
        "legacy-extra-exporter",
        "archive",
        "contract",
        "config",
        "input-binding",
        "attempt-contract",
        "forbidden",
        "partial-update",
        "stack",
    ] {
        let mut files = payloads.clone();
        let mut manifest = original.clone();
        let mut prep: zdn::build::preparation::Preparation =
            serde_json::from_slice(&files["source-preparation.json"]).unwrap();
        match case {
            "missing-preparation" => {
                files.remove("source-preparation.json");
            }
            "missing-receipt" => {
                files.remove("source-snapshot/receipt.json");
            }
            "missing-attempt" => {
                files.remove("build/attempt.json");
            }
            "missing-exporter" => {
                files.remove("build/exporter");
            }
            "repinned-exporter" => {
                let bytes = files.get_mut("build/exporter").unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                let artifact = devnet::Artifact {
                    sha256: sha256(bytes),
                    bytes: bytes.len() as u64,
                };
                let mut attempt: Value =
                    serde_json::from_slice(&files["build/attempt.json"]).unwrap();
                attempt["exporter"]["helper"] = serde_json::to_value(artifact).unwrap();
                files.insert(
                    "build/attempt.json".into(),
                    serde_json::to_vec(&attempt).unwrap(),
                );
            }
            "legacy-extra-exporter" => {
                let mut attempt: Value =
                    serde_json::from_slice(&files["build/attempt.json"]).unwrap();
                attempt.as_object_mut().unwrap().remove("exporter");
                files.insert(
                    "build/attempt.json".into(),
                    serde_json::to_vec(&attempt).unwrap(),
                );
            }
            "archive" => {
                files.insert("source-snapshot/source.tar".into(), b"tampered".to_vec());
            }
            "contract" => prep.contract.revision = "e".repeat(40),
            "config" => prep.config.name.push_str("-changed"),
            "input-binding" | "attempt-contract" => {
                let path = if case == "input-binding" {
                    "source-build-inputs.json"
                } else {
                    "build/attempt.json"
                };
                let mut value: Value = serde_json::from_slice(&files[path]).unwrap();
                if case == "input-binding" {
                    value["config_sha256"] = json!("d".repeat(64));
                } else {
                    value["contract"]["sourceSha256"] = json!("d".repeat(64));
                }
                files.insert(path.into(), serde_json::to_vec(&value).unwrap());
            }
            "forbidden" => {
                files.insert("build/result.json".into(), b"{}".to_vec());
            }
            "partial-update" => {
                files.insert(
                    format!("updates/{}/build/attempt.json", Uuid::new_v4()),
                    b"{}".to_vec(),
                );
            }
            "stack" => manifest.deployment.stack_initialized = true,
            _ => {}
        }
        // Refresh both inventories: rejection must come from the recovery
        // contract, not merely an outdated transport hash or missing tar entry.
        for (path, expected) in &mut prep.files {
            if let Some(bytes) = files.get(path) {
                *expected = devnet::Artifact {
                    sha256: sha256(bytes),
                    bytes: bytes.len() as u64,
                };
            }
        }
        if case != "missing-preparation" {
            files.insert(
                "source-preparation.json".into(),
                serde_json::to_vec(&prep).unwrap(),
            );
        }
        manifest.files = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    devnet::Artifact {
                        sha256: sha256(bytes),
                        bytes: bytes.len() as u64,
                    },
                )
            })
            .collect();
        let candidate = f._inputs.root.path().join(format!("{case}.tar"));
        let mut tar = tar::Builder::new(fs::File::create(&candidate).unwrap());
        for (name, bytes) in std::iter::once((
            "handoff.json".to_owned(),
            serde_json::to_vec(&manifest).unwrap(),
        ))
        .chain(files)
        {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append_data(&mut header, name, &bytes[..]).unwrap();
        }
        tar.finish().unwrap();
        drop(tar);
        let pin = sha256(&fs::read(&candidate).unwrap());
        let receiver =
            zdn::state::StateStore::open(f._inputs.root.path().join(format!("receiver-{case}")))
                .unwrap();
        let profile = zdn::aws::LocalProfile {
            aws_profile: f.deployment.spec.aws_profile.clone(),
            team: f.deployment.team.clone(),
        };
        let result = zdn::handoff::import::import(
            &receiver,
            &f.binding.context,
            f.binding.network_id,
            &profile,
            &candidate,
            &pin,
        );
        assert_eq!(result.is_ok(), case == "control", "{case}: {result:?}");
        if case != "control" {
            assert!(receiver
                .list(&f.deployment.team.scope())
                .unwrap()
                .is_empty());
            assert!(!receiver.root().join("foundation").exists());
        }
    }
}
