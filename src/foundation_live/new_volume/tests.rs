use super::*;
use crate::pulumi::{CommandSpec, ProcessOutput, Progress};
use std::cell::Cell;

#[test]
fn fresh_pulumi_export_without_resources_can_record_intent_but_legacy_cannot() {
    // Pulumi 3.268.0 omits resources for a newly initialized stack.
    let empty = json!({"version":3,"deployment":{"manifest":{}}});
    assert!(empty_stack_for_creation(&empty, false).unwrap());
    assert!(!empty_stack_for_creation(&empty, true).unwrap());
    for malformed in [Value::Null, json!({}), json!("invalid")] {
        let mut bad = empty.clone();
        bad["deployment"]["resources"] = malformed;
        assert!(empty_stack_for_creation(&bad, false).is_err());
    }
    let mut existing = empty.clone();
    existing["deployment"]["resources"] = json!([{"urn":"urn:test","type":"aws:ec2/vpc:Vpc"}]);
    assert!(!empty_stack_for_creation(&existing, false).unwrap());
    existing["deployment"]["pending_operations"] = json!([{"type":"creating"}]);
    assert!(empty_stack_for_creation(&existing, false).is_err());
}

struct Fixture {
    intent: CreationIntent,
    node: ClusterNodeOutputs,
    checkpoint: Value,
    volume: Value,
    now: u64,
}

impl Fixture {
    fn new() -> Self {
        let started = crate::credentials::utc_timestamp("2026-10-15T17:00:00Z").unwrap();
        let tags = BTreeMap::from([
            ("Name".into(), "zdn-fixture-chainDisk".into()),
            ("zdn:network-id".into(), "fixture".into()),
            ("zdn:team-id".into(), "test".into()),
            ("zdn:bootstrap".into(), "owner".into()),
            ("zdn:node-id".into(), "node-1".into()),
        ]);
        let expected = ExpectedNode {
            volume_urn: "urn:pulumi:fixture::zdn-foundation::aws:ebs/volume:Volume::chainDisk".into(),
            host_urn: "urn:pulumi:fixture::zdn-foundation::aws:ec2/instance:Instance::host".into(),
            attachment_urn: "urn:pulumi:fixture::zdn-foundation::aws:ec2/volumeAttachment:VolumeAttachment::attachment".into(),
            tags: tags.clone(),
        };
        let properties =
            json!({"encrypted":true,"size":80,"availabilityZone":"us-east-1a","tags":tags});
        let mut outputs = properties.clone();
        outputs["id"] = json!("vol-0123456789abcdef0");
        outputs["snapshotId"] = json!("");
        outputs["createTime"] = json!("2026-10-15T17:00:03Z");
        outputs["kmsKeyId"] = json!("arn:aws:kms:us-east-1:123456789012:key/test");
        let attachment = json!({"volumeId":"vol-0123456789abcdef0","instanceId":"i-0123456789abcdef0","deviceName":"/dev/sdf"});
        let checkpoint = json!({"version":3,"deployment":{"resources":[
            {"urn":expected.volume_urn,"custom":true,"type":"aws:ebs/volume:Volume","id":"vol-0123456789abcdef0","created":"2026-10-15T17:00:13.524241Z","inputs":properties,"outputs":outputs},
            {"urn":expected.host_urn,"custom":true,"type":"aws:ec2/instance:Instance","id":"i-0123456789abcdef0","created":"2026-10-15T17:01:00Z","outputs":{"id":"i-0123456789abcdef0"}},
            {"urn":expected.attachment_urn,"custom":true,"type":"aws:ec2/volumeAttachment:VolumeAttachment","id":"vai-1","created":"2026-10-15T17:01:03Z","inputs":attachment,"outputs":attachment}
        ]}});
        let volume = json!({"VolumeId":"vol-0123456789abcdef0","Size":80,"Encrypted":true,"AvailabilityZone":"us-east-1a","SnapshotId":"","State":"in-use","KmsKeyId":"arn:aws:kms:us-east-1:123456789012:key/test","CreateTime":"2026-10-15T17:00:03+00:00","Tags":tags.iter().map(|(key,value)|json!({"Key":key,"Value":value})).collect::<Vec<_>>(),"Attachments":[{"VolumeId":"vol-0123456789abcdef0","InstanceId":"i-0123456789abcdef0","Device":"/dev/sdf","State":"attached"}]});
        Self {
            intent: CreationIntent {
                version: 1,
                request_sha256: "a".repeat(64),
                started_at: started,
                availability_zone: "us-east-1a".into(),
                size_gib: 80,
                nodes: BTreeMap::from([("node-1".into(), expected)]),
                lightwallet: None,
            },
            node: ClusterNodeOutputs {
                node_id: "node-1".into(),
                instance_id: "i-0123456789abcdef0".into(),
                volume_id: "vol-0123456789abcdef0".into(),
                private_ip: "10.90.1.10".parse().unwrap(),
            },
            checkpoint,
            volume,
            now: started + 120,
        }
    }

    fn authorize(&self) -> Result<NewVolumeAuthorization> {
        authorize(
            &self.intent,
            &self.node,
            &self.checkpoint,
            &self.volume,
            self.now,
        )
    }
}

#[test]
fn new_encrypted_volume_requires_and_pins_both_creation_proofs() {
    let f = Fixture::new();
    let auth = f.authorize().unwrap();
    assert_eq!(auth.volume_id, f.node.volume_id);
    assert_eq!(auth.instance_id, f.node.instance_id);
    assert_eq!(auth.size_bytes, 80 * GIB);
    assert_eq!(
        auth.creation_intent_sha256,
        devnet::sha256(&serde_json::to_vec(&f.intent).unwrap())
    );
    assert_eq!(
        auth.checkpoint_sha256,
        devnet::sha256(&serde_json::to_vec(&f.checkpoint).unwrap())
    );
    // Saved evidence retains its original observation time across later up and
    // observe calls; later metadata refreshes must not change installer bytes.
    let receipt = VolumeReceipt {
        authorization: auth.clone(),
        observed_at: f.now,
        volume: f.volume.clone(),
    };
    let receipt: VolumeReceipt =
        serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_eq!(
        authorize(
            &f.intent,
            &f.node,
            &f.checkpoint,
            &receipt.volume,
            receipt.observed_at
        )
        .unwrap(),
        auth
    );
    assert!(authorize(
        &f.intent,
        &f.node,
        &f.checkpoint,
        &f.volume,
        f.now + CREATION_WINDOW
    )
    .is_err());
}

#[test]
fn checkpoint_import_reuse_pending_delete_and_duplicate_proofs_are_refused() {
    for (path, value) in [
        (
            "/deployment/pending_operations",
            json!([{"type":"creating"}]),
        ),
        ("/deployment/resources/0/external", json!(true)),
        (
            "/deployment/resources/0/importID",
            json!("vol-0123456789abcdef0"),
        ),
        ("/deployment/resources/0/delete", json!(true)),
        ("/deployment/resources/0/pendingReplacement", json!(true)),
        ("/deployment/resources/0/custom", json!(false)),
        (
            "/deployment/resources/0/created",
            json!("2026-10-15T16:59:59Z"),
        ),
        (
            "/deployment/resources/0/outputs/createTime",
            json!("2026-10-15T16:59:59Z"),
        ),
        (
            "/deployment/resources/0/inputs/snapshotId",
            json!("snap-123"),
        ),
        (
            "/deployment/resources/0/outputs/snapshotId",
            json!("snap-123"),
        ),
        ("/deployment/resources/0/id", json!("vol-fffffffffffffffff")),
        ("/deployment/resources/1/id", json!("i-fffffffffffffffff")),
        (
            "/deployment/resources/1/type",
            json!("aws:ec2/volume:Volume"),
        ),
        (
            "/deployment/resources/1/created",
            json!("2026-10-15T17:30:00Z"),
        ),
        (
            "/deployment/resources/2/outputs/instanceId",
            json!("i-fffffffffffffffff"),
        ),
        (
            "/deployment/resources/2/inputs/volumeId",
            json!("vol-fffffffffffffffff"),
        ),
        (
            "/deployment/resources/0/outputs/tags/zdn:bootstrap",
            json!("other"),
        ),
        ("/deployment/resources/0/inputs/encrypted", json!(false)),
        ("/deployment/resources/0/outputs/size", json!(81)),
    ] {
        let mut f = Fixture::new();
        let (parent, key) = path.rsplit_once('/').unwrap();
        f.checkpoint.pointer_mut(parent).unwrap()[key] = value;
        assert!(f.authorize().is_err(), "accepted mutation {path}");
    }
    let mut f = Fixture::new();
    let duplicate = f.checkpoint["deployment"]["resources"][0].clone();
    f.checkpoint["deployment"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(f.authorize().unwrap_err().to_string().contains("duplicate"));
}

#[test]
fn aws_volume_tags_alone_never_authorize_existing_or_retargeted_data() {
    for (path, value) in [
        ("/VolumeId", json!("vol-fffffffffffffffff")),
        ("/CreateTime", json!("2026-10-15T16:59:59Z")),
        ("/CreateTime", json!("2026-10-15T17:00:04Z")),
        ("/SnapshotId", json!("snap-123")),
        ("/Encrypted", json!(false)),
        ("/Size", json!(81)),
        ("/AvailabilityZone", json!("us-east-1b")),
        ("/KmsKeyId", json!("other")),
        ("/State", json!("available")),
        ("/Tags", json!([])),
        ("/Attachments", json!([])),
        ("/Attachments/0/InstanceId", json!("i-fffffffffffffffff")),
        ("/Attachments/0/State", json!("attaching")),
    ] {
        let mut f = Fixture::new();
        *f.volume.pointer_mut(path).unwrap() = value;
        assert!(f.authorize().is_err(), "accepted mutation {path}");
    }
    let mut f = Fixture::new();
    f.intent.started_at = f.now + 1;
    assert!(f.authorize().is_err());
}

struct CacheFixture {
    base: Fixture,
    cache: ClusterLightwalletOutputs,
}

impl CacheFixture {
    fn new() -> Self {
        let mut base = Fixture::new();
        let node = base.intent.nodes["node-1"].clone();
        let mut expected = ExpectedCache {
            node_id: "node-2".into(),
            size_gib: 40,
            resource: ExpectedNode {
                volume_urn: "urn:pulumi:fixture::zdn-foundation::aws:ebs/volume:Volume::lightwalletCacheDisk".into(),
                host_urn: node.host_urn,
                attachment_urn: "urn:pulumi:fixture::zdn-foundation::aws:ec2/volumeAttachment:VolumeAttachment::lightwalletCacheAttachment".into(),
                tags: node.tags,
            },
        };
        expected
            .resource
            .tags
            .insert("Name".into(), "zdn-fixture-lightwalletCacheDisk".into());
        expected
            .resource
            .tags
            .insert("zdn:node-id".into(), "node-2".into());
        expected
            .resource
            .tags
            .insert("zdn:service".into(), "lightwalletd".into());
        let resources = &mut base.checkpoint["deployment"]["resources"];
        resources[0]["urn"] = json!(expected.resource.volume_urn);
        resources[0]["id"] = json!("vol-0123456789abcdef1");
        resources[0]["outputs"]["id"] = json!("vol-0123456789abcdef1");
        resources[2]["urn"] = json!(expected.resource.attachment_urn);
        for field in ["inputs", "outputs"] {
            resources[0][field]["size"] = json!(40);
            resources[0][field]["tags"] = json!(expected.resource.tags);
            resources[2][field]["volumeId"] = json!("vol-0123456789abcdef1");
            resources[2][field]["deviceName"] = json!(LIGHTWALLET_CACHE_DEVICE);
        }
        base.volume["VolumeId"] = json!("vol-0123456789abcdef1");
        base.volume["Size"] = json!(40);
        base.volume["Attachments"][0]["VolumeId"] = json!("vol-0123456789abcdef1");
        base.volume["Attachments"][0]["Device"] = json!(LIGHTWALLET_CACHE_DEVICE);
        base.volume["Tags"] = json!(expected
            .resource
            .tags
            .iter()
            .map(|(key, value)| json!({"Key":key,"Value":value}))
            .collect::<Vec<_>>());
        base.intent.lightwallet = Some(expected);
        let cache = ClusterLightwalletOutputs {
            node_id: "node-2".into(),
            instance_id: base.node.instance_id.clone(),
            cache_volume_id: "vol-0123456789abcdef1".into(),
            cache_size_gib: 40,
        };
        Self { base, cache }
    }

    fn authorize(&self) -> Result<NewVolumeAuthorization> {
        authorize_lightwallet(
            &self.base.intent,
            &self.cache,
            &self.base.checkpoint,
            &self.base.volume,
            self.base.now,
        )
    }
}

#[test]
fn cache_proof_pins_its_dedicated_volume_size_device_and_creation_evidence() {
    let f = CacheFixture::new();
    let authorization = f.authorize().unwrap();
    assert_eq!(authorization.volume_id, f.cache.cache_volume_id);
    assert_eq!(authorization.instance_id, f.cache.instance_id);
    assert_eq!(authorization.size_bytes, 40 * GIB);
    authorization.validate(&f.cache.cache_volume_id).unwrap();
    assert_eq!(
        authorization.creation_intent_sha256,
        devnet::sha256(&serde_json::to_vec(&f.base.intent).unwrap())
    );
    assert_eq!(
        authorization.checkpoint_sha256,
        devnet::sha256(&serde_json::to_vec(&f.base.checkpoint).unwrap())
    );
    assert!(authorize(
        &f.base.intent,
        &f.base.node,
        &f.base.checkpoint,
        &f.base.volume,
        f.base.now
    )
    .is_err());
    let target = AuthorizationTarget::Lightwallet(&f.cache);
    assert_eq!(target.stem(), "lightwallet");
    assert_eq!(target.volume_id(), f.cache.cache_volume_id);
    assert_eq!(
        target
            .authorize(
                &f.base.intent,
                &f.base.checkpoint,
                &f.base.volume,
                f.base.now
            )
            .unwrap(),
        authorization
    );
}

#[test]
fn cache_proof_refuses_chain_device_reused_host_import_or_mutated_creation_metadata() {
    for (path, value) in [
        ("/deployment/resources/0/inputs/size", json!(80)),
        ("/deployment/resources/0/outputs/size", json!(80)),
        (
            "/deployment/resources/0/inputs/tags/zdn:service",
            json!("node"),
        ),
        (
            "/deployment/resources/0/outputs/tags/zdn:node-id",
            json!("node-1"),
        ),
        (
            "/deployment/resources/0/created",
            json!("2026-10-15T16:59:59Z"),
        ),
        (
            "/deployment/resources/1/created",
            json!("2026-10-15T16:59:59Z"),
        ),
        (
            "/deployment/resources/2/inputs/deviceName",
            json!("/dev/sdf"),
        ),
        (
            "/deployment/resources/2/outputs/deviceName",
            json!("/dev/sdf"),
        ),
        (
            "/deployment/resources/2/outputs/instanceId",
            json!("i-fffffffffffffffff"),
        ),
    ] {
        let mut f = CacheFixture::new();
        *f.base.checkpoint.pointer_mut(path).unwrap() = value;
        assert!(f.authorize().is_err(), "{path}");
    }
    for field in ["external", "delete", "pendingReplacement", "imported"] {
        let mut f = CacheFixture::new();
        f.base.checkpoint["deployment"]["resources"][0][field] = json!(true);
        assert!(f.authorize().is_err(), "{field}");
    }
    let mut f = CacheFixture::new();
    f.base.checkpoint["deployment"]["pending_operations"] = json!([{"type":"creating"}]);
    assert!(f.authorize().is_err());
    let mut f = CacheFixture::new();
    f.base.volume["Attachments"][0]["Device"] = json!("/dev/sdf");
    assert!(f.authorize().is_err());
    let mut f = CacheFixture::new();
    f.base.volume["Size"] = json!(80);
    assert!(f.authorize().is_err());
    let mut f = CacheFixture::new();
    f.cache.node_id = "node-1".into();
    assert!(f.authorize().is_err());
    let mut f = CacheFixture::new();
    f.cache.cache_size_gib = 80;
    assert!(f.authorize().is_err());
    let mut f = CacheFixture::new();
    f.base.intent.lightwallet = None;
    assert!(f.authorize().is_err());
}

#[test]
fn adding_cache_intent_preserves_exact_node_only_serialization_and_proof_hash() {
    let f = Fixture::new();
    let encoded = serde_json::to_vec(&f.intent).unwrap();
    let mut value = serde_json::to_value(&f.intent).unwrap();
    assert!(value.get("lightwallet").is_none());
    let restored: CreationIntent = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored, f.intent);
    assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded);
    value["lightwallet"] = Value::Null;
    let explicit_none: CreationIntent = serde_json::from_value(value).unwrap();
    assert_eq!(serde_json::to_vec(&explicit_none).unwrap(), encoded);
    let mut with_cache = f.intent.clone();
    with_cache.lightwallet = CacheFixture::new().base.intent.lightwallet;
    assert_ne!(
        devnet::sha256(&serde_json::to_vec(&with_cache).unwrap()),
        f.authorize().unwrap().creation_intent_sha256
    );
    assert_eq!(
        serde_json::from_slice::<CreationIntent>(&serde_json::to_vec(&with_cache).unwrap())
            .unwrap(),
        with_cache
    );
}

#[test]
fn interrupted_node_and_cache_proofs_keep_the_original_checkpoint_on_recovery() {
    let node = Fixture::new();
    let cache = CacheFixture::new();
    for (intent, target, checkpoint, volume, now) in [
        (
            &node.intent,
            AuthorizationTarget::Node(&node.node),
            &node.checkpoint,
            &node.volume,
            node.now,
        ),
        (
            &cache.base.intent,
            AuthorizationTarget::Lightwallet(&cache.cache),
            &cache.base.checkpoint,
            &cache.base.volume,
            cache.base.now,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let proof = directory
            .path()
            .join(format!("{}-new-volume-checkpoint.json", target.stem()));
        foundation::write_json(&proof, checkpoint).unwrap();
        let original_bytes = std::fs::read(&proof).unwrap();
        // A later export can differ in irrelevant metadata, but recovery must
        // retain the original checkpoint bytes and the original pinned digest.
        let mut fresh = checkpoint.clone();
        fresh["deployment"]["manifest"] = json!({"time":"later export"});
        assert_ne!(fresh, *checkpoint);
        save_new_authorization(directory.path(), intent, target, &fresh, volume, now).unwrap();
        assert_eq!(std::fs::read(&proof).unwrap(), original_bytes);
        let receipt: VolumeReceipt = foundation::read_json(
            &directory
                .path()
                .join(format!("{}-new-volume.json", target.stem())),
        )
        .unwrap();
        assert_eq!(
            receipt.authorization,
            target.authorize(intent, checkpoint, volume, now).unwrap()
        );
        assert_eq!(receipt.observed_at, now);
        assert_eq!(receipt.volume, *volume);
    }
}

#[test]
fn fresh_export_cannot_replace_an_invalid_interrupted_proof() {
    let f = Fixture::new();
    for (path, value) in [
        ("/deployment/resources/0/id", json!("vol-fffffffffffffffff")),
        ("/deployment/resources/0/imported", json!(true)),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let target = AuthorizationTarget::Node(&f.node);
        let proof = directory
            .path()
            .join(format!("{}-new-volume-checkpoint.json", target.stem()));
        let mut invalid = f.checkpoint.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        invalid.pointer_mut(parent).unwrap()[key] = value;
        foundation::write_json(&proof, &invalid).unwrap();
        let original_bytes = std::fs::read(&proof).unwrap();
        assert!(save_new_authorization(
            directory.path(),
            &f.intent,
            target,
            &f.checkpoint,
            &f.volume,
            f.now,
        )
        .is_err());
        assert_eq!(std::fs::read(&proof).unwrap(), original_bytes);
        assert!(!directory
            .path()
            .join(format!("{}-new-volume.json", target.stem()))
            .exists());
    }
}

struct ExportRunner {
    checkpoint: Value,
    exports: std::rc::Rc<Cell<usize>>,
    generation: Cell<usize>,
}

impl PulumiRunner for ExportRunner {
    fn run(&self, command: &CommandSpec, progress: &mut Progress<'_>) -> Result<ProcessOutput> {
        ensure!(progress()? == RunControl::Continue, "cancelled");
        let stdout = match command.label.as_str() {
            "stack-select" => Vec::new(),
            "stack-export" => {
                self.exports.set(self.exports.get() + 1);
                self.generation.set(self.generation.get() + 1);
                let mut checkpoint = self.checkpoint.clone();
                checkpoint["deployment"]["manifest"] = json!({"generation":self.generation.get()});
                serde_json::to_vec(&checkpoint)?
            }
            other => bail!("unexpected Pulumi command {other}"),
        };
        Ok(ProcessOutput {
            stdout,
            stderr: vec![],
            success: true,
            exit_code: Some(0),
        })
    }
}

struct VolumeApi {
    volumes: BTreeMap<String, Value>,
    observations: Cell<usize>,
}

impl AwsApi for VolumeApi {
    fn call(&self, service: &str, operation: &str, input: Value, _: &[String]) -> Result<Value> {
        assert_eq!((service, operation), ("ec2", "describe-volumes"));
        let ids = input["VolumeIds"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        self.observations.set(self.observations.get() + 1);
        Ok(json!({"Volumes":[self.volumes[ids[0].as_str().unwrap()]]}))
    }
}

struct ProofClock(u64);
impl Runtime for ProofClock {
    fn unix_time(&self) -> Result<u64> {
        Ok(self.0)
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&self, _: Duration) {
        panic!("proof preparation must not sleep")
    }
}

struct OperationFixture {
    _root: tempfile::TempDir,
    deployment: Deployment,
    backend: LiveBackend<'static, VolumeApi, ExportRunner, ProofClock>,
    exports: std::rc::Rc<Cell<usize>>,
}

impl OperationFixture {
    fn new(count: u8, with_cache: bool) -> Self {
        use crate::{
            cluster_infra::LightwalletAllocation,
            config::Size,
            devnet::{Artifact, LightwalletDeployment},
            lightwallet_image,
        };
        let root = tempfile::tempdir().unwrap();
        let mut deployment = crate::foundation_live::cluster::producer_tests::fixture_deployment();
        let team = deployment.team.clone();
        let request = deployment.cluster.as_mut().unwrap();
        request.node_count = count;
        if with_cache {
            request.lightwallet = Some(LightwalletDeployment {
                allocation: LightwalletAllocation::for_size(Size::Medium), capacity_protocol: Some(crate::host::CAPACITY_PROTOCOL.into()),
                image: lightwallet_image::ImageRecord {
                    api_version: lightwallet_image::API_VERSION.into(), image: format!("123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/private-team/lightwalletd@sha256:{}", "a".repeat(64)),
                    config_digest: format!("sha256:{}", "b".repeat(64)), platform: "linux/amd64".into(), source_revision: lightwallet_image::SOURCE_REVISION.into(),
                    source_version: lightwallet_image::SOURCE_VERSION.into(), protocol_revision: lightwallet_image::PROTOCOL_REVISION.into(), protocol_version: lightwallet_image::PROTOCOL_VERSION.into(),
                    binary_path: lightwallet_image::BINARY_PATH.into(), environment_launcher: lightwallet_image::ENVIRONMENT_LAUNCHER.into(),
                },
            });
            for name in [
                "lightwallet-image.json",
                "lightwallet-image-manifest.json",
                "lightwallet-image-config.json",
            ] {
                request.artifacts.insert(
                    name.into(),
                    Artifact {
                        sha256: "f".repeat(64),
                        bytes: 128,
                    },
                );
            }
        }
        let outputs = deployment.outputs.as_mut().unwrap();
        let retained: BTreeSet<_> = outputs
            .nodes
            .keys()
            .take(usize::from(count))
            .cloned()
            .collect();
        outputs.nodes.retain(|id, _| retained.contains(id));
        if with_cache {
            outputs.lightwallet = Some(ClusterLightwalletOutputs {
                node_id: "node-2".into(),
                instance_id: outputs.nodes["node-2"].instance_id.clone(),
                cache_volume_id: "vol-00000000000000004".into(),
                cache_size_gib: 40,
            });
        }
        let base = Fixture::new();
        let intent = CreationIntent::for_deployment(&deployment, base.intent.started_at).unwrap();
        let outputs = deployment.outputs.as_ref().unwrap();
        let targets = outputs.nodes.values().map(AuthorizationTarget::Node).chain(
            outputs
                .lightwallet
                .as_ref()
                .map(AuthorizationTarget::Lightwallet),
        );
        let mut checkpoint = json!({"version":3,"deployment":{"secrets_providers":{"type":"cloud","state":{"url":team.secrets_provider()}},"resources":[]}});
        let mut volumes = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for target in targets {
            let (expected, instance, size, device) = match target {
                AuthorizationTarget::Node(node) => (
                    &intent.nodes[&node.node_id],
                    &node.instance_id,
                    intent.size_gib,
                    "/dev/sdf",
                ),
                AuthorizationTarget::Lightwallet(cache) => (
                    &intent.lightwallet.as_ref().unwrap().resource,
                    &cache.instance_id,
                    cache.cache_size_gib,
                    LIGHTWALLET_CACHE_DEVICE,
                ),
            };
            // Reuse the verifier fixtures' creation evidence; retarget only to
            // identities and immutable properties rendered by this deployment.
            let mut resources = base.checkpoint["deployment"]["resources"]
                .as_array()
                .unwrap()
                .clone();
            resources[0]["urn"] = json!(expected.volume_urn);
            resources[0]["id"] = json!(target.volume_id());
            resources[1]["urn"] = json!(expected.host_urn);
            resources[1]["id"] = json!(instance);
            resources[1]["outputs"]["id"] = json!(instance);
            resources[2]["urn"] = json!(expected.attachment_urn);
            for field in ["inputs", "outputs"] {
                resources[0][field]["size"] = json!(size);
                resources[0][field]["tags"] = json!(expected.tags);
                resources[2][field] = json!({"volumeId":target.volume_id(),"instanceId":instance,"deviceName":device});
            }
            resources[0]["outputs"]["id"] = json!(target.volume_id());
            for resource in resources {
                if seen.insert(resource["urn"].as_str().unwrap().to_owned()) {
                    checkpoint["deployment"]["resources"]
                        .as_array_mut()
                        .unwrap()
                        .push(resource);
                }
            }
            let mut volume = base.volume.clone();
            volume["VolumeId"] = json!(target.volume_id());
            volume["Size"] = json!(size);
            volume["Tags"] = json!(expected
                .tags
                .iter()
                .map(|(key, value)| json!({"Key":key,"Value":value}))
                .collect::<Vec<_>>());
            volume["Attachments"] = json!([{"VolumeId":target.volume_id(),"InstanceId":instance,"Device":device,"State":"attached"}]);
            volumes.insert(target.volume_id().to_owned(), volume);
        }
        let program = deployment.render().unwrap();
        let prefix = format!(
            "urn:pulumi:zdn-{}::{}::",
            deployment.spec.network_id.simple(),
            program.name
        );
        let provider_urn = format!(
            "{prefix}pulumi:providers:aws::{}",
            program.resources["provider"].name
        );
        let provider_ref = format!("{provider_urn}::fixture-provider");
        let mut provider =
            serde_json::to_value(&program.resources["provider"]).unwrap()["properties"].clone();
        provider["version"] = json!(crate::infra::AWS_PROVIDER_VERSION);
        for resource in checkpoint["deployment"]["resources"]
            .as_array_mut()
            .unwrap()
        {
            resource["provider"] = json!(provider_ref);
        }
        checkpoint["deployment"]["resources"].as_array_mut().unwrap().push(json!({"urn":provider_urn,"type":"pulumi:providers:aws","id":"fixture-provider","inputs":provider}));
        let work = root.path().join("project");
        std::fs::create_dir(&work).unwrap();
        let executable = work.join("pulumi");
        std::fs::write(&executable, "fixture only").unwrap();
        std::fs::write(work.join("Pulumi.yaml"), program.to_yaml().unwrap()).unwrap();
        let stack = format!("zdn-{}", deployment.spec.network_id.simple());
        std::fs::write(
            work.join(format!("Pulumi.{stack}.yaml")),
            format!("secretsprovider: {}\n", team.secrets_provider()),
        )
        .unwrap();
        let workspace = PulumiWorkspace {
            tools: ManagedTools {
                executable,
                bin_dir: work.clone(),
                plugins_dir: work.clone(),
            },
            work_dir: work,
            diagnostics_dir: root.path().join("diagnostics"),
            backend_url: team.state.backend.clone(),
            secrets_provider: team.secrets_provider(),
            aws: AwsContext {
                credential_files: None,
                profile: "developer".into(),
                account_id: team.aws.account_id.clone(),
                region: team.aws.region.clone(),
            },
            project: program.name,
            stack,
        };
        let exports = std::rc::Rc::new(Cell::new(0));
        let mut client = PulumiClient::new(
            workspace,
            ExportRunner {
                checkpoint,
                exports: exports.clone(),
                generation: Cell::new(0),
            },
        )
        .unwrap();
        client
            .prepare_stack(false, &mut || Ok(RunControl::Continue))
            .unwrap();
        exports.set(0);
        let directory = root.path().join("deployment");
        std::fs::create_dir(&directory).unwrap();
        foundation::write_json(&directory.join(INTENT), &intent).unwrap();
        let backend = LiveBackend {
            client,
            aws: VolumeApi {
                volumes,
                observations: Cell::new(0),
            },
            selection: AwsSelection {
                profile: "developer".into(),
                account_id: team.aws.account_id.clone(),
                region: team.aws.region.clone(),
            },
            runtime: ProofClock(base.now),
            reservation: NetworkReservation::new(
                deployment.spec.scope.clone(),
                deployment.spec.network_id,
                deployment.owner_id,
            )
            .unwrap(),
            team,
            lease: None,
            cancel: Arc::new(AtomicBool::new(false)),
            heartbeat: Heartbeat::default(),
            recovery_etag: None,
            destroying: false,
            destroy_context: None,
            stack_missing: false,
            state_root: root.path().join("state"),
            deployment_directory: directory,
            command_progress: None,
        };
        Self {
            _root: root,
            deployment,
            backend,
            exports,
        }
    }

    fn proof_bytes(&self) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(&self.backend.deployment_directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_str().unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect()
    }
}

#[test]
fn operation_exports_once_for_missing_targets_and_never_for_saved_or_legacy() {
    for (count, cache) in [(1, false), (2, false), (3, false), (2, true), (3, true)] {
        let mut f = OperationFixture::new(count, cache);
        f.backend.authorize_new_volumes(&f.deployment).unwrap();
        assert_eq!(f.exports.get(), 1);
        assert_eq!(
            f.backend.aws.observations.get(),
            usize::from(count) + usize::from(cache)
        );
        validate_handoff(&f.deployment, &f.backend.deployment_directory).unwrap();
        let saved = f.proof_bytes();
        f.exports.set(0);
        f.backend.aws.observations.set(0);
        f.backend.authorize_new_volumes(&f.deployment).unwrap();
        assert_eq!(f.exports.get(), 0);
        assert_eq!(f.backend.aws.observations.get(), 0);
        assert_eq!(f.proof_bytes(), saved);

        // Remove receipts but leave their immutable checkpoints: resume must
        // export once for the missing receipts and preserve all saved bytes.
        let missing = if cache {
            "lightwallet-new-volume.json"
        } else {
            "node-1-new-volume.json"
        };
        std::fs::remove_file(f.backend.deployment_directory.join(missing)).unwrap();
        let partial = f.proof_bytes();
        f.backend.authorize_new_volumes(&f.deployment).unwrap();
        assert_eq!(f.exports.get(), 1);
        assert_eq!(f.backend.aws.observations.get(), 1);
        for (name, bytes) in partial {
            assert_eq!(
                std::fs::read(f.backend.deployment_directory.join(name)).unwrap(),
                bytes
            );
        }
        validate_handoff(&f.deployment, &f.backend.deployment_directory).unwrap();

        for entry in std::fs::read_dir(&f.backend.deployment_directory).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        f.exports.set(0);
        f.backend.aws.observations.set(0);
        f.backend.authorize_new_volumes(&f.deployment).unwrap();
        assert_eq!(f.exports.get(), 0);
        assert_eq!(f.backend.aws.observations.get(), 0);
        assert!(f.proof_bytes().is_empty());
    }
}
