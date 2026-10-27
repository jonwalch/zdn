use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{HostInstallSpec, S3Object},
    infra::HostObservation,
    lightwallet_service::{LightwalletServiceSpec, API_VERSION, SOURCE_REVISION},
};

const GIB: u64 = 1024 * 1024 * 1024;

pub fn specs() -> (HostInstallSpec, LightwalletServiceSpec) {
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("../fixtures/chain-manifest/valid.json")).unwrap();
    let deployment_id = Uuid::parse_str("12345678-1234-4123-8123-123456789abc").unwrap();
    let mut options = RuntimeOptions::new(deployment_id, "node-2");
    options.network.listen_addr = "10.90.1.11:18233".into();
    options.network.peers = vec!["10.90.1.10:18233".into()];
    let runtime = render_runtime_config(&manifest, &options).unwrap();
    let object = |key: &str| S3Object {
        bucket: "zdn-artifacts-test".into(),
        key: format!("team/test/{key}"),
        sha256: "a".repeat(64),
        bytes: 128,
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
    };
    (
        HostInstallSpec {
            api_version: zdn::host::API_VERSION.into(),
            deployment_id,
            node_id: "node-2".into(),
            consensus_fingerprint: runtime.consensus_fingerprint,
            volume_id: "vol-0123456789abcdef0".into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/zakura@sha256:{}",
                "b".repeat(64)
            ),
            config_toml: runtime.config_toml,
            config_sha256: runtime.config_sha256,
            role: "follower".into(),
            block_interval_seconds: None,
            memory_bytes: 5 * GIB,
            host_reserve_bytes: 2 * GIB,
            cpu_millis: 1250,
            manifest: object("manifest"),
            bundle: object("bundle"),
            helper: object("helper"),
            image_record: object("image-record"),
            image_manifest: object("image-manifest"),
            new_volume: None,
        },
        LightwalletServiceSpec {
            api_version: API_VERSION.into(),
            image: format!(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/lightwalletd@sha256:{}",
                "c".repeat(64)
            ),
            source_revision: SOURCE_REVISION.into(),
            cache_volume_id: "vol-1123456789abcdef0".into(),
            cache_bytes: 8 * GIB,
            memory_bytes: GIB / 2,
            cpu_millis: 500,
            host_observation: HostObservation {
                mem_total_bytes: 8 * GIB,
                ancestor_memory_limits_bytes: vec![],
                online_cpu_count: 2,
                affinity_cpu_count: 2,
                ancestor_cpu_quota_millis: vec![],
            },
        },
    )
}
