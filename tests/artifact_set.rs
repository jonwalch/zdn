//! Tiny data-only artifacts: no executable, container, network, or proof work.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;
use zdn::{
    artifact_set::{artifact_limits, ArtifactSet, Compatibility, Provenance, API_VERSION},
    chain::{artifacts::import_bundle, manifest::ConsensusManifest},
    devnet::Artifact,
    image::{self, ImageCapabilities, ImageProvenance, ImageRecord},
    lightwallet_image as lw,
};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hash(bytes))
}

fn oci(binary: &str) -> (Vec<u8>, Vec<u8>) {
    let config = serde_json::to_vec(&json!({
        "architecture":"amd64","os":"linux",
        "config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":[binary],"Cmd":if binary == "lightwalletd" { vec!["--help"] } else { vec![] },"WorkingDir":"/srv/lightwalletd"},
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}", "a".repeat(64))]}
    }))
    .unwrap();
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}", "b".repeat(64)),"size":1}]
    })).unwrap();
    (config, manifest)
}

struct Fixture {
    dir: TempDir,
    set: ArtifactSet,
}
impl Fixture {
    fn new(lightwallet: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let blocks = tempfile::tempdir().unwrap();
        let bytes = b"synthetic genesis";
        fs::write(blocks.path().join("0000000000.bin"), bytes).unwrap();
        let mut chain: Value =
            serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
        chain["genesis"] = json!({"height":0,"hash":format!("{:064x}",1),"bytesSha256":hash(bytes),"bytesLength":bytes.len()});
        chain["seedBlocks"] = json!([]);
        chain["checkpoints"] = json!([{"height":0,"hash":format!("{:064x}",1)}]);
        let chain: ConsensusManifest = serde_json::from_value(chain).unwrap();
        import_bundle(&chain, blocks.path(), &dir.path().join("chain.tar")).unwrap();
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&chain).unwrap(),
        )
        .unwrap();
        let mut helper = vec![0; 64];
        helper[..4].copy_from_slice(b"\x7fELF");
        helper[4] = 2;
        helper[5] = 1;
        helper[16..18].copy_from_slice(&2_u16.to_le_bytes());
        helper[18..20].copy_from_slice(&62_u16.to_le_bytes());
        fs::write(dir.path().join("zdn"), helper).unwrap();
        let (config, manifest) = oci("zakurad");
        let node_image = ImageRecord {
            api_version: image::API_VERSION.into(),
            image: format!("registry.example/zakura@{}", digest(&manifest)),
            config_digest: digest(&config),
            platform: "linux/amd64".into(),
            provenance: ImageProvenance::Release {
                revision: "c".repeat(40),
                version: "v1.0.0".into(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: image::NODE_BINARY.into(),
            environment_launcher: image::ENV_ENTRYPOINT.into(),
        };
        fs::write(
            dir.path().join("image.json"),
            serde_json::to_vec(&node_image).unwrap(),
        )
        .unwrap();
        fs::write(dir.path().join("image-config.json"), config).unwrap();
        fs::write(dir.path().join("image-manifest.json"), manifest).unwrap();
        let mut provenance = BTreeMap::new();
        for component in ["chain", "node", "helper"] {
            provenance.insert(
                component.into(),
                Provenance {
                    source_url: "https://example.org/source.git".into(),
                    revision: "c".repeat(40),
                    license: "MIT OR Apache-2.0".into(),
                },
            );
        }
        let lightwallet_image = lightwallet.then(|| {
            let (config, manifest) = oci("lightwalletd");
            let record = lw::ImageRecord {
                api_version: lw::API_VERSION.into(),
                image: format!("registry.example/lightwalletd@{}", digest(&manifest)),
                config_digest: digest(&config),
                platform: "linux/amd64".into(),
                source_revision: lw::SOURCE_REVISION.into(),
                source_version: lw::SOURCE_VERSION.into(),
                protocol_revision: lw::PROTOCOL_REVISION.into(),
                protocol_version: lw::PROTOCOL_VERSION.into(),
                binary_path: lw::BINARY_PATH.into(),
                environment_launcher: lw::ENVIRONMENT_LAUNCHER.into(),
            };
            fs::write(
                dir.path().join("lightwallet-image.json"),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            fs::write(dir.path().join("lightwallet-image-config.json"), config).unwrap();
            fs::write(dir.path().join("lightwallet-image-manifest.json"), manifest).unwrap();
            provenance.insert(
                "lightwallet".into(),
                Provenance {
                    source_url: "https://example.org/lightwalletd".into(),
                    revision: lw::SOURCE_REVISION.into(),
                    license: "MIT".into(),
                },
            );
            record
        });
        let set = ArtifactSet {
            api_version: API_VERSION.into(),
            platform: "linux/amd64".into(),
            consensus_fingerprint: chain.fingerprint().unwrap(),
            node_image,
            build: None,
            lightwallet_image,
            compatibility: Compatibility::current(lightwallet),
            provenance,
            artifacts: BTreeMap::new(),
        };
        let mut fixture = Self { dir, set };
        for name in artifact_limits(lightwallet).keys() {
            fixture.repin(name);
        }
        fixture
    }
    fn repin(&mut self, name: &str) {
        let bytes = fs::read(self.dir.path().join(name)).unwrap();
        self.set.artifacts.insert(
            name.into(),
            Artifact {
                sha256: hash(&bytes),
                bytes: bytes.len() as u64,
            },
        );
    }
}

#[test]
fn valid_six_and_nine_sets_roundtrip_and_fingerprint() {
    for lightwallet in [false, true] {
        let fixture = Fixture::new(lightwallet);
        let set =
            ArtifactSet::from_json(&serde_json::to_vec_pretty(&fixture.set).unwrap()).unwrap();
        set.verify(fixture.dir.path()).unwrap();
        assert_eq!(set.artifacts.len(), if lightwallet { 9 } else { 6 });
        assert_eq!(
            set.fingerprint().unwrap(),
            fixture.set.fingerprint().unwrap()
        );
        let mut changed = set.clone();
        changed.provenance.get_mut("helper").unwrap().license = "MIT".into();
        assert_ne!(set.fingerprint().unwrap(), changed.fingerprint().unwrap());
    }
}

#[test]
fn rejects_corrupt_missing_and_repinned_semantic_mismatches() {
    for name in artifact_limits(true).keys() {
        let mut f = Fixture::new(true);
        fs::write(f.dir.path().join(name), b"corrupt").unwrap();
        assert!(f.set.verify(f.dir.path()).is_err(), "{name}");
        f.repin(name);
        assert!(f.set.verify(f.dir.path()).is_err(), "repinned {name}");
        fs::remove_file(f.dir.path().join(name)).unwrap();
        assert!(f.set.verify(f.dir.path()).is_err(), "missing {name}");
    }
    let mut f = Fixture::new(false);
    f.set.consensus_fingerprint = "d".repeat(64);
    assert!(f
        .set
        .verify(f.dir.path())
        .unwrap_err()
        .to_string()
        .contains("consensus"));
    for lightwallet in [false, true] {
        let mut f = Fixture::new(lightwallet);
        let name = if lightwallet {
            "lightwallet-image.json"
        } else {
            "image.json"
        };
        let mut record: Value =
            serde_json::from_slice(&fs::read(f.dir.path().join(name)).unwrap()).unwrap();
        record["image"] = json!(record["image"]
            .as_str()
            .unwrap()
            .replace("registry.example", "other.example"));
        fs::write(
            f.dir.path().join(name),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        f.repin(name);
        assert!(f
            .set
            .verify(f.dir.path())
            .unwrap_err()
            .to_string()
            .contains("record mismatch"));
    }
}

#[test]
fn rejects_invalid_contracts_inventory_and_provenance() {
    let f = Fixture::new(false);
    let value = serde_json::to_value(&f.set).unwrap();
    for (field, replacement) in [
        ("apiVersion", json!("future")),
        ("platform", json!("linux/arm64")),
        ("consensusFingerprint", json!("X".repeat(64))),
    ] {
        let mut v = value.clone();
        v[field] = replacement;
        assert!(ArtifactSet::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for field in [
        "chainBundleApi",
        "runtimeAdapter",
        "helperVersion",
        "lightwalletProtocol",
    ] {
        let mut v = value.clone();
        v["compatibility"][field] = json!("future");
        assert!(ArtifactSet::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for name in ["../zdn", "/zdn", "unknown", "sub/zdn"] {
        let mut set = f.set.clone();
        let artifact = set.artifacts.remove("zdn").unwrap();
        set.artifacts.insert(name.into(), artifact);
        assert!(set.validate().is_err());
    }
    for (field, replacement) in [
        ("sourceUrl", "http://example.org".into()),
        ("sourceUrl", "https://user:pass@example.org".into()),
        ("sourceUrl", "https:///missing".into()),
        ("sourceUrl", "https://example.org\\@evil".into()),
        ("revision", "a".repeat(39)),
        ("revision", "A".repeat(40)),
        ("license", " ".into()),
        ("license", "a".repeat(1025)),
    ] {
        let mut v = value.clone();
        v["provenance"]["helper"][field] = json!(replacement);
        assert!(
            ArtifactSet::from_json(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut set = f.set.clone();
    set.provenance.get_mut("node").unwrap().revision = "d".repeat(40);
    assert!(set.validate().is_err());
    let mut set = f.set.clone();
    set.provenance.remove("chain");
    assert!(set.validate().is_err());
    let mut set = f.set.clone();
    set.artifacts.get_mut("zdn").unwrap().bytes = 0;
    assert!(set.validate().is_err());
    let mut v = value;
    v["unknown"] = json!(true);
    assert!(ArtifactSet::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(ArtifactSet::from_json(&vec![b' '; 2 * 1024 * 1024 + 1]).is_err());
}

#[test]
fn source_build_contract_is_bound_to_image() {
    use zdn::build::{BuildContract, BuildRecipe};
    let mut f = Fixture::new(false);
    f.set.node_image.provenance = ImageProvenance::Source {
        revision: "c".repeat(40),
        snapshot_sha256: "a".repeat(64),
    };
    f.set.build = Some(BuildContract {
        api_version: zdn::build::API_VERSION.into(),
        source_sha256: "a".repeat(64),
        source_bytes: 1,
        revision: "c".repeat(40),
        platform: "linux/amd64".into(),
        required_capabilities: ImageCapabilities::default(),
        recipe: BuildRecipe {
            dockerfile: "Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
        },
    });
    fs::write(
        f.dir.path().join("image.json"),
        serde_json::to_vec(&f.set.node_image).unwrap(),
    )
    .unwrap();
    f.repin("image.json");
    f.set.verify(f.dir.path()).unwrap();
    f.set.build.as_mut().unwrap().source_sha256 = "b".repeat(64);
    assert!(f.set.validate().is_err());
}

#[test]
fn semantic_config_and_chain_changes_cannot_be_hidden_by_repinning() {
    let mut f = Fixture::new(false);
    let mut chain: Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("manifest.json")).unwrap()).unwrap();
    chain["networkMagic"] = json!("11223344");
    fs::write(
        f.dir.path().join("manifest.json"),
        serde_json::to_vec(&chain).unwrap(),
    )
    .unwrap();
    f.repin("manifest.json");
    assert!(f
        .set
        .verify(f.dir.path())
        .unwrap_err()
        .to_string()
        .contains("consensus"));

    let mut f = Fixture::new(false);
    let mut config: Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("image-config.json")).unwrap()).unwrap();
    config["architecture"] = json!("arm64");
    let bytes = serde_json::to_vec(&config).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("image-manifest.json")).unwrap())
            .unwrap();
    manifest["config"]["digest"] = json!(digest(&bytes));
    manifest["config"]["size"] = json!(bytes.len());
    f.set.node_image.config_digest = digest(&bytes);
    fs::write(f.dir.path().join("image-config.json"), bytes).unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    f.set.node_image.image = format!("registry.example/zakura@{}", digest(&bytes));
    fs::write(f.dir.path().join("image-manifest.json"), bytes).unwrap();
    fs::write(
        f.dir.path().join("image.json"),
        serde_json::to_vec(&f.set.node_image).unwrap(),
    )
    .unwrap();
    for name in ["image.json", "image-manifest.json", "image-config.json"] {
        f.repin(name);
    }
    assert!(f.set.verify(f.dir.path()).is_err());
}

#[test]
fn rejects_invalid_sizes_hashes_and_optional_component_binding() {
    let f = Fixture::new(true);
    for name in artifact_limits(true).keys() {
        let mut set = f.set.clone();
        set.artifacts.get_mut(name).unwrap().bytes = artifact_limits(true)[name] + 1;
        assert!(set.validate().is_err(), "oversized {name}");
        let mut set = f.set.clone();
        set.artifacts.get_mut(name).unwrap().sha256 = "A".repeat(64);
        assert!(set.validate().is_err(), "hash {name}");
        let mut set = f.set.clone();
        set.artifacts.remove(name);
        assert!(set.validate().is_err(), "missing {name}");
    }
    let mut set = f.set.clone();
    set.provenance.get_mut("lightwallet").unwrap().revision = "d".repeat(40);
    assert!(set.validate().is_err());
    let mut set = f.set.clone();
    set.lightwallet_image.as_mut().unwrap().protocol_version = "future".into();
    assert!(set.validate().is_err());
    let mut set = f.set.clone();
    set.provenance
        .insert("extra".into(), set.provenance["helper"].clone());
    assert!(set.validate().is_err());
}

#[cfg(unix)]
#[test]
fn rejects_artifact_symlinks() {
    let f = Fixture::new(false);
    fs::rename(f.dir.path().join("zdn"), f.dir.path().join("other")).unwrap();
    std::os::unix::fs::symlink("other", f.dir.path().join("zdn")).unwrap();
    assert!(f.set.verify(f.dir.path()).is_err());
}
