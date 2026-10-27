//! Independent, tiny offline ECR fixtures; no builder or network is used.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zdn::{
    build::{BuildContract, BuildRecipe},
    build_export::{export_downloaded_config, PROTOCOL},
    image,
};

const REPOSITORY: &str = "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn-test";
const URL: &str = "https://example.invalid/config?token=SECRET";

struct ConfigDownload {
    bytes: Vec<u8>,
    calls: std::cell::Cell<usize>,
    fail: bool,
}

impl ConfigDownload {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            calls: Default::default(),
            fail: false,
        }
    }
}

impl zdn::dependencies::Downloader for ConfigDownload {
    fn download(&self, url: &str, file: &mut fs::File, limit: u64) -> eyre::Result<()> {
        use std::io::Write;
        self.calls.set(self.calls.get() + 1);
        assert_eq!(url, URL);
        assert_eq!(limit, image::MAX_CONFIG_BYTES as u64);
        file.write_all(&self.bytes)?;
        if self.fail {
            return Err(eyre::eyre!("transport leaked {url}"))
                .map_err(|e| e.wrap_err("underlying SECRET"));
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn contract() -> BuildContract {
    BuildContract {
        api_version: "zdn-build/v1alpha1".into(),
        source_sha256: "ab".repeat(32),
        source_bytes: 123,
        revision: "12".repeat(20),
        recipe: BuildRecipe {
            dockerfile: "docker/Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
        },
        platform: "linux/amd64".into(),
        required_capabilities: Default::default(),
    }
}

fn config() -> Vec<u8> {
    // Leading/trailing whitespace and Unicode deliberately exercise exact bytes.
    format!(
        " \n{}\n",
        json!({"architecture":"amd64", "os":"linux", "comment":"café",
            "config":{"Env":["HOME=/nonexistent"]},
            "rootfs":{"type":"layers", "diff_ids":[format!("sha256:{}", "34".repeat(32))]}})
    )
    .into_bytes()
}

fn registry(config: &[u8]) -> (Value, Vec<u8>) {
    let manifest = format!(
        "\n{} \n",
        json!({"schemaVersion":2, "mediaType":"application/vnd.docker.distribution.manifest.v2+json",
            "config":{"mediaType":"application/vnd.docker.container.image.v1+json",
                "digest":digest(config),"size":config.len()},
            "layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest":format!("sha256:{}", "56".repeat(32)),"size":3}]})
    ).into_bytes();
    (envelope(&manifest), manifest)
}

fn envelope(manifest: &[u8]) -> Value {
    json!({"failures":[],"images":[{"imageId":{"imageDigest":digest(manifest)},
        "imageManifest":std::str::from_utf8(manifest).unwrap()}]})
}

fn run(
    root: &Path,
    contract: &BuildContract,
    repo: &str,
    response: &Value,
    config: &[u8],
) -> eyre::Result<()> {
    fs::write(root.join("registry.json"), serde_json::to_vec(response)?)?;
    fs::write(
        root.join("download.json"),
        serde_json::to_vec(&json!({
            "downloadUrl":URL, "layerDigest":digest(config)
        }))?,
    )?;
    export_downloaded_config(
        contract,
        repo,
        &root.join("registry.json"),
        &root.join("download.json"),
        &root.join("output"),
        &ConfigDownload::new(config),
    )
}

#[test]
fn exact_bytes_result_binding_and_existing_output() {
    assert_eq!(PROTOCOL, "zdn-build-export/v1alpha2");
    let contract = contract();
    let config = config();
    let (response, manifest) = registry(&config);
    let expected = json!({
        "contractSha256":hex::encode(Sha256::digest(serde_json::to_vec(&contract).unwrap())),
        "image":{
            "apiVersion":"zdn-zakura-image/v1alpha1",
            "image":format!("{REPOSITORY}@{}", digest(&manifest)),
            "configDigest":digest(&config),
            "platform":"linux/amd64",
            "provenance":{"kind":"source", "revision":"12".repeat(20), "snapshotSha256":"ab".repeat(32)},
            "capabilities":{
                "ruleset":"zakura-configured-testnet/v1",
                "chainRulesApi":"zakura-chain-rules/v1",
                "blockInspectionApi":"zakura-block-inspection/v1",
                "runtimeAdapter":"zakura-runtime-toml/v1alpha1",
                "cookieAuth":true, "blockSubmission":true, "generateRpc":true
            },
            "binaryPath":"/usr/local/bin/zakurad",
            "environmentLauncher":"/usr/bin/env"
        }
    });
    let mut omitted = response.clone();
    omitted.as_object_mut().unwrap().remove("failures");
    let mut null = response.clone();
    null["failures"] = Value::Null;
    for response in [response, omitted, null] {
        let root = tempfile::tempdir().unwrap();
        run(root.path(), &contract, REPOSITORY, &response, &config).unwrap();
        let output = root.path().join("output");
        let result = fs::read(output.join("result.json")).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&result).unwrap(), expected);
        assert_eq!(
            fs::read(output.join("image-manifest.json")).unwrap(),
            manifest
        );
        assert_eq!(fs::read(output.join("image-config.json")).unwrap(), config);
        fs::write(output.join("sentinel"), b"preserve").unwrap();
        assert!(run(root.path(), &contract, REPOSITORY, &response, &config).is_err());
        assert_eq!(fs::read(output.join("result.json")).unwrap(), result);
        assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"preserve");
        assert_eq!(fs::read_dir(output).unwrap().count(), 4);
    }
    for symlink in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::write(&target, b"existing file").unwrap();
        if symlink {
            std::os::unix::fs::symlink(&target, root.path().join("output")).unwrap();
        } else {
            fs::write(root.path().join("output"), b"existing file").unwrap();
        }
        let (response, _) = registry(&config);
        assert!(run(root.path(), &contract, REPOSITORY, &response, &config).is_err());
        assert_eq!(
            fs::read(root.path().join("output")).unwrap(),
            b"existing file"
        );
        assert_eq!(fs::read(target).unwrap(), b"existing file");
    }
}

#[test]
fn downloaded_config_rejections() {
    let config = config();
    let (response, _) = registry(&config);
    for case in [
        "digest",
        "size",
        "empty",
        "oversized",
        "identity",
        "response",
        "response_size",
        "missing_url",
        "transport",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("registry.json"),
            serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
        let mut download = json!({"downloadUrl":URL, "layerDigest":digest(&config)});
        match case {
            "identity" => download["layerDigest"] = json!(digest(b"wrong")),
            "response" => download["downloadUrl"] = json!({"SECRET":"not a string"}),
            "missing_url" => download["downloadUrl"] = json!(""),
            _ => {}
        }
        fs::write(
            root.path().join("download.json"),
            serde_json::to_vec(&download).unwrap(),
        )
        .unwrap();
        if case == "response_size" {
            fs::write(root.path().join("download.json"), vec![b' '; 64 * 1024 + 1]).unwrap();
        }
        let mut downloader = ConfigDownload::new(&config);
        match case {
            "digest" => downloader.bytes[0] = b'\t',
            "size" => downloader.bytes.push(b' '),
            "empty" => downloader.bytes.clear(),
            "oversized" => downloader.bytes.resize(image::MAX_CONFIG_BYTES + 1, b' '),
            "transport" => downloader.fail = true,
            _ => {}
        }
        let error = export_downloaded_config(
            &contract(),
            REPOSITORY,
            &root.path().join("registry.json"),
            &root.path().join("download.json"),
            &root.path().join("output"),
            &downloader,
        )
        .unwrap_err();
        assert!(!root.path().join("output").exists(), "{case}");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
        if matches!(
            case,
            "identity" | "response" | "response_size" | "missing_url"
        ) {
            assert_eq!(downloader.calls.get(), 0, "{case}");
        } else {
            assert_eq!(downloader.calls.get(), 1, "{case}");
        }
        if case == "transport" {
            assert_eq!(error.to_string(), "configuration download failed");
            assert_eq!(error.chain().count(), 1);
        }
        assert!(!format!("{error:?}").contains("SECRET"));
        assert!(!format!("{error:?}").contains("example.invalid"));
    }
}

#[test]
fn invalid_inputs_never_publish() {
    let contract = contract();
    let config = config();
    let (response, manifest) = registry(&config);
    let mut responses = Vec::new();
    for failures in [
        json!([{"failureCode":"MissingImage"}]),
        json!({"malformed":true}),
    ] {
        let mut bad = response.clone();
        bad["failures"] = failures;
        responses.push(bad);
    }
    for images in [
        Value::Null,
        json!([]),
        json!([response["images"][0].clone(), response["images"][0].clone()]),
    ] {
        let mut bad = response.clone();
        bad["images"] = images;
        responses.push(bad);
    }
    let mut bad = response.clone();
    bad["images"][0]["imageId"]["imageDigest"] = json!(digest(b"wrong"));
    responses.push(bad);
    for manifest in [
        Vec::new(),
        b"not json".to_vec(),
        vec![b'x'; image::MAX_MANIFEST_BYTES + 1],
    ] {
        responses.push(envelope(&manifest));
    }
    let mut bad = response.clone();
    bad["padding"] = json!("x".repeat(6 * image::MAX_MANIFEST_BYTES + 64 * 1024));
    responses.push(bad);
    for (field, value) in [
        ("digest", json!("sha256:bad")),
        ("size", json!(0)),
        ("mediaType", json!("unsupported")),
    ] {
        let mut bad: Value = serde_json::from_slice(&manifest).unwrap();
        bad["config"][field] = value;
        responses.push(envelope(&serde_json::to_vec(&bad).unwrap()));
    }
    for response in responses {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("registry.json"),
            serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
        fs::write(
            root.path().join("download.json"),
            serde_json::to_vec(&json!({"downloadUrl":URL, "layerDigest":digest(&config)})).unwrap(),
        )
        .unwrap();
        let downloader = ConfigDownload::new(&config);
        assert!(export_downloaded_config(
            &contract,
            REPOSITORY,
            &root.path().join("registry.json"),
            &root.path().join("download.json"),
            &root.path().join("output"),
            &downloader
        )
        .is_err());
        assert_eq!(downloader.calls.get(), 0);
        assert!(!root.path().join("output").exists());
    }
    // Digest-correct but unsupported platform/defaults still fail validation.
    let original: Value = serde_json::from_slice(&config).unwrap();
    let mut wrong_platform = original.clone();
    wrong_platform["architecture"] = json!("arm64");
    let mut wrong_defaults = original;
    wrong_defaults["config"]["Env"] = json!(["SECRET=bad"]);
    for config in [
        b"not json".to_vec(),
        serde_json::to_vec(&wrong_platform).unwrap(),
        serde_json::to_vec(&wrong_defaults).unwrap(),
    ] {
        let (response, _) = registry(&config);
        let root = tempfile::tempdir().unwrap();
        assert!(run(root.path(), &contract, REPOSITORY, &response, &config).is_err());
        assert!(!root.path().join("output").exists());
    }
    for repo in [
        "repo",
        "localhost/image:tag",
        "localhost/image@sha256:bad",
        "localhost/image;bad",
    ] {
        let root = tempfile::tempdir().unwrap();
        assert!(run(root.path(), &contract, repo, &response, &config).is_err());
        assert!(!root.path().join("output").exists());
    }
    let mut bad_contract = contract;
    bad_contract.recipe.target = "other".into();
    let root = tempfile::tempdir().unwrap();
    assert!(run(root.path(), &bad_contract, REPOSITORY, &response, &config).is_err());
    assert!(!root.path().join("output").exists());
}
