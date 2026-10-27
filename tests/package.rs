//! Tiny data-only fixtures; no executable, image, or chain is run.
use eyre::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{cell::Cell, collections::BTreeMap, fs, io::Write, path::PathBuf};
use zdn::package::{self, Location, Package};
use zdn::{
    artifact_set::{ArtifactSet, Compatibility, Provenance},
    dependencies::Downloader,
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hash(bytes))
}

struct Fixture {
    root: tempfile::TempDir,
    package: Package,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let block = b"synthetic genesis, not an encoded block";
        let mut chain: Value =
            serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
        chain["genesis"] = json!({"height":0,"hash":format!("{:064x}",1),"bytesSha256":hash(block),"bytesLength":block.len()});
        chain["seedBlocks"] = json!([]);
        chain["checkpoints"] = json!([{"height":0,"hash":format!("{:064x}",1)}]);
        let chain: zdn::chain::manifest::ConsensusManifest = serde_json::from_value(chain).unwrap();
        let blocks = root.path().join("blocks");
        fs::create_dir(&blocks).unwrap();
        fs::write(blocks.join("0000000000.bin"), block).unwrap();
        let bundle = root.path().join("chain-bundle.tar");
        zdn::chain::artifacts::import_bundle(&chain, &blocks, &bundle).unwrap();
        let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux",
            "config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["zakurad"],"Cmd":[],"Volumes":null,"OnBuild":null},
            "rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","a".repeat(64))]}})).unwrap();
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config),"size":config.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":123}]})).unwrap();
        let image = ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: format!("ghcr.io/example/zakura@{}", digest(&manifest)),
            config_digest: digest(&config),
            platform: "linux/amd64".into(),
            provenance: ImageProvenance::Release {
                revision: "c".repeat(40),
                version: "v0.0.1".into(),
            },
            capabilities: ImageCapabilities::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
        };
        let mut helper = vec![0; 64];
        helper[..4].copy_from_slice(b"\x7fELF");
        helper[4] = 2;
        helper[5] = 1;
        helper[16..18].copy_from_slice(&2_u16.to_le_bytes());
        helper[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let files = BTreeMap::from([
            (
                "manifest.json".to_string(),
                serde_json::to_vec(&chain).unwrap(),
            ),
            ("chain.tar".into(), fs::read(bundle).unwrap()),
            ("image.json".into(), serde_json::to_vec(&image).unwrap()),
            ("image-manifest.json".into(), manifest),
            ("image-config.json".into(), config),
            ("zdn".into(), helper),
        ]);
        let artifacts = files
            .iter()
            .map(|(name, bytes)| {
                fs::write(root.path().join(name), bytes).unwrap();
                (
                    name.clone(),
                    zdn::devnet::Artifact {
                        sha256: hash(bytes),
                        bytes: bytes.len() as u64,
                    },
                )
            })
            .collect();
        let provenance = ["chain", "node", "helper"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    Provenance {
                        source_url: "https://example.invalid/source".into(),
                        revision: if name == "node" {
                            "c".repeat(40)
                        } else {
                            "d".repeat(40)
                        },
                        license: "MIT".into(),
                    },
                )
            })
            .collect();
        let artifact_set = ArtifactSet {
            api_version: zdn::artifact_set::API_VERSION.into(),
            platform: "linux/amd64".into(),
            consensus_fingerprint: chain.fingerprint().unwrap(),
            node_image: image,
            build: None,
            lightwallet_image: None,
            compatibility: Compatibility::current(false),
            provenance,
            artifacts,
        };
        let sources = files
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    Location::File {
                        path: PathBuf::from(name),
                    },
                )
            })
            .collect();
        Self {
            root,
            package: Package {
                api_version: package::API_VERSION.into(),
                artifact_set,
                sources,
            },
        }
    }
    fn save(&self) -> (PathBuf, String) {
        let bytes = serde_json::to_vec(&self.package).unwrap();
        let path = self.root.path().join("package.json");
        fs::write(&path, &bytes).unwrap();
        (path, hash(&bytes))
    }
    fn resolve(&self, overrides: &BTreeMap<String, PathBuf>) -> Result<package::ResolvedPackage> {
        let (path, pin) = self.save();
        package::resolve(&path, &pin, overrides)
    }
}

struct Scripted {
    calls: Cell<usize>,
    bytes: Vec<u8>,
    fail: bool,
}
impl Downloader for Scripted {
    fn download(&self, _: &str, out: &mut fs::File, _: u64) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        out.write_all(&self.bytes)?;
        eyre::ensure!(!self.fail, "scripted download failure");
        Ok(())
    }
}

#[test]
fn valid_local_package_is_verified_and_owned_storage_is_deleted() {
    let fixture = Fixture::new();
    let resolved = fixture.resolve(&BTreeMap::new()).unwrap();
    resolved.artifact_set.verify(resolved.directory()).unwrap();
    let path = resolved.directory().to_path_buf();
    drop(resolved);
    assert!(!path.exists());
}

#[test]
fn machine_verification_reports_integrity_not_execution_and_sanitizes_failures() {
    for format in ["json", "jsonl"] {
        let fixture = Fixture::new();
        let (manifest, pin) = fixture.save();
        let run = || {
            std::process::Command::new(env!("CARGO_BIN_EXE_zdn"))
                .env_clear()
                .env("PATH", "")
                .current_dir(fixture.root.path())
                .args(["--format", format, "package", "verify", "--manifest"])
                .arg(&manifest)
                .args(["--sha256", &pin])
                .output()
                .unwrap()
        };
        for tampered in [false, true] {
            if tampered {
                fs::write(fixture.root.path().join("zdn"), b"SECRET bad artifact").unwrap();
            }
            let output = run();
            assert_eq!(output.status.success(), !tampered);
            assert!(output.stderr.is_empty());
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(!text.contains("SECRET"));
            let records: Vec<Value> = if format == "json" {
                vec![serde_json::from_str(&text).unwrap()]
            } else {
                text.lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect()
            };
            assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
            if format == "jsonl" {
                assert_eq!(records[0]["type"], "command-started");
            }
            let record = records.last().unwrap();
            assert_eq!(record["apiVersion"], "zdn-cli/v1alpha1");
            assert_eq!(record["type"], "result");
            assert_eq!(record["command"], "package verify");
            assert!(record["networkId"].is_null());
            assert!(record["operationId"].is_null());
            if tampered {
                assert_eq!(record["outcome"], "failed");
                assert_eq!(record["error"]["code"], "package-verification-failed");
                assert_eq!(record["error"]["retryClassification"], "blocked");
                assert!(record["data"].is_null());
            } else {
                assert_eq!(record["outcome"], "succeeded");
                assert!(record["error"].is_null());
                let data = &record["data"];
                assert_eq!(data["packageSha256"], pin);
                assert_eq!(
                    data["artifactSet"],
                    serde_json::to_value(&fixture.package.artifact_set).unwrap()
                );
                assert_eq!(data["byteIntegrityVerified"], true);
                assert_eq!(data["compatibilityDeclarationsMatched"], true);
                for key in [
                    "artifactExecutionVerified",
                    "publisherAuthenticated",
                    "launchReady",
                ] {
                    assert_eq!(data[key], false);
                }
                assert_eq!(data["qualification"], "pending");
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn resolved_storage_is_private_under_permissive_umasks() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    const WORKER: &str = "ZDN_PACKAGE_UMASK";
    if let Ok(mask) = std::env::var(WORKER) {
        // umask is process-wide, so only change it in this isolated test process.
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(
            nix::libc::mode_t::from_str_radix(&mask, 8).unwrap(),
        ));
        let fixture = Fixture::new();
        let resolved = fixture.resolve(&BTreeMap::new()).unwrap();
        assert_eq!(
            fs::metadata(resolved.directory())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for name in resolved.artifact_set.artifacts.keys() {
            assert_eq!(
                fs::metadata(resolved.directory().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        return;
    }
    for mask in ["000", "002", "022"] {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "resolved_storage_is_private_under_permissive_umasks",
                "--nocapture",
            ])
            .env(WORKER, mask)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "umask {mask}: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn pin_precedes_decoding_and_any_download() {
    let fixture = Fixture::new();
    let (path, _) = fixture.save();
    fs::write(&path, b"not JSON").unwrap();
    let downloader = Scripted {
        calls: Cell::new(0),
        bytes: vec![],
        fail: false,
    };
    let error =
        package::resolve_with_downloader(&path, &"0".repeat(64), &BTreeMap::new(), &downloader)
            .unwrap_err();
    assert!(error.to_string().contains("package SHA-256 mismatch"));
    assert_eq!(downloader.calls.get(), 0);
}

#[test]
fn inventory_is_exact_even_with_overrides() {
    for extra in [false, true] {
        let mut fixture = Fixture::new();
        if extra {
            fixture.package.sources.insert(
                "extra".into(),
                Location::File {
                    path: "extra".into(),
                },
            );
        } else {
            fixture.package.sources.remove("zdn");
        }
        let overrides = BTreeMap::from([("zdn".into(), fixture.root.path().join("zdn"))]);
        assert!(fixture
            .resolve(&overrides)
            .unwrap_err()
            .to_string()
            .contains("inventory"));
    }
    let fixture = Fixture::new();
    assert!(fixture
        .resolve(&BTreeMap::from([("unknown".into(), "anything".into())]))
        .unwrap_err()
        .to_string()
        .contains("unknown"));
}

#[test]
fn unsafe_paths_and_symlink_components_are_rejected() {
    for path in [
        "../zdn",
        "/tmp/zdn",
        "./zdn",
        "blocks/../zdn",
        "blocks//zdn",
        "blocks\\zdn",
        "",
    ] {
        let mut fixture = Fixture::new();
        fixture
            .package
            .sources
            .insert("zdn".into(), Location::File { path: path.into() });
        assert!(fixture.resolve(&BTreeMap::new()).is_err(), "{path}");
    }
    #[cfg(unix)]
    for directory in [false, true] {
        let mut fixture = Fixture::new();
        let target = if directory {
            fixture.root.path().to_path_buf()
        } else {
            fixture.root.path().join("zdn")
        };
        std::os::unix::fs::symlink(target, fixture.root.path().join("link")).unwrap();
        fixture.package.sources.insert(
            "zdn".into(),
            Location::File {
                path: if directory { "link/zdn" } else { "link" }.into(),
            },
        );
        assert!(fixture.resolve(&BTreeMap::new()).is_err());
    }
}

#[test]
fn overrides_are_pinned_regular_files_not_alternate_semantics() {
    let fixture = Fixture::new();
    let elsewhere = tempfile::tempdir().unwrap();
    let path = elsewhere.path().join("helper");
    fs::copy(fixture.root.path().join("zdn"), &path).unwrap();
    let overrides = BTreeMap::from([("zdn".into(), path.clone())]);
    fixture.resolve(&overrides).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes[63] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(fixture
        .resolve(&overrides)
        .unwrap_err()
        .to_string()
        .contains("SHA-256"));
    fs::write(&path, b"short").unwrap();
    assert!(fixture
        .resolve(&overrides)
        .unwrap_err()
        .to_string()
        .contains("size"));
    fs::write(&path, vec![0; 65]).unwrap();
    assert!(fixture
        .resolve(&overrides)
        .unwrap_err()
        .to_string()
        .contains("size"));
}

#[test]
fn download_failures_partial_size_and_digest_errors_are_rejected() {
    for (bytes, fail) in [
        (vec![0; 64], true),
        (vec![0; 63], false),
        (vec![0; 65], false),
        (vec![0; 64], false),
    ] {
        let mut fixture = Fixture::new();
        fixture.package.sources.insert(
            "zdn".into(),
            Location::Https {
                url: "https://example.invalid/zdn".into(),
            },
        );
        let (path, pin) = fixture.save();
        let downloader = Scripted {
            calls: Cell::new(0),
            bytes,
            fail,
        };
        assert!(
            package::resolve_with_downloader(&path, &pin, &BTreeMap::new(), &downloader).is_err()
        );
        assert_eq!(downloader.calls.get(), 1);
    }
}

#[test]
fn url_policy_and_strict_schemas() {
    for url in [
        "http://example.invalid/zdn",
        "http://127.0.0.1:1234/zdn",
        "https://user:secret@example.invalid/zdn",
        "https://example.invalid/zdn#fragment",
        "https://",
        "https://example.invalid/\nzdn",
    ] {
        let mut fixture = Fixture::new();
        fixture
            .package
            .sources
            .insert("zdn".into(), Location::Https { url: url.into() });
        let overrides = BTreeMap::from([("zdn".into(), fixture.root.path().join("zdn"))]);
        assert!(fixture.resolve(&overrides).is_err(), "{url}");
    }
    assert!(
        serde_json::from_value::<Location>(json!({"kind":"file","path":"zdn","extra":true}))
            .is_err()
    );
    let fixture = Fixture::new();
    let mut value = serde_json::to_value(&fixture.package).unwrap();
    value["extra"] = json!(true);
    assert!(serde_json::from_value::<Package>(value).is_err());
}

#[test]
fn loopback_http_requires_explicit_injection_and_verifies_real_download() {
    use std::{io::Read, net::TcpListener};
    let mut fixture = Fixture::new();
    let bytes = fs::read(fixture.root.path().join("zdn")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/zdn", listener.local_addr().unwrap());
    fixture
        .package
        .sources
        .insert("zdn".into(), Location::Https { url });
    assert!(fixture.resolve(&BTreeMap::new()).is_err());
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).unwrap() > 0);
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .unwrap();
        socket.write_all(&bytes).unwrap();
    });
    let (path, pin) = fixture.save();
    let result = package::resolve_with_downloader(
        &path,
        &pin,
        &BTreeMap::new(),
        &zdn::dependencies::HttpDownloader::for_loopback_tests(),
    );
    server.join().unwrap();
    result.unwrap();
}

#[test]
fn pinned_bytes_still_require_semantic_verification_and_manifest_is_bounded() {
    let mut fixture = Fixture::new();
    let bytes = vec![0; 64];
    fs::write(fixture.root.path().join("zdn"), &bytes).unwrap();
    fixture
        .package
        .artifact_set
        .artifacts
        .get_mut("zdn")
        .unwrap()
        .sha256 = hash(&bytes);
    assert!(fixture
        .resolve(&BTreeMap::new())
        .unwrap_err()
        .to_string()
        .contains("ELF"));
    let (path, _) = fixture.save();
    let bytes = vec![b' '; zdn::artifact_set::MAX_MANIFEST_BYTES as usize + 1];
    fs::write(&path, &bytes).unwrap();
    assert!(package::resolve(&path, &hash(&bytes), &BTreeMap::new())
        .unwrap_err()
        .to_string()
        .contains("size limit"));
}

fn signed_release(location: Location, sha256: String) -> zdn::releases::VerifiedCatalog {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use zdn::releases::{self, Catalog, PinnedPackage};
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let catalog = Catalog {
        api_version: releases::API_VERSION.into(),
        releases: BTreeMap::from([(
            "candidate_2026-10-19".into(),
            PinnedPackage { location, sha256 },
        )]),
    };
    let bytes = serde_json::to_vec(&catalog).unwrap();
    let signature = releases::sign(&bytes, &key).unwrap();
    releases::verify(&bytes, &signature, &[public]).unwrap()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn export_is_relocatable_data_only_and_preserves_artifact_set_and_provenance() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let source = fixture.resolve(&BTreeMap::new()).unwrap();
    let expected = serde_json::to_value(&source.artifact_set).unwrap();
    let storage = tempfile::tempdir().unwrap();
    let exported = package::export(
        source.directory(),
        &source.artifact_set,
        &storage.path().join("release"),
    )
    .unwrap();
    assert_eq!(
        hash(&fs::read(&exported.manifest).unwrap()),
        exported.sha256
    );
    let saved: Package = serde_json::from_slice(&fs::read(&exported.manifest).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&saved.artifact_set).unwrap(), expected);
    assert_eq!(
        fs::read_dir(exported.manifest.parent().unwrap())
            .unwrap()
            .count(),
        saved.artifact_set.artifacts.len() + 1
    );
    for entry in fs::read_dir(exported.manifest.parent().unwrap()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(source);
    drop(fixture);
    let relocated = storage.path().join("relocated");
    fs::rename(storage.path().join("release"), &relocated).unwrap();
    for (target, link, package_path) in [
        (
            "relocated",
            "linked-directory",
            "linked-directory/package.json",
        ),
        (
            "relocated/package.json",
            "linked-manifest",
            "linked-manifest",
        ),
    ] {
        std::os::unix::fs::symlink(target, storage.path().join(link)).unwrap();
        let catalog = signed_release(
            Location::File {
                path: package_path.into(),
            },
            exported.sha256.clone(),
        );
        assert!(catalog
            .resolve("candidate_2026-10-19", storage.path(), &BTreeMap::new())
            .is_err());
    }
    let catalog = signed_release(
        Location::File {
            path: "relocated/package.json".into(),
        },
        exported.sha256,
    );
    let resolved = catalog
        .resolve("candidate_2026-10-19", storage.path(), &BTreeMap::new())
        .unwrap();
    assert_eq!(
        serde_json::to_value(&resolved.artifact_set).unwrap(),
        expected
    );
    assert!(catalog
        .resolve("latest", storage.path(), &BTreeMap::new())
        .is_err());
    assert!(catalog
        .resolve("candidate_2026-10-20", storage.path(), &BTreeMap::new())
        .unwrap_err()
        .to_string()
        .contains("not in catalog"));
    // Catalog signatures do not substitute for the package raw pin.
    fs::write(relocated.join("package.json"), b"not JSON").unwrap();
    assert!(catalog
        .resolve("candidate_2026-10-19", storage.path(), &BTreeMap::new())
        .unwrap_err()
        .to_string()
        .contains("SHA-256 mismatch"));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn export_never_overwrites_and_rejects_semantically_invalid_data_without_partial_output() {
    let mut fixture = Fixture::new();
    let storage = tempfile::tempdir().unwrap();
    for kind in ["empty-directory", "file", "symlink"] {
        let destination = storage.path().join(kind);
        match kind {
            "empty-directory" => fs::create_dir(&destination).unwrap(),
            "file" => fs::write(&destination, b"keep me").unwrap(),
            _ => std::os::unix::fs::symlink("absent", &destination).unwrap(),
        }
        assert!(package::export(
            fixture.root.path(),
            &fixture.package.artifact_set,
            &destination
        )
        .is_err());
        match kind {
            "empty-directory" => assert_eq!(fs::read_dir(&destination).unwrap().count(), 0),
            "file" => assert_eq!(fs::read(&destination).unwrap(), b"keep me"),
            _ => assert_eq!(
                fs::read_link(&destination).unwrap(),
                PathBuf::from("absent")
            ),
        }
    }
    assert_eq!(fs::read_dir(storage.path()).unwrap().count(), 3);
    // A freshly pinned but semantically invalid helper must still be rejected.
    let bytes = vec![0; 64];
    fs::write(fixture.root.path().join("zdn"), &bytes).unwrap();
    fixture
        .package
        .artifact_set
        .artifacts
        .get_mut("zdn")
        .unwrap()
        .sha256 = hash(&bytes);
    let destination = storage.path().join("invalid");
    assert!(package::export(
        fixture.root.path(),
        &fixture.package.artifact_set,
        &destination
    )
    .unwrap_err()
    .to_string()
    .contains("ELF"));
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(storage.path()).unwrap().count(), 3);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn competing_exports_publish_exactly_one_complete_package() {
    let mut fixtures = [Fixture::new(), Fixture::new()];
    for (index, fixture) in fixtures.iter_mut().enumerate() {
        fixture
            .package
            .artifact_set
            .provenance
            .get_mut("helper")
            .unwrap()
            .revision = format!("{:040x}", index + 1);
    }
    let storage = tempfile::tempdir().unwrap();
    let destination = storage.path().join("winner");
    let start = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = fixtures
            .iter()
            .map(|fixture| {
                scope.spawn(|| {
                    start.wait();
                    package::export(
                        fixture.root.path(),
                        &fixture.package.artifact_set,
                        &destination,
                    )
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let (winner, exported) = results
        .iter()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().ok().map(|exported| (index, exported)))
        .unwrap();
    let resolved =
        package::resolve(&exported.manifest, &exported.sha256, &BTreeMap::new()).unwrap();
    assert_eq!(
        serde_json::to_value(&resolved.artifact_set).unwrap(),
        serde_json::to_value(&fixtures[winner].package.artifact_set).unwrap()
    );
    assert_eq!(fs::read_dir(storage.path()).unwrap().count(), 1);
}

#[test]
fn release_https_resolution_verifies_manifest_before_fetching_artifacts_and_semantics_after() {
    use std::cell::RefCell;
    struct Downloads {
        bytes: BTreeMap<String, Vec<u8>>,
        calls: RefCell<Vec<String>>,
    }
    impl Downloader for Downloads {
        fn download(&self, url: &str, out: &mut fs::File, _: u64) -> Result<()> {
            self.calls.borrow_mut().push(url.into());
            out.write_all(self.bytes.get(url).expect("unexpected fixture URL"))?;
            Ok(())
        }
    }
    let mut fixture = Fixture::new();
    let package_url = "https://example.invalid/package.json";
    let mut downloader = Downloads {
        bytes: BTreeMap::new(),
        calls: RefCell::new(vec![]),
    };
    for (name, location) in &mut fixture.package.sources {
        let url = format!("https://example.invalid/{name}");
        downloader.bytes.insert(
            url.clone(),
            fs::read(fixture.root.path().join(name)).unwrap(),
        );
        *location = Location::Https { url };
    }
    let manifest = serde_json::to_vec(&fixture.package).unwrap();
    downloader
        .bytes
        .insert(package_url.into(), manifest.clone());
    let catalog = signed_release(
        Location::Https {
            url: package_url.into(),
        },
        hash(&manifest),
    );
    let resolved = catalog
        .resolve_with_downloader(
            "candidate_2026-10-19",
            fixture.root.path(),
            &BTreeMap::new(),
            &downloader,
        )
        .unwrap();
    assert_eq!(
        resolved.artifact_set.fingerprint().unwrap(),
        fixture.package.artifact_set.fingerprint().unwrap()
    );
    assert_eq!(
        downloader.calls.borrow().len(),
        fixture.package.artifact_set.artifacts.len() + 1
    );
    downloader.calls.borrow_mut().clear();
    downloader
        .bytes
        .insert(package_url.into(), b"not JSON".to_vec());
    assert!(catalog
        .resolve_with_downloader(
            "candidate_2026-10-19",
            fixture.root.path(),
            &BTreeMap::new(),
            &downloader
        )
        .unwrap_err()
        .to_string()
        .contains("SHA-256 mismatch"));
    assert_eq!(*downloader.calls.borrow(), vec![package_url]);
    // Even a signed catalog and matching package/artifact pins cannot qualify a
    // malformed artifact as valid deployment data.
    let invalid = vec![0; 64];
    fixture
        .package
        .artifact_set
        .artifacts
        .get_mut("zdn")
        .unwrap()
        .sha256 = hash(&invalid);
    downloader
        .bytes
        .insert("https://example.invalid/zdn".into(), invalid);
    let manifest = serde_json::to_vec(&fixture.package).unwrap();
    downloader
        .bytes
        .insert(package_url.into(), manifest.clone());
    let catalog = signed_release(
        Location::Https {
            url: package_url.into(),
        },
        hash(&manifest),
    );
    assert!(catalog
        .resolve_with_downloader(
            "candidate_2026-10-19",
            fixture.root.path(),
            &BTreeMap::new(),
            &downloader
        )
        .unwrap_err()
        .to_string()
        .contains("ELF"));
}

#[test]
fn release_package_manifest_downloads_are_bounded_even_for_injected_downloaders() {
    let base = tempfile::tempdir().unwrap();
    for (bytes, fail, expected) in [
        (
            vec![b' '; zdn::artifact_set::MAX_MANIFEST_BYTES as usize + 1],
            false,
            "size limit",
        ),
        (b"partial".to_vec(), true, "scripted download failure"),
    ] {
        let catalog = signed_release(
            Location::Https {
                url: "https://example.invalid/package.json".into(),
            },
            hash(&bytes),
        );
        let downloader = Scripted {
            calls: Cell::new(0),
            bytes,
            fail,
        };
        assert!(catalog
            .resolve_with_downloader(
                "candidate_2026-10-19",
                base.path(),
                &BTreeMap::new(),
                &downloader
            )
            .unwrap_err()
            .to_string()
            .contains(expected));
        assert_eq!(downloader.calls.get(), 1);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cli_exports_signs_and_resolves_relocatable_packages_with_explicit_trust() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::process::Command;
    for format in ["human", "json", "jsonl"] {
        let fixture = Fixture::new();
        let (manifest, pin) = fixture.save();
        let storage = tempfile::tempdir().unwrap();
        let run = |args: &[&str], success: bool| {
            let output = Command::new(env!("CARGO_BIN_EXE_zdn"))
                .env_clear()
                .env("PATH", "")
                .current_dir(storage.path())
                .args(["--format", format])
                .args(args)
                .output()
                .unwrap();
            assert_eq!(output.status.success(), success, "{output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            if format == "human" {
                if !success {
                    return Value::Null;
                }
                serde_json::from_str::<Value>(&text).unwrap()
            } else {
                assert!(output.stderr.is_empty());
                assert!(!text.contains("SECRET"));
                let records: Vec<Value> = if format == "json" {
                    vec![serde_json::from_str(&text).unwrap()]
                } else {
                    text.lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect()
                };
                assert_eq!(records.len(), if format == "jsonl" { 2 } else { 1 });
                let record = records.last().unwrap();
                assert!(record["networkId"].is_null());
                assert!(record["operationId"].is_null());
                if success {
                    assert_eq!(record["outcome"], "succeeded");
                    record["data"].clone()
                } else {
                    assert_eq!(record["outcome"], "failed");
                    assert!(record["data"].is_null());
                    assert_eq!(record["error"]["retryClassification"], "blocked");
                    record["error"].clone()
                }
            }
        };
        let export_args = [
            "package",
            "export",
            "--manifest",
            manifest.to_str().unwrap(),
            "--sha256",
            &pin,
            "--output",
            "exported",
        ];
        let exported = run(&export_args, true);
        assert_eq!(exported["publisherAuthenticated"], false);
        assert_eq!(exported["artifactExecutionVerified"], false);
        let expected = serde_json::to_value(&fixture.package.artifact_set).unwrap();
        drop(fixture);
        let bytes = serde_json::to_vec(&json!({"apiVersion":zdn::releases::API_VERSION,
            "releases":{"candidate_2026-10-19":{"location":{"kind":"file","path":"exported/package.json"},
                "sha256":exported["packageSha256"]}}})).unwrap();
        fs::write(storage.path().join("catalog.json"), &bytes).unwrap();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        fs::write(storage.path().join("SECRET-key.pk8"), pkcs8.as_ref()).unwrap();
        fs::write(
            storage.path().join("trusted.pub"),
            key.public_key().as_ref(),
        )
        .unwrap();
        let sign_args = [
            "release",
            "sign",
            "--catalog",
            "catalog.json",
            "--key",
            "SECRET-key.pk8",
            "--output",
            "catalog.sig",
        ];
        let signed = run(&sign_args, true);
        assert_eq!(signed["packagesVerified"], false);
        let signature = fs::read(storage.path().join("catalog.sig")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(storage.path().join("catalog.sig"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
        zdn::releases::verify(&bytes, &signature, &[public]).unwrap();
        // RFC 8032 test key in OpenSSL's PKCS#8 v1 encoding (no public key).
        // The public key is independently specified by the RFC, not the parser.
        let v1 = hex::decode(concat!(
            "302e020100300506032b657004220420",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ))
        .unwrap();
        fs::write(storage.path().join("SECRET-v1.pk8"), v1).unwrap();
        run(
            &[
                "release",
                "sign",
                "--catalog",
                "catalog.json",
                "--key",
                "SECRET-v1.pk8",
                "--output",
                "v1.sig",
            ],
            true,
        );
        let v1_public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        zdn::releases::verify(
            &bytes,
            &fs::read(storage.path().join("v1.sig")).unwrap(),
            &[v1_public],
        )
        .unwrap();
        let rejected = run(&sign_args, false);
        if format != "human" {
            assert_eq!(rejected["code"], "release-signing-failed");
        }
        assert_eq!(
            fs::read(storage.path().join("catalog.sig")).unwrap(),
            signature
        );
        let relocated = storage.path().join("relocated");
        fs::create_dir(&relocated).unwrap();
        for name in ["exported", "catalog.json", "catalog.sig", "trusted.pub"] {
            fs::rename(storage.path().join(name), relocated.join(name)).unwrap();
        }
        let verify_args = [
            "release",
            "verify",
            "--catalog",
            "relocated/catalog.json",
            "--signature",
            "relocated/catalog.sig",
            "--trusted-key",
            "relocated/trusted.pub",
        ];
        // Authenticating declarations must not access even a corrupt artifact.
        let helper = relocated.join("exported/zdn");
        let original = fs::read(&helper).unwrap();
        fs::write(&helper, b"SECRET tampered").unwrap();
        let verified = run(&verify_args, true);
        assert_eq!(verified["publisherAuthenticated"], true);
        assert_eq!(verified["packagesVerified"], false);
        fs::write(relocated.join("trusted.pub"), [0; 32]).unwrap();
        run(&verify_args, false);
        fs::write(relocated.join("trusted.pub"), public).unwrap();
        let resolve_args = [
            "release",
            "resolve",
            "--catalog",
            "relocated/catalog.json",
            "--signature",
            "relocated/catalog.sig",
            "--trusted-key",
            "relocated/trusted.pub",
            "--release",
            "candidate_2026-10-19",
            "--output",
            "selected",
        ];
        let rejected = run(&resolve_args, false);
        if format != "human" {
            assert_eq!(rejected["code"], "release-resolution-failed");
        }
        assert!(!storage.path().join("selected").exists());
        fs::write(&helper, original).unwrap();
        let resolved = run(&resolve_args, true);
        assert_eq!(resolved["publisherAuthenticated"], true);
        assert_eq!(resolved["catalogSha256"], hash(&bytes));
        assert_eq!(resolved["release"], "candidate_2026-10-19");
        assert_eq!(resolved["qualification"], "pending");
        assert_eq!(resolved["launchReady"], false);
        let selected = package::resolve(
            std::path::Path::new(resolved["manifest"].as_str().unwrap()),
            resolved["packageSha256"].as_str().unwrap(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&selected.artifact_set).unwrap(),
            expected
        );
        // Existing exports and signatures are never replaced, even with valid inputs.
        run(&resolve_args, false);
        let mut altered = bytes;
        altered.push(b'\n');
        fs::write(relocated.join("catalog.json"), altered).unwrap();
        let rejected = run(&verify_args, false);
        if format != "human" {
            assert_eq!(rejected["code"], "release-verification-failed");
        }
        assert_eq!(
            hash(&fs::read(storage.path().join("selected/package.json")).unwrap()),
            resolved["packageSha256"]
        );
    }
}
