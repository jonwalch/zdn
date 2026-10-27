//! These tiny payloads are deliberately not encoded Zcash blocks. Successful
//! checks attest byte integrity only, never block decoding or chain consensus.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, EntryType, Header};
use tempfile::{tempdir, TempDir};
use zdn::chain::artifacts::{block_file_name, import_bundle, verify_bundle};
use zdn::chain::manifest::ConsensusManifest;

const BASE: &str = include_str!("fixtures/chain-manifest/valid.json");
const PAYLOADS: [&[u8]; 3] = [
    b"synthetic genesis bytes; not a Zcash block\0",
    b"synthetic seed one bytes; not a Zcash block\0",
    b"synthetic seed two bytes; not a Zcash block\0",
];
// Captured from the initial v1alpha1 encoding on 2026-10-14. Python's stdlib
// tarfile/json checked the exact inventory, payloads, normalized metadata and
// headers, then hashlib computed this SHA-256. This pins format stability; it
// is not an independent archive-encoder vector or chain qualification evidence.
const BUNDLE_SHA256: &str = "d45666bed96208a91cd0419f5f50d4ccc00ef739af8bb4cf6c174ef5b35abf97";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn manifest_value(payloads: &[&[u8]]) -> Value {
    let mut value: Value = serde_json::from_str(BASE).unwrap();
    let identities: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(height, bytes)| {
            json!({
                "height": height,
                // An arbitrary declared chain hash. This is intentionally
                // unrelated to the raw byte digest, which is all we can check.
                "hash": format!("{:064x}", height + 1),
                "bytesSha256": sha256(bytes),
                "bytesLength": bytes.len(),
            })
        })
        .collect();
    value["genesis"] = identities[0].clone();
    value["seedBlocks"] = json!(&identities[1..]);
    value["checkpoints"] = json!([]);
    value
}

struct Fixture {
    root: TempDir,
    blocks: PathBuf,
    manifest: ConsensusManifest,
}

impl Fixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        let blocks = root.path().join("synthetic source blocks");
        fs::create_dir(&blocks).unwrap();
        for (height, bytes) in PAYLOADS.iter().enumerate() {
            // Independent spelling asserts the public source layout contract.
            fs::write(blocks.join(format!("{height:010}.bin")), bytes).unwrap();
        }
        Self {
            root,
            blocks,
            manifest: serde_json::from_value(manifest_value(&PAYLOADS)).unwrap(),
        }
    }

    fn output(&self) -> PathBuf {
        self.root.path().join("saved-chain.tar")
    }

    fn import(&self) -> PathBuf {
        let output = self.output();
        import_bundle(&self.manifest, &self.blocks, &output).unwrap();
        output
    }
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[derive(Clone)]
struct Entry {
    header: Header,
    data: Vec<u8>,
}

impl Entry {
    fn path(&self) -> String {
        self.header.path().unwrap().to_string_lossy().into_owned()
    }

    fn set_path(&mut self, path: &str) {
        assert!(path.len() < 100);
        // Write the raw field so tar's safe-path builder does not sanitize the
        // hostile path before the product verifier receives it.
        let bytes = self.header.as_mut_bytes();
        bytes[..100].fill(0);
        bytes[..path.len()].copy_from_slice(path.as_bytes());
        self.header.set_cksum();
    }

    fn replace_data(&mut self, data: Vec<u8>) {
        self.header.set_size(data.len() as u64);
        self.header.set_cksum();
        self.data = data;
    }

    fn make_link(&mut self, kind: EntryType) {
        self.replace_data(Vec::new());
        self.header.set_entry_type(kind);
        self.header.set_link_name("../outside-sentinel").unwrap();
        self.header.set_cksum();
    }
}

fn read_entries(bytes: &[u8]) -> Vec<Entry> {
    let mut archive = Archive::new(Cursor::new(bytes));
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let header = entry.header().clone();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            Entry { header, data }
        })
        .collect()
}

fn archive_bytes(entries: &[Entry]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for entry in entries {
        builder
            .append(&entry.header, Cursor::new(&entry.data))
            .unwrap();
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn assert_rejected_archive(fixture: &Fixture, bytes: &[u8], case: &str) {
    let output = fixture.root.path().join("modified.tar");
    fs::write(&output, bytes).unwrap();
    assert!(
        verify_bundle(&fixture.manifest, &output).is_err(),
        "accepted {case}"
    );
    assert_eq!(fs::read(&output).unwrap(), bytes, "rewrote {case}");
}

#[test]
fn successful_import_and_verification_only_claim_exact_byte_integrity() {
    let fixture = Fixture::new();
    let output = fixture.output();
    let imported = import_bundle(&fixture.manifest, &fixture.blocks, &output).unwrap();
    let bytes = fs::read(&output).unwrap();
    let report = serde_json::to_value(imported).unwrap();
    assert_eq!(report["apiVersion"], "zdn-chain-artifact-check/v1alpha1");
    assert_eq!(
        report["consensusFingerprint"],
        fixture.manifest.fingerprint().unwrap()
    );
    assert_eq!(report["bundleSha256"], sha256(&bytes));
    assert_eq!(sha256(&bytes), BUNDLE_SHA256);
    assert_eq!(report["bundleBytes"], bytes.len());
    assert_eq!(report["blockCount"], 3);
    assert_eq!(
        report["blockBytes"],
        PAYLOADS.iter().map(|bytes| bytes.len()).sum::<usize>()
    );
    assert_eq!(report["byteIntegrityVerified"], true);
    assert_eq!(report["blockDecodingVerified"], false);
    assert_eq!(report["consensusVerified"], false);
    assert_eq!(report["qualification"], "pending");
    assert_eq!(report["launchReady"], false);
    let verified = verify_bundle(&fixture.manifest, &output).unwrap();
    assert_eq!(serde_json::to_value(verified).unwrap(), report);

    let entries = read_entries(&bytes);
    assert_eq!(
        entries.iter().map(Entry::path).collect::<Vec<_>>(),
        [
            "bundle.json",
            "blocks/0000000000.bin",
            "blocks/0000000001.bin",
            "blocks/0000000002.bin"
        ]
    );
    let metadata: Value = serde_json::from_slice(&entries[0].data).unwrap();
    assert_eq!(metadata["apiVersion"], "zdn-chain-bundle/v1alpha1");
    assert_eq!(
        metadata["consensusFingerprint"],
        report["consensusFingerprint"]
    );
    assert_eq!(
        metadata["manifest"],
        serde_json::to_value(fixture.manifest.normalized().unwrap()).unwrap()
    );
    for (entry, expected) in entries[1..].iter().zip(PAYLOADS) {
        assert_eq!(entry.data, expected);
        assert_eq!(entry.header.entry_type(), EntryType::Regular);
    }
    assert_eq!(archive_bytes(&entries), bytes);
}

#[test]
fn filenames_use_fixed_width_heights() {
    assert_eq!(block_file_name(0), "0000000000.bin");
    assert_eq!(block_file_name(42), "0000000042.bin");
    assert_eq!(block_file_name(u32::MAX), "4294967295.bin");
}

#[test]
fn bundles_are_deterministic_across_paths_case_and_seed_order() {
    let first = Fixture::new();
    let second = Fixture::new();
    let first_output = first.import();
    let mut value = manifest_value(&PAYLOADS);
    value["networkMagic"] = json!(value["networkMagic"].as_str().unwrap().to_uppercase());
    value["genesis"]["bytesSha256"] = json!(value["genesis"]["bytesSha256"]
        .as_str()
        .unwrap()
        .to_uppercase());
    for identity in value["seedBlocks"].as_array_mut().unwrap() {
        identity["bytesSha256"] = json!(identity["bytesSha256"].as_str().unwrap().to_uppercase());
    }
    value["seedBlocks"].as_array_mut().unwrap().reverse();
    let equivalent: ConsensusManifest = serde_json::from_value(value).unwrap();
    let second_output = second.output();
    import_bundle(&equivalent, &second.blocks, &second_output).unwrap();
    assert_eq!(
        fs::read(&first_output).unwrap(),
        fs::read(&second_output).unwrap()
    );
    assert!(verify_bundle(&equivalent, &first_output).is_ok());
    assert!(verify_bundle(&first.manifest, &second_output).is_ok());
}

#[test]
fn unrelated_source_files_and_an_output_in_the_source_directory_are_ignored() {
    let fixture = Fixture::new();
    fs::write(fixture.blocks.join("README"), "not part of the chain").unwrap();
    fs::create_dir(fixture.blocks.join("unrelated-directory")).unwrap();
    let first = fixture.blocks.join("bundle-one.tar");
    let second = fixture.blocks.join("bundle-two.tar");
    import_bundle(&fixture.manifest, &fixture.blocks, &first).unwrap();
    import_bundle(&fixture.manifest, &fixture.blocks, &second).unwrap();
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    for (height, expected) in PAYLOADS.iter().enumerate() {
        assert_eq!(
            fs::read(fixture.blocks.join(format!("{height:010}.bin"))).unwrap(),
            *expected
        );
    }
}

#[test]
fn missing_short_long_or_corrupted_sources_leave_no_output_or_staging_files() {
    for case in ["missing", "short", "long", "corrupt"] {
        let fixture = Fixture::new();
        let source = fixture.blocks.join("0000000002.bin");
        match case {
            "missing" => fs::remove_file(source).unwrap(),
            "short" => fs::write(source, &PAYLOADS[2][..PAYLOADS[2].len() - 1]).unwrap(),
            "long" => {
                let mut bytes = PAYLOADS[2].to_vec();
                bytes.push(0);
                fs::write(source, bytes).unwrap();
            }
            "corrupt" => {
                let mut bytes = PAYLOADS[2].to_vec();
                bytes[0] ^= 0xff;
                fs::write(source, bytes).unwrap();
            }
            _ => unreachable!(),
        }
        let before = directory_names(fixture.root.path());
        assert!(
            import_bundle(&fixture.manifest, &fixture.blocks, &fixture.output()).is_err(),
            "accepted {case} source"
        );
        assert!(!fixture.output().exists());
        assert_eq!(
            directory_names(fixture.root.path()),
            before,
            "leaked {case}"
        );
    }
}

#[test]
fn import_never_overwrites_a_regular_output_or_directory() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let output = fixture.output();
        let sentinel = if directory {
            fs::create_dir(&output).unwrap();
            output.join("sentinel")
        } else {
            output.clone()
        };
        fs::write(&sentinel, b"existing user data").unwrap();
        let before = directory_names(fixture.root.path());
        assert!(import_bundle(&fixture.manifest, &fixture.blocks, &output).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"existing user data");
        assert_eq!(directory_names(fixture.root.path()), before);
    }
}

#[test]
fn retrying_import_requires_a_new_output_and_preserves_the_saved_bundle() {
    let fixture = Fixture::new();
    let output = fixture.import();
    let before = fs::read(&output).unwrap();
    assert!(import_bundle(&fixture.manifest, &fixture.blocks, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), before);
    verify_bundle(&fixture.manifest, &output).unwrap();
}

#[test]
fn simultaneous_imports_publish_exactly_one_complete_bundle_without_overwriting_it() {
    let first = Fixture::new();
    let mut second = Fixture::new();
    let alternate = b"different synthetic seed two; still not a Zcash block\0";
    fs::write(second.blocks.join("0000000002.bin"), alternate).unwrap();
    second.manifest.seed_blocks[1].bytes_length = alternate.len() as u64;
    second.manifest.seed_blocks[1].bytes_sha256 = sha256(alternate);
    second.manifest.validate().unwrap();
    assert_ne!(
        first.manifest.fingerprint().unwrap(),
        second.manifest.fingerprint().unwrap()
    );
    let output = first.output();
    let mut expected_first = directory_names(first.root.path());
    expected_first.push("saved-chain.tar".to_owned());
    expected_first.sort();
    let expected_second = directory_names(second.root.path());
    let barrier = std::sync::Barrier::new(3);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            import_bundle(&first.manifest, &first.blocks, &output)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            import_bundle(&second.manifest, &second.blocks, &output)
        });
        barrier.wait();
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_ne!(
        left.is_ok(),
        right.is_ok(),
        "left={left:?}; right={right:?}"
    );
    let (report, winner, loser) = match left {
        Ok(report) => (report, &first.manifest, &second.manifest),
        Err(_) => (right.unwrap(), &second.manifest, &first.manifest),
    };
    assert_eq!(verify_bundle(winner, &output).unwrap(), report);
    assert!(verify_bundle(loser, &output).is_err());
    assert_eq!(directory_names(first.root.path()), expected_first);
    assert_eq!(directory_names(second.root.path()), expected_second);
}

#[cfg(unix)]
#[test]
fn import_rejects_output_symlinks_including_dangling_links_without_touching_targets() {
    use std::os::unix::fs::symlink;
    for dangling in [false, true] {
        let fixture = Fixture::new();
        let target = fixture.root.path().join("symlink target");
        if !dangling {
            fs::write(&target, b"existing target").unwrap();
        }
        symlink(&target, fixture.output()).unwrap();
        assert!(import_bundle(&fixture.manifest, &fixture.blocks, &fixture.output()).is_err());
        assert_eq!(fs::read_link(fixture.output()).unwrap(), target);
        if dangling {
            assert!(!target.exists());
        } else {
            assert_eq!(fs::read(target).unwrap(), b"existing target");
        }
    }
}

#[cfg(unix)]
#[test]
fn source_symlinks_directories_and_fifos_are_rejected_without_following_them() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::os::unix::fs::symlink;
    for kind in ["symlink", "directory", "fifo"] {
        let fixture = Fixture::new();
        let source = fixture.blocks.join("0000000001.bin");
        fs::remove_file(&source).unwrap();
        match kind {
            "symlink" => {
                let target = fixture.root.path().join("outside block");
                fs::write(&target, PAYLOADS[1]).unwrap();
                symlink(&target, &source).unwrap();
            }
            "directory" => fs::create_dir(&source).unwrap(),
            "fifo" => mkfifo(&source, Mode::S_IRUSR | Mode::S_IWUSR).unwrap(),
            _ => unreachable!(),
        }
        let before = directory_names(fixture.root.path());
        assert!(
            import_bundle(&fixture.manifest, &fixture.blocks, &fixture.output()).is_err(),
            "accepted {kind} source"
        );
        assert_eq!(directory_names(fixture.root.path()), before);
    }
}

#[cfg(unix)]
#[test]
fn verifier_rejects_symlink_directory_and_fifo_bundles() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let output = fixture.import();
    let link = fixture.root.path().join("bundle-link");
    symlink(&output, &link).unwrap();
    assert!(verify_bundle(&fixture.manifest, &link).is_err());
    assert!(verify_bundle(&fixture.manifest, fixture.root.path()).is_err());
    let fifo = fixture.root.path().join("bundle-fifo");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    assert!(verify_bundle(&fixture.manifest, &fifo).is_err());
    verify_bundle(&fixture.manifest, &output).unwrap();
}

#[cfg(unix)]
#[test]
fn source_directory_symlinks_are_rejected_with_or_without_a_trailing_separator() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let alias = fixture.root.path().join("directory-link");
    symlink(&fixture.blocks, &alias).unwrap();
    for spelling in [
        alias.clone(),
        PathBuf::from(format!("{}/", alias.display())),
        PathBuf::from(format!("{}/.", alias.display())),
    ] {
        assert!(
            import_bundle(&fixture.manifest, &spelling, &fixture.output()).is_err(),
            "accepted symlink source directory {spelling:?}"
        );
        assert!(!fixture.output().exists());
    }
    assert_eq!(fs::read_link(alias).unwrap(), fixture.blocks);
}

#[test]
fn verification_binds_the_saved_bytes_to_the_expected_consensus_manifest() {
    let fixture = Fixture::new();
    let output = fixture.import();
    for field in ["networkMagic", "genesisHash", "declaredBytes", "upgrade"] {
        let mut value = manifest_value(&PAYLOADS);
        match field {
            "networkMagic" => value["networkMagic"] = json!("12345678"),
            "genesisHash" => value["genesis"]["hash"] = json!("45".repeat(32)),
            "declaredBytes" => value["seedBlocks"][0]["bytesSha256"] = json!("67".repeat(32)),
            "upgrade" => value["upgrades"]["NU6.3"] = json!(2),
            _ => unreachable!(),
        }
        let changed: ConsensusManifest = serde_json::from_value(value).unwrap();
        changed.validate().unwrap();
        assert!(
            verify_bundle(&changed, &output).is_err(),
            "accepted different {field}"
        );
    }
    verify_bundle(&fixture.manifest, &output).unwrap();
}

#[test]
fn verification_rehashes_saved_block_bytes_instead_of_trusting_metadata() {
    let fixture = Fixture::new();
    let output = fixture.import();
    verify_bundle(&fixture.manifest, &output).unwrap();
    let bytes = fs::read(&output).unwrap();
    for index in 1..=3 {
        let mut entries = read_entries(&bytes);
        entries[index].data[0] ^= 0xff;
        let corrupted = archive_bytes(&entries);
        assert_rejected_archive(&fixture, &corrupted, &format!("corrupted block {index}"));
    }
    let mut entries = read_entries(&bytes);
    entries[2].data[0] ^= 0xff;
    fs::write(&output, archive_bytes(&entries)).unwrap();
    assert!(verify_bundle(&fixture.manifest, &output).is_err());
}

#[test]
fn unknown_or_forged_metadata_cannot_claim_qualification_or_another_identity() {
    let fixture = Fixture::new();
    let bytes = fs::read(fixture.import()).unwrap();
    for case in [
        "version",
        "fingerprint",
        "manifest",
        "launchReady",
        "qualified",
        "unknown",
    ] {
        let mut entries = read_entries(&bytes);
        let original = String::from_utf8(entries[0].data.clone()).unwrap();
        let changed = match case {
            // Keep metadata length and field ordering unchanged for these
            // identity mutations, so only the changed identity distinguishes it.
            "version" => original.replace("zdn-chain-bundle/v1alpha1", "zdn-chain-bundle/v9alpha1"),
            "fingerprint" => {
                original.replace(&fixture.manifest.fingerprint().unwrap(), &"00".repeat(32))
            }
            "manifest" => original.replace("a1b2c3d4", "12345678"),
            "launchReady" | "qualified" | "unknown" => {
                let mut value: Value = serde_json::from_str(&original).unwrap();
                let (key, forged) = match case {
                    "launchReady" => ("launchReady", json!(true)),
                    "qualified" => ("qualification", json!("passed")),
                    _ => ("ignoredExtension", json!("surprise")),
                };
                value[key] = forged;
                serde_json::to_string(&value).unwrap()
            }
            _ => unreachable!(),
        };
        assert_ne!(changed, original);
        entries[0].replace_data(changed.into_bytes());
        assert_rejected_archive(&fixture, &archive_bytes(&entries), case);
    }
}

#[test]
fn exact_inventory_rejects_missing_extra_duplicate_reordered_and_renamed_entries() {
    let fixture = Fixture::new();
    let bytes = fs::read(fixture.import()).unwrap();
    for case in [
        "missing metadata",
        "missing seed",
        "extra block",
        "duplicate block",
        "reordered blocks",
        "metadata second",
        "wrong basename",
        "wrong metadata path",
    ] {
        let mut entries = read_entries(&bytes);
        match case {
            "missing metadata" => {
                entries.remove(0);
            }
            "missing seed" => {
                entries.pop();
            }
            "extra block" => {
                let mut extra = entries[3].clone();
                extra.set_path("blocks/0000000003.bin");
                entries.push(extra);
            }
            "duplicate block" => entries.push(entries[1].clone()),
            "reordered blocks" => entries.swap(2, 3),
            "metadata second" => entries.swap(0, 1),
            "wrong basename" => entries[1].set_path("blocks/0.bin"),
            "wrong metadata path" => entries[0].set_path("manifest.json"),
            _ => unreachable!(),
        }
        assert_rejected_archive(&fixture, &archive_bytes(&entries), case);
    }
}

#[test]
fn hostile_archive_paths_and_nonregular_entries_are_rejected_without_extraction() {
    let fixture = Fixture::new();
    let bytes = fs::read(fixture.import()).unwrap();
    let sentinel = fixture.root.path().join("outside-sentinel");
    fs::write(&sentinel, b"do not overwrite").unwrap();
    for case in [
        "traversal",
        "absolute",
        "symlink",
        "hardlink",
        "directory",
        "fifo",
    ] {
        let mut entries = read_entries(&bytes);
        match case {
            "traversal" => entries[1].set_path("../outside-sentinel"),
            "absolute" => entries[1].set_path("/tmp/zdn-chain-artifact-outside-sentinel"),
            "symlink" => entries[1].make_link(EntryType::Symlink),
            "hardlink" => entries[1].make_link(EntryType::Link),
            "directory" | "fifo" => {
                entries[1].replace_data(Vec::new());
                entries[1].header.set_entry_type(if case == "directory" {
                    EntryType::Directory
                } else {
                    EntryType::Fifo
                });
                entries[1].header.set_cksum();
            }
            _ => unreachable!(),
        }
        assert_rejected_archive(&fixture, &archive_bytes(&entries), case);
        assert_eq!(fs::read(&sentinel).unwrap(), b"do not overwrite");
    }
}

#[test]
fn truncation_appended_material_and_nonzero_archive_padding_are_rejected() {
    let fixture = Fixture::new();
    let bytes = fs::read(fixture.import()).unwrap();
    for length in [
        0,
        1,
        511,
        512,
        bytes.len() / 2,
        bytes.len() - 1,
        bytes.len() - 512,
    ] {
        assert_rejected_archive(
            &fixture,
            &bytes[..length],
            &format!("truncation to {length}"),
        );
    }
    for tail in [
        vec![0],
        vec![0; 512],
        b"unrecorded trailer".to_vec(),
        bytes.clone(),
    ] {
        let mut appended = bytes.clone();
        appended.extend(tail);
        assert_rejected_archive(&fixture, &appended, "appended material");
    }
    let entries = read_entries(&bytes);
    let mut corrupted = bytes.clone();
    let metadata_length = entries[0].data.len();
    assert_ne!(metadata_length % 512, 0);
    corrupted[512 + metadata_length] = 0xff;
    assert_rejected_archive(&fixture, &corrupted, "nonzero entry padding");
    let mut corrupted = bytes.clone();
    let end = corrupted.len();
    corrupted[end - 1] = 0xff;
    assert_rejected_archive(&fixture, &corrupted, "nonzero archive terminator");
}

#[test]
fn wrong_tar_checksum_or_unrecorded_header_properties_are_rejected() {
    let fixture = Fixture::new();
    let bytes = fs::read(fixture.import()).unwrap();
    let mut checksum = bytes.clone();
    checksum[148] ^= 1;
    assert_rejected_archive(&fixture, &checksum, "invalid header checksum");
    for case in ["mtime", "uid", "mode"] {
        let mut entries = read_entries(&bytes);
        match case {
            "mtime" => entries[1].header.set_mtime(123),
            "uid" => entries[1].header.set_uid(123),
            "mode" => entries[1].header.set_mode(0o777),
            _ => unreachable!(),
        }
        entries[1].header.set_cksum();
        assert_rejected_archive(&fixture, &archive_bytes(&entries), case);
    }
}

#[test]
fn aggregate_block_count_and_byte_limits_are_checked_before_source_io() {
    let fixture = Fixture::new();
    let absent = fixture.root.path().join("no-sources-exist");
    for (case, count, size, expected) in [
        ("count", 4097_u32, 1_u64, "4096"),
        ("bytes", 69_u32, 2_000_000_u64, "128"),
    ] {
        let mut value = manifest_value(&PAYLOADS[..1]);
        value["genesis"]["bytesLength"] = json!(size);
        value["seedBlocks"] = json!((1..count)
            .map(|height| json!({
                "height": height,
                "hash": format!("{:064x}", height + 1),
                "bytesSha256": format!("{:064x}", height + 100_000),
                "bytesLength": size,
            }))
            .collect::<Vec<_>>());
        let manifest: ConsensusManifest = serde_json::from_value(value).unwrap();
        manifest.validate().unwrap();
        let error = import_bundle(&manifest, &absent, &fixture.output()).unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains(expected),
            "{case} limit did not win over missing source: {error}"
        );
        assert!(!fixture.output().exists());
    }
}

#[test]
fn oversized_or_missing_bundle_is_rejected_without_reading_large_contents() {
    let fixture = Fixture::new();
    assert!(verify_bundle(&fixture.manifest, &fixture.output()).is_err());
    let sparse = fs::File::create(fixture.output()).unwrap();
    sparse.set_len(256 * 1024 * 1024 + 1).unwrap();
    drop(sparse);
    assert!(verify_bundle(&fixture.manifest, &fixture.output()).is_err());
}

#[test]
fn serialized_manifest_limit_is_checked_before_reading_any_sources() {
    let fixture = Fixture::new();
    let mut value = manifest_value(&PAYLOADS);
    value["subsidy"]["fundingStreams"] = json!([{
        "startHeight": 1,
        "endHeight": 2,
        "recipients": [{
            "receiver": "ecc",
            "numerator": 7,
            "scriptHashes": vec!["12".repeat(20); 50_000],
        }],
    }]);
    let manifest: ConsensusManifest = serde_json::from_value(value).unwrap();
    manifest.validate().unwrap();
    assert!(serde_json::to_vec(&manifest).unwrap().len() > 2 * 1024 * 1024);
    let absent = fixture.root.path().join("no-sources-exist");
    let error = import_bundle(&manifest, &absent, &fixture.output()).unwrap_err();
    assert!(format!("{error:#}").contains("2 MiB"), "{error:#}");
    assert!(!fixture.output().exists());
}
