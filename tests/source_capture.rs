use eyre::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zdn::source::{
    capture, capture_with_hook, CaptureCheckpoint, CaptureOptions, SnapshotFileKind, SnapshotMode,
    SnapshotReceipt,
};

#[cfg(unix)]
#[path = "support/executable.rs"]
mod executable;

struct Fixture {
    temp: tempfile::TempDir,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("checkout");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--quiet", "--initial-branch=main"]);
        git(&repo, &["config", "user.name", "Source Test"]);
        git(
            &repo,
            &["config", "user.email", "source-test@example.invalid"],
        );
        git(&repo, &["config", "commit.gpgSign", "false"]);
        let fixture = Self { temp, repo };
        fixture.write("LICENSE", b"Test fixture license\n");
        fixture.write("src/main.rs", b"fn main() {}\n");
        fixture.write("remove.me", b"remove this\n");
        fixture.commit();
        fixture
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.repo.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn commit(&self) {
        git(&self.repo, &["add", "."]);
        git(&self.repo, &["commit", "--quiet", "-m", "Fixture"]);
    }

    fn options(&self, name: &str) -> CaptureOptions {
        CaptureOptions {
            source: self.repo.clone(),
            output: self.temp.path().join(name),
            revision: None,
            include: Vec::new(),
        }
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    git_input(root, args, b"")
}

fn git_input(root: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn archive_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let file = fs::File::open(path.join("source.tar")).unwrap();
    tar::Archive::new(file)
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

fn error(options: &CaptureOptions) -> String {
    format!("{:#}", capture(options).unwrap_err())
}

#[test]
fn captures_current_bytes_staged_additions_renames_and_deletions() {
    let fixture = Fixture::new();
    fixture.write("src/main.rs", b"fn main() { println!(\"dirty\"); }\n");
    fixture.write("added.txt", b"staged version\n");
    git(&fixture.repo, &["add", "added.txt"]);
    fixture.write("added.txt", b"working version after staging\n");
    git(&fixture.repo, &["mv", "LICENSE", "COPYING"]);
    fs::remove_file(fixture.repo.join("remove.me")).unwrap();
    fixture.write("untracked.txt", b"do not include without permission\n");
    let options = fixture.options("snapshot");
    let receipt = capture(&options).unwrap();
    let files = archive_files(&options.output);
    assert_eq!(files["added.txt"], b"working version after staging\n");
    assert_eq!(files["COPYING"], b"Test fixture license\n");
    assert_eq!(
        files["src/main.rs"],
        b"fn main() { println!(\"dirty\"); }\n"
    );
    assert!(!files.contains_key("remove.me"));
    assert!(!files.contains_key("untracked.txt"));
    assert_eq!(receipt.deleted_paths, ["LICENSE", "remove.me"]);
    assert_eq!(receipt.omitted_untracked, ["untracked.txt"]);
    assert_eq!(receipt.branch.as_deref(), Some("main"));
    assert!(receipt.dirty);
    assert_eq!(
        receipt.head,
        git(&fixture.repo, &["rev-parse", "HEAD"]).trim()
    );
    for file in &receipt.files {
        assert_eq!(file.sha256, hex::encode(Sha256::digest(&files[&file.path])));
        assert_eq!(file.size, files[&file.path].len() as u64);
    }
    let bytes = fs::read(options.output.join("source.tar")).unwrap();
    assert_eq!(receipt.archive_sha256, hex::encode(Sha256::digest(&bytes)));
    assert_eq!(receipt.archive_bytes, bytes.len() as u64);
    let saved: SnapshotReceipt =
        serde_json::from_slice(&fs::read(options.output.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt, saved);
}

#[test]
fn staged_deletion_stays_deleted_even_if_file_is_recreated_untracked() {
    let fixture = Fixture::new();
    git(&fixture.repo, &["rm", "remove.me"]);
    fixture.write("remove.me", b"new untracked bytes");
    let options = fixture.options("snapshot");
    let receipt = capture(&options).unwrap();
    assert_eq!(receipt.deleted_paths, ["remove.me"]);
    assert_eq!(receipt.omitted_untracked, ["remove.me"]);
    assert!(!archive_files(&options.output).contains_key("remove.me"));
}

#[test]
fn explicit_include_adds_one_untracked_file_and_excludes_the_other() {
    let fixture = Fixture::new();
    fixture.write("inputs/selected.txt", b"selected");
    fixture.write("inputs/omitted.txt", b"omitted");
    let mut options = fixture.options("snapshot");
    options.include.push(PathBuf::from("inputs/selected.txt"));
    let receipt = capture(&options).unwrap();
    assert_eq!(receipt.omitted_untracked, ["inputs/omitted.txt"]);
    assert_eq!(
        archive_files(&options.output)["inputs/selected.txt"],
        b"selected"
    );
}

#[test]
fn ignored_explicit_files_and_assume_unchanged_edits_are_recorded_as_dirty() {
    let fixture = Fixture::new();
    fixture.write(".gitignore", b"local-input.txt\n");
    fixture.commit();
    fixture.write("local-input.txt", b"ignored but explicitly selected");
    let mut options = fixture.options("explicit");
    options.include.push(PathBuf::from("local-input.txt"));
    let receipt = capture(&options).unwrap();
    assert!(receipt.dirty);
    assert_eq!(
        archive_files(&options.output)["local-input.txt"],
        b"ignored but explicitly selected"
    );

    git(
        &fixture.repo,
        &["update-index", "--assume-unchanged", "src/main.rs"],
    );
    fixture.write("src/main.rs", b"hidden dirty bytes");
    assert!(git(&fixture.repo, &["status", "--porcelain"]).is_empty());
    let options = fixture.options("hidden-edit");
    let receipt = capture(&options).unwrap();
    assert!(receipt.dirty);
    assert_eq!(
        archive_files(&options.output)["src/main.rs"],
        b"hidden dirty bytes"
    );
}

#[test]
fn rejects_include_directories_missing_files_and_escape_paths() {
    let fixture = Fixture::new();
    for (include, message) in [
        ("src", "not a regular file"),
        ("missing", "does not exist"),
        ("../elsewhere", "checkout-relative"),
        ("/tmp/elsewhere", "checkout-relative"),
    ] {
        let mut options = fixture.options("snapshot");
        options.include.push(PathBuf::from(include));
        assert!(error(&options).contains(message));
        assert!(!options.output.exists());
    }
}

#[test]
fn archives_are_deterministic_and_preserve_license_bytes() {
    let fixture = Fixture::new();
    // Cross multiple output-buffer boundaries and require a GNU long-name entry.
    let payload: Vec<u8> = (0..131_077).map(|index| (index % 251) as u8).collect();
    let long_path = format!("nested/{}/payload.bin", "segment-".repeat(16));
    fixture.write(&long_path, &payload);
    fixture.write("empty.bin", b"");
    fixture.write("tail.txt", b"last file\n");
    fixture.commit();
    let first = fixture.options("first");
    let second = fixture.options("second");
    let first_receipt = capture(&first).unwrap();
    fixture.write("src/main.rs", b"fn main() {}\n");
    let second_receipt = capture(&second).unwrap();
    assert!(!first_receipt.dirty);
    assert!(!second_receipt.dirty);
    assert_eq!(first_receipt.archive_sha256, second_receipt.archive_sha256);
    // Canonical archive bytes captured from the pre-optimization 18556ac implementation.
    assert_eq!(
        first_receipt.archive_sha256,
        "cbfaa55599173246e7f31ccc7cb51abf04ce86473488c629b38fd2abd7c66a5c"
    );
    assert_eq!(
        fs::read(first.output.join("source.tar")).unwrap(),
        fs::read(second.output.join("source.tar")).unwrap()
    );
    let archive_bytes = fs::read(first.output.join("source.tar")).unwrap();
    assert_eq!(first_receipt.archive_bytes, archive_bytes.len() as u64);
    assert_eq!(
        first_receipt.archive_sha256,
        hex::encode(Sha256::digest(&archive_bytes))
    );
    let mut revision = fixture.options("revision");
    revision.revision = Some("HEAD".into());
    let revision_receipt = capture(&revision).unwrap();
    assert_eq!(
        revision_receipt.archive_sha256,
        first_receipt.archive_sha256
    );
    assert_eq!(
        fs::read(revision.output.join("source.tar")).unwrap(),
        archive_bytes
    );
    let files = archive_files(&second.output);
    assert_eq!(files[&long_path], payload);
    assert_eq!(files["empty.bin"], b"");
    assert_eq!(files["tail.txt"], b"last file\n");
    assert_eq!(files["LICENSE"], b"Test fixture license\n");
    let mut archive = tar::Archive::new(fs::File::open(second.output.join("source.tar")).unwrap());
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        assert_eq!(entry.header().mtime().unwrap(), 0);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
    }
}

#[cfg(unix)]
#[test]
fn captures_current_executable_mode_and_internal_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = Fixture::new();
    fixture.write("script.sh", b"#!/bin/sh\nexit 0\n");
    symlink("src/main.rs", fixture.repo.join("source-link")).unwrap();
    fixture.commit();
    fs::set_permissions(
        fixture.repo.join("script.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let options = fixture.options("snapshot");
    let receipt = capture(&options).unwrap();
    let script = receipt
        .files
        .iter()
        .find(|file| file.path == "script.sh")
        .unwrap();
    assert_eq!(script.mode, 0o755);
    let link = receipt
        .files
        .iter()
        .find(|file| file.path == "source-link")
        .unwrap();
    assert_eq!(link.kind, SnapshotFileKind::Symlink);
    assert_eq!(link.link_target.as_deref(), Some("src/main.rs"));
    let mut archive = tar::Archive::new(fs::File::open(options.output.join("source.tar")).unwrap());
    let link = archive
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap())
        .find(|entry| entry.path().unwrap() == Path::new("source-link"))
        .unwrap();
    assert!(link.header().entry_type().is_symlink());
    assert_eq!(link.link_name().unwrap().unwrap(), Path::new("src/main.rs"));
}

#[cfg(unix)]
#[test]
fn rejects_escaping_dangling_and_omitted_symlink_targets() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fs::write(fixture.temp.path().join("outside"), b"private").unwrap();
    for (target, message) in [
        ("../outside", "escapes the checkout"),
        ("missing", "dangling"),
        ("untracked.txt", "not included"),
    ] {
        fixture.write("untracked.txt", b"untracked");
        symlink(target, fixture.repo.join("link")).unwrap();
        git(&fixture.repo, &["add", "link"]);
        let options = fixture.options("snapshot");
        assert!(error(&options).contains(message));
        assert!(!options.output.exists());
        fs::remove_file(fixture.repo.join("link")).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn rejects_directory_symlink_substitution() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let outside = fixture.temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("main.rs"), b"private").unwrap();
    fs::remove_dir_all(fixture.repo.join("src")).unwrap();
    symlink(&outside, fixture.repo.join("src")).unwrap();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("symlink parent"));
    assert!(!options.output.exists());
}

#[cfg(unix)]
#[test]
fn revision_mode_resolves_intermediate_symlinks_before_parent_traversal() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write("a/secret", b"included decoy");
    fixture.write("d/file", b"directory marker");
    fs::create_dir_all(fixture.repo.join("a/b")).unwrap();
    symlink("../../d", fixture.repo.join("a/b/c")).unwrap();
    symlink("a/b/c/../../secret", fixture.repo.join("escape")).unwrap();
    fixture.commit();
    let mut options = fixture.options("snapshot");
    options.revision = Some("HEAD".to_owned());
    assert!(error(&options).contains("escapes the source checkout"));
    assert!(!options.output.exists());
}

#[cfg(unix)]
#[test]
fn cargo_paths_resolve_intermediate_symlinks_before_parent_traversal() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write(
        "Cargo.toml",
        b"[dependencies]\nexternal = { path = 'a/b/c/../../outside' }\n",
    );
    fixture.write(
        "a/outside/Cargo.toml",
        b"[package]\nname = 'decoy'\nversion = '0.1.0'\n",
    );
    fixture.write("d/file", b"directory marker");
    fs::create_dir_all(fixture.repo.join("a/b")).unwrap();
    symlink("../../d", fixture.repo.join("a/b/c")).unwrap();
    fixture.commit();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("escapes the source checkout"));
    assert!(!options.output.exists());
    fixture.write(
        "Cargo.toml",
        b"[workspace]\nmembers = ['a/b/c/../../outside']\n",
    );
    assert!(error(&options).contains("escapes the source checkout"));
    assert!(!options.output.exists());
}

#[test]
fn rejects_sparse_checkout_omissions_instead_of_recording_a_deletion() {
    let fixture = Fixture::new();
    git(
        &fixture.repo,
        &["update-index", "--skip-worktree", "remove.me"],
    );
    fs::remove_file(fixture.repo.join("remove.me")).unwrap();
    assert!(git(&fixture.repo, &["status", "--porcelain"]).is_empty());
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("sparse checkout or skip-worktree"));
    assert!(!options.output.exists());
}

#[test]
fn excludes_known_secrets_generated_state_and_build_outputs_even_if_tracked() {
    let fixture = Fixture::new();
    let excluded = [
        ".env",
        ".env.local",
        ".aws/credentials",
        "target/debug/program",
        ".context/notes",
        ".zdn/state.json",
        ".pulumi/state.json",
        "wallet.dat",
        "wallet.sqlite",
        "id_ed25519",
        "private.pem",
        "uppercase.PEM",
        "secret.KEY",
        "private.PFX",
        "Pulumi.dev.yaml",
    ];
    for path in excluded {
        fixture.write(path, b"must not leave checkout");
    }
    fixture.write(".env.example", b"EXAMPLE=placeholder\n");
    fixture.commit();
    let options = fixture.options("snapshot");
    let receipt = capture(&options).unwrap();
    let files = archive_files(&options.output);
    for path in excluded {
        assert!(receipt.excluded_paths.contains(&path.to_owned()), "{path}");
        assert!(!files.contains_key(path), "{path}");
    }
    assert!(files.contains_key("LICENSE"));
    assert!(files.contains_key(".env.example"));
    let mut explicit = fixture.options("explicit");
    explicit.include.push(PathBuf::from(".env"));
    assert!(error(&explicit).contains("excluded from source capture"));
}

#[test]
fn supports_linked_git_worktrees() {
    let fixture = Fixture::new();
    let linked = fixture.temp.path().join("linked");
    git(
        &fixture.repo,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature/test",
            linked.to_str().unwrap(),
        ],
    );
    fs::write(linked.join("src/main.rs"), b"worktree edits\n").unwrap();
    let mut options = fixture.options("snapshot");
    options.source = linked.clone();
    let receipt = capture(&options).unwrap();
    assert_eq!(receipt.source_root, linked.canonicalize().unwrap());
    assert_eq!(receipt.branch.as_deref(), Some("feature/test"));
    assert_eq!(
        archive_files(&options.output)["src/main.rs"],
        b"worktree edits\n"
    );
    assert!(!archive_files(&options.output).contains_key(".git"));
}

#[test]
fn exact_revision_uses_committed_objects_and_ignores_export_ignore() {
    let fixture = Fixture::new();
    fixture.write(".gitattributes", b"LICENSE export-ignore\n");
    fixture.commit();
    let committed = git(&fixture.repo, &["rev-parse", "HEAD"]).trim().to_owned();
    fixture.write("src/main.rs", b"dirty ignored\n");
    fs::remove_file(fixture.repo.join("LICENSE")).unwrap();
    let mut options = fixture.options("snapshot");
    options.revision = Some(committed.clone());
    let receipt = capture(&options).unwrap();
    assert_eq!(receipt.mode, SnapshotMode::Revision);
    assert_eq!(receipt.head, committed);
    assert_eq!(receipt.branch, None);
    assert!(!receipt.dirty);
    let files = archive_files(&options.output);
    assert_eq!(files["src/main.rs"], b"fn main() {}\n");
    assert_eq!(files["LICENSE"], b"Test fixture license\n");
    options.output = fixture.temp.path().join("mixed");
    options.include.push(PathBuf::from("src/main.rs"));
    assert!(error(&options).contains("only to worktree"));
}

#[test]
fn exact_revision_preserves_case_collisions_without_checking_out_the_tree() {
    let fixture = Fixture::new();
    // Git trees can contain names that cannot coexist on the local filesystem.
    // Construct these objects and index entries without a working-tree checkout.
    git(&fixture.repo, &["read-tree", "--empty"]);
    let expected: &[(&str, u32, &[u8])] = &[
        ("README", 0o100644, b"UPPER\n"),
        ("readme", 0o100644, b"lowercase has a different length\n"),
        ("EMPTY", 0o100644, b""),
        ("empty", 0o100755, b"#!/bin/sh\nexit 0\n"),
        ("Dir", 0o100644, b"a file, not the lowercase directory\n"),
        (
            "dir/child",
            0o100644,
            b"a child in the lowercase directory\n",
        ),
        (
            "Cargo.toml",
            0o100644,
            b"[workspace]\nmembers = ['Members/Upper', 'members/upper']\n",
        ),
        (
            "Members/Upper/Cargo.toml",
            0o100644,
            b"[package]\nname = 'upper'\nversion = '0.1.0'\n",
        ),
        (
            "members/upper/Cargo.toml",
            0o100644,
            b"[package]\nname = 'lowercase'\nversion = '0.2.0'\n",
        ),
        ("Source-link", 0o120000, b"README"),
        ("source-link", 0o120000, b"readme"),
    ];
    for (path, mode, bytes) in expected {
        let object = git_input(&fixture.repo, &["hash-object", "-w", "--stdin"], bytes);
        git(
            &fixture.repo,
            &[
                "-c",
                "core.ignorecase=false",
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("{mode:o},{},{path}", object.trim()),
            ],
        );
    }
    let tree = git(&fixture.repo, &["write-tree"]);
    let commit = git(
        &fixture.repo,
        &["commit-tree", tree.trim(), "-m", "Case collision fixture"],
    );
    let mut options = fixture.options("case-collisions");
    options.revision = Some(commit.trim().to_owned());
    let receipt = capture(&options).unwrap();
    assert_eq!(receipt.files.len(), expected.len());
    let mut archive = tar::Archive::new(fs::File::open(options.output.join("source.tar")).unwrap());
    let mut actual = BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_str().unwrap().to_owned();
        let captured = receipt.files.iter().find(|file| file.path == path).unwrap();
        assert_eq!(entry.header().mode().unwrap(), captured.mode);
        let bytes = if entry.header().entry_type().is_symlink() {
            assert_eq!(entry.size(), 0);
            assert_eq!(captured.kind, SnapshotFileKind::Symlink);
            let target = entry.link_name().unwrap().unwrap();
            assert_eq!(captured.link_target.as_deref(), target.to_str());
            target.to_str().unwrap().as_bytes().to_vec()
        } else {
            assert_eq!(entry.size(), captured.size);
            assert_eq!(captured.kind, SnapshotFileKind::File);
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            bytes
        };
        assert_eq!(captured.size, bytes.len() as u64);
        assert_eq!(captured.sha256, hex::encode(Sha256::digest(&bytes)));
        assert!(actual.insert(path, bytes).is_none());
    }
    for (path, mode, bytes) in expected {
        assert_eq!(actual[*path], *bytes, "{path}");
        let captured = receipt
            .files
            .iter()
            .find(|file| file.path == *path)
            .unwrap();
        assert_eq!(
            captured.mode,
            if *mode == 0o120000 {
                0o777
            } else {
                mode & 0o777
            }
        );
    }
    let archive_bytes = fs::read(options.output.join("source.tar")).unwrap();
    assert_eq!(receipt.archive_bytes, archive_bytes.len() as u64);
    assert_eq!(
        receipt.archive_sha256,
        hex::encode(Sha256::digest(&archive_bytes))
    );
    options.output = fixture.temp.path().join("case-collisions-again");
    let repeated = capture(&options).unwrap();
    assert_eq!(repeated.archive_sha256, receipt.archive_sha256);
}

#[test]
fn rejects_staged_size_or_hash_changes_before_publishing_an_archive() {
    let fixture = Fixture::new();
    for change_length in [false, true] {
        let options = fixture.options("snapshot");
        let failure = capture_with_hook(&options, |checkpoint| {
            if checkpoint == CaptureCheckpoint::Copied {
                let temporary = fs::read_dir(fixture.temp.path())?
                    .map(|entry| entry.unwrap())
                    .find(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".zdn-capture-")
                    })
                    .unwrap();
                let staged = fs::read_dir(temporary.path().join("data"))?
                    .map(|entry| entry.unwrap())
                    .find(|entry| entry.file_type().unwrap().is_file())
                    .unwrap();
                let mut bytes = fs::read(staged.path())?;
                if change_length {
                    bytes.push(b'!');
                } else {
                    bytes[0] ^= 1;
                }
                fs::write(staged.path(), bytes)?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{failure:#}").contains("staged source bytes changed before archiving"));
        assert!(!options.output.exists());
        assert!(capture(&options).is_ok());
        fs::remove_dir_all(options.output).unwrap();
    }
}

#[test]
fn detects_source_mutation_at_both_capture_boundaries_without_publishing() {
    let fixture = Fixture::new();
    for boundary in [CaptureCheckpoint::Selected, CaptureCheckpoint::Copied] {
        fixture.write("src/main.rs", b"already dirty\n");
        let options = fixture.options("snapshot");
        let mut checkpoints = Vec::new();
        let result = capture_with_hook(&options, |checkpoint| {
            checkpoints.push(checkpoint);
            if checkpoint == boundary {
                fixture.write("src/main.rs", b"changed during capture\n");
            }
            Ok(())
        });
        let failure = result.unwrap_err();
        let diagnostic = format!("{failure:#}");
        assert!(
            diagnostic.contains("changed during capture"),
            "mutation boundary: {boundary:?}; observed checkpoints: {checkpoints:?}; unexpected capture error: {diagnostic}"
        );
        assert!(!options.output.exists());
        assert!(
            !fs::read_dir(fixture.temp.path()).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".zdn-capture-"))
        );
    }
}

#[test]
fn detects_index_change_and_recreated_deletion_without_publishing() {
    let fixture = Fixture::new();
    let options = fixture.options("snapshot");
    let result = capture_with_hook(&options, |checkpoint| {
        if checkpoint == CaptureCheckpoint::Copied {
            fixture.write("added-during-capture", b"new");
            git(&fixture.repo, &["add", "added-during-capture"]);
        }
        Ok(())
    });
    assert!(format!("{:#}", result.unwrap_err()).contains("Git state changed"));
    assert!(!options.output.exists());
    fs::remove_file(fixture.repo.join("remove.me")).unwrap();
    let result = capture_with_hook(&options, |checkpoint| {
        if checkpoint == CaptureCheckpoint::Copied {
            fixture.write("remove.me", b"recreated");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert!(!options.output.exists());
}

#[test]
fn hook_failure_preserves_no_partial_snapshot_and_retry_can_succeed() {
    let fixture = Fixture::new();
    let options = fixture.options("snapshot");
    let result = capture_with_hook(&options, |checkpoint| -> Result<()> {
        if checkpoint == CaptureCheckpoint::Copied {
            bail!("simulated interruption");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert!(!options.output.exists());
    capture(&options).unwrap();
    let original = fs::read(options.output.join("receipt.json")).unwrap();
    assert!(error(&options).contains("already exists"));
    assert_eq!(
        fs::read(options.output.join("receipt.json")).unwrap(),
        original
    );
}

#[test]
fn rejects_output_inside_checkout_before_writing() {
    let fixture = Fixture::new();
    let mut options = fixture.options("unused");
    options.output = fixture.repo.join("snapshot");
    assert!(error(&options).contains("outside the source checkout"));
    assert!(!options.output.exists());
    assert!(!fixture.repo.join(".zdn-source-capture.lock").exists());
}

#[test]
fn refuses_to_expand_a_selected_source_subdirectory_to_the_whole_checkout() {
    let fixture = Fixture::new();
    let mut options = fixture.options("snapshot");
    options.source = fixture.repo.join("src");
    assert!(error(&options).contains("must be the Git worktree root"));
    assert!(!options.output.exists());
    assert!(!fixture
        .temp
        .path()
        .join(".zdn-source-capture.lock")
        .exists());
}

#[test]
fn refuses_a_busy_output_parent_without_waiting_for_the_lock() {
    use fs2::FileExt;
    let fixture = Fixture::new();
    let lock = fs::File::create(fixture.temp.path().join(".zdn-source-capture.lock")).unwrap();
    lock.lock_exclusive().unwrap();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("another source capture is in progress"));
    assert!(!options.output.exists());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_directory_lock_files() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let lock_path = fixture.temp.path().join(".zdn-source-capture.lock");
    let outside = fixture.temp.path().join("outside");
    fs::write(&outside, b"unrelated data").unwrap();
    symlink(&outside, &lock_path).unwrap();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("lock must be a regular file"));
    assert!(!options.output.exists());
    assert_eq!(fs::read(outside).unwrap(), b"unrelated data");
    fs::remove_file(&lock_path).unwrap();
    fs::create_dir(&lock_path).unwrap();
    assert!(error(&options).contains("lock must be a regular file"));
}

#[test]
fn concurrent_capture_cannot_overwrite_a_snapshot() {
    let fixture = Fixture::new();
    let options = fixture.options("snapshot");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let options = options.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                capture(&options)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert!(archive_files(&options.output).contains_key("LICENSE"));
}

#[test]
fn rejects_submodules_before_attempting_to_read_missing_worktrees() {
    let fixture = Fixture::new();
    let head = git(&fixture.repo, &["rev-parse", "HEAD"]).trim().to_owned();
    git(
        &fixture.repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head},vendor/submodule"),
        ],
    );
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("submodules are not supported"));
    assert!(!options.output.exists());
}

#[test]
fn rejects_lfs_pointers_and_hydrated_lfs_files() {
    let fixture = Fixture::new();
    fixture.write(
        "large.bin",
        b"version https://git-lfs.github.com/spec/v1\noid sha256:1111\nsize 1\n",
    );
    fixture.commit();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("LFS pointer"));
    fixture.write("large.bin", b"hydrated bytes");
    fixture.write(
        ".gitattributes",
        b"large.bin filter=lfs diff=lfs merge=lfs -text\n",
    );
    git(&fixture.repo, &["add", ".gitattributes"]);
    assert!(error(&options).contains("Git LFS source is not supported"));
    assert!(!options.output.exists());
    let mut revision = fixture.options("revision");
    revision.revision = Some("HEAD".to_owned());
    assert!(error(&revision).contains("LFS pointer"));
}

#[test]
fn accepts_captured_internal_cargo_path_dependencies() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[package]\nname = 'fixture'\nversion = '0.1.0'\n[dependencies]\nlocal = { path = 'crates/local' }\n[workspace]\nmembers = ['crates/*']\n");
    fixture.write(
        "crates/local/Cargo.toml",
        b"[package]\nname = 'local'\nversion = '0.1.0'\n",
    );
    fixture.write("crates/local/src/lib.rs", b"pub fn fixture() {}\n");
    fixture.commit();
    let options = fixture.options("snapshot");
    capture(&options).unwrap();
    assert!(archive_files(&options.output).contains_key("crates/local/Cargo.toml"));
}

#[test]
fn rejects_external_missing_target_patch_and_workspace_dependencies() {
    let fixture = Fixture::new();
    let manifests = [
        "[dependencies]\nexternal = { path = '../outside' }\n",
        "[target.'cfg(unix)'.build-dependencies]\nexternal = { path = '../outside' }\n",
        "[patch.crates-io]\nexternal = { path = '../outside' }\n",
        "[workspace.dependencies]\nexternal = { path = '../outside' }\n",
        "[workspace]\nmembers = ['../outside']\n",
        "[package]\nworkspace = '../outside'\n",
    ];
    for manifest in manifests {
        fixture.write("Cargo.toml", manifest.as_bytes());
        git(&fixture.repo, &["add", "Cargo.toml"]);
        let options = fixture.options("snapshot");
        assert!(error(&options).contains("external Cargo"), "{manifest}");
        assert!(!options.output.exists());
    }
    fixture.write(
        "Cargo.toml",
        b"[dependencies]\nmissing = { path = 'not-captured' }\n",
    );
    assert!(error(&fixture.options("snapshot")).contains("absent from the snapshot"));
}

#[test]
fn rejects_external_cargo_configuration_path_overrides() {
    let fixture = Fixture::new();
    fixture.write(".cargo/config.toml", b"paths = ['../outside']\n");
    fixture.commit();
    let options = fixture.options("snapshot");
    assert!(error(&options).contains("external Cargo path dependency"));
    assert!(!options.output.exists());
}

#[cfg(unix)]
#[test]
fn capture_disables_repository_fsmonitor() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    executable::write(
        fixture.repo.join(".git/capture-fsmonitor"),
        b"#!/bin/sh\nprintf called > .git/helper-ran\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(
        fixture.repo.join(".git/capture-fsmonitor"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    git(
        &fixture.repo,
        &["config", "core.fsmonitor", ".git/capture-fsmonitor"],
    );
    // Prove the configured command is executable in this Git fixture.
    git(&fixture.repo, &["ls-files"]);
    assert!(fixture.repo.join(".git/helper-ran").exists());
    fs::remove_file(fixture.repo.join(".git/helper-ran")).unwrap();
    for revision in [false, true] {
        let mut options = fixture.options(if revision { "revision" } else { "worktree" });
        options.revision = revision.then(|| "HEAD".to_owned());
        capture(&options).unwrap();
        assert!(!fixture.repo.join(".git/helper-ran").exists());
    }
}

#[test]
fn capture_preserves_raw_bytes_without_running_clean_or_process_filters() {
    for filter in ["clean", "process"] {
        let fixture = Fixture::new();
        fixture.write(".gitattributes", b"src/main.rs filter=capture-test\n");
        fixture.commit();
        git(
            &fixture.repo,
            &[
                "config",
                &format!("filter.capture-test.{filter}"),
                "printf called > .git/filter-ran; exit 1",
            ],
        );
        git(
            &fixture.repo,
            &["config", "filter.capture-test.required", "true"],
        );
        fixture.write(
            "src/main.rs",
            b"raw developer bytes that must not run through a filter\n",
        );
        let options = fixture.options("worktree");
        let receipt = capture(&options).unwrap();
        assert!(receipt.dirty);
        assert_eq!(
            archive_files(&options.output)["src/main.rs"],
            b"raw developer bytes that must not run through a filter\n"
        );
        let mut options = fixture.options("revision");
        options.revision = Some("HEAD".to_owned());
        capture(&options).unwrap();
        assert_eq!(
            archive_files(&options.output)["src/main.rs"],
            b"fn main() {}\n"
        );
        assert!(
            !fixture.repo.join(".git/filter-ran").exists(),
            "{filter} filter executed"
        );
    }
}

#[test]
fn staged_only_changes_still_mark_the_capture_dirty_without_git_status() {
    let fixture = Fixture::new();
    fixture.write("src/main.rs", b"staged change\n");
    git(&fixture.repo, &["add", "src/main.rs"]);
    fixture.write("src/main.rs", b"fn main() {}\n");
    let options = fixture.options("snapshot");
    assert!(capture(&options).unwrap().dirty);
    assert_eq!(
        archive_files(&options.output)["src/main.rs"],
        b"fn main() {}\n"
    );
}

#[test]
fn rejects_external_or_missing_explicit_cargo_entrypoints_in_both_modes() {
    for field in ["build", "lib", "bin"] {
        for path in ["../external.rs", "/tmp/external.rs", "missing.rs", "src"] {
            let fixture = Fixture::new();
            let suffix = match field {
                "build" => format!("build = '{path}'\n"),
                "lib" => format!("[lib]\npath = '{path}'\n"),
                _ => format!("[[bin]]\nname = 'tool'\npath = '{path}'\n"),
            };
            fixture.write(
                "Cargo.toml",
                format!(
                    "[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\n{suffix}"
                )
                .as_bytes(),
            );
            fixture.commit();
            for revision in [false, true] {
                let mut options = fixture.options("snapshot");
                options.revision = revision.then(|| "HEAD".to_owned());
                let failure = error(&options);
                assert!(
                    failure.contains("Cargo") && failure.contains(path),
                    "{field}, {revision}: {failure}"
                );
                assert!(!options.output.exists());
            }
        }
    }
}

#[test]
fn requires_declared_default_library_binary_and_build_script_paths() {
    for suffix in [
        "[lib]\n",
        "[[bin]]\nname = 'missing-tool'\n",
        "build = true\n",
    ] {
        let fixture = Fixture::new();
        fixture.write(
            "Cargo.toml",
            format!("[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\n{suffix}")
                .as_bytes(),
        );
        fixture.commit();
        let options = fixture.options("snapshot");
        assert!(error(&options).contains("snapshot"), "{suffix}");
        assert!(!options.output.exists());
    }
}

#[test]
fn rejects_omitted_implicit_cargo_sources_including_ignored_files() {
    for path in [
        "build.rs",
        "src/main.rs",
        "src/lib.rs",
        "src/bin/helper.rs",
        "src/bin/helper/main.rs",
    ] {
        for ignored in [false, true] {
            let fixture = Fixture::new();
            fixture.write(
                "Cargo.toml",
                b"[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\n",
            );
            if ignored {
                fixture.write(".gitignore", format!("{path}\n").as_bytes());
            }
            if path == "src/main.rs" {
                fs::remove_file(fixture.repo.join(path)).unwrap();
            }
            fixture.commit();
            fixture.write(path, b"fn main() {}\n");
            let options = fixture.options("missing");
            let failure = error(&options);
            assert!(
                failure.contains("snapshot") && failure.contains(path),
                "{failure}"
            );
            assert!(!options.output.exists());
            let mut options = fixture.options("included");
            options.include.push(path.into());
            capture(&options).unwrap();
            assert!(archive_files(&options.output).contains_key(path));
            // Exact revisions must not consult omitted working source files.
            let mut options = fixture.options("revision");
            options.revision = Some("HEAD".to_owned());
            capture(&options).unwrap();
            assert!(!archive_files(&options.output).contains_key(path));
        }
    }
}

#[test]
fn honors_disabled_cargo_auto_discovery_and_explicit_target_overrides() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\nbuild = false\nautolib = false\nautobins = false\n[[bin]]\nname = 'fixture'\npath = 'src/main.rs'\n");
    fixture.commit();
    for path in ["build.rs", "src/lib.rs", "src/bin/helper.rs"] {
        fixture.write(path, b"omitted intentionally");
    }
    capture(&fixture.options("disabled")).unwrap();
    fixture.write("Cargo.toml", b"[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\nbuild = false\n[lib]\npath = 'lib-root.rs'\n[[bin]]\nname = 'helper'\npath = 'src/main.rs'\n");
    fixture.write("lib-root.rs", b"pub fn library() {}\n");
    git(&fixture.repo, &["add", "Cargo.toml", "lib-root.rs"]);
    capture(&fixture.options("overrides")).unwrap();
}

#[test]
fn accepts_internal_cargo_entrypoints_and_named_binary_defaults() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crate']\n");
    fixture.write("crate/Cargo.toml", b"[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\nbuild = '../shared/build.rs'\n[lib]\npath = '../shared/lib.rs'\n[[bin]]\nname = 'fixture'\n[[bin]]\nname = 'helper'\n[[bin]]\nname = 'nested'\n[[bin]]\nname = 'explicit'\npath = '../shared/main.rs'\n");
    for path in [
        "shared/build.rs",
        "shared/lib.rs",
        "shared/main.rs",
        "crate/src/main.rs",
        "crate/src/bin/helper.rs",
        "crate/src/bin/nested/main.rs",
    ] {
        fixture.write(path, b"fn main() {}\n");
    }
    fixture.write("crate/src/bin/README", b"Not a binary\n");
    fixture.commit();
    for revision in [false, true] {
        let mut options = fixture.options(if revision { "revision" } else { "worktree" });
        options.revision = revision.then(|| "HEAD".to_owned());
        capture(&options).unwrap();
    }
}

#[test]
fn accepts_legacy_renamed_default_binary() {
    let fixture = Fixture::new();
    fixture.write(
        "Cargo.toml",
        b"[package]\nname = 'fixture'\nversion = '0.1.0'\n[[bin]]\nname = 'renamed'\n",
    );
    fixture.commit();
    capture(&fixture.options("snapshot")).unwrap();
}

#[test]
fn legacy_named_libraries_use_src_name_only_without_src_lib() {
    for edition in ["2015", "2021"] {
        let fixture = Fixture::new();
        fixture.write("Cargo.toml", format!("[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '{edition}'\n[lib]\nname = 'other'\n").as_bytes());
        fixture.write("src/other.rs", b"pub fn other() {}\n");
        fixture.commit();
        let options = fixture.options("legacy-path");
        if edition == "2015" {
            capture(&options).unwrap();
        } else {
            assert!(error(&options).contains("src/lib.rs"));
        }
        fixture.write("src/lib.rs", b"pub fn preferred() {}\n");
        let options = fixture.options("omitted-default");
        assert!(error(&options).contains("src/lib.rs"));
    }
}

#[test]
fn inherited_legacy_edition_controls_entrypoint_defaults_and_auto_discovery() {
    for explicit_workspace in [false, true] {
        let fixture = Fixture::new();
        let (workspace, member, package_workspace) = if explicit_workspace {
            (
                "workspace/Cargo.toml",
                "../crate",
                "workspace = '../workspace'\n",
            )
        } else {
            ("Cargo.toml", "crate", "")
        };
        fixture.write(
            workspace,
            format!("[workspace]\nmembers = ['{member}']\n[workspace.package]\nedition = '2015'\n")
                .as_bytes(),
        );
        fixture.write("crate/Cargo.toml", format!("[package]\nname = 'fixture'\nversion = '0.1.0'\nedition.workspace = true\n{package_workspace}[lib]\nname = 'other'\n[[bin]]\nname = 'renamed'\n").as_bytes());
        fixture.write("crate/src/main.rs", b"fn main() {}\n");
        fixture.write("crate/src/other.rs", b"pub fn other() {}\n");
        fixture.commit();
        fixture.write("crate/src/bin/ignored.rs", b"fn main() {}\n");
        for revision in [false, true] {
            let mut options = fixture.options(if revision { "revision" } else { "worktree" });
            options.revision = revision.then(|| "HEAD".to_owned());
            capture(&options).unwrap();
        }
    }
}

#[test]
fn inferred_binary_names_need_not_be_rust_identifiers() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[package]\nname = 'fixture'\nversion = '0.1.0'\nedition = '2021'\n[[bin]]\nname = 'my.tool'\n[[bin]]\nname = 'a+b'\n");
    fixture.write("src/bin/my.tool.rs", b"fn main() {}\n");
    fixture.write("src/bin/a+b/main.rs", b"fn main() {}\n");
    fixture.commit();
    capture(&fixture.options("snapshot")).unwrap();
}

#[test]
fn validates_cargo_source_directories_relative_to_each_config_root() {
    let fixture = Fixture::new();
    fixture.write(
        "vendor/local/Cargo.toml",
        b"[package]\nname = 'local'\nversion = '0.1.0'\n",
    );
    fixture.write("vendor/local/src/lib.rs", b"pub fn fixture() {}\n");
    fixture.write(
        "vendor/local/.cargo-checksum.json",
        b"{\"files\":{},\"package\":null}\n",
    );
    fixture.write(
        "crate/.cargo/config.toml",
        b"[source.vendored-sources]\ndirectory = '../../external'\n",
    );
    fixture.commit();
    for path in [
        "../../external",
        "/tmp/external",
        "../missing",
        "../LICENSE",
    ] {
        fixture.write(
            "crate/.cargo/config.toml",
            format!("[source.vendored-sources]\ndirectory = '{path}'\n").as_bytes(),
        );
        let failure = error(&fixture.options("snapshot"));
        assert!(failure.contains("source directory"), "{path}: {failure}");
    }
    fixture.write(
        "crate/.cargo/config.toml",
        b"[source.vendored-sources]\ndirectory = '../vendor'\n",
    );
    fixture.commit();
    for revision in [false, true] {
        let mut options = fixture.options(if revision { "revision" } else { "worktree" });
        options.revision = revision.then(|| "HEAD".to_owned());
        capture(&options).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn cargo_entrypoints_follow_captured_symlinks_and_reject_escaping_traversal() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write(
        "Cargo.toml",
        b"[package]\nname = 'fixture'\nversion = '0.1.0'\nbuild = 'entry'\n[lib]\npath = 'entry'\n",
    );
    symlink("src/main.rs", fixture.repo.join("entry")).unwrap();
    fixture.commit();
    capture(&fixture.options("accepted")).unwrap();
    fixture.write("a/outside.rs", b"decoy\n");
    fixture.write("d/file", b"directory marker\n");
    fs::create_dir_all(fixture.repo.join("a/b")).unwrap();
    symlink("../../d", fixture.repo.join("a/b/c")).unwrap();
    fixture.write(
        "Cargo.toml",
        b"[package]\nname = 'fixture'\nversion = '0.1.0'\nbuild = 'a/b/c/../../outside.rs'\n",
    );
    fixture.commit();
    for revision in [false, true] {
        let mut options = fixture.options("rejected");
        options.revision = revision.then(|| "HEAD".to_owned());
        assert!(error(&options).contains("escapes the source checkout"));
        assert!(!options.output.exists());
    }
}

#[test]
fn captures_paths_with_spaces_tabs_and_newlines_without_splitting_records() {
    let fixture = Fixture::new();
    fixture.write("odd name\twith\nnewline.txt", b"exact bytes");
    fixture.commit();
    let options = fixture.options("snapshot");
    capture(&options).unwrap();
    assert_eq!(
        archive_files(&options.output)["odd name\twith\nnewline.txt"],
        b"exact bytes"
    );
}

#[test]
fn revision_capture_ignores_commit_tree_and_blob_replacements() {
    for object in ["", "^{tree}", ":src/main.rs"] {
        let fixture = Fixture::new();
        let original = git(&fixture.repo, &["rev-parse", "HEAD"]).trim().to_owned();
        let mut baseline = fixture.options("baseline");
        baseline.revision = Some(original.clone());
        let expected = capture(&baseline).unwrap();
        fixture.write("src/main.rs", b"replacement bytes\n");
        fixture.commit();
        let old_object = git(
            &fixture.repo,
            &["rev-parse", &format!("{original}{object}")],
        );
        let new_object = git(&fixture.repo, &["rev-parse", &format!("HEAD{object}")]);
        git(
            &fixture.repo,
            &["replace", old_object.trim(), new_object.trim()],
        );
        let mut options = fixture.options("replaced");
        options.revision = Some(original.clone());
        let actual = capture(&options).unwrap();
        assert_eq!(actual.head, original);
        assert_eq!(actual.archive_sha256, expected.archive_sha256, "{object}");
        assert_eq!(
            archive_files(&options.output)["src/main.rs"],
            b"fn main() {}\n",
            "{object}"
        );
    }
}

#[test]
fn worktree_clean_status_ignores_head_replacement() {
    let fixture = Fixture::new();
    let original = git(&fixture.repo, &["rev-parse", "HEAD"]);
    fixture.write("src/main.rs", b"replacement bytes\n");
    fixture.commit();
    let current = git(&fixture.repo, &["rev-parse", "HEAD"]);
    git(&fixture.repo, &["replace", current.trim(), original.trim()]);
    let options = fixture.options("snapshot");
    let receipt = capture(&options).unwrap();
    assert!(!receipt.dirty);
    assert_eq!(receipt.head, current.trim());
    assert_eq!(
        archive_files(&options.output)["src/main.rs"],
        b"replacement bytes\n"
    );
}

#[test]
fn rejects_omitted_workspace_member_manifest_until_explicitly_included() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['local']\n");
    fixture.commit();
    fixture.write(
        "local/Cargo.toml",
        b"[package]\nname = 'local'\nversion = '0.1.0'\n",
    );
    fixture.write("local/src/lib.rs", b"pub fn fixture() {}\n");
    let mut options = fixture.options("snapshot");
    let failure = error(&options);
    assert!(failure.contains("workspace member"), "{failure}");
    assert!(!options.output.exists());
    options.include = vec!["local/Cargo.toml".into(), "local/src/lib.rs".into()];
    capture(&options).unwrap();
    assert!(archive_files(&options.output).contains_key("local/Cargo.toml"));
}

#[test]
fn expands_workspace_globs_in_intermediate_components() {
    let fixture = Fixture::new();
    for name in ["a", "b"] {
        fixture.write(
            &format!("crates/{name}/core/Cargo.toml"),
            format!("[package]\nname = '{name}'\nversion = '0.1.0'\n").as_bytes(),
        );
        fixture.write(&format!("crates/{name}/core/src/lib.rs"), b"");
    }
    fixture.commit();
    for (index, pattern) in [
        "crates/*/core",
        "crates/**/core",
        "crates/[ab]/co?e",
        "./crates/*/core/",
    ]
    .iter()
    .enumerate()
    {
        fixture.write(
            "Cargo.toml",
            format!("[workspace]\nmembers = ['{pattern}']\n").as_bytes(),
        );
        git(&fixture.repo, &["add", "Cargo.toml"]);
        let options = fixture.options(&format!("snapshot-{index}"));
        capture(&options).unwrap();
        assert!(archive_files(&options.output).contains_key("crates/a/core/Cargo.toml"));
    }
}

#[test]
fn workspace_globs_require_manifests_and_do_not_cross_component_boundaries() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crates/*/core']\n");
    fixture.write(
        "crates/a/core/Cargo.toml",
        b"[package]\nname = 'a'\nversion = '0.1.0'\n",
    );
    fixture.write("crates/a/core/src/lib.rs", b"");
    fixture.write("crates/a/nested/core/README", b"not a crate\n");
    fixture.commit();
    capture(&fixture.options("one-component")).unwrap();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crates/**/core']\n");
    let options = fixture.options("recursive");
    let failure = error(&options);
    assert!(failure.contains("workspace member"), "{failure}");
    assert!(failure.contains("Cargo.toml"), "{failure}");
    assert!(!options.output.exists());
}

#[test]
fn cargo_workspace_exclusions_are_literal_prefixes_and_explicit_members_win() {
    let fixture = Fixture::new();
    fixture.write(
        "crates/good/Cargo.toml",
        b"[package]\nname = 'good'\nversion = '0.1.0'\n",
    );
    fixture.write("crates/good/src/lib.rs", b"");
    fixture.write("crates/no-manifest/README", b"not a crate\n");
    fixture.commit();
    for (index, members, exclude, should_pass) in [
        (0, "'crates/*'", "'crates/no-manifest'", true),
        (1, "'crates/*'", "'crates'", true),
        (2, "'crates/*'", "'crates/no-*'", false),
        (3, "'crates/no-manifest'", "'crates/no-manifest'", false),
        (4, "'crates/*', 'crates/no-manifest'", "'crates'", false),
        (5, "'crates/*'", "'./crates/no-manifest'", true),
        (6, "'./crates/no-manifest'", "'crates'", false),
        (7, "'./crates/*'", "'crates/no-manifest'", true),
        (8, "'crates/*'", "'crates/../crates/no-manifest'", false),
    ] {
        fixture.write(
            "Cargo.toml",
            format!("[workspace]\nmembers = [{members}]\nexclude = [{exclude}]\n").as_bytes(),
        );
        git(&fixture.repo, &["add", "Cargo.toml"]);
        let options = fixture.options(&format!("snapshot-{index}"));
        let result = capture(&options);
        assert_eq!(result.is_ok(), should_pass, "{members}: {result:?}");
        assert_eq!(options.output.exists(), should_pass);
    }
}

#[test]
fn rejects_unmatched_invalid_and_escaping_workspace_patterns() {
    let fixture = Fixture::new();
    for (index, member) in ["missing/*", "src/[", "../*", "/tmp/*"].iter().enumerate() {
        fixture.write(
            "Cargo.toml",
            format!("[workspace]\nmembers = ['{member}']\n").as_bytes(),
        );
        git(&fixture.repo, &["add", "Cargo.toml"]);
        let options = fixture.options(&format!("snapshot-{index}"));
        let failure = error(&options);
        assert!(failure.contains("workspace member"), "{failure}");
        assert!(!options.output.exists());
    }
}

#[cfg(unix)]
#[test]
fn expands_cargo_workspace_globs_through_captured_internal_symlinks() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['alias/*/core']\n");
    fixture.write(
        "crates/a/core/Cargo.toml",
        b"[package]\nname = 'a'\nversion = '0.1.0'\n",
    );
    fixture.write("crates/a/core/src/lib.rs", b"");
    symlink("crates", fixture.repo.join("alias")).unwrap();
    fixture.commit();
    capture(&fixture.options("snapshot")).unwrap();
}

#[test]
fn workspace_globs_ignore_existing_files_but_require_captured_member_manifests() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crates/*']\n");
    fixture.write("crates/README", b"workspace notes\n");
    fixture.commit();
    capture(&fixture.options("files-only")).unwrap();
    fixture.write("crates/local/src/lib.rs", b"");
    fixture.commit();
    fixture.write(
        "crates/local/Cargo.toml",
        b"[package]\nname = 'local'\nversion = '0.1.0'\n",
    );
    let options = fixture.options("missing-manifest");
    let failure = error(&options);
    assert!(
        failure.contains("workspace member manifest crates/local/Cargo.toml"),
        "{failure}"
    );
    assert!(!options.output.exists());
}

#[cfg(unix)]
#[test]
fn rejects_recursive_workspace_globs_that_follow_directory_link_cycles() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crates/**/core']\n");
    fixture.write(
        "crates/a/core/Cargo.toml",
        b"[package]\nname = 'a'\nversion = '0.1.0'\n",
    );
    fixture.write("crates/a/core/src/lib.rs", b"");
    symlink(".", fixture.repo.join("crates/a/again")).unwrap();
    fixture.commit();
    let options = fixture.options("snapshot");
    let failure = error(&options);
    assert!(failure.contains("directory symlink cycle"), "{failure}");
    assert!(!options.output.exists());
}

#[test]
fn recursive_workspace_glob_depth_is_bounded() {
    let fixture = Fixture::new();
    fixture.write("Cargo.toml", b"[workspace]\nmembers = ['crates/**/core']\n");
    let path = format!("crates/{}core/Cargo.toml", "nested/".repeat(65));
    fixture.write(&path, b"[package]\nname = 'a'\nversion = '0.1.0'\n");
    fixture.commit();
    let options = fixture.options("snapshot");
    let failure = error(&options);
    assert!(
        failure.contains("exceeds 64 recursive directories"),
        "{failure}"
    );
    assert!(!options.output.exists());
}

#[test]
fn nested_workspace_glob_matching_is_bounded() {
    let fixture = Fixture::new();
    fixture.write(
        "Cargo.toml",
        format!("[workspace]\nmembers = ['{}core']\n", "**/".repeat(256)).as_bytes(),
    );
    fixture.commit();
    let options = fixture.options("snapshot");
    let failure = error(&options);
    assert!(failure.contains("nested matching limit"), "{failure}");
    assert!(!options.output.exists());
}
