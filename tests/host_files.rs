#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use zdn::host::files::{ArtifactDigest, Directory};

fn fixture() -> (tempfile::TempDir, Directory) {
    let root = tempfile::tempdir().unwrap();
    let owner = fs::metadata(root.path()).unwrap().uid();
    let directory = Directory::open(root.path(), owner).unwrap();
    (root, directory)
}

fn mode(path: impl AsRef<std::path::Path>, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

#[test]
fn immutable_publication_and_streamed_artifact_identity() {
    let (root, directory) = fixture();
    let child = directory.ensure_directory("artifacts", 0o750).unwrap();
    directory.ensure_directory("artifacts", 0o750).unwrap();
    assert!(directory.ensure_directory("artifacts", 0o700).is_err());
    assert_eq!(
        fs::metadata(root.path().join("artifacts")).unwrap().mode() & 0o777,
        0o750
    );
    child.publish("helper", b"abc", 0o555).unwrap();
    let metadata = fs::metadata(root.path().join("artifacts/helper")).unwrap();
    child.publish("helper", b"abc", 0o555).unwrap();
    assert_eq!(
        metadata.ino(),
        fs::metadata(root.path().join("artifacts/helper"))
            .unwrap()
            .ino()
    );
    for (contents, permissions) in [(b"abd".as_slice(), 0o555), (b"ab", 0o555), (b"abc", 0o600)] {
        assert!(child.publish("helper", contents, permissions).is_err());
    }
    assert_eq!(child.read("helper", 3).unwrap(), b"abc");
    assert!(child.read("helper", 2).is_err());
    assert_eq!(
        child.digest("helper", 3).unwrap(),
        ArtifactDigest {
            bytes: 3,
            // Independently checked with GNU sha256sum, not production hashing.
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            prefix: b"abc".to_vec(),
        }
    );
    let mut bundle = vec![b'x'; 65537];
    for (index, byte) in bundle[..64].iter_mut().enumerate() {
        *byte = index as u8;
    }
    bundle[65536] = b'z';
    child.publish("bundle", &bundle, 0o600).unwrap();
    assert_eq!(
        child.digest("bundle", 65537).unwrap(),
        ArtifactDigest {
            bytes: 65537,
            sha256: "1bc5b188b38f3227bd602e7978e6b20532cb3009be1beb1c7d4fb60f59aa90c9".into(),
            prefix: (0_u8..64).collect(),
        }
    );
    assert!(child.digest("bundle", 65536).is_err());
    let mut changed = bundle.clone();
    changed[1] = b'y'; // A later matching chunk must not erase an early mismatch.
    assert!(child.publish("bundle", &changed, 0o600).is_err());
    assert_eq!(child.read("bundle", 65537).unwrap(), bundle);
    child.publish("empty", b"", 0o600).unwrap();
    assert_eq!(child.read("empty", 0).unwrap(), b"");
    assert_eq!(child.digest("empty", u64::MAX).unwrap().bytes, 0);
    assert_eq!(
        fs::read_dir(root.path().join("artifacts")).unwrap().count(),
        3
    );
}

#[test]
fn rejects_untrusted_paths_modes_and_owners_without_repair() {
    let (root, directory) = fixture();
    let owner = fs::metadata(root.path()).unwrap().uid();
    assert!(Directory::open(root.path(), owner + 1).is_err());
    for name in ["", ".", "..", "a/b", "/escape", "x\0y", "trailing/"] {
        assert!(directory.ensure_directory(name, 0o700).is_err());
        assert!(directory.publish(name, b"x", 0o600).is_err());
        assert!(directory.read(name, 10).is_err());
    }
    for permissions in [0o666, 0o620, 0o100600, 0o4600] {
        assert!(directory
            .publish("invalid", b"secret", permissions)
            .is_err());
        assert!(directory.ensure_directory("invalid", permissions).is_err());
    }
    fs::write(root.path().join("unsafe"), b"unchanged").unwrap();
    mode(root.path().join("unsafe"), 0o666);
    assert!(directory.read("unsafe", 100).is_err());
    assert!(directory.publish("unsafe", b"unchanged", 0o600).is_err());
    assert_eq!(
        fs::metadata(root.path().join("unsafe")).unwrap().mode() & 0o777,
        0o666
    );
    fs::create_dir(root.path().join("writable")).unwrap();
    mode(root.path().join("writable"), 0o777);
    assert!(directory.open_directory("writable").is_err());
    assert!(directory.ensure_directory("writable", 0o700).is_err());
    directory.publish("safe", b"secret", 0o600).unwrap();
    directory.ensure_directory("safe-directory", 0o700).unwrap();
    symlink("missing", root.path().join("dangling")).unwrap();
    // Otherwise-valid targets make missing O_NOFOLLOW observably wrong.
    symlink("safe", root.path().join("alias")).unwrap();
    symlink("safe-directory", root.path().join("dir-alias")).unwrap();
    for name in ["alias", "dangling", "dir-alias", "writable"] {
        assert!(directory.read(name, 100).is_err());
        assert!(directory.digest(name, 100).is_err());
        assert!(directory.publish(name, b"secret", 0o600).is_err());
    }
    assert!(directory.open_directory("dir-alias").is_err());
    assert!(directory.ensure_directory("dir-alias", 0o700).is_err());
    assert!(Directory::open(&root.path().join("dir-alias"), owner).is_err());
    assert!(!root.path().join("missing").exists());
    assert_eq!(fs::read(root.path().join("unsafe")).unwrap(), b"unchanged");
    mode(root.path(), 0o777);
    assert!(Directory::open(root.path(), owner).is_err());
    mode(root.path(), 0o700);
}

#[test]
fn directory_descriptors_cannot_be_redirected_by_path_replacement() {
    let (root, directory) = fixture();
    let child = directory.ensure_directory("selected", 0o700).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::rename(root.path().join("selected"), root.path().join("original")).unwrap();
    symlink(outside.path(), root.path().join("selected")).unwrap();
    child.publish("claim", b"identity", 0o600).unwrap();
    assert_eq!(
        fs::read(root.path().join("original/claim")).unwrap(),
        b"identity"
    );
    assert!(!outside.path().join("claim").exists());
    assert!(directory.open_directory("selected").is_err());
}

#[test]
fn concurrent_publishers_only_accept_the_complete_winning_identity_and_mode() {
    let (root, directory) = fixture();
    let directory = Arc::new(directory);
    let gate = Arc::new(Barrier::new(6));
    let handles: Vec<_> = (0..6)
        .map(|index| {
            let directory = Arc::clone(&directory);
            let gate = Arc::clone(&gate);
            thread::spawn(move || {
                let contents = vec![b'a' + (index % 2) as u8; 65537];
                let mode = if index < 3 { 0o600 } else { 0o400 };
                gate.wait();
                (
                    directory.publish("claim", &contents, mode).is_ok(),
                    contents,
                    mode,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    let bytes = fs::read(root.path().join("claim")).unwrap();
    let permissions = fs::metadata(root.path().join("claim")).unwrap().mode() & 0o777;
    assert!(results.iter().any(|(success, _, _)| *success));
    for (success, contents, mode) in results {
        assert_eq!(success, contents == bytes && mode == permissions);
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn special_files_are_rejected_without_waiting_for_a_writer() {
    const WORKER: &str = "ZDN_HOST_FILES_FIFO_WORKER";
    if std::env::var_os(WORKER).is_some() {
        let (root, directory) = fixture();
        nix::unistd::mkfifo(&root.path().join("fifo"), nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(directory.read("fifo", 100).is_err());
        assert!(directory.digest("fifo", 100).is_err());
        assert!(directory.publish("fifo", b"x", 0o600).is_err());
        assert!(directory.lock("fifo").is_err());
        assert!(directory.require_absent("fifo").is_err());
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "special_files_are_rejected_without_waiting_for_a_writer",
        ])
        .env(WORKER, "1")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("trusted host file open blocked on a FIFO");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn host_operation_lock_is_shared_and_released() {
    const WORKER: &str = "ZDN_HOST_LOCK_WORKER";
    if let Some(root) = std::env::var_os(WORKER) {
        let root = std::path::Path::new(&root);
        let directory = Directory::open(root, fs::metadata(root).unwrap().uid()).unwrap();
        assert_eq!(
            directory.lock("install.lock").is_err(),
            std::env::var_os("EXPECT_BUSY").is_some()
        );
        return;
    }
    let (root, directory) = fixture();
    let worker = |busy: bool| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "host_operation_lock_is_shared_and_released"])
            .env(WORKER, root.path())
            .env_remove("EXPECT_BUSY");
        if busy {
            command.env("EXPECT_BUSY", "1");
        }
        assert!(command.status().unwrap().success());
    };
    let lock = directory.lock("install.lock").unwrap();
    let inode = fs::metadata(root.path().join("install.lock"))
        .unwrap()
        .ino();
    assert!(directory.lock("install.lock").is_err());
    // Historical Python uses flock(LOCK_EX | LOCK_NB) on this same inode.
    let historical = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join("install.lock"))
        .unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&historical).is_err());
    worker(true);
    drop(lock);
    worker(false);
    fs2::FileExt::try_lock_exclusive(&historical).unwrap();
    assert!(directory.lock("install.lock").is_err());
    fs2::FileExt::unlock(&historical).unwrap();
    drop(directory.lock("install.lock").unwrap());
    assert_eq!(
        fs::metadata(root.path().join("install.lock"))
            .unwrap()
            .ino(),
        inode
    );
}

#[test]
fn lock_and_absence_checks_reject_unsafe_entries_without_mutating_them() {
    let (root, directory) = fixture();
    directory.require_absent("missing").unwrap();
    assert!(!root.path().join("missing").exists());
    directory.publish("safe", b"unchanged", 0o600).unwrap();
    directory.ensure_directory("directory", 0o700).unwrap();
    symlink("safe", root.path().join("symlink")).unwrap();
    symlink("missing", root.path().join("dangling")).unwrap();
    fs::hard_link(root.path().join("safe"), root.path().join("hardlink")).unwrap();
    for name in ["safe", "directory", "symlink", "dangling", "hardlink"] {
        assert!(directory.require_absent(name).is_err());
        assert!(directory.lock(name).is_err(), "{name}");
    }
    for name in ["", ".", "..", "a/b", "x\0y"] {
        assert!(directory.lock(name).is_err());
        assert!(directory.require_absent(name).is_err());
    }
    directory
        .publish("permissions", b"unchanged", 0o400)
        .unwrap();
    for value in [0o400, 0o640, 0o660, 0o4600] {
        mode(root.path().join("permissions"), value);
        assert!(directory.lock("permissions").is_err());
        assert_eq!(
            fs::metadata(root.path().join("permissions"))
                .unwrap()
                .mode()
                & 0o7777,
            value
        );
    }
    assert_eq!(fs::read(root.path().join("safe")).unwrap(), b"unchanged");
    assert!(!root.path().join("missing").exists());
}
