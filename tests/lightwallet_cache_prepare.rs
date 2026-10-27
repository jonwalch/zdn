#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use zdn::{
    host::{command::Executor, files::Directory, NewVolumeAuthorization},
    lightwallet_service::{
        cache::{
            prepare::{self, Root, Tools},
            Installation,
        },
        render_service, LightwalletInstallSpec, INSTALL_API_VERSION,
    },
};
#[path = "support/executable.rs"]
mod executable;
#[path = "support/lightwallet_service.rs"]
mod fixture;
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

fn spec() -> LightwalletInstallSpec {
    let (host, service) = fixture::specs();
    let object = |key: &str| {
        let mut o = host.helper.clone();
        o.key = format!("team/test/{key}");
        o
    };
    LightwalletInstallSpec {
        api_version: INSTALL_API_VERSION.into(),
        image_record: object("image"),
        image_manifest: object("manifest"),
        image_config: object("config"),
        new_volume: Some(NewVolumeAuthorization {
            api_version: zdn::host::NEW_VOLUME_API_VERSION.into(),
            volume_id: service.cache_volume_id.clone(),
            size_bytes: service.cache_bytes,
            instance_id: "i-0123456789abcdef0".into(),
            created_at: "2026-10-16T12:00:00Z".into(),
            creation_intent_sha256: "d".repeat(64),
            checkpoint_sha256: "e".repeat(64),
        }),
        host,
        service,
    }
}
struct Fixture {
    root: tempfile::TempDir,
    spec: LightwalletInstallSpec,
    cache: PathBuf,
    tools: Tools,
}
impl Fixture {
    fn new(mounted: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let spec = spec();
        let cache = root.path().join(
            render_service(&spec.host, &spec.service)
                .unwrap()
                .cache_root
                .trim_start_matches('/'),
        );
        fs::create_dir_all(&cache).unwrap();
        for p in ["metadata", "commands", "dev"] {
            fs::create_dir(root.path().join(p)).unwrap();
            fs::set_permissions(root.path().join(p), fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.path().join("dev/nvme1n1"), b"not a block device").unwrap();
        fs::write(root.path().join("state"), json!({"mounted":mounted,"blank":false,"fail_mount":false,"bad_fresh":false,"changed":false,"calls":0,"disk":{},"mount":{},"signatures":[],"size":spec.service.cache_bytes}).to_string()).unwrap();
        let tool = |name| {
            let path = root.path().join(name);
            native_tool::install(
                &path,
                "worker",
                &json!({"root":root.path(),"tool":name,"cache":cache,"serial":spec.service.cache_volume_id.replace('-',""),"size":spec.service.cache_bytes}),
            );
            path
        };
        let tools = Tools {
            lsblk: tool("lsblk"),
            findmnt: tool("findmnt"),
            blkid: tool("blkid"),
            wipefs: tool("wipefs"),
            blockdev: tool("blockdev"),
            mount: tool("mount"),
            mkfs_ext4: tool("mkfs"),
        };
        Self {
            root,
            spec,
            cache,
            tools,
        }
    }
    fn state(&self, key: &str, value: Value) {
        let path = self.root.path().join("state");
        let mut s: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        s[key] = value;
        fs::write(path, s.to_string()).unwrap();
    }
    fn run(&self, record: &str, allow: bool, cancelled: bool) -> bool {
        let uid = self.root.path().metadata().unwrap().uid();
        let metadata = Directory::open(&self.root.path().join("metadata"), uid).unwrap();
        let mut installation = Installation::acquire(&metadata, &self.spec).unwrap();
        assert!(Installation::acquire(&metadata, &self.spec).is_err());
        match record {
            "intent" => installation.begin_format().unwrap(),
            "claim" => {
                let mounted = Directory::open(&self.cache, uid).unwrap();
                mounted
                    .publish(
                        ".zdn-lightwalletd-volume.json",
                        installation.cache_identity(),
                        0o600,
                    )
                    .unwrap();
                installation.record_volume_claim(&mounted).unwrap();
            }
            "saved" => {
                metadata
                    .publish("volume-claimed.json", installation.cache_identity(), 0o600)
                    .unwrap();
                // Simulate the retained on-volume record appearing only after
                // the fixture mount, never in the empty pre-mount directory.
                fs::write(
                    self.root.path().join("claim_bytes"),
                    installation.cache_identity(),
                )
                .unwrap();
            }
            "foreign-saved" => {
                metadata
                    .publish("volume-claimed.json", b"foreign", 0o600)
                    .unwrap();
            }
            "foreign" => {
                metadata
                    .publish("format-intent.json", b"foreign", 0o600)
                    .unwrap();
            }
            "foreign-mounted" => {
                Directory::open(&self.cache, uid)
                    .unwrap()
                    .publish(".zdn-lightwalletd-volume.json", b"foreign", 0o600)
                    .unwrap();
            }
            _ => {}
        }
        let mut executor = Executor::new(
            PathBuf::from(env!("CARGO_BIN_EXE_zdn")),
            self.root.path().join("commands"),
            "us-east-1".into(),
            Instant::now() + Duration::from_secs(90),
        )
        .unwrap();
        prepare::prepare(
            &self.spec,
            Root {
                path: self.root.path(),
                owner: uid,
                node_owner: uid,
            },
            &self.tools,
            &mut installation,
            &mut executor,
            &AtomicBool::new(cancelled),
            allow,
        )
        .is_ok()
    }
}

#[test]
fn worker() {
    let Some((work, _, p)) = native_tool::invocation() else {
        return;
    };
    let root = PathBuf::from(p["root"].as_str().unwrap());
    let path = root.join("state");
    let mut s: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut code = 0;
    let output = match p["tool"].as_str().unwrap() {
        "lsblk" => {
            let calls = s["calls"].as_u64().unwrap() + 1;
            s["calls"] = json!(calls);
            let mut d = json!({"path":"/dev/nvme1n1","type":"disk","serial":p["serial"],"size":p["size"],"maj:min":"259:1","mountpoints": if s["mounted"]==true {json!([p["cache"]])} else {json!([null])}});
            for (k, v) in s["disk"].as_object().unwrap() {
                d[k] = v.clone();
            }
            if s["changed"] == true && calls > 1 {
                d["maj:min"] = json!("259:2");
            }
            json!({"blockdevices":[d]}).to_string()
        }
        "findmnt" => {
            if s["mounted"] != true {
                code = 1;
                String::new()
            } else {
                let mut m = json!({"source":"/dev/nvme1n1","target":p["cache"],"fstype":"ext4","fsroot":"/","maj:min":"259:1","options":"rw,nodev,nosuid,noexec"});
                for (k, v) in s["mount"].as_object().unwrap() {
                    m[k] = v.clone();
                }
                json!({"filesystems":[m]}).to_string()
            }
        }
        "blkid" => {
            if s["blank"] == true {
                code = 2;
                String::new()
            } else {
                s["filesystem"].as_str().unwrap_or("TYPE=ext4\n").into()
            }
        }
        "wipefs" => json!({"signatures":s["signatures"]}).to_string(),
        "blockdev" => s["size"].to_string(),
        "mount" => {
            s["mount_called"] = json!(true);
            if s["fail_mount"] == true {
                code = 1;
            } else if s["bad_fresh"] != true {
                s["mounted"] = json!(true);
                if root.join("claim_bytes").exists() {
                    let uid = root.metadata().unwrap().uid();
                    let mounted =
                        Directory::open(&PathBuf::from(p["cache"].as_str().unwrap()), uid).unwrap();
                    mounted
                        .publish(
                            ".zdn-lightwalletd-volume.json",
                            &fs::read(root.join("claim_bytes")).unwrap(),
                            0o600,
                        )
                        .unwrap();
                }
            }
            String::new()
        }
        "mkfs" => {
            s["mkfs_called"] = json!(true);
            String::new()
        }
        _ => panic!("unknown tool"),
    };
    fs::write(path, s.to_string()).unwrap();
    native_tool::reply(&work, output.as_bytes(), b"", code);
}

#[test]
fn mounted_claim_and_first_claim() {
    for record in ["claim", "intent"] {
        let f = Fixture::new(true);
        if record == "intent" {
            fs::create_dir(f.cache.join("lost+found")).unwrap();
        }
        assert!(f.run(record, record == "intent", false));
        assert!(f.cache.join("data").is_dir());
        assert_eq!(
            f.cache.join("data").metadata().unwrap().mode() & 0o777,
            0o700
        );
    }
}
#[test]
fn ext4_retry_and_recovery() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("ext4_retry_and_recovery") else {
        return;
    };
    for record in ["intent", "saved"] {
        let f = Fixture::new(false);
        assert!(f.run(record, record == "intent", false));
        #[cfg(feature = "profiling")]
        {
            trace.assert_spans(
                &[
                    "lightwallet.cache.acquire",
                    "lightwallet.cache.prepare",
                    "lightwallet.cache.observe",
                    "lightwallet.cache.prepare.mount",
                    "lightwallet.cache.claim_mounted",
                ],
                &[
                    f.root.path().to_str().unwrap(),
                    &f.spec.service.cache_volume_id,
                ],
            );
            trace.assert_child(
                "lightwallet.cache.prepare.mount",
                "lightwallet.cache.prepare",
            );
            trace.assert_child(
                "lightwallet.cache.claim_mounted",
                "lightwallet.cache.prepare",
            );
        }
    }
}
#[test]
fn missing_foreign_nonempty_and_restart_rejected() {
    for (mounted, record, allow, nonempty) in [
        (true, "", true, false),
        (true, "foreign", true, false),
        (true, "foreign-mounted", true, false),
        (false, "", true, false),
        (false, "foreign", true, false),
        (false, "foreign-saved", true, false),
        (false, "intent", false, false),
        (false, "intent", true, true),
        (true, "intent", true, true),
    ] {
        let f = Fixture::new(mounted);
        if nonempty {
            fs::write(f.cache.join("foreign"), b"data").unwrap();
        }
        assert!(!f.run(record, allow, false));
    }
}
#[test]
fn bad_attachment_and_mounts() {
    for (kind, key, value) in [
        ("disk", "serial", json!("volforeign")),
        ("disk", "size", json!(1)),
        ("disk", "path", json!("/dev/sda")),
        ("disk", "children", json!([{}])),
        ("disk", "mountpoints", json!(["/elsewhere"])),
        ("mount", "source", json!("/dev/nvme2n1")),
        ("mount", "target", json!("/elsewhere")),
        ("mount", "fstype", json!("xfs")),
        ("mount", "maj:min", json!("259:2")),
        ("mount", "fsroot", json!("/sub")),
        ("mount", "options", json!("ro,nodev,nosuid,noexec")),
    ] {
        let f = Fixture::new(true);
        f.state(kind, json!({key:value}));
        assert!(!f.run("claim", true, false), "{kind} {key}");
    }
}
#[test]
fn failed_mount_fresh_check_and_changed_attachment() {
    for flag in ["fail_mount", "bad_fresh", "changed"] {
        let f = Fixture::new(false);
        f.state(flag, json!(true));
        assert!(!f.run("intent", true, false));
    }
}
#[test]
fn filesystem_and_blank_disk_guards() {
    for filesystem in [
        "TYPE=xfs\n",
        "TYPE=ext4\nPTTYPE=gpt\n",
        "TYPE=ext4\nTYPE=ext4\n",
    ] {
        let f = Fixture::new(false);
        f.state("filesystem", json!(filesystem));
        assert!(!f.run("intent", true, false));
    }
    for (key, value) in [
        ("signatures", json!([{"type":"gpt"}])),
        ("size", json!(1)),
        ("blank", json!(true)),
    ] {
        let f = Fixture::new(false);
        f.state("blank", json!(true));
        f.state(key, value);
        assert!(!f.run("", true, false));
        let s: Value =
            serde_json::from_slice(&fs::read(f.root.path().join("state")).unwrap()).unwrap();
        assert!(s["mkfs_called"].is_null());
        assert!(!f.root.path().join("metadata/format-intent.json").exists());
    }
}
#[test]
fn cancellation_and_complete_spec_binding() {
    let f = Fixture::new(true);
    assert!(!f.run("claim", true, true));
    let uid = f.root.path().metadata().unwrap().uid();
    let d = Directory::open(&f.root.path().join("metadata"), uid).unwrap();
    let mut installation = Installation::acquire(&d, &f.spec).unwrap();
    let mut other = f.spec.clone();
    other.image_config.sha256 = "f".repeat(64);
    let before = fs::read(f.root.path().join("state")).unwrap();
    let mut executor = Executor::new(
        PathBuf::from(env!("CARGO_BIN_EXE_zdn")),
        f.root.path().join("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(90),
    )
    .unwrap();
    // The retained claim is otherwise usable: changing only image metadata
    // must fail at the public preparation boundary, before any tool effects.
    assert!(prepare::prepare(
        &other,
        Root {
            path: f.root.path(),
            owner: uid,
            node_owner: uid,
        },
        &f.tools,
        &mut installation,
        &mut executor,
        &AtomicBool::new(false),
        false,
    )
    .is_err());
    assert_eq!(fs::read(f.root.path().join("state")).unwrap(), before);
    assert!(!f.cache.join("data").exists());
}

#[test]
fn blank_disk_uncertainty_never_reformats_and_regular_files_never_authorize() {
    for record in ["intent", "saved", "foreign", ""] {
        let f = Fixture::new(false);
        f.state("blank", json!(true));
        assert!(!f.run(record, true, false));
        let s: Value =
            serde_json::from_slice(&fs::read(f.root.path().join("state")).unwrap()).unwrap();
        assert!(s["mkfs_called"].is_null());
        assert!(s["mount_called"].is_null());
        if record.is_empty() {
            // All read-only probes succeed; actual BlockDevice rejects the
            // regular file before writing durable intent or invoking mkfs.
            assert!(zdn::host::volume::device::BlockDevice::open(
                &f.root.path().join("dev/nvme1n1")
            )
            .is_err());
            assert!(!f.root.path().join("metadata/format-intent.json").exists());
        }
    }
}
