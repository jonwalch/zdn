#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use zdn::{
    host::{
        files::Directory,
        runtime::{
            self,
            control::Config,
            lightwallet::{self, Operation},
        },
        volume, S3Object,
    },
    lightwallet_service::{
        cache, native, render_service, LightwalletInstallSpec, INSTALL_API_VERSION,
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

mod container {
    pub fn name(host: &zdn::host::HostInstallSpec) -> String {
        format!("zdn-{}-{}", host.deployment_id, host.node_id)
    }
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn put(path: &Path, bytes: impl AsRef<[u8]>, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn pin(base: &S3Object, name: &str, bytes: &[u8]) -> S3Object {
    let mut p = base.clone();
    p.key = format!("team/test/{name}");
    p.sha256 = hash(bytes);
    p.bytes = bytes.len() as u64;
    p
}

// Real ELF fixture helper, not a script bypassing the helper pin/ELF boundary.
// Only tiny local test-worker compilation occurs; no node/container build.
fn helper() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("main.rs"), r#"
fn main() {
 let exe = std::env::current_exe().unwrap(); let dir = exe.parent().unwrap();
 assert_eq!(std::env::args().nth(1).as_deref(), Some("lightwallet"));
 assert_eq!(std::env::args().nth(2).as_deref(), Some("readiness"));
 std::fs::write(dir.join("readiness-called"), b"yes").unwrap();
 if dir.join("fail").exists() { eprintln!("SECRET-HELPER"); std::process::exit(1); }
 if dir.join("lose-node").exists() { std::fs::write(dir.parent().unwrap().join("volume-claimed.json"), b"wrong").unwrap(); }
 print!("{}", std::fs::read_to_string(dir.join("report")).unwrap());
}
"#).unwrap();
        assert!(Command::new("rustc").args(["--edition=2021", "-C", "debuginfo=0", "-o"]).arg(root.path().join("helper")).arg(root.path().join("main.rs")).status().unwrap().success());
        fs::read(root.path().join("helper")).unwrap()
    })
}

fn runtime() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("zdn");
        fs::copy(env!("CARGO_BIN_EXE_zdn"), &path).unwrap();
        // Keep the real supervisor protocol without hashing debug information
        // during the cancellation fixture's bounded startup wait.
        assert!(Command::new("strip")
            .arg("--strip-debug")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        fs::read(path).unwrap()
    })
}

struct Fixture {
    root: tempfile::TempDir,
    manifest: native::Manifest,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let map = |p: &str| root.path().join(p.trim_start_matches('/'));
        for d in [
            "etc/zdn/artifacts",
            "etc/systemd/system",
            "usr/bin",
            "usr/sbin",
            "dev",
            "var/lib/zdn",
            "run",
        ] {
            fs::create_dir_all(map(d)).unwrap();
        }
        // Only read-only mounted observations use these regular pathname
        // fixtures. Real BlockDevice validation is never bypassed for writes.
        put(&map("dev/nvme0n1"), b"not a block device", 0o600);
        put(&map("dev/nvme1n1"), b"not a block device", 0o600);
        let (mut host, mut service) = fixture::specs();
        let base = host.helper.clone();
        let manifest = include_bytes!("fixtures/chain-manifest/valid.json");
        host.manifest = pin(&base, "node-manifest", manifest);
        host.bundle = pin(&base, "bundle", b"retained seed: never execute");
        host.helper = pin(&base, "helper", helper());
        let node_image_manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json", "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}", "a".repeat(64)),"size":123},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":456}]})).unwrap();
        host.image = format!(
            "{}@sha256:{}",
            host.image.split_once('@').unwrap().0,
            hash(&node_image_manifest)
        );
        let node_record = serde_json::to_vec(&zdn::image::ImageRecord {
            api_version: zdn::image::API_VERSION.into(),
            image: host.image.clone(),
            config_digest: format!("sha256:{}", "a".repeat(64)),
            platform: "linux/amd64".into(),
            provenance: zdn::image::ImageProvenance::Release {
                revision: "d".repeat(40),
                version: "v1.2.3".into(),
            },
            capabilities: Default::default(),
            binary_path: zdn::image::NODE_BINARY.into(),
            environment_launcher: zdn::image::ENV_ENTRYPOINT.into(),
        })
        .unwrap();
        host.image_record = pin(&base, "node-image", &node_record);
        host.image_manifest = pin(&base, "node-image-manifest", &node_image_manifest);
        for (name, bytes) in [
            ("manifest.json", manifest.as_slice()),
            ("chain.tar", b"retained seed: never execute".as_slice()),
            ("zdn", helper()),
            ("image.json", node_record.as_slice()),
            ("image-manifest.json", node_image_manifest.as_slice()),
        ] {
            put(
                &map(&format!("etc/zdn/artifacts/{name}")),
                bytes,
                if name == "zdn" { 0o555 } else { 0o600 },
            );
        }
        let runtime_config = json!({"Env":["PATH=/usr/local/bin:/usr/bin:/bin"],"Entrypoint":["lightwalletd"],"Cmd":["--help"],"WorkingDir":"/srv/lightwalletd"});
        let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux","config":runtime_config,"rootfs":{"type":"layers","diff_ids":[format!("sha256:{}","b".repeat(64))]}})).unwrap();
        let image_manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json", "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hash(&config)),"size":config.len()},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":format!("sha256:{}","b".repeat(64)),"size":456}]})).unwrap();
        service.image = format!(
            "{}@sha256:{}",
            service.image.split_once('@').unwrap().0,
            hash(&image_manifest)
        );
        let record = serde_json::to_vec(&zdn::lightwallet_image::ImageRecord {
            api_version: zdn::lightwallet_image::API_VERSION.into(),
            image: service.image.clone(),
            config_digest: format!("sha256:{}", hash(&config)),
            platform: "linux/amd64".into(),
            source_revision: zdn::lightwallet_image::SOURCE_REVISION.into(),
            source_version: zdn::lightwallet_image::SOURCE_VERSION.into(),
            protocol_revision: zdn::lightwallet_image::PROTOCOL_REVISION.into(),
            protocol_version: zdn::lightwallet_image::PROTOCOL_VERSION.into(),
            binary_path: zdn::lightwallet_image::BINARY_PATH.into(),
            environment_launcher: zdn::lightwallet_image::ENVIRONMENT_LAUNCHER.into(),
        })
        .unwrap();
        let binary = runtime();
        let node_manifest = runtime::Manifest::new(
            host.clone(),
            runtime::Selection {
                protocol: runtime::PROTOCOL.into(),
                helper: pin(&base, "native-runtime", binary),
            },
        )
        .unwrap();
        put(
            &map(&format!(
                "etc/zdn/runtime/{}/zdn",
                node_manifest.runtime.helper.sha256
            )),
            binary,
            0o555,
        );
        put(
            &map("etc/zdn/native-install-intent.json"),
            node_manifest.bytes().unwrap(),
            0o600,
        );
        let manifest = native::Manifest::new(
            LightwalletInstallSpec {
                api_version: INSTALL_API_VERSION.into(),
                new_volume: Some(zdn::host::NewVolumeAuthorization {
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
                image_record: pin(&base, "image.json", &record),
                image_manifest: pin(&base, "image-manifest.json", &image_manifest),
                image_config: pin(&base, "image-config.json", &config),
            },
            node_manifest.clone(),
            runtime::Selection {
                protocol: native::PROTOCOL.into(),
                helper: node_manifest.runtime.helper,
            },
        )
        .unwrap();
        let node_metadata =
            Directory::open(&map("etc/zdn"), root.path().metadata().unwrap().uid()).unwrap();
        let node_installation =
            volume::Installation::acquire(&node_metadata, &manifest.spec.host).unwrap();
        let identity = node_installation.identity().to_vec();
        drop(node_installation);
        for p in [
            "etc/zdn/identity.json",
            "etc/zdn/volume-claimed.json",
            "var/lib/zdn/.zdn-volume.json",
        ] {
            put(&map(p), &identity, 0o600);
        }
        put(
            &map("etc/zdn-prerequisites-ready"),
            b"zdn-host-prerequisites/v1alpha1\n",
            0o600,
        );
        put(&map("manifest"), manifest.bytes().unwrap(), 0o600);
        let rendered = render_service(&manifest.spec.host, &manifest.spec.service).unwrap();
        let uid = root.path().metadata().unwrap().uid();
        let metadata = {
            fs::create_dir(map("etc/zdn-lightwalletd")).unwrap();
            fs::set_permissions(
                map("etc/zdn-lightwalletd"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            Directory::open(&map("etc/zdn-lightwalletd"), uid).unwrap()
        };
        let installation = cache::Installation::acquire_native(&metadata, &manifest).unwrap();
        put(
            &map(&format!(
                "{}/.zdn-lightwalletd-volume.json",
                rendered.cache_root
            )),
            installation.cache_identity(),
            0o600,
        );
        installation
            .record_volume_claim(&Directory::open(&map(&rendered.cache_root), uid).unwrap())
            .unwrap();
        fs::create_dir(map(&format!("{}/data", rendered.cache_root))).unwrap();
        fs::set_permissions(
            map(&format!("{}/data", rendered.cache_root)),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        drop(installation);
        put(
            &map(&format!(
                "{}/{}",
                native::MANIFEST_DIRECTORY,
                manifest.file_name().unwrap()
            )),
            manifest.bytes().unwrap(),
            0o600,
        );
        put(
            &map("etc/systemd/system/zdn-lightwalletd.service"),
            native::unit(&manifest).unwrap(),
            0o644,
        );
        for (name, bytes) in [
            ("image.json", record),
            ("image-manifest.json", image_manifest),
            ("image-config.json", config),
        ] {
            put(
                &map(&format!("etc/zdn-lightwalletd/artifacts/{name}")),
                bytes,
                0o600,
            );
        }
        for dir in [
            "etc/zdn-lightwalletd/artifacts",
            "etc/zdn-lightwalletd/runtime",
            "etc/zdn-lightwalletd/runtime/manifests",
        ] {
            fs::set_permissions(map(dir), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (p, v) in [
            ("proc/meminfo", "MemTotal: 8388608 kB\n"),
            ("proc/self/status", "Cpus_allowed_list: 0-1\n"),
            ("proc/self/cgroup", "0::/leaf\n"),
            ("sys/devices/system/cpu/online", "0-1\n"),
            ("sys/fs/cgroup/memory.max", "max\n"),
            ("sys/fs/cgroup/cpu.max", "max 100000\n"),
            ("sys/fs/cgroup/leaf/memory.max", "max\n"),
            ("sys/fs/cgroup/leaf/cpu.max", "max 100000\n"),
        ] {
            put(&map(p), v, 0o600);
        }
        let host = &manifest.spec.host;
        let node_root = host.node_root();
        let node_container = json!([{"Name":format!("/{}",container::name(host)),"State":{"Running":true},"Config":{"Image":host.image,"Labels":{"zdn.install":manifest.node.install_sha256},"User":"10001:10001","WorkingDir":"/","Entrypoint":["/usr/bin/env"],"Cmd":["-i","PATH=/usr/local/bin:/usr/bin:/bin","HOME=/nonexistent","/usr/local/bin/zakurad","--config",format!("{node_root}/zakura.toml"),"start"],"StopSignal":"SIGINT","Healthcheck":{"Test":["NONE"]}},"HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"PidsLimit":1024,"PidMode":"","LogConfig":{"Type":"journald"},"SecurityOpt":["no-new-privileges"],"Memory":host.memory_bytes,"MemorySwap":host.memory_bytes,"NanoCpus":u64::from(host.cpu_millis)*1_000_000},"Mounts":[{"Type":"bind","Source":node_root,"Destination":node_root,"RW":false},{"Type":"bind","Source":format!("{node_root}/state"),"Destination":format!("{node_root}/state"),"RW":true},{"Type":"bind","Source":format!("{node_root}/identity"),"Destination":format!("{node_root}/identity"),"RW":true},{"Type":"bind","Source":format!("{node_root}/rpc"),"Destination":format!("{node_root}/rpc"),"RW":true}]}]);
        let image_index = rendered
            .docker_arguments
            .iter()
            .position(|a| a == &manifest.spec.service.image)
            .unwrap();
        let light_container = json!({"Id":"c".repeat(64),"Name":format!("/zdn-lightwalletd-{}-{}",host.deployment_id,host.node_id),"State":{"Running":true,"Status":"running"},"Config":{"Image":manifest.spec.service.image,"Labels":{"zdn.lightwalletd":rendered.service_sha256},"User":"10001:10001","WorkingDir":"/","Entrypoint":["/usr/bin/env"],"Cmd":rendered.docker_arguments[image_index+1..],"StopSignal":"SIGTERM","Healthcheck":{"Test":["NONE"]}},"HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"PidsLimit":256,"PidMode":"","LogConfig":{"Type":"journald"},"SecurityOpt":["no-new-privileges"],"Memory":manifest.spec.service.memory_bytes,"MemorySwap":manifest.spec.service.memory_bytes,"NanoCpus":u64::from(manifest.spec.service.cpu_millis)*1_000_000},"Mounts":[{"Type":"bind","Source":map(&format!("{}/data",rendered.cache_root)),"Destination":"/var/lib/lightwalletd","RW":true},{"Type":"bind","Source":map(Path::new(&rendered.credential_path).parent().unwrap().to_str().unwrap()),"Destination":"/run/zdn-lightwalletd","RW":false}]});
        put(&map("state"),json!({"active":false,"present":false,"node":node_container,"container":light_container,"image":[{"Id":format!("sha256:{}",manifest.spec.image_config.sha256),"RepoDigests":[manifest.spec.service.image],"Os":"linux","Architecture":"amd64","Config":runtime_config}],"dropins":"","fragment":"/etc/systemd/system/zdn-lightwalletd.service","mounted":true}).to_string(),0o600);
        put(&map("etc/zdn/artifacts/report"),json!({"apiVersion":"zdn-lightwallet-readiness/v1alpha1","consensusFingerprint":host.consensus_fingerprint,"protocolVersion":"v0.5.0","launchReady":false,"paymentQualification":"pending","ironwoodTreeVerified":true,"compactDataVerified":true,"lagBlocks":0,"checkedCompactBlocks":1}).to_string(),0o600);
        for name in [
            "systemctl",
            "docker",
            "aws",
            "lsblk",
            "findmnt",
            "blkid",
            "wipefs",
            "blockdev",
            "mkfs.ext4",
            "mount",
            "iptables",
            "ip6tables",
        ] {
            native_tool::install(
                &map(&format!("usr/bin/{name}")),
                "worker",
                &json!({"root":root.path(),"name":name}),
            );
        }
        Self { root, manifest }
    }
    fn path(&self, p: &str) -> PathBuf {
        self.root.path().join(p.trim_start_matches('/'))
    }
    fn config(&self) -> Config<'_> {
        let uid = self.root.path().metadata().unwrap().uid();
        Config {
            root: self.root.path(),
            owner: uid,
            node_owner: uid,
        }
    }
    fn run(&self, op: Operation) -> eyre::Result<Option<Value>> {
        lightwallet::dispatch(&self.manifest, self.config(), op, &AtomicBool::new(false))
    }
    fn set(&self, k: &str, v: Value) {
        let p = self.path("state");
        let mut s: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        s[k] = v;
        fs::write(p, s.to_string()).unwrap();
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.path("calls")).unwrap_or_default()
    }
}

#[test]
fn worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    let name = payload["name"].as_str().unwrap();
    if name == "bootstrap" {
        fs::write(root.join("capability-called"), args.join(" ")).unwrap();
        assert_eq!(args[0], "__runtime-capabilities");
        native_tool::reply(&work, b"", b"SECRET-CAPABILITY", 1);
        return;
    }
    let manifest = native::Manifest::from_slice(&fs::read(root.join("manifest")).unwrap()).unwrap();
    let rendered = render_service(&manifest.spec.host, &manifest.spec.service).unwrap();
    let cache = root.join(rendered.cache_root.trim_start_matches('/'));
    let mut state: Value = serde_json::from_slice(&fs::read(root.join("state")).unwrap()).unwrap();
    if state["stall-show"] == true && name == "systemctl" {
        fs::write(root.join("stalled"), b"yes").unwrap();
        thread::sleep(Duration::from_secs(30));
    }
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(root.join("calls"))
            .unwrap(),
        "{name} {args:?}"
    )
    .unwrap();
    let a: Vec<_> = args.iter().map(String::as_str).collect();
    let mut code = 0;
    let out=match (name,a.as_slice()) {
        ("iptables"|"ip6tables",_)=>Vec::new(),
        ("systemctl",["show",_,p]) if p.contains("FragmentPath")=>format!("FragmentPath={}\nDropInPaths={}\nLoadState={}\n",state["fragment"].as_str().unwrap(),state["dropins"].as_str().unwrap(),if state["fragment"]=="" {"not-found"} else {"loaded"}).into_bytes(),
        ("systemctl",["show",..])=>if state["transition"]==true {b"LoadState=loaded\nActiveState=activating\nSubState=start\nMainPID=1\n".to_vec()} else if state["active"]==true {b"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=37\n".to_vec()} else {b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n".to_vec()},
        ("systemctl",["start",_])=>{
            let uid=root.metadata().unwrap().uid();
            for p in ["etc/zdn","etc/zdn-lightwalletd"] { drop(Directory::open(&root.join(p),uid).unwrap().lock("install.lock").unwrap()); }
            // Actual child operation takes both installer locks and its own
            // action executor while the parent's start executor remains held.
            lightwallet::dispatch(&manifest,Config {root,owner:uid,node_owner:uid},Operation::Prepare,&AtomicBool::new(false)).unwrap();
            state["active"]=true.into(); state["present"]=true.into(); Vec::new()
        },
        ("systemctl",["stop",_])=>{if state["fail-stop"]==true {code=1;} else {state["active"]=false.into();} Vec::new()},
        ("systemctl",["daemon-reload"])=>{state["fragment"]="/etc/systemd/system/zdn-lightwalletd.service".into();Vec::new()},
        ("systemctl",["enable"|"reset-failed",..])=>Vec::new(),
        ("docker",["container","inspect",id]) if *id==container::name(&manifest.spec.host)=>serde_json::to_vec(&state["node"]).unwrap(),
        ("docker",["container","ls",..])=>if state["present"]==true {format!("{}\n","c".repeat(64)).into_bytes()} else {Vec::new()},
        ("docker",["container","inspect",_])=>serde_json::to_vec(&json!([state["container"]])).unwrap(),
        ("docker",["stop"|"kill",_,_,id])=>{assert_eq!(*id,"c".repeat(64)); state["present"]=false.into(); Vec::new()},
        ("docker",["container","stop"|"kill"|"rm",id,..])=>{assert_eq!(*id,"c".repeat(64)); state["present"]=false.into();Vec::new()},
        ("docker",["image","inspect",..])=>serde_json::to_vec(&state["image"]).unwrap(),
        ("docker",["--config",_,"login"|"pull",..])=>Vec::new(),
        ("aws",["ecr","get-login-password",..])=>b"SECRET-PASSWORD\n".to_vec(),
        ("aws",_)=>panic!("all image artifacts already pinned; no download expected"),
        ("lsblk",_)=>serde_json::to_vec(&json!({"blockdevices":[{"path":"/dev/nvme0n1","type":"disk","serial":manifest.spec.host.volume_id.replace('-',""),"mountpoints":["/var/lib/zdn"]},{"path":"/dev/nvme1n1","type":"disk","serial":manifest.spec.service.cache_volume_id.replace('-',""),"size":manifest.spec.service.cache_bytes,"maj:min":"259:1","mountpoints":[cache]}]})).unwrap(),
        ("findmnt",[_,"--target",_,..])=>serde_json::to_vec(&json!({"filesystems":[{"source":root.join("dev/nvme0n1"),"target":"/var/lib/zdn","fstype":"ext4"}]})).unwrap(),
        ("findmnt",[_,"--mountpoint",_,..])=>{ if state["mounted"]==false {code=1;Vec::new()} else {serde_json::to_vec(&json!({"filesystems":[{"source":"/dev/nvme1n1","target":cache,"fstype":"ext4","fsroot":"/","maj:min":"259:1","options":"rw,nodev,nosuid,noexec"}]})).unwrap()} },
        _=>panic!("unexpected effect {name} {args:?}"),
    };
    fs::write(root.join("state"), state.to_string()).unwrap();
    native_tool::reply(&work, &out, b"SECRET-TOOL-DIAGNOSTIC", code);
}

#[test]
fn lifecycle_exact_retry_start_child_locks_ready_and_stop() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("lifecycle_exact_retry_start_child_locks_ready_and_stop") else {
        return;
    };
    let f = Fixture::new();
    let stopped = f.run(Operation::Observe).unwrap().unwrap();
    assert_eq!(stopped["status"], "stopped");
    assert_eq!(stopped["readiness"], Value::Null);
    let inode = fs::metadata(f.path("etc/zdn-lightwalletd/identity.json"))
        .unwrap()
        .ino();
    let report = f.run(Operation::Start).unwrap().unwrap();
    assert_eq!(report["status"], "ready");
    assert_eq!(report["paymentQualification"], "pending");
    assert_eq!(report["launchReady"], false);
    assert_eq!(
        fs::metadata(f.path("etc/zdn-lightwalletd/identity.json"))
            .unwrap()
            .ino(),
        inode
    );
    let runtime = f.path(&format!(
        "etc/zdn/runtime/{}/zdn",
        f.manifest.runtime.helper.sha256
    ));
    let report = lightwallet::install(
        &f.manifest,
        f.config(),
        File::open(runtime).unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(report["status"], "ready");
    let report = f.run(Operation::Stop).unwrap().unwrap();
    assert_eq!(report["apiVersion"], "zdn-lightwallet-stop/v1alpha1");
    assert_eq!(report["installSha256"], f.manifest.install_sha256);
    assert!(!f.calls().contains("mkfs"));
    assert!(!f.calls().contains("produce"));
    assert!(!f.path("run/zdn-lightwalletd/credentials").exists());
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.runtime.lightwallet.install",
                "host.runtime.lightwallet.dispatch_install",
                "host.runtime.lightwallet.observe",
                "host.runtime.lightwallet.start",
                "host.runtime.lightwallet.startup",
                "host.runtime.lightwallet.stop",
                "host.runtime.lightwallet.verify_node",
                "host.runtime.lightwallet.verify_cache",
                "host.runtime.lightwallet.observation",
                "lightwallet_runtime.observe_container",
                "lightwallet_runtime.cleanup_container_finite",
                "lightwallet.cache.acquire",
            ],
            &[
                f.root.path().to_str().unwrap(),
                &f.manifest.spec.service.image,
                "SECRET-TOOL-DIAGNOSTIC",
            ],
        );
        trace.assert_child(
            "host.runtime.lightwallet.dispatch_install",
            "host.runtime.lightwallet.install",
        );
        trace.assert_child(
            "lightwallet_runtime.cleanup_container_finite",
            "host.runtime.lightwallet.stop",
        );
        trace.assert_child(
            "host.runtime.lightwallet.observation",
            "host.runtime.lightwallet.startup",
        );
    }
}

#[test]
fn immutable_and_native_boundaries_fail_before_effects() {
    for mode in [
        "cancel",
        "node-intent",
        "pin",
        "marker",
        "unit",
        "legacy-program",
        "dropin",
        "legacy-identity",
    ] {
        let mut f = Fixture::new();
        match mode {
            "node-intent" => put(&f.path("etc/zdn/native-install-intent.json"), b"{}", 0o600),
            "pin" => {
                f.manifest.runtime.helper.sha256 = "f".repeat(64);
            }
            "marker" => put(&f.path("etc/zdn-prerequisites-ready"), b"wrong", 0o600),
            "unit" => put(
                &f.path("etc/systemd/system/zdn-lightwalletd.service"),
                b"foreign",
                0o644,
            ),
            "legacy-program" => put(
                &f.path("usr/local/libexec/zdn-lightwalletd.py"),
                b"legacy",
                0o555,
            ),
            "dropin" => {
                fs::create_dir(f.path("etc/systemd/system/zdn-lightwalletd.service.d")).unwrap()
            }
            "legacy-identity" => {
                fs::remove_file(f.path("etc/zdn-lightwalletd/native-install-intent.json")).unwrap()
            }
            _ => {}
        }
        assert!(
            lightwallet::dispatch(
                &f.manifest,
                f.config(),
                Operation::Install,
                &AtomicBool::new(mode == "cancel")
            )
            .is_err(),
            "{mode}"
        );
        assert_eq!(f.calls(), "", "{mode}");
    }
}

#[test]
fn fresh_claim_image_limits_fragment_stopped_and_helper_gates() {
    for mode in [
        "claim",
        "image",
        "limits",
        "fragment",
        "dropins",
        "transition",
        "stop-failure",
        "helper-failure",
        "qualification",
        "post-node",
        "cache",
    ] {
        let f = Fixture::new();
        let mut op = Operation::Observe;
        match mode {
            "claim" => put(&f.path("etc/zdn/volume-claimed.json"), b"wrong", 0o600),
            "image" => put(
                &f.path("etc/zdn-lightwalletd/artifacts/image.json"),
                b"wrong",
                0o600,
            ),
            "limits" => put(
                &f.path("sys/fs/cgroup/leaf/memory.max"),
                b"134217728\n",
                0o600,
            ),
            "fragment" => f.set("fragment", "/usr/lib/systemd/system/foreign.service".into()),
            "dropins" => f.set("dropins", "/run/systemd/system/foreign.conf".into()),
            "transition" => f.set("transition", true.into()),
            "stop-failure" => {
                f.set("fail-stop", true.into());
                op = Operation::Stop;
            }
            "helper-failure" => put(&f.path("etc/zdn/artifacts/fail"), b"", 0o600),
            "post-node" => put(&f.path("etc/zdn/artifacts/lose-node"), b"", 0o600),
            "qualification" => {
                let path = f.path("etc/zdn/artifacts/report");
                let mut r: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                r["launchReady"] = true.into();
                put(&path, r.to_string(), 0o600);
            }
            "cache" => f.set("mounted", false.into()),
            _ => unreachable!(),
        }
        if matches!(
            mode,
            "helper-failure" | "post-node" | "qualification" | "cache"
        ) {
            f.set("active", true.into());
            f.set("present", true.into());
        }
        let error = f.run(op).unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET"), "{mode}");
        if matches!(mode, "helper-failure" | "post-node" | "qualification") {
            assert!(
                f.path("etc/zdn/artifacts/readiness-called").exists(),
                "readiness was not reached: {mode}: {error:#}"
            );
        }
        if mode == "post-node" {
            assert!(error.to_string().contains("node claim differs"));
        }
        if mode == "stop-failure" {
            assert!(!f.calls().contains("docker"));
        }
    }
}

#[test]
fn cli_capability_canonical_and_no_override_or_install_via_runtime() {
    let bin = env!("CARGO_BIN_EXE_zdn");
    for protocol in [native::PROTOCOL, native::INSTALL_PROTOCOL] {
        assert!(Command::new(bin)
            .args(["__runtime-capabilities", "--require", protocol])
            .status()
            .unwrap()
            .success());
    }
    for args in [
        vec!["__lightwallet-install", "--protocol", "wrong"],
        vec![
            "__lightwallet-runtime",
            "--protocol",
            native::PROTOCOL,
            "--manifest",
            "/tmp/foreign",
            "observe",
        ],
        vec![
            "__lightwallet-runtime",
            "--protocol",
            native::PROTOCOL,
            "--manifest",
            "/tmp/foreign",
            "--root",
            "/tmp",
            "stop",
        ],
    ] {
        let out = Command::new(bin).args(args).output().unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("SECRET"));
    }
    let f = Fixture::new();
    let unit = native::unit(&f.manifest).unwrap();
    let bootstrap = native::bootstrap(&f.manifest).unwrap();
    assert!(unit.contains(" prepare\n"));
    assert!(unit.contains(" serve\n"));
    assert!(!unit.contains("ProtectHome"));
    assert!(!unit.contains("python"));
    assert!(!bootstrap.contains("aws"));
    assert!(!bootstrap.contains("get-object"));
    assert!(bootstrap.contains(native::INSTALL_PROTOCOL));
    assert!(
        native::Manifest::from_slice(&serde_json::to_vec_pretty(&f.manifest).unwrap()).is_err()
    );
    assert!(lightwallet::install(
        &f.manifest,
        f.config(),
        File::open(env!("CARGO_BIN_EXE_zdn")).unwrap(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert_eq!(f.calls(), "");
}

#[test]
fn bootstrap_capability_failure_never_enters_installer() {
    let f = Fixture::new();
    let executable = f.path("fake-runtime");
    native_tool::install(
        &executable,
        "worker",
        &json!({"root":f.root.path(),"name":"bootstrap"}),
    );
    let mut manifest = f.manifest.clone();
    let helper = pin(
        &manifest.runtime.helper,
        "bootstrap-test",
        &fs::read(&executable).unwrap(),
    );
    manifest.runtime.helper = helper.clone();
    manifest.node.runtime.helper = helper;
    // Rewrite only the fixed anchor in this local shell fixture. Production
    // exposes no root/path override in either its recipe or privileged CLI.
    let script = native::bootstrap(&manifest).unwrap().replace(
        &format!(
            "runtime=/etc/zdn/runtime/{}/zdn",
            manifest.runtime.helper.sha256
        ),
        &format!("runtime={}", executable.display()),
    );
    let mut child = Command::new("/bin/bash")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(f.path("capability-called").exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("SECRET"));
    assert_eq!(f.calls(), "");
}

#[test]
fn command_cancellation_is_bounded_and_secret_safe() {
    let f = Fixture::new();
    f.set("stall-show", true.into());
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let result = scope
            .spawn(|| lightwallet::dispatch(&f.manifest, f.config(), Operation::Observe, &stop));
        let until = Instant::now() + Duration::from_secs(20);
        while !f.path("stalled").exists() {
            assert!(Instant::now() < until, "tool did not start");
            thread::sleep(Duration::from_millis(20));
        }
        let started = Instant::now();
        stop.store(true, Ordering::SeqCst);
        let error = result.join().unwrap().unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!format!("{error:#}").contains("SECRET"));
    });
}

#[test]
fn prepare_uses_only_retained_cache_in_named_service_leaf() {
    let f = Fixture::new();
    put(
        &f.path("proc/self/cgroup"),
        "0::/leaf/zdn-lightwalletd.service\n",
        0o600,
    );
    put(
        &f.path("sys/fs/cgroup/leaf/zdn-lightwalletd.service/memory.max"),
        "134217728\n",
        0o600,
    );
    put(
        &f.path("sys/fs/cgroup/leaf/zdn-lightwalletd.service/cpu.max"),
        "10000 100000\n",
        0o600,
    );
    assert!(f.run(Operation::Prepare).unwrap().is_none());
    assert!(!f.calls().contains("mkfs"));
    assert!(!f.calls().contains("start"));
    assert!(!f.path("run/zdn-lightwalletd").exists());
}

#[test]
fn intent_only_retry_publishes_exact_role_manifest_and_unit() {
    let f = Fixture::new();
    let identity = fs::read(f.path("etc/zdn-lightwalletd/identity.json")).unwrap();
    fs::remove_file(f.path("etc/zdn-lightwalletd/identity.json")).unwrap();
    fs::remove_file(f.path("etc/systemd/system/zdn-lightwalletd.service")).unwrap();
    let role = f.path(&format!(
        "{}/{}",
        native::MANIFEST_DIRECTORY,
        f.manifest.file_name().unwrap()
    ));
    fs::remove_file(&role).unwrap();
    f.set("fragment", "".into());
    let report = f.run(Operation::Install).unwrap().unwrap();
    assert_eq!(report["status"], "ready");
    assert_eq!(
        fs::read(f.path("etc/zdn-lightwalletd/identity.json")).unwrap(),
        identity
    );
    assert_eq!(fs::read(role).unwrap(), f.manifest.bytes().unwrap());
    assert_eq!(
        fs::read(f.path("etc/systemd/system/zdn-lightwalletd.service")).unwrap(),
        native::unit(&f.manifest).unwrap().as_bytes()
    );
    assert!(!f.calls().contains("mkfs"));
    assert!(!f.calls().contains("produce"));
}
