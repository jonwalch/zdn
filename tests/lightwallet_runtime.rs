#![cfg(target_os = "linux")]

#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{command::Executor, HostInstallSpec, S3Object},
    infra::HostObservation,
    lightwallet_service::{
        render_service,
        runtime::{cleanup_container, observe_container, supervise, RuntimeConfig, Tools},
        LightwalletServiceSpec, API_VERSION, SOURCE_REVISION,
    },
};

const GIB: u64 = 1024 * 1024 * 1024;
const COOKIE: &str = "__cookie__:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn specs() -> (HostInstallSpec, LightwalletServiceSpec) {
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let id = "12345678-1234-4123-8123-123456789abc".parse().unwrap();
    let mut options = RuntimeOptions::new(id, "node-2");
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
    let host = HostInstallSpec {
        api_version: zdn::host::API_VERSION.into(),
        deployment_id: id,
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
    };
    let service = LightwalletServiceSpec {
        api_version: API_VERSION.into(),
        source_revision: SOURCE_REVISION.into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/lightwalletd@sha256:{}",
            "c".repeat(64)
        ),
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
    };
    (host, service)
}

fn write(path: &Path, bytes: impl AsRef<[u8]>, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

struct Fixture {
    root: tempfile::TempDir,
    host: HostInstallSpec,
    service: LightwalletServiceSpec,
    cache: PathBuf,
    credential: PathBuf,
    cookie: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (host, service) = specs();
        let rendered = render_service(&host, &service).unwrap();
        let map = |s: &str| root.path().join(s.trim_start_matches('/'));
        let cache = map(&rendered.cache_root);
        let credential = map(&rendered.credential_path);
        let cookie = map(&format!("{}/rpc/.cookie", host.node_root()));
        write(
            &cache.join(".zdn-lightwalletd-volume.json"),
            &rendered.cache_identity_json,
            0o600,
        );
        fs::create_dir(cache.join("data")).unwrap();
        fs::set_permissions(cache.join("data"), fs::Permissions::from_mode(0o700)).unwrap();
        write(&cache.join("data/retained"), "durable cache", 0o600);
        write(&cookie, COOKIE, 0o600);
        fs::set_permissions(cookie.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        let install_hash = hex::encode(Sha256::digest(serde_json::to_vec(&host).unwrap()));
        write(
            &map("/etc/zdn/volume-claimed.json"),
            serde_json::to_vec(&json!({"apiVersion":"zdn-host-volume/v1alpha1",
            "deploymentId":host.deployment_id,"nodeId":host.node_id,"volumeId":host.volume_id,
            "consensusFingerprint":host.consensus_fingerprint,"installSha256":install_hash}))
            .unwrap(),
            0o600,
        );
        let kernel = root.path().join("kernel");
        for (path, value) in [
            ("proc/meminfo", "MemTotal:       8388608 kB\n"),
            ("proc/self/status", "Cpus_allowed_list:\t0-1\n"),
            ("sys/devices/system/cpu/online", "0-1\n"),
            (
                "proc/self/cgroup",
                "0::/system.slice/zdn-lightwalletd.service\n",
            ),
            ("sys/fs/cgroup/memory.max", "max\n"),
            ("sys/fs/cgroup/cpu.max", "max 100000\n"),
            ("sys/fs/cgroup/system.slice/memory.max", "8589934592\n"),
            ("sys/fs/cgroup/system.slice/cpu.max", "200000 100000\n"),
            (
                "sys/fs/cgroup/system.slice/zdn-lightwalletd.service/memory.max",
                "134217728\n",
            ),
            (
                "sys/fs/cgroup/system.slice/zdn-lightwalletd.service/cpu.max",
                "10000 100000\n",
            ),
        ] {
            write(&kernel.join(path), value, 0o600);
        }
        let node = json!([{"State":{"Running":true},"Config":{"Image":host.image,"Labels":{"zdn.install":install_hash}},
            "HostConfig":{"Memory":host.memory_bytes,"MemorySwap":host.memory_bytes,"NanoCpus":u64::from(host.cpu_millis)*1_000_000}}]);
        let survivor = json!({"Id":"d".repeat(64),"Name":format!("/zdn-lightwalletd-{}-{}",host.deployment_id,host.node_id),
            "State":{"Running":true},"Config":{"Image":service.image,"Labels":{"zdn.lightwalletd":rendered.service_sha256}}});
        let config = json!({"node":node,"survivor":survivor,"credential":credential,
            "image":[{"Os":"linux","Architecture":"amd64","RepoDigests":[service.image]}],
            "lsblk":{"blockdevices":[{"path":"/dev/nvme9n1","type":"disk","serial":service.cache_volume_id.replace('-',""),"size":service.cache_bytes,"maj:min":"259:9","mountpoints":[cache]}]},
            "findmnt":{"filesystems":[{"source":"/dev/nvme9n1","target":cache,"fstype":"ext4","fsroot":"/","maj:min":"259:9","options":"rw,nodev,nosuid,noexec"}]}});
        write(
            &root.path().join("worker.json"),
            serde_json::to_vec(&config).unwrap(),
            0o600,
        );
        for tool in ["docker", "lsblk", "findmnt", "iptables", "ip6tables"] {
            native_tool::install(
                &root.path().join(tool),
                "runtime_tool_worker",
                &json!({"root":root.path(),"tool":tool}),
            );
        }
        Self {
            root,
            host,
            service,
            cache,
            credential,
            cookie,
        }
    }
    fn config(&self) -> RuntimeConfig {
        let uid = self.root.path().metadata().unwrap().uid();
        RuntimeConfig {
            host: self.host.clone(),
            service: self.service.clone(),
            filesystem_root: self.root.path().into(),
            kernel_root: self.root.path().join("kernel"),
            root_uid: uid,
            node_uid: uid,
            node_gid: self.root.path().metadata().unwrap().gid(),
            tools: Tools {
                docker: self.path("docker"),
                lsblk: self.path("lsblk"),
                findmnt: self.path("findmnt"),
                iptables: self.path("iptables"),
                ip6tables: self.path("ip6tables"),
                supervisor: env!("CARGO_BIN_EXE_zdn").into(),
            },
            poll_interval: Duration::from_millis(20),
        }
    }
    fn path(&self, path: &str) -> PathBuf {
        self.root.path().join(path)
    }
    fn finite(&self, budget: Duration) -> Executor {
        self.flag("finite");
        let directory = self.path("finite-commands");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            directory,
            "us-east-1".into(),
            Instant::now() + budget,
        )
        .unwrap()
    }
    fn valid_container(&self) {
        let rendered = render_service(&self.host, &self.service).unwrap();
        let image = rendered
            .docker_arguments
            .iter()
            .position(|v| v == &self.service.image)
            .unwrap();
        self.mutate(|v| {
            let c = &mut v["survivor"];
            c["Config"]["User"] = json!("10001:10001");
            c["Config"]["WorkingDir"] = json!("/");
            c["Config"]["Entrypoint"] = json!(["/usr/bin/env"]);
            c["Config"]["Cmd"] = json!(&rendered.docker_arguments[image + 1..]);
            c["Config"]["StopSignal"] = json!("SIGTERM");
            c["Config"]["Healthcheck"] = json!({"Test":["NONE"]});
            c["HostConfig"] = json!({"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,
                "CapAdd":null,"CapDrop":["ALL"],"PidsLimit":256,"PidMode":"","LogConfig":{"Type":"journald"},
                "SecurityOpt":["no-new-privileges"],"Memory":self.service.memory_bytes,
                "MemorySwap":self.service.memory_bytes,"NanoCpus":u64::from(self.service.cpu_millis)*1_000_000});
            c["Mounts"] = json!([
                {"Type":"bind","Source":self.cache.join("data"),"Destination":"/var/lib/lightwalletd","RW":true},
                {"Type":"bind","Source":self.credential.parent().unwrap(),"Destination":"/run/zdn-lightwalletd","RW":false},
                {"Type":"tmpfs","Destination":"/tmp","RW":true}]);
        });
    }
    fn mutate(&self, change: impl FnOnce(&mut Value)) {
        let path = self.path("worker.json");
        let mut value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut value);
        write(&path, serde_json::to_vec(&value).unwrap(), 0o600);
    }
    fn flag(&self, flag: &str) {
        write(&self.path(flag), "1", 0o600);
    }
    fn log(&self) -> String {
        fs::read_to_string(self.path("calls")).unwrap_or_default()
    }
    fn failed(&self) {
        let error = supervise(self.config(), &AtomicBool::new(false)).unwrap_err();
        assert_eq!(error.to_string(), "zdn lightwalletd supervisor failed");
        assert!(!self.credential.exists());
        assert_eq!(
            fs::read(self.cache.join("data/retained")).unwrap(),
            b"durable cache"
        );
    }
    fn start(&self) -> (Arc<AtomicBool>, std::thread::JoinHandle<eyre::Result<()>>) {
        let flag = Arc::new(AtomicBool::new(false));
        let clone = flag.clone();
        let config = self.config();
        (flag, std::thread::spawn(move || supervise(config, &clone)))
    }
    fn assert_reaped(&self) {
        for line in fs::read_to_string(self.path("pids"))
            .unwrap_or_default()
            .lines()
        {
            let status = fs::read_to_string(format!("/proc/{line}/stat"));
            assert!(
                status.is_err() || status.unwrap().split_whitespace().nth(2) == Some("Z"),
                "live owned descendant {line}"
            );
        }
        assert!(!self.path("daemon").exists());
        assert!(!self.credential.exists());
    }
}

fn wait(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

// Real executable fixtures: Docker's durable daemon state is independent of
// its attached client, with live ordinary session descendants in another PGID.
// No Docker, root privilege, AWS or live service is used.
#[test]
fn runtime_descendant_worker() {
    let Some(ready) = std::env::var_os("ZDN_TEST_DESCENDANT_READY") else {
        return;
    };
    assert_eq!(nix::unistd::getpgrp().as_raw() as u32, std::process::id());
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:\t"))
        .unwrap();
    assert_ne!(
        u64::from_str_radix(ignored, 16).unwrap() & (1 << 14),
        0,
        "descendant must inherit SIGTERM ignored, not merely block it"
    );
    fs::write(ready, "ready").unwrap();
    std::thread::sleep(Duration::from_secs(120));
}

#[test]
// The exit-client scenario deliberately orphans its descendant: production's
// session supervisor, not the fake attached client, must discover and reap it.
#[allow(clippy::zombie_processes)]
fn runtime_tool_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    // The launcher received precisely the production environment. Inspect its
    // exec-time environment separately from the trusted literal transport's
    // ZDN_TEST_* variables and the shell's PWD added to this worker.
    let mut environment: Vec<_> = fs::read(format!("/proc/{}/environ", nix::unistd::getppid()))
        .unwrap()
        .split(|&byte| byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_vec())
        .collect();
    environment.sort();
    let root = Path::new(payload["root"].as_str().unwrap());
    if root.join("finite").exists() {
        assert!(environment.contains(&b"HOME=/root".to_vec()));
        assert!(environment.contains(&b"AWS_REGION=us-east-1".to_vec()));
    } else {
        assert_eq!(
            environment,
            [
                b"HOME=/nonexistent".to_vec(),
                b"PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_vec()
            ]
        );
    }
    let tool = payload["tool"].as_str().unwrap();
    let config: Value =
        serde_json::from_slice(&fs::read(root.join("worker.json")).unwrap()).unwrap();
    let flag = |name: &str| root.join(name).exists();
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .unwrap();
    writeln!(calls, "{tool} {}", serde_json::to_string(&args).unwrap()).unwrap();
    if flag("slow-command") {
        write(
            &root.join("slow-pid"),
            std::process::id().to_string(),
            0o600,
        );
        std::thread::sleep(Duration::from_secs(120));
    }
    let mut output = Vec::new();
    let mut code = 0;
    match tool {
        "lsblk" => {
            output = serde_json::to_vec(&config["lsblk"]).unwrap();
            if flag("exact-output") {
                output.resize(1048576, b' ');
            }
            if flag("overflow") {
                output = vec![b'x'; 1048577];
            }
        }
        "findmnt" => output = serde_json::to_vec(&config["findmnt"]).unwrap(),
        "iptables" | "ip6tables" => code = u8::from(flag(&format!("fail-{tool}"))),
        "docker" => match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["container", "ls", ..] => {
                if flag("daemon") {
                    output = b"dddddddddddd\n".to_vec();
                }
            }
            ["container", "inspect", name, ..] => {
                output = serde_json::to_vec(&if name.starts_with("zdn-") {
                    config["node"].clone()
                } else {
                    json!([config["survivor"]])
                })
                .unwrap();
            }
            ["image", "inspect", ..] => output = serde_json::to_vec(&config["image"]).unwrap(),
            ["run", ..] => {
                fs::write(root.join("daemon"), "owned").unwrap();
                let n = fs::read_dir(root)
                    .unwrap()
                    .filter(|entry| {
                        entry
                            .as_ref()
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with("launch-")
                    })
                    .count()
                    + 1;
                let credential = Path::new(config["credential"].as_str().unwrap());
                let contents = fs::read_to_string(credential).unwrap();
                let meta = credential.metadata().unwrap();
                let ready = root.join(format!("descendant-ready-{n}"));
                // Shell only establishes the inherited ignored signal. The
                // descendant itself is Rust, in a distinct PGID but same session.
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "trap '' TERM; exec \"$@\"", "descendant"])
                    .arg(std::env::current_exe().unwrap())
                    .args(["--exact", "runtime_descendant_worker", "--nocapture"])
                    .env_clear()
                    .env("ZDN_TEST_DESCENDANT_READY", &ready)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .process_group(0)
                    .spawn()
                    .unwrap();
                wait(&ready);
                assert_ne!(nix::unistd::getpgrp().as_raw() as u32, child.id());
                assert_eq!(
                    nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(child.id() as i32)))
                        .unwrap(),
                    nix::unistd::getsid(None).unwrap()
                );
                let mut pids = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(root.join("pids"))
                    .unwrap();
                writeln!(pids, "{}\n{}", std::process::id(), child.id()).unwrap();
                write(&root.join(format!("launch-{n}")), serde_json::to_vec(&json!({
                    "contents":contents,"mode":meta.mode() & 0o7777,"uid":meta.uid(),"gid":meta.gid(),"inode":meta.ino()
                })).unwrap(), 0o600);
                if flag("exit-client") {
                    native_tool::reply(&work, b"", b"", 7);
                    return;
                }
                // Keep the attached client alive, independently of daemon state.
                let _ = child.wait().unwrap();
            }
            ["stop" | "kill", ..] | ["container", "rm", ..] => {
                assert_eq!(
                    args.last().unwrap(),
                    config["survivor"]["Id"].as_str().unwrap()
                );
                if flag("cleanup-fails") {
                    code = u8::from(args[0] != "container");
                } else if args[0] == "stop" && flag("stop-fails") {
                    code = 1;
                } else if flag("daemon") {
                    fs::remove_file(root.join("daemon")).unwrap();
                }
            }
            _ => code = 99,
        },
        _ => panic!("unknown fixture tool {tool}"),
    }
    native_tool::reply(&work, &output, b"", code);
}

#[test]
fn lifetime_rotation_cancellation_lock_and_session_cleanup() {
    #[cfg(feature = "profiling")]
    let Some(trace) = trace::capture("lifetime_rotation_cancellation_lock_and_session_cleanup") else {
        return;
    };
    let f = Fixture::new();
    let (cancel, child) = f.start();
    wait(&f.path("launch-1"));
    // The spec's otherwise-unused finite timeout is 1s. Daemons must outlive it.
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!child.is_finished());
    assert!(supervise(f.config(), &AtomicBool::new(false)).is_err());
    assert!(
        f.credential.exists(),
        "contending supervisor must not clean up the owner"
    );
    let first: Value = serde_json::from_slice(&fs::read(f.path("launch-1")).unwrap()).unwrap();
    assert_eq!(first["mode"], 0o400);
    assert_eq!(first["uid"], f.config().node_uid);
    assert_eq!(first["gid"], f.config().node_gid);
    assert_eq!(
        f.credential.parent().unwrap().metadata().unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        f.credential
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    let rotated = COOKIE.replace('A', "B");
    write(
        &f.cookie.with_extension("new"),
        format!("{rotated}\r\n"),
        0o600,
    );
    fs::rename(f.cookie.with_extension("new"), &f.cookie).unwrap();
    wait(&f.path("launch-2"));
    let second: Value = serde_json::from_slice(&fs::read(f.path("launch-2")).unwrap()).unwrap();
    assert_ne!(first["inode"], second["inode"]);
    assert!(second["contents"]
        .as_str()
        .unwrap()
        .contains(&rotated[11..]));
    cancel.store(true, Ordering::Relaxed);
    child.join().unwrap().unwrap();
    f.assert_reaped();
    assert_eq!(
        fs::read(f.cache.join("data/retained")).unwrap(),
        b"durable cache"
    );
    assert!(!f.log().contains(&COOKIE[11..]));
    // Lock was released, and the same runtime directory can be reused.
    fs::remove_file(&f.cookie).unwrap();
    f.failed();
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "lightwallet_runtime.supervise",
                "lightwallet_runtime.supervision_loop",
                "lightwallet_runtime.verify_cache",
                "lightwallet_runtime.verify_node",
                "lightwallet_runtime.start_client",
                "lightwallet_runtime.rotate_restart",
                "lightwallet_runtime.stop_client",
                "lightwallet_runtime.write_credentials",
                "lightwallet_runtime.remove_credentials",
                "lightwallet_runtime.cleanup_container",
                "lightwallet_runtime.cleanup",
                "pulumi_process.supervisor.spawn_daemon",
                "pulumi_process.supervisor.finish_status",
            ],
            &[
                COOKIE,
                &COOKIE[11..],
                &rotated,
                &rotated[11..],
                f.root.path().to_str().unwrap(),
                &f.host.image,
                &f.host.config_toml,
                &f.service.image,
                "12345678-1234-4123-8123-123456789abc",
                "dddddddddddd",
                "rpcpassword=",
                "zdn lightwalletd supervisor failed",
            ],
        );
        trace.assert_child(
            "pulumi_process.supervisor.spawn_daemon",
            "lightwallet_runtime.start_client",
        );
        trace.assert_child(
            "lightwallet_runtime.rotate_restart",
            "lightwallet_runtime.supervision_loop",
        );
        trace.assert_child(
            "lightwallet_runtime.remove_credentials",
            "lightwallet_runtime.cleanup",
        );
    }
}

#[test]
fn cache_and_kernel_fail_closed_with_valid_later_evidence() {
    for case in [
        "serial",
        "size",
        "ambiguous",
        "children",
        "source",
        "major",
        "fsroot",
        "options",
        "missing-noexec",
        "mount-alias",
        "data",
        "identity",
        "capacity",
        "online",
        "leaf",
    ] {
        let f = Fixture::new();
        match case {
            "serial" => f.mutate(|v| v["lsblk"]["blockdevices"][0]["serial"] = json!("foreign")),
            "size" => f.mutate(|v| v["lsblk"]["blockdevices"][0]["size"] = json!(GIB)),
            "ambiguous" => f.mutate(|v| {
                let disk = v["lsblk"]["blockdevices"][0].clone();
                v["lsblk"]["blockdevices"]
                    .as_array_mut()
                    .unwrap()
                    .push(disk);
            }),
            "children" => f.mutate(|v| v["lsblk"]["blockdevices"][0]["children"] = json!([{}])),
            "source" => {
                f.mutate(|v| v["findmnt"]["filesystems"][0]["source"] = json!("/dev/other"))
            }
            "major" => f.mutate(|v| v["findmnt"]["filesystems"][0]["maj:min"] = json!("259:10")),
            "fsroot" => f.mutate(|v| v["findmnt"]["filesystems"][0]["fsroot"] = json!("/subdir")),
            "options" => f.mutate(|v| {
                v["findmnt"]["filesystems"][0]["options"] = json!("ro,nodev,nosuid,noexec")
            }),
            "missing-noexec" => {
                f.mutate(|v| v["findmnt"]["filesystems"][0]["options"] = json!("rw,nodev,nosuid"))
            }
            "mount-alias" => f.mutate(|v| {
                v["lsblk"]["blockdevices"][0]["mountpoints"] = json!([f.cache, "/other"])
            }),
            "data" => fs::set_permissions(f.cache.join("data"), fs::Permissions::from_mode(0o755))
                .unwrap(),
            "identity" => write(&f.cache.join(".zdn-lightwalletd-volume.json"), "{}", 0o600),
            "capacity" => write(
                &f.path("kernel/sys/fs/cgroup/system.slice/memory.max"),
                "1",
                0o600,
            ),
            // Affinity still permits two CPUs, but the existing service-budget
            // contract must also respect the fresh online-CPU ceiling.
            "online" => write(
                &f.path("kernel/sys/devices/system/cpu/online"),
                "0\n",
                0o600,
            ),
            "leaf" => write(
                &f.path("kernel/proc/self/cgroup"),
                "0::/system.slice/other.service\n",
                0o600,
            ),
            _ => unreachable!(),
        }
        f.failed();
        assert!(!f.path("launch-1").exists(), "{case}");
        if !["capacity", "online", "leaf"].contains(&case) {
            assert!(!f.log().contains("docker"), "{case}");
        }
    }
    // Positive control traverses precisely the same valid later evidence.
    let f = Fixture::new();
    let (cancel, child) = f.start();
    wait(&f.path("launch-1"));
    cancel.store(true, Ordering::Relaxed);
    child.join().unwrap().unwrap();
    f.assert_reaped();
}

#[test]
fn recovers_owned_survivor_before_cookie_failure_but_never_deletes_foreign() {
    let f = Fixture::new();
    f.flag("daemon");
    f.flag("stop-fails");
    fs::remove_file(&f.cookie).unwrap();
    f.failed();
    assert!(!f.path("daemon").exists());
    assert!(f.log().contains("\"kill\""));
    assert!(!f.log().contains("\"run\""));
    for field in ["image", "label", "id", "name"] {
        let f = Fixture::new();
        f.flag("daemon");
        f.mutate(|v| match field {
            "image" => v["survivor"]["Config"]["Image"] = json!("foreign"),
            "label" => v["survivor"]["Config"]["Labels"]["zdn.lightwalletd"] = json!("foreign"),
            "id" => v["survivor"]["Id"] = json!("e".repeat(64)),
            _ => v["survivor"]["Name"] = json!("/foreign"),
        });
        f.failed();
        assert!(f.path("daemon").exists());
        for forbidden in ["\"stop\"", "\"kill\"", "\"rm\"", "\"run\""] {
            assert!(!f.log().contains(forbidden), "{field}");
        }
    }
}

#[test]
fn cookie_security_and_rotation_failures_remove_credentials() {
    for case in [
        "grammar",
        "extra-newline",
        "ini-comment",
        "wrong-user",
        "symlink",
        "parent-link",
        "parent-mode",
        "hardlink",
        "mode",
        "fifo",
        "oversize",
    ] {
        let f = Fixture::new();
        match case {
            "grammar" => write(&f.cookie, "__cookie__:secret\nrpcpassword=injected", 0o600),
            "extra-newline" => write(&f.cookie, format!("{COOKIE}\n\n"), 0o600),
            "ini-comment" => write(&f.cookie, "__cookie__:bad;comment", 0o600),
            "wrong-user" => write(&f.cookie, COOKIE.replace("__cookie__", "wrong"), 0o600),
            "symlink" => {
                fs::rename(&f.cookie, f.path("saved-cookie")).unwrap();
                symlink(f.path("saved-cookie"), &f.cookie).unwrap();
            }
            "parent-link" => {
                let rpc = f.cookie.parent().unwrap();
                fs::rename(rpc, f.path("saved-rpc")).unwrap();
                symlink(f.path("saved-rpc"), rpc).unwrap();
            }
            "hardlink" => fs::hard_link(&f.cookie, f.path("cookie-alias")).unwrap(),
            "parent-mode" => fs::set_permissions(
                f.cookie.parent().unwrap(),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap(),
            "mode" => fs::set_permissions(&f.cookie, fs::Permissions::from_mode(0o644)).unwrap(),
            "fifo" => {
                fs::remove_file(&f.cookie).unwrap();
                nix::unistd::mkfifo(
                    &f.cookie,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            }
            _ => write(&f.cookie, "A".repeat(1025), 0o600),
        }
        f.failed();
        assert!(!f.path("launch-1").exists(), "{case}");
    }
    let f = Fixture::new();
    let (_, child) = f.start();
    wait(&f.path("launch-1"));
    write(&f.cookie, "invalid", 0o600);
    assert!(child.join().unwrap().is_err());
    f.assert_reaped();
}

#[test]
fn exit_restart_revalidation_and_failed_daemon_cleanup_still_reap_clients() {
    let f = Fixture::new();
    f.flag("exit-client");
    f.failed();
    f.assert_reaped();
    for changed in ["capacity", "cache", "node", "firewall"] {
        let f = Fixture::new();
        let (_, child) = f.start();
        wait(&f.path("launch-1"));
        match changed {
            "capacity" => write(
                &f.path("kernel/sys/fs/cgroup/system.slice/cpu.max"),
                "1 100000",
                0o600,
            ),
            "cache" => f.mutate(|v| v["findmnt"]["filesystems"][0]["fsroot"] = json!("/other")),
            "node" => f.mutate(|v| v["node"][0]["State"]["Running"] = json!(false)),
            _ => f.flag("fail-ip6tables"),
        }
        write(&f.cookie, COOKIE.replace('A', "C"), 0o600);
        assert!(child.join().unwrap().is_err());
        f.assert_reaped();
        assert!(!f.path("launch-2").exists(), "{changed}");
    }
    let f = Fixture::new();
    let (cancel, child) = f.start();
    wait(&f.path("launch-1"));
    f.flag("cleanup-fails");
    cancel.store(true, Ordering::Relaxed);
    assert!(child.join().unwrap().is_err());
    assert!(!f.credential.exists());
    assert!(f.path("daemon").exists());
    fs::remove_file(f.path("daemon")).unwrap();
    f.assert_reaped();
    assert!(f.log().contains("\"kill\""));
}

#[test]
fn exact_command_bound_and_secret_free_errors() {
    let f = Fixture::new();
    f.flag("exact-output");
    let (cancel, child) = f.start();
    wait(&f.path("launch-1"));
    cancel.store(true, Ordering::Relaxed);
    child.join().unwrap().unwrap();
    f.assert_reaped();
    let f = Fixture::new();
    f.flag("overflow");
    f.failed();
    assert!(!f.log().contains("docker"));
    for field in ["node", "image", "firewall4", "firewall6"] {
        let f = Fixture::new();
        match field {
            "node" => f.mutate(|v| v["node"][0]["Config"]["Labels"]["zdn.install"] = json!(COOKIE)),
            "image" => f.mutate(|v| v["image"][0]["Architecture"] = json!("arm64")),
            "firewall4" => f.flag("fail-iptables"),
            _ => f.flag("fail-ip6tables"),
        }
        f.failed();
        assert!(!f.path("launch-1").exists());
    }
}

#[test]
fn private_lock_and_foreign_credential_entries_are_not_repaired_or_deleted() {
    for case in ["mode", "hardlink", "symlink", "fifo"] {
        let f = Fixture::new();
        let runtime = f.credential.parent().unwrap().parent().unwrap();
        fs::create_dir_all(runtime).unwrap();
        fs::set_permissions(runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = runtime.join("supervisor.lock");
        match case {
            "mode" => write(&lock, "foreign", 0o644),
            "hardlink" => {
                write(&lock, "foreign", 0o600);
                fs::hard_link(&lock, f.path("alias")).unwrap();
            }
            "symlink" => {
                write(&f.path("foreign"), "foreign", 0o600);
                symlink(f.path("foreign"), &lock).unwrap();
            }
            _ => nix::unistd::mkfifo(
                &lock,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
        }
        assert!(supervise(f.config(), &AtomicBool::new(false)).is_err());
        assert!(f.log().is_empty());
        assert!(fs::symlink_metadata(lock).is_ok());
    }
    let f = Fixture::new();
    let directory = f.credential.parent().unwrap();
    fs::create_dir_all(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        directory.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    write(&f.path("foreign"), "do not delete", 0o600);
    symlink(f.path("foreign"), &f.credential).unwrap();
    assert!(supervise(f.config(), &AtomicBool::new(false)).is_err());
    assert!(!f.path("launch-1").exists());
    assert!(fs::symlink_metadata(&f.credential)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(f.path("foreign")).unwrap(), b"do not delete");
    fs::remove_file(&f.credential).unwrap();
    write(&f.credential, "not an owned 0400 credential", 0o600);
    assert!(supervise(f.config(), &AtomicBool::new(false)).is_err());
    assert_eq!(
        fs::read(&f.credential).unwrap(),
        b"not an owned 0400 credential"
    );
}

/// Run explicitly as root in offline validation to vary actual file ownership,
/// rather than changing the configured node UID and failing at the cache first.
#[test]
fn distinct_filesystem_owners_with_valid_later_evidence() {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("actual alternate-owner cases require an explicit root fixture run");
        return;
    }
    for case in ["cache", "claimed", "rpc", "cookie", "credential"] {
        let f = Fixture::new();
        let target = match case {
            "cache" => f.cache.join("data"),
            "claimed" => f.path("etc/zdn/volume-claimed.json"),
            "rpc" => f.cookie.parent().unwrap().into(),
            "cookie" => f.cookie.clone(),
            _ => {
                write(&f.credential, "foreign credential", 0o400);
                fs::set_permissions(
                    f.credential.parent().unwrap(),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                fs::set_permissions(
                    f.credential.parent().unwrap().parent().unwrap(),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                f.credential.clone()
            }
        };
        nix::unistd::chown(&target, Some(nix::unistd::Uid::from_raw(10001)), None).unwrap();
        assert!(supervise(f.config(), &AtomicBool::new(false)).is_err());
        assert!(!f.path("launch-1").exists(), "{case}");
        if ["rpc", "cookie", "credential"].contains(&case) {
            assert!(
                f.log().contains("\"image\""),
                "must reach valid later node/image evidence: {case}"
            );
        }
        if case == "credential" {
            assert_eq!(fs::read(&f.credential).unwrap(), b"foreign credential");
        }
        // Repair only in the fixture, then prove the exact same remaining
        // evidence permits launch (no unrelated negative masks a bug).
        nix::unistd::chown(&target, Some(nix::unistd::Uid::from_raw(0)), None).unwrap();
        let (cancel, child) = f.start();
        wait(&f.path("launch-1"));
        cancel.store(true, Ordering::Relaxed);
        child.join().unwrap().unwrap();
        f.assert_reaped();
    }
    // Also exercise the real root -> node credential ownership transition.
    let f = Fixture::new();
    for path in [
        f.cache.join("data"),
        f.cookie.parent().unwrap().into(),
        f.cookie.clone(),
    ] {
        nix::unistd::chown(
            &path,
            Some(nix::unistd::Uid::from_raw(10001)),
            Some(nix::unistd::Gid::from_raw(10001)),
        )
        .unwrap();
    }
    let mut config = f.config();
    config.node_uid = 10001;
    config.node_gid = 10001;
    let cancel = Arc::new(AtomicBool::new(false));
    let clone = cancel.clone();
    let child = std::thread::spawn(move || supervise(config, &clone));
    wait(&f.path("launch-1"));
    let metadata = fs::metadata(&f.credential).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
        (10001, 10001, 0o400)
    );
    cancel.store(true, Ordering::Relaxed);
    child.join().unwrap().unwrap();
    f.assert_reaped();
}

#[test]
fn finite_observation_and_owned_cleanup() {
    let f = Fixture::new();
    f.valid_container();
    // Finite controllers are outside the service cgroup and need no cookie.
    fs::remove_file(&f.cookie).unwrap();
    write(
        &f.path("kernel/proc/self/cgroup"),
        "0::/controller\n",
        0o600,
    );
    let mut executor = f.finite(Duration::from_secs(60));
    let cancel = AtomicBool::new(false);
    assert_eq!(
        observe_container(f.config(), &mut executor, &cancel, false).unwrap(),
        None
    );
    f.flag("daemon");
    assert_eq!(
        observe_container(f.config(), &mut executor, &cancel, false).unwrap(),
        Some(true)
    );
    f.mutate(|v| {
        v["survivor"]["State"] = json!({"Running":false,"Status":"created"});
    });
    assert_eq!(
        observe_container(f.config(), &mut executor, &cancel, true).unwrap(),
        Some(false)
    );
    assert!(observe_container(f.config(), &mut executor, &cancel, false).is_err());
    assert!(f.path("daemon").exists());
    assert!(!f.credential.exists());
    assert!(!f.credential.parent().unwrap().parent().unwrap().exists());
    write(&f.credential, COOKIE, 0o400);
    fs::set_permissions(
        f.credential.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        f.credential.parent().unwrap().parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    f.mutate(|v| v["survivor"]["State"]["Running"] = json!(true));
    f.flag("cleanup-fails");
    assert!(cleanup_container(f.config(), &mut executor, &cancel).is_err());
    assert!(
        f.path("daemon").exists(),
        "successful rm status is not absence"
    );
    assert!(
        !f.credential.exists(),
        "credential removal also runs on failure"
    );
    fs::remove_file(f.path("cleanup-fails")).unwrap();
    f.flag("stop-fails");
    cleanup_container(f.config(), &mut executor, &cancel).unwrap();
    assert!(!f.path("daemon").exists());
    assert!(!f.credential.exists());
    assert!(!f.path("launch-1").exists());
    assert!(!f.log().contains(COOKIE));
    assert!(!f
        .credential
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("supervisor.lock")
        .exists());
}

#[test]
fn finite_policy_identity_and_private_credentials_fail_closed() {
    for case in [
        "policy", "mount", "id", "name", "image", "label", "short-id",
    ] {
        let f = Fixture::new();
        f.valid_container();
        f.flag("daemon");
        let mut executor = f.finite(Duration::from_secs(60));
        f.mutate(|v| match case {
            "policy" => v["survivor"]["HostConfig"]["Privileged"] = json!(true),
            "mount" => v["survivor"]["Mounts"][1]["RW"] = json!(true),
            "id" => v["survivor"]["Id"] = json!("e".repeat(64)),
            "short-id" => v["survivor"]["Id"] = json!("d".repeat(12)),
            "name" => v["survivor"]["Name"] = json!("/foreign"),
            "image" => v["survivor"]["Config"]["Image"] = json!("foreign"),
            _ => v["survivor"]["Config"]["Labels"]["zdn.lightwalletd"] = json!(COOKIE),
        });
        let cancel = AtomicBool::new(false);
        assert!(
            observe_container(f.config(), &mut executor, &cancel, true).is_err(),
            "{case}"
        );
        if !["policy", "mount"].contains(&case) {
            assert!(cleanup_container(f.config(), &mut executor, &cancel).is_err());
            assert!(f.path("daemon").exists());
        }
        assert!(!f.credential.exists());
        assert!(!f.path("launch-1").exists());
    }
    let f = Fixture::new();
    let mut executor = f.finite(Duration::from_secs(60));
    write(&f.credential, "foreign private entry", 0o600);
    fs::set_permissions(
        f.credential.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        f.credential.parent().unwrap().parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(cleanup_container(f.config(), &mut executor, &AtomicBool::new(false)).is_err());
    assert_eq!(fs::read(&f.credential).unwrap(), b"foreign private entry");
}

#[test]
fn finite_cancellation_and_cumulative_deadline_reap_real_commands() {
    for cancellation in [false, true] {
        let f = Fixture::new();
        f.flag("slow-command");
        let mut executor = f.finite(if cancellation {
            Duration::from_secs(60)
        } else {
            Duration::from_millis(10500)
        });
        let cancel = AtomicBool::new(false);
        std::thread::scope(|scope| {
            if cancellation {
                scope.spawn(|| {
                    wait(&f.path("slow-pid"));
                    cancel.store(true, Ordering::Relaxed);
                });
            }
            let error = observe_container(f.config(), &mut executor, &cancel, true).unwrap_err();
            assert_eq!(error.to_string(), "zdn lightwalletd observation failed");
        });
        let pid = fs::read_to_string(f.path("slow-pid")).unwrap();
        let status = fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(status.is_err() || status.unwrap().split_whitespace().nth(2) == Some("Z"));
        // Reusing the same executor cannot reset either cancellation or budget.
        assert!(observe_container(f.config(), &mut executor, &cancel, true).is_err());
        f.flag("daemon");
        assert!(cleanup_container(f.config(), &mut executor, &cancel).is_err());
        assert!(f.path("daemon").exists());
        assert!(!f.credential.exists());
        assert!(!f.path("launch-1").exists());
    }
}
