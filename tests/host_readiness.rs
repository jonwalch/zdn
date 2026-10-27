#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        runtime_config::{render_runtime_config, RuntimeOptions},
    },
    host::{
        command::Executor,
        files::Directory,
        readiness::{self, Config},
        volume::Installation,
        HostInstallSpec, S3Object, API_VERSION,
    },
};

#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

#[cfg(feature = "profiling")]
#[path = "support/trace.rs"]
mod trace;

fn spec() -> HostInstallSpec {
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let deployment = Uuid::parse_str("12345678-1234-4123-8123-123456789abc").unwrap();
    let mut options = RuntimeOptions::new(deployment, "node-1");
    options.network.listen_addr = "10.90.1.10:18233".into();
    options.network.peers = vec!["10.90.1.11:18233".into()];
    options.rpc_listen_addr = "127.0.0.2:18339".into();
    let runtime = render_runtime_config(&manifest, &options).unwrap();
    let object = |key: &str| S3Object {
        bucket: "zdn-artifacts-test".into(),
        key: format!("team/test/{key}"),
        sha256: "a".repeat(64),
        bytes: 128,
        owner_account: "123456789012".into(),
        region: "us-east-1".into(),
    };
    HostInstallSpec {
        api_version: API_VERSION.into(),
        deployment_id: deployment,
        node_id: "node-1".into(),
        consensus_fingerprint: runtime.consensus_fingerprint,
        volume_id: "vol-0123456789abcdef0".into(),
        image: format!(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/zakura@sha256:{}",
            "b".repeat(64)
        ),
        config_toml: runtime.config_toml,
        config_sha256: runtime.config_sha256,
        role: "follower".into(),
        block_interval_seconds: Some(25),
        memory_bytes: 8 << 30,
        host_reserve_bytes: 4 << 30,
        cpu_millis: 3500,
        manifest: object("manifest"),
        bundle: object("bundle"),
        helper: object("helper"),
        image_record: object("image-record"),
        image_manifest: object("image-manifest"),
        new_volume: None,
    }
}

struct Fixture {
    root: tempfile::TempDir,
    node: Directory,
    spec: HostInstallSpec,
    image: String,
    executor: Executor,
    helper: PathBuf,
    manifest: PathBuf,
    bundle: PathBuf,
    cookie: PathBuf,
    systemctl: PathBuf,
    docker: PathBuf,
    state: PathBuf,
    kernel: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let node = Directory::open(root.path(), fs::metadata(root.path()).unwrap().uid()).unwrap();
        node.ensure_directory("commands", 0o700).unwrap();
        let spec = spec();
        let state = root.path().join("tools.json");
        let path = spec.node_root();
        let mounts: Vec<_> = ["", "/state", "/identity", "/rpc"]
            .iter()
            .map(|child| {
                let target = format!("{path}{child}");
                json!({"Type":"bind","Source":target,"Destination":target,"RW":!child.is_empty()})
            })
            .collect();
        fs::write(&state, json!({
            "service":"LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n",
            "report":"{\"launchReady\":false,\"fresh\":1}",
            "role":"follower",
            "record":{"Name":format!("/zdn-{}-{}",spec.deployment_id,spec.node_id),"State":{"Running":true},
                "Config":{"Image":spec.image,"Labels":{"zdn.install":spec.install_sha256().unwrap()},
                    "User":"10001:10001","WorkingDir":"/","Entrypoint":["/usr/bin/env"],
                    "Cmd":["-i","PATH=/usr/local/bin:/usr/bin:/bin","HOME=/nonexistent","/usr/local/bin/zakurad","--config",format!("{path}/zakura.toml"),"start"],
                    "StopSignal":"SIGINT","Healthcheck":{"Test":["NONE"]}},
                "HostConfig":{"NetworkMode":"host","ReadonlyRootfs":true,"Privileged":false,
                    "CapDrop":["ALL"],"PidsLimit":1024,"PidMode":"","LogConfig":{"Type":"journald"},
                    "SecurityOpt":["no-new-privileges:true"],"Memory":8589934592u64,"MemorySwap":8589934592u64,"NanoCpus":3500000000u64},
                "Mounts":mounts}
        }).to_string()).unwrap();
        let tool = |name| {
            let path = root.path().join(name);
            native_tool::install(&path, "tool_worker", &json!({"state":state,"kind":name}));
            path
        };
        let helper = tool("helper");
        let manifest = root.path().join("manifest.json");
        let bundle = root.path().join("chain.tar");
        let cookie = root.path().join("rpc.cookie");
        let systemctl = tool("systemctl");
        let docker = tool("docker");
        let kernel = root.path().join("kernel");
        for (path, bytes) in [
            ("proc/meminfo", "MemTotal: 16777216 kB\n"),
            ("proc/self/status", "Cpus_allowed_list: 0-7\n"),
            ("proc/self/cgroup", "0::/\n"),
            ("sys/devices/system/cpu/online", "0-7\n"),
            ("sys/fs/cgroup/memory.max", "max\n"),
            ("sys/fs/cgroup/cpu.max", "max 100000\n"),
        ] {
            let path = kernel.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        let executor = Executor::new(
            env!("CARGO_BIN_EXE_zdn").into(),
            root.path().join("commands"),
            "us-east-1".into(),
            Instant::now() + Duration::from_secs(120),
        )
        .unwrap();
        Self {
            root,
            node,
            image: spec.image.clone(),
            spec,
            executor,
            helper,
            manifest,
            bundle,
            cookie,
            systemctl,
            docker,
            state,
            kernel,
        }
    }

    fn config<'a>(&'a self, installation: &'a Installation<'a>) -> Config<'a> {
        Config {
            spec: &self.spec,
            image: &self.image,
            installation,
            node: &self.node,
            helper: &self.helper,
            manifest: &self.manifest,
            bundle: &self.bundle,
            cookie: &self.cookie,
            producer_state: self.root.path(),
            systemctl: &self.systemctl,
            docker: &self.docker,
            kernel_root: &self.kernel,
        }
    }

    fn set(&self, key: &str, value: Value) {
        let mut state: Value = serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap();
        state
            .pointer_mut(key)
            .map(|slot| *slot = value.clone())
            .unwrap_or_else(|| {
                state[key.strip_prefix('/').unwrap()] = value;
            });
        fs::write(&self.state, state.to_string()).unwrap();
    }

    fn run(&mut self, bootstrap: bool, cancelled: &AtomicBool) -> eyre::Result<Value> {
        // Separate trusted install metadata directory, with guard retained over
        // every command and publication (no self-referential fixture guard).
        let metadata = self.node.ensure_directory("install", 0o700)?;
        let installation = Installation::acquire(&metadata, &self.spec)?;
        let config = Config {
            spec: &self.spec,
            image: &self.image,
            installation: &installation,
            node: &self.node,
            helper: &self.helper,
            manifest: &self.manifest,
            bundle: &self.bundle,
            cookie: &self.cookie,
            producer_state: self.root.path(),
            systemctl: &self.systemctl,
            docker: &self.docker,
            kernel_root: &self.kernel,
        };
        readiness::readiness(&config, &mut self.executor, cancelled, bootstrap)
    }

    fn marker(&self) -> PathBuf {
        self.root.path().join("bootstrap-complete.json")
    }
    fn calls(&self) -> Vec<Vec<String>> {
        fs::read_to_string(self.root.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[test]
fn tool_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let state_path = Path::new(payload["state"].as_str().unwrap());
    let state: Value = serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
    use std::io::Write;
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(state_path.parent().unwrap().join("calls"))
            .unwrap(),
        "{}",
        json!(args)
    )
    .unwrap();
    let mut code = 0;
    let bytes = match payload["kind"].as_str().unwrap() {
        "helper" => {
            let root = state_path.parent().unwrap();
            let mut expected: Vec<String> = vec![
                "chain".into(),
                args[1].clone(),
                "--manifest".into(),
                root.join("manifest.json").to_str().unwrap().into(),
                "--rpc-endpoint".into(),
                "127.0.0.2:18339".into(),
                "--cookie-file".into(),
                root.join("rpc.cookie").to_str().unwrap().into(),
                "--request-timeout-secs".into(),
                "10".into(),
            ];
            let deadline = if args[1] == "wait-rpc" { "60" } else { "180" };
            expected.extend(["--deadline-secs".into(), deadline.into()]);
            match args[1].as_str() {
                "wait-rpc" => {}
                "bootstrap" => expected.extend([
                    "--bundle".into(),
                    root.join("chain.tar").to_str().unwrap().into(),
                    "--producer-stopped".into(),
                ]),
                "readiness" => {
                    expected.extend(["--role".into(), state["role"].as_str().unwrap().into()])
                }
                _ => panic!("unexpected helper action"),
            }
            assert_eq!(args, expected);
            if state["fail"] == args[1] {
                code = 1;
            }
            if state["sleep"] == args[1] {
                fs::write(state_path.parent().unwrap().join("sleeping"), "").unwrap();
                std::thread::sleep(Duration::from_secs(20));
            }
            if args[1] == "readiness" {
                state["report"].as_str().unwrap().as_bytes().to_vec()
            } else {
                b"private-diagnostic-123".to_vec()
            }
        }
        "docker" => {
            assert_eq!(&args[..2], ["container", "inspect"]);
            serde_json::to_vec(&json!([state["record"]])).unwrap()
        }
        "systemctl" => state["service"].as_str().unwrap().as_bytes().to_vec(),
        _ => panic!("unexpected tool"),
    };
    native_tool::reply(&work, &bytes, b"private-diagnostic-123", code);
}

#[test]
fn selected_image_observation_retains_original_identity_and_bootstrap_marker() {
    let mut f = Fixture::new();
    f.run(true, &AtomicBool::new(false)).unwrap();
    let marker = fs::read(f.marker()).unwrap();
    let original = f.spec.install_sha256().unwrap();
    f.image = format!(
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/zdn/test/zakura@sha256:{}",
        "7".repeat(64)
    );
    assert_ne!(f.image, f.spec.image);
    // A responding helper cannot qualify a container still using the old image.
    assert!(f.run(false, &AtomicBool::new(false)).is_err());
    f.set("/record/Config/Image", json!(f.image));
    let report = f.run(false, &AtomicBool::new(false)).unwrap();
    assert_eq!(report["image"], f.image);
    assert_eq!(report["installSha256"], original);
    assert_eq!(report["configSha256"], f.spec.config_sha256);
    assert_eq!(fs::read(f.marker()).unwrap(), marker);
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["paymentQualification"], "pending");
}

#[test]
fn first_bootstrap_and_retained_marker_keep_fresh_gates_and_schema() {
    #[cfg(feature = "profiling")]
    let Some(trace) =
        trace::capture("first_bootstrap_and_retained_marker_keep_fresh_gates_and_schema")
    else {
        return;
    };
    let mut f = Fixture::new();
    let report = f.run(true, &AtomicBool::new(false)).unwrap();
    let metadata = f.node.open_directory("install").unwrap();
    let installation = Installation::acquire(&metadata, &f.spec).unwrap();
    assert_eq!(fs::read(f.marker()).unwrap(), installation.identity());
    assert!(readiness::bootstrap_completed(&f.config(&installation)).unwrap());
    drop(installation);
    assert_eq!(fs::metadata(f.marker()).unwrap().mode() & 0o777, 0o600);
    assert_eq!(report["apiVersion"], "zdn-host-observation/v1alpha1");
    assert_eq!(report["installSha256"], f.spec.install_sha256().unwrap());
    assert_eq!(report["status"], "ready");
    assert_eq!(report["paymentQualification"], "pending");
    assert_eq!(report["launchReady"], false);
    assert_eq!(report["scheduledProducer"], false);
    assert_eq!(report["producer"], Value::Null);
    assert_eq!(
        report["effectiveLimits"]["effectiveMemoryBytes"],
        16u64 << 30
    );
    f.set("/report", json!("{\"launchReady\":false,\"fresh\":2}"));
    fs::write(
        f.kernel.join("sys/fs/cgroup/memory.max"),
        (12u64 << 30).to_string(),
    )
    .unwrap();
    let report = f.run(true, &AtomicBool::new(false)).unwrap();
    assert_eq!(report["readiness"]["fresh"], 2);
    assert_eq!(
        report["effectiveLimits"]["effectiveMemoryBytes"],
        12u64 << 30
    );
    let calls = f.calls();
    for (action, count) in [("bootstrap", 1), ("wait-rpc", 2), ("readiness", 2)] {
        assert_eq!(
            calls
                .iter()
                .filter(|a| a.get(1).is_some_and(|a| a == action))
                .count(),
            count
        );
    }
    f.set("/record/State/Running", json!(false));
    assert!(f.run(true, &AtomicBool::new(false)).is_err());
    f.set("/record/State/Running", json!(true));
    f.set(
        "/service",
        json!("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\n"),
    );
    assert!(
        f.run(true, &AtomicBool::new(false)).is_err(),
        "fresh follower producer observation required"
    );
    #[cfg(feature = "profiling")]
    {
        trace.assert_spans(
            &[
                "host.readiness.readiness",
                "host.readiness.bootstrap_completed",
                "host.readiness.wait_rpc",
                "host.readiness.bootstrap",
                "host.readiness.verify",
                "host.producer.require_stopped",
                "host.producer.service",
                "host.producer.observe",
                "host.container.running_limits",
            ],
            &[
                "private-diagnostic-123",
                "rpc.cookie",
                "12345678-1234-4123-8123-123456789abc",
                "MainPID=42",
                "fresh follower producer observation required",
            ],
        );
        for phase in [
            "host.readiness.wait_rpc",
            "host.readiness.bootstrap",
            "host.readiness.verify",
            "host.producer.require_stopped",
            "host.producer.observe",
            "host.container.running_limits",
        ] {
            trace.assert_child(phase, "host.readiness.readiness");
        }
        trace.assert_child("host.producer.service", "host.producer.require_stopped");
    }
}

#[test]
fn legacy_and_observe_only_never_publish_completion() {
    for legacy in [false, true] {
        let mut f = Fixture::new();
        if legacy {
            f.spec.block_interval_seconds = None;
            f.set(
                "/record/Config/Labels/zdn.install",
                json!(f.spec.install_sha256().unwrap()),
            );
        }
        f.run(legacy, &AtomicBool::new(false)).unwrap();
        assert!(!f.marker().exists());
        assert_eq!(
            f.calls()
                .iter()
                .filter(|a| a.get(1).is_some_and(|a| a == "bootstrap"))
                .count(),
            usize::from(legacy)
        );
        if legacy {
            fs::write(f.marker(), "foreign marker ignored by legacy contract").unwrap();
            f.run(true, &AtomicBool::new(false)).unwrap();
        }
    }
}

#[test]
fn observe_only_reports_fresh_owned_producer_without_bootstrapping() {
    use fs2::FileExt;
    use zdn::chain::{
        producer::{ProducerIdentity, ProducerJournal, ProducerPhase},
        runtime_config::NodeRole,
    };
    let mut f = Fixture::new();
    let manifest: ConsensusManifest =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    let mut options = RuntimeOptions::new(f.spec.deployment_id, "node-1");
    options.network.listen_addr = "10.90.1.10:18233".into();
    options.network.peers = vec!["10.90.1.11:18233".into()];
    options.rpc_listen_addr = "127.0.0.2:18339".into();
    options.role = NodeRole::Producer;
    options.reward_address = Some("tm9iNYCVAhLLa4rJtfqqHauR5xL1REdpiDs".into());
    let runtime = render_runtime_config(&manifest, &options).unwrap();
    f.spec.role = "producer".into();
    f.spec.config_toml = runtime.config_toml;
    f.spec.config_sha256 = runtime.config_sha256;
    f.set("/role", json!("producer"));
    f.set(
        "/record/Config/Labels/zdn.install",
        json!(f.spec.install_sha256().unwrap()),
    );
    f.node
        .publish(
            "producer-authorized.json",
            &zdn::host::producer::authorization(&f.spec).unwrap(),
            0o600,
        )
        .unwrap();
    let lock_path = f.root.path().join("controller.lock");
    let lock = fs::File::create(&lock_path).unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    lock.lock_exclusive().unwrap();
    let mut journal = ProducerJournal {
        api_version: zdn::chain::producer::API_VERSION.into(),
        identity: ProducerIdentity {
            deployment_id: f.spec.deployment_id,
            node_id: f.spec.node_id.clone(),
            consensus_fingerprint: f.spec.consensus_fingerprint.clone(),
        },
        owner_pid: std::process::id(),
        owner_session: Uuid::new_v4(),
        phase: ProducerPhase::Waiting,
        interval_secs: 25,
        last_confirmed_tip: None,
        pending: None,
        confirmed_blocks: 0,
    };
    let journal_path = f.root.path().join("journal.json");
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    f.set(
        "/service",
        json!(format!(
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID={}\n",
            journal.owner_pid
        )),
    );
    let report = f.run(false, &AtomicBool::new(false)).unwrap();
    assert_eq!(report["scheduledProducer"], true);
    assert_eq!(report["producer"]["phase"], "waiting");
    assert_eq!(report["producer"]["launchReady"], false);
    journal.phase = ProducerPhase::Generating;
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let report = f.run(false, &AtomicBool::new(false)).unwrap();
    assert_eq!(report["producer"]["phase"], "generating");
    assert!(!f.marker().exists());
    assert!(!f
        .calls()
        .iter()
        .any(|a| a.get(1).is_some_and(|a| a == "bootstrap")));
    FileExt::unlock(&lock).unwrap();
    assert!(f.run(false, &AtomicBool::new(false)).is_err());
}

#[test]
fn stopped_gate_and_helper_failures_never_publish_or_leak() {
    let mut f = Fixture::new();
    f.set(
        "/service",
        json!("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\n"),
    );
    assert!(f.run(true, &AtomicBool::new(false)).is_err());
    assert!(!f
        .calls()
        .iter()
        .any(|a| a.first().is_some_and(|a| a == "chain")));
    assert!(!f.marker().exists());
    for action in ["wait-rpc", "bootstrap", "readiness"] {
        let mut f = Fixture::new();
        f.set("/fail", json!(action));
        let error = f.run(true, &AtomicBool::new(false)).unwrap_err();
        assert!(!format!("{error:?}").contains("private-diagnostic-123"));
        assert!(!f.marker().exists());
    }
    for raw in [
        "not-json-private-diagnostic-123",
        "{}",
        "[]",
        "{\"launchReady\":true}",
        "{\"launchReady\":0}",
        "{\"launchReady\":\"false\"}",
        "{\"launchReady\":null}",
    ] {
        let mut f = Fixture::new();
        f.set("/report", json!(raw));
        let error = f.run(true, &AtomicBool::new(false)).unwrap_err();
        assert!(!format!("{error:?}").contains("private-diagnostic-123"));
        assert!(!f.marker().exists());
    }
}

#[test]
fn marker_trust_and_full_guard_binding_fail_before_tools() {
    for mode in [
        "foreign",
        "malformed",
        "symlink",
        "writable",
        "directory",
        "oversized",
    ] {
        let mut f = Fixture::new();
        match mode {
            "symlink" => symlink("missing", f.marker()).unwrap(),
            "directory" => fs::create_dir(f.marker()).unwrap(),
            "oversized" => fs::write(f.marker(), vec![0; 8193]).unwrap(),
            _ => {
                fs::write(f.marker(), if mode == "foreign" { "{}\n" } else { "bad" }).unwrap();
                if mode == "writable" {
                    fs::set_permissions(f.marker(), fs::Permissions::from_mode(0o666)).unwrap();
                }
            }
        }
        assert!(f.run(true, &AtomicBool::new(false)).is_err(), "{mode}");
        assert!(f.calls().is_empty());
    }
    let mut f = Fixture::new();
    let metadata = f.node.ensure_directory("install", 0o700).unwrap();
    let installation = Installation::acquire(&metadata, &f.spec).unwrap();
    let mut changed = f.spec.clone();
    changed.cpu_millis += 1;
    let mut config = f.config(&installation);
    config.spec = &changed;
    // Use a separate executor borrow: config's references pin all trust inputs.
    let commands = f.node.ensure_directory("other-commands", 0o700).unwrap();
    drop(commands);
    let mut executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.root.path().join("other-commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert!(readiness::readiness(&config, &mut executor, &AtomicBool::new(false), true).is_err());
    config.spec = &f.spec;
    config.bundle = Path::new("relative");
    assert!(readiness::readiness(&config, &mut executor, &AtomicBool::new(false), true).is_err());
    assert!(f.calls().is_empty());
    drop(installation);
    assert!(f.run(true, &AtomicBool::new(true)).is_err());
    assert!(f.calls().is_empty());
    assert!(!f.marker().exists());
}

#[test]
fn cancellation_during_helper_and_cumulative_deadline_prevent_marker() {
    let mut f = Fixture::new();
    f.set("/sleep", json!("bootstrap"));
    let cancelled = AtomicBool::new(false);
    let sleeping = f.root.path().join("sleeping");
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !sleeping.exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            cancelled.store(true, Ordering::Relaxed);
        });
        assert!(f.run(true, &cancelled).is_err());
    });
    assert!(!f.marker().exists());
    let mut f = Fixture::new();
    drop(f.executor);
    f.executor = Executor::new(
        env!("CARGO_BIN_EXE_zdn").into(),
        f.root.path().join("commands"),
        "us-east-1".into(),
        Instant::now() + Duration::from_secs(9),
    )
    .unwrap();
    let error = f.run(true, &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("cumulative deadline"));
    assert!(f.calls().is_empty());
    assert!(!f.marker().exists());
}
