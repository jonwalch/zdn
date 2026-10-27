#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zdn::{config, foundation_host, foundation_live, infra};
#[path = "support/executable.rs"]
mod executable;
#[path = "support/native_tool.rs"]
mod native_tool;

fn write(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value).unwrap();
}

#[test]
fn native_worker() {
    let Some((work, args, payload)) = native_tool::invocation() else {
        return;
    };
    let root = Path::new(payload["root"].as_str().unwrap());
    // The marker proves unsupported requests do not invoke any providers.
    fs::write(root.join("probed"), "yes").unwrap();
    let mode = fs::read_to_string(root.join("mode")).unwrap_or_default();
    if mode == "hang" {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        fs::write(root.join("descendant"), child.id().to_string()).unwrap();
        let _ = child.wait();
    }
    let fail =
        mode == args.last().unwrap().as_str() || (mode == "docker-info" && args[0] == "info");
    native_tool::reply(
        &work,
        b"provider-secret",
        b"provider-secret",
        if fail { 1 } else { 0 },
    );
}

fn request(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = String::new();
    // A rejected oversized request can close with unread input (TCP reset).
    let _ = stream.read_to_string(&mut response);
    response
}

#[test]
fn observable_readiness_and_bounded_http() {
    assert_eq!(foundation_host::PROTOCOL, "zdn-foundation-health/v1alpha1");
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write(root, "proc/meminfo", "MemTotal: 25165824 kB\n");
    write(root, "proc/self/status", "Cpus_allowed_list: 1-3,8,10-11\n");
    write(root, "sys/devices/system/cpu/online", "0-1\n");
    write(root, "proc/self/cgroup", "0::/slice/service\n");
    write(root, "sys/fs/cgroup/slice/service/memory.max", "268435456");
    write(root, "sys/fs/cgroup/slice/service/cpu.max", "25000 100000");
    write(root, "sys/fs/cgroup/slice/memory.max", "10737418240");
    write(root, "sys/fs/cgroup/cpu.max", "390099 100000");
    let payload = serde_json::json!({"root":root});
    for tool in ["systemctl", "docker"] {
        native_tool::install(&root.join(tool), "native_worker", &payload);
    }
    let old_path = std::env::var_os("PATH");
    std::env::set_var("PATH", root);
    let id = uuid::Uuid::new_v4();
    let observe = |size, mount: &Path| foundation_host::observe(id, size, root, mount);
    let health = observe(config::Size::Medium, Path::new("/")).unwrap();
    assert_eq!(health.network_id, id);
    assert_eq!(health.schema_version, 1);
    assert_eq!(health.status, "ready");
    assert!(health.chain_mounted && health.docker_active && health.ssm_active);
    assert_eq!(health.effective_memory_bytes, 10 * infra::GIB);
    assert_eq!(
        health.application_memory_bytes,
        8 * infra::GIB - infra::FIXTURE_MEMORY_BYTES
    );
    assert_eq!(
        (
            health.visible_cpus,
            health.visible_cpu_millis,
            health.application_cpu_millis
        ),
        (6, 3900, 3400)
    );
    assert_eq!(
        observe(config::Size::Small, Path::new("/"))
            .unwrap()
            .application_memory_bytes,
        6 * infra::GIB - infra::FIXTURE_MEMORY_BYTES
    );
    assert!(observe(config::Size::Medium, root).is_err());
    std::os::unix::fs::symlink("/", root.join("mount-link")).unwrap();
    assert!(observe(config::Size::Medium, &root.join("mount-link")).is_err());
    write(root, "sys/fs/cgroup/slice/memory.max", "2415919104");
    // Exactly reserve + fixture leaves zero for the application.
    assert!(observe(config::Size::Medium, Path::new("/")).is_err());
    write(root, "sys/fs/cgroup/slice/memory.max", "10737418240");
    write(root, "sys/fs/cgroup/cpu.max", "max 100000");
    assert_eq!(
        observe(config::Size::Small, Path::new("/"))
            .unwrap()
            .visible_cpu_millis,
        6000
    );
    write(root, "sys/fs/cgroup/cpu.max", "390099 100000");
    assert!(foundation_host::observe(
        uuid::Uuid::nil(),
        config::Size::Medium,
        root,
        Path::new("/")
    )
    .is_err());
    for failure in ["docker", "amazon-ssm-agent", "zdn-chain", "docker-info"] {
        write(root, "mode", failure);
        let error = observe(config::Size::Medium, Path::new("/")).unwrap_err();
        assert_eq!(format!("{error:#}"), "foundation host is not ready");
    }
    write(root, "mode", "");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            foundation_host::serve(
                listener,
                id,
                config::Size::Medium,
                root,
                Path::new("/"),
                &cancel,
            )
            .unwrap()
        });
        fs::remove_file(root.join("probed")).unwrap();
        for (req, status) in [
            ("GET /else HTTP/1.1\r\n\r\n", "404"),
            ("POST /health HTTP/1.1\r\n\r\n", "405"),
            ("GET /health nonsense\r\n\r\n", "400"),
            ("GET /health HTTP/1.1\r\nbad-header\r\n\r\n", "400"),
            ("GET /health HTTP/1.1\r\nContent-Length: 12\r\n\r\n", "400"),
            (
                "GET /health HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                "400",
            ),
        ] {
            assert!(request(addr, req.as_bytes()).starts_with(&format!("HTTP/1.1 {status}")));
        }
        let large = format!("GET /health HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(9000));
        assert!(!request(addr, large.as_bytes()).contains("200 OK"));
        let mut slow = TcpStream::connect(addr).unwrap();
        slow.write_all(b"GET /health").unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        let start = Instant::now();
        assert_eq!(slow.read(&mut [0; 1]).unwrap(), 0);
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(!root.join("probed").exists());
        let get = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let response = request(addr, get);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let body: foundation_live::HostHealth =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body.application_cpu_millis, 3400);
        write(root, "sys/fs/cgroup/cpu.max", "50100 100000");
        let response = request(addr, get);
        assert!(response.contains("\"application_cpu_millis\":1"));
        write(root, "sys/fs/cgroup/cpu.max", "50000 100000");
        let response = request(addr, get);
        assert!(response.starts_with("HTTP/1.1 503"));
        assert_eq!(
            response.split_once("\r\n\r\n").unwrap().1,
            "{\"status\":\"not-ready\"}"
        );
        write(root, "sys/fs/cgroup/cpu.max", "390000 100000");
        write(root, "mode", "docker-info");
        assert!(!request(addr, get).contains("provider-secret"));
        write(root, "mode", "hang");
        let client = scope.spawn(move || request(addr, get));
        let start = Instant::now();
        while !root.join("descendant").exists() {
            assert!(start.elapsed() < Duration::from_secs(4));
            std::thread::sleep(Duration::from_millis(10));
        }
        cancel.store(true, Ordering::Relaxed);
        server.join().unwrap();
        client.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(7));
        let pid = fs::read_to_string(root.join("descendant")).unwrap();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        assert!(
            stat.is_empty() || stat.split_whitespace().nth(2) == Some("Z"),
            "owned descendant survived: {stat}"
        );
    });
    let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
    assert!(foundation_host::serve(
        wildcard,
        id,
        config::Size::Medium,
        root,
        Path::new("/"),
        &cancel
    )
    .is_err());
    if let Some(path) = old_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
}
