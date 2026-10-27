//! Read-only foundation readiness. No installation or live qualification effects.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use eyre::{ensure, ContextCompat, Result};
use uuid::Uuid;

use crate::{
    config::Size,
    dependencies::run_command_in_memory,
    foundation_live::HostHealth,
    host::capacity::{self, CgroupScope},
    infra::{FIXTURE_MEMORY_BYTES, GIB},
};

pub const PROTOCOL: &str = "zdn-foundation-health/v1alpha1";
const FACTS_BUDGET: Duration = Duration::from_secs(20);
const COMMAND_BUDGET: Duration = Duration::from_secs(5);
const IO_BUDGET: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(10);
const MAX_REQUEST: usize = 8192;

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_host.observe")
)]
pub fn observe(
    network_id: Uuid,
    size: Size,
    root: &Path,
    chain_directory: &Path,
) -> Result<HostHealth> {
    facts(
        network_id,
        size,
        root,
        chain_directory,
        &AtomicBool::new(false),
    )
    .map_err(|_| eyre::eyre!("foundation host is not ready"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_host.facts")
)]
fn facts(
    network_id: Uuid,
    size: Size,
    root: &Path,
    chain_directory: &Path,
    cancel: &AtomicBool,
) -> Result<HostHealth> {
    let deadline = Instant::now() + FACTS_BUDGET;
    ensure!(
        network_id.get_version_num() == 4 && network_id.get_variant() == uuid::Variant::RFC4122,
        "network identity must be UUIDv4"
    );
    ensure!(!cancel.load(Ordering::Relaxed), "cancelled");
    let observed = capacity::observe(root, CgroupScope::AncestorsOnly)?;
    let effective_memory_bytes = observed
        .ancestor_memory_limits_bytes
        .iter()
        .copied()
        .fold(observed.mem_total_bytes, u64::min);
    let visible_cpu_millis = observed.ancestor_cpu_quota_millis.iter().copied().fold(
        observed
            .affinity_cpu_count
            .checked_mul(1000)
            .context("CPU overflow")?,
        u32::min,
    );
    let allocation = size.allocation();
    let application_memory_bytes = effective_memory_bytes
        .checked_sub(u64::from(allocation.host_reserve_gib) * GIB)
        .context("insufficient memory")?
        .min(u64::from(allocation.max_node_gib) * GIB)
        .checked_sub(FIXTURE_MEMORY_BYTES)
        .context("insufficient memory")?;
    ensure!(
        application_memory_bytes > 0 && visible_cpu_millis > 500,
        "insufficient capacity"
    );
    for (program, args) in [
        ("systemctl", vec!["is-active", "--quiet", "docker"]),
        (
            "systemctl",
            vec!["is-active", "--quiet", "amazon-ssm-agent"],
        ),
        ("systemctl", vec!["is-active", "--quiet", "zdn-chain"]),
        ("docker", vec!["info", "--format", "{{.ServerVersion}}"]),
    ] {
        #[cfg(feature = "profiling")]
        let _service_span = if program == "docker" {
            tracing::info_span!("foundation_host.docker_info")
        } else {
            tracing::info_span!("foundation_host.service_check")
        }
        .entered();
        ensure!(!cancel.load(Ordering::Relaxed), "cancelled");
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("facts deadline")?;
        let output = run_command_in_memory(
            Command::new(program).args(args),
            remaining.min(COMMAND_BUDGET),
        )
        .map_err(|_| eyre::eyre!("service check failed"))?;
        ensure!(output.success, "service check failed");
    }
    ensure!(
        is_mount(chain_directory)?,
        "chain filesystem is not mounted"
    );
    ensure!(
        Instant::now() < deadline && !cancel.load(Ordering::Relaxed),
        "facts deadline"
    );
    Ok(HostHealth {
        schema_version: 1,
        network_id,
        status: "ready".into(),
        chain_mounted: true,
        docker_active: true,
        ssm_active: true,
        effective_memory_bytes,
        application_memory_bytes,
        visible_cpus: observed.affinity_cpu_count,
        visible_cpu_millis,
        application_cpu_millis: visible_cpu_millis - 500,
    })
}

// Match POSIX os.path.ismount: lstat rejects a final symlink; compare device
// and inode with the resolved parent. In particular, same-device bind mounts
// are not promoted to mounts via mountinfo or mount IDs.
#[cfg(unix)]
fn is_mount(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let here = std::fs::symlink_metadata(path)?;
    if here.file_type().is_symlink() {
        return Ok(false);
    }
    let parent = std::fs::metadata(path.join("..").canonicalize()?)?;
    Ok(here.dev() != parent.dev() || here.ino() == parent.ino())
}

#[cfg(not(unix))]
fn is_mount(_: &Path) -> Result<bool> {
    Ok(false)
}

/// Serial, bounded HTTP service; cancellation is checked between commands and
/// on each I/O poll. An in-flight owned command may take up to five seconds to
/// finish/clean up. No worker threads or persistent readiness files are used.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_host.serve")
)]
pub fn serve(
    listener: TcpListener,
    network_id: Uuid,
    size: Size,
    root: &Path,
    chain_directory: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    ensure!(
        matches!(listener.local_addr()?.ip(), std::net::IpAddr::V4(ip) if ip.is_loopback()),
        "foundation listener must use IPv4 loopback"
    );
    listener.set_nonblocking(true)?;
    while !cancel.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Peer protocol errors are isolated from the serving lifecycle.
                let _ = handle(&mut stream, network_id, size, root, chain_directory, cancel);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "foundation_host.handle")
)]
fn handle(
    stream: &mut TcpStream,
    network_id: Uuid,
    size: Size,
    root: &Path,
    chain_directory: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    let started = Instant::now();
    let mut request = Vec::new();
    let mut buf = [0; 1024];
    loop {
        ensure!(
            !cancel.load(Ordering::Relaxed) && started.elapsed() < IO_BUDGET,
            "request deadline"
        );
        match stream.read(&mut buf) {
            Ok(0) => eyre::bail!("incomplete request"),
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                ensure!(request.len() <= MAX_REQUEST, "request too large");
                if request.windows(4).any(|v| v == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let read_elapsed = started.elapsed();
    let text = std::str::from_utf8(&request)?;
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    let valid = parts.len() == 3
        && matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[0].bytes().all(|c| c.is_ascii_alphabetic())
        && parts[1].bytes().all(|c| c.is_ascii_graphic())
        && text.ends_with("\r\n\r\n")
        && lines.take_while(|line| !line.is_empty()).all(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                !name.is_empty()
                    && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    && !value.bytes().any(|c| c.is_ascii_control() && c != b'\t')
                    // This endpoint consumes no body. Reject ambiguous framing
                    // rather than probing before an advertised body arrives.
                    && !name.eq_ignore_ascii_case("transfer-encoding")
                    && (!name.eq_ignore_ascii_case("content-length") || value.trim() == "0")
            })
        });
    let (status, body) = if !valid {
        ("400 Bad Request", "{}".into())
    } else if parts[0] != "GET" {
        ("405 Method Not Allowed", "{}".into())
    } else if parts[1] != "/health" {
        ("404 Not Found", "{}".into())
    } else {
        match facts(network_id, size, root, chain_directory, cancel) {
            Ok(health) => ("200 OK", serde_json::to_string(&health)?),
            Err(_) => (
                "503 Service Unavailable",
                "{\"status\":\"not-ready\"}".into(),
            ),
        }
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let deadline = Instant::now() + IO_BUDGET.saturating_sub(read_elapsed);
    let mut bytes = response.as_bytes();
    while !bytes.is_empty() {
        ensure!(
            !cancel.load(Ordering::Relaxed) && Instant::now() < deadline,
            "response deadline"
        );
        match stream.write(bytes) {
            Ok(0) => eyre::bail!("closed response"),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
