//! Read-only Linux capacity observations. No readiness or host identity claims.
//!
//! `root` supplies proc/ and sys/ (normally `/`). Inputs must be a stable,
//! trusted kernel/fixture tree: this is not a snapshot or a hostile-filesystem
//! race boundary. Cgroup paths may not contain symlinks.

use std::{fs, io::Read, path::Path};

use eyre::{ensure, Context, ContextCompat, Result};

use crate::infra::HostObservation;

const MAX_INPUT: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupScope {
    /// Capacity/install probes include the calling process's cgroup.
    CurrentAndAncestors,
    /// Foundation health excludes only the service's own cgroup. At root,
    /// there are no ancestors, so no controller files are consulted.
    AncestorsOnly,
}

/// Collect capacity without effects; finite controller limits are returned in
/// leaf-to-root order, including zero CPU results for allocation to reject.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.capacity.observe")
)]
pub fn observe(root: &Path, scope: CgroupScope) -> Result<HostObservation> {
    ensure!(
        cfg!(target_os = "linux"),
        "capacity observation requires Linux"
    );
    let root = root.canonicalize().context("resolve capacity root")?;
    let required = |name: &str| -> Result<String> {
        read(&root.join(name), &root)?.with_context(|| format!("missing {name}"))
    };
    let meminfo = required("proc/meminfo")?;
    let total = field(&meminfo, "MemTotal:")?;
    let words: Vec<_> = total.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[1] == "kB",
        "invalid MemTotal units"
    );
    let mem_total_bytes = number(words[0])?
        .checked_mul(1024)
        .context("MemTotal overflow")?;
    ensure!(mem_total_bytes > 0, "zero MemTotal");
    let online_cpu_count = cpu_count(required("sys/devices/system/cpu/online")?.trim())?;
    let status = required("proc/self/status")?;
    let affinity_cpu_count = cpu_count(field(&status, "Cpus_allowed_list:")?.trim())?;
    let membership = required("proc/self/cgroup")?;
    let mut unified = None;
    for line in membership.lines() {
        let parts: Vec<_> = line.splitn(3, ':').collect();
        ensure!(parts.len() == 3, "malformed cgroup membership");
        let id = number(parts[0])?;
        if id == 0 || parts[1].is_empty() {
            ensure!(
                parts[0] == "0" && parts[1].is_empty(),
                "invalid unified membership"
            );
            ensure!(
                unified.replace(parts[2]).is_none(),
                "ambiguous unified membership"
            );
        }
    }
    let membership = unified.context("missing unified cgroup membership")?;
    ensure!(membership.starts_with('/'), "cgroup path must be absolute");
    if membership != "/" {
        ensure!(
            membership[1..].split('/').all(|p| !p.is_empty()
                && p != "."
                && p != ".."
                && !p.chars().any(char::is_control)),
            "invalid cgroup path"
        );
    }
    let base = root.join("sys/fs/cgroup");
    let mut current = base.clone();
    // Reject symlink traversal before consulting any controller, even when the
    // current group itself will be excluded by the selected scope.
    let relative = format!("sys/fs/cgroup{}", membership.trim_end_matches('/'));
    let mut checked = root.clone();
    for part in relative.split('/') {
        checked.push(part);
        let metadata = fs::symlink_metadata(&checked).context("inspect cgroup directory")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "cgroup path is not a real directory"
        );
    }
    current.push(&membership[1..]);
    let mut observation = HostObservation {
        mem_total_bytes,
        ancestor_memory_limits_bytes: Vec::new(),
        online_cpu_count,
        affinity_cpu_count,
        ancestor_cpu_quota_millis: Vec::new(),
    };
    if scope == CgroupScope::AncestorsOnly {
        if current == base {
            return Ok(observation);
        }
        current.pop();
    }
    loop {
        if let Some(memory) = read(&current.join("memory.max"), &root)? {
            if memory.trim() != "max" {
                observation
                    .ancestor_memory_limits_bytes
                    .push(number(memory.trim())?);
            }
        }
        if let Some(cpu) = read(&current.join("cpu.max"), &root)? {
            let words: Vec<_> = cpu.split_whitespace().collect();
            ensure!(words.len() == 2, "invalid cpu.max");
            let period = number(words[1])?;
            ensure!(period > 0, "zero CPU period");
            if words[0] != "max" {
                let millis = number(words[0])?
                    .checked_mul(1000)
                    .context("CPU quota overflow")?
                    / period;
                observation
                    .ancestor_cpu_quota_millis
                    .push(u32::try_from(millis).context("CPU millis overflow")?);
            }
        }
        if current == base {
            break;
        }
        ensure!(
            current.pop() && current.starts_with(&base),
            "cgroup escaped root"
        );
    }
    Ok(observation)
}

fn read(path: &Path, root: &Path) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "input must be a regular non-symlink file: {}",
        path.display()
    );
    let resolved = path.canonicalize()?;
    ensure!(resolved.starts_with(root), "input escaped capacity root");
    let mut value = String::new();
    fs::File::open(&resolved)?
        .take(MAX_INPUT + 1)
        .read_to_string(&mut value)?;
    ensure!(value.len() as u64 <= MAX_INPUT, "capacity input too large");
    Ok(Some(value))
}

fn number(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "invalid unsigned integer"
    );
    value.parse().context("integer overflow")
}

fn field<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    let mut matches = text.lines().filter_map(|line| line.strip_prefix(key));
    let value = matches.next().with_context(|| format!("missing {key}"))?;
    ensure!(matches.next().is_none(), "duplicate {key}");
    Ok(value)
}

fn cpu_count(value: &str) -> Result<u32> {
    let mut previous = None;
    let mut count = 0_u64;
    for range in value.split(',') {
        let parts: Vec<_> = range.split('-').collect();
        ensure!(parts.len() <= 2, "invalid CPU range");
        let start = u32::try_from(number(parts[0])?)?;
        let end = if parts.len() == 2 {
            u32::try_from(number(parts[1])?)?
        } else {
            start
        };
        ensure!(
            start <= end && previous.is_none_or(|last| start > last),
            "unordered or overlapping CPU range"
        );
        count = count
            .checked_add(u64::from(end) - u64::from(start) + 1)
            .context("CPU count overflow")?;
        previous = Some(end);
    }
    u32::try_from(count).context("CPU count overflow")
}
