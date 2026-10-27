#![cfg(target_os = "linux")]

use std::{fs, path::Path};
use zdn::{
    config::Size,
    host::capacity::{observe, CgroupScope::*},
    infra::{effective_limits, EffectiveLimits, HostObservation},
};

const GIB: u64 = 1 << 30;

fn write(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value).unwrap();
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "proc/meminfo",
        "MemFree: 10 kB\nMemTotal: 16777216 kB\n",
    );
    write(
        root,
        "proc/self/status",
        "Name: fixture\nCpus_allowed_list:\t1-3,8,10-11\n",
    );
    write(root, "sys/devices/system/cpu/online", "0-7,10-13\n");
    write(root, "proc/self/cgroup", "0::/slice/service\n");
    fs::create_dir_all(root.join("sys/fs/cgroup/slice/service")).unwrap();
    dir
}

fn expected(memory: Vec<u64>, cpu: Vec<u32>) -> HostObservation {
    HostObservation {
        mem_total_bytes: 16 * GIB,
        ancestor_memory_limits_bytes: memory,
        online_cpu_count: 12,
        affinity_cpu_count: 6,
        ancestor_cpu_quota_millis: cpu,
    }
}

fn assert_observation(actual: &HostObservation, expected: HostObservation) {
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

fn allocation(memory: u64, cpu: u32) -> EffectiveLimits {
    EffectiveLimits {
        effective_memory_bytes: memory,
        host_reserve_bytes: 2 * GIB,
        fixture_memory_bytes: GIB / 4,
        application_memory_bytes: memory - 2 * GIB - GIB / 4,
        visible_cpu_millis: cpu,
        application_cpu_millis: cpu - 500,
    }
}

#[test]
fn asymmetric_limits_scopes_and_root_membership() {
    let dir = fixture();
    let root = dir.path();
    for (group, memory, cpu) in [
        ("", 12 * GIB, "390001 100000"),
        ("/slice", 8 * GIB, "max 100000"),
        ("/slice/service", 10 * GIB, "175099 100000"),
    ] {
        write(
            root,
            &format!("sys/fs/cgroup{group}/memory.max"),
            &memory.to_string(),
        );
        write(root, &format!("sys/fs/cgroup{group}/cpu.max"), cpu);
    }
    let current = observe(root, CurrentAndAncestors).unwrap();
    assert_observation(
        &current,
        expected(vec![10 * GIB, 8 * GIB, 12 * GIB], vec![1750, 3900]),
    );
    assert_eq!(
        effective_limits(Size::Medium, &current).unwrap(),
        allocation(8 * GIB, 1750)
    );
    #[cfg(feature = "profiling")]
    {
        use std::process::Command;

        let command = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_zdn"));
            command.env_clear().args([
                "__host-capacity",
                "--protocol",
                "zdn-host-capacity/v1alpha1",
                "--root",
                root.to_str().unwrap(),
            ]);
            command
        };
        let baseline = command().output().unwrap();
        assert!(baseline.status.success(), "{baseline:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&baseline.stdout).unwrap(),
            serde_json::to_value(expected(
                vec![10 * GIB, 8 * GIB, 12 * GIB],
                vec![1750, 3900]
            ))
            .unwrap()
        );
        let trace = root.join("timings.jsonl");
        let traced = command().env("ZDN_TRACE_FILE", &trace).output().unwrap();
        assert!(traced.status.success(), "{traced:?}");
        assert_eq!(traced.stdout, baseline.stdout);
        assert_eq!(traced.stderr, baseline.stderr);
        let text = fs::read_to_string(trace).unwrap();
        assert!(!text.contains(root.to_str().unwrap()));
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let observation = records
            .iter()
            .find(|record| record["span"]["name"] == "host.capacity.observe")
            .unwrap();
        assert_eq!(observation["span"].as_object().unwrap().len(), 1);
        assert!(observation["fields"]["time.busy"].is_string());
        assert!(observation["fields"]["time.idle"].is_string());
        assert!(observation["spans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|span| span["name"] == "cli.run"));
    }
    let parent = observe(root, AncestorsOnly).unwrap();
    assert_observation(&parent, expected(vec![8 * GIB, 12 * GIB], vec![3900]));
    assert_eq!(
        effective_limits(Size::Medium, &parent).unwrap(),
        allocation(8 * GIB, 3900)
    );
    // Reverse which memory level binds; neither scope may skip the root.
    write(
        root,
        "sys/fs/cgroup/slice/service/memory.max",
        &(4 * GIB).to_string(),
    );
    write(root, "sys/fs/cgroup/cpu.max", "125000 100000");
    let current = observe(root, CurrentAndAncestors).unwrap();
    assert_observation(
        &current,
        expected(vec![4 * GIB, 8 * GIB, 12 * GIB], vec![1750, 1250]),
    );
    assert_eq!(
        effective_limits(Size::Medium, &current).unwrap(),
        allocation(4 * GIB, 1250)
    );
    write(root, "proc/self/cgroup", "0::/\n");
    let current = observe(root, CurrentAndAncestors).unwrap();
    assert_observation(&current, expected(vec![12 * GIB], vec![1250]));
    assert_eq!(
        effective_limits(Size::Medium, &current).unwrap(),
        allocation(12 * GIB, 1250)
    );
    let parent = observe(root, AncestorsOnly).unwrap();
    assert_observation(&parent, expected(vec![], vec![]));
    let mut full = allocation(16 * GIB, 4000);
    full.application_memory_bytes = 14 * GIB - GIB / 4;
    assert_eq!(effective_limits(Size::Medium, &parent).unwrap(), full);
}

#[test]
fn absent_unlimited_and_zero_controllers() {
    let dir = fixture();
    let root = dir.path();
    write(root, "sys/fs/cgroup/memory.max", "max\n");
    write(root, "sys/fs/cgroup/slice/cpu.max", "max 100000\n");
    for scope in [CurrentAndAncestors, AncestorsOnly] {
        let observed = observe(root, scope).unwrap();
        assert_observation(&observed, expected(vec![], vec![]));
        assert_eq!(
            effective_limits(Size::Medium, &observed).unwrap(),
            allocation(16 * GIB, 4000)
        );
    }
    let mut large = allocation(16 * GIB, 6000);
    large.host_reserve_bytes = 4 * GIB;
    large.application_memory_bytes = 12 * GIB - GIB / 4;
    assert_eq!(
        effective_limits(Size::Large, &observe(root, CurrentAndAncestors).unwrap()).unwrap(),
        large
    );
    write(root, "sys/devices/system/cpu/online", "0-2\n");
    let observed = observe(root, CurrentAndAncestors).unwrap();
    let mut fewer_online = expected(vec![], vec![]);
    fewer_online.online_cpu_count = 3;
    assert_observation(&observed, fewer_online);
    assert_eq!(
        effective_limits(Size::Medium, &observed).unwrap(),
        allocation(16 * GIB, 3000)
    );
    write(root, "sys/devices/system/cpu/online", "0-7,10-13\n");
    for quota in ["0 100000", "1 100000"] {
        write(root, "sys/fs/cgroup/slice/service/cpu.max", quota);
        let observed = observe(root, CurrentAndAncestors).unwrap();
        assert_observation(&observed, expected(vec![], vec![0]));
        assert!(effective_limits(Size::Medium, &observed).is_err());
    }
}

#[test]
fn rejects_malformed_ambiguous_overflowing_and_unbounded_inputs() {
    for (name, values) in [
        (
            "proc/self/cgroup",
            vec![
                "",
                "0::relative",
                "0::/../escape",
                "0::/slice/./service",
                "0:://slice",
                "0::/slice/",
                "0::/\n0::/slice",
                "0:cpu:/",
                "1::/",
                "bad",
                "0::",
            ],
        ),
        (
            "proc/meminfo",
            vec![
                "MemTotal: 1 MB",
                "MemTotal: -1 kB",
                "MemTotal: 18446744073709551615 kB",
                "MemTotal: 1 kB\nMemTotal: 2 kB",
            ],
        ),
        (
            "sys/devices/system/cpu/online",
            vec![
                "",
                "3-1",
                "0-3,3",
                "1,,2",
                "0-4294967295",
                "4294967296",
                "1-2-3",
            ],
        ),
        (
            "proc/self/status",
            vec![
                "Cpus_allowed_list: 1,1",
                "Cpus_allowed_list: -1",
                "Cpus_allowed_list: 1\nCpus_allowed_list: 2",
            ],
        ),
        (
            "sys/fs/cgroup/slice/service/memory.max",
            vec!["", "-1", "max 1", "18446744073709551616"],
        ),
        (
            "sys/fs/cgroup/slice/service/cpu.max",
            vec![
                "",
                "max",
                "max 0",
                "max nope",
                "1 0",
                "-1 100000",
                "1 1 extra",
                "18446744073709551615 1",
                "4294968 1",
            ],
        ),
    ] {
        for value in values {
            let dir = fixture();
            write(dir.path(), name, value);
            assert!(
                observe(dir.path(), CurrentAndAncestors).is_err(),
                "accepted {name}={value:?}"
            );
        }
    }
    let dir = fixture();
    write(dir.path(), "proc/self/status", &"x".repeat(1024 * 1024 + 1));
    assert!(observe(dir.path(), CurrentAndAncestors).is_err());
    // Both directory and controller symlinks are rejected, not followed.
    let outside = tempfile::tempdir().unwrap();
    let dir = fixture();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("sys/fs/cgroup/escape")).unwrap();
    write(dir.path(), "proc/self/cgroup", "0::/escape");
    assert!(observe(dir.path(), AncestorsOnly).is_err());
    write(dir.path(), "proc/self/cgroup", "0::/slice/service");
    std::os::unix::fs::symlink(
        outside.path().join("missing"),
        dir.path().join("sys/fs/cgroup/memory.max"),
    )
    .unwrap();
    assert!(observe(dir.path(), CurrentAndAncestors).is_err());
}
