//! Native node paths, adapted from retired `runner.py::create_node_paths`.
//!
//! The caller authenticates the inputs, freshly verifies mounted identity, and
//! reopens `volume` after mounting. A matching claim is necessary, not proof of
//! a current mount. Production retains the root-owned installation guard and
//! uses UID/GID 10001 for only the three node-write leaves. Alternate anchors
//! and owners are explicit caller trust inputs for offline filesystem fixtures.
//! Root-controlled ancestors remain stable throughout; this is not protection
//! against a hostile root. Native host installation selects this API.

use eyre::{ensure, Result};

use super::{files::Directory, volume::Installation, HostInstallSpec, DATA_ROOT};

/// Create exact immutable paths beneath a freshly verified mounted volume.
/// Existing entries are checked, never repaired, replaced or recursively chowned.
/// Node data is retained on retries; configuration stays root-owned/read-only.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.node_paths.create")
)]
pub fn create(
    spec: &HostInstallSpec,
    volume: &Directory,
    installation: &Installation<'_>,
    node_owner: u32,
) -> Result<Directory> {
    installation.verify_spec(spec)?;
    ensure!(
        volume.read(".zdn-volume.json", installation.identity().len() as u64)?
            == installation.identity(),
        "chain volume identity differs"
    );
    let logical = spec.node_root();
    let suffix = logical
        .strip_prefix(&format!("{DATA_ROOT}/"))
        .expect("node root prefix");
    let mut components = suffix.split('/');
    let mut current = volume.ensure_directory(components.next().expect("node root"), 0o755)?;
    for component in components {
        current = current.ensure_directory(component, 0o755)?;
    }
    for name in ["state", "identity", "rpc"] {
        current.ensure_owned_directory(name, 0o700, node_owner)?;
    }
    if spec.block_interval_seconds.is_some() && spec.role == "producer" {
        current.ensure_directory("producer", 0o700)?;
    }
    current.publish("zakura.toml", spec.config_toml.as_bytes(), 0o444)?;
    Ok(current)
}
