//! Root-only phase-one executor. Reuses authenticated delivery, image pull,
//! action receipts and the existing volume format/claim algorithm. This action
//! runs only the native identity command, not a node or bootstrap controller.
use super::Manifest;
use crate::{
    host::{
        command::{Executor, HostCommand},
        files, firewall, image_delivery, node_paths,
        runtime::control::Config,
        volume::prepare,
    },
    native_peers::NativeIdentity,
};
use eyre::{ensure, Result};
use serde_json::Value;
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Invoked only with the authenticated manifest on bounded stdin by the pinned
/// host helper. Errors are deliberately fixed: tool output can contain secrets.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.identity.runtime.execute")
)]
pub fn execute(cancelled: &AtomicBool) -> Result<Value> {
    (|| {
        ensure!(nix::unistd::Uid::effective().is_root() && std::env::consts::ARCH == "x86_64", "unsupported host");
        let mut bytes = Vec::new();
        std::io::stdin().take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        let manifest = Manifest::from_slice(&bytes)?;
        provision(&manifest, cancelled)
    })().map_err(|_: eyre::Report| eyre::eyre!("external native identity provisioning failed; retain immutable inputs and inspect host evidence"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.identity.runtime.provision")
)]
fn provision(manifest: &Manifest, cancelled: &AtomicBool) -> Result<Value> {
    manifest.validate()?;
    crate::host::external::require_isolated_execution()?;
    let deadline = Instant::now() + Duration::from_secs(4800);
    let mut check = || {
        ensure!(
            Instant::now() < deadline - Duration::from_secs(10)
                && !cancelled.load(Ordering::Relaxed),
            "external identity action interrupted"
        );
        Ok(())
    };
    let config = Config {
        root: Path::new("/"),
        owner: 0,
        node_owner: crate::image::RUNTIME_UID,
    };
    let mut running = File::open("/proc/self/exe")?;
    let info = running.metadata()?;
    ensure!(
        info.is_file() && info.uid() == 0 && info.mode() & 0o022 == 0 && info.mode() & 0o100 != 0,
        "untrusted native identity helper"
    );
    let pin = &manifest.sources.host_helper;
    let digest = files::digest_file(&mut running, pin.bytes, &mut check)?;
    ensure!(
        digest.bytes == pin.bytes && digest.sha256 == pin.sha256,
        "native identity helper pin differs"
    );
    crate::devnet::validate_helper(&digest.prefix)?;
    let etc = config.open("/etc")?;
    ensure!(
        etc.read("zdn-prerequisites-ready", 33)? == b"zdn-host-prerequisites/v1alpha1\n",
        "host prerequisites are not ready"
    );
    let aws = config.tool("aws")?;
    let docker = config.tool("docker")?;
    let tools = prepare::Tools {
        probe: config.probe_tools()?,
        mkfs_ext4: config.tool("mkfs.ext4")?,
        mount: config.tool("mount")?,
    };
    let iptables = config.tool("iptables")?;
    let ip6tables = config.tool("ip6tables")?;
    let metadata = etc.ensure_directory("zdn", 0o700)?;
    metadata.require_absent("native-install-intent.json")?;
    let mut installation = manifest.provisioning.acquire(&metadata)?;
    let artifacts = metadata.ensure_directory("external-artifacts", 0o700)?;
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("external-native-identity", 0o700)?;
    metadata.ensure_directory("scratch", 0o700)?;
    let mut executor = Executor::new(
        Path::new("/proc/self/exe").into(),
        config.path("/etc/zdn/commands/external-native-identity"),
        pin.region.clone(),
        deadline,
    )?;
    manifest.deliver(&artifacts, &aws, &mut executor, cancelled)?;
    let prepared = manifest.prepare(&artifacts, deadline, cancelled)?;
    image_delivery::pull_image(
        &manifest.request.image.image,
        &pin.region,
        &config.path("/etc/zdn/scratch"),
        &image_delivery::Tools {
            aws,
            docker: docker.clone(),
        },
        &mut executor,
        cancelled,
        || {},
    )?;
    let actual = executor.execute(
        HostCommand {
            program: &docker,
            args: &[
                "image".into(),
                "inspect".into(),
                manifest.request.image.image.clone().into(),
            ],
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    )?;
    prepared.verify_pulled_image(manifest, &actual.stdout)?;
    firewall::ensure_rules(&iptables, &ip6tables, true, &mut executor, cancelled)?;
    prepare::prepare(
        &manifest.provisioning,
        prepare::Root {
            path: config.root,
            owner: config.owner,
        },
        &tools,
        &mut installation,
        &mut executor,
        cancelled,
        true,
    )?;
    let volume = config.open(crate::host::DATA_ROOT)?;
    let node = node_paths::create_external(
        &manifest.provisioning,
        &volume,
        &installation,
        config.node_owner,
    )?;
    let saved = match node.read(
        "native-public-identity.json",
        crate::native_peers::MAX_IDENTITY_BYTES as u64,
    ) {
        Ok(bytes) => Some(NativeIdentity::from_json(&bytes)?),
        Err(error)
            if error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    if saved.is_none() {
        // An interrupted first ensure must not become permission to regenerate
        // a lost key. Once attempted, only a saved public ID can authorize the
        // native command's strict load path. Lost final-runtime metadata is not
        // evidence of a new deployment either.
        require_unattempted(&node, &metadata)?;
    }
    let (name, config_toml) = if let Some(saved) = &saved {
        (
            "native-identity-check.toml",
            prepared.verification_config(manifest, saved, deadline, cancelled)?,
        )
    } else {
        ("native-identity.toml", manifest.config_toml.clone())
    };
    node.publish(name, config_toml.as_bytes(), 0o444)?;
    cleanup(manifest, &docker, &mut executor, cancelled)?;
    let args = arguments(manifest, name)?
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    if saved.is_none() {
        // Publish before dispatch: failure or cancellation cannot make an
        // uncertain native key-generation attempt safe to repeat.
        node.publish(
            "native-identity-attempt.json",
            &manifest.provisioning.bytes()?,
            0o600,
        )?;
    }
    let outcome = executor.execute(
        HostCommand {
            program: &docker,
            args: &args,
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    );
    // Cleanup uses a fresh cancellation flag but the same action deadline and
    // ownership checks. No retry of the native key operation is performed.
    cleanup(manifest, &docker, &mut executor, &AtomicBool::new(false))?;
    let identity = NativeIdentity::from_json(&outcome?.stdout)?;
    ensure!(
        identity.chain_fingerprint.as_deref() == Some(&manifest.provisioning.native_fingerprint)
            && saved.as_ref().is_none_or(|saved| *saved == identity),
        "native public identity changed"
    );
    let bytes = serde_json::to_vec(&identity)?;
    node.publish("native-public-identity.json", &bytes, 0o600)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn require_unattempted(node: &files::Directory, metadata: &files::Directory) -> Result<()> {
    node.require_absent("native-identity-attempt.json")?;
    metadata.require_absent("external-runtime-intent.json")?;
    node.require_absent("zakura.toml")?;
    node.require_absent("bootstrap-complete.json")?;
    node.require_absent("producer-authorized.json")?;
    Ok(())
}

fn name(manifest: &Manifest) -> String {
    format!(
        "zdn-native-identity-{}-{}",
        manifest.provisioning.deployment_id, manifest.provisioning.node_id
    )
}

/// Literal closed argv; only persistent key storage is writable. No cookie,
/// state, home, host credentials, network, start or shell command is exposed.
pub fn arguments(manifest: &Manifest, config_name: &str) -> Result<Vec<String>> {
    manifest.validate()?;
    ensure!(
        matches!(
            config_name,
            "native-identity.toml" | "native-identity-check.toml"
        ),
        "invalid native identity config selection"
    );
    let root = manifest.provisioning.node_root();
    Ok(vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name(manifest),
        "--label".into(),
        format!(
            "zdn.external.identity={}",
            manifest.provisioning.install_sha256()?
        ),
        "--platform".into(),
        "linux/amd64".into(),
        "--network".into(),
        "none".into(),
        "--user".into(),
        format!(
            "{}:{}",
            crate::image::RUNTIME_UID,
            crate::image::RUNTIME_GID
        ),
        "--workdir".into(),
        "/".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--no-healthcheck".into(),
        "--pids-limit".into(),
        "128".into(),
        "--memory".into(),
        "268435456".into(),
        "--memory-swap".into(),
        "268435456".into(),
        "--cpus".into(),
        "1".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777".into(),
        "--mount".into(),
        format!("type=bind,src={root}/{config_name},dst={root}/{config_name},readonly"),
        "--mount".into(),
        format!("type=bind,src={root}/identity,dst={root}/identity"),
        "--entrypoint".into(),
        crate::image::ENV_ENTRYPOINT.into(),
        manifest.request.image.image.clone(),
        "-i".into(),
        format!("PATH={}", crate::image::LAUNCH_PATH),
        format!("HOME={}", crate::image::LAUNCH_HOME),
        crate::image::NODE_BINARY.into(),
        "--config".into(),
        format!("{root}/{config_name}"),
        "native-identity".into(),
        "--identity-dir".into(),
        format!("{root}/identity"),
    ])
}

fn cleanup(
    manifest: &Manifest,
    docker: &Path,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    let output = executor.execute(
        HostCommand {
            program: docker,
            args: &[
                "inspect".into(),
                "--type".into(),
                "container".into(),
                name(manifest).into(),
            ],
            stdin: None,
            timeout: Duration::from_secs(20),
            allowed: &[0, 1],
        },
        cancelled,
    )?;
    if output.exit_code == 1 {
        return Ok(());
    }
    let value: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    ensure!(
        value.len() == 1,
        "native identity container inspection differs"
    );
    let container = &value[0];
    let id = container["Id"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing native identity container ID"))?;
    ensure!(
        id.len() == 64
            && id.bytes().all(|b| b.is_ascii_hexdigit())
            && container["Name"] == format!("/{}", name(manifest))
            && container["Config"]["Image"] == manifest.request.image.image
            && container["Config"]["Labels"]["zdn.external.identity"]
                == manifest.provisioning.install_sha256()?,
        "native identity container is not owned by this provisioning"
    );
    executor.execute(
        HostCommand {
            program: docker,
            args: &["rm".into(), "--force".into(), id.into()],
            stdin: None,
            timeout: Duration::from_secs(20),
            allowed: &[0],
        },
        cancelled,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{files::Directory, require_unattempted};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn uncertain_identity_ensure_and_lost_public_receipts_never_authorize_regeneration() {
        for (in_metadata, name) in [
            (false, "native-identity-attempt.json"),
            (true, "external-runtime-intent.json"),
            (false, "zakura.toml"),
            (false, "bootstrap-complete.json"),
            (false, "producer-authorized.json"),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let directory =
                Directory::open(root.path(), root.path().metadata().unwrap().uid()).unwrap();
            let node = directory.ensure_directory("node", 0o700).unwrap();
            let metadata = directory.ensure_directory("metadata", 0o700).unwrap();
            require_unattempted(&node, &metadata).unwrap();
            let owner = if in_metadata { &metadata } else { &node };
            owner
                .publish(name, b"retained public evidence", 0o600)
                .unwrap();
            assert!(require_unattempted(&node, &metadata).is_err(), "{name}");
        }
    }
}
