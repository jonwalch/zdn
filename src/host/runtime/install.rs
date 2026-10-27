//! Native first installation from runner.py::install/node_unit/producer_unit.
//!
//! The bootstrap must authenticate the manifest and executable pins before
//! invoking this root-only command. This installer authenticates the actual
//! running executable again, then records native intent under the original
//! install lock before identity publication. It cannot migrate a legacy host.
//! Stable trusted administrators, tools/daemon, procfs and outer supervision of
//! blocking filesystem/kernel operations remain required. Alternate roots are
//! explicit offline fixture views, not namespaces or relaxed device authority.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use eyre::{ensure, Context, Result};
use serde_json::Value;

use super::{control::Config, Manifest, PROTOCOL};
use crate::host::{
    artifact_delivery::{self, Artifact},
    command::{Executor, HostCommand},
    files, firewall, image_delivery, inputs, node_paths, readiness,
    volume::{prepare, Installation},
};

/// Fixed diagnostics only: never retain the underlying provider/tool error.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Preflight,
    ArtifactDelivery,
    InputVerification,
    ImageDelivery,
    Firewall,
    VolumePreparation,
    ServicePublication,
    ServiceActivation,
    FinalVerification,
    Readiness,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Preflight => "preflight",
            Self::ArtifactDelivery => "artifact-delivery",
            Self::InputVerification => "input-verification",
            Self::ImageDelivery => "image-delivery",
            Self::Firewall => "firewall",
            Self::VolumePreparation => "volume-preparation",
            Self::ServicePublication => "service-publication",
            Self::ServiceActivation => "service-activation",
            Self::FinalVerification => "final-verification",
            Self::Readiness => "readiness",
        };
        write!(formatter, "native host installation failed at stage {name}")
    }
}

impl std::error::Error for Stage {}

/// Bounded stdin is provided by the pinned bootstrap, not a mutable on-host
/// manifest path. The separate install capability never grants migration. Errors
/// cross the CLI boundary as a stage alone, with no source chain or raw text.
pub fn execute(cancelled: &AtomicBool) -> Result<Value, Stage> {
    (|| {
        ensure!(
            nix::unistd::Uid::effective().is_root(),
            "host install requires root"
        );
        ensure!(
            std::env::consts::ARCH == "x86_64",
            "host install requires x86-64"
        );
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(super::MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let manifest = Manifest::from_slice(&bytes)?;
        install(
            &manifest,
            Config {
                root: Path::new("/"),
                owner: 0,
                node_owner: crate::image::RUNTIME_UID,
            },
            File::open("/proc/self/exe")?,
            cancelled,
        )
    })()
    .map_err(|error: eyre::Report| {
        error
            .downcast_ref::<Stage>()
            .copied()
            .unwrap_or(Stage::Preflight)
    })
}

/// First install or exact native retry only. `running` is /proc/self/exe in
/// production; the caller authenticates that boundary, manifest authority and
/// the filesystem/kernel/tool view. No selection is inferred from a version.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.runtime.install.total")
)]
pub fn install(
    manifest: &Manifest,
    config: Config<'_>,
    mut running: File,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(4800);
    let work_deadline = deadline - Duration::from_secs(10);
    let mut check = || {
        ensure!(
            Instant::now() < work_deadline && !cancelled.load(Ordering::Relaxed),
            "host installation interrupted"
        );
        Ok(())
    };
    let bytes = manifest.bytes()?;
    ensure!(config.root.is_absolute(), "host root must be absolute");
    check()?;
    let pin = &manifest.runtime.helper;
    let info = running.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == config.owner
            && info.mode() & 0o022 == 0
            && info.mode() & 0o100 != 0,
        "untrusted installer executable"
    );
    running.rewind()?;
    let digest = files::digest_file(&mut running, pin.bytes, &mut check)?;
    ensure!(
        digest.bytes == pin.bytes && digest.sha256 == pin.sha256,
        "installer executable differs"
    );
    crate::devnet::validate_helper(&digest.prefix)?;
    let etc = config.open("/etc")?;
    let mut marker = etc.regular("zdn-prerequisites-ready", 33)?;
    ensure!(
        marker.metadata()?.mode() & 0o7777 == 0o600,
        "invalid prerequisite marker mode"
    );
    let mut marker_bytes = Vec::new();
    files::read_chunks(&mut marker, 33, &mut check, |chunk| {
        marker_bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    ensure!(
        marker_bytes == b"zdn-host-prerequisites/v1alpha1\n",
        "invalid prerequisite marker"
    );
    // Lost legacy identity is not permission to replace its program or units.
    // Identity publication by any cooperating installer is serialized below.
    match config.open("/usr/local/libexec") {
        Ok(directory) => directory.require_absent("zdn-host.py")?,
        Err(error)
            if error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(error),
    }
    let units = config.open("/etc/systemd/system")?;
    let (node_unit, producer_unit) = units_for(manifest)?;
    // Reject conflicting installed units before downloads, firewall or disks.
    for (name, expected) in [
        ("zdn-node.service", Some(node_unit.as_str())),
        ("zdn-producer.service", producer_unit.as_deref()),
    ] {
        match units.read(name, 64 * 1024) {
            Ok(actual) => ensure!(
                Some(actual.as_slice()) == expected.map(str::as_bytes),
                "installed service unit differs"
            ),
            Err(error)
                if error.downcast_ref::<nix::errno::Errno>()
                    == Some(&nix::errno::Errno::ENOENT) => {}
            Err(error) => return Err(error),
        }
    }
    let metadata = etc.ensure_directory("zdn", 0o700)?;
    let mut installation = Installation::acquire_native(&metadata, &manifest.spec, &bytes)?;
    ensure!(
        super::revision::Snapshot::from_installation(&metadata, manifest)?
            .is_none_or(|snapshot| snapshot.transaction.is_none()),
        "native image update must be resumed rather than reinstalling the original recipe"
    );
    let runtime = metadata.ensure_directory("runtime", 0o700)?;
    let executable_dir = runtime.ensure_directory(&pin.sha256, 0o700)?;
    let artifacts = metadata.ensure_directory("artifacts", 0o700)?;
    let reuse_helper =
        pin.bytes == manifest.spec.helper.bytes && pin.sha256 == manifest.spec.helper.sha256;
    for destination in std::iter::once(&executable_dir).chain(reuse_helper.then_some(&artifacts)) {
        if !destination.artifact_matches(
            "zdn",
            &digest,
            0o555,
            &mut check,
            crate::devnet::validate_helper,
        )? {
            let staging = destination.download()?;
            let result = (|| {
                running.rewind()?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(staging.path())?;
                files::read_chunks(&mut running, pin.bytes, &mut check, |chunk| {
                    output.write_all(chunk)?;
                    Ok(())
                })?;
                drop(output);
                destination.publish_download(
                    "zdn",
                    &staging,
                    &digest,
                    0o555,
                    &mut check,
                    crate::devnet::validate_helper,
                )
            })();
            staging.close()?;
            result?;
        }
    }
    let executable = config.path(&format!("/etc/zdn/runtime/{}/zdn", pin.sha256));
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("install", 0o700)?;
    let mut executor = Executor::new(
        executable,
        config.path("/etc/zdn/commands/install"),
        manifest.spec.helper.region.clone(),
        deadline,
    )?;
    let aws = config.tool("aws")?;
    let docker = config.tool("docker")?;
    let systemctl = config.tool("systemctl")?;
    let tools = prepare::Tools {
        probe: config.probe_tools()?,
        mkfs_ext4: config.tool("mkfs.ext4")?,
        mount: config.tool("mount")?,
    };
    let iptables = config.tool("iptables")?;
    let ip6tables = config.tool("ip6tables")?;
    for kind in [
        Artifact::Manifest,
        Artifact::Bundle,
        Artifact::Helper,
        Artifact::ImageRecord,
        Artifact::ImageManifest,
    ] {
        if reuse_helper && matches!(kind, Artifact::Helper) {
            continue;
        }
        artifact_delivery::fetch(
            &manifest.spec,
            kind,
            &artifacts,
            &aws,
            &mut executor,
            cancelled,
        )
        .wrap_err(Stage::ArtifactDelivery)?;
    }
    inputs::verify(&manifest.spec, &artifacts).wrap_err(Stage::InputVerification)?;
    metadata
        .ensure_directory("scratch", 0o700)
        .wrap_err(Stage::ImageDelivery)?;
    image_delivery::pull(
        &manifest.spec,
        &artifacts,
        &config.path("/etc/zdn/scratch"),
        &image_delivery::Tools {
            aws,
            docker: docker.clone(),
        },
        &mut executor,
        cancelled,
    )
    .wrap_err(Stage::ImageDelivery)?;
    firewall::ensure_rules(&iptables, &ip6tables, true, &mut executor, cancelled)
        .wrap_err(Stage::Firewall)?;
    prepare::prepare(
        &manifest.spec,
        prepare::Root {
            path: config.root,
            owner: config.owner,
        },
        &tools,
        &mut installation,
        &mut executor,
        cancelled,
        true,
    )
    .wrap_err(Stage::VolumePreparation)?;
    let volume = config
        .open("/var/lib/zdn")
        .wrap_err(Stage::ServicePublication)?;
    node_paths::create(&manifest.spec, &volume, &installation, config.node_owner)
        .wrap_err(Stage::ServicePublication)?;
    let manifests = runtime
        .ensure_directory("manifests", 0o700)
        .wrap_err(Stage::ServicePublication)?;
    manifest
        .publish(&manifests, &installation)
        .wrap_err(Stage::ServicePublication)?;
    check().wrap_err(Stage::ServicePublication)?;
    units
        .publish("zdn-node.service", node_unit.as_bytes(), 0o644)
        .wrap_err(Stage::ServicePublication)?;
    if let Some(unit) = producer_unit {
        units
            .publish("zdn-producer.service", unit.as_bytes(), 0o644)
            .wrap_err(Stage::ServicePublication)?;
    }
    // ExecStartPre/ExecStartPost take this same lock. Retaining it while waiting
    // for systemctl start would deadlock first startup. Intent + immutable units
    // bind recovery; the action executor still excludes competing installers.
    drop(installation);
    #[cfg(feature = "profiling")]
    let activation = tracing::info_span!("host.runtime.install.activate").entered();
    for (args, seconds) in [
        (vec!["daemon-reload"], 60),
        (vec!["enable", "zdn-node.service"], 60),
        (vec!["start", "zdn-node.service"], 650),
        (vec!["is-active", "--quiet", "zdn-node.service"], 60),
    ] {
        executor
            .execute(
                HostCommand {
                    program: &systemctl,
                    args: &args.into_iter().map(Into::into).collect::<Vec<_>>(),
                    stdin: None,
                    timeout: Duration::from_secs(seconds),
                    allowed: &[0],
                },
                cancelled,
            )
            .wrap_err(Stage::ServiceActivation)?;
    }
    #[cfg(feature = "profiling")]
    drop(activation);
    #[cfg(feature = "profiling")]
    let _verification = tracing::info_span!("host.runtime.install.verify").entered();
    let installation = Installation::acquire_native(&metadata, &manifest.spec, &bytes)
        .wrap_err(Stage::FinalVerification)?;
    config
        .mounted(
            manifest,
            installation.identity(),
            &mut executor,
            cancelled,
            false,
        )
        .wrap_err(Stage::FinalVerification)?;
    inputs::verify(&manifest.spec, &artifacts).wrap_err(Stage::FinalVerification)?;
    firewall::ensure_rules(&iptables, &ip6tables, false, &mut executor, cancelled)
        .wrap_err(Stage::FinalVerification)?;
    let node = config
        .open(&manifest.spec.node_root())
        .wrap_err(Stage::Readiness)?;
    let report = readiness::readiness(
        &readiness::Config {
            spec: &manifest.spec,
            image: &manifest.spec.image,
            installation: &installation,
            node: &node,
            helper: &config.path("/etc/zdn/artifacts/zdn"),
            manifest: &config.path("/etc/zdn/artifacts/manifest.json"),
            bundle: &config.path("/etc/zdn/artifacts/chain.tar"),
            cookie: &config.path(&format!("{}/rpc/.cookie", manifest.spec.node_root())),
            producer_state: &config.path(&format!("{}/producer", manifest.spec.node_root())),
            systemctl: &systemctl,
            docker: &docker,
            kernel_root: config.root,
        },
        &mut executor,
        cancelled,
        false,
    )
    .wrap_err(Stage::Readiness)?;
    check().wrap_err(Stage::Readiness)?;
    Ok(report)
}

/// Native units retain the historical ordering, timeouts and producer sandbox.
/// Only fixed content-addressed paths enter systemd syntax. No shell/Python or
/// user-provided executable path is interpolated. No producer authorization is
/// created by installation; the separate cluster-wide gate remains mandatory.
pub fn units_for(manifest: &Manifest) -> Result<(String, Option<String>)> {
    manifest.validate()?;
    let command = format!("/etc/zdn/runtime/{}/zdn __host-runtime --protocol {PROTOCOL} --manifest /etc/zdn/runtime/manifests/{}", manifest.runtime.helper.sha256, manifest.file_name()?);
    let producer =
        manifest.spec.role == "producer" && manifest.spec.block_interval_seconds.is_some();
    let wants = if producer {
        "Wants=zdn-producer.service\n"
    } else {
        ""
    };
    let node = format!(
        r#"[Unit]
Description=zdn pinned private Zakura node
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
{wants}StartLimitIntervalSec=300
StartLimitBurst=3
[Service]
Type=notify
NotifyAccess=main
ExecStartPre={command} prepare
ExecStart={command} run
ExecStartPost={command} ready
ExecStop={command} stop
Restart=on-failure
RestartSec=10
TimeoutStartSec=600
TimeoutStopSec=135
KillMode=control-group
UMask=0077
[Install]
WantedBy=multi-user.target
"#
    );
    let producer = producer.then(|| {
        format!(
            r#"[Unit]
Description=zdn persistent private block controller
After=zdn-node.service
BindsTo=zdn-node.service
PartOf=zdn-node.service
ConditionPathExists={node}/producer-authorized.json
StartLimitIntervalSec=300
StartLimitBurst=3
[Service]
Type=exec
ExecStart={command} produce
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
KillSignal=SIGINT
KillMode=control-group
UMask=0077
MemoryMax=128M
CPUQuota=10%
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
PrivateTmp=true
RuntimeDirectory=zdn-producer
RuntimeDirectoryMode=0700
ReadWritePaths={node}/producer
[Install]
WantedBy=multi-user.target
"#,
            node = manifest.spec.node_root()
        )
    });
    Ok((node, producer))
}
