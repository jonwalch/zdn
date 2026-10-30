//! Image-only resume-forward external revisions using the ordinary runtime's
//! exact transaction/maintenance journal algorithm. Original volume/key/config,
//! helper, peer inventory and producer authorization are never replaced.
use super::{
    control::{self, Operation},
    Manifest, MAX_BYTES,
};
use crate::{
    host::{
        command::{Executor, HostCommand},
        files::Directory,
        image_delivery,
        runtime::{
            control::Config,
            revision::{GenericJournal, GenericSnapshot, Phase, RevisionOriginal, RevisionRequest},
        },
        volume::VolumeSpec,
    },
    public_chain_adapter::contract::{self, Pin},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::Read,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const SCHEMA: &str = "zdn-external-image-update/v1";
pub const NAMESPACE: &str = "external-updates";
pub type Snapshot = GenericSnapshot<Request>;
pub type Journal<'a, 'i> = GenericJournal<'a, 'i, Request>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub original: Manifest,
    pub update_id: Uuid,
    pub expected_image: String,
    pub expected_update_id: Option<Uuid>,
    pub target: Manifest,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA, "unsupported external update");
        self.original.validate()?;
        self.target.validate()?;
        for id in std::iter::once(self.update_id).chain(self.expected_update_id) {
            ensure!(
                id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
                "external update requires UUIDv4"
            );
        }
        ensure!(
            self.expected_update_id != Some(self.update_id),
            "self-referencing external update"
        );
        // Validate expected revision syntax independently, without treating it
        // as an authenticated target or changing its image capabilities.
        ensure!(
            self.expected_image.len() <= 512
                && self.expected_image.rsplit_once("@sha256:").is_some_and(
                    |(repository, digest)| !repository.is_empty()
                        && digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                ),
            "invalid expected image"
        );
        let mut allowed = self.original.clone();
        allowed.image = self.target.image.clone();
        allowed.chain.options.image_digest = self.target.chain.options.image_digest.clone();
        allowed.chain.objects.image_record = self.target.chain.objects.image_record.clone();
        allowed.chain.objects.image_manifest = self.target.chain.objects.image_manifest.clone();
        allowed.chain.objects.image_config = self.target.chain.objects.image_config.clone();
        ensure!(
            allowed.bytes()? == self.target.bytes()?,
            "external update may change only the image and its three authenticated public proofs"
        );
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= crate::host::runtime::revision::MAX_REQUEST_BYTES,
            "external update exceeds journal bound"
        );
        Ok(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= crate::host::runtime::revision::MAX_REQUEST_BYTES,
            "external update exceeds bound"
        );
        let value: Self = contract::parse(bytes)?;
        ensure!(value.bytes()? == bytes, "noncanonical external update");
        Ok(value)
    }
    pub fn render(&self) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(format!("#!/bin/bash\nset -euo pipefail\numask 077\nbase64 --decode <<'ZDN_EXTERNAL_UPDATE' | {} __external-update --protocol {SCHEMA}\n{}\nZDN_EXTERNAL_UPDATE\n",self.original.executable(),STANDARD.encode(self.bytes()?)))
    }
}
impl RevisionOriginal for Manifest {
    type Spec = Manifest;
    fn revision_bytes(&self) -> Result<Vec<u8>> {
        self.bytes()
    }
    fn revision_spec(&self) -> &Self::Spec {
        self
    }
    fn initial_image(&self) -> &str {
        &self.image.image
    }
}
impl RevisionRequest for Request {
    type Original = Manifest;
    const VERSION: &'static str = SCHEMA;
    const NAMESPACE: &'static str = crate::host::external::runtime::update::NAMESPACE;
    fn bytes(&self) -> Result<Vec<u8>> {
        self.bytes()
    }
    fn original(&self) -> &Manifest {
        &self.original
    }
    fn update_id(&self) -> Uuid {
        self.update_id
    }
    fn image(&self) -> &str {
        &self.target.image.image
    }
    fn expected(&self) -> (&str, Option<Uuid>) {
        (&self.expected_image, self.expected_update_id)
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.runtime.update.execute")
)]
pub fn execute(cancelled: &AtomicBool) -> Result<Value> {
    (|| {
        ensure!(nix::unistd::Uid::effective().is_root()&&std::env::consts::ARCH=="x86_64","unsupported host");
        let mut bytes=Vec::new();std::io::stdin().take(crate::host::runtime::revision::MAX_REQUEST_BYTES+1).read_to_end(&mut bytes)?;
        let request=Request::from_slice(&bytes)?;
        control::authenticate_running(&request.original,&mut std::fs::File::open("/proc/self/exe")?,Instant::now()+Duration::from_secs(30),cancelled)?;
        dispatch(&request,Config {root:Path::new("/"),owner:0,node_owner:crate::image::RUNTIME_UID},cancelled)
    })().map_err(|_:eyre::Report|eyre::eyre!("external image update failed; maintenance remains fenced; resume the exact saved request"))
}

fn advance(
    directory: &Directory,
    request: &Request,
    config: &Config<'_>,
    phase: Phase,
) -> Result<Snapshot> {
    let metadata = config.open("/etc/zdn")?;
    let mut installation = request.original.provisioning.acquire(&metadata)?;
    Journal::open(directory, &request.original, &mut installation)?
        .advance(request.update_id, phase)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.runtime.update.dispatch")
)]
pub fn dispatch(request: &Request, config: Config<'_>, cancelled: &AtomicBool) -> Result<Value> {
    request.validate()?;
    crate::host::external::require_isolated_execution()?;
    let original = &request.original;
    let metadata = config.open("/etc/zdn")?;
    ensure!(
        metadata.read("external-runtime-intent.json", MAX_BYTES)? == original.bytes()?,
        "external update original differs"
    );
    let _update_lock = metadata.lock("external-update.lock")?;
    let mut installation = original.provisioning.acquire(&metadata)?;
    let journal = metadata.ensure_directory(NAMESPACE, 0o700)?;
    let state = Journal::open(&journal, original, &mut installation)?.begin(request)?;
    let transaction = state
        .transaction
        .as_ref()
        .context("missing external transaction")?;
    if transaction.phase == Phase::Done {
        return Ok(
            serde_json::json!({"schema":SCHEMA,"updateId":request.update_id,"phase":"done","runtime":Pin::of(&request.target.bytes()?)}),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(4800);
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("external-update", 0o700)?;
    metadata
        .ensure_directory("commands", 0o700)?
        .ensure_directory("external-update-cleanup", 0o700)?;
    metadata.ensure_directory("scratch", 0o700)?;
    let mut executor = Executor::new(
        config.path(&original.executable()),
        config.path("/etc/zdn/commands/external-update"),
        original.chain.objects.host_helper.region.clone(),
        deadline - Duration::from_secs(60),
    )?;
    control::verify_units(original, &config, &mut executor, cancelled)?;
    control::mounted(original, &config, &mut executor, cancelled, false)?;
    control::require_identity(original, &config, &metadata)?;
    let node = config.open(&original.node_root())?;
    ensure!(
        node.read("bootstrap-complete.json", 8192)? == original.volume_identity()?,
        "external update requires original completed bootstrap"
    );
    if original.block_interval_seconds.is_some() {
        ensure!(
            node.read("producer-authorized.json", 8192)? == original.producer_authorization()?,
            "external update cannot create producer authorization"
        );
    }
    let artifacts = journal
        .ensure_directory(&request.update_id.to_string(), 0o700)?
        .ensure_directory("artifacts", 0o700)?;
    let aws = config.tool("aws")?;
    let docker = config.tool("docker")?;
    request
        .target
        .chain
        .deliver(&artifacts, &aws, &mut executor, cancelled)?;
    let prepared = request
        .target
        .chain
        .prepare(&artifacts, deadline, cancelled)?;
    ensure!(
        serde_json::to_vec(prepared.image())? == serde_json::to_vec(&request.target.image)?,
        "external update image differs"
    );
    image_delivery::pull_image(
        &prepared.image().image,
        &original.chain.objects.host_helper.region,
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
                prepared.image().image.clone().into(),
            ],
            stdin: None,
            timeout: Duration::from_secs(60),
            allowed: &[0],
        },
        cancelled,
    )?;
    prepared.verify_pulled_image(&actual.stdout)?;
    if transaction.phase == Phase::Staging {
        Journal::open(&journal, original, &mut installation)?
            .advance(request.update_id, Phase::Stopping)?;
    }
    drop(installation);
    let state = Snapshot::load(&journal, original)?;
    if state.transaction.as_ref().context("missing update")?.phase == Phase::Stopping {
        if original.block_interval_seconds.is_some() {
            control::systemctl(
                &config,
                &mut executor,
                cancelled,
                &["stop", "zdn-producer.service"],
                35,
            )?;
            crate::host::producer::require_service_stopped(
                &config.tool("systemctl")?,
                &mut executor,
                cancelled,
            )?;
        }
        if original.provisioning.node_id == "node-1" {
            control::systemctl(
                &config,
                &mut executor,
                cancelled,
                &["stop", crate::client_gateway::UNIT_NAME],
                35,
            )?;
        }
        control::systemctl(
            &config,
            &mut executor,
            cancelled,
            &["stop", "zdn-node.service"],
            150,
        )?;
        advance(&journal, request, &config, Phase::Activating)?;
    }
    let state = Snapshot::load(&journal, original)?;
    if state.transaction.as_ref().context("missing update")?.phase == Phase::Activating {
        let mut installation = original.provisioning.acquire(&metadata)?;
        Journal::open(&journal, original, &mut installation)?.publish_active(request.update_id)?;
        drop(installation);
        control::systemctl(
            &config,
            &mut executor,
            cancelled,
            &["start", "zdn-node.service"],
            650,
        )?;
        control::dispatch(
            original,
            Config {
                root: config.root,
                owner: config.owner,
                node_owner: config.node_owner,
            },
            Operation::Observe,
            cancelled,
        )?;
        advance(&journal, request, &config, Phase::Ready)?;
    }
    // Revalidate target state and original authorization before releasing the
    // durable hold. No rollback or authorization invention on failure.
    control::dispatch(
        original,
        Config {
            root: config.root,
            owner: config.owner,
            node_owner: config.node_owner,
        },
        Operation::Observe,
        cancelled,
    )?;
    if original.block_interval_seconds.is_some() {
        ensure!(
            node.read("producer-authorized.json", 8192)? == original.producer_authorization()?,
            "external producer authority changed"
        );
    }
    let mut installation = original.provisioning.acquire(&metadata)?;
    Journal::open(&journal, original, &mut installation)?.release_maintenance(request.update_id)?;
    drop(installation);
    let released = (|| {
        if original.block_interval_seconds.is_some() {
            control::dispatch(
                original,
                Config {
                    root: config.root,
                    owner: config.owner,
                    node_owner: config.node_owner,
                },
                Operation::StartProducer,
                cancelled,
            )?;
        }
        if original.provisioning.node_id == "node-1" {
            control::dispatch(
                original,
                Config {
                    root: config.root,
                    owner: config.owner,
                    node_owner: config.node_owner,
                },
                Operation::GatewayInstall,
                cancelled,
            )?;
        }
        advance(&journal, request, &config, Phase::Done)
    })();
    if released.is_err() {
        let mut installation = original.provisioning.acquire(&metadata)?;
        Journal::open(&journal, original, &mut installation)?
            .hold_maintenance(request.update_id)?;
        drop(installation);
        let cleanup = AtomicBool::new(false);
        let mut cleanup_executor = Executor::new(
            config.path(&original.executable()),
            config.path("/etc/zdn/commands/external-update-cleanup"),
            original.chain.objects.host_helper.region.clone(),
            deadline,
        )?;
        if original.block_interval_seconds.is_some() {
            control::systemctl(
                &config,
                &mut cleanup_executor,
                &cleanup,
                &["stop", "zdn-producer.service"],
                35,
            )?;
        }
    }
    released?;
    Ok(
        serde_json::json!({"schema":SCHEMA,"updateId":request.update_id,"phase":"done","runtime":Pin::of(&request.target.bytes()?)}),
    )
}
