//! Explicit, bounded qualification actions, never participant RPC authority.
//! The root helper authenticates its original manifest and expected active
//! revision. Mutating requests are single-use: unknown completion refuses replay.
use super::{control, update, Manifest, ProductionAdmission, MAX_BYTES};
use crate::{
    chain::{
        producer::{self, ProducerOptions},
        rpc::{NodeRpc, RpcError, SystemClock},
    },
    host::{
        command::{Executor, HostCommand},
        files::Directory,
        runtime::{control::Config, revision::Phase},
        volume::VolumeSpec,
    },
    public_chain_adapter::contract::{self, Pin},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const SCHEMA: &str = "zdn-external-qualification/v1";
pub const MAX_REQUEST: u64 = 8192;
pub const MAX_RESPONSE: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Query {
    Tip,
    BlockHash { height: u32 },
    Transaction { txid: String },
    Output { txid: String, index: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Read {
        query: Query,
    },
    GatewayIdentity,
    StopProducer,
    Produce {
        blocks: u64,
        height: u32,
        seconds: u32,
    },
    /// Stop/start the same revision; deliberately leave production stopped.
    RestartNode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub id: Uuid,
    /// Expected effective runtime, not just the original installation.
    pub runtime: Pin,
    pub action: Action,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && self.id.get_version_num() == 4
                && self.id.get_variant() == uuid::Variant::RFC4122,
            "invalid external qualification request"
        );
        ensure!(
            (1..=MAX_BYTES).contains(&self.runtime.bytes) && hash(&self.runtime.sha256),
            "invalid qualification runtime pin"
        );
        match &self.action {
            Action::Read {
                query: Query::Transaction { txid } | Query::Output { txid, .. },
            } => ensure!(hash(txid), "invalid qualification transaction ID"),
            Action::Produce {
                blocks,
                height,
                seconds,
            } => ensure!(
                (1..=20).contains(blocks) && *height > 0 && (1..=600).contains(seconds),
                "invalid qualification production bounds"
            ),
            _ => {}
        }
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() as u64 <= MAX_REQUEST,
            "qualification request exceeds bound"
        );
        Ok(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_REQUEST,
            "qualification request exceeds bound"
        );
        let value: Self = contract::parse(bytes)?;
        ensure!(
            value.bytes()? == bytes,
            "noncanonical qualification request"
        );
        Ok(value)
    }

    /// Offline transport only. The caller must use the original deployment's
    /// exclusive lifecycle/SSM ledger, not auto-repeat a generated script.
    pub fn render(&self, original: &Manifest) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        original.validate()?;
        Ok(format!("#!/bin/bash\nset -euo pipefail\numask 077\n{} __runtime-capabilities --require {SCHEMA} >/dev/null\nbase64 --decode <<'ZDN_EXTERNAL_QUALIFICATION' | {} __external-qualification --protocol {SCHEMA} --manifest /etc/zdn/external-runtime/{}\n{}\nZDN_EXTERNAL_QUALIFICATION\n", original.executable(), original.executable(), original.file_name()?, STANDARD.encode(self.bytes()?)))
    }

    pub fn validate_response(&self, runtime: &Manifest, value: &Value) -> Result<()> {
        self.validate()?;
        self.runtime.check(&runtime.bytes()?)?;
        ensure!(
            serde_json::to_vec(value)?.len() <= MAX_RESPONSE
                && value.is_object()
                && value["schema"] == SCHEMA
                && value["request"] == json!(Pin::of(&self.bytes()?))
                && value["runtime"] == json!(self.runtime)
                && value["deploymentId"] == json!(runtime.provisioning.deployment_id)
                && value["nodeId"] == runtime.provisioning.node_id
                && value["nativeInventory"] == json!(runtime.chain.native_inventory)
                && value["result"].is_object(),
            "qualification response binding differs"
        );
        Ok(())
    }

    /// Host journal admission under the external update and installation locks.
    /// Some returns an already completed result; None permits exactly one
    /// dispatch. A missing result after dispatch is unknown, never permission
    /// to repeat. Callers must not delete these records to bypass uncertainty.
    pub fn begin(&self, records: &Directory, runtime: &Manifest) -> Result<Option<Value>> {
        self.validate()?;
        self.runtime.check(&runtime.bytes()?)?;
        ensure!(
            !matches!(self.action, Action::Read { .. } | Action::GatewayIdentity),
            "reads require fresh observation, not replay receipts"
        );
        let record = records.ensure_directory(&self.id.to_string(), 0o700)?;
        record.publish("request.json", &self.bytes()?, 0o600)?;
        match record.read("result.json", MAX_RESPONSE as u64) {
            Ok(bytes) => {
                ensure!(
                    record.read("dispatched.json", MAX_REQUEST)? == self.bytes()?,
                    "qualification dispatch binding differs"
                );
                let value = contract::parse(&bytes)?;
                self.validate_response(runtime, &value)?;
                return Ok(Some(value));
            }
            Err(e) if missing(&e) => {}
            Err(e) => return Err(e),
        }
        record.require_absent("dispatched.json")?;
        record.publish("dispatched.json", &self.bytes()?, 0o600)?;
        Ok(None)
    }

    pub fn complete(&self, records: &Directory, runtime: &Manifest, value: &Value) -> Result<()> {
        self.validate_response(runtime, value)?;
        let record = records.open_directory(&self.id.to_string())?;
        ensure!(
            record.read("request.json", MAX_REQUEST)? == self.bytes()?
                && record.read("dispatched.json", MAX_REQUEST)? == self.bytes()?,
            "qualification completion binding differs"
        );
        record.publish("result.json", &serde_json::to_vec(value)?, 0o600)
    }
}

fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read-only projection with small output even when a transaction contains a
/// large authorization. The transport's finite body class remains unchanged.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.qualification.read")
)]
pub fn read(query: &Query, rpc: &impl NodeRpc) -> Result<Value> {
    let timeout = Duration::from_secs(10);
    let value = match query {
        Query::Tip => serde_json::to_value(producer::read_tip(rpc, timeout)?)?,
        Query::BlockHash { height } => {
            let value = rpc.call("getblockhash", json!([height]), timeout)?;
            let block_hash = value.as_str().context("missing qualification block hash")?;
            ensure!(hash(block_hash), "invalid qualification block hash");
            json!({"height":height,"hash":block_hash})
        }
        Query::Transaction { txid } => {
            ensure!(hash(txid), "invalid qualification transaction ID");
            let tx = match rpc.call("getrawtransaction", json!([txid, 1]), timeout) {
                Ok(tx) => tx,
                Err(RpcError::Remote { code: -5, .. }) => return Ok(json!({"found":false})),
                Err(error) => return Err(error.into()),
            };
            ensure!(
                tx["txid"] == *txid,
                "qualification transaction identity differs"
            );
            let raw = tx["hex"]
                .as_str()
                .context("missing qualification transaction bytes")?;
            ensure!(
                !raw.is_empty()
                    && raw.len() % 2 == 0
                    && raw.len() <= crate::rpc_limits::LARGE_HEX_BODY,
                "invalid qualification transaction bytes"
            );
            let mut digest = Sha256::new();
            let mut buffer = [0; 4096];
            for chunk in raw.as_bytes().chunks(buffer.len() * 2) {
                let n = chunk.len() / 2;
                hex::decode_to_slice(chunk, &mut buffer[..n])?;
                digest.update(&buffer[..n]);
            }
            let confirmations = tx.get("confirmations").cloned().unwrap_or(json!(0));
            ensure!(
                confirmations.as_i64().is_some(),
                "invalid qualification confirmations"
            );
            let block = tx.get("blockhash").cloned().unwrap_or(Value::Null);
            ensure!(
                block.is_null() || block.as_str().is_some_and(hash),
                "invalid qualification block hash"
            );
            json!({"found":true,"txid":txid,"bytes":raw.len()/2,"sha256":hex::encode(digest.finalize()),"confirmations":confirmations,"blockHash":block})
        }
        Query::Output { txid, index } => {
            ensure!(hash(txid), "invalid qualification transaction ID");
            let output = rpc.call("gettxout", json!([txid, index, true]), timeout)?;
            // Null means unavailable/unspent-not-found, not proof of a mined spend.
            if output.is_null() {
                return Ok(json!({"output":null}));
            }
            ensure!(
                output.is_object()
                    && output["confirmations"].as_u64().is_some()
                    && output["bestblock"].as_str().is_some_and(hash)
                    && output["value"].is_number()
                    && output["coinbase"].is_boolean()
                    && output["scriptPubKey"]["hex"]
                        .as_str()
                        .is_some_and(|s| s.len() <= 8192
                            && s.len() % 2 == 0
                            && s.bytes().all(|c| c.is_ascii_hexdigit())),
                "invalid qualification output"
            );
            json!({"output":{"bestblock":output["bestblock"],"confirmations":output["confirmations"],"value":output["value"],"coinbase":output["coinbase"],"scriptHex":output["scriptPubKey"]["hex"]}})
        }
    };
    ensure!(
        serde_json::to_vec(&value)?.len() <= 12 * 1024,
        "qualification projection exceeds bound"
    );
    Ok(value)
}

pub fn execute(path: &Path, cancelled: &AtomicBool) -> Result<Value> {
    (|| {
        let mut bytes = Vec::new();
        std::io::stdin().take(MAX_REQUEST + 1).read_to_end(&mut bytes)?;
        let request = Request::from_slice(&bytes)?;
        let (original, config) = control::authenticate(path, cancelled)?;
        dispatch(&original, &request, config, cancelled)
    })().map_err(|_: eyre::Report| eyre::eyre!("external qualification failed; preserve request and host journals; do not replay uncertain work"))
}

/// Alternate roots are fixture views only, as in ordinary host dispatch.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.external.qualification.dispatch")
)]
pub fn dispatch(
    original: &Manifest,
    request: &Request,
    config: Config<'_>,
    cancelled: &AtomicBool,
) -> Result<Value> {
    request.validate()?;
    original.validate()?;
    ensure!(!cancelled.load(Ordering::SeqCst), "qualification cancelled");
    let metadata = config.open("/etc/zdn")?;
    let _control = metadata.lock("external-update.lock")?;
    let installation = original.provisioning.acquire(&metadata)?;
    control::require_metadata(original, &metadata)?;
    ensure!(
        metadata.read("external-runtime-intent.json", MAX_BYTES)? == original.bytes()?,
        "qualification original differs"
    );
    let state = update::Snapshot::from_installation(&metadata, original)?;
    ensure!(
        state.as_ref().is_none_or(|s| !s.producer_hold
            && s.transaction
                .as_ref()
                .is_none_or(|t| t.phase == Phase::Done)),
        "qualification blocked by image maintenance"
    );
    let active = state
        .as_ref()
        .and_then(|s| s.active.as_ref())
        .map(|r| &r.target)
        .unwrap_or(original);
    request.runtime.check(&active.bytes()?)?;
    let deadline = Instant::now() + Duration::from_secs(900);
    let commands = metadata.ensure_directory("commands", 0o700)?;
    commands.ensure_directory("external-qualification", 0o700)?;
    let mut executor = Executor::new(
        config.path(&original.executable()),
        config.path("/etc/zdn/commands/external-qualification"),
        original.chain.objects.host_helper.region.clone(),
        deadline,
    )?;
    control::verify_units(original, &config, &mut executor, cancelled)?;
    control::mounted(active, &config, &mut executor, cancelled, false)?;
    control::require_identity(active, &config, &metadata)?;
    let node = config.open(&active.node_root())?;
    ensure!(
        node.read(
            "zakura.toml",
            crate::public_chain_adapter::contract::MAX_METADATA as u64
        )? == active.chain.config_toml.as_bytes()
            && node.read("bootstrap-complete.json", 8192)? == active.volume_identity()?,
        "qualification retained state differs"
    );
    let records = metadata.ensure_directory("external-qualification", 0o700)?;
    let mutating = !matches!(
        request.action,
        Action::Read { .. } | Action::GatewayIdentity
    );
    if mutating {
        if let Some(value) = request.begin(&records, active)? {
            return Ok(value);
        }
    }
    let result = match &request.action {
        Action::GatewayIdentity => {
            ensure!(
                active.provisioning.node_id == "node-1",
                "gateway identity requires node-1"
            );
            gateway_identity(original, &config, &mut executor, deadline, cancelled)?
        }
        Action::StopProducer | Action::RestartNode => {
            if active.block_interval_seconds.is_some() {
                stop_producer(&config, &mut executor, cancelled)?;
            } else {
                ensure!(
                    matches!(request.action, Action::RestartNode),
                    "qualification node has no producer"
                );
            }
            if matches!(request.action, Action::RestartNode) {
                // Child prepare/ready/stop actions acquire the install lock.
                // The external update lock above remains held across the gap.
                drop(installation);
                control::systemctl(
                    &config,
                    &mut executor,
                    cancelled,
                    &["stop", "zdn-node.service"],
                    150,
                )?;
                control::systemctl(
                    &config,
                    &mut executor,
                    cancelled,
                    &["start", "zdn-node.service"],
                    650,
                )?;
                if active.block_interval_seconds.is_some() {
                    crate::host::producer::require_service_stopped(
                        &config.tool("systemctl")?,
                        &mut executor,
                        cancelled,
                    )?;
                }
                // A fresh authenticated observation checks the retained node,
                // while the independent gateway process is never restarted.
                let observed = control::dispatch(
                    original,
                    Config {
                        root: config.root,
                        owner: config.owner,
                        node_owner: config.node_owner,
                    },
                    control::Operation::Observe,
                    cancelled,
                )?
                .context("missing restart readiness")?;
                active.validate_ready_observation(&observed)?;
                json!({"status":"restarted","productionResumed":false,"readiness":observed["readiness"]})
            } else {
                json!({"status":"producer-stopped"})
            }
        }
        Action::Produce {
            blocks,
            height,
            seconds,
        } => {
            ensure!(
                active.block_interval_seconds.is_some(),
                "qualification requires designated producer"
            );
            stop_producer(&config, &mut executor, cancelled)?;
            ensure!(
                node.read("producer-authorized.json", 8192)? == active.producer_authorization()?,
                "qualification producer not authorized"
            );
            let (prepared, rpc, clock) = prepare(active, &state, &config, deadline, cancelled)?;
            let mut options = ProducerOptions::new(
                config.path(&format!("{}/producer", active.node_root())),
                active.producer_identity(),
            );
            options.interval =
                Duration::from_secs(active.block_interval_seconds.context("missing schedule")?);
            options.max_blocks = Some(*blocks);
            options.max_height = Some(*height);
            options.max_duration = Some(Duration::from_secs(u64::from(*seconds)));
            options.unpaced = true;
            let admission = ProductionAdmission::load(active, &node)?;
            admission.constrain(&mut options);
            let rpc = admission.guard(&rpc);
            json!({"producer":prepared.chain().produce(&rpc,&clock,&options,cancelled)?})
        }
        Action::Read { query } => {
            let (prepared, rpc, _) = prepare(active, &state, &config, deadline, cancelled)?;
            prepared
                .chain()
                .verify_rules(&rpc, Duration::from_secs(10))?;
            read(query, &rpc)?
        }
    };
    let value = json!({"schema":SCHEMA,"request":Pin::of(&request.bytes()?),"runtime":request.runtime,
        "deploymentId":active.provisioning.deployment_id,"nodeId":active.provisioning.node_id,
        "nativeInventory":active.chain.native_inventory,"result":result});
    request.validate_response(active, &value)?;
    if mutating {
        request.complete(&records, active, &value)?;
    }
    Ok(value)
}

fn gateway_identity(
    original: &Manifest,
    config: &Config<'_>,
    executor: &mut Executor,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Value> {
    use std::{fs::File, os::unix::fs::MetadataExt};
    let systemctl = config.tool("systemctl")?;
    let mut pid = || -> Result<u32> {
        let result = executor.execute(
            HostCommand {
                program: &systemctl,
                args: &[
                    "show".into(),
                    crate::client_gateway::UNIT_NAME.into(),
                    "--property=MainPID".into(),
                    "--value".into(),
                ],
                stdin: None,
                timeout: Duration::from_secs(10),
                allowed: &[0],
            },
            cancelled,
        )?;
        let pid = std::str::from_utf8(&result.stdout)?.trim().parse::<u32>()?;
        ensure!(pid > 0, "gateway process is not running");
        Ok(pid)
    };
    let expected_pid = pid()?;
    let stat_path = config.path(&format!("/proc/{expected_pid}/stat"));
    let start = || -> Result<u64> {
        let mut stat = String::new();
        File::open(&stat_path)?
            .take(8193)
            .read_to_string(&mut stat)?;
        ensure!(stat.len() <= 8192, "invalid gateway process stat");
        let tail = stat
            .rsplit_once(") ")
            .context("invalid gateway process stat")?
            .1;
        ensure!(
            !matches!(tail.split_whitespace().next(), Some("Z" | "X")),
            "gateway process stopped"
        );
        Ok(tail
            .split_whitespace()
            .nth(19)
            .context("missing gateway process start")?
            .parse()?)
    };
    let start_ticks = start()?;
    let mut executable = File::open(config.path(&format!("/proc/{expected_pid}/exe")))?;
    let actual = executable.metadata()?;
    let expected = std::fs::symlink_metadata(config.path(&original.executable()))?;
    ensure!(
        actual.dev() == expected.dev() && actual.ino() == expected.ino(),
        "gateway executable differs"
    );
    control::authenticate_running(original, &mut executable, deadline, cancelled)?;
    let mut boot = String::new();
    File::open(config.path("/proc/sys/kernel/random/boot_id"))?
        .take(65)
        .read_to_string(&mut boot)?;
    let boot_id = Uuid::parse_str(boot.trim())?;
    ensure!(
        pid()? == expected_pid && start()? == start_ticks,
        "gateway process changed during observation"
    );
    Ok(
        json!({"pid":expected_pid,"startTicks":start_ticks,"bootId":boot_id,"executable":{
        "bytes":original.chain.objects.host_helper.bytes,"sha256":original.chain.objects.host_helper.sha256}}),
    )
}

fn missing(error: &eyre::Report) -> bool {
    error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
}

fn stop_producer(
    config: &Config<'_>,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    control::systemctl(
        config,
        executor,
        cancelled,
        &["stop", "zdn-producer.service"],
        35,
    )?;
    crate::host::producer::require_service_stopped(&config.tool("systemctl")?, executor, cancelled)
}

fn prepare(
    active: &Manifest,
    state: &Option<update::Snapshot>,
    config: &Config<'_>,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(
    crate::host::external::PreparedHost,
    crate::chain::rpc::HttpNodeRpc,
    SystemClock,
)> {
    let artifact_path = state
        .as_ref()
        .and_then(|s| s.active.as_ref())
        .map(|r| format!("/etc/zdn/{}/{}/artifacts", update::NAMESPACE, r.update_id))
        .unwrap_or_else(|| "/etc/zdn/external-artifacts".into());
    let prepared = active
        .chain
        .prepare(&config.open(&artifact_path)?, deadline, cancelled)?;
    let clock = SystemClock::default();
    let rpc = prepared.chain().wait_for_rpc(
        &active.chain.options.rpc_listen,
        &config.path(&format!("{}/.cookie", active.chain.options.cookie_dir)),
        &clock,
        Duration::from_secs(10),
        Duration::from_secs(120),
    )?;
    Ok((prepared, rpc, clock))
}
