//! Explicit operational host contract. Disk ownership precedes peer inventory;
//! service selection binds the complete final manifest without rewriting it.
//! All native operations reuse the common volume, launch, readiness, bootstrap
//! and durable producer algorithms. No ordinary consensus object is fabricated.
use super::{Manifest as ChainManifest, Provisioning};
use crate::{
    chain::{
        producer::ProducerOptions,
        rpc::{NodeRpc, RpcError},
    },
    config::ExternalProductionLimits,
    host::{
        container::LaunchSpec,
        files::Directory,
        volume::{self, VolumeSpec},
    },
    public_chain_adapter::contract::{self, Pin},
};
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod control;
pub mod qualification;
pub mod update;
pub const SCHEMA: &str = "zdn-external-runtime/v1";
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub provisioning: Provisioning,
    pub chain: ChainManifest,
    pub image: crate::image::ImageRecord,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub host_reserve_bytes: u64,
    /// Scheduling is only installed on node-1. Installation never authorizes
    /// it; start-producer is a separate authenticated controller action.
    pub block_interval_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production_limits: Option<ExternalProductionLimits>,
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA, "unsupported external runtime");
        self.provisioning.require_runtime(&self.chain)?;
        let requirements = self.chain.validate()?;
        crate::image::ImageRecord::from_json_for_requirements(
            &serde_json::to_vec(&self.image)?,
            &requirements,
        )?;
        ensure!(
            self.image
                .image
                .ends_with(&format!("@{}", self.chain.options.image_digest)),
            "external image digest differs"
        );
        ensure!(
            self.chain.options.expected_node_id.len() == 64,
            "external service requires a pinned persistent native identity"
        );
        ensure!(
            (1024 * 1024 * 1024..=1024_u64.pow(4)).contains(&self.memory_bytes)
                && (250..=128_000).contains(&self.cpu_millis)
                && (256 * 1024 * 1024..=64 * 1024_u64.pow(3)).contains(&self.host_reserve_bytes),
            "invalid external host resource budget"
        );
        if let Some(seconds) = self.block_interval_seconds {
            ensure!(
                (1..=3600).contains(&seconds)
                    && self.provisioning.node_id == "node-1"
                    && self.chain.options.role == "producer",
                "invalid external producer schedule"
            );
        }
        if let Some(limits) = &self.production_limits {
            limits.validate()?;
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "external runtime exceeds bound"
        );
        Ok(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "external runtime exceeds bound"
        );
        let value: Self = contract::parse(bytes)?;
        ensure!(value.bytes()? == bytes, "noncanonical external runtime");
        Ok(value)
    }
    pub fn file_name(&self) -> Result<String> {
        Ok(format!("{}.json", Pin::of(&self.bytes()?).sha256))
    }
    pub fn executable(&self) -> String {
        format!(
            "/etc/zdn/runtime/{}/zdn",
            self.chain.objects.host_helper.sha256
        )
    }
    pub fn command(&self) -> Result<String> {
        Ok(format!(
            "{} __external-runtime --protocol {SCHEMA} --manifest /etc/zdn/external-runtime/{}",
            self.executable(),
            self.file_name()?
        ))
    }
    /// Canonical fixed action transport for the controller's authenticated SSM
    /// request ledger. The ordinary outer SSM/action supervisor owns cleanup.
    pub fn render_operation(&self, operation: control::Operation) -> Result<String> {
        self.validate()?;
        Ok(format!("#!/bin/bash\nset -euo pipefail\numask 077\n{} __runtime-capabilities --require {SCHEMA} >/dev/null\n{} {}\n",
            self.executable(),self.command()?,operation.argument()))
    }
    pub fn units(&self) -> Result<(String, Option<String>, Option<String>)> {
        self.validate()?;
        let command = self.command()?;
        let (node, producer) = crate::host::runtime::install::units_for_command(
            &command,
            &self.node_root(),
            self.block_interval_seconds.is_some(),
        );
        // External activation already starts production as a separate action.
        // Starting a retained node must not implicitly restart a stopped miner.
        let node = node.replace("Wants=zdn-producer.service\n", "");
        let gateway = (self.provisioning.node_id == "node-1").then(|| {
            crate::client_gateway::native::unit_for_command(&format!("{command} gateway-serve"))
                // Keep the authenticated gateway alive across a node-only
                // restart; it reports unavailable while upstream is absent.
                // Image updates still explicitly stop it before activation.
                .replace("BindsTo=zdn-node.service\n", "")
                .replace("PartOf=zdn-node.service\n", "")
                // External startup recompiles in the unprivileged adapter
                // sandbox before serving. Only its trusted wrapper may drop
                // UID/GID; the companion never inherits these capabilities.
                .replace(
                    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
                    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_SETPCAP",
                )
                // Bubblewrap configures loopback inside its isolated network
                // namespace using NETLINK_ROUTE before running the adapter.
                .replace(
                    "RestrictAddressFamilies=AF_INET AF_INET6",
                    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
                )
        });
        Ok((node, producer, gateway))
    }
    /// Exact durable authorization, independent of mutable service state and
    /// image selection. Retained across image-only updates and recovery.
    pub fn producer_authorization(&self) -> Result<Vec<u8>> {
        self.validate()?;
        ensure!(
            self.block_interval_seconds.is_some(),
            "external producer is unscheduled"
        );
        let mut value = serde_json::json!({"schema":"zdn-external-producer-authorization/v1",
            "provisioning":Pin::of(&self.provisioning.bytes()?), "nativeInventory":self.chain.native_inventory,
            "intervalSeconds":self.block_interval_seconds});
        if let Some(limits) = &self.production_limits {
            value["productionLimits"] = serde_json::to_value(limits)?;
        }
        Ok(serde_json::to_vec(&value)?)
    }
    pub fn producer_identity(&self) -> crate::chain::producer::ProducerIdentity {
        crate::chain::producer::ProducerIdentity {
            deployment_id: self.provisioning.deployment_id,
            node_id: self.provisioning.node_id.clone(),
            consensus_fingerprint: self.provisioning.native_fingerprint.clone(),
        }
    }
    pub fn observation(&self, status: &str) -> Result<serde_json::Value> {
        self.validate()?;
        ensure!(
            ["ready", "stopped"].contains(&status),
            "invalid external runtime status"
        );
        Ok(
            serde_json::json!({"schema":"zdn-external-runtime-observation/v1", "runtime":Pin::of(&self.bytes()?),
            "request":self.chain.request,"nativeInventory":self.chain.native_inventory,
            "deploymentId":self.provisioning.deployment_id,"nodeId":self.provisioning.node_id,
            "nativeFingerprint":self.provisioning.native_fingerprint,"status":status}),
        )
    }

    /// Controller-side validation of the bounded authenticated host response.
    /// Authentication/SSM command identity remains the controller's job; a raw
    /// user-supplied JSON value is never deployment authority.
    pub fn validate_ready_observation(&self, value: &serde_json::Value) -> Result<()> {
        self.validate()?;
        ensure!(
            value["observation"] == self.observation("ready")?,
            "external host observation binding differs"
        );
        let readiness = &value["readiness"];
        ensure!(
            readiness["apiVersion"] == crate::chain::readiness::API_VERSION
                && readiness["consensusFingerprint"] == self.provisioning.native_fingerprint
                && readiness["role"] == self.chain.options.role
                && readiness["effectiveRulesVerified"] == true
                && readiness["historyPresent"] == true
                && readiness["launchReady"] == false
                && (self.chain.options.role != "producer" || readiness["miningReady"] == true),
            "external native readiness did not pass"
        );
        Ok(())
    }
}

const ACTIVATION_FILE: &str = "production-activation.json";

/// Root-owned, create-only activation in the retained node directory. Image
/// selection and process IDs deliberately do not participate in this identity.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionActivation {
    schema: String,
    authorization: Pin,
    limits: ExternalProductionLimits,
    activated_unix_seconds: u64,
    deadline_unix_seconds: u64,
}

impl ProductionActivation {
    fn read(manifest: &Manifest, node: &Directory) -> Result<Self> {
        let bytes = node.read(ACTIVATION_FILE, 8192)?;
        let value: Self = contract::parse(&bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "noncanonical production activation"
        );
        ensure!(
            value.schema == "zdn-external-production-activation/v1"
                && Some(&value.limits) == manifest.production_limits.as_ref()
                && value.authorization == Pin::of(&manifest.producer_authorization()?)
                && value
                    .activated_unix_seconds
                    .checked_add(u64::from(value.limits.lifetime_seconds))
                    == Some(value.deadline_unix_seconds),
            "external production activation differs"
        );
        Ok(value)
    }
}

impl Manifest {
    /// Called only by authenticated start-producer under the installation lock,
    /// before service startup. A retry reads the original deadline, never renews
    /// it. Produce/qualification cannot create or repair a missing activation.
    pub fn activate_production(&self, node: &Directory) -> Result<()> {
        self.validate()?;
        let Some(limits) = &self.production_limits else {
            return Ok(());
        };
        match node.read(ACTIVATION_FILE, 8192) {
            Ok(_) => {
                ProductionActivation::read(self, node)?;
            }
            Err(error)
                if error.downcast_ref::<nix::errno::Errno>()
                    == Some(&nix::errno::Errno::ENOENT) =>
            {
                // A lost activation after authorization is not a new lifetime.
                node.require_absent("producer-authorized.json")?;
                let activated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let value = ProductionActivation {
                    schema: "zdn-external-production-activation/v1".into(),
                    authorization: Pin::of(&self.producer_authorization()?),
                    limits: limits.clone(),
                    activated_unix_seconds: activated,
                    deadline_unix_seconds: activated
                        .checked_add(u64::from(limits.lifetime_seconds))
                        .context("production deadline overflow")?,
                };
                node.publish(ACTIVATION_FILE, &serde_json::to_vec(&value)?, 0o600)?;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

/// Shared admission for scheduled and qualification production. The original
/// producer still owns all locking, pending-intent reconciliation and receipts.
pub struct ProductionAdmission {
    activation: Option<ProductionActivation>,
    deadline: Option<Instant>,
}

impl ProductionAdmission {
    pub fn load(manifest: &Manifest, node: &Directory) -> Result<Self> {
        manifest.validate()?;
        let activation = manifest
            .production_limits
            .as_ref()
            .map(|_| ProductionActivation::read(manifest, node))
            .transpose()?;
        let started = Instant::now();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let deadline = activation.as_ref().map(|a| {
            // A clock earlier than activation is fail-closed. Monotonic time
            // prevents a backward wall-clock jump extending this invocation.
            let remaining = if now.as_secs() < a.activated_unix_seconds {
                Duration::ZERO
            } else {
                Duration::from_secs(a.deadline_unix_seconds).saturating_sub(now)
            };
            started + remaining
        });
        Ok(Self {
            activation,
            deadline,
        })
    }

    pub fn constrain(&self, options: &mut ProducerOptions) {
        if let Some(activation) = &self.activation {
            options.max_height = Some(
                options
                    .max_height
                    .map_or(activation.limits.max_height, |h| {
                        h.min(activation.limits.max_height)
                    }),
            );
            let remaining = self
                .deadline
                .expect("limited admission deadline")
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // A zero ceiling permits the existing pending intent to be
                // reconciled, then returns without creating another intent.
                options.max_height = Some(0);
            } else {
                options.max_duration =
                    Some(options.max_duration.map_or(remaining, |d| d.min(remaining)));
            }
        }
    }

    pub fn guard<'a, R: NodeRpc>(&'a self, rpc: &'a R) -> impl NodeRpc + 'a {
        ProductionRpc {
            admission: self,
            rpc,
        }
    }

    fn generation_allowed(&self) -> bool {
        self.activation.as_ref().is_none_or(|a| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .is_ok_and(|now| {
                    now.as_secs() >= a.activated_unix_seconds
                        && now < Duration::from_secs(a.deadline_unix_seconds)
                })
                && self
                    .deadline
                    .is_some_and(|deadline| Instant::now() < deadline)
        })
    }
}

struct ProductionRpc<'a, R> {
    admission: &'a ProductionAdmission,
    rpc: &'a R,
}

impl<R: NodeRpc> NodeRpc for ProductionRpc<'_, R> {
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, RpcError> {
        if method == "generate" && !self.admission.generation_allowed() {
            // Deadline may cross after the producer's last readiness check.
            // Never forward the call. Its conservative journal retains the
            // intent rather than guessing whether a request was dispatched.
            return Err(RpcError::Protocol(
                "external production lifetime exhausted".into(),
            ));
        }
        self.rpc.call(method, params, timeout)
    }
}

impl volume::sealed::Sealed for Manifest {}
impl VolumeSpec for Manifest {
    fn validate_volume(&self) -> Result<()> {
        self.validate()
    }
    fn volume_id(&self) -> &str {
        &self.provisioning.volume_id
    }
    fn new_volume(&self) -> Option<&crate::host::NewVolumeAuthorization> {
        self.provisioning.new_volume.as_ref()
    }
    fn node_root(&self) -> String {
        self.provisioning.node_root()
    }
    fn install_sha256(&self) -> Result<String> {
        self.provisioning.install_sha256()
    }
    fn volume_identity(&self) -> Result<Vec<u8>> {
        self.provisioning.volume_identity()
    }
}
impl LaunchSpec for Manifest {
    fn validate_launch(&self) -> Result<()> {
        self.validate()
    }
    fn validate_image(&self, image: &str) -> Result<()> {
        self.validate()?;
        ensure!(
            image == self.image.image,
            "external image selection differs"
        );
        Ok(())
    }
    fn deployment_id(&self) -> uuid::Uuid {
        self.provisioning.deployment_id
    }
    fn node_id(&self) -> &str {
        &self.provisioning.node_id
    }
    fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }
    fn cpu_millis(&self) -> u32 {
        self.cpu_millis
    }
    fn host_reserve_bytes(&self) -> u64 {
        self.host_reserve_bytes
    }
}
