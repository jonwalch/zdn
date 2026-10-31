//! Explicit external runtime branch; never coerces a native chain into an
//! ordinary ConsensusManifest. Authenticated immutable inputs are recompiled
//! and security-checked before a caller may publish/start/update services.
//!
//! The companion is explicitly trusted software, not an isolated plugin.
//! Callers retain the host action/installation locks and outer supervisor.
use super::{
    artifact_delivery::{self, Delivery},
    command::Executor,
    files::{self, Directory},
    S3Object,
};
use crate::public_chain_adapter::{
    contract::{self, Pin, RenderOptions},
    package::{CoreTrust, PreparedExternalChain, PublicPackage},
};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const SCHEMA: &str = "zdn-external-host/v1";
pub mod identity;
pub mod runtime;

/// Immutable phase-one disk ownership. This deliberately precedes native key
/// collection: final peer IDs and rendered runtime bytes cannot be part of the
/// original format/claim identity. They are bound by the later host manifest.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provisioning {
    pub schema: String,
    pub deployment_id: uuid::Uuid,
    pub node_id: String,
    pub volume_id: String,
    pub descriptor_sha256: String,
    pub native_fingerprint: String,
    pub request: Pin,
    pub new_volume: Option<super::NewVolumeAuthorization>,
}

impl Provisioning {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "zdn-external-provisioning/v1",
            "unsupported external provisioning schema"
        );
        ensure!(
            self.deployment_id.get_version_num() == 4
                && self.deployment_id.get_variant() == uuid::Variant::RFC4122,
            "external deployment requires UUIDv4"
        );
        ensure!(
            ["node-1", "node-2", "node-3"].contains(&self.node_id.as_str()),
            "invalid external node"
        );
        for hash in [
            &self.descriptor_sha256,
            &self.native_fingerprint,
            &self.request.sha256,
        ] {
            super::digest(hash)?;
        }
        ensure!(
            (1..=4 * 1024 * 1024).contains(&self.request.bytes),
            "invalid external request pin"
        );
        crate::infra::validate_aws_id(&self.volume_id, "vol-")?;
        if let Some(authorization) = &self.new_volume {
            authorization.validate(&self.volume_id)?;
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 8192, "external provisioning exceeds bound");
        let value: Self = contract::parse(bytes)?;
        ensure!(
            value.bytes()? == bytes,
            "noncanonical external provisioning"
        );
        Ok(value)
    }
    pub fn node_root(&self) -> String {
        format!(
            "{}/deployments/{}/nodes/{}/chains/{}",
            super::DATA_ROOT,
            self.deployment_id,
            self.node_id,
            self.descriptor_sha256
        )
    }
    pub fn install_sha256(&self) -> Result<String> {
        Ok(Pin::of(&self.bytes()?).sha256)
    }
    /// Acquire exactly the same existing format/claim state machine, under a
    /// separate external immutable intent. No device effects occur here.
    pub fn acquire<'a>(&self, directory: &'a Directory) -> Result<super::volume::Installation<'a>> {
        super::volume::Installation::acquire_external(directory, self)
    }
    pub fn require_runtime(&self, manifest: &Manifest) -> Result<()> {
        self.validate()?;
        manifest.validate()?;
        let compiled: contract::Compiled = contract::parse(manifest.compiled_json.as_bytes())?;
        ensure!(
            manifest.options.deployment_id == self.deployment_id.to_string()
                && manifest.options.node_id == self.node_id
                && manifest.request == self.request
                && manifest.objects.descriptor.sha256 == self.descriptor_sha256
                && compiled.native_fingerprint == self.native_fingerprint,
            "external runtime belongs to another provisioned volume"
        );
        Ok(())
    }
}

impl super::volume::sealed::Sealed for Provisioning {}
impl super::volume::VolumeSpec for Provisioning {
    fn validate_volume(&self) -> Result<()> {
        self.validate()
    }
    fn volume_id(&self) -> &str {
        &self.volume_id
    }
    fn new_volume(&self) -> Option<&super::NewVolumeAuthorization> {
        self.new_volume.as_ref()
    }
    fn node_root(&self) -> String {
        self.node_root()
    }
    fn install_sha256(&self) -> Result<String> {
        self.install_sha256()
    }
    fn volume_identity(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "apiVersion":"zdn-external-volume/v1","deploymentId":self.deployment_id,"nodeId":self.node_id,
            "volumeId":self.volume_id,"nativeFingerprint":self.native_fingerprint,
            "descriptorSha256":self.descriptor_sha256,"request":self.request,"installSha256":self.install_sha256()?,
        }))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Admission, not a sandbox claim. The current host Executor owns process
/// lifetime but does not deny the host filesystem, cookie or instance metadata.
/// Never invoke the controller's same-UID adapter primitive as a root host
/// substitute. Missing trusted sandbox tools refuse before artifact effects;
/// namespace or privilege-drop failure refuses before adapter execution.
pub fn require_isolated_execution() -> Result<()> {
    super::adapter_sandbox::Sandbox::discover().map(|_| ())
}

/// Finite named source slots. No caller-selected destination filenames or
/// arbitrary attachment lists. These objects are public inputs, never wallets.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Objects {
    pub package: S3Object,
    pub descriptor: S3Object,
    pub native_rules: S3Object,
    pub wallet_profile: S3Object,
    pub seed_bundle: S3Object,
    pub host_adapter: S3Object,
    pub compiled_result: S3Object,
    pub image_record: S3Object,
    pub image_manifest: S3Object,
    pub image_config: S3Object,
    pub host_helper: S3Object,
}

impl Objects {
    pub(crate) fn slots(&self) -> [(&'static str, &S3Object, u64); 11] {
        [
            ("package.json", &self.package, contract::MAX_METADATA as u64),
            (
                "descriptor.json",
                &self.descriptor,
                contract::MAX_METADATA as u64,
            ),
            (
                "native-rules.json",
                &self.native_rules,
                contract::MAX_METADATA as u64,
            ),
            (
                "wallet-profile.json",
                &self.wallet_profile,
                contract::MAX_METADATA as u64,
            ),
            (
                "seed-blocks.bin",
                &self.seed_bundle,
                contract::MAX_BUNDLE as u64,
            ),
            ("host-adapter", &self.host_adapter, 128 * 1024 * 1024),
            ("compiled.json", &self.compiled_result, 4 * 1024 * 1024),
            (
                "image.json",
                &self.image_record,
                crate::image::MAX_RECORD_BYTES as u64,
            ),
            (
                "image-manifest.json",
                &self.image_manifest,
                crate::image::MAX_MANIFEST_BYTES as u64,
            ),
            (
                "image-config.json",
                &self.image_config,
                crate::image::MAX_CONFIG_BYTES as u64,
            ),
            ("zdn", &self.host_helper, crate::devnet::MAX_HELPER_BYTES),
        ]
    }

    /// Authenticate the fixed helper leaf without retaining or snapshotting it.
    /// Adapter preparation consumes only the public chain and adapter slots.
    pub fn verify_helper(
        &self,
        artifacts: &Directory,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let expected = &self.host_helper;
        expected.validate()?;
        ensure!(
            expected.bytes <= crate::devnet::MAX_HELPER_BYTES,
            "external helper exceeds bound"
        );
        let mut file = artifacts.regular("zdn", expected.bytes)?;
        let actual = files::digest_file(&mut file, expected.bytes, &mut || {
            ensure!(
                Instant::now() < deadline && !cancelled.load(Ordering::Relaxed),
                "external helper verification interrupted"
            );
            Ok(())
        })?;
        ensure!(
            actual.bytes == expected.bytes && actual.sha256 == expected.sha256,
            "external helper differs"
        );
        crate::devnet::validate_helper(&actual.prefix)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub request: Pin,
    pub trust: CoreTrust,
    pub objects: Objects,
    /// Exact controller compile bytes and security-checked rendered config.
    pub compiled_json: String,
    pub native_inventory: Pin,
    pub options: RenderOptions,
    pub config_toml: String,
    pub config: Pin,
}

impl Manifest {
    /// A different versioned recipe, never an ordinary gateway service hash.
    /// The exact host manifest binds its compiled transport and inventory pins.
    pub fn gateway_service_sha256(&self) -> Result<String> {
        self.validate()?;
        let compiled: contract::Compiled = contract::parse(self.compiled_json.as_bytes())?;
        ensure!(
            compiled.transport_class == "large-hex-v1",
            "unsupported external gateway transport"
        );
        let mut bytes = b"zdn-external-client-gateway/v1\nlarge-hex-v1\n".to_vec();
        bytes.extend(self.bytes()?);
        Ok(Pin::of(&bytes).sha256)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "external host manifest exceeds bound"
        );
        let manifest: Self = contract::parse(bytes)?;
        manifest.validate()?;
        ensure!(
            manifest.bytes()? == bytes,
            "noncanonical external host manifest"
        );
        Ok(manifest)
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "external host manifest exceeds bound"
        );
        Ok(bytes)
    }

    /// Pure preflight before even artifact delivery. The compile requirements
    /// are passed to the finite core build/image validator here, not deferred
    /// until after service effects.
    pub fn validate(&self) -> Result<crate::image::ImageBuildRequirements> {
        ensure!(self.schema == SCHEMA, "unsupported external host schema");
        super::digest(&self.request.sha256)?;
        ensure!(
            (1..=4 * 1024 * 1024).contains(&self.request.bytes),
            "invalid external request pin"
        );
        self.options.validate()?;
        ensure!(
            self.compiled_json.len() <= 4 * 1024 * 1024,
            "external compile result exceeds bound"
        );
        self.config.check(self.config_toml.as_bytes())?;
        ensure!(
            self.config.bytes <= contract::MAX_METADATA as u64,
            "external config exceeds bound"
        );
        ensure!(
            (1..=16 * 1024).contains(&self.native_inventory.bytes)
                && self.native_inventory.sha256.len() == 64
                && self
                    .native_inventory
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid native inventory evidence pin"
        );
        let compiled: contract::Compiled = contract::parse(self.compiled_json.as_bytes())?;
        let requirements = compiled.image_requirements()?;
        ensure!(
            serde_json::to_vec(&compiled)? == self.compiled_json.as_bytes(),
            "noncanonical external compile result"
        );
        let source = &self.objects.package;
        for (_, object, limit) in self.objects.slots() {
            object.validate()?;
            ensure!(
                object.bytes <= limit
                    && object.bucket == source.bucket
                    && object.owner_account == source.owner_account
                    && object.region == source.region,
                "external artifact exceeds bounds or crosses artifact authority"
            );
        }
        ensure!(
            self.trust.package == pin(source)
                && self.trust.executable == pin(&self.objects.host_adapter)
                && Pin::of(self.compiled_json.as_bytes()) == pin(&self.objects.compiled_result),
            "external artifact and controller pins differ"
        );
        Ok(requirements)
    }

    /// Structural saved ownership only. This path does not require a companion
    /// installation and does not authorize activation or require compatibility.
    pub fn package_metadata(&self, artifacts: &Directory) -> Result<PublicPackage> {
        let bytes = read(artifacts, "package.json", &self.objects.package)?;
        Ok(PublicPackage::from_json(&bytes, &self.trust.package)?)
    }

    /// Reuses the existing authenticated, streaming, create-only delivery
    /// algorithm. The caller must preflight its action and retain supervision.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.deliver")
    )]
    pub fn deliver(
        &self,
        artifacts: &Directory,
        aws: &Path,
        executor: &mut Executor,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        self.validate()?;
        require_isolated_execution()?;
        for (name, object, _) in self.objects.slots() {
            artifact_delivery::fetch_object(
                Delivery {
                    pin: object,
                    name,
                    mode: 0o600,
                    timeout: Duration::from_secs(600),
                },
                artifacts,
                aws,
                executor,
                cancelled,
                |_| Ok(()),
            )?;
        }
        Ok(())
    }

    /// Host install/update/recovery pre-effect gate. Adapter inputs are copied
    /// from descriptor-relative authenticated fixed leaves to a fresh snapshot;
    /// the helper is authenticated in bounded chunks and is not snapshotted.
    /// Retain the returned gate for startup/bootstrap/readiness/production.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.prepare")
    )]
    pub fn prepare(
        &self,
        artifacts: &Directory,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PreparedHost> {
        require_isolated_execution()?;
        let requirements = self.validate()?;
        let metadata = self.package_metadata(artifacts)?;
        let o = &self.objects;
        for (expected, object) in [
            (&metadata.descriptor, &o.descriptor),
            (&metadata.native_rules, &o.native_rules),
            (&metadata.wallet_profile, &o.wallet_profile),
            (&metadata.seed_bundle, &o.seed_bundle),
            (&metadata.compiled_result, &o.compiled_result),
        ] {
            ensure!(
                *expected == pin(object),
                "package slot and host source pins differ"
            );
        }
        ensure!(
            metadata.host_adapter.executable_sha256 == self.trust.executable.sha256
                && metadata.host_adapter.executable_bytes == self.trust.executable.bytes
                && metadata.host_adapter.adapter_selection_sha256
                    == self.trust.adapter_selection_sha256,
            "package adapter and explicit host trust differ"
        );
        self.objects.verify_helper(artifacts, deadline, cancelled)?;
        let snapshot = tempfile::tempdir()?;
        for (name, object, _) in self.objects.slots() {
            if name != "zdn" {
                std::fs::write(snapshot.path().join(name), read(artifacts, name, object)?)?;
            }
        }
        let chain = PreparedExternalChain::prepare_isolated(
            &read(artifacts, "package.json", &o.package)?,
            snapshot.path(),
            &self.trust,
            deadline,
            cancelled,
        )?;
        ensure!(
            chain.requirements()? == requirements,
            "host requirements differ from controller"
        );
        let rendered = chain.render(self.options.clone(), deadline, cancelled)?;
        // render() already ran core's independent security envelope validator.
        ensure!(
            rendered.value().config_toml == self.config_toml,
            "host external render differs from controller bytes"
        );
        let image = crate::image::ImageRecord::from_json_for_requirements(
            &read(artifacts, "image.json", &o.image_record)?,
            &requirements,
        )?;
        ensure!(
            image
                .image
                .ends_with(&format!("@{}", self.options.image_digest)),
            "external image digest differs"
        );
        let image_manifest = crate::image::validate_manifest_bytes_for_requirements(
            &image,
            &requirements,
            &read(artifacts, "image-manifest.json", &o.image_manifest)?,
        )?;
        crate::image::validate_config_bytes_for_requirements(
            &image,
            &requirements,
            &image_manifest,
            &read(artifacts, "image-config.json", &o.image_config)?,
        )?;
        Ok(PreparedHost {
            chain,
            image,
            image_manifest,
            requirements,
            manifest: Pin::of(&self.bytes()?),
            _snapshot: snapshot,
        })
    }
}

pub struct PreparedHost {
    chain: PreparedExternalChain,
    image: crate::image::ImageRecord,
    image_manifest: crate::image::VerifiedManifest,
    requirements: crate::image::ImageBuildRequirements,
    manifest: Pin,
    _snapshot: tempfile::TempDir,
}

impl PreparedHost {
    /// Caller supplies a descriptor-authenticated filesystem anchor, retains
    /// supervision and installs only the service hash exported to participants.
    /// Compile/render/image admission has already completed on this value.
    pub fn serve_gateway(
        &self,
        manifest: &Manifest,
        provisioning: &Provisioning,
        anchor: std::fs::File,
        listener: std::net::TcpListener,
        stop: &AtomicBool,
    ) -> Result<()> {
        use super::volume::VolumeSpec;
        // Keep setup finite rather than timing the gateway daemon lifetime.
        #[cfg(feature = "profiling")]
        let setup = tracing::info_span!("host.external.gateway.setup").entered();
        self.manifest.check(&manifest.bytes()?)?;
        provisioning.require_runtime(manifest)?;
        ensure!(
            serde_json::to_vec(self.chain.compiled())? == manifest.compiled_json.as_bytes(),
            "prepared external gateway chain differs"
        );
        ensure!(
            manifest.options.node_id == "node-1",
            "external gateway requires producer host"
        );
        let rpc = crate::chain::rpc::HttpNodeRpc::with_body_class(
            &manifest.options.rpc_listen,
            &Path::new(&manifest.options.cookie_dir).join(".cookie"),
            crate::rpc_limits::BodyClass::LargeHexV1,
        )?;
        self.chain.verify_rules(&rpc, Duration::from_secs(10))?;
        #[cfg(feature = "profiling")]
        drop(setup);
        crate::client_gateway::runtime::serve_with_body_class(
            listener,
            crate::client_gateway::runtime::Config {
                anchor,
                identity_paths: [
                    "etc/zdn/identity.json".into(),
                    "var/lib/zdn/.zdn-volume.json".into(),
                ],
                cookie_path: format!(
                    "{}/.cookie",
                    manifest.options.cookie_dir.trim_start_matches('/')
                )
                .into(),
                root_uid: 0,
                node_uid: crate::image::RUNTIME_UID,
                identity: serde_json::from_slice(&provisioning.volume_identity()?)?,
                service_sha256: manifest.gateway_service_sha256()?,
                upstream: manifest.options.rpc_listen.parse()?,
            },
            stop,
            crate::rpc_limits::BodyClass::LargeHexV1,
        )
    }

    pub fn chain(&self) -> &PreparedExternalChain {
        &self.chain
    }
    pub fn image(&self) -> &crate::image::ImageRecord {
        &self.image
    }
    pub fn requirements(&self) -> &crate::image::ImageBuildRequirements {
        &self.requirements
    }

    pub fn verify_pulled_image(&self, inspect: &[u8]) -> Result<()> {
        crate::image::validate_docker_inspect_for_requirements(
            &self.image,
            &self.requirements,
            &self.image_manifest,
            inspect,
        )?;
        Ok(())
    }

    pub fn verify_image_config(&self, bytes: &[u8]) -> Result<()> {
        crate::image::validate_config_bytes_for_requirements(
            &self.image,
            &self.requirements,
            &self.image_manifest,
            bytes,
        )?;
        Ok(())
    }
}

fn pin(object: &S3Object) -> Pin {
    Pin {
        bytes: object.bytes,
        sha256: object.sha256.clone(),
    }
}
fn read(directory: &Directory, name: &str, object: &S3Object) -> Result<Vec<u8>> {
    let bytes = directory.read(name, object.bytes)?;
    pin(object).check(&bytes)?;
    Ok(bytes)
}
