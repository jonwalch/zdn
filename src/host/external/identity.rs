//! Separate phase-one native key provisioning. No start, peer synchronization,
//! seed submission or producer authority is granted by this manifest.
use std::{path::Path, sync::atomic::AtomicBool, time::Instant};

use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{Objects, Provisioning};
use crate::{
    devnet::external::ExternalRequest,
    host::files::Directory,
    public_chain_adapter::{
        contract::{self, Pin, RenderOptions},
        package::PreparedExternalChain,
    },
};

pub const SCHEMA: &str = "zdn-external-native-provisioning/v1";
pub mod runtime;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub provisioning: Provisioning,
    pub request: ExternalRequest,
    pub sources: Objects,
    pub options: RenderOptions,
    pub config_toml: String,
    pub config: Pin,
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported native provisioning schema"
        );
        self.provisioning.validate()?;
        self.request.require_sources(&self.sources)?;
        self.provisioning.request.check(&self.request.bytes()?)?;
        self.options.validate_for_render(true)?;
        let p = &self.provisioning;
        ensure!(
            p.descriptor_sha256 == self.request.artifacts["descriptor.json"].sha256
                && p.native_fingerprint == self.request.compiled.native_fingerprint
                && self.options.deployment_id == p.deployment_id.to_string()
                && self.options.node_id == p.node_id
                && self.options.identity_dir == format!("{}/identity", p.node_root())
                && self.options.state_dir == format!("{}/state", p.node_root())
                && self.options.cookie_dir == format!("{}/rpc", p.node_root())
                && self
                    .request
                    .image
                    .image
                    .ends_with(&format!("@{}", self.options.image_digest)),
            "native provisioning belongs to another deployment or chain"
        );
        self.config.check(self.config_toml.as_bytes())?;
        ensure!(
            self.config.bytes <= contract::MAX_METADATA as u64,
            "native provisioning config exceeds bound"
        );
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "native provisioning manifest exceeds bound"
        );
        Ok(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "native provisioning manifest exceeds bound"
        );
        let value: Self = contract::parse(bytes)?;
        ensure!(
            value.bytes()? == bytes,
            "noncanonical native provisioning manifest"
        );
        Ok(value)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.identity.new")
    )]
    pub fn new(
        request: ExternalRequest,
        provisioning: Provisioning,
        sources: Objects,
        options: RenderOptions,
        directory: &Path,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        let mut value = Self {
            schema: SCHEMA.into(),
            provisioning,
            request,
            sources,
            options,
            config_toml: String::new(),
            config: Pin::of(&[]),
        };
        value.validate()?;
        let prepared = value.request.prepare(directory, deadline, cancelled)?;
        value.config_toml = prepared
            .render_identity(value.options.clone(), deadline, cancelled)?
            .value()
            .config_toml
            .clone();
        value.config = Pin::of(value.config_toml.as_bytes());
        value.validate()?;
        Ok(value)
    }

    /// Every mutable host effect follows authenticated input checks and fresh
    /// isolated compilation/rendering, not just a saved result comparison.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.identity.prepare")
    )]
    pub fn prepare(
        &self,
        artifacts: &Directory,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Prepared> {
        self.validate()?;
        super::require_isolated_execution()?;
        let snapshot = tempfile::tempdir()?;
        for (name, object, _) in self.sources.slots() {
            std::fs::write(
                snapshot.path().join(name),
                super::read(artifacts, name, object)?,
            )?;
        }
        let chain = self
            .request
            .prepare_isolated(snapshot.path(), deadline, cancelled)?;
        ensure!(
            chain
                .render_identity(self.options.clone(), deadline, cancelled)?
                .value()
                .config_toml
                == self.config_toml,
            "host native provisioning render differs"
        );
        let requirements = chain.requirements()?;
        let proof = crate::image::validate_manifest_bytes_for_requirements(
            &self.request.image,
            &requirements,
            &super::read(
                artifacts,
                "image-manifest.json",
                &self.sources.image_manifest,
            )?,
        )?;
        Ok(Prepared {
            chain,
            requirements,
            proof,
            _snapshot: snapshot,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.identity.deliver")
    )]
    pub fn deliver(
        &self,
        artifacts: &Directory,
        aws: &Path,
        executor: &mut crate::host::command::Executor,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        self.validate()?;
        super::require_isolated_execution()?;
        for (name, object, _) in self.sources.slots() {
            crate::host::artifact_delivery::fetch_object(
                crate::host::artifact_delivery::Delivery {
                    pin: object,
                    name,
                    mode: 0o600,
                    timeout: std::time::Duration::from_secs(600),
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
}

pub struct Prepared {
    chain: PreparedExternalChain,
    requirements: crate::image::ImageBuildRequirements,
    proof: crate::image::VerifiedManifest,
    _snapshot: tempfile::TempDir,
}

impl Prepared {
    pub fn verify_pulled_image(&self, manifest: &Manifest, inspect: &[u8]) -> Result<()> {
        ensure!(
            serde_json::to_vec(self.chain.compiled())?
                == serde_json::to_vec(&manifest.request.compiled)?,
            "native provisioning compile differs"
        );
        crate::image::validate_docker_inspect_for_requirements(
            &manifest.request.image,
            &self.requirements,
            &self.proof,
            inspect,
        )?;
        Ok(())
    }

    /// A saved public ID turns ensure into strict load: missing/corrupt keys
    /// can never be replaced on a retry after successful identity collection.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "host.external.identity.verification_config")
    )]
    pub fn verification_config(
        &self,
        manifest: &Manifest,
        saved: &crate::native_peers::NativeIdentity,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<String> {
        ensure!(
            saved.chain_fingerprint.as_deref() == Some(&manifest.provisioning.native_fingerprint),
            "saved native identity chain differs"
        );
        let mut options = manifest.options.clone();
        options.expected_node_id = saved.node_id.clone();
        Ok(self
            .chain
            .render(options, deadline, cancelled)?
            .value()
            .config_toml
            .clone())
    }
}
