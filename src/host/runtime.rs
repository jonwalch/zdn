//! Immutable native runtime selection, separate from the original installation.
//!
//! This is data, not permission to migrate an existing deployment. A controller
//! must authenticate the selection and settle its transition before installing
//! units that refer to it. Original helper pins, volume identities, producer
//! authorizations and saved SSM bytes are never rewritten by this contract.

use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{HostInstallSpec, S3Object};

pub mod bootstrap;
#[cfg(target_os = "linux")]
pub mod control;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod install;
#[cfg(target_os = "linux")]
pub mod lightwallet;
pub mod revision;
#[cfg(target_os = "linux")]
pub mod revision_delivery;
#[cfg(target_os = "linux")]
pub mod update;

pub const PROTOCOL: &str = "zdn-host-runtime/v1alpha1";
pub const INSTALL_PROTOCOL: &str = "zdn-host-install-runtime/v1alpha1";
pub const API_VERSION: &str = "zdn-host-runtime-manifest/v1alpha1";
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub protocol: String,
    /// May differ from the original chain helper. A legacy migration must pin
    /// a new runtime without pretending that it was the first-install helper.
    pub helper: S3Object,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: String,
    pub install_sha256: String,
    pub spec: HostInstallSpec,
    pub runtime: Selection,
}

impl Manifest {
    pub fn new(spec: HostInstallSpec, runtime: Selection) -> Result<Self> {
        let manifest = Self {
            api_version: API_VERSION.into(),
            install_sha256: spec.install_sha256()?,
            spec,
            runtime,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION && self.runtime.protocol == PROTOCOL,
            "unsupported native host runtime contract"
        );
        ensure!(
            self.install_sha256 == self.spec.install_sha256()?,
            "native runtime belongs to another installation"
        );
        let helper = &self.runtime.helper;
        helper.validate()?;
        ensure!(
            helper.bytes <= crate::devnet::MAX_HELPER_BYTES
                && helper.bucket == self.spec.helper.bucket
                && helper.owner_account == self.spec.helper.owner_account
                && helper.region == self.spec.helper.region,
            "native runtime helper differs from the installation artifact scope"
        );
        Ok(())
    }

    /// Versioned canonical bytes: compact typed-field JSON followed by LF.
    /// Reject alternate encodings on read so one immutable name has one meaning.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "native runtime manifest exceeded its bound"
        );
        Ok(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "native runtime manifest exceeded its bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| eyre::eyre!("invalid native runtime manifest"))?;
        ensure!(
            manifest.bytes()? == bytes,
            "noncanonical native runtime manifest"
        );
        Ok(manifest)
    }

    pub fn file_name(&self) -> Result<String> {
        Ok(format!("{}.json", super::hash(&self.bytes()?)))
    }

    /// Requires trusted traversal and the retained original installation lock.
    /// Create-only publication deliberately cannot switch active service units.
    #[cfg(target_os = "linux")]
    pub fn publish(
        &self,
        directory: &super::files::Directory,
        installation: &super::volume::Installation<'_>,
    ) -> Result<String> {
        installation.verify_spec(&self.spec)?;
        let name = self.file_name()?;
        directory.publish(&name, &self.bytes()?, 0o600)?;
        Ok(name)
    }

    #[cfg(target_os = "linux")]
    pub fn load(directory: &super::files::Directory, name: &str) -> Result<Self> {
        let manifest = Self::from_slice(&directory.read(name, MAX_MANIFEST_BYTES)?)?;
        ensure!(
            manifest.file_name()? == name,
            "native runtime manifest name differs"
        );
        Ok(manifest)
    }
}
