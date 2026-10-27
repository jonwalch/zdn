//! Opt-in native lightwallet installation data, never deployment selection.
//!
//! The typed spec and canonical install/service identity bindings are preserved.
//! The node manifest is additional
//! evidence of explicit native node intent, not authority to install a node or
//! authorize a producer. Recipes are explicit and never select a deployment.

use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{hash, LightwalletInstallSpec};
use crate::host::runtime::{Manifest as NodeManifest, Selection};

pub const PROTOCOL: &str = "zdn-lightwallet-runtime/v1alpha1";
pub const API_VERSION: &str = "zdn-lightwallet-runtime-manifest/v1alpha1";
pub const MAX_MANIFEST_BYTES: u64 = crate::host::runtime::MAX_MANIFEST_BYTES;
pub const INSTALL_PROTOCOL: &str = "zdn-lightwallet-install-runtime/v1alpha1";
pub const MANIFEST_DIRECTORY: &str = "/etc/zdn-lightwalletd/runtime/manifests";
pub const UNIT_NAME: &str = "zdn-lightwalletd.service";

pub fn rpc_endpoint(manifest: &Manifest) -> Result<std::net::SocketAddr> {
    manifest.validate()?;
    super::rpc_endpoint(&manifest.spec.host)
}

/// Immutable role-specific intent. Inclusion of a node manifest does not prove
/// it is installed: privileged callers must compare its exact saved intent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: String,
    pub install_sha256: String,
    pub spec: LightwalletInstallSpec,
    pub node: NodeManifest,
    pub runtime: Selection,
}

impl Manifest {
    pub fn new(
        spec: LightwalletInstallSpec,
        node: NodeManifest,
        runtime: Selection,
    ) -> Result<Self> {
        let manifest = Self {
            api_version: API_VERSION.into(),
            install_sha256: hash(&serde_json::to_vec(&spec)?),
            spec,
            node,
            runtime,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION && self.runtime.protocol == PROTOCOL,
            "unsupported native lightwallet contract"
        );
        self.spec.validate()?;
        self.node.validate()?;
        ensure!(
            self.install_sha256 == hash(&serde_json::to_vec(&self.spec)?)
                && serde_json::to_vec(&self.node.spec)? == serde_json::to_vec(&self.spec.host)?,
            "native lightwallet installation differs"
        );
        self.runtime.helper.validate()?;
        // This bounded recipe reuses the already-installed native node runtime.
        // A different helper requires a separate authenticated delivery path.
        ensure!(
            serde_json::to_vec(&self.runtime.helper)?
                == serde_json::to_vec(&self.node.runtime.helper)?,
            "native lightwallet executable differs from native node runtime"
        );
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "native lightwallet manifest too large"
        );
        Ok(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "native lightwallet manifest too large"
        );
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| eyre::eyre!("invalid native lightwallet manifest"))?;
        ensure!(
            manifest.bytes()? == bytes,
            "noncanonical native lightwallet manifest"
        );
        Ok(manifest)
    }

    pub fn file_name(&self) -> Result<String> {
        Ok(format!("{}.json", hash(&self.bytes()?)))
    }

    #[cfg(target_os = "linux")]
    pub fn load(directory: &crate::host::files::Directory, name: &str) -> Result<Self> {
        let manifest = Self::from_slice(&directory.read(name, MAX_MANIFEST_BYTES)?)?;
        ensure!(
            manifest.file_name()? == name,
            "native lightwallet manifest name differs"
        );
        Ok(manifest)
    }
}

/// Immutable native recipe. Keep the host mount namespace: preparation mounts
/// the retained cache for the daemon and must not run inside ProtectHome's
/// private mount namespace. Let the main process settle its child supervisors
/// before systemd's bounded final group kill. No producer or seed-bootstrap
/// entry is reachable.
pub fn unit(manifest: &Manifest) -> Result<String> {
    manifest.validate()?;
    let command = format!("/etc/zdn/runtime/{}/zdn __lightwallet-runtime --protocol {PROTOCOL} --manifest {MANIFEST_DIRECTORY}/{}", manifest.runtime.helper.sha256, manifest.file_name()?);
    let cache = super::render_service(&manifest.spec.host, &manifest.spec.service)?.cache_root;
    Ok(format!(
        r#"[Unit]
Description=zdn private lightwalletd
After=docker.service zdn-node.service
Requires=docker.service
BindsTo=zdn-node.service
PartOf=zdn-node.service
RequiresMountsFor={cache}
StartLimitIntervalSec=300
StartLimitBurst=3
[Service]
Type=exec
ExecStartPre={command} prepare
ExecStart={command} serve
Restart=on-failure
RestartSec=10
KillSignal=SIGTERM
KillMode=mixed
TimeoutStartSec=200
TimeoutStopSec=120
UMask=0077
LimitCORE=0
MemoryMax=128M
CPUQuota=10%
NoNewPrivileges=true
[Install]
WantedBy=zdn-node.service
"#
    ))
}

/// First install uses only the executable already authenticated and installed
/// by the native node. There is deliberately no new download/helper authority.
pub fn bootstrap(manifest: &Manifest) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = manifest.bytes()?;
    let pin = &manifest.runtime.helper;
    Ok(format!(
        r#"#!/bin/bash
set -euo pipefail
export LC_ALL=C
unset POSIXLY_CORRECT
umask 077
runtime=/etc/zdn/runtime/{digest}/zdn
[[ $(stat -c '%s' -- "$runtime") == '{size}' ]] || exit 1
printf '%s  %s\n' '{digest}' "$runtime" | sha256sum --check --status || exit 1
timeout --signal=TERM --kill-after=5s 10s "$runtime" __runtime-capabilities --require {protocol} >/dev/null 2>&1
printf '%s' '{manifest}' | base64 --decode | timeout --signal=TERM --kill-after=10s 2405s "$runtime" __lightwallet-install --protocol {protocol} 2>/dev/null
"#,
        digest = pin.sha256,
        size = pin.bytes,
        protocol = INSTALL_PROTOCOL,
        manifest = STANDARD.encode(bytes)
    ))
}
