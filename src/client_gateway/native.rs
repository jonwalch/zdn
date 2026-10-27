//! Explicit native gateway recipe, separate from every historical Python hash.
//! The host manifest pins both original installation and native executable;
//! neither package version nor a same-named unit selects this recipe.

use std::net::SocketAddr;

use eyre::{ensure, Result};
use serde_json::{json, Value};

use super::{ClientGatewayObservation, ENDPOINT, OBSERVATION_API_VERSION};
use crate::host::runtime::Manifest;

pub const PROTOCOL: &str = "zdn-client-gateway-runtime/v1alpha1";

pub fn upstream(manifest: &Manifest) -> Result<SocketAddr> {
    manifest.validate()?;
    super::upstream(&manifest.spec)
}

pub fn service_sha256(manifest: &Manifest) -> Result<String> {
    upstream(manifest)?;
    let mut bytes = PROTOCOL.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes.extend(manifest.bytes()?);
    Ok(super::hash(&bytes))
}

pub fn observation(manifest: &Manifest, status: &str) -> Result<Value> {
    ensure!(
        matches!(status, "ready" | "stopped"),
        "invalid gateway status"
    );
    Ok(json!({"apiVersion":OBSERVATION_API_VERSION,
        "deploymentId":manifest.spec.deployment_id,"nodeId":manifest.spec.node_id,
        "consensusFingerprint":manifest.spec.consensus_fingerprint,
        "serviceSha256":service_sha256(manifest)?,"endpoint":ENDPOINT,"status":status}))
}

pub fn validate_observation(
    value: &Value,
    manifest: &Manifest,
) -> Result<ClientGatewayObservation> {
    let report: ClientGatewayObservation = serde_json::from_value(value.clone())
        .map_err(|_| eyre::eyre!("invalid native gateway observation"))?;
    ensure!(
        *value == observation(manifest, &report.status)?,
        "native gateway observation differs"
    );
    Ok(report)
}

/// Same sandbox/ordering as the original gateway; the service stays root to
/// read the private node cookie, with no writable durable host paths.
pub fn unit(manifest: &Manifest) -> Result<String> {
    upstream(manifest)?;
    let command = format!("/etc/zdn/runtime/{}/zdn __client-gateway --protocol {PROTOCOL} --manifest /etc/zdn/runtime/manifests/{} serve", manifest.runtime.helper.sha256, manifest.file_name()?);
    Ok(format!(
        r#"[Unit]
Description=zdn private participant RPC
After=zdn-node.service
BindsTo=zdn-node.service
PartOf=zdn-node.service
StartLimitIntervalSec=300
StartLimitBurst=3
[Service]
Type=exec
ExecStart={command}
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
KillSignal=SIGTERM
KillMode=control-group
UMask=0077
LimitCORE=0
MemoryMax=256M
CPUQuota=25%
TasksMax=16
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
[Install]
WantedBy=zdn-node.service
"#
    ))
}
