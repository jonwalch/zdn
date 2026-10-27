//! Translate explicit persisted fresh-deployment intent into pinned recipes.
//! Absence is legacy, never an invitation to infer support from a helper pin.
use super::*;
use crate::host::runtime::{Manifest, Selection, PROTOCOL};

pub(super) fn node_manifest(
    protocol: Option<&str>,
    host: &crate::host::HostInstallSpec,
) -> Result<Manifest> {
    ensure!(
        protocol == Some(PROTOCOL),
        "unsupported native runtime selection"
    );
    Manifest::new(
        host.clone(),
        Selection {
            protocol: PROTOCOL.into(),
            helper: host.helper.clone(),
        },
    )
}

pub(in crate::foundation_live) fn node_command(
    protocol: Option<&str>,
    host: &crate::host::HostInstallSpec,
    operation: &str,
) -> Result<String> {
    ensure!(
        matches!(operation, "observe" | "start-producer"),
        "invalid controller node operation"
    );
    let manifest = node_manifest(protocol, host)?;
    command(
        &manifest,
        "__host-runtime",
        PROTOCOL,
        &format!("/etc/zdn/runtime/manifests/{}", manifest.file_name()?),
        operation,
    )
}

pub(super) fn gateway_command(manifest: &Manifest, operation: &str) -> Result<String> {
    ensure!(
        matches!(operation, "install" | "observe"),
        "invalid controller gateway operation"
    );
    command(
        manifest,
        "__client-gateway",
        crate::client_gateway::native::PROTOCOL,
        &format!("/etc/zdn/runtime/manifests/{}", manifest.file_name()?),
        operation,
    )
}

pub(in crate::foundation_live) fn validate_gateway_observation(
    protocol: Option<&str>,
    host: &crate::host::HostInstallSpec,
    value: &Value,
) -> Result<crate::client_gateway::ClientGatewayObservation> {
    crate::client_gateway::native::validate_observation(value, &node_manifest(protocol, host)?)
}

fn command(
    manifest: &Manifest,
    entrypoint: &str,
    protocol: &str,
    path: &str,
    operation: &str,
) -> Result<String> {
    manifest.validate()?;
    Ok(format!(
        "/etc/zdn/runtime/{}/zdn {entrypoint} --protocol {protocol} --manifest {path} {operation}",
        manifest.runtime.helper.sha256
    ))
}

pub(super) fn lightwallet_manifest(
    protocol: Option<&str>,
    spec: &crate::lightwallet_service::LightwalletInstallSpec,
) -> Result<crate::lightwallet_service::native::Manifest> {
    let node = node_manifest(protocol, &spec.host)?;
    crate::lightwallet_service::native::Manifest::new(
        spec.clone(),
        node.clone(),
        Selection {
            protocol: crate::lightwallet_service::native::PROTOCOL.into(),
            helper: node.runtime.helper,
        },
    )
}

pub(in crate::foundation_live) fn lightwallet_command(
    protocol: Option<&str>,
    spec: &crate::lightwallet_service::LightwalletInstallSpec,
    operation: &str,
) -> Result<String> {
    ensure!(
        matches!(operation, "observe" | "start"),
        "invalid controller lightwallet operation"
    );
    let manifest = lightwallet_manifest(protocol, spec)?;
    command(
        &manifest.node,
        "__lightwallet-runtime",
        crate::lightwallet_service::native::PROTOCOL,
        &format!(
            "{}/{}",
            crate::lightwallet_service::native::MANIFEST_DIRECTORY,
            manifest.file_name()?
        ),
        operation,
    )
}
