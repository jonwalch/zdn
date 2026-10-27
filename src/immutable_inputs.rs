//! Redacted diagnostics for immutable local-input comparisons, not authorization.

use eyre::Result;
use serde::Serialize;
use serde_json::Value;
use std::fmt;

/// Only schema-owned field names and presence/change kinds are retained.
/// Values, map keys, paths and backend diagnostics never enter this report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImmutableInputReport {
    pub changed_fields: Vec<ChangedField>,
    pub immutable: bool,
    pub execution_authorized: bool,
    pub live_state_checked: bool,
    pub guidance: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedField {
    pub field: &'static str,
    pub change_kind: ChangeKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

impl ImmutableInputReport {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "immutable_inputs.operation_inputs")
    )]
    pub fn operation_inputs(
        original: &crate::state::OperationInput,
        candidate: &crate::state::OperationInput,
    ) -> Result<Self> {
        Ok(Self::compare(
            &serde_json::to_value(original)?,
            &serde_json::to_value(candidate)?,
            &[
                ("archiveSha256", "/archive_sha256"),
                ("configSha256", "/config_sha256"),
                ("sourceManifestSha256", "/source_manifest_sha256"),
            ],
        ))
    }

    /// A saved fingerprint cannot establish which original config fields changed.
    pub fn config_fingerprint() -> Self {
        Self::new(vec![ChangedField {
            field: "configSha256",
            change_kind: ChangeKind::Modified,
        }])
    }

    /// The request retains this selection even when the full config is unavailable.
    pub fn lightwallet_selection() -> Self {
        Self::new(vec![ChangedField {
            field: "services.lightwallet",
            change_kind: ChangeKind::Modified,
        }])
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "immutable_inputs.cluster_request")
    )]
    pub fn cluster_request(
        original: &crate::devnet::ClusterRequest,
        candidate: &crate::devnet::ClusterRequest,
    ) -> Result<Self> {
        Ok(Self::compare(
            &serde_json::to_value(original)?,
            &serde_json::to_value(candidate)?,
            &[
                ("apiVersion", "/apiVersion"),
                ("artifactSet", "/artifactSet"),
                ("artifacts", "/artifacts"),
                ("blockIntervalSeconds", "/blockIntervalSeconds"),
                ("build", "/build"),
                ("clientAccess", "/clientAccess"),
                ("configSha256", "/configSha256"),
                ("image", "/image"),
                ("installerFetchProtocol", "/installerFetchProtocol"),
                ("lightwallet", "/lightwallet"),
                ("manifest", "/manifest"),
                ("nodeCount", "/nodeCount"),
                ("rewardAddress", "/rewardAddress"),
            ],
        ))
    }

    /// Pass the normalized candidate to omit source/build changes allowed by updates.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "immutable_inputs.config")
    )]
    pub fn config(
        original: &crate::config::Config,
        candidate: &crate::config::Config,
    ) -> Result<Self> {
        Ok(Self::compare(
            &serde_json::to_value(original)?,
            &serde_json::to_value(candidate)?,
            &[
                ("access.visibility", "/access/visibility"),
                ("apiVersion", "/apiVersion"),
                ("deployment.placement", "/deployment/placement"),
                ("deployment.provider", "/deployment/provider"),
                ("name", "/name"),
                ("network.activationHeights", "/network/activationHeights"),
                ("network.kind", "/network/kind"),
                ("network.mining.interval", "/network/mining/interval"),
                ("network.mining.mode", "/network/mining/mode"),
                ("network.mining.producer", "/network/mining/producer"),
                ("network.mining.proofOfWork", "/network/mining/proofOfWork"),
                ("network.nodes", "/network/nodes"),
                ("network.preset", "/network/preset"),
                ("node.adapter", "/node/adapter"),
                ("node.build", "/node/build"),
                ("node.resources.preset", "/node/resources/preset"),
                ("node.source", "/node/source"),
                ("profile", "/profile"),
                ("services.faucet", "/services/faucet"),
                ("services.lightwallet", "/services/lightwallet"),
                ("services.wallet", "/services/wallet"),
            ],
        ))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "immutable_inputs.compare")
    )]
    fn compare(original: &Value, candidate: &Value, fields: &[(&'static str, &str)]) -> Self {
        let changed_fields = fields
            .iter()
            .filter_map(|&(field, pointer)| {
                let before = original.pointer(pointer).filter(|v| !v.is_null());
                let after = candidate.pointer(pointer).filter(|v| !v.is_null());
                (before != after).then_some(ChangedField {
                    field,
                    change_kind: match (before, after) {
                        (None, Some(_)) => ChangeKind::Added,
                        (Some(_), None) => ChangeKind::Removed,
                        _ => ChangeKind::Modified,
                    },
                })
            })
            .collect();
        Self::new(changed_fields)
    }

    fn new(changed_fields: Vec<ChangedField>) -> Self {
        Self {
            changed_fields,
            immutable: true,
            execution_authorized: false,
            live_state_checked: false,
            guidance: "Restore the original inputs to recover the saved operation, or create a separate new deployment for changed immutable inputs.",
        }
    }
}

/// Downcast through `eyre::Report` and serialize `report` for machine output.
/// The message is the boundary's existing static rejection phrase.
#[derive(Debug)]
pub struct ImmutableInputError {
    message: &'static str,
    pub report: ImmutableInputReport,
}

impl ImmutableInputError {
    pub fn new(message: &'static str, report: ImmutableInputReport) -> Self {
        Self { message, report }
    }
}

impl fmt::Display for ImmutableInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; changed fields: ", self.message)?;
        for (index, change) in self.report.changed_fields.iter().enumerate() {
            if index > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{} ({:?})", change.field, change.change_kind)?;
        }
        write!(f, "; {}", self.report.guidance)
    }
}

impl std::error::Error for ImmutableInputError {}
