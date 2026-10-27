//! Controller-facing native gateway installation and observation records.

use serde::{Deserialize, Serialize};

pub const OBSERVATION_API_VERSION: &str = "zdn-client-rpc-observation/v1alpha1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedClientGatewayInstall {
    pub install_sha256: String,
    pub service_sha256: String,
    pub script_sha256: String,
    pub script: String,
    pub observe_script: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientGatewayObservation {
    pub api_version: String,
    pub deployment_id: uuid::Uuid,
    pub node_id: String,
    pub consensus_fingerprint: String,
    pub service_sha256: String,
    pub endpoint: String,
    pub status: String,
}
