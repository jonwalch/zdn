//! Draft chain requests and explicit, unqualified compatibility records.
//! This module has no consensus implementation or node dependency.

pub mod artifacts;
pub mod bootstrap;
pub mod manifest;
pub mod node_config;
pub mod producer;
pub mod readiness;
pub mod rpc;
pub mod runtime_config;
pub mod startup;

use crate::config::Config;
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainRequest {
    pub api_version: String,
    pub kind: String,
    pub preset: String,
    pub payment_pool: String,
    pub activation_heights: BTreeMap<String, u32>,
    pub proof_of_work: String,
    pub public_seeds: bool,
    pub unresolved: Vec<String>,
}

impl ChainRequest {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.request.from_config")
    )]
    pub fn from_config(config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            api_version: "zdn-chain-request/v1alpha1".into(),
            kind: config.network.kind.clone(),
            preset: config.network.preset.clone(),
            payment_pool: "ironwood".into(),
            activation_heights: config.resolved_upgrades()?,
            proof_of_work: config.network.mining.proof_of_work.clone(),
            public_seeds: false,
            unresolved: vec![
                "Pinned Zakura build and complete supported custom-Testnet recipe".into(),
                "Reserved network magic, genesis bytes/hash, subsidy and difficulty parameters"
                    .into(),
                "Private peer addresses and matching wallet/client chain configuration".into(),
                "Ironwood-capable wallet, lightwalletd version, and reward-to-Ironwood recipe"
                    .into(),
                "Human H0 acceptance: mine, mature, fund, send, scan, and spend received notes"
                    .into(),
            ],
        })
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

pub const REQUIRED_CAPABILITIES: &[&str] = &[
    "custom-testnet",
    "authenticated-generate",
    "ironwood-v6-transactions",
    "ironwood-compact-blocks",
    "ironwood-tree-data",
    "ironwood-scan-and-spend",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentPin {
    pub version: String,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityRecord {
    pub api_version: String,
    pub chain_request_sha256: String,
    pub platform: String,
    pub zakura: Option<ComponentPin>,
    pub wallet: Option<ComponentPin>,
    pub lightwalletd: Option<ComponentPin>,
    pub capabilities: BTreeMap<String, bool>,
    pub human_evidence_sha256: Option<String>,
}

impl CompatibilityRecord {
    pub fn pending(chain: &ChainRequest) -> Result<Self> {
        Ok(Self {
            api_version: "zdn-compatibility/v1alpha1".into(),
            chain_request_sha256: chain.fingerprint()?,
            platform: "linux/amd64".into(),
            zakura: None,
            wallet: None,
            lightwalletd: None,
            capabilities: REQUIRED_CAPABILITIES
                .iter()
                .map(|v| ((*v).into(), false))
                .collect(),
            human_evidence_sha256: None,
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.compatibility.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == "zdn-compatibility/v1alpha1",
            "unsupported compatibility record version"
        );
        ensure!(
            self.platform == "linux/amd64",
            "only native Linux x86-64 node images are supported"
        );
        digest(&self.chain_request_sha256)?;
        for name in self.capabilities.keys() {
            ensure!(
                REQUIRED_CAPABILITIES.contains(&name.as_str()),
                "unknown capability {name}"
            );
        }
        for pin in [&self.zakura, &self.wallet, &self.lightwalletd]
            .into_iter()
            .flatten()
        {
            ensure!(
                !pin.version.trim().is_empty(),
                "component version cannot be empty"
            );
            ensure!(
                !["latest", "main", "master", "stable", "nightly"].contains(&pin.version.as_str()),
                "component version must be immutable"
            );
            digest(&pin.artifact_sha256)?;
        }
        if let Some(evidence) = &self.human_evidence_sha256 {
            digest(evidence)?;
        }
        Ok(())
    }

    /// Checks the completeness of a human evidence record, not its authenticity or correctness.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.compatibility.require_complete_evidence")
    )]
    pub fn require_complete_evidence(&self, expected_chain_request: &str) -> Result<()> {
        self.validate()?;
        ensure!(
            self.chain_request_sha256 == expected_chain_request,
            "compatibility evidence belongs to a different chain request"
        );
        ensure!(
            self.zakura.is_some() && self.wallet.is_some() && self.lightwalletd.is_some(),
            "compatible Zakura, wallet, and lightwalletd versions remain unselected"
        );
        for capability in REQUIRED_CAPABILITIES {
            ensure!(
                self.capabilities.get(*capability) == Some(&true),
                "unqualified capability: {capability}"
            );
        }
        ensure!(
            self.human_evidence_sha256.is_some(),
            "human H0 evidence is missing"
        );
        Ok(())
    }
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected a 64-character SHA-256 digest"
    );
    Ok(())
}
