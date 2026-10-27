//! Immutable installation contract for the owned private lightwalletd host.
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{hash, LightwalletServiceSpec};
use crate::host::{HostInstallSpec, NewVolumeAuthorization, S3Object};

pub const INSTALL_API_VERSION: &str = "zdn-lightwallet-install/v1alpha1";
pub const OBSERVATION_API_VERSION: &str = "zdn-lightwallet-host-observation/v1alpha1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletInstallSpec {
    pub api_version: String,
    pub host: HostInstallSpec,
    pub service: LightwalletServiceSpec,
    pub new_volume: Option<NewVolumeAuthorization>,
    pub image_record: S3Object,
    pub image_manifest: S3Object,
    pub image_config: S3Object,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedLightwalletInstall {
    pub api_version: String,
    pub install_sha256: String,
    pub service_sha256: String,
    pub script_sha256: String,
    pub script: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LightwalletHostObservation {
    pub api_version: String,
    pub deployment_id: uuid::Uuid,
    pub node_id: String,
    pub install_sha256: String,
    pub service_sha256: String,
    pub cache_volume_id: String,
    pub image: String,
    pub status: String,
    pub readiness: Option<Value>,
    pub payment_qualification: String,
    pub launch_ready: bool,
}

impl LightwalletInstallSpec {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet_service.install.spec.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == INSTALL_API_VERSION,
            "unsupported lightwallet install version"
        );
        self.service.validate(&self.host)?;
        let authorization = self
            .new_volume
            .as_ref()
            .context("cache installation requires saved new-volume authorization")?;
        authorization.validate(&self.service.cache_volume_id)?;
        ensure!(
            authorization.size_bytes == self.service.cache_bytes,
            "cache authorization size differs"
        );
        let objects = [&self.image_record, &self.image_manifest, &self.image_config];
        for object in objects {
            object.validate()?;
            ensure!(
                object.bucket == self.host.helper.bucket
                    && object.owner_account == self.host.helper.owner_account
                    && object.region == self.host.helper.region,
                "lightwallet artifacts must use the node's owned artifact bucket and region"
            );
            ensure!(
                object.bytes <= 16 * 1024 * 1024,
                "lightwallet image metadata exceeds its bound"
            );
        }
        ensure!(
            self.image_record.key != self.image_manifest.key
                && self.image_record.key != self.image_config.key
                && self.image_manifest.key != self.image_config.key,
            "lightwallet metadata objects must be distinct"
        );
        Ok(())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_service.install.validate_observation")
)]
pub fn validate_observation(
    value: &Value,
    spec: &LightwalletInstallSpec,
) -> Result<LightwalletHostObservation> {
    spec.validate()?;
    // Canonical native identities bind saved intent, not an installer template.
    let install_sha256 = hash(&serde_json::to_vec(spec)?);
    let service_sha256 = super::render_service(&spec.host, &spec.service)?.service_sha256;
    let observation: LightwalletHostObservation =
        serde_json::from_value(value.clone()).context("decode lightwallet host observation")?;
    ensure!(
        observation.api_version == OBSERVATION_API_VERSION
            && observation.deployment_id == spec.host.deployment_id
            && observation.node_id == spec.host.node_id
            && observation.install_sha256 == install_sha256
            && observation.service_sha256 == service_sha256
            && observation.cache_volume_id == spec.service.cache_volume_id
            && observation.image == spec.service.image
            && !observation.launch_ready
            && observation.payment_qualification == "pending",
        "lightwallet observation identity or qualification differs"
    );
    match (observation.status.as_str(), &observation.readiness) {
        ("stopped", None) => {}
        ("ready", Some(report)) => {
            ensure!(
                report["apiVersion"] == crate::lightwallet::API_VERSION
                    && report["consensusFingerprint"] == spec.host.consensus_fingerprint
                    && report["protocolVersion"] == crate::lightwallet::PROTOCOL_VERSION
                    && report["launchReady"] == false
                    && report["paymentQualification"] == "pending"
                    && report["ironwoodTreeVerified"] == true
                    && report["compactDataVerified"] == true
                    && report["lagBlocks"].as_u64().is_some_and(|n| n <= 2)
                    && report["checkedCompactBlocks"]
                        .as_u64()
                        .is_some_and(|n| n > 0),
                "lightwallet readiness report differs from the saved chain"
            );
        }
        _ => eyre::bail!("invalid lightwallet service state"),
    }
    Ok(observation)
}
