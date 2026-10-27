//! One digest-bound deployment artifact set for source builds and releases.
//! Provenance and compatibility fields are publisher declarations, not signatures,
//! reproducibility evidence, storage compatibility, or wallet qualification.
use crate::{build::BuildContract, devnet::Artifact, image::ImageRecord};
use eyre::{ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub const API_VERSION: &str = "zdn-artifact-set/v1alpha1";
pub const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactSet {
    pub api_version: String,
    pub platform: String,
    pub consensus_fingerprint: String,
    pub node_image: ImageRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lightwallet_image: Option<crate::lightwallet_image::ImageRecord>,
    pub compatibility: Compatibility,
    /// Exactly chain, node, helper, and lightwallet when enabled. Image source
    /// revisions must agree with the corresponding image record.
    pub provenance: BTreeMap<String, Provenance>,
    /// Fixed six/nine flat filenames shared with devnet staging; no paths or
    /// executable hooks. Every artifact is mandatory and size/hash pinned.
    pub artifacts: BTreeMap<String, Artifact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    pub source_url: String,
    pub revision: String,
    /// Publisher-supplied license identifier/expression, not a license audit.
    pub license: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Compatibility {
    pub chain_bundle_api: String,
    pub runtime_adapter: String,
    pub helper_version: String,
    pub lightwallet_protocol: Option<String>,
}

impl Compatibility {
    pub fn current(lightwallet: bool) -> Self {
        Self {
            chain_bundle_api: crate::chain::artifacts::BUNDLE_API_VERSION.into(),
            runtime_adapter: crate::chain::runtime_config::ADAPTER.into(),
            helper_version: env!("CARGO_PKG_VERSION").into(),
            lightwallet_protocol: lightwallet
                .then(|| crate::lightwallet_image::PROTOCOL_VERSION.into()),
        }
    }
}

/// Fixed, flat inventory and maximum raw byte lengths accepted by the resolver.
pub fn artifact_limits(lightwallet: bool) -> BTreeMap<String, u64> {
    crate::devnet::INPUTS
        .iter()
        .chain(
            crate::devnet::LIGHTWALLET_INPUTS
                .iter()
                .filter(|_| lightwallet),
        )
        .map(|(name, limit)| ((*name).into(), *limit))
        .collect()
}

impl ArtifactSet {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "artifact_set.from_json")
    )]
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "artifact set is too large"
        );
        let set: Self = serde_json::from_slice(bytes).context("decode artifact set")?;
        set.require_compatible()?;
        Ok(set)
    }

    /// Validate saved identity and supported schemas without requiring the current
    /// helper version. Inspection and cleanup must survive a CLI version bump.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "artifact_set.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported artifact set API"
        );
        ensure!(
            self.platform == "linux/amd64",
            "unsupported artifact set platform"
        );
        ensure!(
            lower_hex(&self.consensus_fingerprint, 64),
            "invalid consensus fingerprint"
        );
        self.node_image.validate()?;
        if let Some(build) = &self.build {
            build.validate_image(&self.node_image)?;
        }
        if let Some(image) = &self.lightwallet_image {
            image.validate()?;
        }
        let lightwallet = self.lightwallet_image.is_some();
        let current = Compatibility::current(lightwallet);
        ensure!(
            self.compatibility.chain_bundle_api == current.chain_bundle_api
                && self.compatibility.runtime_adapter == current.runtime_adapter
                && self.compatibility.lightwallet_protocol == current.lightwallet_protocol,
            "unsupported artifact compatibility contract"
        );
        ensure!(
            !self.compatibility.helper_version.is_empty()
                && self.compatibility.helper_version.len() <= 128
                && self
                    .compatibility
                    .helper_version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b)),
            "invalid helper version declaration"
        );
        let limits = artifact_limits(lightwallet);
        ensure!(
            self.artifacts.len() == limits.len(),
            "incorrect artifact inventory"
        );
        for (name, limit) in limits {
            let artifact = self
                .artifacts
                .get(&name)
                .context("missing fixed artifact")?;
            ensure!(
                lower_hex(&artifact.sha256, 64),
                "invalid artifact hash: {name}"
            );
            ensure!(
                (1..=limit).contains(&artifact.bytes),
                "invalid artifact size: {name}"
            );
        }
        let components = if lightwallet {
            vec!["chain", "node", "helper", "lightwallet"]
        } else {
            vec!["chain", "node", "helper"]
        };
        ensure!(
            self.provenance.len() == components.len(),
            "incorrect provenance inventory"
        );
        for component in components {
            let p = self
                .provenance
                .get(component)
                .context("missing component provenance")?;
            ensure!(
                lower_hex(&p.revision, 40) || lower_hex(&p.revision, 64),
                "provenance requires a full lowercase Git revision"
            );
            ensure!(
                !p.license.trim().is_empty()
                    && p.license.len() <= 1024
                    && !p.license.chars().any(char::is_control),
                "invalid license declaration"
            );
            validate_source_url(&p.source_url)?;
        }
        let revision = match &self.node_image.provenance {
            crate::image::ImageProvenance::Source { revision, .. }
            | crate::image::ImageProvenance::Release { revision, .. } => revision,
        };
        ensure!(
            self.provenance["node"].revision == *revision,
            "node provenance revision mismatch"
        );
        if let Some(image) = &self.lightwallet_image {
            ensure!(
                self.provenance["lightwallet"].revision == image.source_revision,
                "lightwallet provenance revision mismatch"
            );
        }
        Ok(())
    }

    /// Gate new package resolution and execution, not receipt inspection/cleanup.
    pub fn require_compatible(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.compatibility.helper_version == env!("CARGO_PKG_VERSION"),
            "unsupported artifact compatibility contract: helper version differs from this CLI"
        );
        Ok(())
    }

    /// Offline consistency checks only; never executes the helper or images.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "artifact_set.verify")
    )]
    pub fn verify(&self, directory: &Path) -> Result<()> {
        self.require_compatible()?;
        let mut data = BTreeMap::new();
        for (name, limit) in artifact_limits(self.lightwallet_image.is_some()) {
            let path = directory.join(&name);
            let declared = &self.artifacts[&name];
            if name == "chain.tar" || name == "zdn" {
                ensure!(
                    crate::devnet::hash_file(&path, limit)? == *declared,
                    "artifact bytes differ: {name}"
                );
                continue;
            }
            let bytes = crate::devnet::read_bounded(&path, limit)?;
            ensure!(
                bytes.len() as u64 == declared.bytes && hash(&bytes) == declared.sha256,
                "artifact bytes differ: {name}"
            );
            data.insert(name, bytes);
        }
        let record = ImageRecord::from_json(&data["image.json"])?;
        ensure!(record == self.node_image, "node image record mismatch");
        let proof = crate::image::validate_manifest_bytes(&record, &data["image-manifest.json"])?;
        crate::image::validate_config_bytes(&record, &proof, &data["image-config.json"])?;
        if let Some(expected) = &self.lightwallet_image {
            let record =
                crate::lightwallet_image::ImageRecord::from_json(&data["lightwallet-image.json"])?;
            ensure!(record == *expected, "lightwallet image record mismatch");
            crate::lightwallet_image::validate_artifacts(
                &record,
                &data["lightwallet-image-manifest.json"],
                &data["lightwallet-image-config.json"],
                None,
            )?;
        }
        let manifest: crate::chain::manifest::ConsensusManifest =
            serde_json::from_slice(&data["manifest.json"])?;
        ensure!(
            manifest.fingerprint()? == self.consensus_fingerprint,
            "chain consensus fingerprint mismatch"
        );
        crate::chain::artifacts::verify_bundle(&manifest, &directory.join("chain.tar"))?;
        crate::devnet::validate_helper_file(&directory.join("zdn"))?;
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "artifact_set.validate_source_url")
)]
fn validate_source_url(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 4096
            && !value
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\\'),
        "invalid source URL"
    );
    let rest = value
        .strip_prefix("https://")
        .context("source URL must use HTTPS")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    ensure!(
        !authority.is_empty() && !authority.contains('@'),
        "source URL must have a host and no credentials"
    );
    // Parsing a request URL is local only: no request is sent.
    let parsed = ureq::get(value)
        .request_url()
        .context("invalid source URL")?;
    let url = parsed.as_url();
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "source URL must use HTTPS without credentials"
    );
    Ok(())
}
