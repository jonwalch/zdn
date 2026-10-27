//! Offline signed release selection. Trust is supplied by the caller, never by
//! the catalog. Signatures authenticate declarations, not wallet qualification,
//! reproducibility, freshness, or the safety of executing an artifact.
use crate::{
    artifact_set::MAX_MANIFEST_BYTES,
    config::validate_release_id,
    dependencies::{Downloader, HttpDownloader},
    package::{self, Location, ResolvedPackage},
};
use eyre::{ensure, Context, ContextCompat, Result};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const API_VERSION: &str = "zdn-release-catalog/v1alpha1";
pub const MAX_CATALOG_BYTES: u64 = MAX_MANIFEST_BYTES;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalog {
    pub api_version: String,
    /// Exact identifiers using the configuration release policy, including
    /// candidates/prereleases; never automatically selects a channel or alias.
    #[serde(deserialize_with = "unique_releases")]
    pub releases: BTreeMap<String, PinnedPackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedPackage {
    pub location: Location,
    /// Lowercase SHA-256 of the raw deployment-package JSON bytes.
    pub sha256: String,
}

impl Catalog {
    /// Parse for local preparation/inspection only; this does not establish trust.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "releases.catalog.from_json")
    )]
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_CATALOG_BYTES,
            "release catalog is too large"
        );
        let catalog: Self = serde_json::from_slice(bytes).context("decode release catalog")?;
        catalog.validate()?;
        Ok(catalog)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "releases.catalog.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported release catalog API version"
        );
        ensure!(!self.releases.is_empty(), "release catalog is empty");
        for (id, package) in &self.releases {
            validate_release_id(id)?;
            crate::devnet::validate_hash(&package.sha256).context("invalid release package pin")?;
            package.location.validate(false)?;
        }
        Ok(())
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "releases.unique_releases")
)]
fn unique_releases<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, PinnedPackage>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, PinnedPackage>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of unique release identifiers")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut releases = BTreeMap::new();
            while let Some((id, package)) = map.next_entry::<String, PinnedPackage>()? {
                if releases.insert(id, package).is_some() {
                    return Err(serde::de::Error::custom("duplicate release identifier"));
                }
            }
            Ok(releases)
        }
    }
    deserializer.deserialize_map(Unique)
}

/// Sign the supplied raw bytes, without JSON reserialization or canonicalization.
/// Keys are managed by the caller; this library never generates, stores, or
/// publishes signing material. Invalid/oversized catalogs cannot be signed here.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "releases.sign")
)]
pub fn sign(bytes: &[u8], key: &Ed25519KeyPair) -> Result<[u8; 64]> {
    Catalog::from_json(bytes)?;
    Ok(key
        .sign(bytes)
        .as_ref()
        .try_into()
        .expect("Ed25519 signature length"))
}

/// A verified catalog is immutable. It can only be constructed by authenticating
/// bounded raw bytes with at least one explicitly trusted raw Ed25519 public key.
#[derive(Debug)]
pub struct VerifiedCatalog {
    catalog: Catalog,
    sha256: String,
    signer: [u8; 32],
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "releases.verify")
)]
pub fn verify(
    bytes: &[u8],
    signature: &[u8],
    trusted_keys: &[[u8; 32]],
) -> Result<VerifiedCatalog> {
    ensure!(
        bytes.len() as u64 <= MAX_CATALOG_BYTES,
        "release catalog is too large"
    );
    ensure!(
        signature.len() == 64,
        "detached Ed25519 signature must be 64 raw bytes"
    );
    ensure!(
        !trusted_keys.is_empty(),
        "no trusted release public keys supplied"
    );
    let signer = trusted_keys
        .iter()
        .find(|key| {
            UnparsedPublicKey::new(&ED25519, key.as_slice())
                .verify(bytes, signature)
                .is_ok()
        })
        .context("release catalog signature did not match a trusted key")?;
    // No JSON interpretation or package resolution precedes authentication.
    Ok(VerifiedCatalog {
        catalog: Catalog::from_json(bytes)?,
        sha256: hex::encode(Sha256::digest(bytes)),
        signer: *signer,
    })
}

impl VerifiedCatalog {
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }

    /// base is the caller-supplied catalog directory for relative file locations.
    /// HTTPS packages resolve through the same bounded transport, raw pins and
    /// semantic verifier as ordinary deployment packages. No executable is run.
    pub fn resolve(
        &self,
        release: &str,
        base: &Path,
        overrides: &BTreeMap<String, PathBuf>,
    ) -> Result<ResolvedPackage> {
        self.resolve_with_downloader(release, base, overrides, &HttpDownloader::default())
    }

    /// Transport injection for offline fixtures. Catalog URLs still require
    /// HTTPS; unlike package tests, catalogs do not admit loopback HTTP entries.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "releases.verified_catalog.resolve_with_downloader")
    )]
    pub fn resolve_with_downloader(
        &self,
        release: &str,
        base: &Path,
        overrides: &BTreeMap<String, PathBuf>,
        downloader: &impl Downloader,
    ) -> Result<ResolvedPackage> {
        validate_release_id(release)?;
        let entry = self
            .catalog
            .releases
            .get(release)
            .context("release identifier is not in catalog")?;
        package::resolve_location(&entry.location, &entry.sha256, base, overrides, downloader)
    }
}
