//! Source-to-image build contract. Declarations never qualify a running node.

use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

use crate::{
    config::Build,
    image::{ImageBuildRequirements, ImageCapabilities, ImageProvenance, ImageRecord},
    source::SnapshotReceipt,
};

pub mod preparation;

pub const API_VERSION: &str = "zdn-build/v1alpha1";
pub const FEATURE_API_VERSION: &str = "zdn-build/v1alpha2";
pub const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRecipe {
    pub dockerfile: String,
    pub context: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cargo_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildContract {
    pub api_version: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub revision: String,
    pub recipe: BuildRecipe,
    pub platform: String,
    pub required_capabilities: ImageCapabilities,
}

impl BuildContract {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.contract.new")
    )]
    pub fn new(receipt: &SnapshotReceipt, build: &Build) -> Result<Self> {
        ensure!(receipt.schema_version == 1, "unsupported snapshot receipt");
        ensure!(
            build.executor == "aws-codebuild" && build.recipe == "repository",
            "unsupported build executor or recipe"
        );
        let recipe = BuildRecipe {
            dockerfile: build
                .dockerfile
                .to_str()
                .context("non-UTF-8 Dockerfile")?
                .into(),
            context: build
                .context
                .to_str()
                .context("non-UTF-8 build context")?
                .into(),
            target: build.target.clone(),
            cargo_features: build.cargo_features.clone(),
        };
        let required_capabilities = if recipe.cargo_features.is_empty() {
            ImageCapabilities::default()
        } else {
            ImageCapabilities::for_requirements(ImageBuildRequirements::new(
                &recipe.cargo_features,
                &[],
            )?)?
        };
        let value = Self {
            api_version: if recipe.cargo_features.is_empty() {
                API_VERSION
            } else {
                FEATURE_API_VERSION
            }
            .into(),
            source_sha256: receipt.archive_sha256.clone(),
            source_bytes: receipt.archive_bytes,
            revision: receipt.head.clone(),
            recipe,
            platform: build.platform.clone(),
            required_capabilities,
        };
        value.validate()?;
        Ok(value)
    }

    /// Bind a core-validated compiled contract before build preparation or reuse.
    /// A nonempty explicit config feature selection must agree, never be silently
    /// replaced. Source bytes, revision, platform and repository paths are kept.
    pub fn require_external(&mut self, requirements: &ImageBuildRequirements) -> Result<()> {
        self.validate()?;
        requirements.validate()?;
        ensure!(
            self.recipe.cargo_features.is_empty()
                || self.recipe.cargo_features == requirements.cargo_features,
            "configured features differ from compiled requirements"
        );
        let mut value = self.clone();
        value.api_version = FEATURE_API_VERSION.into();
        value.recipe.cargo_features = requirements.cargo_features.clone();
        value.required_capabilities = ImageCapabilities::for_requirements(requirements.clone())?;
        value.validate()?;
        *self = value;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.contract.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version
                == if self.required_capabilities.build_requirements.is_some() {
                    FEATURE_API_VERSION
                } else {
                    API_VERSION
                },
            "unsupported build contract"
        );
        ensure!(hex_string(&self.source_sha256, 64), "invalid source hash");
        ensure!(
            (1..=MAX_SOURCE_BYTES).contains(&self.source_bytes),
            "invalid source archive size"
        );
        ensure!(
            hex_string(&self.revision, 40) || hex_string(&self.revision, 64),
            "build requires a full Git revision"
        );
        ensure!(
            self.platform == "linux/amd64",
            "build requires native linux/amd64"
        );
        self.required_capabilities.validate()?;
        crate::image::validate_cargo_features(&self.recipe.cargo_features)?;
        match &self.required_capabilities.build_requirements {
            Some(requirements) => ensure!(
                requirements.cargo_features == self.recipe.cargo_features,
                "recipe features differ from required image features"
            ),
            None => ensure!(
                self.recipe.cargo_features.is_empty(),
                "unbound recipe features"
            ),
        }
        ensure!(self.recipe.target == "runtime", "unsupported build target");
        for path in [&self.recipe.dockerfile, &self.recipe.context] {
            ensure!(
                !path.is_empty()
                    && path.len() <= 256
                    && !path.starts_with('/')
                    && path.split('/').all(|part| part == "."
                        || (!part.is_empty()
                            && part != ".."
                            && part
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))),
                "build paths must be safe captured-relative paths"
            );
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    /// Check the actual tar, not just its receipt, before any AWS write. Capture
    /// already enforces safe links; reject links here as Dockerfile/context roots.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.contract.verify_archive")
    )]
    pub fn verify_archive(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == self.source_bytes,
            "source archive size changed"
        );
        let mut hash = Sha256::new();
        std::io::copy(&mut file.take(MAX_SOURCE_BYTES + 1), &mut hash)?;
        ensure!(
            hex::encode(hash.finalize()) == self.source_sha256,
            "source archive hash changed"
        );
        let mut archive = tar::Archive::new(std::fs::File::open(path)?);
        let mut dockerfile = false;
        let mut context = self.recipe.context == ".";
        let mut names = std::collections::BTreeSet::new();
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?.into_owned();
            ensure!(
                path.components().all(|p| matches!(
                    p,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )),
                "unsafe source archive path"
            );
            ensure!(names.insert(path.clone()), "duplicate source archive path");
            let kind = entry.header().entry_type();
            ensure!(
                kind.is_file() || kind.is_dir() || kind.is_symlink(),
                "unsupported source archive entry"
            );
            if kind.is_symlink() {
                let target = entry
                    .link_name()?
                    .context("source symlink target missing")?;
                let mut depth = path.parent().map_or(0, |p| p.components().count());
                for component in target.components() {
                    match component {
                        std::path::Component::Normal(_) => depth += 1,
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir if depth > 0 => depth -= 1,
                        _ => eyre::bail!("source symlink escapes archive"),
                    }
                }
            }
            if path == Path::new(&self.recipe.dockerfile) {
                ensure!(kind.is_file(), "Dockerfile must be a captured regular file");
                dockerfile = true;
            }
            if path == Path::new(&self.recipe.context) {
                ensure!(kind.is_dir(), "build context must be a directory");
                context = true;
            } else if path.starts_with(&self.recipe.context) {
                context = true;
            }
        }
        ensure!(
            dockerfile && context,
            "Dockerfile or context missing from captured source"
        );
        // Symlink ancestors could redirect a later extraction outside its root.
        // The source capturer forbids these; enforce that for imported archives too.
        let mut archive = tar::Archive::new(std::fs::File::open(path)?);
        for entry in archive.entries()? {
            let entry = entry?;
            if entry.header().entry_type().is_symlink() {
                let link = entry.path()?;
                ensure!(
                    names
                        .range::<Path, _>((
                            std::ops::Bound::Excluded(link.as_ref()),
                            std::ops::Bound::Unbounded,
                        ))
                        .next()
                        .is_none_or(|p| !p.starts_with(link.as_ref())),
                    "source archive contains a symlink ancestor"
                );
                ensure!(
                    !Path::new(&self.recipe.context).starts_with(link.as_ref())
                        && !Path::new(&self.recipe.dockerfile).starts_with(link.as_ref()),
                    "recipe traverses a source symlink"
                );
            }
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.contract.validate_image")
    )]
    pub fn validate_image(&self, image: &ImageRecord) -> Result<()> {
        self.validate()?;
        match &self.required_capabilities.build_requirements {
            Some(requirements) => requirements.validate_image(image)?,
            None => image.validate()?,
        }
        ensure!(
            image.provenance
                == ImageProvenance::Source {
                    revision: self.revision.clone(),
                    snapshot_sha256: self.source_sha256.clone()
                },
            "build result source differs from contract"
        );
        ensure!(
            image.platform == self.platform && image.capabilities == self.required_capabilities,
            "build result capabilities or architecture differ"
        );
        Ok(())
    }

    pub fn validate_manifest_bytes(
        &self,
        image: &ImageRecord,
        bytes: &[u8],
    ) -> Result<crate::image::VerifiedManifest> {
        self.validate_image(image)?;
        match &self.required_capabilities.build_requirements {
            Some(requirements) => {
                crate::image::validate_manifest_bytes_for_requirements(image, requirements, bytes)
            }
            None => crate::image::validate_manifest_bytes(image, bytes),
        }
    }

    pub fn validate_config_bytes(
        &self,
        image: &ImageRecord,
        verified: &crate::image::VerifiedManifest,
        bytes: &[u8],
    ) -> Result<()> {
        self.validate_image(image)?;
        match &self.required_capabilities.build_requirements {
            Some(requirements) => crate::image::validate_config_bytes_for_requirements(
                image,
                requirements,
                verified,
                bytes,
            ),
            None => crate::image::validate_config_bytes(image, verified, bytes),
        }
    }
}

fn hex_string(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
