//! Source-to-image build contract. Declarations never qualify a running node.

use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

use crate::{
    config::Build,
    image::{ImageCapabilities, ImageProvenance, ImageRecord},
    source::SnapshotReceipt,
};

pub mod preparation;

pub const API_VERSION: &str = "zdn-build/v1alpha1";
pub const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRecipe {
    pub dockerfile: String,
    pub context: String,
    pub target: String,
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
        };
        let value = Self {
            api_version: API_VERSION.into(),
            source_sha256: receipt.archive_sha256.clone(),
            source_bytes: receipt.archive_bytes,
            revision: receipt.head.clone(),
            recipe,
            platform: build.platform.clone(),
            required_capabilities: ImageCapabilities::default(),
        };
        value.validate()?;
        Ok(value)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "build.contract.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
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
        ensure!(
            self.required_capabilities == ImageCapabilities::default(),
            "unsupported required build capabilities"
        );
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
        image.validate()?;
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
}

fn hex_string(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
