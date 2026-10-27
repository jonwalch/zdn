//! Versioned user configuration. Validation never invokes external tools.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const API_VERSION: &str = "zdn/v1alpha1";
pub const UPGRADES: &[&str] = &[
    "Overwinter",
    "Sapling",
    "Blossom",
    "Heartwood",
    "Canopy",
    "NU5",
    "NU6",
    "NU6.1",
    "NU6.2",
    "NU6.3",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub api_version: String,
    pub name: String,
    pub profile: String,
    #[serde(default)]
    pub deployment: Deployment,
    pub node: Node,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub services: Services,
    #[serde(default)]
    pub access: Access,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Deployment {
    pub provider: String,
    pub placement: String,
}
impl Default for Deployment {
    fn default() -> Self {
        Self {
            provider: "aws".into(),
            placement: "one-node-per-vm".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Node {
    pub adapter: String,
    #[serde(default)]
    pub resources: Resources,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Build>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Size {
    Small,
    #[default]
    Medium,
    Large,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default)]
    pub preset: Size,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Allocation {
    pub instance: &'static str,
    pub vcpus: u32,
    pub host_gib: u32,
    pub host_reserve_gib: u32,
    pub max_node_gib: u32,
    pub chain_disk_gib: u32,
    pub root_disk_gib: u32,
    pub qualified: bool,
}
impl Size {
    pub fn allocation(self) -> Allocation {
        let (instance, vcpus, host_gib, host_reserve_gib, chain_disk_gib) = match self {
            Self::Small => ("m7a.large", 2, 8, 2, 40),
            Self::Medium => ("m7a.xlarge", 4, 16, 2, 80),
            Self::Large => ("m7a.2xlarge", 8, 32, 4, 160),
        };
        Allocation {
            instance,
            vcpus,
            host_gib,
            host_reserve_gib,
            max_node_gib: host_gib - host_reserve_gib,
            chain_disk_gib,
            root_disk_gib: 32,
            qualified: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotMode {
    Worktree,
    Revision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Build {
    pub executor: String,
    pub platform: String,
    pub recipe: String,
    pub dockerfile: PathBuf,
    pub context: PathBuf,
    pub target: String,
}
impl Default for Build {
    fn default() -> Self {
        Self {
            executor: "aws-codebuild".into(),
            platform: "linux/amd64".into(),
            recipe: "repository".into(),
            dockerfile: "docker/Dockerfile".into(),
            context: ".".into(),
            target: "runtime".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Network {
    pub kind: String,
    pub preset: String,
    pub nodes: u16,
    #[serde(deserialize_with = "unique_heights")]
    pub activation_heights: BTreeMap<String, u32>,
    pub mining: Mining,
}
impl Default for Network {
    fn default() -> Self {
        Self {
            kind: "custom-testnet".into(),
            preset: "custom-dev-v1".into(),
            nodes: 3,
            activation_heights: [("NU6.3".into(), 1)].into(),
            mining: Mining::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Mining {
    pub mode: String,
    pub producer: String,
    pub interval: String,
    pub proof_of_work: String,
}
impl Default for Mining {
    fn default() -> Self {
        Self {
            mode: "scheduled".into(),
            producer: "node-1".into(),
            interval: "25s".into(),
            proof_of_work: "disabled".into(),
        }
    }
}
impl Mining {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.mining.interval_seconds")
    )]
    pub fn interval_seconds(&self) -> Result<u64> {
        let n = self
            .interval
            .strip_suffix('s')
            .context("mining.interval must be a whole number of seconds, for example 25s")?
            .parse::<u64>()
            .context("invalid mining interval")?;
        ensure!(
            n > 0 && n <= 86_400,
            "mining.interval must be between 1s and 86400s"
        );
        Ok(n)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Services {
    pub wallet: bool,
    pub lightwallet: bool,
    pub faucet: bool,
}
impl Default for Services {
    fn default() -> Self {
        Self {
            wallet: true,
            lightwallet: true,
            faucet: true,
        }
    }
}

/// An explicit choice for newly generated configurations, never a read default.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum ServicePreset {
    /// Nodes only; all optional services disabled.
    #[default]
    NodeOnly,
    /// Nodes and lightwalletd; requires three separately pinned image inputs.
    Lightwallet,
    /// Future service design; wallet and faucet deployment is not implemented.
    Planned,
}

impl ServicePreset {
    pub fn services(self) -> Services {
        match self {
            Self::NodeOnly => Services {
                wallet: false,
                lightwallet: false,
                faucet: false,
            },
            Self::Lightwallet => Services {
                wallet: false,
                lightwallet: true,
                faucet: false,
            },
            Self::Planned => Services::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    #[default]
    Private,
    Public,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Access {
    pub visibility: Visibility,
}

impl Config {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.draft")
    )]
    pub fn draft(name: String, profile: String, source: Source, size: Size) -> Result<Self> {
        let build = source.path.as_ref().map(|_| Build::default());
        let value = Self {
            api_version: API_VERSION.into(),
            name,
            profile,
            deployment: Deployment::default(),
            node: Node {
                adapter: "zakura".into(),
                resources: Resources { preset: size },
                source,
                build,
            },
            network: Network::default(),
            services: Services::default(),
            access: Access::default(),
        };
        value.validate()?;
        Ok(value)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.load")
    )]
    pub fn load(path: &Path) -> Result<Self> {
        let metadata =
            fs::metadata(path).with_context(|| format!("read configuration {}", path.display()))?;
        ensure!(metadata.is_file(), "configuration must be a regular file");
        ensure!(metadata.len() <= 1_048_576, "configuration exceeds 1 MiB");
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "configuration exceeds 1 MiB");
        let value: Self = serde_yaml::from_slice(&bytes).context("invalid devnet configuration")?;
        value.validate()?;
        Ok(value)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.validate")
    )]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported apiVersion {}; expected {API_VERSION}",
            self.api_version
        );
        validate_label(&self.name, "name")?;
        validate_label(&self.profile, "profile")?;
        ensure!(
            self.deployment.provider == "aws" && self.deployment.placement == "one-node-per-vm",
            "only AWS with one-node-per-vm placement is supported"
        );
        ensure!(
            self.node.adapter == "zakura",
            "only the zakura adapter is supported"
        );
        let source = &self.node.source;
        let count = usize::from(source.path.is_some())
            + usize::from(source.release.is_some())
            + usize::from(source.image.is_some());
        ensure!(
            count == 1,
            "select exactly one node.source path, release, or image"
        );
        if let Some(path) = &source.path {
            ensure!(!path.as_os_str().is_empty(), "source path cannot be empty");
            match (source.snapshot, &source.revision) {
                (Some(SnapshotMode::Revision), Some(revision)) if !revision.trim().is_empty() && !revision.starts_with('-') => {},
                (None | Some(SnapshotMode::Worktree), None) => {},
                _ => bail!("revision snapshots require snapshot: revision and a revision; worktree snapshots must omit revision"),
            }
            let build = self
                .node
                .build
                .as_ref()
                .context("local source requires node.build settings")?;
            ensure!(
                build.executor == "aws-codebuild" && build.platform == "linux/amd64",
                "builds require native Linux x86-64 AWS CodeBuild"
            );
            ensure!(
                build.recipe == "repository" && build.target == "runtime",
                "use the repository build recipe and runtime target"
            );
            ensure!(
                !build.dockerfile.as_os_str().is_empty() && !build.context.as_os_str().is_empty(),
                "Dockerfile and build context cannot be empty"
            );
            for path in [&build.dockerfile, &build.context] {
                ensure!(
                    path.components()
                        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
                    "Dockerfile and build context must stay relative to the captured source"
                );
            }
        } else {
            ensure!(
                source.snapshot.is_none() && source.revision.is_none() && self.node.build.is_none(),
                "release/image sources must omit snapshot, revision, and build settings"
            );
        }
        if let Some(release) = &source.release {
            validate_release_id(release)?;
        }
        if let Some(image) = &source.image {
            let (registry, digest) = image
                .rsplit_once("@sha256:")
                .context("image must contain an immutable @sha256: digest")?;
            ensure!(
                !registry.is_empty()
                    && !registry.chars().any(char::is_whitespace)
                    && digest.len() == 64
                    && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid image digest"
            );
        }
        ensure!(
            self.network.kind == "custom-testnet" && self.network.preset == "custom-dev-v1",
            "only the custom-testnet custom-dev-v1 draft preset is supported"
        );
        ensure!(self.network.nodes > 0, "network.nodes must be positive");
        self.resolved_upgrades()?;
        ensure!(
            self.network.mining.mode == "scheduled"
                && self.network.mining.proof_of_work == "disabled",
            "the draft devnet requires scheduled generation with proof-of-work disabled"
        );
        let producer = self
            .network
            .mining
            .producer
            .strip_prefix("node-")
            .context("producer must be node-N")?
            .parse::<u16>()
            .context("invalid producer node")?;
        ensure!(
            producer > 0 && producer <= self.network.nodes,
            "producer is outside the configured node set"
        );
        self.network.mining.interval_seconds()?;
        ensure!(
            !self.services.faucet || self.services.wallet,
            "the private funding service requires the wallet backend"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.resolved_upgrades")
    )]
    pub fn resolved_upgrades(&self) -> Result<BTreeMap<String, u32>> {
        for (upgrade, height) in &self.network.activation_heights {
            ensure!(
                UPGRADES.contains(&upgrade.as_str()),
                "unsupported upgrade {upgrade}"
            );
            ensure!(*height > 0, "upgrade {upgrade} must activate after genesis");
        }
        ensure!(
            self.network.activation_heights.contains_key("NU6.3"),
            "the Ironwood preset requires an explicit NU6.3 activation height"
        );
        let mut previous = 1;
        let mut resolved = BTreeMap::new();
        for upgrade in UPGRADES {
            let height = self
                .network
                .activation_heights
                .get(*upgrade)
                .copied()
                .unwrap_or(previous);
            ensure!(
                height >= previous,
                "upgrade {upgrade} cannot activate before its predecessor"
            );
            resolved.insert((*upgrade).to_owned(), height);
            previous = height;
        }
        Ok(resolved)
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.source_root")
    )]
    pub fn source_root(&self, config_path: &Path) -> Result<Option<PathBuf>> {
        self.node
            .source
            .path
            .as_ref()
            .map(|source| {
                let parent = fs::canonicalize(config_path)?
                    .parent()
                    .context("config has no parent")?
                    .to_owned();
                fs::canonicalize(parent.join(source))
                    .with_context(|| format!("resolve source {}", source.display()))
            })
            .transpose()
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "config.write_new")
    )]
    pub fn write_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(serde_yaml::to_string(self)?.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist_noclobber(path)
            .map_err(|e| e.error)
            .with_context(|| {
                format!(
                    "create {}; existing configurations are never overwritten",
                    path.display()
                )
            })?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

/// Shared exact-release policy for configuration and signed catalogs. Candidate
/// identifiers are permitted; their spelling does not establish qualification.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "config.validate_release_id")
)]
pub(crate) fn validate_release_id(release: &str) -> Result<()> {
    ensure!(
        !release.is_empty()
            && release.len() <= 128
            && release
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)),
        "release must be an exact version identifier"
    );
    ensure!(
        !["latest", "main", "master", "stable", "nightly"].contains(&release),
        "a moving release name is not an immutable version"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "config.validate_label")
)]
fn validate_label(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 80
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)),
        "{field} must contain 1-80 letters, digits, hyphens, or underscores"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "config.unique_heights")
)]
fn unique_heights<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, u32>, D::Error> {
    struct Heights;
    impl<'de> serde::de::Visitor<'de> for Heights {
        type Value = BTreeMap<String, u32>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with one height per upgrade")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut entries: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut heights = BTreeMap::new();
            while let Some((name, height)) = entries.next_entry::<String, u32>()? {
                if heights.insert(name.clone(), height).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate upgrade {name}"
                    )));
                }
            }
            Ok(heights)
        }
    }
    deserializer.deserialize_map(Heights)
}
