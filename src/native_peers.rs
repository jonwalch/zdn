//! Public native identity inventory, not a host-key store or lifecycle journal.
//!
//! The caller invokes `zakurad --config CONFIG native-identity --identity-dir ABS`
//! without starting services, then supplies only its bounded machine stdout.
//! Keep this directory in existing deployment storage, separate from host keys.
//! Persist returned snapshot pins in the existing lifecycle evidence before use;
//! pass those pins to `read_pinned` on restart/recovery. No logs or key paths are
//! accepted here. A lost inventory is not permission to regenerate host keys.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddrV4,
    path::{Path, PathBuf},
};

use eyre::{ensure, Context, ContextCompat, Result};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cluster_infra::{validate_node_outputs, ClusterNodeOutputs, ClusterTopology, NativeListener},
    devnet::read_bounded,
    foundation,
    public_chain_adapter::contract::{parse, strict_value, Peer, Pin, RenderOptions},
};

pub const IDENTITY_SCHEMA: &str = "zakura-native-identity/v1";
pub const INVENTORY_SCHEMA: &str = "zdn-native-public-peers/v1";
pub const MAX_IDENTITY_BYTES: usize = 1024;
const MAX_INVENTORY_BYTES: u64 = 16 * 1024;

/// Only the native command's public machine response is accepted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeIdentity {
    pub schema: String,
    pub node_id: String,
    pub chain_fingerprint: Option<String>,
}

impl NativeIdentity {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_IDENTITY_BYTES,
            "native identity exceeds bound"
        );
        let value = strict_value(bytes).map_err(|_| eyre::eyre!("invalid native identity JSON"))?;
        ensure!(
            value.as_object().is_some_and(|object| object.len() == 3)
                && value.get("chainFingerprint").is_some(),
            "native identity requires exactly the public schema fields"
        );
        let identity: Self = serde_json::from_value(value)
            .map_err(|_| eyre::eyre!("invalid native identity schema"))?;
        ensure!(
            identity.schema == IDENTITY_SCHEMA,
            "unsupported native identity schema"
        );
        hash(&identity.node_id)?;
        if let Some(fingerprint) = &identity.chain_fingerprint {
            hash(fingerprint)?;
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CohortMember {
    pub node_id: String,
    pub host_key: String,
    pub instance_id: String,
    pub endpoint: SocketAddrV4,
}

/// Construct from authenticated deployment outputs, not native command output.
/// All fields are public, but construction and deserialization remain validated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCohort {
    schema: String,
    deployment_id: Uuid,
    public_descriptor_sha256: String,
    native_fingerprint: String,
    members: Vec<CohortMember>,
}

impl NativeCohort {
    pub fn new(
        deployment_id: Uuid,
        public_descriptor_sha256: String,
        native_fingerprint: String,
        topology: &ClusterTopology,
        outputs: &BTreeMap<String, ClusterNodeOutputs>,
        listener: NativeListener,
    ) -> Result<Self> {
        ensure!(
            !deployment_id.is_nil(),
            "native deployment UUID must not be nil"
        );
        hash(&public_descriptor_sha256)?;
        hash(&native_fingerprint)?;
        validate_node_outputs(outputs, topology)?;
        NativeListener::new(listener.address(), topology)?;
        Ok(Self {
            schema: INVENTORY_SCHEMA.into(),
            deployment_id,
            public_descriptor_sha256,
            native_fingerprint,
            members: topology
                .nodes()
                .into_iter()
                .map(|node| CohortMember {
                    instance_id: outputs[&node.node_id].instance_id.clone(),
                    endpoint: SocketAddrV4::new(node.private_ip, listener.port()),
                    node_id: node.node_id,
                    host_key: node.host_key,
                })
                .collect(),
        })
    }

    pub fn members(&self) -> &[CohortMember] {
        &self.members
    }

    pub fn pin(&self) -> Result<Pin> {
        Ok(Pin::of(&serde_json::to_vec(self)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    cohort_sha256: String,
    member: CohortMember,
    identity: NativeIdentity,
}

/// Partial inventories are observable but cannot produce runtime peers.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeInventory {
    cohort: NativeCohort,
    entries: BTreeMap<String, Entry>,
}

impl NativeInventory {
    /// A same-deployment inventory from a different public chain must never
    /// provide peers or managed startup identities to this compile result.
    pub fn require_chain(&self, descriptor_sha256: &str, native_fingerprint: &str) -> Result<()> {
        ensure!(
            self.cohort.public_descriptor_sha256 == descriptor_sha256
                && self.cohort.native_fingerprint == native_fingerprint,
            "native inventory belongs to a different public chain"
        );
        Ok(())
    }

    pub fn completed_count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_complete(&self) -> bool {
        self.entries.len() == self.cohort.members.len()
    }

    /// Pin canonical public inventory bytes in the caller's existing evidence.
    pub fn pin(&self) -> Result<Pin> {
        Ok(Pin::of(&serde_json::to_vec(self)?))
    }

    pub fn expected_node_id(&self, node: &str) -> Result<&str> {
        Ok(&self
            .entries
            .get(node)
            .context("native identity is not provisioned")?
            .identity
            .node_id)
    }

    /// Exact completed topology, excluding self, in stable topology order.
    pub fn peers(&self, node: &str) -> Result<Vec<Peer>> {
        ensure!(
            self.is_complete(),
            "native cohort identity provisioning is incomplete"
        );
        self.expected_node_id(node)?;
        Ok(self
            .cohort
            .members
            .iter()
            .filter(|member| member.node_id != node)
            .map(|member| Peer {
                node_id: self.entries[&member.node_id].identity.node_id.clone(),
                endpoint: member.endpoint.to_string(),
            })
            .collect())
    }

    /// Populate only native identity/peer slots; preserve every other option.
    /// Refuse foreign deployment/member/listener options before modifying them.
    pub fn bind_render_options(&self, options: &mut RenderOptions) -> Result<()> {
        ensure!(
            options.deployment_id == self.cohort.deployment_id.to_string(),
            "foreign native render deployment"
        );
        let member = self
            .cohort
            .members
            .iter()
            .find(|member| member.node_id == options.node_id)
            .context("foreign native render node")?;
        let listener = NativeListener::new(
            options.native_listen.parse()?,
            &ClusterTopology::new(self.cohort.members.len() as u8)?,
        )?;
        ensure!(
            listener.port() == member.endpoint.port()
                && (listener.address().ip().is_unspecified()
                    || listener.address().ip() == std::net::IpAddr::V4(*member.endpoint.ip())),
            "native render listener differs from inventory"
        );
        let mut candidate = options.clone();
        candidate.expected_node_id = self.expected_node_id(&options.node_id)?.into();
        candidate.peers = self.peers(&options.node_id)?;
        candidate
            .validate()
            .map_err(|_| eyre::eyre!("invalid native render options"))?;
        *options = candidate;
        Ok(())
    }
}

/// Immutable binding plus one create-only public entry per cohort member.
/// This is inventory storage only: it neither starts nor journals operations.
pub struct NativeInventoryStore {
    directory: PathBuf,
    cohort: NativeCohort,
}

impl NativeInventoryStore {
    /// Create/reuse an exact binding in a dedicated deployment-owned directory.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "native_inventory.open")
    )]
    pub fn open(directory: &Path, cohort: NativeCohort) -> Result<Self> {
        // Validate even a deserialized cohort before any writes.
        cohort.validate()?;
        foundation::private_directory(directory)?;
        let store = Self {
            directory: directory.into(),
            cohort,
        };
        let _lock = store.lock()?;
        publish(&store.directory.join("cohort.json"), &store.cohort)?;
        store.load()?;
        Ok(store)
    }

    /// Recovery never creates a missing binding or adopts a different cohort.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "native_inventory.open_existing")
    )]
    pub fn open_existing(directory: &Path, cohort: NativeCohort) -> Result<Self> {
        cohort.validate()?;
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "native inventory directory is missing or unsafe"
        );
        let store = Self {
            directory: directory.into(),
            cohort,
        };
        let _lock = store.lock()?;
        store.load()?;
        Ok(store)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "native_inventory.read")
    )]
    pub fn read(&self) -> Result<NativeInventory> {
        let _lock = self.lock()?;
        self.load()
    }

    /// A known partial or complete snapshot cannot silently lose/change entries.
    pub fn read_pinned(&self, pin: &Pin) -> Result<NativeInventory> {
        let inventory = self.read()?;
        ensure!(inventory.pin()? == *pin, "native inventory pin differs");
        Ok(inventory)
    }

    /// Add exactly one public response. Matching retries never replace bytes.
    /// Re-read all entries under the same lock to prevent cross-node ID races.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "native_inventory.record")
    )]
    pub fn record(&self, node: &str, stdout: &[u8]) -> Result<NativeInventory> {
        let identity = NativeIdentity::from_json(stdout)?;
        let _lock = self.lock()?;
        let mut inventory = self.load()?;
        let member = self
            .cohort
            .members
            .iter()
            .find(|member| member.node_id == node)
            .context("foreign native cohort member")?;
        ensure!(
            identity.chain_fingerprint.as_deref() == Some(&self.cohort.native_fingerprint),
            "native identity chain fingerprint differs"
        );
        let entry = Entry {
            cohort_sha256: self.cohort.pin()?.sha256,
            member: member.clone(),
            identity,
        };
        if let Some(saved) = inventory.entries.get(node) {
            ensure!(*saved == entry, "existing native public identity changed");
        } else {
            ensure!(
                inventory
                    .entries
                    .values()
                    .all(|saved| saved.identity.node_id != entry.identity.node_id),
                "native public node ID is duplicated"
            );
        }
        publish(&self.directory.join(format!("{node}.json")), &entry)?;
        inventory.entries.insert(node.into(), entry);
        Ok(inventory)
    }

    fn load(&self) -> Result<NativeInventory> {
        let saved: NativeCohort = read(&self.directory.join("cohort.json"))?;
        ensure!(saved == self.cohort, "native cohort binding changed");
        let mut inventory = NativeInventory {
            cohort: self.cohort.clone(),
            entries: BTreeMap::new(),
        };
        let mut ids = BTreeSet::new();
        for member in &self.cohort.members {
            let path = self.directory.join(format!("{}.json", member.node_id));
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            let entry: Entry = read(&path)?;
            hash(&entry.identity.node_id)?;
            ensure!(
                entry.cohort_sha256 == self.cohort.pin()?.sha256
                    && entry.member == *member
                    && entry.identity.schema == IDENTITY_SCHEMA
                    && entry.identity.chain_fingerprint.as_deref()
                        == Some(&self.cohort.native_fingerprint)
                    && ids.insert(entry.identity.node_id.clone()),
                "native inventory entry differs from the public cohort"
            );
            inventory.entries.insert(member.node_id.clone(), entry);
        }
        // Foreign records must not be silently omitted from the completed set.
        for item in fs::read_dir(&self.directory)? {
            let name = item?.file_name();
            let name = name.to_str().context("invalid native inventory filename")?;
            ensure!(
                name == "inventory.lock"
                    || name == "cohort.json"
                    || name.starts_with(".pending-native-")
                    || self
                        .cohort
                        .members
                        .iter()
                        .any(|member| name == format!("{}.json", member.node_id)),
                "foreign native inventory file"
            );
        }
        Ok(inventory)
    }

    fn lock(&self) -> Result<InventoryLock> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        ensure!(metadata.is_dir(), "unsafe native inventory directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.mode() & 0o7777 == 0o700
                    && metadata.uid() == nix::unistd::geteuid().as_raw(),
                "unsafe native inventory directory"
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = options.open(self.directory.join("inventory.lock"))?;
        ensure!(
            file.metadata()?.is_file(),
            "native inventory lock must be regular"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                file.metadata()?.mode() & 0o7777 == 0o600
                    && file.metadata()?.nlink() == 1
                    && file.metadata()?.uid() == nix::unistd::geteuid().as_raw(),
                "unsafe native inventory lock"
            );
        }
        FileExt::try_lock_exclusive(&file).context("native inventory is busy")?;
        Ok(InventoryLock(file))
    }
}

impl NativeCohort {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == INVENTORY_SCHEMA && !self.deployment_id.is_nil(),
            "invalid native cohort binding"
        );
        hash(&self.public_descriptor_sha256)?;
        hash(&self.native_fingerprint)?;
        let count = u8::try_from(self.members.len())?;
        let topology = ClusterTopology::new(count)?;
        let mut hosts = BTreeSet::new();
        let port = self.members[0].endpoint.port();
        ensure!(port != 0, "native endpoint port must be nonzero");
        for (member, expected) in self.members.iter().zip(topology.nodes()) {
            let suffix = member
                .instance_id
                .strip_prefix("i-")
                .context("invalid native host identity")?;
            ensure!(
                [8, 17].contains(&suffix.len())
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid native host identity"
            );
            ensure!(
                member.node_id == expected.node_id
                    && member.host_key == expected.host_key
                    && *member.endpoint.ip() == expected.private_ip
                    && member.endpoint.port() == port
                    && hosts.insert(&member.instance_id),
                "native cohort topology differs"
            );
        }
        Ok(())
    }
}

struct InventoryLock(File);
impl Drop for InventoryLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn hash(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid public native hash or ID"
    );
    Ok(())
}

fn read<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    let bytes = public_bytes(path)?;
    let value: T =
        parse(&bytes).map_err(|_| eyre::eyre!("invalid native public inventory schema"))?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "native inventory encoding changed"
    );
    Ok(value)
}

fn public_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "native inventory must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.uid() == nix::unistd::geteuid().as_raw(),
            "unsafe native inventory file"
        );
    }
    read_bounded(path, MAX_INVENTORY_BYTES)
}

/// Same durable create-only tempfile publication as existing deployment snapshots.
/// Only canonical identical public bytes permit a retry, never an overwrite.
fn publish(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_INVENTORY_BYTES,
        "native public inventory exceeds bound"
    );
    let parent = path.parent().context("native inventory parent missing")?;
    let mut pending = tempfile::Builder::new()
        .prefix(".pending-native-")
        .tempfile_in(parent)?;
    pending.write_all(&bytes)?;
    pending.as_file().sync_all()?;
    match pending.persist_noclobber(path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                public_bytes(path)? == bytes,
                "saved native public inventory differs"
            );
        }
        Err(error) => return Err(error.error.into()),
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}
