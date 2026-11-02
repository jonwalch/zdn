//! Fixed public input/result contracts. No node, wallet or consensus dependency.
use super::{valid_hash, Failure, Result};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    path::{Component, Path},
};

pub const SCHEMA: &str = "zdn-external-public/v1";
pub const MAX_METADATA: usize = 2 * 1024 * 1024;
pub const MAX_BUNDLE: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pin {
    pub bytes: u64,
    pub sha256: String,
}
impl Pin {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }
    pub fn check(&self, bytes: &[u8]) -> Result<()> {
        if valid_hash(&self.sha256) && *self == Self::of(bytes) {
            Ok(())
        } else {
            Err(Failure::InvalidPublicInput)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub schema: String,
    pub native_name: String,
    pub native_fingerprint: String,
}

/// Strings are exact public file bytes, not arbitrary JSON extension objects.
/// The selected schema owns native rules; core authenticates each fixed slot.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompileInput {
    pub descriptor: Descriptor,
    pub native_rules_json: String,
    pub wallet_profile_json: String,
    pub seed_bundle: Pin,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeedBlock {
    pub height: u32,
    pub hash: String,
    pub pin: Pin,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Upgrade {
    pub name: String,
    pub branch_id: String,
    pub activation_height: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Compiled {
    pub schema: String,
    pub native_name: String,
    pub native_fingerprint: String,
    /// Exact complete diagnostic projection; only used for structural equality.
    pub expected_rules: Value,
    /// Full RPC upgrade list, including implicit upgrades sharing a height.
    /// At a shared height the final entry is the effective diagnostic upgrade.
    pub upgrades: Vec<Upgrade>,
    pub seed_blocks: Vec<SeedBlock>,
    pub cargo_features: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub transport_class: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Peer {
    pub node_id: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderOptions {
    pub deployment_id: String,
    pub node_id: String,
    pub role: String,
    pub image_digest: String,
    pub state_dir: String,
    pub identity_dir: String,
    pub cookie_dir: String,
    pub rpc_listen: String,
    pub native_listen: String,
    pub expected_node_id: String,
    pub peers: Vec<Peer>,
    pub reward_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderInput {
    pub public: CompileInput,
    pub compiled_sha256: String,
    pub options: RenderOptions,
    /// Key provisioning only, never permission to start an unmanaged node.
    #[serde(default, skip_serializing_if = "is_false")]
    pub identity_only: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rendered {
    pub config_toml: String,
}

impl CompileInput {
    pub fn validate(&self, bundle: &[u8]) -> Result<Vec<Pin>> {
        if self.descriptor.schema != SCHEMA
            || !valid_hash(&self.descriptor.native_fingerprint)
            || self.descriptor.native_name.is_empty()
            || self.descriptor.native_name.len() > 30
            || self.native_rules_json.len() > MAX_METADATA
            || self.wallet_profile_json.len() > MAX_METADATA
        {
            return Err(Failure::InvalidPublicInput);
        }
        self.seed_bundle.check(bundle)?;
        strict_value(self.native_rules_json.as_bytes())?;
        strict_value(self.wallet_profile_json.as_bytes())?;
        bundle_blocks(bundle).map(|blocks| blocks.into_iter().map(Pin::of).collect())
    }
}

/// Four-byte little-endian length followed by exact block bytes, no archive paths.
pub fn bundle_blocks(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    if bytes.len() > MAX_BUNDLE {
        return Err(Failure::InvalidPublicInput);
    }
    let mut blocks = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || blocks.len() == 256 {
            return Err(Failure::InvalidPublicInput);
        }
        let length = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| Failure::InvalidPublicInput)?,
        ) as usize;
        bytes = &bytes[4..];
        if length == 0 || length > 2_000_000 || length > bytes.len() {
            return Err(Failure::InvalidPublicInput);
        }
        blocks.push(&bytes[..length]);
        bytes = &bytes[length..];
    }
    if blocks.len() < 2 {
        return Err(Failure::InvalidPublicInput);
    }
    Ok(blocks)
}

impl Compiled {
    pub fn validate(&self, input: &CompileInput, block_pins: &[Pin]) -> Result<()> {
        // These are core's finite build/capability budgets, not a vocabulary
        // delegated to an executable or to image metadata.
        self.image_requirements()?;
        let mut names = BTreeSet::new();
        let mut branches = BTreeSet::new();
        if self.schema != SCHEMA
            || self.native_name != input.descriptor.native_name
            || self.native_fingerprint != input.descriptor.native_fingerprint
            || self.seed_blocks.len() != block_pins.len()
            || !(2..=256).contains(&self.seed_blocks.len())
            || !self.expected_rules.is_object()
            || self.upgrades.is_empty()
            || self.upgrades.len() > 32
            || self.upgrades[0].activation_height != 0
            || self
                .upgrades
                .windows(2)
                .any(|w| w[0].activation_height > w[1].activation_height)
            || self.upgrades.iter().any(|u| {
                u.name.is_empty()
                    || u.name.len() > 32
                    || !names.insert(&u.name)
                    || (u.branch_id != "00000000" && !branches.insert(&u.branch_id))
                    || u.branch_id.len() != 8
                    || !u
                        .branch_id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            || !tokens(&self.cargo_features)
            || !tokens(&self.required_capabilities)
            || self.transport_class != "large-hex-v1"
        {
            return Err(Failure::InvalidOutput);
        }
        for (height, (block, pin)) in self.seed_blocks.iter().zip(block_pins).enumerate() {
            if block.height as usize != height || !valid_hash(&block.hash) || block.pin != *pin {
                return Err(Failure::InvalidOutput);
            }
        }
        let checkpoints: Vec<_> = self
            .seed_blocks
            .iter()
            .map(|b| serde_json::json!({"height":b.height,"hash":b.hash}))
            .collect();
        let effective: BTreeMap<_, _> = self
            .upgrades
            .iter()
            .map(|u| (u.activation_height, &u.name))
            .collect();
        let activations: Vec<_> = effective
            .into_iter()
            .map(|(height, name)| serde_json::json!({"height":height,"upgrade":name}))
            .collect();
        if self.expected_rules["rules"]["checkpoints"] != Value::Array(checkpoints)
            || self.expected_rules["rules"]["activationHeights"] != Value::Array(activations)
            || self.expected_rules["rules"]["genesisHash"] != self.seed_blocks[0].hash
        {
            return Err(Failure::InvalidOutput);
        }
        Ok(())
    }

    pub fn image_requirements(&self) -> Result<crate::image::ImageBuildRequirements> {
        crate::image::ImageBuildRequirements::new(&self.cargo_features, &self.required_capabilities)
            .map_err(|_| Failure::InvalidOutput)
    }
}
fn tokens(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 32
        && values.windows(2).all(|v| v[0] < v[1])
        && values.iter().all(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

impl RenderOptions {
    pub fn validate(&self) -> Result<()> {
        self.validate_for_render(false)
    }

    pub(crate) fn validate_for_render(&self, identity_only: bool) -> Result<()> {
        let uuid =
            uuid::Uuid::parse_str(&self.deployment_id).map_err(|_| Failure::InvalidPublicInput)?;
        let rpc: SocketAddr = self
            .rpc_listen
            .parse()
            .map_err(|_| Failure::InvalidPublicInput)?;
        let listen: SocketAddr = self
            .native_listen
            .parse()
            .map_err(|_| Failure::InvalidPublicInput)?;
        if uuid.to_string() != self.deployment_id
            || self.node_id.is_empty()
            || self.node_id.len() > 64
            || !self
                .node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !matches!(self.role.as_str(), "producer" | "follower")
            || !self
                .image_digest
                .strip_prefix("sha256:")
                .is_some_and(valid_hash)
            || !rpc.ip().is_loopback()
            || rpc.port() == 0
            || listen.port() == 0
            || !match listen.ip() {
                std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_unspecified(),
                std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unspecified(),
            }
            || rpc == listen
            || if identity_only {
                !self.expected_node_id.is_empty()
                    || !self.peers.is_empty()
                    || self.role != "follower"
            } else {
                !valid_hash(&self.expected_node_id)
            }
            || self.peers.len() > 128
            || (self.role == "producer") != self.reward_address.is_some()
            || self
                .reward_address
                .as_ref()
                .is_some_and(|v| v.len() > 256 || !v.bytes().all(|b| b.is_ascii_alphanumeric()))
        {
            return Err(Failure::InvalidPublicInput);
        }
        let mut ids = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for peer in &self.peers {
            let endpoint: SocketAddr = peer
                .endpoint
                .parse()
                .map_err(|_| Failure::InvalidPublicInput)?;
            let private = match endpoint.ip() {
                std::net::IpAddr::V4(ip) => ip.is_private(),
                std::net::IpAddr::V6(ip) => ip.is_unique_local(),
            };
            if !valid_hash(&peer.node_id)
                || peer.node_id == self.expected_node_id
                || !private
                || endpoint.port() == 0
                || !ids.insert(&peer.node_id)
                || !endpoints.insert(endpoint)
            {
                return Err(Failure::InvalidPublicInput);
            }
        }
        for path in [&self.state_dir, &self.identity_dir, &self.cookie_dir] {
            if !Path::new(path).is_absolute()
                || !Path::new(path)
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                || path.len() > 1024
            {
                return Err(Failure::InvalidPublicInput);
            }
        }
        if self.state_dir == self.identity_dir
            || self.state_dir == self.cookie_dir
            || self.identity_dir == self.cookie_dir
        {
            return Err(Failure::InvalidPublicInput);
        }
        Ok(())
    }
}

/// Reject duplicates throughout the tree before serde can discard them.
pub fn strict_value(bytes: &[u8]) -> Result<Value> {
    struct Strict;
    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded integer JSON")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
            Ok(v.into())
        }
        fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut out = vec![];
            while let Some(v) = a.next_element::<StrictValue>()? {
                out.push(v.0);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if out.contains_key(&k) {
                    return Err(de::Error::custom("duplicate field"));
                }
                out.insert(k, a.next_value::<StrictValue>()?.0);
            }
            Ok(Value::Object(out))
        }
    }
    struct StrictValue(Value);
    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(Strict).map(Self)
        }
    }
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|v| v.0)
        .map_err(|_| Failure::InvalidPublicInput)
}

/// Serde structs accept positional arrays. Compare container shapes against
/// serialization of the typed value to reject arrays at every typed object.
pub fn parse<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value = strict_value(bytes)?;
    let typed: T = serde_json::from_slice(bytes).map_err(|_| Failure::InvalidPublicInput)?;
    fn shape(raw: &Value, typed: &Value) -> bool {
        match (raw, typed) {
            (Value::Object(a), Value::Object(b)) => {
                a.iter().all(|(k, v)| b.get(k).is_some_and(|t| shape(v, t)))
            }
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| shape(a, b))
            }
            (Value::Object(_), _)
            | (_, Value::Object(_))
            | (Value::Array(_), _)
            | (_, Value::Array(_)) => false,
            _ => true,
        }
    }
    if !shape(
        &value,
        &serde_json::to_value(&typed).map_err(|_| Failure::InvalidPublicInput)?,
    ) {
        return Err(Failure::InvalidPublicInput);
    }
    Ok(typed)
}

/// Validate complete TOML independently of executable trust or render equality.
/// Every supported table/field is constructed here. Extra settings cannot survive
/// equality, including unsafe settings emitted consistently on both platforms.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "adapter.validate_render")
)]
pub fn validate_render(rendered: &Rendered, input: &RenderInput) -> Result<()> {
    input.options.validate_for_render(input.identity_only)?;
    if rendered.config_toml.len() > 1024 * 1024 {
        return Err(Failure::InvalidOutput);
    }
    let rules = strict_value(input.public.native_rules_json.as_bytes())?;
    let allowed = [
        "network_name",
        "network_magic",
        "genesis_hash",
        "target_difficulty_limit",
        "disable_pow",
        "slow_start_interval",
        "max_block_time_start_height",
        "should_allow_unshielded_coinbase_spends",
        "activation_heights",
        "pre_blossom_halving_interval",
        "funding_streams",
        "lockbox_disbursements",
        "checkpoints",
        "experimental_slh_dsa_b128s_activation_height",
        "experimental_slh_dsa_b128s_max_checks_per_transaction",
        "experimental_slh_dsa_b128s_max_checks_per_block",
    ];
    let object = rules.as_object().ok_or(Failure::InvalidPublicInput)?;
    if object.len() != allowed.len() || object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Failure::InvalidPublicInput);
    }
    let activations = object["activation_heights"]
        .as_object()
        .ok_or(Failure::InvalidPublicInput)?;
    let upgrades = [
        "BeforeOverwinter",
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
        "NU7",
    ];
    if activations.iter().any(|(k, v)| {
        !upgrades.contains(&k.as_str())
            || (!v.is_null() && !v.as_u64().is_some_and(|n| n <= u64::from(u32::MAX)))
    }) {
        return Err(Failure::InvalidPublicInput);
    }
    for key in ["network_name", "genesis_hash", "target_difficulty_limit"] {
        if !object[key]
            .as_str()
            .is_some_and(|v| !v.is_empty() && v.len() <= 128)
        {
            return Err(Failure::InvalidPublicInput);
        }
    }
    for key in ["disable_pow", "should_allow_unshielded_coinbase_spends"] {
        if !object[key].is_boolean() {
            return Err(Failure::InvalidPublicInput);
        }
    }
    for key in [
        "slow_start_interval",
        "max_block_time_start_height",
        "pre_blossom_halving_interval",
        "experimental_slh_dsa_b128s_activation_height",
        "experimental_slh_dsa_b128s_max_checks_per_transaction",
        "experimental_slh_dsa_b128s_max_checks_per_block",
    ] {
        if !object[key]
            .as_u64()
            .is_some_and(|n| n <= u64::from(u32::MAX))
        {
            return Err(Failure::InvalidPublicInput);
        }
    }
    if !object["network_magic"]
        .as_array()
        .is_some_and(|a| a.len() == 4 && a.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255)))
    {
        return Err(Failure::InvalidPublicInput);
    }
    if !object["checkpoints"].as_array().is_some_and(|a| {
        a.len() <= 256
            && a.iter().all(|v| {
                v.as_array().is_some_and(|r| {
                    r.len() == 2
                        && r[0].as_u64().is_some_and(|n| n <= u64::from(u32::MAX))
                        && r[1].as_array().is_some_and(|hash| {
                            hash.len() == 32
                                && hash.iter().all(|byte| {
                                    byte.as_u64().is_some_and(|n| n <= u64::from(u8::MAX))
                                })
                        })
                })
            })
    }) {
        return Err(Failure::InvalidPublicInput);
    }
    // No arbitrary funding or secret-bearing nested objects in revision 1.
    if object["funding_streams"] != serde_json::json!([]) {
        return Err(Failure::InvalidPublicInput);
    }
    for marker in object["lockbox_disbursements"]
        .as_array()
        .ok_or(Failure::InvalidPublicInput)?
    {
        if !marker.as_object().is_some_and(|m| {
            m.len() == 2
                && m.get("address").is_some_and(Value::is_string)
                && m.get("amount").is_some_and(Value::is_u64)
        }) {
            return Err(Failure::InvalidPublicInput);
        }
    }
    let o = &input.options;
    let descriptor_pin = Pin::of(
        &serde_json::to_vec(&input.public.descriptor).map_err(|_| Failure::InvalidPublicInput)?,
    );
    let root = format!(
        "/var/lib/zdn/deployments/{}/nodes/{}/chains/{}",
        o.deployment_id, o.node_id, descriptor_pin.sha256
    );
    if o.state_dir != format!("{root}/state")
        || o.identity_dir != format!("{root}/identity")
        || o.cookie_dir != format!("{root}/rpc")
    {
        return Err(Failure::InvalidPublicInput);
    }
    let mut peers: Vec<_> = o
        .peers
        .iter()
        .map(|p| format!("{}@{}", p.node_id, p.endpoint))
        .collect();
    peers.sort();
    let mut expected = serde_json::json!({
        "network":{"network":rules,"p2p_stack":"zakura","listen_addr":o.native_listen,"identity_dir":o.identity_dir,"initial_mainnet_peers":[],"initial_testnet_peers":[],"cache_dir":false,
            "zakura":{"listen_addr":o.native_listen,"bootstrap_peers":peers,"nat_traversal":false,"expected_node_id":o.expected_node_id}},
        "state":{"cache_dir":o.state_dir,"ephemeral":false,"should_backup_non_finalized_state":true,"delete_old_database":false,"storage_mode":"archive"},
        "consensus":{"checkpoint_sync":true,"vct_fast_sync":false},
        "mempool":{"debug_enable_at_height":0},
        "rpc":{"listen_addr":o.rpc_listen,"cookie_dir":o.cookie_dir,"cookie_file_name":".cookie","enable_cookie_auth":true,"debug_force_finished_sync":false},
        "mining":{"internal_miner":false,"optimistic_block_inventory":false},
        "tracing":{"use_color":false,"force_use_color":false,"use_journald":false},
        "zcashd_compat":{"enabled":false}
    });
    if input.identity_only {
        expected["network"]["zakura"]
            .as_object_mut()
            .ok_or(Failure::InvalidOutput)?
            .remove("expected_node_id");
    }
    if let Some(address) = &o.reward_address {
        expected["mining"]["miner_address"] = address.clone().into();
    }
    fn no_nulls(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.retain(|_, v| !v.is_null());
                for v in m.values_mut() {
                    no_nulls(v);
                }
            }
            Value::Array(a) => {
                for v in a {
                    no_nulls(v);
                }
            }
            _ => {}
        }
    }
    no_nulls(&mut expected);
    let expected = toml::Value::try_from(expected).map_err(|_| Failure::InvalidPublicInput)?;
    let actual: toml::Value =
        toml::from_str(&rendered.config_toml).map_err(|_| Failure::InvalidOutput)?;
    if actual != expected {
        return Err(Failure::InvalidOutput);
    }
    Ok(())
}
