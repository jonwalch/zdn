//! An offline identity contract for a proposed configured Testnet.
//!
//! Field coverage follows Zakura's `ParametersBuilder`, `ConfiguredActivationHeights`,
//! and local genesis generator. This is a structural specification, not a second
//! consensus implementation: it neither checks block bytes nor runs the builder.
//! A launch must still validate saved artifacts, effective node rules, and the
//! selected recipe. The ruleset identifies fixed protocol semantics (including
//! target spacing, branch IDs, maturity, and size rules); it is not a binary pin.
//!
//! Source mapping checked at `jonwalch/zcash-transparent-pq` commit
//! `860203d4d39a480c145f9c04bdf0d1dd08ab0625`:
//! - `node/zakura/crates/zakura-chain/src/parameters/network/testnet.rs`
//! - `node/zakura/crates/zakura-chain/src/work/difficulty.rs`
//! - `node/zakura/crates/zakura-chain/src/local_genesis.rs`
//! - `node/zakura/crates/zakura-consensus/src/block/check.rs` (lockbox multiset)
//!
//! The narrower schema uses canonical compact targets and P2SH script identities.
//! Builder validation, block parsing, funding-period calculations, and generation
//! remain with Zakura. No node code or dependencies are imported.

use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const API_VERSION: &str = "zdn-consensus/v1alpha1";
pub const RULESET: &str = "zakura-configured-testnet/v1";
pub const CANONICAL_PREFIX: &[u8] = b"zdn-consensus/v1alpha1\0";
const MAX_HEIGHT: u32 = i32::MAX as u32;
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
const BUILTIN_GENESIS: [&str; 3] = [
    "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
    "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
    "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327",
];

/// Only consensus identities belong here. Deployment labels, peer addresses,
/// cadence, artifact paths, and component versions are separate contracts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsensusManifest {
    pub api_version: String,
    pub ruleset: String,
    pub network_kind: NetworkKind,
    /// Four bytes in wire order, encoded as eight hexadecimal characters.
    pub network_magic: String,
    pub genesis: BlockIdentity,
    #[serde(default)]
    pub seed_blocks: Vec<BlockIdentity>,
    /// Empty means the genesis checkpoint alone, never public Testnet defaults.
    #[serde(default)]
    pub checkpoints: Vec<Checkpoint>,
    pub upgrades: UpgradeSchedule,
    pub subsidy: SubsidyRules,
    pub difficulty: DifficultyRules,
    /// None declares no temporary disabling rule; it does not inherit a node default.
    pub temporary_orchard_disabling_height: Option<u32>,
    pub experimental_slh: Option<ExperimentalSlh>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkKind {
    CustomTestnet,
}

/// Declared identity of exact saved block bytes. Byte import verifies digest and
/// length. The selected node must later verify decoded height, block hash, and
/// consensus; neither this module nor byte import can attest those claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockIdentity {
    pub height: u32,
    pub hash: String,
    pub bytes_sha256: String,
    pub bytes_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: String,
}

/// The first profile requires every upgrade through Ironwood (NU6.3).
/// Same-height upgrades are allowed; omitted NU7 means it is not scheduled.
/// No public-network schedule or builder default is inherited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct UpgradeSchedule {
    pub before_overwinter: u32,
    pub overwinter: u32,
    pub sapling: u32,
    pub blossom: u32,
    pub heartwood: u32,
    pub canopy: u32,
    #[serde(rename = "NU5")]
    pub nu5: u32,
    #[serde(rename = "NU6")]
    pub nu6: u32,
    #[serde(rename = "NU6.1")]
    pub nu6_1: u32,
    #[serde(rename = "NU6.2")]
    pub nu6_2: u32,
    #[serde(rename = "NU6.3")]
    pub nu6_3: u32,
    #[serde(rename = "NU7")]
    pub nu7: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubsidyRules {
    pub slow_start_interval: u32,
    /// Post-Blossom is exactly twice this interval under the versioned ruleset.
    pub pre_blossom_halving_interval: u32,
    #[serde(default)]
    pub funding_streams: Vec<FundingStream>,
    /// A multiset of expected outputs. Duplicates remain separate outputs.
    pub lockbox_disbursements: Vec<LockboxDisbursement>,
    /// None means derive from chain state; Some(0) is an explicit zero override.
    pub initial_nsm_value_balance: Option<u64>,
    #[serde(default)]
    pub allow_unshielded_coinbase_spends: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FundingStream {
    pub start_height: u32,
    /// Exclusive upper bound. Resolved ranges do not inherit NU7 adjustments.
    pub end_height: u32,
    pub recipients: Vec<FundingRecipient>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FundingRecipient {
    pub receiver: FundingReceiver,
    pub numerator: u64,
    /// P2SH destinations in address-period order. The later adapter encodes these
    /// as Testnet addresses and validates that enough periods are present.
    pub script_hashes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FundingReceiver {
    Ecc,
    ZcashFoundation,
    MajorGrants,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LockboxDisbursement {
    /// P2SH script identity, independent of an address's network spelling.
    pub script_hash: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DifficultyRules {
    /// Canonical positive compact target (big-endian textual nBits). Accepting
    /// only this form avoids silently hashing precision that the builder discards.
    pub target_difficulty_limit_compact: String,
    pub proof_of_work: ProofOfWork,
    pub max_block_time_start_height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofOfWork {
    Disabled,
    Equihash,
}

/// An explicit future-profile request, not evidence that any selected node or
/// wallet supports SLH on custom Testnet. No build features are inferred here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExperimentalSlh {
    pub profile: String,
    pub contract: String,
    pub activation_height: u32,
    pub transaction_checks: u32,
    pub block_checks: u32,
}

impl ConsensusManifest {
    pub fn validate(&self) -> Result<()> {
        self.normalized().map(|_| ())
    }

    /// Resolves local schema defaults and normalizes semantic collections and
    /// hexadecimal spellings. Funding address-period destinations stay ordered.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.manifest.normalized")
    )]
    pub fn normalized(&self) -> Result<Self> {
        let mut normalized = self.clone();
        normalized.network_magic.make_ascii_lowercase();
        normalize_block(&mut normalized.genesis);
        for block in &mut normalized.seed_blocks {
            normalize_block(block);
        }
        normalized.seed_blocks.sort_by_key(|block| block.height);
        if normalized.checkpoints.is_empty() {
            normalized.checkpoints.push(Checkpoint {
                height: 0,
                hash: normalized.genesis.hash.clone(),
            });
        }
        for checkpoint in &mut normalized.checkpoints {
            checkpoint.hash.make_ascii_lowercase();
        }
        normalized.checkpoints.sort_by_key(|entry| entry.height);
        normalized
            .subsidy
            .funding_streams
            .sort_by_key(|stream| (stream.start_height, stream.end_height));
        for stream in &mut normalized.subsidy.funding_streams {
            stream
                .recipients
                .sort_by_key(|recipient| recipient.receiver.key());
            for recipient in &mut stream.recipients {
                for hash in &mut recipient.script_hashes {
                    hash.make_ascii_lowercase();
                }
            }
        }
        for output in &mut normalized.subsidy.lockbox_disbursements {
            output.script_hash.make_ascii_lowercase();
        }
        normalized
            .subsidy
            .lockbox_disbursements
            .sort_by(|left, right| {
                (&left.script_hash, left.amount).cmp(&(&right.script_hash, right.amount))
            });
        normalized
            .difficulty
            .target_difficulty_limit_compact
            .make_ascii_lowercase();
        normalized.validate_normalized()?;
        Ok(normalized)
    }

    /// Versioned encoding: the NUL-terminated domain prefix followed by compact
    /// UTF-8 JSON, with recursively sorted object keys and no trailing newline.
    /// Values are integer-only; normalization resolves all optional schema fields.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.manifest.canonical_bytes")
    )]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self.normalized()?)?;
        let mut bytes = CANONICAL_PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(&sorted_json(value))?);
        Ok(bytes)
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.manifest.validate_normalized")
    )]
    fn validate_normalized(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported consensus manifest version"
        );
        ensure!(self.ruleset == RULESET, "unsupported consensus ruleset");
        hex_field(&self.network_magic, 4, "networkMagic")?;
        ensure!(
            !["24e92764", "fa1af9bf", "aae83f5f"].contains(&self.network_magic.as_str()),
            "custom Testnet requires nonreserved network magic"
        );
        validate_block(&self.genesis)?;
        ensure!(self.genesis.height == 0, "genesis height must be zero");
        let mut block_hashes = BTreeSet::from([self.genesis.hash.as_str()]);
        let mut byte_hashes = BTreeSet::from([self.genesis.bytes_sha256.as_str()]);
        let mut seed_hashes = BTreeMap::from([(0, self.genesis.hash.as_str())]);
        let mut saved_hash_heights = BTreeMap::from([(self.genesis.hash.as_str(), 0)]);
        for (index, block) in self.seed_blocks.iter().enumerate() {
            validate_block(block)?;
            ensure!(
                u64::from(block.height) == index as u64 + 1,
                "seed blocks must cover each height starting at one"
            );
            ensure!(
                block_hashes.insert(&block.hash),
                "duplicate seed block hash"
            );
            ensure!(
                byte_hashes.insert(&block.bytes_sha256),
                "duplicate saved block byte digest"
            );
            seed_hashes.insert(block.height, &block.hash);
            saved_hash_heights.insert(&block.hash, block.height);
        }
        let mut checkpoint_hashes = BTreeSet::new();
        let mut previous_height = None;
        for checkpoint in &self.checkpoints {
            height(checkpoint.height, "checkpoint height")?;
            block_hash(&checkpoint.hash)?;
            ensure!(
                previous_height.is_none_or(|previous| checkpoint.height > previous),
                "duplicate checkpoint height"
            );
            ensure!(
                checkpoint_hashes.insert(&checkpoint.hash),
                "duplicate checkpoint hash"
            );
            if let Some(saved) = seed_hashes.get(&checkpoint.height) {
                ensure!(
                    *saved == checkpoint.hash,
                    "checkpoint conflicts with saved block identity"
                );
            }
            if let Some(saved_height) = saved_hash_heights.get(checkpoint.hash.as_str()) {
                ensure!(
                    *saved_height == checkpoint.height,
                    "checkpoint assigns a saved block hash to a different height"
                );
            }
            previous_height = Some(checkpoint.height);
        }
        ensure!(
            self.checkpoints[0].height == 0,
            "checkpoints must start at genesis"
        );
        ensure!(
            self.checkpoints[0].hash == self.genesis.hash,
            "genesis checkpoint hash mismatch"
        );
        self.upgrades.validate()?;
        ensure!(
            self.checkpoints
                .last()
                .is_some_and(|checkpoint| checkpoint.height >= self.upgrades.canopy - 1),
            "checkpoints must cover the block before Canopy activation"
        );
        self.subsidy.validate()?;
        canonical_compact_target(&self.difficulty.target_difficulty_limit_compact)?;
        height(
            self.difficulty.max_block_time_start_height,
            "max block time start height",
        )?;
        if let Some(value) = self.temporary_orchard_disabling_height {
            height(value, "temporary Orchard disabling height")?;
        }
        if let Some(slh) = &self.experimental_slh {
            ensure!(
                slh.profile == "custom-testnet-slh-v1",
                "unsupported experimental SLH profile"
            );
            ensure!(
                slh.contract == "slh-dsa-b-128s-v1",
                "unsupported experimental SLH contract"
            );
            ensure!(
                !BUILTIN_GENESIS.contains(&self.genesis.hash.as_str()),
                "SLH requires a distinct custom genesis"
            );
            let nu7 = self
                .upgrades
                .nu7
                .ok_or_else(|| eyre::eyre!("SLH requires explicit NU7 activation"))?;
            height(slh.activation_height, "SLH activation height")?;
            let seed_tip = self.seed_blocks.last().map_or(0, |block| block.height);
            let checkpoint_tip = self
                .checkpoints
                .last()
                .map_or(0, |checkpoint| checkpoint.height);
            ensure!(
                slh.activation_height > nu7 && slh.activation_height > seed_tip.max(checkpoint_tip),
                "SLH activation must be after NU7 and every seed block and checkpoint"
            );
            ensure!(
                slh.transaction_checks > 0 && slh.transaction_checks <= slh.block_checks,
                "SLH check limits require 0 < transaction <= block"
            );
            ensure!(
                slh.transaction_checks == 16 && slh.block_checks == 64,
                "the first SLH profile requires 16 transaction and 64 block checks"
            );
        }
        Ok(())
    }
}

impl UpgradeSchedule {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.manifest.upgrades.validate")
    )]
    fn validate(&self) -> Result<()> {
        let heights = [
            self.before_overwinter,
            self.overwinter,
            self.sapling,
            self.blossom,
            self.heartwood,
            self.canopy,
            self.nu5,
            self.nu6,
            self.nu6_1,
            self.nu6_2,
            self.nu6_3,
        ];
        let mut previous = 1;
        for value in heights.into_iter().chain(self.nu7) {
            height(value, "upgrade activation height")?;
            ensure!(
                value >= previous,
                "upgrade heights must be positive and nondecreasing"
            );
            previous = value;
        }
        Ok(())
    }
}

impl SubsidyRules {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.manifest.subsidy.validate")
    )]
    fn validate(&self) -> Result<()> {
        height(self.slow_start_interval, "slow start interval")?;
        ensure!(
            self.pre_blossom_halving_interval > 0
                && self.pre_blossom_halving_interval <= MAX_HEIGHT / 2,
            "halving intervals must be positive and fit supported block heights"
        );
        let mut previous_end = 0;
        for stream in &self.funding_streams {
            height(stream.start_height, "funding stream start height")?;
            height(stream.end_height, "funding stream end height")?;
            ensure!(
                stream.start_height < stream.end_height,
                "funding stream range must be nonempty"
            );
            ensure!(
                stream.start_height >= previous_end,
                "funding stream ranges must not overlap"
            );
            previous_end = stream.end_height;
            let mut receivers = BTreeSet::new();
            let mut numerator_sum = 0u64;
            for recipient in &stream.recipients {
                ensure!(
                    receivers.insert(recipient.receiver),
                    "duplicate funding stream receiver"
                );
                ensure!(
                    recipient.numerator <= 100,
                    "funding numerator exceeds denominator"
                );
                numerator_sum += recipient.numerator;
                ensure!(
                    numerator_sum <= 100,
                    "funding numerators exceed denominator"
                );
                ensure!(
                    recipient.script_hashes.is_empty()
                        == (recipient.receiver == FundingReceiver::Deferred),
                    "only deferred funding recipients have no P2SH destinations"
                );
                for hash in &recipient.script_hashes {
                    hex_field(hash, 20, "funding P2SH script hash")?;
                }
            }
        }
        ensure!(
            !self.lockbox_disbursements.is_empty(),
            "NU6.1 requires explicit lockbox disbursements"
        );
        let mut total = 0u64;
        for output in &self.lockbox_disbursements {
            hex_field(&output.script_hash, 20, "lockbox P2SH script hash")?;
            ensure!(
                output.amount <= MAX_MONEY,
                "lockbox amount exceeds MAX_MONEY"
            );
            total = total
                .checked_add(output.amount)
                .ok_or_else(|| eyre::eyre!("lockbox amount overflow"))?;
            ensure!(total <= MAX_MONEY, "lockbox disbursements exceed MAX_MONEY");
        }
        ensure!(
            self.initial_nsm_value_balance
                .is_none_or(|value| value <= MAX_MONEY),
            "NSM balance exceeds MAX_MONEY"
        );
        Ok(())
    }
}

impl FundingReceiver {
    fn key(self) -> &'static str {
        match self {
            Self::Ecc => "ecc",
            Self::ZcashFoundation => "zcash-foundation",
            Self::MajorGrants => "major-grants",
            Self::Deferred => "deferred",
        }
    }
}

fn normalize_block(block: &mut BlockIdentity) {
    block.hash.make_ascii_lowercase();
    block.bytes_sha256.make_ascii_lowercase();
}

fn validate_block(block: &BlockIdentity) -> Result<()> {
    height(block.height, "block height")?;
    block_hash(&block.hash)?;
    hex_field(&block.bytes_sha256, 32, "block bytes SHA-256")?;
    ensure!(
        (1..=2_000_000).contains(&block.bytes_length),
        "block byte length must be 1..=2000000"
    );
    Ok(())
}

fn height(value: u32, name: &str) -> Result<()> {
    ensure!(
        value <= MAX_HEIGHT,
        "{name} exceeds the supported height limit"
    );
    Ok(())
}

fn block_hash(value: &str) -> Result<()> {
    hex_field(value, 32, "block hash")?;
    ensure!(
        value.bytes().any(|byte| byte != b'0'),
        "block hash cannot be zero"
    );
    Ok(())
}

fn hex_field(value: &str, bytes: usize, name: &str) -> Result<()> {
    ensure!(
        value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name} must contain exactly {} hexadecimal characters",
        bytes * 2
    );
    Ok(())
}

/// Encoding bounds only, not work/difficulty calculation. The canonical compact
/// representation uses the fewest exponent bytes possible, except its sign pad.
fn canonical_compact_target(value: &str) -> Result<()> {
    hex_field(value, 4, "compact target")?;
    let target = u32::from_str_radix(value, 16)?;
    let exponent = target >> 24;
    let mantissa = target & 0x00ff_ffff;
    let canonical = match exponent {
        1 => (0x010000..=0x7f0000).contains(&mantissa) && mantissa & 0xffff == 0,
        2 => (0x008000..=0x7fff00).contains(&mantissa) && mantissa & 0xff == 0,
        3..=32 => (0x008000..=0x7fffff).contains(&mantissa),
        33 => (0x008000..=0x00ffff).contains(&mantissa),
        _ => false,
    };
    ensure!(
        canonical,
        "target difficulty limit must be a positive canonical compact target"
    );
    Ok(())
}

fn sorted_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let entries: BTreeMap<_, _> = object
                .into_iter()
                .map(|(key, value)| (key, sorted_json(value)))
                .collect();
            serde_json::Value::Object(entries.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sorted_json).collect())
        }
        value => value,
    }
}
