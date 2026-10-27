//! Trusted-node transport, not a block decoder or a consensus implementation.
use eyre::{ensure, ContextCompat, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufWriter, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use zdn::chain::manifest::ConsensusManifest;

pub(super) const GENESIS: &str = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";
const MAX_BLOCKS: u32 = 4096;
const MAX_RAW_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize)]
pub struct Tip {
    pub height: u32,
    pub hash: String,
}

pub struct History {
    pub payload: Option<NamedTempFile>,
    pub tip: Tip,
    pub digest: String,
    pub anchor: String,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.history.check_manifest")
)]
pub fn check_manifest(manifest: &ConsensusManifest) -> Result<()> {
    let upgrades = serde_json::to_value(&manifest.upgrades)?;
    ensure!(
        manifest.genesis.hash == GENESIS
            && manifest.experimental_slh.is_none()
            && upgrades
                .as_object()
                .context("invalid upgrade schedule")?
                .iter()
                .all(|(key, height)| {
                    if key == "NU7" {
                        height.is_null()
                    } else {
                        height.as_u64() == Some(1)
                    }
                }),
        "wallet requires Testnet genesis, all pre-NU7 upgrades at height 1, and no NU7/SLH"
    );
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.history.tip")
)]
pub(super) fn tip(rpc: &mut impl FnMut(&str, Value) -> Result<Value>) -> Result<Tip> {
    // The node's exact RPC serializes this hash as 32 internal-order bytes,
    // unlike getblockhash/getbestblockhash's display-order hexadecimal strings.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        height: u32,
        hash: [u8; 32],
    }
    let mut reply: Reply = serde_json::from_value(rpc("getbestblockheightandhash", json!([]))?)
        .map_err(|_| eyre::eyre!("invalid wallet node tip"))?;
    ensure!(
        reply.height < i32::MAX as u32,
        "unsupported node tip height"
    );
    reply.hash.reverse();
    Ok(Tip {
        height: reply.height,
        hash: hex::encode(reply.hash),
    })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.history.block_hash")
)]
pub(super) fn block_hash(
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
    height: u32,
) -> Result<String> {
    let value = rpc("getblockhash", json!([height]))?;
    let Value::String(mut hash) = value else {
        eyre::bail!("invalid canonical block hash");
    };
    ensure!(super::hex_bytes(&hash, 32), "invalid canonical block hash");
    hash.make_ascii_lowercase();
    Ok(hash)
}

struct Blocks {
    output: BufWriter<NamedTempFile>,
    count: u32,
    bytes_total: usize,
    digest: Sha256,
    json_entries_bytes: usize,
}

impl Blocks {
    fn new() -> Result<Self> {
        let mut output = BufWriter::new(NamedTempFile::new()?);
        output.write_all(b"{\"blocks\":[")?;
        Ok(Self {
            output,
            count: 0,
            bytes_total: 0,
            digest: Sha256::new(),
            json_entries_bytes: 0,
        })
    }
}

struct Snapshot {
    tip: Tip,
    treestate: Value,
    anchor: String,
}

// Field order matches serde_json::Value's alphabetically sorted object keys.
#[derive(Serialize)]
struct Payload<'a> {
    blocks: &'a [String],
    genesis_hash: &'a str,
    network: &'a str,
    schema_version: u32,
    treestate: &'a Value,
}

impl Snapshot {
    fn payload<'a>(&'a self, blocks: &'a [String]) -> Payload<'a> {
        Payload {
            blocks,
            genesis_hash: GENESIS,
            network: "h0-testnet-nu6.3-at-1",
            schema_version: 1,
            treestate: &self.treestate,
        }
    }

    fn finish(self, mut blocks: Blocks) -> Result<History> {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("history.serialize").entered();
        // The empty payload supplies the exact sorted metadata suffix. Blocks
        // have already been streamed, so only this bounded metadata is retained.
        let metadata = serde_json::to_vec(&self.payload(&[]))?;
        blocks
            .output
            .write_all(&metadata[b"{\"blocks\":[".len()..])?;
        blocks.output.flush()?;
        let payload = blocks
            .output
            .into_inner()
            .map_err(|error| error.into_error())?;
        Ok(History {
            payload: Some(payload),
            tip: self.tip,
            digest: hex::encode(blocks.digest.finalize()),
            anchor: self.anchor,
        })
    }
}

pub fn collect(
    manifest: &ConsensusManifest,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<History> {
    let mut blocks = Blocks::new()?;
    collect_from(manifest, rpc, &mut blocks, None)?.finish(blocks)
}

/// Catch a moving tip without downloading the already verified prefix again.
/// The RPC session budget and existing history size limits bound this loop.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "history.collect_current")
)]
pub fn collect_current(
    manifest: &ConsensusManifest,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<History> {
    let mut blocks = Blocks::new()?;
    let mut snapshot = collect_from(manifest, rpc, &mut blocks, None)?;
    while observe_tip(&snapshot.tip, rpc)?.height != snapshot.tip.height {
        snapshot = collect_from(manifest, rpc, &mut blocks, Some(&snapshot.tip))?;
    }
    snapshot.finish(blocks)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "history.collect_snapshot")
)]
fn collect_from(
    manifest: &ConsensusManifest,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
    blocks: &mut Blocks,
    previous: Option<&Tip>,
) -> Result<Snapshot> {
    let tip = tip(rpc)?;
    ensure!(
        tip.height < MAX_BLOCKS,
        "legacy wallet history exceeds 4096 blocks; explicit wallet sync does not enable v2 balances or payments"
    );
    if let Some(previous) = previous {
        ensure!(
            tip.height >= previous.height && block_hash(rpc, previous.height)? == previous.hash,
            "node reorged the history prefix; retry with a new snapshot"
        );
    }
    for height in blocks.count..=tip.height {
        let hash = block_hash(rpc, height)?;
        if height == 0 {
            ensure!(
                hash == GENESIS,
                "node genesis does not match the wallet manifest"
            );
        }
        if height == tip.height {
            ensure!(
                hash == tip.hash,
                "node tip changed during history collection"
            );
        }
        let value = rpc("getblock", json!([hash, 0]))?;
        let Value::String(mut raw) = value else {
            eyre::bail!("node did not return a raw block");
        };
        ensure!(
            !raw.is_empty() && raw.len() % 2 == 0,
            "invalid raw block encoding"
        );
        ensure!(
            raw.len() / 2 <= MAX_RAW_BYTES - blocks.bytes_total,
            "wallet history exceeds 64 MiB of raw blocks"
        );
        let bytes = hex::decode(&raw).map_err(|_| eyre::eyre!("invalid raw block encoding"))?;
        blocks.bytes_total += bytes.len();
        if height == 0 {
            ensure!(
                bytes.len() as u64 == manifest.genesis.bytes_length
                    && hex::encode(Sha256::digest(&bytes)) == manifest.genesis.bytes_sha256,
                "raw genesis differs from the reviewed manifest"
            );
        }
        blocks.digest.update((bytes.len() as u64).to_le_bytes());
        blocks.digest.update(&bytes);
        raw.make_ascii_lowercase();
        blocks.json_entries_bytes += raw.len() + 3; // Quotes and separator; hex never escapes.
        if blocks.count != 0 {
            blocks.output.write_all(b",")?;
        }
        serde_json::to_writer(&mut blocks.output, &raw)?;
        blocks.count += 1;
    }
    let treestate = rpc("z_gettreestate", json!([tip.hash]))?;
    ensure!(
        treestate["height"].as_u64() == Some(u64::from(tip.height))
            && treestate["hash"].as_str() == Some(&tip.hash),
        "treestate does not match the pinned history tip"
    );
    let anchor = treestate["ironwood"]["commitments"]["finalRoot"]
        .as_str()
        .context("missing Ironwood treestate root")?
        .to_owned();
    ensure!(
        super::hex_bytes(&anchor, 32),
        "invalid Ironwood treestate root"
    );
    let snapshot = Snapshot {
        tip,
        treestate,
        anchor,
    };
    // Check every pinned snapshot, without traversing/serializing the old prefix.
    let metadata_bytes = serde_json::to_vec(&snapshot.payload(&[]))?.len();
    ensure!(
        metadata_bytes + blocks.json_entries_bytes.saturating_sub(1) <= 129 * 1024 * 1024,
        "wallet history exceeds backend JSON input bound"
    );
    Ok(snapshot)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.history.observe_tip")
)]
pub(super) fn observe_tip(
    pinned: &Tip,
    rpc: &mut impl FnMut(&str, Value) -> Result<Value>,
) -> Result<Tip> {
    let observed = tip(rpc)?;
    ensure!(
        observed.height >= pinned.height
            && block_hash(rpc, pinned.height)? == pinned.hash
            && block_hash(rpc, observed.height)? == observed.hash,
        "node reorged the history snapshot or observed tip; retry with a new snapshot"
    );
    Ok(observed)
}

impl History {
    pub fn path(&self) -> &Path {
        self.payload
            .as_ref()
            .expect("history payload already transferred")
            .path()
    }

    /// Atomically replace an interrupted pre-plan snapshot, with the same
    /// private-file and destination checks as foundation::write_private.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.history.persist_snapshot")
    )]
    pub fn persist_snapshot(&self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "state destination must be a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let parent = path.parent().context("file needs a parent directory")?;
        ensure!(
            fs::symlink_metadata(parent)?.file_type().is_dir(),
            "file parent must be a real directory"
        );
        let mut temporary = NamedTempFile::new_in(parent)?;
        std::io::copy(&mut fs::File::open(self.path())?, &mut temporary)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "wallet_cli.history.history.observe")
    )]
    pub fn observe(&self, rpc: &mut impl FnMut(&str, Value) -> Result<Value>) -> Result<Value> {
        let observed = observe_tip(&self.tip, rpc)?;
        Ok(json!({
            "schema_version":1,
            "as_of":self.tip,
            "observed_tip":observed,
            "scan_lag_blocks":observed.height - self.tip.height,
            "history_sha256":self.digest,
            "anchor_hex":self.anchor,
            "snapshot_tip_canonical_at_observation":true,
            "consensus_validated_by_zdn":false
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    type Calls = VecDeque<(&'static str, Value, Value)>;

    fn hash(height: u32) -> String {
        if height == 0 {
            GENESIS.to_owned()
        } else {
            format!("{height:064x}")
        }
    }

    fn tree(height: u32) -> Value {
        json!({"height":height,"hash":hash(height),"ironwood":{"commitments":{"finalRoot":"AB".repeat(32)}},"extra":"escaped\n\""})
    }

    fn manifest() -> ConsensusManifest {
        let mut manifest: ConsensusManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/chain-manifest/valid.json"
        ))
        .unwrap();
        manifest.genesis.hash = GENESIS.to_owned();
        manifest.genesis.bytes_length = 2;
        manifest.genesis.bytes_sha256 = hex::encode(Sha256::digest([0xab, 0xcd]));
        manifest
    }

    fn tip_call(calls: &mut Calls, height: u32) {
        let mut bytes = hex::decode(hash(height)).unwrap();
        bytes.reverse();
        calls.push_back((
            "getbestblockheightandhash",
            json!([]),
            json!({"height":height,"hash":bytes}),
        ));
    }

    fn hash_call(calls: &mut Calls, height: u32) {
        calls.push_back((
            "getblockhash",
            json!([height]),
            json!(hash(height).to_ascii_uppercase()),
        ));
    }

    fn snapshot(calls: &mut Calls, height: u32, previous: Option<u32>) {
        tip_call(calls, height);
        if let Some(previous) = previous {
            hash_call(calls, previous);
        }
        for next in previous.map_or(0, |h| h + 1)..=height {
            hash_call(calls, next);
            calls.push_back((
                "getblock",
                json!([hash(next), 0]),
                json!(if next == 0 { "ABCD" } else { "EF" }),
            ));
        }
        calls.push_back(("z_gettreestate", json!([hash(height)]), tree(height)));
    }

    fn observation(calls: &mut Calls, pinned: u32, observed: u32) {
        tip_call(calls, observed);
        hash_call(calls, pinned);
        hash_call(calls, observed);
    }

    fn rpc(calls: &mut Calls) -> impl FnMut(&str, Value) -> Result<Value> + '_ {
        |method, params| {
            let (expected_method, expected_params, reply) = calls.pop_front().expect("extra RPC");
            assert_eq!((method, params), (expected_method, expected_params));
            Ok(reply)
        }
    }

    fn assert_payload(history: &History, height: u32) {
        let mut blocks = vec!["abcd"];
        blocks.extend(std::iter::repeat_n("ef", height as usize));
        assert_eq!(
            fs::read(history.path()).unwrap(),
            serde_json::to_vec(&json!({
                "schema_version":1,"network":"h0-testnet-nu6.3-at-1",
                "genesis_hash":GENESIS,"blocks":blocks,"treestate":tree(height)
            }))
            .unwrap()
        );
        let mut input = 2u64.to_le_bytes().to_vec();
        input.extend([0xab, 0xcd]);
        for _ in 0..height {
            input.extend(1u64.to_le_bytes());
            input.push(0xef);
        }
        assert_eq!(history.digest, hex::encode(Sha256::digest(input)));
        assert_eq!(history.tip.height, height);
        assert_eq!(history.anchor, "AB".repeat(32));
    }

    #[test]
    fn growing_tip_appends_only_new_blocks_with_identical_payload() {
        let mut calls = Calls::new();
        snapshot(&mut calls, 0, None);
        observation(&mut calls, 0, 1);
        snapshot(&mut calls, 1, Some(0));
        observation(&mut calls, 1, 2);
        snapshot(&mut calls, 2, Some(1));
        observation(&mut calls, 2, 2);
        let history = collect_current(&manifest(), &mut rpc(&mut calls)).unwrap();
        assert!(calls.is_empty());
        assert_payload(&history, 2);

        let mut calls = Calls::new();
        snapshot(&mut calls, 2, None);
        let asof = collect(&manifest(), &mut rpc(&mut calls)).unwrap();
        assert!(calls.is_empty());
        assert_eq!(
            fs::read(history.path()).unwrap(),
            fs::read(asof.path()).unwrap()
        );
        assert_eq!(history.digest, asof.digest);
    }

    #[test]
    fn asof_keeps_pinned_payload_when_observed_tip_advances() {
        let mut calls = Calls::new();
        snapshot(&mut calls, 0, None);
        let history = collect(&manifest(), &mut rpc(&mut calls)).unwrap();
        assert!(calls.is_empty());
        observation(&mut calls, 0, 2);
        assert_eq!(
            history.observe(&mut rpc(&mut calls)).unwrap()["scan_lag_blocks"],
            2
        );
        assert!(calls.is_empty());
        assert_payload(&history, 0);
    }

    #[test]
    fn payload_transfer_preserves_observation_and_cleans_up_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let mut calls = Calls::new();
        snapshot(&mut calls, 0, None);
        let mut history = collect(&manifest(), &mut rpc(&mut calls)).unwrap();
        let path = history.path().to_owned();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let payload = history.payload.take().unwrap();
        observation(&mut calls, 0, 1);
        let observed = history.observe(&mut rpc(&mut calls)).unwrap();
        assert_eq!(observed["history_sha256"], history.digest);
        assert_eq!(observed["anchor_hex"], history.anchor);
        assert_eq!(observed["scan_lag_blocks"], 1);
        drop(history);
        assert!(path.exists());
        drop(payload);
        assert!(!path.exists());
        assert!(calls.is_empty());
    }

    #[test]
    fn durable_snapshot_replaces_regular_files_but_never_follows_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let mut calls = Calls::new();
        snapshot(&mut calls, 0, None);
        let history = collect(&manifest(), &mut rpc(&mut calls)).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("history.json");
        fs::write(&output, b"interrupted snapshot").unwrap();
        history.persist_snapshot(&output).unwrap();
        assert_eq!(
            fs::read(&output).unwrap(),
            fs::read(history.path()).unwrap()
        );
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = directory.path().join("link.json");
        symlink(&output, &link).unwrap();
        assert!(history.persist_snapshot(&link).is_err());
        let dangling = directory.path().join("dangling.json");
        symlink(directory.path().join("absent"), &dangling).unwrap();
        assert!(history.persist_snapshot(&dangling).is_err());
        let temporary_path = history.path().to_owned();
        drop(history);
        assert!(!temporary_path.exists());
        assert!(output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
    }

    #[test]
    fn reorgs_fail_at_observation_and_catchup_prefix_checks() {
        for at_catchup in [false, true] {
            let mut calls = Calls::new();
            snapshot(&mut calls, 0, None);
            if at_catchup {
                observation(&mut calls, 0, 1);
                tip_call(&mut calls, 1);
            } else {
                tip_call(&mut calls, 1);
            }
            calls.push_back(("getblockhash", json!([0]), json!(hash(9))));
            let error = collect_current(&manifest(), &mut rpc(&mut calls))
                .err()
                .unwrap();
            assert_eq!(
                error.to_string(),
                if at_catchup {
                    "node reorged the history prefix; retry with a new snapshot"
                } else {
                    "node reorged the history snapshot or observed tip; retry with a new snapshot"
                }
            );
            assert!(calls.is_empty());
        }
    }
}
