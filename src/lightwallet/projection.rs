//! Projections from pinned Zakura RPC fields to the pinned light-wallet schema.
use super::wire;
use eyre::{ensure, Context, ContextCompat, Result};
use serde_json::Value;

pub fn height(height: u64) -> Result<u32> {
    ensure!(height < i32::MAX as u64, "unsupported light-wallet height");
    Ok(height as u32)
}
pub fn display_hash(value: &Value, label: &str) -> Result<String> {
    let hash = value
        .as_str()
        .with_context(|| format!("invalid {label} hash"))?;
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid {label} hash"
    );
    Ok(hash.to_ascii_lowercase())
}
pub fn wire_hash(bytes: &[u8], label: &str) -> Result<String> {
    ensure!(bytes.len() == 32, "invalid {label} hash length");
    let mut reversed = [0; 32];
    reversed.copy_from_slice(bytes);
    reversed.reverse();
    Ok(hex::encode(reversed))
}
fn bytes(value: &Value, length: usize, label: &str) -> Result<Vec<u8>> {
    let text = value.as_str().with_context(|| format!("missing {label}"))?;
    ensure!(text.len() == length * 2, "invalid {label} length");
    hex::decode(text).with_context(|| format!("invalid {label} hex"))
}
fn ciphertext(value: &Value, label: &str) -> Result<Vec<u8>> {
    let text = value.as_str().with_context(|| format!("missing {label}"))?;
    ensure!(text.len() == 580 * 2, "invalid {label} length");
    // Validate the entire ciphertext, including the suffix omitted on the wire.
    let mut decoded = [0; 580];
    hex::decode_to_slice(text, &mut decoded).with_context(|| format!("invalid {label} hex"))?;
    Ok(decoded[..52].into())
}
fn array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .with_context(|| format!("missing {label} array"))
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.projection.compact_actions")
)]
fn compact_actions(value: &Value) -> Result<Vec<wire::CompactOrchardAction>> {
    if value.is_null() {
        return Ok(vec![]);
    }
    array(&value["actions"], "shielded actions")?
        .iter()
        .map(|action| {
            Ok(wire::CompactOrchardAction {
                nullifier: bytes(&action["nullifier"], 32, "action nullifier")?,
                cmx: bytes(&action["cmx"], 32, "action cmx")?,
                ephemeral_key: bytes(&action["ephemeralKey"], 32, "action ephemeral key")?,
                ciphertext: ciphertext(&action["encCiphertext"], "action ciphertext")?,
            })
        })
        .collect()
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.projection.transactions")
)]
fn transactions(block: &Value) -> Result<Vec<wire::CompactTx>> {
    let mut compact = Vec::new();
    for (index, tx) in array(&block["tx"], "block transactions")?
        .iter()
        .enumerate()
    {
        let spends = array(&tx["vShieldedSpend"], "Sapling spends")?
            .iter()
            .map(|spend| {
                Ok(wire::CompactSaplingSpend {
                    nf: bytes(&spend["nullifier"], 32, "Sapling nullifier")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let outputs = array(&tx["vShieldedOutput"], "Sapling outputs")?
            .iter()
            .map(|output| {
                Ok(wire::CompactSaplingOutput {
                    cmu: bytes(&output["cmu"], 32, "Sapling cmu")?,
                    ephemeral_key: bytes(&output["ephemeralKey"], 32, "Sapling ephemeral key")?,
                    ciphertext: ciphertext(&output["encCiphertext"], "Sapling ciphertext")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let actions = compact_actions(&tx["orchard"])?;
        let ironwood_actions = compact_actions(&tx["ironwood"])?;
        if spends.is_empty()
            && outputs.is_empty()
            && actions.is_empty()
            && ironwood_actions.is_empty()
        {
            continue;
        }
        let mut txid = bytes(&tx["txid"], 32, "transaction ID")?;
        txid.reverse();
        compact.push(wire::CompactTx {
            index: index as u64,
            txid,
            spends,
            outputs,
            actions,
            ironwood_actions,
            ..Default::default()
        });
    }
    Ok(compact)
}
fn tree_size(block: &Value, pool: &str) -> Result<u32> {
    match block["trees"].get(pool) {
        None => Ok(0),
        Some(value) => value["size"]
            .as_u64()
            .and_then(|size| size.try_into().ok())
            .with_context(|| format!("invalid {pool} tree size")),
    }
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.check_compact")
)]
pub fn check_compact(compact: &wire::CompactBlock, block: &Value) -> Result<usize> {
    ensure!(
        block["height"].as_u64() == Some(compact.height)
            && display_hash(&block["hash"], "node verbose block")?
                == wire_hash(&compact.hash, "compact block")?,
        "node verbose block identity mismatch"
    );
    let expected_parent = if compact.height == 0 {
        "00".repeat(32)
    } else {
        display_hash(&block["previousblockhash"], "node parent")?
    };
    ensure!(
        wire_hash(&compact.prev_hash, "compact parent")? == expected_parent,
        "compact block parent mismatch"
    );
    ensure!(
        block["time"].as_u64() == Some(compact.time.into()) && compact.header.is_empty(),
        "compact block time or header mismatch"
    );
    ensure!(
        block["trees"].is_object(),
        "node block is missing tree metadata"
    );
    let expected_metadata = wire::ChainMetadata {
        sapling_commitment_tree_size: tree_size(block, "sapling")?,
        orchard_commitment_tree_size: tree_size(block, "orchard")?,
        ironwood_commitment_tree_size: tree_size(block, "ironwood")?,
    };
    ensure!(
        compact.chain_metadata.as_ref() == Some(&expected_metadata),
        "compact commitment-tree sizes differ from node"
    );
    let mut expected = transactions(block)?;
    // Fee is optional advisory information; it is not part of scanning data.
    // Adjust only the owned projection, retaining full derived wire equality.
    for (expected_tx, actual_tx) in expected.iter_mut().zip(&compact.vtx) {
        expected_tx.fee = actual_tx.fee;
    }
    ensure!(
        compact.vtx == expected,
        "compact shielded transaction data differs from node"
    );
    Ok(compact.vtx.iter().map(|tx| tx.ironwood_actions.len()).sum())
}
fn tree_hex(value: &str, label: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= 8192
            && value.len().is_multiple_of(2)
            && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "missing or invalid {label} tree"
    );
    Ok(value.to_ascii_lowercase())
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet.projection.check_tree")
)]
pub fn check_tree(tree: &wire::TreeState, node: &Value, height: u32, hash: &str) -> Result<()> {
    ensure!(
        tree.network == "test"
            && tree.height == u64::from(height)
            && tree.hash.eq_ignore_ascii_case(hash),
        "light-wallet tree identity mismatch"
    );
    ensure!(
        node["height"].as_u64() == Some(height.into())
            && display_hash(&node["hash"], "node tree")? == hash
            && node["time"].as_u64() == Some(tree.time.into()),
        "node tree identity mismatch"
    );
    for (pool, actual) in [
        ("sapling", &tree.sapling_tree),
        ("orchard", &tree.orchard_tree),
        ("ironwood", &tree.ironwood_tree),
    ] {
        let expected = node[pool]["commitments"]["finalState"]
            .as_str()
            .with_context(|| format!("node did not return {pool} tree state"))?;
        ensure!(
            tree_hex(actual, pool)? == tree_hex(expected, pool)?,
            "light-wallet {pool} tree differs from node"
        );
    }
    Ok(())
}
