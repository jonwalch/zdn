//! Bounded read-only node observation. Transaction parsing belongs to the backend.
use eyre::{ensure, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub struct Mempool {
    pub bytes: Vec<u8>,
    pub digest: String,
    txids: BTreeSet<String>,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.mempool.txids")
)]
pub(super) fn txids(rpc: &mut dyn FnMut(&str, Value) -> Result<Value>) -> Result<BTreeSet<String>> {
    let reply = rpc("getrawmempool", json!([false]))?;
    let Value::Array(values) = reply else {
        eyre::bail!("invalid mempool transaction list");
    };
    ensure!(
        values.len() <= 1024,
        "wallet mempool exceeds 1024 transactions"
    );
    let mut ids = BTreeSet::new();
    for value in values {
        let Value::String(mut id) = value else {
            eyre::bail!("invalid mempool transaction ID");
        };
        let valid = super::hex_bytes(&id, 32);
        id.make_ascii_lowercase();
        ensure!(
            valid && ids.insert(id),
            "invalid or duplicate mempool transaction ID"
        );
    }
    Ok(ids)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "wallet_cli.mempool.collect")
)]
pub fn collect(rpc: &mut dyn FnMut(&str, Value) -> Result<Value>) -> Result<Mempool> {
    // Alphabetical field order preserves the original json! object encoding.
    #[derive(Serialize)]
    struct Transaction<'a> {
        raw_transaction_hex: String,
        txid: &'a str,
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        schema_version: u32,
        transactions: &'a [Transaction<'a>],
    }
    let txids = txids(rpc)?;
    let mut total = 0usize;
    let mut digest = Sha256::new();
    digest.update(b"ironwood-wallet-mempool/v1\0");
    let mut transactions = Vec::new();
    for txid in &txids {
        let reply = rpc("getrawtransaction", json!([txid, 0]))?;
        let Value::String(mut raw) = reply else {
            eyre::bail!("node did not return a raw mempool transaction");
        };
        ensure!(
            !raw.is_empty() && raw.len() % 2 == 0 && raw.len() / 2 <= 64 * 1024 * 1024 - total,
            "invalid raw mempool transaction or mempool exceeds 64 MiB"
        );
        let bytes =
            hex::decode(&raw).map_err(|_| eyre::eyre!("invalid raw mempool transaction"))?;
        total += bytes.len();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(&bytes);
        raw.make_ascii_lowercase();
        transactions.push(Transaction {
            raw_transaction_hex: raw,
            txid,
        });
    }
    let bytes = serde_json::to_vec(&Payload {
        schema_version: 1,
        transactions: &transactions,
    })?;
    ensure!(
        bytes.len() <= 129 * 1024 * 1024,
        "mempool JSON exceeds backend bound"
    );
    Ok(Mempool {
        bytes,
        digest: hex::encode(digest.finalize()),
        txids,
    })
}

impl Mempool {
    pub fn recheck(&self, rpc: &mut dyn FnMut(&str, Value) -> Result<Value>) -> Result<()> {
        ensure!(
            txids(rpc)? == self.txids,
            "mempool transaction set changed; retry with a new snapshot"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_preserves_sorted_payload_and_digest() {
        let mut requested = Vec::new();
        let pool = collect(&mut |method, params| {
            Ok(match method {
                "getrawmempool" => json!(["BB".repeat(32), "AA".repeat(32)]),
                "getrawtransaction" => {
                    requested.push(params[0].as_str().unwrap().to_owned());
                    json!(if params[0] == "aa".repeat(32) {
                        "ABCD"
                    } else {
                        "EF"
                    })
                }
                _ => panic!("unexpected RPC"),
            })
        })
        .unwrap();
        assert_eq!(requested, ["aa".repeat(32), "bb".repeat(32)]);
        let expected = json!({"schema_version":1,"transactions":[
            {"txid":"aa".repeat(32),"raw_transaction_hex":"abcd"},
            {"txid":"bb".repeat(32),"raw_transaction_hex":"ef"}
        ]});
        assert_eq!(pool.bytes, serde_json::to_vec(&expected).unwrap());
        let mut input = b"ironwood-wallet-mempool/v1\0".to_vec();
        input.extend(2u64.to_le_bytes());
        input.extend([0xab, 0xcd]);
        input.extend(1u64.to_le_bytes());
        input.push(0xef);
        assert_eq!(pool.digest, hex::encode(Sha256::digest(input)));
        pool.recheck(&mut |_, _| Ok(json!(["aa".repeat(32), "bb".repeat(32)])))
            .unwrap();
        assert!(pool.recheck(&mut |_, _| Ok(json!([]))).is_err());
        assert!(collect(&mut |_, _| Ok(json!(["AA".repeat(32), "aa".repeat(32)]))).is_err());
    }
}
