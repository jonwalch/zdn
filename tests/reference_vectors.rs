//! Independent synthetic format references, not node/consensus qualification.
//!
//! Replaces the three Python stdlib generators. Do not import zdn's codecs,
//! normalization, bs58, or sha2 here: the checked-in outputs remain independent
//! of production encoding. ring supplies a separate SHA-256 implementation.

use ring::digest::{digest, SHA256};
use serde::Serialize;
use serde_json::{json, Value};
use std::{fs, path::Path};

#[derive(Serialize)]
struct ScriptAddress {
    #[serde(rename = "scriptHash")]
    script_hash: String,
    address: String,
}

#[derive(Serialize)]
struct Difficulty {
    compact: &'static str,
    expanded: String,
}

#[derive(Serialize)]
struct NodeVectors {
    p2sh: Vec<ScriptAddress>,
    difficulty: Vec<Difficulty>,
}

#[derive(Serialize)]
struct AcceptedAddress {
    kind: &'static str,
    hash: String,
    address: String,
}

#[derive(Serialize)]
struct RejectedAddress {
    reason: &'static str,
    address: String,
}

#[derive(Serialize)]
struct RuntimeVectors {
    accepted: Vec<AcceptedAddress>,
    rejected: Vec<RejectedAddress>,
}

fn address(version: &[u8], payload: &[u8]) -> String {
    let mut raw = [version, payload].concat();
    let first = digest(&SHA256, &raw);
    let second = digest(&SHA256, first.as_ref());
    raw.extend_from_slice(&second.as_ref()[..4]);

    // Long division in base 256, independent of production's bs58 encoder.
    let zeros = raw.iter().take_while(|&&byte| byte == 0).count();
    let mut digits = Vec::new();
    while raw.iter().any(|&byte| byte != 0) {
        let mut remainder = 0_u16;
        for byte in &mut raw {
            let value = remainder * 256 + u16::from(*byte);
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }
        digits.push(
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[remainder as usize],
        );
    }
    let mut encoded = "1".repeat(zeros);
    encoded.extend(digits.into_iter().rev().map(char::from));
    encoded
}

fn expanded(compact: &str) -> String {
    let bits = u32::from_str_radix(compact, 16).unwrap();
    let exponent = (bits >> 24) as i32;
    let mut target = [0_u8; 32];
    // Place the three coefficient bytes at their base-256 powers. Negative
    // powers truncate, like the original Python integer division. These fixed
    // vectors describe encoding only, not general compact-target validation.
    for (index, byte) in bits.to_le_bytes()[..3].iter().copied().enumerate() {
        let power = exponent - 3 + index as i32;
        if byte != 0 && power >= 0 {
            assert!(power < 32, "reference target exceeds 256 bits");
            target[31 - power as usize] = byte;
        }
    }
    format!("0x{}", hex::encode(target))
}

fn pretty(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    // This fixture-specific default is intentionally independent of production
    // normalization. serde_json's default map sorts keys recursively; no zdn
    // manifest types or fingerprint implementation are used.
    let mut manifest: Value =
        serde_json::from_str(include_str!("fixtures/chain-manifest/valid.json")).unwrap();
    assert_eq!(manifest["checkpoints"], json!([]));
    manifest["checkpoints"] = json!([{"height": 0, "hash": manifest["genesis"]["hash"]}]);
    let canonical = serde_json::to_vec(&manifest).unwrap();
    let prefixed = [b"zdn-consensus/v1alpha1\0".as_slice(), &canonical].concat();
    let fingerprint = format!("{}\n", hex::encode(digest(&SHA256, &prefixed).as_ref()));

    let node = NodeVectors {
        p2sh: [
            vec![0; 20],
            (0..20).collect(),
            vec![0x12; 20],
            vec![0xff; 20],
        ]
        .iter()
        .map(|payload| ScriptAddress {
            script_hash: hex::encode(payload),
            address: address(&[0x1c, 0xba], payload),
        })
        .collect(),
        difficulty: [
            "01010000", "017f0000", "02008000", "027fff00", "03008000", "037fffff", "1f07ffff",
            "20008000", "207fffff", "21008000", "2100ffff",
        ]
        .into_iter()
        .map(|compact| Difficulty {
            compact,
            expanded: expanded(compact),
        })
        .collect(),
    };

    // Network versions match zakura-protocol 2.2.0 constants, as in the
    // original generators. Payloads are synthetic hashes, never wallet keys.
    let mut runtime = RuntimeVectors {
        accepted: Vec::new(),
        rejected: Vec::new(),
    };
    for (kind, version) in [("p2pkh", [0x1d, 0x25]), ("p2sh", [0x1c, 0xba])] {
        for payload in [vec![0; 20], (0..20).collect(), vec![0xff; 20]] {
            runtime.accepted.push(AcceptedAddress {
                kind,
                hash: hex::encode(&payload),
                address: address(&version, &payload),
            });
        }
    }
    for (reason, version, length) in [
        ("mainnet p2pkh", &[0x1c, 0xb8][..], 20),
        ("mainnet p2sh", &[0x1c, 0xbd][..], 20),
        ("unknown version", &[0x1c, 0xbb][..], 20),
        ("short p2pkh", &[0x1d, 0x25][..], 19),
        ("long p2pkh", &[0x1d, 0x25][..], 21),
        ("short p2sh", &[0x1c, 0xba][..], 19),
        ("long p2sh", &[0x1c, 0xba][..], 21),
        ("bitcoin p2pkh", &[0x00][..], 20),
    ] {
        runtime.rejected.push(RejectedAddress {
            reason,
            address: address(version, &(0..length).collect::<Vec<_>>()),
        });
    }

    vec![
        ("chain-manifest/canonical.json", canonical),
        ("chain-manifest/sha256.txt", fingerprint.into_bytes()),
        ("node-config/encoding-vectors.json", pretty(&node)),
        ("runtime-config/addresses.json", pretty(&runtime)),
    ]
}

#[test]
fn checked_in_vectors_match_independent_references() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, expected) in vectors() {
        assert_eq!(fs::read(fixtures.join(name)).unwrap(), expected, "{name}");
    }
}

/// Explicit developer tool; ordinary tests must never rewrite their expectations.
#[test]
#[ignore = "rewrites reference fixtures; run explicitly to regenerate"]
fn regenerate() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, bytes) in vectors() {
        fs::write(fixtures.join(name), bytes).unwrap();
    }
}
