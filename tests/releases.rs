//! Synthetic local signing material only; no network or external keys.
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256};
use zdn::releases::{self, Catalog};

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}

fn catalog() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "apiVersion": releases::API_VERSION,
        "releases": {
            "v0.2.0-rc.1": {
                "location": {"kind":"file", "path":"v0.2.0-rc.1/package.json"},
                "sha256": "a".repeat(64)
            },
            "candidate_2026-10-19": {
                "location": {"kind":"https", "url":"https://example.invalid/package.json"},
                "sha256": "b".repeat(64)
            }
        }
    }))
    .unwrap()
}

#[test]
fn signatures_bind_raw_bytes_and_only_explicit_trusted_keys() {
    let bytes = catalog();
    let signer = key(1);
    let other = key(2);
    let signature = releases::sign(&bytes, &signer).unwrap();
    let verified =
        releases::verify(&bytes, &signature, &[public(&other), public(&signer)]).unwrap();
    assert_eq!(verified.signer(), &public(&signer));
    assert_eq!(verified.sha256(), hex::encode(Sha256::digest(&bytes)));
    assert!(verified.catalog().releases.contains_key("v0.2.0-rc.1"));
    assert!(verified
        .catalog()
        .releases
        .contains_key("candidate_2026-10-19"));
    assert!(releases::verify(&bytes, &signature, &[]).is_err());
    assert!(releases::verify(&bytes, &signature, &[public(&other)]).is_err());
    let mut reformatted = bytes.clone();
    reformatted.push(b'\n');
    assert!(Catalog::from_json(&reformatted).is_ok());
    assert!(releases::verify(&reformatted, &signature, &[public(&signer)]).is_err());
    let mut altered = signature;
    altered[17] ^= 1;
    assert!(releases::verify(&bytes, &altered, &[public(&signer)]).is_err());
    for length in [0, 63, 65] {
        assert!(releases::verify(&bytes, &vec![0; length], &[public(&signer)]).is_err());
    }
}

#[test]
fn signed_duplicate_identifiers_are_rejected_not_last_wins() {
    let entry = json!({"location":{"kind":"file","path":"package.json"},"sha256":"a".repeat(64)});
    let different = json!({"location":{"kind":"file","path":"other.json"},"sha256":"b".repeat(64)});
    // Escaped spelling decodes to the same identifier as the first key.
    let bytes = format!(
        r#"{{"apiVersion":"{}","releases":{{"v0.2.0-rc.1":{},"\u00760.2.0-rc.1":{}}}}}"#,
        releases::API_VERSION,
        entry,
        different
    );
    let signer = key(1);
    // Bypass the preparation API to model an externally signed hostile catalog.
    let signature = signer.sign(bytes.as_bytes());
    let error =
        releases::verify(bytes.as_bytes(), signature.as_ref(), &[public(&signer)]).unwrap_err();
    assert!(format!("{error:#}").contains("duplicate release identifier"));
    assert!(releases::sign(bytes.as_bytes(), &signer).is_err());
}

#[test]
fn signed_catalogs_still_require_strict_schemas_pins_ids_and_locations() {
    let base: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
    let signer = key(3);
    let mut invalid = Vec::new();
    let mut value = base.clone();
    value["extra"] = json!(true);
    invalid.push(value);
    let mut value = base.clone();
    value["apiVersion"] = json!("zdn-release-catalog/v99");
    invalid.push(value);
    for id in [
        "",
        "latest",
        "stable",
        "nightly",
        "main",
        "master",
        "v1/escape",
        "v1+build",
        "v1.*",
        " v1",
        &"v".repeat(129),
    ] {
        let mut value = base.clone();
        value["releases"] = json!({id: base["releases"]["v0.2.0-rc.1"].clone()});
        invalid.push(value);
    }
    for location in [
        json!({"kind":"file","path":"../package.json"}),
        json!({"kind":"file","path":"/package.json"}),
        json!({"kind":"file","path":"a//package.json"}),
        json!({"kind":"https","url":"http://127.0.0.1:1234/package.json"}),
        json!({"kind":"https","url":"https://user@example.invalid/package.json"}),
        json!({"kind":"https","url":"https://example.invalid/package.json#fragment"}),
        json!({"kind":"file","path":"package.json","executable":true}),
    ] {
        let mut value = base.clone();
        value["releases"]["v0.2.0-rc.1"]["location"] = location;
        invalid.push(value);
    }
    for pin in ["A".repeat(64), "a".repeat(63), "z".repeat(64)] {
        let mut value = base.clone();
        value["releases"]["v0.2.0-rc.1"]["sha256"] = json!(pin);
        invalid.push(value);
    }
    let mut empty = base;
    empty["releases"] = json!({});
    invalid.push(empty);
    for value in invalid {
        let bytes = serde_json::to_vec(&value).unwrap();
        let signature = signer.sign(&bytes);
        assert!(
            releases::verify(&bytes, signature.as_ref(), &[public(&signer)]).is_err(),
            "{value}"
        );
        assert!(releases::sign(&bytes, &signer).is_err());
    }
}

#[test]
fn raw_catalog_bound_is_inclusive_and_checked_before_authentication_or_decoding() {
    let signer = key(4);
    let mut bytes = catalog();
    bytes.resize(releases::MAX_CATALOG_BYTES as usize, b' ');
    let signature = releases::sign(&bytes, &signer).unwrap();
    releases::verify(&bytes, &signature, &[public(&signer)]).unwrap();
    bytes.push(b' ');
    assert!(releases::sign(&bytes, &signer)
        .unwrap_err()
        .to_string()
        .contains("too large"));
    assert!(releases::verify(&bytes, &signature, &[public(&signer)])
        .unwrap_err()
        .to_string()
        .contains("too large"));
    let malformed = b"not JSON";
    assert!(releases::verify(malformed, &[0; 64], &[public(&signer)])
        .unwrap_err()
        .to_string()
        .contains("signature"));
    let signature = signer.sign(malformed);
    assert!(
        releases::verify(malformed, signature.as_ref(), &[public(&signer)])
            .unwrap_err()
            .to_string()
            .contains("decode release catalog")
    );
}
