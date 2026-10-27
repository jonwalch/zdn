//! Synthetic offline contract tests. None of these fixtures is a qualified chain.

use serde_json::{json, Value};
use zdn::chain::manifest::ConsensusManifest;

const INPUT: &str = include_str!("fixtures/chain-manifest/valid.json");
const CANONICAL_JSON: &[u8] = include_bytes!("fixtures/chain-manifest/canonical.json");
const EXPECTED_SHA256: &str = include_str!("fixtures/chain-manifest/sha256.txt");
const UPGRADES: &[&str] = &[
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
];

fn input() -> Value {
    serde_json::from_str(INPUT).unwrap()
}

fn manifest(value: &Value) -> ConsensusManifest {
    serde_json::from_value(value.clone()).unwrap()
}

fn fingerprint(value: &Value) -> String {
    manifest(value).fingerprint().unwrap()
}

fn set(value: &mut Value, path: &str, replacement: Value) {
    *value
        .pointer_mut(path)
        .unwrap_or_else(|| panic!("fixture has no field {path}")) = replacement;
}

fn remove(value: &mut Value, path: &str) {
    let (parent, key) = path.rsplit_once('/').unwrap();
    assert!(value
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(key)
        .is_some());
}

fn assert_invalid(value: &Value, case: &str) {
    if let Ok(manifest) = serde_json::from_value::<ConsensusManifest>(value.clone()) {
        assert!(
            manifest.validate().is_err(),
            "accepted invalid case: {case}"
        );
        assert!(
            manifest.canonical_bytes().is_err(),
            "canonicalized invalid case: {case}"
        );
        assert!(
            manifest.fingerprint().is_err(),
            "fingerprinted invalid case: {case}"
        );
    }
}

fn reverse_object_order(value: &Value) -> String {
    match value {
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .rev()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).unwrap(),
                    reverse_object_order(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(reverse_object_order)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

fn block(height: u32, hash: &str) -> Value {
    json!({
        "height": height,
        "hash": hash.repeat(32),
        "bytesSha256": format!("{height:064x}"),
        "bytesLength": 100
    })
}

fn seeded() -> Value {
    let mut value = input();
    value["seedBlocks"] = json!([block(1, "12"), block(2, "34")]);
    value["checkpoints"] = json!([
        {"height": 0, "hash": value["genesis"]["hash"]},
        {"height": 2, "hash": "34".repeat(32)}
    ]);
    value
}

fn future_slh() -> Value {
    let mut value = seeded();
    value["upgrades"]["NU7"] = json!(3);
    value["subsidy"]["initialNsmValueBalance"] = json!(0);
    value["experimentalSlh"] = json!({
        "profile": "custom-testnet-slh-v1",
        "contract": "slh-dsa-b-128s-v1",
        "activationHeight": 4,
        "transactionChecks": 16,
        "blockChecks": 64
    });
    value
}

fn funded() -> Value {
    let mut value = input();
    value["subsidy"]["fundingStreams"] = json!([
        {
            "startHeight": 1,
            "endHeight": 4,
            "recipients": [
                {"receiver": "ecc", "numerator": 7, "scriptHashes": ["ab".repeat(20), "bc".repeat(20)]},
                {"receiver": "zcash-foundation", "numerator": 5, "scriptHashes": ["cd".repeat(20)]},
                {"receiver": "deferred", "numerator": 8, "scriptHashes": []}
            ]
        },
        {
            "startHeight": 5,
            "endHeight": 8,
            "recipients": [
                {"receiver": "major-grants", "numerator": 20, "scriptHashes": ["ef".repeat(20)]}
            ]
        }
    ]);
    value["subsidy"]["lockboxDisbursements"] = json!([
        {"scriptHash": "ab".repeat(20), "amount": 1000},
        {"scriptHash": "cd".repeat(20), "amount": 2000}
    ]);
    value
}

#[test]
fn fixed_canonical_bytes_and_digest_match_an_independent_python_vector() {
    let manifest = manifest(&input());
    manifest.validate().unwrap();
    let mut expected = b"zdn-consensus/v1alpha1\0".to_vec();
    expected.extend_from_slice(CANONICAL_JSON);
    assert_eq!(manifest.canonical_bytes().unwrap(), expected);
    assert_eq!(manifest.fingerprint().unwrap(), EXPECTED_SHA256.trim());
}

#[test]
fn json_order_whitespace_hex_case_and_explicit_defaults_have_one_identity() {
    let value = input();
    let canonical = manifest(&value).canonical_bytes().unwrap();
    let reordered = reverse_object_order(&value);
    assert_ne!(reordered, serde_json::to_string(&value).unwrap());
    assert_eq!(
        serde_json::from_str::<ConsensusManifest>(&format!("\n  {reordered}\n"))
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        canonical
    );

    let mut uppercase = value.clone();
    for path in [
        "/networkMagic",
        "/genesis/hash",
        "/genesis/bytesSha256",
        "/difficulty/targetDifficultyLimitCompact",
    ] {
        let upper = uppercase
            .pointer(path)
            .unwrap()
            .as_str()
            .unwrap()
            .to_uppercase();
        set(&mut uppercase, path, json!(upper));
    }
    assert_eq!(manifest(&uppercase).canonical_bytes().unwrap(), canonical);

    let mut implicit = value;
    for path in [
        "/seedBlocks",
        "/checkpoints",
        "/experimentalSlh",
        "/upgrades/NU7",
        "/subsidy/fundingStreams",
        "/subsidy/initialNsmValueBalance",
        "/subsidy/allowUnshieldedCoinbaseSpends",
    ] {
        remove(&mut implicit, path);
    }
    assert_eq!(manifest(&implicit).canonical_bytes().unwrap(), canonical);

    let mut nullable = input();
    nullable["temporaryOrchardDisablingHeight"] = Value::Null;
    let explicit_null = fingerprint(&nullable);
    remove(&mut nullable, "/temporaryOrchardDisablingHeight");
    assert_eq!(fingerprint(&nullable), explicit_null);
}

#[test]
fn normalization_is_idempotent_and_serialized_round_trips_keep_the_fingerprint() {
    for value in [input(), seeded(), future_slh(), funded()] {
        let original = manifest(&value);
        let normalized = original.normalized().unwrap();
        assert_eq!(
            serde_json::to_value(normalized.normalized().unwrap()).unwrap(),
            serde_json::to_value(&normalized).unwrap()
        );
        let round_trip: ConsensusManifest =
            serde_json::from_slice(&serde_json::to_vec(&normalized).unwrap()).unwrap();
        assert_eq!(
            round_trip.fingerprint().unwrap(),
            original.fingerprint().unwrap()
        );
        assert_eq!(
            round_trip.canonical_bytes().unwrap(),
            original.canonical_bytes().unwrap()
        );
    }
}

#[test]
fn every_required_consensus_field_must_be_present() {
    let mut required = vec![
        "/apiVersion".to_string(),
        "/ruleset".into(),
        "/networkKind".into(),
        "/networkMagic".into(),
        "/genesis".into(),
        "/genesis/height".into(),
        "/genesis/hash".into(),
        "/genesis/bytesSha256".into(),
        "/genesis/bytesLength".into(),
        "/upgrades".into(),
        "/subsidy".into(),
        "/subsidy/slowStartInterval".into(),
        "/subsidy/preBlossomHalvingInterval".into(),
        "/subsidy/lockboxDisbursements".into(),
        "/difficulty".into(),
        "/difficulty/targetDifficultyLimitCompact".into(),
        "/difficulty/proofOfWork".into(),
        "/difficulty/maxBlockTimeStartHeight".into(),
    ];
    required.extend(
        UPGRADES
            .iter()
            .map(|upgrade| format!("/upgrades/{upgrade}")),
    );
    for path in required {
        let mut missing = input();
        remove(&mut missing, &path);
        assert_invalid(&missing, &format!("missing {path}"));
    }
}

#[test]
fn unknown_fields_and_deployment_metadata_do_not_enter_the_consensus_contract() {
    for path in [
        "",
        "/genesis",
        "/upgrades",
        "/subsidy",
        "/difficulty",
        "/seedBlocks/0",
        "/checkpoints/0",
        "/experimentalSlh",
    ] {
        let mut value = future_slh();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknownFutureConsensusRule".into(), json!(true));
        assert_invalid(&value, &format!("unknown field at {path}"));
    }
    for field in [
        "name",
        "deploymentId",
        "peers",
        "ports",
        "path",
        "visibility",
        "interval",
        "nodes",
        "producer",
        "imageDigest",
        "nodeVersion",
    ] {
        let mut value = input();
        value[field] = json!("deployment-only");
        assert_invalid(&value, field);
    }
}

#[test]
fn changed_genesis_and_consensus_parameters_change_identity() {
    let value = input();
    let original = fingerprint(&value);
    for (path, replacement) in [
        ("/networkMagic", json!("b1c2d3e4")),
        ("/genesis/hash", json!("ac".repeat(32))),
        ("/genesis/bytesSha256", json!("ce".repeat(32))),
        ("/genesis/bytesLength", json!(101)),
        ("/subsidy/slowStartInterval", json!(20)),
        ("/subsidy/preBlossomHalvingInterval", json!(840001)),
        ("/subsidy/initialNsmValueBalance", json!(1)),
        ("/subsidy/allowUnshieldedCoinbaseSpends", json!(true)),
        (
            "/difficulty/targetDifficultyLimitCompact",
            json!("1f08ffff"),
        ),
        ("/difficulty/proofOfWork", json!("equihash")),
        ("/difficulty/maxBlockTimeStartHeight", json!(653607)),
        ("/temporaryOrchardDisablingHeight", json!(4048501)),
        ("/temporaryOrchardDisablingHeight", Value::Null),
    ] {
        let mut changed = value.clone();
        set(&mut changed, path, replacement);
        assert_ne!(
            fingerprint(&changed),
            original,
            "ignored consensus field {path}"
        );
    }
}

#[test]
fn each_upgrade_height_changes_identity_without_depending_on_map_order() {
    let mut value = input();
    for (index, upgrade) in UPGRADES.iter().enumerate() {
        value["upgrades"][upgrade] = json!((index + 1) * 10);
    }
    value["checkpoints"] = json!([
        {"height": 0, "hash": value["genesis"]["hash"]},
        {"height": 1000, "hash": "56".repeat(32)}
    ]);
    let original = fingerprint(&value);
    for (index, upgrade) in UPGRADES.iter().enumerate() {
        let mut changed = value.clone();
        changed["upgrades"][upgrade] = json!((index + 1) * 10 + 1);
        assert_ne!(fingerprint(&changed), original, "ignored upgrade {upgrade}");
    }
    value["upgrades"]["NU7"] = json!(120);
    value["subsidy"]["initialNsmValueBalance"] = json!(0);
    let original = fingerprint(&value);
    value["upgrades"]["NU7"] = json!(121);
    assert_ne!(fingerprint(&value), original);
}

#[test]
fn seed_and_checkpoint_order_normalize_but_each_saved_identity_matters() {
    let value = seeded();
    let original = fingerprint(&value);
    let mut reversed = value.clone();
    reversed["seedBlocks"].as_array_mut().unwrap().reverse();
    reversed["checkpoints"].as_array_mut().unwrap().reverse();
    assert_eq!(fingerprint(&reversed), original);

    for (path, replacement) in [
        ("/seedBlocks/0/hash", json!("13".repeat(32))),
        ("/seedBlocks/0/bytesSha256", json!("ae".repeat(32))),
        ("/seedBlocks/0/bytesLength", json!(101)),
    ] {
        let mut changed = value.clone();
        set(&mut changed, path, replacement);
        assert_ne!(fingerprint(&changed), original, "ignored seed field {path}");
    }
    let mut changed = value.clone();
    changed["checkpoints"].as_array_mut().unwrap().push(json!({
        "height": 3,
        "hash": "78".repeat(32)
    }));
    let additional_checkpoint = fingerprint(&changed);
    assert_ne!(additional_checkpoint, original);
    changed["checkpoints"][2]["hash"] = json!("79".repeat(32));
    let changed_checkpoint_hash = fingerprint(&changed);
    assert_ne!(changed_checkpoint_hash, additional_checkpoint);
    changed["checkpoints"][2]["height"] = json!(4);
    assert_ne!(fingerprint(&changed), changed_checkpoint_hash);
}

#[test]
fn funding_order_normalizes_except_for_the_address_period_schedule() {
    let value = funded();
    let original = fingerprint(&value);
    let mut reordered = value.clone();
    reordered["subsidy"]["fundingStreams"][0]["recipients"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["subsidy"]["fundingStreams"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["subsidy"]["lockboxDisbursements"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(fingerprint(&reordered), original);

    let mut addresses_reordered = value;
    addresses_reordered["subsidy"]["fundingStreams"][0]["recipients"][0]["scriptHashes"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_ne!(fingerprint(&addresses_reordered), original);
}

#[test]
fn funding_recipients_schedules_and_lockbox_payments_are_consensus_inputs() {
    let value = funded();
    let original = fingerprint(&value);
    for (path, replacement) in [
        ("/subsidy/fundingStreams/0/startHeight", json!(2)),
        ("/subsidy/fundingStreams/0/endHeight", json!(3)),
        (
            "/subsidy/fundingStreams/0/recipients/0/receiver",
            json!("major-grants"),
        ),
        ("/subsidy/fundingStreams/0/recipients/0/numerator", json!(6)),
        (
            "/subsidy/fundingStreams/0/recipients/0/scriptHashes/0",
            json!("ac".repeat(20)),
        ),
        (
            "/subsidy/lockboxDisbursements/0/scriptHash",
            json!("ac".repeat(20)),
        ),
        ("/subsidy/lockboxDisbursements/0/amount", json!(1001)),
    ] {
        let mut changed = value.clone();
        set(&mut changed, path, replacement);
        assert_ne!(
            fingerprint(&changed),
            original,
            "ignored funding rule {path}"
        );
    }
    let mut duplicate = value;
    let payment = duplicate["subsidy"]["lockboxDisbursements"][0].clone();
    duplicate["subsidy"]["lockboxDisbursements"]
        .as_array_mut()
        .unwrap()
        .push(payment);
    assert_ne!(
        fingerprint(&duplicate),
        original,
        "deduplicating payments changes amounts"
    );
}

#[test]
fn seed_checkpoint_funding_and_lockbox_hex_case_is_not_a_rule_change() {
    let mut value = funded();
    let seeds = seeded();
    value["seedBlocks"] = seeds["seedBlocks"].clone();
    value["checkpoints"] = seeds["checkpoints"].clone();
    value["seedBlocks"][0]["hash"] = json!("ae".repeat(32));
    value["seedBlocks"][0]["bytesSha256"] = json!("be".repeat(32));
    value["seedBlocks"][1]["hash"] = json!("ce".repeat(32));
    value["seedBlocks"][1]["bytesSha256"] = json!("de".repeat(32));
    value["checkpoints"][1]["hash"] = json!("ce".repeat(32));
    let original = fingerprint(&value);
    for path in [
        "/seedBlocks/0/hash",
        "/seedBlocks/0/bytesSha256",
        "/seedBlocks/1/hash",
        "/seedBlocks/1/bytesSha256",
        "/checkpoints/0/hash",
        "/checkpoints/1/hash",
        "/subsidy/fundingStreams/0/recipients/0/scriptHashes/0",
        "/subsidy/fundingStreams/0/recipients/0/scriptHashes/1",
        "/subsidy/fundingStreams/0/recipients/1/scriptHashes/0",
        "/subsidy/fundingStreams/1/recipients/0/scriptHashes/0",
        "/subsidy/lockboxDisbursements/0/scriptHash",
        "/subsidy/lockboxDisbursements/1/scriptHash",
    ] {
        let uppercase = value
            .pointer(path)
            .unwrap()
            .as_str()
            .unwrap()
            .to_uppercase();
        set(&mut value, path, json!(uppercase));
    }
    assert_eq!(fingerprint(&value), original);
}

#[test]
fn invalid_funding_and_lockbox_rules_are_rejected() {
    for (path, invalid) in [
        ("/subsidy/lockboxDisbursements", json!([])),
        ("/subsidy/fundingStreams/0/startHeight", json!(4)),
        ("/subsidy/fundingStreams/0/endHeight", json!(1)),
        ("/subsidy/fundingStreams/1/startHeight", json!(3)),
        (
            "/subsidy/fundingStreams/0/recipients/0/receiver",
            json!("unknown"),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/0/receiver",
            json!("zcash-foundation"),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/0/numerator",
            json!(101),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/0/numerator",
            json!(99),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/0/scriptHashes",
            json!([]),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/0/scriptHashes/0",
            json!("ab".repeat(19)),
        ),
        (
            "/subsidy/fundingStreams/0/recipients/2/scriptHashes",
            json!(["ab".repeat(20)]),
        ),
        (
            "/subsidy/lockboxDisbursements/0/scriptHash",
            json!("ab".repeat(21)),
        ),
        (
            "/subsidy/lockboxDisbursements/0/amount",
            json!(2_100_000_000_000_001_u64),
        ),
    ] {
        let mut value = funded();
        set(&mut value, path, invalid.clone());
        assert_invalid(&value, &format!("{path} = {invalid}"));
    }
    for path in [
        "/subsidy/fundingStreams/0",
        "/subsidy/fundingStreams/0/recipients/0",
        "/subsidy/lockboxDisbursements/0",
    ] {
        let mut value = funded();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(true));
        assert_invalid(&value, path);
    }
    let mut excess_sum = funded();
    excess_sum["subsidy"]["lockboxDisbursements"][0]["amount"] = json!(2_100_000_000_000_000_u64);
    assert_invalid(&excess_sum, "lockbox total cannot exceed MAX_MONEY");
}

#[test]
fn consensus_arithmetic_bounds_are_checked_before_fingerprinting() {
    for (path, invalid) in [
        ("/genesis/bytesLength", json!(2_000_001)),
        ("/subsidy/slowStartInterval", json!(2_147_483_648_u64)),
        ("/subsidy/preBlossomHalvingInterval", json!(0)),
        ("/subsidy/preBlossomHalvingInterval", json!(1_073_741_824)),
        ("/subsidy/preBlossomHalvingInterval", json!(u64::MAX)),
        (
            "/subsidy/initialNsmValueBalance",
            json!(2_100_000_000_000_001_u64),
        ),
        (
            "/difficulty/maxBlockTimeStartHeight",
            json!(2_147_483_648_u64),
        ),
        ("/temporaryOrchardDisablingHeight", json!(2_147_483_648_u64)),
        ("/upgrades/NU6.3", json!(2_147_483_648_u64)),
        ("/genesis/bytesLength", json!(1.5)),
    ] {
        let mut value = input();
        set(&mut value, path, invalid.clone());
        assert_invalid(&value, &format!("{path} = {invalid}"));
    }
    for path in ["/seedBlocks/0/height", "/checkpoints/1/height"] {
        let mut value = seeded();
        set(&mut value, path, json!(2_147_483_648_u64));
        assert_invalid(&value, path);
    }
    let mut overflow = future_slh();
    overflow["upgrades"]["NU7"] = json!(2_147_483_647_u64);
    overflow["experimentalSlh"]["activationHeight"] = json!(2_147_483_648_u64);
    assert_invalid(
        &overflow,
        "SLH cannot follow NU7 above the maximum supported height",
    );
}

#[test]
fn compact_difficulty_accepts_only_positive_canonical_nonoverflowing_targets() {
    for target in ["01010000", "02008000", "1d00ffff", "1f07ffff", "2100ffff"] {
        let mut value = input();
        value["difficulty"]["targetDifficultyLimitCompact"] = json!(target);
        manifest(&value)
            .validate()
            .unwrap_or_else(|error| panic!("rejected {target}: {error}"));
    }
    for target in [
        "00000000",
        "01800000",
        "1d80ffff",
        "01010001",
        "02000100",
        "21010000",
        "22000100",
        "23000001",
        "ffffffff",
        "1f07fff",
        "1f07ffff00",
        "1g07ffff",
    ] {
        let mut value = input();
        value["difficulty"]["targetDifficultyLimitCompact"] = json!(target);
        assert_invalid(&value, target);
    }
}

#[test]
fn invalid_identities_and_reserved_networks_cannot_be_fingerprinted() {
    for (path, invalid) in [
        ("/apiVersion", json!("zdn-consensus/v2")),
        ("/ruleset", json!("zakura-configured-testnet/v2")),
        ("/networkKind", json!("mainnet")),
        ("/networkKind", json!("testnet")),
        ("/networkKind", json!("regtest")),
        ("/networkMagic", json!("24e92764")),
        ("/networkMagic", json!("fa1af9bf")),
        ("/networkMagic", json!("aae83f5f")),
        ("/networkMagic", json!("not-hex!")),
        ("/networkMagic", json!("a1b2c3")),
        ("/genesis/height", json!(1)),
        ("/genesis/hash", json!("00".repeat(32))),
        ("/genesis/hash", json!("a".repeat(63))),
        ("/genesis/hash", json!("g".repeat(64))),
        (
            "/genesis/bytesSha256",
            json!("0x".to_owned() + &"ab".repeat(32)),
        ),
        ("/genesis/bytesLength", json!(0)),
        ("/difficulty/proofOfWork", json!("automatic")),
    ] {
        let mut value = input();
        set(&mut value, path, invalid.clone());
        assert_invalid(&value, &format!("{path} = {invalid}"));
    }
}

#[test]
fn gaps_duplicates_or_conflicting_saved_chain_inputs_are_rejected() {
    for (path, invalid) in [
        ("/seedBlocks/0/height", json!(0)),
        ("/seedBlocks/0/height", json!(2)),
        ("/seedBlocks/1/height", json!(3)),
        ("/seedBlocks/1/hash", json!("12".repeat(32))),
        ("/seedBlocks/1/bytesSha256", json!(format!("{:064x}", 1))),
        ("/checkpoints/0/hash", json!("ac".repeat(32))),
        ("/checkpoints/1/hash", json!("35".repeat(32))),
        ("/checkpoints/1/height", json!(0)),
        ("/checkpoints/1/height", json!(3)),
    ] {
        let mut value = seeded();
        set(&mut value, path, invalid.clone());
        assert_invalid(&value, &format!("{path} = {invalid}"));
    }
    let mut value = seeded();
    value["checkpoints"].as_array_mut().unwrap().remove(0);
    assert_invalid(&value, "missing genesis checkpoint");
}

#[test]
fn nonreserved_zero_magic_and_empty_funding_recipients_remain_structurally_valid() {
    let mut value = input();
    value["networkMagic"] = json!("00000000");
    manifest(&value).validate().unwrap();
    let mut no_payments = funded();
    no_payments["subsidy"]["fundingStreams"][0]["recipients"] = json!([]);
    manifest(&no_payments).validate().unwrap();
}

#[test]
fn invalid_upgrade_order_and_missing_canopy_coverage_are_rejected() {
    for (path, invalid) in [
        ("/upgrades/BeforeOverwinter", json!(0)),
        ("/upgrades/Overwinter", json!(2)),
        ("/upgrades/Sapling", Value::Null),
        ("/upgrades/NU6.3", json!(-1)),
        ("/upgrades/NU6.3", json!(u64::MAX)),
    ] {
        let mut value = input();
        set(&mut value, path, invalid.clone());
        assert_invalid(&value, &format!("{path} = {invalid}"));
    }
    let mut value = input();
    for upgrade in UPGRADES {
        value["upgrades"][upgrade] = json!(10);
    }
    assert_invalid(
        &value,
        "Canopy activation lacks a checkpoint at or above height 9",
    );
}

#[test]
fn future_slh_profile_requires_complete_rules_and_strict_activation_order() {
    let value = future_slh();
    manifest(&value).validate().unwrap();
    let original = fingerprint(&value);
    let mut later = value.clone();
    later["experimentalSlh"]["activationHeight"] = json!(5);
    assert_ne!(fingerprint(&later), original);
    let mut ordinary = value.clone();
    ordinary["experimentalSlh"] = Value::Null;
    assert_ne!(fingerprint(&ordinary), original);

    for field in [
        "profile",
        "contract",
        "activationHeight",
        "transactionChecks",
        "blockChecks",
    ] {
        let mut incomplete = value.clone();
        remove(&mut incomplete, &format!("/experimentalSlh/{field}"));
        assert_invalid(&incomplete, &format!("SLH missing {field}"));
    }
    for (path, invalid) in [
        ("/experimentalSlh/profile", json!("regtest-slh-v1")),
        ("/experimentalSlh/contract", json!("slh-dsa-sha2-128s-v1")),
        ("/experimentalSlh/activationHeight", json!(0)),
        ("/experimentalSlh/activationHeight", json!(2)),
        ("/experimentalSlh/activationHeight", json!(3)),
        ("/experimentalSlh/transactionChecks", json!(0)),
        ("/experimentalSlh/transactionChecks", json!(65)),
        ("/experimentalSlh/transactionChecks", json!(15)),
        ("/experimentalSlh/blockChecks", json!(0)),
        ("/experimentalSlh/blockChecks", json!(15)),
        ("/experimentalSlh/blockChecks", json!(65)),
        ("/upgrades/NU7", Value::Null),
    ] {
        let mut invalid_value = value.clone();
        set(&mut invalid_value, path, invalid.clone());
        assert_invalid(&invalid_value, &format!("{path} = {invalid}"));
    }

    let mut checkpoint_after_activation = value;
    checkpoint_after_activation["checkpoints"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "height": 4,
            "hash": "56".repeat(32)
        }));
    assert_invalid(
        &checkpoint_after_activation,
        "SLH cannot activate at a checkpoint",
    );

    // The ordinary profile may name a supported built-in genesis. The optional
    // SLH contract requires a separately generated custom chain identity.
    let mut built_in_genesis = future_slh();
    let hash = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";
    built_in_genesis["genesis"]["hash"] = json!(hash);
    built_in_genesis["checkpoints"][0]["hash"] = json!(hash);
    assert_invalid(
        &built_in_genesis,
        "SLH cannot use built-in public Testnet genesis",
    );
    built_in_genesis["experimentalSlh"] = Value::Null;
    manifest(&built_in_genesis).validate().unwrap();
}
