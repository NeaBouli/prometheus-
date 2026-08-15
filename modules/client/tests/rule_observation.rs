use std::process::Command;

use prometheus_client::blockchain::rule_observation::{
    verify_rule_storage_observation, verify_rule_storage_observation_for_mode, MANIFEST_KIND,
    MAX_MANIFEST_JSON_BYTES, MAX_OBSERVATION_ENTRIES, MAX_OBSERVATION_JSON_BYTES, OBSERVATION_KIND,
    OBSERVATION_NETWORK_ID,
};
use prometheus_client::blockchain::rule_state::MAX_STATE_JSON_BYTES;
use prometheus_client::runtime::RuntimeMode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const UNRELATED_TXID: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const COVENANT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_COVENANT: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const SCRIPT: &str = "51";
const AMOUNT: u64 = 100_000_000;
const BLOCK_DAA: u64 = 1_000;
const MIN_MATURITY: u64 = 100;
const OBSERVED_DAA: u64 = BLOCK_DAA + MIN_MATURITY;

fn int(value: i64) -> Value {
    json!({"kind": "int", "data": value})
}

fn bytes(values: &[u8]) -> Value {
    let data: Vec<_> = values
        .iter()
        .map(|value| json!({"kind": "byte", "data": value}))
        .collect();
    json!({"kind": "array", "data": data})
}

/// One valid GH-193 accepted-state constructor document (proposal 7).
fn constructor_document() -> String {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend(0u8..32);
    serde_json::to_string(&json!([
        bytes(&[4; 32]), int(8), int(7), bytes(&[5; 32]), bytes(&[6; 32]), int(0),
        bytes(&cid), int(9_000), int(100_000), int(3), int(1), int(964_000), int(2),
        int(3), int(2), int(50_000), int(7_500), int(965_000),
        {"kind": "bool", "data": true}, int(1)
    ]))
    .unwrap()
}

fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

fn manifest_json(constructor_hash: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"kind\":\"{MANIFEST_KIND}\",\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\
\"outpoint\":{{\"transaction_id\":\"{TXID}\",\"index\":1}},\"covenant_id\":\"{COVENANT}\",\
\"script_public_key\":{{\"version\":0,\"script_hex\":\"{SCRIPT}\"}},\"amount_sompi\":{AMOUNT},\
\"block_daa_score\":{BLOCK_DAA},\"minimum_virtual_daa_maturity\":{MIN_MATURITY},\
\"constructor_json_sha256\":\"{constructor_hash}\"}}"
    )
}

fn covenant_json(covenant: Option<&str>) -> String {
    match covenant {
        Some(value) => format!("\"{value}\""),
        None => "null".to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn entry_json(
    txid: &str,
    index: u32,
    amount: u64,
    version: u16,
    script: &str,
    block_daa: u64,
    is_coinbase: bool,
    covenant: Option<&str>,
) -> String {
    format!(
        "{{\"outpoint\":{{\"transaction_id\":\"{txid}\",\"index\":{index}}},\"amount_sompi\":{amount},\
\"script_public_key\":{{\"version\":{version},\"script_hex\":\"{script}\"}},\
\"block_daa_score\":{block_daa},\"is_coinbase\":{is_coinbase},\
\"covenant_id\":{}}}",
        covenant_json(covenant)
    )
}

fn matching_entry() -> String {
    entry_json(TXID, 1, AMOUNT, 0, SCRIPT, BLOCK_DAA, false, Some(COVENANT))
}

fn unrelated_entry() -> String {
    entry_json(
        UNRELATED_TXID,
        0,
        42,
        0,
        "00",
        10,
        false,
        Some(OTHER_COVENANT),
    )
}

fn observation_json(observed_daa: u64, entries: &[String]) -> String {
    format!(
        "{{\"schema_version\":1,\"kind\":\"{OBSERVATION_KIND}\",\
\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\"observed_virtual_daa_score\":{observed_daa},\
\"entries\":[{}]}}",
        entries.join(",")
    )
}

struct Fixture {
    expected_hash: String,
    manifest: String,
    observation: String,
    constructor: String,
}

fn valid_fixture() -> Fixture {
    let constructor = constructor_document();
    let manifest = manifest_json(&sha256_hex(&constructor));
    let expected_hash = sha256_hex(&manifest);
    let observation = observation_json(OBSERVED_DAA, &[unrelated_entry(), matching_entry()]);
    Fixture {
        expected_hash,
        manifest,
        observation,
        constructor,
    }
}

fn verify(
    fixture: &Fixture,
) -> Result<
    prometheus_client::blockchain::rule_state::RuleStateMetadata,
    prometheus_client::blockchain::rule_observation::RuleObservationError,
> {
    verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &fixture.observation,
        &fixture.constructor,
    )
}

#[test]
fn valid_fixture_verifies_and_decodes() {
    let metadata = verify(&valid_fixture()).unwrap();
    assert_eq!(metadata.proposal_id(), 7);
    assert_eq!(metadata.rule_id(), "PROM-RULE-0007");
    assert!(metadata.active());
}

#[test]
fn maturity_boundary_passes_and_below_or_underflow_fails() {
    // The valid fixture sits exactly on the boundary (delta == minimum).
    let fixture = valid_fixture();
    assert!(verify(&fixture).is_ok());

    let below = Fixture {
        observation: observation_json(OBSERVED_DAA - 1, &[matching_entry()]),
        ..valid_fixture()
    };
    assert!(verify(&below).is_err());

    let underflow = Fixture {
        observation: observation_json(BLOCK_DAA - 1, &[matching_entry()]),
        ..valid_fixture()
    };
    assert!(verify(&underflow).is_err());
}

#[test]
fn zero_minimum_maturity_is_rejected() {
    let constructor = constructor_document();
    let manifest = manifest_json(&sha256_hex(&constructor)).replace(
        "\"minimum_virtual_daa_maturity\":100",
        "\"minimum_virtual_daa_maturity\":0",
    );
    let fixture = Fixture {
        expected_hash: sha256_hex(&manifest),
        manifest,
        observation: observation_json(OBSERVED_DAA, &[matching_entry()]),
        constructor,
    };
    assert!(verify(&fixture).is_err());
}

#[test]
fn wrong_expected_hash_is_rejected() {
    let fixture = valid_fixture();
    let mut bad = fixture.expected_hash.clone();
    bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
    assert!(verify_rule_storage_observation(
        &bad,
        &fixture.manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    // Wrong length, uppercase, and non-hex expected hashes are all rejected.
    for candidate in [
        fixture.expected_hash[..63].to_string(),
        fixture.expected_hash.to_uppercase(),
        "zz".repeat(32),
    ] {
        assert!(verify_rule_storage_observation(
            &candidate,
            &fixture.manifest,
            &fixture.observation,
            &fixture.constructor
        )
        .is_err());
    }
}

#[test]
fn noncanonical_manifest_is_rejected_even_with_matching_hash() {
    let fixture = valid_fixture();

    // Pretty-printed (whitespace) form of the same document.
    let value: Value = serde_json::from_str(&fixture.manifest).unwrap();
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    assert!(verify_rule_storage_observation(
        &sha256_hex(&pretty),
        &pretty,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    // Reordered keys of the same document.
    let reordered = format!(
        "{{\"kind\":\"{MANIFEST_KIND}\",\"schema_version\":1,\"network_id\":\"{OBSERVATION_NETWORK_ID}\",\
\"outpoint\":{{\"transaction_id\":\"{TXID}\",\"index\":1}},\"covenant_id\":\"{COVENANT}\",\
\"script_public_key\":{{\"version\":0,\"script_hex\":\"{SCRIPT}\"}},\"amount_sompi\":{AMOUNT},\
\"block_daa_score\":{BLOCK_DAA},\"minimum_virtual_daa_maturity\":{MIN_MATURITY},\
\"constructor_json_sha256\":\"{}\"}}",
        sha256_hex(&fixture.constructor)
    );
    assert!(verify_rule_storage_observation(
        &sha256_hex(&reordered),
        &reordered,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    // A noncanonical observation is likewise rejected.
    let pretty_observation =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&fixture.observation).unwrap())
            .unwrap();
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &pretty_observation,
        &fixture.constructor
    )
    .is_err());
}

#[test]
fn unknown_fields_are_rejected() {
    let fixture = valid_fixture();

    let manifest = fixture.manifest.replace(
        "\"schema_version\":1",
        "\"schema_version\":1,\"extra\":true",
    );
    assert!(verify_rule_storage_observation(
        &sha256_hex(&manifest),
        &manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    let observation = fixture.observation.replace(
        "\"schema_version\":1",
        "\"schema_version\":1,\"extra\":true",
    );
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());

    let entry =
        matching_entry().replace("\"is_coinbase\":false", "\"is_coinbase\":false,\"extra\":1");
    let observation = observation_json(OBSERVED_DAA, &[entry]);
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());
}

#[test]
fn oversize_documents_are_rejected_before_parse() {
    let fixture = valid_fixture();

    let padded_manifest = format!(
        "{}{}",
        fixture.manifest,
        " ".repeat(MAX_MANIFEST_JSON_BYTES)
    );
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &padded_manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    let padded_observation = format!(
        "{}{}",
        fixture.observation,
        " ".repeat(MAX_OBSERVATION_JSON_BYTES)
    );
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &padded_observation,
        &fixture.constructor
    )
    .is_err());

    let oversized_constructor = "x".repeat(MAX_STATE_JSON_BYTES + 1);
    let manifest = manifest_json(&sha256_hex(&oversized_constructor));
    assert!(verify_rule_storage_observation(
        &sha256_hex(&manifest),
        &manifest,
        &fixture.observation,
        &oversized_constructor
    )
    .is_err());
}

#[test]
fn wrong_network_ids_are_rejected() {
    for wrong in ["testnet-010", "kaspa-testnet-10", "mainnet"] {
        let constructor = constructor_document();
        let manifest = manifest_json(&sha256_hex(&constructor)).replace(
            "\"network_id\":\"testnet-10\"",
            &format!("\"network_id\":\"{wrong}\""),
        );
        let fixture = Fixture {
            expected_hash: sha256_hex(&manifest),
            manifest,
            observation: observation_json(OBSERVED_DAA, &[matching_entry()]),
            constructor,
        };
        assert!(verify(&fixture).is_err(), "manifest network {wrong}");

        let fixture = valid_fixture();
        let observation = fixture.observation.replace(
            "\"network_id\":\"testnet-10\"",
            &format!("\"network_id\":\"{wrong}\""),
        );
        assert!(
            verify_rule_storage_observation(
                &fixture.expected_hash,
                &fixture.manifest,
                &observation,
                &fixture.constructor
            )
            .is_err(),
            "observation network {wrong}"
        );
    }
}

#[test]
fn wrong_outpoint_yields_no_match() {
    let fixture = valid_fixture();
    for entry in [
        entry_json(
            UNRELATED_TXID,
            1,
            AMOUNT,
            0,
            SCRIPT,
            BLOCK_DAA,
            false,
            Some(COVENANT),
        ),
        entry_json(TXID, 0, AMOUNT, 0, SCRIPT, BLOCK_DAA, false, Some(COVENANT)),
    ] {
        let observation = observation_json(OBSERVED_DAA, &[entry]);
        assert!(verify_rule_storage_observation(
            &fixture.expected_hash,
            &fixture.manifest,
            &observation,
            &fixture.constructor
        )
        .is_err());
    }
}

#[test]
fn entry_field_mismatches_are_rejected() {
    let fixture = valid_fixture();
    let cases = [
        // Wrong script bytes.
        entry_json(TXID, 1, AMOUNT, 0, "52", BLOCK_DAA, false, Some(COVENANT)),
        // Wrong script public key version.
        entry_json(TXID, 1, AMOUNT, 1, SCRIPT, BLOCK_DAA, false, Some(COVENANT)),
        // Wrong covenant ID.
        entry_json(
            TXID,
            1,
            AMOUNT,
            0,
            SCRIPT,
            BLOCK_DAA,
            false,
            Some(OTHER_COVENANT),
        ),
        // Null covenant ID.
        entry_json(TXID, 1, AMOUNT, 0, SCRIPT, BLOCK_DAA, false, None),
        // Wrong amount.
        entry_json(
            TXID,
            1,
            AMOUNT - 1,
            0,
            SCRIPT,
            BLOCK_DAA,
            false,
            Some(COVENANT),
        ),
        // Wrong block DAA score.
        entry_json(
            TXID,
            1,
            AMOUNT,
            0,
            SCRIPT,
            BLOCK_DAA + 1,
            false,
            Some(COVENANT),
        ),
        // Coinbase entry.
        entry_json(TXID, 1, AMOUNT, 0, SCRIPT, BLOCK_DAA, true, Some(COVENANT)),
    ];
    for (index, entry) in cases.iter().enumerate() {
        let observation = observation_json(OBSERVED_DAA, std::slice::from_ref(entry));
        assert!(
            verify_rule_storage_observation(
                &fixture.expected_hash,
                &fixture.manifest,
                &observation,
                &fixture.constructor
            )
            .is_err(),
            "case {index}"
        );
    }
}

#[test]
fn zero_and_multiple_matches_are_rejected() {
    let fixture = valid_fixture();

    // Zero matches: only unrelated entries.
    let observation = observation_json(OBSERVED_DAA, &[unrelated_entry()]);
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());

    // Duplicate identical matches.
    let observation = observation_json(OBSERVED_DAA, &[matching_entry(), matching_entry()]);
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());

    // Duplicate unrelated outpoints also make the RPC-shaped set ambiguous.
    let observation = observation_json(
        OBSERVED_DAA,
        &[unrelated_entry(), unrelated_entry(), matching_entry()],
    );
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());

    // Conflicting matches on the same outpoint.
    let conflicting = entry_json(
        TXID,
        1,
        AMOUNT + 1,
        0,
        SCRIPT,
        BLOCK_DAA,
        false,
        Some(COVENANT),
    );
    let observation = observation_json(OBSERVED_DAA, &[matching_entry(), conflicting]);
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());
}

#[test]
fn empty_and_oversized_entry_lists_are_rejected() {
    let fixture = valid_fixture();

    let observation = observation_json(OBSERVED_DAA, &[]);
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());

    let entries: Vec<String> = (0..=MAX_OBSERVATION_ENTRIES)
        .map(|index| {
            entry_json(
                UNRELATED_TXID,
                index as u32,
                42,
                0,
                "00",
                10,
                false,
                Some(OTHER_COVENANT),
            )
        })
        .collect();
    let observation = observation_json(OBSERVED_DAA, &entries);
    assert!(
        observation.len() <= MAX_OBSERVATION_JSON_BYTES,
        "entry-count overflow must be tested below the byte cap"
    );
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &observation,
        &fixture.constructor
    )
    .is_err());
}

#[test]
fn constructor_hash_is_checked_before_decode() {
    let fixture = valid_fixture();

    // A fully decodable constructor with the wrong bytes fails on the hash
    // binding before any decode is attempted.
    let other = constructor_document().replace("\"data\":9000", "\"data\":9001");
    assert!(verify_rule_storage_observation(
        &fixture.expected_hash,
        &fixture.manifest,
        &fixture.observation,
        &other
    )
    .is_err());

    // The exact bound constructor that fails GH-193 semantics also fails.
    // serde_json serializes object keys sorted, so entries are
    // `{"data":..,"kind":"int"}`; flipping the accepted status fails decode.
    let invalid = constructor_document().replacen(
        "\"data\":2,\"kind\":\"int\"",
        "\"data\":1,\"kind\":\"int\"",
        1,
    );
    assert_ne!(invalid, constructor_document());
    let manifest = manifest_json(&sha256_hex(&invalid));
    let fixture = Fixture {
        expected_hash: sha256_hex(&manifest),
        manifest,
        constructor: invalid,
        ..valid_fixture()
    };
    assert!(verify(&fixture).is_err());
}

#[test]
fn error_and_debug_output_are_redacted() {
    let err = verify_rule_storage_observation("zz", "{}", "{}", "[]").unwrap_err();
    let display = err.to_string();
    let debug = format!("{err:?}");
    for leaked in [TXID, COVENANT, SCRIPT] {
        assert!(!display.contains(leaked));
        assert!(!debug.contains(leaked));
    }
    assert_eq!(display, "invalid RuleStorage UTXO observation");
    assert_eq!(debug, "RuleObservationError");

    // The successful result's Debug never leaks outpoints, covenants, or hashes.
    let metadata = verify(&valid_fixture()).unwrap();
    let debugged = format!("{metadata:?}");
    for leaked in [TXID, COVENANT, "PROM-RULE", "bafkrei"] {
        assert!(!debugged.contains(leaked));
    }
}

#[test]
fn explicit_mode_never_weakens_process_runtime_gate() {
    const CHILD: &str = "PROMETHEUS_RULE_OBSERVATION_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // Under PROMETHEUS_RUNTIME=beta, even an explicit Development mode
        // must fail on the process-wide env gate.
        let fixture = valid_fixture();
        assert!(verify_rule_storage_observation_for_mode(
            RuntimeMode::Development,
            &fixture.expected_hash,
            &fixture.manifest,
            &fixture.observation,
            &fixture.constructor
        )
        .is_err());
        assert!(verify_rule_storage_observation(
            &fixture.expected_hash,
            &fixture.manifest,
            &fixture.observation,
            &fixture.constructor
        )
        .is_err());
        return;
    }

    let fixture = valid_fixture();
    assert!(verify_rule_storage_observation_for_mode(
        RuntimeMode::Development,
        &fixture.expected_hash,
        &fixture.manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_ok());
    assert!(verify_rule_storage_observation_for_mode(
        RuntimeMode::Beta,
        &fixture.expected_hash,
        &fixture.manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());
    assert!(verify_rule_storage_observation_for_mode(
        RuntimeMode::Mainnet,
        &fixture.expected_hash,
        &fixture.manifest,
        &fixture.observation,
        &fixture.constructor
    )
    .is_err());

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("explicit_mode_never_weakens_process_runtime_gate")
        .env(CHILD, "1")
        .env("PROMETHEUS_RUNTIME", "beta")
        .status()
        .unwrap();
    assert!(status.success());
}
