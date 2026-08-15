use std::process::Command;

use prometheus_client::blockchain::krc20::RuleType;
use prometheus_client::blockchain::rule_state::{
    decode_rule_state, decode_rule_state_batch, decode_rule_state_batch_for_mode,
    decode_rule_state_for_mode, MAX_BATCH_JSON_BYTES, MAX_STATES_PER_BATCH, MAX_STATE_JSON_BYTES,
};
use prometheus_client::runtime::RuntimeMode;
use serde_json::{json, Value};

const VECTOR: &str = include_str!("vectors/rule-storage-state-v1.json");

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

fn valid_document(proposal_id: i64) -> Value {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend(0u8..32);
    json!([
        bytes(&[4; 32]), int(proposal_id + 1), int(proposal_id), bytes(&[5; 32]),
        bytes(&[6; 32]), int(0), bytes(&cid), int(9_000), int(100_000), int(3),
        int(1), int(964_000), int(2), int(3), int(2), int(50_000), int(7_500),
        int(965_000), {"kind": "bool", "data": true}, int(1)
    ])
}

fn encoded(document: &Value) -> String {
    serde_json::to_string(document).unwrap()
}

fn replaced(index: usize, value: Value) -> String {
    let mut document = valid_document(7);
    document.as_array_mut().unwrap()[index] = value;
    encoded(&document)
}

#[test]
fn anchored_vector_decodes_to_pinned_metadata() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let case = &vector["valid"][0];
    let document = encoded(&case["document"]);
    let expected = &case["expected"];
    let metadata = decode_rule_state(&document).unwrap();

    assert_eq!(
        metadata.proposal_id(),
        expected["proposal_id"].as_u64().unwrap()
    );
    assert_eq!(metadata.rule_id(), expected["rule_id"].as_str().unwrap());
    assert_eq!(metadata.rule_type(), RuleType::Yara);
    assert_eq!(metadata.ipfs_cid(), expected["ipfs_cid"].as_str().unwrap());
    assert_eq!(
        hex::encode(metadata.guardian_id()),
        expected["guardian_id_hex"]
    );
    assert_eq!(
        hex::encode(metadata.threat_hash()),
        expected["threat_hash_hex"]
    );
    assert_eq!(metadata.confidence_bps() as u64, expected["confidence_bps"]);
    assert_eq!(metadata.consensus_bps() as u64, expected["consensus_bps"]);
    assert_eq!(metadata.stored_at_block(), expected["stored_at_block"]);
    assert!(metadata.active());

    let invalid = encoded(&vector["invalid"][0]["document"]);
    assert!(decode_rule_state(&invalid).is_err());
}

#[test]
fn rejects_noncanonical_shape_and_bounds() {
    assert!(decode_rule_state("not json").is_err());
    assert!(decode_rule_state("[] trailing").is_err());
    assert!(decode_rule_state("{}").is_err());

    let mut short = valid_document(7).as_array().unwrap().clone();
    short.pop();
    assert!(decode_rule_state(&encoded(&Value::Array(short))).is_err());

    let mut unknown = int(8);
    unknown
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), json!(1));
    assert!(decode_rule_state(&replaced(1, unknown)).is_err());
    assert!(decode_rule_state(&replaced(1, json!({"kind": "int"}))).is_err());
    assert!(decode_rule_state(&replaced(1, json!({"kind": "int", "data": 8.0}))).is_err());
    assert!(decode_rule_state(&replaced(3, bytes(&[5; 31]))).is_err());
    assert!(decode_rule_state(&replaced(4, bytes(&[6; 33]))).is_err());

    let base = encoded(&valid_document(7));
    let exact = format!("{base:>width$}", width = MAX_STATE_JSON_BYTES);
    assert!(decode_rule_state(&exact).is_ok());
    assert!(decode_rule_state(&(exact + " ")).is_err());
}

#[test]
fn rejects_each_accepted_state_invariant_family() {
    for status in [0, 1, 3] {
        assert!(decode_rule_state(&replaced(12, int(status))).is_err());
    }
    assert!(decode_rule_state(&replaced(18, json!({"kind": "bool", "data": false}))).is_err());
    for rule_type in [-1, 3] {
        assert!(decode_rule_state(&replaced(5, int(rule_type))).is_err());
    }
    for confidence in [8_499, 10_001] {
        assert!(decode_rule_state(&replaced(7, int(confidence))).is_err());
    }
    assert!(decode_rule_state(&replaced(4, bytes(&[0; 32]))).is_err());
    assert!(decode_rule_state(&replaced(1, int(9))).is_err());
    assert!(decode_rule_state(&replaced(8, int(-1))).is_err());
    assert!(decode_rule_state(&replaced(9, int(-1))).is_err());
    assert!(decode_rule_state(&replaced(11, int(964_001))).is_err());
    assert!(decode_rule_state(&replaced(16, int(7_501))).is_err());
    assert!(decode_rule_state(&replaced(17, int(963_999))).is_err());
    assert!(decode_rule_state(&replaced(13, int(0))).is_err());
    assert!(decode_rule_state(&replaced(14, int(0))).is_err());
    assert!(decode_rule_state(&replaced(15, int(100_001))).is_err());
    assert!(decode_rule_state(&replaced(19, int(0))).is_err());

    let mut no_votes = valid_document(7);
    no_votes.as_array_mut().unwrap()[9] = int(0);
    no_votes.as_array_mut().unwrap()[10] = int(0);
    no_votes.as_array_mut().unwrap()[16] = int(0);
    assert!(decode_rule_state(&encoded(&no_votes)).is_err());

    let mut below_quorum = valid_document(7);
    below_quorum.as_array_mut().unwrap()[9] = int(3);
    below_quorum.as_array_mut().unwrap()[10] = int(2);
    below_quorum.as_array_mut().unwrap()[16] = int(6_000);
    assert!(decode_rule_state(&encoded(&below_quorum)).is_err());

    let mut bad_cid = vec![0x01, 0x70, 0x12, 0x20];
    bad_cid.extend(0u8..32);
    assert!(decode_rule_state(&replaced(6, bytes(&bad_cid))).is_err());
}

#[test]
fn batch_is_bounded_atomic_and_duplicate_free() {
    let one = encoded(&valid_document(1));
    assert!(decode_rule_state_batch(&[&one, &one]).is_err());

    let bad = replaced(12, int(1));
    assert!(decode_rule_state_batch(&[&one, &bad]).is_err());

    let documents: Vec<_> = (0..=MAX_STATES_PER_BATCH)
        .map(|id| encoded(&valid_document(id as i64)))
        .collect();
    let total_bytes: usize = documents.iter().map(String::len).sum();
    assert!(
        total_bytes <= MAX_BATCH_JSON_BYTES,
        "batch must exceed the count cap without exceeding the byte cap"
    );
    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
    assert!(decode_rule_state_batch(&refs).is_err());

    let mut padded = one.clone();
    padded.push_str(&" ".repeat(MAX_BATCH_JSON_BYTES));
    assert!(decode_rule_state_batch(&[&padded]).is_err());
}

#[test]
fn explicit_mode_never_weakens_process_runtime_gate() {
    const CHILD: &str = "PROMETHEUS_RULE_STATE_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let document = encoded(&valid_document(7));
        assert!(decode_rule_state_for_mode(RuntimeMode::Development, &document).is_err());
        assert!(decode_rule_state_batch_for_mode(RuntimeMode::Development, &[&document]).is_err());
        return;
    }

    assert!(decode_rule_state_for_mode(RuntimeMode::Beta, "[]").is_err());
    assert!(decode_rule_state_for_mode(RuntimeMode::Mainnet, "[]").is_err());
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("explicit_mode_never_weakens_process_runtime_gate")
        .env(CHILD, "1")
        .env("PROMETHEUS_RUNTIME", "beta")
        .status()
        .unwrap();
    assert!(status.success());
}
