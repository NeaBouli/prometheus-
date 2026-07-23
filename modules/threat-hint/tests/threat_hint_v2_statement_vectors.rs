use std::collections::HashSet;

use prometheus_threat_hint::{
    ThreatHintV2DisclosureClass, ThreatHintV2Statement, ThreatHintV2StatementError,
    MAX_CANONICAL_V2_STATEMENT_BYTES,
};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/threat-hint-v2-statement-v1.json");
const EXPECTED_DOMAIN_HEX: &str =
    "70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCorpus {
    vector_schema_version: u16,
    statement_digest_domain_hex: String,
    valid_cases: Vec<ValidCase>,
    invalid_cases: Vec<InvalidCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidCase {
    name: String,
    trusted_network_id: String,
    wire_hex: String,
    statement_digest_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidCase {
    name: String,
    trusted_network_id: String,
    wire_hex: String,
}

fn corpus() -> VectorCorpus {
    serde_json::from_slice(VECTOR_BYTES).expect("valid vector corpus")
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid fixture hex")
}

#[test]
fn shared_valid_vectors_have_exact_bytes_and_digests() {
    let vectors = corpus();
    assert_eq!(vectors.vector_schema_version, 1);
    assert_eq!(vectors.statement_digest_domain_hex, EXPECTED_DOMAIN_HEX);
    assert_eq!(vectors.valid_cases.len(), 8);

    let mut names = HashSet::new();
    let mut digests = HashSet::new();
    for case in vectors.valid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        assert!(wire.len() <= MAX_CANONICAL_V2_STATEMENT_BYTES);

        let statement = ThreatHintV2Statement::parse_canonical(&wire, &case.trusted_network_id)
            .expect("valid shared vector");
        assert_eq!(statement.to_canonical_bytes().expect("canonical"), wire);
        assert_eq!(
            hex::encode(statement.statement_digest().expect("statement digest")),
            case.statement_digest_hex
        );
        assert!(digests.insert(case.statement_digest_hex));
    }
    assert_eq!(names.len(), 8);
    assert_eq!(digests.len(), 8);
}

#[test]
fn every_bound_field_changes_the_statement_digest() {
    let vectors = corpus();
    let base = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "base_review_required")
        .expect("base vector");

    for changed_name in [
        "artifact_hash_changed",
        "observable_commitment_changed",
        "confidence_changed",
        "disclosure_class_changed",
        "report_nonce_changed",
        "observed_at_changed",
        "network_changed",
    ] {
        let changed = vectors
            .valid_cases
            .iter()
            .find(|case| case.name == changed_name)
            .expect("changed vector");
        assert_ne!(base.statement_digest_hex, changed.statement_digest_hex);
    }
}

#[test]
fn shared_invalid_vectors_fail_closed_with_one_error() {
    let vectors = corpus();
    assert!(vectors.invalid_cases.len() >= 20);

    let mut names = HashSet::new();
    for case in vectors.invalid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(&wire, &case.trusted_network_id),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );
    }
}

#[test]
fn parsed_fields_preserve_closed_structural_values() {
    let vectors = corpus();
    let review = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "base_review_required")
        .expect("review vector");
    let public = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "disclosure_class_changed")
        .expect("public vector");

    let review = ThreatHintV2Statement::parse_canonical(
        &decode_hex(&review.wire_hex),
        &review.trusted_network_id,
    )
    .expect("review statement");
    let public = ThreatHintV2Statement::parse_canonical(
        &decode_hex(&public.wire_hex),
        &public.trusted_network_id,
    )
    .expect("public statement");

    assert_eq!(
        review.disclosure_class(),
        ThreatHintV2DisclosureClass::ReviewRequiredV1
    );
    assert_eq!(
        public.disclosure_class(),
        ThreatHintV2DisclosureClass::PublicAutoV1
    );
}
