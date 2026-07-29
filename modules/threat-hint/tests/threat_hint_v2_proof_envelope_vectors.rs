use std::collections::HashSet;

use prometheus_threat_hint::{
    ThreatHintEnvelope, ThreatHintV2ProofEnvelope, ThreatHintV2ProofEnvelopeError,
    ThreatIndicatorType, ThreatProofSystem, MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES,
    THREAT_HINT_V2_PROTOCOL_ID, THREAT_HINT_V2_RELATION_ID,
};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/threat-hint-v2-proof-envelope-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCorpus {
    vector_schema_version: u16,
    protocol_id: String,
    relation_id: String,
    valid_cases: Vec<ValidCase>,
    invalid_cases: Vec<InvalidCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidCase {
    name: String,
    trusted_network_id: String,
    wire_hex: String,
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

fn base_wire() -> Vec<u8> {
    let vectors = corpus();
    let base = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "base_review_required")
        .expect("base vector");
    decode_hex(&base.wire_hex)
}

#[test]
fn shared_valid_vectors_parse_with_exact_bytes_and_binding() {
    let vectors = corpus();
    assert_eq!(vectors.vector_schema_version, 1);
    assert_eq!(vectors.protocol_id, THREAT_HINT_V2_PROTOCOL_ID);
    assert_eq!(vectors.relation_id, THREAT_HINT_V2_RELATION_ID);
    assert_eq!(vectors.valid_cases.len(), 3);

    let mut names = HashSet::new();
    for case in vectors.valid_cases {
        assert!(names.insert(case.name.clone()));
        let wire = decode_hex(&case.wire_hex);
        assert!(wire.len() <= MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES);

        let envelope = ThreatHintV2ProofEnvelope::parse_canonical(&wire, &case.trusted_network_id)
            .expect("valid shared vector");
        assert_eq!(envelope.to_canonical_bytes().expect("canonical"), wire);
        assert_eq!(envelope.schema_version(), 2);
        assert_eq!(envelope.protocol_id(), THREAT_HINT_V2_PROTOCOL_ID);
        assert_eq!(envelope.relation_id(), THREAT_HINT_V2_RELATION_ID);
        assert_eq!(
            envelope.statement_digest_hex(),
            hex::encode(envelope.statement().statement_digest().expect("digest"))
        );
        assert_eq!(envelope.statement().network_id(), case.trusted_network_id);
        let proof = envelope.proof_bytes().expect("proof");
        assert_eq!(hex::encode(&proof), envelope.proof_hex());
        assert!(!proof.is_empty());
        assert!(proof.len() <= 1024);
    }
}

#[test]
fn proof_size_boundaries_are_enforced() {
    let vectors = corpus();
    let min = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "public_auto_min_proof")
        .expect("min proof vector");
    let max = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "mainnet_max_proof")
        .expect("max proof vector");

    let min = ThreatHintV2ProofEnvelope::parse_canonical(
        &decode_hex(&min.wire_hex),
        &min.trusted_network_id,
    )
    .expect("min proof envelope");
    assert_eq!(min.proof_bytes().expect("proof"), vec![0x00]);

    let max = ThreatHintV2ProofEnvelope::parse_canonical(
        &decode_hex(&max.wire_hex),
        &max.trusted_network_id,
    )
    .expect("max proof envelope");
    assert_eq!(max.proof_bytes().expect("proof").len(), 1024);
}

#[test]
fn shared_invalid_vectors_fail_closed_with_one_error() {
    let vectors = corpus();
    assert_eq!(vectors.invalid_cases.len(), 30);

    let mut names = HashSet::new();
    for case in vectors.invalid_cases {
        assert!(names.insert(case.name.clone()));
        let wire = decode_hex(&case.wire_hex);
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(&wire, &case.trusted_network_id),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
    }
}

#[test]
fn cross_version_envelopes_are_rejected_bidirectionally() {
    let v2_wire = base_wire();

    let v1_envelope = ThreatHintEnvelope::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        420,
        ThreatIndicatorType::FileHash,
        ThreatProofSystem::Groth16Kip16V1,
        vec![0xaa; 16],
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        1_700_000_000,
    )
    .expect("valid v1 envelope");
    let v1_wire = v1_envelope.to_canonical_bytes().expect("v1 canonical");

    assert_eq!(
        ThreatHintV2ProofEnvelope::parse_canonical(&v1_wire, "testnet-10"),
        Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
    );
    assert!(ThreatHintEnvelope::parse_canonical(&v2_wire).is_err());
}

#[test]
fn envelope_size_limit_is_fail_closed() {
    assert_eq!(
        ThreatHintV2ProofEnvelope::parse_canonical(
            &vec![b'{'; MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES + 1],
            "testnet-10"
        ),
        Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
    );

    let wire = base_wire();
    assert!(wire.len() < MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES);
}
