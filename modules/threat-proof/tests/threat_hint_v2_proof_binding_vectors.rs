use std::collections::HashSet;

use prometheus_threat_hint::{ThreatHintEnvelope, ThreatHintV2ProofEnvelope};
use prometheus_threat_proof::relation_manifest_v2::{
    RelationManifestV2, RELATION_MANIFEST_V2_PROTOCOL_ID,
    RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING, RELATION_MANIFEST_V2_RELATION_ID,
    RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX,
};
use prometheus_threat_proof::threat_hint_v2_proof_binding::{
    ThreatHintV2ProofBinding, ThreatHintV2ProofBindingError,
};
use prometheus_threat_proof::{sha256_hex, RelationManifest};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/threat-hint-v2-proof-binding-v1.json");
const VALID_VECTOR_COUNT: usize = 5;
const INVALID_VECTOR_COUNT: usize = 28;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCorpus {
    vector_schema_version: u16,
    protocol_id: String,
    relation_id: String,
    statement_digest_domain_hex: String,
    public_input_encoding: String,
    valid_cases: Vec<ValidCase>,
    invalid_cases: Vec<InvalidCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidCase {
    name: String,
    trusted_network_id: String,
    envelope_wire_hex: String,
    manifest_wire_hex: String,
    manifest_sha256_hex: String,
    statement_digest_hex: String,
    public_input_first_half_hex: String,
    public_input_second_half_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidCase {
    name: String,
    trusted_network_id: String,
    trusted_manifest_sha256_hex: String,
    envelope_wire_hex: String,
    manifest_wire_hex: String,
}

fn corpus() -> VectorCorpus {
    serde_json::from_slice(VECTOR_BYTES).expect("valid vector corpus")
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid fixture hex")
}

fn find_valid<'a>(vectors: &'a VectorCorpus, name: &str) -> &'a ValidCase {
    vectors
        .valid_cases
        .iter()
        .find(|case| case.name == name)
        .expect("named valid vector")
}

fn find_invalid<'a>(vectors: &'a VectorCorpus, name: &str) -> &'a InvalidCase {
    vectors
        .invalid_cases
        .iter()
        .find(|case| case.name == name)
        .expect("named invalid vector")
}

fn bind_case(case: &ValidCase) -> ThreatHintV2ProofBinding {
    ThreatHintV2ProofBinding::bind_canonical(
        &decode_hex(&case.envelope_wire_hex),
        &decode_hex(&case.manifest_wire_hex),
        &case.trusted_network_id,
        &case.manifest_sha256_hex,
    )
    .expect("valid shared vector")
}

fn bind_invalid(case: &InvalidCase) -> ThreatHintV2ProofBindingError {
    ThreatHintV2ProofBinding::bind_canonical(
        &decode_hex(&case.envelope_wire_hex),
        &decode_hex(&case.manifest_wire_hex),
        &case.trusted_network_id,
        &case.trusted_manifest_sha256_hex,
    )
    .expect_err("invalid shared vector must fail")
}

#[test]
fn shared_corpus_has_exact_schema_and_unique_names() {
    let vectors = corpus();
    assert_eq!(vectors.vector_schema_version, 1);
    assert_eq!(vectors.protocol_id, RELATION_MANIFEST_V2_PROTOCOL_ID);
    assert_eq!(vectors.relation_id, RELATION_MANIFEST_V2_RELATION_ID);
    assert_eq!(
        vectors.statement_digest_domain_hex,
        RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX
    );
    assert_eq!(
        vectors.public_input_encoding,
        RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING
    );
    assert_eq!(vectors.valid_cases.len(), VALID_VECTOR_COUNT);
    assert_eq!(vectors.invalid_cases.len(), INVALID_VECTOR_COUNT);

    let mut names = HashSet::new();
    for case in &vectors.valid_cases {
        assert!(names.insert(case.name.as_str()));
    }
    for case in &vectors.invalid_cases {
        assert!(names.insert(case.name.as_str()));
    }
    assert_eq!(names.len(), VALID_VECTOR_COUNT + INVALID_VECTOR_COUNT);
}

#[test]
fn shared_valid_vectors_bind_with_exact_anchors_and_claimed_inputs() {
    let vectors = corpus();
    let mut manifest_digests = HashSet::new();
    let mut statement_digests = HashSet::new();

    for case in &vectors.valid_cases {
        let binding = bind_case(case);

        let envelope_wire = decode_hex(&case.envelope_wire_hex);
        let manifest_wire = decode_hex(&case.manifest_wire_hex);
        assert_eq!(sha256_hex(&manifest_wire), case.manifest_sha256_hex);
        assert_eq!(binding.raw_manifest_sha256_hex(), case.manifest_sha256_hex);
        assert_eq!(binding.statement_digest_hex(), case.statement_digest_hex);
        assert_eq!(
            binding.envelope().statement_digest_hex(),
            case.statement_digest_hex
        );
        assert_eq!(
            hex::encode(binding.public_input_first_half()),
            case.public_input_first_half_hex
        );
        assert_eq!(
            hex::encode(binding.public_input_second_half()),
            case.public_input_second_half_hex
        );

        let digest = decode_hex(&case.statement_digest_hex);
        assert_eq!(binding.public_input_first_half(), &digest[..16]);
        assert_eq!(binding.public_input_second_half(), &digest[16..]);
        assert_eq!(
            case.statement_digest_hex,
            format!(
                "{}{}",
                case.public_input_first_half_hex, case.public_input_second_half_hex
            )
        );

        assert_eq!(binding.manifest().network_id(), case.trusted_network_id);
        assert_eq!(
            binding.envelope().statement().network_id(),
            case.trusted_network_id
        );
        assert_eq!(
            binding.envelope().protocol_id(),
            binding.manifest().protocol_id()
        );
        assert_eq!(
            binding.envelope().relation_id(),
            binding.manifest().relation_id()
        );
        assert_eq!(
            binding.envelope().to_canonical_bytes().expect("canonical"),
            envelope_wire
        );
        assert_eq!(
            binding.manifest().to_canonical_bytes().expect("canonical"),
            manifest_wire
        );

        manifest_digests.insert(case.manifest_sha256_hex.clone());
        statement_digests.insert(case.statement_digest_hex.clone());
    }

    assert_eq!(manifest_digests.len(), VALID_VECTOR_COUNT);
    assert_eq!(statement_digests.len(), VALID_VECTOR_COUNT);
}

#[test]
fn shared_invalid_vectors_fail_closed_with_one_redacted_error() {
    let vectors = corpus();
    for case in &vectors.invalid_cases {
        let error = bind_invalid(case);
        assert_eq!(error, ThreatHintV2ProofBindingError::InvalidBinding);
        assert_eq!(error.to_string(), "invalid threat-hint v2 proof binding");
    }
}

#[test]
fn trusted_network_binding_is_enforced_for_every_valid_vector() {
    let vectors = corpus();
    for case in &vectors.valid_cases {
        let envelope_wire = decode_hex(&case.envelope_wire_hex);
        let manifest_wire = decode_hex(&case.manifest_wire_hex);
        for other in &vectors.valid_cases {
            if other.trusted_network_id != case.trusted_network_id {
                assert_eq!(
                    ThreatHintV2ProofBinding::bind_canonical(
                        &envelope_wire,
                        &manifest_wire,
                        &other.trusted_network_id,
                        &case.manifest_sha256_hex,
                    )
                    .unwrap_err(),
                    ThreatHintV2ProofBindingError::InvalidBinding
                );
            }
        }
    }
}

#[test]
fn v1_wires_reject_the_binding_but_parse_as_v1() {
    let vectors = corpus();

    let envelope_case = find_invalid(&vectors, "v1_envelope_confusion");
    let v1_envelope_wire = decode_hex(&envelope_case.envelope_wire_hex);
    assert!(ThreatHintEnvelope::parse_canonical(&v1_envelope_wire).is_ok());
    assert!(ThreatHintV2ProofEnvelope::parse_canonical(&v1_envelope_wire, "testnet-10").is_err());
    assert_eq!(
        bind_invalid(envelope_case),
        ThreatHintV2ProofBindingError::InvalidBinding
    );

    let manifest_case = find_invalid(&vectors, "v1_manifest_confusion");
    let v1_manifest_wire = decode_hex(&manifest_case.manifest_wire_hex);
    assert!(RelationManifest::parse_canonical(&v1_manifest_wire).is_ok());
    assert_eq!(
        RelationManifestV2::parse_canonical(&v1_manifest_wire, "testnet-10").unwrap_err(),
        prometheus_threat_proof::relation_manifest_v2::RelationManifestV2Error::InvalidManifest
    );
    assert_eq!(
        bind_invalid(manifest_case),
        ThreatHintV2ProofBindingError::InvalidBinding
    );
}

#[test]
fn derived_claimed_inputs_are_not_proof_acceptance() {
    let vectors = corpus();
    let case = find_valid(&vectors, "base_testnet");
    let binding = bind_case(case);

    // The halves are claimed public-input data derived from the statement
    // digest; no proof bytes are interpreted or verified anywhere.
    let digest = decode_hex(binding.statement_digest_hex());
    assert_eq!(binding.public_input_first_half(), &digest[..16]);
    assert_eq!(binding.public_input_second_half(), &digest[16..]);
    assert_eq!(binding.envelope().proof_hex(), "aa".repeat(16));
}
