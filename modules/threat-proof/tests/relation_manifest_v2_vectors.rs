use std::collections::HashSet;

use prometheus_threat_proof::relation_manifest_v2::{
    RelationManifestV2, RelationManifestV2Error, MAX_CANONICAL_V2_MANIFEST_BYTES,
    RELATION_MANIFEST_V2_KIP16_TAG, RELATION_MANIFEST_V2_MAX_PROVING_KEY_BYTES,
    RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES, RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES,
    RELATION_MANIFEST_V2_PROOF_SYSTEM, RELATION_MANIFEST_V2_PROTOCOL_ID,
    RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT, RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING,
    RELATION_MANIFEST_V2_RELATION_ID, RELATION_MANIFEST_V2_SCHEMA_VERSION,
    RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX,
};
use prometheus_threat_proof::{
    sha256_hex, RelationManifest, ARKWORKS_VERSION, KIP16_STATUS_COMMIT, RUSTY_KASPA_COMMIT,
    RUSTY_KASPA_TAG,
};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/relation-manifest-v2-v1.json");
const EXPECTED_DOMAIN_HEX: &str =
    "70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200";
const VALID_VECTOR_COUNT: usize = 5;
const INVALID_VECTOR_COUNT: usize = 56;

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
    manifest_sha256_hex: String,
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

#[test]
fn shared_valid_vectors_have_exact_bytes_and_manifest_digests() {
    let vectors = corpus();
    assert_eq!(vectors.vector_schema_version, 1);
    assert_eq!(vectors.statement_digest_domain_hex, EXPECTED_DOMAIN_HEX);
    assert_eq!(vectors.valid_cases.len(), VALID_VECTOR_COUNT);

    let mut names = HashSet::new();
    let mut digests = HashSet::new();
    for case in vectors.valid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        assert!(!wire.is_empty() && wire.len() <= MAX_CANONICAL_V2_MANIFEST_BYTES);

        let manifest = RelationManifestV2::parse_canonical(&wire, &case.trusted_network_id)
            .expect("valid shared vector");
        assert_eq!(manifest.to_canonical_bytes().expect("canonical"), wire);
        assert_eq!(sha256_hex(&wire), case.manifest_sha256_hex);
        assert!(digests.insert(case.manifest_sha256_hex));
    }
    assert_eq!(names.len(), VALID_VECTOR_COUNT);
    assert_eq!(digests.len(), VALID_VECTOR_COUNT);
}

#[test]
fn constant_pins_match_the_exact_schema() {
    assert_eq!(RELATION_MANIFEST_V2_SCHEMA_VERSION, 2);
    assert_eq!(
        RELATION_MANIFEST_V2_PROTOCOL_ID,
        "/prometheus/threat-hint/2.0.0"
    );
    assert_eq!(
        RELATION_MANIFEST_V2_RELATION_ID,
        "prometheus-threat-hint-v2"
    );
    assert_eq!(
        RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX,
        EXPECTED_DOMAIN_HEX
    );
    assert_eq!(
        RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX,
        hex::encode(b"prometheus-threat-hint-statement-v2\0")
    );
    assert_eq!(RELATION_MANIFEST_V2_PROOF_SYSTEM, "groth16_bn254_kip16");
    assert_eq!(RELATION_MANIFEST_V2_KIP16_TAG, 32);
    assert_eq!(
        RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING,
        "sha256_split_u128_bn254_v2"
    );
    assert_eq!(RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT, 2);
    assert_eq!(RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES, 1_048_576);
    assert_eq!(RELATION_MANIFEST_V2_MAX_PROVING_KEY_BYTES, 1_073_741_824);
    assert_eq!(RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES, 65_536);
    assert_eq!(
        KIP16_STATUS_COMMIT,
        "e4ae2332117b5cb68bd6188e065ef885b6d17939"
    );
    assert_eq!(RUSTY_KASPA_TAG, "v2.0.1");
    assert_eq!(
        RUSTY_KASPA_COMMIT,
        "cfafeb4c093fa37a303f1b9f19c58f986b870ce3"
    );
    assert_eq!(ARKWORKS_VERSION, "0.6.0");
}

#[test]
fn parsed_fields_preserve_closed_schema_values() {
    let vectors = corpus();
    let base = find_valid(&vectors, "base_testnet");
    let manifest =
        RelationManifestV2::parse_canonical(&decode_hex(&base.wire_hex), &base.trusted_network_id)
            .expect("base vector");

    assert_eq!(
        manifest.schema_version(),
        RELATION_MANIFEST_V2_SCHEMA_VERSION
    );
    assert_eq!(manifest.protocol_id(), RELATION_MANIFEST_V2_PROTOCOL_ID);
    assert_eq!(manifest.relation_id(), RELATION_MANIFEST_V2_RELATION_ID);
    assert_eq!(
        manifest.statement_digest_domain_hex(),
        RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX
    );
    assert_eq!(manifest.proof_system(), RELATION_MANIFEST_V2_PROOF_SYSTEM);
    assert_eq!(manifest.kip16_tag(), RELATION_MANIFEST_V2_KIP16_TAG);
    assert_eq!(
        manifest.public_input_encoding(),
        RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING
    );
    assert_eq!(
        manifest.public_input_count(),
        RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT
    );
    assert_eq!(manifest.network_id(), "testnet-10");
    assert_eq!(manifest.relation_source_bytes(), 4_096);
    assert_eq!(manifest.relation_source_sha256_hex(), "1".repeat(64));
    assert_eq!(manifest.proving_key_bytes(), 1_048_576);
    assert_eq!(manifest.proving_key_sha256_hex(), "2".repeat(64));
    assert_eq!(manifest.verifying_key_bytes(), 1_024);
    assert_eq!(manifest.verifying_key_sha256_hex(), "3".repeat(64));
    assert_eq!(manifest.kip16_status_commit(), KIP16_STATUS_COMMIT);
    assert_eq!(manifest.rusty_kaspa_tag(), RUSTY_KASPA_TAG);
    assert_eq!(manifest.rusty_kaspa_commit(), RUSTY_KASPA_COMMIT);
    assert_eq!(manifest.arkworks_version(), ARKWORKS_VERSION);

    let min = find_valid(&vectors, "min_byte_bounds");
    let min =
        RelationManifestV2::parse_canonical(&decode_hex(&min.wire_hex), &min.trusted_network_id)
            .expect("min vector");
    assert_eq!(min.relation_source_bytes(), 1);
    assert_eq!(min.proving_key_bytes(), 1);
    assert_eq!(min.verifying_key_bytes(), 1);

    let max = find_valid(&vectors, "max_byte_bounds");
    let max =
        RelationManifestV2::parse_canonical(&decode_hex(&max.wire_hex), &max.trusted_network_id)
            .expect("max vector");
    assert_eq!(
        max.relation_source_bytes(),
        RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES
    );
    assert_eq!(
        max.proving_key_bytes(),
        RELATION_MANIFEST_V2_MAX_PROVING_KEY_BYTES
    );
    assert_eq!(
        max.verifying_key_bytes(),
        RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES
    );
}

#[test]
fn shared_invalid_vectors_fail_closed_with_one_error() {
    let vectors = corpus();
    assert_eq!(vectors.invalid_cases.len(), INVALID_VECTOR_COUNT);

    let mut names = HashSet::new();
    for case in vectors.invalid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        assert_eq!(
            RelationManifestV2::parse_canonical(&wire, &case.trusted_network_id),
            Err(RelationManifestV2Error::InvalidManifest)
        );
    }
    assert_eq!(names.len(), INVALID_VECTOR_COUNT);
}

#[test]
fn v1_and_v2_manifests_reject_each_other() {
    let vectors = corpus();

    let v2_case = find_valid(&vectors, "base_testnet");
    let v2_wire = decode_hex(&v2_case.wire_hex);
    assert!(RelationManifestV2::parse_canonical(&v2_wire, &v2_case.trusted_network_id).is_ok());
    assert!(RelationManifest::parse_canonical(&v2_wire).is_err());

    let v1_case = find_invalid(&vectors, "v1_manifest_confusion");
    let v1_wire = decode_hex(&v1_case.wire_hex);
    assert!(RelationManifest::parse_canonical(&v1_wire).is_ok());
    assert_eq!(
        RelationManifestV2::parse_canonical(&v1_wire, &v1_case.trusted_network_id),
        Err(RelationManifestV2Error::InvalidManifest)
    );
}

#[test]
fn trusted_network_binding_is_enforced_for_every_valid_vector() {
    let vectors = corpus();
    for case in &vectors.valid_cases {
        let wire = decode_hex(&case.wire_hex);
        for other in &vectors.valid_cases {
            if other.trusted_network_id != case.trusted_network_id {
                assert_eq!(
                    RelationManifestV2::parse_canonical(&wire, &other.trusted_network_id),
                    Err(RelationManifestV2Error::InvalidManifest)
                );
            }
        }
    }
}
