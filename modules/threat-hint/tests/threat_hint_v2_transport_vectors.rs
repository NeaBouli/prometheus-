use std::collections::HashSet;

use prometheus_threat_hint::{
    ThreatHintV2TransportError, ThreatHintV2TransportPayload, MAX_TRANSPORT_APPROVAL_BYTES,
    MAX_TRANSPORT_BUNDLE_BYTES, MAX_TRANSPORT_ENVELOPE_BYTES, MAX_TRANSPORT_PAYLOAD_BYTES,
    REPORT_NONCE_BYTES, THREAT_HINT_V2_TRANSPORT_MAGIC, THREAT_HINT_V2_TRANSPORT_VERSION,
};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/threat-hint-v2-transport-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCorpus {
    vector_schema_version: u16,
    magic_hex: String,
    version: u8,
    max_envelope_bytes: usize,
    max_bundle_bytes: usize,
    max_approval_bytes: usize,
    max_payload_bytes: usize,
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

fn base_case() -> ValidCase {
    let vectors = corpus();
    vectors
        .valid_cases
        .into_iter()
        .find(|case| case.name == "base_review_required")
        .expect("base vector")
}

#[test]
fn shared_format_constants_match_implementation() {
    let vectors = corpus();
    assert_eq!(vectors.vector_schema_version, 1);
    assert_eq!(
        decode_hex(&vectors.magic_hex),
        THREAT_HINT_V2_TRANSPORT_MAGIC
    );
    assert_eq!(vectors.version, THREAT_HINT_V2_TRANSPORT_VERSION);
    assert_eq!(vectors.max_envelope_bytes, MAX_TRANSPORT_ENVELOPE_BYTES);
    assert_eq!(vectors.max_bundle_bytes, MAX_TRANSPORT_BUNDLE_BYTES);
    assert_eq!(vectors.max_approval_bytes, MAX_TRANSPORT_APPROVAL_BYTES);
    assert_eq!(vectors.max_payload_bytes, MAX_TRANSPORT_PAYLOAD_BYTES);
}

#[test]
fn shared_valid_vectors_parse_with_exact_bytes_and_nonce_binding() {
    let vectors = corpus();
    assert_eq!(vectors.valid_cases.len(), 2);

    let mut names = HashSet::new();
    for case in vectors.valid_cases {
        assert!(names.insert(case.name.clone()));
        let wire = decode_hex(&case.wire_hex);
        assert!(wire.len() <= MAX_TRANSPORT_PAYLOAD_BYTES);

        let payload =
            ThreatHintV2TransportPayload::parse_canonical(&wire, &case.trusted_network_id)
                .expect("valid shared vector");
        assert_eq!(payload.to_canonical_bytes(), wire);

        // The nonce is only an untrusted session lookup key; it must equal the
        // envelope statement nonce but grants no authority by itself.
        let nonce = payload.report_nonce();
        assert_eq!(nonce.len(), REPORT_NONCE_BYTES);
        assert_eq!(
            payload.envelope().statement().report_nonce_hex(),
            hex::encode(nonce)
        );
        assert_eq!(
            payload.envelope().statement().network_id(),
            case.trusted_network_id
        );

        assert_eq!(
            payload.envelope_wire(),
            payload
                .envelope()
                .to_canonical_bytes()
                .expect("canonical envelope")
                .as_slice()
        );
        assert_eq!(
            payload.bundle_wire(),
            payload
                .bundle()
                .to_canonical_bytes()
                .expect("canonical bundle")
                .as_slice()
        );
        assert!(!payload.approval_wire().is_empty());
        assert!(payload.approval_wire().len() <= MAX_TRANSPORT_APPROVAL_BYTES);
        assert!(payload.envelope_wire().len() <= MAX_TRANSPORT_ENVELOPE_BYTES);
        assert!(payload.bundle_wire().len() <= MAX_TRANSPORT_BUNDLE_BYTES);
    }
}

#[test]
fn shared_invalid_vectors_fail_closed_with_one_error() {
    let vectors = corpus();
    assert_eq!(vectors.invalid_cases.len(), 19);

    let mut names = HashSet::new();
    for case in vectors.invalid_cases {
        assert!(names.insert(case.name.clone()));
        let wire = decode_hex(&case.wire_hex);
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&wire, &case.trusted_network_id),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );
    }
}

#[test]
fn payload_size_limit_is_fail_closed() {
    assert_eq!(
        ThreatHintV2TransportPayload::parse_canonical(
            &vec![b'P'; MAX_TRANSPORT_PAYLOAD_BYTES + 1],
            "testnet-10"
        ),
        Err(ThreatHintV2TransportError::InvalidPayload)
    );

    let wire = decode_hex(&base_case().wire_hex);
    assert!(wire.len() < MAX_TRANSPORT_PAYLOAD_BYTES);
}

#[test]
fn errors_do_not_echo_rejected_input() {
    let case = base_case();
    let mut wire = decode_hex(&case.wire_hex);
    wire[0] = b'X';
    let error = ThreatHintV2TransportPayload::parse_canonical(&wire, &case.trusted_network_id)
        .expect_err("bad magic must fail");
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(&case.wire_hex));
    assert_eq!(
        error.to_string(),
        "invalid threat-hint v2 transport payload"
    );
}
