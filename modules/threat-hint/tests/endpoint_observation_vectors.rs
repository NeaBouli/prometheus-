use std::collections::HashSet;

use prometheus_threat_hint::{
    EndpointObservationDomain, EndpointObservationError, EndpointObservationSignal,
    EndpointObservationStatementV1, MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES,
};
use serde::Deserialize;

const VECTOR_BYTES: &[u8] = include_bytes!("vectors/endpoint-observation-v1.json");
const EXPECTED_DOMAIN_HEX: &str =
    "70726f6d6574686575732d656e64706f696e742d6f62736572766174696f6e2d763100";

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
    assert_eq!(vectors.valid_cases.len(), 20);

    let mut names = HashSet::new();
    let mut digests = HashSet::new();
    for case in vectors.valid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        assert!(wire.len() <= MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES);

        let statement =
            EndpointObservationStatementV1::parse_canonical(&wire, &case.trusted_network_id)
                .expect("valid shared vector");
        assert_eq!(statement.to_canonical_bytes().expect("canonical"), wire);
        assert_eq!(
            hex::encode(statement.statement_digest().expect("statement digest")),
            case.statement_digest_hex
        );
        assert!(digests.insert(case.statement_digest_hex));
    }
    assert_eq!(names.len(), 20);
    assert_eq!(digests.len(), 20);
}

#[test]
fn every_signal_vector_matches_its_declared_domain() {
    let vectors = corpus();
    let expected: &[(&str, EndpointObservationDomain, EndpointObservationSignal)] = &[
        (
            "base_process_unexpected_child_process",
            EndpointObservationDomain::Process,
            EndpointObservationSignal::UnexpectedChildProcess,
        ),
        (
            "signal_rapid_process_spawn",
            EndpointObservationDomain::Process,
            EndpointObservationSignal::RapidProcessSpawn,
        ),
        (
            "signal_protected_file_change",
            EndpointObservationDomain::File,
            EndpointObservationSignal::ProtectedFileChange,
        ),
        (
            "signal_executable_file_change",
            EndpointObservationDomain::File,
            EndpointObservationSignal::ExecutableFileChange,
        ),
        (
            "signal_unexpected_egress",
            EndpointObservationDomain::Network,
            EndpointObservationSignal::UnexpectedEgress,
        ),
        (
            "signal_connection_fanout",
            EndpointObservationDomain::Network,
            EndpointObservationSignal::ConnectionFanout,
        ),
        (
            "signal_startup_entry_change",
            EndpointObservationDomain::Persistence,
            EndpointObservationSignal::StartupEntryChange,
        ),
        (
            "signal_scheduled_task_change",
            EndpointObservationDomain::Persistence,
            EndpointObservationSignal::ScheduledTaskChange,
        ),
        (
            "signal_credential_store_access",
            EndpointObservationDomain::CredentialAccess,
            EndpointObservationSignal::CredentialStoreAccess,
        ),
        (
            "signal_bulk_secret_read_attempt",
            EndpointObservationDomain::CredentialAccess,
            EndpointObservationSignal::BulkSecretReadAttempt,
        ),
        (
            "signal_prompt_injection_indicator",
            EndpointObservationDomain::ModelTool,
            EndpointObservationSignal::PromptInjectionIndicator,
        ),
        (
            "signal_tool_policy_violation",
            EndpointObservationDomain::ModelTool,
            EndpointObservationSignal::ToolPolicyViolation,
        ),
        (
            "signal_model_runtime_change",
            EndpointObservationDomain::ModelTool,
            EndpointObservationSignal::ModelRuntimeChange,
        ),
        (
            "signal_sustained_compute_saturation",
            EndpointObservationDomain::ResourceUtilization,
            EndpointObservationSignal::SustainedComputeSaturation,
        ),
        (
            "signal_accelerator_utilization_spike",
            EndpointObservationDomain::ResourceUtilization,
            EndpointObservationSignal::AcceleratorUtilizationSpike,
        ),
    ];

    for (name, domain, signal) in expected {
        let case = vectors
            .valid_cases
            .iter()
            .find(|case| case.name == *name)
            .expect("signal vector");
        let statement = EndpointObservationStatementV1::parse_canonical(
            &decode_hex(&case.wire_hex),
            &case.trusted_network_id,
        )
        .expect("valid signal vector");
        assert_eq!(statement.domain(), *domain);
        assert_eq!(statement.signal(), *signal);
        assert_eq!(statement.signal().domain(), statement.domain());
    }
}

#[test]
fn every_mutable_bound_field_changes_the_statement_digest() {
    let vectors = corpus();
    let base = vectors
        .valid_cases
        .iter()
        .find(|case| case.name == "base_process_unexpected_child_process")
        .expect("base vector");

    for changed_name in [
        "signal_rapid_process_spawn",
        "signal_protected_file_change",
        "event_count_changed",
        "window_seconds_changed",
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
fn shared_invalid_vectors_fail_closed_with_one_redacted_error() {
    let vectors = corpus();
    assert_eq!(vectors.invalid_cases.len(), 42);

    let mut names = HashSet::new();
    for case in vectors.invalid_cases {
        assert!(names.insert(case.name));
        let wire = decode_hex(&case.wire_hex);
        let result =
            EndpointObservationStatementV1::parse_canonical(&wire, &case.trusted_network_id);
        assert_eq!(result, Err(EndpointObservationError::InvalidStatement));
        assert_eq!(
            result.expect_err("invalid shared vector").to_string(),
            "invalid endpoint observation statement"
        );
    }
}

#[test]
fn shared_vectors_cover_trusted_network_mismatch() {
    let vectors = corpus();
    let mismatch = vectors
        .invalid_cases
        .iter()
        .find(|case| case.name == "network_id_trusted_mismatch")
        .expect("mismatch vector");
    assert_eq!(mismatch.trusted_network_id, "testnet-11");
    assert_eq!(
        EndpointObservationStatementV1::parse_canonical(
            &decode_hex(&mismatch.wire_hex),
            &mismatch.trusted_network_id
        ),
        Err(EndpointObservationError::InvalidStatement)
    );
}
