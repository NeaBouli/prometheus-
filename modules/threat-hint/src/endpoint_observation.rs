//! Local-only canonical EndpointObservationStatementV1 parsing.
//!
//! This module performs structural local parsing of one bounded canonical
//! statement shape only. It collects no telemetry and does not access
//! processes, files, networks, the OS, or any sensor. It proves no truth,
//! maliciousness, provenance, or privacy property of the observed events,
//! performs no AI or actor attribution, issues no warning, carries no
//! response authority, implements no transport, and changes no production
//! behavior.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::observable_bundle::validate_network_id;

const ENDPOINT_OBSERVATION_SCHEMA_VERSION: u16 = 1;
const FIXED_HEX_LEN: usize = 64;
const STATEMENT_DIGEST_DOMAIN: &[u8] = b"prometheus-endpoint-observation-v1\0";
const ALLOWED_WINDOW_SECONDS: [u64; 4] = [60, 300, 900, 3600];

/// Maximum accepted canonical endpoint observation statement size.
pub const MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES: usize = 512;

/// Redacted failure returned for every invalid statement or trusted network.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EndpointObservationError {
    /// The statement or separately trusted network is invalid.
    #[error("invalid endpoint observation statement")]
    InvalidStatement,
}

/// Closed structural observation domain classification.
///
/// This value is a structural label only; it does not prove that any event
/// occurred, that it was malicious, or that it may be disclosed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointObservationDomain {
    /// Process lifecycle observations.
    Process,
    /// File change observations.
    File,
    /// Network traffic observations.
    Network,
    /// Persistence mechanism observations.
    Persistence,
    /// Credential store access observations.
    CredentialAccess,
    /// Model and tool runtime observations.
    ModelTool,
    /// Resource utilization observations.
    ResourceUtilization,
}

/// Closed structural observation signal classification.
///
/// Each signal belongs to exactly one domain; a wire whose signal does not
/// match its declared domain is invalid.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointObservationSignal {
    /// Process domain: unexpected child process.
    UnexpectedChildProcess,
    /// Process domain: rapid process spawn.
    RapidProcessSpawn,
    /// File domain: protected file change.
    ProtectedFileChange,
    /// File domain: executable file change.
    ExecutableFileChange,
    /// Network domain: unexpected egress.
    UnexpectedEgress,
    /// Network domain: connection fanout.
    ConnectionFanout,
    /// Persistence domain: startup entry change.
    StartupEntryChange,
    /// Persistence domain: scheduled task change.
    ScheduledTaskChange,
    /// Credential access domain: credential store access.
    CredentialStoreAccess,
    /// Credential access domain: bulk secret read attempt.
    BulkSecretReadAttempt,
    /// Model/tool domain: prompt injection indicator.
    PromptInjectionIndicator,
    /// Model/tool domain: tool policy violation.
    ToolPolicyViolation,
    /// Model/tool domain: model runtime change.
    ModelRuntimeChange,
    /// Resource utilization domain: sustained compute saturation.
    SustainedComputeSaturation,
    /// Resource utilization domain: accelerator utilization spike.
    AcceleratorUtilizationSpike,
}

impl EndpointObservationSignal {
    /// Returns the closed domain this signal structurally belongs to.
    pub fn domain(self) -> EndpointObservationDomain {
        match self {
            Self::UnexpectedChildProcess | Self::RapidProcessSpawn => {
                EndpointObservationDomain::Process
            }
            Self::ProtectedFileChange | Self::ExecutableFileChange => {
                EndpointObservationDomain::File
            }
            Self::UnexpectedEgress | Self::ConnectionFanout => EndpointObservationDomain::Network,
            Self::StartupEntryChange | Self::ScheduledTaskChange => {
                EndpointObservationDomain::Persistence
            }
            Self::CredentialStoreAccess | Self::BulkSecretReadAttempt => {
                EndpointObservationDomain::CredentialAccess
            }
            Self::PromptInjectionIndicator
            | Self::ToolPolicyViolation
            | Self::ModelRuntimeChange => EndpointObservationDomain::ModelTool,
            Self::SustainedComputeSaturation | Self::AcceleratorUtilizationSpike => {
                EndpointObservationDomain::ResourceUtilization
            }
        }
    }
}

/// A canonical local endpoint observation statement.
///
/// Direct deserialization is deliberately unavailable; callers must use
/// [`EndpointObservationStatementV1::parse_canonical`] with a separately
/// trusted network identifier.
///
/// ```compile_fail
/// use prometheus_threat_hint::EndpointObservationStatementV1;
///
/// let _: EndpointObservationStatementV1 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EndpointObservationStatementV1 {
    schema_version: u16,
    domain: EndpointObservationDomain,
    signal: EndpointObservationSignal,
    event_count: u8,
    window_seconds: u64,
    report_nonce: String,
    observed_at: u64,
    network_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointObservationStatementV1Wire {
    schema_version: u16,
    domain: EndpointObservationDomain,
    signal: EndpointObservationSignal,
    event_count: u8,
    window_seconds: u64,
    report_nonce: String,
    observed_at: u64,
    network_id: String,
}

impl EndpointObservationStatementV1 {
    /// The only supported endpoint observation statement schema version.
    pub const SCHEMA_VERSION: u16 = ENDPOINT_OBSERVATION_SCHEMA_VERSION;

    /// Parses exact canonical bytes against a separately trusted local network.
    pub fn parse_canonical(
        wire_bytes: &[u8],
        trusted_network_id: &str,
    ) -> Result<Self, EndpointObservationError> {
        if wire_bytes.is_empty() || wire_bytes.len() > MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES {
            return Err(EndpointObservationError::InvalidStatement);
        }
        validate_network_id(trusted_network_id)
            .map_err(|_| EndpointObservationError::InvalidStatement)?;

        let wire: EndpointObservationStatementV1Wire = serde_json::from_slice(wire_bytes)
            .map_err(|_| EndpointObservationError::InvalidStatement)?;
        let statement = Self {
            schema_version: wire.schema_version,
            domain: wire.domain,
            signal: wire.signal,
            event_count: wire.event_count,
            window_seconds: wire.window_seconds,
            report_nonce: wire.report_nonce,
            observed_at: wire.observed_at,
            network_id: wire.network_id,
        };

        statement.validate()?;
        if statement.network_id != trusted_network_id {
            return Err(EndpointObservationError::InvalidStatement);
        }
        if statement.to_canonical_bytes()? != wire_bytes {
            return Err(EndpointObservationError::InvalidStatement);
        }

        Ok(statement)
    }

    /// Returns the parsed schema version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the structural observation domain.
    pub fn domain(&self) -> EndpointObservationDomain {
        self.domain
    }

    /// Returns the structural observation signal.
    pub fn signal(&self) -> EndpointObservationSignal {
        self.signal
    }

    /// Returns the bounded event count in `1..=255`.
    pub fn event_count(&self) -> u8 {
        self.event_count
    }

    /// Returns the observation window; one of 60, 300, 900, or 3600 seconds.
    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// Returns the report nonce as lowercase hexadecimal.
    pub fn report_nonce_hex(&self) -> &str {
        &self.report_nonce
    }

    /// Returns the positive minute-granularity observed timestamp.
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Returns the network that matched the separately trusted network.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Serializes the validated statement to exact canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EndpointObservationError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| EndpointObservationError::InvalidStatement)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES {
            return Err(EndpointObservationError::InvalidStatement);
        }
        Ok(bytes)
    }

    /// Computes the domain-separated digest binding every canonical field.
    pub fn statement_digest(&self) -> Result<[u8; 32], EndpointObservationError> {
        let canonical = self.to_canonical_bytes()?;
        let canonical_len = u32::try_from(canonical.len())
            .map_err(|_| EndpointObservationError::InvalidStatement)?;

        let mut hasher = Sha256::new();
        hasher.update(STATEMENT_DIGEST_DOMAIN);
        hasher.update(canonical_len.to_be_bytes());
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    fn validate(&self) -> Result<(), EndpointObservationError> {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.signal.domain() != self.domain
            || self.event_count == 0
            || !ALLOWED_WINDOW_SECONDS.contains(&self.window_seconds)
            || !is_fixed_lower_hex(&self.report_nonce)
            || self.observed_at == 0
            || !self.observed_at.is_multiple_of(60)
        {
            return Err(EndpointObservationError::InvalidStatement);
        }
        validate_network_id(&self.network_id)
            .map_err(|_| EndpointObservationError::InvalidStatement)
    }
}

fn is_fixed_lower_hex(value: &str) -> bool {
    value.len() == FIXED_HEX_LEN
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_WIRE: &[u8] = br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#;

    #[test]
    fn parses_canonical_statement_and_binds_all_fields() {
        let statement = EndpointObservationStatementV1::parse_canonical(BASE_WIRE, "testnet-10")
            .expect("valid");

        assert_eq!(statement.schema_version(), 1);
        assert_eq!(statement.domain(), EndpointObservationDomain::Process);
        assert_eq!(
            statement.signal(),
            EndpointObservationSignal::UnexpectedChildProcess
        );
        assert_eq!(statement.event_count(), 1);
        assert_eq!(statement.window_seconds(), 60);
        assert_eq!(statement.report_nonce_hex(), "a".repeat(64));
        assert_eq!(statement.observed_at(), 1_700_000_040);
        assert_eq!(statement.network_id(), "testnet-10");
        assert_eq!(
            statement.to_canonical_bytes().expect("canonical"),
            BASE_WIRE
        );
    }

    #[test]
    fn rejects_untrusted_network_mismatch_and_invalid_trusted_network() {
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(BASE_WIRE, "testnet-11"),
            Err(EndpointObservationError::InvalidStatement)
        );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(BASE_WIRE, "bad_net"),
            Err(EndpointObservationError::InvalidStatement)
        );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(BASE_WIRE, "MAINNET"),
            Err(EndpointObservationError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(b"", "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(
                &vec![b'{'; MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES + 1],
                "testnet-10"
            ),
            Err(EndpointObservationError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_noncanonical_input() {
        let mut trailing = BASE_WIRE.to_vec();
        trailing.push(b'\n');
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(&trailing, "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );

        let whitespace = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(r#""schema_version":1"#, r#""schema_version": 1"#);
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(whitespace.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );

        let reordered = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(
                r#"{"schema_version":1,"domain":"process""#,
                r#"{"domain":"process","schema_version":1"#,
            );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(reordered.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );

        let escaped = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(r#""domain":"process""#, r#""domain":"proc\u0065ss""#);
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(escaped.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_missing_fields() {
        let unknown = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(
                r#""network_id":"testnet-10"}"#,
                r#""network_id":"testnet-10","process_name":"x"}"#,
            );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(unknown.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );

        let duplicate = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(
                r#"{"schema_version":1,"#,
                r#"{"schema_version":1,"schema_version":1,"#,
            );
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(duplicate.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );

        let missing = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(r#""event_count":1,"#, "");
        assert_eq!(
            EndpointObservationStatementV1::parse_canonical(missing.as_bytes(), "testnet-10"),
            Err(EndpointObservationError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_invalid_field_values_with_one_redacted_error() {
        let cases: &[&[u8]] = &[
            br#"{"schema_version":0,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":2,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"registry","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"protected_file_change","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":0,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":256,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":59,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":7200,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":0,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000041,"network_id":"testnet-10"}"#,
            br#"{"schema_version":1,"domain":"process","signal":"unexpected_child_process","event_count":1,"window_seconds":60,"report_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":1700000040,"network_id":"TESTNET-10"}"#,
        ];
        for case in cases {
            let result = EndpointObservationStatementV1::parse_canonical(case, "testnet-10");
            assert_eq!(result, Err(EndpointObservationError::InvalidStatement));
            assert_eq!(
                result.expect_err("invalid").to_string(),
                "invalid endpoint observation statement"
            );
        }
    }

    #[test]
    fn every_allowed_window_is_accepted() {
        for window in [60_u64, 300, 900, 3600] {
            let wire = String::from_utf8(BASE_WIRE.to_vec())
                .expect("ASCII")
                .replace(
                    r#""window_seconds":60"#,
                    &format!(r#""window_seconds":{window}"#),
                );
            assert!(
                EndpointObservationStatementV1::parse_canonical(wire.as_bytes(), "testnet-10")
                    .is_ok()
            );
        }
    }

    #[test]
    fn signal_domain_mapping_is_closed() {
        let mapping: &[(EndpointObservationSignal, EndpointObservationDomain)] = &[
            (
                EndpointObservationSignal::UnexpectedChildProcess,
                EndpointObservationDomain::Process,
            ),
            (
                EndpointObservationSignal::RapidProcessSpawn,
                EndpointObservationDomain::Process,
            ),
            (
                EndpointObservationSignal::ProtectedFileChange,
                EndpointObservationDomain::File,
            ),
            (
                EndpointObservationSignal::ExecutableFileChange,
                EndpointObservationDomain::File,
            ),
            (
                EndpointObservationSignal::UnexpectedEgress,
                EndpointObservationDomain::Network,
            ),
            (
                EndpointObservationSignal::ConnectionFanout,
                EndpointObservationDomain::Network,
            ),
            (
                EndpointObservationSignal::StartupEntryChange,
                EndpointObservationDomain::Persistence,
            ),
            (
                EndpointObservationSignal::ScheduledTaskChange,
                EndpointObservationDomain::Persistence,
            ),
            (
                EndpointObservationSignal::CredentialStoreAccess,
                EndpointObservationDomain::CredentialAccess,
            ),
            (
                EndpointObservationSignal::BulkSecretReadAttempt,
                EndpointObservationDomain::CredentialAccess,
            ),
            (
                EndpointObservationSignal::PromptInjectionIndicator,
                EndpointObservationDomain::ModelTool,
            ),
            (
                EndpointObservationSignal::ToolPolicyViolation,
                EndpointObservationDomain::ModelTool,
            ),
            (
                EndpointObservationSignal::ModelRuntimeChange,
                EndpointObservationDomain::ModelTool,
            ),
            (
                EndpointObservationSignal::SustainedComputeSaturation,
                EndpointObservationDomain::ResourceUtilization,
            ),
            (
                EndpointObservationSignal::AcceleratorUtilizationSpike,
                EndpointObservationDomain::ResourceUtilization,
            ),
        ];
        for (signal, domain) in mapping {
            assert_eq!(signal.domain(), *domain);
        }
    }

    #[test]
    fn statement_digest_is_domain_separated_and_deterministic() {
        let statement = EndpointObservationStatementV1::parse_canonical(BASE_WIRE, "testnet-10")
            .expect("valid");
        let first = statement.statement_digest().expect("digest");
        let second = statement.statement_digest().expect("digest");
        assert_eq!(first, second);

        let mut unrelated = Sha256::new();
        unrelated.update(b"prometheus-threat-hint-statement-v2\0");
        unrelated.update((BASE_WIRE.len() as u32).to_be_bytes());
        unrelated.update(BASE_WIRE);
        let unrelated: [u8; 32] = unrelated.finalize().into();
        assert_ne!(first, unrelated);
    }
}
