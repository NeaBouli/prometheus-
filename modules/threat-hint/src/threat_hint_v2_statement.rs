//! Local-only canonical ThreatHint v2 statement parsing and binding.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::observable_bundle::validate_network_id;

const THREAT_HINT_V2_SCHEMA_VERSION: u16 = 2;
const FIXED_HASH_HEX_LEN: usize = 64;
const STATEMENT_DIGEST_DOMAIN: &[u8] = b"prometheus-threat-hint-statement-v2\0";

/// Maximum accepted canonical ThreatHint v2 statement size.
pub const MAX_CANONICAL_V2_STATEMENT_BYTES: usize = 1024;

/// Redacted failure returned for every invalid statement or trusted network.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreatHintV2StatementError {
    /// The statement or separately trusted network is invalid.
    #[error("invalid threat-hint v2 statement")]
    InvalidStatement,
}

/// Closed structural disclosure classification.
///
/// This value does not authorize disclosure, transport, or promotion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatHintV2DisclosureClass {
    /// Structurally identifies the public-auto profile only.
    PublicAutoV1,
    /// Structurally identifies the local review-required profile only.
    ReviewRequiredV1,
}

/// A canonical local ThreatHint v2 statement.
///
/// Direct deserialization is deliberately unavailable; callers must use
/// [`ThreatHintV2Statement::parse_canonical`] with a separately trusted network.
///
/// ```compile_fail
/// use prometheus_threat_hint::ThreatHintV2Statement;
///
/// let _: ThreatHintV2Statement = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreatHintV2Statement {
    schema_version: u16,
    artifact_hash: String,
    observable_commitment: String,
    confidence_bps: u16,
    disclosure_class: ThreatHintV2DisclosureClass,
    report_nonce: String,
    observed_at: u64,
    network_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatHintV2StatementWire {
    schema_version: u16,
    artifact_hash: String,
    observable_commitment: String,
    confidence_bps: u16,
    disclosure_class: ThreatHintV2DisclosureClass,
    report_nonce: String,
    observed_at: u64,
    network_id: String,
}

impl ThreatHintV2Statement {
    /// The only supported ThreatHint v2 statement schema version.
    pub const SCHEMA_VERSION: u16 = THREAT_HINT_V2_SCHEMA_VERSION;

    /// Parses exact canonical bytes against a separately trusted local network.
    pub fn parse_canonical(
        wire_bytes: &[u8],
        trusted_network_id: &str,
    ) -> Result<Self, ThreatHintV2StatementError> {
        if wire_bytes.is_empty() || wire_bytes.len() > MAX_CANONICAL_V2_STATEMENT_BYTES {
            return Err(ThreatHintV2StatementError::InvalidStatement);
        }
        validate_network_id(trusted_network_id)
            .map_err(|_| ThreatHintV2StatementError::InvalidStatement)?;

        let wire: ThreatHintV2StatementWire = serde_json::from_slice(wire_bytes)
            .map_err(|_| ThreatHintV2StatementError::InvalidStatement)?;
        let statement = Self {
            schema_version: wire.schema_version,
            artifact_hash: wire.artifact_hash,
            observable_commitment: wire.observable_commitment,
            confidence_bps: wire.confidence_bps,
            disclosure_class: wire.disclosure_class,
            report_nonce: wire.report_nonce,
            observed_at: wire.observed_at,
            network_id: wire.network_id,
        };

        statement.validate()?;
        if statement.network_id != trusted_network_id {
            return Err(ThreatHintV2StatementError::InvalidStatement);
        }
        if statement.to_canonical_bytes()? != wire_bytes {
            return Err(ThreatHintV2StatementError::InvalidStatement);
        }

        Ok(statement)
    }

    /// Returns the parsed schema version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the asserted artifact SHA-256 as lowercase hexadecimal.
    pub fn artifact_hash_hex(&self) -> &str {
        &self.artifact_hash
    }

    /// Returns the observable bundle commitment as lowercase hexadecimal.
    pub fn observable_commitment_hex(&self) -> &str {
        &self.observable_commitment
    }

    /// Returns the bounded confidence score in basis points.
    pub fn confidence_bps(&self) -> u16 {
        self.confidence_bps
    }

    /// Returns the structural disclosure classification.
    pub fn disclosure_class(&self) -> ThreatHintV2DisclosureClass {
        self.disclosure_class
    }

    /// Returns the report nonce as lowercase hexadecimal.
    pub fn report_nonce_hex(&self) -> &str {
        &self.report_nonce
    }

    /// Returns the positive observed timestamp.
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Returns the network that matched the separately trusted network.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Serializes the validated statement to exact canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThreatHintV2StatementError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| ThreatHintV2StatementError::InvalidStatement)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_V2_STATEMENT_BYTES {
            return Err(ThreatHintV2StatementError::InvalidStatement);
        }
        Ok(bytes)
    }

    /// Computes the domain-separated digest binding every canonical field.
    pub fn statement_digest(&self) -> Result<[u8; 32], ThreatHintV2StatementError> {
        let canonical = self.to_canonical_bytes()?;
        let canonical_len = u32::try_from(canonical.len())
            .map_err(|_| ThreatHintV2StatementError::InvalidStatement)?;

        let mut hasher = Sha256::new();
        hasher.update(STATEMENT_DIGEST_DOMAIN);
        hasher.update(canonical_len.to_be_bytes());
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    fn validate(&self) -> Result<(), ThreatHintV2StatementError> {
        if self.schema_version != Self::SCHEMA_VERSION
            || !is_fixed_lower_hex(&self.artifact_hash)
            || !is_fixed_lower_hex(&self.observable_commitment)
            || self.confidence_bps == 0
            || self.confidence_bps > 10_000
            || !is_fixed_lower_hex(&self.report_nonce)
            || self.observed_at == 0
        {
            return Err(ThreatHintV2StatementError::InvalidStatement);
        }
        validate_network_id(&self.network_id)
            .map_err(|_| ThreatHintV2StatementError::InvalidStatement)
    }
}

fn is_fixed_lower_hex(value: &str) -> bool {
    value.len() == FIXED_HASH_HEX_LEN
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_WIRE: &[u8] = br#"{"schema_version":2,"artifact_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observable_commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","confidence_bps":7500,"disclosure_class":"review_required_v1","report_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","observed_at":1700000000,"network_id":"testnet-10"}"#;

    #[test]
    fn parses_canonical_statement_and_binds_all_fields() {
        let statement =
            ThreatHintV2Statement::parse_canonical(BASE_WIRE, "testnet-10").expect("valid");

        assert_eq!(statement.schema_version(), 2);
        assert_eq!(statement.artifact_hash_hex(), "a".repeat(64));
        assert_eq!(statement.observable_commitment_hex(), "b".repeat(64));
        assert_eq!(statement.confidence_bps(), 7500);
        assert_eq!(
            statement.disclosure_class(),
            ThreatHintV2DisclosureClass::ReviewRequiredV1
        );
        assert_eq!(statement.report_nonce_hex(), "c".repeat(64));
        assert_eq!(statement.observed_at(), 1_700_000_000);
        assert_eq!(statement.network_id(), "testnet-10");
        assert_eq!(
            statement.to_canonical_bytes().expect("canonical"),
            BASE_WIRE
        );
    }

    #[test]
    fn rejects_untrusted_network_mismatch() {
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(BASE_WIRE, "mainnet"),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(b"", "testnet-10"),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(
                &vec![b'{'; MAX_CANONICAL_V2_STATEMENT_BYTES + 1],
                "testnet-10"
            ),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );
    }

    #[test]
    fn rejects_noncanonical_and_extra_input() {
        let mut trailing = BASE_WIRE.to_vec();
        trailing.push(b'\n');
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(&trailing, "testnet-10"),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );

        let unknown = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(
                r#","network_id":"testnet-10"}"#,
                r#","network_id":"testnet-10","proof":"00"}"#,
            );
        assert_eq!(
            ThreatHintV2Statement::parse_canonical(unknown.as_bytes(), "testnet-10"),
            Err(ThreatHintV2StatementError::InvalidStatement)
        );
    }

    #[test]
    fn statement_digest_is_domain_separated_and_deterministic() {
        let statement =
            ThreatHintV2Statement::parse_canonical(BASE_WIRE, "testnet-10").expect("valid");
        let first = statement.statement_digest().expect("digest");
        let second = statement.statement_digest().expect("digest");
        assert_eq!(first, second);

        let mut unrelated = Sha256::new();
        unrelated.update(b"prometheus-threat-observable-bundle-v1\0");
        unrelated.update((BASE_WIRE.len() as u32).to_be_bytes());
        unrelated.update(BASE_WIRE);
        let unrelated: [u8; 32] = unrelated.finalize().into();
        assert_ne!(first, unrelated);
    }
}
