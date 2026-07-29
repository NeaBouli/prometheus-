//! Local-only canonical ThreatHint v2 proof envelope parsing and binding.
//!
//! Structural validity is not proof acceptance: this slice never verifies the
//! proof bytes and never grants any authority. There is deliberately no
//! `proof_system` field and no development stub; a later RelationManifest v2
//! binds `relation_id` to a separately approved proof system and keys.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::observable_bundle::validate_network_id;
use crate::threat_hint_v2_statement::ThreatHintV2Statement;
use crate::MAX_PROOF_BYTES;

const PROOF_ENVELOPE_SCHEMA_VERSION: u16 = 2;
const MIN_PROOF_BYTES: usize = 1;
const DIGEST_HEX_LEN: usize = 64;

/// The only supported ThreatHint v2 proof envelope protocol identifier.
pub const THREAT_HINT_V2_PROTOCOL_ID: &str = "/prometheus/threat-hint/2.0.0";

/// The only supported ThreatHint v2 proof envelope relation identifier.
pub const THREAT_HINT_V2_RELATION_ID: &str = "prometheus-threat-hint-v2";

/// Maximum accepted canonical ThreatHint v2 proof envelope size.
pub const MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES: usize = 4096;

/// Redacted failure returned for every invalid envelope or trusted network.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreatHintV2ProofEnvelopeError {
    /// The envelope or separately trusted network is invalid.
    #[error("invalid threat-hint v2 proof envelope")]
    InvalidEnvelope,
}

/// A canonical local ThreatHint v2 proof envelope.
///
/// The envelope binds a canonical GH-114 statement and its domain-separated
/// digest to opaque proof bytes. Structural validity is not proof acceptance:
/// no proof system is named, and the proof bytes are never verified here.
///
/// Direct deserialization is deliberately unavailable; callers must use
/// [`ThreatHintV2ProofEnvelope::parse_canonical`] with a separately trusted
/// network.
///
/// ```compile_fail
/// use prometheus_threat_hint::ThreatHintV2ProofEnvelope;
///
/// let _: ThreatHintV2ProofEnvelope = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreatHintV2ProofEnvelope {
    schema_version: u16,
    protocol_id: String,
    relation_id: String,
    statement: String,
    statement_digest: String,
    proof: String,
    #[serde(skip)]
    parsed_statement: ThreatHintV2Statement,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatHintV2ProofEnvelopeWire {
    schema_version: u16,
    protocol_id: String,
    relation_id: String,
    statement: String,
    statement_digest: String,
    proof: String,
}

impl ThreatHintV2ProofEnvelope {
    /// The only supported ThreatHint v2 proof envelope schema version.
    pub const SCHEMA_VERSION: u16 = PROOF_ENVELOPE_SCHEMA_VERSION;

    /// Parses exact canonical bytes against a separately trusted local network.
    pub fn parse_canonical(
        wire_bytes: &[u8],
        trusted_network_id: &str,
    ) -> Result<Self, ThreatHintV2ProofEnvelopeError> {
        if wire_bytes.is_empty() || wire_bytes.len() > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        validate_network_id(trusted_network_id)
            .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;

        let wire: ThreatHintV2ProofEnvelopeWire = serde_json::from_slice(wire_bytes)
            .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;
        let parsed_statement =
            ThreatHintV2Statement::parse_canonical(wire.statement.as_bytes(), trusted_network_id)
                .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;

        let envelope = Self {
            schema_version: wire.schema_version,
            protocol_id: wire.protocol_id,
            relation_id: wire.relation_id,
            statement: wire.statement,
            statement_digest: wire.statement_digest,
            proof: wire.proof,
            parsed_statement,
        };

        envelope.validate()?;
        envelope.validate_statement_binding()?;
        if envelope.to_canonical_bytes()? != wire_bytes {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }

        Ok(envelope)
    }

    /// Returns the parsed schema version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the exact protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the exact relation identifier.
    pub fn relation_id(&self) -> &str {
        &self.relation_id
    }

    /// Returns the bound canonical GH-114 statement.
    pub fn statement(&self) -> &ThreatHintV2Statement {
        &self.parsed_statement
    }

    /// Returns the bound statement digest as lowercase hexadecimal.
    pub fn statement_digest_hex(&self) -> &str {
        &self.statement_digest
    }

    /// Returns the opaque proof bytes as lowercase hexadecimal.
    pub fn proof_hex(&self) -> &str {
        &self.proof
    }

    /// Decodes the opaque proof bytes without interpreting them.
    pub fn proof_bytes(&self) -> Result<Vec<u8>, ThreatHintV2ProofEnvelopeError> {
        if !is_valid_proof_hex(&self.proof) {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        hex::decode(&self.proof).map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
    }

    /// Serializes the validated envelope to exact canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThreatHintV2ProofEnvelopeError> {
        self.validate()?;
        self.validate_statement_binding()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), ThreatHintV2ProofEnvelopeError> {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.protocol_id != THREAT_HINT_V2_PROTOCOL_ID
            || self.relation_id != THREAT_HINT_V2_RELATION_ID
            || !is_lower_hex_64(&self.statement_digest)
            || !is_valid_proof_hex(&self.proof)
        {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        Ok(())
    }

    fn validate_statement_binding(&self) -> Result<(), ThreatHintV2ProofEnvelopeError> {
        let statement_bytes = self
            .parsed_statement
            .to_canonical_bytes()
            .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;
        if self.statement.as_bytes() != statement_bytes.as_slice() {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        let digest = self
            .parsed_statement
            .statement_digest()
            .map_err(|_| ThreatHintV2ProofEnvelopeError::InvalidEnvelope)?;
        if hex::encode(digest) != self.statement_digest {
            return Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope);
        }
        Ok(())
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == DIGEST_HEX_LEN
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_valid_proof_hex(value: &str) -> bool {
    if !value.len().is_multiple_of(2)
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return false;
    }
    let raw_len = value.len() / 2;
    (MIN_PROOF_BYTES..=MAX_PROOF_BYTES).contains(&raw_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATEMENT_WIRE: &[u8] = br#"{"schema_version":2,"artifact_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observable_commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","confidence_bps":7500,"disclosure_class":"review_required_v1","report_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","observed_at":1700000000,"network_id":"testnet-10"}"#;

    fn sample_wire() -> Vec<u8> {
        let statement =
            ThreatHintV2Statement::parse_canonical(STATEMENT_WIRE, "testnet-10").expect("valid");
        let digest = hex::encode(statement.statement_digest().expect("digest"));
        let statement_text = String::from_utf8(STATEMENT_WIRE.to_vec()).expect("ASCII");
        format!(
            "{{\"schema_version\":2,\"protocol_id\":\"{THREAT_HINT_V2_PROTOCOL_ID}\",\"relation_id\":\"{THREAT_HINT_V2_RELATION_ID}\",\"statement\":{},\"statement_digest\":\"{digest}\",\"proof\":\"{}\"}}",
            serde_json::to_string(&statement_text).expect("string"),
            "aa".repeat(16)
        )
        .into_bytes()
    }

    #[test]
    fn roundtrip_byte_identity_and_binding() {
        let wire = sample_wire();
        let envelope =
            ThreatHintV2ProofEnvelope::parse_canonical(&wire, "testnet-10").expect("valid");

        assert_eq!(envelope.schema_version(), 2);
        assert_eq!(envelope.protocol_id(), THREAT_HINT_V2_PROTOCOL_ID);
        assert_eq!(envelope.relation_id(), THREAT_HINT_V2_RELATION_ID);
        assert_eq!(
            envelope
                .statement()
                .to_canonical_bytes()
                .expect("canonical"),
            STATEMENT_WIRE
        );
        assert_eq!(
            envelope.statement_digest_hex(),
            hex::encode(envelope.statement().statement_digest().expect("digest"))
        );
        assert_eq!(envelope.proof_bytes().expect("proof"), vec![0xaa; 16]);
        assert_eq!(envelope.to_canonical_bytes().expect("canonical"), wire);
    }

    #[test]
    fn rejects_empty_oversized_and_untrusted_network() {
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(b"", "testnet-10"),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(
                &vec![b'{'; MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES + 1],
                "testnet-10"
            ),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(&sample_wire(), "mainnet"),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(&sample_wire(), "-testnet-10"),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
    }

    #[test]
    fn rejects_trailing_and_noncanonical_input() {
        let mut trailing = sample_wire();
        trailing.push(b'\n');
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(&trailing, "testnet-10"),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );

        let spaced = String::from_utf8(sample_wire())
            .expect("ASCII")
            .replace(",\"protocol_id\"", ", \"protocol_id\"");
        assert_eq!(
            ThreatHintV2ProofEnvelope::parse_canonical(spaced.as_bytes(), "testnet-10"),
            Err(ThreatHintV2ProofEnvelopeError::InvalidEnvelope)
        );
    }
}
