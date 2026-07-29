#![deny(warnings)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod api_import_producer;
mod byte_pattern_producer;
mod file_sha256_producer;
mod observable_approval;
pub mod observable_bundle;
mod threat_hint_v2_proof_envelope;
mod threat_hint_v2_statement;

pub use api_import_producer::{
    produce_elf_api_import_bundle, ElfApiImportProducerError, MAX_ELF_API_IMPORT_ARTIFACT_BYTES,
    MAX_ELF_DYNAMIC_SYMBOLS,
};
pub use byte_pattern_producer::produce_byte_pattern_bundle;
pub use file_sha256_producer::produce_file_sha256_bundle;
pub use observable_approval::{
    verify_observable_approval, ObservableApprovalContext, ObservableApprovalError,
    VerifiedObservableApproval, MAX_APPROVAL_LIFETIME_SECONDS, MAX_CANONICAL_APPROVAL_BYTES,
};
pub use observable_bundle::{
    DisclosurePolicy, ObservableBundle, ObservableBundleError, ObservableKind, ObservableScope,
    ScopeFormat, ScopePlatform,
};
pub use threat_hint_v2_proof_envelope::{
    ThreatHintV2ProofEnvelope, ThreatHintV2ProofEnvelopeError,
    MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES, THREAT_HINT_V2_PROTOCOL_ID, THREAT_HINT_V2_RELATION_ID,
};
pub use threat_hint_v2_statement::{
    ThreatHintV2DisclosureClass, ThreatHintV2Statement, ThreatHintV2StatementError,
    MAX_CANONICAL_V2_STATEMENT_BYTES,
};

pub const MAX_CANONICAL_BYTES: usize = 2048;
pub const HASH_HEX_LEN: usize = 64;
const MIN_PROOF_BYTES: usize = 1;
pub const MAX_PROOF_BYTES: usize = 1024;

pub const SCHEMA_VERSION: u16 = 1;
pub const CONFIDENCE_BPS_MAX: u16 = 10_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreatHintError {
    #[error("invalid threat-hint payload")]
    InvalidPayload,
    #[error("unsupported schema version")]
    InvalidSchemaVersion,
    #[error("invalid threat hash")]
    InvalidThreatHash,
    #[error("invalid report nonce")]
    InvalidReportNonce,
    #[error("invalid confidence score")]
    InvalidConfidence,
    #[error("invalid proof")]
    InvalidProof,
    #[error("invalid observed_at value")]
    InvalidTimestamp,
    #[error("envelope exceeds 2048-byte canonical limit")]
    EnvelopeTooLarge,
    #[error("non-canonical payload")]
    NotCanonical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIndicatorType {
    FileHash,
    Behavior,
    Network,
    ApiCall,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatProofSystem {
    #[serde(rename = "groth16_kip16_v1")]
    Groth16Kip16V1,
    #[serde(rename = "development_stub_v1")]
    DevelopmentStubV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ThreatHintEnvelope {
    schema_version: u16,
    threat_hash: String,
    confidence_bps: u16,
    indicator_type: ThreatIndicatorType,
    proof_system: ThreatProofSystem,
    proof: String,
    report_nonce: String,
    observed_at: u64,
}

impl ThreatHintEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threat_hash: impl Into<String>,
        confidence_bps: u16,
        indicator_type: ThreatIndicatorType,
        proof_system: ThreatProofSystem,
        proof: Vec<u8>,
        report_nonce: impl Into<String>,
        observed_at: u64,
    ) -> Result<Self, ThreatHintError> {
        let threat_hash = threat_hash.into();
        let report_nonce = report_nonce.into();

        validate_schema_version(SCHEMA_VERSION)?;
        validate_hex_64(&threat_hash).map_err(|_| ThreatHintError::InvalidThreatHash)?;
        validate_hex_64(&report_nonce).map_err(|_| ThreatHintError::InvalidReportNonce)?;
        validate_confidence(confidence_bps).map_err(|_| ThreatHintError::InvalidConfidence)?;
        validate_observed_at(observed_at).map_err(|_| ThreatHintError::InvalidTimestamp)?;

        if proof.len() < MIN_PROOF_BYTES || proof.len() > MAX_PROOF_BYTES {
            return Err(ThreatHintError::InvalidProof);
        }

        let env = ThreatHintEnvelope {
            schema_version: SCHEMA_VERSION,
            threat_hash,
            confidence_bps,
            indicator_type,
            proof_system,
            proof: hex::encode(proof),
            report_nonce,
            observed_at,
        };

        if env.to_canonical_bytes()?.len() > MAX_CANONICAL_BYTES {
            return Err(ThreatHintError::EnvelopeTooLarge);
        }

        Ok(env)
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn threat_hash(&self) -> &str {
        &self.threat_hash
    }

    pub fn confidence_bps(&self) -> u16 {
        self.confidence_bps
    }

    pub fn indicator_type(&self) -> ThreatIndicatorType {
        self.indicator_type
    }

    pub fn proof_system(&self) -> ThreatProofSystem {
        self.proof_system
    }

    pub fn proof_hex(&self) -> &str {
        &self.proof
    }

    pub fn proof_bytes(&self) -> Result<Vec<u8>, ThreatHintError> {
        decode_proof(&self.proof)
    }

    pub fn report_nonce(&self) -> &str {
        &self.report_nonce
    }

    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThreatHintError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ThreatHintError::InvalidPayload)?;
        if bytes.len() > MAX_CANONICAL_BYTES {
            Err(ThreatHintError::EnvelopeTooLarge)
        } else {
            Ok(bytes)
        }
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ThreatHintError> {
        if bytes.is_empty() {
            return Err(ThreatHintError::InvalidPayload);
        }
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(ThreatHintError::EnvelopeTooLarge);
        }

        let env: ThreatHintEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ThreatHintError::InvalidPayload)?;

        if env.to_canonical_bytes()? != bytes {
            return Err(ThreatHintError::NotCanonical);
        }

        validate_schema_version(env.schema_version)
            .map_err(|_| ThreatHintError::InvalidSchemaVersion)?;
        validate_hex_64(&env.threat_hash).map_err(|_| ThreatHintError::InvalidThreatHash)?;
        validate_hex_64(&env.report_nonce).map_err(|_| ThreatHintError::InvalidReportNonce)?;
        validate_confidence(env.confidence_bps).map_err(|_| ThreatHintError::InvalidConfidence)?;
        validate_observed_at(env.observed_at).map_err(|_| ThreatHintError::InvalidTimestamp)?;

        decode_proof(&env.proof)?;

        Ok(env)
    }
}

fn decode_proof(value: &str) -> Result<Vec<u8>, ThreatHintError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(is_hex_lower_byte) {
        return Err(ThreatHintError::InvalidProof);
    }
    let proof = hex::decode(value).map_err(|_| ThreatHintError::InvalidProof)?;
    if proof.len() < MIN_PROOF_BYTES || proof.len() > MAX_PROOF_BYTES {
        return Err(ThreatHintError::InvalidProof);
    }
    Ok(proof)
}

fn is_hex_lower_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn validate_schema_version(version: u16) -> Result<(), ThreatHintError> {
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ThreatHintError::InvalidSchemaVersion)
    }
}

fn validate_hex_64(value: &str) -> Result<(), ThreatHintError> {
    if value.len() != HASH_HEX_LEN {
        return Err(ThreatHintError::InvalidPayload);
    }

    if !value.as_bytes().iter().all(|b| is_hex_lower_byte(*b)) {
        return Err(ThreatHintError::InvalidPayload);
    }

    if hex::decode(value).is_err() {
        return Err(ThreatHintError::InvalidPayload);
    }

    Ok(())
}

fn validate_confidence(confidence_bps: u16) -> Result<(), ThreatHintError> {
    if confidence_bps == 0 || confidence_bps > CONFIDENCE_BPS_MAX {
        return Err(ThreatHintError::InvalidConfidence);
    }

    Ok(())
}

fn validate_observed_at(observed_at: u64) -> Result<(), ThreatHintError> {
    if observed_at == 0 {
        Err(ThreatHintError::InvalidTimestamp)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use serde_json::{Map, Value};

    fn sample() -> ThreatHintEnvelope {
        ThreatHintEnvelope::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            420,
            ThreatIndicatorType::FileHash,
            ThreatProofSystem::Groth16Kip16V1,
            vec![0xaa; 16],
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            1_700_000_000,
        )
        .expect("valid sample")
    }

    #[test]
    fn roundtrip_and_byte_identity() {
        let canonical = sample().to_canonical_bytes().unwrap();
        let parsed = ThreatHintEnvelope::parse_canonical(&canonical).unwrap();
        assert_eq!(parsed, sample());
        assert_eq!(parsed.to_canonical_bytes().unwrap(), canonical);
    }

    #[test]
    fn rejects_non_canonical_whitespace_and_reordered_fields() {
        let canonical = sample().to_canonical_bytes().unwrap();
        let pretty = String::from_utf8(canonical.clone())
            .unwrap()
            .replace(',', ", ")
            .replace(':', ": ");
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(pretty.as_bytes()),
            Err(ThreatHintError::NotCanonical)
        );

        let value: Value = serde_json::from_slice(&canonical).unwrap();
        let object = value.as_object().unwrap();
        let reordered: Map<String, Value> = [
            "threat_hash",
            "schema_version",
            "confidence_bps",
            "proof_system",
            "indicator_type",
            "proof",
            "observed_at",
            "report_nonce",
        ]
        .iter()
        .map(|key| (key.to_string(), object.get(*key).cloned().unwrap()))
        .collect();
        let reordered = serde_json::to_vec(&Value::Object(reordered)).unwrap();
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&reordered),
            Err(ThreatHintError::NotCanonical)
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate_fields() {
        let unknown = b"{\"schema_version\":1,\"threat_hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"confidence_bps\":420,\"indicator_type\":\"file_hash\",\"proof_system\":\"groth16_kip16_v1\",\"proof\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"report_nonce\":\"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\",\"observed_at\":1700000000,\"reporter_id\":\"x\"}";
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(unknown),
            Err(ThreatHintError::InvalidPayload)
        );

        let duplicate = b"{\"schema_version\":1,\"threat_hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"confidence_bps\":420,\"indicator_type\":\"file_hash\",\"proof_system\":\"groth16_kip16_v1\",\"proof\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"threat_hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"report_nonce\":\"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\",\"observed_at\":1700000000}";
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(duplicate),
            Err(ThreatHintError::InvalidPayload)
        );
    }

    #[test]
    fn rejects_bad_version_hash_nonce_confidence_proof_timestamp() {
        let mut bad: Value =
            serde_json::from_slice(&sample().to_canonical_bytes().unwrap()).unwrap();
        bad["schema_version"] = 2.into();
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(matches!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::InvalidSchemaVersion) | Err(ThreatHintError::NotCanonical)
        ));

        bad["schema_version"] = json!(1);
        bad["threat_hash"] = json!("zzzz");
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(matches!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::InvalidThreatHash) | Err(ThreatHintError::NotCanonical)
        ));

        bad["threat_hash"] =
            json!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        bad["confidence_bps"] = json!(20_001);
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::NotCanonical)
        );

        bad["confidence_bps"] = json!(420);
        bad["proof"] = json!("AA");
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::NotCanonical)
        );

        bad["proof"] = json!("aa");
        bad["report_nonce"] = json!("abcd");
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::NotCanonical)
        );

        bad["report_nonce"] =
            json!("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        bad["observed_at"] = json!(0);
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::NotCanonical)
        );
    }

    #[test]
    fn rejects_bad_proof_size_and_trailing_bytes() {
        assert!(ThreatHintEnvelope::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            420,
            ThreatIndicatorType::FileHash,
            ThreatProofSystem::Groth16Kip16V1,
            vec![],
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            1,
        )
        .is_err());

        assert!(ThreatHintEnvelope::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            420,
            ThreatIndicatorType::FileHash,
            ThreatProofSystem::Groth16Kip16V1,
            vec![0u8; 1025],
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            1,
        )
        .is_err());

        let canonical = String::from_utf8(sample().to_canonical_bytes().unwrap()).unwrap();
        let uppercase = canonical.replace(
            "\"proof\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"proof\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
        );
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(uppercase.as_bytes()),
            Err(ThreatHintError::InvalidProof)
        );
        let odd = canonical.replace(
            "\"proof\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"proof\":\"aaa\"",
        );
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(odd.as_bytes()),
            Err(ThreatHintError::InvalidProof)
        );

        let mut bytes = sample().to_canonical_bytes().unwrap();
        bytes.extend_from_slice(b" 123");
        assert_eq!(
            ThreatHintEnvelope::parse_canonical(&bytes),
            Err(ThreatHintError::InvalidPayload)
        );
    }

    #[test]
    fn rejects_overall_size_limit() {
        assert!(ThreatHintEnvelope::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            420,
            ThreatIndicatorType::FileHash,
            ThreatProofSystem::Groth16Kip16V1,
            vec![0xaa; 1024],
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            1,
        )
        .is_err());
    }
}
