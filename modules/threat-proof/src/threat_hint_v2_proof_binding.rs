//! Local-only data-only compatibility binding between the canonical
//! ThreatHint-v2 proof envelope and RelationManifest-v2.
//!
//! The binding reparses both canonical objects against one separately trusted
//! network, pins the raw manifest bytes to a separately trusted SHA-256
//! anchor before manifest parsing, cross-checks the exact protocol, relation,
//! and network identities, recomputes the statement digest from the
//! manifest-declared domain bytes, and derives the two claimed 16-byte
//! big-endian public-input halves of the `sha256_split_u128_bn254_v2`
//! encoding.
//!
//! Structural compatibility and the derived claimed public inputs are not
//! Groth16 proof acceptance and not rollout readiness: this module performs
//! no proof verification, key or source loading, circuit or key approval,
//! ceremony validation, file or network I/O, or any other operational
//! action. The proof bytes remain opaque.
//!
//! The fail-closed order is fixed: trusted network and trusted manifest
//! anchor validation, raw manifest byte-anchor comparison, manifest parsing,
//! envelope parsing (which reparses the embedded canonical statement),
//! identity cross-checks, manifest-domain statement-digest recomputation,
//! and public-input encoding/count assertion with half derivation. Steps
//! five through seven are defense-in-depth drift closures: while both public
//! parsers pin the same closed constants those mismatch branches are
//! unreachable, and they are documented here rather than weakening either
//! parser.

use prometheus_threat_hint::ThreatHintV2ProofEnvelope;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::relation_manifest_v2::{
    RelationManifestV2, RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT,
    RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING,
};

const FIXED_HASH_HEX_LEN: usize = 64;

/// Redacted failure returned for every binding, input, or anchor mismatch.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreatHintV2ProofBindingError {
    /// The envelope, manifest, or separately trusted anchors are invalid.
    #[error("invalid threat-hint v2 proof binding")]
    InvalidBinding,
}

/// An immutable in-memory binding between one canonical ThreatHint-v2 proof
/// envelope and one canonical RelationManifest-v2.
///
/// Construction is only possible through
/// [`ThreatHintV2ProofBinding::bind_canonical`]; there is no public
/// constructor and no deserialization or wire format of its own. A bound
/// value is structural compatibility data plus claimed public inputs only:
/// it is not Groth16 proof acceptance and grants no authority.
///
/// ```compile_fail
/// use prometheus_threat_proof::threat_hint_v2_proof_binding::ThreatHintV2ProofBinding;
///
/// let _: ThreatHintV2ProofBinding = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Debug)]
pub struct ThreatHintV2ProofBinding {
    envelope: ThreatHintV2ProofEnvelope,
    manifest: RelationManifestV2,
    raw_manifest_sha256_hex: String,
    statement_digest_hex: String,
    public_input_first_half: [u8; 16],
    public_input_second_half: [u8; 16],
}

impl ThreatHintV2ProofBinding {
    /// Binds raw canonical envelope and manifest bytes against separately
    /// trusted network and manifest anchors in one atomic fail-closed pass.
    pub fn bind_canonical(
        envelope_wire: &[u8],
        manifest_wire: &[u8],
        trusted_network_id: &str,
        trusted_manifest_sha256_hex: &str,
    ) -> Result<Self, ThreatHintV2ProofBindingError> {
        // Step 1: validate the separately trusted network and manifest
        // anchor before any hashing or parsing.
        if !is_valid_network_id(trusted_network_id)
            || !is_lower_hex_anchor(trusted_manifest_sha256_hex)
        {
            return Err(ThreatHintV2ProofBindingError::InvalidBinding);
        }

        // Step 2: compare the exact raw manifest bytes against the trusted
        // anchor before the manifest is parsed.
        let raw_manifest_digest = Sha256::digest(manifest_wire);
        if hex::encode(raw_manifest_digest) != trusted_manifest_sha256_hex {
            return Err(ThreatHintV2ProofBindingError::InvalidBinding);
        }

        // Step 3: parse the canonical manifest against the trusted network.
        let manifest = RelationManifestV2::parse_canonical(manifest_wire, trusted_network_id)
            .map_err(|_| ThreatHintV2ProofBindingError::InvalidBinding)?;

        // Step 4: parse the canonical envelope against the same trusted
        // network; the envelope parser reparses the embedded statement.
        let envelope =
            ThreatHintV2ProofEnvelope::parse_canonical(envelope_wire, trusted_network_id)
                .map_err(|_| ThreatHintV2ProofBindingError::InvalidBinding)?;

        // Step 5: cross-check the exact protocol, relation, and trusted
        // network identities. Defense-in-depth: both parsers already pin
        // these exact values.
        if envelope.protocol_id() != manifest.protocol_id()
            || envelope.relation_id() != manifest.relation_id()
            || manifest.network_id() != trusted_network_id
            || envelope.statement().network_id() != trusted_network_id
        {
            return Err(ThreatHintV2ProofBindingError::InvalidBinding);
        }

        // Step 6: recompute the statement digest from the manifest-declared
        // domain bytes over the parsed canonical statement wire.
        let domain = hex::decode(manifest.statement_digest_domain_hex())
            .map_err(|_| ThreatHintV2ProofBindingError::InvalidBinding)?;
        let canonical_statement = envelope
            .statement()
            .to_canonical_bytes()
            .map_err(|_| ThreatHintV2ProofBindingError::InvalidBinding)?;
        let canonical_len = u32::try_from(canonical_statement.len())
            .map_err(|_| ThreatHintV2ProofBindingError::InvalidBinding)?;
        let mut hasher = Sha256::new();
        hasher.update(&domain);
        hasher.update(canonical_len.to_be_bytes());
        hasher.update(&canonical_statement);
        let statement_digest: [u8; 32] = hasher.finalize().into();
        if hex::encode(statement_digest) != envelope.statement_digest_hex() {
            return Err(ThreatHintV2ProofBindingError::InvalidBinding);
        }

        // Step 7: assert the exact public-input encoding and count, then
        // derive the two claimed 16-byte big-endian unsigned halves.
        if manifest.public_input_encoding() != RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING
            || manifest.public_input_count() != RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT
        {
            return Err(ThreatHintV2ProofBindingError::InvalidBinding);
        }
        let mut public_input_first_half = [0u8; 16];
        public_input_first_half.copy_from_slice(&statement_digest[..16]);
        let mut public_input_second_half = [0u8; 16];
        public_input_second_half.copy_from_slice(&statement_digest[16..]);

        Ok(Self {
            envelope,
            manifest,
            raw_manifest_sha256_hex: hex::encode(raw_manifest_digest),
            statement_digest_hex: hex::encode(statement_digest),
            public_input_first_half,
            public_input_second_half,
        })
    }

    /// Returns the bound canonical ThreatHint-v2 proof envelope.
    pub fn envelope(&self) -> &ThreatHintV2ProofEnvelope {
        &self.envelope
    }

    /// Returns the bound canonical RelationManifest-v2.
    pub fn manifest(&self) -> &RelationManifestV2 {
        &self.manifest
    }

    /// Returns the raw manifest byte SHA-256 anchor as lowercase hex.
    pub fn raw_manifest_sha256_hex(&self) -> &str {
        &self.raw_manifest_sha256_hex
    }

    /// Returns the recomputed statement digest as lowercase hex.
    pub fn statement_digest_hex(&self) -> &str {
        &self.statement_digest_hex
    }

    /// Returns the claimed first 16-byte big-endian public-input half.
    pub fn public_input_first_half(&self) -> &[u8; 16] {
        &self.public_input_first_half
    }

    /// Returns the claimed second 16-byte big-endian public-input half.
    pub fn public_input_second_half(&self) -> &[u8; 16] {
        &self.public_input_second_half
    }
}

fn is_valid_network_id(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

fn is_lower_hex_anchor(value: &str) -> bool {
    value.len() == FIXED_HASH_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
mod tests {
    use prometheus_threat_hint::ThreatHintV2Statement;

    use super::*;
    use crate::sha256_hex;

    const STATEMENT_WIRE: &[u8] = br#"{"schema_version":2,"artifact_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observable_commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","confidence_bps":7500,"disclosure_class":"review_required_v1","report_nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","observed_at":1700000000,"network_id":"testnet-10"}"#;
    const MANIFEST_WIRE: &[u8] = br#"{"schema_version":2,"protocol_id":"/prometheus/threat-hint/2.0.0","relation_id":"prometheus-threat-hint-v2","statement_digest_domain_hex":"70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200","proof_system":"groth16_bn254_kip16","kip16_tag":32,"public_input_encoding":"sha256_split_u128_bn254_v2","public_input_count":2,"network_id":"testnet-10","relation_source_bytes":4096,"relation_source_sha256":"1111111111111111111111111111111111111111111111111111111111111111","proving_key_bytes":1048576,"proving_key_sha256":"2222222222222222222222222222222222222222222222222222222222222222","verifying_key_bytes":1024,"verifying_key_sha256":"3333333333333333333333333333333333333333333333333333333333333333","kip16_status_commit":"e4ae2332117b5cb68bd6188e065ef885b6d17939","rusty_kaspa_tag":"v2.0.1","rusty_kaspa_commit":"cfafeb4c093fa37a303f1b9f19c58f986b870ce3","arkworks_version":"0.6.0"}"#;

    fn sample_envelope_wire() -> Vec<u8> {
        let statement =
            ThreatHintV2Statement::parse_canonical(STATEMENT_WIRE, "testnet-10").expect("valid");
        let digest = hex::encode(statement.statement_digest().expect("digest"));
        let statement_text = String::from_utf8(STATEMENT_WIRE.to_vec()).expect("ASCII");
        format!(
            "{{\"schema_version\":2,\"protocol_id\":\"/prometheus/threat-hint/2.0.0\",\"relation_id\":\"prometheus-threat-hint-v2\",\"statement\":{},\"statement_digest\":\"{digest}\",\"proof\":\"{}\"}}",
            serde_json::to_string(&statement_text).expect("string"),
            "aa".repeat(16)
        )
        .into_bytes()
    }

    fn bind(
        envelope_wire: &[u8],
        manifest_wire: &[u8],
        network: &str,
        anchor: &str,
    ) -> Result<ThreatHintV2ProofBinding, ThreatHintV2ProofBindingError> {
        ThreatHintV2ProofBinding::bind_canonical(envelope_wire, manifest_wire, network, anchor)
    }

    #[test]
    fn binds_matched_envelope_and_manifest() {
        let envelope_wire = sample_envelope_wire();
        let anchor = sha256_hex(MANIFEST_WIRE);
        let binding = bind(&envelope_wire, MANIFEST_WIRE, "testnet-10", &anchor).expect("valid");

        assert_eq!(binding.raw_manifest_sha256_hex(), anchor);
        assert_eq!(
            binding.statement_digest_hex(),
            binding.envelope().statement_digest_hex()
        );
        let digest = hex::decode(binding.statement_digest_hex()).expect("hex");
        assert_eq!(binding.public_input_first_half(), &digest[..16]);
        assert_eq!(binding.public_input_second_half(), &digest[16..]);
        assert_eq!(binding.manifest().network_id(), "testnet-10");
        assert_eq!(
            binding.envelope().protocol_id(),
            binding.manifest().protocol_id()
        );
        assert_eq!(
            binding.envelope().relation_id(),
            binding.manifest().relation_id()
        );
    }

    #[test]
    fn rejects_invalid_trusted_anchors_before_parsing() {
        let envelope_wire = sample_envelope_wire();
        let anchor = sha256_hex(MANIFEST_WIRE);

        for bad in [
            anchor.to_uppercase(),
            "0".repeat(64),
            anchor[..63].to_string(),
            format!("g{}", &anchor[1..]),
            sha256_hex(b"other"),
        ] {
            assert_eq!(
                bind(&envelope_wire, MANIFEST_WIRE, "testnet-10", &bad).unwrap_err(),
                ThreatHintV2ProofBindingError::InvalidBinding
            );
        }
    }

    #[test]
    fn rejects_invalid_and_mismatched_networks() {
        let envelope_wire = sample_envelope_wire();
        let anchor = sha256_hex(MANIFEST_WIRE);

        for bad in ["mainnet", "-testnet-10", "Testnet-10", "a"] {
            assert_eq!(
                bind(&envelope_wire, MANIFEST_WIRE, bad, &anchor).unwrap_err(),
                ThreatHintV2ProofBindingError::InvalidBinding
            );
        }
    }

    #[test]
    fn rejects_tampered_envelope_statement_and_digest() {
        let envelope_wire = sample_envelope_wire();
        let anchor = sha256_hex(MANIFEST_WIRE);

        let tampered_statement = String::from_utf8(envelope_wire.clone())
            .expect("ASCII")
            .replace("7500", "7501");
        assert_eq!(
            bind(
                tampered_statement.as_bytes(),
                MANIFEST_WIRE,
                "testnet-10",
                &anchor
            )
            .unwrap_err(),
            ThreatHintV2ProofBindingError::InvalidBinding
        );

        let statement = ThreatHintV2Statement::parse_canonical(STATEMENT_WIRE, "testnet-10")
            .expect("valid")
            .statement_digest()
            .expect("digest");
        let mut wrong = statement;
        wrong[0] ^= 0xff;
        let tampered_digest = String::from_utf8(envelope_wire)
            .expect("ASCII")
            .replace(&hex::encode(statement), &hex::encode(wrong));
        assert_eq!(
            bind(
                tampered_digest.as_bytes(),
                MANIFEST_WIRE,
                "testnet-10",
                &anchor
            )
            .unwrap_err(),
            ThreatHintV2ProofBindingError::InvalidBinding
        );
    }

    #[test]
    fn error_is_redacted() {
        let error = ThreatHintV2ProofBindingError::InvalidBinding;
        assert_eq!(error.to_string(), "invalid threat-hint v2 proof binding");
    }
}
