//! Local-only canonical ThreatHint v2 transport payload framing.
//!
//! The payload carries exactly three untrusted candidate wires: a canonical v2
//! proof envelope, a canonical observable bundle, and a canonical approval. It
//! never carries a relation manifest, current time, trusted network,
//! authority, policy, recipient scope, or any signer key.
//!
//! The 32-byte report nonce is an UNTRUSTED session lookup key only: the
//! constructor checks that it equals the envelope statement nonce for internal
//! consistency, but equality with attacker-controlled bytes grants nothing.
//! Downstream consumers must resolve the nonce against separately trusted
//! active local state before calling promotion.
//!
//! The nested approval receives a canonical shape check only, because full
//! approval verification needs a separately trusted key, recipient scope,
//! current time, and network context. Final approval verification remains
//! downstream via `verify_observable_approval`; shape validity is not
//! approval.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::observable_bundle::validate_network_id;
use crate::{
    ObservableBundle, ThreatHintV2ProofEnvelope, MAX_APPROVAL_LIFETIME_SECONDS,
    MAX_CANONICAL_APPROVAL_BYTES, MAX_CANONICAL_OBSERVABLE_BUNDLE_BYTES,
    MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES,
};

/// Fixed transport payload magic bytes.
pub const THREAT_HINT_V2_TRANSPORT_MAGIC: [u8; 4] = *b"PHT2";
/// The only supported transport payload framing version.
pub const THREAT_HINT_V2_TRANSPORT_VERSION: u8 = 1;
/// Exact untrusted report nonce length in bytes.
pub const REPORT_NONCE_BYTES: usize = 32;
/// Maximum nested canonical v2 proof envelope wire size.
pub const MAX_TRANSPORT_ENVELOPE_BYTES: usize = MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES;
/// Maximum nested canonical observable bundle wire size.
pub const MAX_TRANSPORT_BUNDLE_BYTES: usize = MAX_CANONICAL_OBSERVABLE_BUNDLE_BYTES;
/// Maximum nested canonical approval wire size.
pub const MAX_TRANSPORT_APPROVAL_BYTES: usize = MAX_CANONICAL_APPROVAL_BYTES;

const LENGTH_FIELD_BYTES: usize = 4;
const HEADER_BYTES: usize =
    THREAT_HINT_V2_TRANSPORT_MAGIC.len() + 1 + REPORT_NONCE_BYTES + 3 * LENGTH_FIELD_BYTES;
const NONCE_OFFSET: usize = THREAT_HINT_V2_TRANSPORT_MAGIC.len() + 1;
const ENVELOPE_LEN_OFFSET: usize = NONCE_OFFSET + REPORT_NONCE_BYTES;
const BUNDLE_LEN_OFFSET: usize = ENVELOPE_LEN_OFFSET + LENGTH_FIELD_BYTES;
const APPROVAL_LEN_OFFSET: usize = BUNDLE_LEN_OFFSET + LENGTH_FIELD_BYTES;

/// Maximum accepted transport payload size; the total length is exact.
pub const MAX_TRANSPORT_PAYLOAD_BYTES: usize = HEADER_BYTES
    + MAX_TRANSPORT_ENVELOPE_BYTES
    + MAX_TRANSPORT_BUNDLE_BYTES
    + MAX_TRANSPORT_APPROVAL_BYTES;

const APPROVAL_SHAPE_SCHEMA_VERSION: u16 = 1;
const APPROVAL_SHAPE_PURPOSE: &str = "guardian_analysis_v1";
const FIXED_HASH_HEX_LEN: usize = 64;
const SIGNATURE_HEX_LEN: usize = 128;

/// Redacted failure returned for every invalid payload or trusted network.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThreatHintV2TransportError {
    /// The payload, a nested wire, or the separately trusted network is invalid.
    #[error("invalid threat-hint v2 transport payload")]
    InvalidPayload,
}

/// A canonical local ThreatHint v2 transport payload.
///
/// Direct construction is unavailable; callers must use
/// [`ThreatHintV2TransportPayload::parse_canonical`] with a separately trusted
/// network. The report nonce and all nested wires remain untrusted input:
/// structural validity grants no proof, approval, disclosure, or promotion
/// authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ThreatHintV2TransportPayload {
    report_nonce: [u8; REPORT_NONCE_BYTES],
    envelope_wire: Vec<u8>,
    bundle_wire: Vec<u8>,
    approval_wire: Vec<u8>,
    envelope: ThreatHintV2ProofEnvelope,
    bundle: ObservableBundle,
}

impl core::fmt::Debug for ThreatHintV2TransportPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreatHintV2TransportPayload")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalShapeWire {
    schema_version: u16,
    observable_commitment: String,
    approver_xonly_public_key: String,
    purpose: String,
    recipient_scope: String,
    network_id: String,
    not_before: u64,
    expires_at: u64,
    approval_nonce: String,
    signature: String,
}

impl ThreatHintV2TransportPayload {
    /// Parses exact canonical framing against a separately trusted network.
    ///
    /// The framing has a fixed magic and version, big-endian u32 lengths,
    /// strictly nonzero capped wires, and an exact total length with no
    /// trailing bytes. The constructor independently parses the nested
    /// envelope against `trusted_network_id`, requires the envelope statement
    /// report nonce to equal the payload nonce, parses the nested bundle as
    /// canonical, and applies a canonical shape check to the nested approval.
    pub fn parse_canonical(
        wire_bytes: &[u8],
        trusted_network_id: &str,
    ) -> Result<Self, ThreatHintV2TransportError> {
        if wire_bytes.is_empty() || wire_bytes.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }
        if wire_bytes.len() < HEADER_BYTES + 3 {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }
        if wire_bytes[..THREAT_HINT_V2_TRANSPORT_MAGIC.len()] != THREAT_HINT_V2_TRANSPORT_MAGIC
            || wire_bytes[NONCE_OFFSET - 1] != THREAT_HINT_V2_TRANSPORT_VERSION
        {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }

        let report_nonce: [u8; REPORT_NONCE_BYTES] = wire_bytes
            [NONCE_OFFSET..NONCE_OFFSET + REPORT_NONCE_BYTES]
            .try_into()
            .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;

        let envelope_len = read_be_len(wire_bytes, ENVELOPE_LEN_OFFSET)?;
        let bundle_len = read_be_len(wire_bytes, BUNDLE_LEN_OFFSET)?;
        let approval_len = read_be_len(wire_bytes, APPROVAL_LEN_OFFSET)?;
        if envelope_len == 0
            || envelope_len > MAX_TRANSPORT_ENVELOPE_BYTES
            || bundle_len == 0
            || bundle_len > MAX_TRANSPORT_BUNDLE_BYTES
            || approval_len == 0
            || approval_len > MAX_TRANSPORT_APPROVAL_BYTES
        {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }
        if HEADER_BYTES + envelope_len + bundle_len + approval_len != wire_bytes.len() {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }

        let envelope_start = HEADER_BYTES;
        let bundle_start = envelope_start + envelope_len;
        let approval_start = bundle_start + bundle_len;
        let envelope_wire = wire_bytes[envelope_start..bundle_start].to_vec();
        let bundle_wire = wire_bytes[bundle_start..approval_start].to_vec();
        let approval_wire = wire_bytes[approval_start..].to_vec();

        let envelope =
            ThreatHintV2ProofEnvelope::parse_canonical(&envelope_wire, trusted_network_id)
                .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;
        if envelope.statement().report_nonce_hex() != hex::encode(report_nonce) {
            return Err(ThreatHintV2TransportError::InvalidPayload);
        }

        let bundle = ObservableBundle::parse_canonical(&bundle_wire)
            .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;

        validate_approval_shape(&approval_wire)?;

        Ok(Self {
            report_nonce,
            envelope_wire,
            bundle_wire,
            approval_wire,
            envelope,
            bundle,
        })
    }

    /// Returns the UNTRUSTED report nonce session lookup key.
    ///
    /// Callers must resolve this value against separately trusted active local
    /// state before any promotion; it is attacker-controlled input.
    pub fn report_nonce(&self) -> &[u8; REPORT_NONCE_BYTES] {
        &self.report_nonce
    }

    /// Returns the parsed nested v2 proof envelope.
    pub fn envelope(&self) -> &ThreatHintV2ProofEnvelope {
        &self.envelope
    }

    /// Returns the parsed nested observable bundle.
    pub fn bundle(&self) -> &ObservableBundle {
        &self.bundle
    }

    /// Returns the exact nested envelope wire bytes.
    pub fn envelope_wire(&self) -> &[u8] {
        &self.envelope_wire
    }

    /// Returns the exact nested bundle wire bytes.
    pub fn bundle_wire(&self) -> &[u8] {
        &self.bundle_wire
    }

    /// Returns the exact nested approval wire bytes.
    ///
    /// These bytes passed a canonical shape check only; full approval
    /// verification with a separately trusted context remains downstream.
    pub fn approval_wire(&self) -> &[u8] {
        &self.approval_wire
    }

    /// Serializes the validated payload back to exact canonical framing bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            HEADER_BYTES
                + self.envelope_wire.len()
                + self.bundle_wire.len()
                + self.approval_wire.len(),
        );
        bytes.extend_from_slice(&THREAT_HINT_V2_TRANSPORT_MAGIC);
        bytes.push(THREAT_HINT_V2_TRANSPORT_VERSION);
        bytes.extend_from_slice(&self.report_nonce);
        for wire in [&self.envelope_wire, &self.bundle_wire, &self.approval_wire] {
            bytes.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        }
        for wire in [&self.envelope_wire, &self.bundle_wire, &self.approval_wire] {
            bytes.extend_from_slice(wire);
        }
        bytes
    }
}

fn read_be_len(wire_bytes: &[u8], offset: usize) -> Result<usize, ThreatHintV2TransportError> {
    let field: [u8; LENGTH_FIELD_BYTES] = wire_bytes[offset..offset + LENGTH_FIELD_BYTES]
        .try_into()
        .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;
    Ok(u32::from_be_bytes(field) as usize)
}

/// Applies the canonical approval shape check that is possible without a
/// trusted key, recipient scope, current time, or network context.
///
/// This rejects malformed, noncanonical, mistyped, and out-of-shape approval
/// wires. Trusted key equality, recipient-scope equality, the current-time
/// validity window, bundle commitment binding, and Schnorr signature
/// verification all remain downstream in `verify_observable_approval`.
fn validate_approval_shape(wire_bytes: &[u8]) -> Result<(), ThreatHintV2TransportError> {
    if wire_bytes.is_empty() || wire_bytes.len() > MAX_TRANSPORT_APPROVAL_BYTES {
        return Err(ThreatHintV2TransportError::InvalidPayload);
    }

    let shape: ApprovalShapeWire = serde_json::from_slice(wire_bytes)
        .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;
    let canonical =
        serde_json::to_vec(&shape).map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;
    if canonical != wire_bytes {
        return Err(ThreatHintV2TransportError::InvalidPayload);
    }

    if shape.schema_version != APPROVAL_SHAPE_SCHEMA_VERSION
        || shape.purpose != APPROVAL_SHAPE_PURPOSE
    {
        return Err(ThreatHintV2TransportError::InvalidPayload);
    }
    validate_network_id(&shape.network_id)
        .map_err(|_| ThreatHintV2TransportError::InvalidPayload)?;

    let lifetime = shape
        .expires_at
        .checked_sub(shape.not_before)
        .ok_or(ThreatHintV2TransportError::InvalidPayload)?;
    if shape.not_before == 0 || lifetime == 0 || lifetime > MAX_APPROVAL_LIFETIME_SECONDS {
        return Err(ThreatHintV2TransportError::InvalidPayload);
    }

    if !is_lower_hex(&shape.observable_commitment, FIXED_HASH_HEX_LEN)
        || !is_lower_hex(&shape.approver_xonly_public_key, FIXED_HASH_HEX_LEN)
        || !is_lower_hex(&shape.recipient_scope, FIXED_HASH_HEX_LEN)
        || !is_lower_hex(&shape.approval_nonce, FIXED_HASH_HEX_LEN)
        || !is_lower_hex(&shape.signature, SIGNATURE_HEX_LEN)
    {
        return Err(ThreatHintV2TransportError::InvalidPayload);
    }

    Ok(())
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreatHintV2Statement;

    const NONCE_HEX: &str = "a4805ae9672576df4c3f2f60b9d99ab138206a09dacd82211cfe012e2b17dc22";

    fn statement_wire(network_id: &str) -> Vec<u8> {
        format!(
            "{{\"schema_version\":2,\"artifact_hash\":\"{}\",\"observable_commitment\":\"{}\",\"confidence_bps\":7500,\"disclosure_class\":\"review_required_v1\",\"report_nonce\":\"{NONCE_HEX}\",\"observed_at\":1800000100,\"network_id\":\"{network_id}\"}}",
            "00".repeat(32),
            "11".repeat(32),
        )
        .into_bytes()
    }

    fn envelope_wire(network_id: &str) -> Vec<u8> {
        let statement =
            ThreatHintV2Statement::parse_canonical(&statement_wire(network_id), network_id)
                .expect("valid statement");
        let digest = hex::encode(statement.statement_digest().expect("digest"));
        let statement_text = String::from_utf8(statement_wire(network_id)).expect("ASCII");
        format!(
            "{{\"schema_version\":2,\"protocol_id\":\"/prometheus/threat-hint/2.0.0\",\"relation_id\":\"prometheus-threat-hint-v2\",\"statement\":{},\"statement_digest\":\"{digest}\",\"proof\":\"{}\"}}",
            serde_json::to_string(&statement_text).expect("string"),
            "aa".repeat(16)
        )
        .into_bytes()
    }

    fn bundle_wire() -> Vec<u8> {
        br#"{"schema_version":1,"disclosure_policy":"review_required_v1","scope":{"platform":"linux","format":"elf"},"observables":[{"kind":"api_import","value":"mmap"}]}"#.to_vec()
    }

    fn approval_wire() -> Vec<u8> {
        format!(
            "{{\"schema_version\":1,\"observable_commitment\":\"{}\",\"approver_xonly_public_key\":\"{}\",\"purpose\":\"guardian_analysis_v1\",\"recipient_scope\":\"{}\",\"network_id\":\"testnet-10\",\"not_before\":1800000000,\"expires_at\":1800000600,\"approval_nonce\":\"{}\",\"signature\":\"{}\"}}",
            "5c".repeat(32),
            "86".repeat(32),
            "01".repeat(32),
            "5e".repeat(32),
            "99".repeat(64),
        )
        .into_bytes()
    }

    fn payload_wire() -> Vec<u8> {
        let nonce = hex::decode(NONCE_HEX).expect("hex");
        let envelope = envelope_wire("testnet-10");
        let bundle = bundle_wire();
        let approval = approval_wire();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&THREAT_HINT_V2_TRANSPORT_MAGIC);
        bytes.push(THREAT_HINT_V2_TRANSPORT_VERSION);
        bytes.extend_from_slice(&nonce);
        for wire in [&envelope, &bundle, &approval] {
            bytes.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        }
        for wire in [&envelope, &bundle, &approval] {
            bytes.extend_from_slice(wire);
        }
        bytes
    }

    #[test]
    fn roundtrip_byte_identity_and_nonce_binding() {
        let wire = payload_wire();
        let payload =
            ThreatHintV2TransportPayload::parse_canonical(&wire, "testnet-10").expect("valid");
        assert_eq!(payload.to_canonical_bytes(), wire);
        assert_eq!(hex::encode(payload.report_nonce()), NONCE_HEX);
        assert_eq!(
            payload.envelope_wire(),
            payload
                .envelope()
                .to_canonical_bytes()
                .expect("canonical")
                .as_slice()
        );
        assert_eq!(
            payload.bundle_wire(),
            payload
                .bundle()
                .to_canonical_bytes()
                .expect("canonical")
                .as_slice()
        );
        assert_eq!(payload.envelope().statement().report_nonce_hex(), NONCE_HEX);
    }

    #[test]
    fn rejects_framing_violations() {
        let wire = payload_wire();

        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(b"", "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&wire[..30], "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let mut bad_magic = wire.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&bad_magic, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let mut bad_version = wire.clone();
        bad_version[4] = 2;
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&bad_version, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let mut trailing = wire.clone();
        trailing.push(0x00);
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&trailing, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let mut nonce_mismatch = wire;
        nonce_mismatch[5] ^= 0x01;
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&nonce_mismatch, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );
    }

    #[test]
    fn rejects_wrong_trusted_network_and_bad_nested_wires() {
        let wire = payload_wire();
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&wire, "mainnet"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let envelope_len = envelope_wire("testnet-10").len();
        let bundle_start = HEADER_BYTES + envelope_len;

        let mut bad_bundle = wire.clone();
        bad_bundle[bundle_start] = b' ';
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&bad_bundle, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let mut bad_approval = wire;
        let approval_start = bad_approval.len() - approval_wire().len();
        bad_approval[approval_start] = b' ';
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(&bad_approval, "testnet-10"),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );
    }

    #[test]
    fn approval_shape_check_rejects_context_free_violations() {
        let base = String::from_utf8(approval_wire()).expect("ASCII");

        for mutated in [
            base.replace("\"schema_version\":1", "\"schema_version\":2"),
            base.replace("guardian_analysis_v1", "guardian_analysis_v2"),
            base.replace("\"not_before\":1800000000", "\"not_before\":0"),
            base.replace("\"expires_at\":1800000600", "\"expires_at\":1800003601"),
            base.replace(&"99".repeat(64), &"99".repeat(63)),
            base.replace(&"5c".repeat(32), &"5C".repeat(32)),
            base.replace(":", ": "),
        ] {
            assert_eq!(
                validate_approval_shape(mutated.as_bytes()),
                Err(ThreatHintV2TransportError::InvalidPayload)
            );
        }

        assert!(validate_approval_shape(b"").is_err());
        assert!(validate_approval_shape(&vec![b'{'; MAX_TRANSPORT_APPROVAL_BYTES + 1]).is_err());
        assert!(validate_approval_shape(&approval_wire()).is_ok());
    }

    #[test]
    fn total_size_limit_is_fail_closed() {
        assert_eq!(
            ThreatHintV2TransportPayload::parse_canonical(
                &vec![b'P'; MAX_TRANSPORT_PAYLOAD_BYTES + 1],
                "testnet-10"
            ),
            Err(ThreatHintV2TransportError::InvalidPayload)
        );

        let wire = payload_wire();
        assert!(wire.len() < MAX_TRANSPORT_PAYLOAD_BYTES);
        assert_eq!(
            MAX_TRANSPORT_PAYLOAD_BYTES,
            HEADER_BYTES
                + MAX_TRANSPORT_ENVELOPE_BYTES
                + MAX_TRANSPORT_BUNDLE_BYTES
                + MAX_TRANSPORT_APPROVAL_BYTES
        );
    }
}
