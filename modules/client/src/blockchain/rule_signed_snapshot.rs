//! Bounded development-only signed RuleStorage snapshot provider (GH-211).
//!
//! This module authenticates one strict canonical compact-JSON snapshot
//! envelope and exposes the result only through the existing GH-209
//! [`RuleSnapshotProvider`] trait. The envelope binds schema, kind, the exact
//! Testnet-10 network identifier, a nonzero unsigned sequence, a validity
//! window of at most one hour, the complete [`RuleSyncEntry`] list, and the
//! explicit empty-snapshot order into one domain-separated SHA-256 digest that
//! is verified as a BIP340 signature.
//!
//! Verification trusts only two separately supplied values: the owner-pinned
//! canonical 32-byte x-only public key and the caller's trusted current Unix
//! seconds. Neither value is read from the envelope, the environment, a
//! wallet, or the chain. There is no signer, private-key, wallet, transaction,
//! or broadcast API anywhere on this path.
//!
//! The provider authenticates and bounds the request only. Every GH-207
//! durable-checkpoint and GH-205/GH-197 observation, duplicate, content, and
//! ingest check still runs unchanged downstream; a verified envelope never
//! bypasses that validation, and durable rollback/equivocation protection
//! remains owned by the GH-207 checkpoint order.
//!
//! This is an explicit opt-in development/Testnet-10 boundary. It establishes
//! no canonical manifest authority, independent RPC truth/history/finality,
//! IPFS availability or replication, production YARA quality, wallet or chain
//! action, deployment, Mainnet support, or production readiness.

use std::fmt;
use std::sync::{Arc, OnceLock};

use secp256k1::{schnorr::Signature, Message, Secp256k1, VerifyOnly, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

use super::rule_coordinator::{RuleSnapshotFuture, RuleSnapshotProvider, RuleSnapshotRequest};
use super::rule_ingest::MAX_RULES_PER_SNAPSHOT;
use super::rule_observation::{MAX_MANIFEST_JSON_BYTES, OBSERVATION_NETWORK_ID};
use super::rule_state::MAX_STATE_JSON_BYTES;
use super::rule_sync::RuleSyncEntry;

const ENVELOPE_SCHEMA_VERSION: u64 = 1;
const ENVELOPE_KIND: &str = "prometheus.rule-snapshot.envelope.v1";
const SIGNING_DOMAIN: &[u8] = b"prometheus.rule-snapshot.envelope.v1\0";
const SHA256_HEX_BYTES: usize = 64;
const XONLY_PUBLIC_KEY_BYTES: usize = 32;
const SCHNORR_SIGNATURE_BYTES: usize = 64;

/// Hard pre-parse ceiling for one complete envelope document.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
/// Longest accepted validity window: exactly one hour.
pub const MAX_VALIDITY_WINDOW_SECONDS: u64 = 60 * 60;
/// Hard pre-parse ceiling for one entry address string.
pub const MAX_ADDRESS_BYTES: usize = 256;

const COMPONENT: &str = "signed RuleStorage snapshot provider";

/// Generic redacted failure for the complete verification path.
///
/// Display/Debug/logging never contain envelope bytes, keys, signatures,
/// addresses, hashes, or time values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSnapshotEnvelopeError;

impl fmt::Display for RuleSnapshotEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signed RuleStorage snapshot envelope rejected")
    }
}

impl std::error::Error for RuleSnapshotEnvelopeError {}

/// Separately trusted clock used to enforce envelope freshness on every fetch.
pub trait RuleSnapshotTimeSource: Send + Sync {
    /// Return trusted Unix seconds without exposing clock details on failure.
    fn current_unix_seconds(&self) -> Result<u64, RuleSnapshotEnvelopeError>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeEntry {
    expected_manifest_sha256: String,
    manifest_json: String,
    constructor_json: String,
    address: String,
}

/// Make the empty-snapshot order explicit: the field must always be present
/// as either `null` or an unsigned integer, never omitted.
fn deserialize_required_empty_order<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<u64>::deserialize(deserializer)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEnvelope {
    schema_version: u64,
    kind: String,
    network_id: String,
    sequence: u64,
    valid_from: u64,
    valid_until: u64,
    #[serde(deserialize_with = "deserialize_required_empty_order")]
    empty_snapshot_order: Option<u64>,
    entries: Vec<EnvelopeEntry>,
    signature: String,
}

/// Exact canonical payload bytes covered by the BIP340 signature.
#[derive(Serialize)]
struct SnapshotSigningPayload<'a> {
    schema_version: u64,
    kind: &'a str,
    network_id: &'a str,
    sequence: u64,
    valid_from: u64,
    valid_until: u64,
    empty_snapshot_order: Option<u64>,
    entries: &'a [EnvelopeEntry],
}

/// Verified provider for one authenticated complete-snapshot envelope.
///
/// Construction authenticates immutable bytes once. Every fetch rechecks the
/// runtime mode and validity window through the separately supplied clock.
/// The provider retains no key material, and its `Debug` output is redacted.
pub struct SignedRuleSnapshotProvider {
    mode: RuntimeMode,
    entries: Vec<EnvelopeEntry>,
    empty_snapshot_order: Option<u64>,
    valid_from: u64,
    valid_until: u64,
    clock: Arc<dyn RuleSnapshotTimeSource>,
}

impl fmt::Debug for SignedRuleSnapshotProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRuleSnapshotProvider")
            .finish_non_exhaustive()
    }
}

impl SignedRuleSnapshotProvider {
    /// Verify `envelope_bytes` under the process-wide runtime mode.
    pub fn new(
        envelope_bytes: &[u8],
        owner_xonly_public_key: &[u8; XONLY_PUBLIC_KEY_BYTES],
        minimum_sequence: u64,
        clock: Arc<dyn RuleSnapshotTimeSource>,
    ) -> Result<Self, RuleSnapshotEnvelopeError> {
        require_stub_allowed(COMPONENT).map_err(|_| RuleSnapshotEnvelopeError)?;
        Self::verify(
            RuntimeMode::from_env(),
            envelope_bytes,
            owner_xonly_public_key,
            minimum_sequence,
            clock,
        )
    }

    /// Verify under an explicit runtime mode; identical policy to [`Self::new`].
    /// The explicit mode can only be stricter; it never weakens the
    /// process-wide beta/mainnet env gate.
    pub fn new_for_mode(
        mode: RuntimeMode,
        envelope_bytes: &[u8],
        owner_xonly_public_key: &[u8; XONLY_PUBLIC_KEY_BYTES],
        minimum_sequence: u64,
        clock: Arc<dyn RuleSnapshotTimeSource>,
    ) -> Result<Self, RuleSnapshotEnvelopeError> {
        require_stub_allowed(COMPONENT).map_err(|_| RuleSnapshotEnvelopeError)?;
        require_stub_allowed_for(mode, COMPONENT).map_err(|_| RuleSnapshotEnvelopeError)?;
        Self::verify(
            mode,
            envelope_bytes,
            owner_xonly_public_key,
            minimum_sequence,
            clock,
        )
    }

    fn verify(
        mode: RuntimeMode,
        envelope_bytes: &[u8],
        owner_xonly_public_key: &[u8; XONLY_PUBLIC_KEY_BYTES],
        minimum_sequence: u64,
        clock: Arc<dyn RuleSnapshotTimeSource>,
    ) -> Result<Self, RuleSnapshotEnvelopeError> {
        let public_key = XOnlyPublicKey::from_slice(owner_xonly_public_key)
            .map_err(|_| RuleSnapshotEnvelopeError)?;
        let envelope = parse_envelope(envelope_bytes)?;
        validate_policy(&envelope, minimum_sequence)?;
        validate_time_window(
            envelope.valid_from,
            envelope.valid_until,
            clock.current_unix_seconds()?,
        )?;
        let signature = decode_fixed_hex::<SCHNORR_SIGNATURE_BYTES>(&envelope.signature)?;
        let signature = Signature::from_slice(&signature).map_err(|_| RuleSnapshotEnvelopeError)?;

        let payload = SnapshotSigningPayload {
            schema_version: envelope.schema_version,
            kind: &envelope.kind,
            network_id: &envelope.network_id,
            sequence: envelope.sequence,
            valid_from: envelope.valid_from,
            valid_until: envelope.valid_until,
            empty_snapshot_order: envelope.empty_snapshot_order,
            entries: &envelope.entries,
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|_| RuleSnapshotEnvelopeError)?;
        let digest = domain_digest(SIGNING_DOMAIN, &payload_bytes);
        verification_context()
            .verify_schnorr(&signature, &Message::from_digest(digest), &public_key)
            .map_err(|_| RuleSnapshotEnvelopeError)?;

        Ok(Self {
            mode,
            entries: envelope.entries,
            empty_snapshot_order: envelope.empty_snapshot_order,
            valid_from: envelope.valid_from,
            valid_until: envelope.valid_until,
            clock,
        })
    }
}

impl RuleSnapshotProvider for SignedRuleSnapshotProvider {
    fn fetch_snapshot(&self) -> RuleSnapshotFuture<'_> {
        Box::pin(async move {
            require_stub_allowed(COMPONENT)
                .map_err(|_| super::rule_coordinator::RuleCoordinatorError)?;
            require_stub_allowed_for(self.mode, COMPONENT)
                .map_err(|_| super::rule_coordinator::RuleCoordinatorError)?;
            validate_time_window(
                self.valid_from,
                self.valid_until,
                self.clock
                    .current_unix_seconds()
                    .map_err(|_| super::rule_coordinator::RuleCoordinatorError)?,
            )
            .map_err(|_| super::rule_coordinator::RuleCoordinatorError)?;
            Ok(RuleSnapshotRequest {
                entries: self
                    .entries
                    .iter()
                    .map(|entry| RuleSyncEntry {
                        expected_manifest_sha256: entry.expected_manifest_sha256.clone(),
                        manifest_json: entry.manifest_json.clone(),
                        constructor_json: entry.constructor_json.clone(),
                        address: entry.address.clone(),
                    })
                    .collect(),
                empty_snapshot_order: self.empty_snapshot_order,
            })
        })
    }
}

fn parse_envelope(bytes: &[u8]) -> Result<SnapshotEnvelope, RuleSnapshotEnvelopeError> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(RuleSnapshotEnvelopeError);
    }
    let envelope: SnapshotEnvelope =
        serde_json::from_slice(bytes).map_err(|_| RuleSnapshotEnvelopeError)?;
    let canonical = serde_json::to_vec(&envelope).map_err(|_| RuleSnapshotEnvelopeError)?;
    if canonical != bytes {
        return Err(RuleSnapshotEnvelopeError);
    }
    Ok(envelope)
}

fn validate_policy(
    envelope: &SnapshotEnvelope,
    minimum_sequence: u64,
) -> Result<(), RuleSnapshotEnvelopeError> {
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION
        || envelope.kind != ENVELOPE_KIND
        || envelope.network_id != OBSERVATION_NETWORK_ID
        || minimum_sequence == 0
        || envelope.sequence < minimum_sequence
        || envelope.entries.len() > MAX_RULES_PER_SNAPSHOT
    {
        return Err(RuleSnapshotEnvelopeError);
    }

    validate_time_window(
        envelope.valid_from,
        envelope.valid_until,
        envelope.valid_from,
    )?;

    // Explicit empty-snapshot semantics, mirroring the downstream GH-207
    // contract: an empty snapshot requires a nonzero explicit order, and a
    // non-empty snapshot must not carry one.
    match envelope.empty_snapshot_order {
        Some(order) if envelope.entries.is_empty() && order > 0 => {}
        None if !envelope.entries.is_empty() => {}
        _ => return Err(RuleSnapshotEnvelopeError),
    }

    for entry in &envelope.entries {
        if entry.expected_manifest_sha256.len() != SHA256_HEX_BYTES
            || !entry
                .expected_manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || entry.manifest_json.is_empty()
            || entry.manifest_json.len() > MAX_MANIFEST_JSON_BYTES
            || entry.constructor_json.is_empty()
            || entry.constructor_json.len() > MAX_STATE_JSON_BYTES
            || entry.address.is_empty()
            || entry.address.len() > MAX_ADDRESS_BYTES
        {
            return Err(RuleSnapshotEnvelopeError);
        }
    }
    Ok(())
}

fn validate_time_window(
    valid_from: u64,
    valid_until: u64,
    current_unix_seconds: u64,
) -> Result<(), RuleSnapshotEnvelopeError> {
    let window = valid_until
        .checked_sub(valid_from)
        .ok_or(RuleSnapshotEnvelopeError)?;
    if valid_from == 0
        || window == 0
        || window > MAX_VALIDITY_WINDOW_SECONDS
        || current_unix_seconds < valid_from
        || current_unix_seconds > valid_until
    {
        return Err(RuleSnapshotEnvelopeError);
    }
    Ok(())
}

fn verification_context() -> &'static Secp256k1<VerifyOnly> {
    static CONTEXT: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::verification_only)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], RuleSnapshotEnvelopeError> {
    if value.len() != N * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(RuleSnapshotEnvelopeError);
    }
    let decoded = hex::decode(value).map_err(|_| RuleSnapshotEnvelopeError)?;
    decoded.try_into().map_err(|_| RuleSnapshotEnvelopeError)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_error_is_redacted() {
        assert_eq!(
            RuleSnapshotEnvelopeError.to_string(),
            "signed RuleStorage snapshot envelope rejected"
        );
        assert_eq!(
            format!("{RuleSnapshotEnvelopeError:?}"),
            "RuleSnapshotEnvelopeError"
        );
    }

    #[test]
    fn parser_rejects_unknown_and_noncanonical_data() {
        let unknown = br#"{"schema_version":1,"kind":"prometheus.rule-snapshot.envelope.v1","network_id":"testnet-10","sequence":1,"valid_from":1,"valid_until":2,"empty_snapshot_order":1,"entries":[],"signature":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#;
        assert!(parse_envelope(unknown).is_err());
        let pretty = b"{\n  \"schema_version\": 1\n}";
        assert!(parse_envelope(pretty).is_err());
        let missing_order = br#"{"schema_version":1,"kind":"prometheus.rule-snapshot.envelope.v1","network_id":"testnet-10","sequence":1,"valid_from":1,"valid_until":2,"entries":[],"signature":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert!(parse_envelope(missing_order).is_err());
    }
}
