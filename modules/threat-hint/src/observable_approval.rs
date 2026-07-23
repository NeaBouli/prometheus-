//! Local-only verification of canonical Observable Approval statements.

use std::sync::OnceLock;

use secp256k1::{schnorr::Signature, Message, Secp256k1, VerifyOnly, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::observable_bundle::validate_network_id;
use crate::{DisclosurePolicy, ObservableBundle};

const APPROVAL_SCHEMA_VERSION: u16 = 1;
const APPROVAL_PURPOSE: &str = "guardian_analysis_v1";
const APPROVAL_SIGNING_DOMAIN: &[u8] = b"prometheus-observable-approval-v1\0";
const APPROVAL_ID_DOMAIN: &[u8] = b"prometheus-observable-approval-id-v1\0";
const FIXED_HASH_BYTES: usize = 32;
const SCHNORR_SIGNATURE_BYTES: usize = 64;

/// Maximum accepted canonical approval-envelope size.
pub const MAX_CANONICAL_APPROVAL_BYTES: usize = 1024;
/// Maximum duration of one approval statement.
pub const MAX_APPROVAL_LIFETIME_SECONDS: u64 = 60 * 60;

/// Redacted failure returned for every invalid approval or trusted context.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObservableApprovalError {
    /// The approval, bundle, trusted context, time window, or signature is invalid.
    #[error("invalid observable approval")]
    InvalidApproval,
}

/// Independently trusted local context against which an approval is verified.
#[derive(Debug, Clone, Copy)]
pub struct ObservableApprovalContext<'a> {
    report_nonce: &'a [u8; FIXED_HASH_BYTES],
    approver_xonly_public_key: &'a [u8; FIXED_HASH_BYTES],
    recipient_scope: &'a [u8; FIXED_HASH_BYTES],
    network_id: &'a str,
    current_time: u64,
}

impl<'a> ObservableApprovalContext<'a> {
    /// Creates a trusted local verification context.
    pub fn new(
        report_nonce: &'a [u8; FIXED_HASH_BYTES],
        approver_xonly_public_key: &'a [u8; FIXED_HASH_BYTES],
        recipient_scope: &'a [u8; FIXED_HASH_BYTES],
        network_id: &'a str,
        current_time: u64,
    ) -> Result<Self, ObservableApprovalError> {
        validate_network_id(network_id).map_err(|_| ObservableApprovalError::InvalidApproval)?;
        if current_time == 0 {
            return Err(ObservableApprovalError::InvalidApproval);
        }

        Ok(Self {
            report_nonce,
            approver_xonly_public_key,
            recipient_scope,
            network_id,
            current_time,
        })
    }
}

/// Opaque result proving that one approval statement passed every local check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObservableApproval {
    approval_id: [u8; FIXED_HASH_BYTES],
    observable_commitment: [u8; FIXED_HASH_BYTES],
    approver_xonly_public_key: [u8; FIXED_HASH_BYTES],
    recipient_scope: [u8; FIXED_HASH_BYTES],
    approval_nonce: [u8; FIXED_HASH_BYTES],
    network_id: String,
    not_before: u64,
    expires_at: u64,
}

impl VerifiedObservableApproval {
    /// Returns the deterministic identifier a future consumer may persist for replay control.
    pub fn approval_id(&self) -> [u8; FIXED_HASH_BYTES] {
        self.approval_id
    }

    /// Returns the exact bundle commitment authenticated by the approver.
    pub fn observable_commitment(&self) -> [u8; FIXED_HASH_BYTES] {
        self.observable_commitment
    }

    /// Returns the trusted x-only public key that authenticated the statement.
    pub fn approver_xonly_public_key(&self) -> [u8; FIXED_HASH_BYTES] {
        self.approver_xonly_public_key
    }

    /// Returns the trusted recipient-policy digest bound by the statement.
    pub fn recipient_scope(&self) -> [u8; FIXED_HASH_BYTES] {
        self.recipient_scope
    }

    /// Returns the signed nonce. This identifies replays but does not prevent them.
    pub fn approval_nonce(&self) -> [u8; FIXED_HASH_BYTES] {
        self.approval_nonce
    }

    /// Returns the trusted network identifier bound by the statement.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Returns the inclusive lower validity bound.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// Returns the inclusive upper validity bound.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservableApprovalWire {
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

#[derive(Serialize)]
struct ObservableApprovalSigningBody<'a> {
    schema_version: u16,
    observable_commitment: &'a str,
    approver_xonly_public_key: &'a str,
    purpose: &'a str,
    recipient_scope: &'a str,
    network_id: &'a str,
    not_before: u64,
    expires_at: u64,
    approval_nonce: &'a str,
}

/// Verifies one canonical, short-lived approval for one exact review-required bundle.
///
/// This function authenticates a statement only. It performs no signing,
/// replay persistence, transport, analysis, disclosure, wallet, or chain action.
pub fn verify_observable_approval(
    approval_wire: &[u8],
    bundle_wire: &[u8],
    context: &ObservableApprovalContext<'_>,
) -> Result<VerifiedObservableApproval, ObservableApprovalError> {
    if approval_wire.is_empty() || approval_wire.len() > MAX_CANONICAL_APPROVAL_BYTES {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    let approval: ObservableApprovalWire = serde_json::from_slice(approval_wire)
        .map_err(|_| ObservableApprovalError::InvalidApproval)?;
    let canonical =
        serde_json::to_vec(&approval).map_err(|_| ObservableApprovalError::InvalidApproval)?;
    if canonical != approval_wire {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    if approval.schema_version != APPROVAL_SCHEMA_VERSION
        || approval.purpose != APPROVAL_PURPOSE
        || approval.network_id != context.network_id
    {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    validate_time_window(
        approval.not_before,
        approval.expires_at,
        context.current_time,
    )?;

    let observable_commitment =
        decode_fixed_hex::<FIXED_HASH_BYTES>(&approval.observable_commitment)?;
    let approver_xonly_public_key =
        decode_fixed_hex::<FIXED_HASH_BYTES>(&approval.approver_xonly_public_key)?;
    let recipient_scope = decode_fixed_hex::<FIXED_HASH_BYTES>(&approval.recipient_scope)?;
    let approval_nonce = decode_fixed_hex::<FIXED_HASH_BYTES>(&approval.approval_nonce)?;
    let signature = decode_fixed_hex::<SCHNORR_SIGNATURE_BYTES>(&approval.signature)?;

    if !bool::from(approver_xonly_public_key.ct_eq(context.approver_xonly_public_key))
        || !bool::from(recipient_scope.ct_eq(context.recipient_scope))
    {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    let expected_commitment = review_required_commitment(bundle_wire, context)?;
    if !bool::from(observable_commitment.ct_eq(&expected_commitment)) {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    let signing_body = ObservableApprovalSigningBody {
        schema_version: approval.schema_version,
        observable_commitment: &approval.observable_commitment,
        approver_xonly_public_key: &approval.approver_xonly_public_key,
        purpose: &approval.purpose,
        recipient_scope: &approval.recipient_scope,
        network_id: &approval.network_id,
        not_before: approval.not_before,
        expires_at: approval.expires_at,
        approval_nonce: &approval.approval_nonce,
    };
    let signing_body =
        serde_json::to_vec(&signing_body).map_err(|_| ObservableApprovalError::InvalidApproval)?;
    let signing_digest = domain_digest(APPROVAL_SIGNING_DOMAIN, &signing_body);
    let message = Message::from_digest(signing_digest);
    let public_key = XOnlyPublicKey::from_slice(&approver_xonly_public_key)
        .map_err(|_| ObservableApprovalError::InvalidApproval)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| ObservableApprovalError::InvalidApproval)?;
    verification_context()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| ObservableApprovalError::InvalidApproval)?;

    Ok(VerifiedObservableApproval {
        approval_id: domain_digest(APPROVAL_ID_DOMAIN, approval_wire),
        observable_commitment,
        approver_xonly_public_key,
        recipient_scope,
        approval_nonce,
        network_id: approval.network_id,
        not_before: approval.not_before,
        expires_at: approval.expires_at,
    })
}

fn verification_context() -> &'static Secp256k1<VerifyOnly> {
    static CONTEXT: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::verification_only)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ObservableApprovalError> {
    if value.len() != N * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ObservableApprovalError::InvalidApproval);
    }

    let decoded = hex::decode(value).map_err(|_| ObservableApprovalError::InvalidApproval)?;
    decoded
        .try_into()
        .map_err(|_| ObservableApprovalError::InvalidApproval)
}

fn validate_time_window(
    not_before: u64,
    expires_at: u64,
    current_time: u64,
) -> Result<(), ObservableApprovalError> {
    let lifetime = expires_at
        .checked_sub(not_before)
        .ok_or(ObservableApprovalError::InvalidApproval)?;
    if not_before == 0
        || lifetime == 0
        || lifetime > MAX_APPROVAL_LIFETIME_SECONDS
        || current_time < not_before
        || current_time > expires_at
    {
        return Err(ObservableApprovalError::InvalidApproval);
    }
    Ok(())
}

fn review_required_commitment(
    bundle_wire: &[u8],
    context: &ObservableApprovalContext<'_>,
) -> Result<[u8; FIXED_HASH_BYTES], ObservableApprovalError> {
    let bundle = ObservableBundle::parse_canonical(bundle_wire)
        .map_err(|_| ObservableApprovalError::InvalidApproval)?;
    if bundle.disclosure_policy() != DisclosurePolicy::ReviewRequiredV1 {
        return Err(ObservableApprovalError::InvalidApproval);
    }
    bundle
        .commitment(context.network_id, hex::encode(context.report_nonce))
        .map_err(|_| ObservableApprovalError::InvalidApproval)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; FIXED_HASH_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT_NONCE: [u8; FIXED_HASH_BYTES] = [0x11; FIXED_HASH_BYTES];
    const APPROVER_KEY: [u8; FIXED_HASH_BYTES] = [0x22; FIXED_HASH_BYTES];
    const RECIPIENT_SCOPE: [u8; FIXED_HASH_BYTES] = [0x33; FIXED_HASH_BYTES];

    fn context(current_time: u64) -> ObservableApprovalContext<'static> {
        ObservableApprovalContext::new(
            &REPORT_NONCE,
            &APPROVER_KEY,
            &RECIPIENT_SCOPE,
            "testnet-10",
            current_time,
        )
        .expect("valid test context")
    }

    #[test]
    fn time_window_is_inclusive_and_strictly_bounded() {
        assert!(validate_time_window(100, 200, 100).is_ok());
        assert!(validate_time_window(100, 200, 200).is_ok());
        assert!(validate_time_window(100, 100 + MAX_APPROVAL_LIFETIME_SECONDS, 101).is_ok());

        for values in [
            (0, 1, 1),
            (100, 100, 100),
            (101, 100, 100),
            (100, 100 + MAX_APPROVAL_LIFETIME_SECONDS + 1, 101),
            (100, 200, 99),
            (100, 200, 201),
        ] {
            assert_eq!(
                validate_time_window(values.0, values.1, values.2),
                Err(ObservableApprovalError::InvalidApproval)
            );
        }
    }

    #[test]
    fn trusted_context_rejects_invalid_network_and_time() {
        assert_eq!(
            ObservableApprovalContext::new(
                &REPORT_NONCE,
                &APPROVER_KEY,
                &RECIPIENT_SCOPE,
                "Testnet-10",
                1,
            )
            .unwrap_err(),
            ObservableApprovalError::InvalidApproval
        );
        assert_eq!(
            ObservableApprovalContext::new(
                &REPORT_NONCE,
                &APPROVER_KEY,
                &RECIPIENT_SCOPE,
                "testnet-10",
                0,
            )
            .unwrap_err(),
            ObservableApprovalError::InvalidApproval
        );
    }

    #[test]
    fn public_auto_bundle_cannot_enter_approval_verification() {
        let bundle = br#"{"schema_version":1,"disclosure_policy":"public_auto_v1","scope":{"platform":"linux","format":"elf"},"observables":[{"kind":"api_import","value":"mmap"}]}"#;
        assert_eq!(
            review_required_commitment(bundle, &context(150)),
            Err(ObservableApprovalError::InvalidApproval)
        );
    }

    #[test]
    fn errors_do_not_echo_rejected_values() {
        let rejected = "sensitive$network";
        let error = ObservableApprovalContext::new(
            &REPORT_NONCE,
            &APPROVER_KEY,
            &RECIPIENT_SCOPE,
            rejected,
            1,
        )
        .unwrap_err();
        assert!(!error.to_string().contains(rejected));
        assert!(!format!("{error:?}").contains(rejected));
    }
}
