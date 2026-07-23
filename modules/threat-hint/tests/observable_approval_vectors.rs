use hex::decode;
use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use prometheus_threat_hint::{
    verify_observable_approval, ObservableApprovalContext, ObservableApprovalError,
    ObservableBundle, MAX_CANONICAL_APPROVAL_BYTES,
};

const SIGNING_DOMAIN: &[u8] = b"prometheus-observable-approval-v1\0";
const APPROVAL_ID_DOMAIN: &[u8] = b"prometheus-observable-approval-id-v1\0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalVector {
    vector_schema_version: u8,
    bundle_wire_hex: String,
    report_nonce_hex: String,
    network_id: String,
    trusted_approver_xonly_public_key_hex: String,
    trusted_recipient_scope_hex: String,
    current_time: u64,
    not_before: u64,
    expires_at: u64,
    approval_nonce_hex: String,
    observable_commitment_hex: String,
    signing_body_hex: String,
    signing_digest_hex: String,
    approval_wire_hex: String,
    approval_id_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalWire {
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
struct SigningBody<'a> {
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

fn vector() -> ApprovalVector {
    serde_json::from_str(include_str!("vectors/threat-observable-approval-v1.json"))
        .expect("valid approval fixture")
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    decode(value)
        .expect("valid fixture hex")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture value must contain exactly {N} bytes"))
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let length = u32::try_from(bytes.len()).expect("test input length fits u32");
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn context<'a>(
    report_nonce: &'a [u8; 32],
    key: &'a [u8; 32],
    recipient_scope: &'a [u8; 32],
    network_id: &'a str,
    current_time: u64,
) -> ObservableApprovalContext<'a> {
    ObservableApprovalContext::new(report_nonce, key, recipient_scope, network_id, current_time)
        .expect("valid trusted test context")
}

fn assert_invalid(
    result: Result<prometheus_threat_hint::VerifiedObservableApproval, ObservableApprovalError>,
) {
    let error = result.expect_err("approval must be rejected");
    assert_eq!(error, ObservableApprovalError::InvalidApproval);
    assert_eq!(error.to_string(), "invalid observable approval");
}

#[test]
fn fixture_contract_and_signature_validate_independently() {
    let vector = vector();
    assert_eq!(vector.vector_schema_version, 1);

    let bundle_wire = decode(&vector.bundle_wire_hex).expect("bundle hex");
    let report_nonce = fixed::<32>(&vector.report_nonce_hex);
    let approval_wire = decode(&vector.approval_wire_hex).expect("approval hex");
    let signing_body = decode(&vector.signing_body_hex).expect("signing-body hex");
    let approval: ApprovalWire =
        serde_json::from_slice(&approval_wire).expect("canonical approval fixture");

    assert_eq!(
        serde_json::to_vec(&approval).expect("serialize approval"),
        approval_wire
    );
    assert_eq!(
        approval.observable_commitment,
        vector.observable_commitment_hex
    );
    assert_eq!(
        approval.approver_xonly_public_key,
        vector.trusted_approver_xonly_public_key_hex
    );
    assert_eq!(approval.recipient_scope, vector.trusted_recipient_scope_hex);
    assert_eq!(approval.network_id, vector.network_id);
    assert_eq!(approval.not_before, vector.not_before);
    assert_eq!(approval.expires_at, vector.expires_at);
    assert_eq!(approval.approval_nonce, vector.approval_nonce_hex);

    let expected_body = SigningBody {
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
    assert_eq!(
        serde_json::to_vec(&expected_body).expect("serialize signing body"),
        signing_body
    );

    let bundle = ObservableBundle::parse_canonical(&bundle_wire).expect("canonical bundle");
    assert_eq!(
        hex::encode(
            bundle
                .commitment(&vector.network_id, &vector.report_nonce_hex)
                .expect("bundle commitment")
        ),
        vector.observable_commitment_hex
    );

    let signing_digest = digest(SIGNING_DOMAIN, &signing_body);
    assert_eq!(hex::encode(signing_digest), vector.signing_digest_hex);
    let signature = Signature::from_slice(&fixed::<64>(&approval.signature))
        .expect("valid Schnorr signature bytes");
    let public_key = XOnlyPublicKey::from_slice(&fixed::<32>(&approval.approver_xonly_public_key))
        .expect("valid x-only public key");
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(signing_digest),
            &public_key,
        )
        .expect("fixture signature verifies independently");

    assert_eq!(
        hex::encode(digest(APPROVAL_ID_DOMAIN, &approval_wire)),
        vector.approval_id_hex
    );
    assert_eq!(report_nonce, fixed::<32>(&vector.report_nonce_hex));
}

#[test]
fn canonical_fixture_verifies_at_inclusive_time_boundaries() {
    let vector = vector();
    let approval_wire = decode(&vector.approval_wire_hex).expect("approval hex");
    let bundle_wire = decode(&vector.bundle_wire_hex).expect("bundle hex");
    let report_nonce = fixed::<32>(&vector.report_nonce_hex);
    let key = fixed::<32>(&vector.trusted_approver_xonly_public_key_hex);
    let recipient_scope = fixed::<32>(&vector.trusted_recipient_scope_hex);

    for current_time in [vector.not_before, vector.current_time, vector.expires_at] {
        let trusted = context(
            &report_nonce,
            &key,
            &recipient_scope,
            &vector.network_id,
            current_time,
        );
        let verified = verify_observable_approval(&approval_wire, &bundle_wire, &trusted)
            .expect("fixture approval verifies");

        assert_eq!(hex::encode(verified.approval_id()), vector.approval_id_hex);
        assert_eq!(
            hex::encode(verified.observable_commitment()),
            vector.observable_commitment_hex
        );
        assert_eq!(verified.approver_xonly_public_key(), key);
        assert_eq!(verified.recipient_scope(), recipient_scope);
        assert_eq!(
            hex::encode(verified.approval_nonce()),
            vector.approval_nonce_hex
        );
        assert_eq!(verified.network_id(), vector.network_id);
        assert_eq!(verified.not_before(), vector.not_before);
        assert_eq!(verified.expires_at(), vector.expires_at);
    }
}

#[test]
fn trusted_context_mismatches_and_expired_windows_are_rejected() {
    let vector = vector();
    let approval_wire = decode(&vector.approval_wire_hex).expect("approval hex");
    let bundle_wire = decode(&vector.bundle_wire_hex).expect("bundle hex");
    let report_nonce = fixed::<32>(&vector.report_nonce_hex);
    let key = fixed::<32>(&vector.trusted_approver_xonly_public_key_hex);
    let recipient_scope = fixed::<32>(&vector.trusted_recipient_scope_hex);

    for current_time in [vector.not_before - 1, vector.expires_at + 1] {
        let trusted = context(
            &report_nonce,
            &key,
            &recipient_scope,
            &vector.network_id,
            current_time,
        );
        assert_invalid(verify_observable_approval(
            &approval_wire,
            &bundle_wire,
            &trusted,
        ));
    }

    let wrong_nonce = [0x44; 32];
    let trusted = context(
        &wrong_nonce,
        &key,
        &recipient_scope,
        &vector.network_id,
        vector.current_time,
    );
    assert_invalid(verify_observable_approval(
        &approval_wire,
        &bundle_wire,
        &trusted,
    ));

    let wrong_key = [0x55; 32];
    let trusted = context(
        &report_nonce,
        &wrong_key,
        &recipient_scope,
        &vector.network_id,
        vector.current_time,
    );
    assert_invalid(verify_observable_approval(
        &approval_wire,
        &bundle_wire,
        &trusted,
    ));

    let wrong_recipient = [0x66; 32];
    let trusted = context(
        &report_nonce,
        &key,
        &wrong_recipient,
        &vector.network_id,
        vector.current_time,
    );
    assert_invalid(verify_observable_approval(
        &approval_wire,
        &bundle_wire,
        &trusted,
    ));

    let trusted = context(
        &report_nonce,
        &key,
        &recipient_scope,
        "mainnet",
        vector.current_time,
    );
    assert_invalid(verify_observable_approval(
        &approval_wire,
        &bundle_wire,
        &trusted,
    ));
}

#[test]
fn tampering_and_noncanonical_inputs_fail_with_one_redacted_error() {
    let vector = vector();
    let approval_wire = decode(&vector.approval_wire_hex).expect("approval hex");
    let bundle_wire = decode(&vector.bundle_wire_hex).expect("bundle hex");
    let report_nonce = fixed::<32>(&vector.report_nonce_hex);
    let key = fixed::<32>(&vector.trusted_approver_xonly_public_key_hex);
    let recipient_scope = fixed::<32>(&vector.trusted_recipient_scope_hex);
    let trusted = context(
        &report_nonce,
        &key,
        &recipient_scope,
        &vector.network_id,
        vector.current_time,
    );

    let approval: ApprovalWire = serde_json::from_slice(&approval_wire).expect("approval fixture");
    let replacement = if approval.signature.starts_with('0') {
        format!("1{}", &approval.signature[1..])
    } else {
        format!("0{}", &approval.signature[1..])
    };
    let tampered_signature = String::from_utf8(approval_wire.clone())
        .expect("ASCII approval")
        .replace(&approval.signature, &replacement)
        .into_bytes();

    let mut whitespace = approval_wire.clone();
    whitespace.push(b'\n');
    let duplicate = String::from_utf8(approval_wire.clone())
        .expect("ASCII approval")
        .replacen('{', r#"{"schema_version":1,"#, 1)
        .into_bytes();
    let mut unknown = approval_wire.clone();
    unknown.pop();
    unknown.extend_from_slice(br#","unexpected":true}"#);
    let oversized = vec![b'{'; MAX_CANONICAL_APPROVAL_BYTES + 1];

    for rejected in [
        tampered_signature,
        whitespace,
        duplicate,
        unknown,
        oversized,
    ] {
        assert_invalid(verify_observable_approval(
            &rejected,
            &bundle_wire,
            &trusted,
        ));
    }

    let sensitive = "secret$context-marker";
    let error = ObservableApprovalContext::new(&report_nonce, &key, &recipient_scope, sensitive, 1)
        .expect_err("invalid network must fail");
    assert_eq!(error.to_string(), "invalid observable approval");
    assert!(!error.to_string().contains(sensitive));
    assert!(!format!("{error:?}").contains(sensitive));
}
