//! Local-only side-effect-free trusted Groth16 verifier for canonical
//! ThreatHint-v2 proof envelopes bound to RelationManifest-v2 artifacts.
//!
//! The verifier owner-loads the manifest, relation source, and verifying key
//! exactly once, pins every byte anchor before use, and then verifies wires
//! only from the retained in-memory manifest bytes and trusted anchors; the
//! manifest is never reread during verification. It never resolves, opens,
//! requires, or generates a proving-key file: the proving-key manifest
//! anchors stay inert metadata. Verification performs no output, file,
//! network, or other side effects. A `true` result is structural Groth16
//! acceptance only: it is not approval, rollout readiness, or authority.

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use prometheus_threat_hint::MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES;
use thiserror::Error;

use crate::relation_manifest_v2::{
    RelationManifestV2, MAX_CANONICAL_V2_MANIFEST_BYTES,
    RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES, RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES,
    RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT,
};
use crate::threat_hint_v2_proof_binding::ThreatHintV2ProofBinding;
use crate::{is_lower_hex_32, read_owner_file, sha256_hex, valid_network_id, VERIFYING_KEY_FILE};

/// Code-fixed sibling relation-source file under the manifest directory.
pub const RELATION_SOURCE_V2_FILE: &str = "relation-source.bin";

/// Redacted failure returned for every unavailable trusted configuration or
/// artifact. Verification-input failures are reported as `Ok(false)` instead.
#[derive(Debug, Error)]
pub enum ThreatHintV2VerifierError {
    /// Trusted configuration or artifacts are unavailable or untrusted.
    #[error("trusted threat-hint v2 verifier is unavailable")]
    Unavailable,
}

/// A trusted Groth16 verifier bound to one canonical RelationManifest-v2 and
/// its exact relation-source and verifying-key artifacts.
pub struct TrustedGroth16V2Verifier {
    manifest_bytes: Vec<u8>,
    trusted_manifest_sha256: String,
    trusted_network_id: String,
    prepared_key: PreparedVerifyingKey<Bn254>,
}

impl TrustedGroth16V2Verifier {
    /// Owner-loads and binds the manifest, relation source, and verifying key
    /// against the separately trusted manifest anchor and network.
    pub fn load(
        manifest_path: &Path,
        expected_manifest_sha256: &str,
        trusted_network_id: &str,
    ) -> Result<Self, ThreatHintV2VerifierError> {
        if !is_lower_hex_32(expected_manifest_sha256) || !valid_network_id(trusted_network_id) {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }
        let manifest_bytes = read_owner_file(manifest_path, MAX_CANONICAL_V2_MANIFEST_BYTES)
            .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;
        if sha256_hex(&manifest_bytes) != expected_manifest_sha256 {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }
        let manifest = RelationManifestV2::parse_canonical(&manifest_bytes, trusted_network_id)
            .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;

        let directory = manifest_path
            .parent()
            .ok_or(ThreatHintV2VerifierError::Unavailable)?;
        let relation_source = read_owner_file(
            &directory.join(RELATION_SOURCE_V2_FILE),
            RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES as usize,
        )
        .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;
        if relation_source.len() as u64 != manifest.relation_source_bytes()
            || sha256_hex(&relation_source) != manifest.relation_source_sha256_hex()
        {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }

        let key_bytes = read_owner_file(
            &directory.join(VERIFYING_KEY_FILE),
            RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES as usize,
        )
        .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;
        if key_bytes.len() as u64 != manifest.verifying_key_bytes()
            || sha256_hex(&key_bytes) != manifest.verifying_key_sha256_hex()
        {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }
        let mut reader = key_bytes.as_slice();
        let key = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;
        if !reader.is_empty()
            || key.gamma_abc_g1.len() != RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT as usize + 1
        {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }
        let mut canonical_key = Vec::new();
        key.serialize_compressed(&mut canonical_key)
            .map_err(|_| ThreatHintV2VerifierError::Unavailable)?;
        if canonical_key != key_bytes {
            return Err(ThreatHintV2VerifierError::Unavailable);
        }

        Ok(Self {
            manifest_bytes,
            trusted_manifest_sha256: expected_manifest_sha256.to_string(),
            trusted_network_id: trusted_network_id.to_string(),
            prepared_key: prepare_verifying_key(&key),
        })
    }

    /// Verifies one canonical envelope wire against the retained trusted
    /// manifest bytes, anchors, and prepared verifying key. Every malformed
    /// or invalid input returns `Ok(false)`; no output or side effects occur.
    pub fn verify_wire(&self, envelope_wire: &[u8]) -> Result<bool, ThreatHintV2VerifierError> {
        if envelope_wire.is_empty() || envelope_wire.len() > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES {
            return Ok(false);
        }
        let binding = match ThreatHintV2ProofBinding::bind_canonical(
            envelope_wire,
            &self.manifest_bytes,
            &self.trusted_network_id,
            &self.trusted_manifest_sha256,
        ) {
            Ok(binding) => binding,
            Err(_) => return Ok(false),
        };
        let proof_bytes = match binding.envelope().proof_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };
        let mut proof_reader = proof_bytes.as_slice();
        let proof = match Proof::<Bn254>::deserialize_compressed(&mut proof_reader) {
            Ok(proof) if proof_reader.is_empty() => proof,
            _ => return Ok(false),
        };
        let mut canonical_proof = Vec::new();
        if proof.serialize_compressed(&mut canonical_proof).is_err()
            || canonical_proof != proof_bytes
        {
            return Ok(false);
        }
        let public_inputs = [
            Fr::from_be_bytes_mod_order(binding.public_input_first_half()),
            Fr::from_be_bytes_mod_order(binding.public_input_second_half()),
        ];
        let prepared_inputs =
            match Groth16::<Bn254>::prepare_inputs(&self.prepared_key, &public_inputs) {
                Ok(inputs) => inputs,
                Err(_) => return Ok(false),
            };
        Ok(Groth16::<Bn254>::verify_proof_with_prepared_inputs(
            &self.prepared_key,
            &proof,
            &prepared_inputs,
        )
        .unwrap_or(false))
    }
}
