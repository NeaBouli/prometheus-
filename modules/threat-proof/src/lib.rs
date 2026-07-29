#![deny(warnings)]

pub mod relation_manifest_v2;
pub mod threat_hint_v2_groth16_verifier;
pub mod threat_hint_v2_proof_binding;

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use prometheus_threat_hint::{
    ThreatHintEnvelope, ThreatIndicatorType, ThreatProofSystem, MAX_CANONICAL_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RELATION_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const PROOF_SYSTEM: &str = "groth16_bn254_kip16";
pub const VERIFICATION_DOMAIN: &str = "prometheus-threat-hint-v1";
pub const PUBLIC_INPUT_ENCODING: &str = "sha256_split_u128_bn254_v1";
pub const PUBLIC_INPUT_COUNT: u16 = 2;
pub const KIP16_TAG: u8 = 0x20;
pub const KIP16_STATUS_COMMIT: &str = "e4ae2332117b5cb68bd6188e065ef885b6d17939";
pub const RUSTY_KASPA_TAG: &str = "v2.0.1";
pub const RUSTY_KASPA_COMMIT: &str = "cfafeb4c093fa37a303f1b9f19c58f986b870ce3";
pub const ARKWORKS_VERSION: &str = "0.6.0";
pub const VERIFYING_KEY_FILE: &str = "verifying-key.bin";
pub const MAX_MANIFEST_BYTES: usize = 4_096;
pub const MAX_VERIFYING_KEY_BYTES: usize = 65_536;

const STATEMENT_PREFIX: &[u8] = b"prometheus-threat-hint-statement-v1\0";

#[derive(Debug, Error)]
pub enum ThreatProofError {
    #[error("trusted verifier configuration is invalid")]
    InvalidConfiguration,
    #[error("trusted verifier file is unavailable")]
    UnavailableFile(#[source] std::io::Error),
    #[error("relation manifest is invalid")]
    InvalidManifest,
    #[error("relation manifest trust anchor does not match")]
    ManifestTrustMismatch,
    #[error("verifying key is invalid")]
    InvalidVerifyingKey,
    #[error("verifying key trust anchor does not match")]
    VerifyingKeyTrustMismatch,
    #[error("verifier network context does not match")]
    NetworkMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationManifest {
    pub schema_version: u16,
    pub relation_id: String,
    pub relation_source_sha256: String,
    pub proof_system: String,
    pub verification_domain: String,
    pub network_id: String,
    pub public_input_encoding: String,
    pub public_input_count: u16,
    pub kip16_tag: u8,
    pub kip16_status_commit: String,
    pub rusty_kaspa_tag: String,
    pub rusty_kaspa_commit: String,
    pub arkworks_version: String,
    pub verifying_key_file: String,
    pub verifying_key_bytes: u64,
    pub verifying_key_sha256: String,
}

impl RelationManifest {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ThreatProofError> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ThreatProofError::InvalidManifest);
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| ThreatProofError::InvalidManifest)?;
        manifest.validate()?;
        let canonical =
            serde_json::to_vec(&manifest).map_err(|_| ThreatProofError::InvalidManifest)?;
        if canonical != bytes {
            return Err(ThreatProofError::InvalidManifest);
        }
        Ok(manifest)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ThreatProofError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ThreatProofError::InvalidManifest)
    }

    fn validate(&self) -> Result<(), ThreatProofError> {
        if self.schema_version != RELATION_MANIFEST_SCHEMA_VERSION
            || !valid_relation_id(&self.relation_id)
            || !is_lower_hex_32(&self.relation_source_sha256)
            || self.proof_system != PROOF_SYSTEM
            || self.verification_domain != VERIFICATION_DOMAIN
            || !valid_network_id(&self.network_id)
            || self.public_input_encoding != PUBLIC_INPUT_ENCODING
            || self.public_input_count != PUBLIC_INPUT_COUNT
            || self.kip16_tag != KIP16_TAG
            || self.kip16_status_commit != KIP16_STATUS_COMMIT
            || self.rusty_kaspa_tag != RUSTY_KASPA_TAG
            || self.rusty_kaspa_commit != RUSTY_KASPA_COMMIT
            || self.arkworks_version != ARKWORKS_VERSION
            || self.verifying_key_file != VERIFYING_KEY_FILE
            || self.verifying_key_bytes == 0
            || self.verifying_key_bytes > MAX_VERIFYING_KEY_BYTES as u64
            || !is_lower_hex_32(&self.verifying_key_sha256)
        {
            return Err(ThreatProofError::InvalidManifest);
        }
        Ok(())
    }
}

pub struct TrustedGroth16Verifier {
    manifest: RelationManifest,
    prepared_key: PreparedVerifyingKey<Bn254>,
}

impl TrustedGroth16Verifier {
    pub fn load(
        manifest_path: &Path,
        expected_manifest_sha256: &str,
    ) -> Result<Self, ThreatProofError> {
        if !is_lower_hex_32(expected_manifest_sha256) {
            return Err(ThreatProofError::InvalidConfiguration);
        }
        let manifest_bytes = read_owner_file(manifest_path, MAX_MANIFEST_BYTES)?;
        if sha256_hex(&manifest_bytes) != expected_manifest_sha256 {
            return Err(ThreatProofError::ManifestTrustMismatch);
        }
        let manifest = RelationManifest::parse_canonical(&manifest_bytes)?;
        let key_path = manifest_path
            .parent()
            .ok_or(ThreatProofError::InvalidConfiguration)?
            .join(&manifest.verifying_key_file);
        let key_bytes = read_owner_file(&key_path, MAX_VERIFYING_KEY_BYTES)?;
        if key_bytes.len() as u64 != manifest.verifying_key_bytes {
            return Err(ThreatProofError::InvalidVerifyingKey);
        }
        if sha256_hex(&key_bytes) != manifest.verifying_key_sha256 {
            return Err(ThreatProofError::VerifyingKeyTrustMismatch);
        }
        let mut reader = key_bytes.as_slice();
        let key = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|_| ThreatProofError::InvalidVerifyingKey)?;
        if !reader.is_empty() || key.gamma_abc_g1.len() != PUBLIC_INPUT_COUNT as usize + 1 {
            return Err(ThreatProofError::InvalidVerifyingKey);
        }
        let mut canonical_key = Vec::new();
        key.serialize_compressed(&mut canonical_key)
            .map_err(|_| ThreatProofError::InvalidVerifyingKey)?;
        if canonical_key != key_bytes {
            return Err(ThreatProofError::InvalidVerifyingKey);
        }
        Ok(Self {
            manifest,
            prepared_key: prepare_verifying_key(&key),
        })
    }

    pub fn manifest(&self) -> &RelationManifest {
        &self.manifest
    }

    pub fn verify_wire(&self, wire: &[u8], network_id: &str) -> Result<bool, ThreatProofError> {
        if network_id != self.manifest.network_id {
            return Err(ThreatProofError::NetworkMismatch);
        }
        if wire.is_empty() || wire.len() > MAX_CANONICAL_BYTES {
            return Ok(false);
        }
        let envelope = match ThreatHintEnvelope::parse_canonical(wire) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(false),
        };
        if envelope.proof_system() != ThreatProofSystem::Groth16Kip16V1 {
            return Ok(false);
        }
        let proof_bytes = match envelope.proof_bytes() {
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
        let public_inputs = statement_public_inputs(&envelope, network_id)?;
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

pub fn statement_digest(
    envelope: &ThreatHintEnvelope,
    network_id: &str,
) -> Result<[u8; 32], ThreatProofError> {
    if !valid_network_id(network_id) {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    let mut statement = Vec::with_capacity(160);
    statement.extend_from_slice(STATEMENT_PREFIX);
    statement.push(network_id.len() as u8);
    statement.extend_from_slice(network_id.as_bytes());
    statement.extend_from_slice(&envelope.schema_version().to_be_bytes());
    statement.extend_from_slice(
        &hex::decode(envelope.threat_hash()).expect("validated ThreatHint hash"),
    );
    statement.extend_from_slice(&envelope.confidence_bps().to_be_bytes());
    statement.push(indicator_tag(envelope.indicator_type()));
    statement.extend_from_slice(
        &hex::decode(envelope.report_nonce()).expect("validated ThreatHint nonce"),
    );
    statement.extend_from_slice(&envelope.observed_at().to_be_bytes());
    Ok(Sha256::digest(statement).into())
}

pub fn statement_public_inputs(
    envelope: &ThreatHintEnvelope,
    network_id: &str,
) -> Result<[Fr; 2], ThreatProofError> {
    let digest = statement_digest(envelope, network_id)?;
    Ok([
        Fr::from_be_bytes_mod_order(&digest[..16]),
        Fr::from_be_bytes_mod_order(&digest[16..]),
    ])
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn indicator_tag(indicator: ThreatIndicatorType) -> u8 {
    match indicator {
        ThreatIndicatorType::FileHash => 1,
        ThreatIndicatorType::Behavior => 2,
        ThreatIndicatorType::Network => 3,
        ThreatIndicatorType::ApiCall => 4,
    }
}

fn valid_relation_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

pub(crate) fn valid_network_id(value: &str) -> bool {
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
            .is_some_and(u8::is_ascii_alphanumeric)
}

pub(crate) fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

pub(crate) fn read_owner_file(path: &Path, limit: usize) -> Result<Vec<u8>, ThreatProofError> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    validate_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or(ThreatProofError::InvalidConfiguration)?
        .canonicalize()
        .map_err(ThreatProofError::UnavailableFile)?;
    validate_owner_directory(&parent)?;
    let expected = parent.join(
        path.file_name()
            .ok_or(ThreatProofError::InvalidConfiguration)?,
    );
    if expected != path {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    let before = path
        .symlink_metadata()
        .map_err(ThreatProofError::UnavailableFile)?;
    validate_owner_regular_file(&before)?;
    if before.len() == 0 || before.len() > limit as u64 {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    let mut file = File::open(path).map_err(ThreatProofError::UnavailableFile)?;
    let opened = file.metadata().map_err(ThreatProofError::UnavailableFile)?;
    validate_owner_regular_file(&opened)?;
    let after = path
        .symlink_metadata()
        .map_err(ThreatProofError::UnavailableFile)?;
    validate_owner_regular_file(&after)?;
    #[cfg(unix)]
    if before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
    {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    if opened.len() == 0 || opened.len() > limit as u64 {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ThreatProofError::UnavailableFile)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    Ok(bytes)
}

fn validate_absolute_path(path: &Path) -> Result<(), ThreatProofError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_directory(path: &Path) -> Result<(), ThreatProofError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = path.metadata().map_err(ThreatProofError::UnavailableFile)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_directory(_path: &Path) -> Result<(), ThreatProofError> {
    Err(ThreatProofError::InvalidConfiguration)
}

#[cfg(unix)]
fn validate_owner_regular_file(metadata: &std::fs::Metadata) -> Result<(), ThreatProofError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.mode() & 0o400 == 0
    {
        return Err(ThreatProofError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_regular_file(_metadata: &std::fs::Metadata) -> Result<(), ThreatProofError> {
    Err(ThreatProofError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_and_network_identifiers_are_closed() {
        assert!(valid_relation_id("prometheus-threat-membership-v1"));
        assert!(!valid_relation_id("Prometheus"));
        assert!(!valid_relation_id("-bad"));
        assert!(valid_network_id("testnet-10"));
        assert!(!valid_network_id("testnet/10"));
    }
}
