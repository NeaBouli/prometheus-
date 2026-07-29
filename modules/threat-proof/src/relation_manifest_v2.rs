//! Local-only canonical RelationManifest-v2 parsing and byte-anchor binding.
//!
//! The manifest binds only closed protocol/relation/proof-system identities,
//! relation-source and key artifact hashes/sizes, public-input encoding/count,
//! the network, and the pinned KIP-16/Kaspa/Arkworks versions. Source and key
//! hashes are byte anchors only: this parser performs no file I/O, key
//! loading, pairing proof, ceremony validation, proof generation or
//! verification, approval, or any other operational action. Proving-key
//! metadata is mandatory but inert. The raw SHA-256 of the canonical manifest
//! bytes is the external trust anchor.
//!
//! `public_input_encoding` is `sha256_split_u128_bn254_v2`: the 32-byte
//! statement digest is split into two 16-byte halves, each interpreted as a
//! big-endian unsigned 128-bit integer. Every such integer is below the
//! BN254 scalar-field modulus (which is greater than 2^128), so each half
//! embeds into a BN254 `Fr` element without reduction and the encoding is
//! injective over the two halves.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ARKWORKS_VERSION, KIP16_STATUS_COMMIT, RUSTY_KASPA_COMMIT, RUSTY_KASPA_TAG};

/// Maximum accepted canonical RelationManifest-v2 wire size.
pub const MAX_CANONICAL_V2_MANIFEST_BYTES: usize = 4_096;
/// The only supported RelationManifest-v2 schema version.
pub const RELATION_MANIFEST_V2_SCHEMA_VERSION: u64 = 2;
/// The exact bound ThreatHint-v2 protocol identity.
pub const RELATION_MANIFEST_V2_PROTOCOL_ID: &str = "/prometheus/threat-hint/2.0.0";
/// The exact bound relation identity.
pub const RELATION_MANIFEST_V2_RELATION_ID: &str = "prometheus-threat-hint-v2";
/// Lowercase hex of the exact ThreatHint-v2 statement digest domain bytes.
pub const RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX: &str =
    "70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200";
/// The exact bound proof-system identity.
pub const RELATION_MANIFEST_V2_PROOF_SYSTEM: &str = "groth16_bn254_kip16";
/// The exact bound KIP-16 tag.
pub const RELATION_MANIFEST_V2_KIP16_TAG: u64 = 32;
/// The exact bound public-input encoding identity.
pub const RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING: &str = "sha256_split_u128_bn254_v2";
/// The exact bound public-input count.
pub const RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT: u64 = 2;
/// Maximum bound for the relation-source byte anchor.
pub const RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES: u64 = 1_048_576;
/// Maximum bound for the inert proving-key byte anchor.
pub const RELATION_MANIFEST_V2_MAX_PROVING_KEY_BYTES: u64 = 1_073_741_824;
/// Maximum bound for the verifying-key byte anchor.
pub const RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES: u64 = 65_536;

const FIXED_HASH_HEX_LEN: usize = 64;

/// Redacted failure returned for every invalid manifest or trusted network.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelationManifestV2Error {
    /// The manifest or separately trusted network is invalid.
    #[error("invalid relation manifest v2")]
    InvalidManifest,
}

/// A canonical local RelationManifest-v2.
///
/// Direct deserialization is deliberately unavailable; callers must use
/// [`RelationManifestV2::parse_canonical`] with a separately trusted network.
/// All fields are private and immutable after parsing.
///
/// ```compile_fail
/// use prometheus_threat_proof::relation_manifest_v2::RelationManifestV2;
///
/// let _: RelationManifestV2 = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelationManifestV2 {
    schema_version: u64,
    protocol_id: String,
    relation_id: String,
    statement_digest_domain_hex: String,
    proof_system: String,
    kip16_tag: u64,
    public_input_encoding: String,
    public_input_count: u64,
    network_id: String,
    relation_source_bytes: u64,
    relation_source_sha256: String,
    proving_key_bytes: u64,
    proving_key_sha256: String,
    verifying_key_bytes: u64,
    verifying_key_sha256: String,
    kip16_status_commit: String,
    rusty_kaspa_tag: String,
    rusty_kaspa_commit: String,
    arkworks_version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationManifestV2Wire {
    schema_version: u64,
    protocol_id: String,
    relation_id: String,
    statement_digest_domain_hex: String,
    proof_system: String,
    kip16_tag: u64,
    public_input_encoding: String,
    public_input_count: u64,
    network_id: String,
    relation_source_bytes: u64,
    relation_source_sha256: String,
    proving_key_bytes: u64,
    proving_key_sha256: String,
    verifying_key_bytes: u64,
    verifying_key_sha256: String,
    kip16_status_commit: String,
    rusty_kaspa_tag: String,
    rusty_kaspa_commit: String,
    arkworks_version: String,
}

impl RelationManifestV2 {
    /// The only supported RelationManifest-v2 schema version.
    pub const SCHEMA_VERSION: u64 = RELATION_MANIFEST_V2_SCHEMA_VERSION;

    /// Parses exact canonical bytes against a separately trusted local network.
    pub fn parse_canonical(
        wire_bytes: &[u8],
        trusted_network_id: &str,
    ) -> Result<Self, RelationManifestV2Error> {
        if wire_bytes.is_empty() || wire_bytes.len() > MAX_CANONICAL_V2_MANIFEST_BYTES {
            return Err(RelationManifestV2Error::InvalidManifest);
        }
        if !is_valid_network_id(trusted_network_id) {
            return Err(RelationManifestV2Error::InvalidManifest);
        }

        let wire: RelationManifestV2Wire = serde_json::from_slice(wire_bytes)
            .map_err(|_| RelationManifestV2Error::InvalidManifest)?;
        let manifest = Self {
            schema_version: wire.schema_version,
            protocol_id: wire.protocol_id,
            relation_id: wire.relation_id,
            statement_digest_domain_hex: wire.statement_digest_domain_hex,
            proof_system: wire.proof_system,
            kip16_tag: wire.kip16_tag,
            public_input_encoding: wire.public_input_encoding,
            public_input_count: wire.public_input_count,
            network_id: wire.network_id,
            relation_source_bytes: wire.relation_source_bytes,
            relation_source_sha256: wire.relation_source_sha256,
            proving_key_bytes: wire.proving_key_bytes,
            proving_key_sha256: wire.proving_key_sha256,
            verifying_key_bytes: wire.verifying_key_bytes,
            verifying_key_sha256: wire.verifying_key_sha256,
            kip16_status_commit: wire.kip16_status_commit,
            rusty_kaspa_tag: wire.rusty_kaspa_tag,
            rusty_kaspa_commit: wire.rusty_kaspa_commit,
            arkworks_version: wire.arkworks_version,
        };

        manifest.validate()?;
        if manifest.network_id != trusted_network_id {
            return Err(RelationManifestV2Error::InvalidManifest);
        }
        if manifest.to_canonical_bytes()? != wire_bytes {
            return Err(RelationManifestV2Error::InvalidManifest);
        }

        Ok(manifest)
    }

    /// Returns the parsed schema version.
    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }

    /// Returns the bound protocol identity.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the bound relation identity.
    pub fn relation_id(&self) -> &str {
        &self.relation_id
    }

    /// Returns the bound statement digest domain as lowercase hexadecimal.
    pub fn statement_digest_domain_hex(&self) -> &str {
        &self.statement_digest_domain_hex
    }

    /// Returns the bound proof-system identity.
    pub fn proof_system(&self) -> &str {
        &self.proof_system
    }

    /// Returns the bound KIP-16 tag.
    pub fn kip16_tag(&self) -> u64 {
        self.kip16_tag
    }

    /// Returns the bound public-input encoding identity.
    pub fn public_input_encoding(&self) -> &str {
        &self.public_input_encoding
    }

    /// Returns the bound public-input count.
    pub fn public_input_count(&self) -> u64 {
        self.public_input_count
    }

    /// Returns the network that matched the separately trusted network.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Returns the asserted relation-source size byte anchor.
    pub fn relation_source_bytes(&self) -> u64 {
        self.relation_source_bytes
    }

    /// Returns the asserted relation-source SHA-256 anchor as lowercase hex.
    pub fn relation_source_sha256_hex(&self) -> &str {
        &self.relation_source_sha256
    }

    /// Returns the asserted inert proving-key size byte anchor.
    pub fn proving_key_bytes(&self) -> u64 {
        self.proving_key_bytes
    }

    /// Returns the asserted inert proving-key SHA-256 anchor as lowercase hex.
    pub fn proving_key_sha256_hex(&self) -> &str {
        &self.proving_key_sha256
    }

    /// Returns the asserted verifying-key size byte anchor.
    pub fn verifying_key_bytes(&self) -> u64 {
        self.verifying_key_bytes
    }

    /// Returns the asserted verifying-key SHA-256 anchor as lowercase hex.
    pub fn verifying_key_sha256_hex(&self) -> &str {
        &self.verifying_key_sha256
    }

    /// Returns the pinned KIP-16 status commit.
    pub fn kip16_status_commit(&self) -> &str {
        &self.kip16_status_commit
    }

    /// Returns the pinned rusty-kaspa tag.
    pub fn rusty_kaspa_tag(&self) -> &str {
        &self.rusty_kaspa_tag
    }

    /// Returns the pinned rusty-kaspa commit.
    pub fn rusty_kaspa_commit(&self) -> &str {
        &self.rusty_kaspa_commit
    }

    /// Returns the pinned Arkworks version.
    pub fn arkworks_version(&self) -> &str {
        &self.arkworks_version
    }

    /// Serializes the validated manifest to exact canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RelationManifestV2Error> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| RelationManifestV2Error::InvalidManifest)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_V2_MANIFEST_BYTES {
            return Err(RelationManifestV2Error::InvalidManifest);
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), RelationManifestV2Error> {
        if self.schema_version != RELATION_MANIFEST_V2_SCHEMA_VERSION
            || self.protocol_id != RELATION_MANIFEST_V2_PROTOCOL_ID
            || self.relation_id != RELATION_MANIFEST_V2_RELATION_ID
            || self.statement_digest_domain_hex != RELATION_MANIFEST_V2_STATEMENT_DIGEST_DOMAIN_HEX
            || self.proof_system != RELATION_MANIFEST_V2_PROOF_SYSTEM
            || self.kip16_tag != RELATION_MANIFEST_V2_KIP16_TAG
            || self.public_input_encoding != RELATION_MANIFEST_V2_PUBLIC_INPUT_ENCODING
            || self.public_input_count != RELATION_MANIFEST_V2_PUBLIC_INPUT_COUNT
            || !is_valid_network_id(&self.network_id)
            || self.relation_source_bytes == 0
            || self.relation_source_bytes > RELATION_MANIFEST_V2_MAX_RELATION_SOURCE_BYTES
            || !is_lower_hex_anchor(&self.relation_source_sha256)
            || self.proving_key_bytes == 0
            || self.proving_key_bytes > RELATION_MANIFEST_V2_MAX_PROVING_KEY_BYTES
            || !is_lower_hex_anchor(&self.proving_key_sha256)
            || self.verifying_key_bytes == 0
            || self.verifying_key_bytes > RELATION_MANIFEST_V2_MAX_VERIFYING_KEY_BYTES
            || !is_lower_hex_anchor(&self.verifying_key_sha256)
            || self.kip16_status_commit != KIP16_STATUS_COMMIT
            || self.rusty_kaspa_tag != RUSTY_KASPA_TAG
            || self.rusty_kaspa_commit != RUSTY_KASPA_COMMIT
            || self.arkworks_version != ARKWORKS_VERSION
        {
            return Err(RelationManifestV2Error::InvalidManifest);
        }
        Ok(())
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
    use super::*;

    const BASE_WIRE: &[u8] = br#"{"schema_version":2,"protocol_id":"/prometheus/threat-hint/2.0.0","relation_id":"prometheus-threat-hint-v2","statement_digest_domain_hex":"70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200","proof_system":"groth16_bn254_kip16","kip16_tag":32,"public_input_encoding":"sha256_split_u128_bn254_v2","public_input_count":2,"network_id":"testnet-10","relation_source_bytes":4096,"relation_source_sha256":"1111111111111111111111111111111111111111111111111111111111111111","proving_key_bytes":1048576,"proving_key_sha256":"2222222222222222222222222222222222222222222222222222222222222222","verifying_key_bytes":1024,"verifying_key_sha256":"3333333333333333333333333333333333333333333333333333333333333333","kip16_status_commit":"e4ae2332117b5cb68bd6188e065ef885b6d17939","rusty_kaspa_tag":"v2.0.1","rusty_kaspa_commit":"cfafeb4c093fa37a303f1b9f19c58f986b870ce3","arkworks_version":"0.6.0"}"#;

    #[test]
    fn parses_canonical_manifest_and_binds_all_fields() {
        let manifest = RelationManifestV2::parse_canonical(BASE_WIRE, "testnet-10").expect("valid");

        assert_eq!(manifest.schema_version(), 2);
        assert_eq!(manifest.protocol_id(), "/prometheus/threat-hint/2.0.0");
        assert_eq!(manifest.relation_id(), "prometheus-threat-hint-v2");
        assert_eq!(
            manifest.statement_digest_domain_hex(),
            hex::encode(b"prometheus-threat-hint-statement-v2\0")
        );
        assert_eq!(manifest.proof_system(), "groth16_bn254_kip16");
        assert_eq!(manifest.kip16_tag(), 32);
        assert_eq!(
            manifest.public_input_encoding(),
            "sha256_split_u128_bn254_v2"
        );
        assert_eq!(manifest.public_input_count(), 2);
        assert_eq!(manifest.network_id(), "testnet-10");
        assert_eq!(manifest.relation_source_bytes(), 4_096);
        assert_eq!(manifest.relation_source_sha256_hex(), "1".repeat(64));
        assert_eq!(manifest.proving_key_bytes(), 1_048_576);
        assert_eq!(manifest.proving_key_sha256_hex(), "2".repeat(64));
        assert_eq!(manifest.verifying_key_bytes(), 1_024);
        assert_eq!(manifest.verifying_key_sha256_hex(), "3".repeat(64));
        assert_eq!(manifest.kip16_status_commit(), KIP16_STATUS_COMMIT);
        assert_eq!(manifest.rusty_kaspa_tag(), RUSTY_KASPA_TAG);
        assert_eq!(manifest.rusty_kaspa_commit(), RUSTY_KASPA_COMMIT);
        assert_eq!(manifest.arkworks_version(), ARKWORKS_VERSION);
        assert_eq!(manifest.to_canonical_bytes().expect("canonical"), BASE_WIRE);
    }

    #[test]
    fn rejects_untrusted_network_mismatch() {
        assert_eq!(
            RelationManifestV2::parse_canonical(BASE_WIRE, "mainnet"),
            Err(RelationManifestV2Error::InvalidManifest)
        );
        assert_eq!(
            RelationManifestV2::parse_canonical(BASE_WIRE, "-testnet-10"),
            Err(RelationManifestV2Error::InvalidManifest)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_input() {
        assert_eq!(
            RelationManifestV2::parse_canonical(b"", "testnet-10"),
            Err(RelationManifestV2Error::InvalidManifest)
        );
        assert_eq!(
            RelationManifestV2::parse_canonical(
                &vec![b'{'; MAX_CANONICAL_V2_MANIFEST_BYTES + 1],
                "testnet-10"
            ),
            Err(RelationManifestV2Error::InvalidManifest)
        );
    }

    #[test]
    fn rejects_noncanonical_and_extra_input() {
        let mut trailing = BASE_WIRE.to_vec();
        trailing.push(b'\n');
        assert_eq!(
            RelationManifestV2::parse_canonical(&trailing, "testnet-10"),
            Err(RelationManifestV2Error::InvalidManifest)
        );

        let unknown = String::from_utf8(BASE_WIRE.to_vec())
            .expect("ASCII")
            .replace(
                r#","arkworks_version":"0.6.0"}"#,
                r#","arkworks_version":"0.6.0","proof":"00"}"#,
            );
        assert_eq!(
            RelationManifestV2::parse_canonical(unknown.as_bytes(), "testnet-10"),
            Err(RelationManifestV2Error::InvalidManifest)
        );
    }
}
