//! Vote commitment creation and verification.
//!
//! Implements the commit phase of the Commit-Reveal voting protocol.
//! Hash formula MUST match ValidatorStaking.ss exactly:
//!   sha256(vote_byte || salt_le_bytes || block_height_le_bytes)
//! where vote_byte = 1u8 if true, 0u8 if false.

use sha2::{Digest, Sha256};

use crate::BOND_PERCENT;

/// Canonical byte length for commit-reveal preimages:
/// vote_byte(1) || salt_le(8) || block_height_le(8).
pub const COMMITMENT_PREIMAGE_LEN: usize = 17;

/// Current upstream Silverc exposes entrypoint integers as signed `int`.
///
/// The H-001 byte formula remains `u64` little-endian on the Rust side, but
/// deployable current-Silverc calls must stay in this nonnegative signed range
/// until a native unsigned contract type is available.
pub const SILVERC_SIGNED_INT_MAX_U64: u64 = i64::MAX as u64;

/// Boundary error for current-Silverc commit-reveal calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentBoundaryError {
    /// Salt cannot be represented as a nonnegative current-Silverc `int`.
    SaltExceedsSilvercInt { salt: u64 },
    /// Block height cannot be represented as a nonnegative current-Silverc `int`.
    BlockHeightExceedsSilvercInt { block_height: u64 },
}

/// A vote commitment for the Commit-Reveal protocol.
/// Matches the VoteCommitment struct in SCHEMA.md 1.4.
#[derive(Debug, Clone, PartialEq)]
pub struct VoteCommitment {
    /// sha256(vote_byte || salt_le || block_height_le)
    pub commitment_hash: [u8; 32],
    /// The proposal being voted on
    pub proposal_id: u64,
    /// The validator's address
    pub validator_addr: [u8; 32],
    /// Block height at commitment time
    pub block_height: u64,
    /// KAS bond locked with this commitment (10% of stake)
    pub bond_kas: u64,
}

/// Builder for creating vote commitments.
pub struct CommitmentBuilder {
    validator_addr: [u8; 32],
}

impl CommitmentBuilder {
    /// Create a new builder for the given validator address.
    pub fn new(validator_addr: [u8; 32]) -> Self {
        Self { validator_addr }
    }

    /// Build a vote commitment with the given parameters.
    ///
    /// The commitment hash is computed as:
    ///   sha256(vote_byte || salt_le_bytes || block_height_le_bytes)
    /// This MUST match the Silverscript contract formula exactly.
    pub fn build(
        &self,
        proposal_id: u64,
        vote: bool,
        salt: u64,
        block_height: u64,
        stake_kas: u64,
    ) -> VoteCommitment {
        let commitment_hash = compute_commitment_hash(vote, salt, block_height);
        let bond_kas = stake_kas * BOND_PERCENT / 100;

        VoteCommitment {
            commitment_hash,
            proposal_id,
            validator_addr: self.validator_addr,
            block_height,
            bond_kas,
        }
    }

    /// Build a commitment for the current-Silverc deployment path.
    ///
    /// Use this when the commitment will be revealed through current upstream
    /// Silverc, whose entrypoint integers are signed. The raw H-001 hash helper
    /// intentionally remains `u64` so historical vectors stay testable.
    pub fn build_silverc_checked(
        &self,
        proposal_id: u64,
        vote: bool,
        salt: u64,
        block_height: u64,
        stake_kas: u64,
    ) -> Result<VoteCommitment, CommitmentBoundaryError> {
        validate_silverc_commitment_bounds(salt, block_height)?;
        Ok(self.build(proposal_id, vote, salt, block_height, stake_kas))
    }

    /// Verify that a commitment matches the given vote and salt.
    ///
    /// Recomputes the hash and compares to the stored commitment.
    pub fn verify(&self, commitment: &VoteCommitment, vote: bool, salt: u64) -> bool {
        let expected = compute_commitment_hash(vote, salt, commitment.block_height);
        expected == commitment.commitment_hash
    }
}

/// Compute the commitment hash matching ValidatorStaking.ss exactly.
///
/// Formula: sha256(vote_byte || salt_le_bytes || block_height_le_bytes)
/// - vote_byte: 1u8 if true, 0u8 if false
/// - salt_le_bytes: salt as 8-byte little-endian
/// - block_height_le_bytes: block_height as 8-byte little-endian
pub fn compute_commitment_hash(vote: bool, salt: u64, block_height: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(commitment_preimage_bytes(vote, salt, block_height));

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validate whether a Rust commitment tuple is representable by current Silverc.
pub fn validate_silverc_commitment_bounds(
    salt: u64,
    block_height: u64,
) -> Result<(), CommitmentBoundaryError> {
    if salt > SILVERC_SIGNED_INT_MAX_U64 {
        return Err(CommitmentBoundaryError::SaltExceedsSilvercInt { salt });
    }

    if block_height > SILVERC_SIGNED_INT_MAX_U64 {
        return Err(CommitmentBoundaryError::BlockHeightExceedsSilvercInt { block_height });
    }

    Ok(())
}

/// Build the canonical commit-reveal preimage.
///
/// This is the H-001 guardrail. Any Silverscript/ssc implementation must hash
/// exactly these 17 bytes for the same `(vote, salt, block_height)` tuple.
pub fn commitment_preimage_bytes(
    vote: bool,
    salt: u64,
    block_height: u64,
) -> [u8; COMMITMENT_PREIMAGE_LEN] {
    let mut preimage = [0u8; COMMITMENT_PREIMAGE_LEN];
    preimage[0] = u8::from(vote);
    preimage[1..9].copy_from_slice(&salt.to_le_bytes());
    preimage[9..17].copy_from_slice(&block_height.to_le_bytes());
    preimage
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDR: [u8; 32] = [0xAA; 32];

    struct H001Vector {
        vote: bool,
        salt: u64,
        block_height: u64,
        preimage_hex: &'static str,
        hash_hex: &'static str,
    }

    const H001_VECTORS: &[H001Vector] = &[
        H001Vector {
            vote: true,
            salt: 42,
            block_height: 1000,
            preimage_hex: "012a00000000000000e803000000000000",
            hash_hex: "cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb",
        },
        H001Vector {
            vote: false,
            salt: 0,
            block_height: 0,
            preimage_hex: "0000000000000000000000000000000000",
            hash_hex: "0a88111852095cae045340ea1f0b279944b2a756a213d9b50107d7489771e159",
        },
        H001Vector {
            vote: true,
            salt: 0x0102_0304_0506_0708,
            block_height: 0x1112_1314_1516_1718,
            preimage_hex: "0108070605040302011817161514131211",
            hash_hex: "66fb23b92e68c968da255e16a553db24a2dff80e2a9bfe6af494b3480a4af651",
        },
        H001Vector {
            vote: false,
            salt: u64::MAX,
            block_height: u64::MAX,
            preimage_hex: "00ffffffffffffffffffffffffffffffff",
            hash_hex: "1d037f75eb96d1ab0615732e2aacdd2a701ecf59fb048987a47cb50a2b483a86",
        },
    ];

    #[test]
    fn test_build_commitment() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let commitment = builder.build(1, true, 42, 1000, 50000);
        assert_eq!(commitment.proposal_id, 1);
        assert_eq!(commitment.validator_addr, TEST_ADDR);
        assert_eq!(commitment.block_height, 1000);
        assert_eq!(commitment.bond_kas, 5000); // 10% of 50000
    }

    #[test]
    fn test_build_silverc_checked_accepts_signed_int_range() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let commitment = builder
            .build_silverc_checked(
                1,
                true,
                SILVERC_SIGNED_INT_MAX_U64,
                SILVERC_SIGNED_INT_MAX_U64,
                50000,
            )
            .expect("max nonnegative signed Silverc values are valid");

        assert_eq!(
            commitment.commitment_hash,
            compute_commitment_hash(
                true,
                SILVERC_SIGNED_INT_MAX_U64,
                SILVERC_SIGNED_INT_MAX_U64,
            )
        );
    }

    #[test]
    fn test_build_silverc_checked_rejects_u64_max_salt() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let err = builder
            .build_silverc_checked(1, true, u64::MAX, 1000, 50000)
            .expect_err("u64::MAX salt is not representable as current-Silverc signed int");

        assert_eq!(
            err,
            CommitmentBoundaryError::SaltExceedsSilvercInt { salt: u64::MAX }
        );
    }

    #[test]
    fn test_build_silverc_checked_rejects_u64_max_block_height() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let err = builder
            .build_silverc_checked(1, true, 42, u64::MAX, 50000)
            .expect_err("u64::MAX block height is not representable as current-Silverc signed int");

        assert_eq!(
            err,
            CommitmentBoundaryError::BlockHeightExceedsSilvercInt {
                block_height: u64::MAX
            }
        );
    }

    #[test]
    fn test_verify_correct() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let commitment = builder.build(1, true, 42, 1000, 50000);
        assert!(builder.verify(&commitment, true, 42));
    }

    #[test]
    fn test_verify_wrong_vote() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let commitment = builder.build(1, true, 42, 1000, 50000);
        assert!(!builder.verify(&commitment, false, 42));
    }

    #[test]
    fn test_verify_wrong_salt() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let commitment = builder.build(1, true, 42, 1000, 50000);
        assert!(!builder.verify(&commitment, true, 999));
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = compute_commitment_hash(true, 42, 1000);
        let h2 = compute_commitment_hash(true, 42, 1000);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_differs_by_vote() {
        let h_true = compute_commitment_hash(true, 42, 1000);
        let h_false = compute_commitment_hash(false, 42, 1000);
        assert_ne!(h_true, h_false);
    }

    #[test]
    fn test_hash_differs_by_salt() {
        let h1 = compute_commitment_hash(true, 1, 1000);
        let h2 = compute_commitment_hash(true, 2, 1000);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_differs_by_block() {
        let h1 = compute_commitment_hash(true, 42, 1000);
        let h2 = compute_commitment_hash(true, 42, 1001);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_bond_calculation() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let c = builder.build(1, true, 42, 1000, 100_000);
        assert_eq!(c.bond_kas, 10_000); // 10% of 100000
    }

    #[test]
    fn test_cross_verify_with_silverscript_formula() {
        // The Silverscript contract computes:
        //   sha256(vote || salt || committed_at_block)
        // where vote is bool (1 byte), salt is uint64 (LE), block is uint64 (LE)
        // This test ensures our Rust implementation matches exactly.
        let hash = compute_commitment_hash(true, 12345, 67890);
        // Manually compute: SHA256(0x01 || 12345_LE || 67890_LE)
        let mut manual = Sha256::new();
        manual.update([1u8]); // true = 1
        manual.update(12345u64.to_le_bytes());
        manual.update(67890u64.to_le_bytes());
        let expected: [u8; 32] = manual.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_h001_commitment_preimage_known_vectors() {
        for vector in H001_VECTORS {
            let preimage = commitment_preimage_bytes(vector.vote, vector.salt, vector.block_height);
            assert_eq!(hex_lower(&preimage), vector.preimage_hex);

            let hash = compute_commitment_hash(vector.vote, vector.salt, vector.block_height);
            assert_eq!(hex_lower(&hash), vector.hash_hex);
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);

        for byte in bytes {
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0x0f) as usize]));
        }

        out
    }
}
