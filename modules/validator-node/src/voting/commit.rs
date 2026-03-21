//! Vote commitment creation and verification.
//!
//! Implements the commit phase of the Commit-Reveal voting protocol.
//! Hash formula MUST match ValidatorStaking.ss exactly:
//!   sha256(vote_byte || salt_le_bytes || block_height_le_bytes)
//! where vote_byte = 1u8 if true, 0u8 if false.

use sha2::{Digest, Sha256};

use crate::BOND_PERCENT;

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

    let vote_byte: u8 = if vote { 1 } else { 0 };
    hasher.update([vote_byte]);
    hasher.update(salt.to_le_bytes());
    hasher.update(block_height.to_le_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDR: [u8; 32] = [0xAA; 32];

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
}
