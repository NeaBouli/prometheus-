//! Vote reveal validation logic.
//!
//! Implements the reveal phase of the Commit-Reveal protocol.
//! Verifies that the revealed vote matches the commitment hash.
//! On mismatch: bond is slashed via ValidatorStaking contract.

use super::commit::{compute_commitment_hash, VoteCommitment};
use crate::BOND_PERCENT;

/// Result of validating a vote reveal.
#[derive(Debug, Clone, PartialEq)]
pub enum RevealResult {
    /// Reveal matches the commitment — bond returned.
    Valid,
    /// Hash mismatch — bond is slashed.
    InvalidHash {
        /// The expected hash from the commitment
        expected: [u8; 32],
        /// The hash computed from the revealed values
        got: [u8; 32],
    },
    /// Bond provided is less than required (10% of stake).
    BondInsufficient {
        /// Required bond amount
        required: u64,
        /// Actually provided bond
        provided: u64,
    },
}

/// Validates vote reveals against stored commitments.
pub struct RevealValidator;

impl RevealValidator {
    /// Validate a vote reveal against the stored commitment.
    ///
    /// Recomputes the hash from the revealed vote and salt, then compares
    /// to the stored commitment hash. Returns `Valid` on match,
    /// `InvalidHash` on mismatch (triggers bond slashing).
    pub fn validate_reveal(
        &self,
        commitment: &VoteCommitment,
        vote: bool,
        salt: u64,
    ) -> RevealResult {
        let computed = compute_commitment_hash(vote, salt, commitment.block_height);

        if computed == commitment.commitment_hash {
            RevealResult::Valid
        } else {
            RevealResult::InvalidHash {
                expected: commitment.commitment_hash,
                got: computed,
            }
        }
    }

    /// Calculate the required bond for a given stake.
    ///
    /// Bond = BOND_PERCENT (10%) of the validator's current KAS stake.
    pub fn calculate_bond(&self, stake_kas: u64) -> u64 {
        stake_kas * BOND_PERCENT / 100
    }

    /// Check if the provided bond meets the minimum requirement.
    pub fn check_bond(&self, stake_kas: u64, provided_bond: u64) -> RevealResult {
        let required = self.calculate_bond(stake_kas);
        if provided_bond >= required {
            RevealResult::Valid
        } else {
            RevealResult::BondInsufficient {
                required,
                provided: provided_bond,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voting::commit::CommitmentBuilder;

    const TEST_ADDR: [u8; 32] = [0xBB; 32];

    fn make_commitment(vote: bool, salt: u64, block: u64, stake: u64) -> VoteCommitment {
        CommitmentBuilder::new(TEST_ADDR).build(1, vote, salt, block, stake)
    }

    #[test]
    fn test_valid_reveal() {
        let validator = RevealValidator;
        let commitment = make_commitment(true, 42, 1000, 50000);
        assert_eq!(
            validator.validate_reveal(&commitment, true, 42),
            RevealResult::Valid
        );
    }

    #[test]
    fn test_invalid_reveal_wrong_vote() {
        let validator = RevealValidator;
        let commitment = make_commitment(true, 42, 1000, 50000);
        let result = validator.validate_reveal(&commitment, false, 42);
        assert!(matches!(result, RevealResult::InvalidHash { .. }));
    }

    #[test]
    fn test_invalid_reveal_wrong_salt() {
        let validator = RevealValidator;
        let commitment = make_commitment(true, 42, 1000, 50000);
        let result = validator.validate_reveal(&commitment, true, 999);
        assert!(matches!(result, RevealResult::InvalidHash { .. }));
    }

    #[test]
    fn test_invalid_hash_contains_both_hashes() {
        let validator = RevealValidator;
        let commitment = make_commitment(true, 42, 1000, 50000);
        if let RevealResult::InvalidHash { expected, got } =
            validator.validate_reveal(&commitment, false, 42)
        {
            assert_eq!(expected, commitment.commitment_hash);
            assert_ne!(got, expected);
        } else {
            panic!("Expected InvalidHash");
        }
    }

    #[test]
    fn test_calculate_bond() {
        let validator = RevealValidator;
        assert_eq!(validator.calculate_bond(50000), 5000);
        assert_eq!(validator.calculate_bond(100000), 10000);
        assert_eq!(validator.calculate_bond(10000), 1000);
    }

    #[test]
    fn test_bond_sufficient() {
        let validator = RevealValidator;
        assert_eq!(validator.check_bond(50000, 5000), RevealResult::Valid);
        assert_eq!(validator.check_bond(50000, 10000), RevealResult::Valid);
    }

    #[test]
    fn test_bond_insufficient() {
        let validator = RevealValidator;
        let result = validator.check_bond(50000, 4999);
        assert!(matches!(result, RevealResult::BondInsufficient { .. }));
        if let RevealResult::BondInsufficient { required, provided } = result {
            assert_eq!(required, 5000);
            assert_eq!(provided, 4999);
        }
    }

    #[test]
    fn test_reveal_round_trip() {
        let builder = CommitmentBuilder::new(TEST_ADDR);
        let validator = RevealValidator;

        for vote in [true, false] {
            for salt in [0, 1, u64::MAX] {
                let commitment = builder.build(1, vote, salt, 5000, 20000);
                assert_eq!(
                    validator.validate_reveal(&commitment, vote, salt),
                    RevealResult::Valid,
                    "Round-trip failed for vote={vote}, salt={salt}"
                );
            }
        }
    }
}
