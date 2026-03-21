//! Slashing engine for validator penalty calculation.
//!
//! Implements the EXACT same formula as ValidatorStaking.ss slash():
//!   multiplier = min(3, slashing_count / 3 + 1)
//!   penalty = min(stake * percent * multiplier / 100, stake)
//!   deactivate if remaining < MIN_STAKE_KAS
//!
//! This Rust implementation MUST be bit-for-bit identical to the
//! Silverscript contract (Architect-approved V-003).

use crate::MIN_STAKE_KAS;

/// Slashing engine implementing the non-recursive penalty formula.
/// Matches ValidatorStaking.ss slash() exactly.
pub struct SlashingEngine;

impl SlashingEngine {
    /// Calculate the penalty amount for a slashing event.
    ///
    /// Formula (from SCHEMA.md, V-003 approved):
    ///   multiplier = min(3, count / 3 + 1)
    ///   penalty = min(stake * percent * multiplier / 100, stake)
    ///
    /// # Arguments
    /// * `stake` - Current KAS stake of the validator
    /// * `percent` - Base slash percentage (e.g. 5 for 5%)
    /// * `count` - Number of prior slashing events (slashing_count)
    pub fn calculate_penalty(&self, stake: u64, percent: u64, count: u64) -> u64 {
        let multiplier = std::cmp::min(3, count / 3 + 1);
        let raw_penalty = stake.saturating_mul(percent).saturating_mul(multiplier) / 100;
        std::cmp::min(raw_penalty, stake)
    }

    /// Check if a validator should be deactivated after slashing.
    ///
    /// Returns true if the remaining stake is below MIN_STAKE_KAS.
    pub fn should_deactivate(&self, remaining_stake: u64) -> bool {
        remaining_stake < MIN_STAKE_KAS
    }

    /// Execute a full slashing calculation and return the result.
    ///
    /// Returns (penalty, remaining_stake, should_deactivate).
    pub fn execute(&self, stake: u64, percent: u64, count: u64) -> (u64, u64, bool) {
        let penalty = self.calculate_penalty(stake, percent, count);
        let remaining = stake.saturating_sub(penalty);
        let deactivate = self.should_deactivate(remaining);
        (penalty, remaining, deactivate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SLASH_COLLUSION_PCT, SLASH_DOUBLE_VOTE_PCT, SLASH_SIMPLE_PCT};

    #[test]
    fn test_simple_slash_first_offense() {
        let engine = SlashingEngine;
        // count=0, multiplier=min(3, 0/3+1)=1
        let penalty = engine.calculate_penalty(100_000, SLASH_SIMPLE_PCT, 0);
        assert_eq!(penalty, 5_000); // 100000 * 5 * 1 / 100
    }

    #[test]
    fn test_collusion_slash() {
        let engine = SlashingEngine;
        let penalty = engine.calculate_penalty(100_000, SLASH_COLLUSION_PCT, 0);
        assert_eq!(penalty, 20_000); // 100000 * 20 * 1 / 100
    }

    #[test]
    fn test_double_vote_slash() {
        let engine = SlashingEngine;
        let penalty = engine.calculate_penalty(100_000, SLASH_DOUBLE_VOTE_PCT, 0);
        assert_eq!(penalty, 10_000); // 100000 * 10 * 1 / 100
    }

    #[test]
    fn test_escalation_multiplier() {
        let engine = SlashingEngine;
        // count=0,1,2: multiplier=1
        assert_eq!(engine.calculate_penalty(100_000, 5, 0), 5_000);
        assert_eq!(engine.calculate_penalty(100_000, 5, 1), 5_000);
        assert_eq!(engine.calculate_penalty(100_000, 5, 2), 5_000);

        // count=3: multiplier=min(3, 3/3+1)=2
        assert_eq!(engine.calculate_penalty(100_000, 5, 3), 10_000);

        // count=6: multiplier=min(3, 6/3+1)=3
        assert_eq!(engine.calculate_penalty(100_000, 5, 6), 15_000);

        // count=9: multiplier=min(3, 9/3+1)=3 (capped)
        assert_eq!(engine.calculate_penalty(100_000, 5, 9), 15_000);

        // count=100: still capped at 3
        assert_eq!(engine.calculate_penalty(100_000, 5, 100), 15_000);
    }

    #[test]
    fn test_penalty_capped_at_stake() {
        let engine = SlashingEngine;
        // 100% slash with multiplier 3 would be 300% → capped at stake
        let penalty = engine.calculate_penalty(10_000, 100, 6);
        assert_eq!(penalty, 10_000); // capped at full stake
    }

    #[test]
    fn test_should_deactivate_below_min() {
        let engine = SlashingEngine;
        assert!(engine.should_deactivate(9_999));
        assert!(engine.should_deactivate(0));
    }

    #[test]
    fn test_should_not_deactivate_above_min() {
        let engine = SlashingEngine;
        assert!(!engine.should_deactivate(10_000));
        assert!(!engine.should_deactivate(100_000));
    }

    #[test]
    fn test_execute_full_cycle() {
        let engine = SlashingEngine;
        let (penalty, remaining, deactivate) = engine.execute(11_000, SLASH_COLLUSION_PCT, 0);
        // penalty = 11000 * 20 * 1 / 100 = 2200
        assert_eq!(penalty, 2_200);
        assert_eq!(remaining, 8_800);
        assert!(deactivate); // 8800 < MIN_STAKE_KAS (10000)
    }

    #[test]
    fn test_cross_verify_with_silverscript() {
        // Cross-verification: these values must match ValidatorStaking.ss tests
        let engine = SlashingEngine;

        // From test_collusion_slashing: 100000 * 20% * multiplier(count=0)=1 → 20000
        assert_eq!(engine.calculate_penalty(100_000, 20, 0), 20_000);

        // From test_auto_deactivation: 11000 * 20% * 1 → 2200, remaining 8800 < 10000
        let (penalty, remaining, deactivate) = engine.execute(11_000, 20, 0);
        assert_eq!(penalty, 2_200);
        assert_eq!(remaining, 8_800);
        assert!(deactivate);

        // From test_slash_escalation: first slash 100000 * 5% * 1 → 5000
        assert_eq!(engine.calculate_penalty(100_000, 5, 0), 5_000);
    }

    #[test]
    fn test_zero_stake() {
        let engine = SlashingEngine;
        let penalty = engine.calculate_penalty(0, 20, 0);
        assert_eq!(penalty, 0);
    }

    #[test]
    fn test_zero_percent() {
        let engine = SlashingEngine;
        let penalty = engine.calculate_penalty(100_000, 0, 0);
        assert_eq!(penalty, 0);
    }
}
