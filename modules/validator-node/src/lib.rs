//! Prometheus Validator Node
//!
//! Validators stake KAS (not PROM) to participate in consensus.
//! They vote on threat intelligence proposals using commit-reveal
//! with salted voting to prevent collusion.

pub mod slashing;
pub mod voting;

/// Minimum KAS stake for validators (from SCHEMA.md)
pub const MIN_STAKE_KAS: u64 = 10_000;

/// Slashing percentage for simple misbehavior
pub const SLASH_SIMPLE_PCT: u64 = 5;

/// Slashing percentage for double voting
pub const SLASH_DOUBLE_VOTE_PCT: u64 = 10;

/// Slashing percentage for proven collusion
pub const SLASH_COLLUSION_PCT: u64 = 20;

/// Cooldown blocks before withdrawal (~7 days at 10 BPS)
pub const COOLDOWN_BLOCKS: u64 = 100_800;

/// Bond = 10% of current stake
pub const BOND_PERCENT: u64 = 10;

/// Challenge period in seconds (24 hours)
pub const CHALLENGE_PERIOD: u64 = 86_400;

/// Base reward in PROM tokens (earned, not staked)
pub const REWARD_BASE_PROM: u64 = 100;
