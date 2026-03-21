/// Prometheus Validator Node
///
/// Validators stake KAS (not PROM) to participate in consensus.
/// They vote on threat intelligence proposals using commit-reveal
/// with salted voting to prevent collusion.

/// Slashing percentage for simple misbehavior
pub const SLASHING_SIMPLE: f64 = 0.05;

/// Slashing percentage for proven collusion
pub const SLASHING_COLLUSION: f64 = 0.20;

/// Challenge period in seconds (24 hours)
pub const CHALLENGE_PERIOD: u64 = 86400;

/// Base reward in PROM tokens (earned, not staked)
pub const REWARD_BASE_PROM: u64 = 100;
