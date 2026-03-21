/// Prometheus Light Client
///
/// Kaspa-based decentralized threat intelligence client.
/// Connects to the Kaspa network via wRPC, reads KRC-20 rules,
/// and provides local security scanning with Phi-3-mini AI.

/// Minimum KAS stake for validators (in sompi, 1 KAS = 100_000_000 sompi)
pub const MIN_STAKE_KAS: u64 = 10_000 * 100_000_000;

/// Minimum guardian reputation score (0.0 - 10.0)
pub const MIN_GUARDIAN_REP: f64 = 0.3;

/// Minimum AI confidence threshold
pub const MIN_CONFIDENCE_KI: f64 = 0.85;

/// Validator consensus quorum (2/3 majority)
pub const VALIDATOR_CONSENSUS: f64 = 0.67;
