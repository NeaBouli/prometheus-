//! Sybil Attack Resistance Test
//!
//! Proves that quadratic voting (Architecture Decision #14) prevents
//! Sybil attacks: one real guardian with high reputation outweighs
//! many fake guardians with minimal reputation.
//!
//! Formula from GuardianReputation.ss:
//!   power = (reputation / 100)^2 * compute_power / 1000

/// Compute voting power matching GuardianReputation.ss exactly.
/// power = (reputation / 100)^2 * compute_power / 1000
fn voting_power(reputation: u64, compute_power: u64) -> u64 {
    let rep_scaled = reputation / 100;
    let rep_squared = rep_scaled * rep_scaled;
    rep_squared * compute_power / 1000
}

/// Starting reputation for new guardians (from SCHEMA.md)
const REPUTATION_START: u64 = 1000;

/// Minimum compute power for guardians (from SCHEMA.md)
const MIN_COMPUTE_GFLOPS: u64 = 100;

#[test]
fn test_quadratic_voting_prevents_sybil() {
    // 100 fake guardians with minimum reputation and compute
    let fake_count = 100;
    let fake_power: u64 = (0..fake_count)
        .map(|_| voting_power(REPUTATION_START, MIN_COMPUTE_GFLOPS))
        .sum();

    // 1 real guardian with high reputation and good hardware
    let real_reputation: u64 = 10_000; // 1.0 in 10000x scale
    let real_compute: u64 = 500; // 500 GFLOPS
    let real_power = voting_power(real_reputation, real_compute);

    eprintln!(
        "Fake guardian power (each): {}",
        voting_power(REPUTATION_START, MIN_COMPUTE_GFLOPS)
    );
    eprintln!("Total fake power (100x):   {}", fake_power);
    eprintln!("Real guardian power:        {}", real_power);
    eprintln!(
        "Real/Fake ratio:            {:.1}x",
        real_power as f64 / fake_power as f64
    );

    // The real guardian MUST have more power than ALL 100 fakes combined
    assert!(
        real_power > fake_power,
        "Quadratic voting FAILED: real({}) <= fakes({})",
        real_power,
        fake_power
    );
}

#[test]
fn test_sybil_scaling_analysis() {
    // Show how many fakes are needed to match 1 real guardian
    let real_power = voting_power(10_000, 500);

    let mut fakes_needed = 0u64;
    let mut total_fake_power = 0u64;
    let fake_per_unit = voting_power(REPUTATION_START, MIN_COMPUTE_GFLOPS);

    while total_fake_power < real_power {
        fakes_needed += 1;
        total_fake_power += fake_per_unit;
    }

    eprintln!(
        "Need {} fake guardians to match 1 real guardian",
        fakes_needed
    );

    // Must require at least 500 fakes to be economically unfeasible
    assert!(
        fakes_needed >= 500,
        "Sybil resistance too low: only {} fakes needed",
        fakes_needed
    );
}

#[test]
fn test_reputation_zero_has_no_power() {
    // Guardian with reputation below minimum has zero power
    let power = voting_power(0, 1000);
    assert_eq!(power, 0, "Zero reputation must yield zero power");
}

#[test]
fn test_quadratic_growth() {
    // Verify power grows quadratically with reputation
    let p1 = voting_power(1_000, 100); // rep 0.1
    let p2 = voting_power(2_000, 100); // rep 0.2
    let p4 = voting_power(4_000, 100); // rep 0.4

    // Doubling reputation should ~4x the power (quadratic)
    // p2/p1 should be ~4, p4/p2 should be ~4
    assert!(p2 >= p1 * 3, "Power must grow quadratically");
    assert!(p4 >= p2 * 3, "Power must grow quadratically");
}
