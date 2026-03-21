// GuardianReputation.ss — Prometheus Guardian Reputation Contract
// Guardians run LLaMA 3 models to analyze threats and propose YARA rules.
// No financial staking — PROM is EARNED through accepted proposals, never staked.
// Reputation stored as uint64 with 10000x scaling (10000 = 1.0).
// Compile: ssc compile --testnet modules/contracts/GuardianReputation.ss

// ============================================================
// STRUCTS (from SCHEMA.md 1.2 — DO NOT MODIFY)
// ============================================================

struct Guardian {
    pubkey: bytes(32),
    compute_power_gflops: uint64, // GFLOPS der GPU
    reputation: uint64,            // 0 - 100000 (10000x skaliert, 10000 = 1.0)
    proposals_submitted: uint64,
    proposals_accepted: uint64,
    registered_at: uint64,
    model_type: uint8             // 0=LLaMA-3-70B, 1=LLaMA-3-8B
}

// ============================================================
// CONSTANTS (from SCHEMA.md — named, no magic numbers)
// ============================================================

const MIN_COMPUTE_GFLOPS: uint64 = 100;      // Minimum Guardian hardware
const MIN_REPUTATION: uint64 = 1000;          // 0.1 * 10000 — below this: no voting rights
const REPUTATION_START: uint64 = 1000;        // 0.1 * 10000 — starting reputation for new guardians
const REPUTATION_SCALE: uint64 = 10000;       // Scaling factor: stored / 10000 = actual reputation
const REPUTATION_MAX: uint64 = 100000;        // 10.0 * 10000 — maximum reputation
const POW_BASE_DIFFICULTY: uint64 = 1000;     // Base PoW difficulty for registration
const MODEL_TYPE_70B: uint8 = 0;              // LLaMA-3-70B
const MODEL_TYPE_8B: uint8 = 1;               // LLaMA-3-8B (fallback)

// ============================================================
// STATE
// ============================================================

state guardians: map(address => Guardian);
state guardian_count: uint64;

// ============================================================
// FUNCTIONS
// ============================================================

// Register a new guardian with a PoW proof.
// PoW difficulty scales with current guardian count to prevent Sybil attacks.
// No KAS staking required — guardians contribute compute, not capital.
function register(pubkey: bytes(32), compute_power_gflops: uint64) -> void {
    require(!guardians[msg.sender].active(), "Guardian already registered");
    require(compute_power_gflops >= MIN_COMPUTE_GFLOPS, "Insufficient compute power");
    require(compute_power_gflops < 1000000, "Unrealistic compute power value");

    // PoW difficulty scales with guardian count (anti-Sybil)
    let difficulty: uint64 = POW_BASE_DIFFICULTY + guardian_count * 10;
    require(verify_pow(msg.sender, difficulty), "PoW challenge failed");

    // Determine model type based on compute power
    let model: uint8 = if compute_power_gflops >= 500 { MODEL_TYPE_70B } else { MODEL_TYPE_8B };

    guardians[msg.sender] = Guardian {
        pubkey: pubkey,
        compute_power_gflops: compute_power_gflops,
        reputation: REPUTATION_START,
        proposals_submitted: 0,
        proposals_accepted: 0,
        registered_at: block.timestamp,
        model_type: model
    };

    guardian_count += 1;
    emit GuardianRegistered(msg.sender, compute_power_gflops, model);
}

// Calculate voting power using quadratic voting (Architecture Decision #14).
// Formula: reputation^2 * compute_power / 1000 (fixed-point arithmetic).
// Returns uint64 — higher value = more influence in governance.
function voting_power(guardian_addr: address) -> uint64 {
    let g: Guardian = guardians[guardian_addr];
    require(g.registered_at > 0, "Guardian not found");

    // If below minimum reputation: no voting power
    if g.reputation < MIN_REPUTATION {
        return 0;
    }

    // Quadratic voting: rep^2 * compute / 1000
    // All values are uint64, reputation is 10000x scaled
    // rep^2 can overflow for large values, so divide early
    let rep_squared: uint64 = (g.reputation / 100) * (g.reputation / 100);
    let power: uint64 = rep_squared * g.compute_power_gflops / 1000;
    return power;
}

// Called when a guardian's proposal is accepted by validator consensus.
// Increases reputation by 0.01 * sqrt(compute_power), scaled to uint64.
// PROM rewards are distributed separately by the reward system.
function proposal_accepted(guardian_addr: address) -> void {
    require(msg.sender == GOVERNANCE_CONTRACT, "Only governance can call");
    let g: Guardian = guardians[guardian_addr];
    require(g.registered_at > 0, "Guardian not found");

    guardians[guardian_addr].proposals_accepted += 1;

    // reputation += 0.01 * sqrt(compute_power) * REPUTATION_SCALE
    // = sqrt(compute_power) * 100 (since 0.01 * 10000 = 100)
    let sqrt_compute: uint64 = isqrt(g.compute_power_gflops);
    let increase: uint64 = sqrt_compute * 100;

    guardians[guardian_addr].reputation = min(
        g.reputation + increase,
        REPUTATION_MAX
    );

    emit ReputationIncreased(guardian_addr, increase);
}

// Called when a guardian's proposal is rejected by validator consensus.
// Halves reputation. If below MIN_REPUTATION: set to 0 (loses voting rights).
function proposal_rejected(guardian_addr: address) -> void {
    require(msg.sender == GOVERNANCE_CONTRACT, "Only governance can call");
    let g: Guardian = guardians[guardian_addr];
    require(g.registered_at > 0, "Guardian not found");

    // Reputation *= 0.5 (halving)
    guardians[guardian_addr].reputation = g.reputation / 2;

    // If below minimum: zero out (no voting rights)
    if guardians[guardian_addr].reputation < MIN_REPUTATION {
        guardians[guardian_addr].reputation = 0;
    }

    emit ReputationDecreased(guardian_addr, g.reputation - guardians[guardian_addr].reputation);
}

// Read-only: get guardian info
function getGuardian(addr: address) -> Guardian {
    return guardians[addr];
}

// Read-only: get current guardian count
function getGuardianCount() -> uint64 {
    return guardian_count;
}

// Internal: integer square root (Babylonian method)
function isqrt(n: uint64) -> uint64 {
    if n == 0 { return 0; }
    let x: uint64 = n;
    let y: uint64 = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_register_guardian_success() {
    let tx = mock_tx(sender: ADDR_B);
    mock_pow(ADDR_B, true);
    register(PUBKEY_B, 200);
    assert(guardians[ADDR_B].reputation == REPUTATION_START);
    assert(guardians[ADDR_B].compute_power_gflops == 200);
    assert(guardian_count == 1);
}

#[test]
function test_sybil_resistance_pow() {
    // PoW must be verified — registration without valid PoW fails
    mock_pow(ADDR_B, false);
    assert_reverts(register(PUBKEY_B, 200), "PoW challenge failed");
}

#[test]
function test_voting_power_quadratic() {
    // Verify quadratic voting formula
    register_guardian(ADDR_B, 400, REPUTATION_START);
    let power: uint64 = voting_power(ADDR_B);
    // rep=1000, rep/100=10, 10*10=100, 100*400/1000 = 40
    assert(power == 40);
}

#[test]
function test_reputation_increase_on_accept() {
    register_guardian(ADDR_B, 400, REPUTATION_START);
    mock_sender(GOVERNANCE_CONTRACT);
    proposal_accepted(ADDR_B);
    // sqrt(400) = 20, increase = 20 * 100 = 2000
    assert(guardians[ADDR_B].reputation == REPUTATION_START + 2000);
    assert(guardians[ADDR_B].proposals_accepted == 1);
}

#[test]
function test_reputation_halving_on_reject() {
    register_guardian(ADDR_B, 400, 5000); // rep = 0.5
    mock_sender(GOVERNANCE_CONTRACT);
    proposal_rejected(ADDR_B);
    assert(guardians[ADDR_B].reputation == 2500); // halved to 0.25
}

#[test]
function test_voting_right_revocation() {
    // Reputation below MIN_REPUTATION = 0 voting power
    register_guardian(ADDR_B, 400, 800); // below MIN_REPUTATION (1000)
    let power: uint64 = voting_power(ADDR_B);
    assert(power == 0);
}

#[test]
function test_compute_power_minimum() {
    // Below MIN_COMPUTE_GFLOPS should fail
    mock_pow(ADDR_B, true);
    assert_reverts(register(PUBKEY_B, 99), "Insufficient compute power");
}

#[test]
function test_8b_vs_70b_model_type() {
    // >= 500 GFLOPS = 70B model, < 500 = 8B model
    register_guardian(ADDR_B, 500, REPUTATION_START);
    assert(guardians[ADDR_B].model_type == MODEL_TYPE_70B);

    register_guardian(ADDR_C, 300, REPUTATION_START);
    assert(guardians[ADDR_C].model_type == MODEL_TYPE_8B);
}

#[test]
function test_reputation_zero_on_deep_reject() {
    // If halving drops below MIN_REPUTATION, set to 0
    register_guardian(ADDR_B, 200, 1500); // 0.15 reputation
    mock_sender(GOVERNANCE_CONTRACT);
    proposal_rejected(ADDR_B);
    // 1500 / 2 = 750, below MIN_REPUTATION (1000) → set to 0
    assert(guardians[ADDR_B].reputation == 0);
}
