// GovernanceAutoTuning.ss — Prometheus Automatic Parameter Tuning Contract
// Fully automated governance (Architecture Decision #5): no human intervention.
// Adjusts protocol parameters weekly based on network metrics.
// Compile: ssc compile --testnet modules/contracts/GovernanceAutoTuning.ss

// ============================================================
// CONSTANTS (from MEMO.md AUTO-TUNING PARAMETER)
// ============================================================

const TUNING_INTERVAL_BLOCKS: uint64 = 604800;   // ~7 days at 10 BPS
const REPUTATION_SCALE: uint64 = 10000;           // 10000 = 1.0

// Parameter bounds — prevents extreme values
const MIN_STAKE_KAS_FLOOR: uint64 = 1000;         // Minimum possible MIN_STAKE_KAS
const MIN_STAKE_KAS_CEILING: uint64 = 100000;     // Maximum possible MIN_STAKE_KAS
const CONFIDENCE_FLOOR: uint64 = 5000;            // 0.5 minimum confidence
const CONFIDENCE_CEILING: uint64 = 9900;          // 0.99 maximum confidence
const REWARD_FLOOR: uint64 = 10;                  // Minimum PROM reward per proposal
const REWARD_CEILING: uint64 = 1000;              // Maximum PROM reward per proposal

// Target ranges
const TARGET_VALIDATORS_MIN: uint64 = 50;
const TARGET_VALIDATORS_MAX: uint64 = 200;
const TARGET_GUARDIANS_MIN: uint64 = 200;
const TARGET_GUARDIANS_MAX: uint64 = 1000;
const TARGET_FP_RATE_MAX: uint64 = 50;            // 0.005 * 10000 = 0.5%

// Adjustment step sizes (scaled by 10000)
const STEP_STAKE: uint64 = 500;                   // Adjust stake by 500 KAS
const STEP_CONFIDENCE: uint64 = 100;              // Adjust confidence by 0.01
const STEP_REWARD: uint64 = 10;                   // Adjust reward by 10 PROM

// ============================================================
// STATE
// ============================================================

state params: GovernanceParams;
state last_tuning_block: uint64;

struct GovernanceParams {
    min_stake_kas: uint64,        // Current MIN_STAKE_KAS
    min_guardian_rep: uint64,     // Current MIN_GUARDIAN_REP (10000x scaled)
    min_confidence_ki: uint64,   // Current MIN_CONFIDENCE (10000x scaled)
    validator_consensus: uint64, // Current VALIDATOR_QUORUM (10000x scaled)
    reward_base: uint64          // Current REWARD_BASE in PROM
}

// ============================================================
// FUNCTIONS
// ============================================================

// Perform weekly auto-tuning of all governance parameters.
// Called by anyone — but only executes if TUNING_INTERVAL_BLOCKS have passed.
// Reads on-chain metrics and adjusts parameters toward target ranges.
function auto_tune() -> void {
    require(block.height >= last_tuning_block + TUNING_INTERVAL_BLOCKS,
            "Tuning interval not elapsed");

    let active_validators: uint64 = get_active_validator_count();
    let active_guardians: uint64 = get_active_guardian_count();
    let fp_rate: uint64 = oracle_get_fp_rate(); // 10000x scaled
    let proposals_per_day: uint64 = get_proposals_per_day();

    // --- Adjust MIN_STAKE_KAS based on validator count ---
    if active_validators < TARGET_VALIDATORS_MIN {
        // Too few validators — lower the barrier
        params.min_stake_kas = max(
            params.min_stake_kas - STEP_STAKE,
            MIN_STAKE_KAS_FLOOR
        );
    } else if active_validators > TARGET_VALIDATORS_MAX {
        // Too many validators — raise the barrier
        params.min_stake_kas = min(
            params.min_stake_kas + STEP_STAKE,
            MIN_STAKE_KAS_CEILING
        );
    }

    // --- Adjust MIN_CONFIDENCE based on false positive rate ---
    if fp_rate > TARGET_FP_RATE_MAX {
        // High FP rate — raise confidence threshold
        params.min_confidence_ki = min(
            params.min_confidence_ki + STEP_CONFIDENCE,
            CONFIDENCE_CEILING
        );
    } else if fp_rate == 0 && params.min_confidence_ki > CONFIDENCE_FLOOR {
        // Zero FP — can lower threshold slightly
        params.min_confidence_ki = max(
            params.min_confidence_ki - STEP_CONFIDENCE,
            CONFIDENCE_FLOOR
        );
    }

    // --- Adjust REWARD_BASE based on proposals per day ---
    if proposals_per_day < 100 {
        // Too few proposals — increase reward
        params.reward_base = min(params.reward_base + STEP_REWARD, REWARD_CEILING);
    } else if proposals_per_day > 200 {
        // Too many proposals — decrease reward
        params.reward_base = max(params.reward_base - STEP_REWARD, REWARD_FLOOR);
    }

    last_tuning_block = block.height;
    emit ParametersTuned(params);
}

// Read-only: get current value of a governance parameter by name
function get_parameter(name: string) -> uint64 {
    if name == "min_stake_kas" { return params.min_stake_kas; }
    if name == "min_guardian_rep" { return params.min_guardian_rep; }
    if name == "min_confidence_ki" { return params.min_confidence_ki; }
    if name == "validator_consensus" { return params.validator_consensus; }
    if name == "reward_base" { return params.reward_base; }
    revert("Unknown parameter");
}

// STUB: Oracle for false positive rate. Returns fp_rate as uint64 (10000x scaled).
// QUESTION FOR CLAUDE: fp_rate oracle mechanism undefined — stub created,
// awaiting architectural decision on how fp_rate is measured and reported on-chain.
function oracle_get_fp_rate() -> uint64 {
    // Placeholder: reads from an oracle contract or aggregated on-chain data
    // In production: this will query a dedicated FP-rate oracle contract
    // that aggregates reports from light clients
    return 0;
}

// Internal: read active validator count from ValidatorStaking contract
function get_active_validator_count() -> uint64 {
    return call(VALIDATOR_STAKING_CONTRACT, "getActiveCount");
}

// Internal: read active guardian count from GuardianReputation contract
function get_active_guardian_count() -> uint64 {
    return call(GUARDIAN_REPUTATION_CONTRACT, "getGuardianCount");
}

// Internal: calculate proposals per day from on-chain data
function get_proposals_per_day() -> uint64 {
    return call(RULE_STORAGE_CONTRACT, "getRecentProposalCount");
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_fp_rate_increases_confidence() {
    // High false positive rate should raise confidence threshold
    init_params(8500); // MIN_CONFIDENCE starts at 0.85
    mock_oracle_fp_rate(100); // 1% FP rate, above TARGET_FP_RATE_MAX
    mock_validators(100);
    mock_guardians(500);
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    auto_tune();
    assert(params.min_confidence_ki == 8600); // raised by STEP_CONFIDENCE
}

#[test]
function test_low_proposals_increases_reward() {
    init_params_default();
    mock_proposals_per_day(50); // below 100
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    let old_reward: uint64 = params.reward_base;
    auto_tune();
    assert(params.reward_base == old_reward + STEP_REWARD);
}

#[test]
function test_parameter_bounds_respected() {
    // Confidence should never exceed CONFIDENCE_CEILING
    init_params(9850);
    mock_oracle_fp_rate(100);
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    auto_tune();
    assert(params.min_confidence_ki <= CONFIDENCE_CEILING);
}

#[test]
function test_weekly_execution_only() {
    init_params_default();
    auto_tune(); // first call succeeds
    assert_reverts(auto_tune(), "Tuning interval not elapsed");

    advance_blocks(TUNING_INTERVAL_BLOCKS);
    auto_tune(); // second call succeeds after interval
}

#[test]
function test_too_few_validators_lowers_stake() {
    init_params_with_stake(10000);
    mock_validators(30); // below TARGET_VALIDATORS_MIN
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    auto_tune();
    assert(params.min_stake_kas == 10000 - STEP_STAKE);
}

#[test]
function test_too_many_validators_raises_stake() {
    init_params_with_stake(10000);
    mock_validators(250); // above TARGET_VALIDATORS_MAX
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    auto_tune();
    assert(params.min_stake_kas == 10000 + STEP_STAKE);
}

#[test]
function test_stake_floor_respected() {
    init_params_with_stake(MIN_STAKE_KAS_FLOOR + 100);
    mock_validators(10);
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    // Multiple tunings should not go below floor
    auto_tune();
    advance_blocks(TUNING_INTERVAL_BLOCKS);
    auto_tune();
    assert(params.min_stake_kas >= MIN_STAKE_KAS_FLOOR);
}

#[test]
function test_many_proposals_decreases_reward() {
    init_params_default();
    mock_proposals_per_day(300); // above 200
    advance_blocks(TUNING_INTERVAL_BLOCKS);

    let old_reward: uint64 = params.reward_base;
    auto_tune();
    assert(params.reward_base == old_reward - STEP_REWARD);
}
