// ValidatorStaking.ss — Prometheus Validator Staking Contract
// Validators stake KAS (Kaspa native token) to participate in consensus.
// PROM is NEVER staked — it is earned through accepted proposals.
// No emergency stop mechanism (Architecture Decision #3).
// Compile: ssc compile --testnet modules/contracts/ValidatorStaking.ss

// ============================================================
// STRUCTS (from SCHEMA.md 1.1 — DO NOT MODIFY)
// ============================================================

struct Validator {
    pubkey: bytes(32),
    stake_kas: uint64,        // ← KAS (NICHT PROM!)
    active: bool,
    joined_at: uint64,        // Unix-Timestamp
    reputation: uint64,       // 0 - 100000 (10000x skaliert, 10000 = 1.0)
    slashing_count: uint64,   // Anzahl Slashing-Events
    last_vote_block: uint64   // Letzter Abstimmungsblock
}

struct VoteCommitment {
    validator_pubkey: bytes(32),
    proposal_id: uint64,
    commitment: bytes(32),        // sha256(vote || salt || block_height)
    bond_kas: uint64,             // 10% des Stakes als Kaution
    committed_at_block: uint64
}

// ============================================================
// CONSTANTS (from SCHEMA.md — named, no magic numbers)
// ============================================================

const MIN_STAKE_KAS: uint64 = 10000;         // Minimum KAS to register as validator
const SLASH_SIMPLE_PCT: uint64 = 5;           // 5% KAS loss for simple misbehavior
const SLASH_DOUBLE_VOTE_PCT: uint64 = 10;     // 10% KAS loss for double voting
const SLASH_COLLUSION_PCT: uint64 = 20;       // 20% KAS loss for proven collusion
const COOLDOWN_BLOCKS: uint64 = 100800;       // ~7 days at 10 BPS
const BOND_PERCENT: uint64 = 10;              // Bond = 10% of current stake
const REPUTATION_SCALE: uint64 = 10000;       // 10000 = 1.0 reputation
const INITIAL_REPUTATION: uint64 = 10000;     // Start at 1.0

// ============================================================
// STATE
// ============================================================

state validators: map(address => Validator);
state commitments: map(bytes(32) => VoteCommitment); // key = sha256(validator_addr || proposal_id)
state withdraw_requests: map(address => uint64);      // block number of withdrawal request

// ============================================================
// FUNCTIONS
// ============================================================

// Register a new validator by staking KAS via tx.value.
// Requires minimum MIN_STAKE_KAS. tx.value MUST be KAS (native token).
function register(pubkey: bytes(32)) -> void {
    require(tx.value >= MIN_STAKE_KAS, "Insufficient stake: need MIN_STAKE_KAS");
    require(!validators[msg.sender].active, "Validator already registered");

    validators[msg.sender] = Validator {
        pubkey: pubkey,
        stake_kas: tx.value,
        active: true,
        joined_at: block.timestamp,
        reputation: INITIAL_REPUTATION,
        slashing_count: 0,
        last_vote_block: 0
    };

    emit ValidatorRegistered(msg.sender, tx.value);
}

// Submit a vote commitment for a proposal (commit phase of Commit-Reveal).
// commitment = sha256(vote || salt || block_height).
// Bond = 10% of validator's current stake, locked until reveal.
function commitVote(proposal_id: uint64, commitment: bytes(32), bond: uint64) -> void {
    let validator: Validator = validators[msg.sender];
    require(validator.active, "Validator not active");

    let required_bond: uint64 = validator.stake_kas * BOND_PERCENT / 100;
    require(bond >= required_bond, "Bond must be >= 10% of stake");
    require(bond <= validator.stake_kas, "Bond exceeds stake");

    let commitment_key: bytes(32) = sha256(msg.sender || proposal_id);
    require(commitments[commitment_key].committed_at_block == 0, "Already committed");

    commitments[commitment_key] = VoteCommitment {
        validator_pubkey: validator.pubkey,
        proposal_id: proposal_id,
        commitment: commitment,
        bond_kas: bond,
        committed_at_block: block.height
    };

    emit VoteCommitted(msg.sender, proposal_id);
}

// Reveal a previously committed vote. Verifies commitment matches.
// On mismatch: bond is slashed. On match: bond is returned.
function revealVote(proposal_id: uint64, vote: bool, salt: uint64) -> void {
    let validator: Validator = validators[msg.sender];
    require(validator.active, "Validator not active");

    let commitment_key: bytes(32) = sha256(msg.sender || proposal_id);
    let vc: VoteCommitment = commitments[commitment_key];
    require(vc.committed_at_block > 0, "No commitment found");

    // Reconstruct commitment: sha256(vote || salt || committed_at_block)
    let expected: bytes(32) = sha256(vote || salt || vc.committed_at_block);

    if expected != vc.commitment {
        // Invalid reveal — slash the bond
        let penalty: uint64 = vc.bond_kas;
        validators[msg.sender].stake_kas -= penalty;
        validators[msg.sender].slashing_count += 1;

        if validators[msg.sender].stake_kas < MIN_STAKE_KAS {
            validators[msg.sender].active = false;
        }

        emit RevealFailed(msg.sender, proposal_id, penalty);
    } else {
        // Valid reveal — record vote and update last_vote_block
        validators[msg.sender].last_vote_block = block.height;
        emit VoteRevealed(msg.sender, proposal_id, vote);
    }

    // Clear commitment in both cases
    delete commitments[commitment_key];
}

// Slash a validator. NON-RECURSIVE implementation (V-003 approved).
// multiplier = min(3, slashing_count / 3 + 1), applied once.
// penalty = stake_kas * percent * multiplier / 100, capped at total stake.
// If stake drops below MIN_STAKE_KAS: auto-deactivate.
function slash(validator_addr: address, percent: uint64, reason: string) -> uint64 {
    let validator: Validator = validators[validator_addr];
    require(validator.active, "Validator not active");
    require(percent > 0 && percent <= 100, "Invalid slash percentage");

    // Non-recursive escalation: multiplier scales with prior offenses
    let multiplier: uint64 = min(3, validator.slashing_count / 3 + 1);

    // Calculate penalty, capped at entire stake
    let penalty: uint64 = min(
        validator.stake_kas * percent * multiplier / 100,
        validator.stake_kas
    );

    // Apply penalty
    validators[validator_addr].stake_kas -= penalty;
    validators[validator_addr].slashing_count += 1;

    // Auto-deactivate if stake falls below minimum
    if validators[validator_addr].stake_kas < MIN_STAKE_KAS {
        validators[validator_addr].active = false;
    }

    emit ValidatorSlashed(validator_addr, penalty, reason);
    return penalty;
}

// Request withdrawal of staked KAS. Enforces 7-day cooldown.
// Two-step process: call withdraw() to start cooldown, call withdraw() again after COOLDOWN_BLOCKS.
function withdraw() -> void {
    let validator: Validator = validators[msg.sender];
    require(validator.stake_kas > 0, "No stake to withdraw");

    if withdraw_requests[msg.sender] == 0 {
        // Step 1: Initiate withdrawal, start cooldown
        validators[msg.sender].active = false;
        withdraw_requests[msg.sender] = block.height;
        emit WithdrawRequested(msg.sender, validator.stake_kas);
    } else {
        // Step 2: Execute withdrawal after cooldown
        let request_block: uint64 = withdraw_requests[msg.sender];
        require(block.height >= request_block + COOLDOWN_BLOCKS,
                "Cooldown not elapsed: wait COOLDOWN_BLOCKS");

        let amount: uint64 = validators[msg.sender].stake_kas;
        validators[msg.sender].stake_kas = 0;
        delete withdraw_requests[msg.sender];

        // Transfer KAS back to validator
        transfer(msg.sender, amount);
        emit WithdrawCompleted(msg.sender, amount);
    }
}

// Read-only: get validator info
function getValidator(addr: address) -> Validator {
    return validators[addr];
}

// Read-only: get current stake in KAS
function getStake(addr: address) -> uint64 {
    return validators[addr].stake_kas;
}

// Read-only: check if validator is active
function isActive(addr: address) -> bool {
    return validators[addr].active;
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_register_validator_success() {
    // Register with exactly MIN_STAKE_KAS
    let tx = mock_tx(value: 10000, sender: ADDR_A);
    register(PUBKEY_A);
    assert(validators[ADDR_A].active == true);
    assert(validators[ADDR_A].stake_kas == 10000);
    assert(validators[ADDR_A].reputation == INITIAL_REPUTATION);
}

#[test]
function test_register_validator_insufficient_stake() {
    // Attempt to register with less than MIN_STAKE_KAS — must fail
    let tx = mock_tx(value: 9999, sender: ADDR_A);
    assert_reverts(register(PUBKEY_A), "Insufficient stake");
}

#[test]
function test_commit_reveal_cycle() {
    // Full commit-reveal cycle with correct values
    register_validator(ADDR_A, 20000);
    let salt: uint64 = 42;
    let vote: bool = true;
    let commitment: bytes(32) = sha256(vote || salt || block.height);

    commitVote(1, commitment, 2000);
    assert(commitments[sha256(ADDR_A || 1)].bond_kas == 2000);

    revealVote(1, true, 42);
    assert(validators[ADDR_A].last_vote_block == block.height);
    assert(commitments[sha256(ADDR_A || 1)].committed_at_block == 0); // cleared
}

#[test]
function test_slash_on_invalid_reveal() {
    // Submit wrong salt during reveal — bond must be slashed
    register_validator(ADDR_A, 20000);
    let commitment: bytes(32) = sha256(true || 42 || block.height);
    commitVote(1, commitment, 2000);

    revealVote(1, true, 999); // wrong salt
    assert(validators[ADDR_A].stake_kas == 18000); // 20000 - 2000
    assert(validators[ADDR_A].slashing_count == 1);
}

#[test]
function test_cooldown_enforcement() {
    // Withdrawal before cooldown expires must fail
    register_validator(ADDR_A, 15000);
    withdraw(); // initiate
    assert(validators[ADDR_A].active == false);

    // Attempt immediate second withdraw — should fail
    assert_reverts(withdraw(), "Cooldown not elapsed");

    // Advance blocks past cooldown
    advance_blocks(COOLDOWN_BLOCKS);
    withdraw(); // should succeed
    assert(validators[ADDR_A].stake_kas == 0);
}

#[test]
function test_kas_not_prom() {
    // Verify that MIN_STAKE_KAS is used (not MIN_STAKE, not PROM)
    // This test exists to catch PATTERN-001 from ERRORS.md
    assert(MIN_STAKE_KAS == 10000);
    register_validator(ADDR_A, MIN_STAKE_KAS);
    assert(validators[ADDR_A].stake_kas == MIN_STAKE_KAS);
    // tx.value is always KAS — no PROM staking path exists
}

#[test]
function test_double_vote_detection() {
    // Attempting to commit twice for the same proposal must fail
    register_validator(ADDR_A, 20000);
    let commitment: bytes(32) = sha256(true || 42 || block.height);
    commitVote(1, commitment, 2000);
    assert_reverts(commitVote(1, commitment, 2000), "Already committed");
}

#[test]
function test_collusion_slashing() {
    // Slash for collusion at 20%, verify escalation
    register_validator(ADDR_A, 100000);
    let penalty: uint64 = slash(ADDR_A, SLASH_COLLUSION_PCT, "collusion");
    // multiplier = min(3, 0/3+1) = 1, penalty = 100000 * 20 * 1 / 100 = 20000
    assert(penalty == 20000);
    assert(validators[ADDR_A].stake_kas == 80000);
    assert(validators[ADDR_A].slashing_count == 1);
}

#[test]
function test_bond_calculation() {
    // Bond must be at least 10% of current stake
    register_validator(ADDR_A, 50000);
    let required: uint64 = 50000 * BOND_PERCENT / 100; // = 5000
    let commitment: bytes(32) = sha256(true || 1 || block.height);

    // Too low bond should fail
    assert_reverts(commitVote(1, commitment, 4999), "Bond must be >= 10%");

    // Exact bond should succeed
    commitVote(1, commitment, 5000);
    assert(commitments[sha256(ADDR_A || 1)].bond_kas == 5000);
}

#[test]
function test_slash_escalation_non_recursive() {
    // Verify escalation multiplier: min(3, count/3 + 1)
    register_validator(ADDR_A, 100000);

    // First slash: count=0, multiplier=min(3, 0/3+1)=1
    slash(ADDR_A, 5, "test");
    assert(validators[ADDR_A].stake_kas == 95000); // 100000 - 5000

    // Slash 2-3: still multiplier=1
    slash(ADDR_A, 5, "test");
    assert(validators[ADDR_A].stake_kas == 90250); // 95000 - 4750

    slash(ADDR_A, 5, "test");
    // count=2, multiplier=min(3, 2/3+1)=1

    // After 3 slashes: count=3, multiplier=min(3, 3/3+1)=2
    slash(ADDR_A, 5, "test");
    // multiplier=2, higher penalty
    assert(validators[ADDR_A].slashing_count == 4);
}

#[test]
function test_auto_deactivation_below_min_stake() {
    // Slash enough to drop below MIN_STAKE_KAS, verify auto-deactivation
    register_validator(ADDR_A, 11000);
    slash(ADDR_A, SLASH_COLLUSION_PCT, "collusion");
    // penalty = 11000 * 20 * 1 / 100 = 2200, remaining = 8800
    assert(validators[ADDR_A].stake_kas == 8800);
    assert(validators[ADDR_A].active == false); // below MIN_STAKE_KAS
}
