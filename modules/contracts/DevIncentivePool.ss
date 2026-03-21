// DevIncentivePool.ss — Prometheus Developer Incentive Pool Contract
// 5% of annual PROM emission allocated to developer grants.
// Only disbursable via DAO vote — no foundation, no founder pool (Decision #4).
// Compile: ssc compile --testnet modules/contracts/DevIncentivePool.ss

// ============================================================
// STRUCTS (from SCHEMA.md 1.5 — DO NOT MODIFY)
// ============================================================

struct DevGrant {
    id: uint64,
    developer: address,
    contribution_hash: string,    // GitHub Commit/PR URL
    description: string,
    lines_of_code: uint64,
    complexity: uint64,           // 1-10
    requested_amount_prom: uint64,
    votes_for: uint64,
    votes_against: uint64,
    voting_end: uint64,
    executed: bool,
    paid: bool
}

// ============================================================
// CONSTANTS (from SCHEMA.md — named, no magic numbers)
// ============================================================

const MAX_GRANT_PROM: uint64 = 100000;          // Max 100k PROM per grant
const GRANT_VOTING_PERIOD: uint64 = 604800;      // 7 days in seconds
const REWARD_PER_LINE: uint64 = 10;              // 10 PROM per line of code
const MIN_COMPLEXITY: uint64 = 1;                // Minimum complexity score
const MAX_COMPLEXITY: uint64 = 10;               // Maximum complexity score
const QUORUM_VOTES: uint64 = 10;                 // Minimum votes to execute
const VALIDATOR_QUORUM: uint64 = 6700;           // 0.67 * 10000 — 2/3 majority

// ============================================================
// STATE
// ============================================================

state grants: map(uint64 => DevGrant);
state next_grant_id: uint64;
state pool_balance_prom: uint64;
state grant_voters: map(bytes(32) => bool);      // sha256(grant_id || voter) => voted

// ============================================================
// FUNCTIONS
// ============================================================

// Propose a new developer grant. Anyone can propose.
// Recommended amount is computed but requester can specify any amount up to MAX_GRANT_PROM.
function proposeGrant(
    developer: address,
    contribution_hash: string,
    description: string,
    lines: uint64,
    complexity: uint64,
    amount: uint64
) -> uint64 {
    require(complexity >= MIN_COMPLEXITY && complexity <= MAX_COMPLEXITY,
            "Complexity must be 1-10");
    require(amount > 0 && amount <= MAX_GRANT_PROM, "Amount exceeds MAX_GRANT_PROM");
    require(amount <= pool_balance_prom, "Insufficient pool balance");

    let grant_id: uint64 = next_grant_id;
    next_grant_id += 1;

    grants[grant_id] = DevGrant {
        id: grant_id,
        developer: developer,
        contribution_hash: contribution_hash,
        description: description,
        lines_of_code: lines,
        complexity: complexity,
        requested_amount_prom: amount,
        votes_for: 0,
        votes_against: 0,
        voting_end: block.timestamp + GRANT_VOTING_PERIOD,
        executed: false,
        paid: false
    };

    emit GrantProposed(grant_id, developer, amount);
    return grant_id;
}

// Vote on a grant proposal. Only active validators may vote.
// Each validator can vote once per grant.
function vote(grant_id: uint64, support: bool) -> void {
    let grant: DevGrant = grants[grant_id];
    require(!grant.executed, "Grant already executed");
    require(block.timestamp < grant.voting_end, "Voting period expired");

    // Only active validators can vote
    require(is_active_validator(msg.sender), "Only active validators may vote");

    let vote_key: bytes(32) = sha256(grant_id || msg.sender);
    require(!grant_voters[vote_key], "Already voted on this grant");
    grant_voters[vote_key] = true;

    if support {
        grants[grant_id].votes_for += 1;
    } else {
        grants[grant_id].votes_against += 1;
    }

    emit GrantVoted(grant_id, msg.sender, support);
}

// Execute a grant after voting period ends with sufficient support.
// Requires 2/3 majority and minimum quorum.
function executeGrant(grant_id: uint64) -> void {
    let grant: DevGrant = grants[grant_id];
    require(!grant.executed, "Grant already executed");
    require(block.timestamp >= grant.voting_end, "Voting period not ended");

    let total_votes: uint64 = grant.votes_for + grant.votes_against;
    require(total_votes >= QUORUM_VOTES, "Quorum not reached");

    // Check 2/3 majority (using 10000x scaling)
    let approval_rate: uint64 = grant.votes_for * 10000 / total_votes;
    require(approval_rate >= VALIDATOR_QUORUM, "Insufficient approval (need 67%)");

    require(pool_balance_prom >= grant.requested_amount_prom, "Insufficient pool funds");

    grants[grant_id].executed = true;
    grants[grant_id].paid = true;
    pool_balance_prom -= grant.requested_amount_prom;

    // Transfer PROM to developer
    transfer_prom(grant.developer, grant.requested_amount_prom);
    emit GrantExecuted(grant_id, grant.developer, grant.requested_amount_prom);
}

// Calculate recommended reward based on lines of code and complexity.
// Formula: lines * REWARD_PER_LINE * complexity / 5, capped at MAX_GRANT_PROM.
function recommendedReward(lines: uint64, complexity: uint64) -> uint64 {
    require(complexity >= MIN_COMPLEXITY && complexity <= MAX_COMPLEXITY,
            "Complexity must be 1-10");
    let reward: uint64 = lines * REWARD_PER_LINE * complexity / 5;
    return min(reward, MAX_GRANT_PROM);
}

// Deposit PROM into the pool (called by emission contract)
function deposit(amount: uint64) -> void {
    pool_balance_prom += amount;
    emit PoolDeposit(amount, pool_balance_prom);
}

// Read-only: get grant details
function getGrant(grant_id: uint64) -> DevGrant {
    return grants[grant_id];
}

// Read-only: get pool balance
function getPoolBalance() -> uint64 {
    return pool_balance_prom;
}

// Internal: check if address is an active validator
function is_active_validator(addr: address) -> bool {
    return call(VALIDATOR_STAKING_CONTRACT, "isActive", addr);
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_propose_grant_success() {
    deposit_to_pool(500000);
    let id: uint64 = proposeGrant(ADDR_DEV, "github.com/pr/1", "Fix bug", 100, 5, 10000);
    assert(id == 0);
    assert(grants[0].developer == ADDR_DEV);
    assert(grants[0].requested_amount_prom == 10000);
    assert(!grants[0].executed);
}

#[test]
function test_vote_and_execute_grant() {
    deposit_to_pool(500000);
    let id: uint64 = proposeGrant(ADDR_DEV, "pr/1", "Feature", 200, 7, 28000);
    // Simulate 10 validator votes (all for)
    for i in 0..10 {
        mock_active_validator(ADDR_VALIDATORS[i]);
        vote(id, true);
    }
    advance_time(GRANT_VOTING_PERIOD);
    executeGrant(id);
    assert(grants[id].executed == true);
    assert(grants[id].paid == true);
    assert(pool_balance_prom == 500000 - 28000);
}

#[test]
function test_vote_only_active_validators() {
    deposit_to_pool(100000);
    let id: uint64 = proposeGrant(ADDR_DEV, "pr/1", "Docs", 50, 3, 3000);
    mock_inactive_validator(ADDR_C);
    assert_reverts(vote(id, true), "Only active validators");
}

#[test]
function test_double_vote_prevention() {
    deposit_to_pool(100000);
    let id: uint64 = proposeGrant(ADDR_DEV, "pr/1", "Test", 50, 3, 3000);
    mock_active_validator(ADDR_A);
    vote(id, true);
    assert_reverts(vote(id, true), "Already voted");
}

#[test]
function test_quorum_required() {
    deposit_to_pool(100000);
    let id: uint64 = proposeGrant(ADDR_DEV, "pr/1", "Small", 10, 1, 100);
    // Only 5 votes (below QUORUM_VOTES = 10)
    for i in 0..5 {
        mock_active_validator(ADDR_VALIDATORS[i]);
        vote(id, true);
    }
    advance_time(GRANT_VOTING_PERIOD);
    assert_reverts(executeGrant(id), "Quorum not reached");
}

#[test]
function test_insufficient_approval() {
    deposit_to_pool(100000);
    let id: uint64 = proposeGrant(ADDR_DEV, "pr/1", "Controversial", 100, 5, 10000);
    // 6 for, 4 against = 60% (below 67%)
    for i in 0..6 { mock_active_validator(ADDR_VALIDATORS[i]); vote(id, true); }
    for i in 6..10 { mock_active_validator(ADDR_VALIDATORS[i]); vote(id, false); }
    advance_time(GRANT_VOTING_PERIOD);
    assert_reverts(executeGrant(id), "Insufficient approval");
}

#[test]
function test_recommended_reward_calculation() {
    let reward: uint64 = recommendedReward(100, 5);
    // 100 * 10 * 5 / 5 = 1000
    assert(reward == 1000);
}

#[test]
function test_recommended_reward_capped() {
    let reward: uint64 = recommendedReward(100000, 10);
    // 100000 * 10 * 10 / 5 = 2000000, capped at MAX_GRANT_PROM = 100000
    assert(reward == MAX_GRANT_PROM);
}

#[test]
function test_max_grant_exceeded() {
    deposit_to_pool(500000);
    assert_reverts(
        proposeGrant(ADDR_DEV, "pr/1", "Too much", 100, 5, 100001),
        "Amount exceeds MAX_GRANT_PROM"
    );
}
