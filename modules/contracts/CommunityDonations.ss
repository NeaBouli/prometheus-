// CommunityDonations.ss — Prometheus Community Donations Contract
// Accepts KAS donations for the community pool (5% of PROM emission).
// Fully transparent: all donations and disbursements recorded on-chain.
// No foundation, no founder pool (Architecture Decision #4).
// Compile: ssc compile --testnet modules/contracts/CommunityDonations.ss

// ============================================================
// STRUCTS
// ============================================================

struct Donation {
    donor: address,
    amount_kas: uint64,       // Donated KAS amount
    timestamp: uint64,
    message: string           // Optional donor message (max 256 chars)
}

struct DisbursementProposal {
    id: uint64,
    recipient: address,
    amount_kas: uint64,
    purpose: string,
    votes_for: uint64,
    votes_against: uint64,
    voting_end: uint64,
    executed: bool
}

// ============================================================
// CONSTANTS
// ============================================================

const MIN_DONATION_KAS: uint64 = 1;              // Minimum 1 KAS donation
const MAX_MESSAGE_LENGTH: uint64 = 256;           // Max donor message length
const DISBURSEMENT_VOTING_PERIOD: uint64 = 604800; // 7 days in seconds
const DISBURSEMENT_QUORUM: uint64 = 10;           // Minimum votes
const VALIDATOR_QUORUM: uint64 = 6700;            // 0.67 * 10000 — 2/3 majority

// ============================================================
// STATE
// ============================================================

state donations: map(uint64 => Donation);
state donation_count: uint64;
state total_donated_kas: uint64;
state pool_balance_kas: uint64;
state disbursements: map(uint64 => DisbursementProposal);
state next_disbursement_id: uint64;
state disbursement_voters: map(bytes(32) => bool);

// ============================================================
// FUNCTIONS
// ============================================================

// Accept a KAS donation to the community pool.
// tx.value must contain KAS (native token). Optional message.
function donateKas(message: string) -> void {
    require(tx.value >= MIN_DONATION_KAS, "Minimum donation: 1 KAS");
    require(length(message) <= MAX_MESSAGE_LENGTH, "Message too long");

    let id: uint64 = donation_count;
    donation_count += 1;

    donations[id] = Donation {
        donor: msg.sender,
        amount_kas: tx.value,
        timestamp: block.timestamp,
        message: message
    };

    total_donated_kas += tx.value;
    pool_balance_kas += tx.value;

    emit DonationReceived(msg.sender, tx.value, id);
}

// Propose a disbursement from the community pool. Anyone can propose.
function proposeDisbursement(
    recipient: address,
    amount_kas: uint64,
    purpose: string
) -> uint64 {
    require(amount_kas > 0, "Amount must be > 0");
    require(amount_kas <= pool_balance_kas, "Exceeds pool balance");

    let id: uint64 = next_disbursement_id;
    next_disbursement_id += 1;

    disbursements[id] = DisbursementProposal {
        id: id,
        recipient: recipient,
        amount_kas: amount_kas,
        purpose: purpose,
        votes_for: 0,
        votes_against: 0,
        voting_end: block.timestamp + DISBURSEMENT_VOTING_PERIOD,
        executed: false
    };

    emit DisbursementProposed(id, recipient, amount_kas);
    return id;
}

// Vote on a disbursement proposal. Only active validators may vote.
function voteDisbursement(disbursement_id: uint64, support: bool) -> void {
    let d: DisbursementProposal = disbursements[disbursement_id];
    require(!d.executed, "Already executed");
    require(block.timestamp < d.voting_end, "Voting period expired");
    require(is_active_validator(msg.sender), "Only active validators");

    let vote_key: bytes(32) = sha256(disbursement_id || msg.sender);
    require(!disbursement_voters[vote_key], "Already voted");
    disbursement_voters[vote_key] = true;

    if support {
        disbursements[disbursement_id].votes_for += 1;
    } else {
        disbursements[disbursement_id].votes_against += 1;
    }

    emit DisbursementVoted(disbursement_id, msg.sender, support);
}

// Execute a disbursement after voting period ends with 2/3 majority.
function executeDisbursement(disbursement_id: uint64) -> void {
    let d: DisbursementProposal = disbursements[disbursement_id];
    require(!d.executed, "Already executed");
    require(block.timestamp >= d.voting_end, "Voting not ended");

    let total_votes: uint64 = d.votes_for + d.votes_against;
    require(total_votes >= DISBURSEMENT_QUORUM, "Quorum not reached");

    let approval: uint64 = d.votes_for * 10000 / total_votes;
    require(approval >= VALIDATOR_QUORUM, "Insufficient approval (need 67%)");

    require(pool_balance_kas >= d.amount_kas, "Insufficient pool balance");

    disbursements[disbursement_id].executed = true;
    pool_balance_kas -= d.amount_kas;

    transfer(d.recipient, d.amount_kas);
    emit DisbursementExecuted(disbursement_id, d.recipient, d.amount_kas);
}

// Read-only: get all donations by a specific donor
function getDonations(donor: address) -> list(Donation) {
    let result: list(Donation) = [];
    for i in 0..donation_count {
        if donations[i].donor == donor {
            result.append(donations[i]);
        }
    }
    return result;
}

// Read-only: get total donated KAS
function getTotalDonated() -> uint64 {
    return total_donated_kas;
}

// Read-only: get current pool balance
function getPoolBalance() -> uint64 {
    return pool_balance_kas;
}

// Internal: check validator status
function is_active_validator(addr: address) -> bool {
    return call(VALIDATOR_STAKING_CONTRACT, "isActive", addr);
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_donate_kas_success() {
    let tx = mock_tx(value: 500, sender: ADDR_A);
    donateKas("For Prometheus!");
    assert(donation_count == 1);
    assert(total_donated_kas == 500);
    assert(pool_balance_kas == 500);
    assert(donations[0].donor == ADDR_A);
}

#[test]
function test_donate_minimum_enforced() {
    let tx = mock_tx(value: 0, sender: ADDR_A);
    assert_reverts(donateKas(""), "Minimum donation");
}

#[test]
function test_propose_and_execute_disbursement() {
    donate_kas_mock(1000);
    let id: uint64 = proposeDisbursement(ADDR_DEV, 500, "Community event");
    for i in 0..10 {
        mock_active_validator(ADDR_VALIDATORS[i]);
        voteDisbursement(id, true);
    }
    advance_time(DISBURSEMENT_VOTING_PERIOD);
    executeDisbursement(id);
    assert(disbursements[id].executed == true);
    assert(pool_balance_kas == 500);
}

#[test]
function test_disbursement_exceeds_balance() {
    donate_kas_mock(100);
    assert_reverts(
        proposeDisbursement(ADDR_DEV, 101, "Too much"),
        "Exceeds pool balance"
    );
}

#[test]
function test_only_validators_can_vote_disbursement() {
    donate_kas_mock(1000);
    let id: uint64 = proposeDisbursement(ADDR_DEV, 500, "Test");
    mock_inactive_validator(ADDR_C);
    assert_reverts(voteDisbursement(id, true), "Only active validators");
}

#[test]
function test_message_length_limit() {
    let tx = mock_tx(value: 100, sender: ADDR_A);
    let long_msg: string = repeat("A", 257);
    assert_reverts(donateKas(long_msg), "Message too long");
}

#[test]
function test_multiple_donations_tracked() {
    let tx1 = mock_tx(value: 100, sender: ADDR_A);
    donateKas("First");
    let tx2 = mock_tx(value: 200, sender: ADDR_A);
    donateKas("Second");
    assert(donation_count == 2);
    assert(total_donated_kas == 300);
    let donor_list: list(Donation) = getDonations(ADDR_A);
    assert(length(donor_list) == 2);
}

#[test]
function test_disbursement_quorum_required() {
    donate_kas_mock(1000);
    let id: uint64 = proposeDisbursement(ADDR_DEV, 500, "Test");
    for i in 0..5 {
        mock_active_validator(ADDR_VALIDATORS[i]);
        voteDisbursement(id, true);
    }
    advance_time(DISBURSEMENT_VOTING_PERIOD);
    assert_reverts(executeDisbursement(id), "Quorum not reached");
}
