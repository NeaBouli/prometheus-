// RuleStorage.ss — Prometheus Rule Storage Contract
// Stores finalized threat detection rules on-chain as KRC20 assets with supply=1.
// Rules are accepted via validator consensus (2/3 majority).
// Uses CIDv1 binary for IPFS references (36 bytes, NOT CIDv0/base58).
// Compile: ssc compile --testnet modules/contracts/RuleStorage.ss

// ============================================================
// STRUCTS (from SCHEMA.md 1.3 — DO NOT MODIFY)
// ============================================================

struct RuleProposal {
    id: uint64,
    guardian_pubkey: bytes(32),
    threat_hash: bytes(32),       // SHA-256 der Bedrohung
    rule_type: uint8,             // 0=YARA, 1=STIX, 2=Sigma
    rule_content_ipfs: bytes(36), // CIDv1 binary, SHA-256 multihash, 36 bytes (NOT CIDv0/base58)
    confidence: uint64,            // 0 - 10000 (10000x skaliert, 10000 = 1.0)
    submitted_at: uint64,
    votes_for: uint64,
    votes_against: uint64,
    voting_end: uint64,
    status: uint8                 // 0=PENDING, 1=ACCEPTED, 2=REJECTED
}

struct StoredRule {
    rule_id: string,              // "PROM-RULE-2026-XXXX"
    proposal_id: uint64,
    rule_type: uint8,
    rule_content_ipfs: bytes(36), // CIDv1 binary, SHA-256 multihash, 36 bytes (NOT CIDv0/base58)
    guardian_pubkey: bytes(32),
    consensus_score: uint64,      // 10000x scaled
    stored_at: uint64,
    active: bool
}

// ============================================================
// CONSTANTS (from SCHEMA.md — named, no magic numbers)
// ============================================================

const MIN_CONFIDENCE: uint64 = 8500;         // 0.85 * 10000 — minimum AI confidence
const VALIDATOR_QUORUM: uint64 = 6700;       // 0.67 * 10000 — 2/3 majority
const VOTING_BLOCKS: uint64 = 864000;        // ~1 day at 10 BPS
const RULE_TYPE_YARA: uint8 = 0;
const RULE_TYPE_STIX: uint8 = 1;
const RULE_TYPE_SIGMA: uint8 = 2;
const STATUS_PENDING: uint8 = 0;
const STATUS_ACCEPTED: uint8 = 1;
const STATUS_REJECTED: uint8 = 2;
const KRC20_RULE_SUPPLY: uint64 = 1;         // Each rule is a unique KRC20 asset
const KRC20_TICK: string = "PROM-RULES";     // KRC20 tick identifier

// ============================================================
// STATE
// ============================================================

state proposals: map(uint64 => RuleProposal);
state next_proposal_id: uint64;
state stored_rules: map(string => StoredRule);   // rule_id => StoredRule
state rule_count: uint64;
state proposal_voters: map(bytes(32) => bool);   // sha256(proposal_id || voter) => voted
state recent_proposal_count: uint64;              // proposals in last 24h (for auto-tuning)

// ============================================================
// FUNCTIONS
// ============================================================

// Submit a new rule proposal. Called by guardians via the reputation contract.
// Confidence must meet minimum threshold.
// IPFS CID must be 36-byte CIDv1 binary format.
function submitProposal(
    guardian_pubkey: bytes(32),
    threat_hash: bytes(32),
    rule_type: uint8,
    rule_content_ipfs: bytes(36), // CIDv1 binary, SHA-256 multihash, 36 bytes (NOT CIDv0/base58)
    confidence: uint64
) -> uint64 {
    require(confidence >= MIN_CONFIDENCE, "Confidence below MIN_CONFIDENCE threshold");
    require(rule_type <= RULE_TYPE_SIGMA, "Invalid rule type (0=YARA, 1=STIX, 2=Sigma)");
    require(length(rule_content_ipfs) == 36, "CID must be 36 bytes (CIDv1 binary)");

    let proposal_id: uint64 = next_proposal_id;
    next_proposal_id += 1;

    proposals[proposal_id] = RuleProposal {
        id: proposal_id,
        guardian_pubkey: guardian_pubkey,
        threat_hash: threat_hash,
        rule_type: rule_type,
        rule_content_ipfs: rule_content_ipfs,
        confidence: confidence,
        submitted_at: block.timestamp,
        votes_for: 0,
        votes_against: 0,
        voting_end: block.height + VOTING_BLOCKS,
        status: STATUS_PENDING
    };

    recent_proposal_count += 1;
    emit ProposalSubmitted(proposal_id, guardian_pubkey, rule_type);
    return proposal_id;
}

// Vote on a rule proposal. Only active validators may vote.
function voteOnProposal(proposal_id: uint64, support: bool) -> void {
    let p: RuleProposal = proposals[proposal_id];
    require(p.status == STATUS_PENDING, "Proposal not pending");
    require(block.height < p.voting_end, "Voting period expired");
    require(is_active_validator(msg.sender), "Only active validators");

    let vote_key: bytes(32) = sha256(proposal_id || msg.sender);
    require(!proposal_voters[vote_key], "Already voted on this proposal");
    proposal_voters[vote_key] = true;

    if support {
        proposals[proposal_id].votes_for += 1;
    } else {
        proposals[proposal_id].votes_against += 1;
    }

    emit ProposalVoted(proposal_id, msg.sender, support);
}

// Finalize a proposal after voting period ends.
// If accepted: store rule as KRC20 asset with supply=1.
// If rejected: update guardian reputation via GuardianReputation contract.
function finalizeProposal(proposal_id: uint64) -> void {
    let p: RuleProposal = proposals[proposal_id];
    require(p.status == STATUS_PENDING, "Proposal already finalized");
    require(block.height >= p.voting_end, "Voting period not ended");

    let total_votes: uint64 = p.votes_for + p.votes_against;
    require(total_votes > 0, "No votes cast");

    let approval: uint64 = p.votes_for * 10000 / total_votes;

    if approval >= VALIDATOR_QUORUM {
        // ACCEPTED — store rule as KRC20 asset
        proposals[proposal_id].status = STATUS_ACCEPTED;

        let rule_id: string = generate_rule_id(rule_count);
        rule_count += 1;

        stored_rules[rule_id] = StoredRule {
            rule_id: rule_id,
            proposal_id: proposal_id,
            rule_type: p.rule_type,
            rule_content_ipfs: p.rule_content_ipfs,
            guardian_pubkey: p.guardian_pubkey,
            consensus_score: approval,
            stored_at: block.timestamp,
            active: true
        };

        // Mint KRC20 asset with supply=1 representing this rule
        krc20_mint(KRC20_TICK, rule_id, KRC20_RULE_SUPPLY);

        // Notify guardian reputation contract
        call(GUARDIAN_REPUTATION_CONTRACT, "proposal_accepted", p.guardian_pubkey);

        emit RuleAccepted(rule_id, proposal_id, approval);
    } else {
        // REJECTED
        proposals[proposal_id].status = STATUS_REJECTED;

        // Notify guardian reputation contract (halves reputation)
        call(GUARDIAN_REPUTATION_CONTRACT, "proposal_rejected", p.guardian_pubkey);

        emit RuleRejected(proposal_id, approval);
    }
}

// Deactivate an existing rule (e.g., superseded by newer rule).
// Only callable via governance vote.
function deactivateRule(rule_id: string) -> void {
    require(msg.sender == GOVERNANCE_CONTRACT, "Only governance");
    require(stored_rules[rule_id].active, "Rule not active");
    stored_rules[rule_id].active = false;
    emit RuleDeactivated(rule_id);
}

// Read-only: get a stored rule by ID
function getRule(rule_id: string) -> StoredRule {
    return stored_rules[rule_id];
}

// Read-only: get proposal details
function getProposal(proposal_id: uint64) -> RuleProposal {
    return proposals[proposal_id];
}

// Read-only: get total number of stored rules
function getRuleCount() -> uint64 {
    return rule_count;
}

// Read-only: get recent proposal count (for auto-tuning)
function getRecentProposalCount() -> uint64 {
    return recent_proposal_count;
}

// Internal: generate rule ID in format "PROM-RULE-2026-XXXX"
function generate_rule_id(sequence: uint64) -> string {
    return "PROM-RULE-2026-" + zero_pad(sequence, 4);
}

// Internal: check validator status
function is_active_validator(addr: address) -> bool {
    return call(VALIDATOR_STAKING_CONTRACT, "isActive", addr);
}

// ============================================================
// TESTS
// ============================================================

#[test]
function test_submit_proposal_success() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    let id: uint64 = submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, ipfs_cid, 9000);
    assert(id == 0);
    assert(proposals[0].status == STATUS_PENDING);
    assert(proposals[0].confidence == 9000);
}

#[test]
function test_confidence_below_threshold() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    assert_reverts(
        submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, ipfs_cid, 8000),
        "Confidence below MIN_CONFIDENCE"
    );
}

#[test]
function test_invalid_rule_type() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    assert_reverts(
        submitProposal(PUBKEY_G, THREAT_HASH_A, 5, ipfs_cid, 9000),
        "Invalid rule type"
    );
}

#[test]
function test_vote_and_finalize_accepted() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    let id: uint64 = submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, ipfs_cid, 9500);
    // 8 for, 2 against = 80% approval
    for i in 0..8 { mock_active_validator(ADDR_VALIDATORS[i]); voteOnProposal(id, true); }
    for i in 8..10 { mock_active_validator(ADDR_VALIDATORS[i]); voteOnProposal(id, false); }
    advance_blocks(VOTING_BLOCKS);
    finalizeProposal(id);
    assert(proposals[id].status == STATUS_ACCEPTED);
    assert(rule_count == 1);
    assert(stored_rules["PROM-RULE-2026-0000"].active == true);
}

#[test]
function test_vote_and_finalize_rejected() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    let id: uint64 = submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_STIX, ipfs_cid, 8600);
    // 3 for, 7 against = 30% → rejected
    for i in 0..3 { mock_active_validator(ADDR_VALIDATORS[i]); voteOnProposal(id, true); }
    for i in 3..10 { mock_active_validator(ADDR_VALIDATORS[i]); voteOnProposal(id, false); }
    advance_blocks(VOTING_BLOCKS);
    finalizeProposal(id);
    assert(proposals[id].status == STATUS_REJECTED);
    assert(rule_count == 0);
}

#[test]
function test_krc20_minted_on_acceptance() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    let id: uint64 = submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, ipfs_cid, 9500);
    approve_proposal(id, 10, 0);
    advance_blocks(VOTING_BLOCKS);
    finalizeProposal(id);
    // Verify KRC20 asset was minted
    assert(krc20_supply(KRC20_TICK, "PROM-RULE-2026-0000") == KRC20_RULE_SUPPLY);
}

#[test]
function test_only_validators_can_vote() {
    let ipfs_cid: bytes(36) = mock_cidv1_binary();
    let id: uint64 = submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, ipfs_cid, 9000);
    mock_inactive_validator(ADDR_C);
    assert_reverts(voteOnProposal(id, true), "Only active validators");
}

#[test]
function test_deactivate_rule() {
    // Create and accept a rule, then deactivate via governance
    create_and_accept_rule(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_SIGMA, 9500);
    let rule_id: string = "PROM-RULE-2026-0000";
    assert(stored_rules[rule_id].active == true);

    mock_sender(GOVERNANCE_CONTRACT);
    deactivateRule(rule_id);
    assert(stored_rules[rule_id].active == false);
}

#[test]
function test_cid_must_be_36_bytes() {
    let bad_cid: bytes(46) = mock_bytes(46); // wrong size — CIDv0 length
    assert_reverts(
        submitProposal(PUBKEY_G, THREAT_HASH_A, RULE_TYPE_YARA, bad_cid, 9000),
        "CID must be 36 bytes"
    );
}
