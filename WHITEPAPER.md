# Prometheus: Decentralized AI-Powered Threat Intelligence on Kaspa

**Whitepaper v4.0 — March 2026**

*The fire belongs to humanity, not to corporations.*

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [Architecture](#4-architecture)
5. [Token Design](#5-token-design)
6. [Validator System](#6-validator-system)
7. [Guardian System](#7-guardian-system)
8. [Light Client](#8-light-client)
9. [Voting Mechanism](#9-voting-mechanism)
10. [Rule Storage](#10-rule-storage)
11. [Federated Learning](#11-federated-learning)
12. [Governance Auto-Tuning](#12-governance-auto-tuning)
13. [Security Analysis](#13-security-analysis)
14. [Developer Incentive Pool](#14-developer-incentive-pool)
15. [Roadmap](#15-roadmap)
16. [Audit Findings and Resolutions](#16-audit-findings-and-resolutions)

---

## 1. Abstract

Prometheus is a fully decentralized, AI-powered threat intelligence protocol built on the Kaspa blockchain. It transforms every connected device into a node in a global threat detection swarm — without central control, without a foundation, and with zero pre-mined tokens.

The protocol combines three layers:
- **On-device AI** (Phi-3-mini 3.8B, 4-bit quantized) for local anomaly detection
- **Guardian nodes** (LLaMA 3 70B/8B) for advanced threat analysis and YARA rule generation
- **Kaspa L1 consensus** (DAGKnight, 100 BPS) for immutable rule storage and governance

Key properties: 0% pre-mine, no emergency stop, fully automated governance, GDPR non-applicable (no personal data on-chain).

---

## 2. Problem Statement

Current cybersecurity infrastructure suffers from three fundamental flaws:

1. **Centralization**: Threat databases are controlled by a handful of corporations (VirusTotal, CrowdStrike). A single compromise or policy change can blind millions of devices.
2. **Latency**: New threats take hours to days to propagate through signature databases. Zero-day exploits like Pegasus and Predator operate undetected during this window.
3. **Misaligned Incentives**: Security vendors profit from fear, not from prevention. There is no economic incentive for collaborative, open threat intelligence.

Prometheus eliminates all three by creating a permissionless, self-governing threat intelligence network where contributors are rewarded for accuracy and speed.

---

## 3. Solution Overview

```
Light Client (Phi-3-mini)          Guardian (LLaMA 3)           Kaspa L1
 - Local file scanning              - Threat analysis            - Rule storage (KRC-20)
 - Anomaly detection                - YARA rule generation       - Validator consensus
 - ZK-proof threat hints            - Proposal submission        - Governance auto-tuning
 - Rule updates from L1             - Reputation tracking        - Developer grants
```

**Threat Lifecycle (< 60 seconds):**
1. Light Client detects anomaly via Phi-3-mini + YARA rules
2. Anonymous threat hint submitted with ZK proof
3. Guardian node analyzes threat, generates YARA rule
4. Validators vote via Commit-Reveal (2/3 majority required)
5. Accepted rule stored on-chain as KRC-20 asset (supply=1)
6. All light clients receive and load the new rule

---

## 4. Architecture

### 4.1 Blockchain Layer (Kaspa L1)

- **Network**: Kaspa with Silverscript smart contracts
- **Testnet**: kaspa-testnet-10 (verified March 2026; Testnet-12 does not exist in rusty-kaspa v1.1.0)
- **Compiler**: ssc ships with the Covenant-Hardfork (May 5, 2026)
- **Consensus**: DAGKnight with 100 blocks per second
- **Contracts**: 6 Silverscript contracts (see Section 10)

### 4.2 P2P Layer

- **Protocol**: libp2p with Prometheus-specific message types
- **Messages**: ThreatHint, RuleProposal, RuleUpdate, PeerHandshake
- **Header**: Magic 0x50524F4D ("PROM") + version + type + length
- **Port**: 16420 (testnet and mainnet)

### 4.3 Off-Chain Layer

- **Light Client AI**: Phi-3-mini 3.8B (4-bit quantized, 4GB RAM, no GPU)
- **Guardian AI**: LLaMA 3 70B (primary) / LLaMA 3 8B (fallback)
- **Federated Learning**: Fed-DART protocol — only gradients transmitted, never raw data

---

## 5. Token Design

### 5.1 Dual Token Architecture

| Token | Purpose | Mechanism |
|-------|---------|-----------|
| **KAS** | Validator staking | Native Kaspa token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Reputation & Governance | Earned through accepted proposals. Never staked by validators. 0% pre-mine. |

**Critical rule**: Validators stake KAS, never PROM. PROM is exclusively earned through contribution.

### 5.2 Tokenomics (Annual Emission)

| Recipient | Share | Year 1 |
|-----------|-------|--------|
| Validators | 40% | 8,000,000 PROM |
| Guardians | 30% | 6,000,000 PROM |
| Reporters (Light Clients) | 15% | 3,000,000 PROM |
| Reporters (Honeypot) | 5% | 1,000,000 PROM |
| Dev Pool | 5% | 1,000,000 PROM |
| Community | 5% | 1,000,000 PROM |
| **Total** | **100%** | **20,000,000 PROM** |

No foundation allocation. No founder tokens. No pre-mine. Identical to Kaspa's launch philosophy.

---

## 6. Validator System

Validators secure the network by staking KAS and voting on threat proposals.

### 6.1 Registration

- Minimum stake: `MIN_STAKE_KAS = 10,000 KAS`
- `tx.value` = KAS (native token via transaction value)
- Reputation starts at 1.0 (stored as `uint64 = 10000` with 10000x scaling)

### 6.2 Slashing

Non-recursive implementation (Architect-approved V-003):

```
multiplier = min(3, slashing_count / 3 + 1)
penalty = min(stake * percent * multiplier / 100, stake)
if remaining_stake < MIN_STAKE_KAS: deactivate validator
```

| Offense | Base Penalty | Max (3x escalation) |
|---------|-------------|---------------------|
| Simple misbehavior | 5% | 15% |
| Double voting | 10% | 30% |
| Proven collusion | 20% | 60% |

**Access control**: Only `GOVERNANCE_CONTRACT` or `RULE_STORAGE_CONTRACT` can call `slash()`.

### 6.3 Withdrawal

7-day cooldown enforced via `COOLDOWN_BLOCKS = 100,800` (~7 days at 10 BPS).

---

## 7. Guardian System

Guardians run LLaMA 3 models to analyze threats and generate YARA rules.

### 7.1 Registration

- PoW difficulty scales with current guardian count (anti-Sybil)
- Minimum compute: `MIN_COMPUTE_GFLOPS = 100`
- Model auto-assigned: >= 500 GFLOPS = 70B, < 500 = 8B

### 7.2 Reputation

- Stored as `uint64` with 10000x scaling (not float64 — Architect decision Q-002)
- Starting reputation: 0.1 (`REPUTATION_START = 1000`)
- On accepted proposal: `reputation += 0.01 * sqrt(compute_power)`
- On rejected proposal: `reputation *= 0.5`; if below `MIN_REPUTATION (1000)`: set to 0

### 7.3 Voting Power (Quadratic)

```
power = (reputation / 100)^2 * compute_power / 1000
```

Quadratic voting (Architecture Decision #14) provides mathematical Sybil resistance: 1 real guardian with reputation 1.0 and 500 GFLOPS has power 5000, while 100 fake guardians with reputation 0.1 and 100 GFLOPS have total power 1000. The attacker needs 500+ accounts to match 1 legitimate guardian.

---

## 8. Light Client

### 8.1 Phi-3-mini Integration

- Model: Phi-3-mini 3.8B, 4-bit quantized (Architecture Decision #8)
- Runtime: ONNX Runtime (ort crate when available)
- Requirements: 4 GB RAM, no GPU
- Graceful degradation: runs in stub mode without model file

### 8.2 YARA Scanner

- Pattern-based file scanning with custom matcher
- Rules loaded from on-chain KRC-20 assets (tick: PROM-RULES)
- SHA-256 file hashing for threat identification
- EICAR test standard for validation

### 8.3 ZK Proofs

- Anonymous threat reporting via Groth16 ZK proofs
- Parameters from kaspa-zk-params crate (post Covenant-Hardfork)
- Current: stub implementation with SHA-256 commitments
- Public input: threat hash; Private input: reporter identity

---

## 9. Voting Mechanism

### 9.1 Commit-Reveal Protocol

Prevents vote-copying and frontrunning (Architecture Decision #13):

1. **Commit Phase**: Validator submits `sha256(vote_byte || salt_LE || block_height_LE)`
2. **Bond**: 10% of current stake locked as collateral
3. **Reveal Phase**: Validator reveals vote + salt
4. **Verification**: Hash recomputed and compared to commitment
5. **Invalid reveal**: Bond is slashed immediately

### 9.2 Consensus Requirements

- Quorum: 2/3 majority (`VALIDATOR_QUORUM = 6700` at 10000x scale)
- Voting period: 864,000 blocks (~1 day at 10 BPS)
- Minimum votes required for Dev Grants: 10

---

## 10. Rule Storage

### 10.1 KRC-20 Asset Model

Each accepted rule is stored as a unique KRC-20 asset:
- Tick: `PROM-RULES`
- Supply: 1 per rule (NFT-like)
- ID format: `PROM-RULE-2026-XXXX`

### 10.2 IPFS Content Storage

- Rule content stored on IPFS
- On-chain reference: `bytes(36)` CIDv1 binary with SHA-256 multihash
- **Not** bytes(46) — corrected from CIDv0 base58 assumption (Audit V-002)
- Always CIDv1 (base32), never CIDv0 (Pattern-005)

### 10.3 Contracts

| Contract | Functions | Purpose |
|----------|-----------|---------|
| ValidatorStaking.ss | register, commitVote, revealVote, slash, withdraw | KAS staking + consensus voting |
| GuardianReputation.ss | register, voting_power, proposal_accepted/rejected | Reputation + quadratic voting |
| GovernanceAutoTuning.ss | auto_tune, get_parameter | Weekly parameter adjustment |
| DevIncentivePool.ss | proposeGrant, vote, executeGrant | DAO-voted developer rewards |
| CommunityDonations.ss | donateKas, proposeDisbursement | Transparent community fund |
| RuleStorage.ss | submitProposal, voteOnProposal, finalizeProposal | KRC-20 rule minting |

All contracts use `uint64` with 10000x scaling for reputation and confidence values (no float64 in Silverscript).

---

## 11. Federated Learning

### 11.1 Fed-DART Protocol

Architecture Decision #10: Privacy-preserving distributed model improvement.

```
PRIVACY GUARANTEE:
- Only mathematical gradients are transmitted
- Raw data NEVER leaves the device
- Client IDs are anonymized (SHA-256 hash)
- Gradient validation: NaN/Inf values rejected (anti-poisoning)
```

### 11.2 Model Updates

```python
@dataclass
class ModelUpdate:
    gradients: List[float]   # Differential weight updates ONLY
    client_id: bytes         # Anonymized (32 bytes)
    data_size: int           # Sample count, no content
    signature: bytes         # Authenticity proof
```

---

## 12. Governance Auto-Tuning

Fully automated parameter adjustment (Architecture Decision #5):

| Parameter | Start Value | Target |
|-----------|------------|--------|
| MIN_STAKE_KAS | 10,000 | 50-200 active validators |
| MIN_GUARDIAN_REP | 0.3 | 200-1,000 active guardians |
| MIN_CONFIDENCE_KI | 0.85 | False positive rate < 0.5% |
| VALIDATOR_CONSENSUS | 0.67 | Stable rule acceptance |
| REWARD_BASE | 100 PROM | 100-200 proposals/day |

Tuning interval: weekly (604,800 blocks). Parameter bounds enforced to prevent extreme values.

**Note**: `fp_rate` oracle mechanism is stub-implemented (Audit Q-003). Architecture decision pending on whether Light Clients, Guardians, or a dedicated oracle report false positives.

---

## 13. Security Analysis

### 13.1 Sybil Resistance

Quadratic voting mathematically prevents Sybil attacks:
- 1 real guardian (rep 1.0, 500 GFLOPS): power = 5,000
- 100 fake guardians (rep 0.1, 100 GFLOPS each): total power = 1,000
- Ratio: 5:1 in favor of the legitimate participant
- Attacker needs 500+ accounts to match 1 real guardian

### 13.2 False Positive Flood

MIN_CONFIDENCE_KI = 0.85 threshold prevents low-quality proposals:
- 500 proposals with confidence 0.50: ALL blocked
- 1 proposal with confidence 0.90: passes immediately
- Threshold is dynamically adjusted by GovernanceAutoTuning

### 13.3 Collusion Prevention

- Commit-Reveal with salted hashes prevents vote-copying
- Bond system (10% of stake) deters frivolous voting
- Escalating slashing: repeat offenders face up to 3x base penalty
- No emergency stop (Architecture Decision #3): no single point of failure

### 13.4 No Emergency Stop

This is a deliberate design decision, not an oversight. Architecture Decision #3 states: "Ultimate decentralization — feature, not a bug." The protocol cannot be paused, halted, or modified by any individual or foundation. Code is law.

---

## 14. Developer Incentive Pool

5% of annual PROM emission (1,000,000 PROM/year) allocated to developer grants:

- Anyone can propose a grant
- Formula: `lines * 10 * (100 + complexity * 10) / 100`
- Maximum per grant: 100,000 PROM
- Voting period: 7 days
- Quorum: 10 validator votes minimum
- Approval: 2/3 majority (VALIDATOR_QUORUM)
- No foundation — disbursement only by DAO vote

---

## 15. Roadmap

| Phase | Timeline | Status |
|-------|----------|--------|
| Whitepaper v4 | March 2026 | ACCEPTED (10/10 audit) |
| Sprint 0: Setup | March 2026 | DONE |
| Sprint 1: Contracts | March 2026 | ACCEPTED |
| Sprint 2: Client | March 2026 | ACCEPTED |
| Sprint 3: AI | March 2026 | ACCEPTED |
| Sprint 4: Guardian | March 2026 | ACCEPTED |
| Sprint 5: Voting | March 2026 | ACCEPTED |
| Sprint 6: E2E | March 2026 | ACCEPTED |
| Sprint 7: Dashboard | March 2026 | IN PROGRESS |
| **Covenant-Hardfork** | **May 5, 2026** | **ssc compiler + testnet deployment** |
| Mainnet Launch | May 2026 | PLANNED |

---

## 16. Audit Findings and Resolutions

All development is subject to continuous architect audit. Key findings:

| Finding | Severity | Resolution |
|---------|----------|-----------|
| V-001: float64 not supported | HIGH | uint64 with 10000x scaling in all contracts |
| V-002: CID bytes(46) incorrect | HIGH | bytes(36) for CIDv1 binary SHA-256 |
| V-003: Recursive slash() | HIGH | Non-recursive: `multiplier = min(3, count/3+1)` |
| FIX-001: slash() no ACL | CRITICAL | Access control: only GOVERNANCE or RULE_STORAGE |
| FIX-002: .active() compile error | HIGH | Changed to `registered_at == 0` |
| FIX-003: Cumulative counter | HIGH | Time-windowed counter (864,000 blocks) |
| FIX-004: Bond not returned | LOW | `transfer(msg.sender, vc.bond_kas)` on valid reveal |
| FIX-005: Reward formula mismatch | LOW | Corrected to whitepaper formula |
| PATTERN-009: yara C dependency | LOW | Custom pattern matcher, evaluate yara-x for production |
| PATTERN-010: Unnecessary Mutex | LOW | Use `Arc<Phi3Model>` instead of `Arc<Mutex<Phi3Model>>` |
| PATTERN-011: Heuristic confidence | LOW | Replace with LLM confidence extraction in Sprint 6+ |

Total audits: 12 | Accepted: 10 | Rejected: 2 (all fixed and re-accepted)

---

*Prometheus v4.0 — March 2026*
*License: MIT | GitHub: github.com/NeaBouli/prometheus-*
*The fire belongs to humanity.*
