# Prometheus: Decentralized AI-Powered Threat Intelligence on Kaspa

**Whitepaper v4.0 — March 2026**

**Status update — July 2026:** Kaspa Toccata is treated as a post-fork deployment environment for Prometheus. Current Silverc compile/runtime, release-bundle, request/receipt/evidence, metrics-oracle, and exact-commit gates cover the seven contract fixtures without holding signing material. Closed profiles separate the full path from the non-promotable `testnet-10-validator-staking-h001` canary. Public funding and the deterministic schema-v2 H-001 request/digest remain verified and byte-identical; no signature or broadcast has occurred. Sprint 10B includes fail-closed 8B-first/70B escalation, complete 5+ Guardian strict-majority voting, per-session BIP340 authenticated replay-safe intake, and GH-42/GH-44/GH-48/GH-52 ballot transport, persistent identity, relay/AutoNAT operation, packaged sidecars, and explicit bootstrap routes. Merged and exact-main-verified GH-55/GH-58 provide the canonical bounded ThreatHint channel and owner-only durable ingress. GH-63 adds a real manifest-pinned BN254/Arkworks Groth16 verifier aligned with active KIP-16, domain/network binding of every semantic ThreatHint field, strict compressed key/proof parsing, and a bounded owner-only service adapter. No approved production relation, verifying key, proving key, or independent vectors ship yet, so unavailable verification remains fail-closed as `busy` and accepted analysis is not claimed. Real two-host relay operation, broad discovery, trusted membership/key assignment, Sybil protection, real accepted ThreatHint analysis, on-chain ensemble attestation, live model evidence, and production operation remain open. Mainnet remains gated by the explicitly approved external canary signature and evidence, remaining deployments, real oracle/sponsor signatures and successor evidence, and exact-commit rollout evidence.

**Keyless operator update — July 2026:** The repository contains `prometheus-silverc-deployer`, pinned to official `rusty-kaspa` v2.0.1 and the exact Silverc source compiler revision. Its covenant-genesis path constructs transaction version 1 with compute budget 10 and the exact contextual `storage_mass` commitment, derives the official covenant ID, validates the exact live unspent funding UTXO during preflight and immediately before broadcast, and models the final 66-byte Schnorr signature script before exporting the 32-byte `SIG_HASH_ALL` digest. Signing-request schema v2 binds compute, transient, storage, normalized noncontextual/overall mass, the pinned relay rate, and both relay and conservative operator fee floors. The `reportMetrics` path recompiles exact predecessor and successor state, preserves the covenant value, uses a separate P2PK fee sponsor, derives two `SIG_HASH_ALL` digests, verifies both external BIP340 signatures plus every covenant/P2PK input, and revalidates both UTXOs before guarded broadcast. Both paths reject normalized input/output collisions, persist exclusive intent before acknowledged submission, reconcile retry state by transaction ID, enforce wRPC deadlines, and rebuild verified transactions before observation. The Rust package has 49 unit/security tests, including 11 focused metrics-transition tests. No private-key, seed, wallet, keystore, or raw-transaction input exists. Public testnet-10 funding plus an exact-main H-001 schema-v2 request/digest are confirmed. The H-001 canary and real metrics transition still require explicitly approved external signatures, complete operator verification, broadcast, confirmation, and independent chain evidence. Those results cannot authorize the full release by themselves.

The deploy capability gate and repository operator both bind the official SilverScript covenant-genesis profile: transaction version 1, `pay_to_script_hash_script` over the compiled contract script, covenant-ID derivation from the funding outpoint and unbound genesis output, and `CovenantBinding` only after the ID is derived. The repository assembles, verifies, broadcasts, and observes public transactions but delegates all signing to an external vault/HSM and never accepts key material. The current official PSKT/PSKB implementation is not used because its audited v1 path still constructs legacy sigop-count input commitments instead of Toccata compute-budget commitments.

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
- **Kaspa L1 consensus** (high-throughput BlockDAG / DAGKnight path) for immutable rule storage and governance

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
 - Local file scanning              - Threat analysis            - Rule state anchoring
 - Anomaly detection                - YARA rule generation       - Validator consensus
 - ZK-proof threat hints            - Proposal submission        - Governance auto-tuning
 - Rule updates from L1             - L1 reputation tracking     - Developer grants
```

**Threat Lifecycle (< 60 seconds):**
1. Light Client detects anomaly via Phi-3-mini + YARA rules
2. Anonymous threat hint submitted with ZK proof
3. Guardian node analyzes threat, generates YARA rule
4. Validators vote via Commit-Reveal (2/3 majority required)
5. Accepted rule state anchored on-chain; PROM-RULES asset representation remains deployment orchestration
6. All light clients receive and load the new rule

---

## 4. Architecture

### 4.1 Blockchain Layer (Kaspa L1)

- **Network**: Kaspa with Silverscript smart contracts
- **Testnet**: `testnet-10`, the Toccata profile supported by pinned `rusty-kaspa` v2.0.1; `testnet-12` is rejected because that release provides no matching consensus parameters
- **Compiler and deployer**: current Silverc gates pass for H-001 and all six state fixtures. The repository keyless Toccata-v1 operator closes genesis plus value-preserving `reportMetrics` transaction assembly/broadcast without accepting signing keys; its TLS-only official resolver probe confirms live testnet-10 Toccata/node readiness without replacing exact UTXO preflights. Real signatures, confirmed receipts/successor evidence, the remaining deployments, and exact-commit release evidence still gate rollout.
- **Consensus**: high-throughput Kaspa BlockDAG / DAGKnight path
- **Contracts**: 6 Silverscript contracts (see Section 10)

### 4.2 P2P Layer

- **Implemented Guardian protocol**: direct QUIC request/response at `/prometheus/guardian-ballot/1.0.0`, carrying one exact canonical signed ballot of at most 8192 bytes and returning a one-byte status without echoing the ballot
- **Resource boundary**: explicit global request, per-connection stream, connection, frame, and timeout limits; invalid or overloaded input fails before Guardian authorization
- **Local trust boundary**: an owner-only AF_UNIX bridge binds each collector ACK to the exact ballot digest; the existing BIP340/session/freshness/replay verifier remains authoritative
- **Connectivity**: strict bounded IP/UDP/QUIC-v1 direct, relay-circuit, explicit AutoNAT-server routes, and relay-only canonical advertised bootstrap routes are implemented without DNS. The GH-44 isolated three-node harness proves relay reservation/delivery, AutoNAT state, DCUtR relay fallback, and disconnect handling; real two-host relay/NAT operation is not yet proven. mDNS remains excluded because the compatible optional DNS dependency currently carries unresolved RustSec advisories
- **Operated service**: merged GH-48 exposes strict `preflight`, `run`, and `submit` commands for Guardian and relay roles, bounded newline-delimited JSON output, owner-only local submission, and bounded signal shutdown; three process tests cover same-host relay delivery, collector-wait termination, and broken output
- **Target convention**: port 16420 remains the deployment convention, but the carrier accepts explicit multiaddresses and does not hard-code a production listener

### 4.3 Off-Chain Layer

- **Light Client AI**: Phi-3-mini 3.8B (4-bit quantized, 4GB RAM, no GPU)
- **Guardian AI**: LLaMA 3 8B (default) / LLaMA 3 70B (confidence escalation)
- **Federated Learning**: Fed-DART protocol — only gradients transmitted, never raw data

---

## 5. Token Design

### 5.1 Dual Token Architecture

| Token | Purpose | Mechanism |
|-------|---------|-----------|
| **KAS** | Validator staking | Native Kaspa token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Rewards & Governance | Earned through accepted proposals. Never staked by validators. 0% pre-mine. |

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

Reporter percentages are protocol allocation targets, not passive uptime rewards. A miner-side companion receives no PROM merely for running; rewards require a future implementation and consensus-verified contribution path.

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
- Model eligibility: >= 500 GFLOPS may serve 70B escalation; all hybrid routes start with 8B

### 7.2 Reputation

- Stored as `uint64` with 10000x scaling (not float64 — Architect decision Q-002)
- Starting reputation: 0.1 (`REPUTATION_START = 1000`)
- On accepted proposal: `reputation += isqrt(compute_power_gflops) * 100` at 10000x fixed-point scale
- On rejected proposal: `reputation *= 0.5`; if below `MIN_REPUTATION (1000)`: set to 0

Guardian reputation is canonical Kaspa L1 state in `GuardianReputationState`.
It is separate from PROM balances and is not a badge or NFT.

### 7.3 Voting Power (Quadratic)

```
power = (reputation / 100)^2 * compute_power / 1000
```

Quadratic voting (Architecture Decision #14) provides mathematical Sybil resistance: 1 real guardian with reputation 1.0 and 500 GFLOPS has power 5000, while 100 fake guardians with reputation 0.1 and 100 GFLOPS have total power 1000. The attacker needs 500+ accounts to match 1 legitimate guardian.

### 7.4 Hybrid Analysis Routing

The implemented Sprint 10B router invokes an injected 8B analyzer first and
escalates to an independent 70B analyzer only when the primary confidence is
below `0.70` or the primary safety envelope is invalid. The exact `0.70`
boundary remains on the 8B route. Threat-hash mismatches, non-finite or
out-of-range confidence, malformed submission decisions, and failed or invalid
70B output fail closed with no submittable rule. The existing minimum network
submission confidence remains `0.85`.

This implementation is local orchestration with unit-test evidence. It does
not yet prove live 8B/70B operation, model-calibrated confidence, or P2P
delivery.

### 7.5 Local Guardian Ensemble Vote

The Sprint 10B ensemble validator commits the protocol version, threat hash,
exact YARA bytes and metadata, source-rule confidence in integer basis points,
policy hash, and pinned 8B model artifact into a domain-separated candidate
digest. An immutable snapshot commits at least five unique canonical Guardian
IDs, the 8B artifact, and a public membership-source digest. Every configured
member must provide exactly one fully bound vote. Approvals require at least
`8500` basis points, a complete ballot must reach a strict majority, and final
confidence is the minimum of the source rule and all approving votes. Missing,
duplicate, unknown, malformed, mismatched, tied, or below-policy input returns
no submittable rule.

The original ensemble decision remains a side-effect-free local pre-submission
gate. The GH-39 intake adds a separate per-candidate/network session that binds
each Guardian ID to one exact BIP340 x-only public key. Its strict canonical
envelope commits the complete domain vote, session and network IDs, nonce, and
validity window. Public signatures are verified before an owner-only SQLite
ledger atomically consumes one vote per member and one nonce per active
session; persisted envelopes are reverified before `EnsembleVoter` receives
them. Replay and equivocation markers survive restart and concurrent intake.

GH-42 adds a real transport-only Guardian carrier. Merged GH-44 extends it with
atomic owner-only persistent Ed25519 transport identity, strict bounded
direct/relay/AutoNAT routes, data-minimal health events, and a bounded relay
service. Merged and exact-main-verified GH-48 packages those APIs as strict
Guardian and relay processes with owner-only submission, bounded JSON output,
and graceful signal drain. Merged and exact-main-verified GH-52 separates relay bind listeners from explicit
canonical advertised IP/UDP/QUIC bootstrap routes and emits path-free routes
bound to the persistent transport `PeerId`. The isolated three-node harness proves relay
reservation, relay-only ballot/ACK delivery, AutoNAT state, DCUtR failure with
relay fallback, and disconnect handling; separate same-host processes prove
exact ballot/ACK delivery and socket cleanup. A libp2p `PeerId`, static address,
relay, or discovered route cannot assign a Guardian ID or bypass the existing
BIP340 verifier.

This still does not establish that the membership source or key assignment is
trustworthy, prove real two-host relay/NAT operation or broad discovery, prevent Sybil
identities, submit a proposal, or prove an ensemble on Kaspa L1. No production
private-key or signing API is included. Those remain production protocol and
deployment gates.

---

## 8. Light Client

This section describes the target Light Client architecture. The current Rust client contains development implementations and fail-closed runtime guards: beta/mainnet reject the Phi-3 heuristic, SHA-256 ZK placeholder, cached rule reader, and federated-learning placeholder. These components must not be presented as a production threat-reporting pipeline.

### 8.1 Phi-3-mini Integration

- Model: Phi-3-mini 3.8B, 4-bit quantized (Architecture Decision #8)
- Runtime: ONNX Runtime (ort crate when available)
- Requirements: 4 GB RAM, no GPU
- Current implementation: development-only heuristic/stub; real ONNX inference remains open

### 8.2 YARA Scanner

- Pattern-based file scanning with custom matcher
- Rules loaded from canonical L1 rule state; PROM-RULES asset representation is a deployment target
- SHA-256 file hashing for threat identification
- EICAR test standard for validation

### 8.3 ZK Proofs

- Target: anonymous threat reporting via Groth16 ZK proofs
- Active KIP-16 / BN254 Arkworks Groth16 verification is implemented in the manifest-pinned `prometheus-threat-proof` engine
- Every canonical ThreatHint semantic field except the proof is domain/network-bound into two injective 128-bit BN254 public inputs
- No production relation, verifying key, proving key, or independently approved vectors ship yet; operated verification therefore remains fail-closed `busy`
- The manifest SHA-256 is the runtime trust anchor; its relation-source hash is attested metadata that must be independently checked during artifact approval

### 8.4 Experimental Miner Companion

The first miner-facing integration is an opt-in sidecar in `prometheus-client`. It reads health data from an explicitly configured, credential-free local Testnet-10 wRPC endpoint. [Kaspa ASICs and pool miners normally use Stratum](https://wiki.kaspa.org/mining), which is a separate protocol; the companion does not intercept or reuse a Stratum connection and does not modify miner firmware.

The current companion is a development-only RPC observer. Its strict TOML profile rejects remote endpoints, embedded credentials, scanning, reporting, validator operation, honeypot operation, and unknown reward or wallet fields. It starts no host scan and transmits no miner telemetry. Production scanning/reporting requires real Phi-3 inference, real ZK proofs, canonical rule distribution, a reviewed P2P transport, explicit scan scopes, and resource enforcement.

Running the companion does not automatically earn PROM. The reporter allocation applies only to future protocol-verified security contributions after the corresponding reward path is implemented and audited. Validator participation remains a separate role backed by KAS stake; honeypots require isolated infrastructure and a separate threat model.

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

### 10.1 Rule State and Asset Representation

Each accepted rule is anchored as canonical rule state on Kaspa L1. The public product target is a unique PROM-RULES asset representation, but current Silverc verification intentionally covers the rule state machine first:
- Target tick: `PROM-RULES`
- Target supply: 1 per accepted rule
- Target ID format: `PROM-RULE-2026-XXXX`
- Current gate: `RuleStorageState.sil` verifies `byte[36]` CIDv1 storage, confidence threshold, quorum, submit/vote/finalize/deactivate covenant sigscripts, and Guardian reputation outcome events

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
| RuleStorage.ss | submitProposal, voteOnProposal, finalizeProposal | Rule state + target PROM-RULES asset orchestration |

Legacy `.ss` contracts use `uint64` with 10000x scaling for reputation and confidence values (no float64 in Silverscript). Current Silverc fixtures use signed entrypoint integers at the deploy boundary, with deployment calls scoped to `0..=i64::MAX` where numeric values enter Silverc.

Current-Silverc verification status:
- `ValidatorStakingState.sil`: compile/ABI and runtime transition gates pass.
- `GuardianReputationState.sil`: compile/ABI, runtime transition, and accepted-proposal formula gates pass.
- `RuleStorageState.sil`: compile/ABI/runtime gates pass for submit/vote/finalize/deactivate, including low-confidence, late-vote, zero-vote, and pending-rule rejection paths.
- `CommunityDonationsState.sil`: compile/ABI/runtime gates pass for donate/propose/vote/execute disbursement paths, including zero-donation, over-pool proposal, late-vote, and insufficient-quorum rejection paths.
- `DevIncentivePoolState.sil`: compile/ABI/runtime gates pass for propose/vote/execute grant paths, including max-grant, late-vote, quorum, and approval rejection paths.
- `GovernanceAutoTuningState.sil`: compile/ABI/runtime gates pass for signed metrics reporting and deterministic weekly auto-tuning, including invalid `fp_rate`, early tuning, high-FP, and zero-FP paths.
- Keyless genesis operator: official transaction-v1, compute-budget, covenant-ID, external BIP340 signature, full transaction verification, fee-bound, live Toccata preflight, broadcast acknowledgement, and UTXO-observation paths are implemented and CI-gated; a TLS-only public-resolver probe verifies testnet-10 node readiness without funding; no private-key or raw-transaction input exists.
- Deployment profiles: every new request, procedure, receipt, evidence summary, and status draft is bound to either the exact seven-contract `full` profile or the single-contract `testnet-10-validator-staking-h001` profile. Canary statuses are distinct and cannot satisfy full-release or metrics-oracle readiness gates.
- Deployment receipt verification: public receipt records are checked against the release-bundle manifest and selected deployment profile; synthetic `ci_fixture` receipts are kept separate from real `operator_record` deployment evidence.
- Public receipt-evidence verification: real `operator_record` deployment receipts must also match a public node/explorer snapshot before handoff readiness can pass.
- Public orchestrator-result receipt import: confirmed external deploy results are bound to the verified request set, converted into `operator_record` receipts, rejected if they contain secret-like or raw/serialized transaction fields, and re-validated before status staging.
- Deployment status staging: only verified `operator_record` receipts can produce a manual status-update draft; the guard does not write status files and rejects `ci_fixture` evidence.
- Metrics-oracle status staging: only signer-ready unsigned requests plus verified public oracle tx results can produce a manual status-update draft; the guard does not write status files and rejects blocked requests, secrets, and raw transactions.
- Deploy requests: per-contract public requests are generated and independently verified with hashes bound to the release-bundle manifest.
- Deploy operator procedure: verified requests become a public execution checklist and result-evidence contract. The procedure builder itself accepts no keys, raw transactions, signing material, deployment, or status writes; the Rust genesis operator performs assembly, verification, broadcast, and observation while an external vault/HSM provides only the digest signature.
- Operator capability verification: a public capability record binds deploy and metrics-oracle procedure hashes plus the explicit execution boundary while rejecting secret-like fields and raw transaction payloads.
- Operator handoff package: public release archive, deploy preflight, verified keyless-genesis requests and procedure, optional imported operator receipts, receipt verification, optional public receipt evidence, metrics report preflight, unsigned oracle request, keyless metrics-operation procedure, optional operator-capability summary, optional verified oracle result/evidence/status artifacts, and optional public release-hardening evidence are bundled without accepting private signing material or claiming real deployment.
- Public release-hardening evidence: successful CI, Pages deployment, protected-branch controls, rollback documentation, public Pages verification, and release-note requirements are bound to the exact release commit without accepting credentials, changing repository settings, or touching chain material.

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

**Q-003 update**: the legacy `.ss` contract kept `fp_rate` as a stub. The current-Silverc `GovernanceAutoTuningState.sil` path replaces that stub with a signed metrics-oracle report containing active validators, active guardians, proposals/day, and `fp_rate` bounded to `0..10000`. Public report/request/result/evidence gates remain, and the repository-owned Rust operator now deterministically builds the two-input state transition, preserves covenant value, commits fee/mass/compute data, exports separate oracle and sponsor sighashes, verifies both external BIP340 signatures and all inputs, journals acknowledged one-shot broadcast, and observes the exact successor UTXO. Real public UTXOs, signatures, broadcast, confirmation, and independent evidence remain deployment work; the repository accepts no private signing material.

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
| Sprint 7: Dashboard | March 2026 | ACCEPTED |
| Sprint 8: Public Site | March/July 2026 | ACCEPTED / ongoing documentation maintenance |
| **Kaspa Toccata / post-fork verification** | **June/July 2026** | **Runtime/release gates and the keyless Toccata-v1 genesis operator pass local and remote CI. The manifest-bound, non-promotable H-001 canary has confirmed public funding plus an exact-main schema-v2 request/digest; external signature, operator verification, one-shot broadcast, confirmation, and public evidence remain.** |
| Mainnet Launch | Post-verification | PLANNED; gated by a real funded testnet-10 deployment, external signatures, confirmed receipts plus independent chain evidence, external signed oracle transaction integration, and public release-hardening evidence for the exact rollout commit |

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

Total audit rounds: 10 | Sprint findings: 11 | Critical issues fixed; remaining deployment gates are tracked before beta/mainnet

---

*Prometheus v4.0 — March 2026, status refreshed July 2026*
*License: MIT | GitHub: github.com/NeaBouli/prometheus-*
*The fire belongs to humanity.*
