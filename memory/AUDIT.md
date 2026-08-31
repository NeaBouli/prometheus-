# PROMETHEUS – AUDIT LOG
# Every completed module is audited by Claude (Architect) before proceeding to the next sprint.
# Format: | Module | Version | Date | Auditor | Result | Notes |
# Result: ACCEPTED | REJECTED | NEEDS_CHANGES
# Last Updated: 2026-08-31

---

## AUDIT CRITERIA (Claude Code must fulfill ALL)

Every module is checked against these 7 criteria:

| # | Criterion                                         | Weight   |
|---|---------------------------------------------------|----------|
| 1 | Matches MEMO.md architecture decisions?            | CRITICAL |
| 2 | Matches SCHEMA.md data models exactly?             | CRITICAL |
| 3 | KAS/PROM separation correctly implemented?         | CRITICAL |
| 4 | Tests present and all green (min. 80% coverage)?   | HIGH     |
| 5 | Documentation complete (all public functions)?      | HIGH     |
| 6 | No known security vulnerabilities (from ERRORS.md)?| HIGH     |
| 7 | Code standards met (fmt, clippy, pylint)?           | MEDIUM   |

If criterion 1, 2, or 3 is NOT met: automatic REJECTED (no NEEDS_CHANGES).

---

## AUDIT LOG TABLE

| Module                | Version | Date       | Auditor | Result          | Notes                                                |
|-----------------------|---------|------------|---------|-----------------|------------------------------------------------------|
| Whitepaper_v4.docx    | 4.0     | 2026-03-21 | Claude  | ACCEPTED        | 10/10 — all v3 gaps closed, production-ready         |
| memory/MEMO.md        | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | Complete, all architecture decisions correct          |
| memory/TODO.md        | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | Sprint 0-8 fully defined                             |
| memory/STATUS.md      | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | All modules listed, format correct                   |
| memory/SCHEMA.md      | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | KAS/PROM separation explicit, all structs defined    |
| Workflow Architecture | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | Autodidactic loop complete, chat overload avoided    |
| Sprint-1 Pre-Check    | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | V-001 float64→uint64, V-002 CID→bytes(36), V-003 slash non-recursive |
| Sprint-1 Contracts    | 1.2     | 2026-03-21 | Claude  | ACCEPTED        | 6 contracts, 54 tests, all findings fixed            |
| Sprint-2 Client Basis | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | 4 modules, 27 tests, PATTERN-003/004 applied         |
| Sprint-3 Phi-3        | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | 3 modules, 28 tests, PATTERN-010 noted               |
| Sprint-4 Guardian     | 1.0     | 2026-03-21 | Claude  | ACCEPTED        | 4 modules, 26 tests, PATTERN-011 noted               |
| Sprint-5 Voting       | 1.0     | 2026-03-22 | Claude  | ACCEPTED        | 3 modules, 29 tests, no fixes                        |
| Sprint-6 E2E          | 1.0     | 2026-03-22 | Claude  | ACCEPTED        | 4 test suites, 18 tests, no fixes                    |
| Sprint-7 Dashboard    | 1.0     | 2026-03-22 | Claude  | ACCEPTED        | Dashboard, README, WHITEPAPER.md                     |
| scripts/autodidactic.py | 1.1   | 2026-07-12 | Codex   | ACCEPTED        | Regression suite added for memory loading, padded dependency/status table handling, task completion, and blocker detection |
| GH-170 bounded YARA-X validation | 8d8e29c | 2026-08-13 | Codex + Kimi | ACCEPTED | 77 focused + 1207 Guardian pass/4 skip; no P0-P2; PR #171, exact-main CI/Security/Pages and live readback pass |
| Miner Companion Foundation | 0.1 | 2026-07-16 | Codex + Terra + Spark | ACCEPTED | Safe Phase-1 boundary and all review findings resolved; PR #14 plus exact-merge CI/Security/Pages and live Whitepaper verification pass |
| Keyless reportMetrics Operator | 0.1 | 2026-07-16 | Codex + Terra | ACCEPTED | Exact state/value binding, separate P2PK fee sponsor, dual external BIP340 verification, full input execution, UTXO revalidation, collision guards, journal recovery, 49 deployer tests, independent review, PR #26, exact-main CI/Security/Pages, and live Whitepaper pass at `072f04a`; real chain operation/evidence remains gated |

---

## AUDIT QUEUE (waiting for review)

| Module                | Version | Date       | Auditor     | Result         | Notes                                                |
|-----------------------|---------|------------|-------------|----------------|------------------------------------------------------|
| Sprint-1 Contracts    | 1.0     | 2026-03-21 | Claude      | REJECTED       | FIX-001 slash ACL, FIX-002 .active(), FIX-003 cumulative counter, FIX-004 bond return, FIX-005 reward formula |
| Sprint-1 Contracts    | 1.1     | 2026-03-21 | Claude Code | REJECTED       | Fixes applied but test assertion wrong (15000 vs 1500) |
| Sprint-1 Contracts    | 1.2     | 2026-03-21 | Claude      | ACCEPTED       | All 5 fixes verified. 3 test patches for ACL. Sprint 1 complete. |
| Sprint-2 Client Basis | 1.0     | 2026-03-21 | Claude      | ACCEPTED       | 4 modules, 27 tests. Minor fixes applied.            |
| Sprint-3 Phi-3        | 1.0     | 2026-03-21 | Claude      | ACCEPTED       | 3 modules, 28 tests. PATTERN-010 noted.              |
| Sprint-4 Guardian     | 1.0     | 2026-03-21 | Claude      | ACCEPTED       | 4 modules, 26 tests. PATTERN-011 noted.              |
| Sprint-5 Voting       | 1.0     | 2026-03-22 | Claude      | ACCEPTED       | 3 Rust modules, 29 tests. No fixes required.         |
| Sprint-6 E2E          | 1.0     | 2026-03-22 | Claude      | ACCEPTED       | 4 test suites, 18 integration tests. No fixes.       |
| Sprint-7 Dashboard    | 1.0     | 2026-03-22 | Claude      | ACCEPTED       | Dashboard, README, WHITEPAPER.md. Minor logo/count fixes. |
| Sprint-2 Client Basis | 1.0     | 2026-03-21 | Claude      | ACCEPTED       | 4 modules, 26 tests. Minor fixes applied (test rename, new test). |

---

## QUESTIONS FOR CLAUDE (Architect)

### Q-001: Silverscript Compiler (ssc) does not exist (2026-03-21)
```
Context:  Sprint 0, Task 4 — Install Silverscript Compiler
Finding:  The kaspanet/rusty-kaspa repository (v1.1.0) contains no "ssc" package.
          grep for "ssc", "silverscript", "smart.contract" in all Cargo.toml = 0 hits.
          The workspace has 60+ crates, none of which is a smart contract compiler.

Kaspa ecosystem (as of March 2026):
  - KRC-20 token standard exists (rudimentary, asset-based)
  - crypto/txscript crate exists (Bitcoin-Script variant, not Turing-complete)
  - No Silverscript, no .ss file format, no ssc binary

Question for Claude (Architect):
  1. Is "Silverscript" a planned name for Kaspa's future contract system
     (Covenant-Hardfork May 2026)?
  2. Should Claude Code develop its own Silverscript compiler as part of Prometheus?
  3. Or should we build on Kaspa's existing txscript/KRC-20 infrastructure?
  4. Alternative: implement contracts as Rust modules that interact via RPC with kaspad?

Impact: BLOCKS Task 4 (ssc install), Task 5 (Hello-World), and entire Sprint 1 (Contracts).
        Sprint 2+ (Client, Guardian) can be prepared in parallel.
```

**ANSWER (Claude Architect, 2026-03-21):**
```
ssc is not yet released — it ships with the Covenant-Hardfork on May 5, 2026.
For Sprint 1: Write all contracts in Silverscript syntax and test locally via
Rust-based txscript simulation. Deployment slot on Testnet-10 is reserved for
when ssc becomes available. Sprint 1 is NOT blocked — proceed with code writing
and unit tests in Rust.
```

**RESOLUTION UPDATE (2026-07-16):** The historical `ssc` name and implied
compiler-side deploy command were incorrect. The project now pins upstream
`silverc` commit `d25bd3427a093c17327ca3d6b9e1aa5f7688c863` for deterministic
compilation and uses the repository-owned keyless Toccata-v1 operator for
network preflight, transaction assembly, verification, journaled broadcast,
and observation. Q-001 is resolved as a tooling blocker; external signatures,
confirmed receipts/evidence, and remaining deployments are rollout gates.

### Q-002: float64 support verification not possible (2026-03-21)
```
Context:  Sprint 0, Task 4 — float64 verification in ssc
Finding:  Since ssc does not exist, float64 support cannot be verified.
          MEMO.md defines Reputation = float64 (0.0 - 10.0).
          ERRORS.md PATTERN-006 warns about float64 precision issues.

Question for Claude (Architect):
  If building on txscript: txscript does NOT support float64 (Bitcoin-Script derivative).
  Option A: Store reputation as uint64 with scaling factor (rep * 10000)
  Option B: Compute reputation off-chain, only hash on-chain
  Option C: Wait for Covenant-Hardfork specification

Impact: Affects GuardianReputation Contract (Sprint 1) and all reputation calculations.
```

**ANSWER (Claude Architect, 2026-03-21):**
```
Store reputation as uint64 with 10000x scaling.
Example: Reputation 0.5 = stored as 5000.
Update SCHEMA.md accordingly. Change all float64 reputation fields
to uint64 in all struct definitions.
```

### V-001: float64 Support — Pre-Flight Verification (2026-03-21)
```
Context:  Sprint 1 Pre-Check — Verification 1
Finding:  ssc not available (ships with Covenant-Hardfork 2026-05-05).
          float64 support cannot be empirically tested.
          Kaspa txscript (Bitcoin-Script derivative) does not support float64.
          ERRORS.md PATTERN-006 warns about float64 precision issues.

Decision (Claude Architect, Q-002):
  → uint64 with 10000x scaling (Reputation 0.5 = 5000).
  → SCHEMA.md already updated (all float64 → uint64 in Silverscript structs).

Status: RESOLVED — Architect approved uint64 with 10000x scaling.
        SCHEMA.md v2 reflects this. No further action needed.
        Rust-side schemas (ThreatReport, ScanResult) keep f64 for
        internal calculations — only on-chain values use uint64.
```

### V-002: IPFS CID Field Size — Pre-Flight Verification (2026-03-21)
```
Context:  Sprint 1 Pre-Check — Verification 2
Finding:  SCHEMA.md defines rule_content_ipfs: bytes(46) in RuleProposal.
          Actual CIDv1 sizes:

          CIDv1 binary (SHA-256 multihash):
            varint(version=1)         = 1 byte
            varint(codec, e.g. raw)   = 1 byte
            multihash:
              varint(sha2-256=0x12)   = 1 byte
              varint(digest_len=32)   = 1 byte
              digest                  = 32 bytes
            TOTAL binary              = 36 bytes

          CIDv1 base32-encoded (multibase):
            multibase prefix 'b'      = 1 char
            base32lower(36 bytes)     = 58 chars
            TOTAL string              = 59 chars

          bytes(46) matches NEITHER format:
            - 36 bytes (binary) ≠ 46
            - 59 bytes (base32 string) ≠ 46

          Possible explanation for 46: confusion with CIDv0 (Qm...) base58 encoding,
          which is 46 chars long. But CIDv0 should NOT be used per ERRORS.md PATTERN-005
          ("Always use CIDv1").

QUESTION FOR CLAUDE: CID field size — bytes(46) is inconsistent with CIDv1 binary
  (36 bytes) or CIDv1 string (59 chars). Correct options:
  Option A: bytes(36) — store CIDv1 as raw binary (space-efficient, on-chain optimal)
  Option B: string(59) — store CIDv1 as base32 string (human-readable)
  Recommendation: Option A (bytes(36)) for on-chain storage, as space-efficient.
  Clients convert to base32 when reading for IPFS gateway access.
```

**ANSWER (Claude Architect, 2026-03-21):**
```
APPROVED — use bytes(36) for binary CIDv1 with SHA-256.
Update SCHEMA.md: change rule_content_ipfs from bytes(46) to bytes(36).
Add code comment wherever this field appears:
// CIDv1 binary, SHA-256 multihash, 36 bytes (NOT CIDv0/base58)
```

### V-003: Recursive slash() Function — Pre-Flight Verification (2026-03-21)
```
Context:  Sprint 1 Pre-Check — Verification 3
Finding:  The whitepaper describes a slash() function that calls itself recursively
          when slashing_count > 3 (escalating penalties).

          Problems with recursion:
          1. Stack overflow risk with high slashing_count
          2. Unpredictable gas/computation cost
          3. Hard to audit and formally verify
          4. Likely not allowed in Silverscript/txscript

          Proposed non-recursive alternative:

          function slash(validator: Validator, slash_type: uint8) -> uint64 {
              // Base penalty percentage by type
              let base_pct: uint64 = match slash_type {
                  0 => SLASH_SIMPLE_PCT,       // 5%
                  1 => SLASH_DOUBLE_VOTE_PCT,  // 10%
                  2 => SLASH_COLLUSION_PCT,    // 20%
              };

              // Escalation multiplier: doubles from slashing_count > 3
              // Non-recursive: bit-shift instead of recursion
              let escalation: uint64 = if validator.slashing_count <= 3 {
                  1
              } else {
                  // 2^(count-3), capped at 16x (= count 7)
                  let exponent: uint64 = min(validator.slashing_count - 3, 4);
                  1 << exponent  // 2, 4, 8, 16
              };

              // Calculate penalty, capped at entire stake
              let penalty: uint64 = min(
                  validator.stake_kas * base_pct * escalation / 100,
                  validator.stake_kas
              );

              // Reduce stake
              validator.stake_kas -= penalty;
              validator.slashing_count += 1;

              // If stake below minimum: auto-deactivate
              if validator.stake_kas < MIN_STAKE_KAS {
                  validator.active = false;
              }

              return penalty;
          }

          Advantages:
          - O(1) execution, no recursion risk
          - Deterministic gas consumption
          - Escalation capped at 16x (prevents 100% loss from rounding)
          - Auto-deactivation below MIN_STAKE_KAS

QUESTION FOR CLAUDE: Replace recursive slash() with non-recursive version
  using bit-shift escalation. Cap at 16x (slashing_count=7).
  Auto-deactivation when stake falls below MIN_STAKE_KAS. Approve?
```

**ANSWER (Claude Architect, 2026-03-21):**
```
APPROVED — implement non-recursive version.
Escalation logic: multiplier = min(3, slashing_count / 3 + 1), apply once.
Document in SCHEMA.md as a note under the Validator struct.
```

### Q-003: fp_rate Oracle mechanism undefined (2026-03-21)
```
Context:  Sprint 1, GovernanceAutoTuning.ss — auto_tune() function
Finding:  The auto_tune() function requires a false positive rate (fp_rate)
          to dynamically adjust MIN_CONFIDENCE. There is no defined mechanism
          for how fp_rate is measured and reported on-chain.

          Currently implemented: oracle_get_fp_rate() stub in GovernanceAutoTuning.ss
          that always returns 0.

QUESTION FOR CLAUDE: fp_rate oracle mechanism undefined — stub created.
  Possible approaches:
  Option A: Light Clients report FP events via ZK-Proof, aggregated on-chain
  Option B: Guardians submit fp_rate as part of their reputation report
  Option C: Off-chain oracle with multi-sig validation
  Awaiting architectural decision.

Resolution update 2026-07-11:
  Current-Silverc path uses `GovernanceAutoTuningState.sil` with signed
  metrics-oracle reports. The report includes active validators, active
  guardians, proposals/day, and `fp_rate` bounded to `0..10000`. Runtime gates
  verify valid signed reports, reject out-of-range `fp_rate`, and verify
  deterministic weekly tuning. Remaining work is oracle operator/deploy
  integration, not the contract-side Q-003 stub.
```

---

## REJECTED MODULES (with full justification)

### Sprint-1 Contracts v1.0 — REJECTED (2026-03-21)
```
FINDING-001 (CRITICAL): slash() in ValidatorStaking.ss had no access control.
  Anyone could slash arbitrary validators → Funds at Risk.
  FIX: require(msg.sender == GOVERNANCE_CONTRACT || msg.sender == RULE_STORAGE_CONTRACT)

FINDING-002 (HIGH): GuardianReputation.ss — .active() is not a valid
  Silverscript method on structs. Compile error.
  FIX: guardians[msg.sender].registered_at == 0

FINDING-003 (HIGH): RuleStorage.ss — recent_proposal_count was cumulative,
  never reset. GovernanceAutoTuning treated it as "per day".
  FIX: Time-windowed counter with VOTING_BLOCKS (864000) reset interval.

FINDING-004 (LOW): revealVote() did not return bond on valid reveal.
  FIX: transfer(msg.sender, vc.bond_kas) after successful reveal.

FINDING-005 (LOW): recommendedReward() deviated from whitepaper.
  FIX: Formula corrected to lines * REWARD_PER_LINE * (100 + complexity * 10) / 100
```

---

## NEEDS_CHANGES (with comments for Claude Code)

Currently no open changes.

---

## AUDIT WORKFLOW

```
1. Claude Code finishes module
2. Claude Code creates PENDING_AUDIT entry in this file:
   | Module | Version | Date | Claude Code | PENDING | Ready for review |
3. Claude Code informs Core Dev: "Module X ready for audit"
4. Core Dev writes to Claude (claude.ai): "Audit Module X"
5. Claude reads the module from GitHub (public)
6. Claude checks against all 7 criteria
7. Claude writes result in this file:
   - ACCEPTED: Module is complete, next sprint can begin
   - NEEDS_CHANGES: Claude provides specific change instructions
   - REJECTED: Module violates architecture decisions, rewrite completely
8. Claude updates STATUS.md accordingly
9. Core Dev triggers next action in Claude Code
```

---

## AUDIT STATISTICS

```
Total Audits:     15
ACCEPTED:         12
REJECTED:         2
NEEDS_CHANGES:    0
Full Audits:      1 (Pre-Hardfork 2026-04-02)
Acceptance Rate:  100% (all rejections fixed and re-accepted)
```

---

## PRE-HARDFORK AUDIT — 2026-04-02

**Auditor:** Claude Code (autonomous, 5 parallel audit agents)
**Scope:** Full codebase — 7 levels, 35 checks
**Reference docs:** MEMO.md, SCHEMA.md, ERRORS.md, WHITEPAPER.md

---

### CRITICAL (must fix before May 5):

*None found.* All critical architecture decisions (KAS/PROM separation, slash ACL,
uint64 scaling, CID format, CEI pattern) are correctly implemented.

---

### HIGH (should fix before May 5):

**H-001: Commit-Reveal LE encoding ambiguity (Check 1.5)**
```
File:     modules/contracts/ValidatorStaking.ss:111
          modules/contracts/silverc/ValidatorStakingH001.sil
          modules/contracts/silverc/ValidatorStakingState.sil
          modules/contracts/silverc/GuardianReputationState.sil
Finding:  Hash computed as sha256(vote || salt || committed_at_block)
          without explicit to_le_bytes() on uint64 values.
          Spec requires: sha256(vote_byte || salt_LE || block_height_LE).
          Rust client (validator-node/src/voting/commit.rs:79-91) DOES use
          explicit .to_le_bytes() and cross-verifies with test.
Update:   Current-silverc fixture `ValidatorStakingH001.sil` now verifies
          explicit `vote_byte || byte[8](salt) || byte[8](block_height)`
          against Rust vectors at pinned upstream ref
          d25bd3427a093c17327ca3d6b9e1aa5f7688c863.
          `ValidatorStakingState.sil` now compiles and builds covenant
          sigscripts for commit/reveal/slash/withdraw transitions.
          `commitVote`, `revealVote`, `slashInvalidReveal`,
          `requestWithdraw`, and `completeWithdraw` now have runtime tests
          at the pinned upstream ref: valid commit/reveal/slash/
          request-withdraw/complete-withdraw signature/state transitions
          accepted; low bond, wrong reveal salt, valid-reveal slash,
          open-commitment withdrawal, and pre-cooldown complete-withdraw
          rejected.
          Current upstream silverc entrypoint numeric arguments are signed
          `int`; deployable salt/block-height values are therefore scoped
          to `0..=i64::MAX`. Rust retains raw u64 H-001 vectors for byte
          compatibility and exposes `build_silverc_checked` /
          `validate_silverc_commitment_bounds` for deployment calls.
          `GuardianReputationState.sil` compiles, builds covenant sigscripts,
          and runtime-tests `register`, `proposalAccepted`, and
          `proposalRejected` without badge, NFT, Kasplex, or staking semantics.
          Valid guardian/governance signatures and state transitions are
          accepted; low compute power and unregistered rejection paths are
          rejected; reputation caps at `REPUTATION_MAX`. The exact
          accepted-proposal formula is restored with bounded current-Silverc
          `for` loops as `isqrt(compute_power_gflops) * 100`.
          `RuleStorageState.sil` compiles, builds covenant sigscripts, and
          runtime-tests `submitProposal`, `voteOnProposal`,
          `finalizeProposal`, and `deactivateRule`; valid
          guardian/validator/governance signature transitions are accepted,
          while low confidence, late vote, zero-vote finalization, and
          pending-rule deactivation are rejected. It preserves CIDv1
          `byte[36]`, `MIN_CONFIDENCE = 8500`, and
          `VALIDATOR_QUORUM = 6700` while leaving legacy maps, KRC20 minting,
          events, and cross-contract calls out of the current-Silverc fixture
          scope.
          `GovernanceAutoTuningState.sil` now compiles, builds covenant
          sigscripts, and runtime-tests signed metrics reporting plus
          deterministic weekly auto-tuning; valid signed metrics reports are
          accepted, `fp_rate > MAX_FP_RATE` is rejected, high-FP and zero-FP
          tuning paths are accepted, and early tuning is rejected.
Action:   Prove the missing current-Silverc network deploy/orchestration path
          and implement the signed metrics-oracle operator before beta/mainnet
          governance.
Severity: HIGH until network deployment/orchestration and oracle operations are verified
```

**H-002: Arc<Mutex<Phi3Model>> unnecessary lock (Check 2.2, PATTERN-010)**
```
File:     modules/client/src/ai/detection.rs:53,59
Finding:  Phi3Model wrapped in Arc<Mutex<>> but analyze_bytes() takes &self.
          Mutex adds unnecessary lock contention on concurrent scans.
Action:   Change to Arc<Phi3Model>. Update detection.rs and e2e tests.
Severity: HIGH (performance under load, noted since Sprint 3)
```

---

### MEDIUM (fix before full release Aug/Sep):

**M-001: Heuristic confidence in yara_generator.py (Check 3.1, PATTERN-011) — GH-135 MERGED / EXACT-MAIN PASS**
```text
File:     modules/guardian-node/jaeger/yara_generator.py:75-80
Finding:  The former hardcoded heuristic (base 0.7 + indicator bonus) did not
          correlate with actual rule quality.
Action:   GH-135 removes the heuristic and accepts a separate model result
          only as an exact closed JSON object containing integer
          confidence_bps in 0..10000. Invalid output fails closed and the
          0.85 policy is unchanged. Live semantic/adversarial evaluation and
          calibration remain rollout gates.
Severity: MEDIUM (affects rule quality scoring, not fund safety)
```

**M-002: Performance test marginal in debug mode (Check 2.7) - LOCAL PASS 2026-08-01**
```text
File:     modules/client/tests/performance.rs:test_commitment_build_performance_budget
Finding:  The former test_commitment_build_under_1ms failed at 1.17ms in a
          debug build.
          All other tests pass. Likely passes in release mode.
Action:   A warmed, odd-sized sample set uses median steady-state latency to
          resist scheduler stalls without accepting a consistently slow
          implementation. Debug keeps a 2ms smoke budget; CI also runs the
          same test under --release with the strict 1ms budget.
Severity: MEDIUM (CI flakiness, not a real performance issue)
Status:   Locally resolved by GH-131; protected CI and exact-main evidence are
          still required before final closure.
```

---

### LOW (backlog):

**L-001: DevIncentivePool.deposit() has no ACL (Check 6.5)**
```
File:     modules/contracts/DevIncentivePool.ss
Finding:  deposit() is callable by anyone. Comment says "emission contract"
          but no require(msg.sender == EMISSION_CONTRACT) guard.
          Low risk: only adds funds to pool, never removes.
Action:   Add ACL when emission contract address is known.
Severity: LOW
```

**L-002: Q-003 fp_rate oracle operator integration pending (Check 1.12 related)**
```
File:     modules/contracts/GovernanceAutoTuning.ss; modules/contracts/silverc/GovernanceAutoTuningState.sil
Finding:  Legacy `.ss` keeps oracle_get_fp_rate() as an archival stub, but
          current-Silverc GovernanceAutoTuningState replaces it with a signed
          metrics-oracle report and runtime gates. The remaining risk is
          deployment/operator integration for the metrics signer.
Action:   Implement and document the oracle operator before beta/mainnet.
Severity: LOW (contract gate exists; operational integration remains)
Update:   2026-07-12 local tooling now requires real deployment receipts to be
          paired with public node/explorer receipt evidence before handoff
          readiness can pass, and verified oracle tx results to be paired with
          public node/explorer tx evidence before readiness can pass; external
          oracle transaction operation still remains outside this repository
          and pending real deployment evidence.
```

**L-003: revealVote CEI borderline (Check 6.4)**
```
File:     modules/contracts/ValidatorStaking.ss:126,132
Finding:  transfer(msg.sender, vc.bond_kas) at line 126 occurs before
          delete commitments[key] at line 132. Technically Effect-after-
          Interaction, but mitigated by committed_at_block > 0 guard
          preventing re-entry.
Action:   Move delete before transfer when refactoring for ssc.
Severity: LOW (mitigated by guard, no exploit path found)
```

---

### PASSED (verified clean):

**LEVEL 1 — SILVERSCRIPT CONTRACTS (11/12 passed)**
- [PASS] 1.1  KAS/PROM separation — ValidatorStaking.ss:2,13,59,64
- [PASS] 1.2  slash() ACL — ValidatorStaking.ss:140-143
- [PASS] 1.3  float64/uint64 consistency — all 6 files, zero float64
- [PASS] 1.4  IPFS CID bytes(36) — RuleStorage.ss:16,29,75,80
- [HIGH] 1.5  Commit-Reveal LE encoding — see H-001
- [PASS] 1.6  Non-recursive slash — ValidatorStaking.ss:149
- [PASS] 1.7  MIN_STAKE_KAS = 10000 — ValidatorStaking.ss:33
- [PASS] 1.8  Bond return on reveal — ValidatorStaking.ss:126
- [PASS] 1.9  Time-windowed FP counter — RuleStorage.ss:99-104
- [PASS] 1.10 registered_at check — GuardianReputation.ss:49,79,100,122
- [PASS] 1.11 Reward formula — DevIncentivePool.ss:141
- [PASS] 1.12 MIN_CONFIDENCE = 8500 — RuleStorage.ss:40

**LEVEL 2 — RUST CLIENT (5/7 passed)**
- [PASS] 2.1  Commit-Reveal formula matches — validator-node/src/voting/commit.rs:79-91
- [HIGH] 2.2  Arc<Mutex<Phi3Model>> — see H-002
- [PASS] 2.3  tokio::sync::Mutex only — zero std::sync::Mutex in async
- [PASS] 2.4  CIDv1 "bafy" only — krc20.rs:112, zero CIDv0
- [PASS] 2.5  Cargo.toml clean — no suspicious deps
- [PASS] 2.6  cargo clippy — zero warnings
- [LOCAL PASS / PROTECTED EVIDENCE PENDING] 2.7 cargo test — see M-002

**LEVEL 3 — PYTHON GUARDIAN NODE (4/4 passed)**
- [PASS] 3.1  Strict model confidence — see M-001; live calibration remains operational evidence
- [PASS] 3.2  No yara C-binding — custom matcher used
- [PASS] 3.3  No raw data transmission — gradients only
- [PASS] 3.4  pytest — 23/23 passed, 3 skipped (LLM gate)

**LEVEL 4 — TEST COVERAGE (3/3 passed)**
- [PASS] 4.1  Total tests: 180 (target 160+)
- [PASS] 4.2  All 6 critical paths covered (slash, commit, reveal, stake, reputation, reward)
- [PASS] 4.3  E2E lifecycle test exists — e2e_threat_lifecycle.rs, 60s gate

**LEVEL 5 — CROSS-COMPONENT CONSISTENCY (5/5 passed)**
- [PASS] 5.1  VALIDATOR_QUORUM = 6700 — consistent in 3 contracts
- [PASS] 5.2  COOLDOWN_BLOCKS = 100800 — contract + validator-node match
- [PASS] 5.3  REPUTATION_START = 1000 — contract + client test match
- [PASS] 5.4  MIN_CONFIDENCE = 8500 / 0.85 — 4 layers + 4 cross-check assertions
- [PASS] 5.5  Emission 40/30/20/5/5 = 100% — consistent across all sources

**LEVEL 6 — SECURITY (5/5 passed)**
- [PASS] 6.1  Zero hardcoded secrets
- [PASS] 6.2  Zero unwrap() in production (57 in test only)
- [PASS] 6.3  Overflow protection — saturating_mul/sub in Rust, min() cap in SS
- [PASS] 6.4  CEI pattern — all state before transfers (1 borderline, see L-003)
- [PASS] 6.5  Access control complete — all sensitive functions guarded

**LEVEL 7 — DOCS vs CODE (3/3 passed)**
- [PASS] 7.1  All 6 whitepaper values match code exactly
- [PASS] 7.2  All 8 AUDIT.md resolved findings verified in code
- [PASS] 7.3  ERRORS.md: 11/12 patterns implemented (PATTERN-010 = H-002)

---

### SUMMARY

```
Total checks run:       35
Critical findings:      0
High findings:          2  (H-001 LE encoding, H-002 Mutex)
Medium findings:        0 open in repository implementation
                        (M-001 GH-135 and M-002 GH-131 merged)
Low findings:           3  (L-001 deposit ACL, L-002 fp_rate operator integration, L-003 CEI)
Passed clean:           28

Tests passing:          203/204 (180 unit + 23 python + 1 flaky perf)
Contracts audited:      6/6
Rust modules audited:   10/10
Python modules audited: 4/4

Audit confidence:       94%
(Deduction: ValidatorStaking current-silverc compile/ABI and runtime
 transitions plus signed-int deployment bounds are verified,
 GuardianReputation current-silverc compile/ABI/runtime/formula gates are
 verified, RuleStorage, CommunityDonations, DevIncentivePool, and
 GovernanceAutoTuning current-silverc compile/ABI/runtime gates are verified
 locally/in CI, and all 7 current-Silverc fixtures compile through a local
 release-bundle manifest gate,
 but network deploy/orchestration tooling, oracle operator integration, and
 live confidence calibration remain open)
```

**VERDICT UPDATE 2026-07-11:** Toccata/hardfork no longer looks like the
primary blocker. The deployment blocker is now current-Silverscript contract
runtime readiness: H-001 byte-core is verified, `ValidatorStakingState.sil`
compiles/builds covenant sigscripts, and `commitVote`/`revealVote`/
`slashInvalidReveal`/`requestWithdraw`/`completeWithdraw` runtime tests pass.
The signed-int/u64 boundary is resolved by constraining current-Silverc
deployment inputs to `0..=i64::MAX`; GuardianReputationState runtime/formula
gates, RuleStorageState runtime gates, CommunityDonationsState runtime gates,
DevIncentivePoolState runtime gates, GovernanceAutoTuningState signed
metrics/auto-tune runtime gates, and all-fixture release-bundle manifest now pass
locally. Network deploy/orchestration tooling and oracle operator integration
must pass before Sprint 9 deployment.
M-001 has a separate GH-135 local candidate; complete gates, protected CI,
exact-main evidence, and live semantic/calibration work remain. M-002 is
merged and exact-main verified.

**AUDIT UPDATE 2026-07-15:** GH-9 no longer uses the obsolete Hello-World/
`ssc deploy` path. The repository defines two closed deployment profiles bound
to the deterministic release manifest. `full` retains all seven fixtures and
requires the public metrics-oracle key. `testnet-10-validator-staking-h001`
selects exactly the H-001 proof fixture, requires the TLS-only official resolver,
forbids the oracle key, and uses distinct request/procedure/receipt/evidence/
status values that cannot satisfy full readiness. Local Rust and Python
regressions cover profile tampering after rehashing, wrong network, forbidden or
missing oracle inputs, receipt scope, and full-path compatibility. This closes
the avoidable software dependency between the first H-001 canary and the
GovernanceAutoTuning oracle identity; it does not close the external funding,
signature, confirmation, public evidence, remaining-contract, oracle-operation,
or exact-commit hardening gates.

**AUDIT UPDATE 2026-07-16:** The proposed miner integration is feasible only
as an opt-in companion boundary at this stage. Current Kaspa ASIC/pool mining
normally uses Stratum while the Prometheus client uses Kaspa wRPC; the existing
Phi-3, ZK, KRC-20 cache, and federated-learning paths are development stubs and
cannot support production scanning/reporting or passive rewards. GH-13 therefore
accepts only a credential-free loopback Testnet-10 RPC observer, rejects
beta/mainnet and unsupported roles/features, redacts endpoint data, and adds no
wallet, tokenomics, firmware, remote-network, host-process, or filesystem
access. An independent read-only review confirmed this boundary after the
local-wRPC wording was corrected. A bounded Spark review found no code defect;
its missing-file, malformed/oversized-config, failed-connect redaction, and
no-args test gaps were added. Final local verification passes 153 workspace
tests with two intentional live ignores, warning-free Clippy, Rustfmt, Memory,
Pages/JSON-LD, Actionlint, Cargo Audit without vulnerabilities, and staged-diff
Gitleaks. Final acceptance required PR CI/Security and live Pages verification.
PR #14's first ten remote contexts passed. Six CodeRabbit comments were then
addressed: bounded config reads, transient RPC retry behavior, exact reporter
pool eligibility wording, checkpoint path/baseline hygiene, Whitepaper grammar,
and expanded public Rustdoc. All six review threads were resolved, all ten
repeated PR contexts passed, and PR #14 merged normally as `2e4b4ec`. Exact-merge
Prometheus CI `29422667384`, Security Audit `29422667792`, Pages `29422666363`,
and the live Whitepaper check pass. The foundation is accepted; production
scanning, proofs, rule distribution, rewards, and miner-specific integration
remain separately gated future work.

**AUDIT UPDATE 2026-07-16:** GH-9 now has independently verified public TN10
funding. Faucet transaction
`24e81339f3656689643ca86e3c53c4c5336e4273bb127d25bdaf328e5da241c7`
is accepted; output `0` is an unspent, non-coinbase P2PK output holding
`100100000000` sompi at DAA `517772692`. Its script commits to x-only public key
`e5a39b02e8bad5dbe8d793425e2590b008a4517696c756ccf18dfa9f16c1f1cf`
and matches the public deployer address recorded in issue #9. This resolves only
the funding and public-identity gates. Exact-commit artifact/request binding,
the 32-byte digest, approved external BIP340 signing, one-shot broadcast,
confirmation, receipt, and independent deployment evidence remain mandatory.
No private wallet data or raw signed transaction entered the repository or
GitHub. Canary evidence remains non-promotable to full or metrics readiness.

**AUDIT UPDATE 2026-07-16:** The first real funding-bound GH-9 dry run found a
pre-sign reliability defect in the old operator example: an `80000`-sompi
covenant output produced `storage_mass=50000000`, while the operator enforced
only caller-provided absolute fee bounds. GH-17 now calculates the final
66-byte Schnorr signature-script shape, binds compute/transient/storage and
normalized non-contextual/overall mass into signing-request schema v2, mirrors
the pinned rusty-kaspa v2.0.1 `100000` sompi/kg relay baseline, and applies the
same rate conservatively to overall mass for miner prioritization. Rehashed
fee/mass tampering, unknown schema fields, and below-floor funding fail before
digest export. The signature integration test also recomputes the final signed
shape and matches every bound mass and fee floor. A 10-TKAS/500000-sompi live
candidate preflight passes all derived floors and 35 focused tests. The
candidate is intentionally non-authoritative until merge and
exact-main CI; no signature or broadcast occurred.

**AUDIT UPDATE 2026-07-16:** GH-17 merged normally through PR #18 as exact main
commit `9477fabb8a9abb41e0ee82f7e240a99436452d2c`; Prometheus CI
`29442211087`, Security Audit `29442210829`, and Pages `29442209299` pass. The
pre-merge candidate was discarded. All seven release artifacts, the
manifest-bound one-request H-001 canary profile, public funding spec, live
funding preflight, and schema-v2 signing request were rebuilt outside the
repository from that commit. Live preflight reconfirmed the exact P2PK outpoint
as unspent/non-coinbase on a synced, UTXO-indexed rusty-kaspa `2.0.1` node above
Toccata activation. Two independent prepare runs emitted byte-identical JSON;
the public handoff directory passed Gitleaks. Signing-request hash
`6b8e65065ca5ae2ca561ddd3fcb9659c384496fd31db32c137fcc9d811fa5323`
binds sighash
`174ccbe80d1d37e62d2bbabfbfba48245372df2bcf9e6724ac79ebc16b4e0bcd`.
No signature, wallet access, raw signed transaction, or broadcast occurred.
External signing requires explicit approval and complete operator verification
before the one-shot canary broadcast.

**AUDIT UPDATE 2026-07-16:** The GH-9 signing handoff now has a locally verified
canonical public-signature import candidate. `import-signature` accepts only a
64-byte BIP340 signature encoded as 128 lowercase hex characters with at most
one trailing line ending, derives all response identity/digest fields from the
validated schema-v2 request, resolves paths before I/O, rejects output/input and
output/output aliases, and writes outputs only after BIP340 plus full Kaspa
transaction verification. The existing full-JSON response path remains
compatible. The runbook explicitly forbids wallet `message sign` because its
personal-message domain hash is not the transaction sighash. Thirty-eight
focused tests, warning-free Clippy, workspace tests, CLI smoke, YAML parsing,
and independent Terra review pass. PR #23 merged as exact main
`f79150d77ebbf8c71ec8051dc22c7a126d4f38c0`; Prometheus CI `29449066498`,
Security Audit `29449066352`, Pages `29449065192`, and live Whitepaper
verification pass. No wallet, private material, signature, raw signed
transaction, or broadcast was used.

**AUDIT UPDATE 2026-07-16:** GH-25 merged normally through PR #26 as exact main
`072f04a7b6dbdb77970b9d51c6bb13ff79b3ee72`. The protected PR checks and
independent Terra review passed after the stale Handoff instruction was fixed.
Optional CodeRabbit remained stuck without emitting a review, thread, or
finding. The first exact-main CI/Security/Pages attempts froze concurrently in
unrelated steps and were cancelled after about ten hours; rerun attempt 2 for
the same SHA passed as Prometheus CI `29453756167`, Security Audit
`29453756135`, and Pages `29453755086`. Live Whitepaper verification contains
the merged keyless metrics-transition boundaries. GH-25 software/docs/CI are
accepted. Real state and sponsor UTXOs, two external BIP340 signatures,
acknowledged broadcast, confirmation, successor evidence, and exact-rollout
release evidence remain operational gates. No wallet, private material,
signature, raw transaction, or broadcast was used.

**AUDIT UPDATE 2026-07-16:** The non-promotable GH-9 H-001 handoff was rebuilt
from clean exact main `205e1ca928d3048109575cf7a21810c9e6609120` after
Prometheus CI `29454591518`, Security Audit `29454591555`, and Pages
`29454590793` passed. Seven artifacts, the one-request canary set, procedure,
funding spec, and schema-v2 signing request reproduced. Live read-only preflight
reconfirmed the public funding output unspent/non-coinbase through a synced,
UTXO-indexed `rusty-kaspa 2.0.1` node at DAA `517950805`, above activation.
Two prepare runs were byte-identical to each other and the earlier `9477fab`
baseline; signing-request hash and sighash remain unchanged. The owner-only
handoff at `/Users/gio/Desktop/repos/prometheus-handoffs/205e1ca` passed 0700/
0600 mode checks and a full-directory Gitleaks scan. No wallet, private key,
signature, raw transaction, or broadcast was accessed or produced. External
BIP340 signing, complete import verification, separately approved broadcast,
confirmation, receipt, and independent evidence remain mandatory.

**AUDIT UPDATE 2026-07-16:** GH-33 implements the first bounded Sprint 10B
Guardian-decentralization slice as a dependency-injected local hybrid router.
The router always invokes 8B first, keeps the exact `0.70` boundary on the
primary route, and escalates lower confidence or an invalid primary safety
envelope to 70B. It preserves `MIN_CONFIDENCE = 0.85` and fails closed for a
failed/invalid 70B result. Independent Terra review found two medium issues in
the first draft: missing threat-hash binding and permissive runtime submission
types. Both were fixed by binding analysis and YARA-rule hashes to the input,
requiring finite range-checked confidence, a real bool decision, a real
`YaraRule`, and consistent rule/result confidence. Recheck found one further
medium malformed-adapter path; an `isinstance` guard plus regression test now
keeps that path on fail-closed escalation. Final review reports no remaining
high/medium finding. Local verification passes
47 tests with three intentional live-model skips, Black, and Pylint 9.69/10.
No live-model, P2P, chain, wallet, signing, or broadcast behavior is introduced.
PR #34 merged normally as exact main
`ce1d2137adef70addcd493747590053bad0439ce`; Prometheus CI `29459533780`,
Security Audit `29459533770`, and Pages `29459533175` passed. Live Roadmap,
Whitepaper, and FAQ markers were verified. Live 8B/70B wiring, calibrated model
confidence, ensemble voting, and production evidence remain open.

**AUDIT UPDATE 2026-07-16:** GH-36 implements the local fail-closed Guardian
ensemble protocol without changing contracts, P2P, wallets, or submission
behavior. A domain-separated canonical candidate digest binds the protocol,
threat hash, exact YARA bytes/metadata, exact integer-bps source confidence,
policy hash, and pinned 8B model artifact. An immutable sorted snapshot commits
at least five unique canonical Guardian IDs and an explicit membership-source
digest. The validator requires exactly one fully bound 8B vote per member, a
complete-ballot strict majority, `8500` bps for the source and every approval,
and final confidence equal to the minimum of source and approving votes. Any
missing, duplicate, unknown, malformed, mismatched, tied, or below-policy input
returns no rule. Independent review first found missing source-confidence
binding, then found epsilon rounding across the `0.85` boundary; both were
fixed with candidate binding plus exact `Decimal`-to-bps conversion. Final
re-review reports no remaining high/medium finding. Local Guardian verification
passes 96 tests with three intentional live-model skips, Black, CI-scope Pylint
9.87/10, focused Pylint 10.00/10, and the Rust workspace regression. Trusted
membership, signed P2P votes, replay/Sybil resistance, and on-chain ensemble
attestation remain open and must not be inferred from this local gate.
PR #37 merged normally without admin bypass as exact main
`f8ebaacea8b36ebe45ac6ec5419d294431716362`; issue #36 closed automatically.
All protected contexts passed. Exact-main Prometheus CI `29461803530`, Security
Audit `29461803531`, and Pages `29461802700` succeeded, and the live Roadmap,
Whitepaper, and GitHub README contain the merged boundary. CodeRabbit's content
review was rate-limited, so the independent multi-round review and automated
gates remain the substantive review evidence.

**AUDIT UPDATE 2026-07-16:** GH-39 adds a transport-neutral authenticated
Guardian ballot intake around the unchanged GH-36 ensemble decision. A
domain-separated session commits candidate, membership snapshot, network,
validity, nonce, and the exact unique Guardian-to-BIP340-x-only-key mapping.
Exact-schema canonical envelopes bind the complete vote and freshness context;
public signatures are verified through pinned `coincurve==21.0.0` before an
owner-only SQLite ledger atomically consumes one vote per Guardian and one
nonce per active session. Persistence survives restart and concurrent
collectors, retains markers for the complete session, and reverifies stored
envelopes before evaluation. Independent review found one medium
forward-clock/prune/rollback path that could reopen a pruned session. A
persistent monotonic ledger-time watermark updated in the same immediate
transaction as consume/prune plus a restart regression closes it; final
re-review reports 0 blocking/high/medium findings. Local evidence is 70 focused
signed-ballot/ensemble tests, 117 complete Guardian tests with three intentional
live-model skips, Black, Pylint 10.00/10 focused and 9.93/10 CI-scope, Python
compilation, Rustfmt, warning-free Clippy, 170 Rust tests with two intentional
live ignores, no known dependency vulnerabilities, YAML/Actionlint, Memory,
Autodidactic, HTML, Gitleaks, and diff gates. One first Rust run hit the known
sub-millisecond performance jitter at 1.408 ms; isolated and complete reruns
passed. GH-42 later supplied direct ballot transport; operated discovery/NAT/relay,
trusted membership/key assignment, Sybil resistance, on-chain attestation,
proposal submission, and production signer/model operation remain open. No
wallet, private key, signature, raw transaction, broadcast, contract, slash
ACL, commit-reveal formula, KAS/PROM split, or Guardian-reputation behavior was
used or changed. PR #40 merged normally without admin bypass as exact main
`d0f78a9857e654dd487678a031d39ac52a44e0ec`; issue #39 closed automatically.
Exact-main Prometheus CI `29464295373`, Security Audit `29464295355`, and Pages
`29464294890` passed, and live Whitepaper, Roadmap, and GitHub README markers
were verified. CodeRabbit was rate-limited without a content review; the
independent security review/re-review and protected automated gates are the
substantive review evidence.

**AUDIT UPDATE 2026-07-16:** GH-42 adds the first real Guardian ballot carrier
without changing GH-36 voting or GH-39 authentication. Exact opaque ballot
bytes travel over direct QUIC request/response with an 8192-byte pre-allocation
limit, one stream per connection, global request admission, bounded connection
counts, and deadlines. Inbound data reaches the existing collector only through
an owner-only AF_UNIX bridge; directory, socket, and connected peer credentials
must match the sidecar effective UID, and canonical local ACKs are bound to the
exact payload SHA-256 before a one-byte network result is sent. SQLite/BIP340
work runs outside the asyncio event loop. Independent review found one high UID
ownership gap plus medium availability and missing-bridge concerns; effective
UID/peer-credential checks, per-connection/global caps, thread offload, and the
`next_sidecar_event` end-to-end QUIC-to-collector test close them. The
rust-libp2p umbrella crate and mDNS were removed after optional DNS dependencies
introduced two lockfile RustSec findings; direct pinned component crates restore
`cargo audit` to zero known vulnerabilities. Public relay/NAT/discovery,
trusted membership/key assignment, Sybil resistance, proposal transport, and
on-chain attestation remain rollout gates.

CodeRabbit's subsequent review found that Python admission could be released
while a timed-out `to_thread` job still ran, Python client-side ACK parsing did
not bind the returned digest to the submitted ballot, and synchronous collector
awaiting stopped exclusive libp2p swarm polling. A shielded worker task now owns
the admission permit until the worker future completes; non-busy ACKs are
payload-bound; and bounded Rust ingress futures are retained in carrier state
and polled alongside the swarm. New timeout/permit, digest-mismatch, and
two-peer out-of-order tests close these paths. Post-fix local verification is
126 Guardian tests with three intentional live-model skips, 181 Rust workspace
tests with two intentional live-network ignores, Rustfmt, warning-free Clippy,
Black, and Pylint 9.95/10. One first workspace run hit the known sub-millisecond
performance jitter at 1.278 ms; isolated and complete reruns passed.

Follow-up review identified two peer-cancellation orderings around active local
ingress work and libp2p response-channel closure. Separate admitted-work,
active-ingress, and response-channel tracking now keeps capacity consumed until
real local completion. Both already-removed channels and channels that close
before `InboundFailure` handling are nonfatal only in the automatic sidecar
completion path; the manual `respond()` API preserves its explicit error.
Deterministic ordered-cancellation and closed-channel-race tests pass, and final
independent re-review reports zero blocking/high/medium findings. A later
concurrent workspace attempt hit the same performance jitter at 2.291 ms while
Cargo artifact locks were contended; the isolated test completed in 43
microseconds and the clean complete workspace rerun passed.

PR #43 merged normally without admin bypass as exact main
`5224c00956346475d6a48b6e335003237d03c6ed`. Exact-main Prometheus CI
`29468717108`, Security Audit `29468717112`, and Pages `29468716410` passed,
and live Whitepaper, Roadmap, and GitHub README markers were verified. Issue
#42 is closed. GH-44 carries the explicit persistent-identity and operated
relay/NAT follow-up without changing the authorization boundary.

## GH-44 MERGED AUDIT UPDATE (2026-07-16)

Merged GH-44 adds persistent libp2p identity, strict route validation,
data-minimal health events, and a bounded relay/AutoNAT service without changing
Guardian authorization. Identity creation uses an absolute owner-controlled
path, `NOFOLLOW`, effective UID and mode checks, bounded canonical protobuf,
same-directory exclusive temporary creation, sync, and atomic hard-link
publication. Concurrent creation and restart retain one `PeerId`.

The deterministic isolated three-node harness proves relay reservation,
relay-only exact ballot/ACK delivery, AutoNAT state, a failed DCUtR direct upgrade
with continued relay fallback, and circuit/connection close. Public Internet or
multi-host operation, broad discovery, membership/key trust, Sybil resistance,
and on-chain attestation remain explicitly unproven. The initial independent
review caught one displaced duplicate-listener validation block; compiler errors
also exposed it. Re-review then found that dev feature unification masked a
production-only missing `rustix/fs` feature. Both were fixed. Production-only
`cargo check`, 21 crate tests, 191 clean-rerun workspace Rust tests, 126 Guardian
tests, format/lint/dependency/Memory/HTML/workflow gates, and final independent
re-review pass with no remaining blocking/high/medium finding. One concurrent
workspace attempt hit known M-002 jitter at 1.993 ms; isolated rerun passed at
914 microseconds and the clean complete rerun passed.

No secret, wallet, private key from an existing user file, signature, raw
transaction, broadcast, contract, reputation, KAS/PROM, slash ACL, or
commit-reveal behavior was accessed or changed. The known foreign untracked
`Prometheus-1.png` remains untouched. PR #46 merged normally as `27c2edc31`;
exact-main Prometheus CI `29471344601`, Security Audit `29471344556`, and Pages
`29471344050` passed for the same SHA, and live public markers were verified.

## GH-48 OPERATED SIDECAR MERGE AUDIT UPDATE (2026-07-16)

GH-48 packages the existing transport core as an explicit Guardian/relay
process without changing membership, keys, signatures, reputation, stake,
rewards, contracts, or chain behavior. Strict owner-only TOML selects one role;
the Guardian role owns a bounded AF_UNIX submission service and continuously
drives network/collector work, while relay remains transport-only. JSON records
exclude ballot, collector, and local-path data. SIGINT/SIGTERM stops admission
and listeners, drains admitted work to a bounded deadline, emits terminal state,
and removes the owned socket.

The separate-process same-host test proves exact relayed ballot delivery from
the submit CLI to the receiver collector, canonical ACK return, graceful signal
exit, socket cleanup, and stable transport identities. It is not public or
multi-host evidence. Independent review found one medium strict-framing gap:
collector acknowledgements accepted bytes after the declared canonical JSON.
Mandatory ACK EOF and a trailing-byte regression close it. Final verification
passes 33 unit tests plus three process tests, 206 workspace Rust tests with two
intentional live-network ignores, 126 Guardian tests with three intentional
live-model skips, Rustfmt, warning-free workspace/all-target Clippy, locked
release build, Cargo package, Black, Pylint 9.95/10, Memory, Autodidactic, HTML,
Actionlint, dependency, staged Gitleaks, public-status, and diff gates. Final
security and CI/package re-reviews report no remaining actionable finding.

The first PR #49 Rust Workspace run exposed one Linux-only overload behavior:
closing a busy AF_UNIX connection with unread request bytes reset the client
before its `busy` response was observed. A separate bounded rejection pool now
reads and validates one exact request frame before returning `busy`; excess
rejection work remains capped and malformed frames fail as transport errors.
The focused admission regression, then-complete 32-test crate suite, process
test, Rustfmt, and all-target Clippy pass after the fix. CodeRabbit's refreshed
review identified six valid items: synchronous stdout backpressure could
pin signal handling, `stopped` preceded submission-server confirmation, service
paths accepted parent-directory components, the process collector allocated
before checking the frame bound, Backlog named stale baselines, and Audit
metadata was ambiguous. A bounded dedicated JSON writer, corrected shutdown
ordering, lexical path rejection, pre-allocation frame guard, and synchronized
metadata close them. Focused tests, the now-complete 33-test crate suite, three
process tests including broken-stdout and collector-wait SIGTERM coverage, all
206 workspace tests, Rustfmt, and workspace all-target Clippy pass. Independent
Terra re-review reports no actionable finding. All ten final PR contexts passed
in Prometheus CI `29481599742` and Security Audit `29481599706`, including
CodeRabbit with every thread resolved. PR #49 merged normally as exact main
`b14d36fc79ddc7e0b407b42cb4a271e29cb1ddea`; exact-main Prometheus CI
`29481830688`, Security Audit `29481830686`, and Pages `29481830054` pass.

No secret, wallet, existing private key, signature, raw transaction, broadcast,
contract, reputation, KAS/PROM, slash ACL, commit-reveal, or Guardian
authorization behavior was accessed or changed. `Prometheus-1.png` remains
untouched and uncommitted.

*Original pre-hardfork audit completed 2026-04-02 by Claude Code (5 parallel agents, 7 levels, 35 checks); GH-48 merge update completed 2026-07-16 by Codex.*
*The fire belongs to humanity.*

## GH-63 KIP-16 VERIFIER AUDIT UPDATE (2026-07-23)

GH-63 replaces the nonexistent `kaspa-zk-params` assumption with a real
manifest-pinned BN254/Arkworks Groth16 verifier aligned to active KIP-16 and the
pinned `rusty-kaspa` v2.0.1 serialization. Canonical manifest, verifying key,
proof, network, domain, and every semantic ThreatHint field are bound before a
pairing check. Inputs, files, process runtime, and output channels are bounded;
unsafe or incomplete configuration maps to unavailable and preserves `busy`.

Independent read-only review confirmed canonical parse/roundtrip checks,
public-input arity, real pairing verification, owner/mode enforcement, inode
race checks, and negative tests. Its production-vector finding is an explicit
rollout gate rather than a fabricated fix: the repository intentionally ships
no production relation/VK/proving key or approval claim. The relation-source
hash is documented as manifest-bound attested metadata that the artifact
ceremony must independently verify. CLI unavailable moved to exit 3 so Clap's
syntax exit 2 is unambiguous. Locked Cargo resolution controls test-only
dependencies. No blocking/high/medium implementation finding remains in the
current review scope; production proof-artifact approval and analyzer mapping
remain blocking operational evidence.

Final independent re-review after full process-group timeout cleanup, service
connection/path bounds, special-mode rejection, and public documentation
synchronization reports no remaining blocking, high, or medium finding.

Protected CodeRabbit review subsequently found that binary ancestors rejected
group/other-writable modes but did not restrict directory ownership. GH-63 now
requires every verifier-binary ancestor to be owned by root or the effective
user and includes a non-root/non-user owner regression. The complete Guardian
suite passes under Python 3.11 with 144 passes and three intentional live-model
skips; 18 focused ingress/service tests, Black, Ruff, and Pylint 9.80/10 pass.
All four review threads were resolved and all ten protected PR contexts passed.
PR #64 merged normally as `f4f9df95848d41c82379ef59044d12453b12279c`;
exact-main Prometheus CI `29968203074`, Security Audit `29968203053`, and Pages
`29968202562` pass. Production artifact approval remains an operational gate.

## GH-74 THREATHINT ANALYZER ADAPTER AUDIT UPDATE (2026-07-23)

Scope: `jaeger/analyzer.py`, `jaeger/threat_hint_adapter.py`, the GH-58 outbox
contract, focused adapter tests, Guardian docs, public status, and CI discovery.
Result before protected review: 0 blocking, 0 high, 0 medium implementation
findings. ThreatHint v1 has no concrete IOC strings; treating `indicator_type`
as an indicator would fabricate evidence. GH-74 instead defines a frozen
verified input with only actual wire/job fields and no `indicators` member.

The adapter re-parses exact canonical bytes, constant-time compares the stored
SHA-256 digest, binds the configured network, requires the real proof mode, and
rechecks the original freshness admission window. Each per-instance serialized
drain loads at most 32 jobs. The analyzer's verified-v1 entry point does not call
an LLM or YARA generator and can return only confidence `0.0`, no rule, and no
submission. The adapter validates that exact result before marking delivery;
tamper, wrong network, analyzer failure, unsafe result, and clock rollback keep
the job pending. The v1 result has no submission side effects. A future
observable-bearing and side-effecting multi-process consumer requires separate
schema/privacy and claim/lease review.

Local evidence is 24 focused tests and 158 complete Guardian passes with three
intentional live-model skips, plus Black, Ruff, focused Pylint 10.00/10, and
clean diff checks. Existing CI automatically runs the complete Guardian suite,
format/lint gates, secret scan, dependency audit, and public-page checks; no
workflow change is required. Production proof-artifact approval, concrete
observables, actionable analysis, live models, and real operation remain open.

## GH-77 THREATHINT BATCH-PROGRESS AUDIT UPDATE (2026-07-23)

Scope: GH-74 adapter drain semantics, delivery ordering, cancellation during
threaded SQLite acknowledgement, failure-report privacy, bounds, and focused
regressions. Independent post-merge review found that one failed leading job
aborted the complete bounded drain and could starve later independent jobs.

The candidate isolates ordinary adapt, analysis, clock, and delivery failures
per job. Failed jobs stay pending while later safe v1 jobs continue. This
deliberately relaxes FIFO acknowledgement only for independent hash-only v1
jobs, which have no proposal-submission side effect; both delivered and failed
records retain the original bounded batch index. Failure records contain only a
fixed category and a digest validated through complete adaptation or `None`.
Canonical bytes, paths, analyzer output, and arbitrary exception text are never
reported.

Cancellation remains a `BaseException` and is not converted into a failure.
During threaded `mark_delivered`, the adapter holds the per-instance drain lock
until the SQLite worker reaches its durable outcome, then propagates
cancellation. Nineteen focused tests cover leading adapt/analyzer/delivery
failures with later progress, valid-looking mismatched digest redaction, unsafe
results, clock rollback, cancellation in analysis and delivery, serialization,
and batch limits. All 163 complete Guardian tests pass with three intentional
live-model skips; Black, scoped Ruff, focused Pylint 10.00/10, and diff checks
pass. PR #79 merged normally as `4cada95ed2f97c2d0251dd82ef40290b0c664c41`;
exact-main Prometheus CI `29975041446`, Security Audit `29975041416`, and Pages
`29975040944` pass. No protected review thread remained open.

## GH-82 THREAT OBSERVABLE V2 DESIGN AUDIT (2026-07-23)

Scope: ThreatHint v1 schema/client/verifier binding, Guardian analyzer and YARA
boundaries, public privacy/proof claims, and the proposed observable contract.
Read-only architecture and privacy reviews found that v1 `threat_hash` is
caller-supplied. The schema, builder, and verifier validate and bind it but do
not derive it from a file or observable.

Decision: leave v1 and its proof formula unchanged. The preferred v2 design
uses separate `artifact_hash` and `observable_commitment` fields under a new
statement/relation. The canonical bundle is closed, bounded, domain-separated,
network/nonce-bound, and deny-by-default. A digest match proves byte
consistency only; truth, maliciousness, authorship, artifact derivation,
membership, and anonymity are not claimed unless a separately reviewed
relation explicitly proves them.

Public absolute claims that no metadata leaves the device, gradients permit no
inference, current ZK proves anonymous legitimate participation, or the
under-60-second actionable lifecycle is already operational are corrected.
This design slice adds no transport, key, relation, analyzer side effect,
public rule storage, or production acceptance. Local cross-language canonical
validators and vectors are the next implementation boundary.

Closeout: PR #83 passed all refreshed protected contexts with every review
thread resolved and merged normally as exact main
`fceff1d3ae6db0f38c0076bc2c8dc82f34c3d96d`. Prometheus CI `29977301070`,
Security Audit `29977301063`, and Pages `29977300539` passed for that exact
SHA. Raw GitHub and live Pages checks expose the merged boundary. No rollout
estimate changed because no validator, wire, proof relation/artifact, analyzer
side effect, or operated evidence was added.

## GH-86 LOCAL OBSERVABLE VALIDATOR START (2026-07-23)

Exact public/status main `6659ab18a94f92d006fe24efe5a451d74322d1c6`
passed Prometheus CI `29977755581`, Security Audit `29977755619`, and Pages
`29977755074`. Issue #86 owns isolated local Rust/Python validators and shared
byte-exact vectors. No v1 wire, proof formula, verifier, transport, analyzer,
committee, IPFS, chain, or public-rule path may import the new module.

Architecture review identified a semantic limit: a structural parser cannot
prove that a grammar-valid `api_import` token came from a binary import table.
Canonical acceptance therefore proves only syntax and byte consistency, not
extractor provenance or privacy. Reviewed kind-specific extractors, provenance
binding, and disclosure review remain separate promotion gates.

Implementation result: Rust and Python independently parse and commit the same
5 valid, 35 invalid-bundle, and 9 invalid-context vectors. Sol review closed
Python direct-construction and exception-chain leakage paths. Independent Terra
review then found that public Rust `Deserialize` bypassed canonical validation
and that value-bearing `Debug` exposed accepted local observables. Private
wire-only deserialization, defensive validation before serialization/
commitment, a compile-fail public-API regression, and removal of value-bearing
`Debug` close both findings. The targeted re-review reports no remaining
blocking, high, or medium finding. Final full-diff review then found two Python
parity gaps: post-parse mutation through `object.__setattr__` was not
revalidated before commitment, and a non-string disclosure policy escaped as
`TypeError`. Defensive state validation now precedes every Python canonical
serialization/commitment, a mutation regression covers both operations, and a
shared non-string-policy vector exercises both languages. Final targeted
re-review reports no remaining blocking, high, or medium finding.

Evidence: 16 focused Rust tests plus one compile-fail doctest; 16 focused
Python tests; 257 complete Rust workspace passes with two intentional
live-network ignores; 179 complete Guardian Python passes with three
intentional live-model skips; Rustfmt; warning-free workspace all-target
Clippy; locked optimized Guardian/proof builds; verified 9-file ThreatHint and
14/7-file Guardian/proof package sets; Black; Ruff; full Guardian Pylint
9.86/10 and focused new-module Pylint 10.00/10. Existing CI discovers all new
code and vectors; no workflow change is required. One unchanged client
microbenchmark failed once at 1.84 ms against its 1 ms local threshold; the
immediate isolated rerun measured 41 microseconds and subsequent complete
workspace runs passed, most recently all 257 tests. No GH-86 code path was
involved.

Protected review update: initial CI/Security contexts, including Secret
Detection, passed on `1abb4ce`. CodeRabbit found one actionable Python/Rust
validation-order mismatch and one maintenance nit on the manual Rust
constant-time loop. Python now validates grammar before disclosure policy,
matching Rust, with a focused regression. Rust now uses the already-locked
`subtle 2.6.1` `ConstantTimeEq` primitive through an explicit workspace
dependency. Refreshed protected checks remain required.

Claude Code 2.1.218 then completed a bounded read-only second review and found
no blocking, high, or medium issue. Its one concrete low-severity hardening
point was missing explicit Rust coverage for grammar-before-policy precedence;
a matching regression now closes that asymmetry. Its exact dependency-pin
observation was informational and does not change the reviewed behavior.

Closeout: all ten protected contexts passed on `d4396ca`, the only review
thread is resolved, and PR #87 merged normally without admin bypass as exact
main `2bfe5a3cd5df68bd9d17433748c06bb010070fae`. Issue #86 is closed.
Exact-main Prometheus CI `29981646898`, Security Audit `29981646867`, and Pages
`29981646320` passed. GH-86 is complete only as the isolated local
structural/commitment boundary; all extractor, privacy, v2 wire/proof/pairing,
actionable-analysis, chain, and production-operation gates remain.

## GH-90 LOCAL FILE-SHA256 PRODUCER (2026-07-23)

Scope: one local Rust producer in `prometheus-threat-hint`, one shared
producer-vector corpus, independent Python consumption, and synchronized
internal/public documentation. ThreatHint v1, P2P, verifier, analyzer, proof,
wallet, signing, contracts, and chain paths remain out of scope.

Result: PASS for the isolated local producer boundary. The only
new public function accepts exact artifact bytes plus typed platform/format
scope. It computes SHA-256 internally, reaches the existing validated bundle
type through a crate-private fixed-digest constructor, and exposes no path,
caller-supplied digest, generic observable value, or builder. Empty, text, and
binary vectors bind canonical artifact hex, digest, scope, and exact wire;
Rust produces them and Python independently hashes the input and validates the
wire. A one-bit regression proves byte sensitivity.

Security boundary: deterministic derivation is established only from the byte
slice supplied to the function. The implementation does not prove external
file provenance, truth, maliciousness, semantic privacy approval, transport
authorization, or proof binding. `public_auto_v1` remains a structural label
only. No logging or filesystem/network operation exists in the producer.

Evidence: 13 focused Rust tests and 17 focused Python tests pass; the complete
workspace passes 260 Rust tests plus one compile-fail doctest with two
intentional live-network ignores; Guardian passes 180 tests with three
intentional live-model skips. Rustfmt, warning-free workspace all-target
Clippy, verified 12-file ThreatHint package including both vector corpora,
Black, Ruff, Guardian Pylint 9.86/10, Memory Integrity, six Autodidactic tests,
HTML/JSON-LD/public-status checks, workflow YAML parsing, Actionlint 1.7.12,
Cargo Audit with no vulnerabilities and eight known allowed warnings, and
clean diff checks pass. Gitleaks 8.30.1 reports no leak in the staged diff;
protected CI remains authoritative for the full-history secret gate.

Claude Code supplied a no-tool architecture review after an earlier helper
attempt was stopped when its search scope exceeded the explicit file allowlist.
That stopped process returned no file content and its output was discarded. A
separate Terra diff review reports no blocking, high, or medium finding. Sol
retains implementation, integration, and final verification responsibility.

Closeout: PR #91 passed all ten protected contexts and merged normally without
admin bypass as exact main `e7f34bb438d4d2cee43db9e8c019f05b9ced0f33`;
issue #90 is closed. CodeRabbit's only actionable finding identified ambiguous
GH-86 product-merge versus documentation-closeout evidence in the Checkpoint
and Bridge. Commit `90068cf6b8f57f7ffe84adb6fd48a70bcc75a8ed`
disambiguated those records, and the review thread was resolved. Exact-main
Prometheus CI `29984477087`, Security Audit `29984476876`, and Pages
`29984476107` passed. GH-90 does not close external provenance, privacy,
transport, v2 proof, actionable-analysis, chain, or production-operation
gates.

## GH-94 LOCAL BYTE-PATTERN PRODUCER CANDIDATE (2026-07-23)

Scope: one local Rust producer in `prometheus-threat-hint`, one shared
producer-vector corpus, independent Python consumption, and synchronized
internal/public documentation. ThreatHint v1, P2P, verifier, analyzer, proof,
wallet, signing, contracts, and chain paths remain out of scope.

Result: CONDITIONAL PASS pending protected PR/exact-main evidence. The public
function accepts exact artifact bytes, a checked start offset, a boolean
wildcard mask, and typed scope. It derives every fixed token
from the selected artifact range, emits `??` only where the mask requests it,
requires 8..=64 positions and at least eight fixed bytes, and exposes no path,
pattern string, generic observable value, or builder. The crate-private
constructor accepts fixed-or-wildcard byte tokens rather than text and always
assigns `review_required_v1`.

Security boundary: deterministic extraction is established only from the byte
slice, offset, and mask supplied to the function. Wildcard selection, external
file provenance, truth, maliciousness, semantic privacy approval, disclosure
authorization, and proof binding remain unproved. `review_required_v1` remains
local-only and no IPC, P2P, analyzer, committee, IPFS, chain, or public-rule
path is added.

Focused evidence: 18 Rust producer/validator tests and 18 Python observable
tests pass. Shared vectors cover the minimum fixed pattern, checked nonzero
offset with mixed wildcards, script bytes, and the exact 64-token maximum with
only eight fixed bytes. Rust tests additionally cover short/long/empty masks,
insufficient fixed bytes, out-of-range and overflowing offsets, fixed-byte
sensitivity, and wildcard invariance. Independent Terra review reports no
blocking, high, or medium finding and recommended two coverage additions; both
the exact-end offset rejection and 64-token cross-language vector are included.
Claude Code was requested as a no-tool helper but its configured monthly spend
limit rejected the call before analysis or repository access.

Sol's integration review found that the constructor enforced the 64-token cap
only after the public producer had selected and collected tokens. The public
producer now rejects invalid mask lengths and insufficient fixed-byte counts
before range selection or allocation; the constructor repeats both checks
defensively.

Complete local evidence: 265 Rust workspace tests plus one compile-fail doctest
pass with two intentional live-network ignores; Guardian passes 181 tests with
three intentional live-model skips. Rustfmt, warning-free workspace all-target
Clippy, verified 15-file ThreatHint package contents including all producer
modules/tests/vector corpora, Black, Ruff, Guardian Pylint 9.86/10, Memory
Integrity, six Autodidactic tests, HTML/JSON-LD/public-status checks, workflow
YAML parsing, Actionlint 1.7.12, Cargo Audit with no vulnerabilities and eight
known allowed warnings, staged-diff Gitleaks 8.30.1 with no leak, and clean
diff checks pass. Protected CI remains authoritative for the full-history
secret gate.

Protected PR evidence: PR #95 passed all ten CI, Security, and CodeRabbit
contexts for commit `6daa9f3fa1c8af39f6ac4a17a970cac627b43e9e`. CodeRabbit
reported one valid minor documentation ambiguity: the API memory could imply
that GH-94 producer validation reused the generic bundle corpus. The API now
distinguishes the generic bundle corpus from the separate GH-94 byte-pattern
producer corpus. No product or workflow behavior changed; refreshed protected
checks and normal merge remain required.

CI recovery note: GitHub registered both review-fix pushes on #95 but retained
the original PR tracking SHA for the first push and attached reopened workflow
suites to stale commit `6daa9f3` even after the PR commit list advanced. PR #95
was closed. First replacement #96 correctly ran its initial suites on
`96a6f8e`, but GitHub again omitted suites for later final head `95034d1`;
#96 was closed without merge. Final branch
`feat/GH-94-local-byte-pattern-producer-final` contains the identical reviewed
product commit set and is opened only after all changes are committed, avoiding
post-open synchronization. Security Audit's existing manual dispatch correctly
attached to its requested SHA. Prometheus CI now exposes the same
`workflow_dispatch` recovery trigger for future default-branch availability;
no required check is fabricated or bypassed.

## GH-94 EXACT-MAIN CLOSEOUT (2026-07-23)

Result: PASS for the bounded local producer scope. Final PR #97 passed all ten
protected contexts on exact head `4284a88`, had no unresolved review thread,
and merged normally without admin bypass as
`34ab5b7a62b17ef2c9cab672439b77dcf4a66d9c`; issue #94 closed. Exact-main
Prometheus CI `29989116631`, Security Audit `29989117912`, and Pages
`29989118948` passed. Because GitHub omitted the automatic main suites, the
merged CI recovery trigger and existing Security dispatch executed the complete
workflows on exact main, and the Pages build API queued the exact-main deploy.
No status or check was fabricated.

Public evidence: raw GitHub README and live Whitepaper, Roadmap, FAQ, and
`llms.txt` return the GH-94 `byte_pattern` and `review_required_v1` markers.
This closes only deterministic local derivation and mandatory-review
serialization. External artifact provenance, wildcard suitability,
maliciousness, privacy approval, disclosure/transport authorization, v2 proof
binding, actionable analysis, chain acceptance, and production operation remain
open.

## GH-100 SIDECAR SIGNAL READINESS FIX (2026-07-23)

Scope: `modules/guardian-p2p/src/service.rs` process-signal registration and
the existing Unix end-to-end process regression. Protocol frames, transport
authorization, persistence, verifier/analyzer/proof paths, wallets, signing,
chain behavior, KAS/PROM, slash ACL, commit-reveal, reputation, and
emergency-stop policy are out of scope.

Finding: HIGH, reproduced. `run_service()` boxed an async `shutdown_signal()`
future, but the future did not create Tokio signal receivers until first poll.
`run_guardian()` could emit `waiting-for-collector` first, allowing an immediate
SIGTERM to retain the operating-system default action. The existing
`sigterm_during_collector_wait_stops_cleanly` process regression failed in a
compiled-binary stress run at iteration 24.

Fix result: PASS. Signal-listener construction is synchronous and occurs before
`OperatorOutput::start()`. Unix creates SIGINT and SIGTERM receivers before
returning the boxed wait future. Registration errors map to
`ServiceError::Signal` before any operator record. The receivers are owned by
the boxed future for its full lifetime. The crate remains explicitly Unix-only
because AF_UNIX and peer credentials are mandatory.

Independent review: Claude Code 2.1.218 performed a bounded no-tool review and
found the Unix lifetime/error handling sound. Sol retained final integration
and release responsibility.

Evidence: patched compiled-binary stress passed 64/64 immediate post-readiness
SIGTERM iterations. The focused regression passes; the complete three-process
suite passed ten consecutive repetitions; all 53 Guardian P2P unit tests plus
all three process tests pass; and the complete Rust workspace passes with two
intentional live-network ignores. Rustfmt, warning-free crate/workspace
all-target Clippy, locked optimized Guardian build, package checks, Black,
Guardian Pylint 9.86/10, 181 Guardian tests with three intentional live-model
skips, and Cargo Audit with no vulnerabilities pass. One relay-process `busy`
result and one Python verifier-stub timeout occurred once each; focused reruns,
ten process-suite repetitions, and later complete suites passed, so no
unrelated behavior was changed.

Protected closeout: PR #101 passed every attached protected context on exact
head `ced783527a406fff769ae3a22995a9b612c64da2` and merged normally without
admin bypass as `83bdfe0e52e9308e28c8f0984a1219f203aa1f74`; issue #100
closed. Exact-main Prometheus CI `29994190542`, Security Audit `29994190564`,
and Pages `29994189428` passed.

## GH-103 LOCAL LINUX ELF API-IMPORT PRODUCER (2026-07-23)

Scope: one isolated Rust producer in `prometheus-threat-hint` derives one
`api_import` from exact caller-supplied Linux ELF bytes plus a checked index.
It is not imported by ThreatHint v1, P2P, proof, Guardian ingress/analyzer,
committee, IPFS, chain, wallet, signing, reputation, or reward paths.

Result: PASS for local deterministic extraction. The API accepts no path,
caller-supplied import string, platform, format, or generic observable value.
It derives `linux`/`elf` internally and always emits `review_required_v1`.
Exactly pinned `object 0.39.1` uses only `read_core`, `elf`, and `std`.
Artifacts above 16 MiB and dynamic-symbol tables above 4096 entries fail
before sorting. Empty, malformed, non-ELF, invalid-UTF-8/grammar, no-import,
and out-of-range inputs fail with fixed redacted errors. Dynamic symbols are
streamed, then exact names are byte-sorted and deduplicated before selection.

Cross-language evidence: one SHA-256-bound exact ELF64 fixture contains
unsorted and duplicate `mmap`, `close`, and `pthread_create` imports. Rust
produces all three checked canonical bundles; Python independently parses ELF
section headers, dynamic strings, and dynamic symbols before validating the
same `review_required_v1` wire bytes.

Independent review: Claude Code approved the bounded bytes-only direction but
suggested a filesystem return and Tokio timeout. Those recommendations were
rejected because this crate is synchronous and side-effect-free; the valid
mandatory-review and parser-bound concerns were retained. Terra reported no
blocking/high/medium or actionable low finding. Its residual concern that
`Object::imports()` would allocate the complete table was closed by replacing
that API with streaming `dynamic_symbols()` iteration and a 4096-symbol cap.

Evidence: five focused producer security tests, one Rust shared-vector test,
all 30 ThreatHint tests plus one compile-fail doctest, 19 focused Python
observable tests, 182 complete Guardian tests with three intentional
live-model skips, and the complete Rust workspace with two intentional
live-network ignores pass. Rustfmt, warning-free crate/workspace all-target
Clippy, Black, and Guardian Pylint 9.86/10 pass.

Protected closeout: PR #104 passed all nine attached protected CI/Security
contexts on exact head `0774358250c72f60a00ed6326a04fcb427fe6f26` and
merged by the repository-allowed squash method without admin bypass as
`42d9cd939c635474547d1bac7058f30451c926e7`; issue #103 closed. Exact-main
Prometheus CI `29999873100`, Security Audit `29999873126`, and Pages
`29999872424` passed. Raw README and live Whitepaper, Roadmap, FAQ, and
`llms.txt` markers were verified.

Non-claims: the index is a local selection and the scope label is parser
policy, not proof of external artifact provenance, host OS, maliciousness,
privacy approval, disclosure authorization, v2 relation binding, analysis,
publication, or production acceptance.

## GH-107 LOCAL OBSERVABLE APPROVAL VERIFIER (2026-07-23)

Scope: one isolated Rust/Python verifier authenticates one canonical,
short-lived BIP340 approval statement for one exact `review_required_v1`
Observable Bundle. It is not imported by ThreatHint v1, P2P, proof, Guardian
ingress/analyzer, committee, IPFS, chain, wallet, signing, reputation, or
reward paths.

Result: PASS for the focused local statement-authentication boundary. Both
implementations cap the canonical approval at 1024 bytes, reject duplicate,
unknown, reordered, noncanonical, malformed, oversized, expired, future,
cross-network, wrong-key, wrong-recipient, wrong-nonce, wrong-commitment, and
tampered-signature inputs with one fixed error. The verifier reparses the exact
bundle, requires `review_required_v1`, recomputes its commitment from the
trusted network/report nonce, requires separately trusted current time that
must never be attacker-controlled, enforces an inclusive maximum-one-hour
validity window, and verifies a domain-separated BIP340 digest. Rust and Python
also derive the same domain-separated approval ID.

Cross-language evidence: one public-only fixture binds exact bundle bytes,
report nonce, trusted x-only key, recipient-scope digest, times, approval
nonce, signing body/digest, signature, full wire, and approval ID. Rust and
Python independently recompute the commitment and both SHA-256 domains and
verify the same signature. No private key, signing API, raw transaction, or
wallet material is present.

Review: Sol found and fixed a Python field-order parity gap before closeout.
Claude Code then reviewed both production modules. Its high-severity concern
about an implicit Python rehash was disproved against pinned `coincurve
21.0.0`: `PublicKeyXOnly.verify` forwards the supplied message and length
directly to `secp256k1_schnorrsig_verify`. Its valid `u64` parity and explicit
replay non-claim recommendations were implemented. The pinned constructor and
verify paths raise the already redacted `ValueError`/`TypeError` classes for
malformed inputs.

Evidence: all 15 Rust unit tests, 23 Rust integration tests, and one
compile-fail doctest in `prometheus-threat-hint` pass. The 27 focused Python
observable/approval tests pass. Complete local evidence is 280 Rust workspace
passes with two intentional live-network ignores and 190 Guardian passes with
three intentional live-model skips. Rustfmt, warning-free workspace all-target
Clippy, locked Guardian/proof release builds, the verified 21/14/7-file package
set, Black, Guardian Pylint 9.78/10, Memory Integrity, six Autodidactic tests,
HTML/JSON-LD/public-status checks, workflow YAML, Actionlint 1.7.12, Cargo
Audit with no vulnerabilities and eight known allowed warnings, Python audit
with no vulnerabilities, staged Gitleaks 8.30.1 with no leak, and clean diff
checks pass.

Non-claims: verification authenticates one local statement only. It performs
no signing, durable replay prevention, transport, promotion, disclosure,
analysis, publication, proof acceptance, wallet, chain, reputation, KAS/PROM,
slash ACL, commit-reveal, or emergency-stop action. The signed nonce and
approval ID identify repeats but do not prevent replay. Durable one-time
consumption, trusted authority rotation, recipient-scope policy, owner-only
pairing, v2 proof binding, and actionable analysis remain separate gates.

Independent Terra follow-up found one high-severity Python subclass bypass and
one medium object-forgery integration risk. The verifier now requires the exact
`ObservableApprovalContext` type before calling its validator, and an
adversarial subclass with overridden validation/comparisons is rejected. The
Python result is explicitly data only: its object identity grants no authority,
and future consumers must invoke verification in the same trusted call path
rather than accept a caller-supplied instance. Focused and full checks must be
rerun after this review fix. The focused and complete Guardian suites passed
after the fix, and Terra's read-only re-review reports no remaining actionable
finding.

Protected review: PR #108 initially passed all ten CI/Security/CodeRabbit
contexts on exact head `7f23e380752599fda27b80d9cd88cdc93130f489`
(Prometheus CI `30004723271`, Security Audit `30004723262`). CodeRabbit then
correctly required every trust-boundary description to state that current time
is independently trusted and never attacker-controlled, and suggested reusing
one verification-only secp256k1 context. The documentation wording and a static
`OnceLock<Secp256k1<VerifyOnly>>` are implemented locally. Refreshed checks and
both review-thread resolutions remained at that point and are closed by the
exact-main evidence below.

A requested Claude Code re-review could not start because its configured
monthly usage limit was exhausted; it read no repository file. The independent
Terra fallback review approved the static verification context and found three
remaining wording gaps in the FAQ Markdown/HTML pair and the later Whitepaper
description. All three now explicitly require separately trusted current time
that must never be attacker-controlled. Terra's read-only re-review reports no
remaining actionable finding. Focused ThreatHint tests, complete workspace
tests, Rustfmt, warning-free workspace all-target Clippy, Memory/Autodidactic,
HTML/public-status, and clean-diff checks pass after the review fix.

## GH-107 PROTECTED MERGE AND EXACT-MAIN EVIDENCE (2026-07-23)

Review-fix commit `0ca2b0189f465386bee2ce713e39fc5e0c46f03f`
passed refreshed Prometheus CI `30006371006`, Security Audit `30006371003`,
all ten protected contexts, and CodeRabbit status. Both concrete review threads
were answered and resolved. PR #108 merged normally by the repository-allowed
squash method without admin bypass as exact main
`fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe`; issue #107 closed.

Exact-main Prometheus CI `30006654048`, Security Audit `30006654027`, and Pages
`30006653208` passed. Raw README and live Whitepaper, Roadmap, FAQ, and
`llms.txt` expose the verifier plus the separately trusted,
never-attacker-controlled clock and all non-claim boundaries. Result: PASS for
the merged local Observable Approval verification slice.

Issue #109 and branch `docs/GH-109-observable-approval-closeout` reconcile
public/status wording only. Completion estimates and external rollout blockers
remain unchanged. No secret, wallet, signing, transaction, chain, contract,
token-model, reputation, slash-ACL, commit-reveal, or emergency-stop boundary
changed.

GH-109 local documentation evidence passed Memory Integrity, six Autodidactic
tests, HTML/JSON-LD/public-status checks, a stale-candidate scan, and clean-diff
checks. Spark found two short merge-SHA references in Checkpoint/TODO; both use
the full exact SHA, and its read-only re-review reported no remaining
actionable finding. PR #110 merged normally without admin bypass as exact main
`f71740cd79e0ae788fa732f42e7f000276ea1741`; Prometheus CI `30008005279`,
Security Audit `30008005305`, and Pages `30008004574` passed, and live public
markers were verified.
## GH-111 LOCAL DURABLE OBSERVABLE APPROVAL CONSUMPTION (2026-07-23)

Issue #111 and branch `feat/GH-111-local-observable-approval-consumption` added
the smallest local durable consumer after the merged GH-107 verifier. The
Guardian service loads one exact network, x-only approver public key, and opaque
recipient-scope digest from an owner-only exact-schema TOML policy. The public
consume API accepts only canonical approval/bundle bytes plus a trusted
in-process report nonce and current time; it constructs the verification
context internally and invokes GH-107 verification in the same call path. It
does not accept a caller-supplied verified result, key, scope, or network.

After verification, a separate owner-only SQLite ledger atomically records the
32-byte approval ID and enforces uniqueness of the authority-bound
`(approver_xonly_public_key, approval_nonce)` tuple. `BEGIN IMMEDIATE`,
`synchronous = FULL`, a STRICT schema, and a persistent clock high-water close
restart, concurrent duplicate, lock/retry, and rollback replay paths. Existing
unsafe parent/file modes, symlinks, relative paths, unknown policy fields,
malformed values, corrupt databases, and unsupported schema versions fail with
one redacted public message. An injected transaction integrity failure proves
that neither consumption nor the high-water advances partially.

Local evidence currently includes 24 focused consumption tests, 32 combined
approval tests, 214 complete Guardian passes with three intentional live-model
skips, Pylint 10.00/10 for changed production/tests, and complete Guardian
Pylint 9.78/10. Spark found
one possible parallel-test busy flake and missing relative policy-path coverage;
both were fixed. Independent Terra security review found no finding and
recommended constructor-lock, transaction-abort, and corrupt/unknown-ledger
tests; all were added and pass. Claude Code was requested as a helper but its
monthly usage limit remained exhausted and it read no GH-111 file.

Final Sol review found that a pre-existing version-zero SQLite file with the
wrong table shape needed explicit startup rejection. The ledger now validates
the exact STRICT column and unique-index shape after initialization, maps only
real `SQLITE_BUSY`/`SQLITE_LOCKED` codes to retryable failure, and treats other
operational errors as closed corruption. A dedicated regression passes.

Complete local gates pass: 280 Rust workspace tests with two intentional
live-network ignores, Rustfmt, warning-free workspace all-target Clippy, locked
optimized Guardian/proof builds, strict 21-file ThreatHint packaging, Black,
complete Guardian Pylint 9.78/10, Memory Integrity, six Autodidactic tests,
HTML/JSON-LD/public-status checks, workflow YAML parsing, Actionlint 1.7.12,
Cargo Audit with no vulnerabilities and eight allowed warnings, Python Audit
with no known vulnerabilities, staged Gitleaks 8.30.1, and clean staged diff.
PR head `ec4a5d264abb47d08b263bdda1eddf33d42c72bd` passed all ten
attached CI/Security contexts in Prometheus CI `30011641764` and Security Audit
`30011641778`; there were no review threads. CodeRabbit's required status passed
but its content review was rate-limited. PR #112 merged by the
repository-allowed squash method without admin bypass as exact main
`60166bd6d8d3c7d8e88727c2f6d507b206a308ad`; issue #111 closed.
Exact-main Prometheus CI `30011976919`, Security Audit `30011976853`, and Pages
`30011975363` pass. Raw README and live Whitepaper/Roadmap/FAQ/`llms.txt`
markers were verified. GH-111 is accepted within its explicit local-only
boundary.

The receipt is data only and grants no downstream authority. This slice does
not establish real-world approver-key ownership or rotation, recipient-scope
semantics, privacy approval, verified hint/bundle/approval pairing, transport,
promotion, disclosure, analyzer invocation, outbox delivery, proof, signing,
wallet, chain, reputation, KAS/PROM, slash ACL, commit-reveal, or emergency-stop
behavior. A future external action requires a separate crash-safe claim/outbox
design and review. Foreign untracked `Prometheus-1.png` remains untouched.

## GH-114 LOCAL CANONICAL THREATHINT V2 STATEMENT (2026-07-24)

Scope: one isolated Rust parser and one isolated Python parser for a canonical
ThreatHint schema-2 statement. The type is not imported by ThreatHint v1,
Guardian ingress, proof verification, approval consumption, analyzer, outbox,
P2P, wallet, signing, transaction, chain, reputation, or reward paths.

Result: PASS for the focused structural-binding boundary. Both implementations
cap the exact wire at 1024 bytes and require ordered schema version, distinct
artifact hash and observable commitment, bounded confidence, closed structural
disclosure class, report nonce, positive u64 observed time, and a network equal
to separately trusted local context. Unknown, duplicate, reordered,
noncanonical, malformed, wrong-type, cross-network, oversized, escaped, and
trailing inputs fail with one redacted error.

Cross-language evidence: one shared exact-byte corpus contains 8 valid and 20
invalid cases. Rust and Python independently reproduce the same canonical
bytes and
`SHA256("prometheus-threat-hint-statement-v2\0" || u32be(length) || wire)`
digest. Mutating any bound field changes that digest. Python rejects direct and
subclass construction, binds each parsed object identity to its original
canonical bytes, and rejects both valid-shape mutation and manually forged
exact-class instances before serialization or digesting. This is object
integrity hardening, not authority against arbitrary code in the same
interpreter.

Complete local evidence: 290 Rust workspace tests with two intentional
live-network ignores, 223 Guardian tests with three intentional live-model
skips, and two compile-fail doctests pass. Rustfmt, warning-free workspace
all-target Clippy, locked optimized Guardian/proof builds, verified
24/14/7-file packages, Black, changed-file Pylint 10.00/10, complete Guardian
Pylint 9.80/10, Memory Integrity, six Autodidactic tests,
HTML/SEO/JSON-LD/public-status checks, workflow YAML, Actionlint 1.7.12, Cargo
Audit with no vulnerabilities and eight allowed warnings, Python Audit with no
known vulnerabilities, staged Gitleaks 8.30.1 with no leak, and clean staged
diff pass. Terra architecture and Spark parity/security review found no initial
issue. Final Terra review found one medium Python valid-shape mutation/
forged-object gap; the identity-bound parse snapshot and two adversarial
regressions closed it, and targeted re-review reports no remaining blocking,
high, or medium issue. Claude Code's terminal probe passed, but the bounded
read-only review exited before repository access because its configured USD
budget was exhausted.

Protected PR #115 first-round Prometheus CI `30017135102` and Security Audit
`30017136619` passed every technical job. CodeRabbit found four minor
consistency points: distinguish canonical statement `network_id` from
separately trusted parser context in digest wording, state positive-u64
`observed_at` precisely, make the Python regex itself enforce the existing
two-character network minimum, and synchronize public HTML digest wording.
All four are fixed. Nine focused and 223 complete Guardian tests with three
intentional skips, Black, source Pylint 10.00/10, HTML/SEO/JSON-LD/public
status, Memory Integrity, six Autodidactic tests, and clean diff checks pass
after the fixes. Final head `b225a7f4058eb657fd6b29ef1086d046c218263b`
passed all ten contexts with zero unresolved threads. PR #115 merged normally
without admin bypass as exact product main
`70bb8ab0ba4cbb0e32a107d0d426736fa5020ba4`; issue #114 closed. Exact-main
Prometheus CI `30019079713`, Security Audit `30019079960`, and Pages
`30019075639` pass, and raw/live public markers were verified.

Non-claims: the asserted artifact hash and commitment are not proven to derive
from real bytes. The statement digest is not a signature or proof. Structural
`disclosure_class` does not authorize disclosure. No relation, proof
acceptance, signer, approval pairing, replay authority, persistence, transport,
analysis, publication, wallet, or chain action is added. The focused local
structural-binding slice is accepted; the later relation, proof, pairing,
privacy/promotion, transport, actionable-analysis, and external rollout gates
remain separate.

## LOCAL THREATHINT V2 PROOF-BINDING REVIEW (2026-07-26)

Ticket `GIO-PROM-20260726-005` combines the separately reviewed canonical v2
proof-envelope and RelationManifest-v2 candidates through one local Rust/Python
data binding. A separately trusted network and nonzero lowercase manifest
SHA-256 are validated first. The exact raw manifest bytes are hashed before
parsing, both wires are then reparsed canonically, and protocol, relation,
network, statement-domain, public-input encoding, and public-input count must
close. The manifest-domain statement digest is recomputed as
`SHA256(domain || u32be(statement_wire_len) || statement_wire)` and exposed
only as two claimed 16-byte big-endian halves.

Shared evidence contains 5 valid and 28 adversarial invalid binding cases.
Sol found that the first Python snapshot did not bind exact envelope bytes:
another valid envelope with the same statement/digest but different opaque
proof bytes could replace it without invalidating derived reads. The snapshot
now binds both exact wires and the trusted network, nested errors map to one
redacted binding error, and a same-statement/different-proof regression passes.
Final Kimi read-only review independently recomputed every valid anchor,
digest, and half and found no actionable issue.

Complete local evidence passes 317 regular Rust workspace tests plus 5
doctests with 2 intentional live-network ignores, 251 Guardian tests with 3
intentional live-model skips, Rustfmt, warning-free workspace all-target
Clippy, locked optimized Guardian-P2P and ThreatProof builds, verified
27/14/13-file packages, Black, Guardian Pylint 9.80/10, Cargo Audit with no
known vulnerabilities and 8 allowed warnings, Python Audit with no known
vulnerabilities, Memory Integrity, 6 Autodidactic tests, and clean diff checks.

Non-claims: the opaque proof is not interpreted or verified. Relation source,
proving key, and verifying key hashes are assertions only; no artifact is
loaded or approved. No ceremony, signer, transport, analyzer, promotion,
wallet, transaction, chain, reputation, KAS/PROM, slash, commit-reveal, or
emergency-stop behavior changes. The candidate is not committed, merged,
published, deployed, or rollout-ready.

## LOCAL THREATHINT V2 PRIVACY/PROOF PREFLIGHT REVIEW (2026-07-26)

Ticket `GIO-PROM-20260726-006` adds one Python-only, non-consuming preflight
above the local v2 envelope/manifest binding and canonical Observable Approval
verifier. An owner-only exact-schema read-only policy pins one network, BIP340
approver key, opaque recipient-scope digest, and nonzero raw-manifest SHA-256.
The public call accepts no independent statement or trust anchor: it derives
the statement only from the bound envelope, requires `review_required_v1`,
matches the trusted report nonce, recomputes the exact bundle commitment, and
verifies the short-lived approval against the same policy context.

The service opens, creates, migrates, and writes no SQLite file and consumes no
approval. Its receipt contains only statement/approval/commitment identities
plus manifest/envelope hashes and grants no proof, privacy, disclosure,
transport, analyzer, promotion, wallet, chain, or rollout authority. Approved
v2 Groth16 verification and a final atomic durable consumption remain later
acceptance gates.

Sol's final evidence passes 31 focused preflight cases, 95 combined v2/
observable cases, 282 complete Guardian tests with three intentional
live-model skips, changed-file Pylint 10.00/10, full Guardian Pylint 9.81/10,
Black, Rustfmt, warning-free all-target workspace Clippy, 317 regular Rust
tests, five doctests, and two intentional live-network ignores. Kimi's final
read-only review found no P0/P1/P2. Sol closed its P3 deeply nested JSON
`RecursionError` contract gap with explicit redaction and three regressions.
Residual owner-local TOCTOU and pre-cap manifest hashing are documented
hardening limits, not rollout blockers.

No commit, push, PR, Pages deployment, signing, transaction, broadcast,
deployment, secret access, or foreign-file change occurred.

Final ticket closeout: exact Pages existence/SEO/infrastructure/stale-status
gates, five HTML parses, four JSON-LD parses, workflow YAML parsing,
Actionlint 1.7.12, Memory Integrity, six Autodidactic tests, Cargo Audit,
Python Audit, and a redacted Gitleaks 8.30.1 scan of the complete staged
candidate pass. The candidate remains local and uncommitted at exact HEAD
`b556fbbae428e7f6eef07c6d502b32e13e759813`. Ticket
`GIO-PROM-20260726-006` is complete only within that local review-ready scope;
protected CI, publication, deployment, and actual proof acceptance are not
claimed.

## LOCAL THREATHINT V2 GROTH16 VERIFIER REVIEW (2026-07-26)

Ticket `GIO-PROM-20260726-007` adds one Rust-only trusted verification boundary
above the local v2 envelope/manifest binding. `TrustedGroth16V2Verifier::load`
validates one separately trusted lowercase nonzero manifest SHA-256 and
network, owner-loads the exact canonical manifest once, then owner-loads fixed
siblings `relation-source.bin` and `verifying-key.bin`. Exact file sizes and
SHA-256 anchors must match the manifest. The verifying key must be canonical
compressed BN254 with exactly two public inputs plus the constant entry.

`verify_wire` rereads no file. It reuses retained manifest bytes and trusted
anchors, obtains proof bytes and both 16-byte big-endian field inputs only
through `ThreatHintV2ProofBinding`, requires canonical compressed proof bytes,
and executes Arkworks Groth16 verification. The silent `verify-v2` CLI keeps
the existing exits: 0 valid, 1 invalid input/proof, 2 syntax, and 3 unavailable
trusted configuration/artifacts. Runtime never resolves, requires, opens, or
generates a proving-key file.

Kimi supplied the architecture review and initial four-file implementation.
Sol reviewed every write and added hash-matched invalid-key, malformed
canonical-length proof, unsafe parent-directory, uppercase-anchor, and zero-
anchor regressions. Kimi's final read-only review reports PASS with no
P0/P1/P2/P3.

Evidence: all 16 focused verifier-v2 cases pass; all 44 ThreatProof all-target
tests and two package doctests pass; warning-free package/workspace all-target
Clippy and Rustfmt pass; the optimized verifier builds; and its Cargo package
contains the expected 15 files. The complete workspace clean rerun passes 333
regular tests with two intentional live-network ignores plus five doctests.
The first workspace attempt hit known M-002 commitment microbenchmark jitter
at 1.566006 ms; its isolated rerun passed at 43.122 microseconds and the full
rerun passed. Guardian remains 282 passed with three intentional live-model
skips.

All generated setup, relation, key, and proof values are deterministic
non-production test fixtures. No production relation or vector, proving or
verifying key, ceremony evidence, artifact approval, atomic approval
consumption, privacy authority, transport, analyzer, promotion, wallet,
transaction, chain action, deployment, or rollout evidence is added. The
candidate remains local and uncommitted.

## LOCAL THREATHINT V2 VERIFIED PREFLIGHT COMPOSITION REVIEW (2026-07-27)

Ticket `GIO-PROM-20260727-008` adds one Python composition of the existing
non-consuming approval/privacy preflight with the real Rust `verify-v2`
boundary. The existing owner-only policy remains the sole network and
raw-manifest-SHA-256 authority. A separate owner-only exact TOML config pins
only one absolute verifier executable and exact SHA-256, one absolute manifest
path, and a bounded timeout.

Each call owner-loads and hashes the exact manifest, runs the Python preflight
first, checks the exact envelope digest returned by that boundary, then
revalidates the executable and sends the same exact envelope bytes to a
shell-free child. The child has a closed absolute argv, `LANG=C`/`LC_ALL=C`,
`/` working directory, discarded stdout/stderr, closed descriptors, its own
process group, timeout, kill/reap handling, and fail-closed exit mapping. A
nonblocking per-service lock rejects concurrent verifier calls. Success
returns only a frozen, non-constructible, non-serializable data receipt.

Kimi K3 performed a secret-free architecture review, contributed the two
read-only policy properties and their regression, and independently reviewed
the integrated implementation. Final verdict is PASS with no P0/P1/P2. Sol
added the composition, full adversarial process/config/path/hash coverage,
non-POSIX rejection, `communicate` `ValueError` handling, and more robust
concurrency timing.

Focused evidence passes 59 tests, Black, and Pylint 10.00/10. Complete
Guardian evidence passes 310 tests with three intentional live-model skips and
full Pylint remains 9.81/10 with only pre-existing warnings. Rustfmt and
warning-free workspace all-target Clippy pass. The complete Rust rerun passes
333 regular tests with two intentional live-network ignores plus five
doctests. A first Guardian pass had one isolated pre-existing v1 verifier stub
timeout; that exact test and the complete rerun passed. Rust initially hit the
known M-002 timing benchmark while unrelated system load was very high; the
exact isolated benchmark later passed at 39.646 microseconds and the complete
rerun passed without a code or threshold change.

Residual risk is bounded but explicit: Python cannot portably `execve` the
already-hashed descriptor, leaving an owner-local hash-to-exec race. The
executable and all ancestors are therefore constrained to current-user/root
ownership without group/world write permission and are revalidated per call.
The older standalone data-only `ThreatHintV2PreflightReceipt` remains
pickleable; no consumer treats it as authority, and serialization hardening is
tracked as P3.

This ticket opens or changes no SQLite file, consumes no approval, approves no
production relation/key/ceremony artifact, and grants no privacy, disclosure,
transport, analyzer, promotion, wallet, chain, deployment, or rollout
authority. The local candidate is not a production acceptance path.

## AUDIT UPDATE 2026-07-27: Local ThreatHint v2 Atomic Acceptance

Ticket `GIO-PROM-20260727-009` closes the local mechanical
verified-preflight-plus-consumption order without approving production proof
artifacts. One raw-input-only service proves exact network/approver/scope
policy identity before ledger creation, runs ticket-008 proof/privacy
verification first, then re-verifies approval ID and observable commitment
before the existing atomic durable consume.

Kimi K3 final read-only review reports static PASS with no P0/P1/P2. Its one
P3 finding, serialization of the older data-only preflight receipt, is fixed
with direct, replace, and pickle regressions. Sol's dependency-complete
evidence passes 158 focused tests, 349 Guardian tests with three intentional
live-model skips, Black, focused Pylint 10.00/10, full Pylint 9.82/10,
Rustfmt, warning-free workspace all-target Clippy, and the complete Rust
workspace with two intentional live-network ignores plus five doctests.

The known M-002 debug microbenchmark failed at 2.466 ms and once in isolation
at 2.274 ms, then passed exactly at 42.982 microseconds and in the complete
rerun. No product code or threshold changed.

Residual risk remains owner-bounded: Python cannot portably execute the
already-hashed verifier descriptor, so the documented hash-to-exec race
remains. Production relation source, proving/verifying keys, ceremony
evidence, and independent cryptographic review are still P0. Privacy
promotion, pairing, transport, actionable analysis, crash-safe external
effects, chain actions, and rollout evidence remain out of scope.

## AUDIT UPDATE 2026-07-27: Local ThreatHint v2 Owner-Policy Promotion

Ticket `GIO-PROM-20260727-010` adds one raw-input-only promotion boundary above
ticket-009 atomic acceptance. An exact owner-only policy restricts
review-required candidates by platform, format, observable kinds, and count
before the same original envelope, bundle, and approval bytes may enter proof
verification or durable consumption. Rejection leaves verifier invocation,
approval count, and ledger high-water untouched.

Kimi K3's first final review found one P2 trusted-file race relative to the
existing repository pattern. Sol replaced the path read with `O_NOFOLLOW`,
descriptor device/inode/mode/size checks, a bounded read, and guaranteed close,
then added symlink and inode swap regressions. Kimi's re-review reports PASS
with no P0/P1/P2. Its remaining P3 embedded-NUL classification and all earlier
coverage observations are fixed and regression-tested.

Dependency-complete evidence passes 57 focused promotion tests, 207 combined
ticket 005-010 Guardian tests, and 406 complete Guardian tests with three
intentional live-model skips. Black leaves 22 modules unchanged; focused
Pylint is 10.00/10 and full Pylint 9.82/10. Rustfmt, warning-free workspace
all-target Clippy, release builds, verified/package-set Cargo packages, and the
complete Rust workspace pass with 333 regular tests, two intentional
live-network ignores, and five doctests.

M-002 failed at 1.751 ms and one isolated retry at 1.261 ms, then passed at
43.083 microseconds and in the complete workspace rerun. No product code or
threshold changed. Cargo/Python audits, Memory/Autodidactic, Pages/HTML/JSON-LD,
workflow YAML/Actionlint, clean diff, and the redacted complete-candidate
Gitleaks scan pass.

This ticket closes local mechanical pairing and owner-policy restriction only.
It does not approve production relation/key/ceremony artifacts, establish
authority/key ownership or semantic per-kind privacy safety, transport or
analyze observables, publish data, perform crash-safe external effects, sign,
transact, touch chain state, or prove rollout readiness.

## AUDIT UPDATE 2026-07-27: Local Outbox Retention Governance

Ticket `GIO-PROM-20260727-011` adds a pure owner-only policy loader for a
possible future local recoverable analysis queue. The exact schema binds
network, approver key, and recipient scope to separately expected identity,
fixes purpose and canonical payload form, default-denies durable observable
kinds, and caps pending records and retention. Required POSIX ownership,
permissions, `O_NOFOLLOW`, descriptor identity/mode/size checks, and a
4096-byte cap match the established trusted-file boundary.

The privacy model remains explicit and conservative: file hashes can be
matched against corpora, API imports fingerprint software capabilities, and
byte patterns can preserve proprietary content. This declaration is not
semantic privacy approval. It opens no SQLite file and creates no ledger row,
outbox record, worker, transport, disclosure, or external effect.

Kimi K3 implementation plus two independent review passes end with no
P0/P1/P2. Sol added regressions for deep recursion redaction, expected-identity
validation before file access, setgid/sticky modes, and mandatory no-follow
failure without fallback. Evidence passes 114 focused tests, 520 complete
Guardian tests with three intentional skips, Black, focused Pylint 10.00/10,
full Pylint 9.81/10, Rustfmt, warning-free workspace Clippy, and the complete
Rust workspace with 333 regular tests, two intentional live-network ignores,
and five doctests. Release builds/packages, Cargo/Python audits,
Memory/Autodidactic, Pages/HTML/JSON-LD, workflow YAML/Actionlint, diff, and
candidate-secret gates pass.

A real recoverable outbox remains blocked until enqueue can share the same
`BEGIN IMMEDIATE` transaction as approval consumption and ledger high-water.
A digest-only journal is not recoverable work. Authority/key ownership,
recipient-scope meaning, enforceable semantic per-kind privacy decisions,
production relation/key/ceremony approval, transport, actionable analysis,
chain actions, deployment, and rollout evidence remain outside this ticket.

## AUDIT UPDATE 2026-07-27: Enforceable ThreatHint v2 Governance

Ticket `GIO-PROM-20260727-012` composes promotion, governance, retention,
verified precheck, and durable approval consumption into one enforceable
owner-local boundary. The exact governance policy binds network, approver key,
recipient scope, authority epoch/window, same-Guardian local-analysis
semantics, denied external disclosure, and one deny-or-risk-specific decision
for each closed observable kind.

Promotion, governance, and retention kind sets must be exactly equal before
ledger access. Schema v2 preserves all existing consumption and high-water
state, rejects hidden migration authority state, and starts unpinned. The first
valid governed use pins all three exact raw policy digests plus authority
identity/window; a higher epoch advances only in the same `BEGIN IMMEDIATE`
transaction as high-water and approval consumption. Same-identity windows must
not overlap. Lower epochs, same-epoch equivocation, replay, lock contention,
integer overflow, and failed inserts are fail-closed.

Kimi K3 architecture review, implementation support, initial integration
review, and follow-up review
`session_074cbd8e-4b8a-4751-a16d-a215dd96a005` report no P0/P1/P2. Sol fixed
all concrete P3 findings and added retention-only equivocation, v0/v1 hidden
authority state, governed lock, extended SQLite-code, overflow rollback, and
same-identity epoch regressions.

Final evidence:

- governed integration: `18 passed`;
- complete Guardian: `686 passed, 3 skipped`;
- Black: 24 product modules unchanged;
- focused changed-product Pylint: `10.00/10`;
- exact CI Pylint: `9.81/10`;
- Rustfmt and warning-free workspace Clippy: pass;
- Rust workspace: 333 regular tests, two intentional live-network ignores,
  and five doctests pass after one M-002 host-jitter failure at 3.068 ms,
  isolated pass at 44.02 microseconds, and complete clean rerun;
- workspace release build: pass in 21m57s;
- verified threat-hint package and Guardian package set: pass with
  `--allow-dirty`, required only because this reviewed candidate is
  intentionally uncommitted;
- `cargo audit`: no denied vulnerability, eight existing allowed
  unmaintained/unsound/yanked warnings;
- `pip-audit`: no known vulnerability;
- Memory integrity, Autodidactic tests/status, Pages/SEO/JSON-LD/stale-status,
  Actionlint, `git diff --check`, and redacted Gitleaks 8.30.1 directory scan
  of 53.92 MB: pass with no leak.

The protocol uint64 authority-time domain exceeds SQLite's signed 64-bit
integer range. Values above `2^63-1` are documented to fail closed with
rollback and a redacted unavailable result; current operational windows are
far below that boundary.

Ticket 012 creates no outbox or claim, invokes no analyzer or worker,
transports or publishes nothing, and performs no wallet, signing, transaction,
chain, deployment, commit, push, PR, or external GitHub action. Production
authority/key/recipient attestation and production relation/key/ceremony
approval remain external governance gates. The next repository-owned task is
an atomic recoverable local outbox/claim sharing this transaction.

## 2026-07-28 - Ticket 013 governed recoverable outbox audit

**Result:** PASS for the bounded local candidate. No actionable P0/P1/P2 was
found. Ticket 013 migrates only governed ledgers to schema v3 and preserves
legacy v1 plus all v0/v1/v2 consumption, high-water, and authority state.
Capacity and full canonical Bundle enqueue share the exact existing
`BEGIN IMMEDIATE` transaction; failure rolls every prospective write back and
does not consume the approval.

Claim is owner-local, oldest-first, single-winner, and restart-recoverable. A
fresh internal 32-byte token binds each lease, lease expiry cannot exceed
retention, expired leases are reclaimable, expired-retention rows purge before
selection, and only exact approval-ID/token acknowledgement terminally deletes
a row. Errors, including randomness failure, stay fixed and redacted.

Independent Kimi review
`session_3a07dfa5-4464-408c-90aa-afa342f4e15c` reports no actionable
P0/P1/P2. Two informational P3 observations remain accepted: trusted internal
Python code can call the lower governed-construction layer with durable outbox
enabled instead of entering through promotion, although no such in-tree path
exists; and an expired lease holder may acknowledge until a new claim rotates
the token, preserving the selected at-least-once semantics. Neither creates an
external authority or untrusted input path.

Final evidence:

- focused outbox/governance/acceptance/promotion matrix: `282 passed`;
- complete Guardian: `716 passed, 3 skipped`;
- changed-file Black: clean; full-tree Black finds only three pre-existing
  unrelated formatting debts in analyzer/model tests;
- exact CI Pylint: `9.84/10`; compileall: pass;
- Rustfmt and warning-free workspace Clippy: pass;
- Rust workspace: 333 regular tests, two intentional ignores, and five
  doctests pass. One M-002 host-jitter failure at 1.58371 ms passed isolated at
  740.551 microseconds and in the complete rerun without threshold change;
- cached locked workspace release build and verified threat-hint plus
  three-package archive set: pass;
- Cargo audit: zero denied vulnerabilities and eight existing allowed
  maintenance/yank warnings; Python audit: no known vulnerability;
- Memory integrity, six Autodidactic tests/status, exact Pages
  existence/SEO/JSON-LD/stale-status checks, HTML parses, internal Markdown
  links, workflow YAML parsing, Actionlint 1.7.12, `git diff --check`, and a
  redacted Gitleaks 8.30.1 scan of the 7.70 MB tracked/untracked candidate:
  pass with no leak.

No worker or analyzer was executed. No transport, disclosure, wallet, secret,
signature, transaction, broadcast, chain, deployment, commit, push, PR,
publish, Pages update, or external GitHub write occurred. Production
relation/key/ceremony approval and independent cryptographic review, a bounded
worker/actionable-analysis integration, v2 transport, and rollout evidence
remain open.

## 2026-07-29 - Ticket 014 durable non-actionable completion audit

**Result:** PASS for the bounded local repository candidate. Independent Kimi
review `session_754656a0-ce35-4dfb-99d1-173463dd8ffc` found no P0, P1, or P2
issue and changed no file. Sol reviewed the complete diff and retained two
non-blocking P3 decisions:

- `outbox()` remains available to a governed service whose enqueue path is
  disabled because a separately constructed worker/claim service must consume
  the same governed ledger without receiving enqueue authority;
- canonical result-validation failures remain fixed, redacted
  `ObservableApprovalOutboxError` values at the durable completion boundary
  instead of being reclassified as worker errors.

Governed schema v4 stores canonical statement wire/digest and report nonce,
revalidates statement, bundle, network, nonce, and commitment at enqueue,
claim, and completion, and derives a lease/retention-bound input identity.
Only an exact unexpired lease can atomically insert one canonical explicitly
non-actionable result and delete its outbox row. Result metadata and inherited
retention are digest-bound; exact post-commit retries are idempotent. Empty v3
queues migrate, while nonempty v3 queues roll back unchanged because their
missing statement and nonce cannot be reconstructed safely.

Final evidence:

- focused outbox/worker/governance matrix: `72 passed`;
- complete Guardian: `740 passed, 3 skipped`;
- exact CI Black: 25 files unchanged; exact CI Pylint: `9.83/10`;
  Ticket product and test lint: `10.00/10`; scoped isort and py_compile pass;
- Rustfmt and warning-free workspace Clippy pass;
- Rust workspace: 333 regular tests, two intentional ignores, and five
  doctests pass. One M-002 host-jitter benchmark failure at 2.211647 ms passed
  isolated at 713.161 microseconds and in the complete rerun;
- locked workspace release build passes;
- Cargo audit reports no denied vulnerability and eight existing allowed
  maintenance/yank warnings; Python audit reports no known vulnerability;
- Memory integrity, six Autodidactic tests, exact Pages existence/SEO/
  infrastructure/stale-status gates, five HTML parses, `git diff --check`, and
  a redacted repository secret-pattern check pass. Its sole initial match was
  an existing dummy `wallet_private_key` field in a fail-closed Rust negative
  test, not secret material.

The shipped worker uses only the deterministic non-actionable analyzer.
No existing Analyzer, LLM, YARA/rule body, confidence, `should_submit`,
transport, disclosure, wallet, signature, transaction, broadcast, chain,
reward, deployment, commit, push, PR, publish, Pages deployment, or external
write occurred. Real semantic analysis/actionable rules require a separate
explicit high-risk ticket and independent privacy/security review. Production
relation source, proving/verifying keys, ceremony evidence, and independent
cryptographic evidence remain rollout blockers.

## 2026-07-29 - GH-117 protected integration audit

**Result:** PASS for repository integration and exact-main verification; no
production-deployment approval is implied.

The cumulative ThreatHint v2 work was published through issue #117 and PR
#118, never by direct `main` push. PR-head CI `30423242793` and Security
`30423242744` passed every protected check after the Linux sticky-directory
portability fix. Squash commit
`cb3d076d0e698361ce410e993de3edb869c0770e` then passed exact-main CI
`30423663562`, Security `30423663566`, and Pages `30423663016`.

CodeRabbit was still pending without findings and was not part of the required
branch-check set. Required approving-review count was zero. Independent Kimi
security review `session_971020af-c8d2-49e5-adea-4df6af9922b9` reported no
P0/P1/P2. A local/GitHub clock offset invalidated an earlier bot-age estimate;
the merge decision instead rests on the actual protection rules and green
required checks.

No production relation, proving/verifying key, ceremony, real semantic or
actionable analyzer, v2 transport, wallet, signature, transaction, chain,
server, secret, or production deployment was approved or exercised.

## 2026-07-31 - GH-9 exact-main H-001 readiness refresh

**Result:** PASS for a repository-only, non-promotable signing handoff refresh;
no chain execution approval is implied.

Exact main `143a8a0e0e07931d6b91823e939d5ada8a4e042c` reproduced the
accepted `205e1ca` seven-artifact archive, closed one-request
`testnet-10-validator-staking-h001` set, public funding specification, and
schema-v2 signing request byte-for-byte. Archive SHA-256 remains
`4989f0768f2d2fc749fdd3aea227c1be6e55f5cbf35ac9c83e891b6abdf3977d`;
request SHA-256 remains
`c0cad33f23acfee4114092e0211dd642cb97c44891cc8f8826f4656f406f42fa`;
signing-request SHA-256 remains
`6b8e65065ca5ae2ca561ddd3fcb9659c384496fd31db32c137fcc9d811fa5323`;
and the BIP340 sighash remains
`174ccbe80d1d37e62d2bbabfbfba48245372df2bcf9e6724ac79ebc16b4e0bcd`.

The current release operator built successfully. Live read-only preflight
reconfirmed the public funding output unspent/non-coinbase through a synced,
UTXO-indexed `rusty-kaspa 2.0.1` node at virtual DAA `531038718`, above
Toccata activation. Two prepare runs were byte-identical to each other and
the prior handoff. Owner-only 0700/0600 modes and a full-directory Gitleaks
8.30.1 scan over 1.28 MB passed with zero findings.

Independent Terra review initially found one P2: the refreshed directory
lacked a standalone exact-main provenance record. Sol added and verified the
public, versioned
`docs/evidence/gh-9-h001-readiness-refresh-2026-07-31.json`; targeted review
closed the evidence-content finding. A final publication review then required
that record to be locatable from the repository, which the versioned file and
README link now satisfy. Kimi and Claude review attempts were unavailable
because their configured external usage budgets were exhausted.

Local verification passed Rustfmt, the H-001 profile regression, 49 focused
deployer tests, 346 workspace tests with two intentional live-network ignores
and five compile-fail doctests, warning-free workspace Clippy, Guardian
`742 passed, 3 skipped`, Memory Integrity, and public-handoff leak/mode/parity
checks.

No wallet, private key, seed, mnemonic, password, signature, raw transaction,
signing, broadcast, deployment, or chain mutation occurred. Remaining gates
are an explicitly approved external BIP340 response, complete canonical
import and transaction verification, separately approved one-shot broadcast,
confirmation, one public `operator_record` receipt, and independent public
chain evidence. Canary evidence cannot promote full or metrics readiness.

## 2026-08-01 - M-002 local closure evidence (GH-131)

The commitment microbenchmark now warms the builder, measures 65 varied and
optimizer-resistant invocations, and evaluates median steady-state latency.
This rejects a consistently slow implementation while tolerating minority
scheduler stalls. Debug retains a 2 ms smoke budget; the explicit optimized CI
invocation retains the strict 1 ms requirement.

Final local evidence: 64/64 direct debug test-binary repetitions pass (final
median 8.793 us); 32/32 direct release repetitions pass (final median 368 ns);
the complete workspace passes 351 tests with two intentional live-network
ignores and no failures. Rustfmt, locked all-target Clippy, Memory Integrity,
six Autodidactic tests, YAML, Actionlint 1.7.12, diff, and redacted Gitleaks
checks pass.

Kimi's secret-free read-only review attempt was blocked by its provider quota.
Terra reported two P2 and one P3: best-of sampling false negatives, aggregate
CI timeout mismatch, and inconsistent/stale status references. All three were
remediated before the final test rerun. Protected PR CI and exact-main evidence
remain before M-002 is finally closed.

Cargo Audit reports zero vulnerabilities and nine allowed warnings. The new
transitive `event-listener 5.4.1` `RUSTSEC-2026-0221` warning is fixed upstream
in 5.4.2 and tracked separately by GH-132; no dependency update is included in
this performance-only patch.

## 2026-08-01 - GH-138 deterministic confidence evaluation audit

**Result:** MERGED / EXACT-MAIN PASS.

- A standalone stdlib-only evaluator imports no Analyzer, LLM, YARA,
  transport, v2, wallet, deployment, or chain component.
- Canonical ASCII JSONL rejects duplicate keys, non-standard numbers,
  whitespace/order drift, unknown/missing/reordered cases, invalid confidence
  types/ranges, class imbalance, weakened policy, and hash mismatches.
- One co-versioned manifest internally consistency-checks the 24-case synthetic
  corpus, exact predictions, fixed policy, and byte-exact expected report. The
  report additionally commits the three evaluation inputs under a
  domain-separated digest. Neither mechanism is signed or externally anchored.
- The unchanged 8500-bps decision boundary produces TP 11, FP 1, TN 11, FN 1.
  Gate comparisons use integer cross-products and exact sums rather than
  rounded display metrics. Precision and recall are 9167 bps, Brier score is
  36100 ppm, and ten-bin ECE is 750 bps.
- The report is explicitly `synthetic_ci_only`, sets
  `production_authorized=false`, and cannot prove live-model quality,
  production calibration, or authorization.
- Focused evidence: 31 tests, byte-exact CLI reproduction, Black, and focused
  Pylint 10.00 pass. Kimi was quota-blocked and wrote nothing. Terra found no
  P0 and required strict non-authority, rational gate decisions, integrity
  binding, and adversarial coverage; those requirements are incorporated.
- Complete evidence: Guardian 811 pass / 4 intentional live-model skips; full
  Pylint 9.83; warm Rust workspace pass with two intentional network ignores
  and five compile-fail doctests; Rustfmt; locked all-target Clippy; Memory;
  Autodidactic; YAML/Actionlint; Python 3.11 exact report; HTML/status markers;
  Cargo Audit with zero vulnerabilities/four allowed warnings; Gitleaks 8.30.0;
  and diff checks. One initial unchanged 10-MiB scanner load outlier passed
  immediately in isolation and in the warm complete rerun without code change.
- Terra's final exact-diff re-review is PASS with no remaining P0/P1/P2/P3.
- PR #139 review hardening addresses all six CodeRabbit findings: chronological
  audit ordering, explicit input/report label mapping, precise non-anchored
  evidence wording, strict CI shell semantics, pre-read file-size rejection,
  corpus size boundaries, and complete focused definition docstrings.
- Protected PR #139 merged normally without bypass as exact main
  `52209cc9d25fa283f290e65dcb40666b4abc65c8`; issue GH-138 is closed. Exact-main
  Prometheus CI `30697333650`, Security Audit `30697333643`, and Pages
  `30697333307` pass, and the live Whitepaper/Roadmap markers were fetched.

No live model, real malware/private telemetry, v2 operation, transport,
publication, wallet/key/signature, broadcast, deployment, chain, KAS/PROM,
reputation, slash ACL, commit-reveal, or emergency-stop behavior changed.

## 2026-08-01 - GH-132 local dependency remediation evidence

**Result:** LOCAL PASS; independent review and protected publication remain.

From exact green main `6687f1e3fb2611dc4261e66e76bc353fd5f59d94`, the
lockfile-only candidate updates transitive `event-listener 5.4.1` to 5.4.2.
No direct dependency or pinned rusty-kaspa/workflow version changes. Cargo's
resolved inverse tree retains `async-lock 3.4.2` and
`event-listener-strategy 0.5.4`; the patched package no longer resolves its
former `concurrent-queue` dependency.

Cargo Audit scanned 587 dependencies, reports zero vulnerabilities and eight
allowed maintenance/yank warnings, and no longer reports
`RUSTSEC-2026-0221`. Locked metadata resolution passes.

Regression evidence passes: Rustfmt; warning-free locked workspace all-target
Clippy; complete workspace 351 passed, two intentional live-network ignores,
zero failed; optimized Guardian P2P and ThreatProof binaries; verified
ThreatHint package; the three-package Guardian set; strict optimized
commitment performance gate; Memory Integrity; and six Autodidactic tests.

No product/protocol, commit-reveal formula, KAS/PROM separation, reputation,
wallet, signing, broadcast, deployment, or chain-state behavior changed.

Kimi's secret-free bounded review was attempted but blocked by its provider
billing-cycle quota and produced no diff. Claude's read-only independent
review reproduced Cargo Audit and warning-free locked all-target Clippy,
verified the exact baseline run IDs and ten branch-protection contexts, and
confirmed the lockfile edge and documentation claims. Final review result:
PASS with no P0/P1/P2/P3 finding.

## 2026-08-02 - GH-141 local model candidate evidence audit

**Result:** LOCAL PASS; protected publication and exact-main verification remain.

- Candidate capture uses only a validated integer port on literal
  `127.0.0.1`; arbitrary URLs, redirects through environment proxies, malformed
  identifiers, noncanonical responses, incomplete evidence, and output
  overwrite fail closed.
- The canonical prediction header commits the corpus, public served-model ID,
  caller-supplied artifact digest, and repository-pinned prompt digest. The
  artifact digest is an assertion, not independently established provenance.
- Offline evaluation rejects synthetic evidence in candidate mode and emits
  only `local_model_candidate_only` with `production_authorized=false`. The
  prior synthetic fixture and report remain byte-exact.
- Owner-only same-directory temporary creation, fsync, atomic hard-link
  no-clobber publication, symlink rejection, and generic CLI errors are covered
  by adversarial tests. The writer is POSIX-only; trusted-parent and local
  same-host race assumptions remain documented residual risks.
- PASS: 133 focused tests/4 intentional live-model skips; complete Guardian
  880/4; Black; full Pylint 9.84; exact fixture; Rustfmt; locked all-target
  Clippy; complete workspace; Memory/Autodidactic; YAML/Actionlint 1.7.12;
  HTML/status; Cargo Audit zero vulnerabilities/eight allowed warnings;
  Gitleaks 8.30.0 no leaks; diff hygiene.
- Kimi K3's independent read-only review found no P0/P1/P2. Sol corrected the
  public pre-merge status and Memory P3 items. Its pre-existing `health_check`
  exception-filter observation is unrelated to capture and remains out of scope.
- Claude Code was invoked twice for a small read-only helper check; both bounded
  attempts stopped on provider budget before reading or writing project files.

No live model, model download, real malware/private telemetry, remote endpoint,
production authorization, v2 operation, transport, publication, wallet/key/
signature, broadcast, deployment, chain, protocol formula, KAS/PROM,
reputation, slash ACL, commit-reveal, or emergency-stop behavior changed.

### PR #142 review-fix audit EOF mirror

The offline candidate path now requires the exact repository-pinned prompt
digest, and atomic writer cleanup cannot raw-close a descriptor after ownership
passes to `fdopen()`. Three regressions plus focused 136/4 and complete Guardian
883/4 pass; Black, full Pylint 9.84, exact fixture, Memory, and diff pass.
Refreshed protected checks remain.

### GH-141 merge and exact-main verification

PR #142 passed all eleven final protected contexts and squash-merged through
the repository's permitted method without bypass as exact main
`bf3f74f76eba83e7d689ffebd892a1fb19e4ddcc`. Prometheus CI `30727224584`,
Security Audit `30727224572`, and Pages `30727224235` pass. Both actionable and
both nitpick CodeRabbit findings are fixed; both inline threads are resolved.

No live model/result/download, independently proven artifact provenance,
semantic/adversarial quality certification, production calibration/authority,
v2 operation, wallet, signing, broadcast, deployment, chain, protocol formula,
KAS/PROM, reputation, slash ACL, commit-reveal, or emergency-stop change exists.

## 2026-08-04 - GH-144 merge and exact-main verification

PR #145 passed all eleven final protected contexts after six accepted review
fixes and squash-merged normally without bypass as exact main
`95d05ccb246c75f89a79d3601180907452f6b4dc`. Prometheus CI `30858991436`,
Security Audit `30858991557`, and Pages `30858990507` pass. All seven review
threads are answered and resolved. The live FAQ, roadmap, whitepaper and
economics pages serve the merged hardware/runtime wording.

No image/model pull, GPU execution, live inference, independently proven model
artifact, semantic/adversarial quality certification, production calibration
or authority, wallet, signing, broadcast, deployment, chain, protocol formula,
KAS/PROM, reputation, slash ACL, commit-reveal, or emergency-stop change exists.

## 2026-08-04 - GH-147 local membership-source audit

**Result:** LOCAL PASS; protected review and exact-main verification remain.

The candidate accepts only byte-exact canonical schema-v1 JSON for a separately
trusted network and labelled epoch. It binds 5–1024 strictly sorted unique
Guardian IDs one-to-one to structurally valid unique public BIP340 x-only keys,
fixed 8B tier, and model-artifact digests. Duplicate keys, malformed or
reordered schemas, noncanonical bytes, wrong networks, invalid/shared keys, and
conflicting IDs fail closed behind one redacted error. The raw source digest
pins the existing ensemble snapshot; validated member fields derive the signer
mapping without API changes.

The POSIX-only loader requires an exact absolute path, an owner-only resolved
parent and regular file, `O_NOFOLLOW`, pre-open versus descriptor identity and
size equality, bounded reads, and exact final length. Symlinked ancestors,
owner/mode drift, descriptor swaps, short/growing reads, and unavailable POSIX
controls fail closed. It performs no write, signing, network, database, wallet,
chain, reputation, token, or deployment action.

Sol independently reviewed the Kimi implementation and corrected one module
specification-order wording issue. PASS: 198 focused tests; complete Guardian
1043 passed/4 intentional skips; Black 30; changed Pylint 10.00/10; full Pylint
9.84/10; exact vector sidecar and clean diff. Source authorship/trust, key
ownership/rotation, Sybil resistance, multi-host operation, L1 attestation,
production authority, protected review, merge, and exact-main evidence remain.

## 2026-08-04 - GH-147 merge and exact-main verification

PR #148 passed all eleven final protected contexts with all six inline review
threads answered and resolved. It squash-merged normally without bypass as
exact main `aeecffb10a4f2978579b0d211b1052d18758520c`; issue #147 is closed.
Prometheus CI `30863940497`, Security Audit `30863940502`, and Pages
`30863940053` pass on that SHA. Live Whitepaper, roadmap and README GH-147
markers were fetched successfully.

External source authority, key ownership/rotation, Sybil resistance, multi-host
operation, Kaspa-L1 ensemble attestation and production authority remain open.
No private key, signing, transport, wallet, chain, reputation, token, deployment
or production behavior changed.

## 2026-08-04 - GH-9 exact-main H-001 readiness refresh

Exact green main `48b3b74d126aebf6e9e1abcd7af28b432c635c25` reproduced
the accepted `205e1ca` seven-artifact archive and schema-v2 signing request
byte-for-byte. The canary request retains canonical hashes
`b9f4d7a5ee72148165e5479e67551197682f416eb91d3155c4abba9f4fe2f6ed`
and `c0cad33f23acfee4114092e0211dd642cb97c44891cc8f8826f4656f406f42fa`.

Live read-only resolver and funding preflight reached synced, UTXO-indexed
`rusty-kaspa 2.0.1` above Toccata activation and reconfirmed the exact public
funding output unspent/non-coinbase at virtual DAA `534442816`. Two signing
request builds are byte-identical with request hash `6b8e6506...fa5323` and
sighash `174ccbe8...e0bcd`. Owner-only modes pass and Gitleaks 8.30.0 found no
leak in the 1.27-MB public handoff.

No wallet, wallet hint, private key, signature, signed transaction, broadcast,
deployment or chain mutation occurred. External BIP340 signing, full import and
transaction verification, separately approved one-shot broadcast, confirmation,
receipt and independent public evidence remain.

## 2026-08-09 - GH-152 permanent governed identity-pairing audit

**Result:** focused local PASS; independent final review and full repository
gates remain.

Governed schema v5 adds a permanent STRICT pairing table with independent
database uniqueness for statement digest, approval ID, and observable
commitment. The insert follows exact statement/bundle/approval revalidation
inside the existing `BEGIN IMMEDIATE` promotion transaction, so collision or
injected failure rolls authority, high-water, consumption, outbox, and pairing
back together. Retention never deletes pairing rows.

Exact empty schema-v4 state migrates without data loss. Nonempty v4 outbox or
result state remains at v4 and fails closed without partial migration. Legacy
and governed non-outbox consumption are unchanged. Focused outbox/governance
tests pass 62/62. No proof, analyzer, privacy authority, transport, wallet,
chain, contract, token, deployment, or production behavior changed.

## 2026-08-09 - GH-152 full local gate and independent review closeout

**Result:** PASS locally; protected publication pending.

Kimi's final independent review found no P0-P2 issue. A realistic idle-used v4
migration regression now proves that pinned authority, replay high-water, and
approval consumption survive while empty outbox/results permit v5 migration.
Permanent growth, no reconstructable pre-v5 pairing backfill, and fail-closed
manual handling of any nonempty v4 outbox/result state remain explicit
operational constraints.

Verification: 63 focused; full Guardian 1050 passed/4 skipped; Black; Pylint
9.84/10 and 10.00/10; Memory and six Autodidactic tests; model evidence 136/4;
public-page checks; Rust fmt/Clippy/workspace tests/release performance; Cargo
Audit with allowed warnings only; Pip Audit with no known vulnerabilities.
Docker is unavailable locally, so protected CI remains authoritative for
Compose rendering and Gitleaks.

## 2026-08-09 - GH-152 migration wording correction

CodeRabbit's single actionable documentation finding was accepted. Migration
requires only empty v4 outbox and result tables; authority, replay high-water,
and approval-consumption state are preserved. Any retained outbox/result row
fails closed unchanged. No implementation behavior changed.

## 2026-08-09 - GH-152 merged exact-main audit closeout

PR #153 merged as `3d203aa`; issue #152 closed. Exact-main CI `31306353671`,
Security `31306353670`, and Pages `31306353328` pass. Live Whitepaper, Roadmap,
and FAQ markers confirm schema v5 and exact migration wording. No production or
external protocol authority changed.
## 2026-08-10 - GH-161 model artifact provenance audit

PR #162 merged and exact-main verified as `d468426`. The new POSIX-only
provenance boundary rejects unsafe modes, symlink/special tree entries,
duplicate inodes, hard links, count/size/depth/path overflow, noncanonical
manifests, and detected file or directory mutation. Capture verifies the exact
manifest before model adapter construction and keeps legacy caller metadata
mutually exclusive. Focused verification reached 116 tests; full Guardian
verification reached 1116 passed and 4 intentional live-model skips before the
final review patch, with the final focused patch rechecked locally and by PR
CI. Kimi review found no P0-P2, all P3 observations were resolved, and all five
CodeRabbit comments were addressed before merge. Exact-main CI `31340112225`,
Security `31340112204`, and Pages `31340111625` pass. Remaining model risks are
upstream authenticity, binding to already-loaded service memory, semantic and
adversarial quality, calibration, and production authorization.

## 2026-08-13 - GH-167 bounded ThreatHint-v2 transport local audit

**Result:** NEEDS_CHANGES until complete gates and independent final review pass.

The candidate uses one exact bounded frame and shared cross-language corpus.
Rust validates the explicit trusted network before owner-only IPC; Python
reparses the original wires and resolves the untrusted nonce only through
trusted active-session state with a trusted local clock. Peer identity remains
transport metadata. Global admission budgets and strict accepted/rejected/busy
responses fail closed, and a separate-process test covers the real Guardian
boundary. The operated service rejects an absent trusted-network setting; the
library default grants no implicit network trust.

Production artifacts and authority, privacy-reviewed semantic/actionable
analysis, disclosure, public multi-host operation, models/YARA, wallet, chain,
rewards, and deployment are unchanged. Final full repository gates and Kimi's
independent read-only review remain mandatory before acceptance.

## 2026-08-13 - GH-167 local audit closeout

**Result:** ACCEPTED locally; protected publication and exact-main evidence pending.

Kimi's independent read-only review found no P0-P2 issue. The missing normative
v2 protocol-document update was added. Sol identified and fixed a cancellation
edge in which Python cannot kill already-running thread work: the ingress now
uses a dedicated bounded executor and waits for started promotion work before
close returns. A blocking regression proves that shutdown does not report
completion while durable promotion work can still run.

Verification passes: 30 focused transport/ingress tests; Guardian 1147 passed
and 4 intentional live-model skips; Black; Pylint 9.85/10 and 10.00/10; Rust
workspace fmt/clippy/tests; Guardian-P2P 76 library plus 5 process cases twice;
release binaries, package contents and performance; Memory, Autodidactic,
vLLM/public-evidence/HTML checks; Cargo Audit with allowed warnings only; Pip
Audit with no known vulnerabilities; diff and secret-marker hygiene.

## 2026-08-13 - GH-167 protected publication closeout

**Result:** ACCEPTED and exact-main verified.

PR #168 squash-merged normally to protected main as
`7c6260855193cce1ae2790670fcf25371ac08412`; issue #167 closed and the remote
feature branch was removed. All ten required PR contexts passed with no review
thread. Exact-main Prometheus CI `31645624623`, Security Audit `31645624601`,
and Pages `31645623547` pass. Cache-busted live reads confirm GH-167 on the
public roadmap, whitepaper, FAQ, and `llms.txt`. The public and repository
claims remain limited to same-host transport substrate evidence.

No production proof/relation/key approval, privacy authority, semantic or
actionable analysis, public multi-host evidence, model/YARA execution, wallet,
signing, chain, reward, deployment, slash, commit-reveal, reputation, or
emergency-stop behavior changed.

## 2026-08-13 - GH-173 deterministic semantic draft local audit

**Result:** complete local integration PASS; protected CI and merge pending.

The optional governed-worker analyzer revalidates the exact canonical bundle and
statement digest, derives one deterministic bounded memory-only YARA candidate,
and delegates compile-only validation to the pinned GH-170 boundary. The closed
schema-v2 result binds approval, lease-derived input identity, statement,
observable commitment, exact per-kind counts, nonce-bound candidate-binding
SHA-256, and an exact boolean compile verdict. Existing schema-v1 results remain
readable; no SQLite
DDL or migration is required because the result wire remains an opaque bounded
BLOB under ledger schema v5.

The candidate source, transient raw candidate digest, and observable values are
never persisted in the result. File hashes are never embedded. No model,
confidence, `should_submit`, scan, disclosure, publication, wallet, chain,
reward, deployment, semantic-quality claim, actionable rule, or production
authority is added. Current evidence is 61 focused tests and 1269 full Guardian
tests with 4 intentional live-model skips, Black clean, changed-source Pylint
10.00/10, and complete local repository gates except locally unavailable Docker
Compose rendering and Actionlint; protected CI remains authoritative for both.

## 2026-08-13 - GH-173 protected merge and exact-main audit

**Result:** PASS. PR #174 merged normally as exact main `1107b11`; issue #173
closed and the remote feature branch was deleted. All review threads are
resolved. Exact-main Prometheus CI `31654308969`, Security Audit `31654308964`,
and Pages `31654308875` pass. No rollout estimate or production authority
changed.

## 2026-08-13 - GH-177 synthetic YARA semantic-quality local audit

**Result:** complete local candidate PASS; protected CI and merge pending.

The standalone evaluator imports only stdlib plus exact-pinned YARA-X. It
compiles one fixed GH-173-shaped rule and scans only 20 bounded byte buffers
reconstructed in memory from a closed deterministic synthetic recipe. Exact
canonical parsing rejects duplicate keys, noncanonical bytes, wrong types,
oversize inputs, executable magic at offset zero, policy weakening, engine
drift and any corpus/policy/evaluator/report hash mismatch with one stable
redacted error.

Sol review found and fixed two P1 direct-object integrity gaps before commit:
payload bytes now rederive exactly from fully revalidated segments, and corpus
and policy objects reconstruct to the exact claimed canonical hashes before
evaluation. Independent Kimi final review reports no remaining P0/P1/P2.

PASS: 26 focused tests; Guardian 1295 passed/4 intentional live-model skips;
Black; changed-source Pylint 10.00/10 and full Guardian Pylint 9.85/10; Pip
Audit; Rustfmt, warning-free Clippy and full workspace tests; Cargo Audit with
no known vulnerability and eight allowed existing warnings; Memory Integrity;
six Autodidactic tests; structured-data and diff hygiene. The committed
synthetic baseline is 10 TP/0 FP/10 TN/0 FN at exact 10000-bps thresholds.

No real sample, file/process scan, governed worker/outbox/result wiring, model,
transport, disclosure, submission, wallet, signing, chain, reward, deployment,
production-quality certification, or production authority is added.

## 2026-08-13 - GH-177 protected merge and exact-main audit

**Result:** PASS. Feature PR #178 passed every protected context at reviewed
head `c20340c1253f9d732e84334006ae0ed91cd3f441` with no review threads and
squash-merged normally as exact main
`396d34793414add284d450f9b53d40ae287aaa4f`. Issue #177 closed and the remote
feature branch was deleted.

Exact-main Prometheus CI `31658560850`, Security Audit `31658560811`, and Pages
`31658560331` pass. Cache-busted live readback confirms that GitHub Pages serves
the GH-177 feature content. This documentation-only closeout reconciles the
public and internal status surfaces; it changes no product behavior, rollout
estimate, external effect, or production authority.

## 2026-08-13 - GH-180 offline v2 pipeline integration local audit

**Result:** LOCAL PASS. One new test module adds eight POSIX-only integration
cases and changes no product source. Canonical synthetic transport bytes cross
the real Python ingress, governed promotion, schema-v5 atomic acceptance and
outbox, bounded worker, and durable GH-173 non-actionable result boundary.

The tests verify exact statement digest, approval ID, observable commitment,
report nonce, candidate binding, input identity, result schema and retention.
Negative evidence covers rejection before trusted state for malformed and
oversized frames, durable replay/restart, exactly one concurrent winner,
lease-expiry recovery, redacted analyzer failure, and rollback without partial
result on injected SQLite completion failure. A source guard keeps GH-177 out
of worker, consumption, draft, ingress, and promotion modules.

PASS: 8 new tests; 171 adjacent; Guardian 1303 passed/4 intentional live-model
skips; Black; changed-file Pylint 10.00/10; full Guardian Pylint 9.85/10; Pip
Audit; Rustfmt, warning-free Clippy and full workspace tests; Cargo Audit with
no known vulnerability and eight allowed existing warnings; Memory Integrity;
six Autodidactic tests. Kimi implemented the bounded test slice after a
secret-free architecture review; Sol reviewed every line and reran the gates.
Independent final diff review and protected publication remain pending.

No real sample, network service, model, scan, disclosure, submission, wallet,
signing, chain, reward, deployment, actionable result, production artifact
approval, or production authority is exercised or added.

## 2026-08-13 - GH-180 protected merge and exact-main audit

**Result:** PASS. PR #181 exact reviewed head `5119445` passed all eleven
reported protected contexts after five accepted review improvements. Both
CodeRabbit threads were answered and resolved; Kimi's independent review found
no P0/P1/P2. The PR squash-merged normally as exact main
`a28ad00c1f4cb564c1c3ee7dfe49cdfd88bb7bd9`, closing issue #180 and deleting
the remote feature branch.

Exact-main Prometheus CI `31662874366`, Security Audit `31662874399`, and Pages
`31662873670` pass. This documentation closeout changes no product behavior,
rollout estimate, external effect, or production authority.

## 2026-08-15 - GH-193 pre-merge audit

PR #194 adds a development-only decoder for exact caller-supplied current-
Silverc RuleStorage constructor state. Local unit, integration, all-target,
format, Clippy and documentation gates pass; protected PR checks are green.
The work remains pre-merge and grants no chain provenance, finality, content
availability, wallet, deployment or production authority.

## 2026-08-15 - GH-193 protected merge and exact-main audit

**Result:** PASS. PR #194 exact reviewed head `66882df` passed all protected
contexts after the accepted status-synchronization and count-limit review
fixes. It squash-merged normally as exact main `d0cd087`, closing issue #193.
Exact-main CI `31900314121`, Security Audit `31900314143`, and Pages
`31900313745` pass; live Roadmap and README fetches confirm publication. No
production, wallet, chain, deployment, tokenomics or security-policy authority
changed.
## 2026-08-16 - GH-216 binary loopback E2E local audit

- Scope remained test-only: direct real-binary execution against ephemeral local
  Borsh wRPC/IPFS fixtures. No real node, wallet, private operator material,
  chain write, contract, deployment, Mainnet or production claim was introduced.
- Verified canonical checkpoint replay, lower-order rejection and same-order
  different-digest rejection. Kimi identified that an earlier test fixture used
  noncanonical JSON map order; the final fixture uses the exact checkpoint struct
  order and reaches the intended guard.
- Verified stored `Notify` permit semantics, TERM/INT handling, bounded waits,
  kill-on-drop child cleanup, private `0600` checkpoint mode and output redaction.
- Evidence: focused `5/5`; stress `20/20`; workspace Rust, Clippy/rustfmt,
  Guardian `1303/4`, release performance/build/package, Memory/H-001/claims,
  Black/Pylint and dependency audits pass.
- Result: `SHIP for protected PR / Production false`.

## 2026-08-16 - GH-216 exact-main and public-claim audit

- PR #217 merged normally as exact main
  `13c181282af19cc748624e9a376d2274b0703fbd`; issue #216 closed.
- Exact-main CI `31978132036`, Security Audit `31978132044`, and Pages
  `31978131647` all pass on that SHA.
- Public surfaces describe only test-only real-binary loopback evidence and
  retain the production-false boundary. No real/public Testnet operation,
  independent RPC/IPFS truth/availability, wallet, chain, deployment, Mainnet,
  production YARA or rollout readiness is inferred.
- Result: `PASS / Documentation-only closeout candidate`.

## 2026-08-17 - GH-216 final public closeout audit

- Documentation PR #218 passed all eleven protected contexts and merged
  normally as exact main `83c265b`.
- Exact-main CI `31979118045`, Security `31979117981`, and Pages
  `31979117415` pass; cache-busted live readback verifies all updated public
  HTML/text surfaces and the raw main README.
- CodeRabbit's required status passed but its content review was rate-limited;
  independent Kimi final review was `SHIP` with no medium/high finding.
- Result: `PASS / GH-216 complete / Production false`.

## 2026-08-29 - GH-234 protected-PR audit

- GH-234/PR #235 code commit `b450740` adds one Development/Testnet-10-only
  Light Client ThreatHint-v2 one-shot sender for an owner-prepared canonical
  payload. It grants no proof-generation, approval, membership, wallet, chain,
  reward, deployment, Mainnet or production authority.
- Local Sol verification passed focused v2 and unchanged-v1 real-binary QUIC
  tests, workspace tests, strict Clippy/rustfmt, documentation consistency and
  workflow checks. Kimi independently returned `APPROVE` with no P0-P2 finding.
- Protected Prometheus CI run `33271766762`, Security Audit run `33271766806`
  and CodeRabbit status passed on reviewed head `6d81c19`; review-provenance
  corrections are being applied before merge.
- Remaining gates: all corrected-head protected checks, normal review-required
  merge, and exact-main CI, Security Audit and Pages verification.
- Result: `PASS for continued protected review / Production false / Merge pending`.

## 2026-08-29 - GH-234 merge and exact-main audit

- PR #235 passed all corrected-head protected contexts with both actionable
  review threads resolved and squash-merged normally as exact main
  `f146fb2cef3adca4a8b7e861aa47cab506a56bed`; issue #234 closed.
- Exact-main Prometheus CI `33272578070`, Security Audit `33272577951`, and
  Pages `33272577407` pass on that SHA.
- Public claims remain bounded to implemented and same-host-tested
  Development/Testnet-10 repository behavior. Public/multi-host v2 operation,
  proof/approval authority, deployment, Mainnet and production remain false.
- Result: `PASS / GH-234 repository delivery complete / Production false`.

## 2026-08-29 - GH-238 repository-preparation status synchronization audit

- GH-238 implements and locally tests
  repository-only preparation for one later controlled distinct-host
  Development/Testnet-10 ThreatHint-v2 attempt. The tooling uses
  challenge-bound role-specific operator attestations over the source commit,
  actual executable digest, exact canonical payload digest, exact v2 protocol,
  shared observed UTC time, actual rejected status, one attempt, zero retries
  and no persistence, with strict owner-only/no-symlink files, the exact
  9,265-byte Rust wire bound, atomic no-clobber record output, a closed
  redacted verifier and CI tests.
- Bounded local documentation synchronization states the same facts across
  README, whitepaper, roadmap, FAQ, llms.txt, client README and memory status
  surfaces; the public claim-consistency gate now requires the concise GH-238
  marker and its non-operation caveat on each canonical public surface.
- No real GH-238 remote run has occurred and no GH-238 evidence record exists;
  host separation is not independently proven. PR #239 has since merged
  normally as exact main `912d96d`; issue #238 is closed. No remote run or
  evidence record is claimed. GH-229 and GH-234 claims are
  unchanged. No port, firewall, host,
  IAM, wallet, chain, deployment, Mainnet or production action or authority is
  added; a later real run requires separate explicit authorization.
- Result: `Local PASS / GH-238 repository preparation implemented and locally tested / Real remote evidence open / Production false`.

## 2026-08-29 - GH-238 merge and exact-main audit

- PR #239 merged normally as exact main
  `912d96d2d178ef3a2192547ed2bcca6df0fa38b4`; issue #238 closed.
- Exact-main Prometheus CI `33279351831`, Security Audit `33279351822`, and
  Pages `33279351387` pass on that SHA.
- Public claims remain bounded to implemented and locally tested
  repository-only preparation. No real GH-238 remote run has occurred and no
  GH-238 evidence record exists; host separation is not independently proven.
  No port, firewall, host, IAM, wallet, chain, deployment, Mainnet or
  production action or authority is added; a later real run requires separate
  explicit authorization.
- Result: `PASS / GH-238 repository preparation merged exact-main / Real remote evidence open / Production false`.
## 2026-08-31 - GH-242 local membership consumption audit

- The former public `BallotIngress.register(BallotContext(...))` caller-asserted
  committee path is removed. The replacement accepts no caller members, public
  keys, snapshot, source digest or context.
- Exact built-in epoch bounds are checked before file access. One canonical
  owner-only GH-147 source is loaded once, its network and epoch are restricted
  by separately trusted inputs, and its snapshot and BIP340 signer views are
  derived in the same call before unchanged session registration.
- Direct context construction and serialization fail. All establishment errors
  collapse to one data-minimal category. Adversarial tests cover source/network/
  epoch mismatch, unsafe or missing files, source changes, idempotency,
  conflicting same-session state, bypass attempts and existing transport/ACK
  behavior.
- Local evidence: 32 focused tests, 1,326 complete Guardian tests with
  four intentional live-model skips, Black, focused Pylint 10.00/10 and
  package Pylint 9.85/10 pass.
- Kimi's independent full-diff review found no P0/P1 and two P2 test gaps;
  successful one-load counting and distinct-source signer/session isolation
  were added and pass before protected delivery.
- Residual trust is explicit: owner-local source authorship, in-process owner
  trust, key ownership/rotation, Sybil resistance, public/multi-host operation,
  L1 attestation and production authority are not proven.
- PR #243 merged normally as exact main
  `5cb132c670d1e7771ccaf6dab2ddf5b1a6fd905a`; issue #242 is closed. Exact-main
  CI `33433012614`, Security Audit `33433012605`, and Pages `33433011653` pass.
- Public closeout PR #244 merged normally as exact main
  `d9b275452e70717372747ef9359abaec956fcf49`; exact-main CI `33435673539`,
  Security Audit `33435673520`, and Pages `33435672362` pass. Cache-busted live
  readback verifies raw-main README, Landing, Roadmap, Whitepaper, FAQ and
  `llms.txt` expose the bounded GH-242 evidence.
- Result: `PASS / Product and public exact-main verified / Production false`.

## Audit GH-246: Guardian membership transition continuity (local candidate)

- One owner-pinned public BIP340 authority verifies exact canonical membership
  transitions and advances an owner-only SQLite current-source ledger. There
  is no signer, private-key, wallet, chain, broadcast or production path.
- Rollback, same-epoch equivocation, replay, clock rollback, invalid windows,
  source/network/signature mismatch, restart, unsafe paths and concurrent
  duplicate application fail closed. New ballot sessions consume only stored
  current source bytes under the same ledger transaction lock.
- Kimi K3 independently returned `APPROVE` with no P0-P2 finding. Its sole P3
  stale-doc finding was fixed before delivery.
- Evidence passes: 54 focused and 1,348 complete Guardian tests with four
  intentional skips; complete Rust workspace tests with two intentional
  ignored live-node tests; Rustfmt; Clippy with warnings denied; Pylint
  9.85/10 package and 10.00/10 focused; public/docs/Memory/status gates;
  Cargo audit with nine allowed warnings; Python audit with no known
  vulnerability; desktop/mobile public-page checks without viewport overflow.
- Residual trust remains explicit: external authority, key ownership/rotation,
  Sybil resistance, L1 attestation, public multi-host operation and production
  authority are not proven.
- Result: `LOCAL PASS / Protected review pending / Production false`.
