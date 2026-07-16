# PROMETHEUS – ERROR LOG
# Known errors and their solutions. Claude Code reads this before every action.
# Format: | Date | Module | Error | Solution | Status |
# Status: OPEN | RESOLVED | PATTERN (recurring pattern)
# Last Updated: 2026-07-16

---

## KNOWN ERROR PATTERNS (Claude Code: always check!)

These patterns are known from other projects and should be avoided from the start:

### PATTERN-001: KAS/PROM Confusion (CRITICAL)
```
Problem:  MIN_STAKE defined as PROM, but tx.value sends KAS
Symptom:  Contract accepts wrong token, staking fails
Solution: ALWAYS use MIN_STAKE_KAS (KAS) for validators
          PROM is ONLY earned through contribution, never staked by validators
Check:    Before every Silverscript commit: grep -n "MIN_STAKE" to verify
```

### PATTERN-002: Obsolete Silverscript Compiler Invocation
```
Problem:  Historical docs invoke the nonexistent pre-Toccata `ssc` CLI or
          assume a compiler command also performs network deployment.
Symptom:  Builds cannot be reproduced, or compilation is mistaken for a
          funded/signature-backed covenant transaction.
Solution: Build through the pinned upstream `silverc` compiler using
          `scripts/smoke_silverc_artifacts.py`; use the repository keyless
          operator for testnet-10 preflight/assembly/verification/broadcast.
Check:    Verify the pinned Silverc commit, release-manifest hashes, closed
          deployment profile, exact network target, and external signature gate.
```

### PATTERN-003: Rust Borrow-Checker in async
```
Problem:  Arc<Mutex<T>> in async contexts causes deadlocks
Symptom:  Program hangs without error message
Solution: Use tokio::sync::Mutex instead of std::sync::Mutex in async code
          Use RwLock for read-heavy operations
Check:    cargo clippy catches many of these cases
```

### PATTERN-004: ZK-Proof Parameter Mismatch
```
Problem:  Groth16 parameters not compatible with Kaspa KIP-16
Symptom:  ZK-Proof rejected on-chain
Solution: Use parameters from rusty-kaspa repository
          Do not generate your own parameters
Check:    Use kaspa-zk-params crate
```

### PATTERN-005: IPFS CID Format
```
Problem:  CIDv0 (Qm...) used instead of CIDv1 (bafy...)
Symptom:  IPFS link unresolvable, rule content not loadable
Solution: Always use CIDv1 (base32): ipfs add --cid-version 1
Check:    CID must start with "bafy"
```

### PATTERN-006: Silverscript float64 Precision
```
Problem:  Reputation calculation with float64 has rounding errors
Symptom:  Reputation slightly different depending on execution order
Solution: For comparisons always use epsilon: abs(a - b) < 0.001
          For voting power scale to uint64: (rep * 1000) as uint64
Check:    All float64 comparisons with epsilon
```

### PATTERN-007: libp2p Peer Discovery
```
Problem:  Peers found but connection fails (NAT)
Symptom:  Network works locally, not in production
Solution: Set up STUN/TURN server for NAT traversal
          Use Kaspa bootstrap nodes as initial peers
Check:    Integration tests with simulated NAT
```

### PATTERN-008: Tests forgotten after ACL changes
```
Problem:  After adding access control (require msg.sender == X), existing
          tests fail because they call without mock_sender()
Symptom:  Tests revert with "Only governance..." even though logic is correct
Solution: Always add mock_sender(AUTHORIZED_CONTRACT) in tests that call
          access-controlled functions after adding ACL
Check:    After every ACL change: search all tests that call the function
```

### PATTERN-009: yara Crate Cross-Platform Compile
```
Problem:  yara crate (C bindings) requires libyara-dev on the system,
          does not compile cross-platform without additional build configuration
Symptom:  Build error on cargo build on systems without libyara
Solution: Custom pattern matcher implemented in scanner.rs instead of yara crate.
          For production: evaluate yara-x crate (pure Rust, no C dependency)
Check:    cargo build must work on all target platforms without system dependencies
```

### PATTERN-010: Unnecessary Mutex wrapping on immutable &self
```
Problem:  Phi3Model.analyze_bytes() takes &self (immutable), does not need Mutex
Symptom:  Lock contention on many concurrent scans for no reason
Solution: Use Arc<Phi3Model> directly instead of Arc<Mutex<Phi3Model>>
          Mutex only for actually mutable shared state
Check:    Before Mutex wrapping: does the method need &mut self?
```

### PATTERN-011: Heuristic Confidence Scoring in yara_generator.py
```
Problem:  yara_generator.py calculates confidence heuristically (base 0.7 + indicator bonus)
Symptom:  Confidence values do not correlate with actual rule quality
Solution: Replace with real LLM confidence extraction when live LLM is available
          LLM should provide its own confidence as part of the response
Check:    Tracked as TODO — Sprint 6 E2E Integration
```

### PATTERN-012: Guardian Centralization Risk
```
Problem:  70B Guardian requires $60k-120k hardware → only 50-200
          nodes realistic worldwide → contradicts decentralization promise
Symptom:  Network works but is not truly decentralized at Guardian layer
Solution: Implement hybrid routing (8B default) + ensemble voting
          (5x 8B majority) BEFORE mainnet. These are Sprint 10B tasks.
Check:    Before mainnet: verify at least 50 active 8B Guardians
          and ensemble voting protocol deployed
```

### PATTERN-013: Canary Evidence Promoted As Full Rollout
```
Problem:  A single-contract canary can accidentally inherit full-release
          status strings, fixture counts, or metrics-oracle claims.
Symptom:  One confirmed H-001 receipt appears sufficient for rollout readiness.
Solution: Use only closed, manifest-bound deployment profiles. The H-001
          profile requires testnet + kaspa-resolver://public, forbids the
          metrics-oracle key, and emits distinct non-promotable statuses.
Check:    Reject unknown/changed profiles, rehashed profile tampering, oracle
          input on H-001, missing oracle input on full, and any canary status
          consumed by full handoff/readiness.
```

---

## ERROR LOG (populated during development)

| Date | Module | Error | Solution | Status |
|------|--------|-------|----------|--------|
| 2026-03-21 | Sprint 0 / ssc | CRITICAL: `ssc` did not exist in the audited rusty-kaspa workspace, so the original compile/deploy instructions were invalid. | Resolved after Toccata with pinned upstream `silverc` commit `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`, deterministic seven-fixture release gates, and the repository-owned keyless testnet-10 covenant operator. Real signatures and chain evidence remain separate rollout gates, not a compiler blocker. | RESOLVED |
| 2026-03-21 | Sprint 0 / Testnet | MEDIUM: Testnet-12 does not exist in rusty-kaspa v1.1.0. Only Testnet-10 (netsuffix=10) is supported. Panic in params.rs:519. | Testnet-10 used instead. All references in MEMO.md and contracts changed to Testnet-10. | RESOLVED |
| 2026-03-21 | Sprint 0 / kaspad | LOW: `--netsuffix 12` syntax error. kaspad expects `--netsuffix=12` (equals sign). | Correct syntax: `--netsuffix=10` with equals sign. | RESOLVED |
| 2026-07-16 | guardian-p2p/local_submit.rs | MEDIUM: Linux reset an overloaded local submit connection because the server returned `busy` while request bytes remained unread. | Added a separately bounded rejection pool that validates and drains one exact request frame before returning `busy`; malformed overload frames return transport failure and rejection tasks remain capped. | RESOLVED |
| 2026-07-16 | guardian-p2p/service.rs | HIGH: synchronous stdout writes could block the async owner loop and defeat bounded SIGTERM handling. | Serialize into a bounded dedicated writer queue, fail closed on saturation/output failure, bound writer shutdown, and cover broken stdout plus SIGTERM during collector wait in process tests. | RESOLVED |

---

## ERROR CATEGORIES

```
CRITICAL:  Prevents deployment / violates architecture decisions
HIGH:      Functionality impaired
MEDIUM:    Edge case, rarely occurring
LOW:       Cosmetic / performance
```

---

## CLAUDE CODE INSTRUCTIONS

Before every new module:
1. Read this file
2. Check all PATTERN-00X
3. If known pattern is relevant: apply solution directly
4. Document new errors immediately here

Entry format for new errors:
```
| YYYY-MM-DD | module/file.rs | Error message (max 80 chars) | Applied solution | RESOLVED |
```
