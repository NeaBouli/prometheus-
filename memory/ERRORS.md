# PROMETHEUS – ERROR LOG
# Known errors and their solutions. Claude Code reads this before every action.
# Format: | Date | Module | Error | Solution | Status |
# Status: OPEN | RESOLVED | PATTERN (recurring pattern)
# Last Updated: 2026-03-22

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

### PATTERN-002: Silverscript Compilation Error
```
Problem:  ssc compile without --testnet flag on testnet contracts
Symptom:  Contract deployed but incompatible with Testnet-10
Solution: Testnet: ssc compile --testnet --network testnet-10
          Mainnet: ssc compile (no flag)
Check:    Always verify network flag
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

---

## ERROR LOG (populated during development)

| Date | Module | Error | Solution | Status |
|------|--------|-------|----------|--------|
| 2026-03-21 | Sprint 0 / ssc | CRITICAL: `ssc` (Silverscript Compiler) does not exist in rusty-kaspa repo. No "ssc" package in workspace. Silverscript is not a production tool in the Kaspa ecosystem (as of March 2026). | BLOCKED — Core Dev must clarify: (a) Write own compiler, (b) KRC-20/WASM contracts as alternative, (c) Kaspa community fork with ssc. See AUDIT.md QUESTION FOR CLAUDE. | OPEN |
| 2026-03-21 | Sprint 0 / Testnet | MEDIUM: Testnet-12 does not exist in rusty-kaspa v1.1.0. Only Testnet-10 (netsuffix=10) is supported. Panic in params.rs:519. | Testnet-10 used instead. All references in MEMO.md and contracts changed to Testnet-10. | RESOLVED |
| 2026-03-21 | Sprint 0 / kaspad | LOW: `--netsuffix 12` syntax error. kaspad expects `--netsuffix=12` (equals sign). | Correct syntax: `--netsuffix=10` with equals sign. | RESOLVED |

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
