# Prometheus Developer Guide

## Architecture Overview

Prometheus is a workspace of 3 layers:

```
prometheus/
├── modules/
│   ├── contracts/          # Silverscript smart contracts (6 contracts)
│   ├── client/             # Rust Light Client binary + library
│   │   └── src/
│   │       ├── ai/         # Phi-3 wrapper, anomaly detection, Fed-DART
│   │       ├── blockchain/ # Kaspa RPC connection, KRC-20 reader
│   │       ├── security/   # YARA scanner
│   │       └── network/    # ZK proof generation
│   ├── validator-node/     # Rust Validator library
│   │   └── src/
│   │       ├── voting/     # Commit-Reveal protocol
│   │       └── slashing/   # Penalty calculation
│   ├── guardian-node/      # Python Guardian Node
│   │   ├── jaeger/         # LLM server, YARA generator, analyzer
│   │   └── tests/
│   └── web/
│       └── audit/          # Open audit dashboard (HTML)
├── memory/                 # Persistent project memory (MEMO, TODO, STATUS, etc.)
├── scripts/                # Automation scripts
├── docs/                   # Documentation wiki
├── WHITEPAPER.md
├── CONTRIBUTING.md
└── Cargo.toml              # Rust workspace root
```

## Module Overview

| Module | Language | Purpose | Tests |
|--------|----------|---------|-------|
| ValidatorStaking.ss | Silverscript | KAS staking, voting, slashing | 11 |
| GuardianReputation.ss | Silverscript | Reputation, quadratic voting | 9 |
| GovernanceAutoTuning.ss | Silverscript | Weekly parameter adjustment | 8 |
| DevIncentivePool.ss | Silverscript | DAO-voted developer grants | 9 |
| CommunityDonations.ss | Silverscript | Transparent community fund | 8 |
| RuleStorage.ss | Silverscript | KRC-20 rule minting | 9 |
| prometheus-client | Rust | Light Client (scanner, AI, blockchain) | 51 |
| prometheus-validator | Rust | Voting + slashing engine | 29 |
| jaeger (guardian-node) | Python | LLM threat analysis + YARA gen | 26 |

**Total: 160+ tests across 3 languages.**

## Building

```bash
# Full workspace
cargo build

# Individual crates
cargo build -p prometheus-client
cargo build -p prometheus-validator

# Release mode (required for performance tests)
cargo build --release
```

## Testing

```bash
# All Rust tests
cargo test

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test e2e_threat_lifecycle
cargo test --test security_sybil

# Python tests
cd modules/guardian-node
PYTHONPATH=. pytest tests/ -v
```

## Key Design Decisions

All 15 Architecture Decisions are documented in `memory/MEMO.md`. The most important for developers:

1. **KAS = staking, PROM = reputation** — Never mix these in contracts
2. **No emergency stop** — The protocol cannot be paused by anyone
3. **uint64 with 10000x scaling** — No float64 in on-chain contracts
4. **tokio::sync::Mutex** — Never use std::sync::Mutex in async Rust code
5. **CIDv1 bytes(36)** — Always binary CIDv1, never CIDv0 base58

## Memory System

The `memory/` directory is the project's persistent knowledge base:

| File | Purpose |
|------|---------|
| MEMO.md | Architecture decisions (immutable) |
| SCHEMA.md | Canonical data structures |
| STATUS.md | Module status tracker |
| AUDIT.md | Audit log and questions |
| TODO.md | Task queue with priorities |
| ERRORS.md | Known patterns and error log |
| SPRINTS.md | Sprint planning |
| API.md | API definitions |
