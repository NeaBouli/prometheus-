# Contributing to Prometheus

Thank you for your interest in contributing to Prometheus. Every contribution strengthens the decentralized threat intelligence network.

## Code of Conduct

Be respectful, constructive, and collaborative. Technical disagreements are resolved through the architect audit process, not personal attacks.

## Reporting Bugs

Open a [GitHub Issue](https://github.com/NeaBouli/prometheus-/issues) with:
- Module affected (e.g., `modules/client/src/security/scanner.rs`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Proposing Features

1. Write a proposal describing the feature and its impact
2. Submit as a GitHub Issue with the `proposal` label
3. Core Dev reviews and forwards to the Architect (Claude)
4. Architect evaluates against the 15 binding Architecture Decisions in `memory/MEMO.md`
5. If approved, a new entry is added to `memory/TODO.md` with priority

Features that contradict Architecture Decisions are automatically rejected.

## Development Setup

### Rust (Light Client + Validator)

```bash
# Prerequisites: Rust 1.88+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build -p prometheus-client -p prometheus-validator

# Test
cargo test -p prometheus-client -p prometheus-validator

# Lint
cargo fmt --check
cargo clippy -- -D warnings
```

### Python (Guardian Node)

```bash
cd modules/guardian-node
pip install -r requirements.txt

# Test
PYTHONPATH=. pytest tests/ --tb=short

# Lint
black --check jaeger/
pylint jaeger/ --fail-under=7.0
```

## Code Standards

From `memory/MEMO.md` — these are enforced by CI and architect audit:

### Rust
- `cargo fmt` before every commit
- `cargo clippy -- -D warnings` (zero warnings allowed)
- `cargo test` must pass 100%
- Every `pub` function: rustdoc comment
- Minimum test coverage: 80%
- Use `tokio::sync::Mutex` in async code, never `std::sync::Mutex` (PATTERN-003)

### Python
- Black formatter
- Pylint score >= 8.0
- Type hints on all functions
- Docstrings for all classes and functions

### Silverscript
- All structs from `memory/SCHEMA.md` — no deviations
- Named constants only — no magic numbers
- Comment every function with its purpose

## Commit Message Format

```
<type>: <description>

<optional body>

Co-Authored-By: <your name> <your email>
```

Types:
- `feat:` — New feature or module
- `fix:` — Bug fix or audit finding resolution
- `test:` — New or updated tests
- `docs:` — Documentation changes

## Grant Eligibility

5% of annual PROM emission (1,000,000 PROM/year) is allocated to developer grants via the Dev Incentive Pool:

- Anyone can propose a grant via `DevIncentivePool.ss`
- Formula: `lines * 10 * (100 + complexity * 10) / 100`
- Maximum per grant: 100,000 PROM
- Requires DAO vote: 2/3 validator majority + 10 minimum votes
- No foundation approval needed — purely on-chain governance

## Security Disclosure

Report security vulnerabilities via GitHub Security Advisories:
https://github.com/NeaBouli/prometheus-/security/advisories/new

**Do NOT open public issues for security vulnerabilities.**

Include: description, reproduction steps, potential impact.
We follow a **90-day responsible disclosure** policy.
No legal action will be taken against ethical security researchers.
Acknowledged researchers are credited in the WHITEPAPER.md.

Critical vulnerabilities affecting staked KAS funds receive priority response within 24 hours.

---

*Prometheus — The fire belongs to humanity.*
