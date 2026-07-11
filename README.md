![Prometheus](logo/Prometheus.png)

# Prometheus

**Decentralized AI-powered threat intelligence on Kaspa.**

[![CI](https://github.com/NeaBouli/prometheus-/actions/workflows/ci.yml/badge.svg)](https://github.com/NeaBouli/prometheus-/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Network](https://img.shields.io/badge/network-kaspa--post--toccata-orange.svg)](https://kaspa.org)

---

## What is Prometheus?

Prometheus transforms every connected device into a sensor in a global threat detection swarm — without central control, without a foundation, without hidden interests. It combines on-device AI (Phi-3-mini) with LLaMA 3 guardian nodes and Kaspa L1 consensus to create an incorruptible, zero-pre-mine security protocol.

---

## Quick Start

| Node Type | Hardware | Command |
|-----------|----------|---------|
| **Light Client** | Any device, 4 GB RAM | `cargo run -p prometheus-client` |
| **Validator** | Kaspa node + 10,000 KAS stake | `cargo run -p prometheus-validator` |
| **Guardian (8B)** | RTX 4070 Ti+, 16 GB VRAM | `cd modules/guardian-node && docker compose up guardian-8b` |
| **Guardian (70B)** | 4x A100/H100, 128 GB RAM | Uncomment `guardian-70b` in docker-compose.yml |

```bash
git clone https://github.com/NeaBouli/prometheus-.git
cd prometheus-
cargo build --release
```

---

## Architecture

```
Layer 1 (Kaspa L1):  ValidatorStaking | GuardianReputation | RuleStorage | GovernanceAutoTuning
                     Silverscript contracts on Kaspa with DAGKnight consensus

Layer 2 (P2P):       Threat hints | YARA rule proposals | Commit-Reveal voting | ZK proofs
                     Decentralized coordination between clients, guardians, and validators

Off-Chain:           Phi-3-mini (local AI) | LLaMA 3 (guardian AI) | Fed-DART (federated learning)
                     Privacy-preserving — raw data never leaves the device
```

---

## Tokens

| Token | Role | Details |
|-------|------|---------|
| **KAS** | Validator Staking | Kaspa native token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Reputation & Governance | 0% pre-mine. Earned by guardians for accepted proposals. 20M annual emission. |

**Important:** Validators stake KAS, never PROM. PROM is earned through contribution, never purchased or staked.

---

## Project Status

| Sprint | Status | Description |
|--------|--------|-------------|
| 0 — Setup | DONE | Kaspa testnet-10 node, repo structure, CI/CD |
| 1 — Contracts | ACCEPTED | 6 Silverscript contracts, 54 tests |
| 2 — Client | ACCEPTED | Kaspa RPC, KRC-20 reader, YARA scanner, ZK stub |
| 3 — AI | ACCEPTED | Phi-3 wrapper, anomaly detection, Fed-DART |
| 4 — Guardian | ACCEPTED | Docker, vLLM, YARA generator, analyzer |
| 5 — Voting | ACCEPTED | Commit-Reveal, bond system, slashing engine |
| 6 — E2E | ACCEPTED | Full lifecycle test, Sybil + FP flood resistance |
| 7 — Dashboard | ACCEPTED | Audit dashboard, documentation |
| 8 — Public Site | ACCEPTED | Website, SEO, whitepaper, GitHub Pages |
| 9 — Deploy Path | BLOCKED | Current-Silverc runtime gates, release-bundle manifest/archive, deploy preflight, operator runbook, deployment receipt verifier, deployment status staging guard, operator handoff package, metrics-oracle report preflight, and unsigned oracle tx request pass; network deploy/orchestration and release hardening remain |

**Deployment status:** Kaspa Toccata is now in the post-fork verification phase for Prometheus. H-001 commit-reveal byte encoding plus ValidatorStaking, GuardianReputation, RuleStorage, CommunityDonations, DevIncentivePool, and GovernanceAutoTuning runtime gates are covered by the current Silverc verifier. A local release-bundle smoke compiles all current-Silverc fixtures through the pinned upstream `silverc` CLI and writes deterministic source/artifact/script hashes plus an optional deterministic archive for operator handoff. A deploy preflight validates that bundle and public operator inputs, and can emit a Markdown operator runbook with contract hashes, safety rules, and the current deploy blocker list. A deployment receipt verifier validates public receipt records against the release bundle and keeps synthetic CI fixtures separate from real `operator_record` receipts. A deployment status staging guard accepts only verified `operator_record` receipts and emits a manual status-update draft without writing `memory/STATUS.md`, so CI fixtures cannot become release status. A CI-safe operator handoff builder bundles the release archive, preflight outputs, receipt verification, metrics report preflight, and unsigned oracle request into one public handoff directory while still reporting the real blockers. It still reports the remaining upstream gap: `silverc` has no network deploy command. GovernanceAutoTuning now uses a signed metrics-oracle input for Q-003 `fp_rate` instead of the legacy stub; the metrics-oracle report preflight validates public `reportMetrics` payloads, and the unsigned oracle tx-request builder binds that report to the GovernanceAutoTuning artifact for an external transaction assembler without accepting keys, signing, assembling a chain transaction, or broadcasting. Deployment remains gated by missing network deploy/orchestration tooling, external oracle transaction assembly/signing/deploy integration, and release hardening.

---

## Links

- [Whitepaper v4](WHITEPAPER.md) — Full technical specification
- [Audit Dashboard](modules/web/audit/index.html) — Live network transparency
- [Audit Log](memory/AUDIT.md) — All audit results, public and immutable
- [Architecture Decisions](memory/MEMO.md) — 15 binding decisions
- [Sprint Planning](memory/SPRINTS.md) — Detailed roadmap

---

## License

MIT — Fully open source. No foundation. No gatekeeper.

---

*Prometheus — The fire belongs to humanity, not to corporations.*
