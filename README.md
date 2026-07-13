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
| 9 — Deploy Path | BLOCKED | Current-Silverc runtime gates, release-bundle manifest/archive, deploy preflight, operator runbook, external deploy request set plus verifier, public deploy operator procedure, public orchestrator-result receipt import with raw-transaction rejection, deployment receipt verifier, public node/explorer receipt-evidence verifier, deployment status staging guard, operator handoff package, release-readiness audit, metrics-oracle report preflight, unsigned oracle tx request, external oracle operator procedure, public external-operator capability verification, public oracle tx-result verification, public oracle tx-evidence verification, public oracle status-draft staging, and public release-hardening evidence verification pass; network deploy/orchestration, real public receipts plus node/explorer evidence, external oracle transaction operation, and final release-hardening evidence remain |

**Deployment status:** Kaspa Toccata is now in the post-fork verification phase for Prometheus. H-001 commit-reveal byte encoding plus ValidatorStaking, GuardianReputation, RuleStorage, CommunityDonations, DevIncentivePool, and GovernanceAutoTuning runtime gates are covered by the current Silverc verifier. A local release-bundle smoke compiles all current-Silverc fixtures through the pinned upstream `silverc` CLI and writes deterministic source/artifact/script hashes plus an optional deterministic archive for operator handoff. A deploy preflight validates that bundle and public operator inputs, and can emit a Markdown operator runbook with contract hashes, safety rules, and the current deploy blocker list. A deploy request builder emits per-contract public requests for an external orchestrator, with request hashes bound to the release bundle and no signing material; a separate deploy-request verifier re-checks the request set, per-contract files, manifest hashes, and secret-field rejection before handoff. A public deploy operator procedure now turns the verified request set into an external deployment checklist and required public result-evidence contract without accepting keys, raw transactions, signing, assembling, broadcasting, deploying, or writing status files. A public orchestrator-result importer converts confirmed external deploy results into `operator_record` receipts, binds them to the verified request set, rejects secret-like and raw/serialized transaction fields, and immediately re-validates them with the receipt verifier. A deployment receipt verifier validates public receipt records against the release bundle, rejects secret-like and raw/serialized transaction fields, and keeps synthetic CI fixtures separate from real `operator_record` receipts. A public node/explorer receipt-evidence verifier now binds those real operator receipts to an observed public snapshot before handoff readiness can pass. A deployment status staging guard accepts only verified `operator_record` receipts and emits a manual status-update draft without writing `memory/STATUS.md`, so CI fixtures cannot become release status. A CI-safe operator handoff builder bundles the release archive, preflight outputs, verified external deploy requests, deploy operator procedure, optional imported operator receipts, receipt verification, optional public receipt evidence, metrics report preflight, unsigned oracle request, external oracle operator procedure, optional verified external-operator capability record, optional verified oracle tx result, optional public oracle tx evidence, optional oracle status draft, and optional public release-hardening evidence into one public handoff directory while still reporting the real blockers. A release-readiness auditor verifies the generated handoff package, required files, safety flags, component summaries, optional receipt-evidence summary, optional oracle tx-evidence summary, optional external-operator capability summary, optional release-hardening summary, and JSON secret/raw-transaction hygiene, then reports `ROLLOUT_BLOCKED` until the true external blockers are gone. GovernanceAutoTuning now uses a signed metrics-oracle input for Q-003 `fp_rate` instead of the legacy stub; the metrics-oracle report preflight validates public `reportMetrics` payloads, the unsigned oracle tx-request builder binds that report to the GovernanceAutoTuning artifact for an external transaction assembler, the external operator procedure defines the public checklist/evidence boundary for signing and broadcast outside this repo, the public external-operator capability verifier binds a capability record to the deploy/oracle procedures without accepting keys or raw transactions, the oracle tx-result verifier checks the public result against the request and release bundle, the public oracle tx-evidence verifier binds that result to a public node/explorer snapshot, release-hardening evidence binds public CI, Pages, branch-control, rollback, and release-note checks to the exact release commit, and oracle status staging emits a manual status-update draft without accepting keys, raw transactions, signing, assembling, broadcasting, deploying, or updating status files. Deployment remains gated by missing approved network deploy/orchestration tooling, real public deploy results/receipts plus public node/explorer evidence from that path, external oracle transaction assembly/signing/broadcast/deploy operation, and public release-hardening evidence for the exact rollout commit.

**Covenant genesis compatibility:** The public deploy procedure now requires an external operator to attest the official SilverScript genesis shape: Kaspa transaction version 1, P2SH from the compiled contract script, covenant-ID derivation from the funding outpoint plus unbound genesis outputs, and binding to the funding input only after that ID is derived. CI rejects any capability record that changes these invariants; signing and broadcast remain outside this repository.

**Release governance:** `main` is PR-only with strict up-to-date branches, linear history, resolved conversations, nine required CI/Security checks, admin enforcement, and blocked force pushes/deletion. While the repository has only one collaborator, formal approvals are set to zero because GitHub does not permit self-approval; the required approval count returns to one when a second collaborator is added.

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
