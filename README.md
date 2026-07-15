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
| 9 — Deploy Path | BLOCKED | Current-Silverc runtime and release gates pass. The keyless Toccata-v1 genesis operator now builds, externally signs, verifies, broadcasts, and observes covenant deployments without accepting keys. Real testnet-10 funding/signatures/receipts, public chain evidence, the metrics-oracle transaction, and final release-hardening evidence remain. |

**Deployment status:** Prometheus is in post-Toccata rollout verification. All seven current-Silverc compile/ABI/runtime gates pass through the pinned compiler, and the deterministic release archive, keyless genesis request set, request verifier, operation procedure, receipt/evidence guards, handoff auditor, metrics-oracle handoff, and exact-commit release-hardening gates are implemented. The repository-owned Rust operator assembles transaction v1, exports only the 32-byte digest for external BIP340 signing, verifies the returned signature and complete transaction, revalidates the exact live funding UTXO, broadcasts, and observes the covenant output. Public Python builders accept no keys or raw transactions and do not execute chain operations. Rollout remains blocked until PR/remote CI, real funded testnet-10 signatures and confirmed receipts, independent public node/explorer evidence, the external metrics-oracle transaction, and exact-commit release evidence pass.

**Covenant genesis operator:** `prometheus-silverc-deployer` implements the official SilverScript genesis shape with Kaspa transaction version 1, compute budget 10, the exact contextual `storage_mass` commitment, P2SH from the compiled contract script, covenant-ID derivation from the funding outpoint plus the unbound genesis output, and funding-input binding only after the ID is derived. It verifies the exact live unspent funding UTXO during preflight and again immediately before broadcast, exports only a 32-byte sighash to an external vault/HSM, enforces approved fee bounds, verifies the returned BIP340 signature and complete transaction, persists an exclusive crash-recovery intent before submission, reconciles retries by transaction ID, applies per-request wRPC deadlines, and rebuilds the verified transaction before observing its exact covenant UTXO. The CLI has no private-key, seed, wallet, keystore, or raw-transaction input. Twenty-seven unit/security tests include fixed public interoperability values, secret-field rejection, journal recovery, and a public-file handoff roundtrip. Pinned v2.0.1 supports `testnet-10`; `testnet-12` and non-Toccata `simnet` fail closed. See the [operator runbook](docs/runbooks/silverc-genesis-operator.md).

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
