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

## Experimental Miner Companion

[Kaspa mining is ASIC-dominated and normally uses Stratum](https://wiki.kaspa.org/mining), while Prometheus reads Kaspa node state through wRPC. The first integration is therefore an opt-in sidecar for operators who already run a local Testnet-10 node; it is not ASIC firmware and does not reuse a Stratum session.

```bash
cargo run -p prometheus-client -- \
  miner-companion preflight \
  --config modules/client/miner-companion.example.toml
```

The companion currently validates a strict credential-free, loopback-only configuration and can monitor local BlockDAG health. It is development-only: host scanning, threat reporting, validator/honeypot modes, and PROM rewards are disabled. Reporter allocation is reserved for future verified security contributions, not passive mining uptime.

---

## Architecture

```
Layer 1 (Kaspa L1):  ValidatorStaking | GuardianReputation | RuleStorage | GovernanceAutoTuning
                     Silverscript contracts on Kaspa with DAGKnight consensus

Layer 2 (P2P):       Guardian ballot request/response over QUIC (implemented core)
                     Rule distribution and client/validator carriers remain rollout work

Off-Chain:           Phi-3-mini (local AI) | LLaMA 3 8B-first/70B-escalation | Fed-DART
                     Privacy-preserving — raw data never leaves the device
```

---

## Tokens

| Token | Role | Details |
|-------|------|---------|
| **KAS** | Validator Staking | Kaspa native token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Rewards & Governance | 0% pre-mine. Earned by guardians for accepted proposals. 20M annual emission. |

**Important:** Validators stake KAS, never PROM. PROM is earned through contribution, never purchased or staked.
Guardian reputation is a separate canonical Kaspa L1 state in `GuardianReputationState`; it is not a PROM balance, badge, or NFT.

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
| 9 — Deploy Path | BLOCKED | Current-Silverc runtime and release gates pass. A closed, manifest-bound H-001 canary profile isolates the first real testnet-10 `ValidatorStakingH001` genesis run without a metrics-oracle key and cannot promote full rollout status. Public funding and the exact-main schema-v2 request/digest are confirmed; an external signature, operator verification, broadcast, receipt, and independent evidence remain. The keyless `reportMetrics` transition operator is implemented, but its real state/sponsor UTXOs, two external signatures, confirmed successor evidence, the remaining six genesis deployments, and final release hardening are still required. |
| 10B — Guardian Decentralization | IN PROGRESS | GH-33, GH-36, and GH-39 provide fail-closed hybrid analysis, complete 5+ Guardian voting, and BIP340-authenticated replay-safe intake. Merged and exact-main-verified GH-42/GH-44/GH-48/GH-52 provide the bounded ballot carrier, persistent transport identity, relay/AutoNAT operation, packaged sidecar, and explicit bootstrap routes. GH-55 adds a separate canonical 2048-byte-bounded `/prometheus/threat-hint/1.0.0` core plus a Light Client builder whose development proof stub is forbidden in beta/mainnet. The operated sidecar rejects every ThreatHint until a dedicated owner-only real-Groth16 verifier, freshness/replay policy, and bounded analyzer ingress exist. Three process tests continue to prove the unchanged exact same-host ballot path. `PeerId` remains transport metadata only. Real two-host operation, broad discovery, trusted membership/key assignment, Sybil protection, on-chain attestation, accepted ThreatHint analysis, live model wiring, and production operation remain open. |

**Deployment status:** Prometheus is in post-Toccata rollout verification. All seven current-Silverc compile/ABI/runtime gates pass through the pinned compiler, and the deterministic release archive, keyless genesis request set, request verifier, operation procedure, receipt/evidence guards, handoff auditor, metrics-oracle handoff, and exact-commit release-hardening gates are implemented. Deployment requests carry one of two closed profiles bound to the exact release manifest: `full` selects all seven contracts and requires the public metrics-oracle key; `testnet-10-validator-staking-h001` selects only `ValidatorStakingH001`, requires the TLS-only official testnet-10 resolver, omits the oracle key, and emits canary-only statuses that cannot satisfy full rollout or metrics readiness. The repository-owned Rust operator assembles transaction v1, exports only 32-byte digests for external BIP340 signing, verifies returned signatures and complete transactions, revalidates exact live UTXOs, broadcasts behind explicit request-hash acknowledgement, and observes covenant outputs. This now covers both genesis and the value-preserving two-input `GovernanceAutoTuningState.reportMetrics` transition; a separate P2PK sponsor pays its bounded fee, while the covenant state value is preserved exactly. Public funding and the deterministic schema-v2 H-001 request/digest were rebuilt from exact main commit `205e1ca`, passed exact-main CI/Security/Pages, revalidated the live unspent/non-coinbase funding output, and remained byte-identical across two builds and to the earlier `9477fab` baseline; no signature or broadcast has occurred. Public Python builders accept no keys or raw transactions and do not execute chain operations. The immediate GH-9 canary still needs an explicitly approved external BIP340 signature response, full operator verification, one-shot broadcast, confirmation, and independent public evidence. Full rollout additionally remains gated by the remaining six genesis deployments, real oracle/sponsor inputs and signatures plus successor evidence, and exact-commit release evidence.

**Progress estimate (2026-07-19):** the isolated H-001 canary preparation is about **96% complete**; only the explicitly approved external signature, verification, one-shot broadcast, confirmation, receipt, and independent evidence remain. A rollout-capable core network is about **74–78% complete** with the operated Guardian sidecar, explicit relay-bootstrap configuration, and fail-closed ThreatHint transport core implemented; six state-contract deployments, real Groth16 and accepted ThreatHint ingestion, PROM emission, real metrics-oracle execution/evidence, real two-host discovery/relay evidence, remaining P2P paths, and production node evidence remain open. The complete roadmap vision is about **40–45% complete**, so **55–60% remains**. These are scope-weighted engineering estimates, not calendar or release guarantees.

**Covenant genesis operator:** `prometheus-silverc-deployer` implements the official SilverScript genesis shape with Kaspa transaction version 1, compute budget 10, the exact contextual `storage_mass` commitment, P2SH from the compiled contract script, covenant-ID derivation from the funding outpoint plus the unbound genesis output, and funding-input binding only after the ID is derived. It verifies the exact live unspent funding UTXO during preflight and again immediately before broadcast, models the final 66-byte Schnorr signature script, and binds compute, transient, storage, normalized relay/overall mass, plus pinned relay and conservative operator fee floors into signing-request schema v2 before exporting a 32-byte sighash. A canonical `import-signature` path accepts only a public 64-byte BIP340 signature as 128 lowercase hex characters, derives every response field from the validated request, rejects normalized input/output path collisions, and writes output only after BIP340 plus complete Kaspa transaction verification. It persists an exclusive crash-recovery intent before submission, reconciles retries by transaction ID, applies per-request wRPC deadlines, and rebuilds the verified transaction before observing its exact covenant UTXO. The CLI has no private-key, seed, wallet, keystore, or raw-transaction input. Thirty-eight unit/security tests include deterministic public vectors, fee/mass and profile tamper rejection, secret-field rejection, resolver/TLS fail-closed coverage, signature-import failure/collision guards, journal recovery, and public-file handoff roundtrips. Pinned v2.0.1 supports `testnet-10`; public resolver mode is TLS-only and restricted to testnet-10, while `testnet-12` and non-Toccata `simnet` fail closed. See the [operator runbook](docs/runbooks/silverc-genesis-operator.md).

**Metrics state-transition operator:** the same binary now exposes `report-metrics-preflight`, `report-metrics-prepare`, `report-metrics-import-signatures`, `report-metrics-broadcast`, and `report-metrics-observe`. A closed transition spec binds the exact predecessor state/outpoint/covenant, pinned source and compiler commit, public metrics request, separate P2PK fee-sponsor UTXO, fee bounds, and canonical hash. The operator recompiles predecessor and successor states, preserves the covenant value exactly, derives both `SIG_HASH_ALL` digests, commits compute and contextual storage mass, requires external oracle and sponsor signatures, executes both inputs with `TxScriptEngine`, and revalidates both live UTXOs immediately before a journaled one-shot broadcast. Eleven focused tests cover value preservation, both valid and invalid signers, predecessor-state mismatch, sponsor underflow, request tamper, path collisions, acknowledgement, recorded-result recovery, and pre-network tamper rejection. No wallet or private-key input exists.

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
