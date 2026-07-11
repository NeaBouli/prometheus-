# Prometheus — Full Deployment Roadmap
*Target: Full release August / September 2026*
*Working daily. No shortcuts.*

---

## Phase 0 — Foundation (COMPLETE)
**March 2026 · All sprints accepted**

All architecture decisions final. 6 Silverscript contracts written
and audited. Rust light client, Python guardian node, voting mechanism,
E2E tests, documentation, landing page — all complete and on GitHub.

| Sprint | Deliverable | Status |
|--------|-------------|--------|
| 0 | Kaspa Testnet-10, repo structure, CI/CD | ACCEPTED |
| 1 | 6 Silverscript contracts, 54 tests | ACCEPTED |
| 2 | Rust client: RPC, YARA, ZK stub, KRC-20 | ACCEPTED |
| 3 | Phi-3 wrapper, anomaly detection, Fed-DART | ACCEPTED |
| 4 | Docker vLLM, YARA generator, analyzer | ACCEPTED |
| 5 | Commit-Reveal voting, bond system, slashing | ACCEPTED |
| 6 | E2E lifecycle <60s, Sybil + FP flood proof | ACCEPTED |
| 7 | Audit dashboard, README, WHITEPAPER.md | ACCEPTED |
| 8 | CONTRIBUTING.md, 5 wiki guides, landing page | DONE |

---

## Phase A — Post-Toccata Core Integration
**June/July 2026**

Kaspa Toccata moved the ecosystem into the post-fork verification phase.
Prometheus current-Silverc runtime gates now cover H-001, ValidatorStaking,
GuardianReputation, RuleStorage, CommunityDonations, DevIncentivePool, and
GovernanceAutoTuning. A local release-bundle smoke compiles all 7 current-Silverc
fixtures through the pinned upstream `silverc` CLI and writes deterministic
source/artifact/script hashes plus an optional deterministic archive. A deploy
preflight validates release-bundle integrity and public operator inputs, emits a
Markdown operator runbook with contract hashes and safety rules, and confirms
upstream `silverc` still exposes no network deploy command. An external deploy
request builder emits per-contract public request JSON for an approved
orchestrator, with request hashes bound to the release bundle. A public
orchestrator-result importer converts confirmed external deploy results into
verified `operator_record` receipts without accepting signing material. A
deployment receipt verifier validates public receipt records against the release
bundle and keeps synthetic CI fixtures separate from real `operator_record`
receipts. A status staging guard rejects CI fixtures and emits only a manual
status-update draft from verified `operator_record` receipts. A CI-safe operator
handoff builder now packages the release archive, preflight outputs, deploy
requests, optional imported operator receipts, receipt checks, metrics report
preflight, unsigned oracle request, and optional verified oracle tx result into
one public handoff directory while preserving the real blocker list. A separate
metrics-oracle report preflight validates public `reportMetrics` payloads, an
unsigned oracle tx-request builder binds those payloads to the
GovernanceAutoTuning artifact hashes for external assembly, an external
oracle-operator procedure defines the public signing/broadcast checklist and
required result evidence, and a public tx-result verifier checks confirmed
transaction records against the request and release bundle without accepting
signing material or raw transaction payloads.
A release-readiness auditor now checks the generated handoff package, required
files, component summaries, safety flags, and JSON secret/raw-transaction
hygiene before any rollout claim. The remaining deployment blockers are the
missing network deploy/orchestration path, real public deploy results/receipts
from that path, external signed metrics-oracle transaction
assembly/signing/broadcast/deploy operation, and final release hardening.

**Sprint 9 — Contracts Live + Real ZK-Proof**
- Keep current-Silverscript runtime and release-bundle manifest gates green
- Keep release-bundle deploy preflight green
- Keep the generated deploy operator runbook green and free of signing material
- Keep the external deploy request set green and free of signing material
- Keep public orchestrator-result receipt import green and free of signing material
- Keep deployment receipt verification green and free of signing material
- Keep deployment status staging guarded against CI fixture receipts
- Keep the generated operator handoff package green and free of signing material
- Keep the release-readiness audit green and blocked until real external evidence exists
- Keep the metrics-oracle report preflight green and free of signing material
- Keep the unsigned metrics-oracle tx-request builder green and free of signing material
- Keep the external oracle operator procedure green and free of signing/raw transaction material
- Keep public oracle tx-result verification green and free of signing/raw transaction material
- Compile and deploy all 6 contracts to Kaspa Mainnet only after verification passes
- Integrate kaspa-zk-params crate (real Groth16, replacing stub)
- Implement PROM emission contract (minting logic)
- Deploy first KAS/PROM liquidity pool on Kasplex DEX
- Start 10 team-operated Guardian + Validator nodes

**Sprint 10 — Real KRC-20 Reader + P2P Network**
- KRC-20 UTXO queries for "PROM-RULES" tick (real on-chain reads)
- Rule content download from IPFS via CIDv1
- Full libp2p module: peer discovery, NAT traversal, STUN/TURN
- Light Client ↔ Guardian communication over P2P
- Guardian ↔ Validator communication over P2P

**Sprint 11 — Real Phi-3-mini Integration**
- Download Phi-3-mini 3.8B from Microsoft HuggingFace
- 4-bit quantization via ONNX Runtime
- Replace entropy heuristic with real inference in phi3.rs
- Model update mechanism: IPFS distribution + on-chain hash verification
- Test: does Phi-3 detect known malware samples?

---

## Phase B — Guardian + Validator Production
**June 2026**

**Sprint 12 — LLaMA 3 Fine-Tuning**
- Assemble security training datasets:
  - VirusShare (largest public malware database)
  - MalwareBazaar (daily updated samples)
  - Exploit-DB (CVE correlation data)
  - CuckooSandbox reports (behavioral analysis)
- LoRA fine-tuning on LLaMA 3 8B (first)
- Validation: does the model detect Pegasus indicators?
- LLaMA 3 70B fine-tuning
- Publish models to IPFS, hashes stored on-chain

**Sprint 13 — Real Fed-DART + Oracle**
- Integrate Fed-DART protocol (Fraunhofer ITWM)
- Real gradient aggregation client in federated.rs
- Coordinator rotation via reputation
- fp_rate oracle: operate signed metrics reporter for GovernanceAutoTuningState
- Integrate Light Client false-positive reports into the metrics-oracle pipeline
- End-to-end test: FP rate rises → Auto-Tuning responds

---

## Phase C — Desktop Client Full Release
**July / August 2026**

**Sprint 14 — Tauri Desktop UI**
- Tauri v2 app (Rust + React/TypeScript)
- Features:
  - System tray with live status
  - Real-time scan feed
  - Threat history with rule details
  - PROM balance + reputation display
  - Settings: model path, node URL, privacy controls
- Platforms: Windows, macOS, Linux

**Sprint 15 — Installers + Public Beta**
- Windows: MSI installer
- macOS: DMG with Gatekeeper signing (requires Apple Developer Account)
- Linux: .deb, .rpm, .AppImage, Flatpak
- GitHub Releases with automated CI/CD builds
- SHA-256 checksums + GPG signatures for all downloads
- **First public beta release**

---

## Phase D — Mobile Clients
**August / September 2026**

**Technology choice: Flutter**
Flutter is chosen over React Native because background scanning
requires deep native OS integration — Flutter handles this better
on both iOS and Android.

**Sprint 16 — iOS Client**
- Flutter foundation
- Phi-3-mini on iOS via Core ML (ONNX → Core ML conversion)
- iOS Background App Refresh for continuous scanning
- Keychain for ZK-proof keys
- TestFlight beta → App Store submission

**Sprint 17 — Android Client**
- Flutter Android
- Phi-3-mini via ONNX Runtime Mobile
- WorkManager for background scanning
- Android Keystore for keys
- Google Play Store + F-Droid (open source community)

---

## Phase E — Server Tooling Simplified
**August 2026**

**Sprint 18 — One-Click Guardian Installer**
```bash
curl -sSf https://neabouli.github.io/prometheus-/install-guardian.sh | sh
```
- Auto-detects GPU (NVIDIA / AMD / Apple Silicon)
- Downloads LLaMA 3 8B from IPFS (verified via on-chain hash)
- Configures Docker + vLLM automatically
- Installs systemd service for auto-start
- Supported: Ubuntu 22.04+, Debian 12+, Rocky Linux, Windows Server (WSL2)

**Sprint 19 — Validator Dashboard**
- Full web UI for validator operators
- KAS staking interface
- Voting queue with proposal details
- Slashing risk display
- Rewards history and analytics

---

## Phase F — vProgs Integration
**Q4 2026**

vProgs ("verifiable Programs") ships after the DAGKnight deployment.
This is the final architectural milestone described in the whitepaper.

- AI analysis results anchored to L1 via ZK-proofs
- Federated learning auditable on-chain
- CDAG for guardian compute resource tracking
- No more possibility to manipulate AI outputs retroactively

---

## Full Timeline

| Date | Milestone |
|------|-----------|
| March 2026 | All sprints 0-8 accepted. Foundation complete. |
| June/July 2026 | Toccata post-fork verification. Current-Silverscript H-001 vectors checked; validator-state runtime transition gate in progress. |
| Post-verification | First PROM minted. First DEX pool live. |
| June 2026 | Real ZK-proof, P2P network, Phi-3 production |
| June 2026 | LLaMA 3 fine-tuned on security datasets |
| July 2026 | Desktop client beta (Windows / macOS / Linux) |
| **August 2026** | **Full desktop release. One-click Guardian installer.** |
| **September 2026** | **Mobile clients (iOS + Android). Full public release.** |
| Q4 2026 | vProgs integration. Complete architectural vision. |

---

## What This Means Per Device

| Device | How to run Prometheus | When available |
|--------|----------------------|----------------|
| Windows PC | Download installer, run, done | August 2026 |
| macOS | Download DMG, install, done | August 2026 |
| Linux | .deb / .AppImage / Flatpak | August 2026 |
| Ubuntu Server | One-click guardian installer script | August 2026 |
| iPhone / iPad | App Store download | September 2026 |
| Android | Google Play or F-Droid | September 2026 |
| Any VPS | Docker Compose (guardian or validator) | Post-verification |
| Raspberry Pi | ARM Linux client | August 2026 |

---

## Hardware Requirements by Role

| Role | Minimum Hardware | Monthly Cost (est.) |
|------|-----------------|---------------------|
| Light Client | Any device, 4 GB RAM, no GPU | $0 (your existing device) |
| Validator | VPS 2 vCPU / 4 GB RAM + 10,000 KAS stake | ~$20/mo VPS |
| Guardian (8B) | RTX 4070 Ti+, 16 GB VRAM | ~$0 (own hardware) |
| Guardian (70B) | 4x A100/H100, 128 GB RAM | ~$500-2000/mo cloud |
| Honeypot | Any internet-exposed server | ~$5-20/mo VPS |

---

*Daily development. No shortcuts. The fire belongs to humanity.*
