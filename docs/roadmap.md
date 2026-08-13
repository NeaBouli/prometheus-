# Prometheus — Full Deployment Roadmap
*Readiness-gated roadmap; no fixed public-release date is claimed.*
*Last status reconciliation: 2026-08-12 (Europe/Athens project time).*

## Progress Snapshot

| Scope | Estimated complete | Estimated remaining | Current gate |
|-------|-------------------:|--------------------:|--------------|
| H-001 testnet-10 canary | 100% | 0% | Confirmed and independently evidenced; non-promotable canary complete |
| Rollout-capable core network | 84–88% | 12–16% | Production v2 relation/key/ceremony approval and independent cryptographic review, real privacy-reviewed semantic/actionable analysis, operated multi-host v2 transport evidence, six state deployments, PROM emission, real metrics-oracle execution/evidence, public multi-host P2P/rule distribution, production node evidence |
| Complete roadmap vision | 50–55% | 45–50% | Production AI, desktop/mobile clients, installers, operated network, vProgs, plus all core-network gates |

Percentages are scope-weighted engineering estimates. They are not release dates,
financial forecasts, or evidence that any contract is live.

---

## Phase 0 — Foundation (COMPLETE)
**March 2026 · All sprints accepted**

The architecture and tested foundation are complete. Six contract state machines,
the Rust light-client foundation, Python guardian foundation, voting mechanism,
E2E fixtures, documentation, and landing page are in GitHub. Production stubs and
real network operation are tracked in the later phases below.

| Sprint | Deliverable | Status |
|--------|-------------|--------|
| 0 | Kaspa Testnet-10, repo structure, CI/CD | ACCEPTED |
| 1 | 6 Silverscript contracts, 54 tests | ACCEPTED |
| 2 | Rust client: RPC, YARA, ZK stub, KRC-20 | ACCEPTED |
| 3 | Phi-3 wrapper, anomaly detection, Fed-DART | ACCEPTED |
| 4 | Guardian analyzer, local vLLM runtime, and canonical membership source | CORE ACCEPTED / GH-147 MEMBERSHIP MERGED |
| 5 | Commit-Reveal voting, bond system, slashing | ACCEPTED |
| 6 | Development-stub E2E lifecycle fixture <60s, Sybil + FP flood tests | ACCEPTED as test foundation; not production evidence |
| 7 | Audit dashboard, README, WHITEPAPER.md | ACCEPTED |
| 8 | CONTRIBUTING.md, 5 wiki guides, landing page | DONE |

---

## Phase A — Post-Toccata Core Integration
**Current phase — readiness-gated**

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
orchestrator, with request hashes bound to the release bundle. Requests use one
of two closed profiles. `full` selects all seven release fixtures and requires
the public metrics-oracle key. `testnet-10-validator-staking-h001` selects only
the H-001 proof fixture, fixes the target to the TLS-only official testnet-10
resolver, omits the oracle key, and can never advance full rollout or metrics
readiness. The seven fixtures are one H-001 encoding/proof fixture plus six
state contracts; H-001 is not a seventh production-state contract. A public deploy
operator procedure converts the verified request set into a deploy checklist
and required public result-evidence contract without accepting keys or raw
transactions. A public orchestrator-result importer converts confirmed external
deploy results into verified `operator_record` receipts without accepting
signing material or raw/serialized transaction fields. A
deployment receipt verifier validates public receipt records against the release
bundle, rejects secret-like and raw/serialized transaction fields, and keeps synthetic CI fixtures separate from real `operator_record`
receipts. A public node/explorer receipt-evidence verifier binds real
`operator_record` receipts to observed public chain data before handoff
readiness can pass. A status staging guard rejects CI fixtures and emits only a manual
status-update draft from verified `operator_record` receipts. A CI-safe operator
handoff builder now packages the release archive, preflight outputs, deploy
requests, optional imported operator receipts, receipt checks, optional public
receipt evidence, metrics report
preflight, unsigned oracle request, deploy/oracle operator procedures, optional
external-operator capability verification, optional verified oracle tx result,
and optional public oracle tx evidence into one public handoff directory while preserving the real blocker list. A separate
metrics-oracle report preflight validates public `reportMetrics` payloads, an
unsigned oracle tx-request builder binds those payloads to the
GovernanceAutoTuning artifact hashes for external assembly, an external
oracle-operator procedure defines the public signing/broadcast checklist and
required result evidence, and a public tx-result verifier checks confirmed
transaction records against the request and release bundle without accepting
signing material or raw transaction payloads. A public tx-evidence verifier
binds verified metrics-oracle transaction results to public node/explorer
snapshots before handoff readiness can pass. A metrics-oracle status staging
guard emits only a manual status-update draft from verified public tx results
and does not write status files. A public external-operator capability verifier
binds capability records to the deploy/oracle procedures while its verifier
rejects secret-like fields and raw transactions and performs no signing,
deployment, broadcast, or status writes. The deploy capability must also attest
the official SilverScript covenant-genesis profile: transaction version 1,
funding-input compute budget 10, contextual storage mass, P2SH from the compiled script,
official covenant-ID derivation from the funding outpoint plus unbound outputs,
and funding-input binding after ID derivation.
The repository-owned `prometheus-silverc-deployer` now executes that genesis
profile: it assembles the transaction, exports only the 32-byte digest for
external BIP340 signing, verifies the returned signature and complete
transaction, or canonically imports a plain public signature while deriving all
response fields from the validated request and rejecting path collisions before
output. It revalidates the exact live funding UTXO, broadcasts, and observes
the covenant output. Its funding-free TLS-only official-resolver probe now
confirms a synced, UTXO-indexed post-Toccata testnet-10 node while preserving
the mandatory funding-bound preflight. Public H-001 funding and the schema-v2
request/digest were refreshed from exact main `48b3b74` on 2026-08-04; the live
UTXO remained unspent/non-coinbase and the archive, request, and two
signing-request builds stayed byte-identical to the accepted `205e1ca`
baseline. PR #150 published the refresh as exact main `9854c5e`; CI
`30866401314`, Security `30866401257`, and Pages `30866400606` pass on that
commit. The H-001 Testnet-10 canary subsequently completed external signature,
operator verification, exactly one journaled broadcast, confirmation, a public
`operator_record` receipt, and independent node/REST evidence on 2026-08-12.
A public release-hardening evidence verifier binds successful CI, Pages,
branch-control, rollback, and release-note checks to the exact release commit
without querying GitHub, accepting credentials, changing repository settings,
or touching chain material.
A release-readiness auditor now checks the generated handoff package, required
files, component summaries, safety flags, and JSON secret/raw-transaction
hygiene before any rollout claim. The remaining deployment blockers are the six
state-contract deployments, the externally signed keyless metrics-oracle
transition with confirmed successor evidence, production proof and privacy
review, production semantic/actionable analysis and transport, multi-host
operation, and public release-hardening evidence for the exact rollout commit.

**Sprint 9 — Contracts Live + Real ZK-Proof**
- Keep current-Silverscript runtime and release-bundle manifest gates green
- Keep both closed deployment profiles manifest-bound and fail-closed
- Keep the completed non-promotable `ValidatorStakingH001` Testnet-10 canary evidence reproducible
- Preserve the confirmed public P2PK funding, deployer identity, BIP340 verification, receipt, and independent evidence bindings without publishing signing material
- Preserve all seven-fixture, metrics-oracle, and release-hardening gates after the canary; canary success is not rollout readiness
- Keep release-bundle deploy preflight green
- Keep the generated deploy operator runbook green and free of signing material
- Keep the keyless genesis deploy request set green and free of signing material
- Keep the keyless genesis operation procedure green and free of signing/raw transaction material
- Keep public orchestrator-result receipt import green and free of signing/raw transaction material
- Keep deployment receipt verification green and free of signing/raw transaction material
- Keep public receipt-evidence verification green and free of secrets/raw transaction material
- Keep deployment status staging guarded against CI fixture receipts
- Keep the generated operator handoff package green and free of signing material
- Keep the release-readiness audit green and blocked until real external evidence exists
- Keep the metrics-oracle report preflight green and free of signing material
- Keep the metrics-oracle request builder and keyless Rust transition operator green and free of private signing material
- Keep the keyless oracle operation procedure and Rust transition operator green and free of private signing/raw transaction material
- Keep external-operator capability verification green and free of secrets/raw transaction material
- Keep public oracle tx-result verification green and free of signing/raw transaction material
- Keep public oracle tx-evidence verification green and free of secrets/raw transaction material
- Keep public oracle status staging guarded against blocked requests, secrets, and raw transactions
- Keep public release-hardening evidence verification green and bound to the exact release commit
- Keep the keyless Toccata-v1 genesis operator tests, deterministic public vectors, public-file handoff, CLI secret-boundary checks, contextual storage-mass commitment, exact live funding-UTXO checks, fee caps, and broadcast acknowledgement gates green
- Preserve the confirmed H-001 Testnet-10 canary receipt/evidence and keep it non-promotable for full rollout or metrics readiness
- Compile and deploy all six state contracts to Kaspa Mainnet only after the full seven-fixture verification path passes; H-001 remains a proof/canary fixture
- Merged and exact-main-verified in GH-63: manifest-pinned active-KIP-16 BN254/Arkworks Groth16 engine plus bounded owner-aware adapter/service; production relation/VK/vector approval and installation remain
- Implement PROM emission contract (minting logic)
- Deploy first KAS/PROM liquidity pool on Kasplex DEX
- Start 10 team-operated Guardian + Validator nodes

**Sprint 10 — Real KRC-20 Reader + P2P Network**
- KRC-20 UTXO queries for "PROM-RULES" tick (real on-chain reads)
- Rule content download from IPFS via CIDv1
- Merged/exact-main verified: GH-42 Guardian ballot carrier has direct QUIC request/response, static peers, bounded resources, owner-only local collector ingress, cancellation-safe concurrent swarm progress, and relay/AutoNAT/DCUtR behaviours
- Merged/exact-main verified in GH-44: atomic owner-only persistent transport identity, strict bounded direct/relay/AutoNAT routes, data-minimal health events, and a bounded relay service
- Merged and exact-main-verified GH-48: strict Guardian/relay process roles, owner-only local submission, bounded JSON readiness/health, graceful signal drain, and separate-process same-host relay delivery/cleanup evidence
- Merged/exact-main-verified GH-52 adds relay-only canonical advertised IP/UDP/QUIC bootstrap routes, bind/advertise separation, and path-free operator events; configured routes are not reachability or authorization proof
- Merged/exact-main-verified GH-55 adds a separate canonical bounded ThreatHint transport core and development-only Light Client builder
- Merged/exact-main-verified GH-58 adds separate owner-only verifier IPC, trusted context binding, persistent freshness/replay admission, and an atomic durable analyzer outbox; unavailable production Groth16 verification remains fail-closed as `busy`
- Merged and exact-main-verified GH-63 adds real manifest-pinned Groth16 verification aligned with active KIP-16, strict key/proof parsing, complete semantic ThreatHint binding, and a bounded owner-aware service
- Merged and exact-main-verified GH-74 adds a bounded digest/network/time-bound outbox-to-analyzer adapter; hash-only ThreatHint v1 is consumed as an exact zero-confidence, no-rule, non-submittable result without invoking LLM or YARA generation
- Merged and exact-main-verified GH-77 isolates failed jobs inside each bounded analyzer drain, preserves them as pending, lets later safe jobs progress, and emits only data-minimal fixed failure metadata
- Merged and exact-main-verified GH-82 freezes a Threat Observable v2 draft with separate artifact hash and observable commitment, strict canonical bounds, deny-by-default disclosure classes, and exact non-claims
- Merged and exact-main-verified GH-86 adds isolated Rust/Python canonical bundle validators and one shared byte-exact valid/invalid corpus; no v1, P2P, proof, analyzer, committee, IPFS, chain, or public-rule wiring is introduced
- Merged and exact-main-verified GH-90 adds one local Rust `file_sha256` producer from exact caller-supplied bytes plus typed scope, with Python validation of shared vectors; it adds no path API, transport authorization, external provenance, privacy approval, or proof binding
- Merged and exact-main-verified GH-94 adds one local Rust `byte_pattern` producer from exact caller-supplied bytes, checked offset, boolean wildcard mask, and typed scope, with mandatory local-only `review_required_v1` and Python validation of shared vectors; it adds no pattern/path API, transport authorization, external provenance, privacy approval, or proof binding
- Merged and exact-main-verified GH-103 adds one bounded local Rust Linux ELF `api_import` producer from exact bytes plus a checked sorted/deduplicated import index; parser input is capped at 16 MiB/4096 dynamic symbols, scope is derived internally, every result is `review_required_v1`, and Python independently parses shared exact-byte vectors; no path/string/generic builder, transport authorization, external provenance, privacy approval, or proof binding is added
- Merged and exact-main-verified GH-121 adds the same isolated `api_import` boundary for PE32/PE32+ exact bytes; 16 MiB, 4096-import-descriptor, and 4096-thunk-entry limits, fail-closed ordinal/grammar checks, internally fixed `windows`/`pe`, architecture-specific Rust coverage, and independent Python parsing of a synthetic PE32+ vector are complete; library names never become observables and no path/string/generic, transport, proof, analyzer, wallet, chain, or promotion behavior is added
- Merged and exact-main-verified GH-107 adds matching local Rust/Python verification of one canonical, maximum-one-hour BIP340 approval statement bound to the exact review-required bundle, separately trusted approver key, recipient-scope digest, network, report nonce, and separately trusted current time that must never be attacker-controlled; it adds no signer, replay ledger, transport, promotion, disclosure, analyzer, proof, wallet, or chain action
- Merged and exact-main-verified GH-111 adds local durable consumption through one owner-only fixed network/approver-key/recipient-scope policy, same-call verification, atomic approval-ID and authority-nonce persistence, persistent clock high-water, and restart/concurrency/lock/path hardening; it adds no pairing, promotion, analyzer, outbox, wallet, or chain action
- Merged and exact-main-verified GH-114 adds isolated local Rust/Python canonical ThreatHint v2 statement parsers and one shared exact-byte corpus, binding separate artifact hash and observable commitment plus confidence, disclosure class, nonce, time, and separately trusted network under a new digest; it adds no relation, proof acceptance, pairing, transport, analyzer, wallet, or chain action
- Merged and exact-main-verified GH-117, not production-deployed: strict Rust/Python ThreatHint-v2 proof-envelope and `RelationManifest-v2` parsers plus an atomic raw-manifest-anchor/network/domain/public-input compatibility binding; Groth16 verification, approved artifacts, transport, analysis, promotion, and rollout remain separate gates
- Merged and exact-main-verified GH-117, not production-deployed: silent Rust `verify-v2` owner-loads manifest/relation-source/verifying-key bytes, checks exact size/hash/canonical BN254 encodings, and verifies only binding-derived inputs; all generated relation/key/proof fixtures are test-only, no proving key is loaded, and production artifact/ceremony approval plus atomic acceptance remain open
- Merged and exact-main-verified GH-117, not production-deployed: an owner-only read-only v2 preflight pins network/approver/scope/manifest anchors, derives the statement only from the bound envelope, and verifies bundle/approval compatibility without proof verification, approval consumption, SQLite mutation, disclosure authority, or operational side effects
- Merged and exact-main-verified GH-117, not production-deployed: a POSIX-only Guardian verified-preflight service owner-pins the absolute Rust verifier by exact SHA-256, reuses the preflight policy network and manifest anchor, runs approval/privacy checks first, and sends the same envelope bytes to `verify-v2` under bounded, scrubbed, shell-free, fail-closed process control; its receipt is data only and no SQLite access or approval consumption occurs
- Merged and exact-main-verified GH-117, not production-deployed: a raw-input-only Guardian acceptance service proves exact policy identity before ledger creation, runs verified proof/privacy preflight first, and binds approval ID plus observable commitment before final durable consumption; failed verification never consumes or advances ledger time
- Merged and exact-main-verified GH-117, not production-deployed: an owner-only exact-schema promotion boundary requires review-required disclosure, exact platform/format, allowed observable kinds, and a count cap before forwarding the same raw wires into atomic acceptance; rejection never reaches proof verification or the ledger, while success remains restricted local data
- Merged and exact-main-verified GH-117, not production-deployed: an owner-only retention policy declares the exact recoverable local bundle form, allowed durable kinds, pending cap, and retention cap without creating a queue or effect
- Merged and exact-main-verified GH-117, not production-deployed: enforceable authority/privacy governance binds network, key, scope, epoch/window, same-Guardian recipient semantics, denied external disclosure, and explicit per-kind risk decisions; all three policy digests and authority state pin or advance atomically with valid consumption
- Merged and exact-main-verified GH-117, not production-deployed: governed schema v4 binds canonical statement/digest, trusted nonce, canonical bundle, approval, lease and retention; atomic completion stores one canonical non-actionable result before deleting work. The bounded worker uses only a deterministic test analyzer and has no LLM/YARA, actionable rule, transport, publication, chain, reward, deployment, or external effect
- Merged and exact-main-verified GH-152, not production-deployed: governed schema v5 permanently enforces one-to-one-to-one statement-digest, approval-ID and observable-commitment pairing across outbox/result retention; v4 migration requires empty outbox and result tables, preserves authority/high-water/consumption state, and fails closed unchanged for any retained work or result
- Merged and exact-main-verified GH-155: Guardian sidecar process integration tests serialize shared cases, bound diagnostics and waits, coordinate EOF/ACK shutdown, and deterministically kill and reap a child on timeout; this is test reliability only and changes no rollout percentage or production behavior
- Merged and exact-main-verified GH-167 adds the bounded repository ThreatHint-v2 transport substrate: one shared exact Rust/Python payload corpus, independent `/prometheus/threat-hint/2.0.0` channel, trusted-network parsing before owner-only IPC, trusted session/time resolution before governed promotion, strict acknowledgements and shared budgets, plus separate-process same-host evidence. PR #168 published exact main `7c62608`; CI `31645624623`, Security `31645624601`, and Pages `31645623547` pass. No production proof approval, semantic/actionable analysis, disclosure, public multi-host claim, LLM/YARA, wallet, chain, reward, or deployment effect is added
- Merged and exact-main-verified GH-170 replaces substring-only candidate-rule checks with an exact-pinned, compile-only YARA-X boundary: one bounded ASCII rule, no imports/includes/modules, zero compiler errors or warnings, and no scan or external effect. PR #171 published exact main `8d8e29c`; CI `31650123073`, Security `31650123055`, and Pages `31650122593` pass. This is structural validation only; semantic/adversarial quality, actionable analysis, and production authority remain open
- Merged and exact-main-verified GH-173: the governed worker deterministically derives one memory-only YARA draft from already approved local `api_import` and `byte_pattern` observables, compile-checks it through GH-170, and atomically stores only exact bindings, per-kind counts, a nonce-bound candidate-binding SHA-256, and compile status in a non-actionable v2 result while preserving v1 reads. PR #174 published exact main `1107b11`; CI `31654308969`, Security `31654308964`, and Pages `31654308875` pass. No source, model output, confidence, `should_submit`, scan, disclosure, publication, chain, reward, deployment, semantic-quality claim, or production authority is added
- GH-177 local candidate, not merged or production-deployed: one isolated offline evaluator scans only 20 bounded deterministic synthetic in-memory buffers with one fixed GH-173-shaped rule under pinned `yara-x==1.4.0`. Its canonical authority-`none` report binds exact corpus, policy, evaluator bytes, engine version, rule digest, confusion counts, and precision/recall/specificity. Local review and complete gates pass. No real sample, file/process scan, governed worker/outbox/result wiring, model, disclosure, submission, wallet, chain, reward, deployment, real-world semantic-quality claim, or production authority is added
- Pending: production authority/key/recipient attestation, independent approval of the v2 relation/production proof artifacts and cryptographic review, real privacy-reviewed semantic/actionable analysis, and operated multi-host v2 transport evidence
- Proven on an isolated three-node harness: relay reservation/delivery, AutoNAT state, DCUtR relay fallback, and disconnect handling; real two-host operation remains pending
- Pending: public operated relay/NAT infrastructure and broad discovery; mDNS remains excluded while its compatible dependency path has unresolved RustSec advisories
- Light Client ↔ Guardian communication over P2P
- Guardian ↔ Validator communication over P2P

**Sprint 10B — Guardian Decentralization**
- Implemented: local fail-closed 8B-first router with exact 70B escalation below confidence `0.70`
- Implemented: threat-hash binding, finite confidence checks, strict submission types, and unchanged `0.85` submission threshold
- Implemented: separate bounded model confidence assessment with an exact closed JSON schema and integer basis points; malformed output fails closed and the former indicator-count/YARA-shape heuristic is removed
- Merged/exact-main verified GH-138: internally SHA-256-consistent deterministic 24-case synthetic confidence evaluation with the unchanged `8500`-bps threshold, confusion matrix, exact-ratio precision/recall, Brier score, and ten-bin expected calibration error; evidence is offline-only and non-authorizing, and the co-versioned manifest is not an external tamper anchor
- Merged/exact-main verified GH-141: literal-loopback, proxy-independent local model capture binds the canonical corpus, public served-model ID, caller-supplied artifact digest, and pinned prompt specification; atomic owner-only predictions can be re-evaluated offline only as `local_model_candidate_only` with no production authority
- Merged/exact-main verified GH-161: the preferred capture mode derives a canonical manifest digest from exact regular-file bytes in one bounded trusted-owner local model directory and re-verifies the directory before model adapter construction; the old caller digest remains legacy-only, while upstream authenticity and live served-model identity remain unproven. PR #162 merged as `d468426`; CI `31340112225`, Security `31340112204`, and Pages `31340111625` pass
- Merged/exact-main verified GH-144: the official vLLM image is pinned by version and registry digest; 8B and opt-in 70B services use loopback-only publication, local read-only model weights, forced offline resolution, non-root execution, an internal network, bounded resources, and structured CI validation. PR #145 merged as `95d05cc`; CI `30858991436`, Security `30858991557`, and Pages `30858990507` pass. No image/model pull, live inference, independently verified artifact provenance, quality evidence, calibration, or production authority is included
- Implemented: local 5+ Guardian complete-ballot validator with canonical candidate/snapshot commitments, strict majority, and conservative confidence
- Merged/exact-main verified GH-147: an exact schema-v1 source loaded through an owner-only, no-symlink, bounded, descriptor-verified file boundary binds 5–1024 sorted unique Guardian IDs one-to-one to public BIP340 keys, fixed 8B tier, and model-artifact digests. The validated source derives both existing views: its exact-byte digest pins the membership snapshot, while validated member fields derive signer mappings. PR #148 merged as `aeecffb`; CI `30863940497`, Security `30863940502`, and Pages `30863940053` pass. This proves structural assignment consistency only, not source authority, key ownership/rotation, Sybil resistance, chain attestation, or production readiness
- Implemented: transport-neutral BIP340 ballot intake with exact key/session/context binding, strict canonical envelopes, freshness checks, and owner-only SQLite replay/equivocation protection across restarts and concurrent submissions
- Merged/exact-main verified: real Guardian ballot transport over direct QUIC/libp2p request/response with exact 8192-byte-bounded frames, static peers, resource caps, owner-only AF_UNIX collector integration, and cancellation-safe concurrent processing
- Pending: an independently reproducible real 8B/70B candidate run, upstream-authenticated and live-served-model provenance, real adversarial semantic-quality evaluation, production calibration evidence, and authorization
- Merged/exact-main verified: persistent transport identity, isolated operated relay/AutoNAT/DCUtR evidence, and explicit bootstrap configuration; real two-host evidence remains
- Pending: broad discovery, externally trusted membership authority, key ownership/rotation, Sybil resistance, and on-chain ensemble attestation
- Pending: reviewed Guardian pooling and final Sybil-resistance design

**Sprint 11 — Real Phi-3-mini Integration**
- Download Phi-3-mini 3.8B from Microsoft HuggingFace
- 4-bit quantization via ONNX Runtime
- Replace entropy heuristic with real inference in phi3.rs
- Model update mechanism: IPFS distribution + on-chain hash verification
- Test: does Phi-3 detect known malware samples?

---

## Phase B — Guardian + Validator Production
**After the core-network rollout gates pass**

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
**After production AI, ZK, P2P, and rule distribution pass**

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
**After the desktop beta and mobile security review pass**

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

## Experimental Miner Companion Foundation
**July 2026**

- Opt-in `prometheus-client miner-companion` sidecar
- Strict TOML preflight with credential-free loopback Testnet-10 wRPC
- Local BlockDAG health observation only
- No Stratum interception, miner firmware changes, host scanning, reporting, rewards, validator mode, or honeypot mode
- Production expansion waits for real Phi-3, ZK proofs, canonical rule distribution, reviewed transport/privacy scopes, and enforceable resource controls

## Phase E — Server Tooling Simplified
**After production Guardian and Validator operation is proven**

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
**After upstream DAGKnight/vProgs capability is stable and independently verified**

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
| August 2026 | Toccata runtime/release gates plus the non-promotable H-001 Testnet-10 canary are complete: external signature, full verification, one-shot broadcast, confirmation, operator receipt, and independent evidence pass. |
| After H-001 evidence | Deploy the remaining six state contracts only through separately approved operations, execute the metrics-oracle transaction, and complete exact-commit release hardening. |
| After core-network rollout | Approved production Groth16 artifacts, PROM emission, P2P rule distribution, production Phi-3, and operated Guardian/Validator network. |
| After production AI/P2P | Desktop client beta and signed installers for Windows, macOS, and Linux. |
| After desktop beta | Mobile clients for iOS and Android, subject to platform security review and store approval. |
| After upstream readiness | vProgs integration and complete architectural vision. |

---

## What This Means Per Device

| Device | How to run Prometheus | When available |
|--------|----------------------|----------------|
| Windows PC | Download installer, run, done | After production AI/P2P and desktop beta gates |
| macOS | Download DMG, install, done | After production AI/P2P and desktop beta gates |
| Linux | .deb / .AppImage / Flatpak | After production AI/P2P and desktop beta gates |
| Ubuntu Server | One-click guardian installer script | After production Guardian operation is proven |
| iPhone / iPad | App Store download | After desktop beta and mobile security review |
| Android | Google Play or F-Droid | After desktop beta and mobile security review |
| Any VPS | Docker Compose (guardian or validator) | After core-network rollout evidence |
| Raspberry Pi | ARM Linux client | After production Light Client resource validation |

---

## Hardware Requirements by Role

| Role | Minimum Hardware | Monthly Cost (est.) |
|------|-----------------|---------------------|
| Light Client | Any device, 4 GB RAM, no GPU | $0 (your existing device) |
| Validator | VPS 2 vCPU / 4 GB RAM + 10,000 KAS stake | ~$20/mo VPS |
| Guardian (8B) | NVIDIA GPU with 24 GB VRAM | ~$0 (own hardware) |
| Guardian (70B) | 4x A100/H100 80 GB, 256 GB system RAM | ~$500-2000/mo cloud |
| Honeypot | Any internet-exposed server | ~$5-20/mo VPS |

---

*Daily development. No shortcuts. The fire belongs to humanity.*
