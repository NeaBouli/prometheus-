# Prometheus Architecture Map

Baseline: exact `origin/main` `32ca5f121855506a5618e3ef1bc803545c425ca1` (2026-09-27).
Method: skill `architecture-map` — every hop below was opened in source before it was
drawn. Audit reports and status claims are treated as claims; each module row links its
source evidence. No product code was changed.

State labels (brief `plan-arch-map`): `built` = the hop runs in code today;
`partial` = the symbol exists but is a stub, fail-closed placeholder, or lacks its
production input; `open` = the Grundidee names it and no symbol exists;
`blocked` = built software waiting on an external gate (signatures, review, operation);
`target` = whitepaper/spec architecture with no current code claim.

## 1. Grundidee

- Prometheus is an open protocol project targeting a decentralized, AI-assisted
  threat-intelligence network on Kaspa; no production network operates today
  (`README.md:5`, `README.md:15`).
- Actors: Light Clients detect and report, Guardian nodes analyze and vote,
  Validators vote via commit-reveal and stake KAS; Kaspa L1 stores canonical protocol
  state (`docs/agent-bridge/CODEX_BRIDGE.md` §3, `modules/validator-node/src/lib.rs:1-5`).
- Result: YARA rules proposed and stored through RuleStorage; Guardian reputation is
  canonical Kaspa L1 state, never a badge/NFT/PROM balance (`README.md:110`,
  `CODEX_BRIDGE.md` §13).
- Boundary: current execution is owner-operated development foundation; exactly one
  confirmed, non-promotable H-001 Testnet-10 canary exists (`README.md:127`,
  `memory/STATUS.md:460-473`, `docs/evidence/gh-9-h001-canary-confirmed-2026-08-12.json`).
- Invariant: validators stake KAS, never PROM; PROM minting/emission is not implemented
  (`README.md:104-110`).
- Contradiction: the whitepaper lifecycle target (< 60 s) is supported only by a
  same-host development-stub fixture; it remains an unproven public target
  (`memory/STATUS.md:39`, `memory/STATUS.md:687`).

## 2. Spur — ThreatHint v1 submission (the one user-walkable built path)

Command: `cargo run -p prometheus-client -- threat-hint submit --config C --hint H`
(Development/Testnet-10 only; Beta/Mainnet reject before network activity).

| # | Hop | Datum on the edge |
|---|-----|-------------------|
| H1 | `modules/client/src/main.rs::ThreatHintCommand::Submit` → `modules/client/src/network/p2p.rs:265 ThreatHintSubmitConfig::submit` | owner-only TOML config + canonical hint file (≤ 2048 B) |
| H2 | `network/p2p.rs::submit` → `modules/guardian-p2p/src/lib.rs::GuardianP2p` | dial-only QUIC, one static peer, `/prometheus/threat-hint/1.0.0` (`lib.rs:59`), `ThreatHintBytes` |
| H3 | `GuardianP2p` inbound handler → `modules/guardian-p2p/src/threat_hint_ingress.rs::UnixThreatHintIngress::forward` | exact canonical bytes, shared global admission cap |
| H4 | `UnixThreatHintIngress::forward` → `modules/guardian-node/jaeger/threat_hint_service.py::run_service` (`ThreatHintIngressServer`) | 4-byte-length AF_UNIX frame, owner-only socket, peer-UID check |
| H5 | `threat_hint_service.py` → `jaeger/threat_hint_ingress.py::ThreatHintIngress` → verifier subprocess `modules/threat-proof/src/main.rs::Command::Verify` | schema-v1 reparse, freshness (300 s / 30 s skew), replay policy; manifest-pinned KIP-16 Groth16 verify, silent exit 0/1/2/3; default verifier unavailable → fail-closed |
| H6 | `ThreatHintIngress` → SQLite replay ledger + analyzer outbox (`VerifiedThreatHintJob`) | one atomic `BEGIN IMMEDIATE` commit: replay identities + exactly one outbox job |
| H7 | `jaeger/threat_hint_adapter.py:156 ThreatHintAnalyzerAdapter::drain_once` → `jaeger/analyzer.py::Analyzer.process_verified_threat_hint` | `VerifiedThreatHint` (hash commitment + category, **no indicators**) → `AnalysisResult` (confidence 0.0, no rule, `should_submit=false`) → mark-delivered |
| H8 | ACK return: Python ingress ACK → `UnixThreatHintIngress` → `GuardianP2p` → client | digest-bound ACK ≤ 384 B; client maps accepted/duplicate/rejected/busy/transport-failure; no retry, no persistence |

Evidence: GH-226 merged as exact main `6c39af5` (PR #227); GH-229 operator-attested
controlled two-host run, both ends non-authorizing `rejected`
(`docs/evidence/gh-229-controlled-two-host-2026-08-27.json`); GH-55/GH-58/GH-63/GH-74/
GH-77 merged and exact-main verified (`memory/STATUS.md:924-1040`).

Sibling built flows (same modules, drawn in `map.puml`):

- RuleSync (GH-190…GH-216): `main.rs::RuleSyncCommand::Run` → `rule_sync_cli.rs` →
  `blockchain/rule_coordinator.rs::RuleCoordinator` → wRPC UTXO observation (GH-203) →
  local IPFS fetch (GH-205) → durable checkpoint (GH-207) → atomic scanner replacement.
- Guardian ballot (GH-36/39/42/44/48/52): `guardian-p2p main.rs::Command::Run/Submit` →
  `service.rs::run_service` → `/prometheus/guardian-ballot/1.0.0` →
  `ingress.rs::UnixBallotIngress` → `jaeger/ballot_ingress.py` → `signed_ballots` →
  `ensemble.py::EnsembleVoter`.
- ThreatHint v2 (GH-114/117/152/167/173): `network/p2p.rs:666 submit_v2` →
  `/prometheus/threat-hint/2.0.0` → `threat_hint_v2_ingress.rs` →
  `jaeger/threat_hint_v2_transport.py` reparse → `threat_hint_v2_promotion.py::promote`
  → `threat_hint_v2_acceptance.py::accept` (verified preflight + `verify-v2` subprocess +
  durable approval consumption) → governed outbox → `observable_analysis_worker.py` →
  `observable_semantic_draft.py` (non-actionable draft, GH-170 compile-only check).
- Deploy path (GH-4/GH-25): `modules/silverc-deployer/src/main.rs::Cli` →
  `lib.rs` genesis / `oracle.rs` reportMetrics transition → external BIP340 signature
  (outside the repo) → journaled one-shot broadcast → covenant UTXO observation.

## 3. Module

| Modul | Eine Aufgabe | Einstieg | Stand |
| --- | --- | --- | --- |
| `modules/client` (CLI, wRPC, rule sync, hint submit) | Light Client: Kaspa wRPC connection, RuleStorage sync, dev scanner, ThreatHint v1/v2 senders, miner companion | `modules/client/src/main.rs::Cli` | built (Development/Testnet-10 boundaries only) |
| `modules/client` AI + ZK stubs | Phi-3 detection, Fed-DART, client proofs | `client/src/ai/phi3.rs`, `ai/detection.rs`, `ai/federated.rs`, `network/zk_proof.rs` | partial (stubs require explicit Development; missing/invalid selection uses restrictive Beta, not deployment authority); real inference/proving: open |
| `modules/client` dev scanner | Bounded custom byte-pattern matching | `client/src/security/scanner.rs::YaraScanner` | partial (built as dev tool; not a YARA engine; production scan engine: open) |
| `modules/guardian-p2p` | Opaque ballot + ThreatHint v1/v2 transport, persistent identity, relay/AutoNAT, operated sidecar | `modules/guardian-p2p/src/lib.rs::GuardianP2p`, `src/main.rs::Cli` | built (same-host + one controlled two-host run); public multi-host: blocked |
| `modules/guardian-node` hint pipeline (jaeger) | Verifier ingress, replay/outbox durability, v1 adapter, v2 promotion/acceptance/worker | `jaeger/threat_hint_service.py::main`, `jaeger/threat_hint_v2_acceptance.py` | built (local, fail-closed); production proof acceptance: blocked; actionable analysis: open |
| `modules/guardian-node` voting (jaeger) | Ballot intake, ensemble voter, canonical membership source + owner-local transition authority | `jaeger/ballot_ingress.py`, `jaeger/ensemble.py`, `jaeger/guardian_membership_transition.py` | built (owner-local); external membership authority/Sybil/L1 attestation: blocked |
| `modules/guardian-node` legacy analyzer | LLM (vLLM 8B/70B) analysis + YARA generation + hybrid router | `jaeger/analyzer.py::Analyzer`, `jaeger/hybrid_router.py` | partial (machinery + hardened runtime; no live-model evidence; must not become v2 authority) |
| `modules/threat-hint` | Canonical v1/v2 schemas, observable producers (ELF/PE/sha256/byte-pattern), approval, endpoint-observation parser | `modules/threat-hint/src/lib.rs` | built (local boundaries, shared Rust/Python corpora) |
| `modules/threat-proof` | Manifest-pinned KIP-16 Groth16 verification (v1 + v2) | `modules/threat-proof/src/main.rs::Cli` | built with test artifacts; production relation/keys/ceremony: blocked |
| `modules/validator-node` | Commit-reveal voting + slashing state machines | `modules/validator-node/src/lib.rs` | built (state machines); operated validator network: open |
| `modules/contracts` (legacy `.ss`) | Historical Silverscript contracts | `modules/contracts/*.ss` | built (accepted legacy; superseded, do not extend) |
| `modules/contracts/silverc` | Seven current-Silverc fixtures with compile/ABI/runtime gates plus a reviewed compiled-artifact expectation (`expected-compiled-artifacts.json`, GH-283, stand-in branch) | `modules/contracts/silverc/*.sil` | built; six state deployments + oracle execution: blocked; contract bundle v2 proposed (`ms-b-contract-decisions.md`) |
| `modules/silverc-deployer` | Keyless Toccata-v1 genesis + reportMetrics operator | `modules/silverc-deployer/src/main.rs::Cli` | built (H-001 canary executed once, non-promotable); remaining real execution: blocked on external signatures |
| `modules/web` | Static public status surface (GitHub Pages root pages); fabricated audit dashboard removed (GH-273); shared tokens/chrome in `assets/site.css`, WCAG AA text gated by `scripts/verify_site_css.py`, service worker retired (GH-275/278, stand-in branch) | `index.html` + sibling root pages | built |
| `scripts/` | Release tooling: artifacts, requests, receipts, evidence, readiness, hygiene | `scripts/README` n/a — see `scripts/*.py` | built |
| CI runner compatibility | Explicit Ubuntu24.04 OS baseline for the existing hosted CI/Security jobs; floating-label drift rejected by the Toolchain Pin Policy registration tests | `.github/workflows/{ci,security-audit}.yml` -> `scripts/test_toolchain_pins.py::CiRegistrationTest` | configured; future OS upgrades require separate compatibility evidence (not an immutable image lock) |
| Target: client AI/inference | Real Phi-3-mini 4-bit ONNX, Fed-DART gradients-only | — | target (open) |
| Target: endpoint detection (GH-258/261) | Observe-only → warn-only → operator-confirmed containment → separately approved automation | `modules/threat-hint/src/endpoint_observation.rs` (first data contract built); `scripts/verify_endpoint_producer_privacy_gate.py` + `docs/evidence/endpoint-producer-privacy-threat-model-v1.json` (GH-267 pre-producer gate, rebased PR #268 candidate, not on main) | target; producers require independent privacy/threat-model review first |
| Target: PROM emission, IPFS distribution, public multi-host, mobile (Flutter), Tauri UI | Tokenomics and distribution layers | — | target (open) |

## 4. Verdrahtung (one sentence per arrow)

- Client → Guardian P2P: the client reuses the reviewed guardian-p2p transport
  dial-only with one static peer and no listeners (`modules/client/src/network/p2p.rs:1-25`).
- Guardian P2P → Python ingress: exact wire bytes cross the trust boundary only through
  owner-only AF_UNIX frames with peer-UID checks; `PeerId` is transport metadata, never
  membership (`threat_hint_ingress.rs:1-7`, `lib.rs:2-6`).
- Python ingress → proof verifier: verification runs as a hash-pinned, shell-free,
  bounded subprocess with silent exit codes; no approved production artifacts ship, so
  the default is fail-closed (`threat_hint_service.py:18-27`, `threat-proof/src/main.rs:43-57`).
- Ingress → outbox: `accepted` means replay identities plus exactly one analyzer job
  committed atomically; exact retries are duplicates across restart (`memory/STATUS.md:946-968`).
- Adapter → analyzer: v1 carries a hash commitment only, so the analyzer receives a
  type with no indicator field and must return the zero-confidence non-actionable
  result (`analyzer.py:47-55`).
- v2 transport → promotion → acceptance: the untrusted frame is reparsed against a
  trusted network, promotion policy runs before any verifier call, and durable approval
  consumption is the final state-changing step (`threat_hint_v2_promotion.py:11-23`,
  `threat_hint_v2_acceptance.py:1-19`).
- Worker → semantic draft: governed v2 observables become one memory-only YARA draft,
  compile-checked without scanning; only bindings, counts and verdict persist
  (`observable_semantic_draft.py:1-30`).
- Deployer → chain: the operator assembles and verifies covenant transactions keylessly;
  only the 32-byte digest leaves the repo for external BIP340 signing; broadcast is
  journaled and one-shot (`silverc-deployer/src/main.rs:8-22`, `README.md:340`).

## 5. Widerspruch und Lücken

- Resolved 2026-09-30 (stand-in branch): the stale GH-272 TODO row is marked done.
- `modules/guardian-node/jaeger/analyzer.py` hosts two tasks: the legacy heuristic
  LLM/YARA pipeline (`ThreatHint` with `indicators`) and the verified v1 path
  (`VerifiedThreatHint` without indicators). Two tasks in one module → two rows above;
  this is a finding, not a rebuild order. The legacy path must not become v2 submission
  authority (`memory/TODO.md:265`).
- `modules/client/src/security/scanner.rs:1` says "YARA-based" while the status table
  correctly records a bounded custom matcher, not a YARA engine — doc drift, dev-only.
- KRC-20: `memory/TODO.md:62` keeps the reader `[~]` while Sprint 2 rows read ACCEPTED;
  consistent only as dev-foundation vs. target — canonical PROM-RULES KRC-20
  orchestration stays target architecture.
- `docs/agent-bridge/CODEX_BRIDGE.md` §1 startflow references
  `$HOME/Desktop/repos/prometheus`; the fleet works in
  `prometheus-master-plan-20260927-wt/*` worktrees — operational doc drift, no code impact.
- Gap: no client-side proof generation exists anywhere (stub only); no automatic rule
  update loop (canonical manifest authority missing); GH-177 quality gate is merged but
  structurally unwired from the v2 pipeline (`README.md:328-330`).

## 6. Duplikate, obsolete Stubs, nicht bauen

Duplicates / superseded paths:

1. Legacy `modules/contracts/*.ss` vs current `modules/contracts/silverc/*.sil` —
   legacy kept for architecture history only (`memory/STATUS.md:660`).
2. `client/src/blockchain/krc20.rs` cache-based pre-Covenant reader vs RuleStorage
   covenant observation/sync (GH-193…GH-213) — pre-Covenant path, do not extend.
3. `client/src/network/zk_proof.rs` stub vs real verification in `modules/threat-proof`
   — the client prover is open work, not a second verifier.
4. `client/src/security/scanner.rs` custom matcher vs pinned `yara-x` compile boundary
   in the Guardian (GH-170) — dev tool vs. validation boundary, different jobs.
5. `client/src/ai/{phi3,detection,federated}.rs` fail-closed stubs vs M5 real inference.

Explicitly not to build (bound decisions):

- Emergency stop / killswitch (`AGENTS.md`, `memory/MEMO.md`).
- Badge/NFT/Kasplex reputation; canonical reputation stays on L1 (`CODEX_BRIDGE.md` §13).
- PROM staking, pre-mine, ICO, passive mining rewards (`README.md:104-110`).
- Actionable v1 analysis or fabricated indicators from hash-only hints (GH-74/GH-82;
  `analyzer.py:47-55`).
- Stratum interception / ASIC firmware in the miner companion (`README.md:42-50`).
- Endpoint response automation (process kill, quarantine, firewall, credential
  rotation, remote commands, deletion, host isolation) — unauthorized (`README.md:80-86`).
- Extending legacy `.ss` contracts or the pre-Covenant KRC-20 path.

## 7. Milestones (ordered; module/hop boundary + dependencies)

| # | Milestone | Module / hop boundary | Depends on |
|---|-----------|------------------------|------------|
| M1 | L1 rollout evidence: six state deployments + confirmed keyless metrics transition with successor evidence | `modules/silverc-deployer` + `modules/contracts/silverc`; hop `main.rs::ReportMetrics*` → `oracle.rs::prepare_oracle_transition` → external BIP340 → `broadcast_*` → `observe_*` | external oracle/sponsor signatures, funded UTXOs, release-hardening evidence (blocked) |
| M2 | Production v2 proof acceptance | `modules/threat-proof`; approve relation source, proving/verifying keys, ceremony + independent crypto review (`memory/TODO.md:261`); existing `threat_hint_v2_acceptance.py` then accepts non-test artifacts | M-review only (blocked) |
| M3 | Privacy-reviewed actionable v2 analysis → RuleStorage proposals | `modules/guardian-node` worker/semantic-draft + new proposal hop to `RuleStorageState`; new explicit high-risk ticket, deterministic result semantics (`memory/TODO.md:265`) | M2 |
| M4 | Guardian decentralization: real two-host+ operation, discovery, trusted membership/key authority, Sybil resistance, L1 attestation | `modules/guardian-p2p` + `jaeger/guardian_membership_*` + L1 `GuardianReputationState` | M1, M2 |
| M5 | Client production sensing: real Phi-3/ONNX, real scan engine, GH-258/261 observation producers (observe-only first) | `modules/client/src/ai/*`, `security/*`, `threat-hint/src/endpoint_observation.rs` | model artifacts, privacy/threat-model review |
| M6 | PROM emission + governance activation | `modules/contracts` (DevIncentivePool/GovernanceAutoTuning) + tokenomics spec | M1–M4 |

## 8. Nächster Schritt — three safe implementation nodes (repo-local, no external gate)

Update 2026-09-30: the three nodes listed on 2026-09-27 (GH-279, GH-280, the
GH-258/GH-261 producer design) are delivered on
`agent/claude/prometheus-standin-20260930`, pending Codex review. Next nodes:

1. **Contract bundle v2** — after Codex accepts
   `docs/architecture/ms-b-contract-decisions.md`: one reviewed revision of
   `modules/contracts/silverc` + deployer profile (H-001 profile stays frozen).
   D5 follow-up: [trusted-source variants and acceptance specification](d5-trusted-source-model.md)
   (K2, 2026-10-10) names this existing plan -> genesis -> state-binding
   boundary. It is a proposal referencing unmerged worker head `3e94ce0`,
   not an activated trust model or independent security acceptance. Historical
   H-001, v1 pins and the closed v2/D5 gates remain unchanged.
2. **Endpoint producer review** — independent privacy review of
   `docs/endpoint-producer-design-v1.md` before any implementation brief.
3. **Toolchain upgrade** — Rusty Kaspa v2.1.0 / SilverScript v1.0.0 once
   upstream SilverScript depends on a rusty-kaspa release tag
   (`.fleet/reports/a8u1-kaspa-silverscript-upgrade-inventory.md`).

## 9. Diagrammdateien

- `docs/architecture/map.puml` — mindmap + component diagram (PlantUML; `plantuml` is
  not installed on this host, so sources only, no SVG render).
- `docs/architecture/main-path.puml` — sequence diagram of the Spur in §2.

The same mindmap as Mermaid (renders without PlantUML):

```mermaid
mindmap
  root((Prometheus: dezentrale KI-Threat-Intelligence auf Kaspa))
    modules/client
      built: main.rs::Cli (miner-companion, rule-sync, threat-hint, threat-hint-v2)
      built: network/p2p.rs::submit / submit_v2 (dial-only QUIC)
      built: blockchain/rule_coordinator.rs::RuleCoordinator (dev)
      partial: security/scanner.rs::YaraScanner (custom matcher)
      partial: ai/phi3.rs, detection.rs, federated.rs (fail-closed stubs)
      open: echte Phi-3/ONNX-Inferenz, Fed-DART, ZK-Prover
    modules/guardian-p2p
      built: lib.rs::GuardianP2p (ballot + hint v1/v2 channels)
      built: transport_identity, relay_service, service.rs::run_service
      blocked: public multi-host operation
    modules/guardian-node (jaeger)
      built: threat_hint_service.py + ingress (reparse, replay, outbox)
      built: threat_hint_v2 promotion/acceptance/worker/semantic-draft
      built: ballot_ingress.py, ensemble.py, membership source/transition
      partial: legacy analyzer/llm/yara (no live-model evidence)
      open: actionable analysis, production authority
    modules/threat-hint
      built: v1/v2 schemas, producers, approval, endpoint-observation parser
    modules/threat-proof
      built: KIP-16 Groth16 verify / verify-v2 (test artifacts)
      blocked: production relation/keys/ceremony
    modules/validator-node
      built: voting/commit, voting/reveal, slashing (state machines)
      open: operated validator network
    modules/contracts
      built: silverc/*.sil (7 fixtures, gates green)
      built: legacy *.ss (history only)
      blocked: six state deployments + oracle execution
    modules/silverc-deployer
      built: keyless genesis + reportMetrics operator; H-001 canary confirmed
      blocked: remaining external signatures/evidence
    modules/web + scripts
      built: public site pages (repo root), release tooling
      removed: fabricated audit dashboard (GH-273)
    target
      open: PROM emission, IPFS distribution, public multi-host
      open: mobile (Flutter), Tauri UI
      open: GH-258/261 endpoint detection (observe -> warn -> contain)
```

2026-10-10 GH275 browser status (main58d742a, owner-local, partial): existing
`modules/web` / public-web -> historical registration/sw.js -> CacheStorage ->
retirement activate/exact-name cleanup/unregister -> actual reload hop tested
with fresh sandboxed Chrome154 and a narrow harness (66 assertions, nine cases).
Historical JS20e8531 unchanged; successful installation is explicitly a
counterfactual root-availability fixture, while actual public root404 replay
independently rejects installation. Current public HTTP replay matches baseline;
no historical live installation or release acceptance is inferred. Evidence:
`docs/evidence/gh-275-browser-retirement-2026-10-10.json`. Core CI/security/live
and independent archival-history gates remain open; product source unchanged.

2026-10-10 GH275 same-hop consolidation: the original separate-helper deviation
is corrected under Core's explicit scope amendment. Sole canonical test entry:
`scripts/browser_retired_service_worker_regression.mjs`; amended superset runtime,
source pins, Git guards and cases unchanged, authored untracked helper removed.
Core reports amended run34026 exit0/all9 cases66 assertions PASS; consolidation
has syntax/exact-body/Git checks only, no additional browser run. Captured
historical repro/negative observations remain immutable; Core owns current
sanitized evidence and committed-head/CI/postmerge acceptance. No product change.
