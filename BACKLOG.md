# prometheus — Backlog

## 🔴 Aktiv (diese Session)
- Latest documented green baseline is exact main `d0f78a9857e654dd487678a031d39ac52a44e0ec`; run `git log --oneline -1` for the current working HEAD.
- Prometheus CI `29464295373`, Security Audit `29464295355`, and GitHub Pages `29464294890` are green for exact main. Current-Silverc CI validates the keyless Toccata-v1 operator, operator runbook, request/receipt/evidence pipeline, release-readiness audit, metrics-oracle handoff, and exact-commit hardening gates.
- Runtime stub gates added for Rust client; current-Silverc contract gates now cover H-001, ValidatorStaking, GuardianReputation, RuleStorage, CommunityDonations, DevIncentivePool, and GovernanceAutoTuning.
- Local current-Silverc release-bundle smoke now compiles all 7 fixtures through pinned upstream `silverc` and writes a deterministic manifest plus optional archive with source/artifact/script hashes; deploy preflight validates the bundle/operator public inputs, emits a Markdown operator runbook, and confirms upstream `silverc` has no network deploy command.
- Deployment receipt verifier validates public receipt records against the release bundle, rejects secret-like fields, and keeps synthetic `ci_fixture` receipts separate from real `operator_record` deployment evidence.
- Public orchestrator-result receipt importer converts confirmed external deploy results into `operator_record` receipts, binds them to the verified request set, rejects secret-like fields, and re-validates the generated receipts before status staging.
- Deployment status staging guard emits a manual status-update draft only from verified `operator_record` receipts and rejects `ci_fixture` evidence before any `memory/STATUS.md` update.
- External deploy request builder emits per-contract public request JSON for an approved orchestrator, rejects credentialed RPC URLs, and does not sign, assemble, broadcast, deploy, or update status files; the request verifier independently checks request-set/per-contract hashes, manifest binding, constructor args, safety flags, and secret-field rejection.
- Public deploy operator procedure converts verified deploy requests into an external deploy checklist and required public result-evidence contract while rejecting keys, raw transactions, signing material, deployment, and status writes.
- Operator handoff builder packages the release archive, deploy preflight, verified deploy request set, deploy operator procedure, optional imported operator receipts, receipt checks, metrics report preflight, unsigned oracle tx request, external oracle operator procedure, optional verified oracle tx result, and optional oracle status draft into a public handoff directory while preserving real blocker status; release-readiness audit validates the handoff package and keeps rollout blocked until external evidence exists.
- Metrics-oracle report preflight validates public GovernanceAutoTuning `reportMetrics` payloads and rejects secret-like fields; unsigned oracle tx-request builder binds public reports to GovernanceAutoTuning artifacts for external assembly/signing; the external oracle operator procedure defines the public signing/broadcast checklist and required result evidence; public oracle tx-result verifier checks confirmed operator records against the request and release bundle while rejecting signing material and raw transaction payloads; public oracle status-draft staging emits manual status-update drafts from verified public tx results without writing status files.
- Sprint 9 tooling is implemented. It remains blocked by the explicitly approved external H-001 signature, verified one-shot canary broadcast/confirmation/evidence, the remaining six state deployments, real metrics-oracle operation, real Groth16/PROM emission/P2P integration, production node evidence, and exact-commit release hardening.
- GH-33 is merged and exact-main verified at `ce1d213`: a local dependency-injected 8B-first/70B-escalation router with exact `0.70` routing, fail-closed safety checks, and unchanged `0.85` submission policy.
- GH-36 local ensemble software is merged and exact-main verified at `f8ebaac`: domain-separated candidate/snapshot commitments, at least five unique 8B members, complete ballots, strict majority, exact `8500`-bps source/approval policy, and conservative confidence pass locally and in protected CI. Trusted membership, signed P2P ballots, replay/Sybil protection, on-chain attestation, and production evidence remain open.
- GH-39 is merged/exact-main verified at `d0f78a9`: the local transport-neutral intake binds each Guardian ID to an exact per-session BIP340 key, verifies strict canonical envelopes and freshness, and uses owner-only SQLite uniqueness plus a monotonic time watermark for restart/concurrency/clock-rollback-safe replay and equivocation protection. GH-42 now supplies direct ballot transport; operated discovery/NAT/relay infrastructure, trusted membership/key assignment, Sybil resistance, on-chain attestation, and production evidence remain open.
- Merged and exact-main-verified GH-42 implements the first real Guardian P2P vertical slice: exact signed-ballot bytes over bounded direct QUIC request/response, static peers, owner-only AF_UNIX collector integration, digest-bound ACKs, and end-to-end concurrency/cancellation tests. GH-44 tracks persistent transport identity and operated relay/AutoNAT/DCUtR evidence. Broad discovery, trusted membership/key assignment, Sybil resistance, and on-chain attestation remain open. mDNS is excluded because its compatible optional dependency path has unresolved RustSec advisories.

## 🟡 Nächste Session — STARTFLOW

### Pflicht VOR neuem Code:
1. `cd /Users/gio/Desktop/repos/prometheus`
2. `git log --oneline -5` — aktuellen HEAD prüfen; letzter dokumentierter grüner Baseline-Commit ist `d0f78a9`
3. Lies `memory/CHECKPOINT.md` — vollständiger Projektstatus
4. Lies `memory/AUDIT.md` ab Zeile 337 — Pre-Hardfork-Audit-Ergebnisse
5. Lies `memory/ERRORS.md` — 12 bekannte Patterns
6. `cargo test 2>&1 | tail -5` — Tests grün?

### Offene HIGH-Findings (Pre-Hardfork Audit 02.04.2026):
- **H-001**: Commit-Reveal LE encoding — `ValidatorStaking.ss:111`. Current-Silverc H-001 and `ValidatorStakingState.sil` runtime gates verify explicit byte construction, signed deployment bounds, and validator state transitions.
- **H-002**: ~~Arc<Mutex<Phi3Model>>~~ → **FIXED** in Commit `6347b85`. Arc<Phi3Model> direkt.

### Nächste konkrete Tasks (Priorität):
1. **[P0] H-001 Canary ausführen** — exakt vorbereiteten schema-v2 Digest extern per BIP340 signieren, Antwort vollständig verifizieren, einmalig senden, Bestätigung abwarten und unabhängige öffentliche Chain-Evidenz erfassen. Kein Private Key, Seed oder Wallet-Material gehört ins Repository oder in Agent-Chats.
2. **[P1] Oracle Operator Integration** — external signed metrics-oracle transaction assembly/signer/broadcast process für `GovernanceAutoTuningState.sil` operationalisieren; public report preflight, unsigned tx-request builder, operator procedure, public tx-result verifier, and public status-draft staging are local- and CI-covered.
3. **[P1] Sprint 10B: Guardian Decentralization** — GH-33/36/39 and the merged/exact-main-verified GH-42 direct Guardian ballot carrier are implemented. GH-44 is next for operated relay/NAT evidence and persistent transport identity, followed by trusted membership/key assignment and rotation, Sybil resistance, and an explicit on-chain-attestation decision.
4. **[P2] fp_rate Oracle** — Q-003 current-Silverc contract gate uses signed metrics input; public report/request/result verification is covered; production external transaction assembly/signing/broadcast/deploy operation remains
5. **[P2] M-001** — Heuristic confidence in yara_generator.py durch LLM-Confidence ersetzen
6. **[P2] M-002** — Performance test threshold (1ms → 2ms) oder --release gate
7. **[P3] L-001/L-003** — DevIncentivePool ACL, CEI borderline

### Wartet auf externe Events:
- External H-001 BIP340 signing approval and public chain evidence → Sprint 9
- Phi-3-mini Download → Sprint 11
- LLaMA 3 Fine-Tuning → Sprint 12
- vProgs (DAGKnight) → Sprint 14

## 🟢 Irgendwann / Ideas
- PLONK vs Groth16 Evaluation für Light Client ZK-proofs
- YARA-spezialisiertes 8B Fine-Tuning auf CVE-Datensätzen
- Guardian Specialization Sharding (attack class registration)

## ✅ Erledigt (letzte 7 Tage)
- [x] H-002 PATTERN-010 fix: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>> — `6347b85` (06.04.2026)
- [x] GovernanceAutoTuning current-Silverc runtime gates with signed metrics `fp_rate` input — 11.07.2026
- [x] Current-Silverc artifact smoke plus deterministic release manifest/archive for all 7 fixtures — 11.07.2026
- [x] Current-Silverc deploy preflight for release bundle/operator public inputs — 11.07.2026
- [x] Current-Silverc external deploy request set for approved orchestrators — 11.07.2026
- [x] Current-Silverc external deploy request verifier — 11.07.2026
- [x] Current-Silverc public deploy operator procedure for verified deploy request sets — 11.07.2026
- [x] Current-Silverc public orchestrator-result receipt importer — 11.07.2026
- [x] Current-Silverc deployment receipt verifier for public receipts vs release bundle — 11.07.2026
- [x] Current-Silverc deployment status staging guard for verified operator receipts — 11.07.2026
- [x] Current-Silverc operator handoff package builder for public release artifacts — 11.07.2026
- [x] Current-Silverc public oracle tx-result verifier for external metrics-oracle records — 11.07.2026
- [x] Current-Silverc public oracle status-draft staging guard — 12.07.2026
- [x] Current-Silverc release-readiness audit for public handoff packages — 11.07.2026
- [x] Current-Silverc external oracle operator procedure for signer-ready metrics tx requests — `442853f` (11.07.2026)
- [x] Post-Toccata docs/bridge status, Kaspa v2.0.1 pin, Security Audit gate, H-001 vectors, and runtime stub gates — `eeb4808` (08.07.2026)
- [x] Upstream Silverscript `silverc` local build/test and temporary H-001 explicit-preimage probe — 08.07.2026
- [x] Repo-tracked current-Silverscript H-001 fixture + verifier script + CI explicit-byte guard — 08.07.2026
- [x] Pre-Hardfork Full Audit: 35 Checks, 0 CRITICAL, 92% Confidence — `2ad7a1e` (02.04.2026)
- [x] Cargo.lock + Logo Variants + Gitignore Cleanup — `9a8c344` (02.04.2026)

---
*Zuletzt aktualisiert: 2026-07-16*
