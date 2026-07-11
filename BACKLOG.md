# prometheus — Backlog

## 🔴 Aktiv (diese Session)
- Latest documented green product/tooling baseline is `14b89a1` on `main`; run `git log --oneline -1` for the current working HEAD.
- CI, Security Audit, and GitHub Pages deployment were green for `14b89a1`.
- Runtime stub gates added for Rust client; current-Silverc contract gates now cover H-001, ValidatorStaking, GuardianReputation, RuleStorage, CommunityDonations, DevIncentivePool, and GovernanceAutoTuning.
- Local current-Silverc release-bundle smoke now compiles all 7 fixtures through pinned upstream `silverc` and writes a deterministic manifest with source/artifact/script hashes; upstream `silverc` has no network deploy command.
- Sprint 9 remains blocked by missing network deploy/orchestration tooling, oracle operator integration, and release hardening.

## 🟡 Nächste Session — STARTFLOW

### Pflicht VOR neuem Code:
1. `cd /Users/gio/Desktop/repos/prometheus`
2. `git log --oneline -5` — aktuellen HEAD prüfen; letzter dokumentierter grüner Produkt-/Tooling-Baseline-Commit ist `14b89a1`
3. Lies `memory/CHECKPOINT.md` — vollständiger Projektstatus
4. Lies `memory/AUDIT.md` ab Zeile 337 — Pre-Hardfork-Audit-Ergebnisse
5. Lies `memory/ERRORS.md` — 12 bekannte Patterns
6. `cargo test 2>&1 | tail -5` — Tests grün?

### Offene HIGH-Findings (Pre-Hardfork Audit 02.04.2026):
- **H-001**: Commit-Reveal LE encoding — `ValidatorStaking.ss:111`. Current-Silverc H-001 and `ValidatorStakingState.sil` runtime gates verify explicit byte construction, signed deployment bounds, and validator state transitions.
- **H-002**: ~~Arc<Mutex<Phi3Model>>~~ → **FIXED** in Commit `6347b85`. Arc<Phi3Model> direkt.

### Nächste konkrete Tasks (Priorität):
1. **[P0] Sprint 9 Vorbereitung** — current-Silverc network deploy/orchestration path klären; Artifact-Smoke ist lokal vorhanden, echter On-chain-Deploy fehlt mangels upstream deploy CLI.
2. **[P1] Oracle Operator Integration** — signed metrics-oracle signer/process für `GovernanceAutoTuningState.sil` definieren und operationalisieren.
3. **[P1] Sprint 10B: Guardian Decentralization** — Hybrid routing (8B/70B), Ensemble voting (5x 8B)
4. **[P2] fp_rate Oracle** — Q-003 current-Silverc contract gate uses signed metrics input; production oracle operator/integration remains
5. **[P2] M-001** — Heuristic confidence in yara_generator.py durch LLM-Confidence ersetzen
6. **[P2] M-002** — Performance test threshold (1ms → 2ms) oder --release gate
7. **[P3] L-001/L-003** — DevIncentivePool ACL, CEI borderline

### Wartet auf externe Events:
- Current-Silverc network deploy/orchestration tooling → Sprint 9
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
- [x] Current-Silverc artifact smoke and deterministic release manifest for all 7 fixtures — 11.07.2026
- [x] Post-Toccata docs/bridge status, Kaspa v2.0.1 pin, Security Audit gate, H-001 vectors, and runtime stub gates — `eeb4808` (08.07.2026)
- [x] Upstream Silverscript `silverc` local build/test and temporary H-001 explicit-preimage probe — 08.07.2026
- [x] Repo-tracked current-Silverscript H-001 fixture + verifier script + CI explicit-byte guard — 08.07.2026
- [x] Pre-Hardfork Full Audit: 35 Checks, 0 CRITICAL, 92% Confidence — `2ad7a1e` (02.04.2026)
- [x] Cargo.lock + Logo Variants + Gitignore Cleanup — `9a8c344` (02.04.2026)

---
*Zuletzt aktualisiert: 2026-07-11*
