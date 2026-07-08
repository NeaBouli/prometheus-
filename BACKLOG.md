# prometheus — Backlog

## 🔴 Aktiv (diese Session)
- Latest product-code baseline is `eeb4808` on `main`; run `git log --oneline -1` for the current bridge/docs HEAD.
- CI, Security Audit, and GitHub Pages deployment were green for `eeb4808`.
- Runtime stub gates added for Rust client; remaining production-stub task is contract-side Q-003 `fp_rate` oracle.
- Sprint 9 remains blocked by Prometheus-contract Silverscript compatibility plus H-001 verification in the actual contract form.

## 🟡 Nächste Session — STARTFLOW

### Pflicht VOR neuem Code:
1. `cd /Users/gio/Desktop/repos/prometheus`
2. `git log --oneline -5` — aktuellen HEAD prüfen; letzter Produkt-Code-Baseline-Commit ist `eeb4808`
3. Lies `memory/CHECKPOINT.md` — vollständiger Projektstatus
4. Lies `memory/AUDIT.md` ab Zeile 337 — Pre-Hardfork-Audit-Ergebnisse
5. Lies `memory/ERRORS.md` — 12 bekannte Patterns
6. `cargo test 2>&1 | tail -5` — Tests grün?

### Offene HIGH-Findings (Pre-Hardfork Audit 02.04.2026):
- **H-001**: Commit-Reveal LE encoding — `ValidatorStaking.ss:111`. Upstream `silverc` builds/tests locally; repo fixture `modules/contracts/silverc/ValidatorStakingH001.sil` verifies explicit byte construction against Rust vectors for positive 64-bit values. Still open for the full Prometheus state-machine contract because it uses legacy `.ss`/`uint64` syntax and old state abstractions.
- **H-002**: ~~Arc<Mutex<Phi3Model>>~~ → **FIXED** in Commit `6347b85`. Arc<Phi3Model> direkt.

### Nächste konkrete Tasks (Priorität):
1. **[P0] Sprint 9 Vorbereitung** — `ValidatorStaking.ss` auf aktuelle Silverscript-Syntax portieren/kompilieren und H-001 gegen die Rust-Hexvektoren in genau dieser Contract-Form testen.
2. **[P1] H-001 Verifikation** — explizite Byte-Preimage-Konstruktion in `ValidatorStaking.ss` absichern, falls implizite `bool/uint64`-Serialisierung nicht nachweisbar ist.
3. **[P1] Sprint 10B: Guardian Decentralization** — Hybrid routing (8B/70B), Ensemble voting (5x 8B)
4. **[P2] fp_rate Oracle** — Q-003 offen; contract-side stub remains and must be resolved before beta/mainnet governance
5. **[P2] M-001** — Heuristic confidence in yara_generator.py durch LLM-Confidence ersetzen
6. **[P2] M-002** — Performance test threshold (1ms → 2ms) oder --release gate
7. **[P3] L-001/L-002/L-003** — DevIncentivePool ACL, fp_rate stub, CEI borderline

### Wartet auf externe Events:
- Prometheus Contracts auf aktuelle `silverc`-Syntax bringen → Sprint 9
- Phi-3-mini Download → Sprint 11
- LLaMA 3 Fine-Tuning → Sprint 12
- vProgs (DAGKnight) → Sprint 14

## 🟢 Irgendwann / Ideas
- PLONK vs Groth16 Evaluation für Light Client ZK-proofs
- YARA-spezialisiertes 8B Fine-Tuning auf CVE-Datensätzen
- Guardian Specialization Sharding (attack class registration)

## ✅ Erledigt (letzte 7 Tage)
- [x] H-002 PATTERN-010 fix: Arc<Phi3Model> statt Arc<Mutex<Phi3Model>> — `6347b85` (06.04.2026)
- [x] Post-Toccata docs/bridge status, Kaspa v2.0.1 pin, Security Audit gate, H-001 vectors, and runtime stub gates — `eeb4808` (08.07.2026)
- [x] Upstream Silverscript `silverc` local build/test and temporary H-001 explicit-preimage probe — 08.07.2026
- [x] Repo-tracked current-Silverscript H-001 fixture + verifier script + CI explicit-byte guard — 08.07.2026
- [x] Pre-Hardfork Full Audit: 35 Checks, 0 CRITICAL, 92% Confidence — `2ad7a1e` (02.04.2026)
- [x] Cargo.lock + Logo Variants + Gitignore Cleanup — `9a8c344` (02.04.2026)

---
*Zuletzt aktualisiert: 2026-07-08*
