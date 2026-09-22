# Prometheus — Content & Coherence Audit

- **Series:** Collateral Web3 Open Audits
- **Date:** 2026-09-15
- **Target:** NeaBouli/prometheus- @ `8b5da58a34172062cf644db52ba459385d151562`
- **Scope:** README, WHITEPAPER (+HTML), faq/roadmap/guardian-economics pages, llms.txt, SECURITY.md, docs/ + memory/ corpus, BACKLOG, CLAUDE.md, prior internal claim audit (2026-08-14) re-baseline
- **Method:** deep-recon agent claim-drift sweep + lead verification of every finding; sample-based independent re-verification of the internal claim audit's corrections
- **Register:** PRM-34 … PRM-42 (this report) — **0 Critical / 0 High / 3 Medium / 5 Low / 1 Info**

---

## Executive summary

The internal 2026-08-14 claim audit was real work, not theater: its corrections demonstrably landed on all five main pages, and this audit's independent spot-check found the hedged wording consistent across README/WHITEPAPER/faq/roadmap/llms.txt (estimates 84–88%/50–55%, tokenomics, hardware targets, 60s-as-target, decentralization-as-target — all synchronized). The remaining drift lives in the **second ring**: the unfundable PROM bug bounty in SECURITY.md, a 60× arithmetic error in the cooldown comment that propagated into three documents, a cluster of stale memory files that the README links publicly, and pre-audit present tense in two orphan guides. Plus the dashboard covered separately as PRM-28.

## Severity table

| ID | Severity | Title |
|----|----------|-------|
| PRM-34 | Medium | SECURITY.md bug bounty promises 500–100,000 PROM rewards while PROM minting is documented as not implemented |
| PRM-35 | Medium | Cooldown arithmetic wrong by 60×: `COOLDOWN_BLOCKS = 100800 // ~7 days at 10 BPS` (is ≈2.8 hours) — propagated to whitepaper + guide |
| PRM-36 | Medium | Public-linked memory files stale: SPRINTS all-pending, CHECKPOINT pre-GH-253, BACKLOG 5 weeks old |
| PRM-37 | Low | Orphan guides (validator/guardian) retain pre-audit present tense ("earn PROM rewards") |
| PRM-38 | Low | Residual predictive absolutes in guardian-economics solution cards |
| PRM-39 | Low | Stale metrics: "160+ Tests" (actual 1,300+); "100 BPS" vs 10 BPS context; twitter meta 5 vs 6 cards |
| PRM-40 | Low | Operator's local machine paths (`/Users/gio/…`) published in BACKLOG + agent-bridge docs |
| PRM-41 | Low | CLAUDE.md is a generic audit-prompt template — the repo's primary agent file contains no project guidance |
| PRM-42 | Info | Prior claim-audit corrections verified landed; cross-surface consistency spot-check passed |

---

## PRM-34 — Medium — SECURITY.md bug bounty promises PROM that cannot be paid

**Evidence (lead-verified):** `SECURITY.md:15-22` — "Active from Testnet launch. Rewards paid in PROM from the Dev Pool. | CRITICAL 50,000–100,000 PROM | HIGH 10,000–50,000 …" — stated without hedging, while README.md:107 and every status surface state PROM "minting, emission, liquidity, and trading are not implemented, deployed, or active." A researcher can reasonably read this as a funded bounty that currently cannot be paid. (The disclosure channel itself is correctly wired to GitHub Security Advisories — unlike the paradox found in the Stealth audit, STX-30.)

**Recommendation:** label the table as planned/not-yet-funded ("rewards denominated in PROM, payable once emission is live" or a KAS-denominated interim), or commit a payment mechanism.

## PRM-35 — Medium — Cooldown arithmetic wrong by 60×, propagated to three documents

**Evidence (lead-verified):** `modules/contracts/ValidatorStaking.ss:39` — `const COOLDOWN_BLOCKS: uint64 = 100800; // ~7 days at 10 BPS`. At 10 blocks/second, 100,800 blocks ≈ **2.8 hours**, not 7 days (7 days = 6,048,000 blocks). The same constant appears with the wrong justification in `WHITEPAPER.md:272` ("7-day cooldown enforced via COOLDOWN_BLOCKS = 100,800 (~7 days at 10 BPS)"), `whitepaper.html:524` ("7 days (100,800 blocks at 10 BPS)") and `docs/validator-guide.md:60`. The same whitepaper computes the voting period correctly (864,000 ≈ 1 day at 10 BPS, `WHITEPAPER.md:596`), so either the constant or the comment is off by exactly 60×.

**Impact:** a public auditor or validator-guide reader learns a wrong security parameter; if the *intent* was 7 days, the deployed constant gives 2.8 hours of withdrawal protection — if the intent was 100,800 blocks, the docs overstate protection 60×.

**Recommendation (owner decision):** fix either the constant (6,048,000) or the documented duration — and note the `.sil` port inherits whichever value is intended (`ValidatorStakingState.sil` uses the same constant).

## PRM-36 — Medium — Public-linked memory files are stale

**Evidence (agent-verified, lead spot-checked):**
- `memory/SPRINTS.md` ("Last Updated: 2026-09-13") overview table still marks Sprints 0–8 **all PENDING** — contradicts README (DONE/ACCEPTED) and `docs/roadmap.md`; only a footnote notes supersession.
- `memory/CHECKPOINT.md` ("Last updated: 2026-09-06") states "GH-220 is in progress … not yet merged" — GH-220 is long merged (`BACKLOG.md:5`, `llms.txt:15`); its baseline `c243b69` predates GH-253.
- `BACKLOG.md` footer "Zuletzt aktualisiert: 2026-08-09" (5 weeks stale); its STARTFLOW names `db33f56` as last green baseline, contradicting its own header (`c243b69`) and HEAD (`8b5da58a`); GH-253–GH-266 absent.
- `memory/TODO.md` 2026-08-31, `MEMO.md` 2026-08-23, `AUDIT.md` 2026-08-31 all lag STATUS.md (2026-09-13).
- Why it matters beyond hygiene: `README.md:352-354` links `AUDIT.md`/`MEMO.md`/`SPRINTS.md** publicly** as project documentation — the staleness is externally visible, and this project's entire brand is freshness-of-record.

**Recommendation:** regenerate or supersede-banner the stale files; consider a CI freshness gate for memory files (the project already has `check_memory_integrity.py` — extend it with recency checks).

## PRM-37 — Low — Orphan guides retain pre-audit present tense

`docs/validator-guide.md:5` — "Validators secure the Prometheus network… They earn PROM rewards" with no target-status hedging anywhere in the file, instructing readers to send 10,000 KAS to a contract with no production deployment; `docs/guardian-guide.md` same framing (hedged only at `:106`). Neither file is in the 13-surface consistency set; no public page links them (repo-internal exposure only) — Low.

## PRM-38 — Low — Residual predictive absolutes in solution cards

`guardian-economics.html:436` "Lowers 70B entry barrier from $60k to $6k… On-chain split ensures trustless revenue sharing"; `:443` "Fine-tuned 8B models match 70B quality"; `:457` "60-second SLA becomes reliably achievable" — assertive wording inside cards, though the section intro (`:415`) and callout hedge properly. Also `:412`/`:419` duplicate `id="hybrid-routing"` and solution card #5 (`:447`) lacks an id/sidebar entry (HTML validity, cross-ref PRM-47).

## PRM-39 — Low — Stale public metrics

`index.html:501` "**160+ Tests passing**" dates from the March landing commit; the repo now documents 1,303–1,348 Guardian tests plus Rust/contract suites (understated, not overstated). `index.html:381` lists "DAGKnight consensus · 100 BPS" in the L1 target layer while contracts/docs assume 10 BPS (labeled "target" — borderline). `guardian-economics.html` twitter meta says "5 solution paths" while the body renders six cards.

## PRM-40 — Low — Operator machine paths published

`BACKLOG.md:31` publishes `cd /Users/gio/Desktop/repos/prometheus`; `docs/agent-bridge/*` repeat `/Users/gio/...` wrapper paths (`/Users/gio/.local/bin/claude-code-terminal`). Username/tooling disclosure in a public repo — minor, but trivially avoidable (`$HOME`, placeholders). No other sensitive material found (IP inventory: only RFC-5737 documentation ranges + loopback examples; no keys, tokens, internal hosts).

## PRM-41 — Low — CLAUDE.md is a generic template

`CLAUDE.md` (37 KB, 978 lines) is a generic security-audit prompt template with placeholder paths — no project-specific guidance, which is odd for the repo's primary agent instruction file (AGENTS.md carries the real rules). Either trim to a pointer or fill with project-specifics; in its current form it invites generic agent behavior on a non-generic repo.

## PRM-42 — Info — Prior claim-audit corrections verified landed

Independent spot-check (lead + agent): the 2026-08-14 corrections are present on all five main pages; footers synchronized ("reviewed 2026-09-13 · baseline 2026-08-14 · 5cd13bf"); GH-190…GH-264 wording matches across README/WHITEPAPER/faq/roadmap/llms.txt; estimates (84–88% core / 50–55% vision), 10,000 KAS, 20M year-1 + 40/30/20/5/5, no-premine, 8B 24 GB / 70B 4×A100, under-60s-as-target, decentralization-as-target all consistent. `docs/roadmap.md`, `docs/faq.md`, `MIGRATION_SECURITY_MEMO.md`, `repository-security.md`, `endpoint-observation-v1.md` spot-checked consistent. The gaps that remain: the dashboard (PRM-28), the bounty (PRM-34), the guides (PRM-37) and the memory ring (PRM-36) — all outside the 13 gated surfaces. **Root-cause recommendation:** extend `verify_public_claim_consistency.py` to every public/linked document class, not 13 hand-listed ones.

---

## Verified strengths

- The internal claim audit's classification system (implemented/tested vs demonstrated-on-testnet vs production-deployed vs planned vs blocked) is applied with unusual honesty — this series has not seen a cleaner public claim posture; the residual issues are surfaces that escaped the gate list, not gated content.
- README is a model of evidence-linked status reporting: every GH item carries exact-main SHAs + CI run IDs; the claim-audit has a machine-readable companion JSON.
- License consistency: MIT everywhere (repo, badge, footer) — unlike the Stealth project's license drift, none here.
