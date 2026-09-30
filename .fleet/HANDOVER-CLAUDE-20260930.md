# Handover — Claude Code standing in for Codex (2026-09-30)

Audience: Codex on return. Thread: `codex://threads/019f3d96-5391-74c3-abfc-9395094e62e1`.
Claim: `~/agent-fleet/standin/claims/019f3d96-5391-74c3-abfc-9395094e62e1.md`.
Goal: continue exactly from the hand-back point without re-research.

## Starting point (last Codex state, 2026-09-28T15:45Z)
- A1–A8 integrated on `agent/codex/prometheus-master-plan-20260927`, head `60ee6db`;
  PR #284 open, MERGEABLE/CLEAN, hosted CI + Security green (runs 36443057946 / 36443057571,
  head-SHA rerun 36444744803). CodeRabbit skipped (132 files) — not an independent review.
- Codex's stated next block: isolated Rusty Kaspa v2.1.0 / SilverScript v1.0.0 migration.
- Note on numbering: thread "A7" = PLAN A7 (PRM-06/07/08); thread "A8" = Gio-requested toolchain
  pin gate, which took the PLAN slot A8. PLAN's original A8 content (R6, GH-279, PRM-09 Python
  dependency reproducibility) is still OPEN.

## Mandate
- Gio 2026-09-30: take over this Codex chat per `codex-standin`; "so viel wie möglich am Projekt
  weiterbauen bis Samstag, voll autonom, ohne Pause, nach den besten und logischsten Folgeschritten,
  so dass alles user-technisch funktioniert".
- Stays with Codex: merge of PR #284 and anything to main, release gate, pinned contracts
  (toolchain-pins.json identity section, H-001 evidence, relation identity).

## Since then (Claude Code)
| UTC | Ticket | What | Result / evidence |
| --- | --- | --- | --- |
| 2026-09-30 | A8u1 | Kaspa v2.1.0 / SilverScript v1.0.0 compatibility inventory | Upgrade blocked upstream (SilverScript pins rusty-kaspa v2.0.1 resp. untagged a41a333b); deployer API/schema break mapped. Report `.fleet/reports/a8u1-kaspa-silverscript-upgrade-inventory.md`. No product change. |
| 2026-09-30 | GH-279 / PRM-09 | Guardian Python deps exact pins + sha256 lock + CI gate + public policy | Guardian 1426/4 skipped, 374 script tests, pip-audit clean. Report `.fleet/reports/a8r6-guardian-python-deps.md`. |
| 2026-09-30 | GH-283 | Compiled silverc semantic gate + mutation regression | 2 literal-preserving mutants rejected; archive hash reproduces H-001 evidence. Report `.fleet/reports/gh283-silverc-semantic-gate.md`. |
| 2026-09-30 | A4H | Public claim corrections (validator command, KAS staking, sprint labels) | Claim/hygiene gates pass. Report `.fleet/reports/a4h-readme-honesty.md`. |
| 2026-09-30 | A11 / GH-277 | Public records: bounty label, memory banners, guides, paths, CLAUDE.md, robots, landing wording | Gates + 4-viewport visual gate pass. Report `.fleet/reports/a11-public-records.md`. |
| 2026-09-30 | A12a / PRM-43 | WCAG AA contrast on all public pages + CSS dedupe + CI gate | 796→0 failing text nodes; 5 pages × 4 viewports clean. Report `.fleet/reports/a12a-contrast.md`. |
| 2026-09-30 | A12b / PRM-47/48 | noopener, skip link, reduced-motion/no-JS fallbacks | Keyboard + reduced-motion + no-JS checks pass. Report `.fleet/reports/a12b-a11y.md`. |
| 2026-09-30 | A12d | Display-sized images (index ≈3.1 MB → ≈208 KB) | Images load at 1440/390; layout gate clean. Report `.fleet/reports/a12d-images.md`. |
| 2026-09-30 | PRM-34 (Gio decision) | PROM bug bounty removed from SECURITY.md | Gates pass. |
| 2026-09-30 | A10 / GH-275 (delegated decision) | Service worker removed, GSC meta, explorer wording | Browser-verified. Report `.fleet/reports/a10-service-worker.md`. |
| 2026-09-30 | A9 / GH-280 (delegated decision) | Compose 2000:2000, CPU caps, tmpfs rationale, vLLM trust boundary | Guardian 1428/4 skipped. Report `.fleet/reports/a9-guardian-compose.md`. |

## Current state
- Branch/worktree: `agent/claude/prometheus-standin-20260930` in
  `~/Desktop/repos/prometheus-master-plan-20260927-wt/claude-a8u-toolchain-upgrade`, stacked on `60ee6db`.
  One commit series per block; integrate by merging this branch into the integration branch after PR #284.
- Live changes: none (repo-local only).
- Tests: see per-block reports.

## Findings in existing code
- See A8u1 F3/F4 (deployer binds `toccata_activation_daa_score` into signing request/receipt schema).

## Review owed to Codex
- A9: container identity/resources (security surface); A10 cleanup worker.
- GH-279: dependency/CI supply-chain change (ci.yml python-check install + gate). Solo by Claude.
- GH-283: CI contract-assurance gate + expectation file. Solo by Claude.
- A11: visible HTML changes (index/guardian-economics) — post-deploy visual recheck owed after merge.
- A4H: public-claim wording; was meant as independent-worker gate before Reddit activity.

## Next step (exact)
1. (see latest row; next block chosen in PLAN tail)

## Open decisions for Gio
- MS-B #276 seven contract decisions; A9/GH-280 defaults (DECIDED by Claude, delegated); A10/#275 service worker (DECIDED: removed); A11/PRM-34 bug bounty (DECIDED 2026-09-30: removed);
  A3 consent; audit budget. (Unchanged from PLAN §6.)
