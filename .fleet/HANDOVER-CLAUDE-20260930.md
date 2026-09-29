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

## Current state
- Branch/worktree: `agent/claude/prometheus-standin-20260930` in
  `~/Desktop/repos/prometheus-master-plan-20260927-wt/claude-a8u-toolchain-upgrade`, stacked on `60ee6db`.
  One commit series per block; integrate by merging this branch into the integration branch after PR #284.
- Live changes: none (repo-local only).
- Tests: see per-block reports.

## Findings in existing code
- See A8u1 F3/F4 (deployer binds `toccata_activation_daa_score` into signing request/receipt schema).

## Review owed to Codex
- GH-279: dependency/CI supply-chain change (ci.yml python-check install + gate). Solo by Claude.
- GH-283: CI contract-assurance gate + expectation file. Solo by Claude.

## Next step (exact)
1. (see latest row; next block chosen in PLAN tail)

## Open decisions for Gio
- MS-B #276 seven contract decisions; A9/GH-280 defaults; A10/#275 service worker; A11/PRM-34 bug bounty;
  A3 consent; audit budget. (Unchanged from PLAN §6.)
