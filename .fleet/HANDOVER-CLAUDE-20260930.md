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
| 2026-09-30 | PRM-35 (delegated decision) | Cooldown target 7 days; code deferred to contract bundle v2 (H-001 manifest pin) | Docs corrected; full contract job run documented. Report `.fleet/reports/prm35-cooldown-decision.md`. |
| 2026-09-30 | A12c / PRM-44 | Shared stylesheet assets/site.css (tokens + chrome) | 5 pages × 2 viewports + states pixel-identical. Report `.fleet/reports/a12c-shared-css.md`. |
| 2026-09-30 | GH-275 rest | H-001 evidence fallback investigated (API pruned, explorer 402); README wording | Claims/evidence verifier pass. |
| 2026-09-30 | Records | memory/TODO + STATUS refreshed to 2026-09-30 | Memory/status/claim gates pass. |
| 2026-09-30 | DA1 | Endpoint producer design (design only) | Hygiene/claim/GH-267 gates pass. Report `.fleet/reports/da1-endpoint-producer-design.md`. |
| 2026-09-30 | PRM-12 (part) | Actions pinned to commit SHAs | YAML/tests OK; hosted run on f737c7b owed. Report `.fleet/reports/prm12-actions-sha-pin.md`. |
| 2026-09-30 | PRM-12 (part) | deny_unknown_fields on operator-authored deployer formats | Deployer tests + clippy + full local silverc CI job pass. |
| 2026-09-30 | PRM-12 (part) | Saturating bond math + clock high-water runbook | validator 34 tests, clippy, doc gates pass. |
| 2026-09-30 | MS-B / #276 (proposal) | Contract decision record D1–D7 + bundle v2 child plan | Doc gates pass. `docs/architecture/ms-b-contract-decisions.md`. |

## Current state
- Branch/worktree: `agent/claude/prometheus-standin-20260930` in
  `~/Desktop/repos/prometheus-master-plan-20260927-wt/claude-a8u-toolchain-upgrade`, stacked on `60ee6db`.
  One commit series per block; integrate by merging this branch into the integration branch after PR #284.
- Live changes: none (repo-local only).
- Tests: see per-block reports. Hosted: CI `36698349293` + Security `36698357152` all green at `bff7fc1` (workflow_dispatch, no PR). Second dispatch at `40dfd89` (incl. action SHA pins): CI `36702356697` + Security `36702361053` all green.

## Findings in existing code
- `modules/silverc-deployer/src/lib.rs` binds `toccata_activation_daa_score` into the signing
  request/receipt schema and uses Params APIs removed in rusty-kaspa v2.1.0 (A8u1 F3/F4).
- `modules/silverc-deployer/src/lib.rs:54` `FULL_BUNDLE_MANIFEST_SHA256` couples every contract
  fixture change to the frozen H-001 canary profile → any contract change needs "bundle v2".
- The legacy `.ss` cooldown comment (100,800 ≈ "7 days") was wrong by 60× (PRM-35); `.sil` still
  carries 100,800 until bundle v2.
- `scripts/verify_site_css.py` (my A12a gate) initially misread a CSS comment before `@media` as a
  selector; fixed in A12c by stripping comments (regression test added).
- H-001 public re-verification: kaspa.org TN10 explorer 402; api-tn10 indexer healthy but pruned
  (404 for tx/block). Only an archival node/indexer can re-verify now.

## Review owed to Codex
- PRM-12: silverc-deployer `deny_unknown_fields` (Rust, security surface) and saturating bond math.
- A9: container identity/resources (security surface); A10 cleanup service worker.
- GH-279: dependency/CI supply-chain change (python-check install + gate).
- GH-283: CI contract-assurance gate + expectation file.
- PRM-12: GitHub Actions SHA pins (verify the resolved SHAs if desired).
- A11/A12: visible HTML changes — post-deploy visual recheck owed after merge (screenshots under
  `.fleet/artifacts/`).
- A4H: public-claim wording; was meant as independent-worker gate before any Reddit activity.
- MS-B decision record: architecture review (architect profile) before it becomes binding.

## How to integrate
- The branch is stacked linearly on `60ee6db` (= PR #284 head); the Codex integration branch has
  not moved since, so it can be fast-forwarded or merged after PR #284.
- Every block is a code commit followed by a `docs:` report commit; reports live in
  `.fleet/reports/`, evidence in `.fleet/artifacts/`.
- Hosted verification: CI `36698349293` + Security `36698357152` green at `bff7fc1`; second
  dispatch at `40dfd89`: CI `36702356697` + Security `36702361053` all green (8/8 + 3/3).

## Where I used less ceremony than Codex
- All blocks were implemented and self-reviewed by Claude alone; no worker dispatch, no second
  reviewer. Kimi/Grok availability was not probed.
- Owner decisions PRM-35, A9 and A10 were taken by Claude under Gio's explicit delegation
  ("entscheide du, ich kenne mich hier nicht aus"); PRM-34 was Gio's own decision (no bounty).

## Next step (exact)
1. Codex: review and merge PR #284, then integrate `agent/claude/prometheus-standin-20260930`
   (review items above first).
2. Codex (architect profile): review `docs/architecture/ms-b-contract-decisions.md`; if accepted,
   open the 7 child issues and plan "contract bundle v2" (new profile pin next to frozen H-001).
3. After merge: Pages post-deploy check (site.css 200, screenshots at 4 viewports, contrast).
4. Close/update issues after hosted green on main: #274 (PRM-12 parts), #275, #277, #278, #279,
   #280, #283; umbrella #270 totals.
5. Watch upstream: SilverScript release on a rusty-kaspa tag ≥ v2.1.0 unblocks A8u2.

## Open decisions for Gio
- A3 consent for edits to the external-auditor PR #269 (unchanged).
- Budget for the scoped/deep security audits (unchanged, PLAN §5).
- MS-B #276: technical decisions proposed by Claude under delegation; Gio only needs to know that
  slashed KAS would be burned (D3) and that voting relies on one owner-controlled attestation key
  until Guardian decentralization (D1).
