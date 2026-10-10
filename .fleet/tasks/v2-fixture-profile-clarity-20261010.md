# M2-DOC-V1-V2-COOLDOWN

Base:649e4959586dd72b81a539df620802cecae9bfe3 (held Docs296).
Worker: one native Codex writer; Core owns CI/publication/integration.
Architecture: existing contract-fixture documentation -> public-web render hop.

## Scope
- Clarify frozen historical h001-v1 versus unaccepted v2-draft cooldown in
  WHITEPAPER.md, docs/validator-guide.md, index.html and whitepaper.html.
- Preserve v1 100,800 and v2 6,048,000 consensus-score values; durations are
  approximate only under an explicit10-score/s assumption, not wall-time promises.
- No contract/fixture/pin/CSS/JS/workflow/token/policy/date-baseline change.
- Append bounded status in memory/AUDIT.md, memory/STATUS.md, .fleet/PLAN.md and
  docs/agent-bridge/ACTION_LOG.md; report in .fleet/reports/<task-id>.md.
- Preserve previous content and all unrelated work. No private scan/operator
  payloads, credentials, wallet material or raw findings in source/report.

## Acceptance
- All four surfaces make the same scoped claim; no current-v2/full-rollout inference.
- Record exact modified paths, literal/cross-surface checks and actual outcomes.
- Use fleet-developer, architecture-map and frontend-visual-release-gate.
- Two HTML pages: four required responsive viewports, changed-area screenshots
  inspected, quantitative overflow/clipping/error/contrast/focus assertions.
- Evidence outside source under /Users/gio/agent-fleet/evidence/prometheus/v2-fixture-profile-clarity-20261010.
- Do not execute arbitrary repository tests/builds locally. Use installed trusted
  browser tooling with bounded localhost-only static serving and sandboxed browser;
  stop and report if unavailable. Hosted suites/push/PR remain with Core.
- No commits, external writes, deployments, nested agents, provider or config changes.
- Return <=20 lines: status, paths, actual checks, image/evidence paths, risks, next.

## Core Amendment - 2026-10-10
- Partial visual result accepted as a real blocker, not a release pass.
- Extend only whitepaper.html's existing rendered table hop for the smallest
  responsive cell-wrapping/width fix; no shared CSS, JS or design-system changes.
- Keep all text and table columns visible without requiring horizontal scrolling;
  do not hide overflow or weaken assertions. Recheck both pages at four viewports.
- Verify the historical v1 time input before labeling units: do not imply v1's
  caller-provided counter is consensus-enforced DAA or guaranteed wall time.
  Distinguish the v2 consensus DAA-score interval; retain both numeric constants.
- Append the actual semantic/layout correction and evidence; preserve the earlier
  partial result. Core will independently backport the exact finished delta to
  main, then own exact-head hosted CI and publication. No extra worker or restart.
