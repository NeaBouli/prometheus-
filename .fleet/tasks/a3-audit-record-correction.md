# A3 — Correct and rebase public audit records

Architecture boundary: `docs/architecture/MAP.md`, public audit records node;
no runtime hop, product code, contracts, workflows, or deployment.

## Scope

- Start from the orchestrator branch and import only the six files listed by
  draft PR #269 (`docs/community-audits/**`). Use PR #269 and issue #271 as the
  authoritative public inputs; preserve audit authorship and finding IDs.
- Mark PRM-01 invalid without renumbering; correct PRM-26 to state that ties are
  accepted; repair the malformed Markdown span.
- Move the rustls advisory into a distinct addendum ID and recompute the audit
  totals to exactly `0 Critical / 7 High / 15 Medium / 20 Low / 5 Info`.
- Recompute and record SHA-256 pins for every corrected report. Clearly mark
  the old PDF digest beginning `3a9556` and ending `ff37` as superseded; do not
  commit the desktop PDF or invent a replacement digest without an artifact.
- Keep descriptions no more operationally exploitable than the already-public
  source. Do not add fixes, architecture, claims, secrets, or private data.

## Acceptance

- All six PR files are present, internally consistent, and Markdown-clean.
- Finding IDs remain stable; PRM-01 visibly invalid; totals and pins verify.
- Run focused hash/Markdown checks plus relevant documentation and public-claim
  gates. Report exact commands and results in `.fleet/reports/a3-audit-record-correction.md`.
- Work only on `agent/<worker>/a3-audit-record-correction`; no PR merge, main
  push, deploy, external message, or subagent.
