# PRM-31/45 Public Metadata Closeout

Status: implemented; protected publication checks pending.
Owner: Codex. Base: main1315ce41e385d27b6b6eb9b6af19e523629580a4.
Node: MAP modules/web, static metadata -> public discovery/status.
Brief: .fleet/tasks/public-metadata-20261010.md.

## Changes

- manifest.json declares1024x1024 for each existing original PNG, matching IHDR.
- guardian-economics.html has one development/illustrative/non-production
  ai-status meta. All rendered content, CSS, JS, JSON-LD and dates are unchanged.
- llms.txt lists the existing Guardian Economics page once in Pages.
- scripts/test_public_claim_consistency.py adds three focused regressions using
  stdlib JSON, PNG IHDR and HTMLParser; no new dependency or verifier framework.
- Task-only PLAN/Bridge/Memory and catalog addenda carry PR291 completion and
  this bounded candidate without rewriting historical audit records.

## Actual Local Checks

Commands run from the task worktree unless an absolute path is shown:

| Command | Actual result |
| --- | --- |
| node (owner-local public-metadata static harness; private path omitted) | PASS: three corrections; five adverse controls and old baseline rejected; exact public content scope preserved |
| ruff check scripts/test_public_claim_consistency.py | All checks passed |
| git diff --check | PASS, no whitespace errors |
| git diff -- guardian-economics.html llms.txt manifest.json scripts/test_public_claim_consistency.py | Scoped self-review: only intended metadata plus tests |

The parent-owned static harness initially needed an8MiB git-output buffer and
a corrected ledger path; those attempts were not passes. The final run above
passed. No repository-controlled test was executed locally: the previously
attempted OS isolation cannot enforce the required memory bound on this host.
Actual suite results must therefore come from the existing hosted required CI,
not an invented local replay. No dependencies were downloaded locally.

Original assets and public ledger byte-verified unchanged:

- logo/Prometheus.png: fba0f9704471c4519edca500b7e12cb7ff2da5877f7df2e637e01d1bdb6a1e83
- logo/prom_coin.png: 8aabbe78db98056041b358d5422d1c7771ea95371e6cf56e4245b06a16143c9f
- docs/evidence/public-claim-status-2026-08-14.json: 3b9c791a10583fc7fba2bf59d1f50eb0df0053e2743fea37e50e8a59cfa9d9fb

## Prior Task Closure

PR291 normally merged as1315ce41e385d27b6b6eb9b6af19e523629580a4.
Exact candidate d48bc30369d69e5582b9ed1875cb62fcb73c5303 passed CI38006444235
and Security38006444240. Exact-main CI38007173270 (8/8), Security38007173221
(3/3) and Pages38007173026 passed. The catalog and register README were live
byte-identical. Its completed clean worktree was verified and archived; no
foreign or untracked material was removed. CodeRabbit content review was
rate-limited; its green status is not independent security acceptance.

## Remaining Gates

This is non-rendered metadata only; no new screenshots are required or claimed.
No PWA feature, SW behavior, runtime, policy, contract, pin, tokenomics, D5
acceptance or deployment authorization changed. The2026-10-09 project-wide
review baseline is unchanged. Issues273/275 remain open pending bounded
closeout/residual review; audit270 and every full-security/rollout gate remain.
Codex Security NOT CONNECTED/NOT RUN, distinct from Actions Security Audit.
Claude remains paused under owner assignment, not a worker outage. No extra
Kimi payload, production, chain, wallet, infrastructure or access action.

Final exact-head CI, normal merge, live byte checks and cleanup are still pending
at this committed checkpoint. They will be appended without rewriting history.
