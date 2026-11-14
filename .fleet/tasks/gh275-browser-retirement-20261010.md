# GH275 Current Browser Lifecycle Acceptance

Status: CLAIMED; previous full goal turn PROGRESS (PR298 tested, still held).
Owner: Codex; one native implementation worker, no nested agents.
Baseline: main58d742aa7442ddc1663dbd9c3553e644bf0a7a2b.
Architecture: public-web -> historical registration/sw.js -> CacheStorage ->
retirement activate/exact-name cleanup/unregister -> fresh navigation.
Name and trace this existing MAP hop before the first diff; do not add modules.

## Problem / Boundary
GH275 has five of seven criteria checked. Current-source retirement and static
delivery do not prove actual browser lifecycle/cache behavior. Historical
20e8531 SW used root-absolute precache and origin-wide cleanup; do not pretend
it ever installed on current production Pages. No offline feature is promised.
The independent archival-history fallback remains OPEN and outside this task.

## Worker Deliverable
Use existing browser tooling/runtime where available, no dependency install,
provider change, purchases or model override. Fresh sandboxed Chrome contexts
only; no in-app/user/persistent wallet/browser profile, secrets or private data.
Build a narrow reusable real-browser regression harness if one does not exist:
scripts/test_sw_retirement_browser.mjs (or existing same-hop helper, justify).
Allowed writes: that test harness, this task, <=40-line report under .fleet/
reports, sanitized docs/evidence/gh-275-browser-retirement-2026-10-10.json and
an append-only MAP status paragraph. No product UI/SW/policy/workflow change.
If an actual bug is found, report partial/security and let Core bound the fix.

Pin exact current and historical worker bytes. A controlled, satisfiable
legacy-root fixture may exercise an installed legacy worker update, but label
it as a counterfactual origin-availability fixture, never historical live proof.
Separately test the real root-absolute missing-resource installation failure.
Do not change the historical SW code or silently turn 404 into an install pass.
Exercise fresh current pages with zero registrations; retired-worker fresh
install/activation; old-installed-worker update; own-cache removal; exact/prefix
near-match and unrelated foreign-cache retention; reload/controller release;
offline no-stale-response after retirement; online recovery with current bytes.
Capture observations, not only waitForTimeout. Retain negative/failed evidence.
All browser cache writes/deletes are solely synthetic data in own fresh contexts.

Read-only live GETs only for existing public pages/SW/styles/fonts/logo; no
transaction/explorer/faucet/wallet/GSC/account action. If browser networking is
blocked, use an exact fetched-live-response replay and label the distinction.
Never claim replay/loopback fixtures prove a deployed user's historical state.
Capture affected homepage at four project viewports using actual existing fonts
if available, screenshots/assertions/hashes outside source; Core opens all images.
Test failures must not be hidden, skipped, padded or solved by false claims.

## Acceptance / Routing
Actual browser install/update/offline/cache assertions and required current
public HTML/status/claim checks pass. Use structured sanitized evidence: source
hashes, classifications, exact states/results, no private paths/URLs/endpoints,
IPs, profiles or raw operator/chain/browser logs. Public harness is reproducible
with an explicitly supplied installed Playwright module, no production JS.
Leave changes uncommitted for Core review/full existing hosted CI/Security.
Core alone publishes a normal PR, protected merge and actual-main/live recheck.
Do not auto-close GH275 or archival fallback; Core adjudicates one criterion only.
No branch/main merge, external writes/CI/deploy, IAM/network/host/provider action.
Do not touch Prometheus-1.png or foreign changes; no code exploration beyond hop.
Read AGENTS, relevant Bridge/Memory and frontend-visual-release-gate first.
Report partial until Core's suite/release evidence completes; concise return.

Claude owner-paused; Kimi observed weekly403, reset unknown, no retry/transfer.
The separate51-file Kimi source question remains pending. Full goal ACTIVE.

## Owner-local Return (2026-10-10)

Status: partial; browser assertions PASS66/66 in nine cases, Core gates pending.
Canonical harness: scripts/browser_retired_service_worker_regression.mjs; no product source changed.
Public evidence: docs/evidence/gh-275-browser-retirement-2026-10-10.json.
Private reproducibility, all four inspected screenshots, hashes and initial
negative evidence: owner-local GH275 evidence directory named in the report.
Report: .fleet/reports/gh275-browser-retirement-20261010.md.
No commit, push, CI, release, archival-fallback or GH275 closure performed.

## Scope Amendment / Consolidation (2026-10-10)

Core permits extending the existing tracked same-hop helper. The initial
separate-helper brief deviation is corrected: the unchanged amended superset
runtime now resides solely in scripts/browser_retired_service_worker_regression.mjs;
only its filename/help pointer changed and the authored untracked helper was deleted.
Core reports complete amended run34026 exit0, nine cases/66 assertions PASS;
this owner performed no new browser run. Historical captured repro/negative
observations remain immutable; current sanitized evidence is Core-owned.
Checks: node --check, exact runtime-body equality and Git/source guard checks only.
