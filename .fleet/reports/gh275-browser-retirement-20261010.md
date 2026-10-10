id: gh275-browser-retirement-20261010
status: partial
owner: Codex, sole writer; branch agent/codex/gh275-browser-retirement-20261010
baseline: 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b
summary: modules/web public-web -> historical registration/sw.js -> CacheStorage -> retirement activate/exact cleanup/unregister -> actual reload.
implementation: sole canonical scripts/browser_retired_service_worker_regression.mjs now contains the amended superset; initial separate-helper brief deviation corrected, authored untracked helper deleted, no wrapper/product change.
original-browser-proof: PRE-AMENDMENT at exact baseline above; node scripts/test_sw_retirement_browser.mjs exit0, nine cases/66 assertions PASS; not an amended-harness browser qualification.
runtime: Chrome154.0.8037.98, chromiumSandbox=true, fresh nonpersistent contexts; no install or user browsing.
classification: exact public HTTP response replay on loopback; read-only allowlisted GETs, no deployed historical-user-state claim.
pins: old20e8531 SHA256 7e45aadd9d4c1e36df9a74e035b92193bf840d8e78819cadf1bf22da1edc7399; current SW e2821c24c190a8df9c8aff9582654554d0a6d68d8ecd35c9d5b79cb6a00f45a0.
fresh: six current HTMLs match fetched live bytes; registrations0/controller null/cache empty. Fresh retirement clears only own exact cache.
update: unchanged old JS really activated in counterfactual root-availability fixture; foreign/near-match seeds added only AFTER activation.
negative-control: old installed worker served synthetic stale HTML offline before update; not proof of historical live install.
retirement: own prometheus-v1 absent; six foreign/near-match caches and their fixture bytes preserved; controller retained until actual reload, then null/registrations0.
offline: current unique navigation ERR_INTERNET_DISCONNECTED, no stale own response; online recovery byte-equals current homepage with no own cache/worker.
missing-root: actual public404 replay makes unchanged old worker installing -> redundant, registrations0/controller null, empty own cache; no silent404 success.
visual: 1440x1000,1180x820,820x1180,390x844; all final images opened; actual Space Grotesk/Space Mono loaded, images render, overflow0, heading/copy/actions nonoverlap, mobile menu opens/closes.
public-evidence: docs/evidence/gh-275-browser-retirement-2026-10-10.json (sources, actual states, assertions, hashes, preserved negative results; no private paths/IPs/profiles/logs).
retained-evidence: original observations, screenshot hashes, reproducibility instructions and negative evidence retained owner-locally; private locations are not published.
repro: current instructions invoke scripts/browser_retired_service_worker_regression.mjs with explicit EXPECTED_SOURCE_REVISION; captured historical repro/negative evidence unchanged.
sha256 homepage-1440x1000.png: a4e39e250a5f48708afa9e4e273da8b06a9b4e23f87b83c539650c1f424a5972
sha256 homepage-1180x820.png: e0365970897ce8b0f9e5eb94a46c43b080bb49ca2cc956c3e4122cff742ac4bc
sha256 homepage-820x1180.png: 16460a73e3383c520d31cf021f6ab32ea01f5d098c47eff17d2666d2a3d11a76
sha256 homepage-390x844.png: 2fc5efbfb6217597d0c8b7a790a23ccddf2e17e0e2ea4f016c7cf2deecefcf6f
negative-evidence: prior-50d63500b36b retains initial failed observations/repro/images (premature activation snapshot; omitted two fixture logos); prior-0b933121daa8 retains corrected pass before explicit-reload enhancement.
security: none demonstrated in current retirement; no UI/SW/policy/workflow edits; all cache writes synthetic isolated fixtures.
risks: Core independent cache/security review, all-image inspection, full hosted suites/CI, release/main/live acceptance pending; historical live install not proven; archival fallback outside scope.
cleanup: all owned Chrome contexts/browser/server closed; no build/dependency outputs created; durable evidence retained; uncommitted review worktree not archived.
amendment: mandatory canonical lowercase40hex EXPECTED_SOURCE_REVISION, actual HEAD equality, all13 replayed local product files byte-equal exact Git blobs before network; historical/current SW pins and live equality retained without fallback.
amendment-isolation: curl first option -q disables .curlrc; prior screenshot metadata accepts only four exact emitted basenames before any archive/copy; tracked private paths removed.
amendment-checks: node --check PASS; nine bounded preflight cases PASS, each actual child exit1 with expected rejection and zero network/forbidden-read/archive activity (missing/short/uppercase/invalid/mismatched revision; traversal/absolute/unknown filename; synthetic dirty local byte).
amendment-tested-revision: 58d742aa7442ddc1663dbd9c3553e644bf0a7a2b; amended tool uncommitted; raw expected failures and fixture sources retained separately owner-locally; no complete browser rerun.
pre-consolidation-harness-sha256: 6dadef86cfeef692487c9ddd155555f970fbad93da8b920312749384f0d6eca6; Core reports amended complete run34026 exit0/all9 cases66 assertions PASS, not a new owner run.
consolidation-checks: node --check PASS; runtime body exact-equals reviewed superset (SHA2564233d4563d99ce60f3d8f29e2d2acc5e1e156fc329552d3c47855b2ae5edc015); Git/source pins/guards unchanged; no other scripts/CI callers; no browser rerun.
next: Core owns committed-head/full CI/postmerge/live gate/adjudication and current sanitized evidence; no commit/push/external write/CI/deploy performed here.

core: full code372ebfe993eb7a9691c1386f5a6a3ac75261bbd9 canonical run exit0, nine cases/66 assertions; all4 exact image hashes inspected/reused; sanitized browser-only snapshot qualified. Hosted CI/Security/normal merge/main/Pages recheck pending; no product/UI/SW change or archival fallback acceptance.
