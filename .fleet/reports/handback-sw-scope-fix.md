id: handback-sw-scope-fix
status: ok
worker: claude
branch: agent/claude/handback-sw-scope-fix
summary: Module modules/web, hop public web -> retired service worker -> origin CacheStorage (MAP.md row modules/web). sw.js activate deleted every cache on the shared GitHub Pages origin. The historical worker (20e8531, only prior version) created exactly one cache, 'prometheus-v1'; the retired worker now deletes only names in OWNED_CACHES = ['prometheus-v1'] (exact match, no prefix). skipWaiting and registration.unregister unchanged; no registration or feature added.
files: sw.js; scripts/browser_retired_service_worker_regression.mjs (new real-browser regression); docs/agent-bridge/ACTION_LOG.md; .fleet/PLAN.md; this report
tests: |
  Browser regression (Playwright Chromium, localhost, scope /prometheus-/): seeds prometheus-v1 + other-project-v1, prometheus-v2, workbox-precache-v2; activates sw.js -> after: registrations 0, caches [other-project-v1, prometheus-v2, workbox-precache-v2], no page errors -> PASS.
  Negative control with previous sw.js (HEAD): all caches deleted -> regression FAILS (3 unrelated caches lost), proving the test detects the defect.
  verify_site_css OK (5 pages); verify_public_claim_consistency PASS (13 surfaces); check_public_documentation_hygiene pass; verify_project_status_consistency pass; check_memory_integrity pass; unittest test_site_css, test_public_claim_consistency, test_public_documentation_hygiene, test_project_status_consistency: OK.
  frontend-visual-release-gate: not applicable — no rendered HTML/CSS changed (sw.js is not rendered); no screenshots taken.
risks: A client that installed a worker with a cache name other than prometheus-v1 keeps that cache; git history shows no other name. The regression needs Playwright (PLAYWRIGHT_MODULE env); it is not wired into CI because CI has no browser toolchain — Codex decides whether to add it.
security: No finding. Change narrows destructive scope (cross-project cache deletion on shared origin removed). No secrets touched.
next: Codex review of diff and regression; decide on CI wiring of the browser regression; merge via protected PR per release gate.
