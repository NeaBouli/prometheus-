id: handback-sw-scope-fix
worker: claude
mode: implement
branch: agent/claude/handback-sw-scope-fix
architecture_node: public web -> retired service worker -> origin CacheStorage

Codex found sw.js:11 deletes every cache on the shared GitHub Pages origin. Fix only retired-worker cleanup to delete exact known Prometheus-owned legacy cache names, preserving unrelated origin caches. Inspect the historical worker to establish exact names; avoid an unbounded prefix. Keep unregister/skipWaiting behavior. Do not add registrations or features.
Acceptance: real browser regression seeds owned and unrelated caches, activates retired worker, verifies owned caches removed, unrelated caches preserved and registration gone. Follow frontend-visual-release-gate as applicable. Run public CSS/claim/status/hygiene gates and relevant tests. Review your diff; no deploy, main merge, external writes or further agents. Report .fleet/reports/handback-sw-scope-fix.md and append Bridge/PLAN.
