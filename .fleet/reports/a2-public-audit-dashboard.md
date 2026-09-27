id: a2-public-audit-dashboard
status: ok
worker: kimi
branch: agent/kimi/a2-public-audit-dashboard
summary: Module/hop: modules/web public status surface (MAP.md §3 row) — repository evidence -> static public claim; no runtime hop added.
  GH-273 resolved: fabricated modules/web/audit/index.html deleted (mock 12 validators/8 guardians/3 rules on-chain, FP rate,
  response time, truncated kaspa: addresses, PROM grants, 30s Kaspa-L1 refresh, on-chain-verifiability). Every public pointer
  removed: 4 page footers, README links, llms.txt Pages entry, sitemap URL, CLAUDE.md, developer-guide tree, sprint prose in
  index.html + roadmap.html. Claim gate now rejects dashboard pointers on 13 public + 8 doc/memory surfaces, 10 fabricated-claim
  categories, and sitemap URLs without existing repository target. MAP.md/map.puml modules/web row updated; STATUS/CHECKPOINT/TODO
  record the removal; Testnet-10/repository-only/production boundaries untouched.
files: modules/web/audit/index.html (deleted), index.html, faq.html, roadmap.html, whitepaper.html, README.md, llms.txt,
  sitemap.xml, CLAUDE.md, docs/developer-guide.md, docs/architecture/MAP.md, docs/architecture/map.puml,
  memory/STATUS.md, memory/CHECKPOINT.md, memory/TODO.md, scripts/verify_public_claim_consistency.py,
  scripts/test_public_claim_consistency.py
tests: python3 scripts/verify_public_claim_consistency.py -> PASS (13 surfaces)
  python3 -m unittest scripts/test_public_claim_consistency.py -> 76 tests OK (7 new: dangling/foreign sitemap URL, pointer in
  public + doc surface, 10 fabricated categories, legitimate-range negative test; stale-lastmod test updated to new signature)
  check_memory_integrity.py -> passed; verify_project_status_consistency.py + unittest -> passed / 7 OK
  check_public_documentation_hygiene.py + unittest -> passed / 11 OK; verify_h001_canary_closeout_evidence.py + unittest -> verified / 4 OK
  CI HTML-pages equivalents (existence, SEO/JSON-LD, infra files, stale-launch grep) -> all OK; test_autodidactic.py -> 6 OK;
  git diff --check -> clean; residual-pointer grep -> only gate patterns/tests and .fleet governance mention the route (intended)
  Visual gate (Playwright 1.61.1/Chromium, file://, script /tmp/a2-visual-check.mjs): index/faq/roadmap/whitepaper x 1440x1000,
  1180x820, 820x1180, 390x844 -> 16/16 PASS: scrollWidth==innerWidth (no overflow), no footer overlap/clipping, footer link
  counts exactly baseline-1 (7/7/7/6), zero dashboard hrefs, all reveal elements opacity>0.95. States: 4x mobile burger menu
  opens (390x844), faq accordion opens. 20 screenshots /tmp/a2-shots/*.png, all inspected (footers + whitepaper regions at
  native resolution). Footer link boxes 21.4x15.0px are pre-existing 10px mono text links, unchanged by this diff.
risks: memory/SPRINTS.md keeps historical row "7 | Audit Dashboard | PENDING" — table is already framed as a replaced historical
  plan; no route/link. index.html logs 2x ERR_FILE_NOT_FOUND for /prometheus-/logo/*.png under file:// only (absolute Pages
  paths with onerror fallback; pre-existing, untouched lines). No touch-target changes (one footer <li> removed per page).
security: none (no secrets, wallets, keys, runtime, backend, telemetry, wallet/chain calls or deployment; static content + gate).
next: Codex inspects branch + screenshots (/tmp/a2-shots), runs hosted CI/Security/Pages on final head, then PR + protected
  merge; after deploy, post-deploy visual gate on the live URLs with cache-busting query (footer spot-check suffices).
