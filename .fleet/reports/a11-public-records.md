id: a11-public-records (R9, GH-277)
status: ok (PRM-34 resolved by owner decision 2026-09-30: bounty removed; PRM-35 belongs to the contract epic #276)
worker: claude (Codex stand-in, solo)
branch: agent/claude/prometheus-standin-20260930
summary:
  PRM-34: SECURITY.md bug bounty labelled "planned — not active, not funded"; reports create no payment entitlement; table renamed "Planned reward". Whether to fund/publish a real bounty (e.g. KAS interim) is Gio's decision.
  PRM-36: supersede banners (history retained) on memory/SPRINTS, CHECKPOINT, MEMO, AUDIT, TODO and BACKLOG pointing to README/roadmap/STATUS/.fleet/PLAN; TODO GH-272 marked done (PR #281 merged 2026-09-19, main 32ca5f1); GH-279 marked in progress on the stand-in branch. No CI freshness gate added (would need a policy on which files must stay fresh — proposal for Codex).
  PRM-37: validator/guardian guides get target-status banners, conditional tense, working `cargo test` command, the PRM-35 cooldown discrepancy disclosed (value itself untouched), stale YARA validation step corrected.
  PRM-38/39: see HTML commit; visual gate at 1440x1000, 1180x820, 820x1180, 390x844 before/after with computed assertions (no horizontal overflow, no duplicate ids, no broken in-page anchors, no clipped text in changed components, no card outside its grid, no page errors); first attempt "1,400+" clipped at 390px and was replaced by "1k+" (verified 1426 Guardian tests on this branch). All screenshots inspected.
  PRM-40: 14 files: operator home paths replaced by `$HOME` (only the hash-pinned audit quote keeps the original as evidence).
  PRM-41: CLAUDE.md replaced by concise project-specific guidance (layout, invariants, gates) pointing to AGENTS.md.
  PRM-46: robots.txt uses ClaudeBot (retired Claude-Web removed) plus OAI-SearchBot, ChatGPT-User, Google-Extended, CCBot. security.txt deliberately NOT added: the site is a GitHub project page under /prometheus-/, and RFC 9116 requires /.well-known/ at the domain root, which this repository cannot serve — adding it would claim an unsupported standard.
files: SECURITY.md, robots.txt, CLAUDE.md, BACKLOG.md, memory/{SPRINTS,CHECKPOINT,MEMO,AUDIT,TODO,STATUS}.md, docs/{validator-guide,guardian-guide}.md, docs/agent-bridge/*.md (paths), docs/architecture/MAP.md (path), index.html, guardian-economics.html, .fleet/artifacts/a11-public-records/*
tests: public-claim consistency + 94 claim/status/hygiene tests OK; documentation hygiene OK; project-status consistency OK; memory integrity OK; visual gate run3.json: 8/8 "after" views clean.
risks: sw.js is cache-first with a fixed cache name and root-absolute asset paths; on the project page its install likely fails, so stale-HTML caching is unlikely, but this is exactly A10/#275 (repair vs remove, Gio decision). Post-deploy visual recheck is owed after Pages deploys the merge.
security: none.
next: Codex review; Gio: PRM-34 funding decision, A10 service worker decision.
