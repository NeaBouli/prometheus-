id: a1-gh267-rebase
status: partial
worker: claude
branch: agent/claude/a1-gh267-rebase
summary: Module/hop: target endpoint detection gate (MAP GH-258/261 row) -> owner-approved endpoint observation input -> fail-closed pre-producer privacy/threat-model gate.
  PR #268 (head 5960f1b, base 8b5da58) cherry-picked 1:1 onto exact main 32ca5f1 (base was 1 commit behind: #281 lockfile/docs only).
  New commits 6f69a1a, 3717c43, dbc160b; per-file +/- lines identical to PR #268 except ACTION_LOG.md (entries re-ordered chronologically).
  Conflicts only in docs/agent-bridge/ACTION_LOG.md and memory/TODO.md (GH-258/261 line takes PR text; GH-272 section kept). No conflict markers.
  MAP.md GH-258/261 row notes the gate files as rebased candidate (not on main); status column unchanged.
files: .github/workflows/security-audit.yml (+5, see risks), README.md, WHITEPAPER.md, docs/agent-bridge/{ACTION_LOG,CODEX_BRIDGE}.md,
  docs/endpoint-observation-v1.md, docs/evidence/endpoint-producer-privacy-threat-model-v1.json (new), docs/evidence/public-claim-status-2026-08-14.json,
  docs/{faq,roadmap}.md, docs/architecture/MAP.md, faq.html, index.html, roadmap.html, whitepaper.html, llms.txt, memory/{CHECKPOINT,STATUS,TODO}.md,
  modules/{client,guardian-node,threat-hint}/README.md, scripts/{verify,test}_endpoint_producer_privacy_gate.py (new), scripts/{verify,test}_public_claim_consistency.py
tests: python3 scripts/verify_endpoint_producer_privacy_gate.py -> OK
  python3 -m unittest scripts/test_endpoint_producer_privacy_gate.py -> 37 tests OK
  python3 scripts/verify_public_claim_consistency.py -> PASS (13 surfaces); python3 -m unittest scripts/test_public_claim_consistency.py -> 69 tests OK
  check_public_documentation_hygiene.py -> passed; test_public_documentation_hygiene.py -> 11 OK; check_memory_integrity.py -> passed
  verify/test_project_status_consistency.py -> 7 OK; test_autodidactic.py -> 6 OK; git diff --check -> clean
  No Rust/Cargo file changed -> cargo gates not affected (not re-run).
  Visual gate (Playwright/Chrome, file://): index/faq/roadmap/whitepaper x 1440x1000,1180x820,820x1180,390x844 -> 16/16 PASS
  (GH-267 block visible, opacity 1, in viewport, no doc overflow, no clipping; faq accordion opened). Screenshots /tmp/gh267-shots/*.png, viewed 6.
risks: BRIEF CONFLICT: PR #268 intentionally adds a 5-line "Endpoint Producer Privacy Gate" step to .github/workflows/security-audit.yml,
  but the brief forbids workflow/CI-governance changes. I kept it because public surfaces claim a "Security-CI drift gate"; dropping it would make
  those claims false. Orchestrator must decide: keep (additive step, no trigger/permission change) or drop step AND reword Security-CI claims.
  Bridge/memory entries record hosted CI runs of the original PR head; the rebased head has no hosted CI yet. No touch-target changes (text only).
security: none (no secrets, wallets, keys, sensors, transport or runtime behavior; gate is fail-closed, verifier/tests unchanged from PR).
next: Codex decides workflow-step question; then open replacement PR from this branch (original PR #268 branch untouched), hosted CI/Security/Pages on final head.
