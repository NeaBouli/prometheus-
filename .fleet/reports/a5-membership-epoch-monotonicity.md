id: a5-membership-epoch-monotonicity
status: partial
worker: claude
branch: agent/claude/a5-membership-epoch-monotonicity
summary: |
  Module/hop: modules/guardian-node owner-local membership authority (MAP row "voting (jaeger)"),
  hop GuardianMembershipAuthority.apply_transition / rotate_authority -> SQLite ledger. MAP M4 stays blocked.
  PRM-02 re-verification: INVALID on this branch. Strict monotonicity already holds by chaining:
  _parse_transition rejects next_epoch <= previous_epoch (guardian_membership_transition.py:1091) and
  apply_transition requires previous_epoch == durable current epoch + digest (:338-339), so next > current;
  rotation requires next = previous + 1 (:1167) and previous == durable authority epoch (:475).
  The audit's "rollback to bootstrap epoch" needs next < previous or a stale previous; both fail closed.
  File unchanged since audit baseline 8b5da58 (git diff 8b5da58 HEAD empty), so finding was invalid at baseline too.
  Per brief: no speculative patch, no repo test changes.
files: .fleet/reports/a5-membership-epoch-monotonicity.md (only; no code/test changes)
tests: |
  Env: uv venv -p 3.12 /tmp/a5-venv + requirements.txt (system python3.14 cannot build deps).
  Throwaway probe /tmp/a5-probe/test_prm02_probe.py (not committed; reuses repo test helpers):
    signed rollback 1->0 (alt digest), equal 1->1, stale previous 0->1 / 0->2 after reaching epoch 1,
    rotation (0,0),(1,0),(0,2),(1,2) all rejected; durable epoch stays 1 across fresh authority instance;
    controls 0->1->2 + rotation 0->1 succeed -> 10 passed
  PYTHONPATH=. python -m pytest tests/test_guardian_membership_transition.py -q -> 56 passed
  PYTHONPATH=. python -m pytest tests/ --tb=short -q (modules/guardian-node) -> 1391 passed, 4 skipped
  black --check modules/guardian-node/jaeger/ -> 36 files unchanged
  pylint jaeger/guardian_membership_transition.py --disable=C0114,C0115,C0116 -> 9.94/10
risks: |
  Existing coverage of equal/lower epochs is parser-level (test_epoch_and_window_fail_closed (0,0),(1,0));
  there is no committed regression for the specific "rollback to bootstrap epoch after a forward
  transition" or rotation epoch-skip cases. Adding them is test-only hardening, not a fix; needs
  orchestrator decision since the brief forbids patches when the finding is invalid.
  Audit record docs/community-audits/prm-full-scope-audit-2026-09-15.md still lists PRM-02 as Medium.
security: none (finding not reproducible; no new vulnerability observed)
next: |
  Codex: decide (a) mark PRM-02 invalid in the audit record like PRM-01 (docs task, needs auditor consent),
  and/or (b) authorize a test-only follow-up committing the probe cases as regressions.
