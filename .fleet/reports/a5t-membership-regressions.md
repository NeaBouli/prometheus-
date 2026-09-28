id: a5t-membership-regressions
status: ok
worker: claude
branch: agent/claude/a5t-membership-regressions
summary: |
  Module: modules/guardian-node voting (jaeger); hop: GuardianMembershipAuthority
  apply_transition / rotate_authority -> durable SQLite ledger. Test-only hardening,
  no production or fixture change. Two new tests plus helpers (_ledger_snapshot,
  _assert_current_epoch) reusing existing _setup/_wire/_rotation_wire/_next_source:
  1) forward 0->3->5, then rollback to bootstrap epoch 0, unused lower epoch 4,
     applied lower epoch 3, equal epoch 5 with a different signed source, stale
     previous epochs 3/0, and current epoch with stale digest are all rejected with
     GuardianMembershipTransitionError; full ledger snapshot (all tables +
     user_version) unchanged after each rejection, on the live instance and after
     restart from the durable ledger; stale current_source epochs rejected; a valid
     5->6 still applies after restart and the rejections stay rejected.
  2) after membership 0->1 and authority rotation 0->1: rotation replay
     (ReplayError), authority epoch skip 1->3, equal and lower authority epochs,
     retired-key rotation, stale membership binding to bootstrap, retired-key
     membership advance, current-key membership rollback and epoch-1 re-apply are
     rejected; snapshot unchanged, live and after restart; valid key1 1->2 applies.
  PRM-02 conclusion confirmed: production already enforces strict monotonicity.
files:
  - modules/guardian-node/tests/test_guardian_membership_transition.py (+238, insertions only)
  - .fleet/reports/a5t-membership-regressions.md
tests: |
  (modules/guardian-node, /tmp/a5-venv python)
  PYTHONPATH=. python -m pytest tests/test_guardian_membership_transition.py -q -> 58 passed
  PYTHONPATH=. python -m pytest tests/ --tb=short -q -> 1393 passed, 4 skipped
  black --check on the file -> clean (original file was black-clean; only new code formatted)
risks: |
  Low. Tests assert error class hierarchy (TransitionError covers ReplayError) rather
  than exact subclass for membership rejections, since the rejecting check may be
  parse-time or ledger-time; state invariance is asserted via full ledger snapshot.
security: none (test-only; test-only deterministic keys as in existing helpers)
next: Orchestrator review and integration into agent/* ; no docs/runtime change needed.
