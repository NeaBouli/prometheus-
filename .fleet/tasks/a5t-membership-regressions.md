# A5T — Commit monotonicity regression coverage

PRM-02 is invalid; production code already enforces strict monotonicity. Add
test-only hardening in
`modules/guardian-node/tests/test_guardian_membership_transition.py`.

Cover a forward transition followed by bootstrap/lower and equal rollback
attempts, stale previous epochs, authority rotation replay/skip, restart from
the durable ledger, and prove state is unchanged after each rejection. Reuse
existing helpers and public errors; do not edit production code or fixtures.

Run the focused membership file and complete Guardian pytest. Write
`.fleet/reports/a5t-membership-regressions.md`. Work only on
`agent/<worker>/a5t-membership-regressions`; no docs, runtime, migration,
network, deploy, external action, secret, or subagent.
