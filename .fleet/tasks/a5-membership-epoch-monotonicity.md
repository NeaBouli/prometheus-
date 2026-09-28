# A5 — Guardian membership epoch monotonicity (PRM-02)

Architecture boundary: `modules/guardian-node` owner-local membership authority,
`jaeger/guardian_membership_transition.py`; MAP M4 remains blocked.

## Objective and scope

- Re-verify PRM-02 against the current branch before changing code. If invalid,
  return `partial` with evidence and no speculative patch.
- Enforce strict monotonicity for accepted membership transitions: an incoming
  epoch must be greater than the durable current epoch. Reject replayed, equal,
  lower, malformed, missing, or out-of-range epochs before state mutation.
- Preserve existing signatures, canonical serialization, owner-local authority,
  atomicity, error redaction, and crash/restart behavior.
- Limit edits to the existing membership-transition module and its focused
  tests/fixtures. Do not add remote authority, key rotation, retries, network
  paths, L1 attestation, Sybil logic, migrations, or a second state store.

## Acceptance

- Add regressions for forward transition, equal replay, rollback, malformed and
  boundary epochs, restart persistence, and no-mutation on rejection.
- Run focused membership tests, complete Guardian pytest, and available Python
  lint/type checks already used by this module. Do not weaken tests.
- No changes to contracts, KAS/PROM, slash access, commit-reveal, public claims,
  CI governance, deployment, wallet, chain, or production state.
- Report exact commands/results in
  `.fleet/reports/a5-membership-epoch-monotonicity.md`; no main push, deploy,
  external message, secret, or subagent.
