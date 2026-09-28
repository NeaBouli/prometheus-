# A7b - Harden Guardian v1 verifier and ledger paths (PRM-07)

Architecture boundary: `modules/guardian-node`, v1 ThreatHint ingress hop in
`jaeger/threat_hint_ingress.py`: trusted verifier preflight -> subprocess ->
owner-local replay ledger.

## Objective and scope

- Re-verify every PRM-07 subfinding on the current branch. Invalid portions
  must be reported with evidence, not patched speculatively.
- Reuse the v2/sibling invariants: bind the verifier executable to an existing
  trusted expected SHA-256 and re-hash before every invocation; prepare an
  existing ledger with `lstat`/no-follow, regular-file, owner and exact-mode
  checks; handle process-group permission races without leaving a child.
- If v1 has no existing trusted digest source, do not invent/hardcode one or
  add an interface. Return that portion `partial` with the exact missing gate,
  while completing independently valid ledger/process fixes.
- Limit code edits to `jaeger/threat_hint_ingress.py` and its focused tests.
  No v2 behavior, proof relation, crypto, runtime mode, network, database
  schema, CLI/config interface, public claim, or deployment change.

## Acceptance

- Regressions cover executable replacement after preflight, symlink and unsafe
  existing ledger files, exact safe mode, permission/process-exit races, stable
  redacted errors, and no ledger mutation on rejection.
- Run focused ingress tests, the complete Guardian pytest suite, Black, Ruff,
  and changed-file Pylint where configured.
- Write `.fleet/reports/a7b-guardian-v1-verifier-ledger.md`; no main push,
  deploy, external process beyond test fixtures, secret, or subagent.
