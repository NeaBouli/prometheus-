# A7b2 - Require a trusted v1 verifier digest (PRM-07 closeout)

Architecture boundary: Guardian H5,
`Kip16Groth16Verifier` construction -> verifier preflight -> subprocess.

## Objective and scope

- Replace A7b's TOFU-only executable binding with a required caller-supplied
  expected SHA-256. Validate canonical lowercase 64-hex form, compare against
  the descriptor-read digest at construction and before every invocation, and
  keep public errors redacted.
- The expected digest is a trust input, never derived from the executable being
  approved. No default, optional fallback, hardcoded digest, environment read,
  config file, CLI flag, or second verifier path.
- Limit edits to `jaeger/threat_hint_ingress.py`, its focused tests, and the A7b
  report status. Update every in-repo constructor call. Do not alter proof,
  manifest, runtime, network, ledger, database, or v2 behavior.

## Acceptance

- Regressions prove malformed/wrong digests reject at construction, correct
  digest works, post-construction replacement rejects before spawn, and errors
  expose neither paths nor digest values.
- Run focused ingress tests, complete Guardian pytest, Black, Ruff, and
  changed-file Pylint.
- Write `.fleet/reports/a7b2-guardian-v1-verifier-pin.md`; no main push,
  deployment, external verifier, secret, or subagent.
