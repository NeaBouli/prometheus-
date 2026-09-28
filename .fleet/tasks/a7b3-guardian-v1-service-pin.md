# A7b3 - Wire the trusted v1 verifier digest into the service

Architecture boundary: Guardian H5,
`threat_hint_service.py` owner-only config -> `Kip16Groth16Verifier`.

## Objective and scope

- Add a required `expected_executable_sha256` field to the existing
  `kip16_groth16` service configuration, validate canonical lowercase 64-hex,
  retain it in the typed config, and pass it to the now fail-closed verifier
  constructor.
- No default, migration fallback, environment lookup, digest derivation from
  the configured binary, or alternative verifier path. Unknown/missing fields
  remain rejected and errors must not expose paths or digest values.
- Limit edits to `jaeger/threat_hint_service.py`, focused service tests, and a
  module-local example fixture only if an existing test owns it. Do not change
  ingress logic, v2, proof semantics, runtime, network, ledger, public docs, or
  deployment behavior.

## Acceptance

- Regressions cover missing, malformed, wrong and correct executable anchors;
  the positive service build reaches the pinned constructor, and all failures
  remain fail-closed and redacted.
- Run focused service and ingress tests, complete Guardian pytest, Black, Ruff,
  and changed-file Pylint.
- Write `.fleet/reports/a7b3-guardian-v1-service-pin.md`; no main push,
  deployment, external verifier, secret, or subagent.
