id: a7b2-guardian-v1-verifier-pin
status: partial
worker: claude
branch: agent/claude/a7b2-guardian-v1-verifier-pin
summary: |
  Module guardian-node, hop H5 (MAP.md): Kip16Groth16Verifier construction -> preflight -> subprocess.
  Ctor now requires keyword-only expected_executable_sha256 (no default); canonical lowercase
  64-hex enforced, compared (hmac.compare_digest) to the O_NOFOLLOW descriptor-read digest at
  construction and before every Popen. Errors stay fixed strings (no path/digest). TOFU binding removed.
  Blocked: jaeger/threat_hint_service.py::build_service is an in-repo ctor call with no digest source.
files:
  - modules/guardian-node/jaeger/threat_hint_ingress.py (+11/-3)
  - modules/guardian-node/tests/test_threat_hint_ingress.py (+88/-9; all ctor calls updated, 1 new test)
  - .fleet/reports/a7b2-guardian-v1-verifier-pin.md
tests:
  - PYTHONPATH=. pytest tests/test_threat_hint_ingress.py -q -> 22 passed
  - same tests vs HEAD ingress code -> 8 failed (new ctor contract), i.e. regressions bite
  - PYTHONPATH=. pytest tests -q (guardian-node) -> 1 failed, 1399 passed, 4 skipped
    FAILED test_threat_hint_service.py::test_kip16_mode_loads_only_exact_fields
    (build_service -> TypeError: missing expected_executable_sha256) -- NOT weakened
  - black --check (2 files) -> unchanged; ruff check -> all passed
  - pylint ingress+test --disable=C0114,C0115,C0116 -> 9.83/10, no findings on changed lines
risks:
  - BRIEF CONFLICT: "update every in-repo constructor call" vs "no config file source" + edits limited
    to ingress/tests. build_service (kip16_groth16 mode) can only obtain the digest from its owner-only
    TOML config (_KIP16_FIELDS) -- a config source the brief excludes. threat_hint_service.py left untouched;
    kip16 service mode now fails closed at build with TypeError (not ThreatHintIngressError).
  - A7b report claimed v1 verifier is test-only; that was wrong -- the service wires it.
  - Residual TOCTOU hash-check -> exec-by-path unchanged (same as A7b / v2).
security: none new. PRM-07 digest anchor implemented in the verifier; closeout blocked on service wiring.
next: Orchestrator decision needed: follow-up brief adding required `expected_executable_sha256` to
  _KIP16_FIELDS/ThreatHintServiceConfig/build_service (v2 pattern) + service test fixture, or declare
  kip16 service mode unavailable. Branch is red until then; do not merge. Review required.
