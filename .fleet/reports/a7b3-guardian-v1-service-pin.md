id: a7b3-guardian-v1-service-pin
status: ok
worker: claude
branch: agent/claude/a7b3-guardian-v1-service-pin
summary: |
  Module guardian-node hint pipeline, hop H5 (MAP.md): threat_hint_service.py owner-only
  config -> Kip16Groth16Verifier. Added required `expected_executable_sha256` to _KIP16_FIELDS
  (exact-set check, so missing/unknown stay rejected), validated via _sha256 (str + fullmatch
  [0-9a-f]{64}), retained as ThreatHintServiceConfig.verifier_executable_sha256, required non-None
  in build_service and passed as the keyword-only ctor anchor. No default, env, derivation or
  alternate path. Errors are fixed labels (no path/digest). Closes the A7b2 red build.
files:
  - modules/guardian-node/jaeger/threat_hint_service.py (+19/-2)
  - modules/guardian-node/tests/test_threat_hint_service.py (kip16 fixture helpers, 4 tests / 11 cases)
  - .fleet/reports/a7b3-guardian-v1-service-pin.md
tests:
  - PYTHONPATH=. pytest tests/test_threat_hint_service.py tests/test_threat_hint_ingress.py -q -> 35 passed
  - new service tests vs HEAD service code -> 11 failed, 2 passed (regressions bite)
  - covered: missing (schema reject), malformed x8 (upper, short, long, non-hex, empty, int, bool,
    array), wrong digest (build -> "not trusted"), correct digest (spy asserts ctor got the pinned
    digest, real verifier constructed); every failure asserts message excludes dir path and digests
  - PYTHONPATH=. pytest tests -q (guardian-node) -> 1410 passed, 4 skipped
  - black --check (2 files) -> unchanged; ruff check -> all passed
  - pylint (2 files, C0114-6 disabled) -> 9.92/10; only pre-existing R0902 (dataclass attr count
    10->11) and R0916 in untouched _validate_owner_config, both present at HEAD
  - tools: /private/tmp/a5-venv (pytest/black/pylint), ~/.local/bin/ruff
risks:
  - Breaking config change: existing kip16_groth16 TOML configs without the field now fail to load
    (intended, no migration fallback per brief). Operators must add the reviewed digest.
  - manifest anchor still validated only as non-empty string in the service (ctor enforces hex);
    left unchanged as out of scope.
  - Residual TOCTOU hash-check -> exec-by-path unchanged (as A7b/A7b2).
security: none new. PRM-07 executable anchor now wired end-to-end for the v1 service path.
next: Orchestrator review of A7b2+A7b3 together, then integration; no main push/deploy done.
