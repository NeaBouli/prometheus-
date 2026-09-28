id: a7b-guardian-v1-verifier-ledger
status: partial
worker: claude
branch: agent/claude/a7b-guardian-v1-verifier-ledger
summary: |
  Module guardian-node, hop H5 (docs/architecture/MAP.md): ThreatHintIngress ->
  Kip16Groth16Verifier subprocess -> ThreatHintReplayLedger. All three PRM-07 subfindings
  re-verified as valid on HEAD 8a163d8 and fixed: (1) executable bytes are hashed via
  O_NOFOLLOW fd + fstat identity at preflight and re-hashed (hmac.compare_digest) before every
  Popen; (2) ledger prep uses lstat, O_NOFOLLOW create, regular-file/owner/S_IMODE==0o600;
  (3) killpg PermissionError/ProcessLookupError falls back to kill+reap (v2 pattern).
files:
  - modules/guardian-node/jaeger/threat_hint_ingress.py (+65/-24)
  - modules/guardian-node/tests/test_threat_hint_ingress.py (+144, 6 new tests)
tests:
  - PYTHONPATH=. pytest tests/test_threat_hint_ingress.py -q -> 21 passed
  - same 6 new tests against HEAD code -> 4 failed (replacement x2, killpg PermissionError, symlink/unsafe ledger)
  - PYTHONPATH=. pytest tests/ -q (modules/guardian-node) -> 1399 passed, 4 skipped
  - black --check (both files) -> unchanged; ruff check -> all passed
  - pylint jaeger/threat_hint_ingress.py --disable=C0114,C0115,C0116 -> 9.75/10 (HEAD 9.71; 2 pre-existing R0916)
risks:
  - PARTIAL: v1 has no existing trusted executable digest source (Kip16Groth16Verifier is only
    constructed in tests; ctor takes binary/manifest/manifest-sha256 only). Missing gate: an
    operator-supplied expected verifier_executable_sha256 for v1 (as v2 config has). Per brief
    no digest was invented/hardcoded and no interface added; the binding is preflight-observed
    bytes (TOFU): replacement AFTER preflight is rejected, a malicious binary AT preflight is not.
  - Residual TOCTOU: hash-check -> exec by path (same as v2); sqlite3 reopens ledger by path per
    connection (no fd binding). Parents are owner-only, so same-user only.
  - Ledger created under a umask stripping 0o600 bits is now rejected (fail-closed) instead of used.
security: none new; PRM-07 (Low) fixed except external digest anchor (see risks).
next: Orchestrator decides whether v1 gets an expected executable SHA-256 input (interface change,
  separate brief) or v1 verifier stays test-only/unwired. Review required (status partial).
