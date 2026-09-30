id: a7c-guardian-policy-descriptor-reads
status: ok
worker: claude
branch: agent/claude/a7c-guardian-policy-descriptor-reads
summary: |
  Module: modules/guardian-node hint pipeline (jaeger), MAP.md row "Verifier ingress ... v2 promotion/acceptance".
  Hops: H4/H5 service config load (threat_hint_service.py::load_service_config) and the v2 preflight
  policy load (threat_hint_v2_preflight.py::_load_preflight_policy, feeding verified preflight/acceptance).
  PRM-08 re-verified on HEAD 480b303: both loaders did lstat() then Path.read_text() by path
  (TOCTOU: replacement/symlink swap between check and read was parsed). Replaced in place with the
  sibling pattern from outbox_retention_policy.py: lstat checks unchanged -> os.open(O_RDONLY|O_NOFOLLOW)
  -> fstat dev/ino/size/type/owner/mode match -> bounded read (limit+1) -> post-read fstat identity/size
  + byte-count == lstat size -> strict ASCII decode (existing stricter-than-UTF-8 schema kept) -> parse.
  Helpers stay module-local; byte limits (4096 / 8192), schemas and error messages unchanged; no reopen by path.
files:
  - modules/guardian-node/jaeger/threat_hint_v2_preflight.py
  - modules/guardian-node/jaeger/threat_hint_service.py
  - modules/guardian-node/tests/test_threat_hint_v2_preflight.py (+8 tests)
  - modules/guardian-node/tests/test_threat_hint_service.py (+8 tests)
tests: |
  New regressions (both loaders): single O_NOFOLLOW open + no path reread, exact-limit load / over-limit reject,
  invalid UTF-8, replace/symlink swap between check and open, grow/shrink during read, inode change after open,
  redacted messages (no path/contents), tomllib.loads forbidden after rejection (no downstream parse).
  Counter-check: 12 of the new tests fail against the pre-change modules (PRM-08 reproduced).
  Focused: 62 passed. Full Guardian pytest: 1426 passed, 4 skipped.
  Black --check clean, Ruff clean, Pylint changed files 9.99/10 (only pre-existing R0902 on the config dataclass);
  CI-equivalent pylint jaeger/ 9.86/10. (Env: /tmp/a5-venv, Python 3.12.)
risks: |
  Brief says "strict UTF-8"; ASCII decode kept intentionally (preserves existing schema, strict subset).
  Preflight module adds duplicate-code to its existing pylint pragma, same convention as
  threat_hint_v2_verified_preflight.py. Service loader relies on POSIX O_NOFOLLOW (already POSIX-only via getuid).
security: PRM-08 fixed in scope; no new finding. No secrets touched.
next: Codex review + integration of agent/claude/a7c-guardian-policy-descriptor-reads; no main push, no deploy.
