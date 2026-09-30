id: a8b2r-isolated-silverc-build
status: ok
worker: codex (bounded fallback after Claude returned no report/diff)
branch: agent/codex/prometheus-master-plan-20260927
summary: Preflight builds SilverC with `--locked` into a fresh temporary Cargo target, executes only that binary, returns a deterministic redacted path label, and cleans the target on exit. A stale default-target binary is never selected.
files: scripts/preflight_silverc_deploy.py; scripts/test_silverc_manifest_build_pin.py
tests: A8b focused unittests -> 42 passed; Ruff -> passed; Mypy -> passed; py_compile -> passed; git diff --check -> passed
risks: The full real upstream compile is deferred to the combined A8 integration gate; no default pin or artifact changed.
security: Closes the Codex review finding for ignored/incremental Cargo target reuse. No secrets or external state touched.
next: Implement A8c Rusty Kaspa source-policy gate, then run combined verification.
