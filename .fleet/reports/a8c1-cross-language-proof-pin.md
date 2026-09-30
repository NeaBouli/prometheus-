id: a8c1-cross-language-proof-pin
status: ok
worker: claude
branch: agent/claude/a8c1-cross-language-proof-pin
summary: The toolchain pin verifier now AST-parses the Python Guardian relation manifest without importing it. Rust and Python must each bind the policy Rusty Kaspa artifact tag/commit exactly once as canonical module-level string constants.
files: scripts/verify_toolchain_pins.py; scripts/test_toolchain_pins.py
tests: toolchain pin unittests -> 55 passed; real-repo verifier -> passed deterministically; Ruff -> passed; strict Mypy -> passed; git diff --check -> passed
risks: The Rust identity parser remains exact-line regex and intentionally fails closed on formatting drift.
security: Closes the cross-language immutable relation-identity gap; no secrets or external state touched.
next: Codex combined A8 integration verification.
