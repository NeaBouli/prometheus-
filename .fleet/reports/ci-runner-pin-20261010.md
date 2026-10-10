id: ci-runner-pin-20261010
status: partial
worker: Codex (small orchestration configuration/glue task)
branch: agent/codex/ci-runner-pin-20261010
summary: Preserve the tested Ubuntu24.04 major OS baseline at the existing
  workflow -> Toolchain Pin Policy -> required hosted checks hop. Eleven
  labels changed; one registration regression covers both workflow extensions.
files: two workflow files, scripts/test_toolchain_pins.py, MAP, Memory and Fleet/Bridge records
tests:
  - parent-owned YAML parse/equality -> PASS, eleven labels only; Python AST PASS (no target execution)
  - ruff check --isolated --no-cache scripts/test_toolchain_pins.py -> PASS
  - git diff --check -> PASS
  - existing hosted full CI/Security -> pending normal PR; no manual dispatch
  - Actionlint -> NOT RUN (not installed); do not imply a pass
risks: An explicit OS label still receives image/package updates; Ubuntu26 is
  neither evaluated nor enabled here. Hosted regression/full checks still needed.
security: none (permissions, action/dependency pins and trust gates unchanged)
next: normal PR, actual exact-head required checks, protected merge and main evidence;
  no duplicate worker task or local target suite. Keep PR293 Draft and v2/D5 gates closed.

Evidence baseline: main eecbaf5, CI38009850053 job114087074856 ran on
ubuntu-24.04 image20261004.327.1. GitHub's planned floating-label migration:
https://github.com/actions/runner-images/issues/14748 (2026-10-19 through2026-11-19).
