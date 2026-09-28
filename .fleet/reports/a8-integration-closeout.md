id: a8-integration-closeout
status: ok
owner: codex
date: 2026-09-28
summary: The repository now has an offline, fail-closed compatibility and pinning gate for the active Rusty Kaspa and SilverScript toolchains. Security fixes cannot silently change the accepted dependency graph, compiler revision, release-manifest compiler identity, or immutable cross-language threat-proof identity.
active_pins: rusty-kaspa v2.0.1@cfafeb4c093fa37a303f1b9f19c58f986b870ce3; silverscript d25bd3427a093c17327ca3d6b9e1aa5f7688c863
candidate_only: rusty-kaspa v2.1.0@01b532e8b553523216471682649693af92f0fd16; silverscript v1.0.0@3ed973335b59269293564805cc2c58a14595ec03
worker_contribution: Kimi was canonically token-limited. Claude delivered the bounded inventory and implementation slices. Codex integrated them and fixed three security-review findings: symlinked checkout acceptance, reusable default Cargo targets, and an unverified Python Guardian copy of the immutable proof identity.
verification: toolchain verifier passed; 55 toolchain-policy tests passed; 42 SilverC checkout/manifest gate tests passed; Ruff and strict Mypy passed; workflow YAML parsed; cargo tree --locked --offline passed; threat-proof plus silverc-deployer completed 102 tests and 2 compile-fail doc-tests; pinned upstream SilverC probe completed 55 tests; seven release artifacts built; isolated preflight passed with no blockers; H-001 canary-profile regression passed; project-status consistency completed 7 tests; git diff --check passed.
ci_validation: The workflow contains a dedicated toolchain-pins job. Rust workspace and H-001 SilverC jobs depend on it. actionlint was not installed locally; structural YAML parsing and the repository's focused workflow tests passed.
format_note: Ruff lint passed. Ruff format is not the repository's CI formatter for these files and reported legacy formatting differences. The installed environment had no Black executable; the existing CI Black gate covers a different, unchanged Guardian file set.
security: No secrets, wallet material, signed transactions, deployment, broadcast, contract behavior, proof artifacts, or production state changed.
risks: Hosted CI is pending. Tag/commit migration to the observed upstream candidates requires a separate compatibility branch, regenerated lock/policy evidence, full tests, and explicit review. Historical H-001 and proof-identity artifacts remain pinned to their original toolchains.
next: Push the integration branch, observe hosted CI, then open a separate version-reconciliation task without bundling it into security fixes.
