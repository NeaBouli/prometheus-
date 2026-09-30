id: a8b2r-isolated-silverc-build
worker: claude
mode: security fix verification
branch: agent/claude/a8b2r-isolated-silverc-build
architecture_node: SilverC compiler binary provenance in preflight inspect_silverc

Codex review found A8b2 can still execute a tampered ignored `target/debug/silverc` when Cargo reports it fresh. In `scripts/preflight_silverc_deploy.py`, build with `cargo build --locked --target-dir <fresh isolated temporary directory>` and execute only that directory's binary. Ensure cleanup on success/failure and keep returned/error data redacted and deterministic.

Add focused tests proving a pre-existing default-target binary is never selected and the isolated target is passed to Cargo. Touch only preflight, its focused test file(s), and the Fleet report. Run A8b1+A8b2 focused tests, Ruff, Mypy, py_compile, and diff check. Do not change pins, CI, contracts, evidence, artifacts, or versions. Do not start another agent.
