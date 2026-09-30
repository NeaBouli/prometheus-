id: a8b2-silverc-manifest-build-ci
worker: claude
mode: implementation
branch: agent/claude/a8b2-silverc-manifest-build-ci
architecture_node: SilverC compiler build, bundle manifest, and CI trust boundary

Build on integrated A8b1. Touch only `scripts/verify_silverc_h001.py`, `scripts/preflight_silverc_deploy.py`, `scripts/smoke_silverc_artifacts.py`, focused tests for these scripts, and the exact `.github/workflows/ci.yml` registration.

Use Cargo `--locked` for upstream SilverScript build/test calls. Preflight must rebuild the compiler from the already verified checkout instead of accepting an existing binary. Bundle validation must require both `silverscript_ref` and `silverscript_commit` to equal the expected workspace pin. Register the A8b1/A8b2 focused unittest(s) in CI. Preserve redacted errors and all existing artifact hashes/semantics.

Do not change active pins, Cargo.lock, contracts, artifacts, H-001 evidence, public claims, security policy, wallet, chain, deploy, or production state. Run focused tests, Python syntax/lint/type checks, workflow YAML parse, existing SilverC script tests that do not require a real deployment, and diff check. Write the Fleet report; do not start another agent.
