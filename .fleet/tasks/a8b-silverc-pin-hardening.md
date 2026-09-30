id: a8b-silverc-pin-hardening
worker: claude
mode: implementation
branch: agent/claude/a8b-silverc-pin-hardening
architecture_node: SilverC compiler and CI trust boundary before modules/contracts/silverc

Implement only the verified A8a3 hardening. Keep the active SilverScript commit `d25bd3427a093c17327ca3d6b9e1aa5f7688c863` unchanged and do not touch contracts or H-001 evidence.

Files: `scripts/verify_silverc_h001.py`, `scripts/preflight_silverc_deploy.py`, `scripts/smoke_silverc_artifacts.py`, new focused Python test, and the exact CI registration needed for that test.

Require a lowercase 40-hex ref equal to the workspace `silverscript-lang` rev; verify canonical upstream origin, clean reused checkout, exact HEAD after checkout, and clean state before/after temporary probe handling. Never reuse an existing compiler binary without rebuilding from the verified checkout. Bind manifest ref and commit to the expected pin. Use Cargo `--locked` for upstream build/test calls. Fail closed with redacted errors.

Tests: focused new tests, existing SilverC script tests, syntax/format checks, and any safe no-network fixture checks. Do not fetch a new version, regenerate artifacts, change lockfiles/default pins, modify security fixes, deploy, or use wallet/chain/network state. Write the Fleet report; do not start another agent.
