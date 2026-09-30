id: a8c-toolchain-pin-policy
worker: claude
mode: implementation
branch: agent/claude/a8c-toolchain-pin-policy
architecture_node: Cargo/SilverScript dependency policy gate before all Rust workspace builds

Create one small machine-readable active-pin policy, a Python verifier, focused unittests, and one CI registration. Do not change current versions, Cargo.toml, Cargo.lock, proof code, contracts, artifacts, or evidence.

The gate must structurally parse Cargo.toml/Cargo.lock and fail unless: all eight direct rusty-kaspa dependencies use the policy tag and canonical URL; every locked `kaspa-*` package resolves from exactly one canonical source with the policy tag and commit; workspace and locked `silverscript-lang` use the policy commit; no duplicate Kaspa source graph exists; and threat-proof's historical Rusty Kaspa tag/commit remain equal to separately named immutable artifact-identity pins. Policy and errors must be deterministic and contain no candidate approval or rollout claim.

Files: one policy JSON under an existing suitable config/docs boundary, `scripts/verify_toolchain_pins.py`, `scripts/test_toolchain_pins.py`, `.github/workflows/ci.yml`, and Fleet report. Tests must cover tag/commit/source drift, split Kaspa graphs, SilverScript drift, immutable-proof drift, malformed/duplicate policy data, real-repo pass, YAML parse, Ruff, Mypy, and diff check. No network, upgrade, deploy, wallet, chain, or production action. Do not start another agent.
