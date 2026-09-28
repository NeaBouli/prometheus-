id: a8a4-rusty-kaspa-pin-inventory
worker: claude
mode: read-only analysis; write only the Fleet report
branch: agent/claude/a8a4-rusty-kaspa-pin-inventory
architecture_node: Cargo dependency trust boundary feeding Rust workspace modules

Inspect only root/workspace Cargo manifests and lockfile, direct Kaspa-consuming crate manifests, Kaspa dependency/audit CI steps, and the v2 relation-manifest source/tests. Report exact current Rusty Kaspa pins and consumers, what official v2.1.0 compatibility would require, and which historical relation/proof artifacts must remain pinned to v2.0.1.

Define the smallest fail-closed compatibility gate, candidate files, commands/tests, rollback point, and risks. Separate a candidate build/test lane from any default-pin migration. Do not modify code, manifests, lockfile, workflow, proof/evidence, claims, network, chain, deploy, or production state.

Write `.fleet/reports/a8a4-rusty-kaspa-pin-inventory.md` in Fleet format. Do not start another agent.
