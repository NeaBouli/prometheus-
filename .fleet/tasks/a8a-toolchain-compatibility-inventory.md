id: a8a-toolchain-compatibility-inventory
worker: kimi
mode: read-only analysis; only write the requested Fleet report
branch: agent/kimi/a8a-toolchain-compatibility-inventory
architecture_node: build/toolchain trust boundary feeding modules/contracts/silverc and modules/silverc-deployer

Goal: map the exact current Kaspa/SilverScript dependency and compiler pins and design a separate compatibility gate. Do not implement upgrades or security fixes.

Inspect only relevant workspace manifests/lockfiles, SilverC verification scripts, CI jobs, architecture/status documentation, and official upstream release/tag metadata. Identify current exact versions/commits, all consumers of Rusty Kaspa and SilverScript/SilverC, generated-artifact assumptions, and the smallest ordered upgrade slices. Distinguish compatibility evidence from rollout evidence.

Acceptance:
- report current pins and every affected module/hop;
- compare current pins with official Rusty Kaspa v2.1.0 and SilverScript v1.0.0 without assuming compatibility;
- specify fail-closed machine-checkable gates, exact candidate files, tests, rollback point, and risks;
- keep relation/proof manifests and H-001 evidence immutable unless a later explicit migration brief says otherwise;
- no product, contract, lockfile, workflow, public claim, network, wallet, chain, deploy, or production change.

Write `.fleet/reports/a8a-toolchain-compatibility-inventory.md` using the Fleet report format. Do not start another agent.
