id: handback-contract-review
worker: kimi
mode: review
branch: agent/kimi/handback-contract-review
architecture_node: contracts/silverc state transitions -> SilverC runtime validation -> keyless deployer bundle profile

Review only docs/architecture/ms-b-contract-decisions.md and diff agent/claude/prometheus-standin-20260930..agent/claude/contract-bundle-v2-draft. Read MAP. Do not implement or start another agent.
Check attestation authorization/replay, snapshot/quorum, tx.time/this.age semantics, KAS conservation and burn/payout scripts, overflow, dead-state exits, adversarial tests, slash access control and commit-reveal invariants. Specify separation requirements for frozen H-001 and new full-bundle profiles without regenerating historical evidence.
Write .fleet/reports/handback-contract-review.md: verdict ok/changes, exact commit and file:line for findings, verified tests, bounded next Claude brief. No secrets, external writes, deploy, chain, wallet or main merge.
