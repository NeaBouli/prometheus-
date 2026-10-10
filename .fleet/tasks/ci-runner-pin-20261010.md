# CI runner baseline preservation

Status: In Progress. Owner: Codex. Base: eecbaf5731b6a0e2f3a77aebe8f42e97cf1daf47.

Architecture boundary: existing `scripts/` release-tooling node, workflow
`runs-on` -> Toolchain Pin Policy -> required hosted CI/Security jobs.
The green main CI38009850053 used Ubuntu24.04; do not silently migrate it.

Scope: `.github/workflows/{ci,security-audit}.yml`, the existing
`CiRegistrationTest` in `scripts/test_toolchain_pins.py`, and bounded docs/Bridge.
Pin all eleven current jobs to `ubuntu-24.04`; assert every workflow job keeps
that explicit baseline. No product/contract/dependency/action pins, permission,
trigger, topology, provider, rollout, or v2 acceptance changes. No new module.

Acceptance: structured workflow equality except eleven runner labels; regression
actually passes in the hosted Toolchain job; complete required CI/Security green
on exact head; normal protected PR; real main checks and Pages outcome recorded.
Preserve all foreign work. Do not run target code locally without full isolation.

Routing: small orchestration config/glue task, not an outage fallback. Claude
owner-paused; pending Kimi PR293 transfer/review remains a separate task.

Upgrade gate: Ubuntu26 requires a dedicated compatibility change and actual
full hosted evidence, not a floating label or bundled security-fix upgrade.
The explicit OS label is not an immutable image/package lock.

Source: https://github.com/actions/runner-images/issues/14748 (migration starts
2026-10-19, planned completion2026-11-19). No extra paid provider or manual run.
