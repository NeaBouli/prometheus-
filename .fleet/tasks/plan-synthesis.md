# Task: plan-synthesis

## Objective
Turn the accepted architecture map and control-plane inventory into the canonical remaining Prometheus delivery plan.

## Inputs
- `docs/architecture/MAP.md` and PlantUML sources.
- `.fleet/reports/plan-arch-map.md`.
- `.fleet/reports/plan-state-inventory.md`.
- Current `.fleet/PLAN.md` and project Bridge rules.

## Writes
- Replace `.fleet/PLAN.md` with the complete canonical plan.
- Append one dated planning milestone to `docs/agent-bridge/ACTION_LOG.md`.
- Write `.fleet/reports/plan-synthesis.md`.

## Required plan content
- Exact baseline and truthful current status.
- Ordered milestones from public-integrity repair through repository, Testnet, and production gates.
- One architecture node/hop and explicit files/interfaces per next implementation block.
- Non-overlapping Claude/Kimi/Grok/Codex ownership.
- CI strategy before and after the 2026-10-01 Actions reset.
- Cloudflare-origin security-audit timing and scope decision.
- Blockers requiring Gio, and explicit work that must not be built yet.
- Definition of Done and stop conditions per milestone.

## Boundaries
No product/public-page code, GitHub mutations, contract/tokenomics changes, deployment, live probing, wallet/chain activity, or global workflow edits.
