# Task: plan-state-inventory

## Objective
Produce a read-only project control-plane inventory for the remaining Prometheus program.

## Scope
- Reconcile global/project Bridge, Memory, current `origin/main`, open GitHub issues/PRs, CI workflows, audit handoff #269/#270/#271, and September PRM tickets.
- Classify every open item as release gate, security gate, public-integrity work, implementation, evidence/operations, owner decision, or obsolete/duplicate.
- Recommend dependency order, PR boundaries, worker routing, required tests, and what must wait for GitHub Actions quota reset on 2026-10-01.
- Assess whether the Cloudflare-origin `security-audit` skill should run now, after known fixes, or twice in scoped/full modes.

## Boundaries
- Read-only source/GitHub analysis apart from this Fleet report.
- No edits outside `.fleet/reports/plan-state-inventory.md`; no issue/PR mutations, builds, deploys, live probes, or secrets.
- Do not duplicate the architecture map or design implementation details.

## Acceptance
- Complete open-item register with evidence and recommended disposition.
- Critical path to repository-ready, Testnet-ready, and production-ready states.
- Explicit CI-budget strategy and audit timing decision.
- Report follows the Fleet report schema.

