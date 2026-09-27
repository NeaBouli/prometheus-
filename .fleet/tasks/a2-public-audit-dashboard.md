# Task: a2-public-audit-dashboard

## Objective
Resolve issue #273 by removing the fabricated public audit dashboard and every public link or machine-readable pointer to it.

## Architecture boundary
- Node: `modules/web` public status surface in `docs/architecture/MAP.md`.
- Hop: repository evidence -> static public claim; no runtime/backend hop may be added.

## Work
- Remove `modules/web/audit/index.html` and directly owned stale assets if unreferenced.
- Remove or replace dashboard links in landing/footer, README, `llms.txt`, sitemap, and other public surfaces with evidence-backed existing destinations only.
- Extend public-claim and link/status checks so fabricated validator, address, grant, rule, refresh, or on-chain-verifiability claims cannot return unnoticed.
- Preserve truthful Testnet-10, repository-only, deployment, and production boundaries.
- Run the complete `frontend-visual-release-gate` on every visibly changed principal page at mobile and desktop viewports.
- Write `.fleet/reports/a2-public-audit-dashboard.md` using the Fleet schema.

## Boundaries
- No new dashboard, telemetry, JavaScript runtime, backend, wallet, chain call, deployment, production claim, or architecture change.
- Do not touch A1 privacy-gate behavior, contracts, tokenomics, workflow governance, secrets, wallets, or `Prometheus-1.png`.
- Do not merge to main or deploy.

## Acceptance
- No fabricated dashboard content or public route/link remains in the candidate tree.
- Claim, HTML/link, documentation, Memory/status, and visual gates pass.
- Screenshots and measurable no-overflow/no-clipping assertions are retained for Codex inspection.
