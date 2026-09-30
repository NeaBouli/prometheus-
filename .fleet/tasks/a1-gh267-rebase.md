# Task: a1-gh267-rebase

## Objective
Reconstruct PR #268 (`feat/GH-267-endpoint-privacy-gate`) on the current exact-main baseline without expanding its behavior or scope.

## Architecture boundary
- Node: planned endpoint detection gate, GH-258/GH-261 track in `docs/architecture/MAP.md`.
- Hop: owner-approved endpoint observation input -> fail-closed pre-producer privacy/threat-model gate.
- Preserve all current wire formats, claim boundaries, and `origin/main` dependency state.

## Work
- Compare PR #268 to its original base and port only its intended changes onto this task branch.
- Resolve conflicts against current main and the accepted planning documentation.
- Re-run every focused test from PR #268 plus all directly affected Rust/Python/public-claim gates.
- Update architecture status only if the restored code changes the mapped node truthfully.
- Write `.fleet/reports/a1-gh267-rebase.md` using the Fleet schema.

## Boundaries
- No new endpoint sensor, collection, transport, response action, model, wallet, chain, contract, deployment, Mainnet, or production claim.
- No changes to KAS/PROM, reputation, slashing, commit-reveal, workflow, CI governance, or unrelated public pages.
- Never touch `Prometheus-1.png`, secrets, wallets, signed transactions, or private operator data.
- Do not mutate or force-push the existing PR branch and do not merge to main.

## Acceptance
- Intended PR #268 behavior is present on current baseline with no conflict markers or unrelated drift.
- Focused and affected complete gates pass without weakened tests.
- Report identifies exact source/base commits, files, tests, risks, and security status.
