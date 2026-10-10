# MS-B docs reconciliation

- Owner: Codex Core; architecture wording, not a worker fallback.
- Base: held PR29324980e6ddaccfdfa8d09eddb78cbd3675d1afe67; own stacked docs branch.
- MAP: existing M1/MS-B decision record -> current contract README.
- Scope: docs/architecture/ms-b-contract-decisions.md, modules/contracts/silverc/README.md and append-only Fleet/Bridge records.
- Correct D1 actual versioned context, D2 metadata/lower bounds, D4 attester trust/unused constants, D5 off-chain closed status, D6 explicit duration assumption, D7 per-finding closure and the stale tuning paragraph.
- Preserve all requirements and historical references. No new policy, contract, fixture, source/compiled pin, runtime, workflow or public-page change; no private acceptance details.
- Checks: parent exact diff allowlist/source equality and documentation semantics; existing CI/Security once at final head (stacked PR has no automatic main-branch trigger).
- Complete only after actual relevant checks pass. Original293/295 heads and main unchanged; no merge or activation follows.
