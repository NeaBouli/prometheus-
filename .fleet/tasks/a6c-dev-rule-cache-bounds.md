# A6c - Bound and validate the development rule cache (PRM-11)

Architecture boundary: `modules/client` development KRC20 rule cache in
`src/blockchain/krc20.rs`. It is not canonical storage or production ingest.

## Objective and scope

- Re-verify PRM-11 on the current branch. If invalid, return `partial` with
  evidence and no speculative patch.
- Add explicit conservative limits for cache entries and every caller-owned
  string/blob retained by the cache. Validate before cloning or mutating.
- Define deterministic duplicate/update and full-capacity behavior. Rejected
  insertions must leave the cache unchanged; do not silently evict canonical
  data or create two entries for one rule identity.
- Reuse current contract/rule limits where they are already authoritative;
  otherwise document development-only constants locally. Do not add a second
  cache, persistence, network access, production claims, or dependencies.
- Limit edits to `modules/client/src/blockchain/krc20.rs` and focused tests.
  Do not change scanner/parser, AI, rule-ingest, tokenomics, contracts, or docs.

## Acceptance

- Tests cover normal insert, duplicate/update semantics, empty/invalid fields,
  exact and over-limit values, capacity boundary, and unchanged state after
  every rejected operation.
- Run format, focused KRC20 tests, complete client tests, and client Clippy
  with `-D warnings`.
- Write `.fleet/reports/a6c-dev-rule-cache-bounds.md`; no main push, deploy,
  external action, secret, architecture expansion, or subagent.
