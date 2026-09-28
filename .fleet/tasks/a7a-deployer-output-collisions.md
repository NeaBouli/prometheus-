# A7a - Reject genesis deployer path collisions (PRM-06)

Architecture boundary: `modules/silverc-deployer`, hop
`src/main.rs::Cli` command dispatch -> genesis command handlers ->
`write_public_json`.

## Objective and scope

- Re-verify PRM-06 on the current branch; if invalid, return `partial` with
  evidence and no speculative patch.
- Apply the existing oracle/import collision-rejection invariant to every
  genesis CLI command that writes output. Reject an output path that aliases
  any command input or another output before any read, write, truncation,
  journal mutation, broadcast, or observation side effect.
- Reuse the established path comparison and error-redaction behavior. Do not
  add flags, follow symlinks, change transaction bytes, signing, broadcast,
  network behavior, contracts, tokenomics, or SilverScript artifacts.
- Limit code edits to `modules/silverc-deployer/src/main.rs` and focused tests;
  touch another deployer file only if the existing shared invariant lives there
  and explain the exact hop in the report.

## Acceptance

- Regressions cover every affected genesis subcommand, same-path and aliasing
  inputs/outputs, pairwise output collisions, rejection before side effects,
  and valid distinct paths.
- Run Rustfmt, focused deployer tests, complete silverc-deployer tests, and
  Clippy for all deployer targets with `-D warnings`.
- Write `.fleet/reports/a7a-deployer-output-collisions.md`; no main push,
  deployment, signing, broadcast, wallet, chain action, secret, or subagent.
