# A6b - Bound scanner file reads (PRM-05)

Architecture boundary: `modules/client` local file-analysis entry points in
`src/security/scanner.rs` and `src/ai/detection.rs`.

## Objective and scope

- Re-verify PRM-05 on the current branch. If invalid, return `partial` with
  evidence and no speculative patch.
- Ensure every in-scope file API rejects empty and oversized input before an
  unbounded allocation. A metadata check alone is insufficient: the actual
  read must remain capped so file growth or special files cannot bypass it.
- Use one explicit, conservative development-client byte limit per owning
  module or a narrowly shared existing constant; return generic errors and do
  not expose file contents.
- Limit edits to `modules/client/src/security/scanner.rs`,
  `modules/client/src/ai/detection.rs`, and focused tests. Do not change parser
  semantics, model behavior, cache/network/rule ingest, CLI, or public docs.

## Acceptance

- Regressions cover empty, exact-limit, over-limit, and normal files for each
  in-scope file entry point; no test weakens existing detection assertions.
- Run format, focused scanner/detection tests, complete client tests, and
  client Clippy with `-D warnings`.
- Write `.fleet/reports/a6b-scanner-file-bounds.md`; no main push, deploy,
  external action, secret, architecture expansion, or subagent.
