# A6a — Fail-closed scanner rule semantics (PRM-04)

Architecture boundary: `modules/client` dev scanner,
`src/security/scanner.rs::YaraScanner`. This is a bounded development matcher,
not a production YARA engine.

## Objective and scope

- Re-verify PRM-04 on the current branch. If invalid, return `partial` with
  evidence and no speculative patch.
- Never interpret unsupported YARA conditions as different semantics. Preserve
  the intentionally supported minimal grammar and reject `all of them`, mixed
  boolean expressions, malformed sections, escapes/hex/regex, duplicate IDs,
  or any construct the matcher does not implement.
- Prefer explicit fail-closed parsing over adding a YARA engine or silently
  approximating syntax. Preserve existing accepted `any of them` behavior.
- Limit edits to `modules/client/src/security/scanner.rs` and its focused tests.
  No file-bound, cache, AI/model, network, rule-ingest, or public-doc changes.

## Acceptance

- Add regressions proving unsupported `all of them` cannot degrade to any-of,
  malformed/ambiguous rules reject, and supported minimal rules still match.
- Run format, focused scanner tests, complete client tests, and client Clippy
  with `-D warnings`.
- Write `.fleet/reports/a6a-scanner-semantics.md`; no main push, deploy,
  external action, secret, architecture expansion, or subagent.
