# A7c - Descriptor-bind Guardian policy/config reads (PRM-08)

Architecture boundaries: Guardian v2 preflight policy loading in
`jaeger/threat_hint_v2_preflight.py` and service config loading in
`jaeger/threat_hint_service.py`.

## Objective and scope

- Re-verify PRM-08 on the current branch. Replace each in-scope
  lstat-then-`Path.read_text()` sequence with the established sibling pattern:
  no-follow descriptor open, fstat identity/type/owner/mode verification,
  bounded read, post-read identity/size verification, strict UTF-8 decode.
- Preserve current byte limits and schemas. Reject replacement, symlink,
  non-regular, changed-size and oversized input without exposing path or file
  contents. Never reopen the validated file by path.
- Keep helpers local to their owning modules unless an existing shared helper
  already serves this exact hop. No new watcher, retry, flag, dependency,
  policy semantics, v1/v2 proof behavior, network, database, or public claim.
- Limit edits to the two loader modules and their focused tests.

## Acceptance

- Regressions cover safe reads, symlink/replacement races, inode/size changes,
  exact-limit/over-limit, invalid UTF-8, unchanged redacted errors, and no
  downstream parse or mutation after rejection.
- Run focused preflight/service tests, complete Guardian pytest, Black, Ruff,
  and changed-file Pylint.
- Write `.fleet/reports/a7c-guardian-policy-descriptor-reads.md`; no main push,
  deployment, external action, secret, or subagent.
