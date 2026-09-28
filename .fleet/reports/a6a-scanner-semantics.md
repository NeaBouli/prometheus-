id: a6a-scanner-semantics
status: ok
worker: claude
branch: agent/claude/a6a-scanner-semantics
summary: Node `modules/client` dev scanner, hop `security/scanner.rs::parse_simple_yara_rule` -> `CompiledRule` (MAP.md row "dev scanner"). PRM-04 re-verified VALID on 2e73362: the condition section was only a section terminator and required_matches was hardcoded 1, so `all of them` silently became any-of; string extraction was loose (inline `strings:`, first quoted run, escapes/modifiers ignored).
  Fix: replaced the loose extractor with a staged fail-closed parser (header `rule <name> {` must match the name argument, `strings:` line, `$id = "literal"` lines, `condition:` line, one condition line, `}`). Accepted conditions are only those exactly equal to any-of: `any of them`, or `$x` / `$x or $y ...` naming every declared id exactly once. Everything else (all/N of, and/not/parens, partial/duplicate refs, hex, regex, escapes, modifiers, non-printable, duplicate ids/literals, meta/tags, inline or missing sections, trailing content) is rejected with generic errors. required_matches stays 1; no YARA engine, no second code path.
files: modules/client/src/security/scanner.rs (parser + 2 private helpers + 5 regression tests); .fleet/reports/a6a-scanner-semantics.md
tests: cargo fmt --all -- --check -> ok
  cargo test -p prometheus-client --lib security::scanner -> 23 passed, 0 failed (5 new: all-of-them rejection, unsupported conditions, unsupported strings, malformed sections, supported minimal rules still match; existing `$a or $b` test unchanged and green)
  cargo test -p prometheus-client -> all binaries ok, 332 passed, 0 failed, 2 ignored (pre-existing)
  cargo clippy -p prometheus-client --all-targets -- -D warnings -> ok
risks: Stricter grammar: previously tolerated rules (inline sections, `condition: $a` with >1 strings, modifiers, meta blocks) now error. Only callers are unit tests (grep: no production call site); production ingest (`blockchain/rule_ingest.rs`) untouched and already strict. Module doc line "YARA-based" drift (MAP.md) left as-is per no-doc-change scope.
security: none (PRM-04 Low closed on this branch; no secrets touched)
next: Codex review/merge into agent integration; A6b PRM-05 (file-read bounds) and PRM-11 remain separate briefs.
