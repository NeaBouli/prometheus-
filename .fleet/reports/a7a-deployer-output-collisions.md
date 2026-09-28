id: a7a-deployer-output-collisions
status: ok
worker: claude
branch: agent/claude/a7a-deployer-output-collisions
summary: |
  Module modules/silverc-deployer, hop main.rs::Cli dispatch -> genesis arms -> write_public_json.
  PRM-06 re-verified valid on 831810a: Preflight, Prepare, VerifySignature, Broadcast, Observe
  wrote outputs without the collision gate used by oracle commands and ImportSignature.
  Each of these arms now calls the existing reject_import_output_collisions (lib.rs) as its
  first statement, before any load, lock, journal, RPC, broadcast, or observation. Broadcast
  checks result and derived intent-journal paths (oracle parity). Probe has no path inputs and
  one output, so no collision is possible; unchanged. Only other hop touched: lib.rs
  reject_import_output_collisions made `pub` (shared invariant lives there; no logic change).
  Same comparison and label-only error messages; no new flags, tx bytes, signing or network change.
files:
  - modules/silverc-deployer/src/main.rs
  - modules/silverc-deployer/src/lib.rs (visibility only)
  - modules/silverc-deployer/tests/genesis_output_collisions.rs (new, drives the real binary)
tests: |
  New regression (6 tests) runs the built binary per subcommand: every output == every input,
  lexical ../ alias, symlink alias, broadcast journal aliasing each input, pairwise output
  collision, distinct paths pass the gate; asserts failure text, empty stdout and an unchanged
  directory snapshot (no read-side parse, no output/journal/lock/temp file). Against HEAD main.rs:
  4 failed / 2 passed (pairwise + distinct already held); with fix: 6/6 pass.
  cargo fmt --check: ok. cargo test -p prometheus-silverc-deployer: 50 unit + 6 integration pass.
  cargo clippy -p prometheus-silverc-deployer --all-targets -- -D warnings: clean.
risks: |
  Established comparison canonicalizes paths, so a non-existent output parent now fails at the
  gate instead of later (genesis Broadcast previously created it via the lock); same as oracle.
  Broadcast .lock path is not part of the set (oracle parity; opened without truncation).
  Collision check is point-in-time (TOCTOU by same-user rename remains; PRM-07/08 scope).
security: none new; Low operator-error data-destruction path (PRM-06) closed.
next: Orchestrator review/merge; A7b/A7c (PRM-07/08) unaffected.
