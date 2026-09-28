id: a6c-dev-rule-cache-bounds
status: partial
worker: claude
branch: agent/claude/a6c-dev-rule-cache-bounds (commit 13029c2)
summary: |
  Module/hop: modules/client dev pre-Covenant KRC-20 rule cache
  (client/src/blockchain/krc20.rs::Krc20RuleReader::add_cached_rule; MAP.md duplicate-path #2,
  "do not extend"; no new path, only the existing insert was bounded). PRM-11 re-verified as valid:
  add_cached_rule was an unchecked push with no validation, cap, or dedup.
  Fix: validate_rule() runs before the lock/mutation. rule_id is checked against the ingest grammar
  (1..=MAX_RULE_ID_BYTES = 128, [A-Za-z0-9_-]), ipfs_cid goes through the shared
  rule_fetch::validate_canonical_raw_cid, and validator_consensus must be finite and in 0..=1.
  guardian_id/timestamp are fixed-size. Capacity is MAX_CACHED_RULES = rule_ingest::MAX_RULES_PER_SNAPSHOT (256).
  Semantics: one entry per rule_id. An identical re-add is an idempotent Ok. A different rule under the same ID
  -> ConflictingDuplicate, a new ID at capacity -> CapacityExceeded. Nothing is overwritten or evicted.
  add_cached_rule now returns Result<(), Krc20CacheError> (no callers outside krc20.rs). Display is
  generic, with no IDs/CIDs. ThreatRule additionally derives PartialEq (additive).
files:
  - modules/client/src/blockchain/krc20.rs (impl + tests; test fixture CID changed from dag-pb to canonical raw CID)
tests: |
  cargo fmt --all -- --check: OK.
  cargo clippy -p prometheus-client --all-targets -- -D warnings: OK (0 warnings).
  cargo test -p prometheus-client --lib blockchain::krc20: NOT RUN. The lib test compiled; only the link step
  failed with "ld: write() failed, errno=28" (volume /System/Volumes/Data 100% full, 38-52 MiB free).
  The full client test suite is also NOT RUN, for the same reason.
  The build used CARGO_TARGET_DIR=../claude-a6b-scanner-file-bounds/target (warm dep cache); only this worktree's own
  target/ (194 MB) was deleted. No files outside this worktree were deleted.
  New tests: normal insert, idempotent duplicate, conflicting duplicate (type/CID/active), rule_id exact 128 vs 129
  plus empty/space/slash/NL/NUL/non-ASCII, CID (empty, dag-pb, truncated, too long, uppercase, CIDv0),
  consensus 0.0/1.0 vs out-of-range/NaN/Inf, capacity boundary 256/257 incl. idempotent re-add
  and validation-before-capacity, generic Display. Every rejection asserts an unchanged cache snapshot.
risks: |
  Tests unverified until disk space is available. Semantic change: add_cached_rule is now fallible
  and rejects the previously used dag-pb fixture CID (intended: same CID rule as ingest).
  The rule_id charset check duplicates the private rule_ingest::validate_rule_id (not
  shareable because rule_ingest.rs was out of scope); the constant itself is reused.
security: no new finding. PRM-11 (Low) fixed in code, pending the test run.
next: |
  Gio/Codex: free disk space (e.g. stale target/ in finished worktrees a4/a6a/a6b, ~10 GB), then
  `cargo test -p prometheus-client --lib blockchain::krc20` and `cargo test -p prometheus-client`
  on 13029c2. If green -> status ok, review/integration. Optional follow-up: make rule_ingest::validate_rule_id
  pub(crate) and reuse it in krc20.rs.
