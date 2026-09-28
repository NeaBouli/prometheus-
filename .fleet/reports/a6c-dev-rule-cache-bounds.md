id: a6c-dev-rule-cache-bounds
status: ok
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
  Initial test link failed with errno=28 at 41 MiB free. Codex removed only the completed A6a/A6b
  Cargo target artifacts, then reran with the warm A6b target: focused KRC20 12 passed, 1 ignored;
  complete client suite 347 passed, 2 ignored, 0 failed.
  New tests: normal insert, idempotent duplicate, conflicting duplicate (type/CID/active), rule_id exact 128 vs 129
  plus empty/space/slash/NL/NUL/non-ASCII, CID (empty, dag-pb, truncated, too long, uppercase, CIDv0),
  consensus 0.0/1.0 vs out-of-range/NaN/Inf, capacity boundary 256/257 incl. idempotent re-add
  and validation-before-capacity, generic Display. Every rejection asserts an unchanged cache snapshot.
risks: |
  Semantic change: add_cached_rule is now fallible and rejects the previously used dag-pb fixture CID
  (intended: same CID rule as ingest).
  The rule_id charset check duplicates the private rule_ingest::validate_rule_id (not
  shareable because rule_ingest.rs was out of scope); the constant itself is reused.
security: no new finding. PRM-11 (Low) is locally fixed and verified; hosted CI and merge remain pending.
next: Codex records A6 evidence and opens the normal PR/hosted-CI gate; no production promotion.
