id: a8a3-silverc-pin-inventory
status: partial
worker: claude
branch: agent/claude/a8a3-silverc-pin-inventory
summary: |
  Module/hop: MAP.md `modules/contracts/silverc` ← SilverC compiler/CI trust boundary (verify → smoke → preflight). Read-only; only this report was written.
  Current pin (two independent copies of the same commit, no cross-check between them):
  (1) Rust: Cargo.toml:29 `silverscript-lang = {git=kaspanet/silverscript, rev="d25bd3427a093c17327ca3d6b9e1aa5f7688c863"}`; Cargo.lock:4794 resolves the same commit.
  (2) Python: scripts/verify_silverc_h001.py:31-33 has DEFAULT_SILVERSCRIPT_REPO=/tmp/prom-silverscript and DEFAULT_SILVERSCRIPT_REF=d25bd34…. smoke_silverc_artifacts.py and preflight_silverc_deploy.py import these values. ensure_silverscript_repo (:3437) runs clone/fetch plus `git checkout <ref>`.
  modules/contracts/silverc/README.md:29-34 documents d25bd34 and the SILVERSCRIPT_REF=<commit-or-tag> override. CI ci.yml:250-261 runs verify, smoke and preflight with the defaults. The contract-check job (:63-160) only greps the .sil fixtures.
  Official v1.0.0: `git ls-remote` gives refs/tags/v1.0.0 = 3ed973335b59269293564805cc2c58a14595ec03 (lightweight tag, no ^{} line) and v1-rc1 = c7d17a15…. The pin d25bd34 is neither of these. Whether d25bd34 is an ancestor of v1.0.0 is not checked: there is no local clone and I made no fetch.
  Gaps vs a v1.0.0 pin (fail-open):
  (a) SILVERSCRIPT_REF/--silverscript-ref also accept a branch or a tag, which can move.
  (b) After checkout, nothing asserts `rev-parse HEAD` == the pinned 40-hex commit.
  (c) A reused SILVERSCRIPT_REPO is not checked for origin URL or a dirty worktree. `checkout` keeps local edits, and the probe .rs is written into the upstream tree.
  (d) preflight inspect_silverc (:276-282) reuses target/debug/silverc if it already exists, even if it was built from another ref.
  (e) preflight validate_manifest (:177) compares only silverscript_ref. It never checks silverscript_commit == ref == the Cargo.toml rev. compiler_version is only checked for being non-empty (:222).
  (f) Upstream cargo builds/tests run without --locked.
  Generated-artifact assumptions: the smoke step rebuilds silverc on every run and records silverscript_ref/commit (HEAD rev-parse), compiler_version, and source/artifact/script/ctor sha256 per fixture. Preflight re-hashes all of them against the repo sources. Script bytes are compiler-dependent, so a new pin changes script_sha256 and therefore the covenant address.
  Immutable H-001 evidence (bound to d25bd34, do not rewrite): docs/evidence/gh-9-h001-{operator-receipts,public-evidence,canary-confirmed}-2026-08-12.json. Values: silverscript_ref=commit=d25bd34…, source_sha256 ebf17c52…, artifact_sha256 bc2af7e5…, script_sha256 e5d99d86….
  Smallest fail-closed implementation:
  (1) verify_silverc_h001.py: ensure_silverscript_repo requires ref =~ ^[0-9a-f]{40}$ and == DEFAULT_SILVERSCRIPT_REF, asserts origin URL == SILVERSCRIPT_GIT, asserts `status --porcelain` is empty before checkout and before writing the probe, and asserts HEAD == ref after checkout. It also asserts DEFAULT_SILVERSCRIPT_REF == the Cargo.toml silverscript-lang rev (via tomllib).
  (2) preflight: remove the exists-shortcut and always build; require manifest silverscript_commit == silverscript_ref == DEFAULT_SILVERSCRIPT_REF.
  (3) Add `--locked` to the upstream cargo calls.
  Pin migration to v1.0.0 is a separate follow-up commit: Cargo.toml rev + DEFAULT_SILVERSCRIPT_REF + README → 3ed97333…, Cargo.lock updated via cargo, new artifacts and a new evidence line. The H-001 files stay unchanged.
files: .fleet/reports/a8a3-silverc-pin-inventory.md (report only; no product/script/workflow/evidence/claim changes)
tests: none run — read-only analysis, no code changed. Verified by reading: Cargo.toml:29, Cargo.lock:4794, verify_silverc_h001.py:31-33,3437-3465, preflight:161-225,276-320, smoke:281-290,440-450, ci.yml:44-160,206-261, the silverc README and the H-001 evidence JSON. Network check: `git ls-remote` of the upstream tags (read-only). Proposed tests: new scripts/test_silverc_pin.py (unittest with a temp git repo): non-hex/branch ref, HEAD mismatch, dirty tree, wrong origin, and Cargo.toml≠DEFAULT all fail closed; preflight rejects a manifest with commit≠ref; wire it into the ci.yml contract-check job.
risks: |
  Whether d25bd34 is related to v1.0.0 is unverified. Moving to v1.0.0 likely changes script bytes/addresses and invalidates the canary comparison. It must never overwrite the H-001 evidence. A lightweight tag can be re-pointed upstream, so pin the commit hash and not the tag name. Rollback of the hardening: `git revert <commit>` (no data/evidence migration involved).
security: |
  MEDIUM (supply chain / CI trust boundary, not exploited): the compiler ref is not fail-closed. An env override with a movable ref, a reused dirty or foreign-origin /tmp checkout, or a stale silverc binary in preflight can produce artifacts or tooling checks from a different compiler than the pinned one. Preflight only sees the self-reported ref. No secrets found or output.
next: |
  1. Codex: assign the hardening (1)-(3) + test_silverc_pin.py as a single brief (scripts/verify_silverc_h001.py, scripts/preflight_silverc_deploy.py, scripts/smoke_silverc_artifacts.py (--locked), .github/workflows/ci.yml, new test).
  2. Separate brief: run a shallow fetch and `merge-base --is-ancestor d25bd34 3ed97333`, then decide on the v1.0.0 migration with new artifact/evidence and without touching the H-001 files.
