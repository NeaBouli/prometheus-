id: a8b1-silverc-checkout-pin
status: ok
worker: claude
branch: agent/claude/a8b1-silverc-checkout-pin
summary: >
  Module scripts/verify_silverc_h001.py (SilverC upstream verification), hop
  main -> ensure_silverscript_repo -> git clone/fetch/checkout -> probe write -> cargo test -> probe cleanup.
  The requested ref must be lowercase 40-hex and equal the workspace silverscript-lang rev, which is
  parsed with tomllib from [workspace.dependencies] (canonical git URL, rev pin, no branch/tag).
  An existing checkout must be a repo root with exactly one canonical origin URL (raw and after
  insteadOf rewriting) and a clean tree (untracked files included) before fetch. After the detached
  checkout, HEAD^{commit} must equal the pin exactly and the tree must be clean. The probe is written
  inside try, then always removed, and a clean tree is required afterwards. Git runs with hooksPath=/dev/null,
  fsmonitor=false, GIT_TERMINAL_PROMPT=0 and captured output. SilverscriptCheckoutError messages carry
  no paths, git output, ref echo or file content; main() prints them and returns 1.
  Active commit d25bd342 is unchanged, and so are the ensure_silverscript_repo(path, ref) signature,
  DEFAULT_* constants and the cargo command.
files:
  - scripts/verify_silverc_h001.py (checkout/pin core only)
  - scripts/test_verify_silverc_h001_checkout.py (new, 26 unittest cases, offline local git fixtures)
tests: >
  python3 -m unittest scripts/test_verify_silverc_h001_checkout.py -> Ran 26 tests OK;
  python3 scripts/test_project_status_consistency.py -> OK;
  python3 -m unittest scripts/test_h001_canary_closeout_evidence.py scripts/test_public_claim_consistency.py -> OK;
  imports of preflight/smoke/deploy-request/receipt/status/oracle scripts -> OK;
  ruff check + mypy on both files -> clean. Live upstream run (network): fresh clone, re-run on an existing
  checkout and probe add/remove at d25bd342 -> all OK, tree clean. Upstream Cargo.lock is tracked, and
  `cargo metadata --locked` -> rc=0, so cargo test does not dirty it.
  Not run: the full cargo probe (verify_silverc_h001.py end to end) and test_silverc_canary_profile.py
  (needs a smoke --archive).
risks: >
  preflight_silverc_deploy and smoke_silverc_artifacts share ensure_silverscript_repo and now fail
  closed (uncaught SilverscriptCheckoutError) on any SILVERSCRIPT_REF/--silverscript-ref other than the
  Cargo pin or on a dirty or non-canonical checkout. That is intended, but it tightens both callers without
  a caller-side message. A probe cleanup that leaves a dirty tree now fails the run. CI uses a fresh clone,
  so it is unaffected.
security: none (hardening only; no secrets touched)
next: Orchestrator review/merge into agent integration; optional follow-up brief for caller-side error handling in preflight/smoke.
