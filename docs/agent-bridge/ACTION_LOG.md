# Action Log

## 2026-07-08

- Verified working tree after push: branch `main` tracks `origin/main`; only untracked local artifacts are `.claude/` and `Prometheus-1.png`.
- Confirmed local/remote alignment after the post-Toccata bridge/docs update; latest product-code baseline is `eeb4808`.
- Reconciled stale bridge/backlog/checkpoint status entries that still referenced `467ca03` or April startflow data.
- Updated `memory/STATUS.md` to mark GitHub Actions CI/CD as accepted for the green `eeb4808` CI, Security Audit, and Pages runs.
- No product code changed in this reconciliation pass.
- Verified upstream Silverscript tooling in `/tmp/prom-silverscript`: `cargo test -p silverscript-lang` passed, and `cargo run -p silverscript-lang --bin silverc -- --help` works.
- Added and ran a temporary `/tmp`-only H-001 probe test against upstream `silverc`/runtime: explicit `sha256(vote_byte || byte[8](salt) || byte[8](block_height))` matches the Prometheus Rust vectors for positive 64-bit values.
- H-001 is partially verified, not closed: Prometheus `ValidatorStaking.ss` still uses legacy `.ss`/`uint64` syntax and `sha256(vote || salt || block)` form, so the contract must be ported/compiled against current Silverscript syntax before Sprint 9.
- Added repo-tracked current-Silverscript H-001 fixture `modules/contracts/silverc/ValidatorStakingH001.sil`.
- Added `scripts/verify_silverc_h001.py` to inject a temporary upstream integration test and verify the repo fixture against the Rust H-001 vectors.
- Added a lightweight CI guard ensuring the H-001 fixture keeps explicit byte construction and does not regress to implicit `sha256(vote || salt ...)` serialization.
- Pinned the H-001 `silverc` verifier to upstream Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863` and added a GitHub Actions runtime job for the H-001 vectors.
- Added current-Silverscript validator state-machine fixture `modules/contracts/silverc/ValidatorStakingState.sil`.
- Extended `scripts/verify_silverc_h001.py` so the pinned upstream `silverc` test now verifies both H-001 runtime vectors and the ValidatorStaking state fixture compile/ABI path.
- Updated CI contract guards and the runtime job name to cover the H-001 + Validator State current-silverc gate.
- Verified locally: `python3 scripts/verify_silverc_h001.py` passed with 2 upstream tests; Black via `/tmp/prometheus-guardian-venv`; Pylint 10/10; `python3 -m py_compile`; `git diff --check`; memory integrity; contract fixture shell guards.
- Added `.claude/` to `.gitignore` so local agent state cannot be staged accidentally.
- Extended the pinned upstream `silverc` verifier with real `commitVote` runtime transition tests: valid bond/signature/state transition accepted, low bond rejected.
- GitHub Prometheus CI passed for `f1dd616`, including the H-001 + Validator State Silverc Runtime job with 4 injected upstream tests.
- Extended the pinned upstream `silverc` verifier with real `revealVote` runtime transition tests: valid reveal/signature/state transition accepted, wrong salt rejected.
- GitHub Prometheus CI, Security Audit, and Pages passed for `8f05afb`; the H-001 + Validator State Silverc Runtime job now covers H-001 vectors plus commit/reveal runtime paths.
- Extended the pinned upstream `silverc` verifier with real `slashInvalidReveal` runtime transition tests: invalid reveal slash accepted, valid reveal slash rejected.
- GitHub Prometheus CI, Security Audit, and Pages passed for `6dfe133`; the H-001 + Validator State Silverc Runtime job now covers H-001 vectors plus commit/reveal/slash runtime paths.
- Extended the pinned upstream `silverc` verifier with real `requestWithdraw` runtime transition tests: active uncommitted validator withdrawal request accepted, open-commitment withdrawal request rejected.
- GitHub Prometheus CI, Security Audit, and Pages passed for `b36e5f8`; the H-001 + Validator State Silverc Runtime job now covers H-001 vectors plus commit/reveal/slash/request-withdraw runtime paths.
- Extended the pinned upstream `silverc` verifier with real `completeWithdraw` runtime transition tests: zero-output termination after cooldown accepted, pre-cooldown withdrawal completion rejected.
- GitHub Prometheus CI, Security Audit, and Pages passed for `50cb9f4`; the H-001 + Validator State Silverc Runtime job now covers H-001 vectors plus commit/reveal/slash/request-withdraw/complete-withdraw runtime paths.
- Probed the signed-int/u64 boundary and confirmed current Silverc `byte[8](-1)` does not match the Rust `u64::MAX` H-001 vector; no two's-complement deployment shortcut is assumed.
- Enforced deployment bounds in `ValidatorStakingState.sil` and Rust validator commitment helpers: current-Silverc deployment `salt` and `block_height` are scoped to `0..=i64::MAX`, while raw Rust `u64` H-001 byte vectors remain available for compatibility tests.
- Added runtime tests rejecting negative signed deployment inputs for commit/reveal/slash/request-withdraw paths and Rust tests rejecting `u64::MAX` through `build_silverc_checked`.
- GitHub Prometheus CI, Security Audit, and Pages passed for `176ce52`; Prometheus CI includes Memory Integrity, HTML Pages, Python Guardian, Rust Workspace, Silverscript Contracts, and H-001 + Validator State Silverc Runtime.
- Added current-Silverscript GuardianReputation state fixture `modules/contracts/silverc/GuardianReputationState.sil` and extended `scripts/verify_silverc_h001.py` so the pinned upstream verifier compiles the fixture and builds covenant sigscripts for `register`, `proposalAccepted`, and `proposalRejected`.
- Learned and fixed two current-Silverc grammar constraints during the Guardian port: `while` is not available in the upstream grammar, and state field names cannot be reused as entrypoint parameter bindings.
- GuardianReputation compile/ABI scope intentionally does not introduce badge, NFT, Kasplex, or staking semantics; Guardian reputation remains canonical on Kaspa L1.
- GitHub Prometheus CI, Security Audit, and Pages passed for `b094444`; Prometheus CI now includes the GuardianReputationState compile/ABI fixture guard in addition to H-001, ValidatorStaking runtime gates, and signed-int deployment bounds.
- Added GuardianReputation runtime tests to the pinned upstream `silverc` verifier: `register` accepts valid guardian signature/state transition and rejects low compute power; `proposalAccepted` accepts valid governance signature/state transition and rejects negative reputation increase; `proposalRejected` accepts valid governance signature/state transition and rejects unregistered guardian state.
- GitHub Prometheus CI, Security Audit, and Pages passed for `81e7a97`; the H-001 + Validator State Silverc Runtime job now also covers GuardianReputationState runtime paths.

## 2026-07-07

- Codex onboarding check completed at 20:19 EEST: read bridge, cooperation rules, CLAUDE.md, BACKLOG.md, and required memory files.
- Verified current repo state: branch `main`, HEAD `467ca03`, local uncommitted memory/bridge/docs assets present.
- Verified direct Sandbox access via `ssh sandbox` using BatchMode: host `Sandbox`, user `root`.
- Completed read-only repository audit and documented findings in `CODEX_FINDINGS.md`.
- Verified checks: `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, Guardian pytest via temporary `/tmp` venv, memory integrity, and remote HEAD alignment.
- Researched Kaspa Toccata status from current public sources; updated public docs/pages and memory/backlog from stale May 5 launch wording to post-Toccata ssc/H-001 verification status.
- Checked direct Sandbox PATH for `kaspad` and `ssc`; neither was found there, so Sprint 9 still needs local tooling installation/verification.
- Replaced stale current-status wording that said Testnet-12 does not exist with a legacy Testnet-10 baseline plus TN12/Toccata tooling verification requirement.
- Added H-001 Rust guardrail: canonical 17-byte commit-reveal preimage builder plus known hex vectors for normal, zero, endian-visible, and `u64::MAX` cases.
- Updated `ValidatorStaking.ss` comments to document the same canonical H-001 byte preimage without changing contract logic.
- Pinned Rusty-Kaspa workspace dependencies to tag `v2.0.1` and refreshed `Cargo.lock`; local `cargo audit` no longer reports vulnerabilities.
- Re-enabled GitHub Security Audit workflow and changed dependency audits from best-effort `|| true` commands to failing gates.
- Added CI stale public-status check to prevent reintroducing old May 5 launch/Testnet-12 wording.
- Verified after implementation: `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo audit`, Guardian Black/Pylint/pytest, `pip-audit`, stale public-status shell check, and memory integrity.
- Added Rust client runtime gate via `PROMETHEUS_RUNTIME`: development remains stub-capable; beta/mainnet/production reject ZK, Phi-3 fallback/heuristic, KRC-20 cache, and Fed-DART placeholder stubs.
- Verified runtime gate with `cargo fmt --all --check`, `cargo test -p prometheus-client`, and `cargo clippy --workspace -- -D warnings`.
- Added `CODEX_BRIDGE.md` as the central Codex handover/start file.
- Documented direct Sandbox SSH access via local alias `ssh sandbox`.
- Consolidated Prometheus project identity, workflow logic, audit blockers, open issues, and Reputation Badge decision.
- Explicitly excluded plaintext passwords, private keys, tokens, and other secrets from bridge documentation.

## 2026-05-08
<!-- CODEX_CLAUDE_CODE_TERMINAL_BRIDGE_V1 -->
## Codex -> Claude Code Terminal Bridge

Status: configured on 2026-07-07. Codex must call Claude Code through the local terminal wrapper, not through the Anthropic API.

Use this probe:

```bash
env -u LC_ALL claude-code-terminal --probe
```

Expected output:

```text
claude-code-terminal-ok
```

Send prompts to Claude Code with:

```bash
env -u LC_ALL claude-code-terminal "PROMPT_TEXT"
```

or via stdin:

```bash
printf '%s\n' "PROMPT_TEXT" | env -u LC_ALL claude-code-terminal
```

Rules for all dev agents:

- Do not use the Anthropic API, Anthropic SDK, `ANTHROPIC_API_KEY`, or direct HTTP calls for Codex -> Claude Code handoff.
- Do not use `claude --bare`; bare mode does not read the local claude.ai OAuth/keychain session and will report not logged in.
- Do not use `cc` for Claude Code; on this machine `cc` is the C compiler.
- The Claude Code CLI command is `claude`; the stable wrapper is `/Users/gio/.local/bin/claude-code-terminal`.
- If a probe returns `401 Invalid authentication credentials`, the integration is using the wrong path: API instead of terminal.
- Keep secrets, tokens, passwords, private keys, and keychain material out of bridge files.
<!-- /CODEX_CLAUDE_CODE_TERMINAL_BRIDGE_V1 -->
