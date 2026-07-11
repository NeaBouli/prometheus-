# Action Log

## 2026-07-11

- GitHub Prometheus CI and Security Audit passed for `144f71c`; Prometheus CI now covers the GovernanceAutoTuning metrics-oracle report preflight positive path plus secret-field rejection. Latest observed Pages deployment remains green for `98b9f73`.
- Added `scripts/preflight_metrics_oracle_report.py` and `modules/contracts/silverc/metrics-oracle-report.sample.json` for public GovernanceAutoTuning `reportMetrics` payload validation. Local positive plan/runbook generation and negative secret-field rejection passed; CI now checks both paths.
- GitHub Prometheus CI, Security Audit, and Pages passed for `fe4c62f`; Prometheus CI now validates the generated current-Silverc deploy operator runbook in addition to the release archive and JSON preflight plan.
- Added Markdown operator runbook generation to `scripts/preflight_silverc_deploy.py` via `--runbook-out`; local end-to-end archive/preflight/runbook validation passed and CI now asserts the generated runbook remains blocked, explicit about no broadcast, and includes the expected contract hashes/table.
- GitHub Prometheus CI, Security Audit, and Pages passed for `6e33ecf`; the workflow action upgrade removed the observed Node-20 annotations in the checked runs.
- Updated CI workflow action refs to Node 24-compatible majors after checking official action metadata: `actions/checkout@v7`, `actions/setup-python@v6`, and `gitleaks/gitleaks-action@v3`. Local YAML parse, memory integrity, and `git diff --check` passed before push.
- GitHub Prometheus CI, Security Audit, and Pages passed for `408b0f0`; this was the bridge/memory status commit after the Silverc deploy-preflight rollout.
- Added `scripts/preflight_silverc_deploy.py`, a CI-safe deploy preflight that validates release archive layout, manifest/source/constructor-args/artifact/script hashes, public operator inputs, and current upstream `silverc` deploy capability without accepting secrets or pretending to deploy.
- Local preflight passed against a freshly built release archive and reported `deploy_supported: false` with blocker `upstream silverc exposes no network deploy command`; CI now asserts the expected preflight plan fields.
- GitHub Prometheus CI, Security Audit, and Pages passed for `4236d27`; Prometheus CI now covers the current-Silverc release archive and deploy preflight plan.
- Extended `scripts/smoke_silverc_artifacts.py` into a reusable release-bundle builder with `--out-dir`, `--silverscript-ref`, `--silverscript-repo`, and optional deterministic `--archive` output; local two-run byte comparison passed for manifest and archive.
- Updated Prometheus CI to generate the current-Silverc release archive and assert that it contains the manifest.
- GitHub Prometheus CI, Security Audit, and Pages passed for `d07aeba`; Prometheus CI now covers the current-Silverc release archive path.
- Extended `scripts/smoke_silverc_artifacts.py` from compile-only artifact smoke into a deterministic release-bundle gate: it now writes and validates `/tmp/prometheus-silverc-artifacts/manifest.json` with source, constructor-args, artifact, and compiled-script SHA-256 hashes plus ABI/state-layout metadata.
- Verified local release manifest determinism: two consecutive current-Silverc bundle builds produced identical manifests for the pinned Silverscript ref.
- Added `scripts/smoke_silverc_artifacts.py`, which compiles all 7 current-Silverc fixtures through the pinned upstream `silverc` CLI and validates non-empty script bytes, compiler version, state layout, and expected ABI entries.
- Local release-bundle smoke passed and generated JSON artifacts plus manifest under `/tmp/prometheus-silverc-artifacts`; this proves the available current-Silverc CLI artifact path only.
- Confirmed upstream `silverc` has no network deploy command (`silverc --help` exposes compile/AST-only artifact generation), so Sprint 9 remains blocked on a real network deploy/orchestration path plus signed metrics-oracle operator integration and release hardening.
- GitHub Prometheus CI, Security Audit, and Pages passed for `5209414`; Prometheus CI includes the current-Silverc release-bundle manifest step.
- GitHub Prometheus CI, Security Audit, and Pages passed for `2bb7521`; the pinned Silverc runtime job now passes 55 upstream-injected tests and CI has a GovernanceAutoTuningState fixture guard.
- Added current-Silverscript GovernanceAutoTuning state fixture `modules/contracts/silverc/GovernanceAutoTuningState.sil` and runtime gates for `reportMetrics` and `autoTune`.
- Q-003 is resolved in the current-Silverc contract path as signed metrics-oracle input for `fp_rate`; the legacy `.ss` stub remains archival, and the remaining work is oracle operator/deploy integration.
- Verified accepted paths locally: signed metrics report, high-FP weekly auto-tuning, and zero-FP confidence reduction.
- Verified rejected paths locally: `fp_rate` above `MAX_FP_RATE` and `autoTune` before `TUNING_INTERVAL_BLOCKS`.
- Local verifier passed after GovernanceAutoTuning addition: `env PYTHONPYCACHEPREFIX=/tmp/prometheus-pycache python3 scripts/verify_silverc_h001.py` injected 55 upstream tests and all passed at Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
- Sprint 9 blocker narrowed again: current-Silverc contract runtime gates pass locally; network deploy/orchestration tooling and signed metrics-oracle operator integration remain.
- GitHub Prometheus CI, Security Audit, and Pages passed for `73069fd`; the pinned Silverc runtime job now passes 49 upstream-injected tests and CI has a DevIncentivePoolState fixture guard.
- Added current-Silverscript DevIncentivePool state fixture `modules/contracts/silverc/DevIncentivePoolState.sil` and runtime gates for `proposeGrant`, `voteGrant`, and `executeGrant`.
- Verified accepted paths: valid grant proposal, valid validator support vote, and approved grant execution.
- Verified rejected paths: grant amount above `MAX_GRANT_PROM`, vote at `voting_end_block`, execution below `QUORUM_VOTES`, and execution below `VALIDATOR_QUORUM`.
- DevIncentivePoolState keeps PROM-denominated grant pool accounting without introducing PROM staking or pretending to perform direct PROM `transfer(...)`; the legacy `deposit()` ACL question remains a deployment/orchestration decision once emission authority is finalized.
- GitHub Prometheus CI, Security Audit, and Pages passed for `26c31c0`; the pinned Silverc runtime job now passes 41 upstream-injected tests.
- Extended `scripts/verify_silverc_h001.py` with CommunityDonationsState runtime tests for `donateKas`, `proposeDisbursement`, `voteDisbursement`, and `executeDisbursement`.
- Verified accepted paths: valid donor donation, valid disbursement proposal, valid validator support vote, and approved governance execution.
- Verified rejected paths: zero donation amount, disbursement amount above pool balance, vote at `voting_end_block`, and execution below `DISBURSEMENT_QUORUM`.
- Branch protection still reports direct-push bypasses for `main`; this is allowed by current credentials but remains a workflow/process risk to clean up before release governance.
- GitHub Prometheus CI, Security Audit, and Pages passed for `19efaa9`; Prometheus CI now includes the CommunityDonationsState compile/ABI fixture guard and the pinned Silverc runtime job passes 33 upstream-injected tests.
- Added current-Silverscript CommunityDonations state fixture `modules/contracts/silverc/CommunityDonationsState.sil` and extended `scripts/verify_silverc_h001.py` so the pinned upstream verifier compiles the fixture and builds covenant sigscripts for `donateKas`, `proposeDisbursement`, `voteDisbursement`, and `executeDisbursement`.
- CommunityDonationsState keeps KAS-denominated donation/disbursement accounting, `MIN_DONATION_KAS = 1`, `DISBURSEMENT_QUORUM = 10`, and `VALIDATOR_QUORUM = 6700`; it intentionally does not model legacy maps, string storage, `tx.value`, direct KAS transfer, or cross-contract validator lookups in current Silverc.
- Local verifier passed after CommunityDonations addition: `python3 scripts/verify_silverc_h001.py` injected 33 upstream tests and all passed at Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
- GitHub Prometheus CI, Security Audit, and Pages passed for `4029da2`; the H-001 + Validator State Silverc Runtime job now covers 32 upstream-injected tests including RuleStorage submit/vote/finalize/deactivate runtime paths.
- Noted CI annotations: GitHub is forcing Node.js 24 for some Node 20-based actions. This is warning-only today; track action upgrades later, but it did not block CI.
- Extended the pinned upstream `silverc` verifier with RuleStorageState runtime tests for `submitProposal`, `voteOnProposal`, `finalizeProposal`, and `deactivateRule`.
- Verified accepted paths: valid guardian proposal submission, valid validator support vote, accepted proposal finalization, rejected proposal finalization, and active accepted rule deactivation.
- Verified rejected paths: confidence below `MIN_CONFIDENCE`, vote at `voting_end_block`, zero-vote finalization, and deactivation of a pending/non-accepted rule.
- Local verifier passed: `python3 scripts/verify_silverc_h001.py` injected 32 upstream tests and all passed at Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
- Sprint 9 remained blocked after RuleStorage runtime coverage; the blocker later narrowed through CommunityDonations, DevIncentivePool, GovernanceAutoTuning, and release-bundle gates to network deploy/orchestration tooling plus signed metrics-oracle operator integration.

## 2026-07-09

- GitHub Prometheus CI, Security Audit, and Pages passed for `a11545b`; public README/Whitepaper status refresh is now verified remotely.
- GitHub Prometheus CI, Security Audit, and Pages passed for `1b0b4c7`; the RuleStorage silverc gate documentation commit is verified remotely.
- Refreshed public GitHub-facing docs (`README.md`, `WHITEPAPER.md`, `whitepaper.html`) for the July 2026 post-Toccata state: removed stale production-ready wording, marked deployment as gated, aligned current-Silverc gate status, changed RuleStorage/KRC-20 wording from live fact to target/orchestration, and clarified that Kasplex is not a Guardian reputation dependency.
- Pushed bridge/memory documentation commit `c673766` recording the GuardianReputation formula gate; Prometheus CI and GitHub Pages passed.
- Observed Security Audit run `28979986241` stuck in the `cargo audit` step for commit `c673766`; Secret Detection passed, but Dependency Audit did not complete.
- Hardened `.github/workflows/security-audit.yml` with job/step timeouts and split `cargo-audit` install from `cargo audit` execution so dependency-audit jobs cannot hang indefinitely.
- No product-code behavior changed in the CI hardening pass.
- GitHub Prometheus CI, Security Audit, and Pages passed for `aed3cbb`; the hardened Security Audit completed successfully.
- Added current-Silverscript RuleStorage state fixture `modules/contracts/silverc/RuleStorageState.sil` and extended `scripts/verify_silverc_h001.py` so the pinned upstream verifier compiles the fixture and builds covenant sigscripts for `submitProposal`, `voteOnProposal`, `finalizeProposal`, and `deactivateRule`.
- RuleStorageState keeps CIDv1 `byte[36]`, `MIN_CONFIDENCE = 8500`, `VALIDATOR_QUORUM = 6700`, and explicit Guardian reputation outcome events; it intentionally does not model legacy maps, KRC20 minting, `msg.sender`, events, or cross-contract calls in current Silverc.
- GitHub Prometheus CI, Security Audit, and Pages passed for `3e53e29`; Prometheus CI now includes the RuleStorageState compile/ABI fixture guard.

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
- Restored the exact GuardianReputation accepted-proposal formula in current Silverc using a bounded `for`-loop `isqrt` implementation over the allowed `< 1_000_000` compute-power range; `proposalAccepted` now computes `isqrt(compute_power_gflops) * 100` on-chain and caps at `REPUTATION_MAX`.
- GitHub Prometheus CI, Security Audit, and Pages passed for `eebc521`; the GuardianReputation formula gate is now verified against pinned upstream `silverc`.

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
