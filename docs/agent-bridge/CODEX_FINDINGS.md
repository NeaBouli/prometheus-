# Codex Findings

## 2026-07-07 — Repository / Architecture Audit

> Scope: bridge + memory layer, contracts, Rust client/validator, Python Guardian, CI, public GitHub Pages files.
> Mode: read-only audit for product code.
> Result after 2026-07-08 implementation follow-up: 1 FAIL / 5 WARN / 12 PASS.

### Summary

Prometheus is well-structured for a pre-mainnet/prototype codebase. The architecture memory is unusually strong: KAS/PROM separation, no emergency stop, slash ACL, reputation source of truth, CIDv1, and the agent workflow are all documented and mostly reflected in code.

This is not mainnet-ready today. The right verdict is: good work, continue the professional schema, but keep Sprint 9 blocked until the Prometheus contracts compile against current Silverscript tooling and H-001 is verified in that contract form. The stale public May 5 launch language was corrected in the same 2026-07-07 follow-up.

### Findings by Domain

#### Contracts — FAIL

- **[BLOCKING / PARTIALLY VERIFIED 2026-07-08] H-001 commit-reveal preimage encoding still needs Prometheus contract verification** — `modules/contracts/ValidatorStaking.ss:110-112`, `modules/validator-node/src/voting/commit.rs`
  - What: Rust builds a canonical 17-byte preimage through `commitment_preimage_bytes(vote, salt, block_height)` and tests known H-001 hex vectors. Upstream Silverscript tooling now builds locally. The repo now includes `modules/contracts/silverc/ValidatorStakingH001.sil` plus `scripts/verify_silverc_h001.py`; the script verifies explicit `sha256(vote_byte || byte[8](salt) || byte[8](block_height))` against the Rust vectors for positive 64-bit values at pinned Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
  - Remaining risk: The full Prometheus `ValidatorStaking.ss` state machine still uses legacy `.ss`/`uint64` syntax. That full contract form has not been ported, compiled, or executed with upstream `silverc`.
  - Path: If the deployed contract serializes `uint64` or `bool` differently than the Rust preimage, validators can create valid Rust commitments that fail on-chain reveal, causing broken voting or bond loss.
  - Fix: Port or adapt the full `ValidatorStaking.ss` state machine to current Silverscript syntax, keep explicit byte construction, and re-run the H-001 vectors against the ported contract before Sprint 9.

- **[LOW] Known contract cleanups remain before deploy refactor** — `modules/contracts/DevIncentivePool.ss:145-149`, `modules/contracts/ValidatorStaking.ss:124-132`
  - What: DevIncentivePool deposit has no emission-contract ACL, and revealVote transfers bond before deleting commitment.
  - Path: Deposit only adds funds, so blast radius is low. reveal re-entry is mitigated by the commitment guard but still violates strict CEI order.
  - Fix: Add emission contract ACL when address exists; move commitment deletion before transfer during the H-001 refactor.

#### Production Stubs — WARN

- **[PARTIAL / MITIGATED 2026-07-11] Production/beta stub paths are gated in the Rust client and GovernanceAutoTuning has a current-Silverc metrics gate** — `modules/client/src/runtime.rs`, `modules/client/src/network/zk_proof.rs`, `modules/client/src/ai/phi3.rs`, `modules/client/src/blockchain/krc20.rs`, `modules/client/src/ai/federated.rs`, `modules/contracts/silverc/GovernanceAutoTuningState.sil`
  - What: Rust client stubs for ZK proofs, Phi-3 fallback/heuristic inference, KRC-20 cached rules, and Fed-DART placeholder calls now call a central runtime gate. `PROMETHEUS_RUNTIME=beta|mainnet|production|prod` rejects those stubs. Development mode remains offline-testable.
  - Current-Silverc update: `GovernanceAutoTuningState.sil` replaces the contract-side Q-003 stub with signed metrics-oracle input and runtime gates for `reportMetrics` and `autoTune`.
  - Remaining risk: the signed metrics-oracle operator and deploy path still need production integration before beta/mainnet governance.
  - Fix: Keep Rust client gate; implement external oracle transaction assembly/signing/deploy integration and direct deploy smoke before beta/mainnet governance.

#### Guardian / AI Pipeline — WARN

- **[HIGH] LLM prompt/output boundary is too loose for untrusted indicators** — `modules/guardian-node/jaeger/llm_server.py:48-56`, `modules/guardian-node/jaeger/llm_server.py:67-74`, `modules/guardian-node/jaeger/llm_server.py:101-112`, `modules/guardian-node/jaeger/yara_generator.py:72-78`
  - What: User/threat indicators are directly embedded into prompts; output parsing trusts `choices[0].message.content`; YARA validation checks only substrings; confidence is heuristic.
  - Path: A malicious indicator can inject instructions into the prompt or produce syntactically plausible but unsafe/low-quality YARA. The pipeline may assign high confidence based on section presence and indicator count.
  - Fix: Use a strict JSON output schema, escape or delimit indicators as data, validate parsed fields, run real YARA parser/compile checks, and derive confidence from model output plus validation metrics.

#### Public Site / Docs — WARN

- **[PASS / FIXED 2026-07-07] Public launch timeline updated after Toccata research** — `index.html`, `roadmap.html`, `whitepaper.html`, `guardian-economics.html`, `README.md`, `WHITEPAPER.md`, `docs/roadmap.md`, `memory/STATUS.md`, `memory/CHECKPOINT.md`, `BACKLOG.md`
  - What: Public pages still say "Mainnet May 5, 2026" / "Mainnet launches May 5, 2026" although that date is now in the past and bridge says hardfork/ssc/H-001 must be rechecked.
  - Path: GitHub Pages can mislead users/contributors and weakens project credibility.
  - Fix: Updated wording to post-Toccata deploy verification. Prometheus no longer claims contracts are live until ssc/tooling and H-001 pass.

#### CI / Supply Chain — WARN

- **[PASS / FIXED 2026-07-07] Dependency security workflow is now a gate** — `.github/workflows/security-audit.yml`
  - What: `npm audit`, `cargo audit`, and `pip-audit` no longer end with `|| true`; the workflow also supports manual dispatch and has explicit read-only contents permission.
  - Evidence: GitHub Security Audit workflow was re-enabled with `gh workflow enable security-audit.yml`. Local `cargo audit` reports no vulnerabilities after the Rusty-Kaspa v2.0.1 pin; local `pip-audit -r modules/guardian-node/requirements.txt` reports no known vulnerabilities.

#### Agent Workflow / Local Safety — WARN

- **[MEDIUM] Local Claude settings allow broad edit acceptance** — `.claude/settings.json:1-7`
  - What: `defaultMode` is `acceptEdits`; only `.env`, `.env.local`, `node_modules/`, and `.git/` are disallowed.
  - Path: This is workable for trusted local development, but it is looser than the bridge policy for a security/contract repo.
  - Fix: For audit/mainnet work, use a stricter mode or expand disallowed paths to secrets, keys, wallets, dumps, backups, deployment artifacts, and root-only access notes.

#### Tests / Verification — PASS with caveat

- **[PASS] Rust formatting, linting, and tests pass locally**
  - Evidence: `cargo fmt --all --check` passed; `cargo clippy --workspace -- -D warnings` passed; `cargo test --workspace` passed with 100 tests run, 2 ignored live-node tests.

- **[PASS] Python Guardian tests pass locally**
  - Evidence: Temporary `/tmp` venv, `PYTHONPATH=. python -m pytest tests/ --tb=short`: 23 passed, 3 skipped.

- **[PASS] Memory integrity passes**
  - Evidence: `python3 scripts/check_memory_integrity.py` passed all required memory files.

- **[PASS] Remote branch alignment**
  - Evidence: local `main` and `origin/main` were aligned after the post-Toccata update. Use `git log --oneline -1` and `git ls-remote origin refs/heads/main` for the live commit, because bridge-only commits may advance HEAD.

- **[PASS] No tracked env/key filenames found**
  - Evidence: filename scan found no tracked `.env`, `.pem`, `.key`, secret/password/token files.

- **[PASS] Website SEO/GEO basics are present**
  - Evidence: main HTML pages include Schema.org JSON-LD, OG title, canonical, ai-summary, manifest, and mobile menu patterns.

- **[PASS] Core invariants are consistently documented**
  - Evidence: Bridge/memory/code preserve KAS staking, PROM earned-only, no emergency stop, no badges/NFT reputation layer, Guardian reputation on Kaspa L1.

- **[PASS] H-002 appears fixed**
  - Evidence: `modules/client/src/ai/detection.rs` uses `Arc<Phi3Model>` and only keeps `tokio::sync::Mutex` for `YaraScanner`.

- **[PASS] Rusty-Kaspa dependencies are pinned for Toccata**
  - Evidence: workspace Kaspa dependencies in `Cargo.toml` now use `tag = "v2.0.1"` and `Cargo.lock` resolves Kaspa crates to `v2.0.1` instead of a floating `master` branch commit.

- **[PASS] H-001 Rust guard vectors exist**
  - Evidence: `modules/validator-node/src/voting/commit.rs` exposes a canonical 17-byte preimage builder and tests normal, zero, endian-visible, and `u64::MAX` vectors.

- **[PASS] Rust client production/beta stub gate exists**
  - Evidence: `modules/client/src/runtime.rs` defines `PROMETHEUS_RUNTIME` parsing and rejects security-critical stubs in beta/mainnet; `cargo test -p prometheus-client` covers the gate and existing stub behavior in development mode.

### Priority Matrix

#### BLOCKING

1. Direct `ssc`/current-Silverc deploy smoke before Sprint 9 or any contract deployment.
2. External signed metrics-oracle transaction assembly/signing/deploy integration before beta/mainnet governance.

#### HIGH

1. Harden Guardian LLM prompt/output/schema/validation boundary.
2. Public GitHub Pages/README/Whitepaper timeline was updated to reflect the real July 2026 state.

#### MEDIUM

1. Tighten `.claude/settings.json` for mainnet/audit sessions.

#### LOW

1. Add DevIncentivePool deposit ACL once emission contract address exists.
2. Move reveal commitment deletion before bond transfer in the H-001 contract refactor.

### Recommendation

Continue with the current professional schema. The team worked well: the repo has a strong memory layer, transparent caveats, and tests that currently pass. The next practical task should be either:

1. Prove a direct `ssc`/current-Silverc deploy smoke path for at least one state fixture and document the deployment runbook, or
2. Implement the signed metrics-oracle operator path required by `GovernanceAutoTuningState.sil`.
