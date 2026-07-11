# PROMETHEUS CODEX BRIDGE

Last updated: 2026-07-11 EEST
Repo path: /Users/gio/Desktop/repos/prometheus
Branch observed: main
Latest product-code baseline observed: `4236d27 ci: add silverc deploy preflight`
Latest verified tooling baseline observed: `5fd385e ci: add metrics oracle tx request preflight`
Latest CI note: Prometheus CI, Security Audit, and Pages passed for `5fd385e`. Pinned Silverc runtime job passes 55 upstream-injected tests, the current-Silverc release-bundle CI step compiles all 7 fixtures through upstream `silverc`, writes the deterministic manifest/archive, validates the deploy preflight plan, generates and checks the Markdown operator runbook, validates public GovernanceAutoTuning metrics-oracle report payloads with positive/negative secret-field coverage, and builds unsigned metrics-oracle tx requests in blocked and signer-ready states. Workflow actions use Node 24-compatible majors without the prior Node-20 annotations.
Latest tooling note: `scripts/smoke_silverc_artifacts.py` compiles all 7 current-Silverc fixtures through the pinned upstream `silverc` CLI into JSON artifacts and now writes a deterministic `manifest.json` plus optional deterministic `.tar.gz` release archive with source, constructor-args, artifact, and compiled-script SHA-256 hashes plus ABI/state-layout metadata. `scripts/preflight_silverc_deploy.py` validates that bundle and public operator inputs, can emit a Markdown operator runbook with contract hashes and safety rules via `--runbook-out`, and confirms current upstream `silverc` exposes no network deploy command. `scripts/preflight_metrics_oracle_report.py` validates public GovernanceAutoTuning `reportMetrics` payloads, emits JSON/Markdown operator handoff, and rejects secret-like fields. `scripts/build_metrics_oracle_tx_request.py` binds a validated report to the GovernanceAutoTuning artifact hashes as an unsigned request for an external transaction assembler/signer; local and CI blocked/ready/negative checks pass. Chain transaction assembly, signing, and broadcast remain outside this repo. GitHub workflow action refs were updated to `actions/checkout@v7`, `actions/setup-python@v6`, and `gitleaks/gitleaks-action@v3`. Real on-chain deploy/orchestration remains open.
Latest public-docs note: README, `WHITEPAPER.md`, and `whitepaper.html` were refreshed to reflect post-Toccata deployment gating, verified current-Silverc H-001/Validator/Guardian/RuleStorage/CommunityDonations/DevIncentivePool/GovernanceAutoTuning runtime gates, target-only PROM-RULES asset orchestration, and the no-Kasplex-reputation rule.

Purpose: This file is the local bridge for Codex/Claude Code handover. Read it before touching product code. It consolidates the project state, architecture rules, workflow logic, current open issues, the Reputation Badge decision, and the new direct Sandbox access note.

Security rule: Do not write secrets, tokens, passwords, private keys, keystore material, wallet data, dumps, or backups into this bridge. Direct SSH access is documented by alias and host only. Any sensitive fallback data must remain in root-only server files or local keychains, never in this repository.

---

## 1. Immediate Startflow For Codex

Before any task:

```bash
cd /Users/gio/Desktop/repos/prometheus
git status --short
git log --oneline -5
sed -n '1,260p' docs/agent-bridge/CODEX_BRIDGE.md
sed -n '1,220p' docs/agent-bridge/COOPERATION_RULES.md
sed -n '1,260p' CLAUDE.md
find memory -maxdepth 1 -type f -print | sort
```

Then read all `memory/*.md` files before product-code work. The memory layer is the shared long-term state for AI agents. If a task is purely bridge/docs maintenance, read only the bridge files plus any directly relevant memory files.

Mandatory safety checks:

- Treat local uncommitted diffs as user/agent work. Never revert them without explicit approval.
- Do not start parallel feature work. One task goes to verification before the next begins.
- Do not change security, crypto, contract, auth, multisig, key-management, tokenomics, or governance behavior without an explicit risk note and Gio approval.
- Do not add external dependencies to contracts without architect approval.
- Do not continue Sprint 9/Mainnet deploy work until current-Silverc runtime, release-bundle manifest/archive gates, deploy preflight, the missing network deploy/orchestration path, external signed metrics-oracle transaction assembly/signing/deploy integration, and release hardening are proven.

---

## 2. New Direct Sandbox Access

Status on 2026-07-07: direct SSH access to the Sandbox server was tested successfully from this machine.

Local SSH aliases:

```bash
ssh hetzner
ssh sandbox
```

Current local config:

- `hetzner` -> root on `135.181.254.229`
- `sandbox` -> root on `204.168.165.143`, direct, no ProxyJump
- `hub-sandbox` -> deploy on `204.168.165.143`, still uses `ProxyJump hetzner` and is kept unchanged for compatibility

Verified direct Sandbox test:

```text
host: Sandbox
user: root
access: direct ssh sandbox
```

Important:

- Old workflow: access Sandbox via Hetzner hopping/ProxyJump.
- New workflow: use `ssh sandbox` directly.
- Do not copy private keys or passwords into this repo.
- Root-only operational notes exist on the Hetzner server under `/root/.agent-access/`. They may contain sensitive fallback information and must not be mirrored into git.

If direct access fails:

1. Check the local SSH agent: `ssh-add -l`
2. Check local SSH config: `sed -n '1,220p' ~/.ssh/config`
3. Check direct route: `ssh -o BatchMode=yes -o ConnectTimeout=10 sandbox 'hostname; whoami; uptime'`
4. Only if needed, inspect root-only server docs over `ssh hetzner` without copying secrets into the repo.

---

## 3. Project Identity

| Field | Value |
| --- | --- |
| Project | Prometheus |
| Mission | Decentralized AI-powered threat intelligence on Kaspa |
| GitHub | github.com/NeaBouli/prometheus- |
| Local repo | /Users/gio/Desktop/repos/prometheus |
| Core Dev / Product Owner | NeaBouli / Gio / Kaspartisan |
| Architect / Auditor | Claude |
| Implementer | Codex / Claude Code |
| License | MIT |
| Public site | https://neabouli.github.io/prometheus-/ |
| Full release target | August/September 2026 |
| Mainnet / Covenant-Hardfork target in older docs | 2026-05-05, status must be rechecked before Sprint 9 |

Prometheus turns endpoints into anonymous threat sensors. Light clients detect anomalies locally, Guardian nodes generate and validate YARA rules, validators vote through commit-reveal, and Kaspa L1 stores the canonical protocol state. No foundation, no founder pool, no pre-mine, no emergency stop.

---

## 4. Tech Stack

| Area | Stack |
| --- | --- |
| Blockchain | Kaspa L1, DAGKnight, high-BPS PoW |
| Contracts | Silverscript `.ss` |
| Client / Validator | Rust workspace |
| Guardian | Python, Docker, vLLM |
| Client AI | Phi-3-mini, 4-bit / ONNX direction |
| Guardian AI | LLaMA 3 70B required path, 8B fallback path |
| Learning | Fed-DART style federated learning, gradients only |
| Threat format | YARA rules |
| ZK | Groth16 initially; PLONK evaluation remains open |
| Web | Static HTML/JS/PWA, GitHub Pages |
| CI | GitHub Actions |

Repository anchors:

- `modules/client`
- `modules/validator-node`
- `modules/contracts`
- `modules/guardian-node`
- `memory`
- `docs/agent-bridge`

---

## 5. Architecture Layers

L1 - Kaspa Blockchain / Silverscript contracts:

- `ValidatorStaking.ss` - validator registration, KAS stake, commit-reveal, slashing hooks
- `GuardianReputation.ss` - guardian registration, reputation score, voting power
- `RuleStorage.ss` - YARA rule proposals and CIDv1 storage
- `GovernanceAutoTuning.ss` - MIN_CONFIDENCE and protocol parameter tuning
- `DevIncentivePool.ss` - dev rewards, 5% PROM emission
- `CommunityDonations.ss` - community fund

L2 / P2P coordination:

- Threat hints
- YARA rule proposals
- Commit-reveal voting
- ZK proofs
- Client/Guardian/Validator message flow

Off-chain AI layer:

- Phi-3-mini for local anomaly detection
- LLaMA 3 Guardian nodes for YARA generation
- Fed-DART style updates; no raw user data

---

## 6. Token Model

KAS:

- Validator staking asset.
- Minimum stake in docs: 10,000 KAS.
- Slashed for validator misconduct.
- Validators never stake PROM.

PROM:

- Earned-only reputation/governance/reward token.
- 0% pre-mine.
- Minted through accepted protocol activity.
- Never the validator staking asset.

Annual Year-1 emission target from memory/handover:

| Recipient | Share | PROM/year |
| --- | ---: | ---: |
| Validators | 40% | 8,000,000 |
| Guardians | 30% | 6,000,000 |
| Light Clients | 15% | 3,000,000 |
| Honeypot Nodes | 5% | 1,000,000 |
| Dev Pool | 5% | 1,000,000 |
| Community | 5% | 1,000,000 |

Invariant: Validators stake KAS, never PROM. PROM is earned, not bought as staking power.

---

## 7. Immutable Architecture Rules

The following are treated as bound decisions from `memory/MEMO.md` and related handover docs:

- KAS is the validator staking asset.
- PROM is earned-only reputation/governance/reward asset.
- No emergency stop and no killswitch.
- No foundation and no founder pool.
- Governance is automated where possible; code is the authority.
- Guardian AI: LLaMA 3 70B required path, 8B fallback.
- Client AI: Phi-3-mini 4-bit target, usable on low-resource devices.
- Blockchain: Kaspa with Silverscript.
- Federated learning: gradients only; no raw data.
- GDPR wording: "not applicable" because no personal data is stored on-chain. Do not write "circumvented".
- Validator quorum: 67%.
- Anti-Sybil: quadratic voting / reputation weighting.
- Reporter pool: 75% Light Clients / 25% Honeypot.
- Guardian hybrid routing: 8B default, 70B escalation below confidence threshold.
- Ensemble voting: 5+ 8B nodes can be an alternative to 1x 70B where designed.
- Guardian pooling: on-chain PROM split for shared 70B resources.
- Mobile target: Flutter, not React Native, because background scanning needs native integration.
- Guardian installer target: one-command curl installer.

Never self-approve changes touching:

- KAS/PROM separation
- Emergency stop / killswitch
- `slash()` access control
- Commit-reveal formula
- Contract external dependencies
- Reputation source of truth
- Governance authority

If uncertain, write:

```text
QUESTION FOR CLAUDE:
```

in the relevant audit/bridge file and stop before making the risky change.

---

## 8. Deterministic Agent Workflow

Roles:

- Core Dev / Gio: final decision maker, triggers tasks, approves sprints, decides architecture.
- Claude: architect/auditor, writes prompts, audits, answers architecture questions, tracks patterns.
- Codex / Claude Code: implementer/reviewer, writes code when tasked, verifies, updates memory/bridge.

Loop:

```text
Core Dev triggers task
  -> Codex reads bridge + all memory/*.md
  -> Codex checks git status and current diffs
  -> Codex implements only the requested task
  -> Codex runs mandatory checks
  -> Codex updates memory/bridge where required
  -> Codex commits/pushes only if explicitly asked
  -> Claude audits
  -> Core Dev accepts/rejects
  -> next task
```

Mandatory checks by area:

- Rust: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`
- HTML/static: verify structured data and links where relevant
- Security: do not expose secrets; run targeted grep/gitleaks checks when touching configs/docs
- Contracts: no Sprint 9 deploy until current-Silverc runtime, release-bundle manifest/archive gates, deploy preflight, the missing network deploy/orchestration path, external signed metrics-oracle transaction assembly/signing/deploy integration, and release hardening are proven
- Before git add: verify files on disk with `git diff` and targeted reads

No parallel open-ended work. No "finish later" state unless the user explicitly pauses the task and the bridge is updated.

---

## 9. Memory Layer Contract

The `memory/` directory is the long-term shared memory for AI agents:

- `MEMO.md` - architecture decisions and permanent rules; append only unless explicitly approved.
- `AUDIT.md` - findings, fixes, and audit history.
- `ERRORS.md` - known error patterns that must not repeat.
- `TODO.md` - prioritized sprint backlog.
- `STATUS.md` - current status.
- `CHECKPOINT.md` - last known good state.
- `SCHEMA.md` - data structures and contract interfaces.
- `API.md` - API contracts between components.
- `SPRINTS.md` - sprint definitions and sequencing.

Most important rule: If it is in `MEMO.md`, it still applies even if the current user prompt does not repeat it.

---

## 10. Sprint Status Snapshot

Known consolidated status from memory/handover and user-provided synthesis:

| Sprint | Goal | Status |
| --- | --- | --- |
| 0 | Setup and testnet | ACCEPTED |
| 1 | 6 Silverscript contracts, 54 tests | ACCEPTED |
| 2 | Light client basis, 27 tests | ACCEPTED |
| 3 | Phi-3-mini integration, 28 tests | ACCEPTED |
| 4 | Guardian Node Docker/vLLM, 26 tests | ACCEPTED |
| 5 | Commit-reveal voting, 29 tests | ACCEPTED |
| 6 | E2E integration, 18 tests | ACCEPTED |
| 7 | Dashboard and docs | ACCEPTED |
| 8 | Contributing/wiki/site/SEO in older handover | ACCEPTED in older handover |
| 9 | Contract deploy on Testnet/Mainnet path | BLOCKED until the missing network deploy/orchestration path, external signed metrics-oracle transaction assembly/signing/deploy integration, and release hardening pass. Current-Silverc runtime, release-bundle manifest/archive, deploy preflight, operator runbook, public metrics-oracle report preflight, and unsigned oracle tx-request builder gates pass locally and in CI. |
| 10B | Guardian decentralization | Startable, but architecture-sensitive |

Test status from user synthesis:

- 203/204 tests green.
- 1 flaky performance test in debug mode.
- Verify current test state before relying on this number.

---

## 11. Audit Findings Snapshot

Pre-hardfork audit synthesis:

| Severity | Count | Notes |
| --- | ---: | --- |
| Critical | 0 | None known |
| High | 2 | H-001 byte-core + ValidatorStakingState runtime transitions + signed-int deployment bounds verified; GuardianReputationState compile/ABI, runtime transitions, and accepted-proposal formula verified; RuleStorageState, CommunityDonationsState, DevIncentivePoolState, and GovernanceAutoTuningState compile/ABI/runtime gates verified locally; H-002 fixed |
| Medium | 2 | M-001 heuristic confidence; M-002 flaky perf test |
| Low | 3 | L-001 deposit ACL, L-002 fp_rate oracle operator integration, L-003 CEI |
| Passed clean | 28 | From 35-check audit synthesis |

Critical active rule:

```text
H-001 byte-core, current-silverc `ValidatorStakingState.sil` runtime transitions, and deployment signed-int bounds are verified. Current upstream Silverc entrypoint integers are signed, so deployable `salt` and `block_height` values are scoped to `0..=i64::MAX`; Rust keeps the raw H-001 `u64` byte helper for historical vectors and exposes `build_silverc_checked` / `validate_silverc_commitment_bounds` for deployment calls.
On 2026-07-11, the repo contains `modules/contracts/silverc/ValidatorStakingH001.sil`, `modules/contracts/silverc/ValidatorStakingState.sil`, `modules/contracts/silverc/GuardianReputationState.sil`, `modules/contracts/silverc/RuleStorageState.sil`, `modules/contracts/silverc/CommunityDonationsState.sil`, `modules/contracts/silverc/DevIncentivePoolState.sil`, `modules/contracts/silverc/GovernanceAutoTuningState.sil`, and `scripts/verify_silverc_h001.py`; the script verifies explicit `vote_byte || byte[8](salt) || byte[8](block_height)` against the Rust H-001 vectors, proves signed negative Silverc values do not match the Rust `u64::MAX` vector, compiles/builds covenant sigscripts for the ValidatorStaking state fixture, runtime-tests `commitVote` valid-bond acceptance plus low-bond/negative-height rejection, `revealVote` valid-reveal acceptance plus wrong-salt/negative-salt rejection, `slashInvalidReveal` invalid-reveal acceptance plus valid-reveal/negative-salt rejection, `requestWithdraw` active-uncommitted acceptance plus open-commitment/negative-height rejection, and `completeWithdraw` zero-output termination after cooldown plus cooldown rejection, compiles/builds/runtime-tests GuardianReputation `register`, `proposalAccepted`, and `proposalRejected` with exact `isqrt(compute_power) * 100` accepted-proposal formula, compiles/builds/runtime-tests RuleStorage `submitProposal`, `voteOnProposal`, `finalizeProposal`, and `deactivateRule`, compiles/builds/runtime-tests CommunityDonations `donateKas`, `proposeDisbursement`, `voteDisbursement`, and `executeDisbursement`, compiles/builds/runtime-tests DevIncentivePool `proposeGrant`, `voteGrant`, and `executeGrant` including max-grant, late-vote, quorum, and approval rejection paths, and compiles/builds/runtime-tests GovernanceAutoTuning `reportMetrics` and `autoTune` including signed metrics acceptance, invalid `fp_rate`, early tuning, high-FP, and zero-FP paths at pinned Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
```

Known findings:

- H-001: `ValidatorStaking.ss:111` legacy commit-reveal LE-encoding ambiguity. Repo-tracked current-Silverscript H-001 fixture passes; `ValidatorStakingState.sil` compile/ABI gate passes; `commitVote`, `revealVote`, `slashInvalidReveal`, `requestWithdraw`, and `completeWithdraw` runtime tests pass; deployment bounds are explicitly scoped to `0..=i64::MAX`.
- GuardianReputation current-Silverc port: `GuardianReputationState.sil` compile/ABI and runtime gates pass for `register`, `proposalAccepted`, and `proposalRejected` without badge, NFT, Kasplex, or staking semantics. The accepted-proposal reputation formula is restored as exact bounded `isqrt(compute_power_gflops) * 100`.
- RuleStorage current-Silverc port: `RuleStorageState.sil` compile/ABI/runtime gates pass for `submitProposal`, `voteOnProposal`, `finalizeProposal`, and `deactivateRule`; valid submit/vote/finalize/deactivate transitions are accepted, low confidence, late vote, zero-vote finalization, and pending-rule deactivation are rejected. It keeps CIDv1 `byte[36]`, `MIN_CONFIDENCE = 8500`, `VALIDATOR_QUORUM = 6700`, and explicit Guardian reputation outcome events without pretending to support legacy maps, KRC20 minting, or cross-contract calls in current Silverc.
- CommunityDonations current-Silverc port: `CommunityDonationsState.sil` compile/ABI/runtime gates pass locally and in CI for `donateKas`, `proposeDisbursement`, `voteDisbursement`, and `executeDisbursement`; valid donate/propose/vote/execute transitions are accepted, zero donation, over-pool proposal, late vote, and insufficient quorum are rejected. It keeps KAS-denominated pool accounting, `MIN_DONATION_KAS = 1`, `DISBURSEMENT_QUORUM = 10`, and `VALIDATOR_QUORUM = 6700` without pretending to support legacy maps, strings, `tx.value`, direct KAS transfer, or cross-contract validator lookups in current Silverc.
- DevIncentivePool current-Silverc port: `DevIncentivePoolState.sil` compile/ABI/runtime gates pass locally and in CI for `proposeGrant`, `voteGrant`, and `executeGrant`; valid propose/vote/execute transitions are accepted, amount above `MAX_GRANT_PROM`, late vote, insufficient quorum, and insufficient approval are rejected. It keeps PROM-denominated grant pool accounting without introducing PROM staking or pretending to support legacy maps, strings, `msg.sender`, direct PROM transfer, or cross-contract validator lookups in current Silverc. Legacy `deposit()` ACL remains a deployment/orchestration decision once emission authority is finalized.
- GovernanceAutoTuning current-Silverc port: `GovernanceAutoTuningState.sil` compile/ABI/runtime gates pass locally for `reportMetrics` and `autoTune`; valid signed metrics reports are accepted, `fp_rate > MAX_FP_RATE` is rejected, high-FP and zero-FP auto-tune paths are accepted, and early tuning is rejected. `scripts/preflight_metrics_oracle_report.py` validates public report payloads, emits JSON/Markdown operator handoff, and rejects secret-like fields locally and in CI. `scripts/build_metrics_oracle_tx_request.py` binds the report to GovernanceAutoTuning artifact hashes as an unsigned external-assembler request and passes local blocked/ready/negative checks. Q-003 is resolved in the contract gate as signed metrics input; external chain transaction assembly/signing/deploy integration remains.
- Current-Silverc release-bundle manifest/archive/preflight: `scripts/smoke_silverc_artifacts.py` compiles `ValidatorStakingH001`, `ValidatorStakingState`, `GuardianReputationState`, `RuleStorageState`, `CommunityDonationsState`, `DevIncentivePoolState`, and `GovernanceAutoTuningState` through the pinned upstream `silverc` CLI and validates non-empty script bytes, compiler version, state layout, expected ABI entries, and deterministic source/artifact/script hashes. It supports `--out-dir` and optional deterministic `--archive` output for operator handoff. `scripts/preflight_silverc_deploy.py` validates archive layout, manifest/source/constructor-args/artifact/script hashes, public operator inputs, and upstream deploy CLI capability. This proves the available CLI artifact/preflight path only; upstream `silverc` currently has no network deploy command.
- H-002: unnecessary Mutex around Phi3Model. Fixed in commit `6347b85` according to memory/handover.
- M-001: Guardian YARA generator confidence is heuristic, needs real LLM confidence or validated metric.
- M-002: performance test flaky in debug mode, threshold/release gate needed.
- L-001: deposit ACL review, blocked by contract compiler path.
- L-002 / Q-003: current-Silverc contract gate uses signed metrics `fp_rate` input; public metrics report preflight and unsigned tx-request builder pass locally and in GitHub Prometheus CI for `5fd385e`; external chain transaction assembly/signing/deploy integration still needed.
- L-003: CEI pattern around `revealVote`, blocked by contract compiler path.
- NEA-124: `rusty-kaspa` pinning — fixed locally 2026-07-07 by pinning workspace deps to tag `v2.0.1`.

---

## 12. Open Linear Issues From User Synthesis

| Issue | Priority | Blocking |
| --- | --- | --- |
| NEA-116 Hardfork/ssc Status | Urgent | None |
| NEA-117 H-001 LE encoding | High | NEA-116 |
| NEA-118 H-002 Mutex | High | Should be fixed; verify current tree |
| NEA-119 M-001 heuristic confidence | Medium | None |
| NEA-120 M-002 flaky test | Medium | None |
| NEA-121 L-001 deposit ACL | Low | NEA-116 |
| NEA-122 Q-003 fp_rate Oracle operator integration | Medium | None |
| NEA-123 L-003 CEI revealVote | Low | NEA-116 |
| NEA-124 rusty-kaspa pinning | High | None |
| NEA-125 SPRINTS.md docs | Low | None |
| NEA-126 Sprint 9 Deploy | Urgent | NEA-116 |
| NEA-127 Sprint 10B Guardian | High | None |

Before acting on Linear IDs, verify whether they exist in the connected issue tracker and whether local memory has newer status.

---

## 13. Reputation Badges Decision

Question considered: Should Prometheus introduce reputation badges, NFTs, or "Proof of Guardian" badges?

Initial argument for badges:

- Prometheus has a cold-start problem.
- Guardian Nodes are expensive, with RTX 4070 Ti as a minimum direction and much higher cost for serious 70B setups.
- PROM may have no early market value.
- A badge could signal early contribution: accepted rules, Guardian activity, and visible proof before PROM liquidity.
- As a bootstrap signal, a visible reputation artifact has some practical value.

Argument against badges:

- Prometheus already has a native reputation system in `GuardianReputation.ss`.
- Reputation score, quadratic voting, accepted-rule history, and voting-power reduction already form the canonical reputation layer.
- An NFT badge would create a second truth source for the same state.
- Mirroring L1 reputation into an NFT creates sync problems and possible stale/incorrect external state.

Kasplex option considered:

- A lightweight "Proof of Guardian" badge on Kasplex L2 could be externally visible.
- However, Kasplex is not Kaspa L1. It is a separate L2/operator ecosystem.
- If Kasplex fails, forks, loses funding, changes rules, or disappears, reputation badges could freeze or vanish.
- That creates a third-party dependency in a critical identity/reputation path.
- This conflicts with Prometheus' no-foundation/no-gatekeeper/no-central-control principle.

Decision:

```text
No Badge system.
No NFT reputation ecosystem.
No Kasplex dependency for Guardian reputation.
Canonical Guardian reputation lives on Kaspa L1 in GuardianReputation.ss.
```

What Prometheus actually needs:

- Better readability of L1 reputation.
- A clean dashboard/audit frontend that explains Guardian score, accepted rules, voting history, and performance.
- Optional future proof: a ZK-based Proof-of-Reputation directly against Kaspa L1, e.g. "address has reputation >= X and >= Y accepted rules", without minting a badge and without Kasplex.

Allowed future direction, only with architect approval:

- Standardized L1 read model for reputation.
- ZK proof-of-reputation against the L1 canonical state.
- External display layer that reads L1, but does not become a second source of truth.

Disallowed by current decision:

- NFT badge ecosystem.
- Reputation on Kasplex as critical path.
- Any architecture where badge ownership overrides or replaces `GuardianReputation.ss`.
- Any third-party layer as canonical reputation source.

Rationale summary:

The badge concept dissolves under closer analysis. The useful object is already there: L1 reputation. The task is legibility, not another asset.

---

## 14. Contract And Protocol Constants

Start values from synthesis:

| Parameter | Value | Goal |
| --- | --- | --- |
| MIN_STAKE_KAS | 10,000 | 50-200 active validators |
| MIN_CONFIDENCE | 0.85 / 8500 uint64 | False-positive rate below 0.5% |
| VALIDATOR_QUORUM | 67% / 6700 uint64 | Stable rule acceptance |
| REWARD_BASE | 100 PROM | 100-200 proposals/day |
| SLASHING_SIMPLE | 5% | Deter misconduct |
| SLASHING_COLLUSION | 20% | Make collusion expensive |
| COOLDOWN_BLOCKS | 100,800 | About 7 days at 100 BPS assumption |
| CHALLENGE_PERIOD | 86,400s | 24 hours |

Commit-reveal invariant:

```text
commitment = sha256(vote_byte || salt_LE || block_height_LE)
vote_byte = 1 for true, 0 for false
salt = 8-byte little-endian
block_height = 8-byte little-endian
```

H-001 exists because the contract compiler/preimage encoding must be proven bit-exact with Rust.

---

## 15. Known Risks

Technical:

- H-001 LE encoding can break validator voting if contract and Rust preimages differ.
- Upstream `silverc` is the currently verified compiler path; no separate `ssc` binary was found. Prometheus contracts still need current-Silverscript compatibility work before Sprint 9.
- `rusty-kaspa` is pinned to tag `v2.0.1`; keep this pin unless a reviewed upgrade is needed.

Economic:

- Guardian 70B hardware can cost $60k-$120k.
- Pooling helps but does not fully solve early PROM value/cold-start.
- A readable L1 reputation dashboard is more important than badges.

Governance:

- Single-contributor risk exists.
- Succession, multisig, and maintenance procedures need explicit design before production scale.

External:

- Kasplex must not be a critical dependency for reputation.
- Any explorer/wallet display should be treated as UI over L1, not authority.

Legal/privacy:

- Use "GDPR not applicable" only when the architecture stores no personal data on-chain and ZK/anonymity claims are valid.
- Do not claim GDPR is "circumvented".

---

## 16. Handover Provenance And Staleness

Sources consolidated into this file:

- Local bridge files in `docs/agent-bridge/`
- Memory layer files under `memory/`
- User-provided project synthesis on 2026-07-07
- Local file `/Users/gio/Downloads/PROMETHEUS_CODEX_HANDOVER.md` as historical handover
- Live local SSH verification for `ssh sandbox` on 2026-07-07

Staleness warning:

- The downloaded handover says date `2026-03-23` and last commit `6347b85`.
- The local repo observed on 2026-07-08 had a moving product-code baseline; use `git log --oneline -1` as source of truth.
- Bridge-only reconciliation commits may advance `HEAD`; use `git log --oneline -1` as source of truth.
- Therefore the handover is useful for architecture and workflow, but not authoritative for current git state.
- Always verify current files and tests before implementing.

---

## 17. Practical Next Actions

Highest priority:

1. Port or deployment-scope the remaining Prometheus contracts against current upstream Silverscript (`silverc`).
2. Keep deployment commit-reveal inputs within the documented current-Silverc `0..=i64::MAX` bounds.
3. Document Silverscript/TN12/Mainnet compatibility limits before any deploy attempt.
4. Implement external signed metrics-oracle transaction assembly/signing/deploy integration before beta/mainnet governance.
5. Keep Reputation Badge decision as "no badge, L1 reputation only".

If asked to continue project work:

- Start with `memory/MEMO.md`, `memory/AUDIT.md`, `memory/TODO.md`, `memory/CHECKPOINT.md`, and this bridge.
- Check git status first.
- Do not overwrite existing uncommitted changes.
- Use `ssh sandbox` for direct Sandbox access when server work is needed.
- Use `ssh hetzner` only for Hetzner server work or recovery/bridge notes.

---

## 18. One-Line Decision Summary

Prometheus does not need reputation badges; it needs readable, provable Kaspa L1 Guardian reputation. Codex has direct Sandbox access via `ssh sandbox`, upstream `silverc` works in CI, H-001 byte-core plus current-silverc `ValidatorStakingState.sil` runtime transitions pass, `GuardianReputationState.sil` compile/ABI/runtime/formula gates pass, `RuleStorageState.sil` compile/ABI/runtime gates pass, `CommunityDonationsState.sil` compile/ABI/runtime gates pass, `DevIncentivePoolState.sil` compile/ABI/runtime gates pass, `GovernanceAutoTuningState.sil` signed metrics/auto-tune runtime gates pass locally, current-Silverc release-bundle manifest/archive/preflight passes locally and in CI for all 7 fixtures, public metrics-oracle report preflight passes locally and in CI, unsigned oracle tx-request builder passes locally and in CI, signed-int deployment bounds are documented/enforced, and Sprint 9 remains blocked until the missing network deploy/orchestration path plus external signed metrics-oracle transaction assembly/signing/deploy integration pass.
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
