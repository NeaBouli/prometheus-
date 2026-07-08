# PROMETHEUS CODEX BRIDGE

Last updated: 2026-07-08 EEST
Repo path: /Users/gio/Desktop/repos/prometheus
Branch observed: main
Latest product-code baseline observed: eeb4808 - docs: update post-toccata bridge status
Current HEAD: verify with `git log --oneline -1`; bridge-only commits may advance it.

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
- Do not continue Sprint 9/Mainnet work until H-001 is verified or fixed.

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
- Contracts: no Sprint 9 deploy until H-001 is resolved
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
| 9 | Contract deploy on Testnet/Mainnet path | BLOCKED until hardfork/ssc/H-001 verification |
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
| High | 2 | H-001 open/pending ssc; H-002 fixed |
| Medium | 2 | M-001 heuristic confidence; M-002 flaky perf test |
| Low | 3 | L-001 deposit ACL, L-002 fp_rate stub, L-003 CEI |
| Passed clean | 28 | From 35-check audit synthesis |

Critical active rule:

```text
H-001 is still OPEN unless memory/AUDIT.md proves otherwise.
ValidatorStaking.ss commit-reveal LE encoding must be verified after ssc/hardfork before Sprint 9 deployment or any validator mainnet contact.
```

Known findings:

- H-001: `ValidatorStaking.ss:111` commit-reveal LE-encoding ambiguity. Pending compiler/hardfork verification.
- H-002: unnecessary Mutex around Phi3Model. Fixed in commit `6347b85` according to memory/handover.
- M-001: Guardian YARA generator confidence is heuristic, needs real LLM confidence or validated metric.
- M-002: performance test flaky in debug mode, threshold/release gate needed.
- L-001: deposit ACL review, blocked by contract compiler path.
- L-002 / Q-003: `fp_rate` oracle decision needed.
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
| NEA-122 Q-003 fp_rate Oracle decision | Medium | None |
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
- `ssc` compiler/hardfork status must be verified with current upstream state before Sprint 9.
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
- The local repo observed on 2026-07-08 had latest product-code baseline `eeb4808`.
- Bridge-only reconciliation commits may advance `HEAD`; use `git log --oneline -1` as source of truth.
- Therefore the handover is useful for architecture and workflow, but not authoritative for current git state.
- Always verify current files and tests before implementing.

---

## 17. Practical Next Actions

Highest priority:

1. Install/build local Silverscript tooling (`silverc` upstream; no `ssc` binary found yet).
2. Verify H-001 LE encoding before Sprint 9 by comparing Silverscript behavior against the Rust H-001 vectors.
3. Document Silverscript/TN12/Mainnet compatibility limits before any deploy attempt.
4. Resolve Q-003 contract-side `fp_rate` oracle stub before beta/mainnet governance.
5. Keep Reputation Badge decision as "no badge, L1 reputation only".

If asked to continue project work:

- Start with `memory/MEMO.md`, `memory/AUDIT.md`, `memory/TODO.md`, `memory/CHECKPOINT.md`, and this bridge.
- Check git status first.
- Do not overwrite existing uncommitted changes.
- Use `ssh sandbox` for direct Sandbox access when server work is needed.
- Use `ssh hetzner` only for Hetzner server work or recovery/bridge notes.

---

## 18. One-Line Decision Summary

Prometheus does not need reputation badges; it needs readable, provable Kaspa L1 Guardian reputation. Codex has direct Sandbox access via `ssh sandbox`, and Sprint 9 remains blocked until H-001/ssc/hardfork status is verified.
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
