# PROMETHEUS CODEX BRIDGE

Last updated: 2026-07-16 EEST
Repo path: /Users/gio/Desktop/repos/prometheus
Operational baseline: `main` at the verified GH-25 evidence merge; this GH-9 handoff/docs update remains PR-only, and foreign untracked `Prometheus-1.png` remains untouched
Latest verified rollout/docs baseline: `205e1ca928d3048109575cf7a21810c9e6609120 docs: record GH-25 merge evidence (#27)`
Latest in-progress task: preserve the exact-main `205e1ca` H-001 handoff rebuild and public documentation, then obtain an explicitly approved external BIP340 signature response. The first real metrics transition remains a separate explicit-approval gate.
Latest CI note: main Prometheus CI `29454591518`, Security Audit `29454591555`, and Pages `29454590793` passed for exact merged commit `205e1ca928d3048109575cf7a21810c9e6609120`. The exact-main H-001 rebuild then revalidated the public unspent/non-coinbase funding output against a synced `rusty-kaspa 2.0.1` node above Toccata activation. Current rollout issue https://github.com/NeaBouli/prometheus-/issues/9 remains open for execution.
Current PR note: GH-25 product PR https://github.com/NeaBouli/prometheus-/pull/26 merged normally as `072f04a`; evidence PR https://github.com/NeaBouli/prometheus-/pull/27 merged normally as `205e1ca`. All protected contexts passed without direct-main push or admin bypass. GH-9 remains the active rollout issue.
Current GH-13 note: the first miner-facing integration is an experimental `prometheus-client miner-companion` sidecar for a credential-free loopback Testnet-10 wRPC endpoint. Strict TOML preflight rejects beta/mainnet, remote or credential-bearing RPC, scanning, reporting, validator/honeypot roles, and unknown wallet/reward fields. `run` observes BlockDAG health only. It does not alter ASIC firmware, intercept Stratum, inspect the host, send miner telemetry, or award PROM. Reporter allocation remains conditional on future consensus-verified security contributions. Real Phi-3, ZK proofs, canonical rule distribution, reviewed transport/privacy scopes, and enforceable resource controls remain required before production expansion.
Current GH-13 verification: 153 workspace tests pass with two intentional live-test ignores; Rustfmt, warning-free workspace Clippy, Memory Integrity, six Autodidactic tests, Pages/JSON-LD, YAML parsing, checksum-verified Actionlint v1.7.12, Cargo Audit with no vulnerabilities, staged-diff Gitleaks v8.30.1, CLI failure redaction, and independent Terra/Spark reviews pass. All PR contexts and the exact merge-commit CI/Security/Pages runs passed; live Pages contains the merged miner-companion, Stratum/wRPC, privacy, and reward-boundary wording. GH-13 is accepted.
Latest workflow-helper note: `scripts/autodidactic.py` is hardened for padded Markdown table cells and in-progress task completion. `scripts/test_autodidactic.py` is wired into CI and passed locally plus remotely for `9a1ac59`.
Historical pre-GH-4 tooling note follows; its external-only genesis execution boundary is superseded by the current correction immediately below it and by the GH-4 note.
Latest tooling note: `scripts/smoke_silverc_artifacts.py` compiles all 7 current-Silverc fixtures through the pinned upstream `silverc` CLI into JSON artifacts and now writes a deterministic `manifest.json` plus optional deterministic `.tar.gz` release archive with source, constructor-args, artifact, and compiled-script SHA-256 hashes plus ABI/state-layout metadata. `scripts/preflight_silverc_deploy.py` validates that bundle and public operator inputs, can emit a Markdown operator runbook with contract hashes and safety rules via `--runbook-out`, and confirms current upstream `silverc` exposes no network deploy command. `scripts/build_silverc_deploy_requests.py` emits per-contract public deploy requests for an approved external orchestrator, rejects credentialed RPC URLs, and does not sign, assemble, broadcast, deploy, or update status files. `scripts/verify_silverc_deploy_requests.py` independently verifies the request-set hash, every per-contract request hash, manifest-bound source/constructor/artifact/script hashes, constructor args, order, safety flags, and secret-field rejection before handoff. `scripts/build_silverc_deploy_operator_procedure.py` converts the verified request set into a public deploy checklist and required result-evidence contract without accepting keys, raw transactions, signing material, deployment, or status writes. `scripts/build_silverc_operator_receipts.py` converts public external deploy-orchestrator results into canonical `operator_record` receipts, binds every result to the verified request hash, rejects secret-like and raw/serialized transaction fields, and immediately re-validates the generated receipts. `scripts/verify_silverc_deploy_receipts.py` validates public deployment receipt records against the release bundle, rejects secret-like and raw/serialized transaction fields, and separates synthetic `ci_fixture` receipts from real `operator_record` evidence before any status update. `scripts/stage_silverc_deployment_status.py` stages a manual status-update draft only from verified `operator_record` receipts and rejects CI fixtures without writing `memory/STATUS.md`. `scripts/build_silverc_operator_handoff.py` packages the release archive, deploy preflight, verified deploy requests, deploy operator procedure, optional imported operator receipts via `--orchestrator-results`, receipt checks, metrics report preflight, unsigned oracle tx request, optional external oracle operator procedure, optional verified external-operator capability record via `--operator-capability`, optional verified oracle tx result via `--metrics-tx-result`, and optional oracle status draft into a public handoff directory while preserving real blocker status. `scripts/verify_external_operator_capability.py` binds a public capability record to the deploy and optional metrics-oracle operator procedures, checks request/tx hashes and result-evidence types, and rejects secret-like fields, raw/serialized transaction fields, repository-side signing, deployment, broadcast, and status writes. `scripts/audit_silverc_release_readiness.py` validates generated public handoff packages, required files including deploy operator procedure, external-operator capability files when present, and oracle status draft files, included-file consistency, component statuses, safety flags, and JSON secret/raw-transaction hygiene; it emits `ROLLOUT_BLOCKED` until real external evidence exists and makes `--require-ready` fail while blockers remain. `scripts/preflight_metrics_oracle_report.py` validates public GovernanceAutoTuning `reportMetrics` payloads, emits JSON/Markdown operator handoff, and rejects secret-like fields. `scripts/build_metrics_oracle_tx_request.py` binds a validated report to the GovernanceAutoTuning artifact hashes as an unsigned request for an external transaction assembler/signer; local and CI blocked/ready/negative checks pass. `scripts/build_metrics_oracle_operator_procedure.py` turns a signer-ready request into a public external operator checklist and required-result evidence contract without accepting keys, raw transactions, signing material, assembly, broadcast, deploy, or status writes. `scripts/verify_metrics_oracle_tx_result.py` verifies public confirmed metrics-oracle transaction records against the request and release bundle, rejects signing material and raw/serialized transaction payloads, and does not sign, assemble, broadcast, deploy, or update status files. `scripts/stage_metrics_oracle_status.py` emits a manual oracle status-update draft from a signer-ready request plus verified public tx result, rejects blocked requests/secrets/raw transactions, and does not write status files. Chain transaction assembly, signing, and broadcast remain outside this repo. GitHub workflow action refs were updated to `actions/checkout@v7`, `actions/setup-python@v6`, and `gitleaks/gitleaks-action@v3`. Real on-chain deploy/orchestration remains open.
Current execution-boundary correction: the preceding tooling note records the pre-GH-4 public handoff boundary. `prometheus-silverc-deployer` now performs keyless genesis transaction assembly, full verification, broadcast, and observation; only the private BIP340 digest signature remains external. The Python request/procedure/capability builders remain public-data-only and their false safety flags describe those builders, not the Rust operator.
Current GH-25 correction: the repository operator now also owns the value-preserving `GovernanceAutoTuningState.reportMetrics` transition. A closed canonical-hash transition spec binds the exact predecessor state/outpoint/covenant, source hash, pinned Silverc commit, public metrics request, and separate P2PK fee-sponsor UTXO. Output 0 preserves the complete covenant amount and compiles the successor state; input 1 alone funds the bounded fee and change. The operator derives two `SIG_HASH_ALL` digests, accepts only canonical public oracle/sponsor signature files, verifies both BIP340 signatures and every covenant/P2PK input, commits compute plus contextual storage mass, revalidates both live UTXOs before broadcast, requires exact signing-request-hash acknowledgement, persists an exclusive intent journal, forbids ambiguous automatic resubmission, and observes the exact successor UTXO. All output paths are collision-checked. Forty-nine deployer tests pass, including eleven focused metrics-transition tests; workspace fmt/clippy/tests, Python/Memory/YAML checks, 55 pinned upstream Silverc tests, the full local Silverc CI job, and an independent Terra review pass after its stale-HANDOFF finding was fixed. PR #26 merged normally as exact main `072f04a`; exact-main CI/Security/Pages and the live Whitepaper verification pass. No private key, wallet file, signature, raw transaction, or real broadcast was accessed.
Latest hardening note: public release-hardening evidence verification now gates handoff/readiness before any rollout-ready claim. `scripts/verify_release_hardening_evidence.py` validates successful Prometheus CI, Security Audit, Pages deployment, protected-branch controls, rollback documentation, public Pages verification, and release-note requirements for the exact release commit; it rejects secret-like and raw/serialized transaction fields and does not query GitHub, accept credentials, change repository settings, assemble, sign, broadcast, deploy, or update status files. `scripts/build_silverc_operator_handoff.py` accepts `--release-hardening-evidence`; `scripts/audit_silverc_release_readiness.py` requires and safety-validates the release-hardening summary before `ROLLOUT_READY`. Local py_compile, CI YAML parse, Autodidactic regression, Memory Integrity, `git diff --check`, release-hardening verifier smoke, hardening-aware operator handoff/release-readiness smoke, Prometheus CI, Security Audit, and live Pages verification passed for `40bb9a0`.
Latest public-docs note: README, `WHITEPAPER.md`, `whitepaper.html`, `docs/roadmap.md`, `modules/contracts/silverc/README.md`, and `llms.txt` were refreshed to reflect post-Toccata deployment gating, verified current-Silverc H-001/Validator/Guardian/RuleStorage/CommunityDonations/DevIncentivePool/GovernanceAutoTuning runtime gates, public deploy operator procedure, public receipt-evidence verification, public external-operator capability verification, public oracle tx-result/tx-evidence/status-draft staging, target-only PROM-RULES asset orchestration, and the no-Kasplex-reputation rule.
Current GH-1 note: PR https://github.com/NeaBouli/prometheus-/pull/2 merged normally as `9d74c0c` without an admin bypass. The deploy procedure now requires external capability records to attest transaction version 1, `pay_to_script_hash_script` over the compiled contract script, official covenant-ID derivation from the funding outpoint and unbound outputs, and funding-input binding after ID derivation. Main runs passed: Prometheus CI https://github.com/NeaBouli/prometheus-/actions/runs/29184186551, Security Audit https://github.com/NeaBouli/prometheus-/actions/runs/29184186538, and Pages https://github.com/NeaBouli/prometheus-/actions/runs/29184186085.
Current GH-4 note: `modules/silverc-deployer` implements the repository-owned keyless genesis path with official pinned `rusty-kaspa` v2.0.1 APIs. It builds transaction version 1 with compute budget 10 and exact contextual `storage_mass`, derives the official covenant ID, applies the funding-input binding after derivation, validates the exact live unspent funding UTXO during preflight and immediately before broadcast, exports only the 32-byte `SIG_HASH_ALL` digest, verifies an external BIP340 signature plus the complete transaction, enforces minimum/maximum fee bounds, and requires exact signing-request hash acknowledgement. Before submission it acquires an OS-managed process lock and exclusively persists/syncs a public intent journal. The journal changes to `submission_in_progress` immediately before the first RPC submission; every later run may only reconcile the known transaction ID against the covenant UTXO and mempool and fails closed when node visibility is ambiguous, so automatic resubmission is forbidden. All wRPC requests have 20-second deadlines, Silverc artifacts reject secret-like fields, and observation rebuilds and verifies the full source/signature handoff before querying chain evidence. The CLI accepts no private key, seed, wallet, keystore, password, or raw transaction. Twenty-seven unit/security tests include fixed public interoperability values, secret-boundary and journal-recovery coverage, and a file-based Python-request/Rust-operator signing handoff. Deploy-request safety fields are explicitly scoped as `deploy_request_builder_only`. PR #5 merged without admin bypass as `ea67b93b155afcf822821304593ab0fe9f815492`; issue #4 closed, and main Prometheus CI `29404986657`, Security Audit `29404986665`, and Pages `29404985747` passed. GH-4 software/CI is complete. Real testnet-10 funding/signatures/receipts, independent public chain evidence, the metrics-oracle transaction, and exact-commit release evidence remain open. Official PSKT/PSKB is deliberately not used because audited v2.0.1/current code creates legacy sigop-count commitments for v1 inputs instead of required compute-budget commitments.
Current GH-7 note: the exact public target `kaspa-resolver://public` resolves through the pinned official `rusty-kaspa` resolver with mandatory TLS and testnet-10-only enforcement. The operator independently validates the resolved endpoint as credential-free `wss://` before any node RPC. The funding-free `probe` command validates network identity, sync, UTXO index, and Toccata activation and records the resolved endpoint; it does not accept funding, signing material, or broadcast. Python builders/verifiers share network-aware target validation and reject resolver use outside testnet, HTTP(S), credentials, queries, fragments, resolver lookalikes, and secret-like text. Rust rejects non-testnet-10 resolver requests before signing-request generation. A final live read-only probe on 2026-07-15 confirmed `rusty-kaspa 2.0.1`, sync, UTXO index, and virtual DAA `517522160` above activation `467579632`. The deterministic seven-contract resolver request set independently verifies as `f9b4838d116ff931ec5fd02ed3e119b1570b62c6836684e4d822c73166e82e2d`. All 30 operator tests, 135 workspace tests, warning-free workspace Clippy, Python/Memory/CI syntax checks, checksum-verified Actionlint, and an independent final review pass; two intentional live tests remain ignored. PR https://github.com/NeaBouli/prometheus-/pull/8 merged normally as `288ea18`; main CI, Security Audit, and Pages pass. The official resolver is best-effort infrastructure and the probe is not funding or chain-deployment evidence. GH-7 software/CI is complete; funded signing/receipt/evidence gates continue in issue https://github.com/NeaBouli/prometheus-/issues/9.
Current GH-9 note: PR #11 merged two closed deployment profiles bound to the exact deterministic release manifest. `full` retains all seven release fixtures and the public metrics-oracle key. `testnet-10-validator-staking-h001` selects only `ValidatorStakingH001`, requires exact `kaspa-resolver://public`, forbids the oracle key, and cannot promote full or metrics readiness. From clean exact main `205e1ca`, all seven artifacts, the one-request canary set, funding spec, live preflight, and schema-v2 request were rebuilt outside Git under owner-only `/Users/gio/Desktop/repos/prometheus-handoffs/205e1ca`. The public funding output remained unspent/non-coinbase; the resolver reached a synced, UTXO-indexed `rusty-kaspa 2.0.1` node at virtual DAA `517950805`, above activation `467579632`. Request `c0cad33f23acfee4114092e0211dd642cb97c44891cc8f8826f4656f406f42fa`, signing-request hash `6b8e65065ca5ae2ca561ddd3fcb9659c384496fd31db32c137fcc9d811fa5323`, sighash `174ccbe80d1d37e62d2bbabfbfba48245372df2bcf9e6724ac79ebc16b4e0bcd`, unsigned transaction ID `c85fd1e79607370ff63faabbc3158e011158d2bde1af40d4eecd642189d8c22f`, and covenant ID `8cdb49adc2511ed5fa11f71317b66f203f37ce376a2603cd9b118236c1f8219f` remain byte-identical across two new builds and to the earlier `9477fab` baseline. The complete 1.27-MB public handoff passed Gitleaks and 0700/0600 mode checks. No wallet, private key, signature, raw transaction, or broadcast was accessed or produced. Remaining canary gates are an explicitly approved external BIP340 signature response, full operator verification, separately approved one-shot broadcast, confirmation, receipt, and independent public evidence.
Current GH-17 note: PR #18 merged the signed-shape fee/mass hardening normally as exact main commit `9477fabb8a9abb41e0ee82f7e240a99436452d2c`. Signing-request schema v2 models the final 66-byte Schnorr script, binds every relevant mass and pinned fee floor, rejects unknown fields and underpriced transactions, and passes 35 focused tests. PR CI, CodeRabbit review, exact-main Prometheus CI, Security Audit, and Pages all pass. The pre-merge candidate was discarded; only the exact-main GH-9 handoff above is current.
Current GH-9 signature-import hardening note: PR #23 merged `import-signature` as exact main `f79150d77ebbf8c71ec8051dc22c7a126d4f38c0`. It accepts only a public 64-byte BIP340 signature as 128 lowercase hex characters with at most one trailing line ending, derives every response field from the validated schema-v2 request, resolves paths before I/O, rejects output collisions with any input or other output, and writes response/verification files only after BIP340 plus full Kaspa transaction verification. The standard Kaspa wallet `message sign` command is explicitly forbidden for this digest because its personal-message domain hash is incompatible. Thirty-eight focused tests, warning-free Clippy, CLI smoke, workspace tests, all PR contexts, exact-main CI/Security/Pages, live Whitepaper verification, and an independent Terra review pass. No wallet, private material, signature, raw signed transaction, or broadcast was used.
Current CI hardening note: Prometheus CI now declares workflow-level `contents: read` permissions and pins both Rust jobs to toolchain `1.95.0` with explicit `rustfmt` and `clippy` components, matching the locally verified compiler. Fixture CI cannot replace the real funded testnet-10/signature/receipt/public-evidence rollout gate.
Current agent-orchestration note: project-local Codex roles are defined in `AGENTS.md`, `.codex/config.toml`, and `.codex/agents/`. GPT-5.6 Sol remains accountable for architecture, security, integration, and final verification; `spark_worker` uses GPT-5.3-Codex-Spark for bounded low-risk patches; `terra_analyst` uses GPT-5.6-Terra read-only for broad scans and distilled analysis. Fan-out is capped at three threads and one delegation level. Sol must review every delegated diff and run the complete relevant checks. A strict-config live delegation smoke on 2026-07-15 returned `SPARK_AGENT_OK`; all three configured model slugs are present in the local Codex catalog.
Current GitHub governance: `main` requires pull requests, strict up-to-date branches, linear history, resolved conversations, and nine successful CI/Security contexts. Admin enforcement is enabled; force pushes and branch deletion are disabled. Because `NeaBouli` is currently the repository's only collaborator and GitHub forbids self-approval, the formal approving-review count is zero in solo-maintainer mode. Increase it to one when a second collaborator is added.

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
- Do not claim Sprint 9/Mainnet rollout until a real funded testnet-10 run through the keyless genesis operator, external signatures, confirmed `operator_record` receipts, independent node/explorer evidence, a confirmed externally signed keyless metrics transition plus successor evidence, and release-hardening evidence for the exact rollout commit are proven.

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

Current Codex probe on 2026-07-12:

```text
ssh -o BatchMode=yes -o ConnectTimeout=10 sandbox 'hostname; whoami; ...'
root@204.168.165.143: Permission denied (publickey).
```

Treat direct Sandbox access as currently unavailable from this Codex shell until
the local SSH agent/key state is fixed. Do not add fallback passwords, private
keys, or secret operational notes to this repository.

Compatibility access verified on 2026-07-12:

```text
ssh hub-sandbox 'hostname; whoami'
Sandbox
deploy
```

Server work can continue through `hub-sandbox` without copying or changing key
material. The direct `sandbox` root alias remains unavailable.

Important:

- Compatibility workflow: use `ssh hub-sandbox` as `deploy` through Hetzner while direct root access is unavailable.
- Preferred direct workflow after key repair: use `ssh sandbox` directly.
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
- GPT-5.6 Sol: primary Codex agent; owns architecture, security-sensitive and cross-cutting work, integration, final review, complete verification, and Bridge/Memory consistency.
- `spark_worker` / GPT-5.3-Codex-Spark: bounded low-risk patches, targeted searches, mechanical documentation consistency, and focused tests. It must return ambiguous, architectural, security, crypto, contract, deployment, governance, and tokenomics decisions to Sol.
- `terra_analyst` / GPT-5.6-Terra: read-only broad repository scans, dependency maps, documentation audits, and test/log triage. Sol owns all resulting decisions and edits.
- Claude Code: optional implementer/reviewer through the documented local terminal bridge.

Delegation guardrails:

- Do not delegate trivial work merely to use a cheaper model; every subagent thread consumes additional tokens.
- Delegate only substantial independent context or a clearly isolated patch with explicit files, boundaries, acceptance criteria, required checks, and a concise return format.
- Use at most one writing subagent at a time and never assign the same file concurrently.
- Keep subagent depth at one. Sol waits for results, reviews the actual diff, and runs the complete relevant checks before accepting work.
- Project-local configuration is authoritative: `AGENTS.md`, `.codex/config.toml`, `.codex/agents/spark-worker.toml`, and `.codex/agents/terra-analyst.toml`.

Loop:

```text
Core Dev triggers task
  -> Codex reads bridge + all memory/*.md
  -> Codex checks git status and current diffs
  -> Sol classifies architecture/risk and decides whether delegation is useful
  -> Spark implements a bounded low-risk patch or Terra performs read-only analysis when appropriate
  -> Sol reviews and integrates all delegated results
  -> Sol runs mandatory complete checks
  -> Sol updates memory/bridge where required
  -> Codex commits/pushes only if explicitly asked
  -> Claude audits
  -> Core Dev accepts/rejects
  -> next task
```

Mandatory checks by area:

- Rust: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`
- HTML/static: verify structured data and links where relevant
- Security: do not expose secrets; run targeted grep/gitleaks checks when touching configs/docs
- Contracts: the repository-owned keyless genesis and keyless metrics-transition paths pass on exact-main CI; no Sprint 9 rollout until funded testnet-10 signatures and receipts, independent public node/explorer evidence, confirmed metrics successor evidence, and exact-commit release-hardening evidence are proven
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
| 9 | Contract deploy on Testnet/Mainnet path | IN PROGRESS on GH-9 canary execution. Funding, fee/mass hardening, exact-main CI, and the deterministic schema-v2 request/digest are complete. External BIP340 signing, operator verification, one-shot broadcast, confirmation, receipt, and independent evidence remain. Canary success cannot close Sprint 9. Full rollout remains blocked until the other six state-contract deployments, full-profile receipts/evidence, the signed metrics-oracle transaction, and exact-commit release hardening pass. |
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
- GovernanceAutoTuning current-Silverc port: `GovernanceAutoTuningState.sil` compile/ABI/runtime gates pass for `reportMetrics` and `autoTune`; valid signed metrics reports are accepted, `fp_rate > MAX_FP_RATE` is rejected, high-FP and zero-FP auto-tune paths are accepted, and early tuning is rejected. Public Python report/request/procedure/result/evidence/status tooling remains secret-free. GH-25 adds repository-owned two-input Rust assembly with exact predecessor/successor compilation, preserved covenant value, separate P2PK fee sponsor, dual external BIP340 signatures, complete input execution, live UTXO revalidation, acknowledged journaled broadcast, and exact successor observation. Q-003 software integration is merged and exact-main verified at `072f04a`; real inputs/signatures/confirmation/evidence remain.
- Current-Silverc release-bundle manifest/archive/preflight/deploy-request/status staging: `scripts/smoke_silverc_artifacts.py` compiles `ValidatorStakingH001`, `ValidatorStakingState`, `GuardianReputationState`, `RuleStorageState`, `CommunityDonationsState`, `DevIncentivePoolState`, and `GovernanceAutoTuningState` through the pinned upstream `silverc` CLI and validates non-empty script bytes, compiler version, state layout, expected ABI entries, and deterministic source/artifact/script hashes. It supports `--out-dir` and optional deterministic `--archive` output for operator handoff. `scripts/preflight_silverc_deploy.py` validates archive layout, manifest/source/constructor-args/artifact/script hashes, public operator inputs, and upstream deploy CLI capability. `scripts/build_silverc_deploy_requests.py` emits request-hashed public deploy requests for an external orchestrator and rejects credentialed RPC URLs; `scripts/verify_silverc_deploy_requests.py` independently verifies the request set before handoff. `scripts/build_silverc_deploy_operator_procedure.py` emits the public deploy checklist and required result-evidence contract for verified request sets without keys or raw transactions. `scripts/build_silverc_operator_receipts.py` imports confirmed public external deploy results into verified `operator_record` receipts; `scripts/verify_silverc_deploy_receipt_evidence.py` binds verified operator receipts to public node/explorer evidence; `scripts/verify_external_operator_capability.py` verifies public external-operator capability records against deploy/oracle procedures; `scripts/stage_silverc_deployment_status.py` stages manual status-update drafts from verified `operator_record` receipts only and rejects `ci_fixture` receipts. This proves the available CLI artifact/preflight/request/procedure/capability/receipt-import/evidence/status-staging path only; upstream `silverc` currently has no network deploy command and an approved external orchestrator is still required.
- GH-4 supersedes the pre-operator boundary above: the repository-owned Rust operator now assembles the official transaction-v1 genesis, exports only its 32-byte digest for external BIP340 signing, verifies the returned signature and complete transaction, revalidates the exact live UTXO, broadcasts, and observes the covenant output. Upstream `silverc` itself still has no deploy command; funded testnet-10 signatures and public evidence remain required.
- H-002: unnecessary Mutex around Phi3Model. Fixed in commit `6347b85` according to memory/handover.
- M-001: Guardian YARA generator confidence is heuristic, needs real LLM confidence or validated metric.
- M-002: performance test flaky in debug mode, threshold/release gate needed.
- L-001: deposit ACL review, blocked by contract compiler path.
- L-002 / Q-003: current-Silverc contract gate uses signed metrics `fp_rate` input; public metrics report/request/procedure/result/evidence/status gates plus the keyless Rust transition operator pass exact-main checks. Real public state/sponsor UTXOs, external signatures, confirmation, and independent successor evidence remain.
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

1. Keep the accepted GH-13 miner companion inside its development-only boundary until real Phi-3, ZK, canonical rule distribution, transport/privacy, and resource-enforcement work is independently reviewed.
2. Keep the merged GH-9 profile and its full seven-fixture compatibility path green.
3. Preserve the exact-main H-001 schema-v2 request and verify that any returned signature response acknowledges signing-request hash `6b8e65065ca5ae2ca561ddd3fcb9659c384496fd31db32c137fcc9d811fa5323`.
4. Obtain an explicitly approved external BIP340 signature over only the recorded 32-byte sighash without moving private key material into the repository, then run full operator verification before any one-shot `testnet-10-validator-staking-h001` broadcast. Collect the confirmed `operator_record` receipt plus independent node/explorer evidence without promoting full status.
5. Execute the keyless metrics transition through the repository Rust operator with external oracle/sponsor signatures and verified successor evidence before beta/mainnet governance.
6. Keep commit-reveal bounds and the no-badge/L1-reputation decision unchanged.

If asked to continue project work:

- Start with `memory/MEMO.md`, `memory/AUDIT.md`, `memory/TODO.md`, `memory/CHECKPOINT.md`, and this bridge.
- Check git status first.
- Do not overwrite existing uncommitted changes.
- Use `ssh sandbox` for direct Sandbox access when server work is needed.
- Use `ssh hetzner` only for Hetzner server work or recovery/bridge notes.

---

## 18. One-Line Decision Summary

Prometheus does not need reputation badges; it needs readable, provable Kaspa L1 Guardian reputation. All seven current-Silverc compile/ABI/runtime gates and the repository-owned keyless Toccata-v1 genesis operator pass local and remote CI. GH-17 fee/mass hardening is merged and exact-main verified; GH-9 now has confirmed public funding plus a deterministic exact-main schema-v2 request/digest for its manifest-bound, non-promotable H-001 testnet-10 canary. An explicitly approved external signature, operator verification, one-shot broadcast, canary confirmation, receipt, and public evidence remain. The other contracts, metrics-oracle transaction, and exact-commit hardening still gate full rollout. Direct `ssh sandbox` remains unavailable from this Codex shell; no fallback secret is stored in the repo.
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
