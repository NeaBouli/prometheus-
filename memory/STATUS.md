# PROMETHEUS – MODULE STATUS
# Format: | Module | Status | Progress | Last Update | Audit | Testnet Address |
# Status: PENDING | IN_PROGRESS | DONE | BLOCKED | PENDING_AUDIT | ACCEPTED | REJECTED
# Last Updated: 2026-07-31

---

## CURRENT SPRINT

```
Sprint 9: Post-Toccata deployment and production-protocol gates
Status:   BLOCKED on external H-001 signing/execution evidence
Start:    2026-07-08
Goal:     Complete the non-promotable H-001 canary, then the full state-contract, oracle, ZK, P2P, and release-evidence path.
```

## LOCAL THREATHINT V2 PRIVACY/PROOF PREFLIGHT CANDIDATE (2026-07-26)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260726-006
Worktree: /Users/gio/Desktop/repos/prometheus-v2-proof-binding
Policy: owner-only read-only exact schema pins network, BIP340 approver,
        opaque recipient scope, and nonzero raw-manifest SHA-256
Composition: bind envelope/manifest; derive statement only from envelope;
             require review_required_v1; match trusted nonce and bundle
             commitment; verify canonical short-lived approval in same call
Persistence: none; no SQLite open/create/migration/write; no approval consumption
Receipt: data-only statement/approval/commitment IDs plus manifest/envelope hashes
Evidence: 31 focused preflight cases; 95 combined relevant Python cases;
          282 Guardian pass/3 intentional skips; changed Pylint 10.00;
          full Pylint 9.81; Black; 317 Rust regular + 5 doctests pass with
          2 intentional live ignores; fmt and warning-free Clippy pass
Review: Kimi final review 0 P0/P1/P2; Sol fixed the P3 deep-JSON redaction gap
Boundary: no Groth16 verification, proof/artifact approval, privacy/disclosure
          authority, replay consumption, transport, analyzer, promotion,
          wallet, signing, transaction, chain, reputation, KAS/PROM, slash,
          commit-reveal, or emergency-stop change
Remaining: approved v2 relation/keys/ceremony and real proof verification,
           then final atomic durable acceptance; transport, actionable
           analysis, deployments, signatures, chain evidence, production
Estimates: core 78-82%; complete vision 44-49%; 51-56% remains
```

## GH-4 DEPLOY OPERATOR STATUS

`prometheus-silverc-deployer` is implemented locally on
`main` at merged commit `ea67b93`. The repository now owns official
Toccata-v1 covenant transaction assembly with exact contextual storage mass,
external BIP340 digest-signature verification, exact live funding-UTXO checks
during preflight and immediately before broadcast, hash-acknowledged broadcast,
an exclusive crash-recovery journal, transaction-ID retry reconciliation,
20-second per-request wRPC deadlines, and source-bound covenant-UTXO observation
without accepting private keys or raw transaction files. Twenty-seven Rust
unit/security tests include fixed public interoperability values, secret-field
rejection, journal recovery, and a file-based Python-request/Rust-operator
handoff; warning-free clippy passes. The seven-contract release archive, Python
preflight, request builder/verifier, operator procedure, and capability handoff
pass locally and in main CI. Prometheus CI `29404986657`, Security Audit
`29404986665`, and Pages `29404985747` succeeded. The public Python preflight
reports `deploy_supported: true` through this operator; upstream `silverc`
remains compile-only. Real testnet-10 funding/signatures, confirmed receipts,
independent chain evidence, the metrics-oracle transaction, and exact-commit
release evidence remain rollout blockers.

## GH-7 PUBLIC RESOLVER PROBE STATUS

Merged GH-7 PR #8 adds the exact
`kaspa-resolver://public` target to the public request pipeline and Rust
operator. Resolver mode enforces TLS, is restricted to `testnet-10`, records
the resolved endpoint, and rejects lookalikes, HTTP(S), credentials, query
strings, fragments, and unsupported networks. The funding-free `probe` command
requires a synced UTXO-indexed node above Toccata activation but does not inspect
funding, sign, or broadcast. Local Rust tests increased from 27 to 30; clippy and
Python RPC-target checks pass. A live probe on 2026-07-15 reached
`rusty-kaspa 2.0.1`, confirmed `testnet-10`, sync, UTXO index, and virtual DAA
above activation. PR #8 merged normally as `288ea18`; main Prometheus CI
`29408432584`, Security Audit `29408432511`, and Pages `29408431512` passed.
GH-7 software/CI is complete. Real funding/signing/evidence gates continue in
issue #9.

## GH-9 H-001 CANARY STATUS

PR #11 merged closed deployment profiles as `6213c559508d3322b8660aed308df1a696ac5576`,
bound to the exact release-manifest SHA-256. `full` keeps all seven release
fixtures and requires the public metrics-oracle key.
`testnet-10-validator-staking-h001` selects only `ValidatorStakingH001`,
requires `testnet` plus exact `kaspa-resolver://public`, forbids the oracle key,
and emits non-promotable canary statuses through requests, procedure, receipts,
public evidence, and manual status staging. Local focused checks pass with 32
deployer tests, warning-free Clippy, and an end-to-end Python canary regression.
Main Prometheus CI `29412667386`, Security Audit `29412667410`, and Pages
`29412666483` pass for the exact merge commit, and the live whitepaper exposes
the profile and non-promotable boundary.
The public testnet-10 P2PK outpoint and matching deployer identity are now
confirmed at transaction `24e81339f3656689643ca86e3c53c4c5336e4273bb127d25bdaf328e5da241c7`,
output `0`, for `100100000000` sompi. The official TN10 API reports it accepted,
unspent, and non-coinbase. The accepted public handoff and schema-v2
request/digest were first rebuilt from clean exact main `205e1ca`; a
2026-07-31 refresh from exact main `143a8a0` reproduced the archive, request,
funding spec, and both signing-request builds byte-for-byte. Live preflight
reconfirmed the output unspent/non-coinbase at virtual DAA `531038718` through
a synced, UTXO-indexed `rusty-kaspa 2.0.1` node above Toccata activation. The
real canary still needs an explicitly approved external
BIP340 signature, full operator verification, one-shot broadcast, confirmation,
receipt, and independent chain evidence. Canary success cannot mark the full
seven-fixture rollout, six production-state contracts, or metrics oracle ready.

GH-17 hardens the operator before external signing. The merged implementation
models the final 66-byte Schnorr signature-script shape, binds compute,
transient, storage, normalized non-contextual/overall mass and both pinned fee
floors into signing-request schema v2, and rejects underpriced transactions
before digest export. PR #18, exact-main CI/Security/Pages, 35 focused Rust tests,
the exact funding preflight, and a byte-identical two-pass signing-request build
all pass. No signature or broadcast occurred.

GH-9 signature-import hardening merged through PR #23 as exact main
`f79150d77ebbf8c71ec8051dc22c7a126d4f38c0`. The new `import-signature` command
accepts only a public 64-byte BIP340 signature as canonical lowercase hex,
derives the complete response from the validated schema-v2 request, rejects
normalized input/output path collisions, and writes no output until BIP340 and
the complete Kaspa transaction pass. The runbook explicitly rejects Kaspa
wallet `message sign` because personal-message domain hashing is incompatible
with the transaction digest. Thirty-eight focused tests, warning-free Clippy,
CLI smoke, workspace tests, independent review, all PR contexts, exact-main
Prometheus CI `29449066498`, Security Audit `29449066352`, Pages `29449065192`,
and live Whitepaper verification pass. No signature or broadcast occurred.

## GH-25 KEYLESS METRICS TRANSITION STATUS

PR #26 merged normally as exact main
`072f04a7b6dbdb77970b9d51c6bb13ff79b3ee72`. The repository operator owns
deterministic `GovernanceAutoTuningState.reportMetrics` assembly,
verification, guarded broadcast, and successor observation. The closed
transition spec binds exact predecessor state/outpoint/covenant, pinned source
and compiler, public request, and a separate P2PK fee sponsor. Covenant value
is preserved exactly; the sponsor alone pays the bounded fee. Two external
`SIG_HASH_ALL` BIP340 signatures are required and every covenant/P2PK input is
executed before output or broadcast. Live UTXOs are revalidated, output paths
are collision-checked, and an acknowledged exclusive journal prevents
ambiguous automatic resubmission. Forty-nine deployer tests, full workspace
fmt/clippy/tests, the full local Silverc CI job, 55 pinned upstream tests, and
independent review pass. Exact-main Prometheus CI `29453756167`, Security Audit
`29453756135`, Pages `29453755086`, and live Whitepaper verification pass. No
real signature or broadcast occurred. Real state/sponsor inputs, signatures,
confirmation, successor evidence, and release evidence remain.

Scope-weighted status estimate on 2026-07-23: H-001 canary preparation is about
96% complete; rollout-capable core-network work is about 78-82% complete with
the merged/exact-main-verified GH-63 verifier and GH-74 analyzer-domain adapter;
the complete roadmap vision is about 44-49% complete. These values distinguish
prepared software from real chain operation and are not release guarantees.
Latest verified product/public main
`2ad2c44f37ec15ab2004b83daa5a8891945db1b3` passed Prometheus CI
`29985377659`, Security Audit `29985377455`, and Pages `29985377181`.
The GH-82 design/public exact main
`fceff1d3ae6db0f38c0076bc2c8dc82f34c3d96d` passed CI `29977301070`,
Security `29977301063`, and Pages `29977300539`.
Its documentation closeout exact main
`6659ab18a94f92d006fe24efe5a451d74322d1c6` passed CI `29977755581`,
Security `29977755619`, and Pages `29977755074`.
GH-86 is closed after PR #87 merged normally as exact main
`2bfe5a3cd5df68bd9d17433748c06bb010070fae`. Prometheus CI `29981646898`,
Security Audit `29981646867`, and Pages `29981646320` passed for that exact
SHA.
Issue #77 is closed after PR #79 merged normally. Accepted proof verification remains gated on an independently
approved real Groth16 relation/key/vectors; actionable analysis additionally
requires a reviewed privacy-preserving concrete-observable channel or future
schema rather than fabricated v1 indicators.
GH-82 is closed after PR #83 merged normally. The v2 design boundary is now
public and exact-main verified: v1 `threat_hash` is caller-supplied and not
protocol-derived; the preferred v2 keeps artifact hash and observable
commitment separate. Commitment matching proves canonical-byte consistency
only. GH-86 now has merged/exact-main-verified isolated Rust/Python canonical validators
against 5 valid, 35 invalid-bundle, and 9 invalid-context shared vectors.
Direct unvalidated construction and value-bearing debug/repr output are closed.
Independent re-review reports no remaining blocking/high/medium finding; 257
Rust workspace tests plus two intentional live-network ignores and 179
Guardian Python tests plus three intentional live-model skips pass. The slice
does not enable v2 transport or actionable analysis, so progress estimates
remain unchanged.
GH-90 is closed after PR #91 merged normally as exact main
`e7f34bb438d4d2cee43db9e8c019f05b9ced0f33`: one Rust producer computes a
single `file_sha256` internally from exact caller-supplied bytes plus typed
scope, while Python independently validates the shared vectors. The API has no
path, caller-supplied digest, generic observable, transport, analyzer, proof,
wallet, signing, or chain input. This is deterministic function-boundary
derivation only; external provenance, privacy approval, and proof binding
remain open. Exact-main Prometheus CI `29984477087`, Security Audit
`29984476876`, and Pages `29984476107` passed.
GH-94 is closed after PR #97 merged normally as exact main
`34ab5b7a62b17ef2c9cab672439b77dcf4a66d9c`. One local Rust producer derives
a bounded `byte_pattern` from exact caller-supplied bytes, checked offset,
boolean wildcard mask, and typed scope. It accepts no path or pattern string,
requires 8..=64 positions and at least eight fixed bytes, and always emits
local-only `review_required_v1`. Shared vectors cover fixed, offset/wildcard,
script, and 64-token/minimum-fixed boundaries; Python independently derives and
validates the expected wire. Independent Terra review found no
blocking/high/medium issue, and CodeRabbit's one valid corpus-documentation
ambiguity is fixed. Exact-main Prometheus CI `29989116631`, Security Audit
`29989117912`, and Pages `29989118948` pass. External provenance,
maliciousness, privacy approval, disclosure authorization, transport, and proof
binding remain unproved.
GH-100 is closed after protected PR #101 merged normally as exact main
`83bdfe0e52e9308e28c8f0984a1219f203aa1f74`. The explicitly Unix-only Guardian
sidecar now constructs SIGINT/SIGTERM listeners before
`OperatorOutput::start()` can emit any operator record, and registration errors
fail before readiness. Pre-fix compiled-binary stress reproduced the process
assertion at iteration 24; the patch passed 64/64 stress iterations, ten
process-suite repetitions, local complete suites, and remote Rust Workspace.
Claude Code independently found the Unix lifetime/error handling sound.
Exact-main Prometheus CI `29994190542`, Security Audit `29994190564`, and Pages
`29994189428` pass. No protocol or security invariant changed.
The accepted execution-artifact baseline remains `205e1ca`; exact main
`143a8a0` independently reproduced it on 2026-07-31 after the dependency-security update.

## GH-13 EXPERIMENTAL MINER COMPANION STATUS

Issue #13 adds a bounded Phase-1 integration to the existing Rust client. The
strict, opt-in TOML profile accepts only the light role, Testnet-10, and a
credential-free loopback wRPC endpoint. Preflight is network-free unless the
operator supplies `--connect`; `run` observes BlockDAG health only. Beta/mainnet,
remote endpoints, credential-bearing URLs, scanning, reporting, validator and
honeypot roles, unknown wallet/reward fields, and passive PROM rewards fail
closed. Kaspa Stratum sessions and ASIC firmware remain outside this repository.
Full verification passes: 153 workspace tests with two intentional live ignores,
warning-free workspace Clippy, Rustfmt, Memory/Autodidactic, Pages, Actionlint,
Cargo Audit with no vulnerabilities, staged-diff Gitleaks, and independent
Terra/Spark review. PR #14 merged as `2e4b4ec`; exact-merge Prometheus CI
`29422667384`, Security Audit `29422667792`, Pages `29422666363`, and the live
Whitepaper verification pass. GH-13 is accepted as development-only foundation.

---

## MODULE STATUS TABLE

| Modul                        | Status          | Progress | Last Update | Audit        | Testnet-Adresse |
|------------------------------|-----------------|----------|-------------|--------------|-----------------|
| **DOKUMENTATION**            |                 |          |             |              |                 |
| Whitepaper_v4.docx           | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | -               |
| memory/MEMO.md               | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/TODO.md               | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/STATUS.md             | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/AUDIT.md              | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/SCHEMA.md             | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/API.md                | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/ERRORS.md             | DONE            | 100%     | 2026-03-21  | -            | -               |
| memory/SPRINTS.md            | DONE            | 100%     | 2026-03-21  | -            | -               |
| scripts/autodidactic.py      | ACCEPTED        | 100%     | 2026-07-12  | ACCEPTED     | Regression suite added in `scripts/test_autodidactic.py`; covers memory loading, padded dependency/status table handling, task completion, and blocker detection; Prometheus CI Memory Integrity job runs it |
| scripts/audit_trigger.py     | DONE            | 100%     | 2026-03-21  | -            | -               |
| claude-code-start.sh         | DONE            | 100%     | 2026-03-21  | -            | -               |
| **SPRINT 0 – SETUP**         |                 |          |             |              |                 |
| Testnet-10-Node              | DONE            | 100%     | 2026-03-21  | -            | wrpc://127.0.0.1:17210 |
| Silverscript tooling (silverc/ssc) | IN_PROGRESS | 99%      | 2026-07-16  | -            | Upstream `silverc` builds/tests in CI; all seven current-Silverc compile/ABI/runtime gates, deterministic release/handoff/evidence tooling, and the repository keyless genesis plus value-preserving reportMetrics operators pass exact-main CI; upstream `silverc` remains compile-only while the Rust operator supplies the network path; real signatures/receipts/evidence remain |
| prometheus-silverc-deployer | ACCEPTED | 100% | 2026-07-16 | REMOTE PASS | PR #26 merged as `072f04a`; canonical public-signature import, keyless genesis and reportMetrics assembly/verification/guarded broadcast paths, 49 tests, exact-main CI/Security/Pages, and live Whitepaper pass |
| GovernanceAutoTuning reportMetrics operator | ACCEPTED | 100% | 2026-07-16 | REMOTE PASS | GH-25 software/docs merged as `072f04a`: two-input value-preserving transition, external oracle+sponsor BIP340 signatures, full input execution, live UTXO checks, journaled acknowledged broadcast, successor observation, 11 focused tests, exact-main CI/Security/Pages, and live Whitepaper pass; real operation/evidence remains separately gated |
| ValidatorStakingH001 Canary | IN_PROGRESS | 96% | 2026-07-31 | SIGNING HANDOFF READY | Exact main `143a8a0` reproduced the accepted archive/request/signing request after the dependency-security update and live-revalidated the public unspent/non-coinbase UTXO; external BIP340 signature, operator verification, one-shot broadcast, confirmation, receipt, and independent evidence remain; non-promotable by design |
| GitHub Actions CI/CD         | ACCEPTED        | 100%     | 2026-07-31  | ACCEPTED     | Prometheus CI `30598044239`, Security Audit `30598044233`, and Pages `30598043838` pass on exact main `2d03f739`; current-Silverc runtime, Rust/Python, Memory, HTML, Gitleaks, cargo/pip audit, security summary, and public deployment pass |
| Sprint-1 Pre-Check           | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | V-001, V-002, V-003 alle genehmigt |
| **SPRINT 1 – CONTRACTS**     |                 |          |             |              |                 |
| ValidatorStaking.ss          | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | v1.2: slash ACL, bond return, test patches |
| GuardianReputation.ss        | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | v1.2: registered_at check |
| GovernanceAutoTuning.ss      | ACCEPTED        | 100%     | 2026-07-11  | ACCEPTED     | Legacy `.ss` kept for architecture history; current-Silverc GovernanceAutoTuningState compile/ABI/runtime gates added with signed metrics `fp_rate` input |
| DevIncentivePool.ss          | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | v1.2: whitepaper reward formula; current-Silverc DevIncentivePoolState compile/ABI/runtime gates added 2026-07-11 |
| CommunityDonations.ss        | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | v1.2: no changes needed; current-Silverc CommunityDonationsState compile/ABI/runtime gates added 2026-07-11 |
| RuleStorage.ss               | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | v1.2: time-windowed counter |
| **SPRINT 2 – CLIENT**        |                 |          |             |              |                 |
| client/blockchain/connection.rs | ACCEPTED      | 100%     | 2026-03-21  | ACCEPTED     | 4 tests, PATTERN-003 applied |
| client/blockchain/krc20.rs   | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 6 tests, cache-based pre-Covenant |
| client/security/scanner.rs   | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 10 tests, YARA pattern matching |
| client/miner_companion.rs    | ACCEPTED        | 100%     | 2026-07-16  | REMOTE PASS  | GH-13 opt-in development-only local Testnet-10 wRPC observer; strict secret-safe preflight, no scanning/reporting/rewards/validator/honeypot/Stratum or firmware control; PR #14 and exact-merge CI/Security/Pages pass |
| client/security/heuristic.rs | PENDING         | 0%       | -           | -            | Sprint 2 Phase 2 |
| client/security/quarantine.rs| PENDING         | 0%       | -           | -            | Sprint 2 Phase 2 |
| client/network/p2p.rs        | PENDING         | 0%       | -           | -            | Sprint 2 Phase 2 |
| client/network/zk_proof.rs   | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 7 tests, stub (PATTERN-004) |
| **SPRINT 3 – PHI-3**         |                 |          |             |              |                 |
| client/ai/phi3.rs            | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 8 tests, ONNX stub, PATTERN-010 |
| client/ai/detection.rs       | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 10 tests, YARA+AI combined verdict |
| client/ai/federated.rs       | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 10 tests, Fed-DART stub (Decision #10) |
| **SPRINT 4 – GUARDIAN**      |                 |          |             |              |                 |
| guardian-node/llm_server.py  | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 6 tests (3 need LLM) |
| guardian-node/yara_generator.py | ACCEPTED     | 100%     | 2026-03-21  | ACCEPTED     | 10 tests, PATTERN-011 |
| guardian-node/analyzer.py    | ACCEPTED        | 100%     | 2026-03-21  | ACCEPTED     | 10 tests, full pipeline |
| guardian-node/docker-compose.yml | ACCEPTED    | 100%     | 2026-03-21  | ACCEPTED     | 8B active, 70B commented |
| **SPRINT 5 – VOTING**        |                 |          |             |              |                 |
| validator/voting/commit.rs   | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 10 tests, cross-verified with SS |
| validator/voting/reveal.rs   | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 8 tests, bond validation |
| validator/slashing/mod.rs    | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 11 tests, bit-identical to SS |
| **SPRINT 6 – E2E**           |                 |          |             |              |                 |
| tests/e2e_threat_lifecycle   | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | Full pipeline < 60s |
| tests/performance            | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 6 timing benchmarks |
| tests/security_sybil         | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 500:1 Sybil resistance |
| tests/security_fp_flood      | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | 500 flood blocked |
| **SPRINT 7 – DASHBOARD**     |                 |          |             |              |                 |
| web/audit/index.html         | ACCEPTED        | 100%     | 2026-03-22  | ACCEPTED     | Dark theme, logo path fixed |
| README.md                    | ACCEPTED        | 100%     | 2026-07-16  | REMOTE PASS  | Experimental miner companion boundary and no-passive-reward wording merged in PR #14; exact-merge Pages pass |
| WHITEPAPER.md                | ACCEPTED        | 100%     | 2026-07-16  | REMOTE PASS  | Target architecture separated from current stubs; miner companion, Stratum/wRPC, privacy, and reward boundaries merged and live-verified |

---

## IN_PROGRESS

Currently in progress:
```
All sprints 0-7 ACCEPTED. Feature-complete.
Pre-Hardfork Audit completed 2026-04-02: 0 CRITICAL, 2 HIGH, 2 MEDIUM, 3 LOW.
H-002 (PATTERN-010) FIXED in 6347b85 (Arc<Phi3Model>).
Kaspa Toccata status researched 2026-07-07; Rusty-Kaspa v2.0.0 scheduled mainnet activation at DAA 474,165,565 (~2026-06-30 16:15 UTC).
Sandbox access check: direct `ssh sandbox` currently fails public-key authentication, while `ssh hub-sandbox` succeeds through the existing Hetzner ProxyJump as user `deploy`. The reachable deploy account currently exposes Docker but not `kaspad`, `silverc`, `ssc`, `kaspa-cli`, Node.js, or Cargo in PATH.
Local upstream Silverscript check: `/tmp/prom-silverscript` `cargo test -p silverscript-lang` passed; `silverc --help` works.
Repo H-001 fixture: `modules/contracts/silverc/ValidatorStakingH001.sil` plus `scripts/verify_silverc_h001.py` verifies explicit `vote_byte || byte[8](salt) || byte[8](block_height)` against Rust vectors at pinned Silverscript ref `d25bd3427a093c17327ca3d6b9e1aa5f7688c863`.
Repo ValidatorStaking current-silverc state fixture: `modules/contracts/silverc/ValidatorStakingState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts for `commitVote`, `revealVote`, `slashInvalidReveal`, `requestWithdraw`, and `completeWithdraw`.
Repo ValidatorStaking runtime gate: `scripts/verify_silverc_h001.py` now injects upstream runtime tests for `commitVote`, `revealVote`, `slashInvalidReveal`, `requestWithdraw`, and `completeWithdraw`; valid commit/reveal/slash/request-withdraw/complete-withdraw signature/state transitions are accepted, low bond is rejected, wrong reveal salt is rejected, slash of a valid reveal is rejected, withdrawal with an open commitment is rejected, complete-withdraw before cooldown is rejected, and negative signed deployment inputs are rejected in GitHub Prometheus CI for `b094444`.
Repo GuardianReputation current-silverc state fixture: `modules/contracts/silverc/GuardianReputationState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts and runtime-tests `register`, `proposalAccepted`, and `proposalRejected` without badge, NFT, Kasplex, or staking semantics. Valid guardian/governance signature transitions are accepted, low compute power is rejected, unregistered rejection is rejected, reputation caps at `REPUTATION_MAX`, and the accepted-proposal formula is verified as exact bounded `isqrt(compute_power_gflops) * 100`.
Repo RuleStorage current-silverc state fixture: `modules/contracts/silverc/RuleStorageState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts and runtime-tests `submitProposal`, `voteOnProposal`, `finalizeProposal`, and `deactivateRule`. Valid guardian/validator/governance signature transitions are accepted; low confidence, late vote, zero-vote finalization, and pending-rule deactivation are rejected. The fixture keeps CIDv1 `byte[36]`, `MIN_CONFIDENCE = 8500`, `VALIDATOR_QUORUM = 6700`, and explicit Guardian reputation outcome events without pretending to support legacy maps, KRC20 minting, `msg.sender`, events, or cross-contract calls in current Silverc.
Repo CommunityDonations current-silverc state fixture: `modules/contracts/silverc/CommunityDonationsState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts and runtime-tests `donateKas`, `proposeDisbursement`, `voteDisbursement`, and `executeDisbursement`. Valid donor/proposer/validator/governance signature transitions are accepted; zero donation amount, disbursement amount above pool balance, voting at `voting_end_block`, and execution below `DISBURSEMENT_QUORUM` are rejected. The fixture keeps KAS-denominated pool accounting, `MIN_DONATION_KAS = 1`, `DISBURSEMENT_QUORUM = 10`, and `VALIDATOR_QUORUM = 6700` without pretending to support legacy maps, strings, `tx.value`, direct KAS transfer, or cross-contract validator lookups in current Silverc.
Repo DevIncentivePool current-silverc state fixture: `modules/contracts/silverc/DevIncentivePoolState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts and runtime-tests `proposeGrant`, `voteGrant`, and `executeGrant`. Valid proposer/validator execution transitions are accepted; amount above `MAX_GRANT_PROM`, voting at `voting_end_block`, execution below `QUORUM_VOTES`, and execution below `VALIDATOR_QUORUM` are rejected. The fixture keeps PROM-denominated grant pool accounting without introducing PROM staking or pretending to support legacy maps, strings, `msg.sender`, direct PROM transfer, or cross-contract validator lookups in current Silverc. Legacy `deposit()` ACL remains a deployment/orchestration decision once emission authority is finalized.
Repo GovernanceAutoTuning current-silverc state fixture: `modules/contracts/silverc/GovernanceAutoTuningState.sil` compiles against the same pinned upstream `silverc`; the verifier builds covenant sigscripts and runtime-tests `reportMetrics` and `autoTune`. Valid signed metrics-oracle reports are accepted; `fp_rate > MAX_FP_RATE` is rejected; deterministic weekly tuning accepts high-FP and zero-FP paths; early tuning before `TUNING_INTERVAL_BLOCKS` is rejected. Q-003 is resolved in the current-Silverc contract path as signed metrics input. Public Python report/request/procedure/result/evidence/status builders remain keyless metadata tools. The Rust operator now builds the exact two-input state transition in memory, preserves covenant value, uses a separate bounded-fee P2PK sponsor, exports oracle and sponsor sighashes, verifies both external BIP340 signatures plus all inputs, revalidates both live UTXOs, journals exact-hash-acknowledged broadcast, and observes the exact successor. Real public inputs, signatures, broadcast, confirmation, and independent evidence remain open.
Repo current-Silverc release-bundle smoke/preflight: `scripts/smoke_silverc_artifacts.py` compiles all 7 current-Silverc fixtures through pinned upstream `silverc` and validates non-empty script bytes, compiler version, state layout, and expected ABI entries. It writes generated JSON artifacts plus `manifest.json` with source, constructor-args, artifact, and compiled-script SHA-256 hashes, and can emit a deterministic `.tar.gz` archive via `--archive`. `scripts/preflight_silverc_deploy.py` validates archive layout, manifest/source/constructor-args/artifact/script hashes, public operator inputs, upstream deploy CLI capability, and the workspace-registered repository operator without accepting secrets or deploying; it can also emit a Markdown operator runbook via `--runbook-out`. A fresh seven-contract archive/preflight/request/procedure integration passed on 2026-07-15; preflight reports `deploy_supported: true` through `prometheus-silverc-deployer` while separately recording that upstream `silverc` has no network deploy command.
Repo current-Silverc keyless genesis request set: `scripts/build_silverc_deploy_requests.py` emits one public deploy-request JSON per current-Silverc contract plus a request-set summary/runbook for the repository genesis operator and external signer boundary. Requests are bound to the release-bundle manifest by source, constructor-args, artifact, and script hashes. The builder rejects RPC URLs with embedded credentials and does not accept keys, sign, assemble chain transactions, broadcast, deploy, or update status files. `scripts/verify_silverc_deploy_requests.py` independently verifies request-set/per-contract hashes, manifest binding, constructor args, fixture order, safety flags, and secret-field rejection before handoff. Current statuses are `READY_FOR_KEYLESS_GENESIS_OPERATOR` and `REQUESTS_READY_FOR_KEYLESS_GENESIS_OPERATOR`.
Repo current-Silverc deploy operator procedure: `scripts/build_silverc_deploy_operator_procedure.py` converts the verified deploy request set into a public keyless deploy checklist and required result-evidence contract. It separates in-memory repository assembly/verification/broadcast from external digest signing and the public evidence/status path. It publishes the official covenant-genesis profile: transaction version 1, funding-input compute budget 10, contextual storage mass, `kaspa_txscript::pay_to_script_hash_script` over the compiled contract script, `kaspa_consensus_core::hashing::covenant_id` over the funding outpoint and unbound genesis outputs, and funding-input binding after ID derivation. `scripts/verify_external_operator_capability.py` requires an exact capability attestation to this profile. PR #2 merged normally as `9d74c0c`; Prometheus CI `29184186551`, Security Audit `29184186538`, and Pages `29184186085` passed on `main`. The Python builders/verifiers accept no keys or raw transactions and perform no signing, deployment, broadcast, or status writes; those safety flags do not describe the Rust execution operator.
Repo current-Silverc public orchestrator-result receipt import: `scripts/build_silverc_operator_receipts.py` converts confirmed public external deploy results into canonical `operator_record` receipts. It validates the release bundle, re-validates the deploy request set, checks every result against the verified request hash, rejects secret-like and raw/serialized transaction fields, writes receipts, and immediately re-validates them with the deployment receipt verifier. It does not accept keys, sign, assemble chain transactions, broadcast, deploy, or update status files. `scripts/build_silverc_operator_handoff.py` can include this path via `--orchestrator-results`.
Repo current-Silverc deployment receipt verifier: `scripts/verify_silverc_deploy_receipts.py` validates public deployment receipt JSON against the release-bundle manifest, contract order, source/constructor/artifact/script hashes, public deploy IDs, 32-byte tx/block hashes, confirmations, DAA score, and UTC timestamps. It rejects secret-like and raw/serialized transaction fields and does not accept keys, sign, broadcast, deploy, or update status files. `modules/contracts/silverc/deploy-receipts.sample.json` is a synthetic `ci_fixture` for CI only; real status updates require verified `operator_record` receipts and `--require-operator-record`.
Repo current-Silverc public receipt-evidence verifier: `scripts/verify_silverc_deploy_receipt_evidence.py` validates public node/explorer evidence snapshots against verified `operator_record` deployment receipts. It binds the evidence to the receipts SHA-256, release-bundle metadata, one confirmed observation per contract, deploy transaction IDs, block hashes, and confirmation counts, rejects secret-like plus raw/serialized transaction fields, and does not query nodes, accept keys, sign, assemble, broadcast, deploy, or update status files. `scripts/build_silverc_operator_handoff.py` can include this via `--deploy-receipt-evidence`; once real receipts exist, missing public receipt evidence remains a blocker.
Repo current-Silverc deployment status staging guard: `scripts/stage_silverc_deployment_status.py` validates `operator_record` receipts against the release bundle and emits a manual JSON/Markdown status-update draft only after receipt verification passes. It rejects `ci_fixture` receipts, does not update `memory/STATUS.md`, and does not accept keys, sign, broadcast, assemble transactions, or deploy.
Repo current-Silverc operator handoff package: `scripts/build_silverc_operator_handoff.py` builds a public handoff directory from a release archive, deploy preflight, verified keyless genesis request set and operation procedure, optional public operator-result receipt import, CI fixture receipt verification, optional real operator receipt verification, optional public receipt-evidence verification, metrics report preflight, unsigned metrics-oracle tx request, optional keyless metrics-operation procedure, optional verified operator capability record, optional verified oracle tx result, optional oracle status draft, and optional public release-hardening evidence. It emits `HANDOFF.md` and `operator-handoff-summary.json`, keeps status `HANDOFF_BLOCKED` until real funded signatures/receipts/public evidence/instance IDs/release-hardening evidence exist, and does not accept private keys or raw transactions or update status files; the generated Handoff directs real metrics assembly/verification/broadcast through the Rust operator.
Repo current-Silverc release-readiness audit: `scripts/audit_silverc_release_readiness.py` validates generated public operator handoff packages before any rollout claim. It checks required files, included-file consistency, handoff/component statuses, optional public receipt-evidence files, optional external-operator capability files, optional release-hardening evidence files, safety flags, and JSON secret/raw-transaction hygiene; it emits `ROLLOUT_BLOCKED` while real deploy/orchestration, external oracle-operation evidence, or release-hardening evidence is missing, and `--require-ready` fails until the blockers are cleared. It does not accept keys, raw transactions, sign, assemble, broadcast, deploy, or update status files.
Repo current-Silverc public release-hardening evidence verifier: `scripts/verify_release_hardening_evidence.py` validates a public snapshot of Prometheus CI, Security Audit, Pages deployment, protected-branch controls, rollback documentation, public Pages verification, and release-note requirements for the exact release commit. It rejects secret-like and raw/serialized transaction fields, does not query GitHub or change repository settings, and is wired into the operator handoff/readiness path as a remaining rollout gate.
Signed-int boundary decision: current upstream Silverc entrypoint `int` values are deployable only in the nonnegative signed range `0..=i64::MAX`; Rust retains raw `u64` H-001 vectors for byte compatibility and uses `build_silverc_checked` / `validate_silverc_commitment_bounds` for deployment calls.
Rusty-Kaspa workspace dependencies pinned to `v2.0.1`; `cargo audit` now reports no vulnerabilities, only allowed warnings.
GitHub Security Audit workflow re-enabled and dependency audits now fail on findings instead of using `|| true`; after `c673766`, Dependency Audit was hardened with explicit job/step timeouts and split cargo-audit install/run steps. GH-30 extends explicit job-level runtime bounds to every required CI/Security context and pins `cargo-audit 0.22.2`, `pip-audit 2.10.1`, Rust 1.95.0, and Python 3.11 without renaming protected contexts. PR #31 merged as `71e5783`; exact-main Prometheus CI `29457601210`, Security Audit `29457601183`, and Pages `29457600490` passed, including the jointly pinned Dependency Audit in 2m54s and Current Silverc Runtime in 2m35s.
Current remote verification baseline: exact product/public main `bfde0249851af2a11ff9f48b854d61595b8b72ea` passed Prometheus CI `30598666699`, Security Audit `30598666673`, and Pages `30598666135`. All required contexts are bounded and green through the `ruint 1.20.0` security remediation and merged GH-9 public readiness record. The embedded 2026-07-31 read-only H-001 refresh from `143a8a0` reproduced the accepted `205e1ca` archive/request/signing request and revalidated the live funding output. Real two-host Guardian operation, production v2 relation/artifact approval, independent cryptographic/privacy review, v2 transport, semantic/actionable analysis, and H-001 execution gates remain open.
Remote verification baseline: Prometheus CI `29456156122` attempt 2, Security Audit `29456155263` attempt 2, and Pages `29456154432` passed for exact operational main `3ba90a9` on 2026-07-16. The first CI/Security attempts were cancelled after remaining in progress in runtime/dependency paths and then passed unchanged on the same SHA. Exact public-status main `e9a970a` passed Prometheus CI `29455597727`, Security Audit `29455597677`, and Pages `29455597066`; live GitHub Pages exposes the `205e1ca` handoff and unchanged rollout gates. Earlier exact artifact baseline `205e1ca` passed Prometheus CI `29454591518`, Security Audit `29454591555`, and Pages `29454590793`. Earlier GH-9 profile CI `29412667386`, Security Audit `29412667410`, and Pages `29412666483` passed for `6213c559`. The prior official SilverScript covenant-genesis capability baseline `9d74c0c` passed on 2026-07-12. The prior `40bb9a0` baseline passed after adding public release-hardening evidence verification; live GitHub Pages contains both release-hardening and genesis-capability wording. The prior `48a6743` baseline passed after adding public oracle tx-evidence verification. The prior `9a1ac59` baseline passed after recording the Autodidactic workflow-helper regression suite CI run. The prior `4816444` baseline passed after adding the Autodidactic workflow-helper regression suite to CI. The prior `ffbad55` baseline passed after the public receipt-evidence verifier documentation follow-up. The prior `4d7a6b8` baseline passed after adding public node/explorer deployment receipt-evidence verification. The prior `181cde2` baseline passed after adding raw/serialized transaction field rejection to public deploy-result import and deployment receipt verification. The prior `6cc000c` baseline passed after adding public external-operator capability verification. The prior `3d02326` baseline passed after adding public oracle status-draft staging. The prior `a86c1b5` baseline passed after adding the public deploy operator procedure gate for verified Silverc deploy request sets. The prior `442853f` baseline passed after public external oracle operator procedure coverage for signer-ready metrics tx requests. The prior `8bf6a14` baseline passed after public release-readiness audit coverage for generated handoff packages. The prior `fa719fc` baseline passed after public oracle tx-result verification, generated operator receipt verification/status staging, operator handoff import mode, and public result handoff mode; the interim `119fa89` CI failure was workflow-only missing `hashlib` import in the metrics-oracle tx-result fixture block and is fixed by `fa719fc`.
GitHub branch governance: `main` requires pull requests, strict up-to-date branches, linear history, resolved conversations, and ten successful CI/Security contexts, including `Rust Performance`. Admin enforcement is enabled; force pushes and deletion are disabled. Solo-maintainer mode uses zero formal approvals because only one collaborator exists and self-approval is impossible; raise the count to one when a second collaborator is added.
Public docs refreshed by 2026-07-31: README, WHITEPAPER.md, whitepaper.html, docs/roadmap.md, roadmap.html, index.html, modules/contracts/silverc/README.md, and llms.txt state deployment-gated post-Toccata status, verified seven-contract runtime gates, the repository-owned keyless genesis execution boundary, the exact-main `143a8a0` H-001 readiness refresh, public request/receipt/evidence/status guards, metrics-oracle and exact-commit release gates, target-only PROM-RULES asset orchestration, and no Kasplex dependency for Guardian reputation. Expired June-September launch promises are replaced by readiness gates.
Rust client runtime gate added: `PROMETHEUS_RUNTIME=beta|mainnet|production|prod` rejects ZK/Phi-3/KRC-20/Fed-DART stubs; development mode remains testable.
Rollback tag: pre-session-20260413 → 6347b85
```

## BLOCKED

Sprint 9 remains blocked until the already funded H-001 request receives its explicitly approved external Schnorr signature, passes canonical import/full transaction verification, and is separately authorized for one-shot broadcast; confirmation, a public `operator_record` receipt, and independent node/explorer evidence must follow. Full rollout additionally requires the remaining contract deployments, a confirmed externally signed keyless metrics transition with successor evidence, and public release-hardening evidence for the exact rollout commit. GH-25 software/merge verification is complete; real execution/evidence gates remain.

## NEXT ACTIONS (for Claude Code)

```
STARTFLOW — Read in this order:
1. BACKLOG.md → Priorisierte Tasks mit Startflow
2. memory/AUDIT.md (line 337+) → Pre-Hardfork Findings (H-001 open, H-002 fixed)
3. memory/ERRORS.md → 13 known patterns

Priority tasks:
- Sprint 9: run the merged keyless operator against a real funded testnet-10 UTXO and collect confirmed public receipt plus independent node/explorer evidence records
- H-001: keep LE encoding and signed-boundary verification gated in CI
- Oracle: execute the merged/exact-main keyless GovernanceAutoTuning transition operator with real public state/sponsor UTXOs, external oracle/sponsor signatures, confirmed successor evidence, and existing result/evidence/status gates before beta/mainnet governance
- Sprint 10B: GH-33 hybrid routing, GH-36 local 5+ complete-ballot validation, GH-39 local BIP340 authenticated intake, GH-42 direct QUIC/libp2p ballot transport, GH-44 persistent identity plus isolated operated relay/NAT evidence, and GH-48 strict operated Guardian/relay roles are merged/exact-main verified. Public/multi-host operation, broad discovery, trusted membership/key assignment, Sybil resistance, on-chain attestation, live model wiring/calibration, and production evidence remain
- M-001: semantic confidence remains gated on the separately approved live-LLM/privacy design; M-002 has a locally verified GH-131 candidate with a median-sample debug smoke gate plus strict optimized CI gate, while protected CI and exact-main evidence remain
```

## TESTNET CONTRACT ADDRESSES

```
(to be filled only from confirmed operator receipts)
ValidatorStaking H-001 canary: TBD
ValidatorStaking:              TBD
GuardianReputation:            TBD
GovernanceAutoTuning:          TBD
DevIncentivePool:              TBD
CommunityDonations:            TBD
RuleStorage:                   TBD

All seven release fixtures pass their documented compile/ABI/runtime gates;
those gates are readiness evidence and must not be presented as deployed addresses.
```

## GUARDIAN HYBRID ROUTING (GH-33)

```
Status: merged via PR #34 as ce1d213; exact-main CI/Security/Pages green
Primary route: injected LLaMA 3 8B analyzer
Escalation: injected LLaMA 3 70B analyzer when confidence < 0.70
Submission policy: unchanged MIN_CONFIDENCE = 0.85
Safety: threat/rule hash binding, finite [0,1] confidence, strict bool/rule types,
        generic failure notes, no mutable per-request router state
Local evidence: 47 passed, 3 intentionally skipped live-model tests; Black clean;
                Pylint 9.69/10
Remote evidence: Prometheus CI 29459533780; Security Audit 29459533770;
                 Pages 29459533175; live Roadmap/Whitepaper/FAQ markers verified
Not yet proven: live 8B/70B services, calibrated model confidence, P2P transport,
                trusted membership, signed/replay-protected votes, on-chain
                ensemble attestation, production operation
```

## GUARDIAN ENSEMBLE VALIDATION (GH-36)

```
Status: merged/exact-main verified in PR #37 at f8ebaac; issue #36 closed
Candidate: domain-separated canonical JSON binds protocol, threat hash, exact YARA
           bytes/metadata, exact integer-bps source confidence, policy, and 8B artifact
Membership: immutable sorted snapshot, 5+ unique canonical Guardian IDs, explicit
            membership-source digest; source trust itself is not claimed
Ballot: exactly one bound 8B vote per member; missing/duplicate/unknown/malformed,
        wrong snapshot/candidate/model/tier, tie, or below-policy approval fails closed
Decision: strict complete-committee majority; source and every approval >=8500 bps;
          final confidence = min(source, approving votes); negative result has no rule
Local evidence: 96 passed, 3 intentionally skipped Guardian tests; focused ensemble/
                router subset 73 passed; Black clean; CI-scope Pylint 9.87/10;
                focused Pylint 10.00/10; Rust workspace 170 passed/2 ignored
Review: initial medium source-confidence binding and recheck float-rounding findings
        fixed; final independent re-review reports no remaining high/medium finding
Remote evidence: Prometheus CI 29461803530; Security Audit 29461803531;
                 Pages 29461802700; live Roadmap/Whitepaper and README verified
Not yet proven: trusted membership source, signed P2P collection, replay protection,
                Sybil resistance, on-chain ensemble attestation, production operation
```

## AUTHENTICATED GUARDIAN BALLOT INTAKE (GH-39)

```
Status: issue #39 closed; PR #40 merged/exact-main verified at d0f78a9
Session: domain-separated commitment binds candidate, snapshot, network, nonce,
         validity window, and the exact unique Guardian-to-BIP340-key map
Envelope: exact-schema canonical JSON binds complete vote/context/time/nonce;
          malformed, duplicate-field, noncanonical, oversized, cross-context,
          wrong-key, expired, future, and overlong input fails before persistence
Crypto: coincurve 21.0.0 verifies public BIP340 x-only signatures; production code
        exports digest-only signing requests and contains no private-key/signing API
Replay: owner-only SQLite, BEGIN IMMEDIATE, PRIMARY KEY(session_id, guardian_id),
        UNIQUE(session_id, nonce), session-lifetime retention, persistent monotonic
        time watermark, restart/concurrency/clock-rollback fail-closed coverage
Evaluation: persisted canonical envelopes are reverified before the unchanged
            complete-ballot EnsembleVoter receives their domain votes
Local evidence: focused signed-ballot/ensemble suite 70 passed; complete Guardian
                suite 117 passed/3 intentional live-model skips; Black clean;
                focused Pylint 10.00/10; CI-scope Pylint 9.93/10; dependency,
                workflow, Memory, HTML, Gitleaks, compile, and diff gates pass;
                Rustfmt/Clippy and 170 workspace tests/2 live ignores pass
Review: independent review found one medium forward-clock/prune/rollback reopening
        path; persistent high-water enforcement plus restart regression closes it;
        final independent re-review reports no blocking/high/medium finding
Remote evidence: Prometheus CI 29464295373; Security Audit 29464295355;
                 Pages 29464294890; live Whitepaper/Roadmap/README verified
Not yet proven: operated peer discovery/NAT traversal, trusted
                membership/key assignment, Sybil resistance, on-chain attestation,
                proposal submission, production signer/model operation
```

## GUARDIAN OPERATED TRANSPORT (GH-44 MERGED)

```text
Status: merged as 27c2edc31; exact-main CI/Security/Pages and live markers pass
Identity: absolute path, effective-user-owned 0700 parent, NOFOLLOW opens,
          owner-readable regular canonical protobuf, atomic same-directory 0600
          creation, fsync, stable PeerId across restart/concurrent creation
Routes: strict bounded IP/UDP/QUIC-v1 direct, relay-circuit, and explicit direct
        AutoNAT server routes; DNS/mDNS, duplicates, mismatched targets, and
        unsafe dial endpoints fail configuration validation
Relay: bounded reservations, circuits, bytes, durations, connections, and peers;
       data-minimal events expose transport metadata only
Local evidence: 21 Guardian P2P crate tests pass; deterministic isolated
                relay/receiver/sender harness proves reservation, relay-only
                ballot/ACK, AutoNAT Public for the direct sender, failed DCUtR
                upgrade with relay fallback, and circuit/connection close
Boundary: PeerId never authorizes Guardian membership. No wallet, chain, contract,
          signature, reputation, KAS/PROM, slash ACL, or commit-reveal change
Not yet proven: public or multi-host operation, broad discovery, trusted
                membership/key assignment, Sybil
                resistance, and on-chain attestation
```

## GUARDIAN OPERATED SIDECAR (GH-48 MERGED)

```text
Status: PR #49 merged as b14d36fc79ddc7e0b407b42cb4a271e29cb1ddea;
        exact-main CI 29481830688, Security 29481830686, and Pages 29481830054 pass
Process: explicit prometheus-guardian-p2p preflight/run/submit CLI with strict
         role-tagged owner-only TOML for guardian and relay roles
IPC: owner-only AF_UNIX submission, exact EOF-bound frames, effective-UID peer
     checks, bounded admission/timeouts, and collector outages mapped to busy
Lifecycle: live listener readiness, data-minimal path-free JSON records,
           SIGINT/SIGTERM admission stop, bounded work drain, terminal status,
           and owned submission-socket cleanup
Local evidence: 33 unit tests plus three separate-process tests pass; relay,
                receiver, sender, submit client, and collector prove exact-byte
                relayed delivery, canonical ACK propagation, clean SIGTERM,
                socket cleanup, and stable transport identities on one host;
                206 workspace Rust tests/2 live ignores, 126 Guardian tests/3
                live-model skips, release/package, lint, Memory, HTML, workflow,
                dependency, staged Gitleaks, and diff gates pass
Review: independent review found one medium trailing-ACK acceptance gap; strict
        EOF validation closes it. Six CodeRabbit follow-ups are fixed, and the
        final independent Terra review reports no actionable finding
Boundary: no wallet, chain, signing, contract, reputation, KAS/PROM, slash ACL,
          commit-reveal, or Guardian authorization behavior changed
Not yet proven: public/multi-host operation, broad discovery, trusted
                membership/key assignment, Sybil resistance, on-chain
                attestation, or production node evidence
```

## GUARDIAN EXPLICIT RELAY BOOTSTRAP (GH-52 MERGED/EXACT-MAIN VERIFIED)

```text
Status: issue #52 closed; PR #53 merged as f2e52beebe5ec7d6a3e6e0e8d36bced8f6f68ac7
Config: relay-only canonical advertise_addresses are distinct from bind
        listeners; wildcard, multicast, DNS/mDNS, port-zero, duplicate,
        malformed, oversized, over-limit, and noncanonical routes fail closed
Output: each configured address emits one path-free bootstrap-route ending in
        the persistent transport PeerId; ready remains false until listeners bind
Local evidence: 38 Guardian P2P unit tests and three process tests; 211
                workspace Rust tests/2 live ignores; locked release build;
                13-file package; workspace Clippy; 126 Python tests/3 skips;
                Black; Pylint 9.95/10; Memory/HTML/audit/diff gates pass
Boundary: advertised routes are operator metadata, not reachability proof or
          Guardian authorization; no wallet, signing, chain, reputation,
          KAS/PROM, slash ACL, or commit-reveal behavior changed
External evidence: ssh sandbox reaches the host but public-key authentication
                   is rejected, so real two-host evidence is not claimed
Remote evidence: Prometheus CI 29644233106, Security Audit 29644233098, and
                 Pages 29644232771 passed for exact main f2e52be
```

## LIGHT CLIENT TO GUARDIAN THREATHINT CORE (GH-55 MERGED/EXACT-MAIN VERIFIED)

```text
Status: issue #55 closed; PR #56 merged as c8a6cb83419d442542257f470af35d76528786bc
Schema: OS-independent canonical JSON v1; exact lowercase hash/nonce, integer
        confidence basis points, explicit proof system, 1..=1024 proof bytes,
        non-zero timestamp, 2048-byte total cap, no unknown/duplicate fields
Client: proof public input must bind the exact threat hash; confidence floors
        conservatively; development stubs fail in beta/mainnet
Transport: independent /prometheus/threat-hint/1.0.0 request/ACK behaviour;
           ballot and hint state remain separate and share global work/stream caps
Sidecar: rejects every hint until a dedicated owner-only real-Groth16 verifier,
         freshness/replay persistence, and bounded analyzer ingress exist
Local evidence: 6 schema tests, 8 client builder tests, 45 Guardian P2P unit
                tests plus 3 process tests, and 229 workspace tests/2 live ignores
Boundary: PeerId is routing metadata only; no wallet, signing, chain, Guardian or
          reporter authorization, reputation, KAS/PROM, slash ACL, or
          commit-reveal behavior changed
Exact main: Prometheus CI 29646732936, Security Audit 29646732941, and Pages
            29646732673 passed; live public markers were verified
```

## GUARDIAN THREATHINT VERIFIER INGRESS (GH-58 EXACT-MAIN VERIFIED)

```text
Merge: PR #60 -> 22bc55a72bf441a2abc0372bc0eb789fb89fbb0b
Rust: separate UnixThreatHintIngress, canonical digest-bound ACK, owner/mode/
      peer-UID checks, bounded framing/timeouts, independent in-flight state
Service: required distinct threat_hint_socket; unavailable boundary maps busy
Python: canonical schema reparse, trusted network/domain verifier context,
        development-stub rejection, freshness plus monotonic replay policy
Durability: accepted means replay identities and one analyzer-outbox job commit
            atomically in SQLite; exact retry is duplicate across restart
Analyzer boundary: outbox retains canonical bytes/digest/network/admission time
                   and does not fabricate indicators absent from the wire
Production gate: no approved Groth16 relation/verifying key/vectors are bundled;
                 default verifier is unavailable and cannot return accepted
Evidence: 12 focused Python tests, 138 full Guardian passes/3 live-model skips,
          53 Guardian P2P tests plus 3 process tests, 240 Rust workspace passes/
          2 live ignores, Rustfmt, warning-free Clippy, Black, and Pylint pass
Exact main: Prometheus CI 29962533693, Security Audit 29962533720, and Pages
            29962533075 passed; GitHub Pages status is built
Unchanged: PeerId authorization, ballots, wallet/signing/chain, reputation,
           KAS/PROM, slash ACL, commit-reveal, and emergency-stop policy
```

## KIP-16 THREATHINT GROTH16 ENGINE (GH-63 MERGED / EXACT-MAIN VERIFIED)

```text
Engine: real BN254/Arkworks Groth16 pairing verification aligned with active
        KIP-16 and pinned rusty-kaspa v2.0.1 compressed serialization
Trust: canonical manifest SHA-256 anchor; canonical VK length/hash/arity;
       owner-aware symlink-free paths/files with before/open/after inode checks
Statement: fixed domain + network + schema + threat hash + confidence +
           indicator type + report nonce + observation time; proof excluded
Encoding: SHA-256 split into two injective unsigned 128-bit BN254 inputs
Service: exact owner-only TOML; unavailable or fully pinned kip16_groth16 mode;
         fixed no-shell subprocess, clean environment, hard timeout
Exit contract: 0 valid, 1 invalid, 2 CLI syntax, 3 unavailable/configuration
Local evidence: 7 focused Rust and 18 focused Python tests; 247 workspace Rust
                passes/2 live ignores; 144 Guardian passes/3 live-model skips;
                locked release builds and 6/14/7-file Cargo packages; format,
                lint, Memory, HTML, Actionlint, and dependency audit pass
Production gate: no approved production relation, VK, proving key, or
                 independent vectors are bundled; default remains busy
Exact main: f4f9df95848d41c82379ef59044d12453b12279c; Prometheus CI
            29968203074, Security 29968203053, and Pages 29968202562 pass
Remaining: independent production artifact ceremony/vectors, reviewed
           analyzer-domain merge, concrete-observable design, and real
           accepted-analysis evidence
```

## THREATHINT V1 ANALYZER ADAPTER (GH-74 MERGED / EXACT-MAIN VERIFIED)

```text
Input: durable VerifiedThreatHintJob from the GH-58 SQLite outbox
Binding: canonical reparse plus SHA-256 digest, exact trusted network,
         groth16_kip16_v1, and original admission-window checks
Domain: frozen VerifiedThreatHint preserves only v1 wire/job fields and has no
        concrete indicator list
Decision: exact confidence 0.0, no YARA rule, should_submit false; LLM and YARA
          generation are not invoked for hash-only v1 claims
Drain: maximum 32 jobs, per-instance serialization, mark-delivered only after
       exact safe result; ordinary per-job failures remain pending while later
       independent v1 jobs can progress; no FIFO acknowledgement is promised
Local evidence: 24 focused analyzer/adapter tests and 158 complete Guardian
                passes with three intentional live-model skips; Black, Ruff,
                and focused Pylint 10.00/10 pass
Exact main: 17d8ceb34b32f5a81104cc3ad19bc7cff4061266; Prometheus CI
            29973290911, Security 29973290913, and Pages 29973290610 pass
Boundary: no approved production proof artifacts, concrete observable channel,
          live-model evidence, proposal submission, or production acceptance
Unchanged: PeerId authorization, wallets/signing/chain, reputation, KAS/PROM,
           slash ACL, commit-reveal, and emergency-stop policy
```

## THREATHINT BOUNDED DRAIN PROGRESS (GH-77 MERGED / EXACT-MAIN VERIFIED)

```text
Problem: one failed leading GH-74 outbox job aborted the whole bounded drain and
         could repeatedly starve later independent v1 jobs
Decision: isolate ordinary adapt, analysis, clock, and delivery failures per job;
          failed jobs stay pending and later safe jobs continue
Report: structurally immutable tuples; each success and failure retains its
        bounded batch index; failures expose only fixed category plus a digest
        validated through full adaptation or None
Privacy: no canonical bytes, paths, analyzer output, or arbitrary exception text
Cancellation: BaseException is not swallowed; cancellation during threaded
              SQLite acknowledgement waits for its durable outcome, then propagates
Ordering: v1 jobs are independent and have no submission side effects; FIFO
          acknowledgement is explicitly not guaranteed
Local evidence: 19 focused adapter tests and 163 complete Guardian passes with
                three intentional live-model skips; Black, scoped Ruff, focused
                Pylint 10.00/10, and clean diff checks pass
Exact main: 4cada95ed2f97c2d0251dd82ef40290b0c664c41; Prometheus CI
            29975041446, Security 29975041416, and Pages 29975040944 pass
```

## MAINNET CONTRACT ADDRESSES (post-verification)

```
(to be filled on launch day)
```

## GH-103 LOCAL LINUX ELF API-IMPORT PRODUCER

```text
Status: merged through protected PR #104 and exact-main/live verified
Input: exact caller-supplied ELF bytes plus one checked import index
Parser: object 0.39.1, read-only ELF features; 16 MiB and 4096 dynamic-symbol
        limits
Derivation: reject unsupported names, byte-sort, deduplicate, checked selection;
            scope fixed internally to linux/elf
Output: exactly one local review_required_v1 api_import bundle
Vectors: SHA-256-bound exact ELF64 bytes; Rust production and independent Python
         ELF parsing agree on close, mmap, and pthread_create
Evidence: 5 focused producer tests, 1 Rust vector test, 30 ThreatHint tests plus
          1 compile-fail doctest, 19 focused Python tests, 182 Guardian tests
          with 3 skips, complete Rust workspace with 2 live-network ignores,
          Rustfmt, warning-free Clippy, Black, and Pylint pass
Review: Claude Code architecture review plus Terra diff review; no unresolved
        blocking/high/medium finding
Exact main: 42d9cd939c635474547d1bac7058f30451c926e7; Prometheus CI
            29999873100, Security Audit 29999873126, and Pages 29999872424 pass
Boundary: no path/import-string/generic builder, transport, analyzer, proof,
          wallet, signing, chain, reputation, KAS/PROM, slash ACL,
          commit-reveal, or emergency-stop change
Remaining: external provenance/privacy approval; other platform/format
           extractors; v2 relation/proof/pairing/transport; actionable analysis and all
           existing rollout gates
```

## GH-107 LOCAL OBSERVABLE APPROVAL VERIFIER

```text
Status: merged through protected PR #108 and exact-main/live verified
Main: fc6f1c9fdcfb74c4858b12ec9265ebd6cee10dfe
Runs: Prometheus CI 30006654048; Security Audit 30006654027;
      Pages 30006653208
Live: raw README and Pages Whitepaper/Roadmap/FAQ/llms markers verified
Input: one canonical approval wire, one exact canonical review_required_v1
       bundle, and separately trusted report nonce, x-only approver key,
       recipient-scope digest, network, and separately trusted current time
       that must never be attacker-controlled
Checks: exact 1024-byte-bounded field order/lowercase hex; fixed purpose;
        inclusive nonzero validity capped at 3600 seconds; exact bundle
        reparsing/commitment; trusted key/scope/network; domain-separated
        BIP340 signature
Output: opaque verified result with deterministic approval ID and signed nonce
Vectors: one public-only shared corpus; no private key or signer ships
Evidence: 15 Rust unit tests, 23 Rust integration tests plus 1 compile-fail
          doctest across prometheus-threat-hint; 27 focused Python
          observable/approval tests; 280 complete workspace Rust passes with
          2 intentional live-network ignores; 190 complete Guardian passes
          with 3 intentional live-model skips; Rustfmt, warning-free workspace
          all-target Clippy, locked release builds, package checks, Black,
          Pylint 9.78/10, Memory/Autodidactic, HTML/JSON-LD, Actionlint,
          Cargo/Python audits, and staged Gitleaks pass
Review: Claude Code suspected coincurve rehashing; inspection of pinned
        coincurve 21.0.0 proves direct message forwarding to
        secp256k1_schnorrsig_verify. Its valid u64-parity/replay-documentation
        recommendations are implemented. Sol fixed Python field-order parity.
        Terra found and then rechecked exact context-type enforcement for a
        subclass bypass plus Python result-authority documentation; no
        unresolved finding remains.
Boundary: authenticates a local statement only; no signing/private key,
          replay persistence, transport, promotion, disclosure, analyzer,
          publication, proof, wallet, chain, reputation, KAS/PROM, slash ACL,
          commit-reveal, or emergency-stop change
Remaining: GH-111 separately closes fixed-policy local consumption; trusted
           authority rotation, recipient-scope assignment, owner-only pairing,
           v2 relation/proof/transport, actionable analysis, and all existing
           rollout gates remain
```

## GH-111 LOCAL DURABLE OBSERVABLE APPROVAL CONSUMPTION

```text
Status: merged through protected PR #112 and exact-main/live verified
Main: 60166bd6d8d3c7d8e88727c2f6d507b206a308ad
Runs: Prometheus CI 30011976919; Security Audit 30011976853;
      Pages 30011975363
Issue: #111 closed
Policy: owner-only exact-schema TOML fixes one network, x-only approver public
        key, opaque recipient-scope digest, and absolute owner-only ledger path
Call path: service accepts canonical approval/bundle bytes plus trusted
           in-process report nonce/current time; it constructs the GH-107
           context itself and accepts no caller-supplied verified object,
           authority key, recipient scope, or network
Persistence: separate SQLite STRICT tables; BEGIN IMMEDIATE; synchronous FULL;
             unique approval ID and (approver key, approval nonce);
             persistent clock high-water; owner-only parent/file, no symlink
Output: data-only local receipt with approval ID, observable commitment, and
        consumption time; no downstream authority
Evidence: 24 focused consumption tests; 32 combined approval tests; 214
          complete Guardian passes with 3 intentional live-model skips;
          280 complete Rust workspace passes with 2 intentional live-network
          ignores; Rustfmt; warning-free all-target Clippy; locked release
          builds; strict 21-file package; Black; full Guardian Pylint 9.78/10;
          Memory/Autodidactic; HTML/public status; workflow YAML/Actionlint;
          Cargo/Python audits; staged Gitleaks; clean staged diff;
          changed production/tests Pylint 10.00/10;
          Spark findings fixed; Terra security review found no finding and its
          constructor-lock, transaction-abort, and corrupt/unknown-ledger
          recommendations pass; exact STRICT table/index shape is validated
          and only real SQLite busy/locked codes are retryable
Boundary: no transport, pairing, promotion, disclosure, analyzer, outbox,
          publication, proof, signing, wallet, chain, reputation, KAS/PROM,
          slash ACL, commit-reveal, or emergency-stop change
Remaining: authority ownership/rotation, scope assignment, privacy
           review, verified hint/bundle/approval pairing, v2 relation/artifacts,
           crash-safe external side effects, actionable analysis, and rollout
```

## GH-114 LOCAL CANONICAL THREATHINT V2 STATEMENT

```text
Status: merged, exact-main verified, and live public markers verified
Issue: #114 closed through protected PR #115
Input: exact canonical statement bytes plus separately trusted local network
Shape: schema 2; separate artifact hash and observable commitment; confidence;
       structural disclosure class; report nonce; positive observed time;
       network
Checks: exact field order and bytes; closed scalar grammar; positive u64
        observed_at; 1024 byte cap; trusted-network equality; one redacted
        failure
Digest: SHA256("prometheus-threat-hint-statement-v2\0" ||
               u32be(canonical_length) || canonical_statement)
Parity: independent Rust/Python parsers consume 8 valid and 20 invalid shared
        exact-byte vectors; every field mutation changes the digest
Evidence: 290 complete Rust workspace tests with 2 intentional live-network
          ignores; 223 complete Guardian tests with 3 intentional live-model
          skips; 2 compile-fail doctests; Rustfmt; warning-free workspace
          all-target Clippy; locked optimized Guardian/proof builds; verified
          24/14/7-file packages; Black; changed-file Pylint 10.00/10; complete
          Guardian Pylint 9.80/10; Memory/Autodidactic; HTML/JSON-LD/public
          status; workflow YAML/Actionlint; Cargo/Python audits; staged
          Gitleaks 8.30.1; clean staged diff
Review: Terra architecture and Spark parity/security review found no initial
        issue; final Terra review found one medium Python valid-shape
        mutation/forged-object gap, fixed by an identity-bound parse snapshot
        and two regressions; re-review reports no blocking/high/medium issue;
        PR #115 final head passed all ten contexts with zero unresolved
        threads; CodeRabbit's four minor wording/regex consistency findings are
        fixed; exact product main 70bb8ab CI/Security/Pages and live markers
        pass;
        Claude Code terminal probe passed but the bounded read-only request
        stopped before repository access on its USD budget
Boundary: no v1 change, relation, proof acceptance, signer, approval pairing,
          persistence, replay authority, transport, analyzer, outbox, wallet,
          chain, reputation, KAS/PROM, slash ACL, commit-reveal, or
          emergency-stop behavior
Remaining: reviewed relation/artifacts, privacy/pairing, transport, actionable
           analysis, and external rollout gates
```

## LOCAL THREATHINT V2 PROOF-BINDING CANDIDATE (2026-07-26)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Branch: feat/local-v2-proof-binding
Worktree: /Users/gio/Desktop/repos/prometheus-v2-proof-binding
Implemented: canonical Rust/Python v2 proof envelope, strict 19-field
             RelationManifest-v2, and one atomic data-only binding
Trust: separately trusted network plus nonzero lowercase raw-manifest SHA-256
Binding: raw hash before parse; canonical reparse; protocol/relation/network/
         domain/public-input closure; two claimed 16-byte digest halves
Evidence: 5 valid/28 invalid shared binding vectors; full Rust workspace
          317 regular tests + 5 doctests pass with 2 intentional live ignores;
          full Guardian 251 pass/3 intentional skips; fmt, all-target Clippy,
          locked release, 27/14/13 packages, Black, Pylint 9.80, dependency
          audits, Memory Integrity, and 6 Autodidactic tests pass
Review: Sol closed exact-envelope Python substitution with a snapshot regression;
        final Kimi read-only review reports no actionable finding
Boundary: no Groth16 verification, source/key loading or approval, ceremony,
          I/O, transport, analyzer, promotion, wallet, chain, reputation,
          KAS/PROM, slash ACL, commit-reveal, or emergency-stop change
Remaining: approved relation source and keys, real proof verification/acceptance,
           owner-only pairing, privacy/promotion, transport, actionable analysis,
           deployments, signatures, chain evidence, and production operation
```

## LOCAL THREATHINT V2 GROTH16 VERIFIER CANDIDATE (2026-07-26)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260726-007
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Loader: one retained canonical manifest plus fixed owner-only
        relation-source.bin and verifying-key.bin siblings
Trust: separately trusted network and nonzero lowercase raw-manifest SHA-256;
       exact source/VK sizes and hashes; canonical compressed BN254 VK
Runtime: no proving-key path or load; no manifest disk reread during verify
Verification: exact canonical v2 envelope/binding; two 16-byte big-endian Fr
              inputs; canonical compressed proof; real Arkworks Groth16 check
CLI: silent verify-v2; exit 0 valid, 1 invalid, 2 syntax, 3 unavailable
Evidence: 16 focused; ThreatProof 44 all-target + 2 doctests; workspace
          333 pass/2 intentional ignores + 5 doctests; Guardian 282 pass/
          3 intentional skips; fmt, warning-free Clippy, optimized build,
          verified 15-file package
Review: Kimi final PASS with no P0/P1/P2/P3; Sol added malformed proof,
        anchor-matched invalid VK, unsafe parent, uppercase/zero anchor cases
Boundary: deterministic test relation/keys/proofs only; no production
          relation/key/ceremony approval, proving-key runtime, approval
          consumption, privacy/disclosure authority, transport, analyzer,
          wallet, signing, transaction, chain, deployment, or rollout evidence
Remaining: independent production artifact/ceremony approval, then one atomic
           verifier-plus-final-consumption acceptance path; transport,
           actionable analysis, deployments, signatures, chain evidence
Estimates: core 79-83%; complete vision 45-50%; 50-55% remains
```

## LOCAL WINDOWS PE API_IMPORT EXACT-MAIN REINTEGRATION (2026-07-29)

```text
Ticket: GIO-20260726-004
Status: In Progress; repository-only, not published
Baseline: origin/main 12a08d4f07f219d0b7892ff962ac9e5f754a263c
Input: exact PE32/PE32+ bytes plus checked import index
Parser/bounds: object 0.39.1 PE support; 16 MiB; 4096 import descriptors;
4096 thunk entries
Behavior: reject malformed/ordinal/grammar-invalid imports; byte-sort and
          deduplicate named functions; fixed windows/pe scope
Output: exactly one review_required_v1 bundle; library names excluded
Initial evidence: Rust producer tests 9/9; focused independent Python parity
                  1/1; Rustfmt check PASS
Remaining in slice: exact-main Kimi review and complete local verification
Boundary: no commit/push/PR/merge/pages/deploy, transport, analyzer, wallet,
          signing, transaction, chain, server, secret, KAS/PROM, reputation,
          slash ACL, commit-reveal, or emergency-stop change
```

## LOCAL WINDOWS PE API_IMPORT EXACT-MAIN CLOSEOUT (2026-07-29)

```text
Status: Local Done; review-ready, not committed or published
Final producer evidence: 11 focused Rust tests plus 1 shared-vector test
Complete Rust: 345 passed, 2 intentional live-network ignores, 5 doctests
Complete Guardian: 742 passed, 3 intentional live-model skips
Build/package: Guardian and Threat-Proof locked release builds PASS;
               ThreatHint verified package 30 files; package set 30/14/15
Quality: Rustfmt, warning-free workspace all-target Clippy, Black 26 files,
         Pylint 9.83/10, Memory Integrity, 6 Autodidactic tests PASS
Docs/CI: 5 HTML, 4 JSON-LD, SEO/infrastructure/public-status, two workflow
         YAML parses, Actionlint 1.7.12 and diff checks PASS
Security: Cargo Audit 0 vulnerabilities/8 allowed warnings; Pip Audit 0;
          final redacted Gitleaks 8.30.1 complete-diff scan, no leaks
Review: Kimi sessions session_05b560ca-d9b8-402e-b22b-651a9f440dbe and
        session_20f14e1a-e615-4ad7-9dc9-8ae5e253512e; no P0/P1/P2 remains
Publishing: requires separate scoped authorization
```

## WINDOWS PE API_IMPORT PROTECTED PUBLICATION (2026-07-30)

```text
Issue/PR: GH-121 / PR #122
Status: Merged and exact-main verified
Exact main: 2e3e1e1250c1ab979335ca8f9aee9dad4409fa34
Protected evidence: Prometheus CI 30493381824 PASS
                    Security Audit 30493381812 PASS
                    Pages 30493381150 PASS
Review: CodeRabbit threads resolved; UTC/EEST findings withdrawn
        Kimi sessions session_50c61638-d48c-4ee5-afc3-8c3b1b98b6aa and
        session_998a3a6f-c2af-4e2b-981c-1a28f90c38bb; no P0/P1/P2 remains
Boundary: local-only review_required_v1 extraction; no transport, proof,
          analyzer, wallet, signing, transaction, chain, deployment,
          promotion, or production authorization
Original worktree: user-owned dirty changes and Prometheus-1.png untouched
```

## GH-117 MERGED THREATHINT V2 PIPELINE (2026-07-29)

```text
State: merged and exact-main verified; not production-deployed or rollout-ready
Issue/PR: GH-117 / GH-118
Main: cb3d076d0e698361ce410e993de3edb869c0770e
PR evidence: CI 30423242793; Security 30423242744; all protected checks pass
Main evidence: CI 30423663562; Security 30423663566; Pages 30423663016; pass
Review: Kimi no P0/P1/P2; CodeRabbit pending without findings and non-required
Shipped boundary: strict v2 binding, test-artifact Groth16 verification,
                  owner-only preflight, atomic consumption, enforceable
                  governance, recoverable outbox, durable non-actionable worker
Not shipped: production artifacts/ceremony approval, real semantic/actionable
             analyzer, v2 transport, wallet/chain effects, production rollout
Remaining: independent cryptographic/privacy review and operated evidence
Estimates: core 84-88%; complete vision 50-55%; 45-50% remains
```

## LOCAL THREATHINT V2 DURABLE NON-ACTIONABLE WORKER (2026-07-29)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260728-014
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Schema: governed v4; exact statement/digest, report nonce, bundle, approval,
        authority/high-water, lease, input identity, result, and retention
Migration: empty v3 outbox only; nonempty v3 fails closed unchanged
Completion: one BEGIN IMMEDIATE inserts canonical non-actionable result before
            conditional outbox deletion; exact completion retry is idempotent
Worker: bounded async concurrency/batch/timeout; deterministic test analyzer only
Evidence: 72 focused pass; Guardian 740 pass/3 intentional skips; Black;
          Pylint 10.00 focused/9.83 full; isort; py_compile; Rustfmt;
          warning-free Clippy; 333 Rust pass/2 intentional ignores + 5 doctests;
          locked release build; Cargo/Python audits; Memory/Pages/HTML/diff/leak
Review: Kimi final no P0/P1/P2; two deliberate P3 API semantics accepted by Sol
Boundary: no existing Analyzer/LLM/YARA, confidence, should_submit, actionable
          rule, transport, disclosure, wallet, signature, transaction, chain,
          reward, deployment, commit, push, PR, publish, or external write
Remaining: real privacy-reviewed semantic/actionable analysis requires a new
           explicit high-risk ticket; production relation/key/ceremony and
           independent cryptographic evidence still block operated rollout
Estimates: core 84-88%; complete vision 50-55%; 45-50% remains
```

## LOCAL THREATHINT V2 RECOVERABLE OUTBOX (2026-07-28)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260728-013
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Schema: legacy v1 unchanged; governed v0/v1/v2 -> v3 preserving consumption,
        high-water, and authority state; downgrade/hidden outbox rejected
Atomicity: capacity plus full canonical bundle enqueue share the exact
           BEGIN IMMEDIATE transaction with authority, high-water, consumption
Rollback: full queue, enqueue, schema, lock, integrity, random-source, or
          overflow failure consumes no approval and advances no durable state
Claim: oldest eligible row; internally generated opaque 32-byte token;
       pending -> leased -> exact-ID/token terminal deletion
Recovery: restart preserves pending work; expired lease is reclaimable;
          every lease is capped by retention; expired rows purge before claim
Isolation: only governed promotion enqueues; direct governed acceptance and
           legacy consumption do not
Evidence: 282 focused pass; complete Guardian 716 pass/3 intentional skips;
          Black clean for changed files; exact CI Pylint 9.84/10; Rustfmt,
          warning-free Clippy, complete workspace tests and 5 doctests pass
Review: Kimi independent read-only review found no actionable P0/P1/P2/P3
Boundary: no worker/analyzer execution, transport, disclosure, wallet,
          signing, transaction, broadcast, chain, deployment, or external write
Remaining: production relation/key/ceremony approval and cryptographic review;
           bounded worker/actionable analysis; v2 transport; rollout gates
Estimates: core 83-87%; complete vision 49-54%; 46-51% remains
```

## Checkpoint 2026-07-27: local enforceable v2 governance review-ready

- Ticket `GIO-PROM-20260727-012` composes promotion, governance, and retention
  into the first enforceable owner-local ThreatHint v2 policy boundary.
- One exact policy fixes network, approver key, recipient scope, authority
  epoch/window, same-Guardian local-analysis semantics, denied external
  disclosure, and distinct deny-or-kind-specific-risk decisions.
- All three kind sets must match exactly before ledger access. First valid use
  atomically pins all three exact policy digests plus identity/window; a
  higher epoch advances only with a valid signed approval in the same
  transaction as high-water and consumption.
- Lower epochs, same-epoch policy equivocation, overlapping same-identity
  windows, hidden v0/v1 authority state, replay, failed inserts, integer
  overflow, and lock contention are fail-closed and regression-tested.
- Kimi architecture and two integration reviews found no P0/P1/P2. All review
  test gaps were closed by Sol. Current evidence includes 18 governed
  integration tests, `683 passed, 3 skipped` in the complete Guardian suite,
  Black, focused Pylint `10.00/10`, CI Pylint `9.81/10`, Rustfmt,
  warning-free Clippy, and a complete Rust workspace rerun. Final release,
  audit, workflow, secret, and documentation gates are recorded at closeout.
- No outbox, claim, analyzer, worker, transport, publication, chain action,
  production artifact approval, commit, push, or deployment is part of this
  ticket. The next repository-owned task is an atomic recoverable local
  outbox/claim boundary.
- Estimates: core `82-86%`, complete vision `48-53%`, remaining `47-52%`.

## LOCAL OUTBOX RETENTION-GOVERNANCE CANDIDATE (2026-07-27)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260727-011
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Policy: owner-only exact ASCII TOML bound to expected network, approver key,
        and recipient scope; fixed local recoverable-analysis purpose and
        canonical Observable Bundle payload form
Bounds: non-empty duplicate-free closed durable kinds; 1..100000 pending
        records; 1..2592000 retention seconds
Risk: file hashes remain corpus-matchable; API imports fingerprint software
      capabilities; byte patterns may retain proprietary content
Read: POSIX/getuid/O_NOFOLLOW required; owner-only parent/file; descriptor
      device/inode/mode/size checks; 4096-byte cap; guaranteed close
Result: frozen, non-constructible, non-serializable policy data only
Evidence: 114 focused cases; Guardian 520 pass/3 intentional skips; Black;
          focused Pylint 10.00/10; full Pylint 9.81/10; Rustfmt; warning-free
          workspace Clippy; Rust 333 pass/2 intentional ignores + 5 doctests;
          release builds/packages, dependency audits, Memory, Pages/workflow,
          diff, and candidate-secret gates pass
Review: Kimi final PASS with no P0/P1/P2 after Sol fixed deep-recursion,
        expected-identity, mode, and mandatory-no-follow regressions
Boundary: no database, ledger row, outbox record, worker, runtime import,
          transport, disclosure, external effect, wallet, signing, chain,
          deployment, or rollout evidence
Atomicity: future recoverable enqueue must share the BEGIN IMMEDIATE
           transaction with approval consumption and ledger high-water;
           a digest-only journal is not recoverable work
Remaining: production relation/key/ceremony approval and cryptographic review;
           authority/key/scope and enforceable semantic privacy governance;
           real atomic outbox, transport/actionable analysis; deployments,
           signatures, confirmations, and public evidence
Estimates: core 81-85%; complete vision 47-52%; 48-53% remains
```

## LOCAL THREATHINT V2 OWNER-POLICY PROMOTION CANDIDATE (2026-07-27)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260727-010
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Policy: owner-only exact ASCII TOML; platform, format, duplicate-free allowed
        kinds, and max count 1..16 only; no duplicate network/key/scope anchors
Input: raw envelope, bundle, approval bytes plus trusted nonce/time only
Order: exact types; canonical bundle; review-required disclosure; platform/
       format/kind/count restrictions; same original wires to atomic acceptance
Owner read: O_NOFOLLOW; descriptor dev/inode/mode/size validation; bounded read
Failure: rejected promotion never invokes verify-v2, consumes approval, or
         advances ledger high-water
Result: frozen, non-constructible, non-serializable accepted IDs/time, pinned
        scope, and immutable canonical observable string pairs only
Errors: stable redacted invalid, unavailable, replay, retryable busy
Evidence: 57 focused; ticket 005-010 matrix 207; Guardian 406 pass/3 intentional
          skips; Black 22 modules; Pylint 10.00 focused/9.82 full; Rustfmt;
          warning-free all-target Clippy; workspace 333 pass/2 intentional
          ignores + 5 doctests; release builds/packages; audits; Memory;
          Pages/HTML/JSON-LD; workflow YAML/Actionlint; candidate Gitleaks
Review: Kimi final PASS, no P0/P1/P2; initial trusted-file P2 and all P3
        coverage/classification observations fixed and regression-tested by Sol
Residual: established owner-local same-size content/ancestor race assumptions;
          existing verifier hash-to-exec race; M-002 debug timing jitter
Boundary: no semantic privacy, authority/key governance, production artifact/
          ceremony approval, transport, analysis, publication, external effect,
          wallet, signing, transaction, chain, deployment, or rollout evidence
Remaining: independent production relation/key/ceremony and cryptographic
           review; authority/scope/privacy governance; transport/actionable
           analysis; crash-safe effects; deployments, signatures, public evidence
Estimates: core 81-85%; complete vision 47-52%; 48-53% remains
```

## LOCAL THREATHINT V2 ATOMIC ACCEPTANCE CANDIDATE (2026-07-27)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260727-009
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Construction: exact preflight/consumption network, BIP340 approver key, and
              recipient scope before ledger creation/open
Input: raw envelope, bundle, and approval bytes plus trusted nonce/time only
Order: verified proof/privacy preflight first; raw approval/bundle reverify;
       expected approval ID and observable commitment compare; durable consume last
Errors: stable redacted invalid, unavailable, replay, and retryable busy
Receipt: frozen, direct construction/replace/pickle disabled; data only
Failure: proof/privacy/process/config failures consume nothing and do not
         advance approval ledger high-water
Crash: post-commit/pre-receipt retry returns replay; no double consumption
Evidence: 158 focused pass; Guardian 349 pass/3 intentional skips; Black;
          Pylint 10.00 focused/9.82 full; Rustfmt; warning-free Clippy;
          complete Rust workspace pass/2 intentional ignores + 5 doctests
Review: Kimi static PASS with no P0/P1/P2; sole P3 receipt serialization
        parity finding fixed and regression-tested by Sol
Residual: owner-bounded verifier hash-to-exec race; M-002 debug timing jitter
Boundary: deterministic test proof artifacts only; no production artifact/
          ceremony approval, privacy promotion, transport, analyzer/outbox,
          wallet, signing, transaction, chain, deployment, or rollout evidence
Remaining: independent production relation/key/ceremony and cryptographic
           review; owner-only pairing/privacy promotion; transport/actionable
           analysis; deployments, signatures, confirmations, public evidence
Estimates: core 80-84%; complete vision 46-51%; 49-54% remains
```

## LOCAL THREATHINT V2 VERIFIED PREFLIGHT COMPOSITION (2026-07-27)

```text
Historical ticket-close state: local review-ready; superseded by GH-117 merged status
Ticket: GIO-PROM-20260727-008
Baseline: b556fbbae428e7f6eef07c6d502b32e13e759813
Policy: existing owner-only preflight policy is the sole network and raw-
        manifest SHA-256 authority
Config: owner-only exact TOML pins absolute verifier path, exact executable
        SHA-256, absolute manifest path, and 100..60000 ms timeout
Order: owner-read/hash manifest; Python approval/privacy preflight first;
       exact envelope bytes over stdin to verify-v2
Process: POSIX-only; absolute argv; no shell; scrubbed C locale; cwd=/;
         stdout/stderr discarded; new process group; timeout/reap; one
         in-flight verifier per service
Exit: 0 data receipt; 1 stable invalid; 2/3/other/signal/timeout/config/
      artifact/concurrency stable unavailable
Receipt: frozen, direct construction and pickle disabled; data only
Evidence: 59 focused cases; Guardian 310 pass/3 intentional skips; workspace
          333 pass/2 intentional ignores + 5 doctests; Black; changed Pylint
          10.00/10; full Pylint 9.81/10; Rustfmt; warning-free Clippy
Review: Kimi final PASS with no P0/P1/P2; Sol closed non-POSIX,
        communicate-ValueError, and concurrency-test hardening points
Residual: owner-bounded executable hash-to-exec race; older standalone
          preflight receipt serialization hardening remains P3
Boundary: no SQLite access, approval consumption, production artifact/
          ceremony approval, privacy/disclosure authority, transport,
          analyzer, promotion, wallet, signing, transaction, chain,
          deployment, or rollout evidence
Remaining: independent production relation/key/ceremony approval and one
           final atomic verify-plus-consume boundary; external rollout gates
Estimates: core 79-83%; complete vision 45-50%; 50-55% remains
```
