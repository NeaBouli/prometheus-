# Current Silverscript Compatibility Fixtures

This directory contains contracts written for the current upstream `silverc`
toolchain from `kaspanet/silverscript`.

The legacy `.ss` files in `modules/contracts/` are Prometheus architecture
contracts from the pre-Toccata design phase. They use Solidity-like state
features such as `state map`, `msg.sender`, `tx.value`, `emit`, and `transfer`
that are not a direct 1:1 match for current upstream Silverscript syntax.

## ValidatorStakingH001.sil

`ValidatorStakingH001.sil` isolates the deploy-critical commit-reveal preimage:

```text
vote_byte(1) || salt_le(8) || block_height_le(8)
```

It is intentionally small. It proves the H-001 byte encoding with current
`silverc`/runtime before the full `ValidatorStaking.ss` state-machine port.

Run from the Prometheus repo root:

```bash
python3 scripts/verify_silverc_h001.py
python3 scripts/smoke_silverc_artifacts.py
```

The script uses `/tmp/prom-silverscript` and the pinned upstream ref
`d25bd3427a093c17327ca3d6b9e1aa5f7688c863` by default. Override with:

```bash
SILVERSCRIPT_REPO=/path/to/silverscript python3 scripts/verify_silverc_h001.py
SILVERSCRIPT_REF=<commit-or-tag> python3 scripts/verify_silverc_h001.py
SILVERSCRIPT_REPO=/path/to/silverscript python3 scripts/smoke_silverc_artifacts.py
PROMETHEUS_SILVERC_ARTIFACT_DIR=/tmp/out python3 scripts/smoke_silverc_artifacts.py
python3 scripts/smoke_silverc_artifacts.py --out-dir /tmp/out --archive /tmp/prometheus-silverc-artifacts.tar.gz
python3 scripts/preflight_silverc_deploy.py --archive /tmp/prometheus-silverc-artifacts.tar.gz --network sandbox --rpc-url ws://127.0.0.1:17210 --deployer-address kaspatest:qptestpreflight000000000000000000000000000000000 --metrics-oracle-pubkey 1111111111111111111111111111111111111111111111111111111111111111 --plan-out /tmp/prometheus-silverc-deploy-preflight.json --runbook-out /tmp/prometheus-silverc-deploy-runbook.md
python3 scripts/preflight_metrics_oracle_report.py --report modules/contracts/silverc/metrics-oracle-report.sample.json --plan-out /tmp/prometheus-metrics-oracle-preflight.json --runbook-out /tmp/prometheus-metrics-oracle-runbook.md
```

## ValidatorStakingState.sil

`ValidatorStakingState.sil` is the current-`silverc` port fixture for the
validator-owned state machine. It models one validator UTXO and keeps the core
legacy invariants:

- validators stake KAS, never PROM
- minimum stake is `MIN_STAKE_KAS = 10000`
- commit bond is `BOND_PERCENT = 10`
- withdrawal cooldown is `COOLDOWN_BLOCKS = 100800`
- reveal verification uses the same H-001 canonical preimage as
  `ValidatorStakingH001.sil`

The port uses `#[covenant.singleton(mode = transition)]` because current
Silverscript expresses contract state as covenant-authorized UTXO state, not as
legacy global maps. The fixture currently covers:

- `commitVote`
- `revealVote`
- `slashInvalidReveal`
- `requestWithdraw`
- `completeWithdraw`

The shared verifier compiles this fixture against the pinned upstream
Silverscript ref, builds all covenant declaration sigscripts, and runtime-tests
the `commitVote`, `revealVote`, `slashInvalidReveal`, `requestWithdraw`, and
`completeWithdraw` transitions with real Schnorr signatures and authorized
covenant outputs:

```bash
python3 scripts/verify_silverc_h001.py
```

Current runtime coverage:

- `commitVote` accepts a valid 10% bond, validator signature, and successor state
- `commitVote` rejects a bond below 10% of stake
- `commitVote` rejects negative signed block heights
- `revealVote` accepts a valid commitment, validator signature, and successor state
- `revealVote` rejects a salt that does not match the commitment
- `revealVote` rejects negative signed salts
- `slashInvalidReveal` accepts a provably invalid reveal and slashed successor state
- `slashInvalidReveal` rejects slashing when the reveal matches the commitment
- `slashInvalidReveal` rejects negative signed salts
- `requestWithdraw` accepts an active validator with no open commitment
- `requestWithdraw` rejects while a vote commitment is open
- `requestWithdraw` rejects negative signed block heights
- `completeWithdraw` accepts zero-output termination after cooldown
- `completeWithdraw` rejects before the cooldown expires

Current signed-int deployment boundary:

- upstream Silverc entrypoint numeric arguments are signed `int`
- deployable `salt` and `block_height` values are scoped to `0..=i64::MAX`
- Rust retains raw `u64` H-001 byte vectors, including `u64::MAX`, for
  compatibility testing only
- Rust deployment calls must use `build_silverc_checked` or
  `validate_silverc_commitment_bounds`
- CI proves signed negative Silverc values do not match the Rust `u64::MAX`
  vector, so there is no implicit two's-complement workaround

Remaining deployment blockers:

- no network deploy CLI is currently present in upstream `silverc`; deployment
  readiness is therefore split into current-`silverc` runtime tests, a
  deterministic JSON artifact/release-manifest gate, and a still-open network
  deploy/orchestration path once tooling exists

## Silverc CLI release bundle smoke

`scripts/smoke_silverc_artifacts.py` compiles every current-Silverc fixture
through the pinned upstream `silverc` binary and validates the resulting JSON
artifact structure:

- non-empty compiled script bytes
- compiler version
- state layout
- expected ABI entrypoints for each Prometheus fixture

Generated artifacts are written to `/tmp/prometheus-silverc-artifacts` by
default and are not committed. Use `--out-dir` to choose another output
directory. Use `--archive /path/to/prometheus-silverc-artifacts.tar.gz` to
produce a deterministic tarball for operator handoff. The script also writes
`manifest.json` with deterministic rollout metadata:

- pinned Silverscript ref and resolved commit
- source SHA-256 for each fixture
- constructor-args SHA-256 for each fixture
- artifact SHA-256
- compiled script SHA-256 and byte length
- state layout and ABI entrypoints

The script validates the manifest after writing it, and repeated local runs
produce the same manifest and archive for the same source tree and pinned
Silverscript ref. CI builds the manifest and checks that the optional archive
contains the manifest. This is a CI-safe release-bundle gate for the available
current-Silverc CLI surface; it does not claim that contracts were deployed to a
network.

## Deploy preflight

`scripts/preflight_silverc_deploy.py` validates an already-built release bundle
from either `--bundle-dir` or `--archive` before any network deploy attempt. It
checks:

- safe archive layout
- manifest schema and expected fixture order
- source, constructor-args, artifact, and compiled-script SHA-256 hashes
- non-empty ABI and state layout metadata
- public operator inputs: network, RPC URL, deployer address, and metrics-oracle
  public key
- whether the pinned upstream `silverc` CLI exposes a network deploy command

The preflight intentionally does not accept private keys and does not deploy.
Today it reports `deploy_supported: false` because upstream `silverc` exposes
compile/AST artifact generation but no network deploy command. This turns the
remaining Sprint 9 deploy blocker into a concrete, CI-visible capability gap
instead of a vague manual step.

Use `--runbook-out <path>` to emit a Markdown operator handoff next to the JSON
plan. The runbook is generated only after bundle and public-input validation
passes. It lists the inspected network, missing public inputs, the deploy-tool
capability status, each contract artifact with script SHA-256 and script byte
length, the safe operator sequence, and the remaining deploy blockers. It still
does not include private keys, seed phrases, wallet files, or keystore material.
CI checks that the runbook remains generated, blocked while no upstream network
deploy command exists, and explicit about not broadcasting transactions.

## GovernanceAutoTuningState.sil

`GovernanceAutoTuningState.sil` is the current-`silverc` port fixture for
weekly protocol parameter tuning. It resolves the deployment-blocking Q-003
stub in the current-Silverc path by making `fp_rate` an explicit signed
metrics-oracle input instead of an implicit `oracle_get_fp_rate() -> 0` value.

The fixture keeps the legacy tuning invariants that are safe to express in the
current covenant state model:

- tuning interval is `TUNING_INTERVAL_BLOCKS = 604800`
- confidence target remains `TARGET_FP_RATE_MAX = 50` (0.5%, 10000x scaled)
- reported `fp_rate` is bounded to `0..10000`
- confidence bounds remain `CONFIDENCE_FLOOR = 5000` and
  `CONFIDENCE_CEILING = 9900`
- stake bounds remain `MIN_STAKE_KAS_FLOOR = 1000` and
  `MIN_STAKE_KAS_CEILING = 100000`
- reward bounds remain `REWARD_FLOOR = 10` and `REWARD_CEILING = 1000`

The fixture intentionally does not pretend to support legacy global state,
string parameter lookup, cross-contract `call(...)`, or an off-chain oracle
operator implementation. The deploy path must still provision and operate the
metrics signer represented by `metrics_oracle_pk`.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `reportMetrics`
- `autoTune`

Verified rejection paths include `fp_rate` above `MAX_FP_RATE` and auto-tuning
before `TUNING_INTERVAL_BLOCKS`.

## Metrics-oracle report preflight

`scripts/preflight_metrics_oracle_report.py` validates the public metrics report
that an operator will use for `GovernanceAutoTuningState.reportMetrics`.
It does not sign, hold keys, or broadcast. The real covenant signature remains a
transaction-input signature produced by the metrics-oracle wallet outside this
repository.

The report schema is demonstrated in
`metrics-oracle-report.sample.json`. The preflight validates:

- `schema_version = 1`, `contract = GovernanceAutoTuningState`, and
  `entrypoint = reportMetrics`
- `metrics_oracle_pubkey` as a 32-byte public key hex string
- nonnegative `active_validators`, `active_guardians`, and `proposals_per_day`
- `fp_rate` in the contract-compatible range `0..10000`
- monotonic `block_height >= previous_state.last_metrics_block`
- absence of secret-like fields such as private keys, seeds, wallet data, or
  keystore material

It emits a JSON preflight plan with the exact public `reportMetrics` argument
mapping and can emit a Markdown operator runbook. CI checks the sample report,
the generated plan/runbook, and a negative secret-field rejection case.

## DevIncentivePoolState.sil

`DevIncentivePoolState.sil` is the current-`silverc` port fixture for the
developer grant state machine. It models one active grant UTXO slot and PROM
pool accounting.

The fixture keeps the legacy grant invariants that are safe to express in the
current covenant state model:

- maximum grant is `MAX_GRANT_PROM = 100000`
- grant voting period is `GRANT_VOTING_BLOCKS = 604800`
- reward formula uses `REWARD_PER_LINE = 10`
- complexity is bounded by `MIN_COMPLEXITY = 1` and `MAX_COMPLEXITY = 10`
- execution quorum is `QUORUM_VOTES = 10`
- validator approval threshold is `VALIDATOR_QUORUM = 6700`
- pool accounting remains PROM-denominated, but PROM is not a staking asset

The fixture intentionally does not pretend to support legacy global maps,
string storage, `msg.sender`, event emission, cross-contract validator lookups,
emission-contract deposits, or direct PROM `transfer(...)` in current Silverc.
The known legacy `deposit()` ACL question remains a deployment/orchestration
decision once the emission authority is finalized.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `proposeGrant`
- `voteGrant`
- `executeGrant`

Verified rejection paths include grant amount above `MAX_GRANT_PROM`, voting at
`voting_end_block`, execution below `QUORUM_VOTES`, and execution below
`VALIDATOR_QUORUM`.

## CommunityDonationsState.sil

`CommunityDonationsState.sil` is the current-`silverc` port fixture for the
community donation pool state machine. It models donation accounting and one
active disbursement proposal/rule UTXO slot.

The fixture keeps the legacy invariants that are safe to express in the current
covenant state model:

- minimum donation is `MIN_DONATION_KAS = 1`
- disbursement quorum is `DISBURSEMENT_QUORUM = 10`
- validator approval threshold is `VALIDATOR_QUORUM = 6700`
- pool accounting remains KAS-denominated
- disbursements require governance signature at execution

The fixture intentionally does not pretend to support legacy global maps,
string storage, `msg.sender`, `tx.value`, event emission, cross-contract
validator lookups, or direct KAS `transfer(...)` in current Silverc. Those
concerns remain deployment/orchestration work around the covenant state model.

The shared verifier currently compiles this fixture against the same pinned
upstream Silverscript ref and runtime-tests covenant transitions for:

- `donateKas`
- `proposeDisbursement`
- `voteDisbursement`
- `executeDisbursement`

Verified rejection paths include zero donation amount, disbursement amount
above pool balance, voting at `voting_end_block`, and execution below
`DISBURSEMENT_QUORUM`.

## RuleStorageState.sil

`RuleStorageState.sil` is the current-`silverc` port fixture for the rule
proposal and storage state machine. It models one active proposal/rule UTXO
slot and keeps the deployment-critical legacy invariants:

- rule content uses CIDv1 binary as `byte[36]`
- minimum AI confidence is `MIN_CONFIDENCE = 8500`
- validator quorum is `VALIDATOR_QUORUM = 6700`
- voting duration is `VOTING_BLOCKS = 864000`
- accepted/rejected proposal outcomes are represented as explicit Guardian
  reputation events for orchestration with `GuardianReputationState.sil`

The fixture intentionally does not pretend to support legacy global maps,
`msg.sender`, cross-contract `call(...)`, event emission, or KRC20 minting in
current Silverc. Those concerns remain deployment/orchestration work around the
current covenant state model.

The shared verifier compiles this fixture against the same pinned upstream
Silverscript ref, builds covenant declaration sigscripts, and runtime-tests
the proposal lifecycle transitions for:

- `submitProposal`
- `voteOnProposal`
- `finalizeProposal`
- `deactivateRule`

Current runtime coverage:

- `submitProposal` accepts a valid guardian signature and successor state
- `submitProposal` rejects confidence below `MIN_CONFIDENCE`
- `voteOnProposal` accepts a valid validator support vote and successor state
- `voteOnProposal` rejects votes at or after `voting_end_block`
- `finalizeProposal` accepts accepted and rejected proposal outcomes
- `finalizeProposal` rejects zero-vote finalization
- `deactivateRule` accepts deactivation of an active accepted rule
- `deactivateRule` rejects pending/non-accepted rule state

## GuardianReputationState.sil

`GuardianReputationState.sil` is the current-`silverc` port fixture for the
guardian-owned reputation state machine. Guardian reputation remains canonical
on Kaspa L1 and does not introduce badge, NFT, Kasplex, or staking semantics.

The fixture models one guardian reputation UTXO and keeps these legacy
invariants:

- no Guardian staking
- starting reputation is `REPUTATION_START = 1000`
- minimum voting reputation is `MIN_REPUTATION = 1000`
- maximum reputation is `REPUTATION_MAX = 100000`
- minimum compute is `MIN_COMPUTE_GFLOPS = 100`
- model type `0` is LLaMA-3-70B and model type `1` is LLaMA-3-8B

The shared verifier compiles this fixture against the same pinned upstream
Silverscript ref and builds covenant declaration sigscripts for:

- `register`
- `proposalAccepted`
- `proposalRejected`

Current runtime coverage:

- `register` accepts a valid guardian signature and state transition
- `register` rejects compute power below `MIN_COMPUTE_GFLOPS`
- `proposalAccepted` accepts a valid governance signature and state transition
- `proposalAccepted` computes `isqrt(compute_power_gflops) * 100` on-chain
- `proposalRejected` accepts a valid governance signature and state transition
- `proposalRejected` rejects unregistered guardian state

Current scope note:

- current upstream Silverc uses bounded `for` loops rather than `while`
- the legacy `sqrt(compute_power) * 100` accepted-proposal increment is
  implemented as exact integer square root for the allowed `< 1_000_000`
  compute-power range
- `proposalAccepted` caps reputation at `REPUTATION_MAX`
