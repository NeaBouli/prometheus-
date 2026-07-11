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
```

The script uses `/tmp/prom-silverscript` and the pinned upstream ref
`d25bd3427a093c17327ca3d6b9e1aa5f7688c863` by default. Override with:

```bash
SILVERSCRIPT_REPO=/path/to/silverscript python3 scripts/verify_silverc_h001.py
SILVERSCRIPT_REF=<commit-or-tag> python3 scripts/verify_silverc_h001.py
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

- remaining deployment-scoped contract ports

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
