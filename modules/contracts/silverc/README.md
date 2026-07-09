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
the `commitVote`, `revealVote`, and `slashInvalidReveal` transitions with real
Schnorr signatures and authorized covenant outputs:

```bash
python3 scripts/verify_silverc_h001.py
```

Current runtime coverage:

- `commitVote` accepts a valid 10% bond, validator signature, and successor state
- `commitVote` rejects a bond below 10% of stake
- `revealVote` accepts a valid commitment, validator signature, and successor state
- `revealVote` rejects a salt that does not match the commitment
- `slashInvalidReveal` accepts a provably invalid reveal and slashed successor state
- `slashInvalidReveal` rejects slashing when the reveal matches the commitment

Remaining runtime coverage before deployment:

- `requestWithdraw`
- `completeWithdraw`
