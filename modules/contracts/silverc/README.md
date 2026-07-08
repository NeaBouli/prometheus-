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
