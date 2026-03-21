# Prometheus Validator Guide

## What Do Validators Do?

Validators secure the Prometheus network by staking KAS and voting on threat intelligence proposals. They earn PROM rewards for honest participation and face slashing for misbehavior.

## Requirements

| Component | Requirement |
|-----------|-------------|
| KAS Stake | Minimum 10,000 KAS |
| Kaspa Node | Full node running kaspad |
| Network | Stable internet connection |
| Uptime | Recommended 99%+ |

## Setup

### 1. Run a Kaspa Node

```bash
git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa
cargo build --release -p kaspad
./target/release/kaspad --testnet --netsuffix=10 --utxoindex \
    --rpclisten=0.0.0.0:16210 --rpclisten-borsh=0.0.0.0:17210
```

### 2. Build the Validator

```bash
cd prometheus-
cargo build --release -p prometheus-validator
```

### 3. Register as Validator

Send a transaction with `MIN_STAKE_KAS` (10,000 KAS) to the ValidatorStaking contract calling `register(pubkey)`.

## Voting Process

1. **Commit Phase**: When a new rule proposal appears, create a commitment: `sha256(vote || salt || block_height)`
2. **Bond**: 10% of your stake is locked as collateral
3. **Reveal Phase**: After the commit period, reveal your vote and salt
4. **Valid reveal**: Bond returned, vote recorded
5. **Invalid reveal**: Bond slashed

## Slashing Risks

| Offense | Penalty | Escalation |
|---------|---------|------------|
| Invalid reveal | Bond (10% of stake) | Per occurrence |
| Simple misbehavior | 5% of stake | Up to 3x |
| Double voting | 10% of stake | Up to 3x |
| Proven collusion | 20% of stake | Up to 3x |

If your stake drops below 10,000 KAS after slashing, you are automatically deactivated.

## Withdrawal

Withdrawals have a 7-day cooldown (100,800 blocks at 10 BPS). Call `withdraw()` to initiate, then call again after the cooldown.

## Rewards

Validators receive 40% of PROM emission (8,000,000 PROM/year), distributed proportionally to participation and reputation.
