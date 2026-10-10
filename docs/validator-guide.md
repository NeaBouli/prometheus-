# Prometheus Validator Guide

> **Status (reviewed 2026-09-30):** this guide describes the **target** validator
> role. No Prometheus validator network operates today, `prometheus-validator`
> is a tested library crate without a binary, and no production ValidatorStaking
> deployment exists (only the non-promotable H-001 Testnet-10 canary). Do not
> send KAS to any contract on the basis of this guide. PROM emission is not
> implemented. See [README](../README.md) and [roadmap](roadmap.md) for current status.

## What Do Validators Do?

In the target design, validators secure the Prometheus network by staking KAS and voting on threat-intelligence proposals. They would earn PROM rewards for honest participation once emission exists, and face slashing for misbehavior.

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

### 2. Build and test the validator library

```bash
cd prometheus-
cargo test -p prometheus-validator
```

This builds and tests the slashing/voting state machines. There is no validator
binary or network node yet.

### 3. Register as Validator (target — not available)

Once a reviewed ValidatorStaking deployment exists, registration would send a transaction with `MIN_STAKE_KAS` (10,000 KAS) to the ValidatorStaking contract calling `register(pubkey)`.

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

Frozen historical h001-v1 retains a 100,800-count cooldown checked against caller-provided block_height, not consensus-enforced DAA. Unaccepted, non-promotable v2-draft uses 6,048,000 consensus DAA-score units via this.age. Nominally approximately 2.8 hours and 7 days, respectively, only assuming 10 count units/s for v1 and 10 DAA-score units/s for v2; not guaranteed wall-clock durations.

The historical fixture is not fully deployed or production-ready. The draft does not replace the pinned v1 release or establish a new accepted contract duration; D1-D7 adoption, independent acceptance, activation and rollout remain gated. The fixture withdrawal sequence is to initiate a request, then complete it after the fixture-specific count or DAA-score condition; this is not a live-network operating instruction.

## Rewards

Planned: validators would receive 40% of Year-1 PROM emission (8,000,000 PROM), distributed proportionally to participation. PROM minting and emission are not implemented, deployed, or active.
