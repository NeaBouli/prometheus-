# Prometheus — Frequently Asked Questions

## 1. What is Prometheus?

Prometheus is a decentralized, AI-powered threat intelligence protocol on the Kaspa blockchain. It turns every device into a sensor in a global security swarm — no central authority, no foundation, no pre-mine.

## 2. How is Prometheus different from VirusTotal or CrowdStrike?

Prometheus is fully decentralized. No single company controls the threat database. Rules are proposed by AI guardians, voted on by KAS-staking validators, and stored immutably on Kaspa L1. There is no kill switch, no foundation, and no ability for anyone to censor or modify accepted rules.

## 3. Do I need to buy PROM tokens?

No. PROM tokens cannot be purchased — they are exclusively earned through contribution. Guardians earn PROM for accepted threat proposals. Validators earn PROM for honest voting. There is zero pre-mine and no token sale.

## 4. What do validators stake?

Validators stake **KAS** (Kaspa's native token), not PROM. Minimum stake is 10,000 KAS. This is a deliberate design decision: KAS is established and liquid, while PROM is a pure reputation token.

## 5. Does the Light Client upload my files?

**No.** Your files never leave your device. The Light Client runs Phi-3-mini AI locally (4 GB RAM, no GPU). Only SHA-256 hashes and zero-knowledge proofs are transmitted — your data stays private.

## 6. What hardware do I need to run a Guardian?

The 8B model requires an NVIDIA RTX 4070 Ti or better (12-16 GB VRAM) and 32 GB RAM. The 70B model requires 4x A100/H100 GPUs with 128 GB RAM. See the [Guardian Guide](guardian-guide.md) for full details.

## 7. Is there an emergency stop or admin key?

**No.** This is Architecture Decision #3: "Ultimate decentralization — feature, not a bug." The protocol cannot be paused, halted, or modified by any individual. Governance is fully automated through on-chain parameter tuning.

## 8. When does mainnet launch?

The target is **May 5, 2026**, coinciding with the Kaspa Covenant-Hardfork that enables Silverscript smart contracts. The `ssc` compiler ships with this hardfork.

## 9. How fast is threat detection?

The complete lifecycle — from anomaly detection to on-chain rule storage — completes in under 60 seconds. This is verified by the end-to-end integration test suite (Sprint 6).

## 10. How do I earn developer rewards?

The Dev Incentive Pool allocates 5% of PROM emission (1,000,000 PROM/year) for developer grants. Anyone can propose a grant; it requires a 2/3 validator majority vote. The recommended reward formula is: `lines * 10 * (100 + complexity * 10) / 100`. See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
