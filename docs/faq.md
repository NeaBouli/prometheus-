# Prometheus — Frequently Asked Questions

---

## Tokenomics

**Q: What is the difference between KAS and PROM?**
KAS is the Kaspa native token used as economic collateral by validators.
If a validator misbehaves, they lose KAS — real money. PROM is the
Prometheus reputation and governance token. It cannot be purchased.
It is minted exclusively when a threat rule is accepted by consensus.
KAS = economic security. PROM = proof of contribution.

**Q: How does PROM enter the market?**
On launch day, zero PROM exist. The first PROM are minted when the
first threat rule passes consensus. Simultaneously, a KAS/PROM
liquidity pool opens on Kasplex DEX (funded from the community pool).
The price forms organically — no ICO, no presale, no listing price.
The deflationary curve (-10%/year) combined with growing demand
creates natural upward price pressure over time.

**Q: Is there mining for PROM?**
Not in the traditional sense. PROM is minted when a threat rule is
accepted — this is performance-based emission. Guardians are the
closest equivalent to "miners": they run LLaMA 3 AI to analyze
threats and generate rules. Instead of GPU hashrate, they contribute
AI compute and threat intelligence.

**Q: What is the PROM emission schedule?**
Year 1: 20,000,000 PROM. Each subsequent year: -10%.
Year 2: 18M. Year 3: 16M. Year 4: 14M. Year 5: 12M.
Total over 5 years: 80,000,000 PROM.
Distribution: 40% Validators. 30% Guardians. 20% Reporters.
5% Dev Pool. 5% Community.

---

## Security Protocol

**Q: Are threat rules confirmed automatically?**
No — four independent checkpoints exist:
1. AI pre-filter: minimum 85% confidence required (automatic)
2. Collection: minimum 5 independent reports of the same threat
3. Validator vote: 67% majority via Commit-Reveal (bond at risk)
4. 24-hour challenge period: anyone can contest, auto-tuning responds
No single step is fully automatic without verification.

**Q: What happens with a false positive?**
Affected users report the false detection. The false positive rate
rises on-chain. The GovernanceAutoTuning contract automatically
raises the confidence threshold for new rules. The guardian who
submitted the bad rule loses 50% of their reputation score.
No human intervention required.

**Q: How does Prometheus protect my privacy?**
Your device never sends raw files, paths, or metadata. Only a
SHA-256 hash of the suspicious file is transmitted — this is a
one-way fingerprint, the original cannot be reconstructed from it.
The report is wrapped in a Groth16 ZK-proof that proves you are a
legitimate network participant without revealing your identity.
Raw data never leaves your device.

**Q: What is Commit-Reveal voting?**
A cryptographic protocol that prevents validators from copying each
other's votes. In the commit phase, each validator submits
sha256(vote || salt || block_height) — a sealed envelope. After all
validators have committed, the reveal phase begins and everyone
opens their envelope simultaneously. A 10% bond is locked during
voting. Invalid reveals result in immediate bond slashing.

---

## Technical

**Q: Why Kaspa and not Ethereum?**
Kaspa's DAGKnight consensus achieves 100 blocks per second with
sub-second finality. Ethereum finality is 12 seconds — too slow for
real-time threat response. Kaspa also shares the 0% pre-mine
philosophy of Prometheus. Silverscript (native L1 contracts)
eliminates reentrancy attacks by design.

**Q: What is the difference between Prometheus and ClamAV or Wazuh?**
ClamAV and Wazuh are signature-based — they only detect what is
already known. Prometheus detects unknown threats through behavioral
AI analysis and swarm intelligence. It also stores rules permanently
on a public blockchain that no organization can modify or censor.
Prometheus complements existing tools — it does not replace them.

**Q: Can Prometheus be shut down?**
No. There is no foundation, no central server, no emergency stop.
The protocol exists as long as the Kaspa blockchain exists.
No government, corporation, or court can disable it.
This is a deliberate architectural decision, not an oversight.

**Q: When will the mobile app be available?**
iOS and Android clients are targeted for September 2026.
Desktop clients (Windows, macOS, Linux) target August 2026.

---

## Participation

**Q: How do I earn PROM?**
Four ways: (1) Run a Light Client and report validated threats.
(2) Run a Guardian Node with LLaMA 3 and submit accepted rules.
(3) Run a Validator Node, stake KAS, and vote honestly.
(4) Run a Honeypot Node and capture zero-day attacks.
The highest per-report reward goes to Honeypot operators
(zero-days are rare and extremely valuable).

**Q: What hardware do I need?**
Light Client: any device with 4 GB RAM, no GPU required.
Guardian (8B model): RTX 4070 Ti or better, 16 GB VRAM.
Guardian (70B model): 4x A100/H100, 128 GB RAM.
Validator: standard VPS, 2 vCPU, 4 GB RAM + 10,000 KAS stake.
Honeypot: any internet-exposed server.
