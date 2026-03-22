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

---

## AI Architecture

**Q: Does Prometheus develop its own AI model from scratch?**
No — and that would be the wrong approach. Training foundation models
from scratch costs hundreds of millions of dollars and years of time.
Prometheus takes a different path: we take the best existing
open-source models and specialize them for security work.
This is the Prometheus metaphor in practice — we take the fire
that already exists and give it to humanity in a new form.

**Q: Which AI models does Prometheus use and why open source?**
Two models, both fully open source:

Phi-3-mini 3.8B (Microsoft, MIT License) runs locally on every
Light Client. It requires only 4 GB RAM, no GPU, and runs on
Windows, macOS, Linux, and mobile. It handles local anomaly
detection — the first line of defense on your device.

LLaMA 3 (Meta, Community License) runs on Guardian Nodes.
The 8B variant requires an RTX 4070 Ti or better. The 70B variant
requires 4x A100/H100. It handles deep threat analysis and
YARA rule generation.

Proprietary models (GPT-4, Claude, Gemini) are black boxes —
nobody can verify what they actually do. For a security system
whose core principle is transparency, they are structurally
unsuitable. Open source models can be audited, self-hosted,
and fine-tuned. Malware samples never leave the local environment.

**Q: How is LLaMA 3 trained for security tasks?**
We use LoRA (Low-Rank Adaptation) — a technique that fine-tunes
only 1-5% of the model's parameters on security-specific datasets.
This means no supercomputer is needed. A single A100 GPU is
sufficient for training.

Training datasets:
- VirusShare: the largest public malware database, millions of samples
- MalwareBazaar: daily updated malware samples
- Exploit-DB: complete CVE and exploit database
- CuckooSandbox reports: behavioral analysis of malware in sandboxes

The result is a specialized security model built on LLaMA 3 —
trained to recognize threat patterns, correlate CVEs, and generate
valid YARA rules with high confidence.

**Q: How does the network get smarter over time?**
Through federated learning via the Fed-DART protocol
(Fraunhofer Institute, open source). Here is how it works:

Guardian Node A sees malware X in Germany.
Guardian Node B sees malware X in Japan.
Guardian Node C sees malware X in Brazil.

None of them send the malware itself. Each sends only mathematical
gradients — the direction in which the model should improve.
A rotating coordinator (chosen by reputation) aggregates all
gradients and distributes an improved global model to all nodes.
Every Guardian Node becomes smarter simultaneously.
Nobody knows the data of anyone else.

After 1 month: 50 nodes x 1,000 threats = 50,000 new patterns learned.
After 6 months: the model outperforms commercial solutions because
it trains on real threats from the entire world, not lab data.
After 1 year: the model understands regional threat landscapes,
new exploit categories, and attack patterns that did not exist in 2025.

**Q: Can a compromised model be pushed to the network?**
No. Every model update is distributed via IPFS. The SHA-256 hash
of the new model is stored on the Kaspa blockchain before
distribution. Every Guardian Node and Light Client verifies
the IPFS content hash against the on-chain hash before installing
any update. A manipulated model would have a different hash —
it would be automatically rejected. The blockchain is the
tamper-proof source of truth for model integrity.

**Q: What exactly does Prometheus develop vs. what does it reuse?**

Reused (existing open source):
- LLaMA 3 base model (Meta)
- Phi-3-mini base model (Microsoft)
- Fed-DART federated learning protocol (Fraunhofer)
- Kaspa blockchain infrastructure (kaspanet)
- YARA rule engine (VirusTotal)

Developed by Prometheus:
- Security fine-tuning pipeline (LoRA on malware datasets)
- YARA generation prompts and validation logic
- Fed-DART integration and coordinator rotation
- Model distribution via IPFS with on-chain hash verification
- The complete protocol connecting all components
- 6 Silverscript smart contracts
- Rust light client, Python guardian node, Rust validator node

This is software engineering and ML engineering — not AI research.
The distinction matters: we are not reinventing the wheel.
We are building the vehicle.
