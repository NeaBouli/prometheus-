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

**Q: Does running Prometheus beside a Kaspa miner automatically earn PROM?**
No. The current miner companion is a development-only local Testnet-10
wRPC observer. It does not scan, report threats, control mining, or award
PROM. The aggregate future reporter pool is split into 15% for verified Light
Client contributions and 5% for verified Honeypot contributions. The current
companion is eligible for neither allocation and cannot claim the full 20%.
Kaspa mining uses Stratum in most ASIC/pool setups; Prometheus wRPC observation
is separate.

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
Affected users report the false detection. The signed metrics-oracle
pipeline reports the bounded false positive rate on-chain.
GovernanceAutoTuning then deterministically raises the confidence
threshold for new rules. The guardian who submitted the bad rule
loses 50% of their reputation score.
The transition still requires authenticated metrics, external signatures, and
confirmed on-chain execution; those production steps remain gated.

**Q: How does Prometheus protect my privacy?**
The implemented ThreatHint v1 path never sends raw files or paths. It does send
bounded metadata: a caller-supplied 32-byte hash commitment, confidence,
indicator category, proof bytes, nonce, and timestamp. A hash is not encryption
and may allow correlation or matching against known content.

The manifest-pinned Groth16 engine binds the v1 statement to its network and
domain, but no approved production relation or keys ship yet, so operated
verification remains fail-closed. V1 does not prove how the hash was derived,
that a report is true, or that its sender is anonymous. The
[Threat Observable v2 draft](threat-observable-v2.md) defines the additional
privacy and proof boundaries required before concrete indicators are sent.
Merged and exact-main-verified GH-86 adds isolated Rust and Python structural validators against one shared
byte-exact corpus, but they do not prove extractor provenance or semantic
privacy and are not connected to transport, Guardian analysis, or publication.
Merged and exact-main-verified GH-107 can locally authenticate one short-lived approval
statement for one exact `review_required_v1` bundle against separately trusted
context, including separately trusted current time that must never be
attacker-controlled. It does not disclose, transport, analyze, publish, or
persist the bundle. Its signed nonce and deterministic approval ID identify
repeats but do not prevent replay; durable one-time consumption and trusted
approver policy remain required before promotion.

Merged and exact-main-verified GH-111 adds that local consumption boundary in Guardian Node. One owner-only
policy fixes the network, approver public key, and opaque recipient-scope
digest; the service verifies in the same call path and atomically records the
approval ID and authority-bound nonce in an owner-only SQLite ledger. This
prevents local reuse across retries, concurrency, and restarts, but the receipt
grants no external authority. Key ownership/rotation, scope semantics,
hint/bundle pairing, privacy approval, transport, analyzer execution,
promotion, outbox delivery, wallet, and chain behavior remain unimplemented.

Merged and exact-main-verified GH-114 adds an isolated local ThreatHint v2 statement parser in Rust and
Python. It requires exact canonical bytes for separate artifact hash and
observable commitment fields plus bounded confidence, structural disclosure
class, report nonce, positive observed time, and a network matching separately
trusted local context. A domain-separated digest binds every field. This is
only structural consistency: no approved relation, proof, privacy review,
approval pairing, replay authority, transport, analyzer, wallet, or chain path
uses it, and it does not prove that the artifact or report is genuine.

**Q: What is Commit-Reveal voting?**
A cryptographic protocol that prevents validators from copying each
other's votes. In the commit phase, each validator submits
sha256(vote || salt || block_height) — a sealed envelope. After all
validators have committed, the reveal phase begins and everyone
opens their envelope simultaneously. A 10% bond is locked during
voting. Invalid reveals result in immediate bond slashing.

---

## Technical

**Q: Which Light Client features work today?**
The Rust workspace contains tested development components, but Phi-3
inference, Groth16 proofs, canonical rule loading, P2P submission, and the
complete report pipeline are not production implementations yet. Runtime
guards reject those placeholders in beta and mainnet profiles.

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
Prometheus has no repository-controlled emergency stop, foundation server, or
central protocol operator. Once deployed, covenant state transitions follow
their scripts rather than a developer kill switch. Availability still depends
on Kaspa, participating nodes, clients, and network access; infrastructure can
be disrupted or blocked. The absence of an emergency-stop path is a deliberate
architectural decision, not an availability guarantee.

**Q: When will the mobile app be available?**
Desktop and mobile releases are readiness-gated rather than date-gated.
Production proof artifacts, the v2 observable path, operated networking,
security review, and core rollout evidence must pass first. Flutter remains the
mobile implementation target.

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

In the target architecture, none sends the malware itself. Each sends a bounded
model update. Such updates can still leak information, so production requires
clipping, secure aggregation, privacy accounting, authentication, and
validation.
A rotating coordinator (chosen by reputation) aggregates all
gradients and distributes an improved global model to all nodes.
Every Guardian Node becomes smarter simultaneously.
This reduces direct record sharing; it is not an anonymity or
non-reconstruction guarantee.

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
