# Prometheus — Frequently Asked Questions

---

## Tokenomics

**Q: What is the difference between KAS and PROM?**
KAS is the Kaspa native token used as economic collateral by validators.
If a validator misbehaves under the target protocol, they lose KAS. PROM is the
planned reward and governance token, while Guardian reputation is separate
canonical Kaspa L1 state. Validators stake KAS and never PROM. Planned primary
PROM issuance is contribution-based; a planned KAS/PROM pool would permit
secondary-market purchases after issuance. No PROM minting, emission, pool, or
trading is implemented, deployed, or active.

**Q: How does PROM enter the market?**
The specification starts with zero PROM: no pre-mine, ICO, presale, founder, or
foundation allocation. Primary issuance is planned for verified contributions.
A later KAS/PROM liquidity pool funded from the Community allocation is a
secondary-market target, not a deployed feature or price promise.

**Q: Is there mining for PROM?**
No PROM is currently minted. The target tokenomics use performance-based
emission for verified protocol contributions, including validators, Guardians,
reporters, the Dev Pool, and the Community pool. Real model operation and every
reward path remain undeployed.

**Q: Does running Prometheus beside a Kaspa miner automatically earn PROM?**
No. The current miner companion is a development-only local Testnet-10
wRPC observer. It does not scan, report threats, control mining, or award
PROM. The aggregate future reporter pool is split into 15% for verified Light
Client contributions and 5% for verified Honeypot contributions. The current
companion is eligible for neither allocation and cannot claim the full 20%.
Kaspa mining uses Stratum in most ASIC/pool setups; Prometheus wRPC observation
is separate.

**Q: What is the planned PROM emission schedule?**
The specification targets Year 1: 20,000,000 PROM, then -10% annually.
Year 2: 18M. Year 3: 16M. Year 4: 14M. Year 5: 12M.
Total over 5 years: 80,000,000 PROM.
Distribution: 40% Validators. 30% Guardians. 20% Reporters.
5% Dev Pool. 5% Community. These are predefined protocol pools, not founder or
foundation allocations, and none is emitting today.

---

## Security Protocol

**Q: Are threat rules confirmed automatically?**
No production rule-confirmation path is operating. The target architecture has four checkpoints:
1. AI pre-filter: minimum 85% confidence required (automatic)
2. Collection: minimum 5 independent reports of the same threat
3. Validator vote: 67% majority via Commit-Reveal (bond at risk)
4. 24-hour challenge period: anyone can contest, auto-tuning responds
Their state-machine and fixture coverage does not prove an operated end-to-end network.

**Q: Does Prometheus already validate generated YARA rules with a real engine?**
Merged and exact-main-verified GH-170 replaces substring shape
checks with exact-pinned, compile-only YARA-X validation. It accepts one
bounded ASCII rule, disables includes, rejects imports, multiple rules,
compiler errors, and warnings, and performs no scan. This validates syntax and
structure only; semantic quality, model approval, submission, publication, and
production operation remain separate gates. PR #171 published exact main
`8d8e29c`; CI `31650123073`, Security `31650123055`, and Pages `31650122593`
pass.

Merged and exact-main-verified GH-173 composes this boundary with the governed v2
worker. It deterministically derives one memory-only draft from already
approved local API-import and byte-pattern observables, then stores only exact
bindings, per-kind counts, a nonce-bound candidate-binding digest, and compile
status in an explicitly non-actionable result. It invokes no model, persists no
rule source, scans nothing, and grants no submission, publication, or production
authority. PR #174 published exact main `1107b11`; CI `31654308969`, Security
`31654308964`, and Pages `31654308875` pass. Real privacy-reviewed
semantic/actionable quality remains open.

GH-177 is merged and exact-main verified through PR #178 at `396d347`. It scans
only 20 deterministically generated synthetic in-memory buffers with one fixed
rule and records an authority-`none` canonical report with exact false-positive
and false-negative metrics. It is structurally isolated from every governed
worker, result, submission, wallet, chain, and deployment path. Passing this
synthetic gate is regression evidence only, not real-world detection quality,
actionable-rule approval, calibration, certification, or production authority.

GH-180 is merged and exact-main verified through PR #181 at `a28ad00`. Eight
POSIX-only cases drive canonical synthetic transport bytes through the real
Python ingress, governed promotion, schema-v5 atomic outbox, bounded worker,
and durable non-actionable semantic-draft result. They cover exact bindings,
malformed and oversized input, replay/restart, duplicate concurrency, lease
recovery, redacted analyzer failure, and transactional rollback. This adds no
runtime path or authority, keeps GH-177 isolated, and is not production
deployment or real-world detection evidence.
Prometheus CI `31662874366`, Security Audit `31662874399`, and Pages
`31662873670` pass on the exact merge commit.

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

Merged and exact-main-verified GH-167 adds the bounded repository ThreatHint-v2
transport substrate. PR #168 published exact main `7c62608`; Prometheus CI
`31645624623`, Security Audit `31645624601`, and Pages `31645623547` pass. Exact
canonical v2 wires cross an independent libp2p protocol into owner-only local
IPC, where they are reparsed against separately trusted network, active-session,
and time context before the existing governed promotion boundary is called.
This is same-host engineering evidence only. Production proof artifacts,
privacy-reviewed semantic/actionable analysis, public multi-host operation,
disclosure, model/YARA execution, wallet, chain, rewards, and deployment remain
separate blocked gates.

**Q: What is Commit-Reveal voting?**
A cryptographic state machine designed to reduce vote copying. In the commit phase, each validator submits
sha256(vote || salt || block_height) — a sealed envelope. After all
validators have committed, the reveal phase begins and everyone
opens their envelope simultaneously. A 10% bond is locked during
voting. Invalid reveals result in bond slashing in the tested state machines.
No operated validator network or production quorum is proven.

---

## Technical

**Q: Which Light Client features work today?**
The Rust workspace contains tested development components, but Phi-3
inference, Groth16 proofs, canonical rule loading, P2P submission, and the
complete report pipeline are not production implementations yet. Runtime
guards reject those placeholders in beta and mainnet profiles.

Merged and exact-main-verified GH-197/PR #198 adds a local Testnet-10
consistency boundary: a separately
owner-pin-hashed canonical manifest must match exactly one entry in a bounded
caller-supplied RPC-shaped RuleStorage UTXO set before GH-193 decodes the bound
constructor JSON. GH-203/PR #204 adds a development-only live adapter that
queries one connected node for exact Testnet-10 virtual DAA and UTXOs for one
explicit `kaspatest` address, converts only returned pinned-RPC fields, and then
uses the same verifier. This is a live node query, not independent proof of RPC
truth, transaction history, consensus finality, manifest authority, IPFS
availability, deployment, or production readiness.

GH-205 composes one complete owner-pinned snapshot through that injected/live
observation path, a credential-free loopback-only local IPFS gateway, exact
Raw-CIDv1 content verification, and one atomic scanner replacement. GH-207 adds
an owner-local POSIX checkpoint ordered by the minimum verified observation
virtual DAA. It rejects rollback and same-order equivocation across restarts;
exact replay restores the in-memory scanner after a crash or restart. It has no
automatic update loop or product-runtime wiring and does not prove canonical
manifest authority, independent RPC truth or finality, IPFS availability or
replication, production YARA quality, deployment, or production readiness.

**Q: Why Kaspa and not Ethereum?**
Prometheus targets Kaspa because its high-throughput BlockDAG and current
SilverScript path can anchor compact protocol state. The repository verifies
against pinned Kaspa/SilverScript versions; it does not turn network performance
or security assumptions into Prometheus production evidence.

**Q: What is the difference between Prometheus and ClamAV or Wazuh?**
Prometheus targets complementary behavioral analysis and shared rule state.
Today it does not provide production malware or unknown-threat detection. The
target stores canonical rule state and a CID on Kaspa while content lives on
IPFS; `deactivateRule` is an explicit state transition. Anchoring is tamper
evidence, not proof of content availability, replication, or universal
censorship resistance. Prometheus is intended to complement existing tools.

**Q: Can Prometheus be shut down?**
Prometheus has no repository-controlled emergency-stop entrypoint. That
contract invariant is not proof of decentralized operation. Current evidence
depends on owner-operated policy/membership files and local trust anchors; no
public multi-host protocol network is operating. Availability still depends on
Kaspa, IPFS replication, participating nodes, clients, and network access.

**Q: When will the mobile app be available?**
Desktop and mobile releases are readiness-gated rather than date-gated.
Production proof artifacts, the v2 observable path, operated networking,
security review, and core rollout evidence must pass first. Flutter remains the
mobile implementation target.

---

## Participation

**Q: Can I earn PROM today?**
No active PROM reward or emission path exists. The target allocation rewards
verified validator, Guardian, Light Client, and Honeypot contributions after
minting, consensus, anti-abuse, and deployment gates pass. Running development
software or a miner companion earns nothing.

**Q: What hardware is targeted?**
The architecture targets a 4 GB Light Client, a 24 GB VRAM Guardian 8B path,
an opt-in multi-GPU 70B escalation path, and a standard validator host with
10,000 KAS stake. These are planning requirements, not certified production
profiles. The current miner companion is only a local Testnet-10 RPC observer.

---

## AI Architecture

**Q: Does Prometheus develop its own AI model from scratch?**
No — and that would be the wrong approach. Training foundation models
from scratch costs hundreds of millions of dollars and years of time.
Prometheus takes a different path: we take the best existing
open-source models and specialize them for security work.
This is the Prometheus metaphor in practice — we take the fire
that already exists and give it to humanity in a new form.

**Q: Which AI models does Prometheus target?**
The target architecture names two locally operated model families:

Phi-3-mini 3.8B is the Light Client target. Current Rust code has no ONNX
Runtime session and uses only a development heuristic/stub, so no real-model or
real-sample detection claim is made.

LLaMA 3 8B-first with 70B escalation is the Guardian target. Hardened local
runtime configuration and evidence-capture machinery exist, but no real 8B/70B
run has been independently evaluated. Current YARA results are compile-valid
non-actionable drafts or synthetic regression evidence.

Proprietary hosted models do not expose all weights or service internals for
independent inspection. The target therefore favors locally operated,
inspectable models. Open weights alone do not prove quality, privacy,
provenance, or safe operation. No production model, malware-sample workflow,
or privacy proof is currently deployed.

**Q: How is LLaMA 3 planned to be specialized?**
LoRA fine-tuning and security-specific datasets are roadmap targets. No
repository evidence proves that an 8B or 70B model has been fine-tuned,
executed on real samples, independently evaluated, calibrated, or authorized.

Training datasets:
- VirusShare: the largest public malware database, millions of samples
- MalwareBazaar: daily updated malware samples
- Exploit-DB: complete CVE and exploit database
- CuckooSandbox reports: behavioral analysis of malware in sandboxes

Dataset licensing, provenance, handling, evaluation, and privacy review remain
required before this plan can produce a release claim.

**Q: How does the network get smarter over time?**
The target uses federated learning via a Fed-DART-inspired protocol. The current
client implementation is a development placeholder. A future flow would be:

Guardian Node A sees malware X in Germany.
Guardian Node B sees malware X in Japan.
Guardian Node C sees malware X in Brazil.

In the target architecture, none sends the malware itself. Each sends a bounded
model update. Such updates can still leak information, so production requires
clipping, secure aggregation, privacy accounting, authentication, and
validation.
A rotating coordinator selected by governed reputation would aggregate bounded
updates and distribute a candidate model.
This reduces direct record sharing; it is not an anonymity or
non-reconstruction guarantee.

No node-count, learning-rate, quality-improvement, or commercial-outperformance
claim has been demonstrated.

**Q: How is model integrity planned?**
The target anchors a model CID/hash on Kaspa and verifies downloaded IPFS bytes
before use. This can provide tamper evidence for exact content, but does not
prove model quality, upstream authenticity, authorization, availability,
replication, or censorship resistance. The distribution path is not deployed.

**Q: What exactly does Prometheus develop vs. what does it reuse?**

Reused (existing open source):
- LLaMA 3 base model (Meta)
- Phi-3-mini base model (Microsoft)
- Fed-DART federated learning protocol (Fraunhofer)
- Kaspa blockchain infrastructure (kaspanet)
- YARA rule engine (VirusTotal)

Implemented/tested foundations include contract state machines, Rust Light
Client and validator components, Python Guardian boundaries, compile-only YARA-X
validation, and bounded transport/integration tests. Fine-tuning, real model
execution, Fed-DART operation, IPFS model distribution, actionable rules, and a
complete production protocol remain planned or blocked.

This is software engineering and ML engineering — not AI research.
The distinction matters: we are not reinventing the wheel.
We are building the vehicle.
