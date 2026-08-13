# Prometheus: Decentralized AI-Powered Threat Intelligence on Kaspa

**Whitepaper v4.0 — March 2026**

**Current status reconciliation — August 2026:** The isolated H-001 Testnet-10 canary is complete: external BIP340 signing, full Kaspa transaction verification, one-shot broadcast, confirmed covenant output, `operator_record`, and independent public REST evidence pass. This non-promotable canary does not authorize Mainnet or full rollout. The rollout-capable core remains 84-88% complete and the complete roadmap vision remains 50-55% complete; production proof artifacts and independent cryptographic review, privacy-reviewed semantic/actionable analysis, six state deployments, metrics-oracle evidence, and production multi-host/node operation remain open.

The July status paragraph below is retained as a historical snapshot; its H-001 signing and broadcast statements are superseded by the current reconciliation above.

**Status update — July 2026:** Kaspa Toccata is treated as a post-fork deployment environment for Prometheus. Current Silverc compile/runtime, release-bundle, request/receipt/evidence, metrics-oracle, and exact-commit gates cover the seven contract fixtures without holding signing material. Closed profiles separate the full path from the non-promotable `testnet-10-validator-staking-h001` canary. Public funding and the deterministic schema-v2 H-001 request/digest remain verified and byte-identical; no signature or broadcast has occurred. Sprint 10B includes fail-closed 8B-first/70B escalation, complete 5+ Guardian strict-majority voting, per-session BIP340 authenticated replay-safe intake, and GH-42/GH-44/GH-48/GH-52 ballot transport, persistent identity, relay/AutoNAT operation, packaged sidecars, and explicit bootstrap routes. Merged and exact-main-verified GH-55/GH-58/GH-63/GH-74 provide the canonical bounded ThreatHint channel, owner-only durable ingress, a real manifest-pinned BN254/Arkworks Groth16 verifier aligned with active KIP-16, and the bounded analyzer-domain adapter. Merged and exact-main-verified GH-77 isolates per-job drain failures: failed jobs remain pending, later safe jobs progress, and the structurally immutable report contains only a bounded index, fixed failure category, and validated digest or `None`. Merged and exact-main-verified GH-86 adds local-only Rust/Python canonical Observable Bundle validators and one shared byte-exact corpus without wiring them into v1, proof, transport, analysis, or publication. Merged and exact-main-verified GH-114 adds isolated local canonical v2 statement parsing and digest parity while leaving relation, proof, pairing, transport, and analysis disconnected. The adapter revalidates queued canonical bytes, digest, trusted network, proof mode, and admission time, but hash-only v1 has no concrete IOC strings and therefore produces only a zero-confidence, no-rule, non-submittable result without invoking LLM or YARA generation. No approved production relation or production relation vectors, verifying key, or proving key ships yet, so unavailable verification remains fail-closed as `busy` and actionable analysis is not claimed. Real two-host relay operation, broad discovery, trusted membership/key assignment, Sybil protection, reviewed extractors/privacy gates, the reviewed v2 relation/proof/pairing/transport path and real actionable ThreatHint analysis, on-chain ensemble attestation, live model evidence, and production operation remain open. Mainnet remains gated by the explicitly approved external canary signature and evidence, remaining deployments, real oracle/sponsor signatures and successor evidence, and exact-commit rollout evidence.

**GH-90 merged and exact-main verified — July 2026:** One local Rust producer computes a single `file_sha256` observable from exact caller-supplied bytes and typed scope; Python independently validates the shared producer vectors. The API accepts no path, caller-supplied digest, or generic observable value and performs no transport. It proves deterministic function-boundary derivation only, not external file provenance, maliciousness, privacy approval, or proof binding.

**GH-94 merged and exact-main verified — July 2026:** One local Rust producer derives a bounded `byte_pattern` from exact caller-supplied bytes, a checked offset, a boolean wildcard mask, and typed scope; Python independently validates the shared producer vectors. It accepts no path or pattern string, requires at least eight fixed bytes, and always emits local-only `review_required_v1`. It does not authorize disclosure or transport and proves no external provenance, maliciousness, privacy approval, or proof binding.

**GH-103 merged and exact-main verified — July 2026:** One local Rust producer derives a single `api_import` from exact caller-supplied Linux ELF bytes and a checked index. The pinned parser is read-only and bounded to 16 MiB plus 4096 dynamic symbols; scope is derived as `linux`/`elf`, names must satisfy the closed ASCII grammar, and sorting/deduplication is deterministic. The API accepts no path, import string, platform, format, or generic observable value. Every output is local-only `review_required_v1`, and Python independently parses the shared exact-byte ELF vectors. This does not prove external provenance or authorize disclosure, transport, proof acceptance, analysis, or publication.

**GH-121 merged and exact-main verified — July 2026:** One isolated Rust producer derives a checked `api_import` from exact caller-supplied PE32 or PE32+ bytes. Scope is fixed to `windows`/`pe`; parsing is bounded to 16 MiB, 4096 import descriptors, and 4096 thunk entries; ordinal and grammar-invalid imports fail closed; named functions are byte-sorted and deduplicated before selection. Rust covers both PE architectures, while Python independently parses the synthetic shared PE32+ vector. Library names never become observables and every output remains local-only `review_required_v1`. No path/string/generic, transport, proof, analyzer, wallet, chain, or promotion behavior is added. Protected PR #122 is merged as exact-main `2e3e1e1`; CI, Security, and Pages pass on that SHA.

**GH-107 merged and exact-main verified — July 2026:** Rust and Python locally verify one canonical, short-lived BIP340 approval statement over one exact `review_required_v1` bundle. Verification is bound to a separately trusted approver key, recipient-scope digest, network, report nonce, and separately trusted current time that must never be attacker-controlled; it recomputes the observable commitment and caps inclusive validity at one hour. The shared vector contains only public material. No signer, transport, persistence, promotion, disclosure, analyzer, proof, wallet, or chain action is added. The nonce and deterministic approval ID identify repeats but do not prevent replay; durable one-time consumption and trusted authority/policy management remain open.

**GH-111 merged and exact-main verified — local durable approval consumption, July 2026:** Guardian Node now loads one fixed network, approver public key, and opaque recipient-scope digest from an owner-only exact-schema policy, invokes the GH-107 verifier in the same trusted call path, and atomically consumes both the approval ID and authority-bound nonce in a separate owner-only SQLite ledger. Full synchronous durability, a persistent clock high-water, and restart/concurrency/lock handling close local replay without accepting caller-supplied verified objects. The resulting receipt has no external authority or side effect. Key ownership and rotation, scope semantics, privacy approval, verified hint/bundle pairing, promotion, transport, analyzer, outbox, proof, wallet, and chain behavior remain open.

**Merged and exact-main-verified GH-114 local canonical ThreatHint v2 statement, July 2026:** Independent Rust and Python parsers enforce one exact canonical statement containing schema version 2, separate artifact hash and observable commitment, confidence, structural disclosure class, report nonce, positive observed time, and a network that must match separately trusted local context. The wire is capped at 1024 bytes and every field is bound by a new length-prefixed, domain-separated digest. Shared exact-byte valid/invalid vectors prove parser parity only. No relation, proof, signer, pairing, transport, approval, replay authority, analyzer, wallet, or chain path consumes this statement, and it proves no artifact derivation, report truth, maliciousness, privacy safety, authorization, or anonymity.

**Merged and exact-main-verified GH-117 ThreatHint v2 proof binding, July 2026 (not production-deployed):** A bounded canonical opaque-proof envelope, a strict 19-field `RelationManifest-v2`, and one atomic Rust/Python binding now consume shared adversarial corpora. The binding first validates a separately trusted network and nonzero lowercase manifest SHA-256, hashes the exact raw manifest bytes before parsing, reparses both canonical wires, closes protocol, relation, network, statement-domain, and public-input identities, and derives two claimed 16-byte big-endian halves from the statement digest. These are structural compatibility checks and claimed inputs only. No Groth16 proof is verified, no source or key artifact is loaded or approved, and no ceremony, signer, transport, analyzer, promotion, wallet, chain, reputation, KAS/PROM, slash, commit-reveal, or rollout authority is added.

**Merged and exact-main-verified GH-117 ThreatHint v2 Groth16 verifier, July 2026 (not production-deployed):** A separate Rust `verify-v2` boundary owner-loads exact canonical manifest bytes and fixed sibling relation-source/verifying-key files, verifies their manifest-declared sizes and SHA-256 anchors, requires canonical compressed BN254 keys and proofs, derives both field inputs only from the reviewed v2 binding, and performs real Arkworks Groth16 verification. Runtime resolves no proving-key file and the CLI is silent with distinct valid, invalid, syntax, and unavailable exits. Deterministic setup, keys, proofs, and relation source in tests are non-production fixtures. This provides no production relation, artifact or ceremony approval, privacy/disclosure authority, approval consumption, transport, chain action, or rollout evidence.

**Merged and exact-main-verified GH-117 ThreatHint v2 privacy/proof preflight, July 2026 (not production-deployed):** One owner-only exact-schema policy pins the network, BIP340 approver key, opaque recipient-scope digest, and nonzero raw-manifest SHA-256. Guardian Node binds the envelope and manifest against that policy, derives the statement only from the bound envelope, requires `review_required_v1`, recomputes the exact bundle commitment against the same trusted report nonce, and verifies the canonical short-lived approval in the same call. The data-only receipt contains hashes and identifiers only. This preflight verifies no Groth16 proof, consumes no approval, opens or migrates no ledger, and authorizes no privacy, disclosure, transport, analysis, promotion, wallet, chain, reputation, KAS/PROM, slash, commit-reveal, or rollout action. A future durable acceptance path must run approved v2 proof verification first and commit approval consumption only as its final atomic step.

**Merged and exact-main-verified GH-117 ThreatHint v2 verified-preflight composition, July 2026 (not production-deployed):** A separate POSIX-only Guardian service pins one absolute verifier executable by owner-only configuration and exact SHA-256, reads the policy-anchored manifest itself, runs the existing approval/privacy preflight first, and passes the same exact envelope bytes to the silent Rust `verify-v2` process. Invocation is shell-free, environment-scrubbed, time-bounded, process-group-cleaned, and fail-closed; one service instance rejects overlapping calls. Its non-constructible, non-serializable receipt is data only. This layer deliberately opens no SQLite ledger and consumes no approval; the separate merged atomic-acceptance boundary below adds that final mechanical step. Neither layer provides production relation/key/ceremony approval, privacy/disclosure authority, transport, analysis, promotion, wallet, chain, reputation, KAS/PROM, slash, commit-reveal, or rollout evidence.

**Merged and exact-main-verified GH-117 ThreatHint v2 atomic acceptance, July 2026 (not production-deployed):** A raw-input-only Guardian service now requires exact network, approver-key, and recipient-scope identity across the preflight and consumption policies before ledger creation. Each call runs the verified proof/privacy preflight first, then re-verifies the raw approval and bundle and binds the expected approval ID and observable commitment before the existing SQLite consume is allowed to commit as the final state-changing step. Failed proof/privacy checks leave approval count and time high-water unchanged; invalid, unavailable, replay, and busy are stable redacted outcomes. The returned receipt is non-constructible, non-serializable data only. This closes the local mechanical verify-plus-consume path but does not approve production relation/key/ceremony artifacts, establish privacy or disclosure authority, trigger transport or analysis, sign or broadcast a transaction, alter KAS/PROM, reputation, slash or commit-reveal behavior, or prove rollout readiness.

**Merged and exact-main-verified GH-117 ThreatHint v2 owner-policy promotion, July 2026 (not production-deployed):** A separate raw-input-only Guardian boundary owner-loads an exact-schema policy and requires review-required disclosure, exact platform and format, allowed observable kinds, and a bounded count before forwarding the same original envelope, bundle, and approval bytes into atomic acceptance. The owner file is read through a no-follow, descriptor-identity-checked, bounded path. Policy rejection never reaches the proof verifier or approval ledger. Success returns only frozen local data with accepted IDs/time, the pinned scope, and canonical observable string pairs. This is mechanical owner-policy pairing and restriction, not semantic privacy review, authority/key governance, production relation/key/ceremony approval, transport, analysis, publication, an external effect, chain authority, or rollout evidence.

**Merged and exact-main-verified GH-117 ThreatHint v2 enforceable governance, July 2026 (not production-deployed):** An owner-only exact policy now fixes the network, approver, recipient scope, authority epoch/window, same-Guardian local-analysis semantics, denied external disclosure, and one deny-or-kind-specific-risk decision for every closed observable kind. Its allowed set must exactly match promotion and retention before ledger access. The first valid governed acceptance atomically pins all three exact policy-file digests and authority state with high-water and approval consumption; lower epochs, same-epoch equivocation, overlapping same-identity windows, hidden legacy state, replay, and failed inserts change no durable state. This grants no analyzer execution, worker, transport, publication, chain action, or production artifact approval.

**Merged and exact-main-verified GH-117 ThreatHint v2 durable analysis substrate, July 2026 (not production-deployed):** Governed schema v4 atomically stores the canonical statement/digest, trusted report nonce, full Observable Bundle, approval binding, authority state, replay high-water, and retention. Claims revalidate the owner-network statement and nonce-bound bundle commitment and derive a lease-bound input identity. Atomic completion stores one canonical explicitly non-actionable local result before removing work; exact retries recover safely after a committed-but-unreturned completion. Empty schema-v3 queues migrate, while nonempty v3 queues fail closed unchanged because their missing nonce and statement are unrecoverable. The bounded worker contains only a deterministic test analyzer and emits no confidence, `should_submit`, YARA/rule body, semantic finding, transport, disclosure, wallet, signature, transaction, chain, deployment, reward, or external effect.

**Merged and exact-main-verified GH-152 governed ThreatHint v2 permanent identity pairing, August 2026 (not production-deployed):** Governed schema v5 adds one durable strict table that uniquely binds the exact statement digest, approval ID, and observable commitment inside the existing atomic promotion transaction. A fresh approval cannot rebind an accepted statement or commitment, and retention of outbox work or completed results cannot reopen that replay surface. A v4 ledger migrates only when its outbox and result tables are empty; authority, replay high-water, and approval-consumption state are preserved. Any retained v4 outbox or result row fails closed unchanged. PR #153 published exact main `3d203aa`; Prometheus CI `31306353671`, Security Audit `31306353670`, and Pages `31306353328` pass. This per-ledger mechanical replay boundary does not extend proof, privacy, analysis, transport, publication, wallet, chain, token, deployment, or production authority.

**GH-170 merged and exact-main verified - bounded YARA-X structural validation, August 2026 (not production-deployed):** Generated candidate rules are compiled in memory with the exact official `yara-x==1.4.0` binding instead of being accepted by substring shape checks. The boundary admits exactly one size- and name-bounded ASCII rule, disables includes, rejects imports/modules, multiple rules, NUL input, and every compiler error or warning, then discards the compiled object without scanning. PR #171 published exact main `8d8e29c`; Prometheus CI `31650123073`, Security Audit `31650123055`, and Pages `31650122593` pass. This validates structure only. It proves no semantic detection quality, privacy safety, model integrity, production calibration, submission eligibility, or publication authority.

**GH-173 merged and exact-main verified - deterministic non-actionable semantic draft, August 2026 (not production-deployed):** One optional governed-worker analyzer deterministically derives a bounded YARA draft from already approved local `api_import` and `byte_pattern` observables, validates it only through the compile-only GH-170 boundary, and atomically stores a schema-v2 result containing exact input bindings, per-kind counts, a nonce-bound candidate-binding SHA-256, and compile status. The source remains memory-only; `file_sha256` values are count-only. Existing schema-v1 results remain readable. PR #174 published exact main `1107b11`; Prometheus CI `31654308969`, Security Audit `31654308964`, and Pages `31654308875` pass. No model, confidence, `should_submit`, scan, disclosure, publication, wallet, chain, reward, deployment, or production authority is introduced; semantic quality, adversarial detection evidence, actionable-rule review, and production calibration remain open.

**GH-177 merged and exact-main verified - isolated synthetic YARA semantic-quality evidence, August 2026 (not production-deployed):** A standalone evaluator uses the pinned YARA-X scan API only against 20 bounded in-memory buffers reconstructed from a closed deterministic synthetic recipe. One fixed GH-173-shaped rule and a strict development policy produce a canonical report bound to exact corpus, policy, evaluator bytes, engine version, rule digest, confusion counts, and precision/recall/specificity. The baseline has 10 true positives, 10 true negatives, and no false result. Authority is exactly `none`; no governed worker, outbox, result taxonomy, model, transport, disclosure, submission, wallet, chain, reward, deployment, or production path imports the evaluator. This is synthetic regression evidence only, not real-world semantic quality, privacy approval, actionable analysis, calibration, certification, or production authority. PR #178 merged as exact main `396d347`; CI, Security Audit, and Pages pass on that SHA.

**GH-180 merged and exact-main verified - deterministic offline ThreatHint-v2 pipeline integration evidence, August 2026 (not production-deployed):** Eight development-only POSIX integration cases compose existing production classes from canonical synthetic transport bytes through real Python ingress, governed promotion, schema-v5 atomic acceptance/outbox, bounded worker, and the durable GH-173 non-actionable semantic-draft result. Exact identity/binding relationships, malformed and oversized rejection, replay and restart, concurrent duplicates, lease recovery, redacted analyzer failure, and transactional completion rollback are covered. GH-177 remains structurally isolated, and no runtime authority path is added. Local evidence includes 171 adjacent tests; 1303 Guardian tests passed and 4 intentional live-model tests skipped. PR #181 merged as exact main `a28ad00`; Prometheus CI `31662874366`, Security Audit `31662874399`, and Pages `31662873670` pass on that SHA. This is composition regression evidence only, not a real sample, public network, model execution, scan, privacy approval, actionable analysis, deployment, or production certification.

**GH-155 merged and exact-main verified - Guardian sidecar test reliability, August 2026:** Process integration coverage now serializes shared process cases, retains bounded diagnostics, coordinates collector EOF/ACK shutdown, holds the relay-port reservation until spawn, and proves deterministic kill and reap of a real child on timeout. PR #156 published exact main `db33f56`; Prometheus CI `31308756777`, Security Audit `31308756786`, and Pages `31308756387` pass after 20 consecutive stress runs and complete review. This is test-infrastructure evidence only. It changes no protocol or production behavior and does not advance H-001, core-rollout, or roadmap percentages.

**Merged and exact-main-verified GH-167 bounded ThreatHint v2 transport substrate, August 2026 (not production-deployed):** Rust and Python share one exact canonical transport frame and valid/invalid corpus for the v2 proof envelope, Observable Bundle, approval wire, and untrusted report-nonce lookup key. The independent `/prometheus/threat-hint/2.0.0` libp2p channel reparses each frame against an explicit trusted local network before owner-only IPC. Guardian reparses the original wires, resolves nonce and time only from trusted local session state, and calls the existing governed promotion boundary. Shared admission budgets, strict accepted/rejected/busy acknowledgements, adversarial tests, and separate-process same-host evidence pass. PR #168 published exact main `7c62608`; Prometheus CI `31645624623`, Security Audit `31645624601`, and Pages `31645623547` pass. This closes repository transport only: production proof artifacts, semantic/actionable analysis, disclosure, operated public multi-host evidence, models/YARA, wallet, chain, rewards, and deployment remain gated.

**Keyless operator update — August 2026:** The repository contains `prometheus-silverc-deployer`, pinned to official `rusty-kaspa` v2.0.1 and the exact Silverc source compiler revision. Its covenant-genesis path constructs transaction version 1 with compute budget 10 and the exact contextual `storage_mass` commitment, derives the official covenant ID, validates the exact live unspent funding UTXO during preflight and immediately before broadcast, and models the final 66-byte Schnorr signature script before exporting the 32-byte `SIG_HASH_ALL` digest. Signing-request schema v2 binds compute, transient, storage, normalized noncontextual/overall mass, the pinned relay rate, and both relay and conservative operator fee floors. The `reportMetrics` path recompiles exact predecessor and successor state, preserves the covenant value, uses a separate P2PK fee sponsor, derives two `SIG_HASH_ALL` digests, verifies both external BIP340 signatures plus every covenant/P2PK input, and revalidates both UTXOs before guarded broadcast. Both paths reject normalized input/output collisions, persist exclusive intent before acknowledged submission, reconcile retry state by exact transaction ID, enforce wRPC deadlines, and rebuild verified transactions before observation. The Rust package has 50 unit/security tests, including 11 focused metrics-transition tests and exact-ID v2.0.1 remote mempool-absence coverage. No private-key, seed, wallet, keystore, or raw-transaction input exists. The H-001 canary completed this path on Testnet-10 and produced confirmed public evidence; the real metrics transition, six state deployments, and full release gates remain separate.

The deploy capability gate and repository operator both bind the official SilverScript covenant-genesis profile: transaction version 1, `pay_to_script_hash_script` over the compiled contract script, covenant-ID derivation from the funding outpoint and unbound genesis output, and `CovenantBinding` only after the ID is derived. The repository assembles, verifies, broadcasts, and observes public transactions but delegates all signing to an external vault/HSM and never accepts key material. The current official PSKT/PSKB implementation is not used because its audited v1 path still constructs legacy sigop-count input commitments instead of Toccata compute-budget commitments.

*The fire belongs to humanity, not to corporations.*

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [Architecture](#4-architecture)
5. [Token Design](#5-token-design)
6. [Validator System](#6-validator-system)
7. [Guardian System](#7-guardian-system)
8. [Light Client](#8-light-client)
9. [Voting Mechanism](#9-voting-mechanism)
10. [Rule Storage](#10-rule-storage)
11. [Federated Learning](#11-federated-learning)
12. [Governance Auto-Tuning](#12-governance-auto-tuning)
13. [Security Analysis](#13-security-analysis)
14. [Developer Incentive Pool](#14-developer-incentive-pool)
15. [Roadmap](#15-roadmap)
16. [Audit Findings and Resolutions](#16-audit-findings-and-resolutions)

---

## 1. Abstract

Prometheus is a fully decentralized, AI-powered threat intelligence protocol built on the Kaspa blockchain. It transforms every connected device into a node in a global threat detection swarm — without central control, without a foundation, and with zero pre-mined tokens.

The protocol combines three layers:
- **On-device AI** (Phi-3-mini 3.8B, 4-bit quantized) for local anomaly detection
- **Guardian nodes** (LLaMA 3 70B/8B) for advanced threat analysis and YARA rule generation
- **Kaspa L1 consensus** (high-throughput BlockDAG / DAGKnight path) for immutable rule storage and governance

Key properties: 0% pre-mine, no emergency stop, automated governance target,
and data-minimal on-chain state. Applicable privacy obligations depend on the
deployed data flows and jurisdiction; this whitepaper is not a legal
determination.

---

## 2. Problem Statement

Current cybersecurity infrastructure suffers from three fundamental flaws:

1. **Centralization**: Threat databases are controlled by a handful of corporations (VirusTotal, CrowdStrike). A single compromise or policy change can blind millions of devices.
2. **Latency**: New threats take hours to days to propagate through signature databases. Zero-day exploits like Pegasus and Predator operate undetected during this window.
3. **Misaligned Incentives**: Security vendors profit from fear, not from prevention. There is no economic incentive for collaborative, open threat intelligence.

Prometheus eliminates all three by creating a permissionless, self-governing threat intelligence network where contributors are rewarded for accuracy and speed.

---

## 3. Solution Overview

```
Light Client (Phi-3-mini)          Guardian (LLaMA 3)           Kaspa L1
 - Local file scanning              - Threat analysis            - Rule state anchoring
 - Anomaly detection                - YARA rule generation       - Validator consensus
 - ZK-proof threat hints            - Proposal submission        - Governance auto-tuning
 - Rule updates from L1             - L1 reputation tracking     - Developer grants
```

**Target Threat Lifecycle (< 60 seconds after all rollout gates pass):**
1. Light Client detects anomaly via Phi-3-mini + YARA rules
2. Data-minimal threat hint submitted with an approved ZK proof
3. Guardian node analyzes threat, generates YARA rule
4. Validators vote via Commit-Reveal (2/3 majority required)
5. Accepted rule state anchored on-chain; PROM-RULES asset representation remains deployment orchestration
6. All light clients receive and load the new rule

The current verified v1 path stops before step 3: it transports a
caller-supplied hash commitment and bounded metadata but no concrete IOC. It
therefore returns zero confidence, no rule, and no submission. V1 does not
derive the hash from an artifact or prove report truth, artifact derivation, or
reporter anonymity. GH-82's [Threat Observable v2 draft](docs/threat-observable-v2.md)
defines the separate artifact hash and observable commitment. Merged and exact-main-verified GH-86 implements
isolated Rust and Python canonical bundle validators against one shared
byte-exact corpus. Merged and exact-main-verified GH-90 adds one local Rust producer that
computes a single `file_sha256` observable from exact caller-supplied bytes and
typed scope; Python independently validates the shared producer vectors. This
proves only deterministic derivation at that function boundary, not that the
bytes came from a real file, are malicious or privacy-approved, or are bound by
a proof. Merged and exact-main-verified GH-94 additionally derives one bounded byte pattern from an exact
artifact-byte selection and boolean wildcard mask. It is always local-only
`review_required_v1`; no transport or privacy approval follows from successful
construction. None of these slices is connected to v1 transport, proof
verification, Guardian analysis, or rule publication. Reviewed privacy gates,
remaining platform/format extractors, a reviewed v2 relation and approved proof
artifacts, owner-only pairing, transport, and actionable analysis remain
required. GH-114 supplies only the isolated local canonical v2 statement parser
and digest parity; it does not satisfy those promotion gates.

Merged and exact-main-verified GH-103 adds one further local-only producer for
Linux ELF `api_import` values.
It parses exact caller-supplied bytes through a pinned read-only parser, derives
the scope internally, bounds both artifact size and dynamic-symbol count,
sorts and deduplicates grammar-valid imports, and selects one checked index.
Every output is `review_required_v1`; no arbitrary import string or path API,
transport authorization, external provenance, privacy approval, or proof
binding is introduced.

Merged and exact-main-verified GH-121 applies the same deny-by-default boundary
to PE32 and PE32+ import tables. It derives `windows`/`pe` internally, bounds
artifact size, import-descriptor count, and thunk-entry count, rejects ordinal or grammar-invalid
imports, and selects only after exact byte sorting and deduplication. Library
names never become observables. The synthetic shared PE32+ vector is parsed
independently by Python and Rust also exercises PE32-specific thunk and ordinal
handling. Every output remains `review_required_v1`. The producer is merged
but not deployed or authorized for transport, proof, analysis, publication,
wallet, or chain use.

Merged and exact-main-verified GH-107 adds a local authenticated-statement boundary for these
mandatory-review bundles. Both implementations require exact canonical JSON,
recompute the bundle commitment from trusted context, require separately
trusted current time that must never be attacker-controlled, enforce a one-hour
inclusive validity window, and verify the same domain-separated BIP340 digest.
Successful verification is not disclosure authorization and triggers no
transport, analysis, publication, proof, wallet, or chain side effect. No
approver registry exists yet. GH-111 separately adds fixed-policy local durable
one-time consumption, while authority rotation, scope semantics, enforceable
privacy governance, and network/analyzer promotion remain blocked.

---

## 4. Architecture

### 4.1 Blockchain Layer (Kaspa L1)

- **Network**: Kaspa with Silverscript smart contracts
- **Testnet**: `testnet-10`, the Toccata profile supported by pinned `rusty-kaspa` v2.0.1; `testnet-12` is rejected because that release provides no matching consensus parameters
- **Compiler and deployer**: current Silverc gates pass for H-001 and all six state fixtures. The repository keyless Toccata-v1 operator closes genesis plus value-preserving `reportMetrics` transaction assembly/broadcast without accepting signing keys; its TLS-only official resolver probe confirms live testnet-10 Toccata/node readiness without replacing exact UTXO preflights. The isolated H-001 canary is confirmed and independently evidenced; the six remaining state deployments, metrics-oracle signatures and successor evidence, and exact-commit release evidence still gate rollout.
- **Consensus**: high-throughput Kaspa BlockDAG / DAGKnight path
- **Contracts**: 6 Silverscript contracts (see Section 10)

### 4.2 P2P Layer

- **Implemented Guardian protocol**: direct QUIC request/response at `/prometheus/guardian-ballot/1.0.0`, carrying one exact canonical signed ballot of at most 8192 bytes and returning a one-byte status without echoing the ballot
- **Resource boundary**: explicit global request, per-connection stream, connection, frame, and timeout limits; invalid or overloaded input fails before Guardian authorization
- **Local trust boundary**: an owner-only AF_UNIX bridge binds each collector ACK to the exact ballot digest; the existing BIP340/session/freshness/replay verifier remains authoritative
- **Connectivity**: strict bounded IP/UDP/QUIC-v1 direct, relay-circuit, explicit AutoNAT-server routes, and relay-only canonical advertised bootstrap routes are implemented without DNS. The GH-44 isolated three-node harness proves relay reservation/delivery, AutoNAT state, DCUtR relay fallback, and disconnect handling; real two-host relay/NAT operation is not yet proven. mDNS remains excluded because the compatible optional DNS dependency currently carries unresolved RustSec advisories
- **Operated service**: merged GH-48 exposes strict `preflight`, `run`, and `submit` commands for Guardian and relay roles, bounded newline-delimited JSON output, owner-only local submission, and bounded signal shutdown; three process tests cover same-host relay delivery, collector-wait termination, and broken output
- **Target convention**: port 16420 remains the deployment convention, but the carrier accepts explicit multiaddresses and does not hard-code a production listener

### 4.3 Off-Chain Layer

- **Light Client AI**: Phi-3-mini 3.8B (4-bit quantized, 4GB RAM, no GPU)
- **Guardian AI**: LLaMA 3 8B (default) / LLaMA 3 70B (confidence escalation)
- **Federated Learning target**: Fed-DART with local training records and bounded model updates; gradients still require privacy controls

---

## 5. Token Design

### 5.1 Dual Token Architecture

| Token | Purpose | Mechanism |
|-------|---------|-----------|
| **KAS** | Validator staking | Native Kaspa token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Rewards & Governance | Earned through accepted proposals. Never staked by validators. 0% pre-mine. |

**Critical rule**: Validators stake KAS, never PROM. PROM is exclusively earned through contribution.

### 5.2 Tokenomics (Annual Emission)

| Recipient | Share | Year 1 |
|-----------|-------|--------|
| Validators | 40% | 8,000,000 PROM |
| Guardians | 30% | 6,000,000 PROM |
| Reporters (Light Clients) | 15% | 3,000,000 PROM |
| Reporters (Honeypot) | 5% | 1,000,000 PROM |
| Dev Pool | 5% | 1,000,000 PROM |
| Community | 5% | 1,000,000 PROM |
| **Total** | **100%** | **20,000,000 PROM** |

Reporter percentages are protocol allocation targets, not passive uptime rewards. A miner-side companion receives no PROM merely for running; rewards require a future implementation and consensus-verified contribution path.

No foundation allocation. No founder tokens. No pre-mine. Identical to Kaspa's launch philosophy.

---

## 6. Validator System

Validators secure the network by staking KAS and voting on threat proposals.

### 6.1 Registration

- Minimum stake: `MIN_STAKE_KAS = 10,000 KAS`
- `tx.value` = KAS (native token via transaction value)
- Reputation starts at 1.0 (stored as `uint64 = 10000` with 10000x scaling)

### 6.2 Slashing

Non-recursive implementation (Architect-approved V-003):

```
multiplier = min(3, slashing_count / 3 + 1)
penalty = min(stake * percent * multiplier / 100, stake)
if remaining_stake < MIN_STAKE_KAS: deactivate validator
```

| Offense | Base Penalty | Max (3x escalation) |
|---------|-------------|---------------------|
| Simple misbehavior | 5% | 15% |
| Double voting | 10% | 30% |
| Proven collusion | 20% | 60% |

**Access control**: Only `GOVERNANCE_CONTRACT` or `RULE_STORAGE_CONTRACT` can call `slash()`.

### 6.3 Withdrawal

7-day cooldown enforced via `COOLDOWN_BLOCKS = 100,800` (~7 days at 10 BPS).

---

## 7. Guardian System

Guardians run LLaMA 3 models to analyze threats and generate YARA rules.

### 7.1 Registration

- PoW difficulty scales with current guardian count (anti-Sybil)
- Minimum compute: `MIN_COMPUTE_GFLOPS = 100`
- Model eligibility: >= 500 GFLOPS may serve 70B escalation; all hybrid routes start with 8B

### 7.2 Reputation

- Stored as `uint64` with 10000x scaling (not float64 — Architect decision Q-002)
- Starting reputation: 0.1 (`REPUTATION_START = 1000`)
- On accepted proposal: `reputation += isqrt(compute_power_gflops) * 100` at 10000x fixed-point scale
- On rejected proposal: `reputation *= 0.5`; if below `MIN_REPUTATION (1000)`: set to 0

Guardian reputation is canonical Kaspa L1 state in `GuardianReputationState`.
It is separate from PROM balances and is not a badge or NFT.

### 7.3 Voting Power (Quadratic)

```
power = (reputation / 100)^2 * compute_power / 1000
```

Quadratic voting (Architecture Decision #14) provides mathematical Sybil resistance: 1 real guardian with reputation 1.0 and 500 GFLOPS has power 5000, while 100 fake guardians with reputation 0.1 and 100 GFLOPS have total power 1000. The attacker needs 500+ accounts to match 1 legitimate guardian.

### 7.4 Hybrid Analysis Routing

The implemented Sprint 10B router invokes an injected 8B analyzer first and
escalates to an independent 70B analyzer only when the primary confidence is
below `0.70` or the primary safety envelope is invalid. The exact `0.70`
boundary remains on the 8B route. Threat-hash mismatches, non-finite or
out-of-range confidence, malformed submission decisions, and failed or invalid
70B output fail closed with no submittable rule. The existing minimum network
submission confidence remains `0.85`.

The local YARA generator now requests source confidence in a separate bounded
model call and accepts exactly one closed JSON object with integer
`confidence_bps` in `0..10000`. Duplicate, missing, extra, non-integer, or
out-of-range fields and malformed completion envelopes fail closed. Indicator
count and YARA text shape no longer determine confidence, and the accepted
basis-point value is preserved through the ensemble path without conversion
through a float.

GH-138 adds a separate deterministic development evaluator around this
boundary. A canonical 24-case synthetic YARA corpus, exact integer-bps
predictions, fixed policy, expected report, and co-versioned manifest are
internally consistency-checked by SHA-256. The byte-exact report measures the
unchanged `8500`-bps confusion matrix, exact-ratio precision and recall, Brier
score, and fixed ten-bin expected calibration error. Missing, duplicate,
reordered, noncanonical, weakened-policy, or internally hash-inconsistent
evidence fails closed. This detects partial fixture drift within a reviewed
revision. It is neither signed nor externally anchored, so it does not provide
independent tamper evidence.

This is synthetic offline evaluation only. The report explicitly records no
production authority and invokes no model, network, telemetry, YARA engine,
transport, wallet, or chain component. It validates the evaluation machinery,
not live 8B/70B semantic accuracy, real adversarial robustness, production
calibration, P2P delivery, or authorization; those gates remain open.

Merged and exact-main-verified GH-141 adds the next non-authorizing boundary: a
local candidate runner sends the same cases only to a literal-loopback vLLM
service with environment proxies disabled, records one closed-schema score per
case, and atomically creates a canonical owner-only prediction set. Corpus
bytes, public served-model ID,
caller-supplied model-artifact digest, and a pinned repository prompt
specification are bound into the evidence. A separate offline mode recomputes
the exact metrics as `local_model_candidate_only` and always records
`production_authorized=false`. No live model run or result is committed. The
tool does not independently prove the supplied artifact digest, semantic
accuracy, prompt-injection robustness, production calibration, or authority.

Protected PR #142 squash-merged normally without bypass as exact main
`bf3f74f`; Prometheus CI `30727224584`, Security Audit `30727224572`, and Pages
`30727224235` pass on that SHA.

Merged and exact-main-verified GH-144 hardens the local serving boundary
without claiming a model run. Its official vLLM image is pinned by release and registry
digest; 8B and opt-in 70B services publish only to literal host loopback, use
caller-provisioned read-only weights in forced offline mode, and run non-root
on an internal network with bounded processes, memory, shared memory, writable
temporary space, and logs. A structured repository gate rejects mutable images,
remote or writable model sources, unsafe ports, privileges, secrets, missing
resource limits, and profile/GPU drift. No image or model is downloaded, no
inference is executed, and no artifact provenance, semantic quality,
calibration, or production authority is established.

Protected PR #145 squash-merged normally without bypass as exact main
`95d05cc`; Prometheus CI `30858991436`, Security Audit `30858991557`, and
GitHub Pages `30858990507` pass on that SHA.

### 7.5 Local Guardian Ensemble Vote

The Sprint 10B ensemble validator commits the protocol version, threat hash,
exact YARA bytes and metadata, source-rule confidence in integer basis points,
policy hash, and pinned 8B model artifact into a domain-separated candidate
digest. An immutable snapshot commits at least five unique canonical Guardian
IDs, the 8B artifact, and a public membership-source digest. Every configured
member must provide exactly one fully bound vote. Approvals require at least
`8500` basis points, a complete ballot must reach a strict majority, and final
confidence is the minimum of the source rule and all approving votes. Missing,
duplicate, unknown, malformed, mismatched, tied, or below-policy input returns
no submittable rule.

The original ensemble decision remains a side-effect-free local pre-submission
gate. The GH-39 intake adds a separate per-candidate/network session that binds
each Guardian ID to one exact BIP340 x-only public key. Its strict canonical
envelope commits the complete domain vote, session and network IDs, nonce, and
validity window. Public signatures are verified before an owner-only SQLite
ledger atomically consumes one vote per member and one nonce per active
session; persisted envelopes are reverified before `EnsembleVoter` receives
them. Replay and equivocation markers survive restart and concurrent intake.

GH-42 adds a real transport-only Guardian carrier. Merged GH-44 extends it with
atomic owner-only persistent Ed25519 transport identity, strict bounded
direct/relay/AutoNAT routes, data-minimal health events, and a bounded relay
service. Merged and exact-main-verified GH-48 packages those APIs as strict
Guardian and relay processes with owner-only submission, bounded JSON output,
and graceful signal drain. Merged and exact-main-verified GH-52 separates relay bind listeners from explicit
canonical advertised IP/UDP/QUIC bootstrap routes and emits path-free routes
bound to the persistent transport `PeerId`. The isolated three-node harness proves relay
reservation, relay-only ballot/ACK delivery, AutoNAT state, DCUtR failure with
relay fallback, and disconnect handling; separate same-host processes prove
exact ballot/ACK delivery and socket cleanup. A libp2p `PeerId`, static address,
relay, or discovered route cannot assign a Guardian ID or bypass the existing
BIP340 verifier.

Merged and exact-main-verified GH-147 defines the source behind that snapshot
and signer mapping. One exact schema-v1, network-bound and epoch-labelled
canonical JSON
document binds 5–1024 sorted unique Guardian IDs one-to-one to
structurally valid public BIP340 x-only keys, fixed `8b` model tier, and model
artifact digests. The SHA-256 is computed over the exact source bytes. Parsing
rejects malformed, duplicate, missing, extra, reordered, noncanonical,
shared-key, and wrong-network input; a POSIX-only loader additionally requires
an owner-only, no-symlink, bounded, descriptor-verified file. The validated
source derives the existing snapshot and signer types without changing them.

This proves local structural and key-assignment consistency only. It does not
establish who may author or trust the source, prove key ownership or rotation,
prove real two-host relay/NAT operation or broad discovery, prevent Sybil
identities, submit a proposal, or prove an ensemble on Kaspa L1. No production
private-key or signing API is included. Those remain production protocol and
deployment gates.

Protected PR #148 passed all eleven final contexts with all review threads
resolved and squash-merged normally without bypass as exact main `aeecffb`.
Prometheus CI `30863940497`, Security Audit `30863940502`, and GitHub Pages
`30863940053` pass on that SHA.

---

## 8. Light Client

This section describes the target Light Client architecture. The current Rust client contains development implementations and fail-closed runtime guards: beta/mainnet reject the Phi-3 heuristic, SHA-256 ZK placeholder, cached rule reader, and federated-learning placeholder. These components must not be presented as a production threat-reporting pipeline.

### 8.1 Phi-3-mini Integration

- Model: Phi-3-mini 3.8B, 4-bit quantized (Architecture Decision #8)
- Runtime: ONNX Runtime (ort crate when available)
- Requirements: 4 GB RAM, no GPU
- Current implementation: development-only heuristic/stub; real ONNX inference remains open

### 8.2 YARA Scanner

- Pattern-based file scanning with custom matcher
- Rules loaded from canonical L1 rule state; PROM-RULES asset representation is a deployment target
- SHA-256 file hashing for threat identification
- EICAR test standard for validation

### 8.3 ZK Proofs

- Target: data-minimal threat reporting with precisely scoped Groth16 claims
- Active KIP-16 / BN254 Arkworks Groth16 verification is implemented in the manifest-pinned `prometheus-threat-proof` engine
- The v1 statement domain/network-binds schema version, caller-supplied `threat_hash`, confidence, indicator category, nonce, and timestamp into two injective 128-bit BN254 public inputs; `proof_system` is separately restricted to `groth16_kip16_v1`
- V1 does not specify how `threat_hash` is derived. Matching separately revealed bytes to a commitment would prove consistency only, not truth, maliciousness, or artifact derivation
- No production relation, verifying key, proving key, or independently approved vectors ship yet; operated verification therefore remains fail-closed `busy`
- The manifest SHA-256 is the runtime trust anchor; its relation-source hash is attested metadata that must be independently checked during artifact approval

### 8.4 Experimental Miner Companion

The first miner-facing integration is an opt-in sidecar in `prometheus-client`. It reads health data from an explicitly configured, credential-free local Testnet-10 wRPC endpoint. [Kaspa ASICs and pool miners normally use Stratum](https://wiki.kaspa.org/mining), which is a separate protocol; the companion does not intercept or reuse a Stratum connection and does not modify miner firmware.

The current companion is a development-only RPC observer. Its strict TOML profile rejects remote endpoints, embedded credentials, scanning, reporting, validator operation, honeypot operation, and unknown reward or wallet fields. It starts no host scan and transmits no miner telemetry. Production scanning/reporting requires real Phi-3 inference, real ZK proofs, canonical rule distribution, a reviewed P2P transport, explicit scan scopes, and resource enforcement.

Running the companion does not automatically earn PROM. The reporter allocation applies only to future protocol-verified security contributions after the corresponding reward path is implemented and audited. Validator participation remains a separate role backed by KAS stake; honeypots require isolated infrastructure and a separate threat model.

---

## 9. Voting Mechanism

### 9.1 Commit-Reveal Protocol

Prevents vote-copying and frontrunning (Architecture Decision #13):

1. **Commit Phase**: Validator submits `sha256(vote_byte || salt_LE || block_height_LE)`
2. **Bond**: 10% of current stake locked as collateral
3. **Reveal Phase**: Validator reveals vote + salt
4. **Verification**: Hash recomputed and compared to commitment
5. **Invalid reveal**: Bond is slashed immediately

### 9.2 Consensus Requirements

- Quorum: 2/3 majority (`VALIDATOR_QUORUM = 6700` at 10000x scale)
- Voting period: 864,000 blocks (~1 day at 10 BPS)
- Minimum votes required for Dev Grants: 10

---

## 10. Rule Storage

### 10.1 Rule State and Asset Representation

Each accepted rule is anchored as canonical rule state on Kaspa L1. The public product target is a unique PROM-RULES asset representation, but current Silverc verification intentionally covers the rule state machine first:
- Target tick: `PROM-RULES`
- Target supply: 1 per accepted rule
- Target ID format: `PROM-RULE-2026-XXXX`
- Current gate: `RuleStorageState.sil` verifies `byte[36]` CIDv1 storage, confidence threshold, quorum, submit/vote/finalize/deactivate covenant sigscripts, and Guardian reputation outcome events

### 10.2 IPFS Content Storage

- Rule content stored on IPFS
- On-chain reference: `bytes(36)` CIDv1 binary with SHA-256 multihash
- **Not** bytes(46) — corrected from CIDv0 base58 assumption (Audit V-002)
- Always CIDv1 (base32), never CIDv0 (Pattern-005)

### 10.3 Contracts

| Contract | Functions | Purpose |
|----------|-----------|---------|
| ValidatorStaking.ss | register, commitVote, revealVote, slash, withdraw | KAS staking + consensus voting |
| GuardianReputation.ss | register, voting_power, proposal_accepted/rejected | Reputation + quadratic voting |
| GovernanceAutoTuning.ss | auto_tune, get_parameter | Weekly parameter adjustment |
| DevIncentivePool.ss | proposeGrant, vote, executeGrant | DAO-voted developer rewards |
| CommunityDonations.ss | donateKas, proposeDisbursement | Transparent community fund |
| RuleStorage.ss | submitProposal, voteOnProposal, finalizeProposal | Rule state + target PROM-RULES asset orchestration |

Legacy `.ss` contracts use `uint64` with 10000x scaling for reputation and confidence values (no float64 in Silverscript). Current Silverc fixtures use signed entrypoint integers at the deploy boundary, with deployment calls scoped to `0..=i64::MAX` where numeric values enter Silverc.

Current-Silverc verification status:
- `ValidatorStakingState.sil`: compile/ABI and runtime transition gates pass.
- `GuardianReputationState.sil`: compile/ABI, runtime transition, and accepted-proposal formula gates pass.
- `RuleStorageState.sil`: compile/ABI/runtime gates pass for submit/vote/finalize/deactivate, including low-confidence, late-vote, zero-vote, and pending-rule rejection paths.
- `CommunityDonationsState.sil`: compile/ABI/runtime gates pass for donate/propose/vote/execute disbursement paths, including zero-donation, over-pool proposal, late-vote, and insufficient-quorum rejection paths.
- `DevIncentivePoolState.sil`: compile/ABI/runtime gates pass for propose/vote/execute grant paths, including max-grant, late-vote, quorum, and approval rejection paths.
- `GovernanceAutoTuningState.sil`: compile/ABI/runtime gates pass for signed metrics reporting and deterministic weekly auto-tuning, including invalid `fp_rate`, early tuning, high-FP, and zero-FP paths.
- Keyless genesis operator: official transaction-v1, compute-budget, covenant-ID, external BIP340 signature, full transaction verification, fee-bound, live Toccata preflight, broadcast acknowledgement, and UTXO-observation paths are implemented and CI-gated; a TLS-only public-resolver probe verifies testnet-10 node readiness without funding; no private-key or raw-transaction input exists.
- Deployment profiles: every new request, procedure, receipt, evidence summary, and status draft is bound to either the exact seven-contract `full` profile or the single-contract `testnet-10-validator-staking-h001` profile. Canary statuses are distinct and cannot satisfy full-release or metrics-oracle readiness gates.
- Deployment receipt verification: public receipt records are checked against the release-bundle manifest and selected deployment profile; synthetic `ci_fixture` receipts are kept separate from real `operator_record` deployment evidence.
- Public receipt-evidence verification: real `operator_record` deployment receipts must also match a public node/explorer snapshot before handoff readiness can pass.
- Public orchestrator-result receipt import: confirmed external deploy results are bound to the verified request set, converted into `operator_record` receipts, rejected if they contain secret-like or raw/serialized transaction fields, and re-validated before status staging.
- Deployment status staging: only verified `operator_record` receipts can produce a manual status-update draft; the guard does not write status files and rejects `ci_fixture` evidence.
- Metrics-oracle status staging: only signer-ready unsigned requests plus verified public oracle tx results can produce a manual status-update draft; the guard does not write status files and rejects blocked requests, secrets, and raw transactions.
- Deploy requests: per-contract public requests are generated and independently verified with hashes bound to the release-bundle manifest.
- Deploy operator procedure: verified requests become a public execution checklist and result-evidence contract. The procedure builder itself accepts no keys, raw transactions, signing material, deployment, or status writes; the Rust genesis operator performs assembly, verification, broadcast, and observation while an external vault/HSM provides only the digest signature.
- Operator capability verification: a public capability record binds deploy and metrics-oracle procedure hashes plus the explicit execution boundary while rejecting secret-like fields and raw transaction payloads.
- Operator handoff package: public release archive, deploy preflight, verified keyless-genesis requests and procedure, optional imported operator receipts, receipt verification, optional public receipt evidence, metrics report preflight, unsigned oracle request, keyless metrics-operation procedure, optional operator-capability summary, optional verified oracle result/evidence/status artifacts, and optional public release-hardening evidence are bundled without accepting private signing material or claiming real deployment.
- Public release-hardening evidence: successful CI, Pages deployment, protected-branch controls, rollback documentation, public Pages verification, and release-note requirements are bound to the exact release commit without accepting credentials, changing repository settings, or touching chain material.

---

## 11. Federated Learning

### 11.1 Fed-DART Protocol

Architecture Decision #10 target: privacy-preserving distributed model
improvement.

```text
PRIVACY BOUNDARY:
- Training records remain local in the target architecture
- Bounded model updates can still leak information
- Client IDs are pseudonymous hashes, not an anonymity guarantee
- Production requires clipping, aggregation, privacy accounting, authentication,
  and stronger anti-poisoning controls beyond NaN/Inf rejection
```

### 11.2 Model Updates

```python
@dataclass
class ModelUpdate:
    gradients: List[float]   # Differential weight updates ONLY
    client_id: bytes         # Pseudonymous (32 bytes), not anonymous
    data_size: int           # Sample count, no content
    signature: bytes         # Authenticity proof
```

---

## 12. Governance Auto-Tuning

Target: deterministic bounded parameter adjustment from authenticated metrics
(Architecture Decision #5). Real state/sponsor inputs, external signatures,
confirmed successor evidence, and production operation remain gated:

| Parameter | Start Value | Target |
|-----------|------------|--------|
| MIN_STAKE_KAS | 10,000 | 50-200 active validators |
| MIN_GUARDIAN_REP | 0.3 | 200-1,000 active guardians |
| MIN_CONFIDENCE_KI | 0.85 | False positive rate < 0.5% |
| VALIDATOR_CONSENSUS | 0.67 | Stable rule acceptance |
| REWARD_BASE | 100 PROM | 100-200 proposals/day |

Tuning interval: weekly (604,800 blocks). Parameter bounds enforced to prevent extreme values.

**Q-003 update**: the legacy `.ss` contract kept `fp_rate` as a stub. The current-Silverc `GovernanceAutoTuningState.sil` path replaces that stub with a signed metrics-oracle report containing active validators, active guardians, proposals/day, and `fp_rate` bounded to `0..10000`. Public report/request/result/evidence gates remain, and the repository-owned Rust operator now deterministically builds the two-input state transition, preserves covenant value, commits fee/mass/compute data, exports separate oracle and sponsor sighashes, verifies both external BIP340 signatures and all inputs, journals acknowledged one-shot broadcast, and observes the exact successor UTXO. Real public UTXOs, signatures, broadcast, confirmation, and independent evidence remain deployment work; the repository accepts no private signing material.

---

## 13. Security Analysis

### 13.1 Sybil Resistance

Quadratic voting mathematically prevents Sybil attacks:
- 1 real guardian (rep 1.0, 500 GFLOPS): power = 5,000
- 100 fake guardians (rep 0.1, 100 GFLOPS each): total power = 1,000
- Ratio: 5:1 in favor of the legitimate participant
- Attacker needs 500+ accounts to match 1 real guardian

### 13.2 False Positive Flood

MIN_CONFIDENCE_KI = 0.85 threshold prevents low-quality proposals:
- 500 proposals with confidence 0.50: ALL blocked
- 1 proposal with confidence 0.90: passes immediately
- Threshold is dynamically adjusted by GovernanceAutoTuning

### 13.3 Collusion Prevention

- Commit-Reveal with salted hashes prevents vote-copying
- Bond system (10% of stake) deters frivolous voting
- Escalating slashing: repeat offenders face up to 3x base penalty
- No emergency-stop entrypoint (Architecture Decision #3); this removes a
  repository-controlled kill switch, not every availability dependency

### 13.4 No Emergency Stop

This is a deliberate contract-design decision, not an oversight. No
repository-controlled emergency-stop entrypoint is introduced. Once deployed,
covenant transitions follow their scripts rather than an individual developer
kill switch. Availability still depends on Kaspa, nodes, clients, and network
access; the invariant is not an uninterrupted-availability guarantee.

---

## 14. Developer Incentive Pool

5% of annual PROM emission (1,000,000 PROM/year) allocated to developer grants:

- Anyone can propose a grant
- Formula: `lines * 10 * (100 + complexity * 10) / 100`
- Maximum per grant: 100,000 PROM
- Voting period: 7 days
- Quorum: 10 validator votes minimum
- Approval: 2/3 majority (VALIDATOR_QUORUM)
- No foundation — disbursement only by DAO vote

---

## 15. Roadmap

| Phase | Timeline | Status |
|-------|----------|--------|
| Whitepaper v4 | March 2026 | ACCEPTED (10/10 audit) |
| Sprint 0: Setup | March 2026 | DONE |
| Sprint 1: Contracts | March 2026 | ACCEPTED |
| Sprint 2: Client | March 2026 | ACCEPTED |
| Sprint 3: AI | March 2026 | ACCEPTED |
| Sprint 4: Guardian | March/August 2026 | CORE ACCEPTED / GH-144 RUNTIME MERGED |
| Sprint 5: Voting | March 2026 | ACCEPTED |
| Sprint 6: E2E | March 2026 | ACCEPTED |
| Sprint 7: Dashboard | March 2026 | ACCEPTED |
| Sprint 8: Public Site | March/July 2026 | ACCEPTED / ongoing documentation maintenance |
| **Kaspa Toccata / post-fork verification** | **June–August 2026** | **Runtime/release gates and the keyless Toccata-v1 genesis operator pass. The manifest-bound, non-promotable H-001 Testnet-10 canary is externally signed, fully verified, confirmed, receipted, and independently evidenced. This does not authorize the remaining state deployments or Mainnet rollout.** |
| Mainnet Launch | Post-verification | PLANNED; H-001 Testnet-10 canary evidence passes, while the remaining state deployments, external signed oracle transaction integration with successor evidence, production proof artifacts and independent review, multi-host operation, and public release-hardening evidence for the exact rollout commit remain required |

---

## 16. Audit Findings and Resolutions

All development is subject to continuous architect audit. Key findings:

| Finding | Severity | Resolution |
|---------|----------|-----------|
| V-001: float64 not supported | HIGH | uint64 with 10000x scaling in all contracts |
| V-002: CID bytes(46) incorrect | HIGH | bytes(36) for CIDv1 binary SHA-256 |
| V-003: Recursive slash() | HIGH | Non-recursive: `multiplier = min(3, count/3+1)` |
| FIX-001: slash() no ACL | CRITICAL | Access control: only GOVERNANCE or RULE_STORAGE |
| FIX-002: .active() compile error | HIGH | Changed to `registered_at == 0` |
| FIX-003: Cumulative counter | HIGH | Time-windowed counter (864,000 blocks) |
| FIX-004: Bond not returned | LOW | `transfer(msg.sender, vc.bond_kas)` on valid reveal |
| FIX-005: Reward formula mismatch | LOW | Corrected to whitepaper formula |
| PATTERN-009: YARA validation boundary | LOW | GH-170 uses merged, exact-main-verified, exact-pinned compile-only YARA-X with bounded in-memory input, no modules/includes, zero warnings, and no scan; production semantic review remains open |
| PATTERN-010: Unnecessary Mutex | LOW | Use `Arc<Phi3Model>` instead of `Arc<Mutex<Phi3Model>>` |
| PATTERN-011: Heuristic confidence | LOW | GH-135 removes the indicator-count/YARA-shape heuristic and strictly parses model-provided integer basis points; live calibration and semantic quality evidence remain open |

Total audit rounds: 10 | Sprint findings: 11 | Critical issues fixed; remaining deployment gates are tracked before beta/mainnet

### July 2026 local outbox retention-governance addendum

The merged GH-117 read-only Guardian loader now requires an owner-only
exact-schema policy whose network, approver key, and recipient scope equal the
separately expected identity. It declares one local recoverable-analysis
purpose, canonical Observable Bundle payloads, an explicit default-deny
durable-kind allowlist, a 100,000-record maximum, and a 30-day maximum.

The policy treats file hashes as corpus-matchable, API imports as software
fingerprints, and byte patterns as potentially proprietary content. The pure
loader persists nothing and authorizes no key, recipient, extractor, privacy,
analyzer, transport, disclosure, or external effect. Governed promotion is
the only local boundary allowed to turn the exact policy snapshot into a
durable enqueue.

### July 2026 enforceable authority and privacy-governance addendum

The merged GH-117 Guardian composition now enforces one exact owner policy
before proof invocation and durable approval consumption. The policy binds the
network, BIP340 approver, recipient scope, authority epoch and inclusive
validity window, fixed same-owner local-analysis purpose and boundary, denied
external disclosure, and one explicit decision for each closed observable
kind. File hashes, API imports, and byte patterns use distinct risk-acceptance
tokens; a cross-kind token is invalid.

Promotion, governance, and retention kind sets must be exactly equal. The
first valid governed acceptance atomically pins the exact raw SHA-256 digests
of all three policies together with authority identity and window. A higher
epoch advances only with a valid signed approval in the same SQLite
transaction as high-water and consumption. Same-identity authority windows
must not overlap; lower epochs and same-epoch changes fail closed.

This is local enforcement, not real-world key ownership or recipient
attestation. It invokes no analyzer or worker, transports or publishes
nothing, and provides no production relation/key/ceremony, chain, token, or
rollout authority.

### July 2026 atomic recoverable outbox addendum

The governed promotion composition now migrates governed ledgers from schema
v2 to v3 and inserts one approval-bound recoverable record containing the full
canonical Observable Bundle. Enqueue, authority activation or advancement,
replay high-water, and approval consumption share the exact same
`BEGIN IMMEDIATE` transaction. A full queue, failed enqueue, lock, overflow,
or schema error leaves every component unchanged and does not consume the
approval. Legacy schema v1 remains separate and has no outbox.

The owner-local claim API deterministically selects the oldest eligible row,
creates a fresh opaque 32-byte lease token internally, and caps lease expiry
at the row's retention deadline. A lost worker can be replaced after lease
expiry; restart leaves committed pending work recoverable. Acknowledge
terminally deletes only the row matching both approval ID and lease token.
Expired-retention rows are removed atomically before claim. Claim results are
non-constructible, non-serializable, and redact the lease token from their
representation.

This boundary provides local recoverable delivery only. It executes no worker
or analyzer, sends or discloses nothing, and performs no wallet, signature,
transaction, broadcast, chain, deployment, or other external action.

---

*Prometheus v4.0 — March 2026, status refreshed August 2026*
*License: MIT | GitHub: github.com/NeaBouli/prometheus-*
*The fire belongs to humanity.*
