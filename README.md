![Prometheus](logo/Prometheus.png)

# Prometheus

**Decentralized AI-powered threat intelligence on Kaspa.**

[![CI](https://github.com/NeaBouli/prometheus-/actions/workflows/ci.yml/badge.svg)](https://github.com/NeaBouli/prometheus-/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Network](https://img.shields.io/badge/network-kaspa--post--toccata-orange.svg)](https://kaspa.org)

---

## What is Prometheus?

Prometheus transforms every connected device into a sensor in a global threat detection swarm — without central control, without a foundation, without hidden interests. It combines on-device AI (Phi-3-mini) with LLaMA 3 guardian nodes and Kaspa L1 consensus to create an incorruptible, zero-pre-mine security protocol.

---

## Quick Start

| Node Type | Hardware | Command |
|-----------|----------|---------|
| **Light Client** | Any device, 4 GB RAM | `cargo run -p prometheus-client` |
| **Validator** | Kaspa node + 10,000 KAS stake | `cargo run -p prometheus-validator` |
| **Guardian (8B)** | NVIDIA GPU with 24 GB VRAM (RTX 3090/4090 class) | See [Guardian runtime preflight](modules/guardian-node/README.md) |
| **Guardian (70B)** | 4x A100/H100 80 GB, 256 GB system RAM | Opt-in Compose profile `70b`; same preflight required |

```bash
git clone https://github.com/NeaBouli/prometheus-.git
cd prometheus-
cargo build --release
```

---

## Experimental Miner Companion

[Kaspa mining is ASIC-dominated and normally uses Stratum](https://wiki.kaspa.org/mining), while Prometheus reads Kaspa node state through wRPC. The first integration is therefore an opt-in sidecar for operators who already run a local Testnet-10 node; it is not ASIC firmware and does not reuse a Stratum session.

```bash
cargo run -p prometheus-client -- \
  miner-companion preflight \
  --config modules/client/miner-companion.example.toml
```

The companion currently validates a strict credential-free, loopback-only configuration and can monitor local BlockDAG health. It is development-only: host scanning, threat reporting, validator/honeypot modes, and PROM rewards are disabled. Reporter allocation is reserved for future verified security contributions, not passive mining uptime.

---

## Architecture

```
Layer 1 (Kaspa L1):  ValidatorStaking | GuardianReputation | RuleStorage | GovernanceAutoTuning
                     Silverscript contracts on Kaspa with DAGKnight consensus

Layer 2 (P2P):       Guardian ballot request/response over QUIC (implemented core)
                     Rule distribution and client/validator carriers remain rollout work

Off-Chain:           Phi-3-mini (local AI) | LLaMA 3 8B-first/70B-escalation | Fed-DART
                     Data-minimal by design; current v1 sends bounded claim metadata, not raw files
```

---

## Tokens

| Token | Role | Details |
|-------|------|---------|
| **KAS** | Validator Staking | Kaspa native token. Validators stake KAS (min 10,000). Slashed on misbehavior. |
| **PROM** | Rewards & Governance | 0% pre-mine. Earned by guardians for accepted proposals. 20M annual emission. |

**Important:** Validators stake KAS, never PROM. PROM is earned through contribution, never purchased or staked.
Guardian reputation is a separate canonical Kaspa L1 state in `GuardianReputationState`; it is not a PROM balance, badge, or NFT.

---

## Project Status

| Sprint | Status | Description |
|--------|--------|-------------|
| 0 — Setup | DONE | Kaspa testnet-10 node, repo structure, CI/CD |
| 1 — Contracts | ACCEPTED | 6 Silverscript contracts, 54 tests |
| 2 — Client | ACCEPTED | Kaspa RPC, KRC-20 reader, YARA scanner, ZK stub |
| 3 — AI | ACCEPTED | Phi-3 wrapper, anomaly detection, Fed-DART |
| 4 — Guardian | CORE ACCEPTED / RUNTIME IN REVIEW | YARA/analyzer foundation; GH-144 hardens reproducible local vLLM operation without live evidence |
| 5 — Voting | ACCEPTED | Commit-Reveal, bond system, slashing engine |
| 6 — E2E | ACCEPTED | Development-stub lifecycle fixture and security tests; test foundation, not production evidence |
| 7 — Dashboard | ACCEPTED | Audit dashboard, documentation |
| 8 — Public Site | ACCEPTED | Website, SEO, whitepaper, GitHub Pages |
| 9 — Deploy Path | BLOCKED | Current-Silverc runtime and release gates pass. A closed, manifest-bound H-001 canary profile isolates the first real testnet-10 `ValidatorStakingH001` genesis run without a metrics-oracle key and cannot promote full rollout status. A 2026-07-31 refresh from exact main `143a8a0` reproduced the accepted archive, request, and schema-v2 signing request byte-for-byte and revalidated the public funding output as unspent/non-coinbase; an external signature, operator verification, broadcast, receipt, and independent evidence remain. The keyless `reportMetrics` transition operator is implemented, but its real state/sponsor UTXOs, two external signatures, confirmed successor evidence, the remaining six genesis deployments, and final release hardening are still required. |
| 10B — Guardian Decentralization | IN PROGRESS | GH-33, GH-36, and GH-39 provide fail-closed hybrid analysis, complete 5+ Guardian voting, and BIP340-authenticated replay-safe intake. Merged and exact-main-verified GH-42/GH-44/GH-48/GH-52 provide the bounded ballot carrier, persistent transport identity, relay/AutoNAT operation, packaged sidecar, and explicit bootstrap routes. Merged and exact-main-verified GH-55/GH-58/GH-63/GH-74 add the canonical bounded ThreatHint channel, owner-only freshness/replay/outbox ingress, a real manifest-pinned BN254/Arkworks Groth16 engine aligned with active KIP-16, and the bounded digest/network/time-bound outbox-to-analyzer adapter. Merged and exact-main-verified GH-77 isolates failed jobs within each bounded drain, keeps them pending, allows later safe jobs to progress, and reports only a fixed failure category/index plus a validated digest or `None`. Because v1 transports a caller-supplied hash commitment and category but no concrete IOC strings, its verified path emits only a zero-confidence, no-rule, non-submittable result without invoking LLM or YARA generation; it never fabricates analyzer indicators. The protocol does not currently derive that hash from a file or observable. A matching reveal could prove commitment consistency, not truth or artifact derivation. GH-82 specifies the separate artifact-hash/observable-commitment v2 boundary. Merged and exact-main-verified GH-86 adds isolated Rust and Python canonical bundle validators plus one shared byte-exact valid/invalid vector corpus; these local utilities prove only structural and commitment consistency and are not imported by v1, P2P, proof, analyzer, committee, IPFS, chain, or public-rule paths. Merged and exact-main-verified GH-90 adds one local Rust producer that computes a single `file_sha256` from exact caller-supplied bytes and typed scope; Python independently validates its shared vectors. It has no path or generic-value API and proves only deterministic function-boundary derivation, not external file provenance, truth, maliciousness, privacy approval, or proof binding. Merged and exact-main-verified GH-94 adds one local Rust producer for a bounded `byte_pattern` derived from exact bytes, checked offset, boolean wildcard mask, and typed scope. It accepts no pattern string, requires at least eight fixed bytes, and always emits local-only `review_required_v1`; Python independently validates its shared vectors. It does not authorize disclosure or transport and proves no external provenance, maliciousness, privacy approval, or proof binding. Merged and exact-main-verified GH-114 adds isolated local Rust/Python canonical v2 statement parsers and a shared exact-byte corpus with a separately trusted network and a domain-separated digest, without connecting the statement to v1 or any operational path. Merged and exact-main-verified GH-117 integrates strict v2 proof binding, real test-artifact BN254/Arkworks verification, owner-only approval/privacy preflight, atomic approval consumption, enforceable governance, a recoverable outbox, and a bounded deterministic non-actionable worker. Only deterministic proof and analyzer artifacts ship; production proof acceptance and actionable analysis remain disabled. No approved production relation, relation vectors, proving/verifying keys, or ceremony evidence ships, so operated v2 proof acceptance stays fail-closed. `PeerId` remains transport metadata only. Real two-host operation, broad discovery, trusted membership/key assignment, Sybil protection, the remaining reviewed extractor/privacy gates, v2 artifact approval/pairing/transport, real actionable ThreatHint analysis, live model wiring, on-chain attestation, and production operation remain open. |

**GH-135 merged and exact-main verified — model-confidence hardening:** the local YARA path now obtains source
confidence through a separate bounded model call and accepts exactly one
closed JSON object containing integer `confidence_bps` in `0..10000`.
Malformed completion envelopes, duplicate or extra keys, non-integer values,
and out-of-range values fail closed. Indicator count and YARA text shape no
longer set confidence, and accepted basis points reach ensemble commitments
without a float round trip. This is strict format validation, not proof of
semantic quality or calibration; live model operation, adversarial evaluation,
calibration, and production authority remain open.

Protected PR #136 merged without bypass as exact main `3ff3fa1`; Prometheus CI
`30694395348`, Security Audit `30694395356`, and Pages `30694394857` pass on
that SHA.

**GH-138 merged and exact-main verified — deterministic confidence
evaluation:** a standalone offline Guardian evaluator consumes a canonical
24-case synthetic YARA benchmark, exact integer-bps predictions, a fixed
development policy, and a
co-versioned SHA-256 consistency manifest. It reproduces a byte-exact report with the unchanged `8500`-bps
decision boundary, confusion matrix, exact-ratio precision/recall, Brier score,
and ten-bin expected calibration error. Missing, duplicate, reordered,
noncanonical, weakened-policy, or internally hash-inconsistent evidence fails
closed. The manifest detects accidental or partial fixture drift inside one
reviewed revision. It is neither signed nor externally anchored, so it does
not provide independent tamper evidence. CI
evidence is explicitly `synthetic_ci_only` with `production_authorized=false`;
it validates the evaluation machinery, not live-model quality, production
calibration, or authorization.

Protected PR #139 merged normally without bypass as exact main `52209cc`;
Prometheus CI `30697333650`, Security Audit `30697333643`, and Pages
`30697333307` pass on that SHA.

**GH-141 local model candidate evidence (merged and exact-main verified):** the
Guardian can run the same canonical benchmark through an explicitly
literal-loopback vLLM service,
capture one validated integer-bps prediction per case, and write canonical
owner-only JSONL without overwrite or partial output. The evidence binds the
exact corpus, a public served-model identifier, a caller-supplied model
artifact SHA-256, and the repository-pinned prompt specification. A separate
offline `--candidate` evaluator emits exact metrics as
`local_model_candidate_only` with `production_authorized=false`. Environment
proxies and arbitrary endpoint URLs are excluded. This is machinery for a
future real run, not evidence that one occurred: artifact provenance,
semantic/adversarial quality, prompt-injection robustness, production
calibration, and authorization remain open.

Protected PR #142 squash-merged normally without bypass as exact main
`bf3f74f`; Prometheus CI `30727224584`, Security Audit `30727224572`, and Pages
`30727224235` pass on that SHA.

**GH-144 Guardian vLLM runtime hardening (implementation candidate; not yet
merged or exact-main verified):** the Compose boundary pins the official vLLM
release by tag and registry digest, publishes only literal-loopback ports,
forces local offline model resolution, and separates the public served-model
identifier from read-only caller-provisioned weights. The 8B default and opt-in
70B profile run non-root with no added capabilities, no-new-privileges, an
internal network, bounded resources, and a repository-owned structured gate.
This work does not pull an image or model, run inference, prove model-artifact
provenance or quality, calibrate a model, or grant production authority.

**GH-103 merged and exact-main verified — local ELF import extraction:** the Rust Threat Observable boundary can derive one checked `api_import` from exact caller-supplied Linux ELF bytes. It uses the pinned read-only `object` parser, accepts no path, import string, platform, format, or generic observable value, and derives `linux`/`elf` internally. Inputs are capped at 16 MiB and 4096 dynamic symbols; names must match the existing closed ASCII grammar, are byte-sorted and deduplicated, and one checked index is selected. Every result is local-only `review_required_v1`, with shared exact-byte vectors independently parsed by Python. This neither proves external artifact provenance nor authorizes disclosure, transport, proof acceptance, analysis, or publication.

**GH-121 merged and exact-main verified — Windows PE import extraction:** the same isolated boundary derives one checked `api_import` from exact caller-supplied PE32 or PE32+ bytes. It fixes scope to `windows`/`pe`, caps input at 16 MiB, 4096 import descriptors, and 4096 thunk entries, rejects ordinal or grammar-invalid imports, and byte-sorts/deduplicates named functions before selection. Rust exercises both PE architectures and Python independently parses the synthetic shared PE32+ vector. Library names never become observables, every result remains local-only `review_required_v1`, and no path/string/generic, transport, proof, analyzer, wallet, chain, or promotion API is added. Protected PR #122 is merged as exact-main `2e3e1e1`; CI, Security, and Pages pass on that SHA.

**GH-107 merged and exact-main verified — local Observable Approval verification:** Rust and Python verify the same canonical, short-lived BIP340 statement for one exact `review_required_v1` bundle against a separately trusted approver key, recipient-scope digest, network, report nonce, and separately trusted current time that must never be attacker-controlled. The verifier recomputes the observable commitment, enforces a maximum one-hour inclusive validity window, and returns a deterministic approval ID. It contains no signer and performs no transport, persistence, promotion, disclosure, analysis, proof, wallet, or chain action. The signed nonce and approval ID identify repeats but do not prevent replay; durable one-time consumption and authority/policy management remain mandatory promotion gates.

**GH-111 merged and exact-main verified — local durable Observable Approval consumption:** Guardian Node now loads one exact network/approver-key/recipient-scope tuple from an owner-only policy file, invokes the GH-107 verifier itself, and atomically records both the approval ID and authority-bound nonce in a separate owner-only SQLite ledger. Persistent clock high-water, full synchronous transactions, restart/concurrency handling, and closed busy/replay failures prevent local reuse without trusting a caller-supplied verified object. This is only a local consumption receipt: key ownership/rotation, recipient-scope semantics, hint/bundle pairing, privacy approval, transport, analyzer invocation, promotion, outbox delivery, wallet, and chain effects remain outside the implementation.

**Merged and exact-main-verified GH-114 local canonical ThreatHint v2 statement:** separate Rust and Python parsers now accept only one exact 1024-byte-bounded canonical statement shape with distinct artifact hash and observable commitment plus confidence, structural disclosure class, report nonce, observed time, and a network that must equal separately trusted local context. One shared byte-exact corpus fixes field order, scalar bounds, invalid forms, and the domain-separated statement digest. This boundary performs structural binding only: it does not prove artifact derivation, truth, maliciousness, privacy safety, approval, anonymity, proof validity, or replay prevention, and it is not connected to v1, transport, proof acceptance, pairing, analyzer, outbox, wallet, or chain behavior.

**Merged and exact-main-verified GH-117 ThreatHint v2 proof binding (not production-deployed):** Rust and Python now share strict canonical parsers for a bounded opaque-proof envelope and a 19-field `RelationManifest-v2`, plus one atomic data-only binding that requires a separately trusted network and raw-manifest SHA-256 before either object can be paired. The binding reparses both wires, closes protocol/relation/network/domain/public-input identities, and derives two claimed 16-byte big-endian digest halves. It does not verify Groth16, load or approve relation/key artifacts, authorize disclosure, connect transport or analysis, or establish rollout readiness.

**Merged and exact-main-verified GH-117 ThreatHint v2 Groth16 verifier (not production-deployed):** `prometheus-threat-proof verify-v2` owner-loads one canonical manifest plus fixed sibling `relation-source.bin` and `verifying-key.bin` files, binds every size/SHA-256 anchor, requires canonical compressed BN254 keys/proofs and exactly two public inputs, and verifies only the inputs derived by the existing v2 binding. It never resolves or loads a proving key and emits only silent exit status. Its deterministic keys, proofs, and equality relation are test-only. No production relation, verifying/proving key, ceremony approval, privacy authority, approval consumption, transport, analysis, chain action, or rollout evidence is supplied.

**Merged and exact-main-verified GH-117 ThreatHint v2 privacy/proof preflight (not production-deployed):** Guardian Node now has a separate owner-only, read-only policy that pins the network, BIP340 approval key, opaque recipient scope, and exact raw-manifest SHA-256. One Python call binds the envelope/manifest, derives the statement only from that envelope, recomputes the review-required bundle commitment, and verifies the short-lived approval against the same network and trusted report nonce. It returns only data hashes and IDs. It does not verify the opaque Groth16 proof, consume the approval, open or migrate SQLite, authorize disclosure or privacy, or trigger transport, analysis, promotion, wallet, chain, or rollout behavior. Durable acceptance remains blocked until approved v2 proof verification runs in the same trusted call path before the final atomic ledger write.

**Merged and exact-main-verified GH-117 ThreatHint v2 verified-preflight composition (not production-deployed):** Guardian Node now also has one owner-configured, executable-SHA-pinned, POSIX-only service that reads the exact policy-anchored manifest, runs the existing approval/privacy preflight first, and then sends the same exact envelope bytes to the silent Rust `verify-v2` process. The child uses an absolute executable, closed argument set, scrubbed environment, bounded timeout, process-group cleanup, and fail-closed exit mapping; concurrent calls on one service instance fail closed. The returned receipt is non-constructible, non-serializable data only. This layer deliberately opens no SQLite file and consumes no approval; the separate merged atomic-acceptance boundary below adds that final mechanical step. Neither layer approves production artifacts or grants privacy/disclosure, transport, analysis, promotion, wallet, chain, or rollout authority.

**Merged and exact-main-verified GH-117 ThreatHint v2 atomic acceptance (not production-deployed):** one raw-input-only Guardian service now proves exact preflight/consumption network, approver-key, and recipient-scope identity before opening the ledger, runs the verified proof/privacy preflight first, and re-verifies the approval ID and observable commitment before the existing durable SQLite consumption runs as the final state-changing step. Invalid, unavailable, replay, and busy outcomes remain stable and redacted; failed proof or privacy checks never consume an approval or advance ledger time. The receipt is non-constructible and non-serializable data only. This closes the local mechanical verify-plus-consume path, but it does not approve production relation/key/ceremony artifacts, privacy promotion, transport, actionable analysis, signing, chain activity, or rollout.

**Merged and exact-main-verified GH-117 ThreatHint v2 owner-policy promotion (not production-deployed):** one raw-input-only Guardian boundary now owner-loads a separate exact-schema promotion policy, requires `review_required_v1`, exact platform and format, an allowed observable-kind set, and a maximum count before the same original envelope, bundle, and approval bytes may enter atomic acceptance. Check-to-open policy races are bounded with `O_NOFOLLOW`, descriptor identity/mode/size checks, and a capped read. Rejected promotion never invokes the proof verifier or changes approval-consumption count or ledger high-water. Success returns only a frozen, non-constructible, non-serializable local result containing accepted IDs/time, pinned scope, and canonical observable string pairs. This closes local mechanical pairing and owner-policy restriction only; it is not semantic per-kind privacy review, authority/key governance, production artifact approval, transport, analysis, publication, an external effect, or rollout evidence.

**Merged and exact-main-verified GH-117 outbox retention governance (not production-deployed):** a pure read-only Guardian loader now requires one owner-only exact-schema policy bound to the expected network, approver key, and recipient scope. It fixes the local-only retention purpose, canonical Observable Bundle payload form, a default-deny durable-kind allowlist, at most 100,000 pending records, and at most 30 days of retention. The policy records that file hashes remain corpus-matchable, API imports fingerprint software capabilities, and byte patterns may retain proprietary content. The loader itself creates no database or outbox row and proves no key ownership, recipient authorization, extractor provenance, or privacy safety; the governed promotion composition below is the only local boundary allowed to use this policy for durable enqueue.

**Merged and exact-main-verified GH-117 ThreatHint v2 enforceable governance (not production-deployed):** one owner-only policy now binds the exact network, approver key, recipient scope, authority epoch and inclusive validity window, fixed same-Guardian local-analysis purpose/boundary, denied external disclosure, and one explicit deny-or-kind-specific-risk decision for every closed observable kind. Promotion, governance, and retention allowed-kind sets must be exactly equal before the ledger opens. The first valid governed acceptance atomically pins all three exact raw policy digests plus authority identity/window; a higher epoch advances only with a valid signed approval in the same `BEGIN IMMEDIATE` transaction as replay high-water and consumption. Lower epochs, same-epoch policy equivocation, overlapping same-identity windows, hidden legacy authority state, replay, and failed inserts are fail-closed. This closes local policy enforcement only and grants no analyzer execution, transport, disclosure, publication, chain action, or production relation/key/ceremony approval.

**Merged and exact-main-verified GH-117 ThreatHint v2 durable analysis substrate (not production-deployed):** governed schema v4 stores the canonical statement, its digest, trusted report nonce, Observable Bundle, approval binding, and retention in the same `BEGIN IMMEDIATE` transaction as authority state, replay high-water, and approval consumption. Claims revalidate every network/nonce/commitment binding and derive a lease-bound input identity. Atomic `complete(...)` persists one canonical explicitly non-actionable result before deleting the outbox row; exact post-commit retries are idempotent, while stale leases or changed inputs, tokens, results, and retention fail closed. Empty schema-v3 queues migrate; nonempty v3 queues remain unchanged and fail closed because their missing statement/nonce cannot be reconstructed. The included bounded worker uses only a deterministic test analyzer: no LLM, YARA, confidence, `should_submit`, transport, publication, wallet, chain, deployment, or external effect.

**Deployment status:** Prometheus is in post-Toccata rollout verification. All seven current-Silverc fixture compile/ABI/runtime gates pass through the pinned compiler, and the deterministic release archive, keyless genesis request set, request verifier, operation procedure, receipt/evidence guards, handoff auditor, metrics-oracle handoff, and exact-commit release-hardening gates are implemented. Deployment requests carry one of two closed profiles bound to the exact release manifest: `full` selects all seven release fixtures and requires the public metrics-oracle key; `testnet-10-validator-staking-h001` selects only `ValidatorStakingH001`, requires the TLS-only official testnet-10 resolver, omits the oracle key, and emits canary-only statuses that cannot satisfy full rollout or metrics readiness. The repository-owned Rust operator assembles transaction v1, exports only 32-byte digests for external BIP340 signing, verifies returned signatures and complete transactions, revalidates exact live UTXOs, broadcasts behind explicit request-hash acknowledgement, and observes covenant outputs. This now covers both genesis and the value-preserving two-input `GovernanceAutoTuningState.reportMetrics` transition; a separate P2PK sponsor pays its bounded fee, while the covenant state value is preserved exactly. The accepted `205e1ca` H-001 handoff was refreshed from exact main `143a8a0` on 2026-07-31 after the `ruint 1.20.0` security update: the seven-artifact archive, one-request canary set, funding spec, and schema-v2 signing request remained byte-identical, while live read-only preflight again found the public output unspent/non-coinbase on a synced, UTXO-indexed `rusty-kaspa 2.0.1` node above Toccata activation. The [public refresh evidence](docs/evidence/gh-9-h001-readiness-refresh-2026-07-31.json) records the exact hashes, live observation, safety flags, and remaining blockers. No signature or broadcast occurred. Public Python builders accept no keys or raw transactions and do not execute chain operations. The immediate GH-9 canary still needs an explicitly approved external BIP340 signature response, full operator verification, one-shot broadcast, confirmation, and independent public evidence. Full rollout additionally remains gated by the remaining six genesis deployments, real oracle/sponsor inputs and signatures plus successor evidence, and exact-commit release evidence.

**Progress estimate (2026-07-31):** the isolated H-001 canary preparation is about **96% complete**; only the explicitly approved external signature, verification, one-shot broadcast, confirmation, receipt, and independent evidence remain. A rollout-capable core network is about **84–88% complete** with the operated Guardian sidecar, explicit relay-bootstrap configuration, bounded ThreatHint transport, durable ingress, real KIP-16-compatible Groth16 engine, fail-closed v1 analyzer adapter, and merged, exact-main-verified GH-117 v2 binding, test-artifact verifier, verified preflight, atomic local acceptance, owner-policy promotion/pairing, enforceable authority/recipient/per-kind governance, recoverable outbox, and bounded deterministic non-actionable worker. Production relation/key/ceremony approval and independent cryptographic review remain mandatory before that path can accept production proofs. Real privacy-reviewed semantic and actionable v2 analysis, v2 transport, six state-contract deployments, PROM emission, real metrics-oracle execution/evidence, real two-host discovery/relay evidence, remaining P2P paths, and production node evidence remain open. The complete roadmap vision is about **50–55% complete**, so **45–50% remains**. These are scope-weighted engineering estimates, not calendar or release guarantees.

**Covenant genesis operator:** `prometheus-silverc-deployer` implements the official SilverScript genesis shape with Kaspa transaction version 1, compute budget 10, the exact contextual `storage_mass` commitment, P2SH from the compiled contract script, covenant-ID derivation from the funding outpoint plus the unbound genesis output, and funding-input binding only after the ID is derived. It verifies the exact live unspent funding UTXO during preflight and again immediately before broadcast, models the final 66-byte Schnorr signature script, and binds compute, transient, storage, normalized relay/overall mass, plus pinned relay and conservative operator fee floors into signing-request schema v2 before exporting a 32-byte sighash. A canonical `import-signature` path accepts only a public 64-byte BIP340 signature as 128 lowercase hex characters, derives every response field from the validated request, rejects normalized input/output path collisions, and writes output only after BIP340 plus complete Kaspa transaction verification. It persists an exclusive crash-recovery intent before submission, reconciles retries by transaction ID, applies per-request wRPC deadlines, and rebuilds the verified transaction before observing its exact covenant UTXO. The CLI has no private-key, seed, wallet, keystore, or raw-transaction input. Forty-nine unit/security tests, including eleven focused metrics-transition tests, cover deterministic public vectors, fee/mass and profile tamper rejection, secret-field rejection, resolver/TLS fail-closed behavior, signature-import failure/collision guards, journal recovery, and public-file handoff roundtrips. Pinned v2.0.1 supports `testnet-10`; public resolver mode is TLS-only and restricted to testnet-10, while `testnet-12` and non-Toccata `simnet` fail closed. See the [operator runbook](docs/runbooks/silverc-genesis-operator.md).

**Metrics state-transition operator:** the same binary now exposes `report-metrics-preflight`, `report-metrics-prepare`, `report-metrics-import-signatures`, `report-metrics-broadcast`, and `report-metrics-observe`. A closed transition spec binds the exact predecessor state/outpoint/covenant, pinned source and compiler commit, public metrics request, separate P2PK fee-sponsor UTXO, fee bounds, and canonical hash. The operator recompiles predecessor and successor states, preserves the covenant value exactly, derives both `SIG_HASH_ALL` digests, commits compute and contextual storage mass, requires external oracle and sponsor signatures, executes both inputs with `TxScriptEngine`, and revalidates both live UTXOs immediately before a journaled one-shot broadcast. Eleven focused tests cover value preservation, both valid and invalid signers, predecessor-state mismatch, sponsor underflow, request tamper, path collisions, acknowledgement, recorded-result recovery, and pre-network tamper rejection. No wallet or private-key input exists.

**Release governance:** `main` is PR-only with strict up-to-date branches, linear history, resolved conversations, ten required CI/Security checks (including the optimized `Rust Performance` gate), admin enforcement, and blocked force pushes/deletion. While the repository has only one collaborator, formal approvals are set to zero because GitHub does not permit self-approval; the required approval count returns to one when a second collaborator is added.

---

## Links

- [Whitepaper v4](WHITEPAPER.md) — Full technical specification
- [Audit Dashboard](modules/web/audit/index.html) — Live network transparency
- [Audit Log](memory/AUDIT.md) — All audit results, public and immutable
- [Architecture Decisions](memory/MEMO.md) — 15 binding decisions
- [Sprint Planning](memory/SPRINTS.md) — Detailed roadmap

---

## License

MIT — Fully open source. No foundation. No gatekeeper.

---

*Prometheus — The fire belongs to humanity, not to corporations.*
