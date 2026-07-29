# Prometheus Guardian Node

Guardian nodes run LLaMA 3 models to analyze threats and generate YARA rules
for the Prometheus decentralized threat intelligence network.

## Hardware Requirements

### LLaMA 3 8B (Default — Architecture Decision #16)
- **GPU:** NVIDIA RTX 4070 Ti or better (12-16 GB VRAM minimum)
- **RAM:** 32 GB system RAM
- **Storage:** 20 GB for model weights
- **OS:** Linux with NVIDIA drivers + CUDA 12.x

### LLaMA 3 70B (Escalation — Architecture Decision #16)
- **GPU:** 4x NVIDIA A100 or H100 (80 GB each)
- **RAM:** 128 GB system RAM
- **Storage:** 150 GB for model weights
- **OS:** Linux with NVIDIA drivers + CUDA 12.x

## Quick Start (8B)

```bash
# 1. Download model weights
mkdir -p models
# Download Meta-Llama-3-8B-Instruct to ./models/

# 2. Start the guardian node
docker compose up guardian-8b

# 3. Verify health
curl http://localhost:8000/health
```

## Running the Analyzer

```bash
pip install -r requirements.txt
python -m jaeger.analyzer
```

## Hybrid Routing

`HybridAnalyzer` accepts independently constructed 8B and 70B analyzer
pipelines. It always runs 8B first, keeps a valid result at confidence `0.70`
or above, and escalates below that boundary. Invalid confidence, mismatched
threat hashes, malformed submission decisions, or a failed 70B route fail
closed. The network submission threshold remains `0.85`.

This is a local orchestration component. Live model service wiring, calibrated
model-provided confidence, P2P transport, and production evidence remain
separate rollout gates.

## Local Ensemble Voting

`EnsembleVoter` validates an already collected ballot from an immutable
committee snapshot containing at least five unique 8B Guardian IDs. The
candidate digest commits the protocol version, threat hash, exact YARA bytes
and metadata, canonical source confidence in basis points, policy hash, and
pinned model artifact. Every member must provide exactly one vote bound to the
candidate and snapshot. A strict majority may approve only at or above `8500`
basis points; final confidence is `min(source rule, approving votes)`.

Missing, duplicate, unknown, malformed, mismatched, tied, or below-policy
input fails closed with no YARA output. This component does not discover or
trust Guardians, submit proposals, or prove an ensemble on chain. Those are
separate production gates.

## Authenticated Ballot Intake

`BallotSession` binds one candidate, membership snapshot, network, validity
window, session nonce, and the exact BIP340 x-only public key for every member.
`BallotSigningRequest` exports only a 32-byte public digest for an external
signer. `SignedGuardianBallot` uses an exact-schema canonical JSON envelope,
and `BallotVerifier` checks every context, vote, freshness, and public signature
before persistence.

`ReplayLedger` uses an owner-controlled SQLite file. Its parent directory must
not be writable by group or others; the regular database file is held at mode
`0600`, symlinks are rejected, and atomic uniqueness constraints allow at most
one vote per Guardian and one nonce per active session across restarts and
concurrent collectors. Persisted envelopes are reverified before the existing
`EnsembleVoter` evaluates them. A persistent time high-water mark fails closed
after wall-clock rollback so an already pruned session cannot reopen.

Production code contains no private-key or signing API. GH-42 adds an
owner-only AF_UNIX ingress that resolves only locally registered sessions and
passes exact bounded bytes to this collector. The Rust Guardian carrier uses
direct QUIC/libp2p request/response and returns only accepted, duplicate,
rejected, or busy. `PeerId` is transport metadata, never Guardian membership.
Operated relay/NAT traversal, broad discovery, trusted membership and key
assignment, Sybil resistance, proposal submission, and on-chain attestation
remain separate rollout work.

## ThreatHint Verifier Intake

`jaeger/threat_hint_ingress.py` provides the separate GH-58 owner-only AF_UNIX
boundary for canonical ThreatHint v1 bytes. It binds an injected verifier to
the exact canonical payload plus trusted local network/domain context, rejects
development stubs, enforces freshness and monotonic replay policy, and
atomically persists both replay identities and a durable analyzer-outbox job.
The outbox intentionally carries canonical wire data rather than fabricating
concrete analyzer indicators that are absent from the transport schema.

GH-63 adds `prometheus-threat-proof`, a real BN254/Arkworks Groth16 verification
engine aligned with active KIP-16 and the pinned `rusty-kaspa` v2.0.1 encoding.
It accepts exact canonical ThreatHint bytes only on stdin, binds every semantic
field to two 128-bit field inputs, rejects trailing/noncanonical proof or key
bytes, and loads a canonical relation manifest plus verifying key from
owner-only files. The operator-configured manifest SHA-256 is the trust anchor.
`relation_source_sha256` is manifest-bound attested metadata; release tooling
must independently verify it against the reviewed relation source before an
artifact can be approved.

`Kip16Groth16Verifier` invokes that binary with fixed arguments, a clean
environment, no shell, no payload in argv or output, and a hard timeout. Exit 0
means valid, 1 means invalid, and 3 means unavailable; Clap syntax errors remain
distinct at 2. `jaeger.threat_hint_service` loads an exact-schema owner-only TOML
configuration and supports an explicit `unavailable` default or a fully pinned
`kip16_groth16` mode. Example shape:

```toml
schema_version = 1
network_id = "testnet-10"
socket_path = "/run/user/1000/prometheus/threat-hint.sock"
ledger_path = "/var/lib/prometheus/threat-hint/replay.sqlite3"
max_connections = 32
io_timeout_seconds = 5.0

[verifier]
mode = "unavailable"
```

Start it with `python -m jaeger.threat_hint_service --config /absolute/config.toml`.
No production Groth16 relation, verifying key, proving key, or approved
relation vectors are bundled. Until those public artifacts are reviewed and the
complete trusted `kip16_groth16` configuration is installed, the default
verifier raises `ThreatProofVerifierUnavailable` and the ingress returns
fail-closed `busy`. Test keys are generated at test runtime and are never a
deployment default.

`jaeger.threat_hint_adapter` provides the GH-74 analyzer-domain boundary. It
re-parses every queued canonical payload, verifies its SHA-256 digest, trusted
network, real-proof mode, and admission window, and maps only fields present in
ThreatHint v1 into a frozen `VerifiedThreatHint`. The type deliberately has no
concrete `indicators` field: v1 carries a hash commitment and category, not IOC
strings. `Analyzer.process_verified_threat_hint()` therefore returns an exact
zero-confidence, no-rule, non-submittable result without invoking LLM or YARA
generation. The adapter serializes drains per instance, loads at most 32 jobs,
and marks each one delivered only after that exact safe result. Merged and exact-main-verified GH-77 isolates
each job in the bounded batch: malformed, wrong-network, failed,
clock-rollback, delivery-failed, or unsafe-analyzer jobs stay pending while
later safe jobs continue. The structurally immutable drain report contains only delivered
results plus batch index, fixed failure category, and a validated digest or
`None`; it never includes canonical bytes, paths, or exception text.

This closes the repository-owned v1 outbox-to-analyzer boundary without
claiming actionable threat analysis. Concrete rule generation still requires a
separately reviewed privacy-preserving observable channel or future schema,
approved production proof artifacts, live model wiring, and real operational
evidence. Future side-effecting consumers also require a reviewed cross-process
claim/lease design; GH-74's v1 decision has no submission side effects.

## Local Observable Bundle Validation

`jaeger.threat_observable` is the isolated Python counterpart to the Rust
`prometheus-threat-hint` Canonical Observable Bundle v1 utility. Both parse the
same byte-exact valid/invalid corpus, enforce the same closed grammar and
network/nonce-bound commitment, and expose no arbitrary-value builder.
Direct construction and value-bearing representations are disabled.

This module is not imported by ThreatHint v1, verifier ingress, the analyzer,
committee, IPFS, chain, or public-rule paths. Structural acceptance proves
neither extractor provenance nor semantic privacy. Reviewed kind-specific
extractors, privacy gates, a reviewed v2 relation/proof/pairing and transport
design, and production evidence remain required before any observable leaves
its local producer boundary. The isolated local v2 statement parser below does
not satisfy those promotion gates.

## Local ThreatHint v2 Statement Parsing

`jaeger.threat_hint_v2_statement` independently mirrors the Rust canonical
ThreatHint v2 statement parser. Both consume one shared exact-byte corpus,
require the wire network to match separately trusted local context, and compute
the same length-prefixed domain-separated digest over separate artifact-hash
and observable-commitment fields plus confidence, structural disclosure class,
report nonce, and observed time.

The returned Python object is data only. This module is not imported by v1
ingress, proof verification, approval consumption, analyzer, outbox, wallet, or
chain paths and grants no disclosure, replay, or promotion authority.

## Local ThreatHint v2 Proof Binding

`jaeger.threat_hint_v2_proof_envelope`,
`jaeger.relation_manifest_v2`, and
`jaeger.threat_hint_v2_proof_binding` mirror the Rust canonical envelope,
manifest, and atomic compatibility binding. The binding requires exact raw
bytes, a separately trusted network, and a separately trusted nonzero
lowercase manifest SHA-256. It hashes the raw manifest before parsing, reparses
both canonical objects, closes protocol/relation/network/domain/public-input
identities, and returns two claimed 16-byte digest halves.

The Python result is immutable under supported use and uses an identity-bound
weak snapshot of both exact wires and the trusted network to fail closed on
valid-shape mutation or forgery. This is in-process object-integrity hardening,
not authority against arbitrary interpreter code. The slice is a local
review-ready candidate only: it verifies no Groth16 proof, loads or approves no
source or key, and performs no transport, analyzer, promotion, wallet, chain,
or rollout action.

## Local ThreatHint v2 Privacy/Proof Preflight Candidate

`jaeger.threat_hint_v2_preflight` composes the local v2 structural boundaries
without consuming authority. An owner-only read-only TOML policy pins one
network, BIP340 approver key, opaque recipient scope, and nonzero raw-manifest
SHA-256. The service binds canonical envelope/manifest bytes, derives the
statement only from the bound envelope, checks the review-required bundle
commitment against the trusted report nonce, and verifies the canonical
short-lived approval in the same call.

The receipt is data only. The service performs no Groth16 verification, opens
or migrates no SQLite ledger, consumes no approval, and triggers no transport,
analysis, disclosure, promotion, wallet, chain, or external side effect.
By itself this layer is not acceptance; the local verifier and atomic
composition below supply the mechanical call order, while production artifact
approval and independent review remain mandatory.

The sibling Rust package now has a local review-ready `verify-v2` candidate
that performs real Groth16 checks against owner-only manifest,
relation-source, and verifying-key artifacts. This Python preflight does not
invoke it. Only deterministic test artifacts exist, so production
relation/key/ceremony approval remains required; the separate acceptance
candidate below composes the local test-artifact verifier with consumption.

### Non-consuming ThreatHint v2 verified preflight

`jaeger.threat_hint_v2_verified_preflight.ThreatHintV2VerifiedPreflightService`
is a separate POSIX-only local candidate that composes the standalone
preflight with the Rust verifier. Its owner-only exact-schema TOML config pins
an absolute verifier executable path, its exact SHA-256, one absolute relation
manifest path, and a timeout from 100 through 60000 milliseconds. Network and
manifest SHA-256 remain sourced only from the existing preflight policy.

Each call owner-loads and hashes the exact manifest, runs the Python preflight
first, then revalidates the executable and passes the same exact envelope bytes
to `verify-v2` over stdin. Invocation is shell-free, uses a closed argument
set, `LANG=C`/`LC_ALL=C`, `/` as working directory, closed output streams, a
new process group, bounded timeout, and fail-closed exit handling. Concurrent
calls on one service instance fail closed. The result is a non-constructible,
non-serializable data receipt only.

This composition does not open or mutate SQLite, consume an approval, approve
production relation/key/ceremony artifacts, authorize privacy or disclosure,
or trigger transport, analysis, promotion, wallet, chain, or rollout
behavior. An owner-bounded hash-to-`execve` race remains because Python cannot
portably execute the already-hashed descriptor; therefore the executable and
all ancestors must be owned by the current user or root and cannot be
group/world writable. Final production acceptance still requires independent
artifact review; the atomic mechanical boundary is the separate local
candidate below.

### Atomic ThreatHint v2 acceptance candidate

`jaeger.threat_hint_v2_acceptance.ThreatHintV2AcceptanceService` is a
raw-input-only local composition of verified preflight and durable approval
consumption. Construction compares the preflight and consumption policy
network, BIP340 approver key, and recipient scope before the ledger is created
or opened. Each call runs proof/privacy verification first, then re-verifies
the raw approval and bundle and compares the expected approval ID and
observable commitment before the final atomic SQLite consume.

Invalid, unavailable, replay, and busy outcomes are fixed redacted classes.
Proof, privacy, timeout, or process failures do not consume an approval or
advance ledger high-water. Crash after the commit but before receipt delivery
is recovered as replay on the next identical call, never double consumption.
The returned receipt is non-constructible, non-serializable data only and
grants no downstream authority. Production relation/key/ceremony approval,
independent cryptographic review, privacy promotion, transport, analysis,
outbox effects, wallet, chain, and rollout remain outside this candidate.

### Owner-policy ThreatHint v2 promotion candidate

`jaeger.threat_hint_v2_promotion.ThreatHintV2PromotionService` is the
raw-input-only local boundary above atomic acceptance. A separate owner-only,
exact-schema ASCII TOML policy fixes one platform, one format, a non-empty
duplicate-free observable-kind allowlist, and a maximum count from 1 through
16. The policy file is opened with no-follow semantics, checked by descriptor
device/inode, ownership, mode, and size, and read through a fixed cap.

Each call reparses the canonical bundle, requires `review_required_v1`, and
applies every platform/format/kind/count restriction before the same original
envelope, bundle, and approval bytes may enter atomic acceptance. Rejection
does not invoke `verify-v2`, consume an approval, or advance ledger high-water.
Success returns only a frozen, non-constructible, non-serializable local result
with the accepted digest/IDs/time, policy-pinned scope, and immutable canonical
observable string pairs.

This boundary mechanically pairs and restricts one accepted local candidate.
It does not establish approver-key ownership or rotation, recipient-scope
meaning, semantic per-kind privacy safety, production relation/key/ceremony
approval, transport, analysis, publication, crash-safe external effects,
wallet, chain, or rollout authority.

### Owner-local outbox retention-governance candidate

`jaeger.outbox_retention_policy.load_outbox_retention_policy(...)` is a pure,
read-only policy loader for a possible future local recoverable analysis
queue. Its exact owner-only ASCII TOML schema binds the expected network,
BIP340 approver key, and opaque recipient scope, then fixes purpose
`local_recoverable_analysis_queue_v1`, payload form
`canonical_observable_bundle_v1`, a non-empty duplicate-free durable-kind
allowlist, `max_pending_records` in `1..=100000`, and
`max_retention_seconds` in `1..=2592000`.

The policy file is capped at 4096 bytes and requires POSIX ownership,
owner-only permissions, `O_NOFOLLOW`, and descriptor identity/mode/size
validation. File hashes remain corpus-matchable, API imports fingerprint
software capabilities, and byte patterns may retain proprietary content;
allowing a kind is therefore a retention declaration, not semantic privacy
approval.

This module opens no SQLite database and creates no ledger row, outbox record,
worker, transport, disclosure, or external effect. It proves no key ownership,
scope authorization, extractor provenance, or privacy safety. The governed
promotion composition below is the only local candidate allowed to consume
this exact snapshot for durable enqueue.

### Enforceable ThreatHint v2 authority and privacy governance

`jaeger.threat_hint_v2_governance.load_threat_hint_v2_governance_policy(...)`
loads one exact owner-only policy bound to the expected network, approver key,
and recipient scope. It fixes an authority epoch and inclusive validity
window, purpose `guardian_local_analysis_v1`, boundary
`same_guardian_owner_v1`, external disclosure `deny_v1`, and exactly one
decision for every closed observable kind. A kind is either denied or allowed
only by its own risk-specific local-analysis token.

`ThreatHintV2PromotionService.from_governed_policies(...)` composes one
immutable promotion, governance, and retention snapshot before ledger access.
All three allowed-kind sets must be exactly equal. On the first valid governed
promotion, governed schema v4 atomically pins the exact raw SHA-256 digest of every
policy plus network, key, scope, epoch, and authority window in the same
`BEGIN IMMEDIATE` transaction as high-water and approval consumption.

A lower epoch, same-epoch policy change, or overlapping higher-epoch window
using the same key and scope fails closed. Key or scope rotation may overlap
for controlled recovery because an approval under the old identity cannot
verify under the new one. Existing replay rows and high-water survive v1/v2
migration; hidden preexisting authority state is rejected.

This boundary still invokes no analyzer or worker, transports or publishes
nothing, and grants no production
relation/key/ceremony, wallet, chain, token, or rollout authority. Authority
times are protocol uint64 values, while SQLite storage is signed 64-bit; a
far-future value above `2^63-1` therefore fails closed as a redacted
unavailable consumption rather than being persisted.

### Governed recoverable ThreatHint v2 outbox

Only `ThreatHintV2PromotionService.from_governed_policies(...)` enables durable
enqueue. Governed schema v4 stores the approval ID, observable commitment,
canonical statement wire and digest, trusted report nonce, canonical bundle
wire, enqueue time, and retention deadline in the exact `BEGIN IMMEDIATE`
transaction that pins or advances authority state, moves ledger high-water,
and consumes the approval. The pending-record cap is checked in that
transaction. Capacity, enqueue, schema, lock, integrity, or overflow failure
rolls everything back and leaves the approval unconsumed.

An empty schema-v3 outbox migrates transactionally to v4. A nonempty v3 outbox
cannot be upgraded because its report nonce and statement are unrecoverable;
opening it fails closed without changing its version, schema, or rows.

`ObservableApprovalConsumptionService.outbox().claim(...)` opens one
owner-local claim capability. It removes expired-retention rows, selects the
oldest eligible pending or expired-lease row, generates an opaque 32-byte
lease token internally, and caps lease expiry at retention. Restart leaves
committed pending work available; lost work can be reclaimed after lease
expiry. Every claim reparses the owner-network-pinned statement and canonical
bundle, recomputes statement and bundle commitments, and derives one
domain-separated input identity bound to approval, lease, and retention.
Claim results cannot be constructed or serialized and reveal no token in
`repr`.

`complete(...)` is the only v4 terminal transition. It requires the exact
unexpired lease, input identity, canonical non-actionable result, and
completion token; one transaction inserts the retained result and deletes the
outbox row. Exact post-commit retry is idempotent, while changed tokens, leases,
inputs, or results fail closed. `acknowledge(...)` cannot delete v4 work without
a durable result. Results inherit the original retention deadline and remain
owner-local/readable until lazy cleanup at that deadline.

`jaeger.observable_analysis_worker` provides a bounded async worker protocol and
one deterministic test analyzer. The analyzer only validates and counts the
canonical observables. It emits no confidence, `should_submit`, YARA/rule body,
semantic finding, transport, publication, wallet, chain, reward, or external
authority. Legacy consumption remains schema v1; governed acceptance uses
schema v4 but enqueues only when promotion explicitly enables the durable
outbox.

## Local Observable Approval Consumption

`jaeger.observable_approval_consumption` is a local-only policy and persistence
boundary for the canonical Observable Approval verifier. An owner-only,
exact-schema TOML file fixes one network, x-only approver public key, opaque
recipient-scope digest, and absolute owner-only SQLite ledger path:

```toml
schema_version = 1
network_id = "testnet-10"
approver_xonly_public_key = "<64 lowercase hex characters>"
recipient_scope = "<64 lowercase hex characters>"
ledger_path = "/absolute/owner-only/observable-approval.sqlite3"
```

`ObservableApprovalConsumptionService.consume(...)` accepts only canonical
approval and bundle bytes plus a trusted in-process report nonce and current
time. It constructs the verification context itself, verifies in the same call
path, and atomically consumes both the approval ID and authority-bound approval
nonce. Owner-only path checks, `BEGIN IMMEDIATE`, full synchronous SQLite
durability, uniqueness constraints, and a persistent time high-water close
restart, concurrency, retry, and clock-rollback replay paths.

The receipt is data only. This module has no transport, analyzer, outbox,
pairing, promotion, disclosure, signer, proof, wallet, or chain behavior. The
fixed policy does not establish real-world key ownership, key rotation,
recipient-scope semantics, privacy approval, or exactly-once execution of a
future external action.

## Testing

```bash
PYTHONPATH=. python -m pytest tests/ --tb=short
```
