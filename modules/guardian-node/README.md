# Prometheus Guardian Node

This module implements and tests non-production Guardian analysis boundaries.
The target architecture runs LLaMA 3 8B first with optional 70B escalation,
but the repository does not prove a completed real-model run, independent
quality evaluation, calibration, or production authority. Current YARA
evidence is limited to compile-valid syntax, a deterministic non-actionable
draft, and synthetic regression fixtures. No actionable rule is authorized.

GH-246 adds a repository-only membership continuity boundary. One owner-only
policy pins a network, public BIP340 transition key, bootstrap source, and
SQLite ledger. Signed transitions advance exact canonical source bytes with
durable epoch, clock, nonce, and equivocation protection. `BallotIngress`
establishes new sessions from only that stored current source under the ledger
lock. There is no signing/private-key API and no external authority, key
rotation, Sybil-resistance, L1, deployment, or production claim.
PR #247 squash-merged normally as exact main
`f12e821bb492caae3b94e5b3c882488eb7f2982d`; CI `33452085421`, Security Audit
`33452085419`, and Pages `33452084065` pass.

## Target Hardware Requirements

### LLaMA 3 8B (Default — Architecture Decision #16)
- **GPU:** NVIDIA GPU with at least 24 GB VRAM (RTX 3090/4090 class or better)
- **RAM:** 32 GB system RAM
- **Storage:** 20 GB for model weights
- **OS:** Linux with NVIDIA drivers + CUDA 12.x

### LLaMA 3 70B (Escalation — Architecture Decision #16)
- **GPU:** 4x NVIDIA A100 or H100 (80 GB each)
- **RAM:** 256 GB system RAM
- **Storage:** 150 GB for model weights
- **OS:** Linux with NVIDIA drivers + CUDA 12.x

## Local vLLM Runtime (GH-144 / M-005)

`docker-compose.yml` defines a fail-closed, loopback-only local inference
boundary: the exact official image
`vllm/vllm-openai:v0.26.0@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52`,
`pull_policy: never`, host ports bound to literal `127.0.0.1`, an internal
Docker network with no outbound path, read-only local model mounts, forced
`HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE`, non-root UID:GID `2000:0`, all
capabilities dropped, `no-new-privileges`, a read-only root filesystem,
bounded tmpfs/pids/memory/shm, and no host IPC. The Compose file accepts and
requires no `HF_TOKEN` or any other secret.

vLLM listens on `0.0.0.0` only inside that isolated container network so
Docker can forward the published port. The host-side binding remains literal
`127.0.0.1`; the structural gate rejects wildcard host publication.

This is non-authorizing runtime machinery. It performs and authorizes no
model download, live evidence collection, calibration, network submission,
or production rollout; those remain separate gates.

### Operator preflight (deliberate, separate steps)

```bash
cd modules/guardian-node

# 1. Provision model weights locally (no download happens at compose time).
#    Only caller-provisioned local directories are used, mounted read-only:
mkdir -p models
#    place weights at ./models/Meta-Llama-3-8B-Instruct/
#    and, for the 70B profile, ./models/Meta-Llama-3-70B-Instruct/

# 2. Pull the exact pinned image by digest as a separate deliberate step.
#    pull_policy is "never", so compose up will NOT fetch it for you:
docker pull vllm/vllm-openai:v0.26.0@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52

# 3. Verify the rendered compose configuration:
docker compose config

# 4. Install the pinned validator dependency in a local virtual environment,
#    then run the fail-closed structural validator:
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python ../../scripts/verify_guardian_vllm_compose.py
```

### Run the 8B service (default)

```bash
docker compose up -d guardian-8b
curl http://127.0.0.1:8000/health
```

### Run the 70B service (opt-in profile)

```bash
docker compose --profile 70b up -d guardian-70b
curl http://127.0.0.1:8001/health
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

`YaraRuleGenerator` obtains source confidence through a second bounded model
call. It accepts exactly one closed JSON object containing an integer
`confidence_bps` in `0..10000`; malformed completion envelopes, duplicate or
extra keys, non-integer values, and out-of-range values fail closed. Indicator
count and YARA text shape no longer affect the score. The basis-point value is
preserved through ensemble commitments without a float round trip.

This is a local orchestration component. A closed response schema provides
format validation, not semantic trust or production calibration.

GH-170 adds a separate compile-only validation boundary for generated candidate
source. It uses the exact-pinned official `yara-x==1.4.0` binding, accepts one
bounded ASCII rule, disables includes, rejects imports, multiple rules, compiler
errors, and compiler warnings, and discards the compiled object without calling
any scan API. It performs no file, process, or data scan and grants no semantic,
submission, publication, or production authority.

Merged and exact-main-verified GH-173 adds an optional deterministic governed-
worker analyzer. It maps already approved `api_import` and `byte_pattern` observables
to one bounded memory-only YARA draft, validates it only through the GH-170
compile boundary, and returns only per-kind counts, a nonce-bound candidate
binding SHA-256, and the compile verdict. File hashes are counted but never
embedded. No source, model, confidence, scan, or downstream authority is
exposed.

PR #174 published exact main `1107b11`; Prometheus CI `31654308969`, Security
Audit `31654308964`, and Pages `31654308875` pass.

## Offline Confidence Evaluation

GH-138 adds a standalone development gate over a canonical 24-case synthetic
YARA benchmark. It internally consistency-checks the corpus, integer-bps
predictions, fixed policy, and expected report by SHA-256, then reproduces the
`8500`-bps confusion matrix,
exact-ratio precision/recall, Brier score, and fixed ten-bin expected
calibration error without floating-point policy decisions.

```bash
cd modules/guardian-node
vector_dir=tests/vectors/confidence-calibration-v1
PYTHONPATH=. python -m jaeger.confidence_calibration \
  --corpus "$vector_dir/corpus.jsonl" \
  --predictions "$vector_dir/predictions.jsonl" \
  --policy "$vector_dir/policy.json" \
  --expected-report "$vector_dir/expected-report.json" \
  --manifest "$vector_dir/integrity-manifest.json"
```

The committed report is `synthetic_ci_only` and always records
`production_authorized=false`. This gate performs no model, network, YARA,
telemetry, transport, wallet, or chain operation. Live model service wiring,
real adversarial-quality evidence, production calibration, P2P transport, and
production authorization remain separate rollout gates.
The co-versioned manifest catches partial or accidental fixture drift during
review and CI; it is not signed or anchored outside the editable repository.

GH-141 adds a separate local-model candidate path. It accepts only the
repository corpus, a relative public served-model identifier, model-artifact
metadata, a TCP port, and a new output path. Inference is fixed to literal
`127.0.0.1`, ignores environment proxies, and accepts no URL. Predictions are
written atomically as mode `0600` canonical JSONL, then can be re-evaluated
offline. The preferred GH-161 path first creates a canonical manifest from an
exact trusted local model directory and re-hashes that directory before model
adapter construction:

```bash
PYTHONPATH=. python -m jaeger.model_provenance \
  --model-dir /trusted/local/model \
  --output /owner-only/path/model-provenance.json

vector_dir=tests/vectors/confidence-calibration-v1
PYTHONPATH=. python -m jaeger.model_evidence \
  --corpus "$vector_dir/corpus.jsonl" \
  --model meta-llama/Meta-Llama-3-8B-Instruct \
  --model-manifest /owner-only/path/model-provenance.json \
  --model-dir /trusted/local/model \
  --port 8000 \
  --output /owner-only/path/local-model-predictions.jsonl

PYTHONPATH=. python -m jaeger.confidence_calibration --candidate \
  --corpus "$vector_dir/corpus.jsonl" \
  --predictions /owner-only/path/local-model-predictions.jsonl \
  --policy "$vector_dir/policy.json"
```

The legacy `--model-sha256` input remains available as explicit caller-supplied
compatibility metadata and cannot be combined with the manifest mode. The
manifest digest binds sorted relative paths, sizes, and SHA-256 values derived
from exact regular-file bytes. It does not establish upstream authenticity,
approval, or that an already running vLLM process loaded those same bytes. No
live result is committed, and schema/prompt binding does not establish semantic
quality, adversarial robustness, calibration, or production authority.

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

## Canonical Guardian Membership Source

`jaeger.guardian_membership_source` defines the local schema-v1 source behind
the snapshot digest and ballot signer mapping. One exact canonical JSON
document is restricted to a separately trusted network and binds an epoch plus
5–1024 sorted unique Guardian IDs one-to-one to structurally valid public
BIP340 x-only keys, fixed model tier `8b`, and model-artifact SHA-256 values.
The source digest is SHA-256 over the exact accepted bytes. The validated source
derives the existing `MembershipSnapshot` and `BallotSigner` objects without
changing either API.

The parser rejects malformed JSON, duplicate keys, reordered/extra/missing
fields, noncanonical bytes, invalid or shared public keys, unsorted/duplicate
members, and network mismatch. The POSIX-only file loader requires an exact
absolute path, owner-only parent and regular file, `O_NOFOLLOW`, descriptor
identity checks, and a 300,000-byte bound. It performs no writes.

This is local structural and assignment consistency, not identity authority.
It includes no private keys or signing, key ownership/rotation, discovery,
transport, Sybil resistance, on-chain attestation, reputation, or production
authority.

GH-242 introduced local ballot-session establishment from one owner-only source
path. That historical path-input API is superseded by GH-246: current
`BallotIngress.establish_session` receives no source path and consumes only the
authority ledger's stored current source under the transition lock. The former
public arbitrary `register` path and direct `BallotContext` construction remain
disabled. Epoch is an identity pin, not time, freshness, rotation, finality,
source authority, or chain state.
PR #243 merged normally as exact main
`5cb132c670d1e7771ccaf6dab2ddf5b1a6fd905a`; exact-main CI `33433012614`,
Security Audit `33433012605`, and Pages `33433011653` pass. External source
authority, key ownership/rotation, Sybil resistance, multi-host operation, L1
attestation, and production trust remain open.

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
not authority against arbitrary interpreter code. The merged GH-117 structural
slice alone verifies no Groth16 proof, loads or approves no source or key, and
performs no transport, analyzer, promotion, wallet, chain, or rollout action.

## Local ThreatHint v2 Privacy/Proof Preflight

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

The sibling Rust package now has the merged and exact-main-verified GH-117
`verify-v2` boundary that performs real Groth16 checks against owner-only
manifest, relation-source, and verifying-key artifacts. This Python preflight
does not invoke it. Only deterministic test artifacts exist, so production
relation/key/ceremony approval remains required; the separate acceptance
boundary below composes the local test-artifact verifier with consumption.

### Non-consuming ThreatHint v2 verified preflight

`jaeger.threat_hint_v2_verified_preflight.ThreatHintV2VerifiedPreflightService`
is a separate POSIX-only local boundary that composes the standalone
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
artifact review; the atomic mechanical boundary is documented below.

### Atomic ThreatHint v2 acceptance

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
outbox effects, wallet, chain, and rollout remain outside this boundary.

### Owner-policy ThreatHint v2 promotion

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

### Owner-local outbox retention governance

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
promotion composition below is the only local boundary allowed to consume
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
promotion, governed schema v5 atomically pins the exact raw SHA-256 digest of every
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
enqueue. Governed schema v5 stores the approval ID, observable commitment,
canonical statement wire and digest, trusted report nonce, canonical bundle
wire, enqueue time, and retention deadline in the exact `BEGIN IMMEDIATE`
transaction that pins or advances authority state, moves ledger high-water,
and consumes the approval. The pending-record cap is checked in that
transaction. Capacity, enqueue, schema, lock, integrity, or overflow failure
rolls everything back and leaves the approval unconsumed.

The same transaction permanently records a strict one-to-one-to-one pairing of
the statement digest, approval ID, and observable commitment. Outbox and result
retention never removes that pairing, so a fresh counterpart cannot rebind an
accepted identity.

An empty schema-v3 outbox migrates transactionally to v5. A nonempty v3 outbox
cannot be upgraded because its report nonce and statement are unrecoverable;
opening it fails closed without changing its version, schema, or rows.
An exact schema-v4 ledger migrates only when both its outbox and result table
are empty; nonempty v4 state remains unchanged and fails closed because its
historical pairing cannot be reconstructed safely.

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

`complete(...)` is the only v5 terminal transition. It requires the exact
unexpired lease, input identity, canonical non-actionable result, and
completion token; one transaction inserts the retained result and deletes the
outbox row. Exact post-commit retry is idempotent, while changed tokens, leases,
inputs, or results fail closed. `acknowledge(...)` cannot delete v5 work without
a durable result. Results inherit the original retention deadline and remain
owner-local/readable until lazy cleanup at that deadline.

`jaeger.observable_analysis_worker` provides a bounded async worker protocol,
the original deterministic count-only test analyzer, and the optional GH-173
semantic-draft analyzer. The latter derives and compile-checks one candidate in
memory, then persists only a closed non-actionable v2 result with exact bindings,
kind counts, a nonce-bound candidate-binding digest, and verdict. It emits no
source, confidence, `should_submit`, semantic-quality claim, transport,
publication, wallet, chain, reward, or external authority. Existing v1 results
remain readable; governed acceptance uses schema v5 but enqueues and records
permanent identity pairing only when promotion explicitly enables the durable
outbox.

### Synthetic YARA semantic-quality evidence

`jaeger.yara_semantic_quality` is a standalone GH-177 offline evaluator. It
compiles one fixed synthetic GH-173-shaped rule with exact-pinned YARA-X and
scans only bounded bytes reconstructed in memory from a closed deterministic
recipe corpus. The canonical report binds the exact corpus, policy, evaluator
module bytes, engine version, rule digest, confusion counts, and
precision/recall/specificity. Authority is fixed to `none`.

The module is not imported by the governed worker, outbox, result schema,
model, transport, submission, wallet, chain, reward, or deployment paths. It
accepts no scan path or process and persists neither rule source nor payload
bytes. Its synthetic baseline is regression evidence only; it does not prove
real-world semantic quality, privacy safety, actionable-rule approval,
calibration, certification, or production readiness.

### Deterministic v2 pipeline integration gate

`tests/test_threat_hint_v2_pipeline_integration.py` is the GH-180 local
development gate. It composes canonical synthetic transport bytes with the real
Python ingress, governed promotion, schema-v5 atomic acceptance/outbox, bounded
worker, and durable GH-173 non-actionable semantic-draft result. Eight POSIX
cases cover exact binding relationships, malformed and oversized frames,
replay and restart, concurrent duplicates, lease recovery, redacted analyzer
failure, and transactional completion rollback.

The gate adds no product runtime or authority path and asserts that GH-177 is
not imported by the pipeline modules. It uses no real sample, external network,
model, scan, disclosure, submission, wallet, chain, reward, deployment, or
production authority. PR #181 merged as exact main `a28ad00`; Prometheus CI
`31662874366`, Security Audit `31662874399`, and Pages `31662873670` pass.

### ThreatHint-v2 transport ingress substrate

`jaeger.threat_hint_v2_transport` parses the shared canonical transport frame
against a separately trusted network. It preserves the exact proof-envelope,
Observable Bundle, and approval wires, while treating the report nonce only as
an untrusted session lookup key. Rust and Python consume one shared exact-byte
valid/invalid corpus.

`jaeger.threat_hint_v2_ingress` provides a bounded owner-only AF_UNIX server.
It reparses transport first, resolves the nonce through injected trusted active
session state, obtains time only from an injected trusted clock, and then passes
the three original wires to `ThreatHintV2PromotionService`. Rejected transport
or session mismatches never call promotion; local unavailability maps to
`busy`. Acknowledgements contain only protocol version, status, and an exact
payload digest where applicable.

This is a repository transport substrate, not a production promotion service.
It constructs no authority, policy, proof artifacts, session store, or model;
it performs no semantic/actionable analysis, disclosure, publication, wallet,
chain, reward, deployment, or external effect.

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
