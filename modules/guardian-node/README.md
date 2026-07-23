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
extractors, privacy gates, a separate v2 wire/proof/pairing design, and
production evidence remain required before any observable leaves its local
producer boundary.

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
