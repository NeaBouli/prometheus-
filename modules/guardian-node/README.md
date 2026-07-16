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

## Testing

```bash
PYTHONPATH=. python -m pytest tests/ --tb=short
```
