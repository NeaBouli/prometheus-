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
pip install httpx pytest black pylint
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
trust Guardians, collect or sign network votes, prevent replay/Sybil
identities, submit proposals, or prove an ensemble on chain. Those are
separate production gates.

## Testing

```bash
PYTHONPATH=. python -m pytest tests/ --tb=short
```
