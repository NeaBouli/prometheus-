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
model-provided confidence, multi-Guardian ensemble voting, P2P transport, and
production evidence remain separate rollout gates.

## Testing

```bash
PYTHONPATH=. python -m pytest tests/ --tb=short
```
