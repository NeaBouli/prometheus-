# Prometheus Guardian Node

Guardian nodes run LLaMA 3 models to analyze threats and generate YARA rules
for the Prometheus decentralized threat intelligence network.

## Hardware Requirements

### LLaMA 3 8B (Fallback — Architecture Decision #7)
- **GPU:** NVIDIA RTX 4070 Ti or better (12-16 GB VRAM minimum)
- **RAM:** 32 GB system RAM
- **Storage:** 20 GB for model weights
- **OS:** Linux with NVIDIA drivers + CUDA 12.x

### LLaMA 3 70B (Primary — Architecture Decision #6)
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

## Testing

```bash
pytest tests/ --tb=short
```
