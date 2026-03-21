# Prometheus Guardian Guide

## What Do Guardians Do?

Guardians run LLaMA 3 AI models to analyze threats reported by Light Clients and generate YARA detection rules. They earn PROM rewards and build reputation through accepted proposals.

## Hardware Requirements

### LLaMA 3 8B (Recommended for most operators)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | NVIDIA RTX 4070 Ti (12 GB VRAM) | RTX 4090 (24 GB VRAM) |
| RAM | 32 GB | 64 GB |
| Storage | 20 GB (model weights) | 50 GB |
| OS | Linux with NVIDIA drivers | Ubuntu 22.04+ |
| CUDA | 12.x | 12.4+ |

### LLaMA 3 70B (High-performance operators)

| Component | Requirement |
|-----------|-------------|
| GPU | 4x NVIDIA A100 or H100 (80 GB each) |
| RAM | 128 GB+ |
| Storage | 150 GB (model weights) |

## Setup (8B)

### 1. Install Prerequisites

```bash
# NVIDIA drivers + CUDA
sudo apt install nvidia-driver-535 nvidia-cuda-toolkit

# Docker with GPU support
curl -fsSL https://get.docker.com | sh
sudo apt install nvidia-container-toolkit
```

### 2. Download Model Weights

```bash
cd modules/guardian-node
mkdir -p models
# Download Meta-Llama-3-8B-Instruct to ./models/
```

### 3. Start the Guardian

```bash
docker compose up guardian-8b
```

Verify health:
```bash
curl http://localhost:8000/health
```

### 4. Run the Analyzer

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m jaeger.analyzer
```

## How Rule Generation Works

1. Light Client submits a threat hint with ZK proof
2. Guardian receives the hint via the P2P network
3. LLaMA 3 analyzes the threat indicators
4. YARA rule is generated from the analysis
5. Rule is validated (must contain `rule`, `strings:`, `condition:`)
6. If confidence >= 85%, the proposal is submitted to validators
7. Validators vote via Commit-Reveal
8. Accepted rules are stored on-chain as KRC-20 assets

## Reputation System

- Starting reputation: 0.1 (1000 in uint64 at 10000x scale)
- Accepted proposal: reputation += 0.01 * sqrt(compute_power)
- Rejected proposal: reputation *= 0.5
- Below 0.1: lose voting rights
- Voting power: (reputation)^2 * compute_power / 1000 (quadratic)

## Rewards

Guardians receive 30% of PROM emission (6,000,000 PROM/year).
