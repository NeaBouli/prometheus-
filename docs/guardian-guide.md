# Prometheus Guardian Guide

## What Do Guardians Do?

Guardians run LLaMA 3 AI models to analyze threats reported by Light Clients and generate YARA detection rules. They earn PROM rewards and build reputation through accepted proposals.

## Hardware Requirements

### LLaMA 3 8B (Recommended for most operators)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | NVIDIA GPU with 24 GB VRAM | 48 GB datacenter/workstation GPU |
| RAM | 32 GB | 64 GB |
| Storage | 20 GB (model weights) | 50 GB |
| OS | Linux with NVIDIA drivers | Ubuntu 22.04+ |
| CUDA | 12.x | 12.4+ |

### LLaMA 3 70B (High-performance operators)

| Component | Requirement |
|-----------|-------------|
| GPU | 4x NVIDIA A100 or H100 (80 GB each) |
| RAM | 256 GB+ |
| Storage | 150 GB (model weights) |

## Setup (8B)

### 1. Install Prerequisites

Install a supported NVIDIA driver, Docker Engine with Compose v2, and the
NVIDIA Container Toolkit from their official distribution instructions. Do not
pipe remote installation scripts directly into a privileged shell. Verify the
local operator environment before continuing:

```bash
nvidia-smi
docker version
docker compose version
```

### 2. Provision Reviewed Local Artifacts

```bash
cd modules/guardian-node
mkdir -p models/Meta-Llama-3-8B-Instruct
# Place independently reviewed model files in this local directory.
# The directory is gitignored and mounted read-only; Compose has no HF token.
```

From the repository root, validate the source policy before any runtime action:

```bash
python3 scripts/verify_guardian_vllm_compose.py
```

The pinned image and model artifacts are separate operator-controlled inputs.
Review their provenance and digest before performing the explicit image pull
documented in `modules/guardian-node/README.md`. This repository task neither
pulls them nor records a live model result.

The service listens on the container interface only so Docker forwarding can
reach it. Host publication remains restricted to literal `127.0.0.1`, and the
container network is internal.

### 3. Start the Local Runtime

```bash
cd modules/guardian-node
docker compose up guardian-8b
# Optional 70B escalation runtime:
# docker compose --profile 70b up guardian-70b
```

Verify health:
```bash
curl http://127.0.0.1:8000/health
```

### 4. Run the Analyzer

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m jaeger.analyzer
```

## How Rule Generation Works

Current transport status: GH-55 provides the separate canonical
`/prometheus/threat-hint/1.0.0` carrier. GH-58 adds its owner-only verifier
IPC, trusted network/domain binding, persistent freshness/replay admission, and
atomic durable analyzer outbox; GH-63 adds real manifest-pinned verification.
GH-74 maps the outbox into a verified analyzer type without inventing IOC data.
Because v1 carries only a hash commitment and category, that path returns zero
confidence, no YARA rule, and no submission without invoking LLM or YARA.
Merged and exact-main-verified GH-77 isolates failures within each bounded drain and returns only a
data-minimal failure category/index/validated-digest report, so a poison job
stays pending without starving later safe jobs. No canonical bytes, paths, or
exception text enter that report. No approved production Groth16 relation,
verifying key, or vectors ship yet, so
unavailable verification returns fail-closed `busy`; actionable analysis also
needs a reviewed concrete-observable channel or future schema. The steps below
describe the target flow, not current production readiness.

1. Light Client submits a threat hint with ZK proof
2. Guardian receives the hint via the P2P network
3. LLaMA 3 analyzes the threat indicators
4. YARA rule is generated from the analysis
5. Rule is validated (must contain `rule`, `strings:`, `condition:`)
6. If confidence >= 85%, the proposal is submitted to validators
7. Validators vote via Commit-Reveal
8. Accepted rule metadata and CIDv1 references target `RuleStorage`; this path
   does not mint or represent rules as KRC-20 assets

## Reputation System

- Starting reputation: 0.1 (1000 in uint64 at 10000x scale)
- Accepted proposal: reputation += 0.01 * sqrt(compute_power)
- Rejected proposal: reputation *= 0.5
- Below 0.1: lose voting rights
- Voting power: (reputation)^2 * compute_power / 1000 (quadratic)

## Rewards

Guardians receive 30% of PROM emission (6,000,000 PROM/year).
