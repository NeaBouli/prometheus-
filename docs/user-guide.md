# Prometheus Light Client — User Guide

## Current Implementation Status

The repository currently provides development components for:
- YARA-style pattern matching
- a Phi-3 placeholder/heuristic
- a SHA-256 ZK-proof placeholder
- cached rule-reader and federated-learning placeholders

These security-critical placeholders are rejected when `PROMETHEUS_RUNTIME` is `beta`, `mainnet`, `production`, or `prod`. The binary does not yet run an end-to-end scan/report pipeline.

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 2 GB | 4 GB (with Phi-3-mini) |
| Storage | 500 MB | 2 GB |
| GPU | Not required | Not required |
| OS | Linux, macOS, Windows | Linux |
| Network | Internet connection | Kaspa testnet-10 node (optional) |

## Installation

```bash
git clone https://github.com/NeaBouli/prometheus-.git
cd prometheus-
cargo build --release -p prometheus-client
```

The binary is at `target/release/prometheus-client`.

## Running the Experimental Miner Companion

```bash
# Validate the strict local sidecar profile without network activity
./target/release/prometheus-client miner-companion preflight \
  --config modules/client/miner-companion.example.toml

# Optionally verify the configured local Testnet-10 wRPC endpoint
RUST_LOG=info ./target/release/prometheus-client miner-companion preflight \
  --config modules/client/miner-companion.example.toml --connect

# Observe local BlockDAG health until Ctrl-C
RUST_LOG=info ./target/release/prometheus-client miner-companion run \
  --config modules/client/miner-companion.example.toml
```

The companion is opt-in, loopback-only, credential-free, and development-only. It does not control an ASIC or miner, does not connect to Stratum, does not scan files/processes/network traffic, and does not report threats or earn PROM.

## Target Threat Lifecycle

The steps below are the target architecture, not current binary behavior:

1. The client connects to the Kaspa network and loads canonical threat rules
2. Explicitly authorized data is scanned against loaded rules
3. A real local model evaluates suspicious results
4. A real ZK proof protects an eligible threat hint
5. Guardians and validators process the contribution under consensus rules

## Privacy Boundary

The current miner companion emits no miner telemetry and does not start scanning or reporting. Future scanning/reporting needs explicit scan scopes, data minimization, real proof generation, transport review, and operator consent before any privacy guarantee can be made.
