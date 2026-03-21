# Prometheus Light Client — User Guide

## What Does the Light Client Do?

The Light Client runs on your device and provides real-time threat detection using:
- **YARA pattern matching** against on-chain threat rules
- **Phi-3-mini AI** (optional) for anomaly detection
- **Zero-knowledge proofs** for anonymous threat reporting

Your data never leaves your device. Only mathematical proofs are transmitted.

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

## Running

```bash
# Basic start (connects to public Kaspa nodes via resolver)
RUST_LOG=info ./target/release/prometheus-client

# Connect to a specific node
KASPA_RPC=ws://127.0.0.1:17210 ./target/release/prometheus-client
```

## How It Works

1. The client connects to the Kaspa network and loads threat rules from KRC-20 assets
2. Files on your system are scanned against loaded YARA rules
3. If a threat is detected with confidence > 85%, a ZK proof is generated
4. The anonymous threat hint is submitted to the P2P network
5. Guardian nodes analyze the threat and propose new rules
6. Validators vote — accepted rules are distributed to all clients

## Privacy

- Raw files are **never** uploaded or transmitted
- Only SHA-256 hashes and ZK proofs leave your device
- Your identity is anonymized via Groth16 proofs
- Federated learning transmits gradients only, never data
