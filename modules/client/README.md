# Prometheus Light Client

This crate contains an implemented and tested **development foundation**, not
a production malware detector or reporting client.

## Current Boundary

- `ai/phi3.rs` checks for a configured model path but runs a deterministic
  entropy heuristic. It creates no ONNX Runtime session and performs no model
  inference.
- `security/yara_scanner.rs` is a custom YARA-style pattern matcher. It is not
  evidence of production YARA malware detection or real-sample quality.
- `blockchain/krc20.rs` observes the Kaspa DAG and returns a development cache;
  canonical Kaspa state/CID and IPFS content loading are not implemented.
- `network/zk_proof.rs` produces a development SHA-256 placeholder, not a
  production zero-knowledge proof.
- The E2E lifecycle test is an in-process, same-host stub fixture. Its
  under-60-second assertion is a target guard, not public-network performance
  evidence.

Beta, mainnet, and production runtime profiles reject these stubs. Production
use remains blocked on real Phi-3/ONNX inference and real-sample evaluation,
approved proof artifacts, canonical rule loading, reviewed P2P reporting,
privacy controls, and multi-host evidence.
